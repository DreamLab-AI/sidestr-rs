//! `sidestr-agent faucet`: answer kind-23501 requests (SPEC 11) with a grant
//! of plain sats and, when an asset is named, units of it on a carrier.
//!
//! Each request is judged against a fresh replay of the block file, so the
//! faucet never pays from a coin the chain has already spent, and the coins
//! a grant spends are held back until the chain shows them gone (or half an
//! hour passes and the grant is taken to have been dropped). One grant per
//! destination script per window, and at most `per_hour` grants an hour;
//! both survive a restart in the state file.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::Duration;

use bitcoin::{OutPoint, Txid};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sidestr_agent::{AgentKey, ChainView};
use sidestr_core::records::tally_text;
use sidestr_nostr::event::Event;
use sidestr_nostr::kinds::KIND_FAUCET_REQUEST;
use sidestr_nostr::tx::{parse_faucet_request, sign_transaction_event};
use sidestr_round::relay::{follow, ok_count, publish_all, unix_now};
use sidestr_wallet::asset::{sort_coins, CARRIER};
use sidestr_wallet::compose::{build_outputs, OutputsRequest};
use sidestr_wallet::deliver::client;
use sidestr_wallet::spend::resolve_to;
use sidestr_wallet::Permissive;

use crate::{block_file, chain, key, Cli};

/// What one grant is and how often.
pub struct Grant {
    pub sats: u64,
    pub asset: Option<String>,
    pub units: u64,
    pub per_address_secs: u64,
    pub per_hour: usize,
    pub state: PathBuf,
}

#[derive(Default, Serialize, Deserialize)]
struct Remembered {
    /// Destination script hex → when it was last paid.
    paid: HashMap<String, u64>,
    /// When recent grants were made, oldest first.
    recent: VecDeque<u64>,
}

fn load(path: &PathBuf) -> Remembered {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save(path: &PathBuf, r: &Remembered) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(r)?)?;
    std::fs::rename(tmp, path)
}

fn log(msg: impl AsRef<str>) {
    eprintln!("{} faucet: {}", unix_now(), msg.as_ref());
}

pub async fn run(cli: &Cli, g: Grant) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let k = key(cli)?;
    let doc = chain(cli)?;
    let me = k.script();
    let first = ChainView::replay(doc.clone(), &block_file(cli)?, None)?;
    let asset: Option<Txid> = match &g.asset {
        Some(a) => Some(
            first
                .find_asset(a)
                .ok_or_else(|| format!("no asset {a} on {}", doc.id))?
                .0,
        ),
        None => None,
    };
    log(format!(
        "{} on {}: {} sats{} per grant, one per script per {} h, {}/h; key {}…; relays {}",
        if asset.is_some() {
            "sats and asset"
        } else {
            "sats"
        },
        doc.id,
        g.sats,
        asset.map_or(String::new(), |a| format!(
            " + {} of {}…",
            g.units,
            &a.to_string()[..12]
        )),
        g.per_address_secs / 3600,
        g.per_hour,
        &k.pubkey().to_string()[..12],
        cli.relays.join(",")
    ));
    let mut remembered = load(&g.state);
    // outpoints a grant spent, and when, until the chain shows them spent
    let mut held: HashMap<OutPoint, u64> = HashMap::new();
    let mut rx = follow(cli.relays.clone(), vec![KIND_FAUCET_REQUEST], 120, log);
    let mut seen: HashMap<String, u64> = HashMap::new();
    while let Some((relay, ev)) = rx.recv().await {
        if seen.contains_key(&ev.id) {
            continue;
        }
        let now = unix_now();
        seen.retain(|_, t| now.saturating_sub(*t) < 3600);
        seen.insert(ev.id.clone(), now);
        match answer(
            cli,
            &g,
            &k,
            &doc,
            asset,
            &me,
            &ev,
            &mut remembered,
            &mut held,
        )
        .await
        {
            Ok(Some(line)) => {
                log(format!("{line} (asked on {relay})"));
                if let Err(e) = save(&g.state, &remembered) {
                    log(format!("state not saved: {e}"));
                }
            }
            Ok(None) => {}
            Err(e) => log(format!("request {}…: {e}", &ev.id[..12.min(ev.id.len())])),
        }
    }
    Ok(json!({ "stopped": "every relay channel closed" }))
}

#[allow(clippy::too_many_arguments)]
async fn answer(
    cli: &Cli,
    g: &Grant,
    k: &AgentKey,
    doc: &sidestr_core::document::ChainDocument,
    asset: Option<Txid>,
    me: &bitcoin::ScriptBuf,
    ev: &Event,
    remembered: &mut Remembered,
    held: &mut HashMap<OutPoint, u64>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if ev.verify().is_err() {
        return Ok(None);
    }
    let Ok(req) = parse_faucet_request(ev, Some(&doc.id)) else {
        return Ok(None); // another chain's request
    };
    let to = resolve_to(&req.destination, &doc.address_prefix)?.script;
    if to.is_op_return() || &to == me {
        return Err("not a destination the faucet pays".into());
    }
    let now = unix_now();
    let key_hex = to.to_hex_string();
    if let Some(t) = remembered.paid.get(&key_hex) {
        if now.saturating_sub(*t) < g.per_address_secs {
            return Ok(Some(format!(
                "{}… paid within the window; skipped",
                &key_hex[..16]
            )));
        }
    }
    while remembered
        .recent
        .front()
        .is_some_and(|t| now.saturating_sub(*t) >= 3600)
    {
        remembered.recent.pop_front();
    }
    if remembered.recent.len() >= g.per_hour {
        return Ok(Some("hourly limit reached; skipped".into()));
    }

    let view = ChainView::replay(doc.clone(), &block_file(cli)?, None)?;
    let coins = view.coins(me);
    held.retain(|op, t| coins.iter().any(|c| c.outpoint == *op) && now.saturating_sub(*t) < 1800);
    let free: Vec<_> = coins
        .into_iter()
        .filter(|c| !held.contains_key(&c.outpoint))
        .collect();
    let sorted = sort_coins(&free, &view.assets, asset.as_ref());
    let tip = view.state.height();

    let mut outputs = Vec::new();
    let mut records = Vec::new();
    let mut required = Vec::new();
    if let Some(a) = asset {
        let mut carriers = sorted.carriers.clone();
        carriers.sort_by_key(|(_, n)| core::cmp::Reverse(*n));
        let mut have = 0u64;
        for (c, n) in carriers {
            if have >= g.units {
                break;
            }
            have += n;
            required.push(c);
        }
        if have < g.units {
            return Err(format!("holds {have} of the asset, a grant is {}", g.units).into());
        }
        outputs.push((to.clone(), CARRIER));
        let mut assigns = vec![(0u32, g.units)];
        if have > g.units {
            outputs.push((me.clone(), CARRIER));
            assigns.push((1, have - g.units));
        }
        records.push(tally_text(Some(&a), &assigns)?);
    }
    if g.sats > 0 {
        outputs.push((to.clone(), g.sats));
    }
    let spend = build_outputs(
        &OutputsRequest {
            chain: doc,
            coins: &sorted.plain,
            required: &required,
            tip_height: tip,
            outputs: &outputs,
            records: &records,
            fee: None,
        },
        &k.spend_signer(),
        &Permissive,
    )?;
    if asset.is_some() {
        let mut carried_in = Default::default();
        view.assets
            .check(&spend.tx, &mut carried_in)
            .map_err(|e| format!("the grant would break the assets rule: {e}"))?;
    }
    let posted = client::post_tx(&cli.url, &spend.hex);
    let event = sign_transaction_event(&k.event_signer(), &doc.id, &spend.hex, now)?;
    let res = publish_all(&cli.relays, &event, Duration::from_secs(8)).await;
    if posted.is_err() && ok_count(&res) == 0 {
        return Err(format!("nothing took the grant: producer {:?}", posted.err()).into());
    }
    for i in &spend.tx.input {
        held.insert(i.previous_output, now);
    }
    remembered.paid.insert(key_hex.clone(), now);
    remembered.recent.push_back(now);
    Ok(Some(format!(
        "paid {}… {} sats{} in {} (fee {})",
        &key_hex[..16],
        g.sats,
        asset.map_or(String::new(), |_| format!(" + {} units", g.units)),
        spend.txid,
        spend.fee
    )))
}
