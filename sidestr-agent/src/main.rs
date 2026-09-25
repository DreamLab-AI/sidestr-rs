//! `sidestr-agent`: a did:nostr agent's wallet on a sidestr sidechain.
//! Testnet4 and experimental chains only. See the crate documentation for
//! what each command does.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use serde_json::json;
use sidestr_agent::{
    announced_peg_address, destination, fetch_announced_peg_script, identity, parent_explorer_api,
    parse_pubkey, pegin_plan, prepare, prepare_issue, prepare_transfer, refuse_secret, AgentKey,
    ChainView, Payment, PegTarget, Prepared,
};
use sidestr_core::document::ChainDocument;
use sidestr_round::relay::{ok_count, publish_all, unix_now};
use sidestr_wallet::deliver::client;

/// The five public relays siding publishes to by default.
const RELAYS: &str = "wss://nos.lol,wss://relay.damus.io,wss://relay.primal.net,wss://nostr.mom,wss://nostr.oxtr.dev";

#[derive(Parser, Debug)]
#[command(
    name = "sidestr-agent",
    version,
    about = "A did:nostr agent's wallet on a sidestr sidechain: the Nostr key is the wallet. Testnet only."
)]
struct Cli {
    /// The producer (`/coins`, `/tip`, `/chain.json`, `POST /tx`), or a
    /// mirror for reading.
    #[arg(long, global = true, default_value = "http://127.0.0.1:3450")]
    url: String,
    /// Relays for the kind-23500 event, comma-separated.
    #[arg(long, global = true, default_value = RELAYS, value_delimiter = ',')]
    relays: Vec<String>,
    /// The agent's key file: 64 hex characters or an nsec1…. Never pass a
    /// key on the command line.
    #[arg(long, global = true)]
    key_file: Option<PathBuf>,
    /// Read the chain document from this file instead of `<url>/chain.json`.
    #[arg(long, global = true)]
    chain: Option<PathBuf>,
    /// The block file to replay for the assets view (SPEC 12): a path, or
    /// an http(s) URL; `<url>/blocks.dat` when absent. Plain payments spend
    /// only coins that carry no asset, so every spend reads it.
    #[arg(long, global = true)]
    blocks: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// The agent's coins and balance at the producer's tip.
    Balance,
    /// Every name of a key: npub, did:nostr, script, chain address. The
    /// agent's own with no argument.
    Address {
        /// An npub1…, did:nostr:<hex> or 64-hex x-only key.
        who: Option<String>,
        /// The chain's address prefix; read from the chain document if absent.
        #[arg(long)]
        prefix: Option<String>,
    },
    /// Pay a sidechain destination: an npub, a did:nostr, an address or a script hex.
    Send {
        /// Where to.
        to: String,
        /// Sats.
        amount: u64,
        #[command(flatten)]
        deliver: Deliver,
    },
    /// Issued assets on the chain, and what the agent holds of each.
    Assets,
    /// Issue an asset (SPEC 12): the whole supply on one carrier to the agent.
    Issue {
        /// 1 to 8 of A-Z0-9.
        ticker: String,
        /// Units created.
        supply: u64,
        /// Display decimals, 0 to 8.
        #[arg(long, default_value_t = 0)]
        decimals: u8,
        #[command(flatten)]
        deliver: Deliver,
    },
    /// Move units of an issued asset: an npub, a did:nostr, an address or a script hex.
    SendAsset {
        /// The asset: its id (the issuing txid) or its ticker.
        asset: String,
        /// Where to.
        to: String,
        /// Units.
        amount: u64,
        /// A record written beside the tally (repeatable), e.g. `tip:nostr:<event id>`.
        #[arg(long)]
        memo: Vec<String>,
        #[command(flatten)]
        deliver: Deliver,
    },
    /// Answer kind-23501 faucet requests on the relays with plain sats and,
    /// optionally, units of an asset; one grant per script per window.
    Faucet {
        /// Plain sats per grant.
        #[arg(long, default_value_t = 2_000)]
        sats: u64,
        /// An asset to grant too (id or ticker).
        #[arg(long)]
        asset: Option<String>,
        /// Units of the asset per grant.
        #[arg(long, default_value_t = 100)]
        units: u64,
        /// Hours before one script may be paid again.
        #[arg(long, default_value_t = 24)]
        per_address_hours: u64,
        /// Grants per hour, all scripts together.
        #[arg(long, default_value_t = 20)]
        per_hour: usize,
        /// Where grants are remembered across restarts.
        #[arg(long)]
        state: PathBuf,
    },
    /// Peg out: burn sats owed to a parent address (SPEC 7).
    Burn {
        /// The parent address (or script hex) the peg holders pay.
        to: String,
        /// Sats, at least the chain's pegoutMin.
        amount: u64,
        #[command(flatten)]
        deliver: Deliver,
    },
    /// What a parent wallet pays to peg in: the peg address and its descriptor, and the marker.
    PeginPlan {
        /// Sats to peg.
        #[arg(long)]
        amount: u64,
        /// The refund key (npub, did:nostr or hex); the agent's own by default.
        #[arg(long)]
        refund: Option<String>,
        /// Where the coins appear on the sidechain; the agent's own script by default.
        #[arg(long)]
        to: Option<String>,
        /// Level 1: an address the producer's parent wallet gave, which it
        /// owns. Absent, the peg script the chain's signer announces with its
        /// tip is used (SPEC 0.0.4, the `peg` tag). Level 2 defaults to the
        /// challenge address.
        #[arg(long)]
        peg_address: Option<String>,
        /// Instead: build `tr(<key>, and_v(v:pk(<refund>), older(n)))` and print
        /// the descriptor, which the peg holders must import before paying it.
        #[arg(long, conflicts_with = "peg_address")]
        peg_key: Option<String>,
    },
    /// Send a signed *parent* transaction (a peg-in) with no node of your
    /// own: to the parent's public explorer, and if that refuses or does not
    /// answer, as a kind-23503 event for a producer with a node to broadcast
    /// if and only if its node's policy accepts it (SPEC 11, 0.0.4).
    PublishParent {
        /// The signed parent transaction, hex.
        hex: String,
        /// Skip the explorer: the relays only.
        #[arg(long)]
        no_explorer: bool,
        /// Another explorer API base (Esplora `POST /tx`); the parent's public one by default.
        #[arg(long, conflicts_with = "no_explorer")]
        explorer: Option<String>,
        /// Print the kind-23503 event and deliver nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(clap::Args, Debug)]
struct Deliver {
    /// A fixed fee in sats; the chain's minFeeRate × vsize otherwise.
    #[arg(long)]
    fee: Option<u64>,
    /// Also `POST /tx` to the producer.
    #[arg(long)]
    post: bool,
    /// Build and sign, print, deliver nothing.
    #[arg(long)]
    dry_run: bool,
}

fn key(cli: &Cli) -> Result<AgentKey, Box<dyn std::error::Error>> {
    let path = cli
        .key_file
        .as_ref()
        .ok_or("--key-file is required for this command")?;
    Ok(AgentKey::from_file(path)?)
}

fn chain(cli: &Cli) -> Result<ChainDocument, Box<dyn std::error::Error>> {
    Ok(match &cli.chain {
        Some(p) => ChainDocument::from_json(&std::fs::read_to_string(p)?)?,
        None => client::chain(&cli.url)?,
    })
}

/// The values that are destinations or peg addresses, found in the raw
/// arguments before clap reads them: `--to` and `--peg-address` (as
/// `--flag value` or `--flag=value`), and the first positional argument of
/// `send` and `burn`. Only these are checked, because `--refund`,
/// `--peg-key` and `address` legitimately take a 64-hex public key.
fn destination_args(args: &[String]) -> Vec<&str> {
    const WITH_VALUE: [&str; 7] = [
        "--url",
        "--relays",
        "--key-file",
        "--chain",
        "--fee",
        "--refund",
        "--peg-key",
    ];
    let mut out = Vec::new();
    let mut i = 0;
    let mut payment = false;
    let mut positional_seen = false;
    while i < args.len() {
        let a = args[i].as_str();
        if let Some(v) = a
            .strip_prefix("--to=")
            .or_else(|| a.strip_prefix("--peg-address="))
        {
            out.push(v);
        } else if a == "--to" || a == "--peg-address" {
            if let Some(v) = args.get(i + 1) {
                out.push(v);
            }
            i += 1;
        } else if WITH_VALUE.contains(&a) {
            i += 1;
        } else if a == "send" || a == "burn" {
            payment = true;
        } else if a == "send-asset" {
            // `send-asset <asset> <to> …`: the destination is the second positional
            out.extend(args.get(i + 2).map(String::as_str));
            i += 2;
        } else if payment && !positional_seen && !a.starts_with('-') {
            out.push(a);
            positional_seen = true;
        }
        i += 1;
    }
    out
}

#[tokio::main]
async fn main() {
    // secret-shaped destinations are refused before anything else is judged,
    // parsing included: no other error comes first, and nothing repeats them
    let args: Vec<String> = std::env::args().skip(1).collect();
    for v in destination_args(&args) {
        if let Err(e) = refuse_secret(v) {
            eprintln!("sidestr-agent: {e}");
            std::process::exit(1);
        }
    }
    let cli = Cli::parse();
    match run(&cli).await {
        Ok(v) => println!("{v}"),
        Err(e) => {
            eprintln!("sidestr-agent: {e}");
            std::process::exit(1);
        }
    }
}

mod faucet;

async fn run(cli: &Cli) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    match &cli.cmd {
        Cmd::Balance => {
            let k = key(cli)?;
            let script = k.script().to_hex_string();
            let tip = client::tip(&cli.url)?;
            let coins = client::coins(&cli.url, &script)?;
            let mature: u64 = coins
                .iter()
                .filter(|c| c.is_mature(tip.height))
                .map(|c| c.value)
                .sum();
            Ok(json!({
                "did": format!("did:nostr:{}", k.pubkey()),
                "script": script,
                "tip": tip.height,
                "coins": coins.len(),
                "balance": coins.iter().map(|c| c.value).sum::<u64>(),
                "spendable": mature,
            }))
        }
        Cmd::Address { who, prefix } => {
            let pubkey = match who {
                Some(w) => parse_pubkey(w)?,
                None => key(cli)?.pubkey(),
            };
            let prefix = match prefix {
                Some(p) => p.clone(),
                None => chain(cli)?.address_prefix,
            };
            let id = identity(&pubkey, &prefix)
                .ok_or_else(|| format!("{prefix:?} is not a bech32 prefix"))?;
            Ok(serde_json::to_value(id)?)
        }
        Cmd::Send {
            to,
            amount,
            deliver,
        } => pay(cli, Payment::Send, &destination(to)?, *amount, deliver).await,
        Cmd::Burn {
            to,
            amount,
            deliver,
        } => pay(cli, Payment::Burn, refuse_secret(to)?, *amount, deliver).await,
        Cmd::Assets => {
            let doc = chain(cli)?;
            let v = view(cli, doc)?;
            let me = cli.key_file.as_ref().map(|_| key(cli)).transpose()?;
            let assets: Vec<serde_json::Value> = v
                .assets
                .issued()
                .iter()
                .map(|(id, i)| {
                    let mut a = json!({
                        "id": id.to_string(), "ticker": i.ticker, "decimals": i.decimals,
                        "height": i.height, "supply": i.supply,
                    });
                    if let Some(k) = &me {
                        a["held"] = json!(v.asset_balance(&k.script(), id));
                    }
                    a
                })
                .collect();
            let mut out = json!({ "tip": v.state.height(), "assets": assets });
            if let Some(k) = &me {
                out["plain"] = json!(v
                    .plain_coins(&k.script())
                    .iter()
                    .map(|c| c.value)
                    .sum::<u64>());
            }
            Ok(out)
        }
        Cmd::Issue {
            ticker,
            supply,
            decimals,
            deliver: d,
        } => {
            let k = key(cli)?;
            let v = view(cli, chain(cli)?)?;
            let id = v.state.document().id.clone();
            let p = prepare_issue(&k, &v, ticker, *decimals, *supply, None, d.fee, unix_now())?;
            let mut out = deliver(cli, "issue", &id, p, d).await?;
            out["asset"] = out["txid"].clone();
            Ok(out)
        }
        Cmd::SendAsset {
            asset,
            to,
            amount,
            memo,
            deliver: d,
        } => {
            let k = key(cli)?;
            let v = view(cli, chain(cli)?)?;
            let (asset_id, info) = v
                .find_asset(asset)
                .ok_or_else(|| format!("no asset {asset} on this chain"))?;
            let id = v.state.document().id.clone();
            let p = prepare_transfer(
                &k,
                &v,
                asset_id,
                &destination(to)?,
                *amount,
                memo,
                d.fee,
                unix_now(),
            )?;
            let mut out = deliver(cli, "send-asset", &id, p, d).await?;
            out["asset"] =
                json!({ "id": asset_id.to_string(), "ticker": info.ticker, "units": amount });
            Ok(out)
        }
        Cmd::Faucet {
            sats,
            asset,
            units,
            per_address_hours,
            per_hour,
            state,
        } => {
            faucet::run(
                cli,
                faucet::Grant {
                    sats: *sats,
                    asset: asset.clone(),
                    units: *units,
                    per_address_secs: per_address_hours * 3600,
                    per_hour: *per_hour,
                    state: state.clone(),
                },
            )
            .await
        }
        Cmd::PeginPlan {
            amount,
            refund,
            to,
            peg_key,
            peg_address,
        } => {
            let doc = chain(cli)?;
            let own = cli.key_file.as_ref().map(|_| key(cli)).transpose()?;
            let refund = match (refund, &own) {
                (Some(r), _) => parse_pubkey(r)?,
                (None, Some(k)) => k.pubkey(),
                (None, None) => return Err("--refund or --key-file names the refund key".into()),
            };
            let side = match (to, &own) {
                (Some(t), _) => t.clone(),
                (None, Some(k)) => k.script().to_hex_string(),
                (None, None) => return Err("--to or --key-file names the sidechain script".into()),
            };
            let mut announced = None;
            let target = match (peg_key, peg_address) {
                (Some(k), _) => Some(PegTarget::Key(parse_pubkey(k)?)),
                (None, Some(a)) => Some(PegTarget::Address(a.clone())),
                // level 1 with nothing given: the peg script the signer
                // announces with its tip (SPEC 0.0.4), newest announcement wins
                (None, None)
                    if sidestr_core::federation::Federation::for_document(&doc)?.is_none() =>
                {
                    match fetch_announced_peg_script(&cli.relays, &doc, Duration::from_secs(6))
                        .await
                    {
                        Some(script) => {
                            let address = announced_peg_address(&doc, &script)?;
                            announced = Some(script);
                            Some(PegTarget::Address(address))
                        }
                        None => {
                            return Err(format!(
                                "{} announces no peg script yet: its producer predates SPEC 0.0.4 or has no peg wallet. Pass --peg-address (an address the producer's parent wallet gave) or --peg-key",
                                doc.id
                            )
                            .into())
                        }
                    }
                }
                (None, None) => None,
            };
            let mut plan =
                serde_json::to_value(pegin_plan(&doc, *amount, &refund, &side, target)?)?;
            if let Some(script) = announced {
                plan["pegScript"] = json!(script);
                plan["note"] = json!(format!(
                    "paid to the peg script {} announces with its tip (SPEC 0.0.4); the producer's parent wallet owns it",
                    doc.id
                ));
            }
            Ok(plan)
        }
        Cmd::PublishParent {
            hex,
            no_explorer,
            explorer,
            dry_run,
        } => {
            let doc = chain(cli)?;
            let hex = hex.trim().to_ascii_lowercase();
            let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize_hex(&hex)
                .map_err(|e| format!("not a parent transaction: {e}"))?;
            let txid = tx.compute_txid().to_string();
            let mut note: Option<String> = None;
            let api = if *no_explorer {
                None
            } else {
                explorer
                    .clone()
                    .or_else(|| parent_explorer_api(&doc))
                    .map(|a| a.trim_end_matches('/').to_string())
            };
            if let (Some(api), false) = (&api, *dry_run) {
                match ureq::post(&format!("{api}/tx")).send(&hex) {
                    Ok(mut r) => {
                        let body = r.body_mut().read_to_string().unwrap_or_default();
                        let id = body.trim();
                        return Ok(json!({
                            "cmd": "publish-parent",
                            "chain": doc.id,
                            "txid": if id.is_empty() { txid.clone() } else { id.to_string() },
                            "via": "explorer",
                            "explorer": api,
                        }));
                    }
                    Err(ureq::Error::StatusCode(code)) => {
                        note = Some(format!("the parent explorer refused it (HTTP {code})"));
                    }
                    Err(e) => note = Some(format!("the parent explorer did not answer: {e}")),
                }
            }
            // the parent transaction authorises itself: any key signs the event
            let mut secret = [0u8; 32];
            getrandom::fill(&mut secret)
                .map_err(|e| format!("no randomness for the event key: {e}"))?;
            let throwaway = sidestr_nostr::event::SecretKeySigner::from_bytes(&secret)?;
            let event = sidestr_nostr::tx::sign_parent_transaction_event(
                &throwaway,
                &doc.id,
                &hex,
                unix_now(),
            )?;
            if *dry_run {
                return Ok(json!({
                    "cmd": "publish-parent",
                    "chain": doc.id,
                    "txid": txid,
                    "explorer": api,
                    "signedEvent": event,
                }));
            }
            let res = publish_all(&cli.relays, &event, Duration::from_secs(8)).await;
            let ok = ok_count(&res);
            if ok == 0 {
                return Err(format!(
                    "{}no relay accepted the kind-23503 event either",
                    note.map(|n| format!("{n}; ")).unwrap_or_default()
                )
                .into());
            }
            Ok(json!({
                "cmd": "publish-parent",
                "chain": doc.id,
                "txid": txid,
                "via": "relay",
                "event": event.id,
                "relaysOk": ok,
                "relays": res.len(),
                "note": format!(
                    "{}sent to the relays for a producer's node to broadcast if its policy accepts it",
                    note.map(|n| format!("{n}; ")).unwrap_or_default()
                ),
            }))
        }
    }
}

async fn pay(
    cli: &Cli,
    what: Payment,
    to: &str,
    amount: u64,
    d: &Deliver,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let k = key(cli)?;
    let doc = chain(cli)?;
    let v = view(cli, doc.clone())?;
    let coins = v.plain_coins(&k.script());
    let p = prepare(
        &k,
        &doc,
        &coins,
        v.state.height(),
        what,
        to,
        amount,
        d.fee,
        unix_now(),
    )?;
    deliver(cli, what_name(&what), &doc.id, p, d).await
}

fn what_name(p: &Payment) -> &'static str {
    match p {
        Payment::Send => "send",
        Payment::Burn => "burn",
    }
}

/// The block file's bytes, from a path or a URL.
fn block_file(cli: &Cli) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let src = cli
        .blocks
        .clone()
        .unwrap_or_else(|| format!("{}/blocks.dat", cli.url.trim_end_matches('/')));
    if src.starts_with("http://") || src.starts_with("https://") {
        let mut body = ureq::get(&src).call()?.into_body();
        Ok(body.with_config().limit(256 * 1024 * 1024).read_to_vec()?)
    } else {
        Ok(std::fs::read(&src)?)
    }
}

fn view(cli: &Cli, doc: ChainDocument) -> Result<ChainView, Box<dyn std::error::Error>> {
    Ok(ChainView::replay(
        doc,
        &block_file(cli)?,
        Some(unix_now() as u32),
    )?)
}

async fn deliver(
    cli: &Cli,
    what: &str,
    chain_id: &str,
    p: Prepared,
    d: &Deliver,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut out = json!({
        "cmd": what,
        "chain": chain_id,
        "txid": p.spend.txid.to_string(),
        "event": p.event.id,
        "amount": p.spend.amount,
        "fee": p.spend.fee,
        "change": p.spend.change,
        "vsize": p.spend.vsize,
        "note": p.spend.note,
    });
    if d.dry_run {
        out["hex"] = json!(p.spend.hex);
        out["signedEvent"] = serde_json::to_value(&p.event)?;
        return Ok(out);
    }
    if d.post {
        let r = client::post_tx(&cli.url, &p.spend.hex)?;
        out["posted"] = json!({ "txid": r.txid, "fee": r.fee, "dup": r.dup });
    }
    let res = publish_all(&cli.relays, &p.event, Duration::from_secs(8)).await;
    out["relaysOk"] = json!(ok_count(&res));
    out["relays"] = json!(res.len());
    Ok(out)
}
