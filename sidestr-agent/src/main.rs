//! `sidestr-agent`: a did:nostr agent's wallet on a sidestr sidechain.
//! Testnet4 and experimental chains only. See the crate documentation for
//! what each command does.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use serde_json::json;
use sidestr_agent::{
    destination, identity, parse_pubkey, pegin_plan, prepare, AgentKey, Payment, PegTarget,
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
        /// The peg holders' key for the descriptor, when the document does not name it.
        #[arg(long, conflicts_with = "peg_address")]
        peg_key: Option<String>,
        /// Pay an address the peg holders' wallet gave instead of a descriptor.
        #[arg(long)]
        peg_address: Option<String>,
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

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match run(&cli).await {
        Ok(v) => println!("{v}"),
        Err(e) => {
            eprintln!("sidestr-agent: {e}");
            std::process::exit(1);
        }
    }
}

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
        } => pay(cli, Payment::Burn, to, *amount, deliver).await,
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
            let target = match (peg_key, peg_address) {
                (Some(k), _) => Some(PegTarget::Key(parse_pubkey(k)?)),
                (None, Some(a)) => Some(PegTarget::Address(a.clone())),
                (None, None) => None,
            };
            Ok(serde_json::to_value(pegin_plan(
                &doc, *amount, &refund, &side, target,
            )?)?)
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
    let tip = client::tip(&cli.url)?;
    let coins = client::coins(&cli.url, &k.script().to_hex_string())?;
    let p = prepare(
        &k,
        &doc,
        &coins,
        tip.height,
        what,
        to,
        amount,
        d.fee,
        unix_now(),
    )?;
    let mut out = json!({
        "cmd": what,
        "chain": doc.id,
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
