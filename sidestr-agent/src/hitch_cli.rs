//! `sidestr-agent hitch …`: the command surface over `sidestr_agent::hitch`.
//!
//! The spend key is `--key-file` when given, else `<state>/spend.key`
//! (minted by `bind`). Every command except `bind` and `status` checks it
//! against the binding and refuses the identity key. A command goes to the
//! `watch` daemon of its state directory when one is running; otherwise it
//! takes the directory's lock and runs the host itself until done.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Subcommand};
use serde_json::{json, Value};

/// The environment switch that unlocks the developer-only commands
/// (`cheat`, `--hold-htlcs`), as Hitch hides Cheat behind a developer switch.
pub const DEVELOPER_ENV: &str = "SIDESTR_HITCH_DEVELOPER";

#[derive(Args, Debug)]
pub struct HitchArgs {
    /// The state directory: spend key, binding, snapshots, journal.
    /// `~/.sidestr/hitch/<chain name>` by default.
    #[arg(long, global = true)]
    state: Option<PathBuf>,
    /// A mirror (`blocks.json`, `blocks.dat`) read when the producer is
    /// down, and compared with it.
    #[arg(long, global = true)]
    mirror: Option<String>,
    /// Milliseconds between chain polls.
    #[arg(long, global = true, default_value_t = 5_000)]
    poll_ms: u64,
    /// Seconds a command waits for its outcome.
    #[arg(long, global = true, default_value_t = 600)]
    timeout: u64,
    /// Answer once the command is under way, without waiting for its outcome.
    #[arg(long, global = true)]
    no_wait: bool,
    #[command(subcommand)]
    cmd: HitchCmd,
}

#[derive(Subcommand, Debug)]
enum HitchCmd {
    /// ADR-2101 D3: mint this agent's spend key (k_spend, from OS entropy,
    /// never from k_id) unless one exists, and have the identity key sign
    /// the kind-38420 binding that names it.
    ///
    /// Or, with `--import`, adopt a binding already minted elsewhere (agentbox's
    /// `sidestr-spend-key.js` writes `<spend key>.binding.json`): it is
    /// verified against the chain and `--key-file` (the spend key it names),
    /// and k_id is never read.
    Bind {
        /// The identity key file (k_id). Read once to sign; never stored here.
        #[arg(long, required_unless_present = "import", conflicts_with = "import")]
        identity_file: Option<PathBuf>,
        /// A signed kind-38420 binding to adopt instead of signing one.
        #[arg(long)]
        import: Option<PathBuf>,
        /// The chain's hash (its kind-3500 event id) for a chain sealed at
        /// SPEC 0.0.5 or later; without it the binding is keyed by the
        /// genesis hash and tagged `legacy`, as agentbox's mint does.
        #[arg(long)]
        chain_hash: Option<String>,
        /// Also publish the binding to `--relays`.
        #[arg(long)]
        publish: bool,
    },
    /// Fund a channel from the spend key's coins and open it.
    Open {
        /// The peer: its spend key (npub or hex), or its `did:nostr`
        /// (resolved through its binding).
        #[arg(long)]
        peer: String,
        /// Sats in the channel (at least 10,000).
        #[arg(long)]
        amount: u64,
        /// Sats given to the peer at the start.
        #[arg(long, default_value_t = 0)]
        push: u64,
        /// The CSV delay of a forced close, in blocks (3 to 144).
        #[arg(long, default_value_t = sidestr_hitch::DEFAULT_DELAY)]
        delay: u16,
        /// The fixed fee of every channel transaction, in sats.
        #[arg(long, default_value_t = sidestr_hitch::DEFAULT_FEE)]
        fee: u64,
    },
    /// An invoice for a payment to this agent (printed as JSON).
    Invoice {
        /// Sats.
        #[arg(long)]
        amount: u64,
        /// Memo.
        #[arg(long)]
        memo: Option<String>,
        /// Seconds until it expires.
        #[arg(long, default_value_t = 3_600)]
        expiry_secs: u64,
    },
    /// Pay over a channel: `--amount` directly, or `--invoice` with an HTLC.
    Pay {
        /// The channel id; chosen by `--peer` otherwise.
        #[arg(long)]
        channel: Option<String>,
        /// The peer, to choose the channel.
        #[arg(long)]
        peer: Option<String>,
        /// Sats, for a direct payment.
        #[arg(long)]
        amount: Option<u64>,
        /// Memo.
        #[arg(long)]
        memo: Option<String>,
        /// An invoice: its JSON, or `@file`.
        #[arg(long)]
        invoice: Option<String>,
        /// Blocks from now to the HTLC's expiry.
        #[arg(long)]
        expiry_blocks: Option<u32>,
    },
    /// Close cooperatively at the current state.
    Close {
        /// The channel id.
        #[arg(long)]
        channel: String,
    },
    /// Close by publishing this agent's latest commitment; its own output
    /// is swept after the CSV delay.
    ForceClose {
        /// The channel id.
        #[arg(long)]
        channel: String,
    },
    /// Run the host: answer peers, follow the chain, punish a revoked
    /// commitment, sweep, claim, and serve the other commands.
    Watch {
        /// Spend keys or `did:nostr` identities allowed to open channels here.
        #[arg(long, value_delimiter = ',')]
        accept_from: Vec<String>,
        /// Accept a channel from anyone.
        #[arg(long)]
        accept_any: bool,
        /// The largest channel accepted, in sats.
        #[arg(long)]
        max_accept: Option<u64>,
        /// The shortest CSV delay accepted.
        #[arg(long, default_value_t = sidestr_hitch::MIN_DELAY)]
        min_delay: u16,
        /// Developer: never settle or fail an incoming HTLC.
        #[arg(long, hide = true)]
        hold_htlcs: bool,
    },
    /// The channels, handshakes, invoices and the host's last view.
    Status,
    /// Developer: publish a revoked commitment to exercise the penalty.
    #[command(hide = true)]
    Cheat {
        /// The channel id.
        #[arg(long)]
        channel: String,
        /// The revoked state to publish.
        #[arg(long)]
        revoked_state: u64,
    },
}

fn developer() -> bool {
    std::env::var(DEVELOPER_ENV).is_ok_and(|v| v == "1")
}

#[cfg(not(unix))]
pub async fn run(_cli: &crate::Cli, _h: &HitchArgs) -> Result<Value, Box<dyn std::error::Error>> {
    Err("the Hitch host needs a Unix system (owner-only files, a lock, a control socket)".into())
}

#[cfg(unix)]
pub async fn run(cli: &crate::Cli, h: &HitchArgs) -> Result<Value, Box<dyn std::error::Error>> {
    use sidestr_agent::hitch::binding::{mint_spend_key, sign_binding, verify_binding};
    use sidestr_agent::hitch::host::{
        bind_control, forward, lock, status_from_files, AcceptConfig, Command, Host, HostConfig,
        Request,
    };
    use sidestr_agent::hitch::store::{Store, BINDING, SPEND_KEY};
    use sidestr_agent::{parse_pubkey, AgentKey};
    use sidestr_round::relay::{ok_count, publish_all, unix_now};

    // status reads files only: with --state it needs neither the chain nor
    // the network, so it answers while a producer is down
    if let (HitchCmd::Status, Some(state)) = (&h.cmd, &h.state) {
        return Ok(status_from_files(&Store::open(state)?)?);
    }
    let doc = crate::chain(cli)?;
    let state = match &h.state {
        Some(s) => s.clone(),
        None => {
            let home = std::env::var_os("HOME").ok_or("no $HOME: pass --state")?;
            PathBuf::from(home).join(".sidestr/hitch").join(&doc.name)
        }
    };
    let store = Store::open(&state)?;

    if let HitchCmd::Status = h.cmd {
        return Ok(status_from_files(&store)?);
    }

    if let HitchCmd::Bind {
        identity_file,
        import,
        chain_hash,
        publish,
    } = &h.cmd
    {
        if let Some(file) = import {
            // adopt: verify, check the spend key, keep; k_id is never read
            let spend_file = cli
                .key_file
                .as_ref()
                .ok_or("--import needs --key-file: the spend key the binding names")?;
            let spend = AgentKey::from_file(spend_file)?;
            let ev: sidestr_nostr::event::Event =
                serde_json::from_str(&std::fs::read_to_string(file)?)?;
            let genesis = genesis_hash(&cli.url, doc.genesis_hash.as_deref())?;
            let b = verify_binding(&ev, &doc.id, Some(&genesis))?;
            b.check_spender(&spend)?;
            store.write(BINDING, serde_json::to_string_pretty(&ev)?.as_bytes())?;
            return Ok(json!({
                "cmd": "hitch bind",
                "imported": file.display().to_string(),
                "chain": doc.id,
                "chainHash": b.chain_hash,
                "genesis": genesis,
                "identity": b.identity,
                "did": format!("did:nostr:{}", b.identity),
                "spend": b.spend,
                "spendKeyFile": spend_file.display().to_string(),
                "binding": ev.id,
                "state": store.dir().display().to_string(),
            }));
        }
        let identity_file = identity_file
            .as_ref()
            .ok_or("--identity-file or --import")?;
        let identity = AgentKey::from_file(identity_file)?;
        let (spend, minted) = match &cli.key_file {
            Some(p) => (AgentKey::from_file(p)?, false),
            None => match store.read(SPEND_KEY)? {
                Some(b) => (AgentKey::parse(&String::from_utf8_lossy(&b))?, false),
                None => {
                    let mut entropy = [0u8; 32];
                    getrandom::fill(&mut entropy).map_err(|e| format!("no randomness: {e}"))?;
                    let k = mint_spend_key(&entropy)?;
                    entropy.fill(0);
                    (k, true)
                }
            },
        };
        if spend.pubkey() == identity.pubkey() {
            return Err(Box::new(sidestr_agent::hitch::Error::SpendIsIdentity));
        }
        let genesis = genesis_hash(&cli.url, doc.genesis_hash.as_deref())?;
        let ev = sign_binding(
            &identity,
            &spend.pubkey(),
            &doc.id,
            chain_hash.as_deref(),
            &genesis,
            unix_now(),
        )?;
        let b = verify_binding(&ev, &doc.id, Some(&genesis))?;
        if minted {
            // the secret goes to disk 0600 and nowhere else; never printed
            store.write_spend_key(&spend)?;
        }
        store.write(BINDING, serde_json::to_string_pretty(&ev)?.as_bytes())?;
        let mut out = json!({
            "cmd": "hitch bind",
            "chain": doc.id,
            "genesis": genesis,
            "identity": b.identity,
            "did": format!("did:nostr:{}", b.identity),
            "spend": b.spend,
            "spendNpub": sidestr_agent::npub(&b.spend_key()),
            "minted": minted,
            "binding": ev.id,
            "state": store.dir().display().to_string(),
        });
        if *publish {
            let res = publish_all(&cli.relays, &ev, Duration::from_secs(8)).await;
            out["relaysOk"] = json!(ok_count(&res));
            out["relays"] = json!(res.len());
        }
        return Ok(out);
    }

    let key = match &cli.key_file {
        Some(p) => AgentKey::from_file(p)?,
        None => {
            let b = store.read(SPEND_KEY)?.ok_or(
                "no spend key: run `hitch bind --identity-file <k_id>` first, or pass --key-file",
            )?;
            AgentKey::parse(&String::from_utf8_lossy(&b))?
        }
    };
    // ADR-2101 D3, before anything is read from the network: the identity
    // key never spends
    if let Some(b) = store.read(BINDING)? {
        let ev: sidestr_nostr::event::Event = serde_json::from_slice(&b)?;
        verify_binding(&ev, &doc.id, doc.genesis_hash.as_deref())?.check_spender(&key)?;
    }

    let mut accept = AcceptConfig {
        min_delay: sidestr_hitch::MIN_DELAY,
        ..Default::default()
    };
    let mut hold_htlcs = false;
    let request = match &h.cmd {
        HitchCmd::Watch {
            accept_from,
            accept_any,
            max_accept,
            min_delay,
            hold_htlcs: hold,
        } => {
            for a in accept_from {
                let k = parse_pubkey(a)?;
                if a.trim().to_ascii_lowercase().starts_with("did:nostr:") {
                    accept.dids.push(k);
                } else {
                    accept.keys.push(k);
                }
            }
            accept.any = *accept_any;
            accept.max_amount = *max_accept;
            accept.min_delay = *min_delay;
            if *hold && !developer() {
                return Err(
                    format!("--hold-htlcs is a developer switch ({DEVELOPER_ENV}=1)").into(),
                );
            }
            hold_htlcs = *hold;
            None
        }
        HitchCmd::Open {
            peer,
            amount,
            push,
            delay,
            fee,
        } => Some(Request::Open {
            peer: peer.clone(),
            amount: *amount,
            push: *push,
            delay: *delay,
            fee: *fee,
        }),
        HitchCmd::Invoice {
            amount,
            memo,
            expiry_secs,
        } => Some(Request::Invoice {
            amount: *amount,
            memo: memo.clone(),
            expiry_secs: *expiry_secs,
        }),
        HitchCmd::Pay {
            channel,
            peer,
            amount,
            memo,
            invoice,
            expiry_blocks,
        } => {
            let invoice = match invoice {
                Some(text) => {
                    let text = match text.strip_prefix('@') {
                        Some(path) => std::fs::read_to_string(path)?,
                        None => text.clone(),
                    };
                    let v: Value = serde_json::from_str(&text)?;
                    // `hitch invoice` prints {"invoice": …}; accept that or the bare invoice
                    let inner = if v.get("invoice").is_some() {
                        v["invoice"].clone()
                    } else {
                        v
                    };
                    Some(Box::new(serde_json::from_value(inner)?))
                }
                None => None,
            };
            Some(Request::Pay {
                channel: channel.clone(),
                peer: peer.clone(),
                amount: *amount,
                memo: memo.clone(),
                invoice,
                expiry_blocks: *expiry_blocks,
            })
        }
        HitchCmd::Close { channel } => Some(Request::Close {
            channel: channel.clone(),
        }),
        HitchCmd::ForceClose { channel } => Some(Request::ForceClose {
            channel: channel.clone(),
        }),
        HitchCmd::Cheat {
            channel,
            revoked_state,
        } => {
            if !developer() {
                return Err(format!("cheat is a developer command ({DEVELOPER_ENV}=1)").into());
            }
            Some(Request::Cheat {
                channel: channel.clone(),
                state: *revoked_state,
            })
        }
        HitchCmd::Bind { .. } | HitchCmd::Status => unreachable!("answered above"),
    };

    let config = HostConfig {
        state: state.clone(),
        url: cli.url.clone(),
        mirror: h.mirror.clone(),
        relays: cli.relays.clone(),
        doc,
        poll: Duration::from_millis(h.poll_ms.max(100)),
        accept,
        hold_htlcs,
        developer: developer(),
        stale_after: Duration::from_millis(h.poll_ms.max(100) * 6).max(Duration::from_secs(30)),
    };

    match request {
        None => {
            let _lock = lock(&store)?;
            let listener = bind_control(&store)?;
            let host = Host::load(config, key)?;
            eprintln!(
                "hitch: watching {} as {} (did:nostr:{}); commands on {}",
                host.binding().chain_id,
                host.node_id(),
                host.binding().identity,
                state.join(sidestr_agent::hitch::store::CONTROL).display()
            );
            host.serve(listener).await?;
            Ok(json!({"cmd": "hitch watch", "stopped": true}))
        }
        Some(request) => {
            let command = Command {
                request,
                wait: !h.no_wait,
                timeout_secs: h.timeout,
            };
            if let Some(v) = forward(&state, &command).await? {
                return Ok(v);
            }
            let _lock = lock(&store)?;
            let host = Host::load(config, key)?;
            Ok(host.run_command(command).await?)
        }
    }
}

/// The chain's genesis hash: the producer's block 0, checked against the
/// document's `genesisHash` when it has one.
#[cfg(unix)]
fn genesis_hash(url: &str, documented: Option<&str>) -> Result<String, Box<dyn std::error::Error>> {
    let text = ureq::get(&format!("{}/blocks.json", url.trim_end_matches('/')))
        .call()?
        .body_mut()
        .read_to_string()?;
    let index: sidestr_core::blockfile::Index = serde_json::from_str(&text)?;
    let first = index
        .blocks
        .first()
        .ok_or("the producer serves no genesis block")?
        .hash
        .clone();
    if let Some(d) = documented {
        if !d.eq_ignore_ascii_case(&first) {
            return Err(format!("the producer's genesis {first} is not the document's {d}").into());
        }
    }
    Ok(first)
}
