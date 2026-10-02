//! The Hitch host engine (feature `cli`, Unix): one agent's channels, run
//! against a producer, a mirror and relays.
//!
//! The kernel's contract is honoured literally. After every call that
//! changes a channel, its snapshot is saved atomically ([`super::store`]).
//! Only then are the returned messages sent and the transactions
//! broadcast. If the save fails, the channel goes back to its last saved
//! snapshot and nothing is sent.
//!
//! # What the loop does
//!
//! Each poll, in order:
//!
//! 1. The chain is read: the producer's `/tip`, then `blocks.json` and a
//!    ranged `blocks.dat`. The mirror is used when the producer is down.
//!    A reorganisation is reported with its depth. Every channel whose
//!    funding spend it undid is taken back (`un_spend`), and every
//!    transaction of this host's that it undid is published again. A
//!    relative or absolute lock is waited out first, so a CSV sweep never
//!    reaches the producer early.
//! 2. Every channel is watched:
//!    - the funding confirms at [`MIN_CONF`], and its output must be
//!      exactly the channel's;
//!    - a spend of the funding output is classified (`on_spend`). A revoked
//!      commitment of the other side's is answered at once with the
//!      penalty, inside the commitment's CSV window;
//!    - a close is followed (`after_close`). Sweeps go out after the
//!      delay, HTLCs are claimed or refunded after expiry, and a
//!      cooperative close is final at [`CLOSE_DEPTH`].
//! 3. Every channel ticks: resends with backoff, resyncs, the protective
//!    close before an HTLC deadline, and an overdue HTLC taken to the
//!    chain.
//! 4. Handshakes in progress resend, and commands that met a retryable
//!    refusal try again (Hitch: twenty tries, 1.5 s apart).
//!
//! Messages arrive between polls over the relay pool (kind 23600; see
//! [`super::envelope`]). An `open` is accepted only from a key the
//! [`AcceptConfig`] allows. A `did:nostr` is allowed through its kind-38420
//! binding, so a peer known by identity is trusted only for the spend key
//! that identity signed.
//!
//! Broadcasts go to the producer's `POST /tx`. If the producer cannot be
//! reached, the transaction is published as a kind-23500 event signed by
//! the spend key, for the producer's relay follower. A refusal is
//! recorded, not retried by another route.
//!
//! Every message, broadcast, spend and reorganisation is appended to the
//! journal with its event id, txid and height. That journal is the receipt.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::secp256k1::{Keypair, Message, SecretKey};
use bitcoin::{Amount, OutPoint, Transaction, TxOut, Txid, Witness};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sidestr_core::assets::AssetView;
use sidestr_core::block::secp;
use sidestr_core::blockfile::Index;
use sidestr_core::document::ChainDocument;
use sidestr_core::sighash::{key_path_sighash, rules_for, SighashRules};
use sidestr_hitch::protocol::{
    AcceptMessage, AcceptPolicy, AcceptedFunder, Broadcast, Bytes32, ChainSpend, ChannelEvent,
    ChannelId, ChannelMachine, ChannelSnapshot, ChannelStatus, Context, FinalisedUpdate,
    FunderOpening, FunderSync, NodeId, OpenMessage, OpenParams, OpeningKeys, OutputLookup,
    PaymentOutcome, PeerMessage, ReadyMessage, ReadyTag, ReceiveUpdate, ReceiverOpening,
    TickAction, TickOptions, CLAIM_MARGIN, CLOSE_DEPTH, EXPIRY_MARGIN, MIN_CONF, MIN_OPEN,
};
use sidestr_hitch::route::{Invoice, InvoiceRecord, RouteAction, Router};
use sidestr_hitch::Side;
use sidestr_nostr::event::Event;
use sidestr_nostr::kinds::{KIND_ACCOUNT_BINDING, KIND_HITCH_MESSAGE};
use sidestr_nostr::relay::Filter;
use sidestr_nostr::tx::sign_transaction_event;
use sidestr_round::relay::{fetch, follow, ok_count, publish_all, unix_now};
use sidestr_wallet::asset::plain_coins;
use sidestr_wallet::deliver::client;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};

use super::binding::{newest_binding, verify_binding, SpendBinding};
use super::envelope::{message_event, read_message, Inbound};
use super::follow::{Advance, ChainFollower, Plan};
use super::store::{Store, BINDING, CHANNELS, CONTROL, INVOICES, LOCK, OPENINGS, STATUS};
use super::{Error, Result};
use crate::{parse_pubkey, prepare, AgentKey, Payment};

/// Seconds of relay history read on start (Hitch's `since: 3600`).
pub const RELAY_SINCE: u64 = 3_600;
/// Seconds between resends of an unanswered handshake message.
pub const HANDSHAKE_RESEND: u64 = 30;
/// Tries for a command refused with a retryable error, and the pause
/// between them (Hitch's router: twenty tries, 1.5 s apart).
pub const RETRY_TRIES: u32 = 20;
const RETRY_PAUSE: Duration = Duration::from_millis(1_500);
/// Blocks between resends of a funding still in no block.
pub const FUNDING_RESEND: u32 = 3;
/// Version of the host's own files around the kernel's snapshot.
pub const FILE_VERSION: u8 = 1;

/// Who may open a channel to this host.
#[derive(Debug, Clone, Default)]
pub struct AcceptConfig {
    /// Spend keys accepted directly.
    pub keys: Vec<XOnlyPublicKey>,
    /// Identities (`did:nostr`) accepted through their kind-38420 binding.
    pub dids: Vec<XOnlyPublicKey>,
    /// Accept any opener.
    pub any: bool,
    /// The largest funding accepted, in sats.
    pub max_amount: Option<u64>,
    /// The shortest CSV delay accepted.
    pub min_delay: u16,
}

/// How a host runs.
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// The state directory ([`super::store`]).
    pub state: PathBuf,
    /// The producer: `/tip`, `/blocks.json`, `/blocks.dat`, `/coins`, `POST /tx`.
    pub url: String,
    /// A mirror serving `blocks.json` and `blocks.dat`, read when the
    /// producer is down and compared with it.
    pub mirror: Option<String>,
    /// Relays for kind 23600 (and the kind-23500 fallback).
    pub relays: Vec<String>,
    /// The chain.
    pub doc: ChainDocument,
    /// Time between polls of the chain.
    pub poll: Duration,
    /// Who may open a channel here.
    pub accept: AcceptConfig,
    /// Developer switch: never settle or fail an incoming HTLC (a payee
    /// that holds). For testing timeouts only.
    pub hold_htlcs: bool,
    /// Developer switch: allow [`Request::Cheat`].
    pub developer: bool,
    /// After this long without a good chain read, the view is stale and
    /// HTLC decisions wait.
    pub stale_after: Duration,
}

/// A command to the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Request {
    /// Fund and open a channel to `peer`.
    Open {
        /// The peer's spend key (npub or hex), or `did:nostr:` resolved
        /// through its binding.
        peer: String,
        /// Sats in the funding output.
        amount: u64,
        /// Sats given to the peer in state zero.
        push: u64,
        /// The CSV delay, in blocks.
        delay: u16,
        /// The fixed fee of every channel transaction.
        fee: u64,
    },
    /// Make an invoice for a payment to this host.
    Invoice {
        /// Sats.
        amount: u64,
        /// Memo.
        memo: Option<String>,
        /// Seconds until it expires.
        expiry_secs: u64,
    },
    /// Pay over a channel: directly (`amount`) or an invoice (an HTLC).
    Pay {
        /// The channel id, or none to choose by peer.
        channel: Option<String>,
        /// The peer, to choose the channel.
        peer: Option<String>,
        /// Sats, for a direct payment.
        amount: Option<u64>,
        /// Memo.
        memo: Option<String>,
        /// An invoice to pay with an HTLC.
        invoice: Option<Box<Invoice>>,
        /// Blocks from now to the HTLC's expiry.
        expiry_blocks: Option<u32>,
    },
    /// Close cooperatively.
    Close {
        /// The channel id.
        channel: String,
    },
    /// Close by publishing this host's latest commitment.
    ForceClose {
        /// The channel id.
        channel: String,
    },
    /// Developer only: publish a *revoked* commitment, to exercise the
    /// counterparty's penalty. Never in production.
    Cheat {
        /// The channel id.
        channel: String,
        /// The revoked state to publish.
        state: u64,
    },
}

/// A request with how to wait for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Command {
    /// What to do.
    pub request: Request,
    /// Whether to answer only once it is done: an open is open, a payment
    /// final, a close settled on the chain.
    pub wait: bool,
    /// Seconds to wait at most.
    pub timeout_secs: u64,
}

type Reply = std::result::Result<Value, String>;

/// The host's file for one channel: the kernel's snapshot and the host's
/// notes about it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelFile {
    /// [`FILE_VERSION`].
    pub version: u8,
    /// The chain id.
    pub chain: String,
    /// The peer's channel key, hex.
    pub peer: String,
    /// The kernel's snapshot (secrets inside).
    pub snapshot: ChannelSnapshot,
    /// The funding transaction, hex, for the funder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding_tx: Option<String>,
    /// When the channel was made.
    pub opened_at: u64,
    /// Why the funding was refused, if it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bad_funding: Option<String>,
}

/// Which side of a handshake this host is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OpeningRole {
    /// It proposed, and funds.
    Funder,
    /// It accepted.
    Receiver,
}

/// A handshake in progress, with what rebuilds it after a restart: the
/// kernel's opening steps are deterministic in their keys and randomness.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpeningFile {
    /// [`FILE_VERSION`].
    pub version: u8,
    /// Funder or receiver.
    pub role: OpeningRole,
    /// The chain id.
    pub chain: String,
    /// The peer's channel key, hex.
    pub peer: String,
    /// The revocation basepoint secret, hex.
    pub revocation_base: String,
    /// The per-state secrets for states 0 and 1, hex.
    pub revocation: [String; 2],
    /// The signing randomness the handshake used, hex.
    pub aux: String,
    /// When it began.
    pub created_at: u64,
    /// The funder's half.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funder: Option<FunderPart>,
    /// The receiver's half.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver: Option<ReceiverPart>,
}

/// What a funder keeps while it opens.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunderPart {
    /// The funding outpoint.
    pub funding: String,
    /// Sats in it.
    pub funding_value: u64,
    /// Sats pushed to the peer.
    pub push: u64,
    /// CSV delay.
    pub delay: u16,
    /// Channel fee.
    pub fee: u64,
    /// The signed funding transaction, broadcast after `ready`.
    pub funding_tx: String,
    /// The peer's `accept`, once taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept: Option<AcceptMessage>,
}

/// What a receiver keeps while it opens.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiverPart {
    /// The funder's `open`.
    pub open: OpenMessage,
    /// The delay policy it was accepted under.
    pub min_delay: u16,
}

/// An invoice this host issued, with its secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoiceFile {
    /// The invoice as given to the payer.
    pub invoice: Invoice,
    /// The preimage, amount and paid flag.
    pub record: InvoiceRecord,
}

enum OpeningState {
    Proposed(Box<FunderOpening>),
    Accepted(Box<AcceptedFunder>),
    Receiver(Box<ReceiverOpening>),
}

struct Opening {
    file: OpeningFile,
    state: OpeningState,
    sent_at: u64,
}

struct Live {
    m: ChannelMachine,
    file: ChannelFile,
    saved: String,
}

enum Goal {
    Opened(ChannelId),
    PayFinal(ChannelId, u64),
    Htlc(Bytes32),
    Settled(ChannelId),
}

struct Waiter {
    goal: Goal,
    deadline: Instant,
    reply: oneshot::Sender<Reply>,
    started: Value,
}

struct Retry {
    command: Command,
    reply: oneshot::Sender<Reply>,
    tries: u32,
    next: Instant,
}

struct Repair {
    tx: Transaction,
    label: String,
    tried_at: Option<u32>,
}

/// One agent's Hitch host: its spend key, its channels, its view of the
/// chain. Build with [`Host::load`], then [`Host::serve`] (the `watch`
/// daemon) or [`Host::run_command`] (one command, then exit).
pub struct Host {
    cfg: HostConfig,
    key: AgentKey,
    me: XOnlyPublicKey,
    store: Store,
    binding: SpendBinding,
    rules: SighashRules,
    follower: ChainFollower,
    chain_ok_at: Option<Instant>,
    chain_error: Option<String>,
    alerts: Vec<String>,
    channels: BTreeMap<ChannelId, Live>,
    openings: BTreeMap<ChannelId, Opening>,
    invoices: BTreeMap<[u8; 32], InvoiceFile>,
    router: Router,
    seen: HashSet<String>,
    seen_order: VecDeque<String>,
    waiters: Vec<Waiter>,
    retries: Vec<Retry>,
    repairs: BTreeMap<Txid, Repair>,
    sent: HashSet<bitcoin::Wtxid>,
    funding_sent: BTreeMap<ChannelId, u32>,
    accept_keys: HashSet<XOnlyPublicKey>,
    dids_at: Option<Instant>,
    mirror_at: Option<Instant>,
    last_status: String,
    polls: u64,
}

impl std::fmt::Debug for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Host")
            .field("me", &self.me)
            .field("chain", &self.cfg.doc.id)
            .field("channels", &self.channels.len())
            .field("openings", &self.openings.len())
            .finish_non_exhaustive()
    }
}

fn random32() -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| Error::Host(format!("no randomness: {e}")))?;
    Ok(b)
}

fn fresh_secret() -> Result<SecretKey> {
    loop {
        if let Ok(k) = SecretKey::from_slice(&random32()?) {
            return Ok(k);
        }
    }
}

fn secret_hex(k: &SecretKey) -> String {
    hex::encode(k.secret_bytes())
}

fn secret_from(text: &str) -> Result<SecretKey> {
    let bytes =
        hex::decode(text.trim()).map_err(|_| Error::Host("a stored secret is not hex".into()))?;
    SecretKey::from_slice(&bytes).map_err(|_| Error::Host("a stored secret is not a key".into()))
}

fn bytes32(text: &str) -> Result<[u8; 32]> {
    let v = hex::decode(text.trim()).map_err(|_| Error::Host("not 32 bytes of hex".into()))?;
    v.try_into()
        .map_err(|_| Error::Host("not 32 bytes of hex".into()))
}

fn channel_path(id: ChannelId) -> String {
    format!("{CHANNELS}/{id}.json")
}

fn opening_path(id: ChannelId) -> String {
    format!("{OPENINGS}/{id}.json")
}

fn invoice_path(hash: &[u8; 32]) -> String {
    format!("{INVOICES}/{}.json", hex::encode(hash))
}

fn kind_of(msg: &PeerMessage) -> String {
    serde_json::to_value(msg)
        .ok()
        .and_then(|v| v["t"].as_str().map(str::to_string))
        .unwrap_or_default()
}

fn role_name(side: Side) -> &'static str {
    match side {
        Side::A => "a",
        Side::B => "b",
    }
}

/// Why `tx` may not yet go into the block at height `next`, or `None` if
/// it may. Every input's BIP 68 relative lock and the transaction's
/// `nLockTime` are judged with `sidestr-core`'s own rule
/// ([`sidestr_core::channel::earliest_height`]). `coin_height` gives the
/// block that holds each input's coin, or `None` for a coin in no block yet,
/// which a relative lock counts from the next block at the earliest. A
/// time-based lock is never sent: this host has no median time past.
///
/// The reference producer (siding `fa86dac`) admits a lock-immature
/// transaction to its mempool and then cannot produce, so nothing this
/// host broadcasts may be early: a premature transaction is held back and
/// sent when this says it may be.
pub fn premature(
    tx: &Transaction,
    next: u32,
    coin_height: impl Fn(&Txid) -> Option<u32>,
) -> Option<String> {
    for (i, input) in tx.input.iter().enumerate() {
        let coin = coin_height(&input.previous_output.txid).unwrap_or(next);
        match sidestr_core::channel::earliest_height(tx, i, coin) {
            None => return Some(format!("input {i} carries a time-based lock")),
            Some(from) if from > next => {
                return Some(format!(
                    "input {i} may be in a block from height {from}; the next block is {next}"
                ))
            }
            Some(_) => {}
        }
    }
    None
}

fn http() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(20)))
            .build(),
    )
}

fn fetch_index(base: &str) -> std::result::Result<Index, String> {
    let url = format!("{}/blocks.json", base.trim_end_matches('/'));
    let mut r = http().get(&url).call().map_err(|e| e.to_string())?;
    if !r.status().is_success() {
        return Err(format!("{url}: HTTP {}", r.status()));
    }
    let text = r.body_mut().read_to_string().map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("{url}: {e}"))
}

fn fetch_tail(base: &str, offset: u64) -> std::result::Result<Vec<u8>, String> {
    let url = format!("{}/blocks.dat", base.trim_end_matches('/'));
    let mut r = http()
        .get(&url)
        .header("range", &format!("bytes={offset}-"))
        .call()
        .map_err(|e| e.to_string())?;
    let status = r.status().as_u16();
    let body = r
        .body_mut()
        .with_config()
        .limit(256 * 1024 * 1024)
        .read_to_vec()
        .map_err(|e| e.to_string())?;
    match status {
        206 => Ok(body),
        200 => Ok(body.get(offset as usize..).unwrap_or_default().to_vec()),
        s => Err(format!("{url}: HTTP {s}")),
    }
}

fn fetch_tip(base: &str) -> Option<(u32, String)> {
    let t = client::tip(base).ok()?;
    Some((t.height, t.hash))
}

/// Hold the state directory's lock (non-blocking): one running host per
/// directory. Keep the returned file open for as long as the host runs.
pub fn lock(store: &Store) -> Result<File> {
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(store.path(LOCK)?)?;
    rustix::fs::flock(&f, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(|_| {
        Error::Host(format!(
            "another host holds {}: is `hitch watch` running for it?",
            store.dir().display()
        ))
    })?;
    Ok(f)
}

/// Send a command to the `watch` daemon of `state`, if one is running.
/// `Ok(None)` means none is: the caller runs the command itself.
pub async fn forward(state: &Path, command: &Command) -> Result<Option<Value>> {
    let stream = match UnixStream::connect(state.join(CONTROL)).await {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let (read, mut write) = stream.into_split();
    let mut line = serde_json::to_vec(command)?;
    line.push(b'\n');
    write.write_all(&line).await?;
    write.shutdown().await?;
    let mut answer = String::new();
    BufReader::new(read).read_line(&mut answer).await?;
    let v: Value = serde_json::from_str(answer.trim())
        .map_err(|e| Error::Host(format!("the daemon's answer does not parse: {e}")))?;
    if v["ok"] == json!(true) {
        Ok(Some(v["result"].clone()))
    } else {
        Err(Error::Host(
            v["error"]
                .as_str()
                .unwrap_or("the daemon refused")
                .to_string(),
        ))
    }
}

/// Bind the daemon's command socket (`0600`). Call with the lock held: a
/// socket file left by a dead daemon is removed first.
pub fn bind_control(store: &Store) -> Result<UnixListener> {
    let path = store.path(CONTROL)?;
    let _ = std::fs::remove_file(&path);
    let l = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

async fn accept_commands(
    listener: UnixListener,
    tx: mpsc::Sender<(Command, oneshot::Sender<Reply>)>,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let tx = tx.clone();
        tokio::spawn(async move {
            let (read, mut write) = stream.into_split();
            let mut line = String::new();
            if BufReader::new(read).read_line(&mut line).await.is_err() {
                return;
            }
            let answer = match serde_json::from_str::<Command>(line.trim()) {
                Err(e) => json!({"ok": false, "error": format!("not a command: {e}")}),
                Ok(command) => {
                    let (reply, rx) = oneshot::channel();
                    if tx.send((command, reply)).await.is_err() {
                        json!({"ok": false, "error": "the host is stopping"})
                    } else {
                        match rx.await {
                            Ok(Ok(v)) => json!({"ok": true, "result": v}),
                            Ok(Err(e)) => json!({"ok": false, "error": e}),
                            Err(_) => json!({"ok": false, "error": "the host stopped"}),
                        }
                    }
                }
            };
            let mut out = serde_json::to_vec(&answer).unwrap_or_default();
            out.push(b'\n');
            let _ = write.write_all(&out).await;
            let _ = write.shutdown().await;
        });
    }
}

impl Host {
    /// Open the state, check the spend key against the binding (ADR-2101
    /// D3: the identity key is refused), and restore every channel, handshake
    /// and invoice. Nothing is sent and the chain is not read yet.
    pub fn load(cfg: HostConfig, key: AgentKey) -> Result<Self> {
        let store = Store::open(&cfg.state)?;
        let binding = match store.read(BINDING)? {
            Some(bytes) => {
                let ev: Event = serde_json::from_slice(&bytes)?;
                verify_binding(&ev, &cfg.doc.id, cfg.doc.genesis_hash.as_deref())?
            }
            None => {
                return Err(Error::Binding(format!(
                "{} holds no binding: run `sidestr-agent hitch bind --identity-file <k_id>` first",
                store.dir().display()
            )))
            }
        };
        binding.check_spender(&key)?;
        let me = key.pubkey();
        let rules = rules_for(cfg.doc.family()?);
        let follower = ChainFollower::new(&cfg.doc)?;
        let mut host = Self {
            accept_keys: cfg.accept.keys.iter().copied().collect(),
            cfg,
            key,
            me,
            store,
            binding,
            rules,
            follower,
            chain_ok_at: None,
            chain_error: None,
            alerts: Vec::new(),
            channels: BTreeMap::new(),
            openings: BTreeMap::new(),
            invoices: BTreeMap::new(),
            router: Router::new(false, 0),
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
            waiters: Vec::new(),
            retries: Vec::new(),
            repairs: BTreeMap::new(),
            sent: HashSet::new(),
            funding_sent: BTreeMap::new(),
            dids_at: None,
            mirror_at: None,
            last_status: String::new(),
            polls: 0,
        };
        for name in host.store.list(CHANNELS)? {
            let rel = format!("{CHANNELS}/{name}");
            let text = String::from_utf8(host.store.read(&rel)?.unwrap_or_default())
                .map_err(|_| Error::Host(format!("{rel} is not UTF-8")))?;
            let file: ChannelFile = serde_json::from_str(&text)?;
            let m = ChannelMachine::restore(file.snapshot.clone())?;
            if m.channel().key(m.role()) != me {
                return Err(Error::Host(format!(
                    "{rel} belongs to another key: this state directory is not this spend key's"
                )));
            }
            host.channels.insert(
                m.id(),
                Live {
                    m,
                    file,
                    saved: text,
                },
            );
        }
        for name in host.store.list(OPENINGS)? {
            let rel = format!("{OPENINGS}/{name}");
            let file: OpeningFile =
                serde_json::from_slice(&host.store.read(&rel)?.unwrap_or_default())?;
            let (id, state) = host.rebuild_opening(&file)?;
            host.openings.insert(
                id,
                Opening {
                    file,
                    state,
                    sent_at: 0,
                },
            );
        }
        for name in host.store.list(INVOICES)? {
            let rel = format!("{INVOICES}/{name}");
            let file: InvoiceFile =
                serde_json::from_slice(&host.store.read(&rel)?.unwrap_or_default())?;
            host.invoices.insert(file.invoice.h.0, file);
        }
        Ok(host)
    }

    /// The spend key's x-only public key: this host's node id.
    pub fn node_id(&self) -> XOnlyPublicKey {
        self.me
    }

    /// The binding this host runs under.
    pub fn binding(&self) -> &SpendBinding {
        &self.binding
    }

    /// Run as the `watch` daemon until interrupted: commands arrive on the
    /// control socket.
    pub async fn serve(self, listener: UnixListener) -> Result<()> {
        self.run(Some(listener), None).await.map(|_| ())
    }

    /// Run one command (waiting as it asks), then return its answer.
    pub async fn run_command(self, command: Command) -> Result<Value> {
        let (tx, rx) = oneshot::channel();
        self.run(None, Some((command, tx))).await?;
        match rx.await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(Error::Host(e)),
            Err(_) => Err(Error::Host("the command was dropped".into())),
        }
    }

    async fn run(
        mut self,
        listener: Option<UnixListener>,
        first: Option<(Command, oneshot::Sender<Reply>)>,
    ) -> Result<()> {
        let daemon = listener.is_some();
        let mut inbox = follow(
            self.cfg.relays.clone(),
            vec![KIND_HITCH_MESSAGE],
            RELAY_SINCE,
            |s| eprintln!("{} hitch: {s}", unix_now()),
        );
        let (req_tx, mut req_rx) = mpsc::channel(16);
        if let Some(l) = listener {
            tokio::spawn(accept_commands(l, req_tx.clone()));
        }
        self.journal(json!({"ev": "start", "me": self.me.to_string(), "identity": self.binding.identity, "chain": self.cfg.doc.id, "daemon": daemon}));
        self.step().await;
        if let Some((command, reply)) = first {
            self.submit(command, reply).await;
        }
        let mut tick = tokio::time::interval(self.cfg.poll);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            if !daemon && self.waiters.is_empty() && self.retries.is_empty() {
                break;
            }
            tokio::select! {
                got = inbox.recv() => match got {
                    Some((_, ev)) => self.on_event(ev).await,
                    None => tokio::time::sleep(self.cfg.poll).await,
                },
                Some((command, reply)) = req_rx.recv() => self.submit(command, reply).await,
                _ = tick.tick() => self.step().await,
                _ = tokio::signal::ctrl_c(), if daemon => break,
            }
            // the view is on disk before any answer leaves, so a caller that
            // reads `hitch status` after its command sees what it waited for
            self.write_status();
            self.check_waiters();
        }
        self.write_status();
        self.journal(json!({"ev": "stop"}));
        if daemon {
            let _ = self.store.remove(CONTROL);
        }
        Ok(())
    }

    // ---- bookkeeping

    fn journal(&self, mut entry: Value) {
        entry["at"] = json!(unix_now());
        if let Some(h) = self.follower.height() {
            entry["height"] = json!(h);
        }
        if let Err(e) = self.store.journal(&entry) {
            eprintln!("hitch: the journal could not be written: {e}");
        }
    }

    fn alert(&mut self, text: String) {
        eprintln!("hitch ALERT: {text}");
        self.journal(json!({"ev": "alert", "text": text}));
        self.alerts.push(text);
        if self.alerts.len() > 32 {
            self.alerts.remove(0);
        }
    }

    fn stale(&self) -> bool {
        self.chain_ok_at
            .is_none_or(|t| t.elapsed() > self.cfg.stale_after)
    }

    fn ctx(&self) -> Result<Context> {
        Ok(Context {
            height: self.follower.height().unwrap_or(0),
            now: unix_now(),
            aux: random32()?,
            stale: self.stale(),
        })
    }

    /// Save a channel's snapshot if it changed. On failure the channel goes
    /// back to its last saved state, so the caller sends nothing.
    fn save(&mut self, id: ChannelId) -> Result<()> {
        let Some(live) = self.channels.get_mut(&id) else {
            return Ok(());
        };
        live.file.snapshot = live.m.snapshot();
        let text = serde_json::to_string_pretty(&live.file)?;
        if text == live.saved {
            return Ok(());
        }
        match self.store.write(&channel_path(id), text.as_bytes()) {
            Ok(()) => {
                live.saved = text;
                Ok(())
            }
            Err(e) => {
                let back = serde_json::from_str::<ChannelFile>(&live.saved)
                    .ok()
                    .and_then(|f| {
                        ChannelMachine::restore(f.snapshot.clone())
                            .ok()
                            .map(|m| (f, m))
                    });
                match back {
                    Some((f, m)) => {
                        live.file = f;
                        live.m = m;
                    }
                    None => {
                        self.channels.remove(&id);
                    }
                }
                Err(e)
            }
        }
    }

    fn save_opening(&self, id: ChannelId, file: &OpeningFile) -> Result<()> {
        self.store.write(
            &opening_path(id),
            serde_json::to_string_pretty(file)?.as_bytes(),
        )
    }

    fn rebuild_opening(&self, file: &OpeningFile) -> Result<(ChannelId, OpeningState)> {
        let peer: XOnlyPublicKey = file
            .peer
            .parse()
            .map_err(|_| Error::Host("an opening names a bad peer".into()))?;
        let keys = OpeningKeys {
            channel: self.key.secret_key(),
            revocation_base: secret_from(&file.revocation_base)?,
            revocation: [
                secret_from(&file.revocation[0])?,
                secret_from(&file.revocation[1])?,
            ],
        };
        let aux = bytes32(&file.aux)?;
        match file.role {
            OpeningRole::Funder => {
                let f = file
                    .funder
                    .as_ref()
                    .ok_or_else(|| Error::Host("a funder's opening without its half".into()))?;
                let params = OpenParams {
                    funding: f
                        .funding
                        .parse()
                        .map_err(|_| Error::Host("a bad funding outpoint".into()))?,
                    funding_value: Amount::from_sat(f.funding_value),
                    push: Amount::from_sat(f.push),
                    delay: f.delay,
                    fee: Amount::from_sat(f.fee),
                    hub_fee: None,
                };
                let (fo, _) = FunderOpening::propose(params, keys, peer, self.rules, &aux)?;
                let id = fo.id();
                match &f.accept {
                    Some(a) => {
                        let (accepted, _) = fo.accept(a.clone(), &aux)?;
                        Ok((id, OpeningState::Accepted(Box::new(accepted))))
                    }
                    None => Ok((id, OpeningState::Proposed(Box::new(fo)))),
                }
            }
            OpeningRole::Receiver => {
                let r = file
                    .receiver
                    .as_ref()
                    .ok_or_else(|| Error::Host("a receiver's opening without its half".into()))?;
                let policy = AcceptPolicy {
                    min_delay: r.min_delay,
                    hub_fee: None,
                };
                let (ro, _) =
                    ReceiverOpening::accept(r.open.clone(), peer, keys, self.rules, policy, &aux)?;
                Ok((ro.id(), OpeningState::Receiver(Box::new(ro))))
            }
        }
    }

    // ---- sending

    async fn send(&self, peer: XOnlyPublicKey, msg: &PeerMessage) {
        let ev = match message_event(&self.key, &self.cfg.doc.id, &peer, msg, unix_now()) {
            Ok(ev) => ev,
            Err(e) => {
                self.journal(json!({"ev": "send-failed", "error": e.to_string()}));
                return;
            }
        };
        let res = publish_all(&self.cfg.relays, &ev, Duration::from_secs(8)).await;
        self.journal(json!({
            "ev": "sent", "t": kind_of(msg), "ch": msg.channel().to_hex(),
            "to": peer.to_string(), "event": ev.id, "relaysOk": ok_count(&res),
        }));
    }

    /// The outputs `tx` spends, from the channels' funding outputs and the
    /// followed chain; `None` if one is unknown.
    fn prevouts(&self, tx: &Transaction) -> Option<Vec<TxOut>> {
        tx.input
            .iter()
            .map(|i| {
                let op = i.previous_output;
                self.channels
                    .values()
                    .find(|l| l.m.channel().funding_outpoint == op)
                    .map(|l| l.m.channel().funding_prevout())
                    .or_else(|| {
                        self.follower
                            .find_tx(&op.txid)
                            .and_then(|(_, t)| t.output.get(op.vout as usize).cloned())
                    })
            })
            .collect()
    }

    /// `tx` signed again with fresh randomness: the same txid, another
    /// witness. A channel's own transactions are re-signed by the kernel
    /// ([`ChannelMachine::resign`]); a wallet spend of the spend key's own
    /// coins (a funding) is re-signed on the key path. `None` if this host
    /// cannot sign it.
    fn fresh_bytes(&self, tx: &Transaction) -> Option<Transaction> {
        let prevouts = self.prevouts(tx)?;
        let aux = random32().ok()?;
        let txid = tx.compute_txid();
        let owner = self.channels.values().find(|l| {
            tx.input[0].previous_output == l.m.channel().funding_outpoint
                || l.m.claims().iter().any(|c| c.txid == txid)
        });
        if let Some(l) = owner {
            return l.m.resign(tx, &prevouts, &aux).ok();
        }
        let mine = self.key.script();
        if prevouts.iter().any(|p| p.script_pubkey != mine) {
            return None;
        }
        let keypair = Keypair::from_secret_key(secp(), &self.key.secret_key());
        let mut out = tx.clone();
        for i in 0..tx.input.len() {
            let (msg, hash_type) = key_path_sighash(tx, i, &prevouts, self.rules).ok()?;
            let aux = random32().ok()?;
            let sig = secp().sign_schnorr_with_aux_rand(&Message::from_digest(msg), &keypair, &aux);
            let mut wire = sig.as_ref().to_vec();
            wire.push(hash_type);
            out.input[i].witness = Witness::from_slice(&[wire]);
        }
        Some(out)
    }

    /// Broadcast, under both of the producer's constraints. A transaction
    /// whose lock is not yet satisfied is held back ([`premature`]) and sent
    /// by the repair loop when it may be. What is sent is signed afresh
    /// ([`Self::fresh_bytes`]), so bytes a producer refused or evicted are
    /// never sent again; if it cannot be signed afresh, the same bytes are
    /// sent once and never repeated.
    async fn broadcast(&mut self, label: &str, tx: &Transaction) {
        let txid = tx.compute_txid();
        let next = self.follower.height().map_or(0, |h| h + 1);
        if let Some(why) = premature(tx, next, |t| self.follower.find_tx(t).map(|(h, _)| h)) {
            self.journal(
                json!({"ev": "deferred", "label": label, "txid": txid.to_string(), "why": why}),
            );
            self.repairs.entry(txid).or_insert(Repair {
                tx: tx.clone(),
                label: label.to_string(),
                tried_at: None,
            });
            return;
        }
        let tx = match self.fresh_bytes(tx) {
            Some(t) => t,
            None if !self.sent.contains(&tx.compute_wtxid()) => tx.clone(),
            None => {
                self.journal(json!({"ev": "not-resent", "label": label, "txid": txid.to_string(), "why": "these bytes were sent before and cannot be signed again"}));
                return;
            }
        };
        let tx = &tx;
        self.sent.insert(tx.compute_wtxid());
        let hex = serialize_hex(tx);
        let url = self.cfg.url.clone();
        let posted = {
            let hex = hex.clone();
            tokio::task::spawn_blocking(move || client::post_tx(&url, &hex)).await
        };
        let mut entry = json!({"ev": "broadcast", "label": label, "txid": txid.to_string(), "wtxid": tx.compute_wtxid().to_string()});
        match posted {
            Ok(Ok(a)) => {
                entry["via"] = json!("post");
                entry["dup"] = json!(a.dup.unwrap_or(false));
            }
            Ok(Err(sidestr_wallet::Error::Refused(why))) => {
                entry["via"] = json!("post");
                entry["refused"] = json!(why);
            }
            other => {
                let why = match other {
                    Ok(Err(e)) => e.to_string(),
                    Err(e) => e.to_string(),
                    Ok(Ok(_)) => unreachable!(),
                };
                entry["postError"] = json!(why);
                match sign_transaction_event(
                    &self.key.event_signer(),
                    &self.cfg.doc.id,
                    &hex,
                    unix_now(),
                ) {
                    Ok(ev) => {
                        let res = publish_all(&self.cfg.relays, &ev, Duration::from_secs(8)).await;
                        entry["via"] = json!("relay");
                        entry["event"] = json!(ev.id);
                        entry["relaysOk"] = json!(ok_count(&res));
                    }
                    Err(e) => entry["eventError"] = json!(e.to_string()),
                }
            }
        }
        self.journal(entry);
    }

    async fn send_all(&mut self, id: ChannelId, msgs: Vec<PeerMessage>, txs: Vec<Broadcast>) {
        let Some(peer) = self.channels.get(&id).map(|l| l.m.peer()) else {
            return;
        };
        for m in &msgs {
            self.send(peer, m).await;
        }
        for b in &txs {
            self.broadcast(&b.label, &b.tx).await;
        }
        self.drain_events(id);
    }

    fn drain_events(&mut self, id: ChannelId) {
        let Some(live) = self.channels.get_mut(&id) else {
            return;
        };
        let events = live.m.drain_events();
        for e in events {
            let entry = match &e {
                ChannelEvent::Dropped(d) => {
                    json!({"ev": "dropped", "ch": id.to_hex(), "update": d.update.label(), "reason": d.reason})
                }
                ChannelEvent::Preimage { hash, .. } => {
                    json!({"ev": "preimage-from-chain", "ch": id.to_hex(), "hash": hex::encode(hash.0)})
                }
                ChannelEvent::Payment {
                    hash,
                    outcome,
                    reason,
                } => {
                    let outcome = match outcome {
                        PaymentOutcome::InFlight => "in-flight",
                        PaymentOutcome::Sent => "sent",
                        PaymentOutcome::Failed => "failed",
                        PaymentOutcome::NotMade => "not-made",
                    };
                    let done = matches!(outcome, "sent" | "failed" | "not-made");
                    if done {
                        let mut i = 0;
                        while i < self.waiters.len() {
                            if matches!(self.waiters[i].goal, Goal::Htlc(h) if h == *hash) {
                                let w = self.waiters.swap_remove(i);
                                let mut v = w.started;
                                v["outcome"] = json!(outcome);
                                v["reason"] = json!(reason);
                                let _ = w.reply.send(if outcome == "sent" {
                                    Ok(v)
                                } else {
                                    Err(format!(
                                        "the payment {outcome}: {}",
                                        reason.clone().unwrap_or_default()
                                    ))
                                });
                            } else {
                                i += 1;
                            }
                        }
                    }
                    json!({"ev": "payment", "ch": id.to_hex(), "hash": hex::encode(hash.0), "outcome": outcome, "reason": reason})
                }
            };
            self.journal(entry);
        }
    }

    // ---- inbound

    async fn on_event(&mut self, ev: Event) {
        if !self.seen.insert(ev.id.clone()) {
            return;
        }
        self.seen_order.push_back(ev.id.clone());
        if self.seen_order.len() > 10_000 {
            if let Some(old) = self.seen_order.pop_front() {
                self.seen.remove(&old);
            }
        }
        match read_message(&ev, &self.me, &self.cfg.doc.id) {
            Ok(Some(inbound)) => {
                self.journal(json!({
                    "ev": "received", "t": kind_of(&inbound.message), "ch": inbound.message.channel().to_hex(),
                    "from": inbound.sender.to_string(), "event": inbound.event_id,
                }));
                self.on_message(inbound).await;
            }
            Ok(None) => {}
            Err(e) => {
                self.journal(json!({"ev": "refused-event", "event": ev.id, "error": e.to_string()}))
            }
        }
    }

    async fn on_message(&mut self, inbound: Inbound) {
        let Inbound {
            sender, message, ..
        } = inbound;
        let id = message.channel();
        // a channel message from anyone but the channel's peer is dropped
        if let Some(live) = self.channels.get(&id) {
            if live.m.peer() != sender {
                self.journal(
                    json!({"ev": "wrong-sender", "ch": id.to_hex(), "from": sender.to_string()}),
                );
                return;
            }
        } else if let Some(op) = self.openings.get(&id) {
            if op.file.peer != sender.to_string() {
                self.journal(
                    json!({"ev": "wrong-sender", "ch": id.to_hex(), "from": sender.to_string()}),
                );
                return;
            }
        }
        let outcome = match message {
            PeerMessage::Open(m) => self.on_open(sender, m).await,
            PeerMessage::Accept(m) => self.on_accept(id, m).await,
            PeerMessage::Commit(m) => self.on_commit(id, m).await,
            PeerMessage::Ready(m) => self.on_ready(id, m).await,
            PeerMessage::Sync(m) => self.on_sync(id, m).await,
            PeerMessage::Update(m) => self.on_update(id, m).await,
            PeerMessage::Revoke(m) => self.on_revoke(id, m).await,
            PeerMessage::Ack(m) => {
                self.channel_call(id, move |c, _| {
                    let o = c.receive_ack(m)?;
                    Ok((vec![o.revoke.into()], vec![]))
                })
                .await
            }
            PeerMessage::Reject(m) => {
                self.channel_call(id, move |c, ctx| {
                    let sync = c.receive_reject(m, ctx)?;
                    Ok((sync.map(PeerMessage::from).into_iter().collect(), vec![]))
                })
                .await
            }
            PeerMessage::Close(m) => {
                self.channel_call(id, move |c, ctx| {
                    Ok((vec![], vec![c.receive_close(m, ctx)?]))
                })
                .await
            }
        };
        if let Err(e) = outcome {
            self.journal(json!({"ev": "refused", "ch": id.to_hex(), "error": e.to_string()}));
            // Hitch's recovery: a resync, at most every 30 seconds
            let sync = match (self.ctx(), self.channels.get_mut(&id)) {
                (Ok(ctx), Some(live)) => live.m.resync(&ctx, false),
                _ => None,
            };
            if let Some(sync) = sync {
                if self.save(id).is_ok() {
                    self.send_all(id, vec![sync.into()], vec![]).await;
                }
            }
        }
    }

    /// Call the kernel on one channel, save, then send what it returned.
    async fn channel_call(
        &mut self,
        id: ChannelId,
        f: impl FnOnce(
            &mut ChannelMachine,
            &Context,
        ) -> std::result::Result<
            (Vec<PeerMessage>, Vec<Broadcast>),
            sidestr_hitch::protocol::ProtocolError,
        >,
    ) -> Result<()> {
        let ctx = self.ctx()?;
        let live = self
            .channels
            .get_mut(&id)
            .ok_or_else(|| Error::Host(format!("no channel {id} here")))?;
        let (msgs, txs) = f(&mut live.m, &ctx)?;
        self.save(id)?;
        self.send_all(id, msgs, txs).await;
        Ok(())
    }

    async fn accepts(&mut self, sender: XOnlyPublicKey) -> bool {
        if self.cfg.accept.any || self.accept_keys.contains(&sender) {
            return true;
        }
        if self.cfg.accept.dids.is_empty()
            || self
                .dids_at
                .is_some_and(|t| t.elapsed() < Duration::from_secs(10))
        {
            return false;
        }
        self.dids_at = Some(Instant::now());
        for did in self.cfg.accept.dids.clone() {
            if let Ok(spend) = self.resolve_did(&did).await {
                self.accept_keys.insert(spend);
            }
        }
        self.accept_keys.contains(&sender)
    }

    /// The spend key a `did:nostr` bound on this chain (kind 38420, signed by
    /// the identity), from the relays.
    async fn resolve_did(&self, did: &XOnlyPublicKey) -> Result<XOnlyPublicKey> {
        // by author and kind: the `d` key is the chain hash, which the host
        // may not know; verification then holds the alias and genesis
        let filter = Filter {
            kinds: vec![KIND_ACCOUNT_BINDING],
            authors: vec![did.to_string()],
            ..Default::default()
        };
        let events = fetch(&self.cfg.relays, filter, Duration::from_secs(6)).await;
        let b = newest_binding(
            &events,
            did,
            &self.cfg.doc.id,
            self.cfg.doc.genesis_hash.as_deref(),
        )
        .ok_or_else(|| {
            Error::Binding(format!(
                "did:nostr:{did} has published no binding on {}",
                self.cfg.doc.id
            ))
        })?;
        self.journal(json!({"ev": "binding-resolved", "did": did.to_string(), "spend": b.spend, "event": b.event.id}));
        Ok(b.spend_key())
    }

    async fn resolve_peer(&self, text: &str) -> Result<XOnlyPublicKey> {
        let t = text.trim();
        if t.to_ascii_lowercase().starts_with("did:nostr:") {
            return self.resolve_did(&parse_pubkey(t)?).await;
        }
        Ok(parse_pubkey(t)?)
    }

    async fn on_open(&mut self, sender: XOnlyPublicKey, open: OpenMessage) -> Result<()> {
        let id = open.id;
        if self.channels.contains_key(&id) {
            return Ok(());
        }
        if let Some(Opening {
            state: OpeningState::Receiver(ro),
            ..
        }) = self.openings.get(&id)
        {
            let again = PeerMessage::Accept(ro.message().clone());
            self.send(sender, &again).await;
            return Ok(());
        }
        if !self.accepts(sender).await {
            return Err(Error::Host(format!(
                "an open from {sender}, who is not accepted here"
            )));
        }
        if let Some(max) = self.cfg.accept.max_amount {
            if open.funding.value > max {
                return Err(Error::Host(format!(
                    "an open of {} sats, above the {max} accepted",
                    open.funding.value
                )));
            }
        }
        let (rb, r0, r1, aux) = (
            fresh_secret()?,
            fresh_secret()?,
            fresh_secret()?,
            random32()?,
        );
        let keys = OpeningKeys {
            channel: self.key.secret_key(),
            revocation_base: rb,
            revocation: [r0, r1],
        };
        let policy = AcceptPolicy {
            min_delay: self.cfg.accept.min_delay,
            hub_fee: None,
        };
        let (ro, accept) =
            ReceiverOpening::accept(open.clone(), sender, keys, self.rules, policy, &aux)?;
        let file = OpeningFile {
            version: FILE_VERSION,
            role: OpeningRole::Receiver,
            chain: self.cfg.doc.id.clone(),
            peer: sender.to_string(),
            revocation_base: secret_hex(&rb),
            revocation: [secret_hex(&r0), secret_hex(&r1)],
            aux: hex::encode(aux),
            created_at: unix_now(),
            funder: None,
            receiver: Some(ReceiverPart {
                open,
                min_delay: policy.min_delay,
            }),
        };
        self.save_opening(id, &file)?;
        self.openings.insert(
            id,
            Opening {
                file,
                state: OpeningState::Receiver(Box::new(ro)),
                sent_at: unix_now(),
            },
        );
        self.send(sender, &PeerMessage::Accept(accept)).await;
        Ok(())
    }

    async fn on_accept(&mut self, id: ChannelId, accept: AcceptMessage) -> Result<()> {
        let Some(op) = self.openings.get_mut(&id) else {
            return Ok(());
        };
        let peer: XOnlyPublicKey = op
            .file
            .peer
            .parse()
            .map_err(|_| Error::Host("bad peer".into()))?;
        let commit = match &op.state {
            OpeningState::Accepted(acc) => acc.commit_message().clone(),
            OpeningState::Receiver(_) => return Ok(()),
            OpeningState::Proposed(fo) => {
                let aux = bytes32(&op.file.aux)?;
                let (accepted, commit) = fo.accept(accept.clone(), &aux)?;
                if let Some(f) = op.file.funder.as_mut() {
                    f.accept = Some(accept);
                }
                op.state = OpeningState::Accepted(Box::new(accepted));
                op.sent_at = unix_now();
                let file = op.file.clone();
                self.save_opening(id, &file)?;
                commit
            }
        };
        self.send(peer, &PeerMessage::Commit(commit)).await;
        Ok(())
    }

    async fn on_commit(
        &mut self,
        id: ChannelId,
        commit: sidestr_hitch::protocol::CommitMessage,
    ) -> Result<()> {
        if let Some(live) = self.channels.get(&id) {
            if live.m.role() == Side::B {
                let peer = live.m.peer();
                let ready = PeerMessage::Ready(ReadyMessage {
                    t: ReadyTag::Ready,
                    id,
                });
                self.send(peer, &ready).await;
            }
            return Ok(());
        }
        let Some(Opening {
            state: OpeningState::Receiver(ro),
            file,
            ..
        }) = self.openings.get(&id)
        else {
            return Ok(());
        };
        let (m, ready) = ro.commit(commit)?;
        let peer = m.peer();
        let cf = ChannelFile {
            version: FILE_VERSION,
            chain: file.chain.clone(),
            peer: peer.to_string(),
            snapshot: m.snapshot(),
            funding_tx: None,
            opened_at: unix_now(),
            bad_funding: None,
        };
        self.channels.insert(
            id,
            Live {
                m,
                file: cf,
                saved: String::new(),
            },
        );
        self.save(id)?;
        self.openings.remove(&id);
        self.store.remove(&opening_path(id))?;
        self.journal(
            json!({"ev": "channel", "ch": id.to_hex(), "role": "b", "peer": peer.to_string()}),
        );
        self.send(peer, &PeerMessage::Ready(ready)).await;
        Ok(())
    }

    async fn on_ready(&mut self, id: ChannelId, ready: ReadyMessage) -> Result<()> {
        if self.channels.contains_key(&id) {
            return Ok(());
        }
        let Some(Opening {
            state: OpeningState::Accepted(acc),
            ..
        }) = self.openings.get(&id)
        else {
            return Ok(());
        };
        let m = acc.ready(ready)?;
        self.adopt_funded(id, m).await
    }

    /// The funder's channel exists: save it, drop the handshake, then
    /// broadcast the funding.
    async fn adopt_funded(&mut self, id: ChannelId, m: ChannelMachine) -> Result<()> {
        let Some(op) = self.openings.get(&id) else {
            return Ok(());
        };
        let funding_tx = op.file.funder.as_ref().map(|f| f.funding_tx.clone());
        let peer = m.peer();
        let cf = ChannelFile {
            version: FILE_VERSION,
            chain: op.file.chain.clone(),
            peer: peer.to_string(),
            snapshot: m.snapshot(),
            funding_tx: funding_tx.clone(),
            opened_at: unix_now(),
            bad_funding: None,
        };
        self.channels.insert(
            id,
            Live {
                m,
                file: cf,
                saved: String::new(),
            },
        );
        self.save(id)?;
        self.openings.remove(&id);
        self.store.remove(&opening_path(id))?;
        self.journal(
            json!({"ev": "channel", "ch": id.to_hex(), "role": "a", "peer": peer.to_string()}),
        );
        if let Some(hex) = funding_tx {
            let tx: Transaction = bitcoin::consensus::encode::deserialize_hex(&hex)
                .map_err(|e| Error::Host(format!("the stored funding does not decode: {e}")))?;
            self.funding_sent
                .insert(id, self.follower.height().unwrap_or(0));
            self.broadcast("funding", &tx).await;
        }
        Ok(())
    }

    /// A funding of this host's still in no block is sent again (signed
    /// afresh) every [`FUNDING_RESEND`] blocks: a producer may have refused
    /// or lost it.
    async fn resend_funding(&mut self, id: ChannelId) {
        let Some(height) = self.follower.height() else {
            return;
        };
        let due = self.channels.get(&id).and_then(|l| {
            let hex = l.file.funding_tx.as_ref()?;
            let waiting = l.m.status() == ChannelStatus::Funding
                && l.file.bad_funding.is_none()
                && self
                    .follower
                    .find_tx(&l.m.channel().funding_outpoint.txid)
                    .is_none();
            waiting.then(|| hex.clone())
        });
        let Some(hex) = due else {
            return;
        };
        if self
            .funding_sent
            .get(&id)
            .is_some_and(|at| height.saturating_sub(*at) < FUNDING_RESEND)
        {
            return;
        }
        let Ok(tx) = bitcoin::consensus::encode::deserialize_hex::<Transaction>(&hex) else {
            return;
        };
        self.funding_sent.insert(id, height);
        self.broadcast("funding (again, still in no block)", &tx)
            .await;
    }

    async fn on_sync(
        &mut self,
        id: ChannelId,
        sync: sidestr_hitch::protocol::SyncMessage,
    ) -> Result<()> {
        if self.channels.contains_key(&id) {
            let mut finalised = None;
            self.channel_call(id, |c, ctx| {
                let o = c.receive_sync(&sync, ctx)?;
                finalised = o.finalised;
                Ok((o.replies, vec![]))
            })
            .await?;
            if let Some(f) = finalised {
                self.on_finalised(id, f).await;
            }
            return Ok(());
        }
        let Some(op) = self.openings.get(&id) else {
            return Ok(());
        };
        let peer: XOnlyPublicKey = op
            .file
            .peer
            .parse()
            .map_err(|_| Error::Host("bad peer".into()))?;
        match &op.state {
            OpeningState::Accepted(acc) => match acc.receive_sync(&sync)? {
                FunderSync::ResendCommit(c) => self.send(peer, &PeerMessage::Commit(c)).await,
                FunderSync::Ready(m) => return self.adopt_funded(id, *m).await,
                FunderSync::Waiting => {}
            },
            OpeningState::Proposed(fo) => {
                let open = PeerMessage::Open(fo.message().clone());
                self.send(peer, &open).await;
            }
            OpeningState::Receiver(ro) => {
                let accept = PeerMessage::Accept(ro.message().clone());
                self.send(peer, &accept).await;
            }
        }
        Ok(())
    }

    async fn on_update(
        &mut self,
        id: ChannelId,
        update: sidestr_hitch::protocol::UpdateMessage,
    ) -> Result<()> {
        let secret = fresh_secret()?;
        self.channel_call(id, move |c, ctx| {
            let msg = match c.receive_update(update, secret, ctx)? {
                ReceiveUpdate::Acknowledge(a) | ReceiveUpdate::ResendAcknowledgement(a) => {
                    Some(PeerMessage::Ack(a))
                }
                ReceiveUpdate::Rejected(r) | ReceiveUpdate::LocalProposalWins(r) => {
                    Some(PeerMessage::Reject(r))
                }
                ReceiveUpdate::Buffered => None,
            };
            Ok((msg.into_iter().collect(), vec![]))
        })
        .await
    }

    async fn on_revoke(
        &mut self,
        id: ChannelId,
        revoke: sidestr_hitch::protocol::RevokeMessage,
    ) -> Result<()> {
        let mut finalised = None;
        self.channel_call(id, |c, _| {
            finalised = c.receive_revoke(revoke)?;
            Ok((vec![], vec![]))
        })
        .await?;
        if let Some(f) = finalised {
            self.on_finalised(id, f).await;
        }
        // an update held while that state waited for its revocation
        loop {
            let next = self
                .channels
                .get_mut(&id)
                .and_then(|l| l.m.take_buffered_update());
            let Some(u) = next else { break };
            if let Err(e) = self.on_update(id, u).await {
                self.journal(json!({"ev": "refused", "ch": id.to_hex(), "error": e.to_string()}));
                break;
            }
        }
        Ok(())
    }

    /// An update of the other side's is final: the router settles an HTLC
    /// paying one of this host's invoices (unless the developer hold is on).
    async fn on_finalised(&mut self, id: ChannelId, f: FinalisedUpdate) {
        self.journal(json!({"ev": "final", "ch": id.to_hex(), "n": f.n, "by": role_name(f.sender), "update": serde_json::to_value(&f.update).unwrap_or_default()}));
        if self.cfg.hold_htlcs {
            return;
        }
        let height = self.follower.height().unwrap_or(0);
        let actions = {
            let refs: Vec<&ChannelMachine> = self.channels.values().map(|l| &l.m).collect();
            let invoices = &self.invoices;
            self.router.on_update(
                &refs,
                id,
                &f,
                |h| invoices.get(&h.0).map(|i| i.record),
                height,
            )
        };
        self.route(actions).await;
    }

    async fn route(&mut self, actions: Vec<RouteAction>) {
        for a in actions {
            let (id, result) = match a {
                RouteAction::Settle {
                    channel,
                    htlc_id,
                    preimage,
                    invoice,
                    ..
                } => {
                    let r = match fresh_secret() {
                        Ok(secret) => {
                            self.channel_call(channel, move |c, ctx| {
                                Ok((
                                    vec![c.settle_htlc(htlc_id, preimage, secret, ctx)?.into()],
                                    vec![],
                                ))
                            })
                            .await
                        }
                        Err(e) => Err(e),
                    };
                    if r.is_ok() {
                        if let Some(h) = invoice {
                            if let Some(inv) = self.invoices.get_mut(&h.0) {
                                inv.record.paid = true;
                                let text = serde_json::to_string_pretty(&*inv).unwrap_or_default();
                                let _ = self.store.write(&invoice_path(&h.0), text.as_bytes());
                            }
                        }
                    }
                    (channel, r)
                }
                RouteAction::Fail {
                    channel,
                    htlc_id,
                    reason,
                    ..
                } => {
                    let r = match fresh_secret() {
                        Ok(secret) => {
                            self.channel_call(channel, move |c, ctx| {
                                Ok((
                                    vec![c.fail_htlc(htlc_id, Some(&reason), secret, ctx)?.into()],
                                    vec![],
                                ))
                            })
                            .await
                        }
                        Err(e) => Err(e),
                    };
                    (channel, r)
                }
                RouteAction::ForceClose { channel, reason } => {
                    self.journal(
                        json!({"ev": "protective-close", "ch": channel.to_hex(), "reason": reason}),
                    );
                    let r = self
                        .channel_call(channel, |c, ctx| {
                            Ok((vec![], vec![c.force_close(None, "protective", ctx)?]))
                        })
                        .await;
                    (channel, r)
                }
                RouteAction::Forward { channel, .. } => (channel, Ok(())),
            };
            if let Err(e) = result {
                self.journal(
                    json!({"ev": "route-failed", "ch": id.to_hex(), "error": e.to_string()}),
                );
            }
        }
    }

    // ---- commands

    async fn submit(&mut self, command: Command, reply: oneshot::Sender<Reply>) {
        self.submit_try(command, reply, 0).await;
    }

    async fn submit_try(&mut self, command: Command, reply: oneshot::Sender<Reply>, tries: u32) {
        self.journal(json!({"ev": "command", "request": serde_json::to_value(&command.request).unwrap_or_default(), "try": tries}));
        match self.execute(&command.request).await {
            Ok((started, goal)) => match (command.wait, goal) {
                (true, Some(goal)) => self.waiters.push(Waiter {
                    goal,
                    deadline: Instant::now() + Duration::from_secs(command.timeout_secs),
                    reply,
                    started,
                }),
                _ => {
                    let _ = reply.send(Ok(started));
                }
            },
            Err(Error::Protocol(e)) if e.is_retryable() && tries + 1 < RETRY_TRIES => {
                self.retries.push(Retry {
                    command,
                    reply,
                    tries: tries + 1,
                    next: Instant::now() + RETRY_PAUSE,
                });
            }
            Err(e) => {
                self.journal(json!({"ev": "command-failed", "error": e.to_string()}));
                let _ = reply.send(Err(e.to_string()));
            }
        }
    }

    fn channel_id(&self, text: &str) -> Result<ChannelId> {
        let id = ChannelId::from_hex(text.trim())
            .map_err(|_| Error::Host(format!("{text:?} is not a channel id (16 hex)")))?;
        if !self.channels.contains_key(&id) {
            return Err(Error::Host(format!("no channel {id} here")));
        }
        Ok(id)
    }

    async fn pick_channel(
        &self,
        channel: &Option<String>,
        peer: Option<XOnlyPublicKey>,
        amount: u64,
    ) -> Result<ChannelId> {
        if let Some(c) = channel {
            return self.channel_id(c);
        }
        let peer = peer.ok_or_else(|| Error::Host("name --channel or --peer".into()))?;
        self.channels
            .iter()
            .filter(|(_, l)| l.m.peer() == peer && l.m.status() == ChannelStatus::Open)
            .find(|(_, l)| l.m.room() >= amount as i64)
            .map(|(id, _)| *id)
            .ok_or_else(|| {
                Error::Host(format!(
                    "no open channel with {peer} has {amount} sats of room"
                ))
            })
    }

    async fn execute(&mut self, request: &Request) -> Result<(Value, Option<Goal>)> {
        match request.clone() {
            Request::Open {
                peer,
                amount,
                push,
                delay,
                fee,
            } => {
                let peer = self.resolve_peer(&peer).await?;
                let id = self.open(peer, amount, push, delay, fee).await?;
                Ok((
                    json!({"cmd": "open", "channel": id.to_hex(), "peer": peer.to_string(), "amount": amount}),
                    Some(Goal::Opened(id)),
                ))
            }
            Request::Invoice {
                amount,
                memo,
                expiry_secs,
            } => {
                let preimage = random32()?;
                let (_, invoice) = Invoice::new(
                    NodeId(self.me),
                    amount,
                    memo,
                    vec![],
                    0,
                    unix_now() + expiry_secs,
                    preimage,
                )
                .map_err(|e| Error::Host(e.to_string()))?;
                let file = InvoiceFile {
                    invoice: invoice.clone(),
                    record: InvoiceRecord {
                        preimage: Bytes32(preimage),
                        amount,
                        paid: false,
                    },
                };
                self.store.write(
                    &invoice_path(&invoice.h.0),
                    serde_json::to_string_pretty(&file)?.as_bytes(),
                )?;
                self.invoices.insert(invoice.h.0, file);
                Ok((json!({"cmd": "invoice", "invoice": invoice}), None))
            }
            Request::Pay {
                channel,
                peer,
                amount,
                memo,
                invoice: Some(inv),
                expiry_blocks,
            } => {
                if inv.x < unix_now() {
                    return Err(Error::Host("the invoice has expired".into()));
                }
                let amount = amount.unwrap_or(inv.a).max(inv.a);
                let peer = match peer {
                    Some(p) => Some(self.resolve_peer(&p).await?),
                    None => Some(inv.p.0),
                };
                let id = self.pick_channel(&channel, peer, amount).await?;
                let delay = u32::from(self.channels[&id].m.delay());
                let height = self.follower.height().unwrap_or(0);
                let expiry =
                    height + expiry_blocks.unwrap_or(delay + EXPIRY_MARGIN + CLAIM_MARGIN + 6);
                let secret = fresh_secret()?;
                let memo = memo.or(inv.m.clone());
                let hash = inv.h;
                self.channel_call(id, move |c, ctx| {
                    Ok((
                        vec![c
                            .add_htlc(amount, hash, expiry, None, memo, secret, ctx)?
                            .into()],
                        vec![],
                    ))
                })
                .await?;
                Ok((
                    json!({"cmd": "pay", "channel": id.to_hex(), "amount": amount, "hash": hex::encode(hash.0), "expiry": expiry}),
                    Some(Goal::Htlc(hash)),
                ))
            }
            Request::Pay {
                channel,
                peer,
                amount,
                memo,
                invoice: None,
                ..
            } => {
                let amount =
                    amount.ok_or_else(|| Error::Host("name --amount or --invoice".into()))?;
                let peer = match peer {
                    Some(p) => Some(self.resolve_peer(&p).await?),
                    None => None,
                };
                let id = self.pick_channel(&channel, peer, amount).await?;
                let secret = fresh_secret()?;
                let mut n = 0;
                self.channel_call(id, |c, ctx| {
                    let u = c.pay(amount, memo, secret, ctx)?;
                    n = u.n;
                    Ok((vec![u.into()], vec![]))
                })
                .await?;
                Ok((
                    json!({"cmd": "pay", "channel": id.to_hex(), "amount": amount, "state": n}),
                    Some(Goal::PayFinal(id, n)),
                ))
            }
            Request::Close { channel } => {
                let id = self.channel_id(&channel)?;
                self.channel_call(id, |c, ctx| {
                    Ok((vec![c.close_channel(ctx)?.into()], vec![]))
                })
                .await?;
                Ok((
                    json!({"cmd": "close", "channel": id.to_hex()}),
                    Some(Goal::Settled(id)),
                ))
            }
            Request::ForceClose { channel } => {
                let id = self.channel_id(&channel)?;
                let mut txid = None;
                self.channel_call(id, |c, ctx| {
                    let b = c.force_close(None, "forced", ctx)?;
                    txid = Some(b.tx.compute_txid());
                    Ok((vec![], vec![b]))
                })
                .await?;
                Ok((
                    json!({"cmd": "force-close", "channel": id.to_hex(), "commitment": txid.map(|t| t.to_string())}),
                    Some(Goal::Settled(id)),
                ))
            }
            Request::Cheat { channel, state } => {
                if !self.cfg.developer {
                    return Err(Error::Host(
                        "cheat publishes a revoked state: developer builds only (SIDESTR_HITCH_DEVELOPER=1)".into(),
                    ));
                }
                let id = self.channel_id(&channel)?;
                self.alert(format!(
                    "DEVELOPER: publishing revoked state {state} of channel {id}"
                ));
                let mut txid = None;
                self.channel_call(id, |c, ctx| {
                    let b = c.force_close(Some(state), "cheat", ctx)?;
                    txid = Some(b.tx.compute_txid());
                    Ok((vec![], vec![b]))
                })
                .await?;
                Ok((
                    json!({"cmd": "cheat", "channel": id.to_hex(), "state": state, "commitment": txid.map(|t| t.to_string())}),
                    None,
                ))
            }
        }
    }

    /// Coins on the spend key's script that carry no asset and that no
    /// handshake or unconfirmed funding of this host's already spends.
    async fn funding_coins(&self) -> Result<Vec<sidestr_wallet::coins::Coin>> {
        let url = self.cfg.url.clone();
        let script = self.key.script().to_hex_string();
        let coins = tokio::task::spawn_blocking(move || client::coins(&url, &script))
            .await
            .map_err(|e| Error::Host(e.to_string()))?
            .map_err(crate::Error::from)?;
        let mut view = AssetView::new();
        for (h, txs) in self.follower.transactions() {
            view.apply_transactions(txs, h);
        }
        let mut reserved: HashSet<OutPoint> = HashSet::new();
        let pending = self
            .openings
            .values()
            .filter_map(|o| o.file.funder.as_ref().map(|f| f.funding_tx.clone()))
            .chain(self.channels.values().filter_map(|l| {
                (l.m.status() == ChannelStatus::Funding)
                    .then(|| l.file.funding_tx.clone())
                    .flatten()
            }));
        for hex in pending {
            if let Ok(tx) = bitcoin::consensus::encode::deserialize_hex::<Transaction>(&hex) {
                reserved.extend(tx.input.iter().map(|i| i.previous_output));
            }
        }
        Ok(plain_coins(&coins, &view)
            .into_iter()
            .filter(|c| !reserved.contains(&c.outpoint))
            .collect())
    }

    async fn open(
        &mut self,
        peer: XOnlyPublicKey,
        amount: u64,
        push: u64,
        delay: u16,
        fee: u64,
    ) -> Result<ChannelId> {
        if peer == self.me {
            return Err(Error::Host("a channel needs two peers".into()));
        }
        if peer == self.binding.identity_key() {
            return Err(Error::SpendIsIdentity);
        }
        if amount < MIN_OPEN {
            return Err(Error::Host(format!(
                "a channel holds at least {MIN_OPEN} sats"
            )));
        }
        let height = self
            .follower
            .height()
            .ok_or_else(|| Error::Host("the chain has not been read yet".into()))?;
        let funding_script = sidestr_hitch::funding_script(self.me, peer)?.script_pubkey;
        let coins = self.funding_coins().await?;
        let prepared = prepare(
            &self.key,
            &self.cfg.doc,
            &coins,
            height,
            Payment::Send,
            &funding_script.to_hex_string(),
            amount,
            None,
            unix_now(),
        )?;
        let vout = prepared
            .spend
            .tx
            .output
            .iter()
            .position(|o| o.script_pubkey == funding_script && o.value.to_sat() == amount)
            .ok_or_else(|| Error::Host("the wallet's funding has no channel output".into()))?;
        let funding = OutPoint {
            txid: prepared.spend.txid,
            vout: vout as u32,
        };
        let (rb, r0, r1, aux) = (
            fresh_secret()?,
            fresh_secret()?,
            fresh_secret()?,
            random32()?,
        );
        let params = OpenParams {
            funding,
            funding_value: Amount::from_sat(amount),
            push: Amount::from_sat(push),
            delay,
            fee: Amount::from_sat(fee),
            hub_fee: None,
        };
        let keys = OpeningKeys {
            channel: self.key.secret_key(),
            revocation_base: rb,
            revocation: [r0, r1],
        };
        let (fo, open) = FunderOpening::propose(params, keys, peer, self.rules, &aux)?;
        let id = fo.id();
        let file = OpeningFile {
            version: FILE_VERSION,
            role: OpeningRole::Funder,
            chain: self.cfg.doc.id.clone(),
            peer: peer.to_string(),
            revocation_base: secret_hex(&rb),
            revocation: [secret_hex(&r0), secret_hex(&r1)],
            aux: hex::encode(aux),
            created_at: unix_now(),
            funder: Some(FunderPart {
                funding: funding.to_string(),
                funding_value: amount,
                push,
                delay,
                fee,
                funding_tx: prepared.spend.hex.clone(),
                accept: None,
            }),
            receiver: None,
        };
        self.save_opening(id, &file)?;
        self.openings.insert(
            id,
            Opening {
                file,
                state: OpeningState::Proposed(Box::new(fo)),
                sent_at: unix_now(),
            },
        );
        self.journal(json!({"ev": "opening", "ch": id.to_hex(), "peer": peer.to_string(), "funding": funding.to_string(), "amount": amount, "push": push, "delay": delay, "fee": fee}));
        self.send(peer, &PeerMessage::Open(open)).await;
        Ok(id)
    }

    fn check_waiters(&mut self) {
        let now = Instant::now();
        let mut i = 0;
        while i < self.waiters.len() {
            let done = match &self.waiters[i].goal {
                Goal::Opened(id) => self
                    .channels
                    .get(id)
                    .map(|l| !matches!(l.m.status(), ChannelStatus::Funding)),
                Goal::PayFinal(id, n) => self
                    .channels
                    .get(id)
                    .map(|l| l.m.state_number() >= *n && l.m.pending().is_none_or(|p| p.n != *n)),
                Goal::Settled(id) => self.channels.get(id).map(|l| self.settled(&l.m)),
                Goal::Htlc(_) => Some(false),
            };
            let expired = now >= self.waiters[i].deadline;
            if done == Some(true) || expired {
                let w = self.waiters.swap_remove(i);
                let mut v = w.started;
                let id = match &w.goal {
                    Goal::Opened(id) | Goal::PayFinal(id, _) | Goal::Settled(id) => Some(*id),
                    Goal::Htlc(_) => None,
                };
                if let Some(l) = id.and_then(|id| self.channels.get(&id)) {
                    v["status"] = self.summary(&l.m, &l.file);
                }
                let _ = w.reply.send(if done == Some(true) {
                    Ok(v)
                } else {
                    Err(format!(
                        "timed out waiting; the host carries on with it when it runs again: {v}"
                    ))
                });
            } else {
                i += 1;
            }
        }
    }

    /// Terminal, and the spend that decided it is [`CLOSE_DEPTH`] deep, and
    /// every claim of this host's is in a block.
    fn settled(&self, m: &ChannelMachine) -> bool {
        m.status().is_terminal()
            && m.spent_by()
                .is_some_and(|(_, h)| self.follower.confirmations(h) >= CLOSE_DEPTH)
            && m.claims()
                .iter()
                .all(|c| self.follower.find_tx(&c.txid).is_some())
    }

    // ---- the poll

    async fn step(&mut self) {
        self.polls += 1;
        match self.refresh_chain().await {
            Ok(advance) => self.on_advance(advance).await,
            Err(e) => {
                let text = e.to_string();
                if self.chain_error.as_deref() != Some(text.as_str()) {
                    self.journal(json!({"ev": "chain-error", "error": text}));
                }
                self.chain_error = Some(text);
            }
        }
        let ids: Vec<ChannelId> = self.channels.keys().copied().collect();
        for id in &ids {
            self.watch_channel(*id).await;
            self.resend_funding(*id).await;
        }
        for id in &ids {
            self.tick_channel(*id).await;
        }
        self.tick_openings().await;
        self.run_retries().await;
        self.run_repairs().await;
        self.check_mirror().await;
    }

    async fn refresh_chain(&mut self) -> Result<Advance> {
        let mut sources = vec![(self.cfg.url.clone(), true)];
        if let Some(m) = &self.cfg.mirror {
            sources.push((m.clone(), false));
        }
        let mut last = String::new();
        for (base, producer) in sources {
            if producer {
                if let Some((h, held)) = self.follower.tip() {
                    let b = base.clone();
                    let tip = tokio::task::spawn_blocking(move || fetch_tip(&b))
                        .await
                        .ok()
                        .flatten();
                    if tip
                        .as_ref()
                        .is_some_and(|(th, hash)| *th == h && *hash == held.to_string())
                    {
                        self.chain_ok_at = Some(Instant::now());
                        self.chain_error = None;
                        return Ok(Advance::Unchanged);
                    }
                }
            }
            let b = base.clone();
            let index = match tokio::task::spawn_blocking(move || fetch_index(&b)).await {
                Ok(Ok(i)) => i,
                Ok(Err(e)) => {
                    last = e;
                    continue;
                }
                Err(e) => {
                    last = e.to_string();
                    continue;
                }
            };
            let advance = match self.follower.plan(&index)? {
                Plan::UpToDate => Advance::Unchanged,
                Plan::Truncate { len } => self.follower.truncate(len),
                Plan::Fetch { from, offset } => {
                    let b = base.clone();
                    let tail =
                        match tokio::task::spawn_blocking(move || fetch_tail(&b, offset)).await {
                            Ok(Ok(t)) => t,
                            Ok(Err(e)) => {
                                last = e;
                                continue;
                            }
                            Err(e) => {
                                last = e.to_string();
                                continue;
                            }
                        };
                    match self.follower.apply(&index, from, &tail) {
                        Ok(a) => a,
                        Err(e) => {
                            last = e.to_string();
                            continue;
                        }
                    }
                }
            };
            self.chain_ok_at = Some(Instant::now());
            self.chain_error = None;
            return Ok(advance);
        }
        Err(Error::Chain(last))
    }

    async fn on_advance(&mut self, advance: Advance) {
        let Advance::Reorg {
            fork,
            depth,
            to,
            undone,
        } = advance
        else {
            return;
        };
        self.journal(json!({"ev": "reorg", "fork": fork, "depth": depth, "to": to, "undone": undone.iter().map(|t| t.to_string()).collect::<Vec<_>>()}));
        if depth >= CLOSE_DEPTH {
            self.alert(format!(
                "a reorganisation {depth} blocks deep (from height {fork}) reached CLOSE_DEPTH; a close counted final may be undone"
            ));
        }
        // this host's transactions it undid are published again, locks permitting
        let undone: HashSet<Txid> = undone.into_iter().collect();
        let mut mine: Vec<(String, Transaction)> = Vec::new();
        for live in self.channels.values() {
            if let Some(hex) = &live.file.funding_tx {
                if let Ok(tx) = bitcoin::consensus::encode::deserialize_hex::<Transaction>(hex) {
                    mine.push(("funding (again after a reorganisation)".into(), tx));
                }
            }
            if let Some(tx) = live.m.close_transaction_published() {
                mine.push(("close (again after a reorganisation)".into(), tx.clone()));
            }
            for c in live.m.claims() {
                mine.push((
                    format!("{} (again after a reorganisation)", c.kind),
                    c.tx.clone(),
                ));
            }
        }
        for (label, tx) in mine {
            let txid = tx.compute_txid();
            if undone.contains(&txid) {
                self.repairs.insert(
                    txid,
                    Repair {
                        tx,
                        label,
                        tried_at: None,
                    },
                );
            }
        }
    }

    async fn watch_channel(&mut self, id: ChannelId) {
        let Ok(ctx) = self.ctx() else {
            return;
        };
        let dest = self.key.script();
        let stale = ctx.stale;
        let mut outs: Vec<Broadcast> = Vec::new();
        let mut notes: Vec<Value> = Vec::new();
        {
            let follower = &self.follower;
            let Some(live) = self.channels.get_mut(&id) else {
                return;
            };
            let m = &mut live.m;
            let op = m.channel().funding_outpoint;
            if m.status() == ChannelStatus::Funding && live.file.bad_funding.is_none() {
                if let Some((h, tx)) = follower.find_tx(&op.txid) {
                    let fits = tx.output.get(op.vout as usize).is_some_and(|o| {
                        o.script_pubkey == m.channel().funding_script.script_pubkey
                            && o.value == m.channel().funding_value
                    });
                    if !fits {
                        let why = format!(
                            "the funding output {op} is not the channel's 2-of-2 for {} sats",
                            m.channel().funding_value.to_sat()
                        );
                        notes.push(json!({"ev": "bad-funding", "ch": id.to_hex(), "why": why}));
                        live.file.bad_funding = Some(why);
                    } else if follower.confirmations(h) >= MIN_CONF {
                        m.confirm_funding(h);
                        notes.push(json!({"ev": "funded", "ch": id.to_hex(), "fundingHeight": h, "funding": op.to_string()}));
                    }
                }
            }
            let lookup = move |o: OutPoint, _: u32| {
                if stale {
                    return OutputLookup::Unknown;
                }
                match follower.spender(&o) {
                    Some((txid, height, tx)) => OutputLookup::Spent {
                        txid,
                        height,
                        tx: tx.clone(),
                    },
                    None => OutputLookup::Unspent,
                }
            };
            let on_chain = follower.spender(&op).map(|(t, h, _)| (t, h));
            let classify = |m: &mut ChannelMachine,
                            txid: Txid,
                            height: u32,
                            notes: &mut Vec<Value>,
                            outs: &mut Vec<Broadcast>| {
                match m.on_spend(ChainSpend { txid, height }, &dest, &ctx, lookup) {
                    Ok(o) => {
                        notes.push(json!({"ev": "funding-spent", "ch": id.to_hex(), "txid": txid.to_string(), "spendHeight": height, "kind": serde_json::to_value(o.kind).unwrap_or_default(), "status": m.status().as_str()}));
                        outs.extend(o.broadcasts);
                    }
                    Err(e) => notes.push(
                        json!({"ev": "on-spend-failed", "ch": id.to_hex(), "error": e.to_string()}),
                    ),
                }
            };
            match (m.spent_by(), on_chain) {
                (None, Some((txid, h))) => classify(m, txid, h, &mut notes, &mut outs),
                (Some((was, wh)), Some((txid, h))) if was != txid || wh != h => {
                    notes.push(json!({"ev": "spend-moved", "ch": id.to_hex(), "was": was.to_string(), "wasHeight": wh, "txid": txid.to_string(), "spendHeight": h}));
                    if let Some(b) = m.un_spend() {
                        outs.push(b);
                    }
                    classify(m, txid, h, &mut notes, &mut outs);
                }
                (Some((was, wh)), None) => {
                    notes.push(json!({"ev": "spend-undone", "ch": id.to_hex(), "txid": was.to_string(), "spendHeight": wh, "status": m.status().as_str()}));
                    if let Some(b) = m.un_spend() {
                        outs.push(b);
                    }
                }
                (Some(_), Some(_)) if m.status().is_following() => {
                    outs.extend(m.after_close(&dest, &ctx, lookup));
                }
                _ => {}
            }
        }
        if let Err(e) = self.save(id) {
            self.journal(json!({"ev": "save-failed", "ch": id.to_hex(), "error": e.to_string()}));
            return;
        }
        for n in notes {
            self.journal(n);
        }
        for b in outs {
            self.broadcast(&b.label, &b.tx).await;
        }
        self.drain_events(id);
    }

    async fn tick_channel(&mut self, id: ChannelId) {
        let Ok(ctx) = self.ctx() else {
            return;
        };
        let actions = match self.channels.get_mut(&id) {
            Some(live) if !live.m.status().is_terminal() => {
                live.m.tick(&ctx, &TickOptions::default())
            }
            _ => return,
        };
        if actions.is_empty() {
            return;
        }
        if self.save(id).is_err() {
            return;
        }
        let mut msgs = Vec::new();
        let mut txs = Vec::new();
        let mut later = Vec::new();
        for a in actions {
            match a {
                TickAction::Send(m) => msgs.push(*m),
                TickAction::Broadcast(b) => txs.push(b),
                other => later.push(other),
            }
        }
        self.send_all(id, msgs, txs).await;
        for a in later {
            let r = match a {
                TickAction::Settle { htlc_id, preimage } if !self.cfg.hold_htlcs => {
                    match fresh_secret() {
                        Ok(s) => {
                            self.channel_call(id, move |c, ctx| {
                                Ok((
                                    vec![c.settle_htlc(htlc_id, preimage, s, ctx)?.into()],
                                    vec![],
                                ))
                            })
                            .await
                        }
                        Err(e) => Err(e),
                    }
                }
                TickAction::Fail { htlc_id, reason } if !self.cfg.hold_htlcs => {
                    match fresh_secret() {
                        Ok(s) => {
                            self.channel_call(id, move |c, ctx| {
                                Ok((
                                    vec![c.fail_htlc(htlc_id, Some(&reason), s, ctx)?.into()],
                                    vec![],
                                ))
                            })
                            .await
                        }
                        Err(e) => Err(e),
                    }
                }
                _ => Ok(()),
            };
            if let Err(e) = r {
                self.journal(
                    json!({"ev": "tick-failed", "ch": id.to_hex(), "error": e.to_string()}),
                );
            }
        }
    }

    async fn tick_openings(&mut self) {
        let now = unix_now();
        let due: Vec<(ChannelId, XOnlyPublicKey, PeerMessage)> = self
            .openings
            .iter()
            .filter(|(_, o)| now.saturating_sub(o.sent_at) >= HANDSHAKE_RESEND)
            .filter_map(|(id, o)| {
                let peer = o.file.peer.parse().ok()?;
                let msg = match &o.state {
                    OpeningState::Proposed(fo) => PeerMessage::Open(fo.message().clone()),
                    OpeningState::Accepted(acc) => {
                        PeerMessage::Commit(acc.commit_message().clone())
                    }
                    OpeningState::Receiver(ro) => PeerMessage::Accept(ro.message().clone()),
                };
                Some((*id, peer, msg))
            })
            .collect();
        for (id, peer, msg) in due {
            if let Some(o) = self.openings.get_mut(&id) {
                o.sent_at = now;
            }
            self.send(peer, &msg).await;
        }
    }

    async fn run_retries(&mut self) {
        let now = Instant::now();
        let (due, wait): (Vec<Retry>, Vec<Retry>) = std::mem::take(&mut self.retries)
            .into_iter()
            .partition(|r| r.next <= now);
        self.retries = wait;
        for r in due {
            self.submit_try(r.command, r.reply, r.tries).await;
        }
    }

    async fn run_repairs(&mut self) {
        let Some(height) = self.follower.height() else {
            return;
        };
        let txids: Vec<Txid> = self.repairs.keys().copied().collect();
        for txid in txids {
            if self.follower.find_tx(&txid).is_some() {
                self.journal(json!({"ev": "repaired", "txid": txid.to_string()}));
                self.repairs.remove(&txid);
                continue;
            }
            let Some(r) = self.repairs.get(&txid) else {
                continue;
            };
            if r.tried_at.is_some_and(|t| height.saturating_sub(t) < 2) {
                continue;
            }
            if premature(&r.tx, height + 1, |t| {
                self.follower.find_tx(t).map(|(h, _)| h)
            })
            .is_some()
            {
                continue;
            }
            let (tx, label) = (r.tx.clone(), r.label.clone());
            if let Some(r) = self.repairs.get_mut(&txid) {
                r.tried_at = Some(height);
            }
            self.broadcast(&label, &tx).await;
        }
    }

    async fn check_mirror(&mut self) {
        let Some(mirror) = self.cfg.mirror.clone() else {
            return;
        };
        if self
            .mirror_at
            .is_some_and(|t| t.elapsed() < Duration::from_secs(60))
        {
            return;
        }
        self.mirror_at = Some(Instant::now());
        let Ok(Ok(index)) = tokio::task::spawn_blocking(move || fetch_index(&mirror)).await else {
            return;
        };
        let disagree = index.blocks.iter().find(|e| {
            self.follower
                .hash_at(e.height)
                .is_some_and(|h| h.to_string() != e.hash)
        });
        if let Some(e) = disagree {
            let text = format!(
                "the mirror disagrees with the producer at height {}: {} against {}",
                e.height,
                e.hash,
                self.follower
                    .hash_at(e.height)
                    .map(|h| h.to_string())
                    .unwrap_or_default()
            );
            if !self.alerts.contains(&text) {
                self.alert(text);
            }
        }
    }

    // ---- status

    fn summary(&self, m: &ChannelMachine, file: &ChannelFile) -> Value {
        summary(m, file, Some(&self.follower))
    }

    fn write_status(&mut self) {
        let channels: Vec<Value> = self
            .channels
            .values()
            .map(|l| self.summary(&l.m, &l.file))
            .collect();
        let body = json!({
            "me": self.me.to_string(),
            "identity": self.binding.identity,
            "chain": {
                "id": self.cfg.doc.id,
                "height": self.follower.height(),
                "tip": self.follower.tip().map(|(_, h)| h.to_string()),
                "stale": self.stale(),
                "error": self.chain_error,
            },
            "alerts": self.alerts,
            "channels": channels,
            "openings": self.openings.iter().map(|(id, o)| json!({"channel": id.to_hex(), "role": o.file.role, "peer": o.file.peer})).collect::<Vec<_>>(),
            "repairs": self.repairs.keys().map(|t| t.to_string()).collect::<Vec<_>>(),
        });
        let text = serde_json::to_string_pretty(&body).unwrap_or_default();
        if text != self.last_status {
            let mut stamped = body;
            stamped["asOf"] = json!(unix_now());
            if self
                .store
                .write(
                    STATUS,
                    serde_json::to_string_pretty(&stamped)
                        .unwrap_or_default()
                        .as_bytes(),
                )
                .is_ok()
            {
                self.last_status = text;
            }
        }
    }
}

/// One channel as `hitch status` shows it: balances, lifecycle, the funding,
/// the spend, the claims and penalties. With a follower, `final` is whether
/// it is terminal with its deciding spend [`CLOSE_DEPTH`] deep and every
/// claim of this host's in a block. No secrets.
pub fn summary(m: &ChannelMachine, file: &ChannelFile, follower: Option<&ChainFollower>) -> Value {
    let op = m.channel().funding_outpoint;
    let claims: Vec<Value> = m
        .claims()
        .iter()
        .map(|c| {
            json!({
                "kind": c.kind.to_string(),
                "txid": c.txid.to_string(),
                "vout": c.vout,
                "confirmed": follower.and_then(|f| f.find_tx(&c.txid)).map(|(h, _)| h),
            })
        })
        .collect();
    let settled = follower.map(|f| {
        m.status().is_terminal()
            && m.spent_by()
                .is_some_and(|(_, h)| f.confirmations(h) >= CLOSE_DEPTH)
            && m.claims().iter().all(|c| f.find_tx(&c.txid).is_some())
    });
    json!({
        "channel": m.id().to_hex(),
        "role": role_name(m.role()),
        "peer": m.peer().to_string(),
        "status": m.status().as_str(),
        "state": m.state_number(),
        "mine": m.my_balance(),
        "theirs": m.their_balance(),
        "htlcs": m.htlcs(),
        "funding": op.to_string(),
        "fundingValue": m.channel().funding_value.to_sat(),
        "fundedHeight": m.funded_height(),
        "delay": m.delay(),
        "fee": m.channel().fee.to_sat(),
        "spentBy": m.spent_by().map(|(t, h)| json!({"txid": t.to_string(), "height": h})),
        "closeTx": m.close_transaction_published().map(|t| t.compute_txid().to_string()),
        "coopTxid": m.coop_txid().map(|t| t.to_string()),
        "claims": claims,
        "penalties": m.penalties().iter().map(|t| t.to_string()).collect::<Vec<_>>(),
        "badFunding": file.bad_funding,
        "final": settled,
    })
}

/// `hitch status` without a running host: every channel from its saved
/// snapshot, the handshakes and invoices in progress, and the host's last
/// view (`status.json`) when there is one.
pub fn status_from_files(store: &Store) -> Result<Value> {
    let mut channels = Vec::new();
    for name in store.list(CHANNELS)? {
        let rel = format!("{CHANNELS}/{name}");
        let file: ChannelFile = serde_json::from_slice(&store.read(&rel)?.unwrap_or_default())?;
        let m = ChannelMachine::restore(file.snapshot.clone())?;
        channels.push(summary(&m, &file, None));
    }
    let mut openings = Vec::new();
    for name in store.list(OPENINGS)? {
        let file: OpeningFile = serde_json::from_slice(
            &store
                .read(&format!("{OPENINGS}/{name}"))?
                .unwrap_or_default(),
        )?;
        openings.push(
            json!({"file": name, "role": file.role, "peer": file.peer, "since": file.created_at}),
        );
    }
    let mut invoices = Vec::new();
    for name in store.list(INVOICES)? {
        let file: InvoiceFile = serde_json::from_slice(
            &store
                .read(&format!("{INVOICES}/{name}"))?
                .unwrap_or_default(),
        )?;
        invoices.push(json!({"invoice": file.invoice, "paid": file.record.paid}));
    }
    let host: Value = match store.read(STATUS)? {
        Some(b) => serde_json::from_slice(&b)?,
        None => Value::Null,
    };
    let binding: Value = match store.read(BINDING)? {
        Some(b) => {
            let ev: Event = serde_json::from_slice(&b)?;
            json!({"event": ev.id, "identity": ev.pubkey, "spend": ev.content})
        }
        None => Value::Null,
    };
    Ok(json!({
        "state": store.dir().display().to_string(),
        "binding": binding,
        "channels": channels,
        "openings": openings,
        "invoices": invoices,
        "host": host,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{ScriptBuf, Sequence, TxIn};

    fn tx(version: i32, sequence: u32, lock: u32) -> Transaction {
        Transaction {
            version: Version(version),
            lock_time: LockTime::from_consensus(lock),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence(sequence),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    #[test]
    fn nothing_is_sent_before_its_locks() {
        let at = |h| move |_: &Txid| Some(h);
        // a delayed sweep, CSV 3, of a commitment in block 100
        let sweep = tx(2, 3, 0);
        assert!(premature(&sweep, 102, at(100)).is_some());
        assert!(premature(&sweep, 103, at(100)).is_none());
        // ... whose commitment is in no block yet: not before the next block plus 3
        assert!(premature(&sweep, 103, |_| None).is_some());
        // a penalty or a commitment: no lock at all
        assert!(premature(&tx(2, 0xffff_fffd, 0), 1, |_| None).is_none());
        // an HTLC refund locked to height 812: from 813
        let refund = tx(2, 0xffff_fffe, 812);
        assert!(premature(&refund, 812, at(10)).is_some());
        assert!(premature(&refund, 813, at(10)).is_none());
        // a time-based relative lock is never sent
        assert!(premature(&tx(2, 0x0040_0006, 0), 10_000, at(1)).is_some());
        // version 1 does not enforce BIP 68
        assert!(premature(&tx(1, 6, 0), 101, at(100)).is_none());
    }

    #[test]
    fn a_command_travels_as_json() {
        let c = Command {
            request: Request::Pay {
                channel: Some("0011223344556677".into()),
                peer: None,
                amount: Some(7_000),
                memo: Some("tea".into()),
                invoice: None,
                expiry_blocks: None,
            },
            wait: true,
            timeout_secs: 60,
        };
        let text = serde_json::to_string(&c).unwrap();
        assert!(text.contains(r#""op":"pay""#));
        assert_eq!(serde_json::from_str::<Command>(&text).unwrap(), c);
    }
}
