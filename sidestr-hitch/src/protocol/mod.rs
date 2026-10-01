//! Hitch's channel protocol (`lib/peer.mjs`) as a pure, sans-IO state
//! machine.
//!
//! A channel update has three messages. The proposer signs the receiver's
//! next commitment in [`UpdateMessage`]. The receiver verifies the whole
//! proposed state, signs the proposer's commitment and reveals its previous
//! per-state secret in [`AckMessage`]. The proposer checks both, advances,
//! and reveals its own previous secret in [`RevokeMessage`]. The receiver
//! treats the update as final only after that last reveal. This is the safety
//! boundary Hitch's router and user notifications rely on.
//!
//! # Invariants, as Hitch states them
//!
//! - The revocation key of a commitment is a two-party key: the other side's
//!   basepoint plus the owner's per-state point ([`crate::revocation_pub`]).
//!   The owner can never use its own revocation leaf; the other side can only
//!   once the state is revoked. Every announced point carries a proof of
//!   possession ([`crate::pop_sign`]), so neither side can choose a point
//!   that cancels the other's.
//! - A signature sent for a state binds its signer until the other side
//!   revokes that state. A pending update is never simply dropped: when both
//!   sides propose at once the lower key's update stands and the other's
//!   signed state is remembered as an alternative the peer might publish; the
//!   same when an update is rejected. A set-aside state's HTLCs stay bound
//!   ([`ChannelMachine::bound`]) until the other side revokes that state
//!   number or the funding output is spent by something else.
//! - A payment is final only when the other side has revoked the state before
//!   it; until then nothing is forwarded, settled or announced, and no further
//!   update is accepted or proposed.
//! - A signature or a revocation secret leaves the node only after the state
//!   it belongs to is saved. Here that is the host's half of the contract:
//!   after every call that changes the machine, persist
//!   [`ChannelMachine::snapshot`] atomically, then send what the call
//!   returned. If the save fails, send nothing and restore the previous
//!   snapshot.
//! - A settle is refused after the HTLC's expiry, a fail by the offerer is
//!   refused while the receiver holds the preimage, and every preimage learnt
//!   (from a message or from the chain) is kept so an HTLC can be claimed
//!   after a forced close.
//! - An HTLC this peer can claim is taken to the chain `delay +
//!   CLAIM_MARGIN` blocks before its expiry if the settle is not
//!   acknowledged, whatever else is pending.
//! - Every field of every message is checked for shape before it is used
//!   ([`PeerMessage::well_formed`]), and nothing is written to the channel
//!   until the message has been verified in full.
//!
//! # The host's part
//!
//! The machine performs no IO. A host supplies relay transport (sign and
//! carry each returned [`PeerMessage`] as a kind-[`KIND`] event), wallet
//! funding, atomic snapshot storage, chain watches and broadcasting. Where
//! Hitch calls `io.onDropped`, `io.onPreimage` and `io.onPayment`, the
//! machine queues a [`ChannelEvent`] for [`ChannelMachine::drain_events`].
//! Hitch's `io.onUpdate` is the [`FinalisedUpdate`] returned when an incoming
//! update crosses its finality boundary; [`crate::route::Router`] consumes
//! all of these. New per-state secrets come from the host's key generator, so
//! the machine stays deterministic.
//!
//! # Departures from Hitch
//!
//! Each is deliberate; the first two are tested as departures:
//!
//! - Points are parsed at the boundary. Hitch's `wellFormed` accepts any 64
//!   hex characters as a key and refuses a point off the curve later, at the
//!   proof-of-possession check (with a reject); here such a message does not
//!   deserialise, so it is dropped without a reject. Both refuse it.
//! - Hitch reads channel documents from before the two-party key (no
//!   basepoints) with a single-party fallback. Version 1 snapshots of
//!   `sidestr-hitch` 0.1 are refused instead ([`ChannelSnapshot`]).
//! - Hitch's tab and hub keep failed broadcasts, retry timers and the
//!   proposal, funding and unfunded timeouts on the channel document; here
//!   they are the host's scheduler, with Hitch's constants exported.

use bitcoin::secp256k1::{Keypair, SecretKey, XOnlyPublicKey};
use bitcoin::Transaction;
use serde::{Deserialize, Serialize};
use sidestr_core::block::secp;

mod chain;
mod machine;
mod opening;
mod snapshot;
mod wire;

pub use chain::{ChainSpend, ClaimKind, ClaimRecord, FollowedOutput, OutputLookup, SpendOutcome};
pub use machine::{
    AckOutcome, AwaitingRevoke, Bound, ChannelMachine, DroppedUpdate, FinalisedUpdate,
    FundingSpend, PendingUpdate, ProtocolState, ReceiveUpdate, SignedAlternative, SyncOutcome,
    TickAction, TickOptions,
};
pub use opening::{
    AcceptPolicy, AcceptedFunder, FunderOpening, FunderSync, OpenParams, OpeningKeys,
    ReceiverOpening,
};
pub use snapshot::ChannelSnapshot;
pub use wire::{
    AcceptMessage, AcceptTag, AckMessage, AckTag, Bytes32, ChannelId, CloseMessage, CloseTag,
    CommitMessage, CommitTag, FundingOffer, NodeId, OfferedHtlc, OpenMessage, OpenTag, PeerMessage,
    ProtocolHtlc, ReadyMessage, ReadyTag, RejectMessage, RejectTag, RevocationProofs,
    RevokeMessage, RevokeTag, Route, SyncMessage, SyncTag, Update, UpdateMessage, UpdateTag,
    WireSide,
};

/// Nostr event kind used by Hitch channel messages.
pub const KIND: u16 = 23_600;
/// Smallest channel Hitch opens, in satoshis.
pub const MIN_OPEN: u64 = 10_000;
/// Smallest HTLC Hitch accepts, in satoshis.
pub const MIN_HTLC: u64 = 1_000;
/// Blocks an off-chain HTLC must keep beyond the channel CSV delay.
pub const EXPIRY_MARGIN: u32 = 12;
/// Blocks kept before an on-chain deadline: an HTLC this peer can claim goes
/// to the chain `delay + CLAIM_MARGIN` blocks before its expiry.
pub const CLAIM_MARGIN: u32 = 3;
/// Blocks after which a close is final and stops being followed.
pub const CLOSE_DEPTH: u32 = 6;
/// Longest memo and failure-reason string in JavaScript UTF-16 code units.
pub const MEMO_MAX: usize = 140;
/// Seconds before an unconfirmed funding is set aside as unfunded (host
/// scheduler; the funding is the wallet's).
pub const FUNDING_TIMEOUT: u64 = 24 * 3_600;
/// Seconds before an unanswered proposal is abandoned (host scheduler).
pub const PROPOSAL_TIMEOUT: u64 = 6 * 3_600;
/// Seconds before an unfunded channel is abandoned (host scheduler).
pub const UNFUNDED_TIMEOUT: u64 = 7 * 24 * 3_600;
/// Confirmations Hitch waits for before a channel opens.
pub const MIN_CONF: u32 = 2;
/// Hitch's default seconds before an unanswered update is sent again; each
/// further try doubles the wait, up to [`MAX_PENDING_BACKOFF`].
pub const DEFAULT_PENDING_TIMEOUT: u64 = 90;
/// Longest wait between retries of an unanswered update, in seconds.
pub const MAX_PENDING_BACKOFF: u64 = 600;
/// Largest satoshi value on Hitch's wire (21 million coins).
pub const MAX_SATS: u64 = 2_100_000_000_000_000;
/// Largest hub fee Hitch's wire carries, in satoshis.
pub const MAX_HUB_FEE: u64 = 100_000;

const MAX_SYNC_ITEMS: usize = 64;
const MAX_STATUS_LEN: usize = 32;
/// Seconds an incoming update may wait for its revocation before a resync.
const AWAITING_RESYNC: u64 = 60;
/// Minimum seconds between unforced resyncs of one channel.
const RESYNC_INTERVAL: u64 = 30;
/// Blocks before an unconfirmed close of mine is published again.
const CLOSE_REBROADCAST: u32 = 3;
/// Blocks before an unconfirmed claim of mine is published again.
const CLAIM_REBROADCAST: u32 = 6;

/// What the host knows at the moment of a call: chain height, wall-clock
/// time and fresh signing randomness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    /// Current parent-chain height.
    pub height: u32,
    /// Unix time in seconds.
    pub now: u64,
    /// BIP 340 auxiliary randomness for the signatures made in this call.
    pub aux: [u8; 32],
    /// Whether the host's chain view is stale. Hitch makes no HTLC decision
    /// on a stale view: HTLC updates wait until it returns.
    pub stale: bool,
}

impl Context {
    /// A context with a fresh chain view.
    pub fn new(height: u32, now: u64, aux: [u8; 32]) -> Self {
        Self {
            height,
            now,
            aux,
            stale: false,
        }
    }
}

/// A transaction the host should broadcast, with Hitch's label for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Broadcast {
    /// Hitch's description, such as `"protective close"` or `"penalty on
    /// to_local (their revoked state 3)"`.
    pub label: String,
    /// Fully witnessed transaction.
    pub tx: Transaction,
}

/// A channel's lifecycle after both initial commitments are signed, named
/// as in Hitch.
///
/// The opening states before that (`proposed`, `accepted`) are the
/// typestates [`FunderOpening`], [`AcceptedFunder`] and [`ReceiverOpening`];
/// `unfunded`, `abandoned` and `bad-funding` are the wallet's view of a
/// funding that never confirmed, decided by the host's scheduler with
/// [`FUNDING_TIMEOUT`] and [`UNFUNDED_TIMEOUT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChannelStatus {
    /// Both initial commitments signed; the funding is not yet confirmed.
    Funding,
    /// Updates flow.
    Open,
    /// This peer signed and sent a cooperative close at the current state.
    ClosingAsked,
    /// This peer holds a fully signed cooperative close and published it.
    Closing,
    /// This peer published its own commitment.
    ForceClosing,
    /// This peer's commitment is in a block.
    ClosedMine,
    /// The other side's unrevoked commitment is in a block.
    ClosedTheirs,
    /// The other side published an unrevoked alternative this peer signed.
    ClosedTheirsAlt,
    /// The other side published a revoked commitment; penalties are out.
    Punishing,
    /// Everything of this peer's is claimed; waiting for the claims to
    /// confirm.
    Settling,
    /// The cooperative close is in a block, not yet [`CLOSE_DEPTH`] deep.
    ClosedCoop,
    /// Final.
    Closed,
    /// Every penalty is settled on the chain.
    Punished,
    /// The funding output was spent by a transaction this peer never signed.
    SpentUnknown,
}

impl ChannelStatus {
    /// Hitch's status string, as carried in [`SyncMessage::status`].
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Funding => "funding",
            Self::Open => "open",
            Self::ClosingAsked => "closing-asked",
            Self::Closing => "closing",
            Self::ForceClosing => "force-closing",
            Self::ClosedMine => "closed-mine",
            Self::ClosedTheirs => "closed-theirs",
            Self::ClosedTheirsAlt => "closed-theirs-alt",
            Self::Punishing => "punishing",
            Self::Settling => "settling",
            Self::ClosedCoop => "closed-coop",
            Self::Closed => "closed",
            Self::Punished => "punished",
            Self::SpentUnknown => "spent-unknown",
        }
    }

    /// Hitch's `LIVE`: the channel still exchanges messages.
    pub fn is_live(self) -> bool {
        matches!(self, Self::Funding | Self::Open | Self::ClosingAsked)
    }

    /// Hitch's `WATCHED`: the host must watch the funding outpoint and feed
    /// spends to [`ChannelMachine::on_spend`].
    pub fn is_watched(self) -> bool {
        !self.is_terminal()
    }

    /// Hitch's `FOLLOWING`: a close whose outputs are still being followed.
    pub fn is_following(self) -> bool {
        matches!(
            self,
            Self::ClosedMine
                | Self::ClosedTheirs
                | Self::ClosedTheirsAlt
                | Self::Punishing
                | Self::Settling
                | Self::ClosedCoop
        )
    }

    /// Hitch's `TERMINAL`: nothing more happens.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Closed | Self::Punished | Self::SpentUnknown)
    }

    /// Hitch's `CLOSED_OUT`: a close of this peer's is signed or published,
    /// so no update can be made or taken.
    pub fn is_closed_out(self) -> bool {
        matches!(
            self,
            Self::ForceClosing | Self::Closing | Self::ClosingAsked
        )
    }
}

/// What became of an HTLC this peer offered, as Hitch reports it through
/// `io.onPayment`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentOutcome {
    /// A set-aside add was acknowledged after all and is in force.
    InFlight,
    /// The other side took it with the preimage.
    Sent,
    /// It came back, off chain or as a refund on the chain.
    Failed,
    /// The add was set aside and is not retried by itself.
    NotMade,
}

/// Something the host should act on after a call, in Hitch's `io` hooks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelEvent {
    /// Hitch's `io.onDropped`: an update of this peer's was set aside and
    /// will not be retried by itself. For an `add` the other side could still
    /// acknowledge it late; see [`ChannelMachine::bound`].
    Dropped(DroppedUpdate),
    /// Hitch's `io.onPreimage`: a preimage read from the chain, where the
    /// other side claimed an HTLC this peer offered.
    Preimage {
        /// Payment hash.
        hash: Bytes32,
        /// Its preimage.
        preimage: Bytes32,
    },
    /// Hitch's `io.onPayment` for an HTLC this peer offered.
    Payment {
        /// Payment hash.
        hash: Bytes32,
        /// What happened.
        outcome: PaymentOutcome,
        /// Hitch's reason text, when it gives one.
        reason: Option<String>,
    },
}

/// Why a peer message or state transition was refused.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// Wire field had the wrong shape; the text is Hitch's reason.
    #[error("malformed message: {0}")]
    Malformed(&'static str),
    /// Message named another channel.
    #[error("message is for another channel")]
    WrongChannel,
    /// Secret channel key does not match this machine's A/B role.
    #[error("channel key does not match this peer's role")]
    WrongChannelKey,
    /// Snapshot version is not the one this implementation reads.
    #[error("unsupported channel snapshot version {0}")]
    SnapshotVersion(u8),
    /// Persisted state failed an internal consistency check.
    #[error("corrupt channel snapshot: {0}")]
    CorruptSnapshot(&'static str),
    /// Funding output index does not fit Hitch's two-byte wire boundary.
    #[error("funding output index exceeds 65535")]
    FundingVout,
    /// Opening value is outside Hitch's channel bounds.
    #[error("funding value is below {MIN_OPEN} sats or above 21 million coins")]
    FundingValue,
    /// A peer tried to open a channel with itself.
    #[error("the two channel peers must differ")]
    SamePeer,
    /// Push would leave the funder without both its fee and a non-dust output.
    #[error("push must leave the funder its fee and dust")]
    BadPush,
    /// Authenticated sender or addressed recipient does not match the message.
    #[error("opening message peer does not match its authenticated envelope")]
    WrongPeer,
    /// Receiver policy requires a longer channel delay.
    #[error("channel delay is below the receiver's minimum")]
    DelayBelowPolicy,
    /// Hub routing fee lies outside Hitch's wire boundary.
    #[error("hub fee exceeds 100000 sats")]
    HubFee,
    /// A revocation point came without a valid proof of possession.
    #[error("a revocation point comes without proof of its secret")]
    MissingProof,
    /// The channel's lifecycle does not allow this.
    #[error("the channel is {0}")]
    Status(&'static str),
    /// A different state number was expected.
    #[error("state {got}, expected {expected}")]
    UnexpectedState {
        /// Received state number.
        got: u64,
        /// Required state number.
        expected: u64,
    },
    /// Another local update is still pending.
    #[error("an update is already pending")]
    Pending,
    /// No local update matches the message.
    #[error("no matching update is pending")]
    NoPending,
    /// This peer waits for the previous-state secret.
    #[error("waiting for their revocation of the previous state")]
    AwaitingRevocation,
    /// An update or close is in flight.
    #[error("an update is in flight; try again when it settles")]
    InFlight,
    /// Counterparty revocation secret is missing.
    #[error("their revocation secret for state {0} is missing; resyncing first")]
    MissingReveal(u64),
    /// Revocation point was not announced.
    #[error("revocation key for state {0} is missing")]
    MissingRevocationKey(u64),
    /// State document was not retained.
    #[error("state {0} is missing")]
    MissingState(u64),
    /// Counterparty signature for a commitment state is absent.
    #[error("state {0} was never signed by them")]
    MissingSignature(u64),
    /// Schnorr signature did not authorise the derived commitment.
    #[error("signature on the commitment does not verify")]
    BadSignature,
    /// Revealed secret does not match the announced per-state point.
    #[error("revealed secret is not the announced revocation key")]
    BadRevocation,
    /// The host's chain view is stale; HTLC decisions wait.
    #[error("my view of the chain is stale; HTLCs wait until it returns")]
    StaleChain,
    /// The payment hash still has force on this channel.
    #[error("that payment hash is still bound on this channel ({0})")]
    HashBound(Bound),
    /// A payment exceeds the spendable balance.
    #[error("at most {0} sat")]
    TooMuch(u64),
    /// Payment amount was zero.
    #[error("payment amount must be positive")]
    ZeroAmount,
    /// Memo or failure reason exceeded Hitch's boundary.
    #[error("a memo is at most {MEMO_MAX} characters")]
    MemoTooLong,
    /// HTLC amount was below Hitch's floor.
    #[error("HTLC amount is below {MIN_HTLC} sats")]
    HtlcTooSmall,
    /// HTLC expiry is outside the allowed block-height range.
    #[error("bad HTLC expiry")]
    BadExpiry,
    /// HTLC id did not follow the channel's sequence.
    #[error("bad htlc id")]
    BadHtlcId,
    /// Absolute expiry leaves insufficient safety margin.
    #[error("the htlc would expire too soon")]
    ExpiryTooSoon,
    /// Another HTLC already uses the payment hash.
    #[error("an htlc with that hash is already in flight")]
    DuplicatePaymentHash,
    /// Update spends more than the sender's free balance.
    #[error("a balance would go negative")]
    NegativeBalance,
    /// Balance arithmetic overflowed.
    #[error("balance overflow")]
    BalanceOverflow,
    /// A state leaving the funder below its fee cannot be mined; never signed.
    #[error("the funder must keep its fee")]
    FunderFee,
    /// No in-flight HTLC has that id.
    #[error("no such htlc")]
    NoSuchHtlc,
    /// The offerer tried to settle its own HTLC.
    #[error("the offerer cannot settle")]
    OffererCannotSettle,
    /// Preimage does not match the payment hash.
    #[error("wrong preimage")]
    WrongPreimage,
    /// Off-chain settlement came at or after expiry.
    #[error("the htlc has expired; it settles on the chain or not at all")]
    HtlcExpired,
    /// Offerer tried to fail before expiry.
    #[error("the offerer may fail only after the expiry")]
    OffererFailBeforeExpiry,
    /// Receiver already knows the preimage and must retain its claim.
    #[error("I hold the preimage: it settles, on the chain if need be")]
    KnownPreimage,
    /// The funding is not confirmed; there is nothing to close yet.
    #[error("the funding is not confirmed; there is nothing to close yet")]
    Unfunded,
    /// Transaction-layer construction failed.
    #[error(transparent)]
    Channel(#[from] crate::Error),
}

impl ProtocolError {
    /// Whether Hitch's router would retry the call shortly: the error names
    /// a pending update, a missing revocation or a resync in progress.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Pending | Self::AwaitingRevocation | Self::MissingReveal(_)
        )
    }
}

pub(crate) fn public(secret: &SecretKey) -> XOnlyPublicKey {
    Keypair::from_secret_key(secp(), secret)
        .x_only_public_key()
        .0
}

pub(crate) fn secret(bytes: Bytes32) -> Result<SecretKey, ProtocolError> {
    SecretKey::from_slice(&bytes.0).map_err(|_| ProtocolError::BadRevocation)
}

pub(crate) fn sha(preimage: &[u8; 32]) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash};
    sha256::Hash::hash(preimage).to_byte_array()
}

pub(crate) fn node_less(a: XOnlyPublicKey, b: XOnlyPublicKey) -> bool {
    a.serialize() < b.serialize()
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

pub(crate) fn decode_hex(text: &str, output: &mut [u8]) -> Option<()> {
    if text.len() != output.len() * 2 {
        return None;
    }
    for (target, pair) in output.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *target = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(())
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// The context string a proof of possession signs: the channel, the role
/// that owns the point, and `base` or the state number.
pub(crate) fn pop_context(id: ChannelId, owner: WireSide, place: PopPlace) -> String {
    let role = match owner {
        WireSide::A => "a",
        WireSide::B => "b",
    };
    match place {
        PopPlace::Base => format!("{id}/{role}/base"),
        PopPlace::State(n) => format!("{id}/{role}/{n}"),
    }
}

/// Where an announced revocation point sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PopPlace {
    Base,
    State(u64),
}

#[cfg(test)]
mod tests;
