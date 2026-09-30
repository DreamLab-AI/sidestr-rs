//! Hitch's off-chain update handshake as a pure state machine.
//!
//! A channel update has three messages. The proposer signs the receiver's
//! next commitment in [`UpdateMessage`]. The receiver verifies the whole
//! proposed state, signs the proposer's commitment and reveals its previous
//! revocation secret in [`AckMessage`]. The proposer checks both, advances,
//! and reveals its own previous secret in [`RevokeMessage`]. The receiver
//! treats the update as final only after that last reveal. This is the safety
//! boundary Hitch's router and user notifications rely on.
//!
//! The machine also preserves a commitment it signed during simultaneous
//! proposals. The lexicographically lower node id wins the collision; the
//! loser retains the alternative state until the winner's matching state
//! number is revoked, because the winner could still publish that signed
//! transaction.

use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, SecretKey, XOnlyPublicKey};
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, Txid};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    claim_htlc, sweep_to_local, Balances, Channel, ChannelState, Htlc, HtlcClaim, HtlcClaimPath,
    LeafSignature, RevocationKeys, Side, SweepPath, DUST, MAX_EXPIRY,
};
use sidestr_core::block::secp;
use sidestr_core::sighash::SighashRules;

/// Nostr event kind used by Hitch channel messages.
pub const KIND: u16 = 23_600;
/// Smallest channel Hitch opens, in satoshis.
pub const MIN_OPEN: u64 = 10_000;
/// Smallest HTLC Hitch accepts, in satoshis.
pub const MIN_HTLC: u64 = 1_000;
/// Extra blocks an off-chain HTLC keeps beyond the channel CSV delay.
pub const EXPIRY_MARGIN: u32 = 12;
/// Longest memo and failure-reason string in JavaScript UTF-16 code units.
pub const MEMO_MAX: usize = 140;

/// Eight bytes carried as the first sixteen hex characters of the funding
/// transaction id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChannelId(pub [u8; 8]);

impl ChannelId {
    /// Parse Hitch's sixteen-character lower-case identifier.
    pub fn from_hex(text: &str) -> std::result::Result<Self, ProtocolError> {
        let mut bytes = [0u8; 8];
        decode_hex(text, &mut bytes).ok_or(ProtocolError::Malformed("bad id"))?;
        Ok(Self(bytes))
    }

    /// Lower-case wire representation.
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }

    /// Derive Hitch's short id from the display-order funding transaction id.
    pub fn from_txid(txid: Txid) -> Self {
        let text = txid.to_string();
        Self::from_hex(&text[..16]).expect("a txid begins with sixteen hex characters")
    }
}

impl Serialize for ChannelId {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ChannelId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

/// A validated x-only node or revocation public key, encoded as 64 lower-case
/// hex characters on Hitch's wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub XOnlyPublicKey);

impl Serialize for NodeId {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() != 64
            || text
                .as_bytes()
                .iter()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(byte))
        {
            return Err(serde::de::Error::custom("bad x-only key"));
        }
        XOnlyPublicKey::from_str(&text)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// Exactly 32 bytes encoded as 64 lower-case hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes32(pub [u8; 32]);

impl Serialize for Bytes32 {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes32 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let mut bytes = [0u8; 32];
        decode_hex(&text, &mut bytes).ok_or_else(|| serde::de::Error::custom("bad 32-byte hex"))?;
        Ok(Self(bytes))
    }
}

impl Serialize for LeafSignature {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for LeafSignature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        LeafSignature::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

/// Optional next hop carried on an HTLC offered to a hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// Destination node with which the hub must already have a channel.
    pub to: NodeId,
}

/// An HTLC in the off-chain protocol, including the optional routing hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolHtlc {
    /// Monotonic id within the channel.
    pub id: u64,
    /// Protocol role of the offerer.
    pub from: WireSide,
    /// Satoshis locked in the output.
    pub amount: u64,
    /// SHA-256 payment hash.
    pub hash: Bytes32,
    /// Absolute timeout height.
    pub expiry: u32,
    /// One-hop destination for a hub, absent on the downstream HTLC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<Route>,
}

impl ProtocolHtlc {
    fn channel_htlc(&self) -> Htlc {
        Htlc {
            id: self.id,
            from: self.from.into(),
            amount: Amount::from_sat(self.amount),
            payment_hash: self.hash.0,
            expiry: self.expiry,
        }
    }
}

/// HTLC fields sent in an `add` update.
///
/// The offerer's side is deliberately absent from Hitch's wire format. Both
/// peers derive it from the authenticated message sender, which prevents a
/// proposer from assigning the output to the wrong commitment branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferedHtlc {
    /// Monotonic id within the channel. [`ChannelMachine::propose`] replaces
    /// this with the next id before signing.
    pub id: u64,
    /// Satoshis locked in the output.
    pub amount: u64,
    /// SHA-256 payment hash.
    pub hash: Bytes32,
    /// Absolute timeout height.
    pub expiry: u32,
    /// One-hop destination for a hub, absent on the downstream HTLC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<Route>,
}

/// A/B role encoded as the one-character strings Hitch uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WireSide {
    /// Funder.
    A,
    /// Other peer.
    B,
}

impl From<Side> for WireSide {
    fn from(side: Side) -> Self {
        match side {
            Side::A => Self::A,
            Side::B => Self::B,
        }
    }
}

impl From<WireSide> for Side {
    fn from(side: WireSide) -> Self {
        match side {
            WireSide::A => Self::A,
            WireSide::B => Self::B,
        }
    }
}

/// The deterministic state change both peers independently compute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Update {
    /// Direct balance transfer.
    Pay {
        /// Satoshis sent to the other peer.
        amount: u64,
        /// Human-readable note, never part of the on-chain transaction.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        memo: Option<String>,
    },
    /// Add an HTLC.
    Add {
        /// HTLC including the id allocated by the proposer.
        htlc: OfferedHtlc,
        /// Human-readable note.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        memo: Option<String>,
    },
    /// Settle an HTLC with its preimage.
    Settle {
        /// HTLC id.
        #[serde(rename = "htlcId")]
        htlc_id: u64,
        /// Payment preimage.
        preimage: Bytes32,
    },
    /// Remove an HTLC and return its value to the offerer.
    Fail {
        /// HTLC id.
        #[serde(rename = "htlcId")]
        htlc_id: u64,
        /// Display reason.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

/// `t=update`: proposer signature and its next revocation public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateMessage {
    /// Literal message discriminator.
    pub t: UpdateTag,
    /// Channel id.
    pub id: ChannelId,
    /// Proposed state number.
    pub n: u64,
    /// State transition fields at the top level, as in Hitch.
    #[serde(flatten)]
    pub update: Update,
    /// Proposer's signature on the receiver's new commitment.
    pub sig: LeafSignature,
    /// Proposer's revocation public key one state ahead.
    #[serde(rename = "nextRev")]
    pub next_rev: NodeId,
}

/// Serde discriminator that only accepts the string `"update"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateTag {
    /// Update message.
    #[serde(rename = "update")]
    Update,
}

/// `t=ack`: receiver signature, previous secret and next public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AckMessage {
    /// Literal message discriminator.
    pub t: AckTag,
    /// Channel id.
    pub id: ChannelId,
    /// State being acknowledged.
    pub n: u64,
    /// Receiver's signature on the proposer's new commitment.
    pub sig: LeafSignature,
    /// Receiver's secret for the previous state.
    pub reveal: Bytes32,
    /// Receiver's revocation public key one state ahead.
    #[serde(rename = "nextRev")]
    pub next_rev: NodeId,
}

/// Serde discriminator that only accepts the string `"ack"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AckTag {
    /// Acknowledgement message.
    #[serde(rename = "ack")]
    Ack,
}

/// `t=revoke`: proposer's previous revocation secret, which makes the
/// receiver's accepted update final.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeMessage {
    /// Literal message discriminator.
    pub t: RevokeTag,
    /// Channel id.
    pub id: ChannelId,
    /// New state number.
    pub n: u64,
    /// Proposer's secret for state `n - 1`.
    pub reveal: Bytes32,
}

/// Serde discriminator that only accepts the string `"revoke"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevokeTag {
    /// Revocation message.
    #[serde(rename = "revoke")]
    Revoke,
}

/// Funding output named in an opening proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundingOffer {
    /// Display-order transaction id.
    #[serde(
        serialize_with = "serialize_txid",
        deserialize_with = "deserialize_txid"
    )]
    pub txid: Txid,
    /// Funding output index.
    pub vout: u32,
    /// Funding value in satoshis.
    pub value: u64,
}

/// `t=open`: A's channel parameters and first two revocation public keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenMessage {
    /// Literal message discriminator.
    pub t: OpenTag,
    /// First sixteen characters of the funding transaction id.
    pub id: ChannelId,
    /// Funding outpoint and value.
    pub funding: FundingOffer,
    /// Value assigned to B in state zero.
    #[serde(default)]
    pub push: u64,
    /// Relative delay for commitment-owner claims.
    pub delay: u16,
    /// Fixed transaction fee paid by A.
    pub fee: u64,
    /// Funder node key.
    pub a: NodeId,
    /// Receiving node key.
    pub b: NodeId,
    /// A's revocation public keys for states zero and one.
    pub rev: [NodeId; 2],
    /// Optional one-hop routing fee advertised by a hub.
    #[serde(rename = "hubFee", default, skip_serializing_if = "Option::is_none")]
    pub hub_fee: Option<u64>,
}

/// Serde discriminator that only accepts the string `"open"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpenTag {
    /// Opening proposal.
    #[serde(rename = "open")]
    Open,
}

/// `t=accept`: B's first keys and signature on A's initial commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptMessage {
    /// Literal message discriminator.
    pub t: AcceptTag,
    /// Channel id.
    pub id: ChannelId,
    /// B's revocation public keys for states zero and one.
    pub rev: [NodeId; 2],
    /// B's signature on A's state-zero commitment.
    pub sig: LeafSignature,
    /// Optional one-hop routing fee advertised by a hub.
    #[serde(rename = "hubFee", default, skip_serializing_if = "Option::is_none")]
    pub hub_fee: Option<u64>,
}

/// Serde discriminator that only accepts the string `"accept"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcceptTag {
    /// Opening acceptance.
    #[serde(rename = "accept")]
    Accept,
}

/// `t=commit`: A's signature on B's initial commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitMessage {
    /// Literal message discriminator.
    pub t: CommitTag,
    /// Channel id.
    pub id: ChannelId,
    /// A's signature on B's state-zero commitment.
    pub sig: LeafSignature,
}

/// Serde discriminator that only accepts the string `"commit"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitTag {
    /// Commitment signature.
    #[serde(rename = "commit")]
    Commit,
}

/// `t=ready`: B confirms that both initial commitments are signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadyMessage {
    /// Literal message discriminator.
    pub t: ReadyTag,
    /// Channel id.
    pub id: ChannelId,
}

/// Serde discriminator that only accepts the string `"ready"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReadyTag {
    /// Initial commitments are ready.
    #[serde(rename = "ready")]
    Ready,
}

/// `t=close`: signature on the cooperative close at the current state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseMessage {
    /// Literal message discriminator.
    pub t: CloseTag,
    /// Channel id.
    pub id: ChannelId,
    /// State being closed.
    pub n: u64,
    /// Sender signature on the cooperative-close transaction.
    pub sig: LeafSignature,
}

/// Serde discriminator that only accepts the string `"close"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloseTag {
    /// Cooperative close request.
    #[serde(rename = "close")]
    Close,
}

/// `t=sync|synced`: persisted position and revocation recovery data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncMessage {
    /// Request or response discriminator.
    pub t: SyncTag,
    /// Channel id.
    pub id: ChannelId,
    /// Current state number.
    pub n: u64,
    /// Host lifecycle status, carried through without interpretation.
    pub status: String,
    /// Locally pending proposal, or `null`.
    #[serde(rename = "pendingN")]
    pub pending_n: Option<u64>,
    /// Previous-state secret repeated by a peer at state one or later.
    pub reveal: Option<Bytes32>,
    /// State numbers for which the sender lacks our secret.
    #[serde(default)]
    pub missing: Vec<u64>,
    /// Requested historical secrets, present on a `synced` response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reveals: Option<BTreeMap<u64, Bytes32>>,
}

/// Sync request or response tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncTag {
    /// Recovery request.
    #[serde(rename = "sync")]
    Sync,
    /// Recovery response.
    #[serde(rename = "synced")]
    Synced,
}

/// Free balances and in-flight HTLCs, without revocation keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolState {
    /// A's free balance.
    pub balance_a: u64,
    /// B's free balance.
    pub balance_b: u64,
    /// In-flight HTLCs.
    pub htlcs: Vec<ProtocolHtlc>,
}

/// A pending locally proposed update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingUpdate {
    /// Proposed state number.
    pub n: u64,
    /// Transition that produced it.
    pub update: Update,
    /// Signed wire message to send or retry.
    pub message: UpdateMessage,
}

/// An incoming update that has been acknowledged but is not final until the
/// sender's previous-state secret arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwaitingRevoke {
    /// New state number.
    pub n: u64,
    /// Previous state whose secret is owed.
    pub previous: u64,
    /// Verified update.
    pub update: Update,
    /// Sender role.
    pub sender: Side,
}

/// A verified update that crossed its finality boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalisedUpdate {
    /// New state number.
    pub n: u64,
    /// Transition now safe to act upon.
    pub update: Update,
    /// Peer who proposed it.
    pub sender: Side,
}

/// Classification of a transaction spending the channel funding output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FundingSpend {
    /// Current cooperative-close transaction.
    Cooperative,
    /// One of this peer's commitment transactions.
    LocalCommitment {
        /// Commitment state number.
        state: u64,
    },
    /// A counterparty commitment, including a state signed during a
    /// simultaneous-update collision.
    RemoteCommitment {
        /// Commitment state number.
        state: u64,
        /// Position in [`ChannelMachine::signed_alternatives`], or `None` for
        /// the agreed state at that number.
        alternative: Option<usize>,
        /// Whether the counterparty has revealed this state's secret.
        revoked: bool,
    },
    /// Transaction is not one of the closes retained by this machine.
    Unknown,
}

/// Result of receiving an update during normal operation or a collision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveUpdate {
    /// Incoming update won and must be answered with this acknowledgement.
    Acknowledge(AckMessage),
    /// Local pending update belongs to the lower node id and remains binding.
    LocalProposalWins,
    /// The same accepted update arrived again; resend this acknowledgement.
    ResendAcknowledgement(AckMessage),
    /// A next update arrived before the prior revocation and was retained for
    /// processing after finality.
    Buffered,
}

/// Secret material generated by one peer for the opening handshake.
pub struct OpeningKeys {
    /// Static channel signing key, whose public half is the node id.
    pub channel: SecretKey,
    /// Revocation secrets for states zero and one.
    pub revocation: [SecretKey; 2],
}

/// Parameters chosen by the funder after its wallet builds the funding
/// transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenParams {
    /// Funding transaction output.
    pub funding: OutPoint,
    /// Value in the funding output.
    pub funding_value: Amount,
    /// Value assigned to B in state zero.
    pub push: Amount,
    /// Relative delay for commitment-owner claims.
    pub delay: u16,
    /// Fixed per-transaction channel fee.
    pub fee: Amount,
    /// Optional routing fee advertised by a hub.
    pub hub_fee: Option<u64>,
}

/// Receiver policy applied before it signs an opening proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptPolicy {
    /// Smallest CSV delay this receiver accepts.
    pub min_delay: u16,
    /// Optional routing fee advertised by this receiver when it is a hub.
    pub hub_fee: Option<u64>,
}

impl Default for AcceptPolicy {
    fn default() -> Self {
        Self {
            min_delay: crate::MIN_DELAY,
            hub_fee: None,
        }
    }
}

/// Funder state before B's acceptance is checked.
pub struct FunderOpening {
    id: ChannelId,
    channel: Channel,
    channel_key: SecretKey,
    initial_state: ProtocolState,
    my_revocation: [SecretKey; 2],
    rules: SighashRules,
}

/// Funder state after it has verified B's initial signature.
pub struct AcceptedFunder {
    opening: FunderOpening,
    their_revocation: [XOnlyPublicKey; 2],
    their_signature_zero: LeafSignature,
}

/// Receiver state after it has signed A's initial commitment.
pub struct ReceiverOpening {
    id: ChannelId,
    channel: Channel,
    channel_key: SecretKey,
    initial_state: ProtocolState,
    my_revocation: [SecretKey; 2],
    their_revocation: [XOnlyPublicKey; 2],
    rules: SighashRules,
}

/// Versioned durable state for an open channel.
///
/// Its serialised form contains the channel signing key, revocation secrets
/// and payment preimages. Hosts must protect it as wallet key material and
/// persist it atomically before sending the corresponding wire message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSnapshot {
    version: u8,
    id: ChannelId,
    role: WireSide,
    channel_key: Bytes32,
    channel: SnapshotChannel,
    state_number: u64,
    states: BTreeMap<u64, ProtocolState>,
    my_revocation: BTreeMap<u64, Bytes32>,
    their_revocation: BTreeMap<u64, Bytes32>,
    their_revocation_public: BTreeMap<u64, NodeId>,
    signatures: BTreeMap<u64, LeafSignature>,
    pending: Option<PendingUpdate>,
    awaiting: Option<SnapshotAwaiting>,
    buffered: Option<UpdateMessage>,
    signed_alternatives: BTreeMap<u64, Vec<ProtocolState>>,
    preimages: BTreeMap<Bytes32, Bytes32>,
    rules: SnapshotRules,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SnapshotChannel {
    keys: [NodeId; 2],
    funding: FundingOffer,
    fee: u64,
    delay: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SnapshotAwaiting {
    n: u64,
    previous: u64,
    update: Update,
    sender: WireSide,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SnapshotRules {
    Bip341,
    KnotsUnified,
}

impl FunderOpening {
    /// Construct and validate an `open` message from a wallet-selected funding
    /// outpoint. The wallet remains responsible for broadcasting and watching
    /// the funding transaction.
    pub fn propose(
        params: OpenParams,
        keys: OpeningKeys,
        peer: XOnlyPublicKey,
        rules: SighashRules,
    ) -> std::result::Result<(Self, OpenMessage), ProtocolError> {
        validate_hub_fee(params.hub_fee)?;
        if params.funding.vout > u32::from(u16::MAX) {
            return Err(ProtocolError::FundingVout);
        }
        if params.funding_value.to_sat() < MIN_OPEN {
            return Err(ProtocolError::FundingTooSmall);
        }
        let mine = public(&keys.channel);
        if mine == peer {
            return Err(ProtocolError::SamePeer);
        }
        validate_push(params.funding_value, params.push, params.fee)?;
        let channel = Channel::new(
            mine,
            peer,
            params.funding,
            params.funding_value,
            params.fee,
            params.delay,
        )?;
        let id = ChannelId::from_txid(params.funding.txid);
        let initial_state = initial_state(params.funding_value, params.push)?;
        let message = OpenMessage {
            t: OpenTag::Open,
            id,
            funding: FundingOffer {
                txid: params.funding.txid,
                vout: params.funding.vout,
                value: params.funding_value.to_sat(),
            },
            push: params.push.to_sat(),
            delay: params.delay,
            fee: params.fee.to_sat(),
            a: NodeId(mine),
            b: NodeId(peer),
            rev: [
                NodeId(public(&keys.revocation[0])),
                NodeId(public(&keys.revocation[1])),
            ],
            hub_fee: params.hub_fee,
        };
        Ok((
            Self {
                id,
                channel,
                channel_key: keys.channel,
                initial_state,
                my_revocation: keys.revocation,
                rules,
            },
            message,
        ))
    }

    /// Verify B's signature on A's initial commitment and sign B's matching
    /// commitment.
    pub fn accept(
        self,
        message: AcceptMessage,
        aux: &[u8; 32],
    ) -> std::result::Result<(AcceptedFunder, CommitMessage), ProtocolError> {
        if message.id != self.id {
            return Err(ProtocolError::WrongChannel);
        }
        validate_hub_fee(message.hub_fee)?;
        let theirs = [message.rev[0].0, message.rev[1].0];
        let state = opening_channel_state(
            &self.initial_state,
            public(&self.my_revocation[0]),
            theirs[0],
        );
        let mine = self.channel.commitment(0, Side::A, &state)?;
        if !self.channel.verify_funding(
            &mine.tx,
            &self.channel.key(Side::B),
            &message.sig,
            self.rules,
        ) {
            return Err(ProtocolError::BadSignature);
        }
        let theirs_commitment = self.channel.commitment(0, Side::B, &state)?;
        let signature =
            self.channel
                .sign_funding(&theirs_commitment.tx, &self.channel_key, self.rules, aux)?;
        let commit = CommitMessage {
            t: CommitTag::Commit,
            id: self.id,
            sig: signature,
        };
        Ok((
            AcceptedFunder {
                opening: self,
                their_revocation: theirs,
                their_signature_zero: message.sig,
            },
            commit,
        ))
    }
}

impl AcceptedFunder {
    /// Consume B's readiness acknowledgement and enter the update state
    /// machine. The funding transaction may now be broadcast by the host.
    pub fn ready(
        self,
        message: ReadyMessage,
    ) -> std::result::Result<ChannelMachine, ProtocolError> {
        if message.id != self.opening.id {
            return Err(ProtocolError::WrongChannel);
        }
        ChannelMachine::new(
            self.opening.id,
            Side::A,
            self.opening.channel_key,
            self.opening.channel,
            self.opening.initial_state,
            self.opening.my_revocation[0],
            self.opening.my_revocation[1],
            self.their_revocation[0],
            self.their_revocation[1],
            self.their_signature_zero,
            self.opening.rules,
        )
    }
}

impl ReceiverOpening {
    /// Validate A's authenticated proposal and return B's signature on A's
    /// initial commitment.
    pub fn accept(
        message: OpenMessage,
        authenticated_sender: XOnlyPublicKey,
        keys: OpeningKeys,
        rules: SighashRules,
        policy: AcceptPolicy,
        aux: &[u8; 32],
    ) -> std::result::Result<(Self, AcceptMessage), ProtocolError> {
        validate_open(
            &message,
            authenticated_sender,
            public(&keys.channel),
            policy,
        )?;
        let outpoint = OutPoint {
            txid: message.funding.txid,
            vout: message.funding.vout,
        };
        let value = Amount::from_sat(message.funding.value);
        let channel = Channel::new(
            message.a.0,
            message.b.0,
            outpoint,
            value,
            Amount::from_sat(message.fee),
            message.delay,
        )?;
        let state = initial_state(value, Amount::from_sat(message.push))?;
        let mine = [public(&keys.revocation[0]), public(&keys.revocation[1])];
        let theirs = [message.rev[0].0, message.rev[1].0];
        let full = opening_channel_state(&state, theirs[0], mine[0]);
        let commitment = channel.commitment(0, Side::A, &full)?;
        let signature = channel.sign_funding(&commitment.tx, &keys.channel, rules, aux)?;
        let id = message.id;
        let response = AcceptMessage {
            t: AcceptTag::Accept,
            id,
            rev: [NodeId(mine[0]), NodeId(mine[1])],
            sig: signature,
            hub_fee: policy.hub_fee,
        };
        Ok((
            Self {
                id,
                channel,
                channel_key: keys.channel,
                initial_state: state,
                my_revocation: keys.revocation,
                their_revocation: theirs,
                rules,
            },
            response,
        ))
    }

    /// Verify A's signature on B's initial commitment and enter the update
    /// state machine.
    pub fn commit(
        self,
        message: CommitMessage,
    ) -> std::result::Result<(ChannelMachine, ReadyMessage), ProtocolError> {
        if message.id != self.id {
            return Err(ProtocolError::WrongChannel);
        }
        let full = opening_channel_state(
            &self.initial_state,
            self.their_revocation[0],
            public(&self.my_revocation[0]),
        );
        let commitment = self.channel.commitment(0, Side::B, &full)?;
        if !self.channel.verify_funding(
            &commitment.tx,
            &self.channel.key(Side::A),
            &message.sig,
            self.rules,
        ) {
            return Err(ProtocolError::BadSignature);
        }
        let ready = ReadyMessage {
            t: ReadyTag::Ready,
            id: self.id,
        };
        let machine = ChannelMachine::new(
            self.id,
            Side::B,
            self.channel_key,
            self.channel,
            self.initial_state,
            self.my_revocation[0],
            self.my_revocation[1],
            self.their_revocation[0],
            self.their_revocation[1],
            message.sig,
            self.rules,
        )?;
        Ok((machine, ready))
    }
}

/// One peer's pure update-handshake state.
#[derive(Debug, Clone)]
pub struct ChannelMachine {
    id: ChannelId,
    role: Side,
    channel_key: SecretKey,
    channel: Channel,
    state_number: u64,
    states: BTreeMap<u64, ProtocolState>,
    my_revocation: BTreeMap<u64, SecretKey>,
    my_revocation_public: BTreeMap<u64, XOnlyPublicKey>,
    their_revocation: BTreeMap<u64, SecretKey>,
    their_revocation_public: BTreeMap<u64, XOnlyPublicKey>,
    signatures: BTreeMap<u64, LeafSignature>,
    pending: Option<PendingUpdate>,
    awaiting: Option<AwaitingRevoke>,
    buffered: Option<UpdateMessage>,
    signed_alternatives: BTreeMap<u64, Vec<ProtocolState>>,
    preimages: BTreeMap<[u8; 32], [u8; 32]>,
    rules: SighashRules,
}

impl ChannelMachine {
    /// Begin at state zero after the opening handshake has exchanged each
    /// side's first two revocation public keys and the remote signature on
    /// this peer's initial commitment.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: ChannelId,
        role: Side,
        channel_key: SecretKey,
        channel: Channel,
        initial_state: ProtocolState,
        my_revocation_zero: SecretKey,
        my_revocation_one: SecretKey,
        their_revocation_zero: XOnlyPublicKey,
        their_revocation_one: XOnlyPublicKey,
        their_signature_zero: LeafSignature,
        rules: SighashRules,
    ) -> std::result::Result<Self, ProtocolError> {
        let my_public = public(&channel_key);
        if my_public != channel.key(role) {
            return Err(ProtocolError::WrongChannelKey);
        }
        let mut machine = Self {
            id,
            role,
            channel_key,
            channel,
            state_number: 0,
            states: BTreeMap::from([(0, initial_state)]),
            my_revocation: BTreeMap::from([(0, my_revocation_zero), (1, my_revocation_one)]),
            my_revocation_public: BTreeMap::new(),
            their_revocation: BTreeMap::new(),
            their_revocation_public: BTreeMap::from([
                (0, their_revocation_zero),
                (1, their_revocation_one),
            ]),
            signatures: BTreeMap::from([(0, their_signature_zero)]),
            pending: None,
            awaiting: None,
            buffered: None,
            signed_alternatives: BTreeMap::new(),
            preimages: BTreeMap::new(),
            rules,
        };
        machine.refresh_my_public();
        let initial = machine.commitment_for(role, 0, machine.state(0)?)?;
        if !machine.channel.verify_funding(
            &initial.tx,
            &machine.peer_key(),
            &their_signature_zero,
            rules,
        ) {
            return Err(ProtocolError::BadSignature);
        }
        Ok(machine)
    }

    /// Capture all state needed to recover safely after a restart.
    pub fn snapshot(&self) -> ChannelSnapshot {
        ChannelSnapshot {
            version: 1,
            id: self.id,
            role: self.role.into(),
            channel_key: Bytes32(self.channel_key.secret_bytes()),
            channel: SnapshotChannel {
                keys: [
                    NodeId(self.channel.key(Side::A)),
                    NodeId(self.channel.key(Side::B)),
                ],
                funding: FundingOffer {
                    txid: self.channel.funding_outpoint.txid,
                    vout: self.channel.funding_outpoint.vout,
                    value: self.channel.funding_value.to_sat(),
                },
                fee: self.channel.fee.to_sat(),
                delay: self.channel.delay,
            },
            state_number: self.state_number,
            states: self.states.clone(),
            my_revocation: self
                .my_revocation
                .iter()
                .map(|(n, secret)| (*n, Bytes32(secret.secret_bytes())))
                .collect(),
            their_revocation: self
                .their_revocation
                .iter()
                .map(|(n, secret)| (*n, Bytes32(secret.secret_bytes())))
                .collect(),
            their_revocation_public: self
                .their_revocation_public
                .iter()
                .map(|(n, key)| (*n, NodeId(*key)))
                .collect(),
            signatures: self.signatures.clone(),
            pending: self.pending.clone(),
            awaiting: self.awaiting.as_ref().map(|awaiting| SnapshotAwaiting {
                n: awaiting.n,
                previous: awaiting.previous,
                update: awaiting.update.clone(),
                sender: awaiting.sender.into(),
            }),
            buffered: self.buffered.clone(),
            signed_alternatives: self.signed_alternatives.clone(),
            preimages: self
                .preimages
                .iter()
                .map(|(hash, preimage)| (Bytes32(*hash), Bytes32(*preimage)))
                .collect(),
            rules: self.rules.into(),
        }
    }

    /// Restore a snapshot only after verifying its key relationships,
    /// accounting and every retained counterparty signature.
    pub fn restore(snapshot: ChannelSnapshot) -> std::result::Result<Self, ProtocolError> {
        if snapshot.version != 1 {
            return Err(ProtocolError::SnapshotVersion(snapshot.version));
        }
        let channel_key = secret(snapshot.channel_key)?;
        let channel = Channel::new(
            snapshot.channel.keys[0].0,
            snapshot.channel.keys[1].0,
            OutPoint {
                txid: snapshot.channel.funding.txid,
                vout: snapshot.channel.funding.vout,
            },
            Amount::from_sat(snapshot.channel.funding.value),
            Amount::from_sat(snapshot.channel.fee),
            snapshot.channel.delay,
        )?;
        let my_revocation = decode_secret_map(snapshot.my_revocation)?;
        let their_revocation = decode_secret_map(snapshot.their_revocation)?;
        let mut machine = Self {
            id: snapshot.id,
            role: snapshot.role.into(),
            channel_key,
            channel,
            state_number: snapshot.state_number,
            states: snapshot.states,
            my_revocation,
            my_revocation_public: BTreeMap::new(),
            their_revocation,
            their_revocation_public: snapshot
                .their_revocation_public
                .into_iter()
                .map(|(n, key)| (n, key.0))
                .collect(),
            signatures: snapshot.signatures,
            pending: snapshot.pending,
            awaiting: snapshot.awaiting.map(|awaiting| AwaitingRevoke {
                n: awaiting.n,
                previous: awaiting.previous,
                update: awaiting.update,
                sender: awaiting.sender.into(),
            }),
            buffered: snapshot.buffered,
            signed_alternatives: snapshot.signed_alternatives,
            preimages: snapshot
                .preimages
                .into_iter()
                .map(|(hash, preimage)| (hash.0, preimage.0))
                .collect(),
            rules: snapshot.rules.into(),
        };
        machine.refresh_my_public();
        machine.validate_snapshot()?;
        Ok(machine)
    }

    /// Current agreed state number.
    pub fn state_number(&self) -> u64 {
        self.state_number
    }

    /// Current free balances and HTLCs.
    pub fn current_state(&self) -> &ProtocolState {
        self.states
            .get(&self.state_number)
            .expect("current state is always present")
    }

    /// Pending locally proposed update, if any.
    pub fn pending(&self) -> Option<&PendingUpdate> {
        self.pending.as_ref()
    }

    /// Incoming update still waiting for the proposer's revocation.
    pub fn awaiting_revoke(&self) -> Option<&AwaitingRevoke> {
        self.awaiting.as_ref()
    }

    /// Take an update held while the preceding state awaited its revocation.
    /// Call this after [`Self::receive_revoke`] or [`Self::apply_sync`]
    /// finalises that state, then pass it back to [`Self::receive_update`].
    pub fn take_buffered_update(&mut self) -> Option<UpdateMessage> {
        if self.awaiting.is_none() {
            self.buffered.take()
        } else {
            None
        }
    }

    /// Alternative states this peer signed during a collision.
    pub fn signed_alternatives(&self, n: u64) -> &[ProtocolState] {
        self.signed_alternatives
            .get(&n)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Whether the counterparty's secret for state `n` is known.
    pub fn has_their_revocation(&self, n: u64) -> bool {
        self.their_revocation.contains_key(&n)
    }

    /// Remember a preimage for off-chain settlement or an on-chain claim.
    pub fn remember_preimage(&mut self, preimage: [u8; 32]) {
        self.preimages
            .entry(sha256::Hash::hash(&preimage).to_byte_array())
            .or_insert(preimage);
    }

    /// State numbers below the current state for which the peer still owes a
    /// revocation secret.
    pub fn missing_reveals(&self) -> Vec<u64> {
        (0..self.state_number)
            .filter(|n| {
                self.their_revocation_public.contains_key(n)
                    && !self.their_revocation.contains_key(n)
            })
            .collect()
    }

    /// Sign the cooperative close for the current agreed state.
    pub fn close_message(
        &self,
        aux: &[u8; 32],
    ) -> std::result::Result<CloseMessage, ProtocolError> {
        let tx = self.close_transaction()?;
        Ok(CloseMessage {
            t: CloseTag::Close,
            id: self.id,
            n: self.state_number,
            sig: self
                .channel
                .sign_funding(&tx, &self.channel_key, self.rules, aux)?,
        })
    }

    /// Verify the counterparty's cooperative-close signature and return the
    /// fully witnessed transaction ready for broadcast.
    pub fn accept_close(
        &self,
        message: CloseMessage,
        aux: &[u8; 32],
    ) -> std::result::Result<Transaction, ProtocolError> {
        self.check_id(message.id)?;
        if message.n != self.state_number {
            return Err(ProtocolError::UnexpectedState {
                got: message.n,
                expected: self.state_number,
            });
        }
        let mut tx = self.close_transaction()?;
        if !self
            .channel
            .verify_funding(&tx, &self.peer_key(), &message.sig, self.rules)
        {
            return Err(ProtocolError::BadSignature);
        }
        let mine = self
            .channel
            .sign_funding(&tx, &self.channel_key, self.rules, aux)?;
        tx.input[0].witness = self.channel.funding_witness(&BTreeMap::from([
            (self.my_key(), mine),
            (self.peer_key(), message.sig),
        ]))?;
        Ok(tx)
    }

    /// Build this peer's latest fully signed commitment for unilateral
    /// broadcast.
    pub fn force_close(&self, aux: &[u8; 32]) -> std::result::Result<Transaction, ProtocolError> {
        let mut commitment =
            self.commitment_for(self.role, self.state_number, self.current_state())?;
        let theirs = *self
            .signatures
            .get(&self.state_number)
            .ok_or(ProtocolError::MissingSignature(self.state_number))?;
        let mine = self
            .channel
            .sign_funding(&commitment.tx, &self.channel_key, self.rules, aux)?;
        commitment.tx.input[0].witness = self.channel.funding_witness(&BTreeMap::from([
            (self.my_key(), mine),
            (self.peer_key(), theirs),
        ]))?;
        Ok(commitment.tx)
    }

    /// Identify a transaction that spends the funding output against every
    /// agreed and collision-alternative state retained by this peer.
    pub fn classify_funding_spend(
        &self,
        txid: Txid,
    ) -> std::result::Result<FundingSpend, ProtocolError> {
        if self
            .close_transaction()
            .is_ok_and(|close| close.compute_txid() == txid)
        {
            return Ok(FundingSpend::Cooperative);
        }
        for n in 0..=self.state_number {
            let state = self.state(n)?;
            if self.commitment_for(self.role, n, state)?.tx.compute_txid() == txid {
                return Ok(FundingSpend::LocalCommitment { state: n });
            }
            if self
                .commitment_for(self.role.other(), n, state)?
                .tx
                .compute_txid()
                == txid
            {
                return Ok(FundingSpend::RemoteCommitment {
                    state: n,
                    alternative: None,
                    revoked: self.their_revocation.contains_key(&n),
                });
            }
            for (index, alternative) in self.signed_alternatives(n).iter().enumerate() {
                if self
                    .commitment_for(self.role.other(), n, alternative)?
                    .tx
                    .compute_txid()
                    == txid
                {
                    return Ok(FundingSpend::RemoteCommitment {
                        state: n,
                        alternative: Some(index),
                        revoked: self.their_revocation.contains_key(&n),
                    });
                }
            }
        }
        Ok(FundingSpend::Unknown)
    }

    /// Build every immediately available penalty spend for a revoked remote
    /// commitment. Outputs that are absent or uneconomical are omitted.
    pub fn penalty_transactions(
        &self,
        state: u64,
        alternative: Option<usize>,
        destination: ScriptBuf,
        fee: Amount,
        aux: &[u8; 32],
    ) -> std::result::Result<Vec<Transaction>, ProtocolError> {
        let secret = self
            .their_revocation
            .get(&state)
            .ok_or(ProtocolError::MissingReveal(state))?;
        let logical_state = match alternative {
            Some(index) => self
                .signed_alternatives(state)
                .get(index)
                .ok_or(ProtocolError::MissingAlternative { state, index })?,
            None => self.state(state)?,
        };
        let commitment = self.commitment_for(self.role.other(), state, logical_state)?;
        let mut penalties = Vec::new();
        match sweep_to_local(
            &commitment,
            SweepPath::Revocation,
            destination.clone(),
            fee,
            secret,
            self.rules,
            aux,
        ) {
            Ok(tx) => penalties.push(tx),
            Err(crate::Error::MissingOutput(_) | crate::Error::DustClaim) => {}
            Err(error) => return Err(ProtocolError::Channel(error)),
        }
        for htlc in &commitment.htlcs {
            match claim_htlc(
                &commitment,
                htlc,
                HtlcClaim {
                    path: HtlcClaimPath::Revocation,
                    destination: destination.clone(),
                    fee,
                    preimage: None,
                },
                secret,
                self.rules,
                aux,
            ) {
                Ok(tx) => penalties.push(tx),
                Err(crate::Error::DustClaim) => {}
                Err(error) => return Err(ProtocolError::Channel(error)),
            }
        }
        Ok(penalties)
    }

    /// Build this peer's current sync position. Hosts carry their lifecycle
    /// status as a string because Hitch's recovery logic also runs while a
    /// channel is funding or closing.
    pub fn sync_message(&self, status: impl Into<String>, tag: SyncTag) -> SyncMessage {
        SyncMessage {
            t: tag,
            id: self.id,
            n: self.state_number,
            status: status.into(),
            pending_n: self.pending.as_ref().map(|pending| pending.n),
            reveal: self
                .state_number
                .checked_sub(1)
                .and_then(|n| self.my_revocation.get(&n))
                .map(|secret| Bytes32(secret.secret_bytes())),
            missing: self.missing_reveals(),
            reveals: None,
        }
    }

    /// Answer a sync request, including at most the historical secrets the
    /// remote peer explicitly asked for.
    pub fn sync_response(
        &self,
        status: impl Into<String>,
        request: &SyncMessage,
    ) -> std::result::Result<SyncMessage, ProtocolError> {
        self.check_sync(request)?;
        let reveals = request
            .missing
            .iter()
            .filter_map(|n| {
                if *n < self.state_number {
                    self.my_revocation
                        .get(n)
                        .map(|secret| (*n, Bytes32(secret.secret_bytes())))
                } else {
                    None
                }
            })
            .collect();
        let mut response = self.sync_message(status, SyncTag::Synced);
        response.reveals = Some(reveals);
        Ok(response)
    }

    /// Import valid secrets repeated during recovery and finalise an incoming
    /// update if its last revocation was among them. Invalid or irrelevant
    /// secrets are ignored, matching Hitch's recovery behaviour.
    pub fn apply_sync(
        &mut self,
        message: &SyncMessage,
    ) -> std::result::Result<Option<FinalisedUpdate>, ProtocolError> {
        self.check_sync(message)?;
        if let Some(index) = message.n.checked_sub(1) {
            if let Some(reveal) = message.reveal {
                self.take_their_reveal(index, reveal);
            }
        }
        if let Some(reveals) = &message.reveals {
            for (index, reveal) in reveals {
                self.take_their_reveal(*index, *reveal);
            }
        }
        let Some(awaiting) = self.awaiting.clone() else {
            return Ok(None);
        };
        if !self.their_revocation.contains_key(&awaiting.previous) {
            return Ok(None);
        }
        self.awaiting = None;
        Ok(Some(FinalisedUpdate {
            n: awaiting.n,
            update: awaiting.update,
            sender: awaiting.sender,
        }))
    }

    /// Propose the next update and return the signed `update` message. The
    /// caller supplies the new secret for state `n+1`, keeping key generation
    /// outside this deterministic machine.
    pub fn propose(
        &mut self,
        mut update: Update,
        height: u32,
        next_revocation: SecretKey,
        aux: &[u8; 32],
    ) -> std::result::Result<UpdateMessage, ProtocolError> {
        if self.pending.is_some() {
            return Err(ProtocolError::Pending);
        }
        if self.awaiting.is_some() {
            return Err(ProtocolError::AwaitingRevocation);
        }
        self.require_all_reveals()?;
        let n = self.state_number + 1;
        if let Update::Add { htlc, .. } = &mut update {
            htlc.id = next_htlc_id(self.current_state());
        }
        let state = self.next_state(self.current_state(), &update, self.role, height)?;
        if let Update::Settle { preimage, .. } = &update {
            self.remember_preimage(preimage.0);
        }
        self.install_my_revocation(n + 1, next_revocation);
        self.states.insert(n, state.clone());
        let commitment = self.commitment_for(self.role.other(), n, &state)?;
        let sig = self
            .channel
            .sign_funding(&commitment.tx, &self.channel_key, self.rules, aux)?;
        let message = UpdateMessage {
            t: UpdateTag::Update,
            id: self.id,
            n,
            update: update.clone(),
            sig,
            next_rev: NodeId(self.my_revocation_public[&(n + 1)]),
        };
        self.pending = Some(PendingUpdate {
            n,
            update,
            message: message.clone(),
        });
        Ok(message)
    }

    /// Verify and accept a peer's update, or resolve a simultaneous proposal.
    /// The supplied secret becomes this peer's state-`n+1` revocation key.
    pub fn receive_update(
        &mut self,
        message: UpdateMessage,
        height: u32,
        next_revocation: SecretKey,
        aux: &[u8; 32],
    ) -> std::result::Result<ReceiveUpdate, ProtocolError> {
        self.check_id(message.id)?;
        if message.n == self.state_number && self.signatures.get(&message.n) == Some(&message.sig) {
            return Ok(ReceiveUpdate::ResendAcknowledgement(
                self.acknowledgement(message.n, aux)?,
            ));
        }
        if message.n != self.state_number + 1 {
            return Err(ProtocolError::UnexpectedState {
                got: message.n,
                expected: self.state_number + 1,
            });
        }
        if self.awaiting.is_some() {
            self.buffered = Some(message);
            return Ok(ReceiveUpdate::Buffered);
        }
        self.require_all_reveals()?;
        validate_update(&message.update)?;
        let sender = self.role.other();
        let state = self.next_state(self.current_state(), &message.update, sender, height)?;
        let mut future = self.their_revocation_public.clone();
        future.insert(message.n + 1, message.next_rev.0);
        let commitment = self.commitment_with_revisions(
            self.role,
            message.n,
            &state,
            &self.my_revocation_public,
            &future,
        )?;
        if !self
            .channel
            .verify_funding(&commitment.tx, &self.peer_key(), &message.sig, self.rules)
        {
            return Err(ProtocolError::BadSignature);
        }
        if self.pending.is_some() && node_less(self.my_key(), self.peer_key()) {
            return Ok(ReceiveUpdate::LocalProposalWins);
        }
        if self.pending.is_some() {
            let pending_state = self.state(message.n)?.clone();
            self.signed_alternatives
                .entry(message.n)
                .or_default()
                .push(pending_state);
            self.pending = None;
        }
        self.install_my_revocation(message.n + 1, next_revocation);
        self.states.insert(message.n, state);
        self.their_revocation_public
            .insert(message.n + 1, message.next_rev.0);
        self.signatures.insert(message.n, message.sig);
        let previous = self.state_number;
        self.state_number = message.n;
        if let Update::Settle { preimage, .. } = message.update {
            self.remember_preimage(preimage.0);
        }
        self.awaiting = Some(AwaitingRevoke {
            n: message.n,
            previous,
            update: message.update,
            sender,
        });
        Ok(ReceiveUpdate::Acknowledge(
            self.acknowledgement(message.n, aux)?,
        ))
    }

    /// Verify the receiver's acknowledgement of our pending proposal,
    /// advance locally and return the final revocation message.
    pub fn receive_ack(
        &mut self,
        message: AckMessage,
    ) -> std::result::Result<(RevokeMessage, FinalisedUpdate), ProtocolError> {
        self.check_id(message.id)?;
        let pending = self.pending.clone().ok_or(ProtocolError::NoPending)?;
        if message.n != pending.n {
            return Err(ProtocolError::UnexpectedState {
                got: message.n,
                expected: pending.n,
            });
        }
        let mut future = self.their_revocation_public.clone();
        future.insert(message.n + 1, message.next_rev.0);
        let state = self.state(message.n)?;
        let commitment = self.commitment_with_revisions(
            self.role,
            message.n,
            state,
            &self.my_revocation_public,
            &future,
        )?;
        if !self
            .channel
            .verify_funding(&commitment.tx, &self.peer_key(), &message.sig, self.rules)
        {
            return Err(ProtocolError::BadSignature);
        }
        let revealed = secret(message.reveal)?;
        if public(&revealed) != self.their_revocation_public[&self.state_number] {
            return Err(ProtocolError::BadRevocation);
        }
        let previous = self.state_number;
        self.their_revocation.insert(previous, revealed);
        self.their_revocation_public
            .insert(message.n + 1, message.next_rev.0);
        self.signatures.insert(message.n, message.sig);
        self.state_number = message.n;
        self.pending = None;
        if let Update::Settle { preimage, .. } = pending.update {
            self.remember_preimage(preimage.0);
        }
        let reveal = Bytes32(self.my_revocation[&previous].secret_bytes());
        let finalised = FinalisedUpdate {
            n: message.n,
            update: pending.update,
            sender: self.role,
        };
        Ok((
            RevokeMessage {
                t: RevokeTag::Revoke,
                id: self.id,
                n: message.n,
                reveal,
            },
            finalised,
        ))
    }

    /// Accept the proposer's previous-state secret and cross the receiver's
    /// finality boundary.
    pub fn receive_revoke(
        &mut self,
        message: RevokeMessage,
    ) -> std::result::Result<Option<FinalisedUpdate>, ProtocolError> {
        self.check_id(message.id)?;
        if message.n > self.state_number {
            return Err(ProtocolError::UnexpectedState {
                got: message.n,
                expected: self.state_number,
            });
        }
        let index = message
            .n
            .checked_sub(1)
            .ok_or(ProtocolError::BadRevocation)?;
        if self.their_revocation.contains_key(&index) {
            return Ok(None);
        }
        let revealed = secret(message.reveal)?;
        if self.their_revocation_public.get(&index) != Some(&public(&revealed)) {
            return Err(ProtocolError::BadRevocation);
        }
        self.their_revocation.insert(index, revealed);
        let Some(awaiting) = self.awaiting.clone() else {
            return Ok(None);
        };
        if awaiting.previous != index {
            return Ok(None);
        }
        self.awaiting = None;
        Ok(Some(FinalisedUpdate {
            n: awaiting.n,
            update: awaiting.update,
            sender: awaiting.sender,
        }))
    }

    fn acknowledgement(
        &self,
        n: u64,
        aux: &[u8; 32],
    ) -> std::result::Result<AckMessage, ProtocolError> {
        let commitment = self.commitment_for(self.role.other(), n, self.state(n)?)?;
        let sig = self
            .channel
            .sign_funding(&commitment.tx, &self.channel_key, self.rules, aux)?;
        let previous = n.checked_sub(1).ok_or(ProtocolError::BadRevocation)?;
        Ok(AckMessage {
            t: AckTag::Ack,
            id: self.id,
            n,
            sig,
            reveal: Bytes32(self.my_revocation[&previous].secret_bytes()),
            next_rev: NodeId(self.my_revocation_public[&(n + 1)]),
        })
    }

    fn next_state(
        &self,
        current: &ProtocolState,
        update: &Update,
        sender: Side,
        height: u32,
    ) -> std::result::Result<ProtocolState, ProtocolError> {
        validate_update(update)?;
        let mut state = current.clone();
        let other = sender.other();
        match update {
            Update::Pay { amount, .. } => {
                move_balance(&mut state, sender, other, *amount)?;
            }
            Update::Add { htlc, .. } => {
                if htlc.id != next_htlc_id(current) {
                    return Err(ProtocolError::BadHtlcId);
                }
                if htlc.expiry <= height + u32::from(self.channel.delay) + EXPIRY_MARGIN {
                    return Err(ProtocolError::ExpiryTooSoon);
                }
                if state.htlcs.iter().any(|known| known.hash == htlc.hash) {
                    return Err(ProtocolError::DuplicatePaymentHash);
                }
                subtract_balance(&mut state, sender, htlc.amount)?;
                state.htlcs.push(ProtocolHtlc {
                    id: htlc.id,
                    from: sender.into(),
                    amount: htlc.amount,
                    hash: htlc.hash,
                    expiry: htlc.expiry,
                    route: htlc.route,
                });
            }
            Update::Settle { htlc_id, preimage } => {
                let index = state
                    .htlcs
                    .iter()
                    .position(|htlc| htlc.id == *htlc_id)
                    .ok_or(ProtocolError::NoSuchHtlc)?;
                let htlc = state.htlcs[index].clone();
                if Side::from(htlc.from) == sender {
                    return Err(ProtocolError::OffererCannotSettle);
                }
                if sha256::Hash::hash(&preimage.0).to_byte_array() != htlc.hash.0 {
                    return Err(ProtocolError::WrongPreimage);
                }
                if height >= htlc.expiry {
                    return Err(ProtocolError::HtlcExpired);
                }
                state.htlcs.remove(index);
                add_balance(&mut state, sender, htlc.amount)?;
            }
            Update::Fail { htlc_id, .. } => {
                let index = state
                    .htlcs
                    .iter()
                    .position(|htlc| htlc.id == *htlc_id)
                    .ok_or(ProtocolError::NoSuchHtlc)?;
                let htlc = state.htlcs[index].clone();
                if Side::from(htlc.from) == sender {
                    if height < htlc.expiry {
                        return Err(ProtocolError::OffererFailBeforeExpiry);
                    }
                    if self.preimages.contains_key(&htlc.hash.0) {
                        return Err(ProtocolError::KnownPreimage);
                    }
                }
                state.htlcs.remove(index);
                add_balance(&mut state, Side::from(htlc.from), htlc.amount)?;
            }
        }
        if state.balance_a != 0 && state.balance_a < self.channel.fee.to_sat() {
            return Err(ProtocolError::FunderFee);
        }
        Ok(state)
    }

    fn commitment_for(
        &self,
        owner: Side,
        n: u64,
        state: &ProtocolState,
    ) -> std::result::Result<crate::Commitment, ProtocolError> {
        self.commitment_with_revisions(
            owner,
            n,
            state,
            &self.my_revocation_public,
            &self.their_revocation_public,
        )
    }

    fn commitment_with_revisions(
        &self,
        owner: Side,
        n: u64,
        state: &ProtocolState,
        mine: &BTreeMap<u64, XOnlyPublicKey>,
        theirs: &BTreeMap<u64, XOnlyPublicKey>,
    ) -> std::result::Result<crate::Commitment, ProtocolError> {
        let revisions = match self.role {
            Side::A => RevocationKeys {
                a: *mine.get(&n).ok_or(ProtocolError::MissingRevocationKey(n))?,
                b: *theirs
                    .get(&n)
                    .ok_or(ProtocolError::MissingRevocationKey(n))?,
            },
            Side::B => RevocationKeys {
                a: *theirs
                    .get(&n)
                    .ok_or(ProtocolError::MissingRevocationKey(n))?,
                b: *mine.get(&n).ok_or(ProtocolError::MissingRevocationKey(n))?,
            },
        };
        let channel_state = ChannelState {
            balances: Balances {
                a: Amount::from_sat(state.balance_a),
                b: Amount::from_sat(state.balance_b),
            },
            revocation: revisions,
            htlcs: state.htlcs.iter().map(ProtocolHtlc::channel_htlc).collect(),
        };
        self.channel
            .commitment(n, owner, &channel_state)
            .map_err(ProtocolError::Channel)
    }

    fn state(&self, n: u64) -> std::result::Result<&ProtocolState, ProtocolError> {
        self.states.get(&n).ok_or(ProtocolError::MissingState(n))
    }

    fn my_key(&self) -> XOnlyPublicKey {
        self.channel.key(self.role)
    }

    fn peer_key(&self) -> XOnlyPublicKey {
        self.channel.key(self.role.other())
    }

    fn install_my_revocation(&mut self, n: u64, secret: SecretKey) {
        self.my_revocation.insert(n, secret);
        self.my_revocation_public.insert(n, public(&secret));
    }

    fn refresh_my_public(&mut self) {
        self.my_revocation_public = self
            .my_revocation
            .iter()
            .map(|(n, secret)| (*n, public(secret)))
            .collect();
    }

    fn require_all_reveals(&self) -> std::result::Result<(), ProtocolError> {
        for n in 0..self.state_number {
            if self.their_revocation_public.contains_key(&n)
                && !self.their_revocation.contains_key(&n)
            {
                return Err(ProtocolError::MissingReveal(n));
            }
        }
        Ok(())
    }

    fn check_id(&self, id: ChannelId) -> std::result::Result<(), ProtocolError> {
        if id != self.id {
            return Err(ProtocolError::WrongChannel);
        }
        Ok(())
    }

    fn close_transaction(&self) -> std::result::Result<Transaction, ProtocolError> {
        let state = self.channel_state_with_revisions(
            self.state_number,
            self.current_state(),
            &self.my_revocation_public,
            &self.their_revocation_public,
        )?;
        self.channel
            .cooperative_close(&state)
            .map_err(ProtocolError::Channel)
    }

    fn channel_state_with_revisions(
        &self,
        n: u64,
        state: &ProtocolState,
        mine: &BTreeMap<u64, XOnlyPublicKey>,
        theirs: &BTreeMap<u64, XOnlyPublicKey>,
    ) -> std::result::Result<ChannelState, ProtocolError> {
        let revisions = match self.role {
            Side::A => RevocationKeys {
                a: *mine.get(&n).ok_or(ProtocolError::MissingRevocationKey(n))?,
                b: *theirs
                    .get(&n)
                    .ok_or(ProtocolError::MissingRevocationKey(n))?,
            },
            Side::B => RevocationKeys {
                a: *theirs
                    .get(&n)
                    .ok_or(ProtocolError::MissingRevocationKey(n))?,
                b: *mine.get(&n).ok_or(ProtocolError::MissingRevocationKey(n))?,
            },
        };
        Ok(ChannelState {
            balances: Balances {
                a: Amount::from_sat(state.balance_a),
                b: Amount::from_sat(state.balance_b),
            },
            revocation: revisions,
            htlcs: state.htlcs.iter().map(ProtocolHtlc::channel_htlc).collect(),
        })
    }

    fn check_sync(&self, message: &SyncMessage) -> std::result::Result<(), ProtocolError> {
        self.check_id(message.id)?;
        if message.missing.len() > 64
            || message
                .reveals
                .as_ref()
                .is_some_and(|reveals| reveals.len() > 64)
            || message.pending_n == Some(0)
        {
            return Err(ProtocolError::BadSync);
        }
        Ok(())
    }

    fn take_their_reveal(&mut self, index: u64, reveal: Bytes32) -> bool {
        if self.their_revocation.contains_key(&index) {
            return false;
        }
        let Ok(secret) = secret(reveal) else {
            return false;
        };
        if self.their_revocation_public.get(&index) != Some(&public(&secret)) {
            return false;
        }
        self.their_revocation.insert(index, secret);
        true
    }

    fn validate_snapshot(&self) -> std::result::Result<(), ProtocolError> {
        if self.id != ChannelId::from_txid(self.channel.funding_outpoint.txid) {
            return Err(ProtocolError::CorruptSnapshot("channel id"));
        }
        if public(&self.channel_key) != self.my_key() {
            return Err(ProtocolError::WrongChannelKey);
        }
        if !self.states.contains_key(&self.state_number) {
            return Err(ProtocolError::MissingState(self.state_number));
        }
        let next = self
            .state_number
            .checked_add(1)
            .ok_or(ProtocolError::CorruptSnapshot("state number"))?;
        for n in [self.state_number, next] {
            if !self.my_revocation.contains_key(&n)
                || !self.their_revocation_public.contains_key(&n)
            {
                return Err(ProtocolError::MissingRevocationKey(n));
            }
        }
        for (n, secret) in &self.their_revocation {
            if self.their_revocation_public.get(n) != Some(&public(secret)) {
                return Err(ProtocolError::CorruptSnapshot("counterparty revocation"));
            }
        }
        for (hash, preimage) in &self.preimages {
            if sha256::Hash::hash(preimage).to_byte_array() != *hash {
                return Err(ProtocolError::CorruptSnapshot("payment preimage"));
            }
        }
        for (n, state) in &self.states {
            self.commitment_for(self.role, *n, state)?;
        }
        for (n, alternatives) in &self.signed_alternatives {
            for state in alternatives {
                self.commitment_for(self.role.other(), *n, state)?;
            }
        }
        for n in 0..=self.state_number {
            let signature = self
                .signatures
                .get(&n)
                .ok_or(ProtocolError::MissingSignature(n))?;
            let commitment = self.commitment_for(self.role, n, self.state(n)?)?;
            if !self
                .channel
                .verify_funding(&commitment.tx, &self.peer_key(), signature, self.rules)
            {
                return Err(ProtocolError::BadSignature);
            }
        }
        if let Some(pending) = &self.pending {
            if pending.n != next
                || pending.message.id != self.id
                || pending.message.n != pending.n
                || pending.message.update != pending.update
            {
                return Err(ProtocolError::CorruptSnapshot("pending update"));
            }
            let commitment =
                self.commitment_for(self.role.other(), pending.n, self.state(pending.n)?)?;
            if !self.channel.verify_funding(
                &commitment.tx,
                &self.my_key(),
                &pending.message.sig,
                self.rules,
            ) {
                return Err(ProtocolError::BadSignature);
            }
        }
        if let Some(awaiting) = &self.awaiting {
            if awaiting.n != self.state_number
                || awaiting.previous.checked_add(1) != Some(awaiting.n)
                || awaiting.sender != self.role.other()
            {
                return Err(ProtocolError::CorruptSnapshot("awaiting revocation"));
            }
        }
        if self
            .buffered
            .as_ref()
            .is_some_and(|message| message.id != self.id || message.n != next)
        {
            return Err(ProtocolError::CorruptSnapshot("buffered update"));
        }
        Ok(())
    }
}

/// Why a peer message or state transition was refused.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// Wire field had the wrong shape.
    #[error("malformed message: {0}")]
    Malformed(&'static str),
    /// Message named another channel.
    #[error("message is for another channel")]
    WrongChannel,
    /// Secret channel key does not match this machine's A/B role.
    #[error("channel key does not match this peer's role")]
    WrongChannelKey,
    /// Snapshot version is newer or older than this implementation supports.
    #[error("unsupported channel snapshot version {0}")]
    SnapshotVersion(u8),
    /// Persisted state failed an internal consistency check.
    #[error("corrupt channel snapshot: {0}")]
    CorruptSnapshot(&'static str),
    /// Funding output index does not fit Hitch's two-byte wire boundary.
    #[error("funding output index exceeds 65535")]
    FundingVout,
    /// Opening value is below Hitch's channel floor.
    #[error("funding value is below {MIN_OPEN} sats")]
    FundingTooSmall,
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
    /// No local update exists for an acknowledgement.
    #[error("no update is pending")]
    NoPending,
    /// This peer waits for the previous-state secret.
    #[error("waiting for their revocation of the previous state")]
    AwaitingRevocation,
    /// Counterparty revocation secret is missing.
    #[error("their revocation secret for state {0} is missing")]
    MissingReveal(u64),
    /// Revocation public key was not announced.
    #[error("revocation key for state {0} is missing")]
    MissingRevocationKey(u64),
    /// State document was not retained.
    #[error("state {0} is missing")]
    MissingState(u64),
    /// Collision alternative index was not retained for the named state.
    #[error("alternative {index} for state {state} is missing")]
    MissingAlternative {
        /// State number.
        state: u64,
        /// Alternative position.
        index: usize,
    },
    /// Counterparty signature for a commitment state is absent.
    #[error("counterparty signature for state {0} is missing")]
    MissingSignature(u64),
    /// Schnorr signature did not authorise the derived commitment.
    #[error("signature on the commitment does not verify")]
    BadSignature,
    /// Revealed secret does not match the announced revocation public key.
    #[error("revealed secret is not the announced revocation key")]
    BadRevocation,
    /// Payment amount was zero.
    #[error("payment amount must be positive")]
    ZeroAmount,
    /// Memo or failure reason exceeded Hitch's boundary.
    #[error("memo or reason is longer than {MEMO_MAX} characters")]
    MemoTooLong,
    /// HTLC amount was below Hitch's floor.
    #[error("HTLC amount is below {MIN_HTLC} sats")]
    HtlcTooSmall,
    /// HTLC expiry is outside the allowed block-height range.
    #[error("bad HTLC expiry")]
    BadExpiry,
    /// HTLC id did not follow the current maximum.
    #[error("bad HTLC id")]
    BadHtlcId,
    /// Absolute expiry leaves insufficient safety margin.
    #[error("the HTLC would expire too soon")]
    ExpiryTooSoon,
    /// Another HTLC already uses the payment hash.
    #[error("an HTLC with that hash is already in flight")]
    DuplicatePaymentHash,
    /// Update spends more than the sender's free balance.
    #[error("a balance would go negative")]
    NegativeBalance,
    /// Balance arithmetic overflowed.
    #[error("balance overflow")]
    BalanceOverflow,
    /// A non-zero A balance cannot pay the fixed channel fee.
    #[error("the funder must keep its fee")]
    FunderFee,
    /// No in-flight HTLC has that id.
    #[error("no such HTLC")]
    NoSuchHtlc,
    /// The offerer tried to settle its own HTLC.
    #[error("the offerer cannot settle")]
    OffererCannotSettle,
    /// Preimage does not match the payment hash.
    #[error("wrong preimage")]
    WrongPreimage,
    /// Off-chain settlement came at or after expiry.
    #[error("the HTLC has expired")]
    HtlcExpired,
    /// Offerer tried to fail before expiry.
    #[error("the offerer may fail only after the expiry")]
    OffererFailBeforeExpiry,
    /// Receiver already knows the preimage and must retain its claim.
    #[error("the preimage is known; the HTLC must settle")]
    KnownPreimage,
    /// Sync arrays or pending state number exceed Hitch's wire boundary.
    #[error("bad sync message")]
    BadSync,
    /// Transaction-layer construction failed.
    #[error(transparent)]
    Channel(#[from] crate::Error),
}

impl From<SighashRules> for SnapshotRules {
    fn from(rules: SighashRules) -> Self {
        match rules {
            SighashRules::Bip341 => Self::Bip341,
            SighashRules::KnotsUnified => Self::KnotsUnified,
        }
    }
}

impl From<SnapshotRules> for SighashRules {
    fn from(rules: SnapshotRules) -> Self {
        match rules {
            SnapshotRules::Bip341 => Self::Bip341,
            SnapshotRules::KnotsUnified => Self::KnotsUnified,
        }
    }
}

fn decode_secret_map(
    encoded: BTreeMap<u64, Bytes32>,
) -> std::result::Result<BTreeMap<u64, SecretKey>, ProtocolError> {
    encoded
        .into_iter()
        .map(|(n, bytes)| secret(bytes).map(|secret| (n, secret)))
        .collect()
}

fn validate_open(
    message: &OpenMessage,
    sender: XOnlyPublicKey,
    receiver: XOnlyPublicKey,
    policy: AcceptPolicy,
) -> std::result::Result<(), ProtocolError> {
    if message.id != ChannelId::from_txid(message.funding.txid) {
        return Err(ProtocolError::WrongChannel);
    }
    if message.funding.vout > u32::from(u16::MAX) {
        return Err(ProtocolError::FundingVout);
    }
    if message.funding.value < MIN_OPEN {
        return Err(ProtocolError::FundingTooSmall);
    }
    if message.a.0 == message.b.0 {
        return Err(ProtocolError::SamePeer);
    }
    if message.a.0 != sender || message.b.0 != receiver {
        return Err(ProtocolError::WrongPeer);
    }
    if message.delay < policy.min_delay {
        return Err(ProtocolError::DelayBelowPolicy);
    }
    validate_hub_fee(message.hub_fee)?;
    validate_hub_fee(policy.hub_fee)?;
    validate_push(
        Amount::from_sat(message.funding.value),
        Amount::from_sat(message.push),
        Amount::from_sat(message.fee),
    )?;
    Ok(())
}

fn validate_hub_fee(fee: Option<u64>) -> std::result::Result<(), ProtocolError> {
    if fee.is_some_and(|value| value > 100_000) {
        return Err(ProtocolError::HubFee);
    }
    Ok(())
}

fn validate_push(
    funding: Amount,
    push: Amount,
    fee: Amount,
) -> std::result::Result<(), ProtocolError> {
    let minimum = fee
        .to_sat()
        .checked_add(DUST)
        .ok_or(ProtocolError::BadPush)?;
    let maximum = funding
        .to_sat()
        .checked_sub(minimum)
        .ok_or(ProtocolError::BadPush)?;
    if push.to_sat() > maximum {
        return Err(ProtocolError::BadPush);
    }
    Ok(())
}

fn initial_state(
    funding: Amount,
    push: Amount,
) -> std::result::Result<ProtocolState, ProtocolError> {
    let balance_a = funding
        .to_sat()
        .checked_sub(push.to_sat())
        .ok_or(ProtocolError::BadPush)?;
    Ok(ProtocolState {
        balance_a,
        balance_b: push.to_sat(),
        htlcs: vec![],
    })
}

fn opening_channel_state(
    state: &ProtocolState,
    revocation_a: XOnlyPublicKey,
    revocation_b: XOnlyPublicKey,
) -> ChannelState {
    ChannelState {
        balances: Balances {
            a: Amount::from_sat(state.balance_a),
            b: Amount::from_sat(state.balance_b),
        },
        revocation: RevocationKeys {
            a: revocation_a,
            b: revocation_b,
        },
        htlcs: vec![],
    }
}

fn validate_update(update: &Update) -> std::result::Result<(), ProtocolError> {
    let text_ok = |text: &Option<String>| {
        text.as_ref()
            .is_none_or(|value| value.encode_utf16().count() <= MEMO_MAX)
    };
    match update {
        Update::Pay { amount, memo } => {
            if *amount == 0 {
                return Err(ProtocolError::ZeroAmount);
            }
            if !text_ok(memo) {
                return Err(ProtocolError::MemoTooLong);
            }
        }
        Update::Add { htlc, memo } => {
            if htlc.id == 0 {
                return Err(ProtocolError::BadHtlcId);
            }
            if htlc.amount < MIN_HTLC {
                return Err(ProtocolError::HtlcTooSmall);
            }
            if htlc.expiry == 0 || htlc.expiry >= MAX_EXPIRY {
                return Err(ProtocolError::BadExpiry);
            }
            if !text_ok(memo) {
                return Err(ProtocolError::MemoTooLong);
            }
        }
        Update::Settle { htlc_id, .. } => {
            if *htlc_id == 0 {
                return Err(ProtocolError::BadHtlcId);
            }
        }
        Update::Fail {
            htlc_id, reason, ..
        } => {
            if *htlc_id == 0 {
                return Err(ProtocolError::BadHtlcId);
            }
            if !text_ok(reason) {
                return Err(ProtocolError::MemoTooLong);
            }
        }
    }
    Ok(())
}

fn next_htlc_id(state: &ProtocolState) -> u64 {
    state.htlcs.iter().map(|htlc| htlc.id).max().unwrap_or(0) + 1
}

fn move_balance(
    state: &mut ProtocolState,
    from: Side,
    to: Side,
    amount: u64,
) -> std::result::Result<(), ProtocolError> {
    subtract_balance(state, from, amount)?;
    add_balance(state, to, amount)
}

fn subtract_balance(
    state: &mut ProtocolState,
    side: Side,
    amount: u64,
) -> std::result::Result<(), ProtocolError> {
    let balance = match side {
        Side::A => &mut state.balance_a,
        Side::B => &mut state.balance_b,
    };
    *balance = balance
        .checked_sub(amount)
        .ok_or(ProtocolError::NegativeBalance)?;
    Ok(())
}

fn add_balance(
    state: &mut ProtocolState,
    side: Side,
    amount: u64,
) -> std::result::Result<(), ProtocolError> {
    let balance = match side {
        Side::A => &mut state.balance_a,
        Side::B => &mut state.balance_b,
    };
    *balance = balance
        .checked_add(amount)
        .ok_or(ProtocolError::BalanceOverflow)?;
    Ok(())
}

fn public(secret: &SecretKey) -> XOnlyPublicKey {
    Keypair::from_secret_key(secp(), secret)
        .x_only_public_key()
        .0
}

fn secret(bytes: Bytes32) -> std::result::Result<SecretKey, ProtocolError> {
    SecretKey::from_slice(&bytes.0).map_err(|_| ProtocolError::BadRevocation)
}

fn node_less(a: XOnlyPublicKey, b: XOnlyPublicKey) -> bool {
    a.serialize() < b.serialize()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn decode_hex(text: &str, output: &mut [u8]) -> Option<()> {
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

fn serialize_txid<S: Serializer>(
    txid: &Txid,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&txid.to_string())
}

fn deserialize_txid<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Txid, D::Error> {
    let text = String::deserialize(deserializer)?;
    if text.len() != 64
        || text
            .as_bytes()
            .iter()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(byte))
    {
        return Err(serde::de::Error::custom("bad txid"));
    }
    Txid::from_str(&text).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, Txid};

    use super::*;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn setup() -> (ChannelMachine, ChannelMachine) {
        let channel_key_a = key(0x11);
        let channel_key_b = key(0x22);
        let rev_a0 = key(0x31);
        let rev_a1 = key(0x32);
        let rev_b0 = key(0x41);
        let rev_b1 = key(0x42);
        let channel = Channel::new(
            public(&channel_key_a),
            public(&channel_key_b),
            OutPoint {
                txid: Txid::from_byte_array([0xab; 32]),
                vout: 1,
            },
            Amount::from_sat(100_000),
            Amount::from_sat(300),
            6,
        )
        .unwrap();
        let state = ProtocolState {
            balance_a: 100_000,
            balance_b: 0,
            htlcs: vec![],
        };
        let state_with_revs = |a: XOnlyPublicKey, b: XOnlyPublicKey| ChannelState {
            balances: Balances {
                a: Amount::from_sat(100_000),
                b: Amount::ZERO,
            },
            revocation: RevocationKeys { a, b },
            htlcs: vec![],
        };
        let initial = state_with_revs(public(&rev_a0), public(&rev_b0));
        let commit_a = channel.commitment(0, Side::A, &initial).unwrap();
        let commit_b = channel.commitment(0, Side::B, &initial).unwrap();
        let sig_for_a = channel
            .sign_funding(
                &commit_a.tx,
                &channel_key_b,
                SighashRules::KnotsUnified,
                &[0; 32],
            )
            .unwrap();
        let sig_for_b = channel
            .sign_funding(
                &commit_b.tx,
                &channel_key_a,
                SighashRules::KnotsUnified,
                &[0; 32],
            )
            .unwrap();
        let id = ChannelId([0xab; 8]);
        let a = ChannelMachine::new(
            id,
            Side::A,
            channel_key_a,
            channel.clone(),
            state.clone(),
            rev_a0,
            rev_a1,
            public(&rev_b0),
            public(&rev_b1),
            sig_for_a,
            SighashRules::KnotsUnified,
        )
        .unwrap();
        let b = ChannelMachine::new(
            id,
            Side::B,
            channel_key_b,
            channel,
            state,
            rev_b0,
            rev_b1,
            public(&rev_a0),
            public(&rev_a1),
            sig_for_b,
            SighashRules::KnotsUnified,
        )
        .unwrap();
        (a, b)
    }

    fn open_pair() -> (ChannelMachine, ChannelMachine) {
        let channel_a = key(0x11);
        let channel_b = key(0x22);
        let params = OpenParams {
            funding: OutPoint {
                txid: Txid::from_byte_array([0xab; 32]),
                vout: 1,
            },
            funding_value: Amount::from_sat(100_000),
            push: Amount::from_sat(20_000),
            delay: 6,
            fee: Amount::from_sat(300),
            hub_fee: None,
        };
        let (funder, open) = FunderOpening::propose(
            params,
            OpeningKeys {
                channel: channel_a,
                revocation: [key(0x31), key(0x32)],
            },
            public(&channel_b),
            SighashRules::KnotsUnified,
        )
        .unwrap();
        let wire = serde_json::to_value(&open).unwrap();
        assert_eq!(wire["t"], "open");
        assert_eq!(wire["id"], "abababababababab");
        assert_eq!(wire["funding"]["txid"], "ab".repeat(32));
        assert!(wire.get("hubFee").is_none());
        let (receiver, accept) = ReceiverOpening::accept(
            open,
            public(&channel_a),
            OpeningKeys {
                channel: channel_b,
                revocation: [key(0x41), key(0x42)],
            },
            SighashRules::KnotsUnified,
            AcceptPolicy::default(),
            &[0; 32],
        )
        .unwrap();
        let (funder, commit) = funder.accept(accept, &[0; 32]).unwrap();
        let (b, ready) = receiver.commit(commit).unwrap();
        let a = funder.ready(ready).unwrap();
        (a, b)
    }

    #[test]
    fn opening_close_and_force_close_complete_the_signed_lifecycle() {
        let (a, b) = open_pair();
        assert_eq!(a.current_state(), b.current_state());
        assert_eq!(a.current_state().balance_a, 80_000);
        assert_eq!(a.current_state().balance_b, 20_000);

        let close = a.close_message(&[0; 32]).unwrap();
        let signed_close = b.accept_close(close, &[0; 32]).unwrap();
        assert_eq!(signed_close.input[0].witness.len(), 4);
        assert!(signed_close.input[0].witness[0].len() == 65);

        let force = a.force_close(&[0; 32]).unwrap();
        assert_eq!(force.input[0].witness.len(), 4);
        assert!(force.input[0].witness[0].len() == 65);
    }

    #[test]
    fn sync_repeats_a_lost_revoke_and_crosses_finality() {
        let (mut a, mut b) = setup();
        let update = a
            .propose(
                Update::Pay {
                    amount: 1_000,
                    memo: None,
                },
                152_100,
                key(0x33),
                &[0; 32],
            )
            .unwrap();
        let ack = match b
            .receive_update(update, 152_100, key(0x43), &[0; 32])
            .unwrap()
        {
            ReceiveUpdate::Acknowledge(ack) => ack,
            other => panic!("unexpected {other:?}"),
        };
        let (_lost_revoke, _) = a.receive_ack(ack).unwrap();
        let sync = a.sync_message("open", SyncTag::Sync);
        let wire = serde_json::to_value(&sync).unwrap();
        assert_eq!(wire["t"], "sync");
        assert_eq!(wire["pendingN"], serde_json::Value::Null);
        assert_eq!(wire["missing"], serde_json::json!([]));
        assert!(b.apply_sync(&sync).unwrap().is_some());
        assert!(b.awaiting_revoke().is_none());

        let response = b.sync_response("open", &sync).unwrap();
        assert_eq!(response.t, SyncTag::Synced);
        assert_eq!(response.reveals, Some(BTreeMap::new()));
    }

    #[test]
    fn snapshot_round_trip_preserves_pending_secrets_and_rejects_damage() {
        let (mut a, _) = open_pair();
        a.remember_preimage([0x77; 32]);
        a.propose(
            Update::Pay {
                amount: 1_000,
                memo: Some("persist me".into()),
            },
            152_100,
            key(0x33),
            &[0; 32],
        )
        .unwrap();
        let snapshot = a.snapshot();
        let json = serde_json::to_vec(&snapshot).unwrap();
        let decoded: ChannelSnapshot = serde_json::from_slice(&json).unwrap();
        let restored = ChannelMachine::restore(decoded).unwrap();
        assert_eq!(restored.snapshot(), snapshot);
        assert_eq!(restored.pending().unwrap().n, 1);

        let mut damaged = snapshot;
        damaged.signatures.remove(&0);
        assert!(matches!(
            ChannelMachine::restore(damaged),
            Err(ProtocolError::MissingSignature(0))
        ));
    }

    #[test]
    fn revoked_remote_commitment_is_classified_and_penalised() {
        let (mut a, mut b) = open_pair();
        let old = a
            .commitment_for(Side::B, 0, a.state(0).unwrap())
            .unwrap()
            .tx
            .compute_txid();
        let update = a
            .propose(
                Update::Pay {
                    amount: 1_000,
                    memo: None,
                },
                152_100,
                key(0x33),
                &[0; 32],
            )
            .unwrap();
        let ack = match b
            .receive_update(update, 152_100, key(0x43), &[0; 32])
            .unwrap()
        {
            ReceiveUpdate::Acknowledge(ack) => ack,
            other => panic!("unexpected {other:?}"),
        };
        a.receive_ack(ack).unwrap();
        assert_eq!(
            a.classify_funding_spend(old).unwrap(),
            FundingSpend::RemoteCommitment {
                state: 0,
                alternative: None,
                revoked: true,
            }
        );
        let penalties = a
            .penalty_transactions(
                0,
                None,
                crate::to_remote_script(a.my_key()),
                Amount::from_sat(200),
                &[0; 32],
            )
            .unwrap();
        assert_eq!(penalties.len(), 1);
        assert_eq!(penalties[0].input[0].witness.len(), 3);
    }

    #[test]
    fn update_ack_revoke_crosses_finality_only_on_the_last_message() {
        let (mut a, mut b) = setup();
        let update = a
            .propose(
                Update::Pay {
                    amount: 40_000,
                    memo: Some("first".into()),
                },
                152_100,
                key(0x33),
                &[0; 32],
            )
            .unwrap();
        let ack = match b
            .receive_update(update, 152_100, key(0x43), &[0; 32])
            .unwrap()
        {
            ReceiveUpdate::Acknowledge(ack) => ack,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(b.state_number(), 1);
        assert!(b.awaiting_revoke().is_some());
        assert!(!b.has_their_revocation(0));
        assert!(matches!(
            b.propose(
                Update::Pay {
                    amount: 1,
                    memo: None
                },
                152_100,
                key(0x44),
                &[0; 32]
            ),
            Err(ProtocolError::AwaitingRevocation)
        ));
        let (revoke, proposer_final) = a.receive_ack(ack).unwrap();
        assert_eq!(proposer_final.n, 1);
        assert!(a.has_their_revocation(0));
        let next = a
            .propose(
                Update::Pay {
                    amount: 1,
                    memo: None,
                },
                152_100,
                key(0x34),
                &[0; 32],
            )
            .unwrap();
        assert_eq!(
            b.receive_update(next, 152_100, key(0x44), &[0; 32])
                .unwrap(),
            ReceiveUpdate::Buffered
        );
        let receiver_final = b.receive_revoke(revoke).unwrap().unwrap();
        assert_eq!(receiver_final.n, 1);
        assert!(b.has_their_revocation(0));
        assert!(b.awaiting_revoke().is_none());
        assert!(b.take_buffered_update().is_some());
        assert_eq!(a.current_state(), b.current_state());
        assert_eq!(a.current_state().balance_a, 60_000);
        assert_eq!(a.current_state().balance_b, 40_000);
    }

    #[test]
    fn lower_node_id_wins_a_simultaneous_proposal_and_the_loser_remembers_its_signature() {
        let (mut a, mut b) = setup();
        let from_a = a
            .propose(
                Update::Pay {
                    amount: 100,
                    memo: None,
                },
                152_100,
                key(0x33),
                &[0; 32],
            )
            .unwrap();
        let from_b = b.propose(
            Update::Pay {
                amount: 0,
                memo: None,
            },
            152_100,
            key(0x43),
            &[0; 32],
        );
        assert!(matches!(from_b, Err(ProtocolError::ZeroAmount)));

        // Give B a balance first so both directions can validly propose.
        let ack = match b
            .receive_update(from_a, 152_100, key(0x43), &[0; 32])
            .unwrap()
        {
            ReceiveUpdate::Acknowledge(ack) => ack,
            other => panic!("unexpected {other:?}"),
        };
        let (revoke, _) = a.receive_ack(ack).unwrap();
        b.receive_revoke(revoke).unwrap();

        let from_a = a
            .propose(
                Update::Pay {
                    amount: 10,
                    memo: None,
                },
                152_100,
                key(0x34),
                &[0; 32],
            )
            .unwrap();
        let from_b = b
            .propose(
                Update::Pay {
                    amount: 20,
                    memo: None,
                },
                152_100,
                key(0x44),
                &[0; 32],
            )
            .unwrap();
        let a_is_lower = node_less(a.my_key(), b.my_key());
        let at_a = a
            .receive_update(from_b, 152_100, key(0x35), &[0; 32])
            .unwrap();
        let at_b = b
            .receive_update(from_a, 152_100, key(0x45), &[0; 32])
            .unwrap();
        if a_is_lower {
            assert_eq!(at_a, ReceiveUpdate::LocalProposalWins);
            assert!(matches!(at_b, ReceiveUpdate::Acknowledge(_)));
            assert_eq!(b.signed_alternatives(2).len(), 1);
        } else {
            assert_eq!(at_b, ReceiveUpdate::LocalProposalWins);
            assert!(matches!(at_a, ReceiveUpdate::Acknowledge(_)));
            assert_eq!(a.signed_alternatives(2).len(), 1);
        }
    }

    #[test]
    fn htlc_expiry_and_known_preimage_rules_match_hitch() {
        let (mut a, mut b) = setup();
        let preimage = [0x55; 32];
        let hash = sha256::Hash::hash(&preimage).to_byte_array();
        let too_soon = a.propose(
            Update::Add {
                htlc: OfferedHtlc {
                    id: 0,
                    amount: 2_000,
                    hash: Bytes32(hash),
                    expiry: 152_118,
                    route: None,
                },
                memo: None,
            },
            152_100,
            key(0x33),
            &[0; 32],
        );
        assert!(matches!(too_soon, Err(ProtocolError::ExpiryTooSoon)));
        let add = a
            .propose(
                Update::Add {
                    htlc: OfferedHtlc {
                        id: 0,
                        amount: 2_000,
                        hash: Bytes32(hash),
                        expiry: 152_140,
                        route: None,
                    },
                    memo: None,
                },
                152_100,
                key(0x34),
                &[0; 32],
            )
            .unwrap();
        let ack = match b.receive_update(add, 152_100, key(0x43), &[0; 32]).unwrap() {
            ReceiveUpdate::Acknowledge(ack) => ack,
            other => panic!("unexpected {other:?}"),
        };
        let (revoke, _) = a.receive_ack(ack).unwrap();
        b.receive_revoke(revoke).unwrap();
        b.remember_preimage(preimage);
        let fail = Update::Fail {
            htlc_id: 1,
            reason: Some("expired".into()),
        };
        let current = b.current_state().clone();
        assert!(matches!(
            b.next_state(&current, &fail, Side::A, 152_141),
            Err(ProtocolError::KnownPreimage)
        ));
        let settle = Update::Settle {
            htlc_id: 1,
            preimage: Bytes32(preimage),
        };
        assert!(matches!(
            b.next_state(&current, &settle, Side::B, 152_140),
            Err(ProtocolError::HtlcExpired)
        ));
    }

    #[test]
    fn update_wire_is_exact_and_malformed_hex_is_refused() {
        let (mut a, _) = setup();
        let message = a
            .propose(
                Update::Pay {
                    amount: 1_000,
                    memo: Some("rent".into()),
                },
                152_100,
                key(0x33),
                &[0; 32],
            )
            .unwrap();
        let value = serde_json::to_value(&message).unwrap();
        assert_eq!(value["t"], "update");
        assert_eq!(value["kind"], "pay");
        assert_eq!(value["amount"], 1_000);
        assert_eq!(value["memo"], "rent");
        assert_eq!(value["sig"].as_str().unwrap().len(), 130);
        assert_eq!(value["nextRev"].as_str().unwrap().len(), 64);
        assert_eq!(
            serde_json::from_value::<UpdateMessage>(value).unwrap(),
            message
        );
        assert!(serde_json::from_str::<UpdateMessage>(
            r#"{"t":"update","id":"zz","n":1,"kind":"pay","amount":1,"sig":"00","nextRev":"00"}"#
        )
        .is_err());

        let (mut a, _) = setup();
        let add = a
            .propose(
                Update::Add {
                    htlc: OfferedHtlc {
                        id: 0,
                        amount: MIN_HTLC,
                        hash: Bytes32([0x77; 32]),
                        expiry: 152_140,
                        route: None,
                    },
                    memo: None,
                },
                152_100,
                key(0x33),
                &[0; 32],
            )
            .unwrap();
        let value = serde_json::to_value(add).unwrap();
        assert_eq!(value["htlc"]["id"], 1);
        assert!(value["htlc"].get("from").is_none());
    }
}
