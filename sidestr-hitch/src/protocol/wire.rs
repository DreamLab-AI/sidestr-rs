//! Hitch's JSON wire messages and the boundary check every one passes.

use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{Amount, Txid};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    decode_hex, encode_hex, ProtocolError, MAX_HUB_FEE, MAX_SATS, MAX_STATUS_LEN, MAX_SYNC_ITEMS,
    MEMO_MAX, MIN_HTLC, MIN_OPEN,
};
use crate::{
    Htlc, LeafSignature, PopSignature, Side, MAX_DELAY, MAX_EXPIRY, MAX_FEE, MIN_DELAY, MIN_FEE,
};

/// Eight bytes carried as the first sixteen hex characters of the funding
/// transaction id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChannelId(pub [u8; 8]);

impl ChannelId {
    /// Parse Hitch's sixteen-character lower-case identifier.
    pub fn from_hex(text: &str) -> Result<Self, ProtocolError> {
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

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for ChannelId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ChannelId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

/// A validated x-only node or revocation public key, encoded as 64 lower-case
/// hex characters on Hitch's wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub XOnlyPublicKey);

impl Serialize for NodeId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if !lower_hex(&text, 64) {
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
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes32 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let mut bytes = [0u8; 32];
        decode_hex(&text, &mut bytes).ok_or_else(|| serde::de::Error::custom("bad 32-byte hex"))?;
        Ok(Self(bytes))
    }
}

impl Serialize for LeafSignature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for LeafSignature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        LeafSignature::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

impl Serialize for PopSignature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PopSignature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        PopSignature::from_hex(&text).map_err(serde::de::Error::custom)
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
    pub(crate) fn channel_htlc(&self) -> Htlc {
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
    /// this with the next id before signing; ids never repeat on a channel.
    ///
    /// [`ChannelMachine::propose`]: super::ChannelMachine::propose
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

impl Update {
    /// Hitch's one-line description of the update, as used in its logs.
    pub fn label(&self) -> String {
        match self {
            Self::Pay { amount, .. } => format!("pay of {amount} sat"),
            Self::Add { htlc, .. } => format!("add of htlc {} ({} sat)", htlc.id, htlc.amount),
            Self::Settle { htlc_id, .. } => format!("settle of htlc {htlc_id}"),
            Self::Fail { htlc_id, .. } => format!("fail of htlc {htlc_id}"),
        }
    }

    /// The payment hash an `add` locks, if this is one.
    pub fn added_hash(&self) -> Option<Bytes32> {
        match self {
            Self::Add { htlc, .. } => Some(htlc.hash),
            _ => None,
        }
    }

    pub(crate) fn well_formed(&self) -> Result<(), ProtocolError> {
        let text_ok =
            |text: &Option<String>| text.as_ref().is_none_or(|t| utf16_len(t) <= MEMO_MAX);
        match self {
            Self::Pay { amount, memo } => {
                if !text_ok(memo) {
                    return Err(ProtocolError::Malformed("bad update"));
                }
                if !(1..=MAX_SATS).contains(amount) {
                    return Err(ProtocolError::Malformed("bad pay"));
                }
            }
            Self::Add { htlc, memo } => {
                if !text_ok(memo) {
                    return Err(ProtocolError::Malformed("bad update"));
                }
                if htlc.id < 1
                    || !(MIN_HTLC..=MAX_SATS).contains(&htlc.amount)
                    || !(1..MAX_EXPIRY).contains(&htlc.expiry)
                {
                    return Err(ProtocolError::Malformed("bad add"));
                }
            }
            Self::Settle { htlc_id, .. } => {
                if *htlc_id < 1 {
                    return Err(ProtocolError::Malformed("bad settle"));
                }
            }
            Self::Fail { htlc_id, reason } => {
                if *htlc_id < 1 || !text_ok(reason) {
                    return Err(ProtocolError::Malformed("bad fail"));
                }
            }
        }
        Ok(())
    }
}

macro_rules! tag {
    ($(#[$doc:meta])* $name:ident, $variant:ident, $text:literal, $vdoc:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $name {
            #[doc = $vdoc]
            #[serde(rename = $text)]
            $variant,
        }
    };
}

tag!(
    /// Serde discriminator that only accepts the string `"open"`.
    OpenTag, Open, "open", "Opening proposal."
);
tag!(
    /// Serde discriminator that only accepts the string `"accept"`.
    AcceptTag, Accept, "accept", "Opening acceptance."
);
tag!(
    /// Serde discriminator that only accepts the string `"commit"`.
    CommitTag, Commit, "commit", "Commitment signature."
);
tag!(
    /// Serde discriminator that only accepts the string `"ready"`.
    ReadyTag, Ready, "ready", "Initial commitments are ready."
);
tag!(
    /// Serde discriminator that only accepts the string `"update"`.
    UpdateTag, Update, "update", "Update message."
);
tag!(
    /// Serde discriminator that only accepts the string `"ack"`.
    AckTag, Ack, "ack", "Acknowledgement message."
);
tag!(
    /// Serde discriminator that only accepts the string `"revoke"`.
    RevokeTag, Revoke, "revoke", "Revocation message."
);
tag!(
    /// Serde discriminator that only accepts the string `"reject"`.
    RejectTag, Reject, "reject", "Refusal of an update."
);
tag!(
    /// Serde discriminator that only accepts the string `"close"`.
    CloseTag, Close, "close", "Cooperative close request."
);

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

/// Proofs of possession for the revocation points of an `open` or `accept`:
/// the basepoint and the per-state points of states zero and one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationProofs {
    /// Proof for the revocation basepoint, context `<id>/<role>/base`.
    pub base: PopSignature,
    /// Proofs for the per-state points of states zero and one, contexts
    /// `<id>/<role>/0` and `<id>/<role>/1`.
    pub rev: [PopSignature; 2],
}

/// `t=open`: A's channel parameters, revocation basepoint and first two
/// per-state revocation points, each with its proof of possession.
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
    /// A's per-state revocation points for states zero and one.
    pub rev: [NodeId; 2],
    /// A's revocation basepoint, the half of B's revocation keys A holds.
    #[serde(rename = "revBase")]
    pub rev_base: NodeId,
    /// Proofs of possession for `rev_base` and `rev`.
    pub pop: RevocationProofs,
    /// Optional one-hop routing fee advertised by a hub.
    #[serde(rename = "hubFee", default, skip_serializing_if = "Option::is_none")]
    pub hub_fee: Option<u64>,
}

/// `t=accept`: B's revocation basepoint and first points with proofs, and
/// B's signature on A's initial commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptMessage {
    /// Literal message discriminator.
    pub t: AcceptTag,
    /// Channel id.
    pub id: ChannelId,
    /// B's per-state revocation points for states zero and one.
    pub rev: [NodeId; 2],
    /// B's revocation basepoint.
    #[serde(rename = "revBase")]
    pub rev_base: NodeId,
    /// Proofs of possession for `rev_base` and `rev`.
    pub pop: RevocationProofs,
    /// B's signature on A's state-zero commitment.
    pub sig: LeafSignature,
    /// Optional one-hop routing fee advertised by a hub.
    #[serde(rename = "hubFee", default, skip_serializing_if = "Option::is_none")]
    pub hub_fee: Option<u64>,
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

/// `t=ready`: B confirms that both initial commitments are signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadyMessage {
    /// Literal message discriminator.
    pub t: ReadyTag,
    /// Channel id.
    pub id: ChannelId,
}

/// `t=update`: proposer signature and its next revocation point with proof.
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
    /// Proposer's signature on the receiver's new commitment. A resent
    /// update carries the same signature, so a reject can name it.
    pub sig: LeafSignature,
    /// Proposer's per-state revocation point for state `n + 1`.
    #[serde(rename = "nextRev")]
    pub next_rev: NodeId,
    /// Proof of possession for `next_rev`, context `<id>/<role>/<n + 1>`.
    #[serde(rename = "nextRevPop")]
    pub next_rev_pop: PopSignature,
}

/// `t=ack`: receiver signature, previous secret and next point with proof.
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
    /// Receiver's per-state secret for the previous state.
    pub reveal: Bytes32,
    /// Receiver's per-state revocation point for state `n + 1`.
    #[serde(rename = "nextRev")]
    pub next_rev: NodeId,
    /// Proof of possession for `next_rev`.
    #[serde(rename = "nextRevPop")]
    pub next_rev_pop: PopSignature,
}

/// `t=revoke`: proposer's previous per-state secret, which makes the
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

/// `t=reject`: an update the receiver will not sign. It names the update's
/// signature, so a reject answering an earlier attempt is ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectMessage {
    /// Literal message discriminator.
    pub t: RejectTag,
    /// Channel id.
    pub id: ChannelId,
    /// State number of the refused update.
    pub n: u64,
    /// Signature carried by the refused update.
    pub sig: LeafSignature,
    /// Display reason, at most [`MEMO_MAX`] UTF-16 code units.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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

/// `t=sync|synced`: persisted position and revocation recovery data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncMessage {
    /// Request or response discriminator.
    pub t: SyncTag,
    /// Channel id.
    pub id: ChannelId,
    /// Current state number.
    pub n: u64,
    /// Sender lifecycle status (see [`ChannelStatus::as_str`]), at most 32
    /// characters.
    ///
    /// [`ChannelStatus::as_str`]: super::ChannelStatus::as_str
    #[serde(default)]
    pub status: Option<String>,
    /// Locally pending proposal, or `null`.
    #[serde(rename = "pendingN", default)]
    pub pending_n: Option<u64>,
    /// Previous-state secret repeated by a peer at state one or later, unless
    /// that secret belongs to a commitment the peer has published.
    #[serde(default)]
    pub reveal: Option<Bytes32>,
    /// State numbers for which the sender lacks our secret.
    #[serde(default)]
    pub missing: Vec<u64>,
    /// Requested historical secrets, present on a `synced` response. On
    /// the wire the state numbers are JSON object keys, so strings.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_reveals"
    )]
    pub reveals: Option<BTreeMap<u64, Bytes32>>,
}

/// Any Hitch channel message, discriminated by its `t` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PeerMessage {
    /// `open`.
    Open(OpenMessage),
    /// `accept`.
    Accept(AcceptMessage),
    /// `commit`.
    Commit(CommitMessage),
    /// `ready`.
    Ready(ReadyMessage),
    /// `update`.
    Update(UpdateMessage),
    /// `ack`.
    Ack(AckMessage),
    /// `revoke`.
    Revoke(RevokeMessage),
    /// `reject`.
    Reject(RejectMessage),
    /// `close`.
    Close(CloseMessage),
    /// `sync` or `synced`.
    Sync(SyncMessage),
}

impl PeerMessage {
    /// The channel the message names.
    pub fn channel(&self) -> ChannelId {
        match self {
            Self::Open(m) => m.id,
            Self::Accept(m) => m.id,
            Self::Commit(m) => m.id,
            Self::Ready(m) => m.id,
            Self::Update(m) => m.id,
            Self::Ack(m) => m.id,
            Self::Revoke(m) => m.id,
            Self::Reject(m) => m.id,
            Self::Close(m) => m.id,
            Self::Sync(m) => m.id,
        }
    }

    /// Hitch's `wellFormed`: every field of the message has the shape and
    /// range Hitch accepts. Serde already enforced the encodings (hex
    /// lengths, integers, valid points); this adds the ranges and limits.
    /// The error names Hitch's reason (`"bad open"`, `"bad add"`, ...).
    pub fn well_formed(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Open(m) => m.well_formed(),
            Self::Accept(m) => m.well_formed(),
            Self::Commit(_) | Self::Ready(_) => Ok(()),
            Self::Update(m) => m.well_formed(),
            Self::Ack(m) => m.well_formed(),
            Self::Revoke(m) => m.well_formed(),
            Self::Reject(m) => m.well_formed(),
            Self::Close(_) => Ok(()),
            Self::Sync(m) => m.well_formed(),
        }
    }
}

macro_rules! into_peer_message {
    ($($ty:ident => $variant:ident),* $(,)?) => {$(
        impl From<$ty> for PeerMessage {
            fn from(message: $ty) -> Self {
                Self::$variant(message)
            }
        }
    )*};
}

into_peer_message!(
    OpenMessage => Open,
    AcceptMessage => Accept,
    CommitMessage => Commit,
    ReadyMessage => Ready,
    UpdateMessage => Update,
    AckMessage => Ack,
    RevokeMessage => Revoke,
    RejectMessage => Reject,
    CloseMessage => Close,
    SyncMessage => Sync,
);

fn hub_fee_ok(fee: Option<u64>) -> bool {
    fee.is_none_or(|fee| fee <= MAX_HUB_FEE)
}

impl OpenMessage {
    /// Hitch's boundary check for `open`.
    pub fn well_formed(&self) -> Result<(), ProtocolError> {
        let ok = self.funding.vout <= u32::from(u16::MAX)
            && (MIN_OPEN..=MAX_SATS).contains(&self.funding.value)
            && self.id == ChannelId::from_txid(self.funding.txid)
            && (MIN_DELAY..=MAX_DELAY).contains(&self.delay)
            && (MIN_FEE..=MAX_FEE).contains(&self.fee)
            && self.a != self.b
            && hub_fee_ok(self.hub_fee);
        if ok {
            Ok(())
        } else {
            Err(ProtocolError::Malformed("bad open"))
        }
    }
}

impl AcceptMessage {
    /// Hitch's boundary check for `accept`.
    pub fn well_formed(&self) -> Result<(), ProtocolError> {
        if hub_fee_ok(self.hub_fee) {
            Ok(())
        } else {
            Err(ProtocolError::Malformed("bad accept"))
        }
    }
}

impl UpdateMessage {
    /// Hitch's boundary check for `update`.
    pub fn well_formed(&self) -> Result<(), ProtocolError> {
        if self.n < 1 {
            return Err(ProtocolError::Malformed("bad update"));
        }
        self.update.well_formed()
    }
}

impl AckMessage {
    /// Hitch's boundary check for `ack`.
    pub fn well_formed(&self) -> Result<(), ProtocolError> {
        if self.n < 1 {
            return Err(ProtocolError::Malformed("bad ack"));
        }
        Ok(())
    }
}

impl RevokeMessage {
    /// Hitch's boundary check for `revoke`.
    pub fn well_formed(&self) -> Result<(), ProtocolError> {
        if self.n < 1 {
            return Err(ProtocolError::Malformed("bad revoke"));
        }
        Ok(())
    }
}

impl RejectMessage {
    /// Hitch's boundary check for `reject`.
    pub fn well_formed(&self) -> Result<(), ProtocolError> {
        if self.n < 1
            || self
                .reason
                .as_ref()
                .is_some_and(|r| utf16_len(r) > MEMO_MAX)
        {
            return Err(ProtocolError::Malformed("bad reject"));
        }
        Ok(())
    }
}

impl SyncMessage {
    /// Hitch's boundary check for `sync` and `synced`.
    pub fn well_formed(&self) -> Result<(), ProtocolError> {
        let ok = self.pending_n.is_none_or(|n| n >= 1)
            && self.missing.len() <= MAX_SYNC_ITEMS
            && self
                .reveals
                .as_ref()
                .is_none_or(|reveals| reveals.len() <= MAX_SYNC_ITEMS)
            && self
                .status
                .as_ref()
                .is_none_or(|status| utf16_len(status) <= MAX_STATUS_LEN);
        if ok {
            Ok(())
        } else {
            Err(ProtocolError::Malformed("bad sync"))
        }
    }
}

/// Length in JavaScript string units (UTF-16 code units), the measure
/// Hitch's limits use.
pub(crate) fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// Truncate to at most `limit` UTF-16 code units without splitting a
/// character, as Hitch's `String(reason).slice(0, MEMO_MAX)` does for text
/// in the Basic Multilingual Plane.
pub(crate) fn truncate_utf16(text: &str, limit: usize) -> String {
    let mut used = 0;
    let mut out = String::new();
    for c in text.chars() {
        used += c.len_utf16();
        if used > limit {
            break;
        }
        out.push(c);
    }
    out
}

fn lower_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn serialize_txid<S: Serializer>(txid: &Txid, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&txid.to_string())
}

/// The `reveals` map with its keys read as decimal strings. A JSON object's
/// keys are strings. `serde_json` turns them into integers when it reads a
/// `SyncMessage` directly, but not inside the untagged [`PeerMessage`],
/// which buffers its content first. Without this, every `synced` that
/// carries a secret was dropped by a host reading `PeerMessage`.
fn deserialize_reveals<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<BTreeMap<u64, Bytes32>>, D::Error> {
    let Some(raw) = Option::<BTreeMap<String, Bytes32>>::deserialize(deserializer)? else {
        return Ok(None);
    };
    raw.into_iter()
        .map(|(k, v)| {
            let canonical = !k.is_empty()
                && k.bytes().all(|b| b.is_ascii_digit())
                && (k == "0" || !k.starts_with('0'));
            if !canonical {
                return Err(serde::de::Error::custom("bad reveals key"));
            }
            k.parse::<u64>()
                .map(|n| (n, v))
                .map_err(|_| serde::de::Error::custom("bad reveals key"))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()
        .map(Some)
}

fn deserialize_txid<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Txid, D::Error> {
    let text = String::deserialize(deserializer)?;
    if !lower_hex(&text, 64) {
        return Err(serde::de::Error::custom("bad txid"));
    }
    Txid::from_str(&text).map_err(serde::de::Error::custom)
}
