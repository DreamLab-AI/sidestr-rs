//! One peer's channel: the update handshake, set-aside states, recovery,
//! closes and the periodic tick.

use std::collections::BTreeMap;

use bitcoin::secp256k1::{SecretKey, XOnlyPublicKey};
use bitcoin::{Amount, Transaction, Txid};
use serde::{Deserialize, Serialize};
use sidestr_core::sighash::SighashRules;

use super::chain::{ClaimRecord, CloseRecord, FollowedOutput, SpendRecord};
use super::wire::truncate_utf16;
use super::{
    node_less, pop_context, public, secret, sha, AckMessage, AckTag, Broadcast, Bytes32,
    ChannelEvent, ChannelId, ChannelStatus, CloseMessage, CloseTag, CommitMessage, CommitTag,
    Context, NodeId, OfferedHtlc, OpeningKeys, PaymentOutcome, PeerMessage, PopPlace,
    ProtocolError, ProtocolHtlc, ReadyMessage, ReadyTag, RejectMessage, RejectTag, RevokeMessage,
    RevokeTag, Route, SyncMessage, SyncTag, Update, UpdateMessage, UpdateTag, WireSide,
    AWAITING_RESYNC, CLAIM_MARGIN, CLOSE_DEPTH, CLOSE_REBROADCAST, DEFAULT_PENDING_TIMEOUT,
    EXPIRY_MARGIN, MAX_PENDING_BACKOFF, MEMO_MAX, MIN_HTLC, RESYNC_INTERVAL,
};
use crate::{
    pop_sign, pop_verify, revocation_pub, Balances, Channel, ChannelState, Commitment,
    LeafSignature, PopSignature, RevocationKeys, Side, MAX_EXPIRY,
};

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

impl ProtocolState {
    fn balance(&self, side: Side) -> u64 {
        match side {
            Side::A => self.balance_a,
            Side::B => self.balance_b,
        }
    }

    fn same_outputs(&self, other: &Self) -> bool {
        self.balance_a == other.balance_a
            && self.balance_b == other.balance_b
            && self.htlcs == other.htlcs
    }
}

/// A pending locally proposed update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingUpdate {
    /// Proposed state number.
    pub n: u64,
    /// Transition that produced it.
    pub update: Update,
    /// Signed wire message, resent unchanged so a reject can name its
    /// signature.
    pub message: UpdateMessage,
    /// Unix time of the latest send.
    pub at: u64,
    /// How many times it has been sent.
    pub tries: u32,
}

/// An incoming update that has been acknowledged but is not final until the
/// sender's previous-state secret arrives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwaitingRevoke {
    /// New state number.
    pub n: u64,
    /// Previous state whose secret is owed.
    pub previous: u64,
    /// Verified update.
    pub update: Update,
    /// Sender role.
    pub sender: WireSide,
    /// Unix time the acknowledgement was made.
    pub at: u64,
}

/// A verified update that crossed its finality boundary (Hitch's
/// `io.onUpdate` when the other side sent it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalisedUpdate {
    /// New state number.
    pub n: u64,
    /// Transition now safe to act upon.
    pub update: Update,
    /// Peer who proposed it.
    pub sender: Side,
}

/// A state this peer signed for the other side that did not become the
/// agreed state. The other side may still publish it until it revokes that
/// state number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAlternative {
    /// Balances and HTLCs of the signed state.
    pub state: ProtocolState,
    /// The update that produced it, so a late acknowledgement can adopt it.
    pub update: Update,
}

/// An update of this peer's that was set aside, waiting to be announced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DroppedUpdate {
    /// The update.
    pub update: Update,
    /// Why it was set aside.
    pub reason: String,
}

/// Where a payment hash still has force on a channel (Hitch's `bound`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// An HTLC of the agreed state.
    State,
    /// This peer's pending `add`.
    Pending,
    /// A set-aside state this peer signed and the other side has not
    /// revoked: they could still publish it.
    Alt,
    /// An output of a close that is still being followed.
    Chain,
}

impl std::fmt::Display for Bound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::State => "state",
            Self::Pending => "pending",
            Self::Alt => "alt",
            Self::Chain => "chain",
        })
    }
}

/// Result of receiving an update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveUpdate {
    /// The update is accepted: send this acknowledgement.
    Acknowledge(AckMessage),
    /// The same accepted update arrived again: send this acknowledgement
    /// again.
    ResendAcknowledgement(AckMessage),
    /// The next update arrived before the prior revocation and is held until
    /// that state is final ([`ChannelMachine::take_buffered_update`]).
    Buffered,
    /// The update is refused: send this reject so the proposer sets its
    /// signed state aside.
    Rejected(RejectMessage),
    /// Both proposed at once and this peer's pending update stands (lower
    /// node id): send this reject.
    LocalProposalWins(RejectMessage),
}

/// Result of an acknowledgement of this peer's update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckOutcome {
    /// The revocation to send.
    pub revoke: RevokeMessage,
    /// The update that is now the agreed state.
    pub update: FinalisedUpdate,
    /// Whether the acknowledged state was one this peer had set aside and
    /// adopted after all, because the signature it gave was binding.
    pub adopted: bool,
}

/// Result of a sync or synced message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    /// An incoming update that became final with a secret the sync carried.
    pub finalised: Option<FinalisedUpdate>,
    /// Messages to send, in order: the `synced` answer, then whatever the
    /// reconcile resends.
    pub replies: Vec<PeerMessage>,
}

/// Classification of a transaction spending the channel funding output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum FundingSpend {
    /// The cooperative close this peer signed.
    Cooperative,
    /// This peer's published commitment.
    LocalCommitment {
        /// Commitment state number.
        state: u64,
    },
    /// A commitment of the other side's: the agreed state, the state of this
    /// peer's pending update, or an alternative this peer signed.
    RemoteCommitment {
        /// Commitment state number.
        state: u64,
        /// Whether it is a set-aside alternative.
        alternative: bool,
        /// Whether the other side has revealed this state's secret.
        revoked: bool,
    },
    /// None of the transactions this peer knows.
    Unknown,
}

/// What the periodic tick asks of the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TickAction {
    /// Send this message.
    Send(Box<PeerMessage>),
    /// Broadcast this transaction.
    Broadcast(Broadcast),
    /// Propose a settle with this preimage, via
    /// [`ChannelMachine::settle_htlc`] with a fresh secret.
    Settle {
        /// HTLC id.
        htlc_id: u64,
        /// Its preimage.
        preimage: Bytes32,
    },
    /// Propose a fail of an expired HTLC this peer offered, via
    /// [`ChannelMachine::fail_htlc`].
    Fail {
        /// HTLC id.
        htlc_id: u64,
        /// Hitch's reason, `"expired"`.
        reason: String,
    },
}

/// Host settings for [`ChannelMachine::tick`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TickOptions {
    /// Seconds before an unanswered update is sent again; doubles per try,
    /// at most [`MAX_PENDING_BACKOFF`].
    pub pending_timeout: u64,
}

impl Default for TickOptions {
    fn default() -> Self {
        Self {
            pending_timeout: DEFAULT_PENDING_TIMEOUT,
        }
    }
}

#[derive(Clone)]
pub(crate) struct Keys {
    pub(crate) channel: SecretKey,
    pub(crate) revocation_base: SecretKey,
    pub(crate) revocation: [SecretKey; 2],
}

impl From<OpeningKeys> for Keys {
    fn from(keys: OpeningKeys) -> Self {
        Self {
            channel: keys.channel,
            revocation_base: keys.revocation_base,
            revocation: keys.revocation,
        }
    }
}

/// One peer's channel after both initial commitments are signed.
///
/// Every method that changes the machine must be followed by an atomic save
/// of [`Self::snapshot`] before anything it returned is sent or broadcast.
/// Methods return `Err` without changing the machine, except that a set-aside
/// queued by an earlier call may be announced.
#[derive(Debug, Clone)]
pub struct ChannelMachine {
    pub(crate) id: ChannelId,
    pub(crate) role: Side,
    pub(crate) channel_key: SecretKey,
    pub(crate) channel: Channel,
    pub(crate) status: ChannelStatus,
    pub(crate) funded_height: Option<u32>,
    pub(crate) state_number: u64,
    pub(crate) states: BTreeMap<u64, ProtocolState>,
    pub(crate) my_revocation_base: SecretKey,
    pub(crate) their_revocation_base: XOnlyPublicKey,
    pub(crate) my_revocation: BTreeMap<u64, SecretKey>,
    pub(crate) their_revocation: BTreeMap<u64, SecretKey>,
    pub(crate) their_revocation_public: BTreeMap<u64, XOnlyPublicKey>,
    pub(crate) signatures: BTreeMap<u64, LeafSignature>,
    pub(crate) pending: Option<PendingUpdate>,
    pub(crate) awaiting: Option<AwaitingRevoke>,
    pub(crate) buffered: Option<UpdateMessage>,
    pub(crate) signed_alternatives: BTreeMap<u64, Vec<SignedAlternative>>,
    pub(crate) dropped: Option<DroppedUpdate>,
    pub(crate) preimages: BTreeMap<[u8; 32], [u8; 32]>,
    pub(crate) htlc_seq: u64,
    pub(crate) peer_hub_fee: Option<u64>,
    pub(crate) coop_txid: Option<Txid>,
    pub(crate) close: Option<CloseRecord>,
    pub(crate) spend: Option<SpendRecord>,
    pub(crate) close_state: Option<u64>,
    pub(crate) close_state_obj: Option<ProtocolState>,
    pub(crate) outputs: BTreeMap<u32, FollowedOutput>,
    pub(crate) claims: Vec<ClaimRecord>,
    pub(crate) penalties: Vec<Txid>,
    pub(crate) last_sync_at: Option<u64>,
    pub(crate) peer_ahead: Option<u64>,
    pub(crate) events: Vec<ChannelEvent>,
    pub(crate) rules: SighashRules,
}

impl ChannelMachine {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: ChannelId,
        role: Side,
        channel: Channel,
        initial_state: ProtocolState,
        keys: Keys,
        their_revocation_base: XOnlyPublicKey,
        their_revocation: [XOnlyPublicKey; 2],
        their_signature_zero: LeafSignature,
        peer_hub_fee: Option<u64>,
        rules: SighashRules,
    ) -> Result<Self, ProtocolError> {
        if public(&keys.channel) != channel.key(role) {
            return Err(ProtocolError::WrongChannelKey);
        }
        let machine = Self {
            id,
            role,
            channel_key: keys.channel,
            channel,
            status: ChannelStatus::Funding,
            funded_height: None,
            state_number: 0,
            states: BTreeMap::from([(0, initial_state)]),
            my_revocation_base: keys.revocation_base,
            their_revocation_base,
            my_revocation: BTreeMap::from([(0, keys.revocation[0]), (1, keys.revocation[1])]),
            their_revocation: BTreeMap::new(),
            their_revocation_public: BTreeMap::from([
                (0, their_revocation[0]),
                (1, their_revocation[1]),
            ]),
            signatures: BTreeMap::from([(0, their_signature_zero)]),
            pending: None,
            awaiting: None,
            buffered: None,
            signed_alternatives: BTreeMap::new(),
            dropped: None,
            preimages: BTreeMap::new(),
            htlc_seq: 1,
            peer_hub_fee,
            coop_txid: None,
            close: None,
            spend: None,
            close_state: None,
            close_state_obj: None,
            outputs: BTreeMap::new(),
            claims: Vec::new(),
            penalties: Vec::new(),
            last_sync_at: None,
            peer_ahead: None,
            events: Vec::new(),
            rules,
        };
        let initial = machine.my_commitment(0)?;
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

    // ---- queries

    /// Channel id.
    pub fn id(&self) -> ChannelId {
        self.id
    }

    /// This peer's role.
    pub fn role(&self) -> Side {
        self.role
    }

    /// The other peer's node id.
    pub fn peer(&self) -> XOnlyPublicKey {
        self.peer_key()
    }

    /// Lifecycle status.
    pub fn status(&self) -> ChannelStatus {
        self.status
    }

    /// The channel's transaction parameters.
    pub fn channel(&self) -> &Channel {
        &self.channel
    }

    /// The channel's CSV delay.
    pub fn delay(&self) -> u16 {
        self.channel.delay
    }

    /// Height at which the funding confirmed, once known.
    pub fn funded_height(&self) -> Option<u32> {
        self.funded_height
    }

    /// The hub fee the other side advertised when the channel opened.
    pub fn peer_hub_fee(&self) -> Option<u64> {
        self.peer_hub_fee
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

    /// A state this peer holds, by number.
    pub fn state_at(&self, n: u64) -> Option<&ProtocolState> {
        self.states.get(&n)
    }

    /// HTLCs of the agreed state.
    pub fn htlcs(&self) -> &[ProtocolHtlc] {
        &self.current_state().htlcs
    }

    /// This peer's free balance in the agreed state.
    pub fn my_balance(&self) -> u64 {
        self.current_state().balance(self.role)
    }

    /// The other peer's free balance in the agreed state.
    pub fn their_balance(&self) -> u64 {
        self.current_state().balance(self.role.other())
    }

    /// What this peer can still send: its balance less the fee the funder
    /// keeps. Negative when a funder's balance is below the fee.
    pub fn room(&self) -> i64 {
        let fee = if self.role == Side::A {
            self.channel.fee.to_sat()
        } else {
            0
        };
        self.my_balance() as i64 - fee as i64
    }

    /// Pending locally proposed update, if any.
    pub fn pending(&self) -> Option<&PendingUpdate> {
        self.pending.as_ref()
    }

    /// Incoming update still waiting for the proposer's revocation.
    pub fn awaiting_revoke(&self) -> Option<&AwaitingRevoke> {
        self.awaiting.as_ref()
    }

    /// Alternative states this peer signed at state number `n`.
    pub fn signed_alternatives(&self, n: u64) -> &[SignedAlternative] {
        self.signed_alternatives
            .get(&n)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// A set-aside update not yet announced through
    /// [`ChannelEvent::Dropped`] (it is, once nothing is pending or awaited).
    pub fn dropped(&self) -> Option<&DroppedUpdate> {
        self.dropped.as_ref()
    }

    /// This peer's per-state revocation point for state `n`, as announced to
    /// the other side.
    pub fn my_revocation_point(&self, n: u64) -> Option<XOnlyPublicKey> {
        self.my_revocation.get(&n).map(public)
    }

    /// This peer's revocation basepoint, as announced when the channel opened.
    pub fn my_revocation_basepoint(&self) -> XOnlyPublicKey {
        public(&self.my_revocation_base)
    }

    /// Whether the counterparty's secret for state `n` is known.
    pub fn has_their_revocation(&self, n: u64) -> bool {
        self.their_revocation.contains_key(&n)
    }

    /// The state the other side claims when it is more than one ahead of
    /// this peer's (a restored file?), kept in memory only.
    pub fn peer_ahead(&self) -> Option<u64> {
        self.peer_ahead
    }

    /// Hitch's `knownPreimage`: a preimage this peer has checked and kept.
    pub fn known_preimage(&self, hash: &Bytes32) -> Option<Bytes32> {
        self.preimages.get(&hash.0).copied().map(Bytes32)
    }

    /// Hitch's `rememberPreimage`: keep a preimage for off-chain settlement or
    /// an on-chain claim. The hash is computed here, so only a true preimage
    /// is ever kept.
    pub fn remember_preimage(&mut self, preimage: [u8; 32]) {
        self.preimages.entry(sha(&preimage)).or_insert(preimage);
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

    /// The transaction id of the cooperative close this peer signed, if any.
    pub fn coop_txid(&self) -> Option<Txid> {
        self.coop_txid
    }

    /// The close this peer holds fully signed and published, if any.
    pub fn close_transaction_published(&self) -> Option<&Transaction> {
        self.close.as_ref().map(|close| &close.tx)
    }

    /// The state number of the commitment that closed the channel, once
    /// classified.
    pub fn close_state(&self) -> Option<u64> {
        self.close_state
    }

    /// The state of a set-aside alternative the other side published, once
    /// classified.
    pub fn close_state_alternative(&self) -> Option<&ProtocolState> {
        self.close_state_obj.as_ref()
    }

    /// Take the events queued since the last call.
    pub fn drain_events(&mut self) -> Vec<ChannelEvent> {
        std::mem::take(&mut self.events)
    }

    /// Hitch's `bound`: where a payment hash still has force on this channel.
    /// A hub keeps the upstream HTLC until this returns `None`.
    pub fn bound(&self, hash: &Bytes32, height: u32) -> Option<Bound> {
        if self.htlcs().iter().any(|h| h.hash == *hash) {
            return Some(Bound::State);
        }
        if self
            .pending
            .as_ref()
            .and_then(|p| p.update.added_hash())
            .is_some_and(|added| added == *hash)
        {
            return Some(Bound::Pending);
        }
        // A shallow spend could still be reorganised away.
        let shallow = self.spend.as_ref().is_none_or(|spend| {
            height.saturating_add(1).saturating_sub(spend.height) < CLOSE_DEPTH
        });
        if shallow
            && self.signed_alternatives.iter().any(|(n, alternatives)| {
                !self.their_revocation.contains_key(n)
                    && alternatives
                        .iter()
                        .any(|alt| alt.state.htlcs.iter().any(|h| h.hash == *hash))
            })
        {
            return Some(Bound::Alt);
        }
        if self.spend.is_some()
            && self.outputs.values().any(|output| {
                output.hash == Some(*hash) && output.confirmed.is_none() && output.theirs.is_none()
            })
        {
            return Some(Bound::Chain);
        }
        None
    }

    /// This peer's commitment at agreed state `n` (Hitch's `myCommitAt`).
    pub fn my_commitment(&self, n: u64) -> Result<Commitment, ProtocolError> {
        let state = self.state(n)?;
        self.commitment_at(self.role, n, state)
    }

    /// The other side's commitment at state `n` for `state` (Hitch's
    /// `theirCommitAt`).
    pub fn their_commitment(
        &self,
        n: u64,
        state: &ProtocolState,
    ) -> Result<Commitment, ProtocolError> {
        self.commitment_at(self.role.other(), n, state)
    }

    // ---- funding

    /// The funding confirmed: a `funding` channel opens. Hitch opens at
    /// [`super::MIN_CONF`] confirmations; the host decides when.
    pub fn confirm_funding(&mut self, height: u32) {
        if self.funded_height.is_none() {
            self.funded_height = Some(height);
        }
        if self.status == ChannelStatus::Funding {
            self.status = ChannelStatus::Open;
        }
    }

    // ---- updates from this peer

    /// Propose the next update and return the signed `update` message.
    /// The caller supplies a fresh secret for state `n + 2`'s announcement,
    /// keeping key generation outside this deterministic machine; it is kept
    /// only if that state has no secret yet.
    pub fn propose(
        &mut self,
        update: Update,
        next_revocation: SecretKey,
        ctx: &Context,
    ) -> Result<UpdateMessage, ProtocolError> {
        if self.status != ChannelStatus::Open {
            return Err(ProtocolError::Status("not open"));
        }
        if self.pending.is_some() {
            return Err(ProtocolError::Pending);
        }
        if self.awaiting.is_some() {
            return Err(ProtocolError::AwaitingRevocation);
        }
        if let Some(n) = self.missing_reveals().first() {
            return Err(ProtocolError::MissingReveal(*n));
        }
        let n = self.state_number + 1;
        if !self.their_revocation_public.contains_key(&n) {
            return Err(ProtocolError::MissingRevocationKey(n));
        }
        let text_ok = |text: &Option<String>| {
            text.as_ref()
                .is_none_or(|t| super::wire::utf16_len(t) <= MEMO_MAX)
        };
        match &update {
            Update::Pay { memo, .. } | Update::Add { memo, .. } if !text_ok(memo) => {
                return Err(ProtocolError::MemoTooLong)
            }
            Update::Fail { reason, .. } if !text_ok(reason) => {
                return Err(ProtocolError::MemoTooLong)
            }
            _ => {}
        }
        if !matches!(update, Update::Pay { .. }) && ctx.stale {
            return Err(ProtocolError::StaleChain);
        }
        let mut update = update;
        if let Update::Add { htlc, .. } = &mut update {
            htlc.id = self.next_htlc_id(self.current_state());
            if let Some(bound) = self.bound(&htlc.hash, ctx.height) {
                return Err(ProtocolError::HashBound(bound));
            }
        }
        update.well_formed()?;
        let state = self.next_state(self.current_state(), &update, self.role, ctx.height)?;
        if !self.my_revocation.contains_key(&n) {
            return Err(ProtocolError::MissingRevocationKey(n));
        }
        let commitment = self.commitment_at(self.role.other(), n, &state)?;
        let sig =
            self.channel
                .sign_funding(&commitment.tx, &self.channel_key, self.rules, &ctx.aux)?;
        self.my_revocation.entry(n + 1).or_insert(next_revocation);
        self.states.insert(n, state);
        let message = UpdateMessage {
            t: UpdateTag::Update,
            id: self.id,
            n,
            update: update.clone(),
            sig,
            next_rev: NodeId(public(&self.my_revocation[&(n + 1)])),
            next_rev_pop: self.my_pop(n + 1, &ctx.aux),
        };
        self.pending = Some(PendingUpdate {
            n,
            update,
            message: message.clone(),
            at: ctx.now,
            tries: 1,
        });
        Ok(message)
    }

    /// Hitch's `pay`: send `amount` directly.
    pub fn pay(
        &mut self,
        amount: u64,
        memo: Option<String>,
        next_revocation: SecretKey,
        ctx: &Context,
    ) -> Result<UpdateMessage, ProtocolError> {
        if amount == 0 {
            return Err(ProtocolError::ZeroAmount);
        }
        if amount as i64 > self.room() {
            return Err(ProtocolError::TooMuch(self.room().max(0) as u64));
        }
        self.propose(Update::Pay { amount, memo }, next_revocation, ctx)
    }

    /// Hitch's `addHtlc`: lock `amount` to `hash` until `expiry`, optionally
    /// routed one hop further by a hub.
    #[allow(clippy::too_many_arguments)]
    pub fn add_htlc(
        &mut self,
        amount: u64,
        hash: Bytes32,
        expiry: u32,
        route: Option<Route>,
        memo: Option<String>,
        next_revocation: SecretKey,
        ctx: &Context,
    ) -> Result<UpdateMessage, ProtocolError> {
        if amount < MIN_HTLC {
            return Err(ProtocolError::HtlcTooSmall);
        }
        if amount as i64 > self.room() {
            return Err(ProtocolError::TooMuch(self.room().max(0) as u64));
        }
        if !(1..MAX_EXPIRY).contains(&expiry) {
            return Err(ProtocolError::BadExpiry);
        }
        let htlc = OfferedHtlc {
            id: 0,
            amount,
            hash,
            expiry,
            route,
        };
        self.propose(Update::Add { htlc, memo }, next_revocation, ctx)
    }

    /// Hitch's `settleHtlc`. The preimage is kept first, whatever becomes of
    /// the update, so the HTLC can still be claimed on the chain.
    pub fn settle_htlc(
        &mut self,
        htlc_id: u64,
        preimage: Bytes32,
        next_revocation: SecretKey,
        ctx: &Context,
    ) -> Result<UpdateMessage, ProtocolError> {
        self.remember_preimage(preimage.0);
        self.propose(Update::Settle { htlc_id, preimage }, next_revocation, ctx)
    }

    /// Hitch's `failHtlc`; the reason is cut to [`MEMO_MAX`] characters.
    pub fn fail_htlc(
        &mut self,
        htlc_id: u64,
        reason: Option<&str>,
        next_revocation: SecretKey,
        ctx: &Context,
    ) -> Result<UpdateMessage, ProtocolError> {
        let reason = reason.map(|text| truncate_utf16(text, MEMO_MAX));
        self.propose(Update::Fail { htlc_id, reason }, next_revocation, ctx)
    }

    /// The pending update to send again, unchanged (the same signature), with
    /// its try counted.
    pub fn resend_update(&mut self, ctx: &Context) -> Option<UpdateMessage> {
        let pending = self.pending.as_mut()?;
        pending.tries = pending.tries.saturating_add(1);
        pending.at = ctx.now;
        Some(pending.message.clone())
    }

    // ---- messages from the other side

    /// Verify and accept a peer's update, refuse it with a reject, or resolve
    /// a simultaneous proposal. The supplied secret becomes this peer's
    /// state-`n + 1` revocation secret unless that state already has one.
    pub fn receive_update(
        &mut self,
        message: UpdateMessage,
        next_revocation: SecretKey,
        ctx: &Context,
    ) -> Result<ReceiveUpdate, ProtocolError> {
        message.well_formed()?;
        self.check_id(message.id)?;
        if self.status == ChannelStatus::ClosingAsked {
            return Ok(ReceiveUpdate::Rejected(reject(
                &message,
                "a cooperative close at the current state is signed; answer it (a resync brings it again)",
            )));
        }
        if self.status != ChannelStatus::Open {
            return Err(ProtocolError::Status(self.status.as_str()));
        }
        if message.n == self.state_number && self.signatures.get(&message.n) == Some(&message.sig) {
            return self
                .acknowledgement(ctx)?
                .map(ReceiveUpdate::ResendAcknowledgement)
                .ok_or(ProtocolError::Status(self.status.as_str()));
        }
        if message.n == self.state_number {
            return Ok(ReceiveUpdate::Rejected(reject(
                &message,
                &format!(
                    "state {} is already agreed with a different update",
                    message.n
                ),
            )));
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
        if let Some(n) = self.missing_reveals().first() {
            return Err(ProtocolError::MissingReveal(*n));
        }
        if !matches!(message.update, Update::Pay { .. }) && ctx.stale {
            return Err(ProtocolError::StaleChain);
        }
        if !self.their_pop_ok(message.n + 1, &message.next_rev.0, &message.next_rev_pop) {
            return Ok(ReceiveUpdate::Rejected(reject(
                &message,
                "the next revocation point comes without proof of its secret",
            )));
        }
        let sender = self.role.other();
        let state = match self.next_state(self.current_state(), &message.update, sender, ctx.height)
        {
            Ok(state) => state,
            Err(error) => {
                return Ok(ReceiveUpdate::Rejected(reject(
                    &message,
                    &error.to_string(),
                )))
            }
        };
        let mine = self.commitment_at(self.role, message.n, &state)?;
        if !self
            .channel
            .verify_funding(&mine.tx, &self.peer_key(), &message.sig, self.rules)
        {
            return Ok(ReceiveUpdate::Rejected(reject(
                &message,
                "the signature on my new commitment does not verify",
            )));
        }
        if self.pending.is_some() {
            if !node_less(self.peer_key(), self.my_key()) {
                return Ok(ReceiveUpdate::LocalProposalWins(reject(
                    &message,
                    "collision: the lower key's update stands",
                )));
            }
            self.drop_pending("they proposed at the same time and the lower key wins");
        }
        self.states.insert(message.n, state);
        self.their_revocation_public
            .insert(message.n + 1, message.next_rev.0);
        self.my_revocation
            .entry(message.n + 1)
            .or_insert(next_revocation);
        self.signatures.insert(message.n, message.sig);
        self.bump_htlc_seq(&message.update);
        if let Update::Settle { preimage, .. } = &message.update {
            self.remember_preimage(preimage.0);
        }
        let previous = self.state_number;
        self.state_number = message.n;
        self.awaiting = Some(AwaitingRevoke {
            n: message.n,
            previous,
            update: message.update,
            sender: sender.into(),
            at: ctx.now,
        });
        let ack = self
            .acknowledgement(ctx)?
            .ok_or(ProtocolError::Status(self.status.as_str()))?;
        Ok(ReceiveUpdate::Acknowledge(ack))
    }

    /// Verify the acknowledgement of this peer's pending update, advance, and
    /// return the revocation to send. An acknowledgement of a state this
    /// peer had set aside is adopted, since the signature it gave was
    /// binding; one that fits an earlier attempt at the pending state number
    /// is adopted over the newer pending, which is set aside.
    pub fn receive_ack(&mut self, message: AckMessage) -> Result<AckOutcome, ProtocolError> {
        message.well_formed()?;
        self.check_id(message.id)?;
        if !matches!(
            self.status,
            ChannelStatus::Open | ChannelStatus::ClosingAsked
        ) {
            return Err(ProtocolError::Status(self.status.as_str()));
        }
        if self.pending.is_none() && message.n == self.state_number + 1 {
            return self.adopt_alternative(&message);
        }
        let pending = match &self.pending {
            Some(pending) if pending.n == message.n => pending.clone(),
            _ => return Err(ProtocolError::NoPending),
        };
        let mine = self.commitment_at(self.role, pending.n, self.state(pending.n)?)?;
        if !self
            .channel
            .verify_funding(&mine.tx, &self.peer_key(), &message.sig, self.rules)
        {
            let current = self.state_number;
            let reveal_ok = self
                .their_revocation
                .get(&current)
                .is_some_and(|known| known.secret_bytes() == message.reveal.0)
                || secret(message.reveal)
                    .is_ok_and(|s| self.their_revocation_public.get(&current) == Some(&public(&s)));
            let earlier = self.status == ChannelStatus::Open
                && reveal_ok
                && self.their_pop_ok(message.n + 1, &message.next_rev.0, &message.next_rev_pop)
                && self.find_alternative(message.n, &message.sig).is_some();
            if !earlier {
                return Err(ProtocolError::BadSignature);
            }
            self.drop_pending("they acknowledged an earlier attempt at this state instead");
            let outcome = self.adopt_alternative(&message);
            self.announce_dropped();
            return outcome;
        }
        if !self.their_pop_ok(pending.n + 1, &message.next_rev.0, &message.next_rev_pop) {
            return Err(ProtocolError::MissingProof);
        }
        let current = self.state_number;
        if !self.take_their_reveal(current, message.reveal)
            && self
                .their_revocation
                .get(&current)
                .is_none_or(|known| known.secret_bytes() != message.reveal.0)
        {
            return Err(ProtocolError::BadRevocation);
        }
        self.their_revocation_public
            .insert(pending.n + 1, message.next_rev.0);
        self.signatures.insert(pending.n, message.sig);
        self.bump_htlc_seq(&pending.update);
        let previous = self.state_number;
        self.state_number = pending.n;
        self.pending = None;
        match &pending.update {
            Update::Settle { preimage, .. } => self.remember_preimage(preimage.0),
            Update::Fail { htlc_id, reason } => {
                if let Some(was) = self.offered_in(previous, *htlc_id) {
                    self.events.push(ChannelEvent::Payment {
                        hash: was.hash,
                        outcome: PaymentOutcome::Failed,
                        reason: Some(reason.clone().unwrap_or_else(|| "expired".into())),
                    });
                }
            }
            _ => {}
        }
        Ok(AckOutcome {
            revoke: self.revoke_message(pending.n, previous),
            update: FinalisedUpdate {
                n: pending.n,
                update: pending.update,
                sender: self.role,
            },
            adopted: false,
        })
    }

    /// Accept the proposer's previous-state secret and cross this peer's
    /// finality boundary. After a finalised update, call
    /// [`Self::take_buffered_update`].
    pub fn receive_revoke(
        &mut self,
        message: RevokeMessage,
    ) -> Result<Option<FinalisedUpdate>, ProtocolError> {
        message.well_formed()?;
        self.check_id(message.id)?;
        if !matches!(
            self.status,
            ChannelStatus::Open | ChannelStatus::ClosingAsked
        ) && self.awaiting.is_none()
        {
            return Err(ProtocolError::Status(self.status.as_str()));
        }
        if message.n > self.state_number {
            return Err(ProtocolError::UnexpectedState {
                got: message.n,
                expected: self.state_number,
            });
        }
        let index = message.n - 1;
        if !self.take_their_reveal(index, message.reveal) {
            if self.their_revocation.contains_key(&index) {
                return Ok(None);
            }
            return Err(ProtocolError::BadRevocation);
        }
        Ok(self.finalise())
    }

    /// A refusal of this peer's pending update. Only a reject naming the
    /// pending update's state and signature counts; the update is set aside
    /// (its signed state remembered) and a resync is returned to send.
    pub fn receive_reject(
        &mut self,
        message: RejectMessage,
        ctx: &Context,
    ) -> Result<Option<SyncMessage>, ProtocolError> {
        message.well_formed()?;
        self.check_id(message.id)?;
        match &self.pending {
            Some(pending) if pending.n == message.n && pending.message.sig == message.sig => {}
            _ => return Err(ProtocolError::NoPending),
        }
        let reason = message
            .reason
            .as_deref()
            .unwrap_or("no reason given")
            .to_owned();
        self.drop_pending(&format!("they refused it: {reason}"));
        self.announce_dropped();
        Ok(self.resync(ctx, false))
    }

    /// Take an update held while the preceding state awaited its revocation.
    /// Pass it back to [`Self::receive_update`] with a fresh secret.
    pub fn take_buffered_update(&mut self) -> Option<UpdateMessage> {
        if self.awaiting.is_none() {
            self.buffered.take()
        } else {
            None
        }
    }

    // ---- closing

    /// Sign the cooperative close at the current state and enter
    /// `closing-asked`: from here updates at this state are refused with a
    /// reject.
    pub fn close_channel(&mut self, ctx: &Context) -> Result<CloseMessage, ProtocolError> {
        if !matches!(self.status, ChannelStatus::Open | ChannelStatus::Funding) {
            return Err(ProtocolError::Status("not open"));
        }
        if self.pending.is_some() || self.awaiting.is_some() {
            return Err(ProtocolError::InFlight);
        }
        let message = self.close_message(ctx)?;
        self.status = ChannelStatus::ClosingAsked;
        self.coop_txid = Some(self.cooperative_tx()?.compute_txid());
        Ok(message)
    }

    /// Verify the other side's cooperative-close signature at the current
    /// state and return the fully witnessed close to broadcast.
    pub fn receive_close(
        &mut self,
        message: CloseMessage,
        ctx: &Context,
    ) -> Result<Broadcast, ProtocolError> {
        self.check_id(message.id)?;
        if !matches!(
            self.status,
            ChannelStatus::Open | ChannelStatus::Funding | ChannelStatus::ClosingAsked
        ) {
            return Err(ProtocolError::Status(self.status.as_str()));
        }
        if message.n != self.state_number {
            return Err(ProtocolError::UnexpectedState {
                got: message.n,
                expected: self.state_number,
            });
        }
        if self.pending.is_some() || self.awaiting.is_some() {
            return Err(ProtocolError::InFlight);
        }
        let mut tx = self.cooperative_tx()?;
        if !self
            .channel
            .verify_funding(&tx, &self.peer_key(), &message.sig, self.rules)
        {
            return Err(ProtocolError::BadSignature);
        }
        let mine = self
            .channel
            .sign_funding(&tx, &self.channel_key, self.rules, &ctx.aux)?;
        tx.input[0].witness = self.channel.funding_witness(&BTreeMap::from([
            (self.my_key(), mine),
            (self.peer_key(), message.sig),
        ]))?;
        let txid = tx.compute_txid();
        self.status = ChannelStatus::Closing;
        self.coop_txid = Some(txid);
        self.close = Some(CloseRecord {
            txid,
            tx: tx.clone(),
            state: None,
            at: ctx.height,
        });
        Ok(Broadcast {
            label: "cooperative close".into(),
            tx,
        })
    }

    /// Publish this peer's commitment at state `state` (the current one by
    /// default). A pending update is set aside first; after this no
    /// acknowledgement or sync draws out the secret of the published state.
    pub fn force_close(
        &mut self,
        state: Option<u64>,
        why: &str,
        ctx: &Context,
    ) -> Result<Broadcast, ProtocolError> {
        if !matches!(
            self.status,
            ChannelStatus::Open
                | ChannelStatus::ClosingAsked
                | ChannelStatus::Closing
                | ChannelStatus::Funding
        ) {
            return Err(ProtocolError::Status(self.status.as_str()));
        }
        let n = state.unwrap_or(self.state_number);
        if !self.signatures.contains_key(&n) {
            return Err(ProtocolError::MissingSignature(n));
        }
        if self.funded_height.is_none() && self.status != ChannelStatus::Open {
            return Err(ProtocolError::Unfunded);
        }
        let tx = self.signed_commitment(n, &ctx.aux)?;
        if self.pending.is_some() {
            self.drop_pending("the channel is being closed");
        }
        self.status = ChannelStatus::ForceClosing;
        self.close = Some(CloseRecord {
            txid: tx.compute_txid(),
            tx: tx.clone(),
            state: Some(n),
            at: ctx.height,
        });
        self.awaiting = None;
        self.buffered = None;
        self.announce_dropped();
        Ok(Broadcast {
            label: format!("{why} close"),
            tx,
        })
    }

    /// This peer's commitment at agreed state `n` with both funding
    /// signatures installed, as a forced close would publish it. Nothing
    /// changes; the other side's retained signature is checked first.
    pub fn signed_commitment(&self, n: u64, aux: &[u8; 32]) -> Result<Transaction, ProtocolError> {
        let theirs = *self
            .signatures
            .get(&n)
            .ok_or(ProtocolError::MissingSignature(n))?;
        let mut commitment = self.my_commitment(n)?;
        if !self
            .channel
            .verify_funding(&commitment.tx, &self.peer_key(), &theirs, self.rules)
        {
            return Err(ProtocolError::BadSignature);
        }
        let mine = self
            .channel
            .sign_funding(&commitment.tx, &self.channel_key, self.rules, aux)?;
        commitment.tx.input[0].witness = self.channel.funding_witness(&BTreeMap::from([
            (self.my_key(), mine),
            (self.peer_key(), theirs),
        ]))?;
        Ok(commitment.tx)
    }

    // ---- recovery

    /// This peer's position: state, pending proposal, the previous secret
    /// (never one of a commitment this peer has published) and the secrets
    /// it lacks.
    pub fn sync_message(&self, tag: SyncTag) -> SyncMessage {
        let reveal = self
            .state_number
            .checked_sub(1)
            .filter(|n| self.may_reveal(*n))
            .and_then(|n| self.my_revocation.get(&n))
            .map(|secret| Bytes32(secret.secret_bytes()));
        SyncMessage {
            t: tag,
            id: self.id,
            n: self.state_number,
            status: Some(self.status.as_str().into()),
            pending_n: self.pending.as_ref().map(|pending| pending.n),
            reveal,
            missing: self.missing_reveals(),
            reveals: None,
        }
    }

    /// Hitch's `resync`: a sync to send, at most once every 30 seconds unless
    /// `force`.
    pub fn resync(&mut self, ctx: &Context, force: bool) -> Option<SyncMessage> {
        if !force
            && self
                .last_sync_at
                .is_some_and(|at| ctx.now.saturating_sub(at) < RESYNC_INTERVAL)
        {
            return None;
        }
        self.last_sync_at = Some(ctx.now);
        Some(self.sync_message(SyncTag::Sync))
    }

    /// Import the secrets a sync carries, finalise an update they complete,
    /// answer a `sync` with the secrets asked for (never one of a published
    /// commitment), and reconcile: resend what the other side lost, resolve a
    /// collision, carry the close or the opening handshake forward.
    pub fn receive_sync(
        &mut self,
        message: &SyncMessage,
        ctx: &Context,
    ) -> Result<SyncOutcome, ProtocolError> {
        message.well_formed()?;
        self.check_id(message.id)?;
        if let (Some(reveal), Some(index)) = (message.reveal, message.n.checked_sub(1)) {
            self.take_their_reveal(index, reveal);
        }
        if let Some(reveals) = &message.reveals {
            for (index, reveal) in reveals {
                self.take_their_reveal(*index, *reveal);
            }
        }
        let finalised = self.finalise();
        let mut replies = Vec::new();
        if message.t == SyncTag::Sync {
            let reveals = message
                .missing
                .iter()
                .filter(|n| self.may_reveal(**n))
                .filter_map(|n| {
                    self.my_revocation
                        .get(n)
                        .map(|secret| (*n, Bytes32(secret.secret_bytes())))
                })
                .collect();
            let mut synced = self.sync_message(SyncTag::Synced);
            synced.reveals = Some(reveals);
            replies.push(synced.into());
        }
        self.reconcile(message, ctx, &mut replies)?;
        Ok(SyncOutcome { finalised, replies })
    }

    /// An acknowledgement of the current state again, for a peer one state
    /// behind; `None` if its secret belongs to a published commitment.
    pub fn acknowledgement(&self, ctx: &Context) -> Result<Option<AckMessage>, ProtocolError> {
        let n = self.state_number;
        let Some(previous) = n.checked_sub(1) else {
            return Ok(None);
        };
        if !self.signatures.contains_key(&n) || !self.may_reveal(previous) {
            return Ok(None);
        }
        let theirs = self.commitment_at(self.role.other(), n, self.state(n)?)?;
        let sig = self
            .channel
            .sign_funding(&theirs.tx, &self.channel_key, self.rules, &ctx.aux)?;
        let next = self
            .my_revocation
            .get(&(n + 1))
            .ok_or(ProtocolError::MissingRevocationKey(n + 1))?;
        Ok(Some(AckMessage {
            t: AckTag::Ack,
            id: self.id,
            n,
            sig,
            reveal: Bytes32(self.my_revocation[&previous].secret_bytes()),
            next_rev: NodeId(public(next)),
            next_rev_pop: self.my_pop(n + 1, &ctx.aux),
        }))
    }

    /// Hitch's periodic tick for this channel: an unconfirmed close published
    /// again, a pending add that would expire set aside, an unanswered update
    /// resent with backoff, a late revocation resynced, a set-aside update
    /// announced, the protective close for an HTLC this peer can claim
    /// (`delay + CLAIM_MARGIN` before its expiry) or for an overdue offered
    /// HTLC whose fail is unanswered, and then one settle or fail to propose.
    pub fn tick(&mut self, ctx: &Context, options: &TickOptions) -> Vec<TickAction> {
        let mut out = Vec::new();
        let height = ctx.height;
        if matches!(
            self.status,
            ChannelStatus::ForceClosing | ChannelStatus::Closing
        ) && self.spend.is_none()
        {
            if let Some(close) = &mut self.close {
                if height.saturating_sub(close.at) > CLOSE_REBROADCAST {
                    close.at = height;
                    out.push(TickAction::Broadcast(Broadcast {
                        label: "close (again, still unconfirmed)".into(),
                        tx: close.tx.clone(),
                    }));
                }
            }
        }
        if !self.status.is_live() {
            return out;
        }
        let delay = u32::from(self.channel.delay);
        if let Some(pending) = self.pending.clone() {
            let expiring = match &pending.update {
                Update::Add { htlc, .. } => {
                    height >= htlc.expiry.saturating_sub(delay + EXPIRY_MARGIN)
                }
                _ => false,
            };
            let wait = options
                .pending_timeout
                .saturating_mul(1u64 << pending.tries.saturating_sub(1).min(32))
                .min(MAX_PENDING_BACKOFF);
            if expiring {
                self.drop_pending("the HTLC would expire before it could be added");
                self.announce_dropped();
            } else if ctx.now.saturating_sub(pending.at) >= wait {
                if let Some(sync) = self.resync(ctx, false) {
                    out.push(TickAction::Send(Box::new(sync.into())));
                }
                if let Some(update) = self.resend_update(ctx) {
                    out.push(TickAction::Send(Box::new(update.into())));
                }
            }
        }
        let late = self
            .awaiting
            .as_ref()
            .is_some_and(|w| ctx.now.saturating_sub(w.at) > AWAITING_RESYNC);
        if late || !self.missing_reveals().is_empty() {
            if let Some(sync) = self.resync(ctx, false) {
                out.push(TickAction::Send(Box::new(sync.into())));
            }
        }
        if self.status != ChannelStatus::Open {
            return out;
        }
        self.announce_dropped();
        let me: WireSide = self.role.into();
        // Deadlines on the chain come before anything a pending update could
        // hold up: an HTLC this peer can claim must be on the chain `delay +
        // CLAIM_MARGIN` blocks before its expiry, because the claim on its
        // own commitment waits `delay` blocks and the refund does not.
        let urgent = self.htlcs().iter().any(|h| {
            h.from != me
                && self.preimages.contains_key(&h.hash.0)
                && height >= h.expiry.saturating_sub(delay + CLAIM_MARGIN)
        });
        if urgent {
            if let Ok(broadcast) = self.force_close(None, "protective", ctx) {
                out.push(TickAction::Broadcast(broadcast));
            }
            return out;
        }
        let overdue = self
            .htlcs()
            .iter()
            .find(|h| h.from == me && height >= h.expiry.saturating_add(CLOSE_DEPTH))
            .map(|h| h.id);
        if let Some(id) = overdue {
            let fail_unanswered =
                self.pending
                    .as_ref()
                    .is_some_and(|p| matches!(p.update, Update::Fail { .. }))
                    || self.awaiting.is_some()
                    || self.signed_alternatives(self.state_number + 1).iter().any(
                        |alt| matches!(alt.update, Update::Fail { htlc_id, .. } if htlc_id == id),
                    );
            if fail_unanswered {
                if let Ok(broadcast) = self.force_close(None, "protective", ctx) {
                    out.push(TickAction::Broadcast(broadcast));
                }
                return out;
            }
        }
        if self.pending.is_some() || self.awaiting.is_some() || !self.missing_reveals().is_empty() {
            return out;
        }
        for htlc in self.htlcs() {
            if htlc.from != me {
                if let Some(preimage) = self.preimages.get(&htlc.hash.0) {
                    out.push(TickAction::Settle {
                        htlc_id: htlc.id,
                        preimage: Bytes32(*preimage),
                    });
                    break;
                }
            } else if height >= htlc.expiry {
                out.push(TickAction::Fail {
                    htlc_id: htlc.id,
                    reason: "expired".into(),
                });
                break;
            }
        }
        out
    }

    // ---- internals

    pub(crate) fn state(&self, n: u64) -> Result<&ProtocolState, ProtocolError> {
        self.states.get(&n).ok_or(ProtocolError::MissingState(n))
    }

    pub(crate) fn my_key(&self) -> XOnlyPublicKey {
        self.channel.key(self.role)
    }

    pub(crate) fn peer_key(&self) -> XOnlyPublicKey {
        self.channel.key(self.role.other())
    }

    /// The two-party revocation key of `owner`'s commitment at state `n`:
    /// the counterparty's basepoint plus the owner's per-state point.
    pub(crate) fn revocation_for(
        &self,
        owner: Side,
        n: u64,
    ) -> Result<XOnlyPublicKey, ProtocolError> {
        if owner == self.role {
            let per_state = self
                .my_revocation
                .get(&n)
                .ok_or(ProtocolError::MissingRevocationKey(n))?;
            Ok(revocation_pub(self.their_revocation_base, per_state)?)
        } else {
            let point = self
                .their_revocation_public
                .get(&n)
                .ok_or(ProtocolError::MissingRevocationKey(n))?;
            Ok(revocation_pub(*point, &self.my_revocation_base)?)
        }
    }

    pub(crate) fn commitment_at(
        &self,
        owner: Side,
        n: u64,
        state: &ProtocolState,
    ) -> Result<Commitment, ProtocolError> {
        // A commitment uses only its owner's revocation key.
        let key = self.revocation_for(owner, n)?;
        let channel_state = ChannelState {
            balances: Balances {
                a: Amount::from_sat(state.balance_a),
                b: Amount::from_sat(state.balance_b),
            },
            revocation: RevocationKeys { a: key, b: key },
            htlcs: state.htlcs.iter().map(ProtocolHtlc::channel_htlc).collect(),
        };
        Ok(self.channel.commitment(n, owner, &channel_state)?)
    }

    fn cooperative_tx(&self) -> Result<Transaction, ProtocolError> {
        let state = self.current_state();
        let channel_state = ChannelState {
            balances: Balances {
                a: Amount::from_sat(state.balance_a),
                b: Amount::from_sat(state.balance_b),
            },
            revocation: RevocationKeys {
                a: self.channel.keys[0],
                b: self.channel.keys[1],
            },
            htlcs: state.htlcs.iter().map(ProtocolHtlc::channel_htlc).collect(),
        };
        Ok(self.channel.cooperative_close(&channel_state)?)
    }

    fn close_message(&self, ctx: &Context) -> Result<CloseMessage, ProtocolError> {
        let tx = self.cooperative_tx()?;
        Ok(CloseMessage {
            t: CloseTag::Close,
            id: self.id,
            n: self.state_number,
            sig: self
                .channel
                .sign_funding(&tx, &self.channel_key, self.rules, &ctx.aux)?,
        })
    }

    fn my_pop(&self, n: u64, aux: &[u8; 32]) -> PopSignature {
        pop_sign(
            &self.my_revocation[&n],
            &pop_context(self.id, self.role.into(), PopPlace::State(n)),
            aux,
        )
    }

    fn their_pop_ok(&self, n: u64, point: &XOnlyPublicKey, proof: &PopSignature) -> bool {
        pop_verify(
            point,
            proof,
            &pop_context(self.id, self.role.other().into(), PopPlace::State(n)),
        )
    }

    fn revoke_message(&self, n: u64, previous: u64) -> RevokeMessage {
        RevokeMessage {
            t: RevokeTag::Revoke,
            id: self.id,
            n,
            reveal: Bytes32(self.my_revocation[&previous].secret_bytes()),
        }
    }

    /// Never the secret of a commitment this peer has published.
    pub(crate) fn may_reveal(&self, n: u64) -> bool {
        n < self.state_number
            && !self
                .close
                .as_ref()
                .is_some_and(|close| n >= close.state.unwrap_or(self.state_number))
    }

    fn next_htlc_id(&self, state: &ProtocolState) -> u64 {
        let above = state.htlcs.iter().map(|h| h.id).max().unwrap_or(0) + 1;
        self.htlc_seq.max(above)
    }

    fn bump_htlc_seq(&mut self, update: &Update) {
        if let Update::Add { htlc, .. } = update {
            self.htlc_seq = self.htlc_seq.max(htlc.id + 1);
        }
    }

    fn offered_in(&self, n: u64, htlc_id: u64) -> Option<ProtocolHtlc> {
        let me: WireSide = self.role.into();
        self.states
            .get(&n)?
            .htlcs
            .iter()
            .find(|h| h.id == htlc_id && h.from == me)
            .cloned()
    }

    fn find_alternative(&self, n: u64, sig: &LeafSignature) -> Option<usize> {
        self.signed_alternatives(n).iter().position(|alt| {
            self.commitment_at(self.role, n, &alt.state)
                .is_ok_and(|mine| {
                    self.channel
                        .verify_funding(&mine.tx, &self.peer_key(), sig, self.rules)
                })
        })
    }

    fn adopt_alternative(&mut self, message: &AckMessage) -> Result<AckOutcome, ProtocolError> {
        if self.status != ChannelStatus::Open {
            return Err(ProtocolError::Status(self.status.as_str()));
        }
        let index = self
            .find_alternative(message.n, &message.sig)
            .ok_or(ProtocolError::NoPending)?;
        if !self.their_pop_ok(message.n + 1, &message.next_rev.0, &message.next_rev_pop) {
            return Err(ProtocolError::MissingProof);
        }
        if !self.my_revocation.contains_key(&(message.n + 1)) {
            return Err(ProtocolError::MissingRevocationKey(message.n + 1));
        }
        let current = self.state_number;
        if !self.take_their_reveal(current, message.reveal)
            && self
                .their_revocation
                .get(&current)
                .is_none_or(|known| known.secret_bytes() != message.reveal.0)
        {
            return Err(ProtocolError::BadRevocation);
        }
        let alternative = self
            .signed_alternatives
            .get_mut(&message.n)
            .expect("found above")
            .remove(index);
        self.states.insert(message.n, alternative.state);
        self.their_revocation_public
            .insert(message.n + 1, message.next_rev.0);
        self.signatures.insert(message.n, message.sig);
        self.bump_htlc_seq(&alternative.update);
        let previous = self.state_number;
        self.state_number = message.n;
        match &alternative.update {
            Update::Settle { preimage, .. } => self.remember_preimage(preimage.0),
            Update::Add { htlc, .. } => self.events.push(ChannelEvent::Payment {
                hash: htlc.hash,
                outcome: PaymentOutcome::InFlight,
                reason: None,
            }),
            _ => {}
        }
        Ok(AckOutcome {
            revoke: self.revoke_message(message.n, previous),
            update: FinalisedUpdate {
                n: message.n,
                update: alternative.update,
                sender: self.role,
            },
            adopted: true,
        })
    }

    pub(crate) fn take_their_reveal(&mut self, index: u64, reveal: Bytes32) -> bool {
        if self.their_revocation.contains_key(&index) {
            return false;
        }
        let Some(point) = self.their_revocation_public.get(&index) else {
            return false;
        };
        let Ok(secret) = secret(reveal) else {
            return false;
        };
        if public(&secret) != *point {
            return false;
        }
        self.their_revocation.insert(index, secret);
        true
    }

    /// Their revocation of the state before the one they proposed makes that
    /// state final: only now is it acted on.
    fn finalise(&mut self) -> Option<FinalisedUpdate> {
        let awaiting = self.awaiting.clone()?;
        if !self.their_revocation.contains_key(&awaiting.previous) {
            return None;
        }
        self.awaiting = None;
        match &awaiting.update {
            Update::Settle { htlc_id, .. } => {
                if let Some(was) = self.offered_in(awaiting.previous, *htlc_id) {
                    self.events.push(ChannelEvent::Payment {
                        hash: was.hash,
                        outcome: PaymentOutcome::Sent,
                        reason: None,
                    });
                }
            }
            Update::Fail { htlc_id, reason } => {
                if let Some(was) = self.offered_in(awaiting.previous, *htlc_id) {
                    self.events.push(ChannelEvent::Payment {
                        hash: was.hash,
                        outcome: PaymentOutcome::Failed,
                        reason: reason.clone(),
                    });
                }
            }
            _ => {}
        }
        let finalised = FinalisedUpdate {
            n: awaiting.n,
            update: awaiting.update,
            sender: awaiting.sender.into(),
        };
        self.announce_dropped();
        Some(finalised)
    }

    fn remember_alternative(&mut self, n: u64, state: ProtocolState, update: Update) {
        let alternatives = self.signed_alternatives.entry(n).or_default();
        if !alternatives
            .iter()
            .any(|alt| alt.state.same_outputs(&state))
        {
            alternatives.push(SignedAlternative { state, update });
        }
    }

    /// Set the pending update aside: the state signed for it is remembered as
    /// one the other side might publish.
    pub(crate) fn drop_pending(&mut self, why: &str) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        if let Some(state) = self.states.remove(&pending.n) {
            self.remember_alternative(pending.n, state, pending.update.clone());
        }
        self.dropped = Some(DroppedUpdate {
            update: pending.update,
            reason: why.into(),
        });
    }

    fn announce_dropped(&mut self) {
        if self.pending.is_some() || self.awaiting.is_some() {
            return;
        }
        let Some(dropped) = self.dropped.take() else {
            return;
        };
        if let Update::Add { htlc, .. } = &dropped.update {
            self.events.push(ChannelEvent::Payment {
                hash: htlc.hash,
                outcome: PaymentOutcome::NotMade,
                reason: Some(dropped.reason.clone()),
            });
        }
        self.events.push(ChannelEvent::Dropped(dropped));
    }

    fn reconcile(
        &mut self,
        message: &SyncMessage,
        ctx: &Context,
        out: &mut Vec<PeerMessage>,
    ) -> Result<(), ProtocolError> {
        let theirs = message.status.as_deref().unwrap_or("");
        // The opening handshake, by the status each side reports.
        if self.status == ChannelStatus::Funding && self.role == Side::A {
            if theirs == "accepted" {
                let commitment = self.commitment_at(Side::B, 0, self.state(0)?)?;
                out.push(
                    CommitMessage {
                        t: CommitTag::Commit,
                        id: self.id,
                        sig: self.channel.sign_funding(
                            &commitment.tx,
                            &self.channel_key,
                            self.rules,
                            &ctx.aux,
                        )?,
                    }
                    .into(),
                );
            }
            return Ok(());
        }
        if self.status == ChannelStatus::Funding
            && self.role == Side::B
            && matches!(theirs, "funding" | "open")
        {
            out.push(
                ReadyMessage {
                    t: ReadyTag::Ready,
                    id: self.id,
                }
                .into(),
            );
        }
        if self.status == ChannelStatus::ClosingAsked
            && matches!(theirs, "open" | "funding" | "closing-asked")
        {
            out.push(self.close_message(ctx)?.into());
        }
        if !matches!(
            self.status,
            ChannelStatus::Open | ChannelStatus::ClosingAsked
        ) {
            return Ok(());
        }
        let n = self.state_number;
        if message.n == n {
            let pending_n = self.pending.as_ref().map(|p| p.n);
            match (pending_n, message.pending_n) {
                (Some(_), None) => {
                    if let Some(update) = self.resend_update(ctx) {
                        out.push(update.into());
                    }
                }
                (Some(mine), Some(theirs)) if mine == theirs => {
                    if node_less(self.peer_key(), self.my_key()) {
                        self.drop_pending("both of us proposed at once and the lower key wins");
                        self.announce_dropped();
                    } else if let Some(update) = self.resend_update(ctx) {
                        out.push(update.into());
                    }
                }
                _ => {}
            }
            return Ok(());
        }
        if message.n + 1 == n && message.pending_n.is_none_or(|p| p == n) {
            if let Some(ack) = self.acknowledgement(ctx)? {
                out.push(ack.into());
            }
            return Ok(());
        }
        if message.n == n + 1 && self.pending.as_ref().is_some_and(|p| p.n == message.n) {
            // They reached the state on my update; they resend the
            // acknowledgement on their own resync.
            return Ok(());
        }
        if message.n > n + 1 {
            self.peer_ahead = Some(message.n);
        }
        Ok(())
    }

    fn check_id(&self, id: ChannelId) -> Result<(), ProtocolError> {
        if id != self.id {
            return Err(ProtocolError::WrongChannel);
        }
        Ok(())
    }

    /// The next state from `current` by `update` from `sender`; both sides
    /// compute it and must agree.
    pub(crate) fn next_state(
        &self,
        current: &ProtocolState,
        update: &Update,
        sender: Side,
        height: u32,
    ) -> Result<ProtocolState, ProtocolError> {
        let mut state = current.clone();
        let other = sender.other();
        match update {
            Update::Pay { amount, .. } => {
                subtract_balance(&mut state, sender, *amount)?;
                add_balance(&mut state, other, *amount)?;
            }
            Update::Add { htlc, .. } => {
                if htlc.id != self.next_htlc_id(current) {
                    return Err(ProtocolError::BadHtlcId);
                }
                if htlc.expiry
                    <= height
                        .saturating_add(u32::from(self.channel.delay))
                        .saturating_add(EXPIRY_MARGIN)
                {
                    return Err(ProtocolError::ExpiryTooSoon);
                }
                let pending_same = self
                    .pending
                    .as_ref()
                    .and_then(|p| p.update.added_hash())
                    .is_some_and(|hash| hash == htlc.hash);
                if state.htlcs.iter().any(|known| known.hash == htlc.hash) || pending_same {
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
                if sha(&preimage.0) != htlc.hash.0 {
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
        // A commitment with no fee cannot be mined: never sign one.
        if state.balance_a < self.channel.fee.to_sat() {
            return Err(ProtocolError::FunderFee);
        }
        Ok(state)
    }
}

fn reject(message: &UpdateMessage, why: &str) -> RejectMessage {
    RejectMessage {
        t: RejectTag::Reject,
        id: message.id,
        n: message.n,
        sig: message.sig,
        reason: Some(truncate_utf16(why, MEMO_MAX)),
    }
}

fn subtract_balance(
    state: &mut ProtocolState,
    side: Side,
    amount: u64,
) -> Result<(), ProtocolError> {
    let balance = match side {
        Side::A => &mut state.balance_a,
        Side::B => &mut state.balance_b,
    };
    *balance = balance
        .checked_sub(amount)
        .ok_or(ProtocolError::NegativeBalance)?;
    Ok(())
}

fn add_balance(state: &mut ProtocolState, side: Side, amount: u64) -> Result<(), ProtocolError> {
    let balance = match side {
        Side::A => &mut state.balance_a,
        Side::B => &mut state.balance_b,
    };
    *balance = balance
        .checked_add(amount)
        .ok_or(ProtocolError::BalanceOverflow)?;
    Ok(())
}
