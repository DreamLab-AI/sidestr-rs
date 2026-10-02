//! The funding output was spent: classify the spend, then answer it with
//! penalties, delayed sweeps and HTLC claims, and follow every output until
//! it is settled on the chain.

use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut, Txid, Witness};
use serde::{Deserialize, Serialize};

use super::machine::{ChannelMachine, FundingSpend, ProtocolState};
use super::{
    Broadcast, Bytes32, ChannelEvent, ChannelStatus, Context, PaymentOutcome, ProtocolError,
    WireSide, CLAIM_REBROADCAST, CLOSE_DEPTH,
};
use crate::{
    claim_htlc, preimage_in, revocation_key, sign_leaf, sweep_to_local, CommitmentHtlc, HtlcClaim,
    HtlcClaimPath, LeafSignature, SweepPath,
};

type TxHex = bitcoin::consensus::serde::With<bitcoin::consensus::serde::Hex>;

/// A close of this peer's: the cooperative close it holds fully signed, or
/// its own commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CloseRecord {
    pub(crate) txid: Txid,
    #[serde(with = "TxHex")]
    pub(crate) tx: Transaction,
    /// The commitment's state, or `None` for a cooperative close.
    pub(crate) state: Option<u64>,
    /// Height of the latest broadcast.
    pub(crate) at: u32,
}

/// The transaction that spent the funding output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SpendRecord {
    pub(crate) txid: Txid,
    pub(crate) height: u32,
    /// The status before the spend, restored if a reorganisation undoes it.
    pub(crate) previous_status: ChannelStatus,
    pub(crate) kind: FundingSpend,
}

/// A spend of the funding output seen in a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainSpend {
    /// The spending transaction.
    pub txid: Txid,
    /// The block height that holds it.
    pub height: u32,
}

/// What a host's chain watch knows about one output of a close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputLookup {
    /// Not spent in any block the host has seen.
    Unspent,
    /// Spent in a block.
    Spent {
        /// Spending transaction id.
        txid: Txid,
        /// Block height.
        height: u32,
        /// The spending transaction, read for a preimage the other side
        /// revealed.
        tx: Transaction,
    },
    /// The lookup failed; the output counts as still open.
    Unknown,
}

/// The answer to a funding spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendOutcome {
    /// What the spend was.
    pub kind: FundingSpend,
    /// Penalties, sweeps and claims to broadcast now.
    pub broadcasts: Vec<Broadcast>,
}

/// A claim this peer makes on an output of a close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "htlc", rename_all = "kebab-case")]
pub enum ClaimKind {
    /// This peer's `to_local`, after the delay.
    SweepToLocal,
    /// An HTLC paid to this peer, with the preimage.
    HtlcSuccess(u64),
    /// An HTLC this peer offered, after its expiry.
    HtlcRefund(u64),
    /// A revoked commitment's `to_local`.
    PenaltyToLocal,
    /// A revoked commitment's HTLC output.
    PenaltyHtlc(u64),
}

impl std::fmt::Display for ClaimKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SweepToLocal => f.write_str("sweep of to_local"),
            Self::HtlcSuccess(id) => write!(f, "claim of htlc {id} with the preimage"),
            Self::HtlcRefund(id) => write!(f, "refund of htlc {id} after its expiry"),
            Self::PenaltyToLocal => f.write_str("penalty on to_local"),
            Self::PenaltyHtlc(id) => write!(f, "penalty on htlc {id}"),
        }
    }
}

/// A claim transaction this peer made and published.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimRecord {
    /// What it claims.
    pub kind: ClaimKind,
    /// Claim transaction id.
    pub txid: Txid,
    /// The claimed output of the close.
    pub vout: u32,
    /// The claim, kept for a rebroadcast.
    #[serde(with = "TxHex")]
    pub tx: Transaction,
    /// Height of the latest broadcast.
    pub at: u32,
}

/// An output of a close this peer follows until it settles on the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FollowedOutput {
    /// Hitch's name for it, such as `"htlc 3"` or a claim's name.
    pub name: String,
    /// The payment hash of an HTLC output.
    pub hash: Option<Bytes32>,
    /// Whether this peer offered that HTLC.
    pub offered_by_me: bool,
    /// Whether this peer claims it.
    pub mine: bool,
    /// Height at which this peer's claim confirmed.
    pub confirmed: Option<u32>,
    /// The other side's spend, if they took it.
    pub theirs: Option<Txid>,
}

impl FollowedOutput {
    fn named(name: String) -> Self {
        Self {
            name,
            hash: None,
            offered_by_me: false,
            mine: false,
            confirmed: None,
            theirs: None,
        }
    }
}

impl ChannelMachine {
    /// The funding transaction id this peer saw spent, and when.
    pub fn spent_by(&self) -> Option<(Txid, u32)> {
        self.spend.as_ref().map(|spend| (spend.txid, spend.height))
    }

    /// The outputs of the close being followed, by output index.
    pub fn followed_outputs(&self) -> &std::collections::BTreeMap<u32, FollowedOutput> {
        &self.outputs
    }

    /// Claims and penalties this peer published.
    pub fn claims(&self) -> &[ClaimRecord] {
        &self.claims
    }

    /// Penalty transaction ids published against a revoked commitment.
    pub fn penalties(&self) -> &[Txid] {
        &self.penalties
    }

    /// Hitch's `onSpend`: the funding output was spent in a block. The spend
    /// is classified against the cooperative close, this peer's published
    /// commitment, and every commitment of the other side's it signed (each
    /// agreed state, the state of a pending update, and every set-aside
    /// alternative). An unrevoked close of theirs is followed; a revoked one
    /// is answered with a penalty on each output, paid to `destination`.
    pub fn on_spend(
        &mut self,
        spend: ChainSpend,
        destination: &ScriptBuf,
        ctx: &Context,
        lookup: impl FnMut(OutPoint, u32) -> OutputLookup,
    ) -> Result<SpendOutcome, ProtocolError> {
        if let Some(seen) = &self.spend {
            if seen.txid == spend.txid {
                let kind = seen.kind;
                let broadcasts = self.after_close(destination, ctx, lookup);
                return Ok(SpendOutcome { kind, broadcasts });
            }
        }
        let previous_status = self.status;
        let record = |kind| SpendRecord {
            txid: spend.txid,
            height: spend.height,
            previous_status,
            kind,
        };
        self.outputs.clear();
        if self.coop_txid == Some(spend.txid) {
            self.spend = Some(record(FundingSpend::Cooperative));
            self.status = ChannelStatus::ClosedCoop;
            return Ok(SpendOutcome {
                kind: FundingSpend::Cooperative,
                broadcasts: vec![],
            });
        }
        if let Some(close) = self.close.as_ref().filter(|close| close.txid == spend.txid) {
            let kind = FundingSpend::LocalCommitment {
                state: close.state.unwrap_or(self.state_number),
            };
            self.spend = Some(record(kind));
            self.status = ChannelStatus::ClosedMine;
            self.close_state_obj = None;
            let broadcasts = self.after_close(destination, ctx, lookup);
            return Ok(SpendOutcome { kind, broadcasts });
        }
        let mut candidates: Vec<(u64, ProtocolState, bool)> = Vec::new();
        for n in 0..=self.state_number {
            candidates.push((n, self.state(n)?.clone(), false));
            for alt in self.signed_alternatives(n) {
                candidates.push((n, alt.state.clone(), true));
            }
        }
        if let Some(pending) = &self.pending {
            candidates.push((pending.n, self.state(pending.n)?.clone(), false));
        }
        for alt in self.signed_alternatives(self.state_number + 1) {
            candidates.push((self.state_number + 1, alt.state.clone(), true));
        }
        for (n, state, alternative) in candidates {
            let Ok(commitment) = self.their_commitment(n, &state) else {
                continue;
            };
            if commitment.tx.compute_txid() != spend.txid {
                continue;
            }
            let revoked = self.their_revocation.contains_key(&n);
            let kind = FundingSpend::RemoteCommitment {
                state: n,
                alternative,
                revoked,
            };
            self.spend = Some(record(kind));
            self.close_state = Some(n);
            self.close_state_obj = Some(state);
            if !revoked {
                self.status = if alternative {
                    ChannelStatus::ClosedTheirsAlt
                } else {
                    ChannelStatus::ClosedTheirs
                };
                let broadcasts = self.after_close(destination, ctx, lookup);
                return Ok(SpendOutcome { kind, broadcasts });
            }
            let broadcasts = self.punish(n, &commitment, destination, ctx)?;
            return Ok(SpendOutcome { kind, broadcasts });
        }
        self.spend = Some(record(FundingSpend::Unknown));
        self.status = ChannelStatus::SpentUnknown;
        Ok(SpendOutcome {
            kind: FundingSpend::Unknown,
            broadcasts: vec![],
        })
    }

    fn punish(
        &mut self,
        n: u64,
        commitment: &crate::Commitment,
        destination: &ScriptBuf,
        ctx: &Context,
    ) -> Result<Vec<Broadcast>, ProtocolError> {
        let secret = revocation_key(&self.my_revocation_base, &self.their_revocation[&n])?;
        let fee = self.channel.fee;
        let mut made: Vec<(ClaimKind, u32, Transaction)> = Vec::new();
        if let Some(vout) = commitment.to_local_vout {
            if let Ok(tx) = sweep_to_local(
                commitment,
                SweepPath::Revocation,
                destination.clone(),
                fee,
                &secret,
                self.rules,
                &ctx.aux,
            ) {
                made.push((ClaimKind::PenaltyToLocal, vout, tx));
            }
        }
        for htlc in &commitment.htlcs {
            let claim = HtlcClaim {
                path: HtlcClaimPath::Revocation,
                destination: destination.clone(),
                fee,
                preimage: None,
            };
            if let Ok(tx) = claim_htlc(commitment, htlc, claim, &secret, self.rules, &ctx.aux) {
                made.push((ClaimKind::PenaltyHtlc(htlc.htlc.id), htlc.vout, tx));
            }
        }
        self.status = ChannelStatus::Punishing;
        self.penalties.clear();
        let mut broadcasts = Vec::new();
        for (kind, vout, tx) in made {
            let claim_txid = tx.compute_txid();
            self.penalties.push(claim_txid);
            self.claims.retain(|claim| claim.kind != kind);
            self.claims.push(ClaimRecord {
                kind,
                txid: claim_txid,
                vout,
                tx: tx.clone(),
                at: ctx.height,
            });
            let output = self
                .outputs
                .entry(vout)
                .or_insert_with(|| FollowedOutput::named(kind.to_string()));
            output.name = kind.to_string();
            output.mine = true;
            broadcasts.push(Broadcast {
                label: format!("{kind} (their revoked state {n})"),
                tx,
            });
        }
        Ok(broadcasts)
    }

    /// Hitch's `unSpend`: the spend was undone by a reorganisation. The
    /// channel goes back to where it was and the claims are forgotten; a close
    /// this peer published stays published (it can confirm later), so the
    /// channel never goes back to `open` and the close is returned to send
    /// again.
    pub fn un_spend(&mut self) -> Option<Broadcast> {
        let spend = self.spend.take()?;
        let back = spend.previous_status;
        self.claims.clear();
        self.penalties.clear();
        self.outputs.clear();
        self.close_state_obj = None;
        match &self.close {
            Some(close) if back.is_closed_out() => {
                self.status = if back == ChannelStatus::ClosingAsked {
                    ChannelStatus::Closing
                } else {
                    back
                };
                Some(Broadcast {
                    label: "close (again after a reorganisation)".into(),
                    tx: close.tx.clone(),
                })
            }
            _ => {
                self.status = back;
                None
            }
        }
    }

    /// Hitch's `afterClose`: after a close by either side's commitment, claim
    /// what is this peer's when it can be claimed (its `to_local` after the
    /// delay, an HTLC paid to it with the preimage, an HTLC it offered after
    /// the expiry), then follow every output. A cooperative close is final
    /// at [`CLOSE_DEPTH`] blocks.
    pub fn after_close(
        &mut self,
        destination: &ScriptBuf,
        ctx: &Context,
        lookup: impl FnMut(OutPoint, u32) -> OutputLookup,
    ) -> Vec<Broadcast> {
        let height = ctx.height;
        if self.status == ChannelStatus::ClosedCoop {
            if self.spend.as_ref().is_some_and(|spend| {
                height.saturating_add(1).saturating_sub(spend.height) >= CLOSE_DEPTH
            }) {
                self.status = ChannelStatus::Closed;
            }
            return vec![];
        }
        if matches!(
            self.status,
            ChannelStatus::Punishing | ChannelStatus::Settling
        ) {
            return self.watch_outputs(ctx, lookup);
        }
        let mine = match self.status {
            ChannelStatus::ClosedMine => true,
            ChannelStatus::ClosedTheirs | ChannelStatus::ClosedTheirsAlt => false,
            _ => return vec![],
        };
        let Some(spend) = self.spend.clone() else {
            return vec![];
        };
        let n = if mine {
            self.close.as_ref().and_then(|close| close.state)
        } else {
            self.close_state
        }
        .unwrap_or(self.state_number);
        let state = match (&self.close_state_obj, mine) {
            (Some(state), false) => state.clone(),
            _ => match self.state(n) {
                Ok(state) => state.clone(),
                Err(_) => return vec![],
            },
        };
        let commitment = if mine {
            self.commitment_at(self.role, n, &state)
        } else {
            self.their_commitment(n, &state)
        };
        let Ok(commitment) = commitment else {
            return vec![];
        };
        let confirmations = height.saturating_add(1).saturating_sub(spend.height);
        let delay = u32::from(self.channel.delay);
        let fee = self.channel.fee;
        let me: WireSide = self.role.into();
        let mut broadcasts = Vec::new();
        let mut left = 0;

        if mine {
            if let Some(vout) = commitment.to_local_vout {
                if confirmations >= delay {
                    let built = sweep_to_local(
                        &commitment,
                        SweepPath::Delayed,
                        destination.clone(),
                        fee,
                        &self.channel_key,
                        self.rules,
                        &ctx.aux,
                    );
                    self.record_claim(
                        ClaimKind::SweepToLocal,
                        vout,
                        built,
                        height,
                        &mut broadcasts,
                    );
                } else {
                    left += 1;
                }
            }
        }
        for htlc in &commitment.htlcs {
            let offered_by_me = WireSide::from(htlc.htlc.from) == me;
            let hash = Bytes32(htlc.htlc.payment_hash);
            let output = self
                .outputs
                .entry(htlc.vout)
                .or_insert_with(|| FollowedOutput {
                    hash: Some(hash),
                    offered_by_me,
                    ..FollowedOutput::named(format!("htlc {}", htlc.htlc.id))
                });
            if output.theirs.is_some() {
                continue; // already taken by the other side
            }
            let preimage = if offered_by_me {
                None
            } else {
                self.preimages.get(&hash.0).copied()
            };
            if let Some(preimage) = preimage {
                if mine && confirmations < delay {
                    left += 1;
                    continue;
                }
                let built = self.htlc_claim(
                    &commitment,
                    htlc,
                    HtlcClaimPath::Success,
                    Some(preimage),
                    destination,
                    ctx,
                );
                self.record_claim(
                    ClaimKind::HtlcSuccess(htlc.htlc.id),
                    htlc.vout,
                    built,
                    height,
                    &mut broadcasts,
                );
            } else if offered_by_me && height >= htlc.htlc.expiry {
                if mine && confirmations < delay {
                    left += 1;
                    continue;
                }
                let built = self.htlc_claim(
                    &commitment,
                    htlc,
                    HtlcClaimPath::Timeout,
                    None,
                    destination,
                    ctx,
                );
                self.record_claim(
                    ClaimKind::HtlcRefund(htlc.htlc.id),
                    htlc.vout,
                    built,
                    height,
                    &mut broadcasts,
                );
            } else {
                left += 1; // theirs to claim, or not yet claimable by me
            }
        }
        if left == 0 {
            self.status = ChannelStatus::Settling;
        }
        broadcasts.extend(self.watch_outputs(ctx, lookup));
        broadcasts
    }

    fn htlc_claim(
        &self,
        commitment: &crate::Commitment,
        htlc: &CommitmentHtlc,
        path: HtlcClaimPath,
        preimage: Option<[u8; 32]>,
        destination: &ScriptBuf,
        ctx: &Context,
    ) -> Result<Transaction, crate::Error> {
        claim_htlc(
            commitment,
            htlc,
            HtlcClaim {
                path,
                destination: destination.clone(),
                fee: self.channel.fee,
                preimage,
            },
            &self.channel_key,
            self.rules,
            &ctx.aux,
        )
    }

    fn record_claim(
        &mut self,
        kind: ClaimKind,
        vout: u32,
        built: Result<Transaction, crate::Error>,
        height: u32,
        broadcasts: &mut Vec<Broadcast>,
    ) {
        if self.claims.iter().any(|claim| claim.kind == kind) {
            return;
        }
        // An output not worth claiming after the fee is left alone, as in Hitch.
        let Ok(tx) = built else {
            return;
        };
        self.claims.push(ClaimRecord {
            kind,
            txid: tx.compute_txid(),
            vout,
            tx: tx.clone(),
            at: height,
        });
        let output = self
            .outputs
            .entry(vout)
            .or_insert_with(|| FollowedOutput::named(kind.to_string()));
        output.name = kind.to_string();
        output.mine = true;
        broadcasts.push(Broadcast {
            label: kind.to_string(),
            tx,
        });
    }

    /// Hitch's `watchOutputs`: every followed output of the close is looked
    /// up. A claim of this peer's confirms, or the other side takes the
    /// output; when it takes an HTLC this peer offered with the preimage, the
    /// preimage is read from its witness, kept, and reported as
    /// [`ChannelEvent::Preimage`]. An unconfirmed claim is published again
    /// after six blocks. When nothing is left open, `settling` becomes
    /// `closed` and `punishing` becomes `punished`.
    pub fn watch_outputs(
        &mut self,
        ctx: &Context,
        mut lookup: impl FnMut(OutPoint, u32) -> OutputLookup,
    ) -> Vec<Broadcast> {
        let Some(spend) = self.spend.clone() else {
            return vec![];
        };
        let height = ctx.height;
        let mut broadcasts = Vec::new();
        let mut open = 0;
        let vouts: Vec<u32> = self.outputs.keys().copied().collect();
        for vout in vouts {
            let output = self.outputs[&vout].clone();
            if output.confirmed.is_some() || output.theirs.is_some() {
                continue;
            }
            let outpoint = OutPoint {
                txid: spend.txid,
                vout,
            };
            match lookup(outpoint, spend.height) {
                OutputLookup::Unknown => open += 1,
                OutputLookup::Unspent => {
                    open += 1;
                    if let Some(claim) = self.claims.iter_mut().find(|claim| claim.vout == vout) {
                        if height.saturating_sub(claim.at) > CLAIM_REBROADCAST {
                            claim.at = height;
                            broadcasts.push(Broadcast {
                                label: format!("{} (again)", output.name),
                                tx: claim.tx.clone(),
                            });
                        }
                    }
                }
                OutputLookup::Spent {
                    txid,
                    height: at,
                    tx,
                } => {
                    let by_me = self.claims.iter().any(|claim| claim.txid == txid);
                    if by_me {
                        self.outputs.get_mut(&vout).expect("listed").confirmed = Some(at);
                        if let (Some(hash), true) = (output.hash, output.offered_by_me) {
                            self.events.push(ChannelEvent::Payment {
                                hash,
                                outcome: PaymentOutcome::Failed,
                                reason: Some("refunded on the chain after the expiry".into()),
                            });
                        }
                    } else {
                        self.outputs.get_mut(&vout).expect("listed").theirs = Some(txid);
                        if let (Some(hash), true) = (output.hash, output.offered_by_me) {
                            if !self.preimages.contains_key(&hash.0) {
                                if let Some(preimage) = preimage_in(&tx, &hash.0) {
                                    self.remember_preimage(preimage);
                                    self.events.push(ChannelEvent::Payment {
                                        hash,
                                        outcome: PaymentOutcome::Sent,
                                        reason: Some("taken on the chain with the preimage".into()),
                                    });
                                    self.events.push(ChannelEvent::Preimage {
                                        hash,
                                        preimage: Bytes32(preimage),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        if open == 0 {
            match self.status {
                ChannelStatus::Settling => self.status = ChannelStatus::Closed,
                ChannelStatus::Punishing => self.status = ChannelStatus::Punished,
                _ => {}
            }
        }
        broadcasts
    }

    /// One of this peer's own transactions signed again with fresh
    /// randomness `aux`: the same transaction (the same txid), a different
    /// witness. A host sends this instead of the stored bytes whenever it
    /// broadcasts a transaction a second time: a producer that refused or
    /// evicted the first bytes (siding from `c3b9e7a` keeps a per-session
    /// reject map keyed on the exact bytes) judges these afresh.
    ///
    /// `tx` is a spend of the funding output (a commitment of this peer's or
    /// the cooperative close): this peer's funding signature is made again
    /// and the other side's, read from the witness and checked, is kept. Or
    /// it is one of this peer's [`Self::claims`]: its single leaf signature is
    /// made again with the key that made it (the channel key, or for a
    /// penalty the two-party revocation key of the punished state).
    /// `prevouts` are the outputs `tx` spends. Nothing in the machine
    /// changes.
    pub fn resign(
        &self,
        tx: &Transaction,
        prevouts: &[TxOut],
        aux: &[u8; 32],
    ) -> Result<Transaction, ProtocolError> {
        if tx.input.len() != 1 || prevouts.len() != 1 {
            return Err(ProtocolError::Malformed(
                "a channel transaction has one input",
            ));
        }
        let mut unsigned = tx.clone();
        unsigned.input[0].witness = Witness::new();
        let mut out = tx.clone();
        if tx.input[0].previous_output == self.channel.funding_outpoint {
            let theirs = tx.input[0]
                .witness
                .iter()
                .filter_map(|item| LeafSignature::from_slice(item).ok())
                .find(|sig| {
                    self.channel
                        .verify_funding(&unsigned, &self.peer_key(), sig, self.rules)
                })
                .ok_or(ProtocolError::BadSignature)?;
            let mine = self
                .channel
                .sign_funding(&unsigned, &self.channel_key, self.rules, aux)?;
            out.input[0].witness =
                self.channel
                    .funding_witness(&std::collections::BTreeMap::from([
                        (self.my_key(), mine),
                        (self.peer_key(), theirs),
                    ]))?;
            return Ok(out);
        }
        let txid = tx.compute_txid();
        let claim = self
            .claims
            .iter()
            .find(|c| c.txid == txid)
            .ok_or(ProtocolError::Malformed(
                "not a transaction of this channel",
            ))?;
        let key = match claim.kind {
            ClaimKind::PenaltyToLocal | ClaimKind::PenaltyHtlc(_) => {
                let n = self.close_state.ok_or(ProtocolError::MissingState(0))?;
                let theirs = self
                    .their_revocation
                    .get(&n)
                    .ok_or(ProtocolError::MissingReveal(n))?;
                revocation_key(&self.my_revocation_base, theirs)?
            }
            _ => self.channel_key,
        };
        let mut items: Vec<Vec<u8>> = tx.input[0].witness.to_vec();
        if items.len() < 3 {
            return Err(ProtocolError::Malformed("a claim's witness is too short"));
        }
        let script = ScriptBuf::from_bytes(items[items.len() - 2].clone());
        let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
        let sig = sign_leaf(&unsigned, 0, prevouts, leaf_hash, &key, self.rules, aux)?;
        items[0] = sig.as_bytes().to_vec();
        out.input[0].witness = Witness::from_slice(&items);
        Ok(out)
    }

    /// Outputs of a punished close that the other side took before the
    /// penalty landed.
    pub fn penalties_lost(&self) -> usize {
        self.outputs
            .values()
            .filter(|output| output.mine && output.theirs.is_some())
            .count()
    }
}
