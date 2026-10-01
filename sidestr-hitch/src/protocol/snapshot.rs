//! The durable form of a channel, checked in full on restore.

use std::collections::BTreeMap;

use bitcoin::secp256k1::SecretKey;
use bitcoin::{Amount, OutPoint, Txid};
use serde::{Deserialize, Serialize};
use sidestr_core::sighash::SighashRules;

use super::chain::{ClaimRecord, CloseRecord, FollowedOutput, SpendRecord};
use super::machine::{
    AwaitingRevoke, ChannelMachine, DroppedUpdate, PendingUpdate, ProtocolState, SignedAlternative,
};
use super::{
    public, secret, sha, Bytes32, ChannelId, ChannelStatus, FundingOffer, NodeId, ProtocolError,
    UpdateMessage, WireSide,
};
use crate::{Channel, LeafSignature};

const VERSION: u8 = 2;

/// Versioned durable state of one channel.
///
/// Its serialised form contains the channel signing key, the revocation
/// basepoint and per-state secrets, and payment preimages. Hosts must protect
/// it as wallet key material and persist it atomically before sending what
/// the call that produced it returned.
///
/// Version 2 carries the two-party revocation keys of `sidestr-hitch` 0.2.
/// Version 1 snapshots from 0.1 are refused: their single-party revocation
/// keys let a commitment's owner spend its own revocation leaf, the flaw this
/// version fixes, so such a channel should be closed with 0.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSnapshot {
    version: u8,
    id: ChannelId,
    role: WireSide,
    channel_key: Bytes32,
    channel: SnapshotChannel,
    status: ChannelStatus,
    funded_height: Option<u32>,
    state_number: u64,
    states: BTreeMap<u64, ProtocolState>,
    my_revocation_base: Bytes32,
    their_revocation_base: NodeId,
    my_revocation: BTreeMap<u64, Bytes32>,
    their_revocation: BTreeMap<u64, Bytes32>,
    their_revocation_public: BTreeMap<u64, NodeId>,
    signatures: BTreeMap<u64, LeafSignature>,
    pending: Option<PendingUpdate>,
    awaiting: Option<AwaitingRevoke>,
    buffered: Option<UpdateMessage>,
    signed_alternatives: BTreeMap<u64, Vec<SignedAlternative>>,
    dropped: Option<DroppedUpdate>,
    preimages: BTreeMap<Bytes32, Bytes32>,
    htlc_seq: u64,
    peer_hub_fee: Option<u64>,
    coop_txid: Option<Txid>,
    close: Option<CloseRecord>,
    spend: Option<SpendRecord>,
    close_state: Option<u64>,
    close_state_obj: Option<ProtocolState>,
    outputs: BTreeMap<u32, FollowedOutput>,
    claims: Vec<ClaimRecord>,
    penalties: Vec<Txid>,
    last_sync_at: Option<u64>,
    rules: SnapshotRules,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SnapshotChannel {
    keys: [NodeId; 2],
    funding: FundingOffer,
    fee: u64,
    delay: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SnapshotRules {
    Bip341,
    KnotsUnified,
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

fn encode_secrets(secrets: &BTreeMap<u64, SecretKey>) -> BTreeMap<u64, Bytes32> {
    secrets
        .iter()
        .map(|(n, secret)| (*n, Bytes32(secret.secret_bytes())))
        .collect()
}

fn decode_secrets(
    encoded: BTreeMap<u64, Bytes32>,
) -> Result<BTreeMap<u64, SecretKey>, ProtocolError> {
    encoded
        .into_iter()
        .map(|(n, bytes)| secret(bytes).map(|secret| (n, secret)))
        .collect()
}

impl ChannelMachine {
    /// Capture all state needed to recover safely after a restart. Events
    /// not yet drained, and the in-memory record of a peer far ahead, are
    /// not part of it.
    pub fn snapshot(&self) -> ChannelSnapshot {
        ChannelSnapshot {
            version: VERSION,
            id: self.id,
            role: self.role.into(),
            channel_key: Bytes32(self.channel_key.secret_bytes()),
            channel: SnapshotChannel {
                keys: [NodeId(self.channel.keys[0]), NodeId(self.channel.keys[1])],
                funding: FundingOffer {
                    txid: self.channel.funding_outpoint.txid,
                    vout: self.channel.funding_outpoint.vout,
                    value: self.channel.funding_value.to_sat(),
                },
                fee: self.channel.fee.to_sat(),
                delay: self.channel.delay,
            },
            status: self.status,
            funded_height: self.funded_height,
            state_number: self.state_number,
            states: self.states.clone(),
            my_revocation_base: Bytes32(self.my_revocation_base.secret_bytes()),
            their_revocation_base: NodeId(self.their_revocation_base),
            my_revocation: encode_secrets(&self.my_revocation),
            their_revocation: encode_secrets(&self.their_revocation),
            their_revocation_public: self
                .their_revocation_public
                .iter()
                .map(|(n, key)| (*n, NodeId(*key)))
                .collect(),
            signatures: self.signatures.clone(),
            pending: self.pending.clone(),
            awaiting: self.awaiting.clone(),
            buffered: self.buffered.clone(),
            signed_alternatives: self.signed_alternatives.clone(),
            dropped: self.dropped.clone(),
            preimages: self
                .preimages
                .iter()
                .map(|(hash, preimage)| (Bytes32(*hash), Bytes32(*preimage)))
                .collect(),
            htlc_seq: self.htlc_seq,
            peer_hub_fee: self.peer_hub_fee,
            coop_txid: self.coop_txid,
            close: self.close.clone(),
            spend: self.spend.clone(),
            close_state: self.close_state,
            close_state_obj: self.close_state_obj.clone(),
            outputs: self.outputs.clone(),
            claims: self.claims.clone(),
            penalties: self.penalties.clone(),
            last_sync_at: self.last_sync_at,
            rules: self.rules.into(),
        }
    }

    /// Restore a snapshot only after verifying its key relationships,
    /// accounting, every retained counterparty signature and every
    /// recorded transaction.
    pub fn restore(snapshot: ChannelSnapshot) -> Result<Self, ProtocolError> {
        if snapshot.version != VERSION {
            return Err(ProtocolError::SnapshotVersion(snapshot.version));
        }
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
        let machine = Self {
            id: snapshot.id,
            role: snapshot.role.into(),
            channel_key: secret(snapshot.channel_key)?,
            channel,
            status: snapshot.status,
            funded_height: snapshot.funded_height,
            state_number: snapshot.state_number,
            states: snapshot.states,
            my_revocation_base: secret(snapshot.my_revocation_base)?,
            their_revocation_base: snapshot.their_revocation_base.0,
            my_revocation: decode_secrets(snapshot.my_revocation)?,
            their_revocation: decode_secrets(snapshot.their_revocation)?,
            their_revocation_public: snapshot
                .their_revocation_public
                .into_iter()
                .map(|(n, key)| (n, key.0))
                .collect(),
            signatures: snapshot.signatures,
            pending: snapshot.pending,
            awaiting: snapshot.awaiting,
            buffered: snapshot.buffered,
            signed_alternatives: snapshot.signed_alternatives,
            dropped: snapshot.dropped,
            preimages: snapshot
                .preimages
                .into_iter()
                .map(|(hash, preimage)| (hash.0, preimage.0))
                .collect(),
            htlc_seq: snapshot.htlc_seq,
            peer_hub_fee: snapshot.peer_hub_fee,
            coop_txid: snapshot.coop_txid,
            close: snapshot.close,
            spend: snapshot.spend,
            close_state: snapshot.close_state,
            close_state_obj: snapshot.close_state_obj,
            outputs: snapshot.outputs,
            claims: snapshot.claims,
            penalties: snapshot.penalties,
            last_sync_at: snapshot.last_sync_at,
            peer_ahead: None,
            events: Vec::new(),
            rules: snapshot.rules.into(),
        };
        machine.validate()?;
        Ok(machine)
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        let corrupt = ProtocolError::CorruptSnapshot;
        if self.id != ChannelId::from_txid(self.channel.funding_outpoint.txid) {
            return Err(corrupt("channel id"));
        }
        if public(&self.channel_key) != self.my_key() {
            return Err(ProtocolError::WrongChannelKey);
        }
        if self.htlc_seq == 0 {
            return Err(corrupt("htlc sequence"));
        }
        let n = self.state_number;
        if !self.states.contains_key(&n) {
            return Err(ProtocolError::MissingState(n));
        }
        if self
            .states
            .keys()
            .any(|k| *k > n && self.pending.as_ref().is_none_or(|p| p.n != *k))
        {
            return Err(corrupt("state beyond the agreed one"));
        }
        let next = n.checked_add(1).ok_or(corrupt("state number"))?;
        for k in [n, next] {
            if !self.my_revocation.contains_key(&k)
                || !self.their_revocation_public.contains_key(&k)
            {
                return Err(ProtocolError::MissingRevocationKey(k));
            }
        }
        for (k, secret) in &self.their_revocation {
            if self.their_revocation_public.get(k) != Some(&public(secret)) {
                return Err(corrupt("counterparty revocation"));
            }
        }
        for (hash, preimage) in &self.preimages {
            if sha(preimage) != *hash {
                return Err(corrupt("payment preimage"));
            }
        }
        for (k, state) in self.states.range(..=n) {
            self.commitment_at(self.role, *k, state)?;
            self.commitment_at(self.role.other(), *k, state)?;
            let signature = self
                .signatures
                .get(k)
                .ok_or(ProtocolError::MissingSignature(*k))?;
            let mine = self.commitment_at(self.role, *k, state)?;
            if !self
                .channel
                .verify_funding(&mine.tx, &self.peer_key(), signature, self.rules)
            {
                return Err(ProtocolError::BadSignature);
            }
            if state.htlcs.iter().any(|htlc| htlc.id >= self.htlc_seq) {
                return Err(corrupt("htlc sequence"));
            }
        }
        for (k, alternatives) in &self.signed_alternatives {
            for alternative in alternatives {
                self.commitment_at(self.role.other(), *k, &alternative.state)?;
            }
        }
        if let Some(pending) = &self.pending {
            if pending.n != next
                || pending.message.id != self.id
                || pending.message.n != pending.n
                || pending.message.update != pending.update
            {
                return Err(corrupt("pending update"));
            }
            let theirs =
                self.commitment_at(self.role.other(), pending.n, self.state(pending.n)?)?;
            if !self.channel.verify_funding(
                &theirs.tx,
                &self.my_key(),
                &pending.message.sig,
                self.rules,
            ) {
                return Err(ProtocolError::BadSignature);
            }
        }
        if let Some(awaiting) = &self.awaiting {
            if awaiting.n != n
                || awaiting.previous.checked_add(1) != Some(awaiting.n)
                || awaiting.sender != self.role.other().into()
            {
                return Err(corrupt("awaiting revocation"));
            }
        }
        if self
            .buffered
            .as_ref()
            .is_some_and(|message| message.id != self.id || message.n != next)
        {
            return Err(corrupt("buffered update"));
        }
        if self
            .close
            .as_ref()
            .is_some_and(|close| close.tx.compute_txid() != close.txid)
        {
            return Err(corrupt("close transaction"));
        }
        if self
            .claims
            .iter()
            .any(|claim| claim.tx.compute_txid() != claim.txid)
        {
            return Err(corrupt("claim transaction"));
        }
        Ok(())
    }
}
