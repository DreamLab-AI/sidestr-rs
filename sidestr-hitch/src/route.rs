//! Hitch's one-hop invoices and HTLC routing (`lib/route.mjs`) as a pure
//! decision engine.
//!
//! After a state becomes final, a payee settles an HTLC that pays one of its
//! invoices (the right amount, enough time left, not already paid); a hub
//! forwards an HTLC with a route to the next channel and carries the settle
//! or the fail back. Forwards are recorded before the downstream `add` is
//! made, keyed by the downstream channel and the payment hash, so a restart
//! or a second payment in flight cannot lose them.
//!
//! A [`Router`] reads the channels it is given and returns [`RouteAction`]s;
//! the host carries each out through the named [`ChannelMachine`] with a
//! fresh revocation secret, retrying for a while when
//! [`ProtocolError::is_retryable`] says so (Hitch tries twenty times, 1.5 s
//! apart). Wire the machine's outputs in as Hitch wires `io`:
//!
//! - a [`FinalisedUpdate`] of the other side's → [`Router::on_update`];
//! - [`ChannelEvent::Dropped`] → [`Router::on_dropped`];
//! - [`ChannelEvent::Preimage`] → [`Router::on_preimage`];
//! - on every block or timer → [`Router::tick`].
//!
//! [`ProtocolError::is_retryable`]: crate::protocol::ProtocolError::is_retryable
//! [`ChannelEvent::Dropped`]: crate::protocol::ChannelEvent::Dropped
//! [`ChannelEvent::Preimage`]: crate::protocol::ChannelEvent::Preimage

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};

use crate::protocol::{
    Bound, Bytes32, ChannelId, ChannelMachine, ChannelStatus, DroppedUpdate, FinalisedUpdate,
    NodeId, OfferedHtlc, ProtocolHtlc, Update, WireSide, CLAIM_MARGIN, CLOSE_DEPTH, EXPIRY_MARGIN,
    MEMO_MAX, MIN_HTLC,
};

/// Portable Hitch invoice carried out of band by the payer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invoice {
    /// Payee node id.
    pub p: NodeId,
    /// Requested amount in satoshis.
    pub a: u64,
    /// Optional human-readable memo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub m: Option<String>,
    /// SHA-256 payment hash.
    pub h: Bytes32,
    /// Suggested hub node ids.
    pub r: Vec<NodeId>,
    /// Fee hint in satoshis per hop.
    pub f: u64,
    /// Unix expiry time.
    pub x: u64,
    /// First sixteen hex characters of the payment hash.
    pub i: ChannelId,
}

impl Invoice {
    /// Create an invoice and return the preimage that must remain private
    /// until an incoming HTLC is final.
    pub fn new(
        payee: NodeId,
        amount: u64,
        memo: Option<String>,
        hops: Vec<NodeId>,
        fee_hint: u64,
        expires_at: u64,
        preimage: [u8; 32],
    ) -> Result<(Bytes32, Self), RouteError> {
        if memo
            .as_ref()
            .is_some_and(|value| value.encode_utf16().count() > MEMO_MAX)
        {
            return Err(RouteError::MemoTooLong);
        }
        let hash = sha256::Hash::hash(&preimage).to_byte_array();
        let mut id = [0u8; 8];
        id.copy_from_slice(&hash[..8]);
        Ok((
            Bytes32(preimage),
            Self {
                p: payee,
                a: amount,
                m: memo,
                h: Bytes32(hash),
                r: hops,
                f: fee_hint,
                x: expires_at,
                i: ChannelId(id),
            },
        ))
    }
}

/// Locally retained invoice secret, expected amount and whether it is paid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvoiceRecord {
    /// Preimage whose SHA-256 digest is the invoice hash.
    pub preimage: Bytes32,
    /// Smallest acceptable amount.
    pub amount: u64,
    /// Whether an HTLC has already been settled for it; a second one is
    /// failed.
    pub paid: bool,
}

/// Durable link between an upstream HTLC and the forward made for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardRecord {
    /// Payment hash.
    pub hash: Bytes32,
    /// Channel on which the HTLC arrived.
    pub upstream_channel: ChannelId,
    /// Incoming HTLC id.
    pub upstream_htlc_id: u64,
    /// Channel on which the forward is offered.
    pub downstream_channel: ChannelId,
    /// Height at which the forward was recorded.
    pub at: u32,
}

impl ForwardRecord {
    /// The record's key.
    pub fn key(&self) -> ForwardKey {
        ForwardKey {
            downstream: self.downstream_channel,
            hash: self.hash,
        }
    }
}

/// A forward is keyed by its downstream channel and payment hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ForwardKey {
    /// Downstream channel.
    pub downstream: ChannelId,
    /// Payment hash.
    pub hash: Bytes32,
}

/// An action for the host to carry out through a channel machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteAction {
    /// Settle an HTLC with its preimage
    /// ([`ChannelMachine::settle_htlc`], which also keeps the preimage).
    Settle {
        /// Channel containing the HTLC.
        channel: ChannelId,
        /// HTLC id on that channel.
        htlc_id: u64,
        /// Payment preimage.
        preimage: Bytes32,
        /// The forward this settles upstream: once the settle is proposed,
        /// pass it to [`Router::forget`].
        forward: Option<ForwardKey>,
        /// The invoice this pays: mark it paid.
        invoice: Option<Bytes32>,
    },
    /// Fail an HTLC ([`ChannelMachine::fail_htlc`]).
    Fail {
        /// Channel containing the HTLC.
        channel: ChannelId,
        /// HTLC id on that channel.
        htlc_id: u64,
        /// Hitch's reason.
        reason: String,
        /// The forward this fails upstream: once the fail is proposed, pass
        /// it to [`Router::forget`].
        forward: Option<ForwardKey>,
    },
    /// Offer an HTLC downstream ([`ChannelMachine::add_htlc`]). The record is
    /// already kept by the router (persist it); report the outcome with
    /// [`Router::forward_attempted`].
    Forward {
        /// Downstream channel.
        channel: ChannelId,
        /// The HTLC to offer, cut by the hub fee and [`forward_delta`].
        htlc: OfferedHtlc,
        /// The forward's record.
        record: ForwardRecord,
    },
    /// Close the channel with this peer's latest commitment
    /// ([`ChannelMachine::force_close`] with reason `"protective"`), so the
    /// chain decides.
    ForceClose {
        /// The channel.
        channel: ChannelId,
        /// Why, for the host's log.
        reason: String,
    },
}

/// The blocks a forward must give up between the upstream and the downstream
/// expiry: the hub must have the downstream preimage on the chain (or in
/// hand) before its own claim deadline upstream, `delay + CLAIM_MARGIN`
/// before the upstream expiry. This is Hitch's `forwardDelta`.
pub fn forward_delta(upstream_delay: u16, downstream_delay: u16) -> u32 {
    EXPIRY_MARGIN + u32::from(upstream_delay) + CLAIM_MARGIN + u32::from(downstream_delay)
}

/// Hitch's router: invoice settlement for a payee, one-hop forwarding for a
/// hub.
#[derive(Debug, Clone, Default)]
pub struct Router {
    hub: bool,
    hub_fee: u64,
    forwards: BTreeMap<ForwardKey, ForwardRecord>,
    inflight: BTreeSet<Bytes32>,
}

fn me(channel: &ChannelMachine) -> WireSide {
    channel.role().into()
}

fn by_id<'a>(channels: &[&'a ChannelMachine], id: ChannelId) -> Option<&'a ChannelMachine> {
    channels.iter().copied().find(|channel| channel.id() == id)
}

fn upstream_htlc<'a>(up: &'a ChannelMachine, hash: &Bytes32) -> Option<&'a ProtocolHtlc> {
    up.htlcs()
        .iter()
        .find(|htlc| htlc.hash == *hash && htlc.from != me(up))
}

fn fail(channel: ChannelId, htlc_id: u64, reason: &str) -> RouteAction {
    RouteAction::Fail {
        channel,
        htlc_id,
        reason: reason.into(),
        forward: None,
    }
}

impl Router {
    /// A router; `hub` enables forwarding, keeping `hub_fee` from each.
    pub fn new(hub: bool, hub_fee: u64) -> Self {
        Self {
            hub,
            hub_fee,
            forwards: BTreeMap::new(),
            inflight: BTreeSet::new(),
        }
    }

    /// Restore the router's durable forwards after a restart.
    pub fn with_forwards(mut self, records: impl IntoIterator<Item = ForwardRecord>) -> Self {
        self.forwards = records
            .into_iter()
            .map(|record| (record.key(), record))
            .collect();
        self
    }

    /// The durable forwards, to persist with the channels.
    pub fn forwards(&self) -> impl Iterator<Item = &ForwardRecord> {
        self.forwards.values()
    }

    /// The forward recorded for `hash` on `downstream`.
    pub fn forward(&self, downstream: ChannelId, hash: &Bytes32) -> Option<&ForwardRecord> {
        self.forwards.get(&ForwardKey {
            downstream,
            hash: *hash,
        })
    }

    /// Drop a forward once its upstream settle or fail has been proposed.
    pub fn forget(&mut self, key: ForwardKey) {
        self.forwards.remove(&key);
    }

    /// Act on an update of the other side's that just became final on
    /// `channel` (Hitch's `onUpdate`).
    pub fn on_update(
        &mut self,
        channels: &[&ChannelMachine],
        channel: ChannelId,
        update: &FinalisedUpdate,
        invoices: impl Fn(&Bytes32) -> Option<InvoiceRecord>,
        height: u32,
    ) -> Vec<RouteAction> {
        let Some(ch) = by_id(channels, channel) else {
            return vec![];
        };
        if update.sender == ch.role() {
            return vec![];
        }
        match &update.update {
            Update::Add { htlc, .. } => {
                vec![self.on_add(channels, ch, htlc, invoices, height)]
            }
            Update::Settle { htlc_id, preimage } if self.hub => {
                self.on_resolved(channels, ch, update.n, *htlc_id, Some(*preimage), None)
            }
            Update::Fail { htlc_id, reason } if self.hub => {
                self.on_resolved(channels, ch, update.n, *htlc_id, None, reason.as_deref())
            }
            _ => vec![],
        }
    }

    fn on_add(
        &mut self,
        channels: &[&ChannelMachine],
        ch: &ChannelMachine,
        htlc: &OfferedHtlc,
        invoices: impl Fn(&Bytes32) -> Option<InvoiceRecord>,
        height: u32,
    ) -> RouteAction {
        let id = ch.id();
        if let Some(invoice) = invoices(&htlc.hash) {
            if invoice.paid {
                return fail(id, htlc.id, "invoice already paid");
            }
            if htlc.amount < invoice.amount {
                return fail(id, htlc.id, "amount below the invoice");
            }
            if htlc.expiry
                < height
                    .saturating_add(u32::from(ch.delay()))
                    .saturating_add(EXPIRY_MARGIN)
            {
                return fail(id, htlc.id, "expiry too close");
            }
            return RouteAction::Settle {
                channel: id,
                htlc_id: htlc.id,
                preimage: invoice.preimage,
                forward: None,
                invoice: Some(htlc.hash),
            };
        }
        let Some(route) = htlc.route.filter(|_| self.hub) else {
            return fail(id, htlc.id, "unknown hash");
        };
        let amount = htlc.amount.checked_sub(self.hub_fee);
        let to_target =
            |c: &&&ChannelMachine| c.status() == ChannelStatus::Open && c.peer() == route.to.0;
        let down = channels
            .iter()
            .filter(to_target)
            .find(|c| {
                amount.is_some_and(|amount| c.room() >= amount as i64)
                    && c.bound(&htlc.hash, height).is_none()
            })
            .or_else(|| channels.iter().find(to_target))
            .copied();
        let expiry = down.and_then(|down| {
            htlc.expiry
                .checked_sub(forward_delta(ch.delay(), down.delay()))
        });
        let (Some(down), Some(amount), Some(expiry)) = (down, amount, expiry) else {
            return fail(id, htlc.id, "no route");
        };
        if down.room() < amount as i64
            || amount < MIN_HTLC
            || expiry
                <= height
                    .saturating_add(u32::from(down.delay()))
                    .saturating_add(EXPIRY_MARGIN)
        {
            return fail(id, htlc.id, "no route");
        }
        let key = ForwardKey {
            downstream: down.id(),
            hash: htlc.hash,
        };
        if down.htlcs().iter().any(|x| x.hash == htlc.hash) || self.forwards.contains_key(&key) {
            return fail(id, htlc.id, "duplicate hash");
        }
        let record = ForwardRecord {
            hash: htlc.hash,
            upstream_channel: id,
            upstream_htlc_id: htlc.id,
            downstream_channel: down.id(),
            at: height,
        };
        self.forwards.insert(key, record);
        self.inflight.insert(htlc.hash);
        RouteAction::Forward {
            channel: down.id(),
            htlc: OfferedHtlc {
                id: 0,
                amount,
                hash: htlc.hash,
                expiry,
                route: None,
            },
            record,
        }
    }

    /// Report how a [`RouteAction::Forward`] went. A forward that failed is
    /// failed back at once, unless the add is in fact out (signed and
    /// pending, or in the state).
    pub fn forward_attempted(
        &mut self,
        channels: &[&ChannelMachine],
        record: &ForwardRecord,
        ok: bool,
    ) -> Vec<RouteAction> {
        self.inflight.remove(&record.hash);
        if ok {
            return vec![];
        }
        let out = by_id(channels, record.downstream_channel).is_some_and(|down| {
            down.pending()
                .and_then(|p| p.update.added_hash())
                .is_some_and(|hash| hash == record.hash)
                || down.htlcs().iter().any(|x| x.hash == record.hash)
        });
        if out {
            return vec![];
        }
        self.forwards.remove(&record.key());
        vec![fail(
            record.upstream_channel,
            record.upstream_htlc_id,
            "could not forward",
        )]
    }

    fn on_resolved(
        &mut self,
        channels: &[&ChannelMachine],
        down: &ChannelMachine,
        n: u64,
        htlc_id: u64,
        preimage: Option<Bytes32>,
        reason: Option<&str>,
    ) -> Vec<RouteAction> {
        // Only HTLCs this hub offered downstream have an upstream.
        let Some(before) = n.checked_sub(1).and_then(|n| down.state_at(n)) else {
            return vec![];
        };
        let Some(htlc) = before.htlcs.iter().find(|x| x.id == htlc_id) else {
            return vec![];
        };
        if htlc.from != me(down) {
            return vec![];
        }
        let hash = htlc.hash;
        match preimage {
            Some(preimage) => self.settle_upstream(channels, down.id(), &hash, preimage),
            None => self.fail_upstream(
                channels,
                down.id(),
                &hash,
                reason.unwrap_or("downstream failed"),
            ),
        }
        .into_iter()
        .collect()
    }

    fn upstream_of<'a>(
        &self,
        channels: &[&'a ChannelMachine],
        down: ChannelId,
        hash: &Bytes32,
    ) -> Option<&'a ChannelMachine> {
        match self.forwards.get(&ForwardKey {
            downstream: down,
            hash: *hash,
        }) {
            Some(record) => by_id(channels, record.upstream_channel),
            None => channels.iter().copied().find(|c| {
                c.status() == ChannelStatus::Open
                    && c.id() != down
                    && upstream_htlc(c, hash).is_some()
            }),
        }
    }

    fn settle_upstream(
        &mut self,
        channels: &[&ChannelMachine],
        down: ChannelId,
        hash: &Bytes32,
        preimage: Bytes32,
    ) -> Option<RouteAction> {
        let up = self.upstream_of(channels, down, hash)?;
        let key = ForwardKey {
            downstream: down,
            hash: *hash,
        };
        let Some(htlc) = upstream_htlc(up, hash) else {
            self.forwards.remove(&key);
            return None;
        };
        Some(RouteAction::Settle {
            channel: up.id(),
            htlc_id: htlc.id,
            preimage,
            forward: Some(key),
            invoice: None,
        })
    }

    fn fail_upstream(
        &mut self,
        channels: &[&ChannelMachine],
        down: ChannelId,
        hash: &Bytes32,
        reason: &str,
    ) -> Option<RouteAction> {
        let up = self.upstream_of(channels, down, hash)?;
        let key = ForwardKey {
            downstream: down,
            hash: *hash,
        };
        let Some(htlc) = upstream_htlc(up, hash) else {
            self.forwards.remove(&key);
            return None;
        };
        Some(RouteAction::Fail {
            channel: up.id(),
            htlc_id: htlc.id,
            reason: reason.into(),
            forward: Some(key),
        })
    }

    /// A forward of this hub's was set aside (a collision, a rejection, a
    /// close). The signature on it still binds the hub until the other side
    /// revokes that state, so it is failed back only once nothing binds the
    /// hash any more; [`Self::tick`] watches for that (Hitch's `onDropped`).
    pub fn on_dropped(
        &mut self,
        channels: &[&ChannelMachine],
        channel: ChannelId,
        dropped: &DroppedUpdate,
        height: u32,
    ) -> Vec<RouteAction> {
        if !self.hub {
            return vec![];
        }
        let Some(hash) = dropped.update.added_hash() else {
            return vec![];
        };
        let Some(down) = by_id(channels, channel) else {
            return vec![];
        };
        if down.bound(&hash, height).is_some() {
            return vec![];
        }
        self.fail_upstream(channels, channel, &hash, "could not forward")
            .into_iter()
            .collect()
    }

    /// A preimage read from the chain (the payee claimed on a closed
    /// downstream channel) settles upstream (Hitch's `onPreimage`).
    pub fn on_preimage(
        &mut self,
        channels: &[&ChannelMachine],
        channel: ChannelId,
        hash: &Bytes32,
        preimage: Bytes32,
    ) -> Vec<RouteAction> {
        if !self.hub {
            return vec![];
        }
        self.settle_upstream(channels, channel, hash, preimage)
            .into_iter()
            .collect()
    }

    /// Hitch's router tick, for a hub. A forward whose upstream HTLC is gone
    /// is dropped. A forward with nothing downstream (lost in a crash, or the
    /// downstream channel closed without it) is settled upstream when the
    /// preimage is known, failed when nothing binds the hash and nothing is in
    /// flight, and, when only a set-aside state binds it, the downstream
    /// channel is closed at the agreed state before the upstream deadline to
    /// kill that alternative. A forwarded HTLC still unresolved past its
    /// downstream expiry closes the downstream channel so the chain decides.
    pub fn tick(&mut self, channels: &[&ChannelMachine], height: u32) -> Vec<RouteAction> {
        if !self.hub {
            return vec![];
        }
        let mut actions = Vec::new();
        let records: Vec<ForwardRecord> = self.forwards.values().copied().collect();
        for record in records {
            if self.inflight.contains(&record.hash) {
                continue;
            }
            let Some(down) = by_id(channels, record.downstream_channel) else {
                continue;
            };
            let hash = record.hash;
            let up = by_id(channels, record.upstream_channel);
            let Some((up, up_htlc)) = up.and_then(|up| upstream_htlc(up, &hash).map(|h| (up, h)))
            else {
                self.forwards.remove(&record.key());
                continue;
            };
            let down_htlc = down.htlcs().iter().find(|x| x.hash == hash);
            let bound = down.bound(&hash, height);
            if down_htlc.is_none() && height > record.at {
                if let Some(preimage) = down.known_preimage(&hash) {
                    actions.extend(self.settle_upstream(channels, down.id(), &hash, preimage));
                    continue;
                }
                match bound {
                    None => {
                        if down.pending().is_none() && down.awaiting_revoke().is_none() {
                            actions.extend(self.fail_upstream(
                                channels,
                                down.id(),
                                &hash,
                                "the forward was lost",
                            ));
                        }
                    }
                    Some(Bound::Alt)
                        if matches!(
                            down.status(),
                            ChannelStatus::Open | ChannelStatus::ClosingAsked
                        ) && height
                            >= up_htlc.expiry.saturating_sub(
                                u32::from(up.delay()) + CLAIM_MARGIN + CLOSE_DEPTH,
                            ) =>
                    {
                        actions.push(RouteAction::ForceClose {
                            channel: down.id(),
                            reason: "a forward is bound only by a set-aside state and the upstream deadline is near".into(),
                        });
                    }
                    Some(_) => {}
                }
                continue;
            }
            if down.status() != ChannelStatus::Open {
                continue;
            }
            if let Some(down_htlc) = down_htlc {
                let blocking = down
                    .pending()
                    .is_some_and(|p| !matches!(p.update, Update::Fail { .. }));
                if height > down_htlc.expiry && !blocking {
                    actions.push(RouteAction::ForceClose {
                        channel: down.id(),
                        reason: "a forwarded htlc is unresolved past its expiry".into(),
                    });
                }
            }
        }
        actions
    }
}

/// Invalid invoice construction.
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    /// Invoice memo exceeded Hitch's wire limit.
    #[error("invoice memo is longer than {MEMO_MAX} characters")]
    MemoTooLong,
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Keypair, SecretKey};
    use bitcoin::{Amount, OutPoint, Txid};
    use sidestr_core::block::secp;
    use sidestr_core::sighash::SighashRules;

    use super::*;
    use crate::protocol::{
        AcceptPolicy, Context, FunderOpening, OpenParams, OpeningKeys, ReceiverOpening, Route,
    };
    use crate::Side;

    const H: u32 = 1_000;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn node(byte: u8) -> NodeId {
        NodeId(
            Keypair::from_secret_key(secp(), &key(byte))
                .x_only_public_key()
                .0,
        )
    }

    /// A channel from `funder` to the hub (0x99), the hub holding `push`.
    fn channel(funder: u8, txid: u8, push: u64) -> (ChannelMachine, ChannelMachine) {
        let (opening, open) = FunderOpening::propose(
            OpenParams {
                funding: OutPoint {
                    txid: Txid::from_byte_array([txid; 32]),
                    vout: 0,
                },
                funding_value: Amount::from_sat(100_000),
                push: Amount::from_sat(push),
                delay: 6,
                fee: Amount::from_sat(300),
                hub_fee: None,
            },
            OpeningKeys {
                channel: key(funder),
                revocation_base: key(funder + 1),
                revocation: [key(funder + 2), key(funder + 3)],
            },
            node(0x99).0,
            SighashRules::Bip341,
            &[0; 32],
        )
        .unwrap();
        let (receiver, accept) = ReceiverOpening::accept(
            open,
            node(funder).0,
            OpeningKeys {
                channel: key(0x99),
                revocation_base: key(txid),
                revocation: [key(txid + 1), key(txid + 2)],
            },
            SighashRules::Bip341,
            AcceptPolicy::default(),
            &[0; 32],
        )
        .unwrap();
        let (accepted, commit) = opening.accept(accept, &[0; 32]).unwrap();
        let (mut hub, ready) = receiver.commit(commit).unwrap();
        let mut theirs = accepted.ready(ready).unwrap();
        hub.confirm_funding(H);
        theirs.confirm_funding(H);
        (theirs, hub)
    }

    fn add(
        id: u64,
        amount: u64,
        hash: [u8; 32],
        expiry: u32,
        to: Option<NodeId>,
    ) -> FinalisedUpdate {
        FinalisedUpdate {
            n: 1,
            update: Update::Add {
                htlc: OfferedHtlc {
                    id,
                    amount,
                    hash: Bytes32(hash),
                    expiry,
                    route: to.map(|to| Route { to }),
                },
                memo: None,
            },
            sender: Side::A,
        }
    }

    #[test]
    fn invoice_shape_matches_hitch() {
        let preimage = [0x44; 32];
        let (secret, invoice) = Invoice::new(
            node(1),
            5_000,
            Some("coffee".into()),
            vec![node(2)],
            10,
            2_000,
            preimage,
        )
        .unwrap();
        assert_eq!(secret.0, preimage);
        assert_eq!(invoice.h.0, sha256::Hash::hash(&preimage).to_byte_array());
        assert_eq!(invoice.i.0, invoice.h.0[..8]);
        assert!(Invoice::new(node(1), 1, Some("x".repeat(141)), vec![], 0, 0, preimage).is_err());
    }

    #[test]
    fn a_payee_settles_once_and_refuses_short_late_or_paid_htlcs() {
        let (_, hub) = channel(0x10, 0xa0, 0);
        let channels = [&hub];
        let mut router = Router::new(false, 10);
        let preimage = Bytes32([0x44; 32]);
        let hash = sha256::Hash::hash(&preimage.0).to_byte_array();
        let record = |paid| InvoiceRecord {
            preimage,
            amount: 5_000,
            paid,
        };
        let decide = |router: &mut Router, update: &FinalisedUpdate, paid| {
            router.on_update(&channels, hub.id(), update, |_| Some(record(paid)), H)
        };
        let reason = |actions: Vec<RouteAction>| match &actions[..] {
            [RouteAction::Fail { reason, .. }] => reason.clone(),
            other => panic!("expected a fail, got {other:?}"),
        };
        assert!(matches!(
            &decide(&mut router, &add(7, 5_000, hash, H + 40, None), false)[..],
            [RouteAction::Settle {
                htlc_id: 7,
                invoice: Some(_),
                forward: None,
                ..
            }]
        ));
        assert_eq!(
            reason(decide(
                &mut router,
                &add(8, 5_000, hash, H + 40, None),
                true
            )),
            "invoice already paid"
        );
        assert_eq!(
            reason(decide(
                &mut router,
                &add(9, 4_999, hash, H + 40, None),
                false
            )),
            "amount below the invoice"
        );
        assert_eq!(
            reason(decide(
                &mut router,
                &add(10, 5_000, hash, H + 17, None),
                false
            )),
            "expiry too close"
        );
        let unknown = router.on_update(
            &channels,
            hub.id(),
            &add(11, 5_000, [1; 32], H + 40, None),
            |_| None,
            H,
        );
        assert_eq!(reason(unknown), "unknown hash");
        // The router acts only on the other side's updates.
        let mut own = add(12, 5_000, hash, H + 40, None);
        own.sender = Side::B;
        assert!(decide(&mut router, &own, false).is_empty());
    }

    #[test]
    fn a_hub_forwards_with_its_fee_and_both_delays_and_records_the_forward_first() {
        let (_, up) = channel(0x10, 0xa0, 0);
        let (payee, down) = channel(0x20, 0xb0, 50_000);
        let channels = [&up, &down];
        let mut router = Router::new(true, 10);
        let to = NodeId(payee.channel().key(Side::A));
        let hash = [5; 32];
        let actions = router.on_update(
            &channels,
            up.id(),
            &add(7, 5_010, hash, H + 60, Some(to)),
            |_| None,
            H,
        );
        let [RouteAction::Forward {
            channel,
            htlc,
            record,
        }] = &actions[..]
        else {
            panic!("expected a forward, got {actions:?}")
        };
        assert_eq!(*channel, down.id());
        assert_eq!(htlc.amount, 5_000);
        assert_eq!(forward_delta(6, 6), 12 + 6 + 3 + 6);
        assert_eq!(htlc.expiry, H + 60 - forward_delta(6, 6));
        assert_eq!(record.upstream_htlc_id, 7);
        assert_eq!(router.forward(down.id(), &Bytes32(hash)), Some(record));
        // The same hash again is refused while the forward is recorded.
        let again = router.on_update(
            &channels,
            up.id(),
            &add(8, 5_010, hash, H + 60, Some(to)),
            |_| None,
            H,
        );
        assert!(
            matches!(&again[..], [RouteAction::Fail { reason, .. }] if reason == "duplicate hash")
        );
        // A forward that could not be made, and is not out, fails back.
        let back = router.forward_attempted(&channels, record, false);
        assert!(
            matches!(&back[..], [RouteAction::Fail { htlc_id: 7, reason, .. }] if reason == "could not forward")
        );
        assert!(router.forward(down.id(), &Bytes32(hash)).is_none());
        // Too little room, or too little time, is no route.
        let poor = router.on_update(
            &channels,
            up.id(),
            &add(9, 60_000, [6; 32], H + 60, Some(to)),
            |_| None,
            H,
        );
        assert!(matches!(&poor[..], [RouteAction::Fail { reason, .. }] if reason == "no route"));
        let late = router.on_update(
            &channels,
            up.id(),
            &add(10, 5_010, [7; 32], H + 45, Some(to)),
            |_| None,
            H,
        );
        assert!(matches!(&late[..], [RouteAction::Fail { reason, .. }] if reason == "no route"));
        // A non-hub never forwards.
        let mut payee_router = Router::new(false, 10);
        let refused = payee_router.on_update(
            &channels,
            up.id(),
            &add(11, 5_010, [8; 32], H + 60, Some(to)),
            |_| None,
            H,
        );
        assert!(
            matches!(&refused[..], [RouteAction::Fail { reason, .. }] if reason == "unknown hash")
        );
    }

    #[test]
    fn a_set_aside_forward_waits_while_bound_and_is_failed_once_lost() {
        let (_, up) = channel(0x10, 0xa0, 0);
        let (payee, mut down) = channel(0x20, 0xb0, 50_000);
        let mut router = Router::new(true, 10);
        let to = NodeId(payee.channel().key(Side::A));
        let hash = [5; 32];
        let ctx = Context::new(H, 0, [0; 32]);
        let forward = {
            let channels = [&up, &down];
            router.on_update(
                &channels,
                up.id(),
                &add(7, 5_010, hash, H + 60, Some(to)),
                |_| None,
                H,
            )
        };
        let [RouteAction::Forward { htlc, record, .. }] = &forward[..] else {
            panic!("a forward")
        };
        let message = down
            .add_htlc(
                htlc.amount,
                htlc.hash,
                htlc.expiry,
                None,
                None,
                key(0x77),
                &ctx,
            )
            .unwrap();
        router.forward_attempted(&[&up, &down], record, true);
        // The payee refuses it: set aside, but its signed state still binds.
        let reject = crate::protocol::RejectMessage {
            t: crate::protocol::RejectTag::Reject,
            id: down.id(),
            n: 1,
            sig: message.sig,
            reason: None,
        };
        down.receive_reject(reject, &ctx).unwrap();
        let dropped = match &down.drain_events()[..] {
            [crate::protocol::ChannelEvent::Payment {
                outcome: crate::protocol::PaymentOutcome::NotMade,
                ..
            }, crate::protocol::ChannelEvent::Dropped(dropped)] => dropped.clone(),
            other => panic!("expected a payment not made and a dropped update, got {other:?}"),
        };
        assert_eq!(down.bound(&Bytes32(hash), H), Some(Bound::Alt));
        assert!(router
            .on_dropped(&[&up, &down], down.id(), &dropped, H)
            .is_empty());
        // The router's tick: the upstream HTLC is not in `up` (this test made
        // no add there), so the forward is dropped as resolved.
        assert!(router.tick(&[&up, &down], H + 1).is_empty());
        assert!(router.forward(down.id(), &Bytes32(hash)).is_none());
    }
}
