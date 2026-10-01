//! A deterministic network of Hitch hosts for the scenario suites: the Rust
//! counterpart of the `host()`, `pump()` and `chain` fixtures in Hitch's
//! `test/peer-test.mjs` and `test/adversarial-test.mjs`.
//!
//! Each host keeps its channels as `sidestr-hitch` machines and saves every
//! one through a JSON snapshot round trip after each call, so the suites
//! also prove that a restart at any step loses nothing. Messages travel as
//! JSON text, routed actions are retried like Hitch's `withRetry`, and the
//! chain records broadcasts and the spends they make.
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap, VecDeque};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, SecretKey, XOnlyPublicKey};
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, Txid};
use sidestr_core::block::secp;
use sidestr_core::sighash::SighashRules;
use sidestr_hitch::protocol::{
    AcceptPolicy, AcceptedFunder, Broadcast, Bytes32, ChainSpend, ChannelEvent, ChannelId,
    ChannelMachine, ChannelSnapshot, ChannelStatus, Context, FinalisedUpdate, FunderOpening,
    FunderSync, NodeId, OpenParams, OpeningKeys, OutputLookup, PaymentOutcome, PeerMessage,
    ProtocolError, ReceiveUpdate, ReceiverOpening, Route, TickAction, TickOptions, Update,
};
use sidestr_hitch::route::{Invoice, InvoiceRecord, RouteAction, Router};
use sidestr_hitch::to_remote_script;

pub const RULES: SighashRules = SighashRules::KnotsUnified;
const RETRIES: u32 = 20;

pub fn sha(bytes: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(bytes).to_byte_array()
}

pub fn secret(seed: &[u8]) -> SecretKey {
    SecretKey::from_slice(&sha(seed)).unwrap()
}

pub fn public(key: &SecretKey) -> XOnlyPublicKey {
    Keypair::from_secret_key(secp(), key).x_only_public_key().0
}

/// The chain: a height, every broadcast in order, and the spends the mined
/// ones made (Hitch's `chain.mine()` records them all at the current height).
#[derive(Default)]
pub struct Chain {
    pub height: u32,
    pub broadcasts: Vec<Published>,
    pub spent: HashMap<OutPoint, (Txid, u32, Transaction)>,
    pub refuse: bool,
}

pub struct Published {
    pub from: String,
    pub label: String,
    pub tx: Transaction,
}

impl Chain {
    pub fn mine(&mut self) {
        for published in &self.broadcasts {
            let txid = published.tx.compute_txid();
            for input in &published.tx.input {
                self.spent.insert(
                    input.previous_output,
                    (txid, self.height, published.tx.clone()),
                );
            }
        }
    }

    pub fn last(&self) -> &Published {
        self.broadcasts.last().expect("a broadcast")
    }
}

pub struct Envelope {
    pub to: XOnlyPublicKey,
    pub from: XOnlyPublicKey,
    pub body: String,
}

impl Envelope {
    pub fn message(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap()
    }

    pub fn t(&self) -> String {
        self.message()["t"].as_str().unwrap_or_default().to_owned()
    }
}

pub struct Host {
    pub name: String,
    pub key: SecretKey,
    pub pub_key: XOnlyPublicKey,
    pub hub: bool,
    pub fee: u64,
    pub delay: u16,
    pub min_delay: u16,
    pub machines: Vec<ChannelMachine>,
    pub funders: Vec<(FunderOpening, u64)>,
    pub accepted: Vec<AcceptedFunder>,
    pub receivers: Vec<ReceiverOpening>,
    pub router: Router,
    pub invoices: HashMap<Bytes32, InvoiceRecord>,
    pub notes: Vec<String>,
    pub unsent: Vec<Broadcast>,
    pub save_fails: bool,
    /// Blocks this host's chain view runs ahead of the others'.
    pub height_skew: u32,
    /// A passive host takes no routed action on its own (an offline payee).
    pub passive: bool,
    /// Every secret this host generated, by its public point.
    pub known: HashMap<XOnlyPublicKey, SecretKey>,
    seq: u64,
    retries: VecDeque<(RouteAction, u32)>,
}

impl Host {
    pub fn channel(&self, id: ChannelId) -> &ChannelMachine {
        self.machines
            .iter()
            .find(|m| m.id() == id)
            .expect("channel")
    }

    pub fn channel_mut(&mut self, id: ChannelId) -> &mut ChannelMachine {
        self.machines
            .iter_mut()
            .find(|m| m.id() == id)
            .expect("channel")
    }

    pub fn has(&self, id: ChannelId) -> bool {
        self.machines.iter().any(|m| m.id() == id)
    }

    pub fn fresh(&mut self) -> SecretKey {
        self.seq += 1;
        let mut seed = self.name.as_bytes().to_vec();
        seed.extend_from_slice(b"/secret/");
        seed.extend_from_slice(&self.seq.to_be_bytes());
        let key = secret(&seed);
        self.known.insert(public(&key), key);
        key
    }

    /// The secret behind one of this host's revocation points.
    pub fn secret_of(&self, point: XOnlyPublicKey) -> SecretKey {
        self.known[&point]
    }

    fn aux(&mut self) -> [u8; 32] {
        self.seq += 1;
        let mut seed = self.name.as_bytes().to_vec();
        seed.extend_from_slice(b"/aux/");
        seed.extend_from_slice(&self.seq.to_be_bytes());
        sha(&seed)
    }

    pub fn script(&self) -> ScriptBuf {
        to_remote_script(self.pub_key)
    }

    pub fn note(&mut self, text: impl Into<String>) {
        self.notes.push(text.into());
    }

    pub fn noted(&self, needle: &str) -> bool {
        self.notes.iter().any(|note| note.contains(needle))
    }

    /// Hitch's `invoice()`: a fresh preimage and the invoice for it.
    pub fn invoice(
        &mut self,
        amount: u64,
        memo: &str,
        hops: &[XOnlyPublicKey],
    ) -> (Bytes32, Invoice) {
        let preimage = self.fresh().secret_bytes();
        Invoice::new(
            NodeId(self.pub_key),
            amount,
            Some(memo.into()),
            hops.iter().copied().map(NodeId).collect(),
            10,
            4_000_000_000,
            preimage,
        )
        .unwrap()
    }

    /// Keep an invoice so an incoming HTLC paying it is settled.
    pub fn keep(&mut self, preimage: Bytes32, invoice: &Invoice) {
        self.invoices.insert(
            invoice.h,
            InvoiceRecord {
                preimage,
                amount: invoice.a,
                paid: false,
            },
        );
    }
}

pub struct HostOptions {
    pub hub: bool,
    pub fee: u64,
    pub delay: u16,
    pub min_delay: u16,
}

impl Default for HostOptions {
    fn default() -> Self {
        Self {
            hub: false,
            fee: 300,
            delay: 6,
            min_delay: 3,
        }
    }
}

pub struct Net {
    pub hosts: Vec<Host>,
    pub inbox: VecDeque<Envelope>,
    pub chain: Chain,
    pub now: u64,
    funding_seq: u64,
}

pub type H = usize;

impl Default for Net {
    fn default() -> Self {
        Self::new()
    }
}

impl Net {
    pub fn new() -> Self {
        Self {
            hosts: vec![],
            inbox: VecDeque::new(),
            chain: Chain {
                height: 152_100,
                ..Chain::default()
            },
            now: 1_800_000_000,
            funding_seq: 0,
        }
    }

    pub fn host(&mut self, name: &str, options: HostOptions) -> H {
        let key = secret(format!("hitch-test-{name}").as_bytes());
        self.hosts.push(Host {
            name: name.into(),
            key,
            pub_key: public(&key),
            hub: options.hub,
            fee: options.fee,
            delay: options.delay,
            min_delay: options.min_delay,
            machines: vec![],
            funders: vec![],
            accepted: vec![],
            receivers: vec![],
            router: Router::new(options.hub, 10),
            invoices: HashMap::new(),
            notes: vec![],
            unsent: vec![],
            save_fails: false,
            height_skew: 0,
            passive: false,
            known: HashMap::new(),
            seq: 0,
            retries: VecDeque::new(),
        });
        self.hosts.len() - 1
    }

    /// The same node restarted from its saved channels, forwards and
    /// invoices: in-memory state (opening typestates, retries) is lost.
    pub fn restart(&mut self, h: H) {
        let host = &mut self.hosts[h];
        host.machines = host
            .machines
            .iter()
            .map(|m| {
                let json = serde_json::to_string(&m.snapshot()).unwrap();
                ChannelMachine::restore(serde_json::from_str(&json).unwrap()).unwrap()
            })
            .collect();
        let forwards: Vec<_> = host.router.forwards().copied().collect();
        host.router = Router::new(host.hub, 10).with_forwards(forwards);
        host.retries.clear();
    }

    pub fn pub_key(&self, h: H) -> XOnlyPublicKey {
        self.hosts[h].pub_key
    }

    fn by_pub(&self, key: XOnlyPublicKey) -> Option<H> {
        self.hosts.iter().position(|host| host.pub_key == key)
    }

    pub fn ctx(&mut self, h: H) -> Context {
        let aux = self.hosts[h].aux();
        Context::new(self.chain.height + self.hosts[h].height_skew, self.now, aux)
    }

    /// Every channel of a host as saved JSON, to compare before and after.
    pub fn fingerprint(&self, h: H) -> String {
        let host = &self.hosts[h];
        let snapshots: Vec<_> = host.machines.iter().map(|m| m.snapshot()).collect();
        format!(
            "{}|{}|{}|{}",
            serde_json::to_string(&snapshots).unwrap(),
            host.receivers.len(),
            host.funders.len(),
            host.accepted.len()
        )
    }

    /// The host drops a channel whose funding never confirmed (Hitch's
    /// `abandoned`).
    pub fn abandon(&mut self, h: H, id: ChannelId) {
        self.hosts[h].machines.retain(|m| m.id() != id);
        self.hosts[h].receivers.retain(|r| r.id() != id);
    }

    /// Queue a message as if `from` had sent it.
    pub fn send_as(&mut self, from: H, to: H, message: impl Into<PeerMessage>) {
        let to = self.pub_key(to);
        self.send(from, to, message);
    }

    fn send(&mut self, from: H, to: XOnlyPublicKey, message: impl Into<PeerMessage>) {
        let message: PeerMessage = message.into();
        self.inbox.push_back(Envelope {
            to,
            from: self.hosts[from].pub_key,
            body: serde_json::to_string(&message).unwrap(),
        });
    }

    /// Deliver a raw JSON body from `from` to `to`, as a relay would.
    pub fn deliver_raw(&mut self, from: XOnlyPublicKey, to: H, body: &str) {
        self.on_message(to, from, body);
    }

    /// Deliver one queued envelope.
    pub fn deliver(&mut self, envelope: Envelope) {
        if let Some(to) = self.by_pub(envelope.to) {
            self.on_message(to, envelope.from, &envelope.body);
        }
    }

    /// Hitch's `pump()`: deliver everything queued, up to `limit` messages.
    pub fn pump_limit(&mut self, limit: usize) -> usize {
        let mut count = 0;
        while count < limit {
            let Some(envelope) = self.inbox.pop_front() else {
                break;
            };
            count += 1;
            self.deliver(envelope);
        }
        count
    }

    pub fn pump(&mut self) -> usize {
        self.pump_limit(200)
    }

    /// Hitch's `settle()`: pump, and let routed retries run, a few times.
    pub fn settle(&mut self) {
        for _ in 0..12 {
            self.pump();
            self.run_retries();
        }
        self.pump();
    }

    pub fn take(&mut self, t: &str) -> Envelope {
        let index = self
            .inbox
            .iter()
            .position(|e| e.t() == t)
            .unwrap_or_else(|| panic!("no {t} in the inbox"));
        self.inbox.remove(index).unwrap()
    }

    pub fn shift(&mut self) -> Envelope {
        self.inbox.pop_front().expect("a message")
    }

    pub fn drop_all(&mut self) {
        self.inbox.clear();
    }

    // ---- persistence

    /// Save every machine through a snapshot round trip. Returns false when
    /// the host's storage is failing.
    fn persist(&mut self, h: H, id: ChannelId) -> bool {
        if self.hosts[h].save_fails {
            return false;
        }
        let machine = self.hosts[h].channel_mut(id);
        let events = machine.drain_events();
        let json = serde_json::to_string(&machine.snapshot()).unwrap();
        let snapshot: ChannelSnapshot = serde_json::from_str(&json).unwrap();
        let restored = ChannelMachine::restore(snapshot).expect("a saved channel restores");
        assert_eq!(
            restored.snapshot(),
            machine.snapshot(),
            "snapshot round trip"
        );
        self.on_events(h, id, events);
        true
    }

    /// Run `call` on a channel; on a failed save restore the machine as it
    /// was and report that nothing may be sent.
    fn with_channel<T>(
        &mut self,
        h: H,
        id: ChannelId,
        call: impl FnOnce(&mut ChannelMachine, &Context, SecretKey) -> Result<T, ProtocolError>,
    ) -> Result<T, String> {
        let ctx = self.ctx(h);
        let fresh = self.hosts[h].fresh();
        let before = self.hosts[h].channel(id).clone();
        let result = call(self.hosts[h].channel_mut(id), &ctx, fresh);
        if !self.persist(h, id) {
            *self.hosts[h].channel_mut(id) = before;
            return Err("the state could not be saved; nothing was sent".into());
        }
        result.map_err(|error| error.to_string())
    }

    // ---- opening

    pub fn open(&mut self, h: H, peer: H, amount: u64, push: u64) -> ChannelId {
        self.funding_seq += 1;
        let txid =
            Txid::from_byte_array(sha(
                format!("{}{}", self.hosts[h].name, self.funding_seq).as_bytes()
            ));
        let keys = OpeningKeys {
            channel: self.hosts[h].key,
            revocation_base: self.hosts[h].fresh(),
            revocation: [self.hosts[h].fresh(), self.hosts[h].fresh()],
        };
        let host = &self.hosts[h];
        let params = OpenParams {
            funding: OutPoint { txid, vout: 0 },
            funding_value: Amount::from_sat(amount),
            push: Amount::from_sat(push),
            delay: host.delay,
            fee: Amount::from_sat(host.fee),
            hub_fee: host.hub.then_some(10),
        };
        let aux = self.hosts[h].aux();
        let to = self.pub_key(peer);
        let (funder, open) = FunderOpening::propose(params, keys, to, RULES, &aux).unwrap();
        let id = funder.id();
        self.hosts[h].funders.push((funder, self.now));
        self.send(h, to, open);
        id
    }

    /// Hitch's test `confirm()`: the funding is in a block on both sides.
    pub fn confirm(&mut self, id: ChannelId) {
        let height = self.chain.height;
        for h in 0..self.hosts.len() {
            if let Some(machine) = self.hosts[h].machines.iter_mut().find(|m| m.id() == id) {
                if machine.status() == ChannelStatus::Funding {
                    machine.confirm_funding(height);
                    self.persist(h, id);
                }
            }
        }
    }

    /// Open and confirm a channel, pumping the handshake.
    pub fn channel(&mut self, h: H, peer: H, amount: u64, push: u64) -> ChannelId {
        let id = self.open(h, peer, amount, push);
        self.pump();
        self.confirm(id);
        id
    }

    // ---- updates by hand

    pub fn pay(&mut self, h: H, id: ChannelId, amount: u64) -> Result<(), String> {
        let peer = self.hosts[h].channel(id).peer();
        let message = self.with_channel(h, id, |m, ctx, fresh| m.pay(amount, None, fresh, ctx))?;
        self.send(h, peer, message);
        Ok(())
    }

    pub fn add_htlc(
        &mut self,
        h: H,
        id: ChannelId,
        amount: u64,
        hash: Bytes32,
        expiry: u32,
        route: Option<XOnlyPublicKey>,
    ) -> Result<u64, String> {
        let peer = self.hosts[h].channel(id).peer();
        let route = route.map(|to| Route { to: NodeId(to) });
        let message = self.with_channel(h, id, |m, ctx, fresh| {
            m.add_htlc(amount, hash, expiry, route, None, fresh, ctx)
        })?;
        let htlc_id = match &message.update {
            Update::Add { htlc, .. } => htlc.id,
            _ => unreachable!(),
        };
        self.send(h, peer, message);
        Ok(htlc_id)
    }

    pub fn settle_htlc(
        &mut self,
        h: H,
        id: ChannelId,
        htlc: u64,
        preimage: Bytes32,
    ) -> Result<(), String> {
        let peer = self.hosts[h].channel(id).peer();
        let message = self.with_channel(h, id, |m, ctx, fresh| {
            m.settle_htlc(htlc, preimage, fresh, ctx)
        })?;
        self.send(h, peer, message);
        Ok(())
    }

    pub fn fail_htlc(
        &mut self,
        h: H,
        id: ChannelId,
        htlc: u64,
        reason: &str,
    ) -> Result<(), String> {
        let peer = self.hosts[h].channel(id).peer();
        let message = self.with_channel(h, id, |m, ctx, fresh| {
            m.fail_htlc(htlc, Some(reason), fresh, ctx)
        })?;
        self.send(h, peer, message);
        Ok(())
    }

    pub fn close(&mut self, h: H, id: ChannelId) -> Result<(), String> {
        let peer = self.hosts[h].channel(id).peer();
        let message = self.with_channel(h, id, |m, ctx, _| m.close_channel(ctx))?;
        self.send(h, peer, message);
        Ok(())
    }

    pub fn force_close(&mut self, h: H, id: ChannelId, state: Option<u64>) -> Result<(), String> {
        let broadcast =
            self.with_channel(h, id, |m, ctx, _| m.force_close(state, "forced", ctx))?;
        self.broadcast(h, broadcast);
        Ok(())
    }

    pub fn resync(&mut self, h: H, id: ChannelId, force: bool) {
        let peer = self.hosts[h].channel(id).peer();
        if let Ok(Some(sync)) = self.with_channel(h, id, |m, ctx, _| Ok(m.resync(ctx, force))) {
            self.send(h, peer, sync);
        }
    }

    pub fn resync_all(&mut self, h: H, force: bool) {
        let ids: Vec<ChannelId> = self.hosts[h]
            .machines
            .iter()
            .filter(|m| m.status().is_live())
            .map(|m| m.id())
            .collect();
        for id in ids {
            self.resync(h, id, force);
        }
    }

    pub fn broadcast(&mut self, h: H, broadcast: Broadcast) -> bool {
        if self.chain.refuse {
            self.hosts[h].unsent.push(broadcast);
            return false;
        }
        self.chain.broadcasts.push(Published {
            from: self.hosts[h].name.clone(),
            label: broadcast.label,
            tx: broadcast.tx,
        });
        true
    }

    // ---- the chain

    fn lookup(&self) -> impl FnMut(OutPoint, u32) -> OutputLookup + '_ {
        |outpoint, _from| match self.chain.spent.get(&outpoint) {
            Some((txid, height, tx)) => OutputLookup::Spent {
                txid: *txid,
                height: *height,
                tx: tx.clone(),
            },
            None => OutputLookup::Unspent,
        }
    }

    pub fn on_spend(&mut self, h: H, id: ChannelId, txid: Txid, height: u32) {
        let ctx = self.ctx(h);
        let script = self.hosts[h].script();
        let spent = self.chain.spent.clone();
        let lookup = move |outpoint: OutPoint, _from: u32| match spent.get(&outpoint) {
            Some((txid, height, tx)) => OutputLookup::Spent {
                txid: *txid,
                height: *height,
                tx: tx.clone(),
            },
            None => OutputLookup::Unspent,
        };
        let status_before = self.hosts[h].channel(id).status();
        let outcome = self.hosts[h]
            .channel_mut(id)
            .on_spend(ChainSpend { txid, height }, &script, &ctx, lookup)
            .unwrap();
        self.persist(h, id);
        self.after_status(h, id, status_before);
        for broadcast in outcome.broadcasts {
            self.broadcast(h, broadcast);
        }
    }

    pub fn after_close(&mut self, h: H, id: ChannelId) {
        let ctx = self.ctx(h);
        let script = self.hosts[h].script();
        let spent = self.chain.spent.clone();
        let lookup = move |outpoint: OutPoint, _from: u32| match spent.get(&outpoint) {
            Some((txid, height, tx)) => OutputLookup::Spent {
                txid: *txid,
                height: *height,
                tx: tx.clone(),
            },
            None => OutputLookup::Unspent,
        };
        let status_before = self.hosts[h].channel(id).status();
        let broadcasts = self.hosts[h]
            .channel_mut(id)
            .after_close(&script, &ctx, lookup);
        self.persist(h, id);
        self.after_status(h, id, status_before);
        for broadcast in broadcasts {
            self.broadcast(h, broadcast);
        }
    }

    pub fn un_spend(&mut self, h: H, id: ChannelId) {
        if let Some(close) = self.hosts[h].channel_mut(id).un_spend() {
            self.hosts[h].unsent.push(close);
        }
        self.persist(h, id);
    }

    fn after_status(&mut self, h: H, id: ChannelId, before: ChannelStatus) {
        let machine = self.hosts[h].channel(id);
        if before != ChannelStatus::Punished && machine.status() == ChannelStatus::Punished {
            let lost = machine.penalties_lost();
            let text = if lost == 0 {
                "Penalty confirmed".to_owned()
            } else {
                format!("Penalty partly lost: {lost}")
            };
            self.hosts[h].note(text);
        }
    }

    // ---- ticks

    /// Hitch's `peer.tick()` for every channel of a host, and its resend of
    /// failed broadcasts and unanswered proposals.
    pub fn tick(&mut self, h: H) {
        let unsent = std::mem::take(&mut self.hosts[h].unsent);
        for broadcast in unsent {
            self.broadcast(h, broadcast);
        }
        let stale: Vec<usize> = self.hosts[h]
            .funders
            .iter()
            .enumerate()
            .filter(|(_, (_, at))| self.now.saturating_sub(*at) > 90)
            .map(|(i, _)| i)
            .collect();
        for i in stale {
            let open = self.hosts[h].funders[i].0.message().clone();
            self.hosts[h].funders[i].1 = self.now;
            let to = open.b.0;
            self.send(h, to, open);
        }
        let ids: Vec<ChannelId> = self.hosts[h].machines.iter().map(|m| m.id()).collect();
        for id in ids {
            let ctx = self.ctx(h);
            let peer = self.hosts[h].channel(id).peer();
            let actions = self.hosts[h]
                .channel_mut(id)
                .tick(&ctx, &TickOptions { pending_timeout: 0 });
            self.persist(h, id);
            for action in actions {
                match action {
                    TickAction::Send(message) => self.send(h, peer, *message),
                    TickAction::Broadcast(broadcast) => {
                        self.broadcast(h, broadcast);
                    }
                    TickAction::Settle { htlc_id, preimage } => {
                        let _ = self.settle_htlc(h, id, htlc_id, preimage);
                    }
                    TickAction::Fail { htlc_id, reason } => {
                        let _ = self.fail_htlc(h, id, htlc_id, &reason);
                    }
                }
            }
        }
    }

    /// Hitch's `router.tick()`.
    pub fn router_tick(&mut self, h: H) {
        let height = self.chain.height;
        let host = &mut self.hosts[h];
        let channels: Vec<&ChannelMachine> = host.machines.iter().collect();
        let actions = host.router.tick(&channels, height);
        for action in actions {
            self.route(h, action, 0);
        }
    }

    // ---- routing

    fn run_retries(&mut self) {
        for h in 0..self.hosts.len() {
            let queued: Vec<_> = self.hosts[h].retries.drain(..).collect();
            for (action, tries) in queued {
                self.route(h, action, tries);
            }
        }
    }

    fn route(&mut self, h: H, action: RouteAction, tries: u32) {
        let outcome = match &action {
            RouteAction::Settle {
                channel,
                htlc_id,
                preimage,
                ..
            } => self.settle_htlc(h, *channel, *htlc_id, *preimage),
            RouteAction::Fail {
                channel,
                htlc_id,
                reason,
                ..
            } => self.fail_htlc(h, *channel, *htlc_id, reason),
            RouteAction::Forward { channel, htlc, .. } => self
                .add_htlc(h, *channel, htlc.amount, htlc.hash, htlc.expiry, None)
                .map(|_| ()),
            RouteAction::ForceClose { channel, .. } => {
                let broadcast = self.with_channel(h, *channel, |m, ctx, _| {
                    m.force_close(None, "protective", ctx)
                });
                broadcast.map(|broadcast| {
                    self.broadcast(h, broadcast);
                })
            }
        };
        let retryable = |error: &str| {
            ["pending", "revocation", "resyncing"]
                .iter()
                .any(|word| error.contains(word))
        };
        match (&action, outcome) {
            (_, Err(error)) if retryable(&error) && tries < RETRIES => {
                self.hosts[h].retries.push_back((action, tries + 1));
            }
            (RouteAction::Forward { record, .. }, result) => {
                let host = &mut self.hosts[h];
                let channels: Vec<&ChannelMachine> = host.machines.iter().collect();
                let follow = host
                    .router
                    .forward_attempted(&channels, record, result.is_ok());
                for next in follow {
                    self.route(h, next, 0);
                }
            }
            (
                RouteAction::Settle {
                    forward, invoice, ..
                },
                Ok(()),
            ) => {
                if let Some(key) = forward {
                    self.hosts[h].router.forget(*key);
                }
                if let Some(hash) = invoice {
                    if let Some(record) = self.hosts[h].invoices.get_mut(hash) {
                        record.paid = true;
                    }
                    self.hosts[h].note("Invoice paid");
                }
            }
            (
                RouteAction::Fail {
                    forward: Some(key), ..
                },
                Ok(()),
            ) => {
                self.hosts[h].router.forget(*key);
            }
            _ => {}
        }
    }

    fn on_finalised(&mut self, h: H, id: ChannelId, update: FinalisedUpdate) {
        if self.hosts[h].passive {
            return;
        }
        let height = self.chain.height;
        let host = &mut self.hosts[h];
        let invoices = host.invoices.clone();
        let channels: Vec<&ChannelMachine> = host.machines.iter().collect();
        let actions = host.router.on_update(
            &channels,
            id,
            &update,
            |hash| invoices.get(hash).copied(),
            height,
        );
        for action in actions {
            self.route(h, action, 0);
        }
    }

    fn on_events(&mut self, h: H, id: ChannelId, events: Vec<ChannelEvent>) {
        for event in events {
            match event {
                ChannelEvent::Dropped(dropped) => {
                    if matches!(dropped.update, Update::Pay { .. } | Update::Add { .. }) {
                        self.hosts[h].note(format!("Payment not made: {}", dropped.reason));
                    }
                    let height = self.chain.height;
                    let host = &mut self.hosts[h];
                    let channels: Vec<&ChannelMachine> = host.machines.iter().collect();
                    let actions = host.router.on_dropped(&channels, id, &dropped, height);
                    for action in actions {
                        self.route(h, action, 0);
                    }
                }
                ChannelEvent::Preimage { hash, preimage } => {
                    let host = &mut self.hosts[h];
                    let channels: Vec<&ChannelMachine> = host.machines.iter().collect();
                    let actions = host.router.on_preimage(&channels, id, &hash, preimage);
                    for action in actions {
                        self.route(h, action, 0);
                    }
                }
                ChannelEvent::Payment { outcome, .. } => {
                    let text = match outcome {
                        PaymentOutcome::InFlight => "Payment in flight",
                        PaymentOutcome::Sent => "Payment sent",
                        PaymentOutcome::Failed => "Payment failed",
                        PaymentOutcome::NotMade => "Payment outcome: not made",
                    };
                    self.hosts[h].note(text);
                }
            }
        }
    }

    // ---- messages

    fn on_message(&mut self, h: H, from: XOnlyPublicKey, body: &str) {
        let Ok(message) = serde_json::from_str::<PeerMessage>(body) else {
            return; // malformed: dropped
        };
        if message.well_formed().is_err() {
            return;
        }
        let me = self.hosts[h].pub_key;
        let id = message.channel();
        match message {
            PeerMessage::Open(open) => {
                if open.b.0 != me || open.a.0 != from {
                    return;
                }
                if let Some(receiver) = self.hosts[h].receivers.iter().find(|r| r.id() == id) {
                    let accept = receiver.message().clone();
                    self.send(h, from, accept);
                    return;
                }
                if self.hosts[h].has(id) || self.hosts[h].funders.iter().any(|(f, _)| f.id() == id)
                {
                    return;
                }
                let keys = OpeningKeys {
                    channel: self.hosts[h].key,
                    revocation_base: self.hosts[h].fresh(),
                    revocation: [self.hosts[h].fresh(), self.hosts[h].fresh()],
                };
                let policy = AcceptPolicy {
                    min_delay: self.hosts[h].min_delay,
                    hub_fee: self.hosts[h].hub.then_some(10),
                };
                let aux = self.hosts[h].aux();
                if let Ok((receiver, accept)) =
                    ReceiverOpening::accept(open, from, keys, RULES, policy, &aux)
                {
                    self.hosts[h].receivers.push(receiver);
                    self.send(h, from, accept);
                }
            }
            PeerMessage::Accept(accept) => {
                let Some(i) = self.hosts[h]
                    .funders
                    .iter()
                    .position(|(f, _)| f.id() == id && f.message().b.0 == from)
                else {
                    return;
                };
                let aux = self.hosts[h].aux();
                if let Ok((accepted, commit)) = self.hosts[h].funders[i].0.accept(accept, &aux) {
                    self.hosts[h].funders.remove(i);
                    self.hosts[h].accepted.push(accepted);
                    self.send(h, from, commit);
                }
            }
            PeerMessage::Commit(commit) => {
                if let Some(i) = self.hosts[h].receivers.iter().position(|r| r.id() == id) {
                    if let Ok((machine, ready)) = self.hosts[h].receivers[i].commit(commit) {
                        self.hosts[h].receivers.remove(i);
                        self.hosts[h].machines.push(machine);
                        self.persist(h, id);
                        self.send(h, from, ready);
                    }
                } else if self.hosts[h].has(id)
                    && self.hosts[h].channel(id).status() == ChannelStatus::Funding
                {
                    self.send(
                        h,
                        from,
                        sidestr_hitch::protocol::ReadyMessage {
                            t: sidestr_hitch::protocol::ReadyTag::Ready,
                            id,
                        },
                    );
                }
            }
            PeerMessage::Ready(ready) => {
                if let Some(i) = self.hosts[h].accepted.iter().position(|a| a.id() == id) {
                    if let Ok(machine) = self.hosts[h].accepted[i].ready(ready) {
                        self.hosts[h].accepted.remove(i);
                        self.hosts[h].machines.push(machine);
                        self.persist(h, id);
                    }
                }
            }
            other => self.on_channel_message(h, from, id, other),
        }
    }

    fn on_channel_message(
        &mut self,
        h: H,
        from: XOnlyPublicKey,
        id: ChannelId,
        message: PeerMessage,
    ) {
        if let PeerMessage::Sync(sync) = &message {
            if let Some(i) = self.hosts[h].accepted.iter().position(|a| a.id() == id) {
                match self.hosts[h].accepted[i].receive_sync(sync) {
                    Ok(FunderSync::ResendCommit(commit)) => self.send(h, from, commit),
                    Ok(FunderSync::Ready(machine)) => {
                        self.hosts[h].accepted.remove(i);
                        self.hosts[h].machines.push(*machine);
                        self.persist(h, id);
                    }
                    Ok(FunderSync::Waiting) | Err(_) => {}
                }
                return;
            }
            if let Some(receiver) = self.hosts[h].receivers.iter().find(|r| r.id() == id) {
                if sync.status.as_deref() == Some("proposed") {
                    let accept = receiver.message().clone();
                    self.send(h, from, accept);
                }
                return;
            }
        }
        if !self.hosts[h].has(id) || self.hosts[h].channel(id).peer() != from {
            return;
        }
        match message {
            PeerMessage::Update(update) => {
                let Ok(result) =
                    self.with_channel(h, id, |m, ctx, fresh| m.receive_update(update, fresh, ctx))
                else {
                    return;
                };
                match result {
                    ReceiveUpdate::Acknowledge(ack) | ReceiveUpdate::ResendAcknowledgement(ack) => {
                        self.send(h, from, ack)
                    }
                    ReceiveUpdate::Rejected(reject) | ReceiveUpdate::LocalProposalWins(reject) => {
                        self.send(h, from, reject)
                    }
                    ReceiveUpdate::Buffered => {}
                }
            }
            PeerMessage::Ack(ack) => {
                if let Ok(outcome) = self.with_channel(h, id, |m, _, _| m.receive_ack(ack)) {
                    if outcome.adopted {
                        self.hosts[h].note("Update applied after all");
                    }
                    self.send(h, from, outcome.revoke);
                }
            }
            PeerMessage::Revoke(revoke) => {
                if let Ok(Some(finalised)) =
                    self.with_channel(h, id, |m, _, _| m.receive_revoke(revoke))
                {
                    self.after_final(h, id, from, finalised);
                }
            }
            PeerMessage::Reject(reject) => {
                if let Ok(Some(sync)) =
                    self.with_channel(h, id, |m, ctx, _| m.receive_reject(reject, ctx))
                {
                    self.send(h, from, sync);
                }
            }
            PeerMessage::Close(close) => {
                if let Ok(broadcast) =
                    self.with_channel(h, id, |m, ctx, _| m.receive_close(close, ctx))
                {
                    self.broadcast(h, broadcast);
                }
            }
            PeerMessage::Sync(sync) => {
                if let Ok(outcome) =
                    self.with_channel(h, id, |m, ctx, _| m.receive_sync(&sync, ctx))
                {
                    for reply in outcome.replies {
                        self.send(h, from, reply);
                    }
                    if let Some(finalised) = outcome.finalised {
                        self.after_final(h, id, from, finalised);
                    }
                }
            }
            _ => {}
        }
    }

    fn after_final(
        &mut self,
        h: H,
        id: ChannelId,
        from: XOnlyPublicKey,
        finalised: FinalisedUpdate,
    ) {
        self.on_finalised(h, id, finalised);
        let buffered = self.hosts[h].channel_mut(id).take_buffered_update();
        if let Some(update) = buffered {
            self.persist(h, id);
            let body = serde_json::to_string(&PeerMessage::Update(update)).unwrap();
            self.on_message(h, from, &body);
        }
    }

    // ---- helpers for assertions

    pub fn balance(&self, h: H, id: ChannelId, side: char) -> u64 {
        let state = self.hosts[h].channel(id).current_state();
        if side == 'a' {
            state.balance_a
        } else {
            state.balance_b
        }
    }

    pub fn htlc_count(&self, h: H, id: ChannelId) -> usize {
        self.hosts[h].channel(id).htlcs().len()
    }

    pub fn broadcasts_from(&self, start: usize) -> &[Published] {
        &self.chain.broadcasts[start..]
    }

    pub fn statuses(&self, id: ChannelId) -> BTreeMap<String, ChannelStatus> {
        self.hosts
            .iter()
            .filter(|host| host.has(id))
            .map(|host| (host.name.clone(), host.channel(id).status()))
            .collect()
    }
}

// ---- a small tapscript interpreter for the spends Hitch makes

use bitcoin::secp256k1::{schnorr::Signature, Message};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use bitcoin::{ScriptBuf as Script, TxOut};

fn script_num(bytes: &[u8]) -> i64 {
    if bytes.is_empty() {
        return 0;
    }
    let mut value: i64 = 0;
    for (i, byte) in bytes.iter().enumerate() {
        value |= i64::from(*byte) << (8 * i);
    }
    let last = bytes[bytes.len() - 1];
    if last & 0x80 != 0 {
        -(value & !(0x80_i64 << (8 * (bytes.len() - 1))))
    } else {
        value
    }
}

fn truthy(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .enumerate()
        .any(|(i, b)| *b != 0 && !(i == bytes.len() - 1 && *b == 0x80))
}

fn verify_sig(
    tx: &Transaction,
    input: usize,
    prevouts: &[TxOut],
    leaf: Option<TapLeafHash>,
    key: &[u8],
    sig: &[u8],
) -> Result<bool, String> {
    if sig.is_empty() {
        return Ok(false);
    }
    let key = XOnlyPublicKey::from_slice(key).map_err(|e| format!("key: {e}"))?;
    let (message, hash_type) = match leaf {
        Some(leaf) => sidestr_hitch::script_path_sighash(tx, input, prevouts, leaf, RULES)
            .map_err(|e| e.to_string())?,
        None => sidestr_core::sighash::key_path_sighash(tx, input, prevouts, RULES)
            .map_err(|e| e.to_string())?,
    };
    if sig.len() != 65 || sig[64] != hash_type {
        return Err("signature hash type".into());
    }
    let signature = Signature::from_slice(&sig[..64]).map_err(|e| e.to_string())?;
    secp()
        .verify_schnorr(&signature, &Message::from_digest(message), &key)
        .map_err(|_| "signature does not verify".to_string())?;
    Ok(true)
}

/// Check input `input` of `tx` against its previous outputs as a
/// Taproot-aware interpreter would, for the scripts Hitch builds: the
/// commitment of the leaf to the output key, every signature, the preimage,
/// and the relative and absolute timelocks.
pub fn verify_input(tx: &Transaction, input: usize, prevouts: &[TxOut]) -> Result<(), String> {
    let spk = prevouts[input].script_pubkey.as_bytes();
    if spk.len() != 34 || spk[0] != 0x51 || spk[1] != 0x20 {
        return Err("not a taproot output".into());
    }
    let output_key = XOnlyPublicKey::from_slice(&spk[2..]).map_err(|e| e.to_string())?;
    let witness: Vec<Vec<u8>> = tx.input[input].witness.iter().map(<[u8]>::to_vec).collect();
    if witness.len() == 1 {
        return match verify_sig(tx, input, prevouts, None, &spk[2..], &witness[0])? {
            true => Ok(()),
            false => Err("empty key-path signature".into()),
        };
    }
    if witness.len() < 2 {
        return Err("empty witness".into());
    }
    let control = ControlBlock::decode(&witness[witness.len() - 1]).map_err(|e| e.to_string())?;
    let script = Script::from_bytes(witness[witness.len() - 2].clone());
    if !control.verify_taproot_commitment(secp(), output_key, &script) {
        return Err("the leaf is not committed to by the output key".into());
    }
    let leaf = TapLeafHash::from_script(&script, LeafVersion::TapScript);
    let mut stack: Vec<Vec<u8>> = witness[..witness.len() - 2].to_vec();
    let bytes = script.as_bytes();
    let mut i = 0;
    let pop = |stack: &mut Vec<Vec<u8>>| stack.pop().ok_or_else(|| "stack underflow".to_string());
    while i < bytes.len() {
        let op = bytes[i];
        i += 1;
        match op {
            0x00 => stack.push(vec![]),
            0x01..=0x4b => {
                let n = usize::from(op);
                stack.push(bytes[i..i + n].to_vec());
                i += n;
            }
            0x51..=0x60 => stack.push(vec![op - 0x50]),
            0x75 => {
                pop(&mut stack)?;
            }
            0x88 => {
                let b = pop(&mut stack)?;
                let a = pop(&mut stack)?;
                if a != b {
                    return Err("EQUALVERIFY failed (wrong preimage?)".into());
                }
            }
            0x9c => {
                let b = script_num(&pop(&mut stack)?);
                let a = script_num(&pop(&mut stack)?);
                stack.push(if a == b { vec![1] } else { vec![] });
            }
            0xa8 => {
                let top = pop(&mut stack)?;
                stack.push(sha(&top).to_vec());
            }
            0xac => {
                let key = pop(&mut stack)?;
                let sig = pop(&mut stack)?;
                let ok = verify_sig(tx, input, prevouts, Some(leaf), &key, &sig)?;
                stack.push(if ok { vec![1] } else { vec![] });
            }
            0xba => {
                let key = pop(&mut stack)?;
                let n = script_num(&pop(&mut stack)?);
                let sig = pop(&mut stack)?;
                let ok = verify_sig(tx, input, prevouts, Some(leaf), &key, &sig)?;
                let sum = n + i64::from(ok);
                stack.push(if sum == 0 { vec![] } else { vec![sum as u8] });
            }
            0xb1 => {
                let n = script_num(stack.last().ok_or("stack underflow")?);
                let lock = i64::from(tx.lock_time.to_consensus_u32());
                if tx.input[input].sequence.0 == 0xffff_ffff || lock < n || n >= 500_000_000 {
                    return Err(format!("CHECKLOCKTIMEVERIFY: locktime {lock} < {n}"));
                }
            }
            0xb2 => {
                let n = script_num(stack.last().ok_or("stack underflow")?);
                let sequence = tx.input[input].sequence.0;
                if tx.version.0 < 2
                    || sequence & (1 << 31) != 0
                    || sequence & (1 << 22) != 0
                    || i64::from(sequence & 0xffff) < n
                {
                    return Err(format!("CHECKSEQUENCEVERIFY: sequence {sequence} < {n}"));
                }
            }
            other => return Err(format!("unexpected opcode {other:#x}")),
        }
    }
    match stack.as_slice() {
        [top] if truthy(top) => Ok(()),
        _ => Err("script did not leave exactly one true element".into()),
    }
}

/// Every input of `tx`, each spending the matching `prevouts` entry.
pub fn verify_tx(tx: &Transaction, prevouts: &[TxOut]) -> Result<(), String> {
    (0..tx.input.len()).try_for_each(|i| verify_input(tx, i, prevouts))
}

/// Hitch's `t(name, cond)`: every check is reported, and the test fails at
/// the end with the list of those that did not hold.
#[derive(Default)]
pub struct Checks {
    passed: usize,
    failed: Vec<String>,
}

impl Checks {
    pub fn t(&mut self, name: &str, condition: bool) {
        println!("  {}  {name}", if condition { "PASS" } else { "FAIL" });
        if condition {
            self.passed += 1;
        } else {
            self.failed.push(name.to_owned());
        }
    }

    pub fn finish(self) -> usize {
        println!("\n{} passed, {} failed", self.passed, self.failed.len());
        assert!(
            self.failed.is_empty(),
            "failed checks:\n  {}",
            self.failed.join("\n  ")
        );
        self.passed
    }
}

impl Net {
    /// Whether host `h`'s commitment at state `n` on `id` is fully signed and
    /// valid against the funding output.
    pub fn commitment_verifies(&mut self, h: H, id: ChannelId, n: u64) -> bool {
        let aux = self.hosts[h].aux();
        let machine = self.hosts[h].channel(id);
        let Ok(tx) = machine.signed_commitment(n, &aux) else {
            return false;
        };
        verify_tx(&tx, &[machine.channel().funding_prevout()]).is_ok()
    }

    /// Remove the first queued message of type `t`, as Hitch's `drop(t)`.
    pub fn drop_first(&mut self, t: &str) {
        if let Some(i) = self.inbox.iter().position(|e| e.t() == t) {
            self.inbox.remove(i);
        }
    }

    /// Deliver the first queued message (Hitch's `inbox.shift()` then
    /// `onMessage`).
    pub fn step(&mut self) -> String {
        let envelope = self.shift();
        let t = envelope.t();
        self.deliver(envelope);
        t
    }

    /// Deliver an update, its acknowledgement and the revocation by hand.
    pub fn three_steps(&mut self) {
        self.step();
        self.step();
        self.step();
    }
}
