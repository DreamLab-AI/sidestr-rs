//! The relay conversation, without a socket: NIP-01 client and relay
//! messages, the two subscriptions siding makes, the on-receipt checks, and
//! the port an I/O layer implements (`siding/lib/relay.mjs`,
//! `announce.mjs fetchLatestTip`).
//!
//! # Why no socket
//!
//! siding uses the platform's `WebSocket` — Node 22's or the browser's — so
//! its relay code is pure and portable. A Rust crate has no platform socket;
//! choosing one (`tokio-tungstenite`, `async-std`, a blocking client) would
//! choose a runtime for every consumer. So this module gives the messages
//! and the rules, and [`RelayClient`] names what an I/O layer must do. A
//! producer with tokio wraps a websocket in it; a test answers from a
//! `Vec`. Relay I/O behind a feature is a 0.2 item.
//!
//! # The two subscriptions
//!
//! - [`tip_filter`]: `{kinds: [33333], "#d": [chain alias], limit: 5}` — a
//!   relay indexes `d`, so this is cheap.
//! - [`event_filter`]: `{ids: [id], limit: 1}` — one event by id, the chain
//!   event a tip names (`announce.mjs fetchEvent`, SPEC 0.0.5).
//! - [`follow_filter`]: `{kinds: [kind], since}` — **by kind only**. Relays
//!   "index single-letter tags for filtering and refuse `#chain`
//!   ('unindexed tag filter'), so the chain tag is checked here on each
//!   event instead". That check is [`Follower::accept`], which also
//!   deduplicates by id (a bounded set, as upstream's `seen`), verifies the
//!   signature and refuses another chain's event. DDD-022 names the cost:
//!   a producer on a shared relay downloads every sidestr chain's traffic
//!   of that kind and discards the rest.
//!
//! ```
//! use sidestr_nostr::event::SecretKeySigner;
//! use sidestr_nostr::relay::{ClientMessage, Follower, RelayMessage, follow_filter, tip_filter};
//! use sidestr_nostr::tx::sign_transaction_event;
//!
//! let req = ClientMessage::Req { subscription_id: "tip".into(), filters: vec![tip_filter("sidestr:example")] };
//! assert_eq!(req.to_json(), r##"["REQ","tip",{"kinds":[33333],"#d":["sidestr:example"],"limit":5}]"##);
//!
//! let ev = sign_transaction_event(&SecretKeySigner::from_bytes(&[1u8; 32]).unwrap(), "sidestr:example", "0200", 1).unwrap();
//! let wire = format!(r#"["EVENT","k23500",{}]"#, serde_json::to_string(&ev).unwrap());
//! let RelayMessage::Event { event, .. } = RelayMessage::from_json(&wire).unwrap() else { panic!() };
//!
//! let mut f = Follower::new(23500, "sidestr:example");
//! assert!(f.accept(&event).is_some());     // verified, tagged for this chain, new
//! assert!(f.accept(&event).is_none());     // seen
//! let _ = follow_filter(23500, 3600, 1_790_100_000);
//! ```

use std::collections::{HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::event::Event;
use crate::kinds::KIND_TIP;
use crate::tags::is_for_chain;

/// A NIP-01 filter, the fields sidestr uses.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filter {
    /// Event ids (SPEC 0.0.5: the chain event by its id, [`event_filter`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ids: Vec<String>,
    /// Kinds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<u32>,
    /// Authors (x-only pubkeys).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authors: Vec<String>,
    /// `#d` values.
    #[serde(rename = "#d", default, skip_serializing_if = "Vec::is_empty")]
    pub d: Vec<String>,
    /// `#t` values.
    #[serde(rename = "#t", default, skip_serializing_if = "Vec::is_empty")]
    pub t: Vec<String>,
    /// Events created at or after this unix time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    /// At most this many.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// The tip subscription (`announce.mjs fetchLatestTip`): kind 33333, `#d` =
/// chain id, limit 5.
pub fn tip_filter(chain_id: &str) -> Filter {
    Filter {
        kinds: vec![KIND_TIP],
        d: vec![chain_id.to_string()],
        limit: Some(5),
        ..Default::default()
    }
}

/// One event by its id (`announce.mjs fetchEvent`): `{ids: [id], limit:
/// 1}`. A tip's `e` tag names the chain event this way (SPEC 0.0.5).
///
/// ```
/// use sidestr_nostr::relay::event_filter;
/// let id = "ab".repeat(32);
/// assert_eq!(serde_json::to_string(&event_filter(&id)).unwrap(), format!(r#"{{"ids":["{id}"],"limit":1}}"#));
/// ```
pub fn event_filter(id: &str) -> Filter {
    Filter {
        ids: vec![id.to_string()],
        limit: Some(1),
        ..Default::default()
    }
}

/// A directory's subscription: every sidestr chain's tip at once (`#t` =
/// `sidestr`, SPEC 11).
pub fn directory_filter() -> Filter {
    Filter {
        kinds: vec![KIND_TIP],
        t: vec![crate::tags::TOPIC_SIDESTR.into()],
        ..Default::default()
    }
}

/// The follow subscription (`relay.mjs subscribe`): one kind, since `now -
/// since_secs`, no tag filter.
pub fn follow_filter(kind: u32, since_secs: u64, now: u64) -> Filter {
    Filter {
        kinds: vec![kind],
        since: Some(now.saturating_sub(since_secs)),
        ..Default::default()
    }
}

/// What a client sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientMessage {
    /// `["REQ", <id>, <filter>…]`.
    Req {
        /// The subscription id.
        subscription_id: String,
        /// One or more filters.
        filters: Vec<Filter>,
    },
    /// `["EVENT", <event>]`.
    Event(Event),
    /// `["CLOSE", <id>]`.
    Close(String),
}

impl ClientMessage {
    /// The wire JSON.
    pub fn to_json(&self) -> String {
        match self {
            ClientMessage::Req {
                subscription_id,
                filters,
            } => {
                let mut arr = vec![
                    serde_json::Value::from("REQ"),
                    serde_json::Value::from(subscription_id.as_str()),
                ];
                arr.extend(
                    filters
                        .iter()
                        .map(|f| serde_json::to_value(f).expect("plain fields")),
                );
                serde_json::Value::Array(arr).to_string()
            }
            ClientMessage::Event(ev) => {
                serde_json::to_string(&("EVENT", ev)).expect("plain fields")
            }
            ClientMessage::Close(id) => {
                serde_json::to_string(&("CLOSE", id)).expect("plain fields")
            }
        }
    }
}

/// What a relay sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayMessage {
    /// `["EVENT", <sub id>, <event>]`.
    Event {
        /// The subscription it answers.
        subscription_id: String,
        /// The event, unverified.
        event: Event,
    },
    /// `["EOSE", <sub id>]`: stored events are done; live ones may follow.
    Eose(String),
    /// `["OK", <event id>, <accepted>, <message>]`.
    Ok {
        /// The event id.
        event_id: String,
        /// Whether the relay took it.
        accepted: bool,
        /// The relay's message, often empty.
        message: String,
    },
    /// `["CLOSED", <sub id>, <message>]`.
    Closed(String, String),
    /// `["NOTICE", <message>]`.
    Notice(String),
}

impl RelayMessage {
    /// Parse one wire message. Unknown verbs are [`Error::Content`].
    pub fn from_json(text: &str) -> Result<Self> {
        let v: Vec<serde_json::Value> = serde_json::from_str(text)?;
        let verb = v.first().and_then(|x| x.as_str()).unwrap_or("");
        let s = |i: usize| v.get(i).and_then(|x| x.as_str()).map(str::to_string);
        match verb {
            "EVENT" => Ok(RelayMessage::Event {
                subscription_id: s(1)
                    .ok_or_else(|| Error::Content("EVENT without a subscription id".into()))?,
                event: serde_json::from_value(
                    v.get(2)
                        .cloned()
                        .ok_or_else(|| Error::Content("EVENT without an event".into()))?,
                )?,
            }),
            "EOSE" => Ok(RelayMessage::Eose(s(1).unwrap_or_default())),
            "OK" => Ok(RelayMessage::Ok {
                event_id: s(1).unwrap_or_default(),
                accepted: v.get(2).and_then(|x| x.as_bool()).unwrap_or(false),
                message: s(3).unwrap_or_default(),
            }),
            "CLOSED" => Ok(RelayMessage::Closed(
                s(1).unwrap_or_default(),
                s(2).unwrap_or_default(),
            )),
            "NOTICE" => Ok(RelayMessage::Notice(s(1).unwrap_or_default())),
            other => Err(Error::Content(format!("unknown relay message {other:?}"))),
        }
    }
}

/// What a relay said to a publish (`relay.mjs publish`): `ok`, the relay's
/// rejection message, `timeout`, or `closed before OK`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Accepted.
    Ok,
    /// Refused, with the relay's reason (`rejected` when it gave none).
    Rejected(String),
    /// No `OK` within the deadline.
    Timeout,
    /// The socket closed first.
    Closed,
}

impl PublishOutcome {
    /// From an `OK` message for the event.
    pub fn from_ok(accepted: bool, message: &str) -> Self {
        if accepted {
            PublishOutcome::Ok
        } else if message.is_empty() {
            PublishOutcome::Rejected("rejected".into())
        } else {
            PublishOutcome::Rejected(message.into())
        }
    }
}

/// The on-receipt checks of `relay.mjs subscribe`, as state: one kind, one
/// chain, a bounded set of ids already seen. [`Self::accept`] returns the
/// event when it is of the kind, carries `chain` = this chain, has not been
/// seen, and verifies; `None` otherwise. What it returns is still only an
/// envelope — "then the transaction itself must validate to be included".
#[derive(Debug)]
pub struct Follower {
    kind: u32,
    chain_id: String,
    seen: HashSet<String>,
    order: VecDeque<String>,
    cap: usize,
}

impl Follower {
    /// Follow one kind for one chain, remembering the last 10 000 ids.
    pub fn new(kind: u32, chain_id: &str) -> Self {
        Self::with_capacity(kind, chain_id, 10_000)
    }

    /// As [`Self::new`] with a different memory.
    pub fn with_capacity(kind: u32, chain_id: &str, cap: usize) -> Self {
        Self {
            kind,
            chain_id: chain_id.to_string(),
            seen: HashSet::new(),
            order: VecDeque::new(),
            cap: cap.max(1),
        }
    }

    /// The checks, in upstream's order: kind, seen, chain tag, signature.
    pub fn accept<'a>(&mut self, ev: &'a Event) -> Option<&'a Event> {
        if ev.kind != self.kind || self.seen.contains(&ev.id) {
            return None;
        }
        if !is_for_chain(&ev.tags, &self.chain_id) {
            return None;
        }
        self.remember(ev.id.clone());
        ev.verify().ok().map(|_| ev)
    }

    fn remember(&mut self, id: String) {
        if self.seen.insert(id.clone()) {
            self.order.push_back(id);
            if self.order.len() > self.cap {
                if let Some(old) = self.order.pop_front() {
                    self.seen.remove(&old);
                }
            }
        }
    }

    /// How many ids are remembered.
    pub fn seen(&self) -> usize {
        self.seen.len()
    }
}

/// The port an I/O layer implements. Two operations are all siding needs
/// (`publish`, and a `REQ` drained to `EOSE` for `fetchLatestTip`); a
/// long-lived follow is the same `query` kept open, which is the I/O layer's
/// business. Implementations decide their own runtime, timeouts and
/// reconnection; the pure rules ([`Follower`], [`crate::tip::newest`])
/// are applied to what comes back.
pub trait RelayClient {
    /// Send `["EVENT", event]` to one relay and report what it said.
    fn publish(&mut self, relay: &str, event: &Event) -> PublishOutcome;
    /// Send a `REQ` to one relay and return every `EVENT` up to `EOSE`, or
    /// an error naming the relay.
    fn query(
        &mut self,
        relay: &str,
        filters: &[Filter],
    ) -> core::result::Result<Vec<Event>, String>;
}

/// Publish to every relay (`relay.mjs publish`): each one's verdict, in order.
pub fn publish_all(
    client: &mut dyn RelayClient,
    relays: &[String],
    event: &Event,
) -> Vec<(String, PublishOutcome)> {
    relays
        .iter()
        .map(|r| (r.clone(), client.publish(r, event)))
        .collect()
}

/// The newest announcement for a chain from any of the relays
/// (`announce.mjs fetchLatestTip`): [`tip_filter`] on each, then
/// [`crate::tip::newest`] over everything that came back. A relay that
/// errors is skipped.
pub fn fetch_latest_tip(
    client: &mut dyn RelayClient,
    relays: &[String],
    chain_id: &str,
    signer: Option<&str>,
) -> Option<crate::tip::Tip> {
    let filters = [tip_filter(chain_id)];
    let mut all = Vec::new();
    for r in relays {
        if let Ok(evs) = client.query(r, &filters) {
            all.extend(evs);
        }
    }
    crate::tip::newest(&all, chain_id, signer)
}

/// One event by id from any of the relays (`announce.mjs fetchEvent`):
/// [`event_filter`] to each in turn, and the first event whose id is the one
/// asked for ends the search; `None` when no relay has it. The event is not
/// verified here ([`crate::chain::parse_chain_event`] verifies it).
///
/// Upstream asks every relay at once and closes every socket on the first
/// answer, or gives up after 6 s; how many relays are asked at once, and
/// when, is the I/O layer's business ([`RelayClient`]), so here the relays
/// are asked in order and the first answer wins.
pub fn fetch_event(client: &mut dyn RelayClient, relays: &[String], id: &str) -> Option<Event> {
    let filters = [event_filter(id)];
    relays.iter().find_map(|r| {
        client
            .query(r, &filters)
            .ok()?
            .into_iter()
            .find(|e| e.id == id)
    })
}

/// [`crate::chain::resolve_chain`] over the port (`announce.mjs
/// resolveChain` with its default lookups): the newest tip by
/// [`fetch_latest_tip`] (any author: the rule checks the author against the
/// chain event's), the event by [`fetch_event`], and a mirror's JSON by
/// `fetch_json`.
pub fn resolve_chain(
    client: &mut dyn RelayClient,
    relays: &[String],
    alias: Option<&str>,
    hash: Option<&str>,
    fetch_json: impl FnMut(&str) -> core::result::Result<serde_json::Value, String>,
) -> Result<crate::chain::Resolved> {
    let client = core::cell::RefCell::new(client);
    crate::chain::resolve_chain(
        alias,
        hash,
        relays.len(),
        |a| fetch_latest_tip(&mut **client.borrow_mut(), relays, a, None),
        |id| fetch_event(&mut **client.borrow_mut(), relays, id),
        fetch_json,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::SecretKeySigner;
    use crate::tip::{sign_tip, TipTemplate};
    use crate::tx::sign_transaction_event;

    fn signer() -> SecretKeySigner {
        SecretKeySigner::from_bytes(&[1u8; 32]).unwrap()
    }

    #[test]
    fn filters_serialise_as_nip01() {
        assert_eq!(
            serde_json::to_string(&tip_filter("sidestr:t")).unwrap(),
            r##"{"kinds":[33333],"#d":["sidestr:t"],"limit":5}"##
        );
        assert_eq!(
            serde_json::to_string(&follow_filter(23500, 3600, 10_000)).unwrap(),
            r#"{"kinds":[23500],"since":6400}"#
        );
        assert_eq!(
            serde_json::to_string(&directory_filter()).unwrap(),
            r##"{"kinds":[33333],"#t":["sidestr"]}"##
        );
        assert_eq!(follow_filter(1, 10, 5).since, Some(0));
        assert_eq!(
            serde_json::to_string(&event_filter(&"ab".repeat(32))).unwrap(),
            format!(r#"{{"ids":["{}"],"limit":1}}"#, "ab".repeat(32))
        );
        let back: Filter = serde_json::from_str(r#"{"ids":["x"]}"#).unwrap();
        assert_eq!(back.ids, ["x"]);
        let back: Filter =
            serde_json::from_str(r##"{"kinds":[33333],"#d":["x"],"authors":["a"]}"##).unwrap();
        assert_eq!(
            (back.d, back.authors),
            (vec!["x".to_string()], vec!["a".to_string()])
        );
    }

    #[test]
    fn client_messages() {
        let ev = sign_transaction_event(&signer(), "sidestr:t", "0200", 1).unwrap();
        assert!(ClientMessage::Event(ev.clone())
            .to_json()
            .starts_with(r#"["EVENT",{"id":""#));
        assert_eq!(
            ClientMessage::Close("x".into()).to_json(),
            r#"["CLOSE","x"]"#
        );
        let req = ClientMessage::Req {
            subscription_id: "k".into(),
            filters: vec![Filter::default(), tip_filter("c")],
        };
        assert_eq!(
            req.to_json(),
            r##"["REQ","k",{},{"kinds":[33333],"#d":["c"],"limit":5}]"##
        );
    }

    #[test]
    fn relay_messages() {
        let ev = sign_transaction_event(&signer(), "sidestr:t", "0200", 1).unwrap();
        let m = RelayMessage::from_json(&format!(
            r#"["EVENT","s",{}]"#,
            serde_json::to_string(&ev).unwrap()
        ))
        .unwrap();
        assert_eq!(
            m,
            RelayMessage::Event {
                subscription_id: "s".into(),
                event: ev.clone()
            }
        );
        assert_eq!(
            RelayMessage::from_json(r#"["EOSE","s"]"#).unwrap(),
            RelayMessage::Eose("s".into())
        );
        assert_eq!(
            RelayMessage::from_json(&format!(r#"["OK","{}",true,""]"#, ev.id)).unwrap(),
            RelayMessage::Ok {
                event_id: ev.id.clone(),
                accepted: true,
                message: String::new()
            }
        );
        assert_eq!(
            RelayMessage::from_json(r#"["CLOSED","s","why"]"#).unwrap(),
            RelayMessage::Closed("s".into(), "why".into())
        );
        assert_eq!(
            RelayMessage::from_json(r#"["NOTICE","hi"]"#).unwrap(),
            RelayMessage::Notice("hi".into())
        );
        assert!(RelayMessage::from_json(r#"["AUTH","x"]"#).is_err());
        assert!(RelayMessage::from_json(r#"["EVENT","s"]"#).is_err());
        assert!(RelayMessage::from_json("nope").is_err());
        assert_eq!(
            PublishOutcome::from_ok(false, ""),
            PublishOutcome::Rejected("rejected".into())
        );
        assert_eq!(
            PublishOutcome::from_ok(false, "blocked: x"),
            PublishOutcome::Rejected("blocked: x".into())
        );
        assert_eq!(PublishOutcome::from_ok(true, ""), PublishOutcome::Ok);
    }

    #[test]
    fn the_follower_applies_the_on_receipt_checks_in_order() {
        let mine = sign_transaction_event(&signer(), "sidestr:t", "0200", 1).unwrap();
        let theirs = sign_transaction_event(&signer(), "sidestr:u", "0200", 1).unwrap();
        let mut forged = mine.clone();
        forged.content = "0300".into();
        let mut f = Follower::with_capacity(23500, "sidestr:t", 2);
        assert!(f.accept(&mine).is_some());
        assert!(f.accept(&mine).is_none(), "seen");
        assert!(f.accept(&theirs).is_none(), "another chain's");
        assert!(f.accept(&forged).is_none(), "bad signature");
        let mut wrong_kind = mine.clone();
        wrong_kind.kind = 23501;
        assert!(f.accept(&wrong_kind).is_none());
        // the memory is bounded and forgets the oldest first
        let a = sign_transaction_event(&signer(), "sidestr:t", "0201", 2).unwrap();
        let b = sign_transaction_event(&signer(), "sidestr:t", "0202", 3).unwrap();
        assert!(f.accept(&a).is_some());
        assert!(f.accept(&b).is_some());
        assert_eq!(f.seen(), 2);
        assert!(f.accept(&mine).is_some(), "forgotten, so accepted again");
    }

    struct Canned(Vec<Event>);
    impl RelayClient for Canned {
        fn publish(&mut self, relay: &str, _: &Event) -> PublishOutcome {
            if relay.contains("bad") {
                PublishOutcome::Timeout
            } else {
                PublishOutcome::Ok
            }
        }
        fn query(
            &mut self,
            relay: &str,
            filters: &[Filter],
        ) -> core::result::Result<Vec<Event>, String> {
            if relay.contains("bad") {
                return Err("down".into());
            }
            assert_eq!(filters, [tip_filter("sidestr:t")]);
            Ok(self.0.clone())
        }
    }

    #[test]
    fn fetch_latest_tip_and_publish_all_over_the_port() {
        let t = |tip| {
            sign_tip(
                &signer(),
                &TipTemplate::new("sidestr:t", tip, vec![], vec![]).unwrap(),
                1,
            )
            .unwrap()
        };
        let mut c = Canned(vec![t(3), t(8), t(5)]);
        let relays = vec!["wss://good".to_string(), "wss://bad".to_string()];
        assert_eq!(
            fetch_latest_tip(&mut c, &relays, "sidestr:t", None)
                .unwrap()
                .tip,
            8
        );
        assert!(fetch_latest_tip(&mut c, &relays, "sidestr:t", Some(&"ab".repeat(32))).is_none());
        let r = publish_all(&mut c, &relays, &t(1));
        assert_eq!(r[0].1, PublishOutcome::Ok);
        assert_eq!(r[1].1, PublishOutcome::Timeout);
    }

    /// A relay set that answers `REQ`s by filter, as a relay would.
    struct Store(Vec<Event>, Vec<String>);
    impl RelayClient for Store {
        fn publish(&mut self, _: &str, _: &Event) -> PublishOutcome {
            PublishOutcome::Ok
        }
        fn query(
            &mut self,
            relay: &str,
            filters: &[Filter],
        ) -> core::result::Result<Vec<Event>, String> {
            self.1.push(relay.to_string());
            if relay.contains("bad") {
                return Err("down".into());
            }
            let f = &filters[0];
            Ok(self
                .0
                .iter()
                .filter(|e| f.ids.is_empty() || f.ids.contains(&e.id))
                .filter(|e| f.kinds.is_empty() || f.kinds.contains(&e.kind))
                .filter(|e| {
                    f.d.is_empty()
                        || e.tags
                            .iter()
                            .any(|t| t.len() > 1 && t[0] == "d" && f.d.contains(&t[1]))
                })
                .cloned()
                .collect())
        }
    }

    #[test]
    fn fetch_event_and_resolve_chain_over_the_port() {
        let s = signer();
        let me = crate::event::Signer::pubkey_hex(&s).unwrap();
        let doc = format!(
            r#"{{"id":"sidestr:t","name":"t","parent":"tbtc4","challenge":"5120{me}","signer":"{me}"}}"#
        );
        let chain_ev = crate::chain::sign_chain_event(&s, &doc, 5).unwrap();
        let tip = sign_tip(
            &s,
            &TipTemplate::new("sidestr:t", 3, vec![], vec!["https://m.example".into()])
                .unwrap()
                .with_chain_hash(&chain_ev.id)
                .unwrap(),
            6,
        )
        .unwrap();
        let relays = vec![
            "wss://bad".to_string(),
            "wss://a".to_string(),
            "wss://b".to_string(),
        ];
        let mut store = Store(vec![tip.clone(), chain_ev.clone()], vec![]);
        // the first relay that has it ends the search: b is never asked
        assert_eq!(
            fetch_event(&mut store, &relays, &chain_ev.id),
            Some(chain_ev.clone())
        );
        assert_eq!(store.1, ["wss://bad", "wss://a"]);
        assert_eq!(fetch_event(&mut store, &relays, &"cd".repeat(32)), None);
        // by alias, then by hash, over the same port
        let r = resolve_chain(&mut store, &relays, Some("sidestr:t"), None, |_| {
            Err("404".into())
        })
        .unwrap();
        assert_eq!(r.hash.as_deref(), Some(chain_ev.id.as_str()));
        assert_eq!(r.mirror.as_deref(), Some("https://m.example"));
        let r = resolve_chain(&mut store, &relays, None, Some(&chain_ev.id), |_| {
            Err("404".into())
        })
        .unwrap();
        assert_eq!((r.alias.as_str(), r.legacy), ("sidestr:t", false));
        let e = resolve_chain(
            &mut Store(vec![], vec![]),
            &relays,
            Some("sidestr:t"),
            None,
            |_| Err("404".into()),
        )
        .unwrap_err();
        assert!(
            e.to_string()
                .contains("no announcement for sidestr:t on 3 relay(s)"),
            "{e}"
        );
    }
}
