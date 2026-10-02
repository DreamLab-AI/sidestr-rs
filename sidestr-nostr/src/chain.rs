//! The chain document as an event, kind 3500, and resolving a chain by its
//! alias or its hash (SPEC 3, 11 and Appendix A, 0.0.5;
//! `siding/lib/announce.mjs` `chainEvent`, `parseChainEvent`,
//! `resolveChain`).
//!
//! In Melvin Carvalho's words, adapted from SPEC 3 (0.0.5): the chain
//! document is a Nostr event of kind 3500, a regular kind: signed by the
//! chain's key, and immutable, since a chain must not change under its users
//! (changes are rule documents with activation heights). Its **event id is
//! the chain's hash**, the one value that names this chain and no other: it
//! is what the tip announcement points at, what a client verifies the
//! document against, and what anything that must commit to a chain uses (a
//! peg-in tweak; a nested chain's `parent`). The event's pubkey is the
//! signer; the document carries no `signer` field. A chain is final once its
//! document is signed: re-signing gives a new id, which is a new chain.
//!
//! # Two names
//!
//! - The **chain alias**, `sidestr:<name>`: the document's `id` field, the
//!   `d` and `n` of a tip announcement, the name in a `pegin:`/`pegout:`
//!   `OP_RETURN`, the `d` of a rule document, the genesis's `chain` field.
//!   A document cannot contain its own hash, so inside it, and in everything
//!   written before the hash exists, the chain is its alias. **The alias is
//!   a name, not a proof**: two signers can both announce `sidestr:poker`.
//! - The **chain hash**: the kind-3500 event's id. A tip names it with an
//!   `e` tag ([`crate::tip::TipTemplate::with_chain_hash`]); a client that
//!   knows the hash takes no other document.
//!
//! # The hash is the hash of the document's JSON as JavaScript writes it
//!
//! The content of the event is `JSON.stringify` of the document with its
//! `signer` deleted, and the id is SHA-256 over the NIP-01 serialisation of
//! that content, so a Rust-built event has siding's id only if it writes the
//! same bytes. [`chain_event`] therefore takes the document's **JSON text**
//! and writes it as `JSON.parse` then `JSON.stringify` would: keys in the
//! source's order (a repeated key keeps its first place and its last value),
//! except that integer-like keys move to the front in ascending order, as
//! JavaScript orders an object's own keys; numbers as JavaScript prints them
//! (`1.0` is `1`, `1e21` is `1e+21`, an integer past 2^53 is rounded to the
//! nearest double); no whitespace. `tests/chain_event.rs` holds this to
//! events siding built (`fixtures/chain-event-vectors.json`).
//! [`chain_event_of`] builds from a parsed
//! [`ChainDocument`] instead, in the struct's field order: a valid event,
//! but not the hash siding gives for the same file, so use it only for a
//! document that exists nowhere else as text.
//!
//! # Resolving (SPEC 11)
//!
//! [`resolve_chain`] is `resolveChain` without sockets: the caller answers
//! three questions (the newest tip for an alias, an event by id, a mirror's
//! JSON) and the rule decides. A chain made before 0.0.5 has no `e` on its
//! tip and resolves the old way, by a mirror's `chain.json` whose `signer` is
//! the tip's author ([`crate::tip::choose_mirror`]), with `hash: None` and
//! `legacy: true`: that is how the live `sidestr:dreamlab` resolves until its
//! signer publishes its document as an event.
//!
//! # A sidestr chain as a parent (SPEC 3.1)
//!
//! [`resolve_nested_parent`] resolves a document's `parent` when it is a
//! sidestr chain's hash: the chain event with that id is fetched, verified
//! and read back, and its own `parent` followed down to a row of the SPEC
//! 3.2 table, whose header family every level inherits
//! ([`sidestr_core::parents::resolve_parent_with`]). The reference's
//! `parents.mjs` at `e8deb63` refuses such a parent: this is a departure
//! from it, following the SPEC's prose (ADR-0001 D4), and an alias resolves
//! exactly as there.
//!
//! ```
//! use sidestr_nostr::chain::{parse_chain_event, sign_chain_event, KIND_CHAIN_DOCUMENT};
//! use sidestr_nostr::event::{SecretKeySigner, Signer};
//!
//! let signer = SecretKeySigner::from_hex(&"07".repeat(32)).unwrap();
//! let me = signer.pubkey_hex().unwrap();
//! let doc = format!(r#"{{"id":"sidestr:example","name":"example","parent":"tbtc4",
//!   "challenge":"5120{me}","signer":"{me}","genesisTime":1790000000}}"#);
//!
//! let ev = sign_chain_event(&signer, &doc, 1_790_100_000).unwrap();
//! assert_eq!(ev.kind, KIND_CHAIN_DOCUMENT);
//! assert!(!ev.content.contains("\"signer\""));            // the event's author is the signer
//!
//! let parsed = parse_chain_event(&ev).unwrap();             // verifies id and signature first
//! assert_eq!(parsed.hash, ev.id);                            // the chain's hash
//! assert_eq!(parsed.alias, "sidestr:example");
//! assert_eq!(parsed.chain["signer"], me.as_str());           // filled from the author (level 1)
//! ```

use std::collections::HashMap;

use serde_json::{Map, Number, Value};
use sidestr_core::document::ChainDocument;
use sidestr_core::parents::{resolve_parent_with, ParentRef};

use crate::error::{Error, Result};
use crate::event::{sign, Event, Signer, UnsignedEvent};
use crate::tags::{tag, TAG_ALT, TAG_N, TAG_T, TOPIC_SIDESTR};
use crate::tip::{choose_mirror, MirrorChain, Tip};

pub use crate::kinds::KIND_CHAIN_DOCUMENT;

/// The file a mirror serves the chain event as, beside `chain.json`, and
/// that `siding chain-event` writes beside the document.
pub const CHAIN_EVENT_FILE: &str = "chain-event.json";

/// Whether `s` is a chain alias as `chainEvent` requires one:
/// `/^sidestr:[a-z0-9][a-z0-9-]*$/`.
///
/// ```
/// use sidestr_nostr::chain::is_alias;
/// assert!(is_alias("sidestr:txbt4-siding"));
/// assert!(!is_alias("poker") && !is_alias("sidestr:-x") && !is_alias("sidestr:Poker"));
/// ```
pub fn is_alias(s: &str) -> bool {
    let Some(name) = s.strip_prefix("sidestr:") else {
        return false;
    };
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Whether `s` is a chain hash: 64 hex characters, either case
/// (`/^[0-9a-f]{64}$/i`, untrimmed).
pub fn is_chain_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Where a mirror serves the chain event: `<mirror>/chain-event.json`.
pub fn chain_event_url(mirror: &str) -> String {
    format!("{}/{CHAIN_EVENT_FILE}", mirror.trim_end_matches('/'))
}

/// The unsigned chain event for a document given as JSON text
/// (`announce.mjs chainEvent`): kind 3500, tags `n` = alias, `t` =
/// `sidestr`, `alt` = "sidestr chain document `<alias>`", content the
/// document as `JSON.stringify` writes it with its `signer` deleted
/// (`signers`, level 2, stays: it names the set). The document's `id` must
/// be an alias ([`is_alias`]), or this refuses as the reference throws. Only
/// the alias is judged here, as upstream judges it; a validator checks the
/// document itself with [`ChainDocument::validate_with`].
///
/// ```
/// use sidestr_nostr::chain::chain_event;
///
/// let ev = chain_event(r#"{ "id": "sidestr:x", "name": "x", "signer": "ab", "n": 1.0 }"#, 1).unwrap();
/// assert_eq!(ev.content, r#"{"id":"sidestr:x","name":"x","n":1}"#);
/// assert_eq!(ev.tags[0], ["n", "sidestr:x"]);
/// assert!(chain_event(r#"{ "id": "poker" }"#, 1).is_err());
/// ```
pub fn chain_event(document_json: &str, created_at: u64) -> Result<UnsignedEvent> {
    let doc: Value = serde_json::from_str(document_json)?;
    chain_event_from_value(&doc, created_at)
}

/// [`chain_event`] for a document already parsed into a [`Value`] (whose
/// key order, with `serde_json`'s `preserve_order`, is the source's).
pub fn chain_event_from_value(document: &Value, created_at: u64) -> Result<UnsignedEvent> {
    let alias = document
        .get("id")
        .and_then(Value::as_str)
        .filter(|a| is_alias(a))
        .ok_or_else(|| {
            Error::Chain("the document names its alias in `id` (sidestr:<name>)".into())
        })?
        .to_string();
    let mut doc = document.clone();
    if let Value::Object(m) = &mut doc {
        m.shift_remove("signer");
    }
    Ok(UnsignedEvent {
        pubkey: String::new(),
        created_at,
        kind: KIND_CHAIN_DOCUMENT,
        tags: vec![
            tag(TAG_N, &alias),
            tag(TAG_T, TOPIC_SIDESTR),
            tag(TAG_ALT, format!("sidestr chain document {alias}")),
        ],
        content: js_stringify(&doc),
    })
}

/// [`chain_event`] for a parsed [`ChainDocument`], its fields in the
/// struct's order and [`ChainDocument::extra`] after them, sorted. A valid
/// chain event, but **not** the hash siding gives for the same document's
/// file, whose key order is the file's: see the module documentation.
pub fn chain_event_of(document: &ChainDocument, created_at: u64) -> Result<UnsignedEvent> {
    chain_event_from_value(&serde_json::to_value(document)?, created_at)
}

/// Sign [`chain_event`] with the chain's signer (level 1) or one of its
/// signers (level 2). The event's pubkey is the signer's whatever the
/// document said.
pub fn sign_chain_event(
    signer: &dyn Signer,
    document_json: &str,
    created_at: u64,
) -> Result<Event> {
    sign(signer, chain_event(document_json, created_at)?)
}

/// Sign [`chain_event_of`].
pub fn sign_chain_event_of(
    signer: &dyn Signer,
    document: &ChainDocument,
    created_at: u64,
) -> Result<Event> {
    sign(signer, chain_event_of(document, created_at)?)
}

/// A chain event read back (`announce.mjs parseChainEvent`).
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedChain {
    /// The chain's hash: the event's id.
    pub hash: String,
    /// The chain's alias: the document's `id`.
    pub alias: String,
    /// The event's author, the chain's signer (level 1) or one of its
    /// signers (level 2).
    pub pubkey: String,
    /// The document as upstream returns it: the content, with `signer` set
    /// to the author when the document names neither `signer` nor `signers`
    /// (appended last, as `{ ...chain, signer }` places it).
    pub chain: Value,
    /// The event itself.
    pub event: Event,
}

impl ParsedChain {
    /// The document as a [`ChainDocument`], parsed but not validated: a
    /// validator calls [`ChainDocument::validate_with`] with the rules it
    /// carries. Because `signer` is filled from the author for a level-1
    /// document, that validation checks the challenge is the author's key.
    pub fn document(&self) -> Result<ChainDocument> {
        document_of(&self.chain)
    }
}

fn document_of(chain: &Value) -> Result<ChainDocument> {
    serde_json::from_value(chain.clone())
        .map_err(|e| Error::Content(format!("the chain document does not parse: {e}")))
}

/// Read a chain event back (`announce.mjs parseChainEvent`), in upstream's
/// order: kind 3500; the event verifies (its id is the hash of its fields
/// and its signature is the author's), or "the chain event does not verify
/// (id or signature)"; the content is a JSON object with a string `id`; a
/// `signer` field, if present, is the author; a `signers` array, if
/// present, includes the author. The document is not otherwise judged
/// ([`ParsedChain::document`]).
///
/// The comparisons are upstream's: exact strings, so a `signer` in upper
/// case is "a signer other than the event's author".
pub fn parse_chain_event(ev: &Event) -> Result<ParsedChain> {
    if ev.kind != KIND_CHAIN_DOCUMENT {
        return Err(Error::Kind {
            expected: KIND_CHAIN_DOCUMENT,
            found: ev.kind,
            what: "chain event",
        });
    }
    if ev.verify().is_err() {
        return Err(Error::Signature(
            "the chain event does not verify (id or signature)".into(),
        ));
    }
    let mut chain: Value = serde_json::from_str(&ev.content)
        .map_err(|_| Error::Content("the chain event's content is not JSON".into()))?;
    let Some(m) = chain
        .as_object_mut()
        .filter(|m| m.get("id").is_some_and(Value::is_string))
    else {
        return Err(Error::Content(
            "the chain event carries no document with an alias".into(),
        ));
    };
    let author = Value::String(ev.pubkey.clone());
    if m.get("signer").is_some_and(|s| *s != author) {
        return Err(Error::Chain(
            "the document names a signer other than the event's author".into(),
        ));
    }
    let signers = m.get("signers").and_then(Value::as_array);
    if signers.is_some_and(|s| !s.contains(&author)) {
        return Err(Error::Chain(
            "the event's author is not one of the document's signers".into(),
        ));
    }
    if !m.contains_key("signer") && signers.is_none() {
        m.insert("signer".into(), author);
    }
    let alias = m["id"].as_str().expect("checked a string").to_string();
    Ok(ParsedChain {
        hash: ev.id.clone(),
        alias,
        pubkey: ev.pubkey.clone(),
        chain,
        event: ev.clone(),
    })
}

/// [`parse_chain_event`] for an event that arrived as JSON (a mirror's
/// `chain-event.json`): the kind is judged first, as upstream judges it,
/// and JSON that is not a whole event does not verify.
pub fn parse_chain_event_value(v: &Value) -> Result<ParsedChain> {
    let kind = v.get("kind").and_then(Value::as_u64);
    if kind != Some(u64::from(KIND_CHAIN_DOCUMENT)) {
        return Err(Error::Kind {
            expected: KIND_CHAIN_DOCUMENT,
            found: kind.and_then(|k| u32::try_from(k).ok()).unwrap_or(0),
            what: "chain event",
        });
    }
    let ev: Event = serde_json::from_value(v.clone()).map_err(|_| {
        Error::Signature("the chain event does not verify (id or signature)".into())
    })?;
    parse_chain_event(&ev)
}

/// What [`resolve_chain`] settled on (`announce.mjs resolveChain`'s
/// result).
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved {
    /// The chain's hash, `None` for a chain made before 0.0.5 (`legacy`).
    pub hash: Option<String>,
    /// The chain's alias.
    pub alias: String,
    /// The key the chain was settled on: the chain event's author, or for a
    /// legacy chain the announcement's author, whom the mirror's document
    /// names as its signer.
    pub pubkey: String,
    /// The document: the chain event's (as [`ParsedChain::chain`]), or for a
    /// legacy chain the mirror's `chain.json` as it was served.
    pub chain: Value,
    /// The newest tip announcement, when there is one.
    pub tip: Option<Tip>,
    /// The first mirror the tip names (legacy: the mirror whose
    /// `chain.json` checked out).
    pub mirror: Option<String>,
    /// Every mirror the tip names.
    pub mirrors: Vec<String>,
    /// Resolved the pre-0.0.5 way: no chain event, the mirror's
    /// `chain.json` by its `signer` field.
    pub legacy: bool,
}

impl Resolved {
    /// The document as a [`ChainDocument`], parsed but not validated.
    pub fn document(&self) -> Result<ChainDocument> {
        document_of(&self.chain)
    }
}

fn short(s: &str, n: usize) -> &str {
    s.get(..n).unwrap_or(s)
}

/// Resolve a chain by its alias, or by its hash (`announce.mjs
/// resolveChain`, SPEC 11), over three lookups the caller answers:
///
/// - `get_tip(alias)`: the newest verified tip announcement for an alias
///   ([`crate::tip::newest`] over what the relays hold;
///   [`crate::relay::fetch_latest_tip`] over the port);
/// - `get_event(id)`: the event with this id from a relay, unverified
///   ([`crate::relay::fetch_event`]);
/// - `fetch_json(url)`: a mirror's `chain-event.json` or `chain.json`.
///
/// `relays` is how many relays were asked, for the messages. The rule, step
/// for step as upstream: a hash must be 64 hex. With an alias, the newest tip
/// for it; the chain to find is the hash given, else the tip's `e`. No such
/// hash: no tip is "no announcement for `<alias>`", a tip is a chain made
/// before 0.0.5, resolved by [`choose_mirror`] (`legacy`). Otherwise the
/// event by id from a relay, or else from each mirror the tip names
/// (`<mirror>/chain-event.json`, taken when its `id` is the hash); it must
/// verify ([`parse_chain_event`]) and be the one asked for. Without a tip
/// yet, the newest tip for the document's alias. That tip's author must be
/// the event's author or one of the document's `signers`, and a tip naming
/// another chain hash is refused.
///
/// One departure: with neither an alias nor a hash there is nothing to
/// resolve, which is refused up front rather than reported as "no
/// announcement for null".
///
/// A mirror's `chain.json` (legacy) that is not a document [`MirrorChain`]
/// reads (no string `id`, a `signer` that is not a string) counts as a
/// mirror that does not check out, with the reason in the error.
pub fn resolve_chain(
    alias: Option<&str>,
    hash: Option<&str>,
    relays: usize,
    mut get_tip: impl FnMut(&str) -> Option<Tip>,
    mut get_event: impl FnMut(&str) -> Option<Event>,
    mut fetch_json: impl FnMut(&str) -> core::result::Result<Value, String>,
) -> Result<Resolved> {
    if let Some(h) = hash {
        if !is_chain_hash(h) {
            return Err(Error::Hex {
                what: "chain hash",
                reason: "a chain hash is 64 hex".into(),
            });
        }
    }
    if alias.is_none() && hash.is_none() {
        return Err(Error::Chain(
            "a chain is resolved by its alias or its hash".into(),
        ));
    }
    let mut tip = alias.and_then(&mut get_tip);
    let id = hash
        .map(str::to_ascii_lowercase)
        .or_else(|| tip.as_ref().and_then(|t| t.chain_hash.clone()));
    let Some(id) = id else {
        let alias = alias.expect("no hash, so an alias");
        let Some(tip) = tip else {
            return Err(Error::Chain(format!(
                "no announcement for {alias} on {relays} relay(s)"
            )));
        };
        let mut served: HashMap<String, Value> = HashMap::new();
        let chosen = choose_mirror(&tip, alias, |url| {
            let v = fetch_json(url)?;
            let m: MirrorChain = serde_json::from_value(v.clone()).map_err(|e| e.to_string())?;
            served.insert(url.to_string(), v);
            Ok(m)
        })?;
        let chain = served
            .remove(&crate::tip::chain_json_url(&chosen.mirror))
            .expect("the chosen mirror's document was fetched");
        return Ok(Resolved {
            hash: None,
            alias: alias.to_string(),
            pubkey: tip.pubkey.clone(),
            chain,
            mirror: Some(chosen.mirror),
            mirrors: tip.mirrors.clone(),
            tip: Some(tip),
            legacy: true,
        });
    };
    let parsed = match get_event(&id) {
        Some(ev) => parse_chain_event(&ev)?,
        None => {
            let from_mirror = tip.as_ref().and_then(|t| {
                t.mirrors.iter().find_map(|m| {
                    fetch_json(&chain_event_url(m))
                        .ok()
                        .filter(|c| c.get("id").and_then(Value::as_str) == Some(id.as_str()))
                })
            });
            match from_mirror {
                Some(v) => parse_chain_event_value(&v)?,
                None => {
                    return Err(Error::Chain(format!(
                        "the chain event {}… is on none of {relays} relay(s){}",
                        short(&id, 16),
                        if tip.is_some() {
                            " or the mirrors the tip names"
                        } else {
                            ""
                        }
                    )))
                }
            }
        }
    };
    if parsed.hash != id {
        return Err(Error::Chain(
            "the event found is not the one asked for".into(),
        ));
    }
    if tip.is_none() {
        tip = get_tip(&parsed.alias);
    }
    if let Some(t) = &tip {
        let by_a_signer = parsed
            .chain
            .get("signers")
            .and_then(Value::as_array)
            .is_some_and(|s| s.contains(&Value::String(t.pubkey.clone())));
        if t.pubkey != parsed.pubkey && !by_a_signer {
            return Err(Error::Chain(format!(
                "the tip for {} is by {}…, not the chain's signer {}…",
                parsed.alias,
                short(&t.pubkey, 8),
                short(&parsed.pubkey, 8)
            )));
        }
        if let Some(other) = t.chain_hash.as_deref().filter(|h| *h != id) {
            return Err(Error::Chain(format!(
                "the newest tip for {} names another chain ({}…)",
                parsed.alias,
                short(other, 16)
            )));
        }
    }
    Ok(Resolved {
        hash: Some(id),
        alias: parsed.alias,
        pubkey: parsed.pubkey,
        chain: parsed.chain,
        mirror: tip.as_ref().and_then(|t| t.mirrors.first().cloned()),
        mirrors: tip.as_ref().map(|t| t.mirrors.clone()).unwrap_or_default(),
        tip,
        legacy: false,
    })
}

/// Resolve a document's `parent` (SPEC 3, 3.1): an alias or long id
/// through the SPEC 3.2 table, exactly as
/// [`sidestr_core::parents::resolve_parent`] (and `parents.mjs`) resolve it
/// and without asking for any event; a sidestr chain's hash through that
/// chain's kind-3500 event.
///
/// `get_event(id)` answers the event with this id, unverified, from a relay
/// ([`crate::relay::fetch_event`]) or a mirror's `chain-event.json`. Each
/// one is held to [`parse_chain_event`] (its id is the hash of its content
/// and its signature the author's) and must be the event asked for; its
/// document's `parent` is then followed the same way, so a chain nested
/// under a nested chain resolves too, down to the table row whose header
/// family, proof of work and key encodings every level inherits.
///
/// A departure from `siding/lib/parents.mjs` at `e8deb63`, which refuses a
/// hash as an unknown parent (ADR-0001 D4; `sidestr-core`'s
/// `tests/nested_parent.rs` holds the reference to that refusal).
///
/// ```
/// use sidestr_core::parents::Family;
/// use sidestr_nostr::chain::{resolve_nested_parent, sign_chain_event};
/// use sidestr_nostr::event::{SecretKeySigner, Signer};
///
/// let key = SecretKeySigner::from_hex(&"07".repeat(32)).unwrap();
/// let me = key.pubkey_hex().unwrap();
/// let siding = format!(r#"{{"id":"sidestr:siding","name":"siding","parent":"txbt4",
///   "challenge":"5120{me}","powLimit":"7f{}","addressPrefix":"sdg",
///   "signer":"{me}","genesisTime":1790000000}}"#, "ff".repeat(31));
/// let ev = sign_chain_event(&key, &siding, 1_790_100_000).unwrap();
///
/// // a child whose document says "parent": <the siding's hash>
/// let p = resolve_nested_parent(&ev.id, |id| (id == ev.id).then(|| ev.clone())).unwrap();
/// assert_eq!(p.family(), Family::Blake2b);
/// assert_eq!(p.chain_hash(), Some(ev.id.as_str()));
/// assert!(resolve_nested_parent(&"00".repeat(32), |_| None).is_err());
/// ```
pub fn resolve_nested_parent(
    parent: &str,
    mut get_event: impl FnMut(&str) -> Option<Event>,
) -> Result<ParentRef> {
    let mut failure: Option<Error> = None;
    let resolved = resolve_parent_with(parent, |hash| {
        let found = get_event(hash)
            .ok_or_else(|| {
                Error::Chain(format!(
                    "the parent chain's event {}… was not found",
                    short(hash, 16)
                ))
            })
            .and_then(|ev| parse_chain_event(&ev))
            .and_then(|parsed| {
                if parsed.hash != hash {
                    return Err(Error::Chain(
                        "the event found is not the one asked for".into(),
                    ));
                }
                parsed.document()
            });
        found.map_err(|e| {
            let message = e.to_string();
            failure = Some(e);
            sidestr_core::error::Error::Document(message)
        })
    });
    resolved.map_err(|e| {
        failure
            .take()
            .unwrap_or_else(|| Error::Chain(e.to_string()))
    })
}

// ---- JSON as JavaScript writes it --------------------------------------------------

/// `JSON.stringify(value)` for a value `JSON.parse` produced, which is how
/// a chain event's content is written: integer-like keys first in ascending
/// order, then the rest in insertion order; numbers as JavaScript prints
/// them; strings escaped as `serde_json` and `JSON.stringify` both escape
/// them (`\"`, `\\`, `\b \f \n \r \t`, other controls as `\u00XX`, nothing
/// else); no whitespace.
///
/// ```
/// use sidestr_nostr::chain::js_stringify;
/// let v: serde_json::Value = serde_json::from_str(r#"{ "b": 1.0, "10": 2e21, "a": [0.5] }"#).unwrap();
/// assert_eq!(js_stringify(&v), r#"{"10":2e+21,"b":1,"a":[0.5]}"#);
/// ```
pub fn js_stringify(v: &Value) -> String {
    let mut out = String::new();
    write_js(v, &mut out);
    out
}

fn write_js(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&js_number(n)),
        Value::String(s) => out.push_str(&serde_json::to_string(s).expect("a string serialises")),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_js(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, x)) in js_key_order(m).into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("a string serialises"));
                out.push(':');
                write_js(x, out);
            }
            out.push('}');
        }
    }
}

/// An array index as ECMAScript defines one: the canonical decimal string
/// of an integer below 2^32 - 1.
fn array_index(k: &str) -> Option<u32> {
    if k.is_empty() || k.len() > 10 || !k.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if k.len() > 1 && k.starts_with('0') {
        return None;
    }
    k.parse::<u64>()
        .ok()
        .filter(|n| *n < u64::from(u32::MAX))
        .map(|n| n as u32)
}

/// OrdinaryOwnPropertyKeys: array indices ascending, then strings in
/// creation order.
fn js_key_order(m: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut indices: Vec<(u32, &String, &Value)> = m
        .iter()
        .filter_map(|(k, v)| array_index(k).map(|i| (i, k, v)))
        .collect();
    indices.sort_by_key(|(i, _, _)| *i);
    indices
        .into_iter()
        .map(|(_, k, v)| (k, v))
        .chain(m.iter().filter(|(k, _)| array_index(k).is_none()))
        .collect()
}

/// A number as JavaScript prints it. `JSON.parse` reads every number as a
/// double, so an integer past 2^53 is the nearest double, printed as one.
/// The double is the correctly rounded one because this crate turns on
/// `serde_json`'s `float_roundtrip`.
fn js_number(n: &Number) -> String {
    const EXACT: u64 = 1 << 53;
    if let Some(u) = n.as_u64() {
        return if u <= EXACT {
            u.to_string()
        } else {
            js_double(u as f64)
        };
    }
    if let Some(i) = n.as_i64() {
        return if i.unsigned_abs() <= EXACT {
            i.to_string()
        } else {
            js_double(i as f64)
        };
    }
    js_double(n.as_f64().unwrap_or(0.0))
}

/// `Number.prototype.toString()` (ECMA-262 Number::toString, radix 10) for a
/// finite double: the shortest digits that round-trip, then decimal
/// notation between 1e-7 and 1e21 and exponent notation (`1e+21`,
/// `1.5e-7`) outside it. Rust's `{:e}` gives the same shortest digits.
fn js_double(x: f64) -> String {
    if x == 0.0 {
        return "0".into(); // -0 prints as 0
    }
    if !x.is_finite() {
        return "null".into(); // JSON.stringify's answer; JSON.parse never makes one
    }
    let sci = format!("{:e}", x.abs());
    let (mantissa, exp) = sci.split_once('e').expect("{:e} has an exponent");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i64;
    let n = exp.parse::<i64>().expect("{:e} exponent is an integer") + 1;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let sign = if e < 0 { '-' } else { '+' };
        if k == 1 {
            format!("{digits}e{sign}{}", e.abs())
        } else {
            format!("{}.{}e{sign}{}", &digits[..1], &digits[1..], e.abs())
        }
    };
    if x < 0.0 {
        format!("-{body}")
    } else {
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::SecretKeySigner;
    use crate::tip::{parse_tip, sign_tip, sign_tip_with_peg, TipTemplate};

    // siding/test/announce-test.mjs at e8deb63, the 0.0.5 block: the same
    // shapes, with fixed keys where the reference draws random ones

    fn key() -> SecretKeySigner {
        SecretKeySigner::from_bytes(&[0x21; 32]).unwrap()
    }
    fn other_key() -> SecretKeySigner {
        SecretKeySigner::from_bytes(&[0x22; 32]).unwrap()
    }
    fn pub_() -> String {
        key().pubkey_hex().unwrap()
    }
    /// `sidestr-core/fixtures/trial/chain.json`, inline so the packaged
    /// crate's tests stand alone.
    const TRIAL: &str = r#"{
 "id": "sidestr:trial",
 "name": "trial",
 "parent": "tbtc4",
 "comment": "A sidestr chain beside Bitcoin testnet4, made 2026-09-22. Level 1: one signer. Coins with no value.",
 "challenge": "512098b4e74305dac5ce76d5bee8e57a71549a27618a0e51b3bada3074fcba02325b",
 "powLimit": "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
 "addressPrefix": "trl",
 "magic": "a8f6706f",
 "pegConfirmations": 6,
 "refundBlocks": 10000,
 "pegoutBlocks": 144,
 "pegoutMin": 10000,
 "minFeeRate": 1,
 "genesisTime": 1790076612,
 "pegs": [],
 "signer": "98b4e74305dac5ce76d5bee8e57a71549a27618a0e51b3bada3074fcba02325b",
 "genesisHash": "0bdfdb3194f067d15b7a1cfa865de391b7ac00e1970863946d143e7329784402"
}"#;
    const AT: u64 = 1_759_300_000;

    /// `const doc = { ...chain, signer: pub, challenge: '5120' + pub }; delete doc.genesisHash;`
    fn doc() -> String {
        let mut v: Value = serde_json::from_str(TRIAL).unwrap();
        let m = v.as_object_mut().unwrap();
        m.insert("signer".into(), pub_().into());
        m.insert("challenge".into(), format!("5120{}", pub_()).into());
        m.shift_remove("genesisHash");
        v.to_string()
    }
    fn cev() -> Event {
        sign_chain_event(&key(), &doc(), AT).unwrap()
    }
    fn h(i: u8) -> String {
        format!("{i:02x}").repeat(164)
    }
    fn tip_with(signer: &SecretKeySigner, hash: Option<&str>, tip: u32, mirror: &str) -> Tip {
        let mut t =
            TipTemplate::new("sidestr:trial", tip, vec![h(7)], vec![mirror.into()]).unwrap();
        if let Some(hash) = hash {
            t = t.with_chain_hash(hash).unwrap();
        }
        parse_tip(&sign_tip(signer, &t, AT).unwrap()).unwrap()
    }
    /// `pe`: the tip naming the chain event, by the chain's signer.
    fn pe() -> Tip {
        tip_with(&key(), Some(&cev().id), 7, "https://a.example/siding")
    }
    fn no_json(_: &str) -> core::result::Result<Value, String> {
        Err("404".into())
    }

    #[test]
    fn the_chain_event_is_kind_3500_tagged_without_a_signer_field_and_verifies() {
        let ev = cev();
        assert_eq!(ev.kind, KIND_CHAIN_DOCUMENT);
        assert!(ev
            .tags
            .iter()
            .any(|x| x[0] == "n" && x[1] == "sidestr:trial"));
        assert!(ev.tags.iter().any(|x| x[0] == "t" && x[1] == "sidestr"));
        assert!(ev
            .tags
            .iter()
            .any(|x| x[0] == "alt" && x[1] == "sidestr chain document sidestr:trial"));
        let content: Value = serde_json::from_str(&ev.content).unwrap();
        assert!(content.get("signer").is_none());
        assert_eq!(content["challenge"], format!("5120{}", pub_()));
        ev.verify().unwrap();
    }

    #[test]
    fn the_same_document_signed_again_at_another_time_is_another_hash() {
        let again = sign_chain_event(&key(), &doc(), AT + 1).unwrap();
        assert_ne!(again.id, cev().id);
    }

    #[test]
    fn it_parses_back_with_the_author_as_its_signer() {
        let ev = cev();
        let d = parse_chain_event(&ev).unwrap();
        assert_eq!(
            (d.hash.as_str(), d.alias.as_str(), d.pubkey.as_str()),
            (ev.id.as_str(), "sidestr:trial", pub_().as_str())
        );
        assert_eq!(d.chain["signer"], pub_());
        assert_eq!(d.chain["challenge"], format!("5120{}", pub_()));
        // the signer lands last, where `{ ...chain, signer }` puts it
        assert_eq!(
            d.chain.as_object().unwrap().keys().next_back().unwrap(),
            "signer"
        );
        // and the document's own check runs on it: the challenge is the author's key
        let doc = d.document().unwrap();
        assert_eq!(doc.signer.as_deref(), Some(pub_().as_str()));
        doc.validate().unwrap();
    }

    #[test]
    fn a_changed_content_is_refused() {
        let mut ev = cev();
        ev.content = ev.content.replacen("5120", "5121", 1);
        let e = parse_chain_event(&ev).unwrap_err();
        assert!(e.to_string().contains("does not verify"), "{e}");
        // so is a forged id over the changed content (the signature is over the old one)
        ev.id = ev.to_unsigned().id();
        assert!(parse_chain_event(&ev)
            .unwrap_err()
            .to_string()
            .contains("does not verify"));
        let mut kind = cev();
        kind.kind = 33501;
        assert!(matches!(parse_chain_event(&kind), Err(Error::Kind { .. })));
    }

    #[test]
    fn a_foreign_signer_or_signers_without_the_author_are_refused() {
        // the reference signs these with events.signEvent directly, so the
        // content keeps the field chainEvent would delete
        let raw = |content: String| {
            sign(
                &key(),
                UnsignedEvent {
                    pubkey: String::new(),
                    created_at: AT,
                    kind: KIND_CHAIN_DOCUMENT,
                    tags: vec![],
                    content,
                },
            )
            .unwrap()
        };
        let mut v: Value = serde_json::from_str(&doc()).unwrap();
        v["signer"] = "ee".repeat(32).into();
        let e = parse_chain_event(&raw(v.to_string())).unwrap_err();
        assert!(e.to_string().contains("other than the event"), "{e}");
        let fed = format!(
            r#"{{"id":"sidestr:fed","signers":["{}"]}}"#,
            "aa".repeat(32)
        );
        let e = parse_chain_event(&raw(fed)).unwrap_err();
        assert!(e.to_string().contains("not one of the document"), "{e}");
        // a level-2 document that names the author: accepted, and no signer is invented
        let fed = format!(
            r#"{{"id":"sidestr:fed","signers":["{}","{}"]}}"#,
            "aa".repeat(32),
            pub_()
        );
        let d = parse_chain_event(&raw(fed)).unwrap();
        assert!(d.chain.get("signer").is_none());
        // the same signer, named explicitly: kept where it stands
        let mut v: Value = serde_json::from_str(&doc()).unwrap();
        v["signer"] = pub_().into();
        v["zz"] = 1.into();
        let d = parse_chain_event(&raw(v.to_string())).unwrap();
        assert_ne!(
            d.chain.as_object().unwrap().keys().next_back().unwrap(),
            "signer"
        );
        // content that is not a document with an alias
        for (content, want) in [
            ("nope".to_string(), "not JSON"),
            ("[1]".to_string(), "no document with an alias"),
            (r#"{"id":5}"#.to_string(), "no document with an alias"),
        ] {
            let e = parse_chain_event(&raw(content)).unwrap_err();
            assert!(e.to_string().contains(want), "{e}");
        }
    }

    #[test]
    fn an_alias_that_is_not_sidestr_name_is_refused_when_building() {
        let mut v: Value = serde_json::from_str(&doc()).unwrap();
        v["id"] = "poker".into();
        assert!(sign_chain_event(&key(), &v.to_string(), AT).is_err());
        for bad in [
            "sidestr:",
            "sidestr:-a",
            "sidestr:A",
            "sidestr:a_b",
            "Sidestr:a",
        ] {
            assert!(!is_alias(bad), "{bad}");
        }
        assert!(chain_event("[]", 1).is_err());
        assert!(chain_event("{", 1).is_err());
    }

    #[test]
    fn the_tip_carries_the_chain_hash_as_an_e_tag_and_parses_it_back() {
        let ev = cev();
        let t = TipTemplate::new(
            "sidestr:trial",
            7,
            vec![h(7)],
            vec!["https://a.example/siding".into()],
        )
        .unwrap()
        .with_chain_hash(&ev.id.to_uppercase())
        .unwrap();
        let tip_ev = sign_tip(&key(), &t, AT).unwrap();
        assert!(tip_ev
            .tags
            .iter()
            .any(|x| *x == ["e", ev.id.as_str(), "", "chain"]));
        assert_eq!(
            parse_tip(&tip_ev).unwrap().chain_hash.as_deref(),
            Some(ev.id.as_str())
        );
        let without = tip_with(&key(), None, 7, "https://a.example/siding");
        assert_eq!(without.chain_hash, None);
        // the e tag follows the peg tag
        let with_peg =
            sign_tip_with_peg(&key(), &t, Some(&format!("5120{}", "ab".repeat(32))), AT).unwrap();
        let names: Vec<&str> = with_peg.tags.iter().map(|x| x[0].as_str()).collect();
        assert_eq!(names, ["d", "n", "t", "tip", "alt", "u", "peg", "e"]);
    }

    #[test]
    fn by_alias_the_newest_tip_names_the_event() {
        let ev = cev();
        let pe = pe();
        let r = resolve_chain(
            Some("sidestr:trial"),
            None,
            0,
            |_| Some(pe.clone()),
            |id| (id == ev.id).then(|| ev.clone()),
            no_json,
        )
        .unwrap();
        assert_eq!(r.hash.as_deref(), Some(ev.id.as_str()));
        assert_eq!(r.chain["challenge"], format!("5120{}", pub_()));
        assert_eq!(r.tip.as_ref(), Some(&pe));
        assert_eq!(r.mirror.as_deref(), Some("https://a.example/siding"));
        assert!(!r.legacy);
        assert_eq!(r.document().unwrap().id, "sidestr:trial");
    }

    #[test]
    fn by_hash_the_event_then_the_tip_by_the_document_s_alias() {
        let ev = cev();
        let pe = pe();
        let mut asked = vec![];
        let r = resolve_chain(
            None,
            Some(&ev.id.to_uppercase()),
            0,
            |a| {
                asked.push(a.to_string());
                Some(pe.clone())
            },
            |_| Some(ev.clone()),
            no_json,
        )
        .unwrap();
        assert_eq!(asked, ["sidestr:trial"]);
        assert_eq!(
            (r.hash.as_deref(), r.alias.as_str(), r.tip.as_ref()),
            (Some(ev.id.as_str()), "sidestr:trial", Some(&pe))
        );
        // with no tip anywhere: resolved, no mirror
        let r = resolve_chain(
            None,
            Some(&ev.id),
            0,
            |_| None,
            |_| Some(ev.clone()),
            no_json,
        )
        .unwrap();
        assert_eq!((r.mirror, r.mirrors.len()), (None, 0));
    }

    #[test]
    fn no_relay_has_the_event_a_mirror_serves_chain_event_json() {
        let ev = cev();
        let pe = pe();
        let served = serde_json::to_value(&ev).unwrap();
        let r = resolve_chain(
            Some("sidestr:trial"),
            None,
            2,
            |_| Some(pe.clone()),
            |_| None,
            |u| {
                if u == "https://a.example/siding/chain-event.json" {
                    Ok(served.clone())
                } else {
                    Err("404".into())
                }
            },
        )
        .unwrap();
        assert_eq!(r.hash.as_deref(), Some(ev.id.as_str()));
        assert!(!r.legacy);
        // a mirror's chain-event.json verified the same way: a changed content is refused
        let mut forged = served.clone();
        forged["content"] = ev.content.replacen("5120", "5121", 1).into();
        let e = resolve_chain(
            Some("sidestr:trial"),
            None,
            2,
            |_| Some(pe.clone()),
            |_| None,
            |_| Ok(forged.clone()),
        )
        .unwrap_err();
        assert!(e.to_string().contains("does not verify"), "{e}");
    }

    #[test]
    fn a_tip_by_someone_else_naming_this_chain_event_is_refused() {
        let ev = cev();
        let other = tip_with(&other_key(), Some(&ev.id), 8, "https://x.example");
        let e = resolve_chain(
            Some("sidestr:trial"),
            None,
            0,
            |_| Some(other.clone()),
            |_| Some(ev.clone()),
            no_json,
        )
        .unwrap_err();
        assert!(e.to_string().contains("not the chain's signer"), "{e}");
        // the same tip is fine when the document names its author among the signers
        // (a level-2 chain announced by another member)
        let fed = format!(
            r#"{{"id":"sidestr:trial","signers":["{}","{}"]}}"#,
            pub_(),
            other_key().pubkey_hex().unwrap()
        );
        let fev = sign_chain_event(&key(), &fed, AT).unwrap();
        let other = tip_with(&other_key(), Some(&fev.id), 8, "https://x.example");
        let r = resolve_chain(
            Some("sidestr:trial"),
            None,
            0,
            |_| Some(other.clone()),
            |_| Some(fev.clone()),
            no_json,
        )
        .unwrap();
        assert_eq!(r.mirror.as_deref(), Some("https://x.example"));
    }

    #[test]
    fn an_event_that_is_not_the_one_asked_for_is_refused() {
        let ev = cev();
        let pe = pe();
        let mut wrong = ev.clone();
        wrong.id = "ab".repeat(32);
        assert!(resolve_chain(
            None,
            Some(&ev.id),
            0,
            |_| Some(pe.clone()),
            |_| Some(wrong.clone()),
            no_json
        )
        .is_err());
        // a valid event, but another chain's
        let another = sign_chain_event(&key(), &doc(), AT + 9).unwrap();
        let e = resolve_chain(
            None,
            Some(&ev.id),
            0,
            |_| Some(pe.clone()),
            |_| Some(another.clone()),
            no_json,
        )
        .unwrap_err();
        assert!(e.to_string().contains("not the one asked for"), "{e}");
        // and a newest tip naming another chain is refused when the hash is given
        let e = resolve_chain(
            None,
            Some(&another.id),
            0,
            |_| Some(pe.clone()),
            |_| Some(another.clone()),
            no_json,
        )
        .unwrap_err();
        assert!(e.to_string().contains("names another chain"), "{e}");
    }

    #[test]
    fn the_event_on_no_relay_and_no_mirror_is_a_clear_error() {
        let pe = pe();
        let e = resolve_chain(
            Some("sidestr:trial"),
            None,
            3,
            |_| Some(pe.clone()),
            |_| None,
            no_json,
        )
        .unwrap_err();
        let m = e.to_string();
        assert!(
            m.contains("on none of 3 relay(s) or the mirrors the tip names"),
            "{m}"
        );
        assert!(m.contains(&format!("{}…", &cev().id[..16])), "{m}");
        let e = resolve_chain(None, Some(&cev().id), 3, |_| None, |_| None, no_json).unwrap_err();
        assert!(e.to_string().ends_with("on none of 3 relay(s)"), "{e}");
        // the hash must be a hash; something must be asked for; an alias nobody announced
        assert!(
            resolve_chain(None, Some("ab"), 0, |_| None, |_| None, no_json)
                .unwrap_err()
                .to_string()
                .contains("a chain hash is 64 hex")
        );
        assert!(resolve_chain(None, None, 0, |_| None, |_| None, no_json).is_err());
        assert!(
            resolve_chain(Some("sidestr:nobody"), None, 5, |_| None, |_| None, no_json)
                .unwrap_err()
                .to_string()
                .contains("no announcement for sidestr:nobody on 5 relay(s)")
        );
    }

    #[test]
    fn a_tip_with_no_e_tag_resolves_the_old_way() {
        // announce-test's `p` and `docs`: two mirrors, the second vouching for the announcer
        let t = TipTemplate::new(
            "sidestr:trial",
            12,
            vec![h(1), h(2), h(3)],
            vec![
                "https://a.example/siding/".into(),
                "https://b.example/siding".into(),
            ],
        )
        .unwrap();
        let p = parse_tip(&sign_tip(&key(), &t, AT).unwrap()).unwrap();
        let docs = |u: &str| -> core::result::Result<Value, String> {
            match u {
                "https://a.example/siding/chain.json" => {
                    Ok(serde_json::json!({ "id": "sidestr:trial", "signer": "ff".repeat(32) }))
                }
                "https://b.example/siding/chain.json" => {
                    Ok(serde_json::json!({ "id": "sidestr:trial", "signer": pub_(), "extra": 1 }))
                }
                _ => Err("404".into()),
            }
        };
        let r = resolve_chain(
            Some("sidestr:trial"),
            None,
            0,
            |_| Some(p.clone()),
            |_| None,
            docs,
        )
        .unwrap();
        assert!(r.legacy);
        assert_eq!(r.hash, None);
        assert_eq!(r.mirror.as_deref(), Some("https://b.example/siding"));
        assert_eq!(r.chain["extra"], 1); // the mirror's document as served
        assert_eq!(r.pubkey, pub_());
        // another key's tip: no mirror vouches for it
        let q = parse_tip(&sign_tip(&other_key(), &t, AT).unwrap()).unwrap();
        let e = resolve_chain(
            Some("sidestr:trial"),
            None,
            0,
            |_| Some(q.clone()),
            |_| None,
            docs,
        )
        .unwrap_err();
        assert!(matches!(e, Error::NoMirror { .. }), "{e}");
        // a mirror whose chain.json is not a document is a mirror that does not check out
        let e = resolve_chain(
            Some("sidestr:trial"),
            None,
            0,
            |_| Some(p.clone()),
            |_| None,
            |_| Ok(serde_json::json!([1, 2])),
        )
        .unwrap_err();
        assert!(matches!(e, Error::NoMirror { .. }), "{e}");
    }

    /// A chain event for `doc()` with `parent` and `id` replaced.
    fn chain_beside(parent: &str, name: &str) -> Event {
        let mut v: Value = serde_json::from_str(&doc()).unwrap();
        v["parent"] = parent.into();
        v["id"] = format!("sidestr:{name}").into();
        v["name"] = name.into();
        sign_chain_event(&key(), &v.to_string(), AT).unwrap()
    }

    // SPEC 3.1 prose; parents.mjs at e8deb63 refuses the hash (sidestr-core tests/nested_parent.rs)
    #[test]
    fn a_nested_parent_resolves_its_family_through_the_parent_s_chain_event() {
        use sidestr_core::parents::{resolve_parent, Family};
        let siding = chain_beside("txbt4", "siding");
        let middle = chain_beside(&siding.id, "middle");
        let events = [siding.clone(), middle.clone()];
        let by_id = |id: &str| events.iter().find(|e| e.id == id).cloned();

        // one level: the siding's family is txbt4's
        let p = resolve_nested_parent(&siding.id, by_id).unwrap();
        assert_eq!(p.family(), Family::Blake2b);
        assert_eq!(p.depth(), 1);
        let ParentRef::Chain(n) = &p else { panic!() };
        assert_eq!(n.alias, "sidestr:siding");
        // two levels: through the middle chain's event to the siding's
        let q = resolve_nested_parent(&middle.id, by_id).unwrap();
        assert_eq!(q.family(), Family::Blake2b);
        assert_eq!(q.depth(), 2);
        let ParentRef::Chain(n) = &q else { panic!() };
        assert_eq!(n.path, vec![middle.id.clone(), siding.id.clone()]);
        // a stock root
        let stock = cev();
        let r = resolve_nested_parent(&stock.id, |_| Some(stock.clone())).unwrap();
        assert_eq!(r.family(), Family::Stock);
        // an alias answers as the table, asking for nothing
        assert_eq!(
            resolve_nested_parent("txbt4", |_| panic!("no event for an alias")).unwrap(),
            ParentRef::Table(resolve_parent("txbt4").unwrap())
        );
        // the child document validates only through the events
        let child = ChainDocument {
            parent: middle.id.clone(),
            ..parse_chain_event(&siding).unwrap().document().unwrap()
        };
        assert!(child.validate().is_err());
        child
            .validate_nested(&[], |h| {
                parse_chain_event(&by_id(h).unwrap())
                    .unwrap()
                    .document()
                    .map_err(|e| sidestr_core::error::Error::Document(e.to_string()))
            })
            .unwrap();
    }

    #[test]
    fn a_nested_parent_s_event_must_verify_and_be_the_one_asked_for() {
        let siding = chain_beside("txbt4", "siding");
        let e = resolve_nested_parent(&siding.id, |_| None).unwrap_err();
        assert!(e.to_string().contains("was not found"), "{e}");
        let mut forged = siding.clone();
        forged.content = forged.content.replace("txbt4", "tbtc4");
        let e = resolve_nested_parent(&siding.id, |_| Some(forged.clone())).unwrap_err();
        assert!(matches!(e, Error::Signature(_)), "{e}");
        let other = chain_beside("tbtc4", "other");
        let e = resolve_nested_parent(&siding.id, |_| Some(other.clone())).unwrap_err();
        assert!(e.to_string().contains("not the one asked for"), "{e}");
        // a root the table reserves
        let ltc = chain_beside("ltc", "lite");
        let e = resolve_nested_parent(&ltc.id, |_| Some(ltc.clone())).unwrap_err();
        assert!(e.to_string().contains("reserved"), "{e}");
    }

    #[test]
    fn javascript_numbers_and_key_order() {
        for (text, js) in [
            ("1.0", "1"),
            ("-0.0", "0"),
            ("-0", "0"),
            ("1e21", "1e+21"),
            ("1e20", "100000000000000000000"),
            ("123456789012345678901234", "1.2345678901234569e+23"),
            ("2.2250738585072011e-308", "2.225073858507201e-308"),
            ("0.30000000000000004", "0.30000000000000004"),
            ("8.98846567431158e307", "8.98846567431158e+307"),
            ("0.000001", "0.000001"),
            ("1e-7", "1e-7"),
            ("1.5e-7", "1.5e-7"),
            ("123.456", "123.456"),
            ("1.5e300", "1.5e+300"),
            ("-2.5e-9", "-2.5e-9"),
            ("9007199254740993", "9007199254740992"),
            ("-9007199254740993", "-9007199254740992"),
            ("18446744073709551615", "18446744073709552000"),
            ("0.1", "0.1"),
            ("5e-324", "5e-324"),
            ("1.7976931348623157e308", "1.7976931348623157e+308"),
            ("4294967295", "4294967295"),
        ] {
            let v: Value = serde_json::from_str(text).unwrap();
            assert_eq!(js_stringify(&v), js, "{text}");
        }
        let v: Value = serde_json::from_str(
            r#"{"b":1,"4294967294":0,"4294967295":0,"01":0,"1":0,"0":0,"a":{"9":0,"z":0,"2":0},"b":2}"#,
        )
        .unwrap();
        assert_eq!(
            js_stringify(&v),
            r#"{"0":0,"1":0,"4294967294":0,"b":2,"4294967295":0,"01":0,"a":{"2":0,"9":0,"z":0}}"#
        );
    }
}
