//! The chain document as a kind-3500 event, and finding a chain by its
//! alias or its hash (SPEC 3 and 11, 0.0.5): `siding chain-event` and
//! `announce.mjs resolveChain`, for an agent.
//!
//! A chain's **hash** is the id of its document published as a kind-3500
//! event; its **alias** (`sidestr:<name>`) is the name people, tags and
//! `OP_RETURN`s use. [`sign_chain_document`] is `siding chain-event`'s
//! check and build: the key must be the chain's signer (level 1: the
//! challenge is `5120‖key`; level 2: the key is one of the document's
//! `signers`), the event is built from the document's JSON text so its id is
//! the one siding gives for the same file, and it is read back before it is
//! written. [`event_file_json`] is the file siding writes. Resolution is
//! [`sidestr_nostr::chain::resolve_chain`]; with feature `cli`,
//! `resolve_chain_on` asks relays for what it needs.
//!
//! ```
//! use sidestr_agent::chain::{event_file_json, sign_chain_document};
//! use sidestr_agent::AgentKey;
//!
//! let me = AgentKey::parse(&"07".repeat(32)).unwrap();
//! let doc = format!(r#"{{"id":"sidestr:example","name":"example","parent":"tbtc4",
//!   "challenge":"5120{0}","signer":"{0}",
//!   "powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
//!   "addressPrefix":"ex","genesisTime":1790000000,"pegs":[]}}"#, me.pubkey());
//!
//! let made = sign_chain_document(&me, &doc, 1_790_100_000).unwrap();
//! assert_eq!(made.parsed.hash, made.event.id);            // the chain's hash
//! assert_eq!(made.parsed.alias, "sidestr:example");
//! assert!(event_file_json(&made.event).starts_with("{\n  \"pubkey\""));
//!
//! let stranger = AgentKey::parse(&"08".repeat(32)).unwrap();
//! assert!(sign_chain_document(&stranger, &doc, 1_790_100_000).is_err());
//! ```

use serde_json::{json, Value};
use sidestr_core::document::ChainDocument;
use sidestr_core::federation::Federation;
use sidestr_nostr::chain::{parse_chain_event, sign_chain_event, ParsedChain};
use sidestr_nostr::event::Event;

use crate::{AgentKey, Error, Result};

/// The rules a validator of the reference carries (`siding/lib/overlays/
/// index.mjs KNOWN`): a document naming them can be published as an event
/// here, though this crate replays none of them.
pub const KNOWN_RULES: [&str; 4] = ["assets", "pool", "evm", "markets"];

/// A chain event made and read back.
#[derive(Debug, Clone)]
pub struct ChainEvent {
    /// The signed kind-3500 event.
    pub event: Event,
    /// It, read back: the chain's hash and alias, and the document.
    pub parsed: ParsedChain,
}

/// Whether `key` may sign the chain's document (`siding chain-event`): the
/// level-1 challenge is `5120‖key`, or the key is one of the level-2
/// document's `signers`. The `Err` carries siding's words, "not the chain's
/// signer" or "not one of the chain's signers".
pub fn check_signer(doc: &ChainDocument, key: &AgentKey) -> core::result::Result<(), String> {
    let pubkey = key.pubkey();
    match Federation::for_document(doc).map_err(|e| e.to_string())? {
        Some(fed) if fed.signers.contains(&pubkey) => Ok(()),
        Some(_) => Err("not one of the chain's signers".into()),
        None if doc.challenge == format!("5120{pubkey}") => Ok(()),
        None => Err("not the chain's signer".into()),
    }
}

/// `siding chain-event`'s build: the document's JSON text is read as a
/// [`ChainDocument`] (validated, naming only [`KNOWN_RULES`]), the key is
/// checked against it ([`check_signer`]: refused as "the key is not the
/// chain's signer"), and the event is built from the text itself
/// ([`sidestr_nostr::chain::chain_event`]: the document as `JSON.stringify`
/// writes it, `signer` deleted), signed, and read back
/// ([`parse_chain_event`]).
pub fn sign_chain_document(
    key: &AgentKey,
    document_json: &str,
    created_at: u64,
) -> Result<ChainEvent> {
    let doc = ChainDocument::from_json_with(document_json, &KNOWN_RULES)?;
    check_signer(&doc, key)
        .map_err(|why| Error::Nostr(sidestr_nostr::Error::Chain(format!("the key is {why}"))))?;
    let event = sign_chain_event(&key.event_signer(), document_json, created_at)?;
    let parsed = parse_chain_event(&event)?;
    Ok(ChainEvent { event, parsed })
}

/// The event as `siding chain-event` writes `chain-event.json`:
/// `JSON.stringify(ev, null, 2)` and a newline, the fields in the order
/// siding's `signEvent` makes them (`pubkey`, `created_at`, `kind`, `tags`,
/// `content`, `id`, `sig`). A mirror serves this file beside `chain.json`.
pub fn event_file_json(ev: &Event) -> String {
    let v = json!({
        "pubkey": ev.pubkey,
        "created_at": ev.created_at,
        "kind": ev.kind,
        "tags": ev.tags,
        "content": ev.content,
        "id": ev.id,
        "sig": ev.sig,
    });
    let mut s = serde_json::to_string_pretty(&v).expect("plain fields");
    s.push('\n');
    s
}

/// What `resolve_chain_on` (feature `cli`) settled on, as the `resolve` command prints
/// it: the hash (`null` for a chain made before 0.0.5), the alias, the
/// signer, the mirror and the mirrors, the tip height, whether it resolved
/// the legacy way, and the document.
pub fn resolved_json(r: &sidestr_nostr::chain::Resolved) -> Value {
    json!({
        "hash": r.hash,
        "alias": r.alias,
        "signer": r.pubkey,
        "legacy": r.legacy,
        "mirror": r.mirror,
        "mirrors": r.mirrors,
        "tip": r.tip.as_ref().map(|t| t.tip),
        "chain": r.chain,
        "note": if r.legacy {
            "a chain made before SPEC 0.0.5: its mirror's chain.json was accepted because its signer is the announcement's author; it has no hash until its signer publishes the document as a kind-3500 event"
        } else {
            "the hash is the chain's identity: the event's id is the hash of the document, signed by the key the tip's author must be; the alias is only a name"
        },
    })
}

/// Resolve a chain by its alias or its hash over relays (`announce.mjs
/// resolveChain` with its default lookups; feature `cli`): the newest tip
/// for the alias and the chain event by id are fetched once each with
/// `sidestr_round::relay::fetch` (every relay asked at once, each answering
/// until `EOSE` or `timeout`), then [`sidestr_nostr::chain::resolve_chain`]
/// decides over them, `fetch_json` answering for mirrors. With only a hash,
/// the tips are fetched for the alias the event names, once it has been
/// read and verified.
#[cfg(feature = "cli")]
pub async fn resolve_chain_on(
    relays: &[String],
    alias: Option<&str>,
    hash: Option<&str>,
    timeout: std::time::Duration,
    fetch_json: impl FnMut(&str) -> core::result::Result<Value, String>,
) -> Result<sidestr_nostr::chain::Resolved> {
    use sidestr_nostr::chain::is_chain_hash;
    use sidestr_nostr::relay::{event_filter, tip_filter};
    use sidestr_nostr::tip::newest;
    use sidestr_round::relay::fetch;
    use std::collections::HashMap;

    let mut tips: HashMap<String, Vec<Event>> = HashMap::new();
    if let Some(a) = alias {
        tips.insert(a.to_string(), fetch(relays, tip_filter(a), timeout).await);
    }
    let id = hash.map(str::to_ascii_lowercase).or_else(|| {
        alias
            .and_then(|a| newest(&tips[a], a, None))
            .and_then(|t| t.chain_hash)
    });
    let mut event = None;
    if let Some(id) = id.as_deref().filter(|i| is_chain_hash(i)) {
        event = fetch(relays, event_filter(id), timeout)
            .await
            .into_iter()
            .find(|e| e.id == id);
        if alias.is_none() {
            if let Some(d) = event.as_ref().and_then(|e| parse_chain_event(e).ok()) {
                let found = fetch(relays, tip_filter(&d.alias), timeout).await;
                tips.insert(d.alias, found);
            }
        }
    }
    Ok(sidestr_nostr::chain::resolve_chain(
        alias,
        hash,
        relays.len(),
        |a| tips.get(a).and_then(|evs| newest(evs, a, None)),
        |i| event.clone().filter(|e| e.id == i),
        fetch_json,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DREAMLAB: &str = include_str!("../tests/fixtures/dreamlab-chain.json");

    fn rewritten(key: &AgentKey) -> String {
        let mut v: Value = serde_json::from_str(DREAMLAB).unwrap();
        v["challenge"] = format!("5120{}", key.pubkey()).into();
        v["signer"] = key.pubkey().to_string().into();
        serde_json::to_string_pretty(&v).unwrap()
    }

    #[test]
    fn only_the_chain_s_signer_signs_its_document() {
        let throwaway = AgentKey::parse(&"5a".repeat(32)).unwrap();
        let e = sign_chain_document(&throwaway, DREAMLAB, 1).unwrap_err();
        assert!(e.to_string().contains("not the chain's signer"), "{e}");
        let made = sign_chain_document(&throwaway, &rewritten(&throwaway), 1).unwrap();
        assert_eq!(made.parsed.hash, made.event.id);
        assert_eq!(made.parsed.alias, "sidestr:dreamlab");
        // the estate's fields ride in the document, the signer does not
        let content: Value = serde_json::from_str(&made.event.content).unwrap();
        assert_eq!(content["containment"]["parent"], "tbtc4");
        assert!(content.get("signer").is_none());
        // the file reads back as the same event
        let back: Event = serde_json::from_str(&event_file_json(&made.event)).unwrap();
        assert_eq!(back, made.event);
    }

    #[test]
    fn a_level_2_document_is_signed_by_one_of_its_signers() {
        // the sibling crate's disposable federation, when the workspace is around us
        let at = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../sidestr-core/fixtures/fedtest"
        );
        let (Ok(fed), Ok(key)) = (
            std::fs::read_to_string(format!("{at}/chain.json")),
            std::fs::read_to_string(format!("{at}/signer3.key")),
        ) else {
            return;
        };
        let fed = fed.as_str();
        let signer = AgentKey::parse(&key).unwrap();
        let made = sign_chain_document(&signer, fed, 1).unwrap();
        assert_eq!(made.parsed.pubkey, signer.pubkey().to_string());
        assert!(made.parsed.chain.get("signer").is_none());
        made.parsed.document().unwrap().validate().unwrap();
        let e =
            sign_chain_document(&AgentKey::parse(&"5a".repeat(32)).unwrap(), fed, 1).unwrap_err();
        assert!(
            e.to_string().contains("not one of the chain's signers"),
            "{e}"
        );
    }

    #[test]
    fn the_file_is_written_as_siding_writes_it() {
        let k = AgentKey::parse(&"5a".repeat(32)).unwrap();
        let made = sign_chain_document(&k, &rewritten(&k), 1_790_100_000).unwrap();
        let text = event_file_json(&made.event);
        let keys: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("  \""))
            .map(|l| l.trim().split('"').nth(1).unwrap())
            .collect();
        assert_eq!(
            keys,
            [
                "pubkey",
                "created_at",
                "kind",
                "tags",
                "content",
                "id",
                "sig"
            ]
        );
        assert!(
            text.contains("  \"tags\": [\n    [\n      \"n\",\n      \"sidestr:dreamlab\"\n    ],")
        );
        assert!(text.ends_with("}\n"));
    }
}
