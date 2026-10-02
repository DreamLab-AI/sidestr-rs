//! The reference as oracle for the chain event (SPEC 3, 0.0.5):
//! `fixtures/chain-event-vectors.json` was written by siding's own
//! `chainEvent`, `parseChainEvent`, `tipEvent` and `parseTip`
//! (`siding/lib/announce.mjs` at sidestr/spec
//! `e8deb63161c7459ed39c01d2ca9fda3d860b65b6`) over the schema kernel's hash
//! and secp256k1, by `tests/oracle/chain-event-oracle.mjs`, for the
//! disposable keys `sidestr-core` carries (`fixtures/trial/trial.key`,
//! `fixtures/fedtest/signer2.key`), with zero BIP-340 auxiliary randomness.
//!
//! Three levels of proof:
//! - **verify-only**, always: every event verifies here, and reads back as
//!   upstream read it (hash, alias, author, and the document byte for byte
//!   as `JSON.stringify` wrote it).
//! - **byte-identical**, when the sibling crate's keys are on disk: the same
//!   documents' texts, built and signed here, are the same events (id,
//!   content, tags and signature), so the chain's hash is the same.
//! - **live**, when `SIDESTR_SIDING`, `SCHEMA` and `BLAKETESTNODE` name the
//!   reference checkouts: the generator runs again and must print exactly
//!   the committed fixture.

use serde_json::Value;
use sidestr_nostr::chain::{
    chain_event, js_stringify, parse_chain_event, sign_chain_event, KIND_CHAIN_DOCUMENT,
};
use sidestr_nostr::event::{Event, SecretKeySigner};
use sidestr_nostr::tip::{chain_hash_of, parse_tip, sign_tip, sign_tip_with_peg, TipTemplate};

fn vectors() -> Value {
    serde_json::from_str(include_str!("../fixtures/chain-event-vectors.json")).unwrap()
}

fn event(v: &Value, name: &str) -> Event {
    serde_json::from_value(v["events"][name].clone()).unwrap()
}

fn key(path: &str) -> Option<SecretKeySigner> {
    let path = format!(
        "{}/../sidestr-core/fixtures/{path}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(path).ok()?;
    Some(SecretKeySigner::from_hex(&text).unwrap())
}

const DOCUMENTS: [(&str, &str); 3] = [
    ("trial", "trial/trial.key"),
    ("fed", "fedtest/signer2.key"),
    ("awkward", "trial/trial.key"),
];

#[test]
fn every_chain_event_verifies_and_reads_back_as_upstream_read_it() {
    let v = vectors();
    for (name, _) in DOCUMENTS {
        let ev = event(&v, name);
        assert_eq!(ev.kind, KIND_CHAIN_DOCUMENT, "{name}");
        ev.verify().unwrap_or_else(|e| panic!("{name}: {e}"));
        let up = &v["upstream"][format!("parseChainEvent_{name}")];
        let d = parse_chain_event(&ev).unwrap();
        assert_eq!(d.hash, up["hash"].as_str().unwrap(), "{name}");
        assert_eq!(d.alias, up["alias"].as_str().unwrap(), "{name}");
        assert_eq!(d.pubkey, up["pubkey"].as_str().unwrap(), "{name}");
        assert_eq!(
            js_stringify(&d.chain),
            up["chain"].as_str().unwrap(),
            "{name}"
        );
        // the content is the document as JSON.stringify wrote it, without a signer
        let source: Value = serde_json::from_str(v["documents"][name].as_str().unwrap()).unwrap();
        let mut unsigned = source.clone();
        unsigned.as_object_mut().unwrap().shift_remove("signer");
        assert_eq!(ev.content, js_stringify(&unsigned), "{name}");
    }
    // level 1 documents get their author as signer; the level-2 one does not
    let trial = parse_chain_event(&event(&v, "trial")).unwrap();
    trial.document().unwrap().validate().unwrap();
    let fed = parse_chain_event(&event(&v, "fed")).unwrap();
    assert!(fed.chain.get("signer").is_none());
    let doc = fed.document().unwrap();
    doc.validate().unwrap(); // the federation derives the challenge
    assert_eq!(doc.signers.unwrap()[1], fed.pubkey);
}

#[test]
fn the_same_documents_signed_here_are_the_same_events() {
    let v = vectors();
    let at = v["created_at"].as_u64().unwrap();
    for (name, key_file) in DOCUMENTS {
        let theirs = event(&v, name);
        let text = v["documents"][name].as_str().unwrap();
        // the id needs no key: the unsigned event's hash is the chain's hash
        let mut unsigned = chain_event(text, at).unwrap();
        unsigned.pubkey = theirs.pubkey.clone();
        assert_eq!(unsigned.id(), theirs.id, "{name}: the chain's hash");
        assert_eq!(unsigned.content, theirs.content, "{name}");
        assert_eq!(unsigned.tags, theirs.tags, "{name}");
        let Some(signer) = key(key_file) else {
            continue;
        };
        let ours = sign_chain_event(&signer, text, at).unwrap();
        assert_eq!(ours, theirs, "{name}: id, content, tags and signature");
    }
}

#[test]
fn the_tip_with_the_chain_hash_matches_upstream() {
    let v = vectors();
    let at = v["created_at"].as_u64().unwrap();
    let theirs = event(&v, "tipChainHash");
    theirs.verify().unwrap();
    let hash = v["events"]["trial"]["id"].as_str().unwrap();
    let up = v["upstream"]["parseTip_chainHash"].as_str().unwrap();
    assert_eq!(up, hash);
    assert_eq!(parse_tip(&theirs).unwrap().chain_hash.as_deref(), Some(up));
    assert_eq!(chain_hash_of(&theirs).as_deref(), Some(up));
    let last = theirs.tags.last().unwrap();
    assert_eq!(last, &["e", hash, "", "chain"]);

    let s = |i: u8| format!("{i:02x}").repeat(80);
    let t = TipTemplate::new(
        "sidestr:trial",
        12,
        vec![s(1), s(2), s(3)],
        vec!["https://a.example/siding/".into()],
    )
    .unwrap()
    .with_chain_hash(&hash.to_uppercase())
    .unwrap();
    let bare = TipTemplate::new("sidestr:trial", 0, vec![s(1)], vec![])
        .unwrap()
        .with_chain_hash(hash)
        .unwrap();
    let only = event(&v, "tipChainHashOnly");
    let peg = format!("5120{}", "AB".repeat(32));
    let refused = TipTemplate::new("sidestr:trial", 0, vec![s(1)], vec![])
        .unwrap()
        .with_chain_hash("ab")
        .unwrap_err();
    assert!(refused
        .to_string()
        .contains(v["upstream"]["tipEvent_badChainHash"].as_str().unwrap()));
    if let Some(signer) = key("trial/trial.key") {
        assert_eq!(
            sign_tip_with_peg(&signer, &t, Some(&peg), at).unwrap(),
            theirs
        );
        assert_eq!(sign_tip(&signer, &bare, at).unwrap(), only);
    } else {
        let mut ours = sidestr_nostr::tip::tip_event_with_peg(&t, Some(&peg), at).unwrap();
        ours.pubkey = theirs.pubkey.clone();
        assert_eq!(ours.id(), theirs.id);
    }
}

#[test]
fn the_generator_prints_the_committed_fixture() {
    if ["SIDESTR_SIDING", "SCHEMA", "BLAKETESTNODE"]
        .iter()
        .any(|n| std::env::var(n).is_err())
    {
        eprintln!("skipped the reference half: set SIDESTR_SIDING, SCHEMA and BLAKETESTNODE");
        return;
    }
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/oracle/chain-event-oracle.mjs"
    );
    let out = std::process::Command::new("node")
        .arg(script)
        .output()
        .expect("node runs");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        include_str!("../fixtures/chain-event-vectors.json"),
        "siding at the pinned commit builds other events than the fixture holds"
    );
}
