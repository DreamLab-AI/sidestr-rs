//! Real-world vectors: `fixtures/live-33333.json` holds kind-33333 sidestr
//! announcements fetched read-only from public relays on 2026-09-22 (one copy
//! per event id, with the relay and the unix time it was first received).
//! Nothing was published. Every one verifies under the schema kernel; this
//! test asks the same of this crate, parses each, and checks the departure
//! from upstream (before spec 0.0.3) on the live `sidestr:dreamlab`
//! announcement: one 80-byte stock header, which siding's `parseTip` rejected
//! until sidestr/spec PR #7.

use serde::Deserialize;
use sidestr_core::parents::Family;
use sidestr_nostr::event::Event;
use sidestr_nostr::kinds::KIND_TIP;
use sidestr_nostr::relay::Follower;
use sidestr_nostr::tip::{chain_of, newest, parse_tip, parse_tip_as, TIP_HEADERS};

#[derive(Deserialize)]
struct Live {
    relay: String,
    fetched_at: u64,
    event: Event,
}

fn live() -> Vec<Live> {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/live-33333.json")).unwrap();
    serde_json::from_value(v["events"].clone()).unwrap()
}

#[test]
fn every_live_announcement_verifies_and_parses() {
    let all = live();
    assert!(all.len() >= 10, "{} events", all.len());
    let mut chains = std::collections::BTreeSet::new();
    let mut stock = 0;
    let mut v2 = 0;
    for l in &all {
        assert!(l.relay.starts_with("wss://"));
        assert!(l.fetched_at >= l.event.created_at, "{}", l.event.id);
        assert_eq!(l.event.kind, KIND_TIP);
        l.event
            .verify()
            .unwrap_or_else(|e| panic!("{} from {}: {e}", l.event.id, l.relay));
        let t =
            parse_tip(&l.event).unwrap_or_else(|e| panic!("{} from {}: {e}", l.event.id, l.relay));
        assert_eq!(chain_of(&l.event), Some(t.chain_id.as_str()));
        assert!(t.chain_id.starts_with("sidestr:"), "{}", t.chain_id);
        assert!(t.headers_hex.len() <= TIP_HEADERS);
        assert!(l
            .event
            .tags
            .iter()
            .any(|x| x[0] == "t" && x[1] == "sidestr"));
        assert!(!t.mirrors.is_empty(), "{}: no mirror", t.chain_id);
        assert!(t.mirrors.iter().all(|m| !m.ends_with('/')));
        match t.family {
            Some(Family::Stock) => stock += 1,
            Some(Family::Blake2b) => v2 += 1,
            None => {}
        }
        chains.insert(t.chain_id);
    }
    assert!(stock >= 1, "a stock-family announcement is on the relays");
    assert!(v2 >= 1, "a BLAKE2b-family announcement is on the relays");
    assert!(chains.contains("sidestr:dreamlab"), "{chains:?}");
}

#[test]
fn the_dreamlab_announcement_is_stock_family_and_upstream_rejects_it() {
    let all = live();
    let events: Vec<&Event> = all.iter().map(|l| &l.event).collect();
    let t = newest(events.iter().copied(), "sidestr:dreamlab", None).unwrap();
    assert_eq!(t.family, Some(Family::Stock));
    assert_eq!(
        t.headers_hex.len(),
        t.tip as usize + 1 - t.first_height().unwrap() as usize
    );
    let ev = events.iter().find(|e| e.id == t.id).unwrap();
    assert_eq!(ev.content.len() % 160, 0);
    assert_ne!(
        ev.content.len() % 328,
        0,
        "siding parseTip before spec 0.0.3: content.length % 328 !== 0 -> null"
    );
    // explicit family from the chain's parent (tbtc4 -> stock) agrees; the wrong one is refused
    assert_eq!(
        parse_tip_as(
            ev,
            sidestr_core::parents::resolve_parent("tbtc4")
                .unwrap()
                .family
        )
        .unwrap(),
        t
    );
    assert!(parse_tip_as(ev, Family::Blake2b).is_err());
    // and the header really is the sealed genesis: hash it as sidestr-core does
    if t.tip == 0 {
        let bytes = hex::decode(&t.headers_hex[0]).unwrap();
        let header: bitcoin::block::Header = bitcoin::consensus::deserialize(&bytes).unwrap();
        assert_eq!(
            header.block_hash().to_string(),
            "4db37517728bd509c0cb96ee5a2e3e2a77f9e965a092e9f67948b413d453dbc0"
        );
    }
}

#[test]
fn a_v2_announcement_carries_a_full_window_of_164_byte_headers() {
    let all = live();
    let full = all
        .iter()
        .filter_map(|l| parse_tip(&l.event).ok())
        .find(|t| t.family == Some(Family::Blake2b) && t.headers_hex.len() == TIP_HEADERS)
        .expect("a v2 chain past height 12");
    assert!(full.headers_hex.iter().all(|h| h.len() == 328));
    assert_eq!(full.first_height(), Some(full.tip - 11));
    assert_eq!(
        full.header_at(full.tip),
        full.headers_hex.last().map(String::as_str)
    );
}

#[test]
fn newest_picks_one_announcement_per_chain_and_a_follower_would_not_take_them() {
    let all = live();
    let events: Vec<&Event> = all.iter().map(|l| &l.event).collect();
    let chains: std::collections::BTreeSet<String> = events
        .iter()
        .filter_map(|e| chain_of(e))
        .map(str::to_string)
        .collect();
    for c in &chains {
        let best = newest(events.iter().copied(), c, None).unwrap();
        let signer = best.pubkey.clone();
        assert_eq!(
            newest(events.iter().copied(), c, Some(&signer)).unwrap().id,
            best.id
        );
        assert!(newest(events.iter().copied(), c, Some(&"00".repeat(32))).is_none());
    }
    // tips carry `d`, not `chain`: a kind-33333 follower keyed on the chain tag takes nothing,
    // which is why tips are fetched by #d and transactions are followed by kind
    let mut f = Follower::new(KIND_TIP, "sidestr:dreamlab");
    assert!(events.iter().all(|e| f.accept(e).is_none()));
}

/// SPEC 0.0.5 keeps a chain made before it resolving as it did: the live
/// `sidestr:dreamlab` announcement names no chain event (no `e` tag), so
/// `resolve_chain` by its alias reads the mirror's `chain.json` (the
/// estate's document, `sidestr-core/fixtures/dreamlab/chain.json`, whose
/// `signer` is the announcement's author) and settles on it with no hash.
#[test]
fn the_live_dreamlab_chain_resolves_the_pre_0_0_5_way() {
    use sidestr_nostr::chain::resolve_chain;
    use sidestr_nostr::event::SecretKeySigner;
    use sidestr_nostr::tip::{sign_tip, TipTemplate};

    let all = live();
    let events: Vec<&Event> = all.iter().map(|l| &l.event).collect();
    let tip = newest(events.iter().copied(), "sidestr:dreamlab", None).unwrap();
    assert_eq!(tip.chain_hash, None, "the live announcement predates 0.0.5");
    assert!(events
        .iter()
        .filter(|e| chain_of(e) == Some("sidestr:dreamlab"))
        .all(|e| !e.tags.iter().any(|t| t[0] == "e")));
    // the estate's document, from the sibling crate when the workspace is around us
    let Ok(text) = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../sidestr-core/fixtures/dreamlab/chain.json"
    )) else {
        return;
    };
    let document: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(document["signer"], tip.pubkey.as_str());
    let mirrors = tip.mirrors.clone();
    let serve = |url: &str| -> Result<serde_json::Value, String> {
        if mirrors.iter().any(|m| format!("{m}/chain.json") == url) {
            Ok(document.clone())
        } else {
            Err("404".into())
        }
    };
    let r = resolve_chain(
        Some("sidestr:dreamlab"),
        None,
        2,
        |_| Some(tip.clone()),
        |_| None,
        serve,
    )
    .unwrap();
    assert!(r.legacy);
    assert_eq!(r.hash, None);
    assert_eq!(r.mirror.as_deref(), Some(tip.mirrors[0].as_str()));
    assert_eq!(r.pubkey, tip.pubkey);
    let doc = r.document().unwrap();
    doc.validate().unwrap();
    assert_eq!(
        doc.signer.as_deref(),
        Some("7092810a05359b29acfa1f884d0e1a8e0290309e1133198b0f059447a4c76d62")
    );

    // a tip for it by another key is refused: no mirror's document names that key
    let impostor = SecretKeySigner::from_bytes(&[0x42; 32]).unwrap();
    let forged = sign_tip(
        &impostor,
        &TipTemplate::new(
            "sidestr:dreamlab",
            tip.tip,
            tip.headers_hex.clone(),
            tip.mirrors.clone(),
        )
        .unwrap(),
        tip.created_at + 1,
    )
    .unwrap();
    let forged = parse_tip(&forged).unwrap();
    let e = resolve_chain(
        Some("sidestr:dreamlab"),
        None,
        2,
        |_| Some(forged.clone()),
        |_| None,
        serve,
    )
    .unwrap_err();
    assert!(
        e.to_string().contains("no mirror it names checks out"),
        "{e}"
    );
}
