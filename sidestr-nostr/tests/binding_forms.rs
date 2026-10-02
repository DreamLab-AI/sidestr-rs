//! The kind-38420 account binding in its three forms, held to bytes made
//! elsewhere.
//!
//! - `fixtures/binding-dreamlab-legacy.json`: the live `sidestr:dreamlab`
//!   binding as sidestr-nostr 0.5.0 (`41df9c7f`) signed it, `d` =
//!   `sidestr:dreamlab:<did>`. The chain has no chain event, so this form
//!   must stay readable, flagged legacy, and be made again to the same bytes.
//! - `fixtures/binding-dreamlab-genesis-js.json`: the same chain's binding as
//!   agentbox's `management-api/lib/sidestr-spend-key.js` `buildBinding`
//!   (agentbox `6db0ffc8d`, nostr-tools) signs it, `d` =
//!   `<genesis hash>:<did>` with a `legacy` tag. Its own known-answer test
//!   pins the id (`tests/sovereign/sidestr-spend-key.node-test.js`,
//!   `2235e3d8…`). `sidestr-agent`'s `hitch_binding_kat` holds the same form
//!   to another of agentbox's vectors; this one keeps the codec's own crate
//!   holding an external vector.
//! - the hash form's id, `e55eb681…`, computed by nostr-tools
//!   `getEventHash` over the tags `buildBinding` writes when the chain has a
//!   hash: the only external vector for the `chain`-tagged form.

use sidestr_nostr::chain::{parse_chain_event, sign_chain_event};
use sidestr_nostr::estate::{
    account_binding_event, check_binding_chain, legacy_alias_binding_event, parse_account_binding,
    parse_binding, sign_account_binding, sign_legacy_alias_binding, AccountBinding, BindingForm,
};
use sidestr_nostr::event::{Event, SecretKeySigner, Signer};

const LEGACY: &str = include_str!("../fixtures/binding-dreamlab-legacy.json");
const GENESIS_JS: &str = include_str!("../fixtures/binding-dreamlab-genesis-js.json");
const DREAMLAB_GENESIS: &str = "4db37517728bd509c0cb96ee5a2e3e2a77f9e965a092e9f67948b413d453dbc0";

#[test]
fn the_live_dreamlab_alias_form_round_trips_byte_for_byte() {
    let ev: Event = serde_json::from_str(LEGACY.trim()).unwrap();
    ev.verify().unwrap();
    // the wire bytes, re-serialised, are the captured ones
    assert_eq!(serde_json::to_string(&ev).unwrap(), LEGACY.trim());

    // the current reader refuses it; the reader of every form flags it legacy
    assert!(parse_account_binding(&ev).is_err());
    let p = parse_binding(&ev).unwrap();
    assert_eq!(p.form, BindingForm::Alias);
    assert!(p.legacy());
    assert_eq!(p.binding.alias, "sidestr:dreamlab");
    assert_eq!(p.binding.chain_hash, None);
    assert_eq!(p.binding.genesis_hash, DREAMLAB_GENESIS);

    // made again from what was read, by the same key: the same bytes
    let identity = SecretKeySigner::from_bytes(&[11u8; 32]).unwrap();
    assert_eq!(identity.pubkey_hex().unwrap(), p.binding.did_hex);
    let template = legacy_alias_binding_event(&p.binding, ev.created_at).unwrap();
    assert_eq!(template.id(), ev.id);
    let again = sign_legacy_alias_binding(&identity, &p.binding, ev.created_at).unwrap();
    assert_eq!(serde_json::to_string(&again).unwrap(), LEGACY.trim());
}

#[test]
fn agentbox_s_genesis_form_reads_as_legacy_and_is_made_to_the_same_id() {
    let js: Event = serde_json::from_str(GENESIS_JS.trim()).unwrap();
    js.verify().unwrap();
    assert_eq!(
        js.id,
        "2235e3d8c9acb8da72eadb71da3eb0de4b69122a42562cdb6093e25712ee23f9"
    );
    let p = parse_binding(&js).unwrap();
    assert_eq!(p.form, BindingForm::Genesis);
    assert!(p.legacy());
    assert_eq!(
        p.binding,
        AccountBinding {
            alias: "sidestr:dreamlab".into(),
            chain_hash: None,
            genesis_hash: DREAMLAB_GENESIS.into(),
            did_hex: "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa".into(),
            spend_pubkey: "466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27".into(),
        }
    );
    assert_eq!(parse_account_binding(&js).unwrap(), p.binding);
    // Rust writes the same template: the id agrees and nostr-tools' signature verifies on it
    let ours = account_binding_event(&p.binding, js.created_at).unwrap();
    assert_eq!(ours.id(), js.id);
    assert_eq!(ours.tags, js.tags);
    assert_eq!(ours.with_signature(&js.sig).unwrap(), js);
}

#[test]
fn the_hash_form_carries_the_chain_hash_in_d_and_matches_agentbox_s_id() {
    let genesis_form = parse_binding(&serde_json::from_str(GENESIS_JS.trim()).unwrap())
        .unwrap()
        .binding;
    let hash = "9f".repeat(32);
    let b = AccountBinding {
        chain_hash: Some(hash.clone()),
        ..genesis_form
    };
    let ev = account_binding_event(&b, 1_790_971_200).unwrap();
    assert_eq!(
        ev.id(),
        "e55eb6812472358a1e2604561ac3b20d93ae33b87d6c9f61e9985024f2cdadaf"
    );
    assert_eq!(
        ev.tags[0],
        ["d".to_string(), format!("{hash}:{}", b.did_hex)]
    );
    assert_eq!(ev.tags[1], ["alias", "sidestr:dreamlab"]);
    assert_eq!(ev.tags[2], ["genesis", DREAMLAB_GENESIS]);
    assert_eq!(ev.tags[3], ["chain", hash.as_str()]);

    let k_id = SecretKeySigner::from_bytes(&[0x11u8; 32]).unwrap();
    let p = parse_binding(&sign_account_binding(&k_id, &b, 1).unwrap()).unwrap();
    assert_eq!(p.form, BindingForm::Hash);
    assert!(!p.legacy());
    assert_eq!(p.binding, b);
}

#[test]
fn a_binding_is_held_to_its_chain_event_with_genesis_as_the_cross_check() {
    let chain_key = SecretKeySigner::from_bytes(&[0x31u8; 32]).unwrap();
    let me = chain_key.pubkey_hex().unwrap();
    let doc = |genesis: &str| {
        format!(
            r#"{{"id":"sidestr:poker","name":"poker","parent":"tbtc4","challenge":"5120{me}","genesisTime":1790000000,"genesisHash":"{genesis}"}}"#
        )
    };
    let chain =
        parse_chain_event(&sign_chain_event(&chain_key, &doc(&"4d".repeat(32)), 1).unwrap())
            .unwrap();
    let k_id = SecretKeySigner::from_bytes(&[0x11u8; 32]).unwrap();
    let b = |chain_hash: Option<String>| AccountBinding {
        alias: "sidestr:poker".into(),
        chain_hash,
        genesis_hash: "4d".repeat(32),
        did_hex: k_id.pubkey_hex().unwrap(),
        spend_pubkey: "ab".repeat(32),
    };

    check_binding_chain(&b(Some(chain.hash.clone())), &chain).unwrap();
    // another chain's hash
    assert!(check_binding_chain(&b(Some("9f".repeat(32))), &chain).is_err());
    // the legacy forms pass on alias and genesis, and say they are legacy
    let genesis = parse_binding(&sign_account_binding(&k_id, &b(None), 1).unwrap()).unwrap();
    let alias = parse_binding(&sign_legacy_alias_binding(&k_id, &b(None), 1).unwrap()).unwrap();
    for p in [genesis, alias] {
        assert!(p.legacy());
        check_binding_chain(&p.binding, &chain).unwrap();
    }
    // the genesis cross-check: a document pinning another genesis refuses the binding
    let other =
        parse_chain_event(&sign_chain_event(&chain_key, &doc(&"5e".repeat(32)), 1).unwrap())
            .unwrap();
    let e = check_binding_chain(&b(Some(other.hash.clone())), &other).unwrap_err();
    assert!(e.to_string().contains("genesis"), "{e}");
    // another alias
    let renamed = AccountBinding {
        alias: "sidestr:other".into(),
        ..b(Some(chain.hash.clone()))
    };
    assert!(check_binding_chain(&renamed, &chain).is_err());
}
