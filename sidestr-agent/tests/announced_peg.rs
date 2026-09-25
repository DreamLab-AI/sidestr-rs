//! SPEC 0.0.4: a level-1 peg-in pays the peg script the chain's signer
//! announces with its newest tip (the `peg` tag), read from relays once, as
//! the JS wallet's `pegInScript` does. Against sidestr-round's in-process
//! relay, so no network.
#![cfg(feature = "cli")]

use std::time::Duration;

use sidestr_agent::{announced_peg_address, fetch_announced_peg_script};
use sidestr_core::document::ChainDocument;
use sidestr_nostr::event::{SecretKeySigner, Signer};
use sidestr_nostr::tip::{sign_tip_with_peg, TipTemplate};
use sidestr_round::relay::{publish_one, RelayStandIn};

fn tip(
    signer: &SecretKeySigner,
    height: u32,
    peg: Option<&str>,
    created: u64,
) -> sidestr_nostr::event::Event {
    let t = TipTemplate::new("sidestr:t", height, vec!["01".repeat(80)], vec![]).unwrap();
    sign_tip_with_peg(signer, &t, peg, created).unwrap()
}

#[tokio::test]
async fn the_newest_announcement_by_the_chain_s_signer_names_the_peg() {
    let relay = RelayStandIn::start("127.0.0.1:0").await.unwrap();
    let relays = vec![relay.url()];
    let signer = SecretKeySigner::from_bytes(&[5u8; 32]).unwrap();
    let stranger = SecretKeySigner::from_bytes(&[6u8; 32]).unwrap();
    let doc = ChainDocument::from_json(&format!(
        r#"{{"id":"sidestr:t","name":"t","parent":"tbtc4",
        "challenge":"5120{0}",
        "powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","addressPrefix":"t",
        "genesisTime":1790000000,"signer":"{0}","pegs":[]}}"#,
        signer.pubkey_hex().unwrap()
    ))
    .unwrap();
    let old = format!("5120{}", "aa".repeat(32));
    let new = format!("5120{}", "bb".repeat(32));
    let forged = format!("5120{}", "ee".repeat(32));
    let wait = Duration::from_secs(5);
    publish_one(&relays[0], &tip(&signer, 5, Some(&old), 100), wait).await;
    publish_one(&relays[0], &tip(&signer, 6, Some(&new), 101), wait).await;
    // a higher tip from someone else is not the chain's signer's
    publish_one(&relays[0], &tip(&stranger, 99, Some(&forged), 102), wait).await;

    let got = fetch_announced_peg_script(&relays, &doc, wait).await;
    assert_eq!(got.as_deref(), Some(new.as_str()));
    let address = announced_peg_address(&doc, &new).unwrap();
    assert!(address.starts_with("tb1p"), "{address}");

    // a newer announcement with none: none (the newest's rotates it away)
    publish_one(&relays[0], &tip(&signer, 7, None, 103), wait).await;
    assert_eq!(fetch_announced_peg_script(&relays, &doc, wait).await, None);
}
