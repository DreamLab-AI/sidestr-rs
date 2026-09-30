//! Live wire-shape cross-check against Hitch's exact `wellFormed` validator.

use std::io::Write;
use std::process::{Command, Stdio};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, SecretKey, XOnlyPublicKey};
use bitcoin::{Amount, OutPoint, Txid};
use serde_json::json;
use sidestr_core::block::secp;
use sidestr_core::sighash::SighashRules;
use sidestr_hitch::protocol::{
    AcceptPolicy, Bytes32, FunderOpening, OfferedHtlc, OpenParams, OpeningKeys, ReceiveUpdate,
    ReceiverOpening, Route, SyncTag, Update,
};

fn key(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).unwrap()
}

fn public(key: &SecretKey) -> XOnlyPublicKey {
    Keypair::from_secret_key(secp(), key).x_only_public_key().0
}

#[test]
fn hitch_accepts_every_rust_wire_message() {
    let Ok(hitch) = std::env::var("HITCH") else {
        eprintln!("skipped the Hitch wire cross-check: set HITCH");
        return;
    };
    let channel_a = key(0x11);
    let channel_b = key(0x22);
    let (funder, open) = FunderOpening::propose(
        OpenParams {
            funding: OutPoint {
                txid: Txid::from_byte_array([0xab; 32]),
                vout: 1,
            },
            funding_value: Amount::from_sat(100_000),
            push: Amount::from_sat(20_000),
            delay: 6,
            fee: Amount::from_sat(300),
            hub_fee: None,
        },
        OpeningKeys {
            channel: channel_a,
            revocation: [key(0x31), key(0x32)],
        },
        public(&channel_b),
        SighashRules::KnotsUnified,
    )
    .unwrap();
    let (receiver, accept) = ReceiverOpening::accept(
        open.clone(),
        public(&channel_a),
        OpeningKeys {
            channel: channel_b,
            revocation: [key(0x41), key(0x42)],
        },
        SighashRules::KnotsUnified,
        AcceptPolicy::default(),
        &[0; 32],
    )
    .unwrap();
    let (funder, commit) = funder.accept(accept.clone(), &[0; 32]).unwrap();
    let (mut b, ready) = receiver.commit(commit.clone()).unwrap();
    let mut a = funder.ready(ready.clone()).unwrap();

    let update = a
        .propose(
            Update::Pay {
                amount: 1_000,
                memo: Some("wire oracle".into()),
            },
            152_100,
            key(0x33),
            &[0; 32],
        )
        .unwrap();
    let ack = match b
        .receive_update(update.clone(), 152_100, key(0x43), &[0; 32])
        .unwrap()
    {
        ReceiveUpdate::Acknowledge(ack) => ack,
        other => panic!("unexpected {other:?}"),
    };
    let (revoke, _) = a.receive_ack(ack.clone()).unwrap();
    b.receive_revoke(revoke.clone()).unwrap();
    let add = a
        .propose(
            Update::Add {
                htlc: OfferedHtlc {
                    id: 0,
                    amount: 2_000,
                    hash: Bytes32(sha256::Hash::hash(&[0x55; 32]).to_byte_array()),
                    expiry: 152_140,
                    route: Some(Route {
                        to: sidestr_hitch::protocol::NodeId(public(&key(0x66))),
                    }),
                },
                memo: None,
            },
            152_100,
            key(0x34),
            &[0; 32],
        )
        .unwrap();
    let close = a.close_message(&[0; 32]).unwrap();
    let sync = a.sync_message("open", SyncTag::Sync);
    let synced = b.sync_response("open", &sync).unwrap();
    let messages = vec![
        serde_json::to_value(open).unwrap(),
        serde_json::to_value(accept).unwrap(),
        serde_json::to_value(commit).unwrap(),
        serde_json::to_value(ready).unwrap(),
        serde_json::to_value(update).unwrap(),
        serde_json::to_value(ack).unwrap(),
        serde_json::to_value(revoke).unwrap(),
        serde_json::to_value(add).unwrap(),
        serde_json::to_value(close).unwrap(),
        serde_json::to_value(sync).unwrap(),
        serde_json::to_value(synced).unwrap(),
    ];

    let mut child = Command::new("node")
        .arg(format!(
            "{}/tests/wirecheck.mjs",
            env!("CARGO_MANIFEST_DIR")
        ))
        .env("HITCH", hitch)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("node");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(json!({ "messages": messages }).to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "Hitch wire oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let verdict: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(verdict["ok"], true, "wire disagreements: {verdict}");
}
