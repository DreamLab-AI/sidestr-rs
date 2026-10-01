//! Live wire-shape cross-check against Hitch's exact `wellFormed` validator:
//! every kind of message the Rust machine sends, taken from a real exchange.

use std::io::Write;
use std::process::{Command, Stdio};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, SecretKey, XOnlyPublicKey};
use bitcoin::{Amount, OutPoint, Txid};
use serde_json::json;
use sidestr_core::block::secp;
use sidestr_core::sighash::SighashRules;
use sidestr_hitch::protocol::{
    AcceptPolicy, Bytes32, Context, FunderOpening, NodeId, OpenParams, OpeningKeys, PeerMessage,
    ReceiveUpdate, ReceiverOpening, Route, SyncTag,
};

fn key(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).unwrap()
}

fn public(key: &SecretKey) -> XOnlyPublicKey {
    Keypair::from_secret_key(secp(), key).x_only_public_key().0
}

/// The messages of a real exchange: the opening, a payment, an HTLC routed
/// on, a collision answered with a reject, a sync and its answer, a close.
fn exchange() -> Vec<PeerMessage> {
    let ctx = Context::new(152_100, 1_800_000_000, [5; 32]);
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
            hub_fee: Some(10),
        },
        OpeningKeys {
            channel: channel_a,
            revocation_base: key(0x30),
            revocation: [key(0x31), key(0x32)],
        },
        public(&channel_b),
        SighashRules::KnotsUnified,
        &[0; 32],
    )
    .unwrap();
    let (receiver, accept) = ReceiverOpening::accept(
        open.clone(),
        public(&channel_a),
        OpeningKeys {
            channel: channel_b,
            revocation_base: key(0x40),
            revocation: [key(0x41), key(0x42)],
        },
        SighashRules::KnotsUnified,
        AcceptPolicy {
            hub_fee: Some(10),
            ..AcceptPolicy::default()
        },
        &[0; 32],
    )
    .unwrap();
    let (accepted, commit) = funder.accept(accept.clone(), &[0; 32]).unwrap();
    let (mut b, ready) = receiver.commit(commit.clone()).unwrap();
    let mut a = accepted.ready(ready.clone()).unwrap();
    a.confirm_funding(152_100);
    b.confirm_funding(152_100);

    let update = a
        .pay(1_000, Some("wire oracle".into()), key(0x33), &ctx)
        .unwrap();
    let ReceiveUpdate::Acknowledge(ack) =
        b.receive_update(update.clone(), key(0x43), &ctx).unwrap()
    else {
        panic!("acknowledged")
    };
    let revoke = a.receive_ack(ack.clone()).unwrap().revoke;
    b.receive_revoke(revoke.clone()).unwrap();
    let add = a
        .add_htlc(
            2_000,
            Bytes32(sha256::Hash::hash(&[0x55; 32]).to_byte_array()),
            152_140,
            Some(Route {
                to: NodeId(public(&key(0x66))),
            }),
            Some("routed".into()),
            key(0x34),
            &ctx,
        )
        .unwrap();
    // B proposes at the same time; whichever key is lower answers with a reject.
    let from_b = b.pay(500, None, key(0x44), &ctx).unwrap();
    let reject = match (
        a.receive_update(from_b, key(0x35), &ctx).unwrap(),
        b.receive_update(add.clone(), key(0x45), &ctx).unwrap(),
    ) {
        (ReceiveUpdate::LocalProposalWins(reject), _)
        | (_, ReceiveUpdate::LocalProposalWins(reject)) => reject,
        other => panic!("a collision, got {other:?}"),
    };
    let sync = a.sync_message(SyncTag::Sync);
    let synced = b.receive_sync(&sync, &ctx).unwrap().replies;
    // A close needs nothing in flight: take it on a second, quiet channel.
    let close = quiet_close();
    let mut messages: Vec<PeerMessage> = vec![
        open.into(),
        accept.into(),
        commit.into(),
        ready.into(),
        update.into(),
        ack.into(),
        revoke.into(),
        add.into(),
        reject.into(),
        sync.into(),
        close.into(),
    ];
    messages.extend(synced);
    messages
}

fn quiet_close() -> sidestr_hitch::protocol::CloseMessage {
    let ctx = Context::new(152_100, 1_800_000_000, [6; 32]);
    let (funder, open) = FunderOpening::propose(
        OpenParams {
            funding: OutPoint {
                txid: Txid::from_byte_array([0xcd; 32]),
                vout: 0,
            },
            funding_value: Amount::from_sat(50_000),
            push: Amount::ZERO,
            delay: 6,
            fee: Amount::from_sat(300),
            hub_fee: None,
        },
        OpeningKeys {
            channel: key(0x12),
            revocation_base: key(0x50),
            revocation: [key(0x51), key(0x52)],
        },
        public(&key(0x23)),
        SighashRules::KnotsUnified,
        &[0; 32],
    )
    .unwrap();
    let (receiver, accept) = ReceiverOpening::accept(
        open,
        public(&key(0x12)),
        OpeningKeys {
            channel: key(0x23),
            revocation_base: key(0x60),
            revocation: [key(0x61), key(0x62)],
        },
        SighashRules::KnotsUnified,
        AcceptPolicy::default(),
        &[0; 32],
    )
    .unwrap();
    let (accepted, commit) = funder.accept(accept, &[0; 32]).unwrap();
    let (_, ready) = receiver.commit(commit).unwrap();
    let mut x = accepted.ready(ready).unwrap();
    x.confirm_funding(152_100);
    x.close_channel(&ctx).unwrap()
}

#[test]
fn every_rust_message_is_serialisable_and_well_formed_by_its_own_check() {
    for message in exchange() {
        let json = serde_json::to_string(&message).unwrap();
        let back: PeerMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
        assert!(back.well_formed().is_ok(), "{json}");
    }
}

#[test]
fn hitch_accepts_every_rust_wire_message() {
    let Ok(hitch) = std::env::var("HITCH") else {
        eprintln!("skipped the Hitch wire cross-check: set HITCH");
        return;
    };
    let messages: Vec<serde_json::Value> = exchange()
        .into_iter()
        .map(|message| serde_json::to_value(message).unwrap())
        .collect();
    let kinds: Vec<String> = messages
        .iter()
        .map(|m| m["t"].as_str().unwrap().to_owned())
        .collect();
    for t in [
        "open", "accept", "commit", "ready", "update", "ack", "revoke", "reject", "close", "sync",
        "synced",
    ] {
        assert!(kinds.iter().any(|k| k == t), "the exchange sends a {t}");
    }

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
    assert_eq!(verdict["checked"], messages.len());
}
