//! Live cross-check against Hitch's JavaScript channel module and the schema
//! kernel interpreter. The pure Rust suite always runs; this test adds the
//! reference half when `HITCH`, `SIDESTR_SIDING`, `SCHEMA` and
//! `BLAKETESTNODE` name the pinned checkouts.

use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, SecretKey, XOnlyPublicKey};
use bitcoin::{Amount, OutPoint, Transaction, TxOut, Txid};
use serde_json::json;
use sidestr_core::block::secp;
use sidestr_core::sighash::SighashRules;
use sidestr_hitch::{
    claim_htlc, key_path_spend, sweep_to_local, to_remote_script, Balances, Channel, ChannelState,
    Htlc, HtlcClaim, HtlcClaimPath, RevocationKeys, Side, SweepPath,
};

fn key(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).unwrap()
}

fn public(key: &SecretKey) -> XOnlyPublicKey {
    Keypair::from_secret_key(secp(), key).x_only_public_key().0
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn signed(
    channel: &Channel,
    mut tx: Transaction,
    a: &SecretKey,
    b: &SecretKey,
) -> (Transaction, String, String) {
    let sig_a = channel
        .sign_funding(&tx, a, SighashRules::KnotsUnified, &[0; 32])
        .unwrap();
    let sig_b = channel
        .sign_funding(&tx, b, SighashRules::KnotsUnified, &[0; 32])
        .unwrap();
    tx.input[0].witness = channel
        .funding_witness(&BTreeMap::from([(public(a), sig_a), (public(b), sig_b)]))
        .unwrap();
    (tx, hex(sig_a.as_bytes()), hex(sig_b.as_bytes()))
}

#[test]
fn reference_accepts_every_rust_built_spend() {
    if ["HITCH", "SIDESTR_SIDING", "SCHEMA", "BLAKETESTNODE"]
        .iter()
        .any(|name| std::env::var(name).is_err())
    {
        eprintln!(
            "skipped the Hitch reference cross-check: set HITCH, SIDESTR_SIDING, SCHEMA and BLAKETESTNODE"
        );
        return;
    }

    let a = key(0x11);
    let b = key(0x22);
    let rev_a = key(0x33);
    let channel = Channel::new(
        public(&a),
        public(&b),
        OutPoint {
            txid: Txid::from_byte_array([0xab; 32]),
            vout: 1,
        },
        Amount::from_sat(100_000),
        Amount::from_sat(300),
        6,
    )
    .unwrap();
    let preimage = [0x55; 32];
    let state = ChannelState {
        balances: Balances {
            a: Amount::from_sat(40_000),
            b: Amount::from_sat(40_000),
        },
        revocation: RevocationKeys {
            a: public(&rev_a),
            b: public(&key(0x44)),
        },
        htlcs: vec![Htlc {
            id: 1,
            from: Side::A,
            amount: Amount::from_sat(20_000),
            payment_hash: sha256::Hash::hash(&preimage).to_byte_array(),
            expiry: 152_200,
        }],
    };
    let commit_a = channel.commitment(2, Side::A, &state).unwrap();
    let commit_b = channel.commitment(2, Side::B, &state).unwrap();
    let (signed_a, sig_a, sig_b) = signed(&channel, commit_a.tx.clone(), &a, &b);
    let destination_a = to_remote_script(public(&a));
    let destination_b = to_remote_script(public(&b));
    let sweep = sweep_to_local(
        &commit_a,
        SweepPath::Delayed,
        destination_a.clone(),
        Amount::from_sat(200),
        &a,
        SighashRules::KnotsUnified,
        &[0; 32],
    )
    .unwrap();
    let penalty = sweep_to_local(
        &commit_a,
        SweepPath::Revocation,
        destination_b.clone(),
        Amount::from_sat(200),
        &rev_a,
        SighashRules::KnotsUnified,
        &[0; 32],
    )
    .unwrap();
    let success = claim_htlc(
        &commit_a,
        &commit_a.htlcs[0],
        HtlcClaim {
            path: HtlcClaimPath::Success,
            destination: destination_b.clone(),
            fee: Amount::from_sat(200),
            preimage: Some(preimage),
        },
        &b,
        SighashRules::KnotsUnified,
        &[0; 32],
    )
    .unwrap();
    let timeout = claim_htlc(
        &commit_a,
        &commit_a.htlcs[0],
        HtlcClaim {
            path: HtlcClaimPath::Timeout,
            destination: destination_a.clone(),
            fee: Amount::from_sat(200),
            preimage: None,
        },
        &a,
        SighashRules::KnotsUnified,
        &[0; 32],
    )
    .unwrap();
    let htlc_penalty = claim_htlc(
        &commit_a,
        &commit_a.htlcs[0],
        HtlcClaim {
            path: HtlcClaimPath::Revocation,
            destination: destination_b.clone(),
            fee: Amount::from_sat(200),
            preimage: None,
        },
        &rev_a,
        SighashRules::KnotsUnified,
        &[0; 32],
    )
    .unwrap();
    let key_path = key_path_spend(
        OutPoint {
            txid: commit_a.tx.compute_txid(),
            vout: 1,
        },
        TxOut {
            value: commit_a.remote_value,
            script_pubkey: to_remote_script(public(&b)),
        },
        destination_b,
        Amount::from_sat(200),
        &b,
        SighashRules::KnotsUnified,
        &[0; 32],
    )
    .unwrap();

    let close_state = ChannelState {
        balances: Balances {
            a: Amount::from_sat(60_000),
            b: Amount::from_sat(40_000),
        },
        revocation: state.revocation,
        htlcs: vec![],
    };
    let close = channel.cooperative_close(&close_state).unwrap();
    let (signed_close, close_sig_a, close_sig_b) = signed(&channel, close.clone(), &a, &b);
    let request = json!({
        "commitAUnsigned": serialize_hex(&commit_a.tx),
        "commitBUnsigned": serialize_hex(&commit_b.tx),
        "commitASigned": serialize_hex(&signed_a),
        "sigA": sig_a,
        "sigB": sig_b,
        "sweep": serialize_hex(&sweep),
        "penalty": serialize_hex(&penalty),
        "success": serialize_hex(&success),
        "timeout": serialize_hex(&timeout),
        "htlcPenalty": serialize_hex(&htlc_penalty),
        "keyPath": serialize_hex(&key_path),
        "closeUnsigned": serialize_hex(&close),
        "closeSigned": serialize_hex(&signed_close),
        "closeSigA": close_sig_a,
        "closeSigB": close_sig_b,
    });
    let mut child = Command::new("node")
        .arg(format!("{}/tests/xcheck.mjs", env!("CARGO_MANIFEST_DIR")))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("node");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(serde_json::to_string(&request).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "Hitch reference failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let verdict: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        verdict["ok"], true,
        "reference disagreements: {}",
        verdict["failures"]
    );
}
