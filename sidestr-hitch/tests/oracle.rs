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
use sidestr_hitch::protocol::{
    AcceptPolicy, Bytes32, ChainSpend, ChannelMachine, Context, FunderOpening, OpenParams,
    OpeningKeys, OutputLookup, ReceiveUpdate, ReceiverOpening,
};
use sidestr_hitch::{
    claim_htlc, key_path_spend, pop_sign, revocation_key, revocation_pub, sweep_to_local,
    to_remote_script, Balances, Channel, ChannelState, Commitment, Htlc, HtlcClaim, HtlcClaimPath,
    RevocationKeys, Side, SweepPath,
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
        "revocation": revocation_vectors(),
        "spends": protocol_spends(),
        "mustFail": owner_cannot_cheat(),
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
    eprintln!("Hitch reference: {} checks", verdict["checked"]);
    assert_eq!(verdict["checked"], 32, "every reference check ran");
}

fn prevout(output: &TxOut) -> serde_json::Value {
    json!({ "value": output.value.to_sat(), "spk": hex(output.script_pubkey.as_bytes()) })
}

fn spend(name: &str, tx: &Transaction, prevouts: &[TxOut]) -> serde_json::Value {
    json!({
        "name": name,
        "hex": serialize_hex(tx),
        "prevouts": prevouts.iter().map(prevout).collect::<Vec<_>>(),
    })
}

/// Hitch's golden two-party key, computed by Rust, and a Rust proof of
/// possession, for Hitch to recompute and verify.
fn revocation_vectors() -> serde_json::Value {
    let r = key(0x33);
    let s = key(0x44);
    let point = revocation_pub(public(&r), &s).unwrap();
    let context = "abababababababab/a/2";
    json!({
        "basepoint": public(&r).to_string(),
        "basepointSecret": hex(&r.secret_bytes()),
        "perStatePoint": public(&s).to_string(),
        "perStateSecret": hex(&s.secret_bytes()),
        "point": point.to_string(),
        "secret": hex(&revocation_key(&r, &s).unwrap().secret_bytes()),
        "popPoint": public(&key(0x51)).to_string(),
        "pop": pop_sign(&key(0x51), context, &[9; 32]).to_hex(),
        "popContext": context,
    })
}

const H: u32 = 152_100;

fn ctx(height: u32) -> Context {
    Context::new(height, 1_800_000_000, [4; 32])
}

fn pair() -> (ChannelMachine, ChannelMachine) {
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
            channel: key(0x11),
            revocation_base: key(0x30),
            revocation: [key(0x31), key(0x32)],
        },
        public(&key(0x22)),
        SighashRules::KnotsUnified,
        &[0; 32],
    )
    .unwrap();
    let (receiver, accept) = ReceiverOpening::accept(
        open,
        public(&key(0x11)),
        OpeningKeys {
            channel: key(0x22),
            revocation_base: key(0x40),
            revocation: [key(0x41), key(0x42)],
        },
        SighashRules::KnotsUnified,
        AcceptPolicy::default(),
        &[0; 32],
    )
    .unwrap();
    let (accepted, commit) = funder.accept(accept, &[0; 32]).unwrap();
    let (mut b, ready) = receiver.commit(commit).unwrap();
    let mut a = accepted.ready(ready).unwrap();
    a.confirm_funding(H);
    b.confirm_funding(H);
    (a, b)
}

fn round(
    from: &mut ChannelMachine,
    to: &mut ChannelMachine,
    message: sidestr_hitch::protocol::UpdateMessage,
    seed: u8,
) {
    let ReceiveUpdate::Acknowledge(ack) = to.receive_update(message, key(seed), &ctx(H)).unwrap()
    else {
        panic!("acknowledged")
    };
    let outcome = from.receive_ack(ack).unwrap();
    to.receive_revoke(outcome.revoke).unwrap().unwrap();
}

fn to_local(commitment: &Commitment) -> TxOut {
    TxOut {
        value: commitment.local_value,
        script_pubkey: commitment.to_local.script_pubkey.clone(),
    }
}

fn htlc_output(commitment: &Commitment) -> TxOut {
    TxOut {
        value: commitment.htlcs[0].htlc.amount,
        script_pubkey: commitment.htlcs[0].scripts.script_pubkey.clone(),
    }
}

/// A Rust protocol run, every transaction it would broadcast: signed
/// commitments, the penalty on a revoked state (two-party key), the delayed
/// sweep, the HTLC success claim with its preimage and the refund.
fn protocol_spends() -> Vec<serde_json::Value> {
    let (mut a, mut b) = pair();
    let funding = a.channel().funding_prevout();
    let mut spends = vec![spend(
        "the state-0 commitment",
        &b.signed_commitment(0, &[1; 32]).unwrap(),
        std::slice::from_ref(&funding),
    )];
    let pay = a.pay(1_000, None, key(0x33), &ctx(H)).unwrap();
    round(&mut a, &mut b, pay, 0x43);
    let preimage = [0x55; 32];
    let hash = Bytes32(sha256::Hash::hash(&preimage).to_byte_array());
    let add = a
        .add_htlc(5_000, hash, H + 40, None, None, key(0x34), &ctx(H))
        .unwrap();
    round(&mut a, &mut b, add, 0x44);
    b.remember_preimage(preimage);
    let destination_a = to_remote_script(public(&key(0x11)));
    let destination_b = to_remote_script(public(&key(0x22)));
    let none = |_: OutPoint, _: u32| OutputLookup::Unspent;

    // B's revoked state 0 published: A punishes it with r_A + s_B0.
    let old = b.signed_commitment(0, &[2; 32]).unwrap();
    let old_commitment = b.my_commitment(0).unwrap();
    let mut punisher = a.clone();
    let penalties = punisher
        .on_spend(
            ChainSpend {
                txid: old.compute_txid(),
                height: H + 1,
            },
            &destination_a,
            &ctx(H + 1),
            none,
        )
        .unwrap()
        .broadcasts;
    assert_eq!(penalties.len(), 1);
    spends.push(spend(
        "the penalty on a revoked to_local",
        &penalties[0].tx,
        &[to_local(&old_commitment)],
    ));

    // B force-closes at state 2 with the HTLC in flight.
    let mut closer = b.clone();
    let close = closer.force_close(None, "forced", &ctx(H)).unwrap().tx;
    spends.push(spend("the forced close with an HTLC", &close, &[funding]));
    let mine = closer.my_commitment(2).unwrap();
    closer
        .on_spend(
            ChainSpend {
                txid: close.compute_txid(),
                height: H,
            },
            &destination_b,
            &ctx(H),
            none,
        )
        .unwrap();
    let claims = closer.after_close(&destination_b, &ctx(H + 6), none);
    let sweep = claims
        .iter()
        .find(|c| c.label == "sweep of to_local")
        .unwrap();
    spends.push(spend("the delayed sweep", &sweep.tx, &[to_local(&mine)]));
    let success = claims
        .iter()
        .find(|c| c.label.contains("with the preimage"))
        .unwrap();
    let mut entry = spend(
        "the HTLC success claim on its own commitment",
        &success.tx,
        &[htlc_output(&mine)],
    );
    entry["preimage"] = json!(hex(&preimage));
    entry["hash"] = json!(hex(&hash.0));
    spends.push(entry);

    // A sees B's close and takes the refund after the expiry.
    let mut refunder = a.clone();
    refunder
        .on_spend(
            ChainSpend {
                txid: close.compute_txid(),
                height: H,
            },
            &destination_a,
            &ctx(H),
            none,
        )
        .unwrap();
    let theirs = refunder
        .their_commitment(2, refunder.current_state())
        .unwrap();
    let refunds = refunder.after_close(&destination_a, &ctx(H + 40), none);
    let refund = refunds.iter().find(|c| c.label.contains("refund")).unwrap();
    spends.push(spend(
        "the HTLC refund after its expiry",
        &refund.tx,
        &[htlc_output(&theirs)],
    ));
    spends
}

/// The flaw 0.2 fixes: the owner's own per-state secret, or its channel key,
/// must not open its commitment's revocation leaf.
fn owner_cannot_cheat() -> Vec<serde_json::Value> {
    let (a, _) = pair();
    let mine = a.my_commitment(0).unwrap();
    let destination = to_remote_script(public(&key(0x11)));
    [
        ("the owner's per-state secret", key(0x31)),
        ("the owner's channel key", key(0x11)),
    ]
    .into_iter()
    .map(|(name, secret)| {
        let tx = sweep_to_local(
            &mine,
            SweepPath::Revocation,
            destination.clone(),
            Amount::from_sat(300),
            &secret,
            SighashRules::KnotsUnified,
            &[0; 32],
        )
        .unwrap();
        spend(
            &format!("a revocation spend by {name}"),
            &tx,
            &[to_local(&mine)],
        )
    })
    .collect()
}
