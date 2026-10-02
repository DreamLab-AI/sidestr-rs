//! Fid's own vectors (bitcoin-blake/fidsigner `2c4057c`, `vectors.json`,
//! vendored as `tests/fixtures/fidsigner-vectors.json` and in sidestr-core's
//! `fixtures/fidsigner/`): one key, a two-input PSBT paying it, signed on
//! btc, tbtc, xbt and txbt with zero BIP 340 auxiliary randomness. The
//! wallet's signer reproduces every final transaction and every finalised
//! PSBT byte for byte: `0x21` unified beside BLAKE2b, 64-byte
//! `SIGHASH_DEFAULT` beside stock Bitcoin ([`sign_parent_inputs`]).
//!
//! The oracle is Fid itself: `npm ci && node test.mjs` in a fidsigner
//! checkout at that commit.

use base64::Engine;
use bitcoin::consensus::encode::serialize;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::SecretKey;
use bitcoin::TxOut;
use serde_json::Value;
use sidestr_core::parents::resolve_parent;
use sidestr_core::sighash::{key_path_sighash, rules_for, SighashRules};
use sidestr_wallet::key::address_for;
use sidestr_wallet::parent_sign::sign_parent_inputs;
use sidestr_wallet::{PlainKey, SpendSigner};

const VECTORS: &str = include_str!("fixtures/fidsigner-vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn key(v: &Value) -> PlainKey {
    PlainKey::new(
        SecretKey::from_slice(&hex::decode(v["key"]["priv"].as_str().unwrap()).unwrap()).unwrap(),
    )
}

fn psbt(text: &str) -> Psbt {
    Psbt::deserialize(
        &base64::engine::general_purpose::STANDARD
            .decode(text)
            .unwrap(),
    )
    .unwrap()
}

/// Fid's chain names and the parent each stands for.
fn parent_rules(chain: &str) -> SighashRules {
    let alias = match chain {
        "btc" => "btc",
        "tbtc" => "tbtc4",
        "xbt" => "xbt",
        "txbt" => "txbt4",
        other => panic!("{other}"),
    };
    rules_for(resolve_parent(alias).unwrap().family)
}

#[test]
fn the_key_and_its_addresses() {
    let v = vectors();
    let k = key(&v);
    assert_eq!(k.pubkey().to_string(), v["key"]["xonly"].as_str().unwrap());
    for (chain, hrp) in [("btc", "bc"), ("tbtc", "tb"), ("xbt", "bc"), ("txbt", "tb")] {
        assert_eq!(
            address_for(&k.pubkey(), hrp).unwrap(),
            v["key"]["addresses"][chain].as_str().unwrap()
        );
    }
}

#[test]
fn every_chains_final_transaction_byte_for_byte() {
    let v = vectors();
    let k = key(&v);
    let unsigned = psbt(v["psbt"]["unsigned"].as_str().unwrap());
    assert_eq!(
        unsigned.unsigned_tx.compute_txid().to_string(),
        v["psbt"]["txid"].as_str().unwrap()
    );
    let prevouts: Vec<TxOut> = unsigned
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().unwrap())
        .collect();
    for (p, s) in prevouts.iter().zip(v["psbt"]["spent"].as_array().unwrap()) {
        assert_eq!(p.value.to_sat(), s["value"].as_u64().unwrap());
        assert_eq!(
            p.script_pubkey.to_hex_string(),
            s["script"].as_str().unwrap()
        );
    }
    let chains = v["psbt"]["chains"].as_object().unwrap();
    assert_eq!(chains.len(), 4);
    for (chain, want) in chains {
        let rules = parent_rules(chain);
        let mut tx = unsigned.unsigned_tx.clone();
        assert_eq!(
            sign_parent_inputs(&mut tx, &prevouts, rules, &k).unwrap(),
            vec![0, 1]
        );
        for i in &tx.input {
            match rules {
                SighashRules::KnotsUnified => {
                    assert_eq!((i.witness[0].len(), i.witness[0][64]), (65, 0x21))
                }
                SighashRules::Bip341 => assert_eq!(i.witness[0].len(), 64),
            }
        }
        assert_eq!(
            hex::encode(serialize(&tx)),
            want["finalTx"].as_str().unwrap(),
            "{chain}"
        );
        // the finalised PSBT too: each input's final witness, nothing else added
        let mut signed = unsigned.clone();
        for (inp, txin) in signed.inputs.iter_mut().zip(&tx.input) {
            inp.final_script_witness = Some(txin.witness.clone());
        }
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(signed.serialize()),
            want["signedPsbt"].as_str().unwrap(),
            "{chain}"
        );
        // signing twice gives the same bytes; a signed input is not signed again
        let mut again = unsigned.unsigned_tx.clone();
        sign_parent_inputs(&mut again, &prevouts, rules, &k).unwrap();
        assert_eq!(again, tx);
        assert!(sign_parent_inputs(&mut again, &prevouts, rules, &k)
            .unwrap()
            .is_empty());
    }
    // the chain only picks the sighash
    assert_eq!(chains["xbt"]["finalTx"], chains["txbt"]["finalTx"]);
    assert_eq!(chains["btc"]["finalTx"], chains["tbtc"]["finalTx"]);
    assert_ne!(chains["xbt"]["finalTx"], chains["btc"]["finalTx"]);
}

#[test]
fn the_sidechain_key_path_message_is_fids_beside_blake2b() {
    // beside a BLAKE2b family the wallet's builders sign exactly Fid's message and byte
    let v = vectors();
    let k = key(&v);
    let unsigned = psbt(v["psbt"]["unsigned"].as_str().unwrap());
    let prevouts: Vec<TxOut> = unsigned
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().unwrap())
        .collect();
    let mut tx = unsigned.unsigned_tx.clone();
    for i in 0..tx.input.len() {
        let (msg, ht) = key_path_sighash(&tx, i, &prevouts, SighashRules::KnotsUnified).unwrap();
        let mut item = k.sign_key_path(&msg).unwrap().serialize().to_vec();
        item.push(ht);
        tx.input[i].witness = bitcoin::Witness::from_slice(&[item]);
    }
    assert_eq!(
        hex::encode(serialize(&tx)),
        v["psbt"]["chains"]["txbt"]["finalTx"].as_str().unwrap()
    );
}

#[test]
fn inputs_not_paying_the_key_are_left_alone() {
    let v = vectors();
    let k = key(&v);
    let other = PlainKey::new(SecretKey::from_slice(&[0x42; 32]).unwrap());
    let unsigned = psbt(v["psbt"]["unsigned"].as_str().unwrap());
    let mut prevouts: Vec<TxOut> = unsigned
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().unwrap())
        .collect();
    prevouts[1].script_pubkey = other.script();
    let mut tx = unsigned.unsigned_tx.clone();
    assert_eq!(
        sign_parent_inputs(&mut tx, &prevouts, SighashRules::KnotsUnified, &k).unwrap(),
        vec![0]
    );
    assert!(tx.input[1].witness.is_empty());
    assert!(sign_parent_inputs(&mut tx, &prevouts[..1], SighashRules::Bip341, &k).is_err());
}
