//! Knots' unified opt-in sighash against its 166 known answers, as
//! bitcoin-blake/fidsigner (`2c4057c`, `unified_sighash.json`) carries them
//! from Knots v29.4.1.knots20260508: script types 2 (key path) and 3
//! (tapscript) through [`unified_taproot_sighash`], script types 0 (bare or
//! P2SH) and 1 (segwit v0) through [`unified_legacy_sighash`]. Every row
//! passes, NONE, SINGLE and ANYONECANPAY included.
//!
//! The oracle these rows came from is Fid's own suite: `npm ci && node
//! test.mjs` in a fidsigner checkout at that commit.

use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::{Amount, Script, ScriptBuf, Transaction, TxOut};
use serde_json::Value;
use sidestr_core::sighash::{
    unified_legacy_sighash, unified_taproot_sighash, UnifiedLegacy, UnifiedTaproot,
};

const ROWS: &str = include_str!("../fixtures/fidsigner/unified_sighash.json");

#[test]
fn every_knots_unified_sighash_vector() {
    let rows: Vec<Value> = serde_json::from_str(ROWS).unwrap();
    let (header, rows) = rows.split_first().unwrap();
    assert_eq!(
        header,
        &serde_json::json!([
            "scriptCode",
            "rawTx",
            "inIdx",
            "hashType",
            "scriptType",
            "spentOutputs",
            "sighash"
        ])
    );
    assert_eq!(rows.len(), 166);
    let mut by_type = [0usize; 4];
    for (n, r) in rows.iter().enumerate() {
        let code = hex::decode(r[0].as_str().unwrap()).unwrap();
        let tx: Transaction = deserialize(&hex::decode(r[1].as_str().unwrap()).unwrap())
            .unwrap_or_else(|e| panic!("row {n}: {e}"));
        let index = r[2].as_u64().unwrap() as usize;
        let hash_type = u8::try_from(r[3].as_u64().unwrap()).unwrap();
        let script_type = r[4].as_u64().unwrap() as usize;
        let prevouts: Vec<TxOut> = r[5]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| TxOut {
                value: Amount::from_sat(p[0].as_u64().unwrap()),
                script_pubkey: ScriptBuf::from_hex(p[1].as_str().unwrap()).unwrap(),
            })
            .collect();
        let leaf = TapLeafHash::from_script(Script::from_bytes(&code), LeafVersion::TapScript)
            .to_byte_array();
        let got = match script_type {
            0 | 1 => unified_legacy_sighash(
                &tx,
                index,
                &prevouts,
                hash_type,
                if script_type == 0 {
                    UnifiedLegacy::Base
                } else {
                    UnifiedLegacy::WitnessV0
                },
                &code,
            ),
            2 => unified_taproot_sighash(
                &tx,
                index,
                &prevouts,
                hash_type,
                None,
                UnifiedTaproot::KeyPath,
            ),
            3 => unified_taproot_sighash(
                &tx,
                index,
                &prevouts,
                hash_type,
                None,
                UnifiedTaproot::ScriptPath {
                    leaf_hash: &leaf,
                    codesep_pos: 0xffff_ffff,
                },
            ),
            t => panic!("row {n}: script type {t}"),
        }
        .unwrap_or_else(|e| panic!("row {n}: {e}"));
        assert_eq!(
            hex::encode(got),
            r[6].as_str().unwrap(),
            "row {n}: script type {script_type}, hash type {hash_type:#04x}, input {index}"
        );
        by_type[script_type] += 1;
    }
    assert_eq!(by_type, [76, 66, 12, 12]);
}

#[test]
fn the_legacy_message_needs_the_bit_and_every_prevout() {
    let rows: Vec<Value> = serde_json::from_str(ROWS).unwrap();
    let r = &rows[1];
    let tx: Transaction = deserialize(&hex::decode(r[1].as_str().unwrap()).unwrap()).unwrap();
    let prevouts: Vec<TxOut> = r[5]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| TxOut {
            value: Amount::from_sat(p[0].as_u64().unwrap()),
            script_pubkey: ScriptBuf::from_hex(p[1].as_str().unwrap()).unwrap(),
        })
        .collect();
    assert!(unified_legacy_sighash(&tx, 0, &prevouts, 0x01, UnifiedLegacy::Base, &[]).is_err());
    assert!(
        unified_legacy_sighash(&tx, 0, &prevouts[1..], 0x21, UnifiedLegacy::Base, &[]).is_err()
    );
    assert!(unified_legacy_sighash(&tx, 99, &prevouts, 0x21, UnifiedLegacy::Base, &[]).is_err());
    // the two script types are two messages
    let a = unified_legacy_sighash(&tx, 0, &prevouts, 0x21, UnifiedLegacy::Base, &[0x51]).unwrap();
    let b =
        unified_legacy_sighash(&tx, 0, &prevouts, 0x21, UnifiedLegacy::WitnessV0, &[0x51]).unwrap();
    assert_ne!(a, b);
}
