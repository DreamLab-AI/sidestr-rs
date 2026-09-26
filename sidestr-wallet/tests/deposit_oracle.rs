//! The EVM deposit against the reference: for the same coins, tip, fee and
//! key, [`build_evm_deposit`] and siding's own `buildSpend({ evmDeposit:
//! true })` (`lib/spend.mjs` at fa86dac, signing with zero auxiliary
//! randomness as [`PlainKey`] does) make the same transaction, byte for
//! byte: the same coins picked in the same order, the reserve payment, the
//! `evmin:` marker, the change, the fee sized with the marker in place, and
//! the key-path signature of the parent's family. Beside tbtc4 and beside the
//! BLAKE2b txbt4, with the reserve taken from the challenge and from
//! `evm.reserve`, with a fixed fee, and where siding refuses (too few coins,
//! not a `0x` address) this crate refuses too.
//!
//! The reference half needs the checkouts named by `SIDESTR_SIDING`,
//! `SCHEMA` and `BLAKETESTNODE`; without them it reports itself skipped and
//! the Rust half (each deposit re-verified under the family's rule) still runs.

use std::path::PathBuf;
use std::process::Command;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Amount, TxOut};
use sidestr_core::block::{challenge_for, pubkey_of};
use sidestr_core::document::ChainDocument;
use sidestr_core::marker::evm_deposit_marker;
use sidestr_core::sighash::{rules_for, verify_taproot_key_path};
use sidestr_wallet::coins::Coin;
use sidestr_wallet::deposit::{build_evm_deposit, parse_evm_address, DepositRequest};
use sidestr_wallet::{Error, Permissive, PlainKey, SpendSigner};

/// Keys that are the same on every run. Not secrets: anyone can derive
/// them, and the chains they name are throwaway.
fn key(seed: &str) -> SecretKey {
    SecretKey::from_slice(
        &sha256::Hash::hash(format!("sidestr-wallet deposit key {seed}").as_bytes())
            .to_byte_array(),
    )
    .unwrap()
}

/// A throwaway chain naming the `evm` rule beside `parent`; `evm` is the
/// document's `evm` section.
fn document(parent: &str, rate: u64, evm: serde_json::Value) -> ChainDocument {
    let signer = key("signer");
    let mut v = serde_json::json!({
        "id": format!("sidestr:dep-{parent}"), "name": format!("dep-{parent}"), "parent": parent,
        "comment": "throwaway: the sidestr-wallet deposit oracle chain; coins with no value",
        "challenge": challenge_for(&pubkey_of(&signer)).to_hex_string(),
        "powLimit": "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "addressPrefix": "dp", "minFeeRate": rate, "genesisTime": 1790200000u32, "pegs": [],
        "signer": pubkey_of(&signer).to_string(), "rules": ["evm"],
    });
    if !evm.is_null() {
        v["evm"] = evm;
    }
    ChainDocument::from_json_with(&v.to_string(), &["assets", "evm"]).unwrap()
}

fn coin(n: u8, vout: u32, value: u64, height: u32, coinbase: bool) -> Coin {
    Coin {
        outpoint: format!("{}:{vout}", format!("{n:02x}").repeat(32))
            .parse()
            .unwrap(),
        value,
        height,
        coinbase,
    }
}

#[derive(Clone)]
struct Case {
    name: &'static str,
    doc: ChainDocument,
    coins: Vec<Coin>,
    tip: u32,
    to: &'static str,
    amount: u64,
    fee: Option<u64>,
}

fn cases() -> Vec<Case> {
    let other_reserve = challenge_for(&pubkey_of(&key("reserve"))).to_hex_string();
    vec![
        Case {
            name: "one coin, the challenge as reserve, beside tbtc4",
            doc: document("tbtc4", 1, serde_json::Value::Null),
            coins: vec![coin(0xab, 0, 100_000, 5, false)],
            tip: 10,
            to: "0x7777777777777777777777777777777777777777",
            amount: 25_000,
            fee: None,
        },
        Case {
            // largest first past an immature coinbase coin; equal values keep the listed order
            name: "three inputs, evm.reserve, minFeeRate 3, mixed-case address",
            doc: document(
                "tbtc4",
                3,
                serde_json::json!({ "chainId": 21474, "reserve": other_reserve.to_ascii_uppercase() }),
            ),
            coins: vec![
                coin(0x01, 0, 40_000, 3, false),
                coin(0x02, 1, 900_000, 60, true),
                coin(0x03, 2, 40_000, 4, false),
                coin(0x04, 0, 30_000, 7, false),
                coin(0x05, 3, 1_000, 8, false),
            ],
            tip: 100,
            to: "0xAbCdEf0123456789aBcDeF0123456789ABCDEF01",
            amount: 100_000,
            fee: None,
        },
        Case {
            name: "a fixed fee",
            doc: document("tbtc4", 1, serde_json::json!({ "gasLimit": 1000000 })),
            coins: vec![
                coin(0x11, 1, 60_000, 1, false),
                coin(0x12, 0, 70_000, 2, true),
            ],
            tip: 150,
            to: "0x0000000000000000000000000000000000000001",
            amount: 90_000,
            fee: Some(2_500),
        },
        Case {
            name: "beside the BLAKE2b txbt4: the unified sighash",
            doc: document("txbt4", 2, serde_json::Value::Null),
            coins: vec![coin(0x21, 0, 500_000, 1, true)],
            tip: 120,
            to: "0x00000000000000000000000000000000000501de",
            amount: 330,
            fee: None,
        },
    ]
}

fn reference(doc: &ChainDocument, req: serde_json::Value) -> Option<serde_json::Value> {
    if ["SIDESTR_SIDING", "SCHEMA", "BLAKETESTNODE"]
        .iter()
        .any(|v| std::env::var(v).is_err())
    {
        return None;
    }
    let dir = std::env::temp_dir().join(format!(
        "sidestr-wallet-deposit-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let chain_file = dir.join("chain.json");
    std::fs::write(&chain_file, doc.to_json().unwrap()).unwrap();
    let out = Command::new("node")
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/xcheck-wallet.mjs"))
        .arg("deposit")
        .arg(&chain_file)
        .arg(req.to_string())
        .output()
        .expect("node");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "reference engine failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(serde_json::from_slice(&out.stdout).expect("json from the reference engine"))
}

fn request(case: &Case, wallet: &PlainKey) -> serde_json::Value {
    serde_json::json!({
        "coins": case.coins, "tip": case.tip, "to": case.to, "amount": case.amount, "fee": case.fee,
        "key": hex::encode(wallet.secret_key().secret_bytes()),
    })
}

#[test]
fn deposits_are_sidings_byte_for_byte() {
    let wallet = PlainKey::new(key("wallet"));
    let cases = cases();
    let mut compared = 0;
    for case in &cases {
        let d = build_evm_deposit(
            &DepositRequest {
                chain: &case.doc,
                coins: &case.coins,
                tip_height: case.tip,
                to: case.to,
                amount: case.amount,
                fee: case.fee,
            },
            &wallet,
            &Permissive,
        )
        .unwrap_or_else(|e| panic!("{}: {e}", case.name));

        // --- Rust: the layout, and every input verifies under the family's rule ---
        let reserve = case.doc.evm_reserve().unwrap();
        assert_eq!(d.tx.output[0].script_pubkey, reserve, "{}", case.name);
        assert_eq!(d.tx.output[0].value.to_sat(), case.amount);
        assert_eq!(
            d.tx.output[1].script_pubkey,
            evm_deposit_marker(&parse_evm_address(case.to).unwrap())
        );
        assert_eq!(d.tx.output[1].value, Amount::ZERO);
        let value_of = |op| case.coins.iter().find(|c| c.outpoint == op).unwrap().value;
        let prevouts: Vec<TxOut> =
            d.tx.input
                .iter()
                .map(|i| TxOut {
                    value: Amount::from_sat(value_of(i.previous_output)),
                    script_pubkey: wallet.script(),
                })
                .collect();
        let rules = rules_for(case.doc.parent().unwrap().family);
        for i in 0..d.tx.input.len() {
            verify_taproot_key_path(&d.tx, i, &prevouts, rules).unwrap();
        }

        // --- siding: the same request, the same bytes ---
        let Some(r) = reference(&case.doc, request(case, &wallet)) else {
            continue;
        };
        assert_eq!(r["ok"], true, "{}: siding refused: {r}", case.name);
        assert_eq!(r["hex"], d.hex, "{}", case.name);
        assert_eq!(r["txid"], d.txid.to_string(), "{}", case.name);
        assert_eq!(
            (
                r["fee"].as_u64(),
                r["vsize"].as_u64(),
                r["change"].as_u64(),
                r["inputs"].as_u64()
            ),
            (
                Some(d.fee),
                Some(d.vsize),
                Some(d.change),
                Some(d.inputs as u64)
            ),
            "{}",
            case.name
        );
        assert_eq!(r["note"].as_str(), d.note.as_deref(), "{}", case.name);
        compared += 1;
    }
    if compared == 0 {
        eprintln!("skipped the reference half: set SIDESTR_SIDING, SCHEMA and BLAKETESTNODE");
    } else {
        assert_eq!(compared, cases.len());
    }
}

#[test]
fn refusals_match_sidings() {
    let wallet = PlainKey::new(key("wallet"));
    let short = Case {
        name: "too few coins for the amount and the fee bound",
        doc: document("tbtc4", 1, serde_json::Value::Null),
        coins: vec![coin(0x31, 0, 10_000, 1, false)],
        tip: 10,
        to: "0x7777777777777777777777777777777777777777",
        amount: 9_900,
        fee: None,
    };
    let not_0x = Case {
        name: "not a 0x address",
        to: "7777777777777777777777777777777777777777",
        amount: 1_000,
        ..short.clone()
    };
    for case in [short, not_0x] {
        let e = build_evm_deposit(
            &DepositRequest {
                chain: &case.doc,
                coins: &case.coins,
                tip_height: case.tip,
                to: case.to,
                amount: case.amount,
                fee: case.fee,
            },
            &wallet,
            &Permissive,
        )
        .unwrap_err();
        assert!(
            matches!(e, Error::Insufficient { .. } | Error::Evm(_)),
            "{}: {e}",
            case.name
        );
        let Some(r) = reference(&case.doc, request(&case, &wallet)) else {
            eprintln!("skipped the reference half: set SIDESTR_SIDING, SCHEMA and BLAKETESTNODE");
            return;
        };
        assert_eq!(r["ok"], false, "{}: siding built it: {r}", case.name);
        // the reference's words are this crate's, with what was refused named after them
        let theirs = r["error"].as_str().unwrap();
        assert!(
            e.to_string().contains(theirs),
            "{}: {e} / {theirs}",
            case.name
        );
    }
}
