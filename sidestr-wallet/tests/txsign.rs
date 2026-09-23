//! Key-path signatures follow the parent's family (SPEC 3, 0.0.3): a port of
//! `siding/test/txsign-test.mjs` (sidestr/spec `722ad42`), the signing half,
//! through the wallet and each family's mempool check.
//!
//! - Beside BLAKE2b (`txbt4`) the wallet signs Knots' unified sighash, hash
//!   type `0x21`. Beside stock Bitcoin (`tbtc4`) it signs BIP 341's, `0x01`.
//! - Each chain's `submit` (the producer's mempool check) accepts its own
//!   family's signature.
//! - A unified signature is refused beside stock Bitcoin, which is the bug
//!   the first stock-parent chain hit. A BIP 341 signature is still accepted
//!   beside BLAKE2b, because the flag byte selects the rule.
//!
//! With `SIDESTR_SIDING`, `SCHEMA` and `BLAKETESTNODE` set, the reference
//! judges each Rust transaction under both rules. It also re-signs the same
//! unsigned transaction with its own `keyPathSighash` and zero auxiliary
//! randomness, and the witnesses must match **byte for byte**. It signs once
//! more with its own `signKeyPath` (fresh randomness) for Rust to verify.

use std::path::PathBuf;
use std::process::Command;

use bitcoin::consensus::encode::{deserialize, serialize_hex};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Amount, Transaction, TxOut};
use sidestr_core::block::{challenge_for, pubkey_of, HeaderFamily};
use sidestr_core::document::{ChainDocument, Peg};
use sidestr_core::parents::resolve_parent;
use sidestr_core::sighash::{rules_for, verify_taproot_key_path, SighashRules};
use sidestr_core::state::{NextBlock, StateOf};
use sidestr_core::Stock;
use sidestr_header::Blake2bV2;
use sidestr_wallet::coins::{from_state, Coin};
use sidestr_wallet::key::address_for;
use sidestr_wallet::spend::{build_spend, Spend, SpendRequest};
use sidestr_wallet::{Permissive, PlainKey, SpendSigner};

/// Deterministic, disposable keys: anyone can derive them, and the chains
/// they sign for are throwaway.
fn key(seed: &str) -> SecretKey {
    SecretKey::from_slice(
        &sha256::Hash::hash(format!("sidestr-wallet txsign key {seed}").as_bytes()).to_byte_array(),
    )
    .unwrap()
}

/// A throwaway chain beside `parent` whose genesis pegs one coin to the wallet.
fn document(parent: &str, signer: &SecretKey, wallet: &dyn SpendSigner) -> ChainDocument {
    let mut d = ChainDocument::from_json(&format!(
        r#"{{"id":"sidestr:sig-{parent}","name":"sig-{parent}","parent":"{parent}",
        "comment":"throwaway: the sidestr-wallet txsign chain; coins with no value",
        "challenge":"{}","powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "addressPrefix":"sg","pegConfirmations":6,"refundBlocks":10000,"pegoutBlocks":144,
        "pegoutMin":10000,"minFeeRate":1,"genesisTime":1790150000,"pegs":[],"signer":"{}"}}"#,
        challenge_for(&pubkey_of(signer)).to_hex_string(),
        pubkey_of(signer)
    ))
    .unwrap();
    d.pegs.push(Peg {
        txid: "a".repeat(64),
        vout: 0,
        amount: 500_000,
        script: wallet.script().to_hex_string(),
        extra: Default::default(),
    });
    d
}

/// A chain of family `F` beside `parent`, matured past the genesis coinbase.
fn matured<F: HeaderFamily>(
    parent: &str,
    signer: &SecretKey,
    wallet: &PlainKey,
) -> (ChainDocument, StateOf<F>) {
    let doc = document(parent, signer, wallet);
    let mut chain = StateOf::<F>::with_key(doc.clone(), signer).unwrap();
    for i in 1..=100 {
        chain
            .produce(
                signer,
                &NextBlock {
                    time: doc.genesis_time + i,
                    claims: vec![],
                },
                None,
            )
            .unwrap();
    }
    (doc, chain)
}

fn pay(doc: &ChainDocument, coins: &[Coin], tip: u32, wallet: &PlainKey) -> Spend {
    let you = address_for(&PlainKey::new(key("you")).pubkey(), "sg").unwrap();
    build_spend(
        &SpendRequest {
            chain: doc,
            coins,
            tip_height: tip,
            to: &you,
            amount: 100_000,
            fee: None,
        },
        wallet,
        &Permissive,
    )
    .unwrap()
}

fn prevouts(wallet: &PlainKey, coins: &[Coin], tx: &Transaction) -> Vec<TxOut> {
    tx.input
        .iter()
        .map(|i| TxOut {
            value: Amount::from_sat(
                coins
                    .iter()
                    .find(|c| c.outpoint == i.previous_output)
                    .unwrap()
                    .value,
            ),
            script_pubkey: wallet.script(),
        })
        .collect()
}

fn hash_type(tx: &Transaction) -> u8 {
    tx.input[0].witness.nth(0).unwrap()[64]
}

#[test]
fn signatures_follow_the_parent_family() {
    // txsign-test 1: the BLAKE2b family uses the unified sighash, the stock family does not
    assert_eq!(
        rules_for(resolve_parent("txbt4").unwrap().family),
        SighashRules::KnotsUnified
    );
    assert_eq!(
        rules_for(resolve_parent("tbtc4").unwrap().family),
        SighashRules::Bip341
    );
    // and it is the answer each HeaderFamily gives for a sidestr chain (fork height 0)
    assert_eq!(Stock.sighash_rules(0), SighashRules::Bip341);

    let signer = key("signer");
    let wallet = PlainKey::new(key("wallet"));

    // beside txbt4: 0x21, and the chain's own mempool accepts it
    let (bdoc, mut bchain) = matured::<Blake2bV2>("txbt4", &signer, &wallet);
    assert_eq!(
        StateOf::<Blake2bV2>::family_of(&bdoc)
            .unwrap()
            .sighash_rules(0),
        SighashRules::KnotsUnified
    );
    let bcoins = from_state(&bchain, &wallet.script());
    let b = pay(&bdoc, &bcoins, bchain.height(), &wallet);
    assert_eq!(hash_type(&b.tx), 0x21, "hash types: unified is 0x21");
    let bprev = prevouts(&wallet, &bcoins, &b.tx);
    assert!(verify_taproot_key_path(&b.tx, 0, &bprev, SighashRules::KnotsUnified).is_ok());
    // txsign-test 3: a unified signature is refused beside stock Bitcoin
    assert!(verify_taproot_key_path(&b.tx, 0, &bprev, SighashRules::Bip341).is_err());

    // beside tbtc4: 0x01, and the chain's own mempool accepts it
    let (sdoc, mut schain) = matured::<Stock>("tbtc4", &signer, &wallet);
    let scoins = from_state(&schain, &wallet.script());
    let s = pay(&sdoc, &scoins, schain.height(), &wallet);
    assert_eq!(hash_type(&s.tx), 0x01, "hash types: stock is 0x01");
    let sprev = prevouts(&wallet, &scoins, &s.tx);
    assert!(verify_taproot_key_path(&s.tx, 0, &sprev, SighashRules::Bip341).is_ok());
    // txsign-test 5: a BIP 341 signature is still accepted beside a BLAKE2b parent
    assert!(verify_taproot_key_path(&s.tx, 0, &sprev, SighashRules::KnotsUnified).is_ok());

    // the mempool check is the block rule's: a stock chain refuses a unified signature at
    // the door. The wallet is handed the stock chain's coins with the BLAKE2b document,
    // so it signs 0x21 for a coin on a chain beside tbtc4.
    let wrong = pay(&bdoc, &scoins, schain.height(), &wallet);
    assert_eq!(hash_type(&wrong.tx), 0x21);
    let e = schain.submit(wrong.tx.clone()).unwrap_err().to_string();
    assert!(e.contains("sighash type"), "{e}");
    // and a BLAKE2b chain takes a 0x01 signature on its own coin
    let plain = pay(&sdoc, &bcoins, bchain.height(), &wallet);
    assert_eq!(hash_type(&plain.tx), 0x01);
    let ok = bchain.submit(plain.tx.clone()).unwrap();
    assert_eq!(ok.txid, plain.txid);
    // the family-correct ones go in, and are mined
    let ok = schain.submit(s.tx.clone()).unwrap();
    assert_eq!((ok.txid, ok.fee), (s.txid, s.fee));
    let (mined, _) = schain
        .produce(
            &signer,
            &NextBlock {
                time: sdoc.genesis_time + 101,
                claims: vec![],
            },
            None,
        )
        .unwrap();
    assert_eq!((mined.height, mined.fees), (101, s.fee));

    // --- the reference: same rules, same message, same bytes ---
    if ["SIDESTR_SIDING", "SCHEMA", "BLAKETESTNODE"]
        .iter()
        .any(|v| std::env::var(v).is_err())
    {
        eprintln!("skipped the reference half: set SIDESTR_SIDING, SCHEMA and BLAKETESTNODE");
        return;
    }
    for (doc, spend, prev, unified) in [(&bdoc, &b, &bprev, true), (&sdoc, &s, &sprev, false)] {
        let r = reference(doc, spend, prev, &wallet);
        assert_eq!(r["unified"], unified, "{r}");
        assert_eq!(r["hashTypes"][0], if unified { "21" } else { "01" }, "{r}");
        assert_eq!(r["verifyKeyPath"], true, "verifyKeyPath: {r}");
        assert_eq!(r["ownRule"], true, "the chain's own rule: {r}");
        // unified refused beside stock; BIP 341 accepted beside BLAKE2b
        assert_eq!(r["otherRule"], !unified, "the other family's rule: {r}");
        assert_eq!(r["txid"], spend.txid.to_string());
        assert_eq!(
            r["resigned"].as_str().unwrap(),
            spend.hex,
            "keyPathSighash + zero aux: the reference signs the same bytes"
        );
        let fresh: Transaction =
            deserialize(&hex::decode(r["fresh"].as_str().unwrap()).unwrap()).unwrap();
        let rules = if unified {
            SighashRules::KnotsUnified
        } else {
            SighashRules::Bip341
        };
        assert_eq!(hash_type(&fresh), hash_type(&spend.tx));
        for i in 0..fresh.input.len() {
            verify_taproot_key_path(&fresh, i, prev, rules).unwrap();
        }
        eprintln!(
            "reference agrees beside {}: hash type {}, byte-identical witness",
            doc.parent, r["hashTypes"][0]
        );
    }
}

fn reference(
    doc: &ChainDocument,
    spend: &Spend,
    prevouts: &[TxOut],
    wallet: &PlainKey,
) -> serde_json::Value {
    let dir = std::env::temp_dir().join(format!(
        "sidestr-wallet-txsign-{}-{}",
        std::process::id(),
        doc.parent
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let chain_file = dir.join("chain.json");
    std::fs::write(&chain_file, doc.to_json().unwrap()).unwrap();
    let prev: Vec<serde_json::Value> = prevouts
        .iter()
        .map(|p| {
            serde_json::json!({ "value": p.value.to_sat(), "scriptPubKey": p.script_pubkey.to_hex_string() })
        })
        .collect();
    let out = Command::new("node")
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/xcheck-wallet.mjs"))
        .arg("txsign")
        .arg(&chain_file)
        .arg(serialize_hex(&spend.tx))
        .arg(serde_json::Value::from(prev).to_string())
        .arg(hex::encode(wallet.secret_key().secret_bytes()))
        .output()
        .expect("node");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "reference engine failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("json from the reference engine")
}
