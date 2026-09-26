//! `sidestr-wallet`'s EVM deposit against this rule. The wallet does not
//! depend on this crate (revm stays out of it), so it writes the marker and
//! reads the reserve through `sidestr-core`; here the two halves are held
//! together: `sidestr_core::marker::evm_deposit_marker` writes the bytes
//! [`deposit_script`] writes and [`parse_deposit`] reads,
//! `ChainDocument::evm_reserve` names the script [`EvmConfig`] credits, and
//! a deposit built by `sidestr_wallet::deposit::build_evm_deposit` passes the
//! producer's check, is mined, and credits the address at 1 sat = 1 gwei on
//! the producer and on a validator that shares nothing with it but the
//! blocks — with the reserve from the challenge and from `evm.reserve`.

use alloy_primitives::{Address, U256};
use bitcoin::secp256k1::SecretKey;
use sidestr_core::block::{challenge_for, pubkey_of};
use sidestr_core::marker::evm_deposit_marker;
use sidestr_core::state::{NextBlock, State};
use sidestr_core::ChainDocument;
use sidestr_evm::records::{deposit_script, parse_deposit, GWEI};
use sidestr_evm::{rules_for, EvmConfig};
use sidestr_wallet::coins::from_state;
use sidestr_wallet::deposit::{build_evm_deposit, DepositRequest};
use sidestr_wallet::{Permissive, PlainKey, SpendSigner};

/// A chain naming the rule whose genesis pegs one coin to `wallet`; `evm`
/// is the document's `evm` section.
fn doc_for(key: &SecretKey, wallet: &PlainKey, evm: serde_json::Value) -> ChainDocument {
    let me = challenge_for(&pubkey_of(key)).to_hex_string();
    serde_json::from_value(serde_json::json!({
        "id": "sidestr:evmdeposit", "name": "evmdeposit", "parent": "tbtc4", "challenge": me,
        "signer": pubkey_of(key).to_string(),
        "powLimit": "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "addressPrefix": "evd", "genesisTime": 1790000000u32, "rules": ["evm"], "evm": evm,
        "pegs": [{ "txid": "a".repeat(64), "vout": 0, "amount": 2_000_000u64, "script": wallet.script().to_hex_string() }],
    }))
    .unwrap()
}

#[test]
fn the_wallet_and_the_rule_agree_on_the_marker_and_the_reserve() {
    for bytes in [[0u8; 20], [0xff; 20], *Address::repeat_byte(0x42).0, {
        let mut b = [0u8; 20];
        b.iter_mut().enumerate().for_each(|(i, x)| *x = i as u8);
        b
    }] {
        let a = Address::from(bytes);
        assert_eq!(evm_deposit_marker(&bytes), deposit_script(a));
        assert_eq!(parse_deposit(&evm_deposit_marker(&bytes)), Some(a));
    }
    let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let wallet = PlainKey::new(SecretKey::from_slice(&[8u8; 32]).unwrap());
    for evm in [
        serde_json::Value::Null,
        serde_json::json!({ "chainId": 21474 }),
        serde_json::json!({ "reserve": "5120ABCDEF" }),
        serde_json::json!({ "reserve": null }),
    ] {
        let doc = doc_for(&key, &wallet, evm.clone());
        assert_eq!(
            doc.evm_reserve().unwrap(),
            EvmConfig::from_document(&doc).unwrap().reserve,
            "{evm}"
        );
    }
    // what the rule refuses to read, the accessor refuses too
    for evm in [
        serde_json::json!("21474"),
        serde_json::json!({ "reserve": 5 }),
        serde_json::json!({ "reserve": "zz" }),
    ] {
        let doc = doc_for(&key, &wallet, evm.clone());
        assert!(doc.evm_reserve().is_err(), "{evm}");
        assert!(EvmConfig::from_document(&doc).is_err(), "{evm}");
    }
}

fn deposit_on_a_chain(evm: serde_json::Value) {
    let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let wallet = PlainKey::new(SecretKey::from_slice(&[8u8; 32]).unwrap());
    let doc = doc_for(&key, &wallet, evm);
    let rules = rules_for(&doc).unwrap();
    let mut state = State::with_key_and_rules(doc.clone(), &key, rules.boxed()).unwrap();
    let follower_rules = rules_for(&doc).unwrap();
    let mut follower = State::from_genesis_with_rules(
        doc.clone(),
        &State::genesis_block_for(&doc, &key).unwrap(),
        None,
        follower_rules.boxed(),
    )
    .unwrap();
    let mut time = 1_790_000_000;
    let mut produce = |state: &mut State, follower: &mut State| {
        time += 60;
        let made = rules
            .produce(
                state,
                &key,
                &NextBlock {
                    time,
                    claims: vec![],
                },
                None,
            )
            .unwrap();
        assert!(made.dropped.is_empty(), "{:?}", made.dropped);
        follower.add_block(&made.block, None, None).unwrap();
    };
    // the genesis coin matures
    for _ in 0..100 {
        produce(&mut state, &mut follower);
    }

    let alice = Address::repeat_byte(0x42);
    let to = alice.to_string();
    let coins = from_state(&state, &wallet.script());
    let d = build_evm_deposit(
        &DepositRequest {
            chain: &doc,
            coins: &coins,
            tip_height: state.height(),
            to: &to,
            amount: 1_234_567,
            fee: None,
        },
        &wallet,
        &Permissive,
    )
    .unwrap();
    assert_eq!(
        d.tx.output[0].script_pubkey,
        rules.evm.as_ref().unwrap().state().config().reserve
    );

    // the producer's EVM check, then its mempool, then a block; the validator follows
    let next = state.height() + 1;
    let checked = rules
        .evm
        .as_ref()
        .unwrap()
        .state()
        .check_tx(&d.tx, next, state.tip().time + 60);
    assert!(checked.error.is_none(), "{:?}", checked.error);
    let ok = state.submit(d.tx.clone()).unwrap();
    assert_eq!((ok.txid, ok.fee), (d.txid, d.fee));
    produce(&mut state, &mut follower);
    assert_eq!(follower.tip(), state.tip());

    let credited = U256::from(1_234_567u64) * U256::from(GWEI);
    for evm in [
        rules.evm.as_ref().unwrap().state(),
        follower_rules.evm.as_ref().unwrap().state(),
    ] {
        assert_eq!(evm.balance(&alice), credited);
    }
    // the change came back to the wallet
    let left = from_state(&follower, &wallet.script());
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].value, d.change);
}

#[test]
fn a_wallet_deposit_credits_the_address() {
    deposit_on_a_chain(serde_json::json!({ "chainId": 21474 }));
}

#[test]
fn a_wallet_deposit_pays_evm_reserve_when_the_document_names_one() {
    let reserve = challenge_for(&pubkey_of(&SecretKey::from_slice(&[9u8; 32]).unwrap()));
    deposit_on_a_chain(serde_json::json!({ "reserve": reserve.to_hex_string() }));
}
