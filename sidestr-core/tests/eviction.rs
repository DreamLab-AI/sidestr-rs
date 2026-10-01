//! Producer eviction: exact replay is remembered, while a witness-only repair
//! with the same txid is judged again.

mod common;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, Message};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{TxOut, Witness};
use sidestr_core::block::{secp, Stock};
use sidestr_core::rules::{BlockContext, BlockRule};
use sidestr_core::state::{NextBlock, State};

use common::{challenge, doc, mature_coin, pay, signer, spend};

#[test]
fn exact_replay_is_refused_but_a_resigned_transaction_is_judged_again() {
    let key = signer("eviction");
    let me = challenge(&key);
    let document = doc(
        "eviction",
        &key,
        vec![("aa".repeat(32), 0, 5_000_000_000, me.clone())],
    );
    let mut state = State::with_key(document, &key).unwrap();
    while state.height() < 100 {
        state.produce(&key, &NextBlock::default(), None).unwrap();
    }

    let coin = mature_coin(&state, &key);
    let tx = spend(&key, &coin, vec![pay(coin.value - 1_000, &me)]);
    let txid = tx.compute_txid();
    state.submit(tx.clone()).unwrap();
    assert!(state.evict(txid, "sidestr:rule-test"));
    assert_eq!(state.mempool().count(), 0);
    assert_eq!(state.rejected()[&txid].why, "sidestr:rule-test");

    let error = state.submit(tx.clone()).unwrap_err().to_string();
    assert!(error.contains("rejected this session: sidestr:rule-test"));

    let mut repaired = tx;
    repaired.input[0].witness = Witness::new();
    let prevouts = [TxOut {
        value: bitcoin::Amount::from_sat(coin.value),
        script_pubkey: me,
    }];
    let sighash = SighashCache::new(&repaired)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
        .unwrap();
    let signature = secp().sign_schnorr_with_aux_rand(
        &Message::from_digest(sighash.to_byte_array()),
        &Keypair::from_secret_key(secp(), &key),
        &[1; 32],
    );
    repaired.input[0].witness = Witness::from_slice(&[signature.serialize().to_vec()]);
    assert_eq!(repaired.compute_txid(), txid);
    state.submit(repaired).unwrap();
    assert_eq!(state.mempool().count(), 1);
}

#[derive(Debug)]
struct RejectOpTrueOutput;

impl BlockRule<Stock> for RejectOpTrueOutput {
    fn id(&self) -> &str {
        "sidestr:rule-test-unblockable"
    }

    fn check(&self, ctx: &BlockContext<Stock>) -> Option<bool> {
        Some(!ctx.block.txdata.iter().skip(1).any(|tx| {
            tx.output
                .iter()
                .any(|output| output.script_pubkey.as_bytes() == [0x51])
        }))
    }
}

#[test]
fn production_evicts_a_transaction_that_only_the_block_rule_refuses() {
    let key = signer("automatic eviction");
    let me = challenge(&key);
    let document = doc(
        "automatic-eviction",
        &key,
        vec![
            ("aa".repeat(32), 0, 5_000_000_000, me.clone()),
            ("bb".repeat(32), 0, 5_000_000_000, me.clone()),
        ],
    );
    let mut state =
        State::with_key_and_rules(document, &key, vec![Box::new(RejectOpTrueOutput)]).unwrap();
    while state.height() < 100 {
        state.produce(&key, &NextBlock::default(), None).unwrap();
    }
    let coins: Vec<_> = state
        .coins(&me)
        .into_iter()
        .filter(|coin| coin.height == 0)
        .collect();
    let good = spend(&key, &coins[0], vec![pay(coins[0].value - 1_000, &me)]);
    let bad = spend(
        &key,
        &coins[1],
        vec![pay(
            coins[1].value - 1_000,
            &bitcoin::ScriptBuf::from_bytes(vec![0x51]),
        )],
    );
    let bad_id = bad.compute_txid();
    state.submit(good).unwrap();
    state.submit(bad.clone()).unwrap();

    let (applied, _) = state.produce(&key, &NextBlock::default(), None).unwrap();
    assert_eq!(
        applied.txs, 2,
        "coinbase and the transaction the block can carry"
    );
    assert_eq!(state.mempool().count(), 0);
    assert_eq!(
        state.rejected()[&bad_id].why,
        "sidestr:rule-test-unblockable"
    );
    assert!(state
        .submit(bad)
        .unwrap_err()
        .to_string()
        .contains("rejected this session"));
}
