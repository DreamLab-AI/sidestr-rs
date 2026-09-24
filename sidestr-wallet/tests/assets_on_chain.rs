//! Issued assets end to end on a chain in memory: issue, transfer with a
//! memo, pay plain sats beside carriers, each through the producer's own
//! mempool check (`State::submit`) and into a block, and the view rebuilt
//! from the block file bytes by `State::replay_with` exactly as a browser
//! reading a mirror does.

use bitcoin::secp256k1::SecretKey;
use bitcoin::OutPoint;
use sidestr_core::assets::AssetView;
use sidestr_core::block::{challenge_for, pubkey_of, SidestrBlock};
use sidestr_core::document::{ChainDocument, Peg};
use sidestr_core::mirror::encode_record;
use sidestr_core::records::records_of;
use sidestr_core::state::{NextBlock, State};
use sidestr_wallet::asset::{
    balance_of, build_issue, build_transfer, plain_coins, IssueRequest, TransferRequest, CARRIER,
};
use sidestr_wallet::coins::{from_state, Coin};
use sidestr_wallet::key::PlainKey;
use sidestr_wallet::spend::{build_spend, SpendRequest};
use sidestr_wallet::{Error, Permissive, SpendSigner};

struct World {
    doc: ChainDocument,
    producer: SecretKey,
    chain: State,
    dat: Vec<u8>,
    view: AssetView,
    time: u32,
}

impl World {
    fn new(alice: &PlainKey) -> Self {
        let producer = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let json = format!(
            r#"{{"id":"sidestr:example","name":"example","parent":"tbtc4","challenge":"{}",
            "powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","addressPrefix":"ex",
            "genesisTime":1790000000,"signer":"{}","pegs":[],"minFeeRate":1}}"#,
            challenge_for(&pubkey_of(&producer)).to_hex_string(),
            pubkey_of(&producer)
        );
        let mut doc = ChainDocument::from_json(&json).unwrap();
        doc.pegs.push(Peg {
            txid: "a".repeat(64),
            vout: 0,
            amount: 100_000,
            script: alice.script().to_hex_string(),
            extra: Default::default(),
        });
        let genesis = State::genesis_block_for(&doc, &producer).unwrap();
        let dat = encode_record(0, &genesis.encode());
        let chain = State::from_genesis(doc.clone(), &genesis, None).unwrap();
        let mut w = Self {
            doc,
            producer,
            chain,
            dat,
            view: AssetView::new(),
            time: 1_790_000_000,
        };
        w.view.apply_transactions(&genesis.txdata, 0);
        for _ in 0..100 {
            w.block();
        }
        w
    }

    fn block(&mut self) {
        self.time += 1;
        let (applied, block) = self
            .chain
            .produce(
                &self.producer,
                &NextBlock {
                    time: self.time,
                    claims: vec![],
                },
                None,
            )
            .unwrap();
        self.view.apply_transactions(&block.txdata, applied.height);
        self.dat
            .extend(encode_record(applied.height, &block.encode()));
    }

    fn coins(&self, k: &PlainKey) -> Vec<Coin> {
        from_state(&self.chain, &k.script())
    }

    fn mine(&mut self, tx: bitcoin::Transaction) {
        self.chain
            .submit(tx)
            .expect("the producer's mempool accepts it");
        self.block();
    }
}

fn key(b: u8) -> PlainKey {
    PlainKey::new(SecretKey::from_slice(&[b; 32]).unwrap())
}

#[test]
fn issue_tip_and_pay_plain_all_pass_the_producer_and_replay_the_same() {
    let alice = key(1);
    let bob = key(2);
    let mut w = World::new(&alice);

    // alice issues DREAM
    let issue = build_issue(
        &IssueRequest {
            chain: &w.doc,
            coins: &w.coins(&alice),
            view: &w.view,
            tip_height: w.chain.height(),
            ticker: "DREAM",
            decimals: 0,
            supply: 1_000_000,
            to: None,
            fee: None,
        },
        &alice,
        &Permissive,
    )
    .unwrap();
    let dream = issue.txid;
    w.mine(issue.tx);
    assert_eq!(balance_of(&w.coins(&alice), &w.view, &dream), 1_000_000);

    // alice tips bob 250 DREAM on a post
    let memo = format!("tip:nostr:{}", "e1".repeat(32));
    let t = build_transfer(
        &TransferRequest {
            chain: &w.doc,
            coins: &w.coins(&alice),
            view: &w.view,
            tip_height: w.chain.height(),
            asset: dream,
            to: &bob.script().to_hex_string(),
            amount: 250,
            memos: std::slice::from_ref(&memo),
            fee: None,
        },
        &alice,
        &Permissive,
    )
    .unwrap();
    assert!(records_of(&t.spend.tx).iter().any(|(_, r)| *r == memo));
    let tip_txid = t.spend.txid;
    w.mine(t.spend.tx);
    assert_eq!(balance_of(&w.coins(&bob), &w.view, &dream), 250);
    assert_eq!(balance_of(&w.coins(&alice), &w.view, &dream), 999_750);
    assert_eq!(
        w.coins(&bob)
            .iter()
            .find(|c| c.outpoint
                == OutPoint {
                    txid: tip_txid,
                    vout: 0
                })
            .unwrap()
            .value,
        CARRIER
    );

    // alice pays plain sats: only plain coins are offered, so the carrier survives
    let pay = build_spend(
        &SpendRequest {
            chain: &w.doc,
            coins: &plain_coins(&w.coins(&alice), &w.view),
            tip_height: w.chain.height(),
            to: &bob.script().to_hex_string(),
            amount: 5_000,
            fee: None,
        },
        &alice,
        &Permissive,
    )
    .unwrap();
    w.mine(pay.tx);
    assert_eq!(balance_of(&w.coins(&alice), &w.view, &dream), 999_750);

    // bob, holding only a carrier, cannot move DREAM without plain sats for the fee…
    // …but he has the 5,000 alice sent, so he passes 100 on
    let back = build_transfer(
        &TransferRequest {
            chain: &w.doc,
            coins: &w.coins(&bob),
            view: &w.view,
            tip_height: w.chain.height(),
            asset: dream,
            to: &alice.script().to_hex_string(),
            amount: 100,
            memos: &[],
            fee: None,
        },
        &bob,
        &Permissive,
    )
    .unwrap();
    w.mine(back.spend.tx);
    assert_eq!(balance_of(&w.coins(&bob), &w.view, &dream), 150);

    // a browser replays the block file and reaches the same balances
    let mut replayed = AssetView::new();
    let state = State::replay_with(w.doc.clone(), &w.dat, None, |_, h, block| {
        replayed.apply_transactions(&block.txdata, h);
    })
    .unwrap();
    assert_eq!(state.tip(), w.chain.tip());
    for k in [&alice, &bob] {
        let coins = from_state(&state, &k.script());
        assert_eq!(
            balance_of(&coins, &replayed, &dream),
            balance_of(&w.coins(k), &w.view, &dream)
        );
    }
    assert_eq!(replayed.issued()[&dream].supply, 1_000_000);
}

#[test]
fn a_transfer_refuses_what_it_cannot_do() {
    let alice = key(1);
    let mut w = World::new(&alice);
    let issue = build_issue(
        &IssueRequest {
            chain: &w.doc,
            coins: &w.coins(&alice),
            view: &w.view,
            tip_height: w.chain.height(),
            ticker: "DREAM",
            decimals: 0,
            supply: 10,
            to: None,
            fee: None,
        },
        &alice,
        &Permissive,
    )
    .unwrap();
    let dream = issue.txid;
    w.mine(issue.tx);
    let req = |amount, memos: &'static [String]| TransferRequest {
        chain: &w.doc,
        coins: Box::leak(w.coins(&alice).into_boxed_slice()),
        view: &w.view,
        tip_height: w.chain.height(),
        asset: dream,
        to: "5120ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        amount,
        memos,
        fee: None,
    };
    assert!(matches!(
        build_transfer(&req(11, &[]), &alice, &Permissive),
        Err(Error::Asset(_))
    ));
    let bad: &'static [String] = Box::leak(vec!["tally:self:0=1".to_string()].into_boxed_slice());
    assert!(matches!(
        build_transfer(&req(1, bad), &alice, &Permissive),
        Err(Error::Asset(_))
    ));
    assert!(matches!(
        build_issue(
            &IssueRequest {
                chain: &w.doc,
                coins: &w.coins(&alice),
                view: &w.view,
                tip_height: w.chain.height(),
                ticker: "dream",
                decimals: 0,
                supply: 1,
                to: None,
                fee: None,
            },
            &alice,
            &Permissive
        ),
        Err(Error::Asset(_))
    ));
    // the whole balance, no asset change output
    let all = build_transfer(&req(10, &[]), &alice, &Permissive).unwrap();
    assert_eq!(all.asset_change, 0);
    w.mine(all.spend.tx);
    assert_eq!(balance_of(&w.coins(&alice), &w.view, &dream), 0);
}
