//! Whole-chain coverage for the pool and prediction-market overlays, porting
//! the consensus path exercised by siding's `rules-test.mjs` and
//! `markets-test.mjs`.

use bitcoin::secp256k1::{Keypair, Message, SecretKey};
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, Block, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use sidestr_core::block::{
    build_block, challenge_for, pubkey_of, secp, sign_block, BlockTemplate, HeaderFamily, MARKER,
};
use sidestr_core::document::RuleEntry;
use sidestr_core::markets::{no_id_of, MarketStatus};
use sidestr_core::mirror::encode_record;
use sidestr_core::records::record_script;
use sidestr_core::sighash::key_path_sighash;
use sidestr_core::state::{CoinRef, NextBlock, State};
use sidestr_core::{ChainDocument, Error as CoreError};
use sidestr_evm::{rules_for, Rules};

#[derive(Clone)]
struct SpendInput {
    outpoint: OutPoint,
    prevout: TxOut,
    key: Option<SecretKey>,
}

struct TestChain {
    key: SecretKey,
    resolver: SecretKey,
    me: ScriptBuf,
    resolver_script: ScriptBuf,
    doc: ChainDocument,
    rules: Rules,
    state: State,
    blocks: Vec<Block>,
    time: u32,
}

impl TestChain {
    fn new() -> Self {
        let key = SecretKey::from_slice(&[7; 32]).unwrap();
        let resolver = SecretKey::from_slice(&[9; 32]).unwrap();
        let me = challenge_for(&pubkey_of(&key));
        let resolver_script = challenge_for(&pubkey_of(&resolver));
        let doc: ChainDocument = serde_json::from_value(serde_json::json!({
            "id": "sidestr:markets-rust",
            "name": "markets-rust",
            "parent": "tbtc4",
            "challenge": me.to_hex_string(),
            "signer": pubkey_of(&key).to_string(),
            "powLimit": "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "addressPrefix": "pm",
            "genesisTime": 1_790_000_000,
            "rules": ["assets", "pool", { "name": "markets", "from": 0 }],
            "pegs": [{
                "txid": "aa".repeat(32), "vout": 0,
                "amount": 5_000_000_000u64, "script": me.to_hex_string()
            }]
        }))
        .unwrap();
        let rules = rules_for(&doc).unwrap();
        let state = State::with_key_and_rules(doc.clone(), &key, rules.boxed()).unwrap();
        let genesis = State::genesis_block_for(&doc, &key).unwrap();
        Self {
            key,
            resolver,
            me,
            resolver_script,
            doc,
            rules,
            state,
            blocks: vec![genesis],
            time: 1_790_000_000,
        }
    }

    fn produce(&mut self) -> Block {
        self.time += 60;
        let made = self
            .rules
            .produce(
                &mut self.state,
                &self.key,
                &NextBlock {
                    time: self.time,
                    claims: vec![],
                },
                None,
            )
            .unwrap();
        assert!(made.dropped.is_empty(), "{:?}", made.dropped);
        self.blocks.push(made.block.clone());
        made.block
    }

    fn mature(&mut self) {
        while self.state.height() < 101 {
            self.produce();
        }
    }

    fn plain_coin(&self, script: &ScriptBuf) -> CoinRef {
        let assets = self.rules.assets.as_ref().unwrap().view();
        self.state
            .coins(script)
            .into_iter()
            .filter(|coin| {
                (!coin.coinbase || self.state.height() + 1 - coin.height >= 100)
                    && assets.carried(&coin.outpoint).is_none()
            })
            .max_by_key(|coin| coin.value)
            .expect("a plain spendable coin")
    }

    fn owned_input(&self, coin: &CoinRef, script: &ScriptBuf, key: SecretKey) -> SpendInput {
        SpendInput {
            outpoint: coin.outpoint,
            prevout: TxOut {
                value: Amount::from_sat(coin.value),
                script_pubkey: script.clone(),
            },
            key: Some(key),
        }
    }

    fn known_input(
        &self,
        outpoint: OutPoint,
        output: &TxOut,
        key: Option<SecretKey>,
    ) -> SpendInput {
        SpendInput {
            outpoint,
            prevout: output.clone(),
            key,
        }
    }

    fn spend(
        &self,
        inputs: Vec<SpendInput>,
        mut outputs: Vec<TxOut>,
        change_script: &ScriptBuf,
    ) -> Transaction {
        let input_value: u64 = inputs
            .iter()
            .map(|input| input.prevout.value.to_sat())
            .sum();
        let output_value: u64 = outputs.iter().map(|output| output.value.to_sat()).sum();
        let change = input_value
            .checked_sub(output_value + 5_000)
            .expect("inputs cover outputs and fee");
        if change > 0 {
            outputs.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: change_script.clone(),
            });
        }
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .map(|input| TxIn {
                    previous_output: input.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence(0xffff_fffd),
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs,
        };
        let prevouts: Vec<TxOut> = inputs.iter().map(|input| input.prevout.clone()).collect();
        let sighash = self.state.family().sighash_rules(self.state.height() + 1);
        for (index, input) in inputs.iter().enumerate() {
            let Some(key) = input.key else { continue };
            let (message, hash_type) = key_path_sighash(&tx, index, &prevouts, sighash).unwrap();
            let keypair = Keypair::from_secret_key(secp(), &key);
            let signature = secp().sign_schnorr_with_aux_rand(
                &Message::from_digest(message),
                &keypair,
                &[0; 32],
            );
            tx.input[index].witness =
                Witness::from_slice(&[[signature.serialize().as_slice(), &[hash_type]].concat()]);
        }
        tx
    }

    fn submit_and_produce(&mut self, tx: Transaction) -> Txid {
        let txid = tx.compute_txid();
        self.state.submit(tx).unwrap();
        self.produce();
        txid
    }

    fn candidate(&self, tx: Transaction) -> Block {
        let tip = self.state.tip();
        let block = build_block(
            self.state.family(),
            &BlockTemplate {
                height: tip.height + 1,
                prev: tip.hash,
                time: tip.time + 1,
                transactions: vec![tx],
                outputs: vec![TxOut {
                    value: Amount::from_sat(5_000),
                    script_pubkey: self.me.clone(),
                }],
                bits: self.state.bits(),
                marker: MARKER.into(),
            },
        );
        sign_block(self.state.family(), &block, &self.me, &self.key, &[0; 32]).unwrap()
    }
}

fn pay(value: u64, script: &ScriptBuf) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: script.clone(),
    }
}

fn op_true(value: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    }
}

fn record(text: &str) -> TxOut {
    TxOut {
        value: Amount::ZERO,
        script_pubkey: record_script(text).unwrap(),
    }
}

#[test]
fn pools_and_markets_validate_end_to_end_and_replay_from_activation() {
    let mut chain = TestChain::new();
    chain.mature();

    // Issue one million SHELL.
    let coin = chain.plain_coin(&chain.me);
    let issue = chain.spend(
        vec![chain.owned_input(&coin, &chain.me, chain.key)],
        vec![
            pay(1_000, &chain.me),
            record("issue:SHELL:0"),
            record("tally:self:0=1000000"),
        ],
        &chain.me,
    );
    let shell = chain.submit_and_produce(issue);
    let shell_coin = OutPoint {
        txid: shell,
        vout: 0,
    };
    let shell_output = pay(1_000, &chain.me);

    // Open a pool with 1,000,000 sats and 600,000 SHELL. sqrt(x*y)=774,596.
    let plain = chain.plain_coin(&chain.me);
    let open_outputs = |shares| {
        vec![
            op_true(1_000_000),
            pay(1_000, &chain.me),
            pay(1_000, &chain.me),
            record("pool:self:0"),
            record(&format!("tally:{shell}:0=600000,2=400000")),
            record(&format!("tally:self:1={shares}")),
        ]
    };
    let bad_open_outputs = open_outputs(1);
    let good_open_outputs = open_outputs(774_596);
    let bad_open = chain.spend(
        vec![
            chain.known_input(shell_coin, &shell_output, Some(chain.key)),
            chain.owned_input(&plain, &chain.me, chain.key),
        ],
        bad_open_outputs,
        &chain.me,
    );
    match chain
        .state
        .add_block(&chain.candidate(bad_open), None, None)
        .unwrap_err()
    {
        CoreError::Rejected { rules, .. } => {
            assert!(rules.contains(&"sidestr:rule-pool".to_string()))
        }
        error => panic!("{error}"),
    }
    let open = chain.spend(
        vec![
            chain.known_input(shell_coin, &shell_output, Some(chain.key)),
            chain.owned_input(&plain, &chain.me, chain.key),
        ],
        good_open_outputs,
        &chain.me,
    );
    let pool = chain.submit_and_produce(open);
    let p = chain.rules.pool.as_ref().unwrap().view();
    assert_eq!(
        (
            p.get(&pool).unwrap().sats,
            p.get(&pool).unwrap().assets,
            p.get(&pool).unwrap().shares
        ),
        (1_000_000, 600_000, 774_596)
    );

    // Swap 100,000 sats for 54,000 SHELL; the fee-adjusted product grows.
    let before = p.get(&pool).unwrap().clone();
    let plain = chain.plain_coin(&chain.me);
    let swap = chain.spend(
        vec![
            chain.owned_input(&plain, &chain.me, chain.key),
            chain.known_input(before.outpoint, &op_true(before.sats), None),
        ],
        vec![
            op_true(1_100_000),
            pay(1_000, &chain.me),
            record(&format!("pool:{pool}:0")),
            record(&format!("tally:{shell}:0=546000,1=54000")),
        ],
        &chain.me,
    );
    chain.submit_and_produce(swap);
    let p = chain.rules.pool.as_ref().unwrap().view();
    assert_eq!(
        (p.get(&pool).unwrap().sats, p.get(&pool).unwrap().assets),
        (1_100_000, 546_000)
    );

    // Give the resolver a signed coin, then open a market.
    let plain = chain.plain_coin(&chain.me);
    let fund_resolver = chain.spend(
        vec![chain.owned_input(&plain, &chain.me, chain.key)],
        vec![pay(100_000, &chain.resolver_script)],
        &chain.me,
    );
    let resolver_funding = chain.submit_and_produce(fund_resolver);
    let resolver_coin = OutPoint {
        txid: resolver_funding,
        vout: 0,
    };
    let resolver_output = pay(100_000, &chain.resolver_script);

    let open_height = chain.state.height() + 1;
    let expiry = open_height + 20;
    let plain = chain.plain_coin(&chain.me);
    let open_market = chain.spend(
        vec![chain.owned_input(&plain, &chain.me, chain.key)],
        vec![
            op_true(1),
            record(&format!(
                "market:self:0:{}:{expiry}:5",
                pubkey_of(&chain.resolver)
            )),
            record("question:Will it rain in Prague on 1 October 2026?"),
        ],
        &chain.me,
    );
    let market = chain.submit_and_produce(open_market);
    let no = no_id_of(&market);
    let view = chain.rules.markets.as_ref().unwrap().view();
    assert_eq!(view.get(&market).unwrap().status, MarketStatus::Open);
    let assets = chain.rules.assets.as_ref().unwrap().view();
    assert_eq!(assets.issued()[&market].ticker, "YES");
    assert_eq!(assets.issued()[&no].ticker, "NO");
    assert_eq!(assets.issued()[&no].market, Some(market));

    // A split mints exactly one YES and one NO per added sat.
    let market_coin = view.get(&market).unwrap().coin;
    let plain = chain.plain_coin(&chain.me);
    let split_outputs = |yes| {
        vec![
            op_true(1_001),
            pay(1_000, &chain.me),
            pay(1_000, &chain.me),
            record(&format!("split:{market}:0")),
            record(&format!("tally:{market}:1={yes}")),
            record(&format!("tally:{no}:2=1000")),
        ]
    };
    let bad_split_outputs = split_outputs(999);
    let good_split_outputs = split_outputs(1_000);
    let split_inputs = vec![
        chain.owned_input(&plain, &chain.me, chain.key),
        chain.known_input(market_coin, &op_true(1), None),
    ];
    let bad_split = chain.spend(split_inputs.clone(), bad_split_outputs, &chain.me);
    match chain
        .state
        .add_block(&chain.candidate(bad_split), None, None)
        .unwrap_err()
    {
        CoreError::Rejected { rules, .. } => {
            assert!(rules.contains(&"sidestr:rule-markets".to_string()))
        }
        error => panic!("{error}"),
    }
    let split = chain.spend(split_inputs, good_split_outputs, &chain.me);
    let split_id = chain.submit_and_produce(split);
    let assets = chain.rules.assets.as_ref().unwrap().view();
    assert_eq!(
        assets
            .carried(&OutPoint {
                txid: split_id,
                vout: 1,
            })
            .unwrap()[&market],
        1_000
    );
    assert_eq!(
        assets
            .carried(&OutPoint {
                txid: split_id,
                vout: 2,
            })
            .unwrap()[&no],
        1_000
    );

    // The resolver spends its own coin and preserves collateral to answer YES.
    let market_coin = chain
        .rules
        .markets
        .as_ref()
        .unwrap()
        .view()
        .get(&market)
        .unwrap()
        .coin;
    let resolve = chain.spend(
        vec![
            chain.known_input(resolver_coin, &resolver_output, Some(chain.resolver)),
            chain.known_input(market_coin, &op_true(1_001), None),
        ],
        vec![op_true(1_001), record(&format!("resolve:{market}:yes"))],
        &chain.resolver_script,
    );
    chain.submit_and_produce(resolve);
    let market_state = chain.rules.markets.as_ref().unwrap().view();
    assert_eq!(
        market_state.get(&market).unwrap().status,
        MarketStatus::Resolved
    );

    // 1,000 YES releases 1,000 sats; the NO supply remains worthless.
    let market_coin = market_state.get(&market).unwrap().coin;
    let plain = chain.plain_coin(&chain.me);
    let redeem = chain.spend(
        vec![
            chain.known_input(
                OutPoint {
                    txid: split_id,
                    vout: 1,
                },
                &pay(1_000, &chain.me),
                Some(chain.key),
            ),
            chain.owned_input(&plain, &chain.me, chain.key),
            chain.known_input(market_coin, &op_true(1_001), None),
        ],
        vec![op_true(1), record(&format!("redeem:{market}:0"))],
        &chain.me,
    );
    chain.submit_and_produce(redeem);
    assert_eq!(
        chain
            .rules
            .markets
            .as_ref()
            .unwrap()
            .view()
            .get(&market)
            .unwrap()
            .collateral,
        1
    );

    // A fresh validator may adopt markets exactly at the opening height.
    let data: Vec<u8> = chain
        .blocks
        .iter()
        .enumerate()
        .flat_map(|(height, block)| {
            encode_record(height as u32, &bitcoin::consensus::serialize(block))
        })
        .collect();
    let mut activated = chain.doc.clone();
    activated.rules = Some(vec![
        "assets".into(),
        "pool".into(),
        RuleEntry::Activated {
            name: "markets".into(),
            from: open_height,
        },
    ]);
    let replay_rules = rules_for(&activated).unwrap();
    let replayed = State::replay_with_rules(activated, &data, None, replay_rules.boxed()).unwrap();
    assert_eq!(replayed.tip(), chain.state.tip());
    assert_eq!(
        replay_rules
            .markets
            .as_ref()
            .unwrap()
            .view()
            .get(&market)
            .unwrap()
            .status,
        MarketStatus::Resolved
    );

    // Starting one block late ignores the opening; the split then attempts
    // to mint assets from nothing and is refused by asset conservation.
    let mut late = chain.doc.clone();
    late.rules = Some(vec![
        "assets".into(),
        "pool".into(),
        RuleEntry::Activated {
            name: "markets".into(),
            from: open_height + 1,
        },
    ]);
    let late_rules = rules_for(&late).unwrap();
    let error = State::replay_with_rules(late, &data, None, late_rules.boxed()).unwrap_err();
    assert!(error.to_string().contains("sidestr:rule-assets"), "{error}");
}
