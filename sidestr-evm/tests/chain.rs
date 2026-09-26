//! The rule on a whole chain, through `sidestr-core`: `siding/test/evm-test.mjs`
//! step for step, with a producer and a validator that shares nothing with
//! it but the blocks. A deposit credits at 1 sat = 1 gwei; a carried
//! transfer runs; a contract deploys and answers a call; a withdrawal is
//! paid by the coinbase; a block committing the wrong root is refused, and
//! so is one that pays itself what no withdrawal allows; the mempool check
//! refuses a deposit without its payment; replaying the block file reaches
//! the same state.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use bitcoin::consensus::encode::serialize;
use bitcoin::secp256k1::{Keypair, Message, SecretKey};
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, Block, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Witness,
};
use sidestr_core::block::{
    build_block, challenge_for, pubkey_of, secp, sign_block, BlockTemplate, HeaderFamily, MARKER,
};
use sidestr_core::mirror::encode_record;
use sidestr_core::records::record_script;
use sidestr_core::sighash::key_path_sighash;
use sidestr_core::state::{NextBlock, State};
use sidestr_core::{ChainDocument, Error as CoreError};
use sidestr_evm::records::{carrier_script, deposit_script, root_script, GWEI, WITHDRAW};
use sidestr_evm::{rules_for, Rules, KNOWN};

const CHAIN_ID: u64 = 21_474;

struct Chain {
    key: SecretKey,
    me: ScriptBuf,
    doc: ChainDocument,
    rules: Rules,
    state: State,
    follower_rules: Rules,
    follower: State,
    blocks: Vec<Block>,
    time: u32,
}

fn doc_for(key: &SecretKey, rules: &str) -> ChainDocument {
    let me = challenge_for(&pubkey_of(key));
    let text = format!(
        r#"{{"id": "sidestr:evmtest", "name": "evmtest", "parent": "tbtc4", "challenge": "{me}", "signer": "{pk}",
        "powLimit": "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "addressPrefix": "evt", "genesisTime": 1790000000, "rules": {rules},
        "evm": {{ "chainId": {CHAIN_ID}, "gasLimit": 30000000 }},
        "pegs": [{{ "txid": "{peg}", "vout": 0, "amount": 5000000000, "script": "{me}" }}]}}"#,
        me = me.to_hex_string(),
        pk = pubkey_of(key),
        peg = "a".repeat(64),
    );
    serde_json::from_str(&text).unwrap()
}

impl Chain {
    fn new() -> Self {
        let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let me = challenge_for(&pubkey_of(&key));
        let doc = doc_for(&key, r#"["evm"]"#);
        let rules = rules_for(&doc).unwrap();
        let state = State::with_key_and_rules(doc.clone(), &key, rules.boxed()).unwrap();
        let genesis = State::genesis_block_for(&doc, &key).unwrap();
        let follower_rules = rules_for(&doc).unwrap();
        let follower =
            State::from_genesis_with_rules(doc.clone(), &genesis, None, follower_rules.boxed())
                .unwrap();
        Self {
            key,
            me,
            doc,
            rules,
            state,
            follower_rules,
            follower,
            blocks: vec![genesis],
            time: 1_790_000_000,
        }
    }

    fn evm(&self) -> std::sync::MutexGuard<'_, sidestr_evm::EvmState> {
        self.rules.evm.as_ref().unwrap().state()
    }

    fn follower_evm(&self) -> std::sync::MutexGuard<'_, sidestr_evm::EvmState> {
        self.follower_rules.evm.as_ref().unwrap().state()
    }

    /// Produce the next block and hand it to the validator.
    fn produce(&mut self) -> Vec<(bitcoin::Txid, String)> {
        self.time += 60;
        let next = NextBlock {
            time: self.time,
            claims: vec![],
        };
        let made = self
            .rules
            .produce(&mut self.state, &self.key, &next, None)
            .unwrap();
        let (block, dropped) = (made.block, made.dropped);
        self.follower.add_block(&block, None, None).unwrap();
        self.blocks.push(block);
        assert_eq!(self.follower.tip(), self.state.tip());
        assert_eq!(self.follower_evm().root(), self.evm().root());
        dropped
    }

    /// A signed spend of the largest mature coin not in the mempool, paying
    /// `outputs` then change.
    fn spend(&self, outputs: Vec<TxOut>) -> Transaction {
        let reserved: Vec<_> = self
            .state
            .mempool()
            .flat_map(|t| t.input.iter().map(|i| i.previous_output))
            .collect();
        let coin = self
            .state
            .coins(&self.me)
            .into_iter()
            .filter(|c| {
                !reserved.contains(&c.outpoint)
                    && (!c.coinbase || self.state.height() + 1 - c.height >= 100)
            })
            .max_by_key(|c| c.value)
            .expect("a mature coin");
        let total: u64 = outputs.iter().map(|o| o.value.to_sat()).sum();
        let mut output = outputs;
        output.push(TxOut {
            value: Amount::from_sat(coin.value - total - 5_000),
            script_pubkey: self.me.clone(),
        });
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: coin.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xffff_fffd),
                witness: Witness::new(),
            }],
            output,
        };
        let prevouts = [TxOut {
            value: Amount::from_sat(coin.value),
            script_pubkey: self.me.clone(),
        }];
        let rules = self.state.family().sighash_rules(self.state.height() + 1);
        let (msg, ht) = key_path_sighash(&tx, 0, &prevouts, rules).unwrap();
        let kp = Keypair::from_secret_key(secp(), &self.key);
        let sig = secp().sign_schnorr_with_aux_rand(&Message::from_digest(msg), &kp, &[0; 32]);
        tx.input[0].witness = Witness::from_slice(&[[sig.serialize().as_slice(), &[ht]].concat()]);
        tx
    }

    /// Through the producer's EVM check first, as `siding submit` does, then its mempool.
    fn submit(&mut self, tx: Transaction) -> Result<(), String> {
        let o = self
            .evm()
            .check_tx(&tx, self.state.height() + 1, self.time + 60);
        if let Some(e) = o.error {
            return Err(e);
        }
        self.state.submit(tx).map(|_| ()).map_err(|e| e.to_string())
    }

    /// A block built by hand on the tip: `txs`, a coinbase of `outputs`, sealed.
    fn hand_built(&self, txs: Vec<Transaction>, outputs: Vec<TxOut>) -> Block {
        let tip = self.state.tip();
        let block = build_block(
            self.state.family(),
            &BlockTemplate {
                height: tip.height + 1,
                prev: tip.hash,
                time: tip.time + 1,
                transactions: txs,
                outputs,
                bits: self.state.bits(),
                marker: MARKER.to_string(),
            },
        );
        sign_block(self.state.family(), &block, &self.me, &self.key, &[0; 32]).unwrap()
    }
}

fn signer(byte: u8) -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::repeat_byte(byte)).unwrap()
}

fn legacy(
    s: &PrivateKeySigner,
    nonce: u64,
    to: TxKind,
    value: U256,
    gas: u64,
    input: &[u8],
) -> Vec<u8> {
    let tx = TxLegacy {
        chain_id: Some(CHAIN_ID),
        nonce,
        gas_price: u128::from(GWEI),
        gas_limit: gas,
        to,
        value,
        input: Bytes::copy_from_slice(input),
    };
    let sig = s.sign_hash_sync(&tx.signature_hash()).unwrap();
    TxEnvelope::from(tx.into_signed(sig)).encoded_2718()
}

fn carrier(rlp: &[u8]) -> TxOut {
    TxOut {
        value: Amount::ZERO,
        script_pubkey: carrier_script(rlp).unwrap(),
    }
}

fn gwei(n: u64) -> U256 {
    U256::from(n) * U256::from(GWEI)
}

#[test]
fn the_reference_test_on_a_whole_chain() {
    let mut c = Chain::new();
    let empty = c.evm().root();

    // 101 empty blocks each commit the unchanged state root; the peg's coin matures
    for _ in 0..101 {
        c.produce();
    }
    assert_eq!(c.evm().height(), 101);
    assert_eq!(c.evm().block(101).unwrap().root, empty);
    // the peg's coin split, so the steps below each have one to spend
    let split = c.spend(
        (0..12)
            .map(|_| TxOut {
                value: Amount::from_sat(100_000_000),
                script_pubkey: c.me.clone(),
            })
            .collect(),
    );
    c.submit(split).unwrap();
    c.produce();

    // a deposit (reserve payment + evmin) credits 1,000,000 sats as 1,000,000 gwei
    let alice_key = signer(0x42);
    let alice = alice_key.address();
    let bob = Address::repeat_byte(0x77);
    let dep = c.spend(vec![
        TxOut {
            value: Amount::from_sat(1_000_000),
            script_pubkey: c.me.clone(),
        },
        TxOut {
            value: Amount::ZERO,
            script_pubkey: deposit_script(alice),
        },
    ]);
    c.submit(dep).unwrap();
    c.produce();
    assert_eq!(c.follower_evm().balance(&alice), gwei(1_000_000));

    // a deposit without the reserve payment before the marker is refused by the mempool check
    let bad = c.spend(vec![TxOut {
        value: Amount::ZERO,
        script_pubkey: deposit_script(bob),
    }]);
    assert!(c
        .submit(bad.clone())
        .unwrap_err()
        .contains("no reserve payment"));
    // and were it in the mempool anyway, the producer leaves it out of its block
    c.state.submit(bad.clone()).unwrap();

    // a carried transfer alice -> bob
    let xfer = legacy(&alice_key, 0, TxKind::Call(bob), gwei(250_000), 21_000, &[]);
    let carry = c.spend(vec![carrier(&xfer)]);
    let carry_txid = carry.compute_txid();
    c.submit(carry).unwrap();
    // a second nonce-0 transaction passes the check against the confirmed state, and is dropped at sequencing
    let again = c.spend(vec![carrier(&legacy(
        &alice_key,
        0,
        TxKind::Call(bob),
        U256::from(1),
        21_000,
        &[],
    ))]);
    let again_txid = again.compute_txid();
    c.submit(again).unwrap();
    let dropped: Vec<_> = c.produce().into_iter().map(|(t, _)| t).collect();
    assert!(dropped.contains(&bad.compute_txid()) && dropped.contains(&again_txid));
    let h = c.state.height();
    {
        let evm = c.follower_evm();
        assert_eq!(evm.balance(&bob), gwei(250_000));
        assert_eq!(evm.balance(&alice), gwei(1_000_000 - 250_000 - 21_000));
        let hash = alloy_primitives::keccak256(&xfer);
        let rc = evm.receipt(&hash).unwrap();
        assert!(
            rc.status && rc.height == h && rc.sidechain_txid == carry_txid && rc.gas_used == 21_000
        );
    }

    // a contract: runtime code that returns 42, deployed by init code that returns it
    let runtime = hex::decode("602a60005260206000f3").unwrap();
    let init = hex::decode("69602a60005260206000f3600052600a6016f3").unwrap();
    let deploy = legacy(&alice_key, 1, TxKind::Create, U256::ZERO, 100_000, &init);
    c.submit(c.spend(vec![carrier(&deploy)])).unwrap();
    c.produce();
    let contract = {
        let evm = c.follower_evm();
        let contract = evm
            .receipt(&alloy_primitives::keccak256(&deploy))
            .unwrap()
            .contract_address
            .unwrap();
        assert_eq!(evm.world().code(&contract).as_ref(), &runtime[..]);
        // a read-only call returns 42 and moves nothing
        let before = evm.root();
        let (ok, out) = evm.call(alice, contract, Bytes::new(), 100_000).unwrap();
        assert!(ok && out.last() == Some(&0x2a));
        assert_eq!(evm.world().root(), before);
        contract
    };
    assert_eq!(contract, alice.create(1));

    // a withdrawal: 100,000 gwei to a sidechain script, paid by the coinbase
    let target = challenge_for(&pubkey_of(&SecretKey::from_slice(&[9u8; 32]).unwrap()));
    let wd = legacy(
        &alice_key,
        2,
        TxKind::Call(WITHDRAW),
        gwei(100_000),
        30_000,
        target.as_bytes(),
    );
    c.submit(c.spend(vec![carrier(&wd)])).unwrap();
    c.produce();
    let paid = c.follower.coins(&target);
    assert_eq!(paid.len(), 1);
    assert!(paid[0].value == 100_000 && paid[0].coinbase);
    assert_eq!(c.follower_evm().balance(&WITHDRAW), U256::ZERO);
    assert!(
        c.follower_evm().world().account(&WITHDRAW).is_some(),
        "emptied, not removed"
    );

    // a hand-built block whose coinbase commits the wrong root is refused, by the rule's name; the
    // coinbase-amount rule fails with it, as the reference's version of that rule does on a block
    // whose EVM verdict is not ok
    let wrong = c.hand_built(
        vec![],
        vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: root_script(B256::repeat_byte(0x11)),
        }],
    );
    match c.follower.add_block(&wrong, None, None).unwrap_err() {
        CoreError::Rejected { rules, .. } => assert_eq!(
            rules,
            vec![
                "btc:rule-blockctx-coinbase-amount".to_string(),
                "sidestr:rule-evm".to_string()
            ]
        ),
        e => panic!("{e}"),
    }
    // one that pays itself 1,000 sats no withdrawal allows is refused by the coinbase-amount rule
    let greedy = c.hand_built(
        vec![],
        vec![
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: c.me.clone(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: root_script(c.evm().root()),
            },
        ],
    );
    match c.follower.add_block(&greedy, None, None).unwrap_err() {
        CoreError::Rejected { rules, .. } => {
            assert_eq!(rules, vec!["btc:rule-blockctx-coinbase-amount".to_string()])
        }
        e => panic!("{e}"),
    }
    // a coinbase carrying an asset record breaks the assets rule, which every chain naming a rule carries
    let tally = c.hand_built(
        vec![],
        vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: record_script("issue:EVM:0").unwrap(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: root_script(c.evm().root()),
            },
        ],
    );
    match c.follower.add_block(&tally, None, None).unwrap_err() {
        CoreError::Rejected { rules, .. } => {
            assert_eq!(rules, vec!["sidestr:rule-assets".to_string()])
        }
        e => panic!("{e}"),
    }
    // and the chain still produces after the refusals, which changed nothing
    let before = c.follower_evm().root();
    c.produce();
    assert_eq!(c.follower_evm().root(), before);

    // an EIP-1559 transfer with a tip: the zero-address coinbase collects it
    let tip = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce: 3,
        gas_limit: 21_000,
        max_fee_per_gas: 3 * u128::from(GWEI),
        max_priority_fee_per_gas: 2 * u128::from(GWEI),
        to: TxKind::Call(bob),
        value: U256::from(1),
        access_list: Default::default(),
        input: Bytes::new(),
    };
    let sig = alice_key.sign_hash_sync(&tip.signature_hash()).unwrap();
    c.submit(c.spend(vec![carrier(
        &TxEnvelope::from(tip.into_signed(sig)).encoded_2718(),
    )]))
    .unwrap();
    c.produce();
    assert_eq!(c.follower_evm().balance(&Address::ZERO), gwei(42_000));

    // replaying the block file reaches the same state root and balances
    let dat: Vec<u8> = c
        .blocks
        .iter()
        .enumerate()
        .flat_map(|(h, b)| encode_record(h as u32, &serialize(b)))
        .collect();
    let replay_rules = rules_for(&c.doc).unwrap();
    let replayed =
        State::replay_with_rules(c.doc.clone(), &dat, None, replay_rules.boxed()).unwrap();
    assert_eq!(replayed.tip(), c.state.tip());
    let evm = replay_rules.evm.as_ref().unwrap().state();
    assert_eq!(evm.root(), c.evm().root());
    assert_eq!(evm.world(), c.evm().world());
    assert_eq!(evm.balance(&bob), gwei(250_000) + U256::from(1));
}

#[test]
fn a_document_naming_evm_needs_the_rule() {
    let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let doc = doc_for(&key, r#"["evm"]"#);
    // without the rule the document is refused, as loadEngine refuses a rule it lacks
    let e = State::with_key(doc.clone(), &key).unwrap_err().to_string();
    assert!(
        e.contains("names rule \"evm\", which this validator does not have"),
        "{e}"
    );
    // the assets rule alone does not carry it either
    let e = State::with_key_and_rules(
        doc.clone(),
        &key,
        vec![Box::new(sidestr_core::assets::AssetsRule::new())],
    )
    .unwrap_err()
    .to_string();
    assert!(e.contains("\"evm\""), "{e}");
    assert!(State::with_key_and_rules(doc.clone(), &key, rules_for(&doc).unwrap().boxed()).is_ok());
    assert!(ChainDocument::from_json_with(&serde_json::to_string(&doc).unwrap(), KNOWN).is_ok());
    // pool and anything else this crate does not carry stay refused
    for (rules, name) in [(r#"["evm", "pool"]"#, "pool"), (r#"["desk"]"#, "desk")] {
        let e = rules_for(&doc_for(&key, rules)).unwrap_err().to_string();
        assert!(
            e.contains(&format!("\"{name}\", which this validator does not have")),
            "{e}"
        );
    }
    // no rules named: nothing carried, and the document needs nothing
    let plain = doc_for(&key, "[]");
    let r = rules_for(&plain).unwrap();
    assert!(r.assets.is_none() && r.evm.is_none());
    assert!(State::with_key(plain, &key).is_ok());
}

#[test]
fn the_rule_reads_the_documents_evm_section() {
    let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let mut v = serde_json::to_value(doc_for(&key, r#"["evm"]"#)).unwrap();
    v["evm"] = serde_json::json!({ "chainId": "777", "gasLimit": 1000000, "reserve": "51200000" });
    let cfg =
        sidestr_evm::EvmConfig::from_document(&serde_json::from_value(v.clone()).unwrap()).unwrap();
    assert_eq!(
        (cfg.chain_id, cfg.gas_limit, cfg.reserve.to_hex_string()),
        (777, 1_000_000, "51200000".into())
    );
    v["evm"] = serde_json::json!({ "chainId": 1.5 });
    assert!(
        sidestr_evm::EvmConfig::from_document(&serde_json::from_value(v.clone()).unwrap()).is_err()
    );
    v["evm"] = serde_json::json!("21474");
    assert!(sidestr_evm::EvmConfig::from_document(&serde_json::from_value(v).unwrap()).is_err());
}

#[test]
fn the_genesis_is_judged_with_the_rules() {
    // block 0 passes every rule, the EVM's skipped at height 0 and the assets rule applied
    let c = Chain::new();
    assert_eq!(c.follower.height(), 0);
    assert_eq!(c.follower_evm().height(), 0);
    let family = sidestr_core::Stock;
    assert_eq!(
        family.block_hash(&c.blocks[0].header),
        c.follower.genesis_hash()
    );
}
