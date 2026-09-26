//! The reference's verdicts, replayed. `tests/fixtures/*.json` were written
//! by `tests/oracle/oracle.mjs`: siding's `evm` rule (`evm.mjs` at fa86dac,
//! cross-checked against the module itself) on ethereumjs 10.1.3, over a
//! scripted chain. Every accepted block's state root, withdrawal list,
//! Ethereum transaction hashes and receipts must come out the same here,
//! every refused block must be refused, and the accounts at the end must
//! match field for field; so must every carrier the reference reads or
//! refuses, and every record script it parses.

use std::str::FromStr;

use alloy_primitives::{Address, B256, U256};
use bitcoin::hashes::Hash;
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, BlockHash, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use serde::Deserialize;
use sidestr_evm::records::{parse_carrier, parse_deposit, parse_root};
use sidestr_evm::tx::decode_carrier;
use sidestr_evm::{EvmConfig, EvmState};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Chain {
    cross_checked: bool,
    chain: ChainDoc,
    empty_root: String,
    blocks: Vec<Block>,
    #[serde(rename = "final")]
    final_: Vec<Dumped>,
}

#[derive(Deserialize)]
struct ChainDoc {
    challenge: String,
    evm: EvmDoc,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EvmDoc {
    chain_id: u64,
    gas_limit: u64,
}

#[derive(Deserialize)]
struct Out {
    value: u64,
    script: String,
}

#[derive(Deserialize)]
struct Tx {
    txid: String,
    outputs: Vec<Out>,
}

#[derive(Deserialize)]
struct Block {
    label: String,
    height: u32,
    time: u32,
    hash: String,
    coinbase: Vec<Out>,
    txs: Vec<Tx>,
    verdict: JsVerdict,
    receipts: Vec<JsReceipt>,
}

#[derive(Deserialize)]
struct JsWithdrawal {
    script: String,
    sats: u64,
    hash: String,
}

#[derive(Deserialize)]
struct JsVerdict {
    ok: bool,
    root: Option<String>,
    error: Option<String>,
    withdrawals: Vec<JsWithdrawal>,
    hashes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsReceipt {
    hash: String,
    status: u8,
    gas_used: String,
    contract_address: Option<String>,
    logs: usize,
    from: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Dumped {
    name: String,
    address: String,
    exists: bool,
    nonce: Option<String>,
    balance: Option<String>,
    code_hash: Option<String>,
    storage_root: Option<String>,
}

fn outputs(outs: &[Out]) -> Vec<TxOut> {
    outs.iter()
        .map(|o| TxOut {
            value: Amount::from_sat(o.value),
            script_pubkey: ScriptBuf::from_hex(&o.script).unwrap(),
        })
        .collect()
}

fn tx(input: OutPoint, output: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: input,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output,
    }
}

/// The block's transactions as the rule sees them: the coinbase, then the
/// others, whose inputs the rule never reads (each spends the fixture's
/// synthetic txid, so every transaction is distinct).
fn txdata(b: &Block) -> Vec<Transaction> {
    let mut out = vec![tx(OutPoint::null(), outputs(&b.coinbase))];
    for t in &b.txs {
        out.push(tx(
            OutPoint {
                txid: Txid::from_str(&t.txid).unwrap(),
                vout: 0,
            },
            outputs(&t.outputs),
        ));
    }
    out
}

fn chain() -> Chain {
    serde_json::from_str(include_str!("fixtures/chain.json")).unwrap()
}

#[test]
fn every_root_and_verdict_of_the_reference_chain() {
    let c = chain();
    assert!(
        c.cross_checked,
        "the fixtures were written against the reference module"
    );
    let mut state = EvmState::new(EvmConfig {
        chain_id: c.chain.evm.chain_id,
        gas_limit: c.chain.evm.gas_limit,
        reserve: ScriptBuf::from_hex(&c.chain.challenge).unwrap(),
    });
    assert_eq!(state.root().to_string(), c.empty_root);
    let (mut accepted, mut refused) = (0, 0);
    for b in &c.blocks {
        let hash = BlockHash::from_byte_array(hex::decode(&b.hash).unwrap().try_into().unwrap());
        let v = state.prepare(hash, b.height, b.time, &txdata(b));
        let label = &b.label;
        assert_eq!(
            v.ok, b.verdict.ok,
            "{label}: {:?} / {:?}",
            v.error, b.verdict.error
        );
        // A refused block's root is what its execution gave as far as it got: information, not
        // consensus. Where ethereumjs throws from inside execution (the KZG precompile), its
        // journal is left a checkpoint deep and the root it reports holds part of the throwing
        // transaction; here the transaction leaves nothing. Every other root is compared.
        let kzg_throw = !b.verdict.ok
            && b.verdict
                .error
                .as_deref()
                .is_some_and(|e| e.ends_with("kzg not initialized"));
        if kzg_throw {
            assert!(
                v.error.as_deref().unwrap().ends_with("kzg not initialized"),
                "{label}"
            );
        } else {
            assert_eq!(
                v.root.map(|r| r.to_string()),
                b.verdict.root,
                "{label}: the root the block's execution gives"
            );
        }
        assert_eq!(
            v.hashes.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
            b.verdict.hashes,
            "{label}"
        );
        assert_eq!(
            v.withdrawals
                .iter()
                .map(|w| (w.script.to_hex_string(), w.sats, w.hash.to_string()))
                .collect::<Vec<_>>(),
            b.verdict
                .withdrawals
                .iter()
                .map(|w| (w.script.clone(), w.sats, w.hash.clone()))
                .collect::<Vec<_>>(),
            "{label}"
        );
        if !v.ok {
            refused += 1;
            let before = state.root();
            assert!(
                !state.commit(&hash),
                "{label}: a refused block commits nothing"
            );
            assert_eq!(state.root(), before, "{label}");
            continue;
        }
        accepted += 1;
        assert!(state.commit(&hash), "{label}");
        assert_eq!(
            (state.height(), Some(state.root())),
            (b.height, v.root),
            "{label}"
        );
        for r in &b.receipts {
            let mine = state
                .receipt(&B256::from_str(&r.hash).unwrap())
                .unwrap_or_else(|| panic!("{label}: no receipt for {}", r.hash));
            assert_eq!(mine.status, r.status == 1, "{label}: {} status", r.hash);
            assert_eq!(
                mine.gas_used.to_string(),
                r.gas_used,
                "{label}: {} gas",
                r.hash
            );
            assert_eq!(
                mine.contract_address.map(|a| a.to_string().to_lowercase()),
                r.contract_address,
                "{label}: {} contract",
                r.hash
            );
            assert_eq!(mine.logs.len(), r.logs, "{label}: {} logs", r.hash);
            assert_eq!(mine.from.to_string().to_lowercase(), r.from, "{label}");
        }
    }
    assert_eq!((accepted, refused), (20, 15));
    for d in &c.final_ {
        let a = state
            .world()
            .account(&Address::from_str(&d.address).unwrap());
        assert_eq!(a.is_some(), d.exists, "{} exists", d.name);
        let Some(a) = a else { continue };
        assert_eq!(Some(a.nonce.to_string()), d.nonce, "{} nonce", d.name);
        assert_eq!(Some(a.balance.to_string()), d.balance, "{} balance", d.name);
        assert_eq!(
            Some(a.code_hash.to_string()),
            d.code_hash,
            "{} code",
            d.name
        );
        assert_eq!(
            Some(a.storage_root().to_string()),
            d.storage_root,
            "{} storage",
            d.name
        );
    }
}

#[test]
fn replaying_the_accepted_blocks_reaches_the_same_state() {
    // evm-test.mjs: reopening the chain replays every carrier to the same root
    let c = chain();
    let config = EvmConfig {
        chain_id: c.chain.evm.chain_id,
        gas_limit: c.chain.evm.gas_limit,
        reserve: ScriptBuf::from_hex(&c.chain.challenge).unwrap(),
    };
    let run = |blocks: &mut dyn Iterator<Item = &Block>| {
        let mut s = EvmState::new(config.clone());
        for b in blocks {
            let hash =
                BlockHash::from_byte_array(hex::decode(&b.hash).unwrap().try_into().unwrap());
            if s.prepare(hash, b.height, b.time, &txdata(b)).ok {
                s.commit(&hash);
            }
        }
        s
    };
    let first = run(&mut c.blocks.iter());
    let again = run(&mut c.blocks.iter().filter(|b| b.verdict.ok));
    assert_eq!(again.world(), first.world());
    assert_eq!(again.root(), first.root());
    assert_eq!(
        again.balance(&Address::from_str("0x00000000000000000000000000000000000501de").unwrap()),
        U256::ZERO
    );
}

#[derive(Deserialize)]
struct Decode {
    #[serde(rename = "chainId")]
    chain_id: u64,
    cases: Vec<DecodeCase>,
}

#[derive(Deserialize)]
struct DecodeCase {
    label: String,
    rlp: String,
    ok: bool,
    sender: Option<String>,
    hash: Option<String>,
}

#[test]
fn every_carrier_reads_as_the_reference_reads_it() {
    let d: Decode = serde_json::from_str(include_str!("fixtures/decode.json")).unwrap();
    assert_eq!(d.cases.len(), 25);
    for c in &d.cases {
        let r = decode_carrier(&hex::decode(&c.rlp).unwrap(), d.chain_id);
        assert_eq!(r.is_ok(), c.ok, "{}: {:?}", c.label, r.as_ref().err());
        if let Ok(t) = r {
            assert_eq!(
                Some(t.sender.to_string().to_lowercase()),
                c.sender,
                "{}",
                c.label
            );
            assert_eq!(Some(t.hash.to_string()), c.hash, "{}", c.label);
        }
    }
}

#[derive(Deserialize)]
struct Records {
    cases: Vec<RecordCase>,
}

#[derive(Deserialize)]
struct RecordCase {
    label: String,
    script: String,
    carrier: Option<String>,
    deposit: Option<String>,
    root: Option<String>,
}

#[test]
fn every_record_parses_as_the_reference_parses_it() {
    let r: Records = serde_json::from_str(include_str!("fixtures/records.json")).unwrap();
    assert_eq!(r.cases.len(), 16);
    for c in &r.cases {
        let s = ScriptBuf::from_hex(&c.script).unwrap();
        assert_eq!(parse_carrier(&s).map(hex::encode), c.carrier, "{}", c.label);
        assert_eq!(
            parse_deposit(&s).map(|a| a.to_string().to_lowercase()),
            c.deposit,
            "{}",
            c.label
        );
        assert_eq!(parse_root(&s).map(|a| a.to_string()), c.root, "{}", c.label);
    }
}
