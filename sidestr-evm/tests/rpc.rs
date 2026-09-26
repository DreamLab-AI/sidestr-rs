//! The JSON-RPC on a whole chain, through `sidestr-core`:
//! `siding/test/evmrpc-test.mjs` step for step — what MetaMask asks, in the
//! order it asks it. The host is a producer: [`ChainView`] over its
//! `sidestr-core` state, carrying a raw transaction in a spend of its own
//! coin, through the EVM check and into the mempool, as `bin/siding.mjs`
//! does; a validator that shares nothing with it but the blocks follows.

use std::time::{SystemTime, UNIX_EPOCH};

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use bitcoin::secp256k1::{Keypair, Message, SecretKey};
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, BlockHash, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use serde_json::{json, Value};
use sidestr_core::block::{challenge_for, pubkey_of, secp, HeaderFamily};
use sidestr_core::sighash::key_path_sighash;
use sidestr_core::state::{NextBlock, State};
use sidestr_core::ChainDocument;
use sidestr_evm::records::{deposit_script, GWEI};
use sidestr_evm::rpc::{ChainView, EvmRpc};
use sidestr_evm::{rules_for, Rules};

const CHAIN_ID: u64 = 21_474;

/// The producer: its key, its state and rules, and a validator following it.
struct Node {
    key: SecretKey,
    me: ScriptBuf,
    rules: Rules,
    state: State,
    follower_rules: Rules,
    follower: State,
    time: u32,
}

impl Node {
    fn new() -> Self {
        let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let me = challenge_for(&pubkey_of(&key));
        let text = format!(
            r#"{{"id": "sidestr:evmrpctest", "name": "evmrpctest", "parent": "tbtc4", "challenge": "{me}", "signer": "{pk}",
            "powLimit": "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "addressPrefix": "evr", "genesisTime": 1790000000, "rules": ["evm"], "evm": {{ "chainId": {CHAIN_ID} }},
            "pegs": [{{ "txid": "{peg}", "vout": 0, "amount": 5000000000, "script": "{me}" }}]}}"#,
            me = me.to_hex_string(),
            pk = pubkey_of(&key),
            peg = "a".repeat(64),
        );
        let doc: ChainDocument = serde_json::from_str(&text).unwrap();
        let rules = rules_for(&doc).unwrap();
        let state = State::with_key_and_rules(doc.clone(), &key, rules.boxed()).unwrap();
        let genesis = State::genesis_block_for(&doc, &key).unwrap();
        let follower_rules = rules_for(&doc).unwrap();
        let follower =
            State::from_genesis_with_rules(doc, &genesis, None, follower_rules.boxed()).unwrap();
        Self {
            key,
            me,
            rules,
            state,
            follower_rules,
            follower,
            time: 1_790_000_000,
        }
    }

    fn rpc(&self) -> EvmRpc {
        EvmRpc::new(self.rules.evm.clone().unwrap(), "sidestr:evmrpctest")
    }

    fn produce(&mut self) {
        self.time += 60;
        let next = NextBlock {
            time: self.time,
            claims: vec![],
        };
        let made = self
            .rules
            .produce(&mut self.state, &self.key, &next, None)
            .unwrap();
        assert!(made.dropped.is_empty(), "{:?}", made.dropped);
        self.follower.add_block(&made.block, None, None).unwrap();
        let (ours, theirs) = (
            self.rules.evm.as_ref().unwrap().state().root(),
            self.follower_rules.evm.as_ref().unwrap().state().root(),
        );
        assert_eq!(ours, theirs);
    }

    /// `evmrpc-test.mjs mk`: the largest mature coin not spent in the
    /// mempool pays `outputs`, a fee of 5,000 and the change.
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

    /// `chain.mjs submit`: the EVM check at the next height, then the mempool.
    fn submit(&mut self, tx: Transaction) -> Result<Txid, String> {
        let now = u32::try_from(self.now()).unwrap();
        let o =
            self.rules
                .evm
                .as_ref()
                .unwrap()
                .state()
                .check_tx(&tx, self.state.height() + 1, now);
        if let Some(e) = o.error {
            return Err(format!("evm: {e}"));
        }
        self.state
            .submit(tx)
            .map(|s| s.txid)
            .map_err(|e| e.to_string())
    }
}

impl ChainView for Node {
    fn height(&self) -> u32 {
        self.state.height()
    }
    fn block_hash(&self, height: u32) -> Option<BlockHash> {
        self.state.hash_at(height)
    }
    fn header_time(&self, height: u32) -> Option<u32> {
        self.state.header_at(height).map(|h| h.time)
    }
    fn mempool(&self) -> Vec<Transaction> {
        self.state.mempool().cloned().collect()
    }
    /// `bin/siding.mjs carrier`: a spend of the producer's coin with the carrier first.
    fn carry(&mut self, script: ScriptBuf) -> Result<Txid, String> {
        let tx = self.spend(vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: script,
        }]);
        self.submit(tx)
    }
}

fn call(rpc: &EvmRpc, node: &mut Node, method: &str, params: Value) -> Result<Value, Value> {
    let r = rpc.handle(
        node,
        &json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }),
    );
    match r.get("error") {
        Some(e) => Err(e.clone()),
        None => Ok(r["result"].clone()),
    }
}

fn sign(
    key: &PrivateKeySigner,
    nonce: u64,
    to: TxKind,
    value: U256,
    gas: u64,
    input: &[u8],
) -> String {
    let tx = TxLegacy {
        chain_id: Some(CHAIN_ID),
        nonce,
        gas_price: u128::from(GWEI),
        gas_limit: gas,
        to,
        value,
        input: Bytes::copy_from_slice(input),
    };
    let sig = key.sign_hash_sync(&tx.signature_hash()).unwrap();
    format!(
        "0x{}",
        hex::encode(TxEnvelope::from(tx.into_signed(sig)).encoded_2718())
    )
}

fn big(v: &Value) -> U256 {
    v.as_str().unwrap().parse().unwrap()
}

#[test]
fn the_reference_rpc_test_on_a_whole_chain() {
    let mut node = Node::new();
    while node.state.height() < 101 {
        node.produce();
    }
    let rpc = node.rpc();
    let n = &mut node;
    let alice_key = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x42)).unwrap();
    let alice = format!("{:#x}", alice_key.address()).to_lowercase();
    let bob = format!("0x{}", "77".repeat(20));

    // eth_chainId / net_version / eth_blockNumber
    assert_eq!(
        call(&rpc, n, "eth_chainId", json!([])).unwrap(),
        json!("0x53e2")
    );
    assert_eq!(
        call(&rpc, n, "net_version", json!([])).unwrap(),
        json!("21474")
    );
    assert_eq!(
        call(&rpc, n, "eth_blockNumber", json!([])).unwrap(),
        json!("0x65")
    );
    // the balance of an empty account is 0x0
    assert_eq!(
        call(&rpc, n, "eth_getBalance", json!([alice, "latest"])).unwrap(),
        json!("0x0")
    );

    // after a deposit of 2,000,000 sats the balance is 2,000,000 gwei
    let dep = n.spend(vec![
        TxOut {
            value: Amount::from_sat(2_000_000),
            script_pubkey: n.me.clone(),
        },
        TxOut {
            value: Amount::ZERO,
            script_pubkey: deposit_script(alice_key.address()),
        },
    ]);
    n.submit(dep).unwrap();
    n.produce();
    assert_eq!(
        big(&call(&rpc, n, "eth_getBalance", json!([alice, "latest"])).unwrap()),
        U256::from(2_000_000u64) * U256::from(GWEI)
    );

    // eth_gasPrice is 1 gwei; eth_feeHistory has base fees
    assert_eq!(
        call(&rpc, n, "eth_gasPrice", json!([])).unwrap(),
        json!("0x3b9aca00")
    );
    let fh = call(&rpc, n, "eth_feeHistory", json!(["0x4", "latest", [50]])).unwrap();
    assert_eq!(fh["baseFeePerGas"].as_array().unwrap().len(), 5);

    // eth_estimateGas for a transfer is 21000
    let est = call(
        &rpc,
        n,
        "eth_estimateGas",
        json!([{ "from": alice, "to": bob, "value": "0x1" }]),
    )
    .unwrap();
    assert_eq!(est, json!("0x5208"));

    // eth_sendRawTransaction returns the hash and the carrier sits in the mempool
    let bob_addr: Address = bob.parse().unwrap();
    let raw = sign(
        &alice_key,
        0,
        TxKind::Call(bob_addr),
        U256::from(500_000u64) * U256::from(GWEI),
        21_000,
        &[],
    );
    let h1 = call(&rpc, n, "eth_sendRawTransaction", json!([raw])).unwrap();
    let h1s = h1.as_str().unwrap().to_string();
    assert!(
        h1s.len() == 66
            && h1s.starts_with("0x")
            && h1s[2..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert_eq!(n.state.mempool().count(), 1);
    // eth_getTransactionCount: pending counts the carrier, latest does not
    assert_eq!(
        call(
            &rpc,
            n,
            "eth_getTransactionCount",
            json!([alice, "pending"])
        )
        .unwrap(),
        json!("0x1")
    );
    assert_eq!(
        call(&rpc, n, "eth_getTransactionCount", json!([alice, "latest"])).unwrap(),
        json!("0x0")
    );
    // the receipt is null until a block
    assert_eq!(
        call(&rpc, n, "eth_getTransactionReceipt", json!([h1s])).unwrap(),
        Value::Null
    );
    n.produce();
    // after the block: receipt status 0x1, gasUsed 0x5208, blockNumber, blockHash
    let rc = call(&rpc, n, "eth_getTransactionReceipt", json!([h1s])).unwrap();
    assert_eq!(rc["status"], json!("0x1"));
    assert_eq!(rc["gasUsed"], json!("0x5208"));
    assert_eq!(rc["blockNumber"], json!(format!("{:#x}", n.state.height())));
    assert_eq!(rc["blockHash"], json!(format!("0x{}", n.state.tip().hash)));
    // eth_getTransactionByHash: from, to, value, nonce
    let tj = call(&rpc, n, "eth_getTransactionByHash", json!([h1s])).unwrap();
    assert_eq!(
        (tj["from"].as_str().unwrap(), tj["to"].as_str().unwrap()),
        (alice.as_str(), bob.as_str())
    );
    assert_eq!(big(&tj["value"]), U256::from(500_000u64) * U256::from(GWEI));
    assert_eq!(tj["nonce"], json!("0x0"));
    // bob has the 500,000 gwei
    assert_eq!(
        big(&call(&rpc, n, "eth_getBalance", json!([bob])).unwrap()),
        U256::from(500_000u64) * U256::from(GWEI)
    );

    // a deployment receipt names the contract
    let init = hex::decode("69602a60005260206000f3600052600a6016f3").unwrap();
    let h2 = call(
        &rpc,
        n,
        "eth_sendRawTransaction",
        json!([sign(
            &alice_key,
            1,
            TxKind::Create,
            U256::ZERO,
            100_000,
            &init
        )]),
    )
    .unwrap();
    n.produce();
    let rc2 = call(&rpc, n, "eth_getTransactionReceipt", json!([h2])).unwrap();
    let contract = rc2["contractAddress"].as_str().unwrap().to_string();
    assert!(contract.len() == 42 && contract.starts_with("0x"));
    // eth_getCode returns the runtime
    assert_eq!(
        call(&rpc, n, "eth_getCode", json!([contract])).unwrap(),
        json!("0x602a60005260206000f3")
    );
    // eth_call returns 42 and does not move the state root
    let root = n.rules.evm.as_ref().unwrap().state().root();
    let r = call(
        &rpc,
        n,
        "eth_call",
        json!([{ "to": contract, "from": alice }, "latest"]),
    )
    .unwrap();
    assert!(r.as_str().unwrap().ends_with("2a"));
    {
        let evm = n.rules.evm.as_ref().unwrap().state();
        assert_eq!(evm.root(), root);
        assert_eq!(
            evm.world().root(),
            evm.block(n.state.height()).unwrap().root
        );
    }

    // a contract returning block.timestamp: eth_call sees the block it would land in, not a zero block
    let h2b = call(
        &rpc,
        n,
        "eth_sendRawTransaction",
        json!([sign(
            &alice_key,
            2,
            TxKind::Create,
            U256::ZERO,
            100_000,
            &hex::decode("66425f5260205ff35f5260076019f3").unwrap()
        )]),
    )
    .unwrap();
    n.produce();
    let tsc = call(&rpc, n, "eth_getTransactionReceipt", json!([h2b])).unwrap()["contractAddress"]
        .clone();
    let ts = big(&call(&rpc, n, "eth_call", json!([{ "to": tsc }, "latest"])).unwrap());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        u64::try_from(ts).unwrap().abs_diff(now) < 120,
        "eth_call sees a real block.timestamp ({ts})"
    );

    // eth_getBlockByNumber latest: number, hash, one transaction, baseFee
    let blk = call(&rpc, n, "eth_getBlockByNumber", json!(["latest", false])).unwrap();
    assert_eq!(blk["number"], json!(format!("{:#x}", n.state.height())));
    assert_eq!(blk["hash"], json!(format!("0x{}", n.state.tip().hash)));
    assert_eq!(blk["transactions"].as_array().unwrap().len(), 1);
    assert_eq!(blk["baseFeePerGas"], json!("0x3b9aca00"));
    // eth_getBlockByNumber of an unknown height is null
    assert_eq!(
        call(
            &rpc,
            n,
            "eth_getBlockByNumber",
            json!(["0x7fffffff", false])
        )
        .unwrap(),
        Value::Null
    );

    // a malformed raw transaction is refused with an error
    let err = call(&rpc, n, "eth_sendRawTransaction", json!(["0x1234"])).unwrap_err();
    assert!(err["message"]
        .as_str()
        .unwrap()
        .contains("not a transaction"));
    // a call to an account with data succeeds: nothing to run
    assert!(call(
        &rpc,
        n,
        "eth_call",
        json!([{ "to": alice, "data": format!("0x{}", "ff".repeat(4)) }])
    )
    .is_ok());
    // a batch answers each, unknown methods with -32601
    let batch = rpc.handle(
        n,
        &json!([
            { "jsonrpc": "2.0", "id": "a", "method": "eth_chainId" },
            { "jsonrpc": "2.0", "id": "b", "method": "nope" }
        ]),
    );
    let batch = batch.as_array().unwrap();
    assert_eq!(batch.len(), 2);
    assert_eq!(batch[0]["result"], json!("0x53e2"));
    assert_eq!(batch[1]["error"]["code"], json!(-32601));

    // beyond the reference's test: the host's refusal comes back as the error, and nothing is carried
    let stale = sign(
        &alice_key,
        0,
        TxKind::Call(bob_addr),
        U256::from(1),
        21_000,
        &[],
    );
    let err = call(&rpc, n, "eth_sendRawTransaction", json!([stale])).unwrap_err();
    assert_eq!(err["code"], json!(-32000));
    assert!(
        err["message"]
            .as_str()
            .unwrap()
            .starts_with("evm: carrier at output 0: "),
        "{err}"
    );
    assert_eq!(n.state.mempool().count(), 0);
    // the validator, which shares nothing with the producer but the blocks, answers the same
    let follower_rpc = EvmRpc::new(n.follower_rules.evm.clone().unwrap(), "sidestr:evmrpctest");
    let q = json!({ "id": 1, "method": "eth_getTransactionReceipt", "params": [h1s] });
    let ours = rpc.handle(n, &q);
    assert_eq!(follower_rpc.handle(n, &q), ours);
}
