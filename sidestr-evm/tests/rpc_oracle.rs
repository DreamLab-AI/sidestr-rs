//! The reference's JSON-RPC answers, replayed. `tests/fixtures/rpc.json` was
//! written by `tests/oracle/rpc-oracle.mjs`: siding's `evmrpc.mjs` itself
//! (fa86dac) over its `evm.mjs`, on ethereumjs 10.1.3, driven by a scripted
//! host with a frozen clock. The same chain is built here through
//! [`EvmState::prepare`] (every block's state root must come out the same),
//! the same host is played through [`ChainView`], and every request must
//! draw the same answer, as the same bytes on the wire.
//!
//! One normalisation: where the fixture marks a request `normalise` with a
//! prefix, the error message is compared only as far as that prefix, and
//! must start with it on both sides. The rest is ethereumjs's own text (why
//! a raw transaction does not read, why its VM refused a carrier at the
//! host's mempool check); this crate gives its reasons in its own words.

use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, BlockHash, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use serde::Deserialize;
use serde_json::Value;
use sidestr_evm::rpc::{ChainView, EvmRpc};
use sidestr_evm::{EvmConfig, EvmRule};

#[derive(Deserialize)]
struct Fixture {
    chain: ChainDoc,
    genesis: Genesis,
    now: u64,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct ChainDoc {
    id: String,
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
struct Genesis {
    hash: String,
    time: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum Step {
    Submit {
        label: String,
        outputs: Vec<Out>,
    },
    Block {
        label: String,
        height: u32,
        hash: String,
        time: u32,
        root: String,
        coinbase: Vec<Out>,
    },
    Rpc {
        label: String,
        request: Value,
        response: String,
        normalise: Option<String>,
    },
    Http {
        label: String,
        body: String,
        status: u16,
        response: String,
    },
}

#[derive(Deserialize)]
struct Out {
    value: u64,
    script: String,
}

fn outputs(outs: &[Out]) -> Vec<TxOut> {
    outs.iter()
        .map(|o| TxOut {
            value: Amount::from_sat(o.value),
            script_pubkey: ScriptBuf::from_hex(&o.script).unwrap(),
        })
        .collect()
}

/// A transaction the rule reads only for its outputs; its input makes it
/// distinct.
fn tx(n: u32, output: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0x5a; 32]),
                vout: n,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output,
    }
}

/// The scripted host, as `rpc-oracle.mjs` plays `chain.mjs` and
/// `bin/siding.mjs`: the chain's hashes and times, a mempool whose entries
/// pass the EVM check at the next height, carriers with one output.
struct Host {
    rule: EvmRule,
    hashes: Vec<BlockHash>,
    times: Vec<u32>,
    mempool: Vec<Transaction>,
    now: u64,
    made: u32,
    logged: Vec<String>,
}

impl Host {
    fn submit(&mut self, output: Vec<TxOut>) -> Result<Txid, String> {
        self.made += 1;
        let t = tx(self.made, output);
        let height = self.height() + 1;
        let o = self
            .rule
            .state()
            .check_tx(&t, height, u32::try_from(self.now).unwrap());
        if let Some(e) = o.error {
            return Err(format!("evm: {e}"));
        }
        let txid = t.compute_txid();
        self.mempool.push(t);
        Ok(txid)
    }
}

impl ChainView for Host {
    fn height(&self) -> u32 {
        u32::try_from(self.hashes.len()).unwrap() - 1
    }
    fn block_hash(&self, height: u32) -> Option<BlockHash> {
        self.hashes.get(height as usize).copied()
    }
    fn header_time(&self, height: u32) -> Option<u32> {
        self.times.get(height as usize).copied()
    }
    fn mempool(&self) -> Vec<Transaction> {
        self.mempool.clone()
    }
    fn carry(&mut self, script: ScriptBuf) -> Result<Txid, String> {
        self.submit(vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: script,
        }])
    }
    fn now(&self) -> u64 {
        self.now
    }
    fn log(&mut self, line: &str) {
        self.logged.push(line.to_string());
    }
}

/// The error message cut at `prefix`, which both sides must start with.
fn normalised(wire: &str, prefix: &str, side: &str, label: &str) -> Value {
    let mut v: Value = serde_json::from_str(wire).unwrap();
    let m = v["error"]["message"].as_str().unwrap_or_default();
    assert!(
        m.starts_with(prefix),
        "{label}: the {side} message {m:?} does not start with {prefix:?}"
    );
    v["error"]["message"] = Value::String(prefix.to_string());
    v
}

#[test]
fn every_answer_of_the_reference_rpc() {
    let f: Fixture = serde_json::from_str(include_str!("fixtures/rpc.json")).unwrap();
    let rule = EvmRule::new(EvmConfig {
        chain_id: f.chain.evm.chain_id,
        gas_limit: f.chain.evm.gas_limit,
        reserve: ScriptBuf::from_hex(&f.chain.challenge).unwrap(),
    });
    let rpc = EvmRpc::new(rule.clone(), f.chain.id.clone());
    let mut host = Host {
        rule,
        hashes: vec![BlockHash::from_str(&f.genesis.hash).unwrap()],
        times: vec![f.genesis.time],
        mempool: Vec::new(),
        now: f.now,
        made: 0,
        logged: Vec::new(),
    };
    let (mut exact, mut prefixed, mut bodies, mut blocks) = (0, 0, 0, 0);
    for step in &f.steps {
        match step {
            Step::Submit { label, outputs: o } => {
                host.submit(outputs(o))
                    .unwrap_or_else(|e| panic!("{label}: {e}"));
            }
            Step::Block {
                label,
                height,
                hash,
                time,
                root,
                coinbase,
            } => {
                let hash = BlockHash::from_str(hash).unwrap();
                let mut txdata = vec![Transaction {
                    input: vec![TxIn::default()],
                    ..tx(0, outputs(coinbase))
                }];
                txdata.append(&mut host.mempool);
                let mut st = host.rule.state();
                let v = st.prepare(hash, *height, *time, &txdata);
                assert!(v.ok, "{label}: {:?}", v.error);
                assert_eq!(
                    v.root.unwrap().to_string(),
                    *root,
                    "{label}: the state root"
                );
                assert!(st.commit(&hash));
                drop(st);
                host.hashes.push(hash);
                host.times.push(*time);
                blocks += 1;
            }
            Step::Rpc {
                label,
                request,
                response,
                normalise,
            } => {
                let got = EvmRpc::to_wire(&rpc.handle(&mut host, request));
                match normalise {
                    None => {
                        assert_eq!(got, *response, "{label}: {request}");
                        exact += 1;
                    }
                    Some(prefix) => {
                        assert_eq!(
                            normalised(&got, prefix, "port's", label),
                            normalised(response, prefix, "reference's", label),
                            "{label}: {request}"
                        );
                        prefixed += 1;
                    }
                }
            }
            Step::Http {
                label,
                body,
                status,
                response,
            } => {
                let reply = rpc.handle_body(&mut host, body.as_bytes());
                assert_eq!(
                    (reply.status, reply.body.as_str()),
                    (*status, response.as_str()),
                    "{label}: {body}"
                );
                bodies += 1;
            }
        }
    }
    assert_eq!((blocks, exact + prefixed, bodies), (6, 223, 10));
    assert_eq!(prefixed, 8, "the normalised answers");
    // every carried transaction was logged as `bin/siding.mjs` logs it
    assert!(host
        .logged
        .iter()
        .all(|l| l.starts_with("evm: carried 0x") && l.ends_with('…')));
}

#[test]
fn a_body_over_the_limit_is_413() {
    let rule = EvmRule::new(EvmConfig {
        chain_id: 21474,
        gas_limit: 30_000_000,
        reserve: ScriptBuf::new(),
    });
    let rpc = EvmRpc::new(rule.clone(), "sidestr:limit");
    let mut host = Host {
        rule,
        hashes: vec![BlockHash::all_zeros()],
        times: vec![0],
        mempool: Vec::new(),
        now: 0,
        made: 0,
        logged: Vec::new(),
    };
    let at = format!("[{}]", " ".repeat(sidestr_evm::rpc::MAX_BODY - 2));
    assert_eq!(rpc.handle_body(&mut host, at.as_bytes()).status, 200);
    let over = format!("[{}]", " ".repeat(sidestr_evm::rpc::MAX_BODY - 1));
    let reply = rpc.handle_body(&mut host, over.as_bytes());
    assert_eq!(
        (reply.status, reply.body.as_str()),
        (413, r#"{"error":"too large"}"#)
    );
    // the limit counts UTF-16 units, as a JavaScript string's length does: "é" is one
    let accents = format!("\"{}\"", "é".repeat(sidestr_evm::rpc::MAX_BODY - 2));
    assert_eq!(rpc.handle_body(&mut host, accents.as_bytes()).status, 200);
}
