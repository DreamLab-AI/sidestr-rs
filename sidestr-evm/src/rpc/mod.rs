//! The Ethereum JSON-RPC a wallet expects (`siding/lib/evmrpc.mjs`,
//! proposals/evm.md): enough of `eth_*` for MetaMask, ethers and viem to see
//! the chain, read state, estimate and send. A raw transaction is handed to
//! the host, which wraps it in a carrier sidechain transaction paid from the
//! producer's coins (the producer sponsors the sidechain fee; the sender
//! pays EVM gas) and submits it like any transaction. Read-only calls run
//! against the applied state, in the block they would land in (the next
//! height, now), and change nothing: a validator's state moves only by
//! blocks.
//!
//! [`EvmRpc`] is transport-agnostic. [`EvmRpc::handle`] takes a request (or
//! a batch) as a JSON value and gives the answer; [`EvmRpc::handle_body`]
//! takes the bytes of a `POST /evm` body and gives the status and the text
//! `bin/siding.mjs` would send, parse errors and the 1 MiB limit included.
//! What the chain knows — its height, block hashes and times, the mempool,
//! how to carry a transaction, the clock — the host supplies through
//! [`ChainView`]. Serving it over HTTP is the host's: this crate pulls in no
//! server. Answer every `POST /evm` with [`EvmRpc::handle_body`], the
//! content type `application/json` and [`CORS_HEADERS`], and `OPTIONS` with
//! 204 and the same headers, as siding does.
//!
//! | method | answer |
//! |---|---|
//! | `web3_clientVersion` | `siding/<chain id>` (see [`EvmRpc::with_client`]) |
//! | `net_version`, `eth_chainId` | the EIP-155 chain id, decimal and hex |
//! | `eth_syncing`, `eth_mining`, `eth_accounts` | `false`, `false`, `[]` |
//! | `eth_blockNumber` | the sidechain height |
//! | `eth_gasPrice`, `eth_maxPriorityFeePerGas` | 1 gwei, 0 |
//! | `eth_feeHistory` | a flat 1 gwei base fee, no tips |
//! | `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt` | the applied state (`pending` counts the sender's carriers in the mempool) |
//! | `eth_call`, `eth_estimateGas` | a read-only execution in the next block; a failure is error 3 with the returned data |
//! | `eth_sendRawTransaction` | read, signature checked, carried; the hash |
//! | `eth_getTransactionReceipt`, `eth_getTransactionByHash` | once its block is applied |
//! | `eth_getBlockByNumber`, `eth_getBlockByHash`, `eth_getBlockTransactionCountByNumber` | the sidechain block as an Ethereum block, with the EVM's root and transactions |
//! | `eth_getLogs` | by block range, address and topics |
//!
//! Every answer is the reference's, byte for byte, error texts included:
//! `tests/rpc_oracle.rs` replays the requests `tests/oracle/rpc-oracle.mjs`
//! put to `evmrpc.mjs` itself, over ethereumjs 10.1.3. Where the reference's
//! answer comes from JavaScript itself — `BigInt("…")`, a property read on
//! `null`, `String(…)` of an object — the text is V8's, as Node 22 writes
//! it. What differs is listed in the crate's documentation ("Where this port
//! departs from siding").
//!
//! ```
//! use bitcoin::{BlockHash, ScriptBuf, Transaction, Txid};
//! use bitcoin::hashes::Hash;
//! use serde_json::json;
//! use sidestr_evm::rpc::{ChainView, EvmRpc};
//! use sidestr_evm::{EvmConfig, EvmRule};
//!
//! struct Host;
//! impl ChainView for Host {
//!     fn height(&self) -> u32 { 0 }
//!     fn block_hash(&self, height: u32) -> Option<BlockHash> { (height == 0).then(BlockHash::all_zeros) }
//!     fn header_time(&self, height: u32) -> Option<u32> { (height == 0).then_some(1_790_000_000) }
//!     fn mempool(&self) -> Vec<Transaction> { Vec::new() }
//!     fn carry(&mut self, _script: ScriptBuf) -> Result<Txid, String> { Err("read-only".into()) }
//! }
//!
//! let rule = EvmRule::new(EvmConfig { chain_id: 21474, gas_limit: 30_000_000, reserve: Default::default() });
//! let rpc = EvmRpc::new(rule, "sidestr:example");
//! let answer = rpc.handle(&mut Host, &json!({ "jsonrpc": "2.0", "id": 1, "method": "eth_chainId" }));
//! assert_eq!(answer, json!({ "jsonrpc": "2.0", "id": 1, "result": "0x53e2" }));
//! let reply = rpc.handle_body(&mut Host, br#"[{"id":"a","method":"eth_blockNumber"},{"id":"b","method":"nope"}]"#);
//! assert_eq!((reply.status, reply.body.as_str()), (200,
//!     r#"[{"jsonrpc":"2.0","id":"a","result":"0x0"},{"jsonrpc":"2.0","id":"b","error":{"code":-32601,"message":"nope is not supported"}}]"#));
//! ```

mod js;
mod json;

use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_consensus::transaction::{to_eip155_value, RlpEcdsaDecodableTx};
use alloy_consensus::{Transaction as _, TxEip1559, TxEip2930, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::{Decodable2718, Typed2718};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, Bytes, Signature, B256, U256};
use alloy_rlp::{Decodable, Header};
use bitcoin::{BlockHash, ScriptBuf, Transaction, Txid};
use serde_json::{json, Map, Value};

use crate::exec::Simulation;
use crate::records::{carrier_script, parse_carrier, GWEI};
use crate::rule::EvmRule;
use crate::state::Receipt;
use crate::tx::{decode_carrier, Carried};

use js::{thrown, BigInt, Js};

/// The largest `POST /evm` body `bin/siding.mjs` reads, in UTF-16 code
/// units (JavaScript's string length); longer is 413.
pub const MAX_BODY: usize = 1_048_576;

/// The headers `bin/siding.mjs` sends with every answer, `OPTIONS` included.
pub const CORS_HEADERS: [(&str, &str); 3] = [
    ("access-control-allow-origin", "*"),
    ("access-control-allow-headers", "range, content-type"),
    ("access-control-allow-methods", "GET, POST, OPTIONS"),
];

/// What the RPC needs from the chain beside the EVM state: `evmrpc.mjs`'s
/// `s` (the node) and `carrier`. A producer or a mirror implements it over
/// its chain; the heights and hashes must be those of the chain whose blocks
/// the [`EvmRule`] has applied.
pub trait ChainView {
    /// The height of the tip (`s.height()`).
    fn height(&self) -> u32;
    /// The hash of the block at `height` on the chain, `None` above the tip
    /// (`s.node.chain[h]`). It is written as a block hash is displayed.
    fn block_hash(&self, height: u32) -> Option<BlockHash>;
    /// The time in the header at `height` (`s.node.headers[h].time`).
    fn header_time(&self, height: u32) -> Option<u32>;
    /// The height of the block `hash` on the chain, if it is on it. The
    /// default looks at every height from 0; a host with an index should
    /// answer from it.
    fn height_of(&self, hash: &BlockHash) -> Option<u32> {
        (0..=self.height()).find(|h| self.block_hash(*h).as_ref() == Some(hash))
    }
    /// The transactions waiting in the mempool (`s.mempool`), in any order:
    /// `eth_getTransactionCount` with `pending` counts the carriers in them
    /// signed by the address.
    fn mempool(&self) -> Vec<Transaction>;
    /// Carry a raw Ethereum transaction: wrap `script` (its carrier record,
    /// `OP_RETURN evm:<rlp>`) in a sidechain transaction paid from the
    /// producer's coins and submit it (`bin/siding.mjs carrier`), running the
    /// mempool's EVM check ([`crate::EvmState::check_tx`]) as `submit` does.
    /// The sidechain transaction's id, or why it was refused, which the
    /// caller receives as the error's message (code -32000).
    fn carry(&mut self, script: ScriptBuf) -> Result<Txid, String>;
    /// Seconds since 1970: the timestamp of the block a read-only call runs
    /// in (`Date.now()`). The default reads the system clock.
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
    /// A line for the host's log: each transaction carried. The default
    /// drops it.
    fn log(&mut self, _line: &str) {}
}

/// An error as the reference answers it: `{code, message, data?}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    /// -32601 for a method not supported, -32602 for a raw transaction that
    /// does not read, 3 for a call that failed, -32000 for everything else.
    pub code: i64,
    /// What went wrong.
    pub message: String,
    /// A failed call's returned data, `0x`-prefixed.
    pub data: Option<String>,
}

impl RpcError {
    /// An error with no data.
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("code".into(), json!(self.code));
        m.insert("message".into(), json!(self.message));
        if let Some(d) = &self.data {
            m.insert("data".into(), json!(d));
        }
        Value::Object(m)
    }
}

/// An HTTP answer to a `POST /evm` body ([`EvmRpc::handle_body`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpReply {
    /// 200, 400 for a body that is not JSON, 413 for one over [`MAX_BODY`].
    pub status: u16,
    /// The JSON text.
    pub body: String,
}

/// The JSON-RPC over one chain's EVM: a handle on the [`EvmRule`]'s state,
/// read afresh for every request.
#[derive(Debug, Clone)]
pub struct EvmRpc {
    rule: EvmRule,
    chain: String,
    chain_id: u64,
    client: String,
}

type Answer = Result<Value, RpcError>;

const ZERO32: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
const ZEROADDR: &str = "0x0000000000000000000000000000000000000000";

fn hexn(n: impl std::fmt::LowerHex) -> Value {
    Value::String(format!("{n:#x}"))
}

fn hexb(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn zero_bloom() -> String {
    format!("0x{}", "00".repeat(256))
}

/// A height as `evmrpc.mjs heightOf` reads a block tag, as a JavaScript
/// number: the tip for none, `latest`, `pending`, `safe` and `finalized`, 0
/// for `earliest`, otherwise `Number(BigInt(tag))`.
fn height_of_tag(tag: Js<'_>, tip: u32) -> Result<f64, RpcError> {
    match tag {
        None => Ok(f64::from(tip)),
        Some(Value::String(s))
            if matches!(s.as_str(), "latest" | "pending" | "safe" | "finalized") =>
        {
            Ok(f64::from(tip))
        }
        Some(Value::String(s)) if s == "earliest" => Ok(0.0),
        tag => Ok(js::bigint(tag)?.to_f64()),
    }
}

/// A JavaScript number that is an existing height's index.
fn as_height(h: f64) -> Option<u32> {
    (h >= 0.0 && h <= f64::from(u32::MAX) && h.fract() == 0.0).then_some(h as u32)
}

/// A key as the reference's maps hold Ethereum hashes: `0x` and 64
/// lower-case hex digits, after `String(h).toLowerCase()`.
fn hash_key(h: Js<'_>) -> Option<B256> {
    let s = js::to_string(h).to_lowercase();
    let body = s.strip_prefix("0x")?;
    (body.len() == 64 && body.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| B256::from_str(body).ok())
        .flatten()
}

/// The read of a raw transaction, as `createTxFromRLP` and then
/// `isSigned() && verifySignature()` sort it: bytes ethereumjs will not
/// build a transaction from are -32602 (`not a transaction: …`, the reason in
/// this crate's words); a transaction it builds whose signature is missing
/// or does not verify is -32000 `unsigned or bad signature`.
fn read_raw(rlp: &[u8], chain_id: u64) -> Result<Carried, RpcError> {
    let not = |why: String| RpcError::new(-32602, format!("not a transaction: {why}"));
    let unsigned = || RpcError::new(-32000, "unsigned or bad signature");
    match decode_carrier(rlp, chain_id) {
        Ok(c) => {
            // ethereumjs's constructor refuses a tip above the fee cap
            if let TxEnvelope::Eip1559(t) = &c.envelope {
                if t.tx().max_priority_fee_per_gas > t.tx().max_fee_per_gas {
                    return Err(not(
                        "the tip (maxPriorityFeePerGas) is above the fee cap (maxFeePerGas)".into(),
                    ));
                }
            }
            Ok(c)
        }
        Err(e) if e == "unsigned or bad signature" => {
            // the typed constructors refuse a high s themselves; a legacy one is built and fails verification
            match TxEnvelope::decode_2718_exact(rlp) {
                Ok(env) if !env.is_legacy() && env.signature().normalize_s().is_some() => {
                    Err(not("the signature's s is above secp256k1n/2 (EIP-2)".into()))
                }
                _ => Err(unsigned()),
            }
        }
        Err(e) => {
            if unsigned_form(rlp, chain_id) {
                Err(unsigned())
            } else {
                Err(not(e))
            }
        }
    }
}

/// Bytes that ethereumjs reads as an unsigned transaction (it builds one,
/// and `isSigned()` is false): a legacy list of its six fields, or of nine
/// with `v`, `r` and `s` empty; an EIP-2930 or EIP-1559 one of its eight or
/// nine fields, for the chain.
fn unsigned_form(rlp: &[u8], chain_id: u64) -> bool {
    fn exact<T>(mut body: &[u8], f: impl FnOnce(&mut &[u8]) -> alloy_rlp::Result<T>) -> Option<T> {
        let t = f(&mut body).ok()?;
        body.is_empty().then_some(t)
    }
    fn list(mut buf: &[u8]) -> Option<&[u8]> {
        let h = Header::decode(&mut buf).ok()?;
        (h.list && buf.len() == h.payload_length).then_some(buf)
    }
    match rlp.first() {
        Some(b) if *b >= 0xc0 => {
            let Some(body) = list(rlp) else { return false };
            exact(body, TxLegacy::rlp_decode_fields).is_some()
                || exact(body, |b| {
                    TxLegacy::rlp_decode_fields(b)?;
                    let vrs: [Bytes; 3] = [Bytes::decode(b)?, Bytes::decode(b)?, Bytes::decode(b)?];
                    Ok(vrs.iter().all(|x| x.is_empty()))
                }) == Some(true)
        }
        Some(1) => list(&rlp[1..])
            .and_then(|body| exact(body, TxEip2930::rlp_decode_fields))
            .is_some_and(|t| t.chain_id == chain_id),
        Some(2) => list(&rlp[1..])
            .and_then(|body| exact(body, TxEip1559::rlp_decode_fields))
            .is_some_and(|t| {
                t.chain_id == chain_id && t.max_priority_fee_per_gas <= t.max_fee_per_gas
            }),
        _ => false,
    }
}

/// `v` as the transaction carries it: `27 + y` or `35 + 2·id + y` for a
/// legacy one, the y parity for a typed one.
fn v_of(e: &TxEnvelope, sig: &Signature) -> u128 {
    match e {
        TxEnvelope::Legacy(t) => to_eip155_value(sig.v(), t.tx().chain_id),
        _ => u128::from(sig.v()),
    }
}

fn access_list_json(list: &AccessList) -> Value {
    Value::Array(
        list.iter()
            .map(|item| {
                json!({
                    "address": hexb(item.address.as_slice()),
                    "storageKeys": item.storage_keys.iter().map(|k| hexb(k.as_slice())).collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

impl EvmRpc {
    /// The RPC over `rule`'s state, for the chain whose document id is
    /// `chain` (named in `web3_clientVersion`).
    pub fn new(rule: EvmRule, chain: impl Into<String>) -> Self {
        let chain_id = rule.state().config().chain_id;
        Self {
            rule,
            chain: chain.into(),
            chain_id,
            client: "siding".into(),
        }
    }

    /// Name the client in `web3_clientVersion` (`<client>/<chain id>`); the
    /// reference's is `siding`, and so is the default.
    pub fn with_client(mut self, client: impl Into<String>) -> Self {
        self.client = client.into();
        self
    }

    /// Answer a request, or a batch (an array of them, answered in order),
    /// as `evmrpc.mjs`'s `handle` does: `{jsonrpc: "2.0", id, result}` or
    /// `{jsonrpc: "2.0", id, error: {code, message, data?}}`, the id `null`
    /// when there is none.
    pub fn handle<V: ChainView + ?Sized>(&self, view: &mut V, body: &Value) -> Value {
        match body {
            Value::Array(reqs) => Value::Array(reqs.iter().map(|r| self.one(view, r)).collect()),
            req => self.one(view, req),
        }
    }

    /// Answer the body of a `POST /evm` as `bin/siding.mjs` does: over
    /// [`MAX_BODY`] is 413 `{"error":"too large"}`; a body that is not JSON
    /// is 400 with the JSON-RPC parse error (-32700); otherwise 200 and the
    /// text `JSON.stringify` makes of [`EvmRpc::handle`]'s answer. The body
    /// is read as UTF-8, a malformed sequence as U+FFFD.
    pub fn handle_body<V: ChainView + ?Sized>(&self, view: &mut V, body: &[u8]) -> HttpReply {
        let text = String::from_utf8_lossy(body);
        if text.encode_utf16().count() > MAX_BODY {
            return HttpReply {
                status: 413,
                body: r#"{"error":"too large"}"#.into(),
            };
        }
        match serde_json::from_str::<Value>(&text) {
            Err(_) => HttpReply {
                status: 400,
                body:
                    r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}"#
                        .into(),
            },
            Ok(v) => HttpReply {
                status: 200,
                body: json::stringify(&self.handle(view, &v)),
            },
        }
    }

    /// [`EvmRpc::handle`]'s answer as the text `JSON.stringify` makes of it:
    /// what goes on the wire.
    pub fn to_wire(answer: &Value) -> String {
        json::stringify(answer)
    }

    fn one<V: ChainView + ?Sized>(&self, view: &mut V, req: &Value) -> Value {
        let member = |k: &str| match req {
            Value::Object(m) => m.get(k),
            _ => None,
        };
        let id = member("id").cloned().unwrap_or(Value::Null);
        let method = js::to_string(member("method"));
        let params = member("params");
        let mut out = Map::new();
        out.insert("jsonrpc".into(), json!("2.0"));
        out.insert("id".into(), id);
        match self.call(view, &method, params) {
            None => {
                out.insert(
                    "error".into(),
                    RpcError::new(-32601, format!("{method} is not supported")).to_json(),
                );
            }
            Some(Ok(result)) => {
                out.insert("result".into(), result);
            }
            Some(Err(e)) => {
                out.insert("error".into(), e.to_json());
            }
        }
        Value::Object(out)
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn call<V: ChainView + ?Sized>(
        &self,
        view: &mut V,
        method: &str,
        params: Js<'_>,
    ) -> Option<Answer> {
        let p = |i: usize| -> Result<Option<Value>, RpcError> {
            Ok(js::params(params)?.get(i).cloned())
        };
        Some(match method {
            "web3_clientVersion" => Ok(json!(format!("{}/{}", self.client, self.chain))),
            "net_version" => Ok(json!(self.chain_id().to_string())),
            "eth_chainId" => Ok(hexn(self.chain_id())),
            "eth_syncing" | "eth_mining" => Ok(json!(false)),
            "eth_accounts" => Ok(json!([])),
            "eth_blockNumber" => Ok(hexn(view.height())),
            "eth_gasPrice" => Ok(hexn(GWEI)),
            "eth_maxPriorityFeePerGas" => Ok(json!("0x0")),
            "eth_feeHistory" => js::params(params).and_then(|ps| self.fee_history(view, &ps)),
            "eth_getBalance" => p(0).and_then(|a| {
                let a = js::address(a.as_ref())?;
                Ok(hexn(self.rule.state().balance(&a)))
            }),
            "eth_getTransactionCount" => js::params(params).and_then(|ps| {
                let a = js::address(ps.first())?;
                let n = self.rule.state().nonce(&a);
                let pending = matches!(ps.get(1), Some(Value::String(t)) if t == "pending");
                Ok(hexn(if pending {
                    u128::from(n) + self.pending_from(view, a)
                } else {
                    u128::from(n)
                }))
            }),
            "eth_getCode" => p(0).and_then(|a| {
                let a = js::address(a.as_ref())?;
                Ok(json!(hexb(&self.rule.state().world().code(&a))))
            }),
            "eth_getStorageAt" => js::params(params).and_then(|ps| {
                let a = js::address(ps.first())?;
                let slot = js::set_length_left_32(&js::hex_to_bytes(ps.get(1))?)?;
                let v = self
                    .rule
                    .state()
                    .world()
                    .storage(&a, U256::from_be_bytes(slot));
                // the stored value as the trie keeps it: without leading zero bytes
                let bytes = v.to_be_bytes::<32>();
                let first = bytes.iter().position(|b| *b != 0).unwrap_or(32);
                Ok(json!(hexb(&bytes[first..])))
            }),
            "eth_call" => p(0).and_then(|c| {
                let s = self.run(view, c.as_ref())?;
                Ok(json!(hexb(&s.output)))
            }),
            "eth_estimateGas" => p(0).and_then(|c| self.estimate(view, c.as_ref())),
            "eth_sendRawTransaction" => p(0).and_then(|raw| self.send_raw(view, raw.as_ref())),
            "eth_getTransactionReceipt" => p(0).map(|h| {
                let st = self.rule.state();
                hash_key(h.as_ref())
                    .and_then(|k| st.receipt(&k))
                    .map_or(Value::Null, |r| self.receipt_json(view, r))
            }),
            "eth_getTransactionByHash" => p(0).map(|h| {
                let st = self.rule.state();
                hash_key(h.as_ref())
                    .and_then(|k| st.receipt(&k))
                    .map_or(Value::Null, |r| self.tx_json(view, r))
            }),
            "eth_getBlockByNumber" => js::params(params).and_then(|ps| {
                let h = height_of_tag(ps.first(), view.height())?;
                Ok(self.block_json(view, h, js::truthy(ps.get(1))))
            }),
            "eth_getBlockByHash" => js::params(params).map(|ps| {
                let key = js::to_string(ps.first()).to_lowercase();
                let hash = key
                    .strip_prefix("0x")
                    .filter(|b| b.len() == 64 && b.bytes().all(|c| c.is_ascii_hexdigit()))
                    .and_then(|b| BlockHash::from_str(b).ok());
                match hash.and_then(|h| view.height_of(&h)) {
                    Some(i) => self.block_json(view, f64::from(i), js::truthy(ps.get(1))),
                    None => Value::Null,
                }
            }),
            "eth_getBlockTransactionCountByNumber" => p(0).and_then(|tag| {
                let h = height_of_tag(tag.as_ref(), view.height())?;
                let st = self.rule.state();
                let n = as_height(h)
                    .and_then(|h| st.block(h))
                    .map_or(0, |b| b.hashes.len());
                Ok(hexn(n))
            }),
            "eth_getLogs" => p(0).and_then(|f| self.logs(view, f.as_ref())),
            _ => return None,
        })
    }

    /// `eth_feeHistory([count, , percentiles])`: `count` blocks back from the
    /// tip at a flat 1 gwei, no gas used, no tips.
    fn fee_history<V: ChainView + ?Sized>(&self, view: &V, ps: &[Value]) -> Answer {
        /// The most blocks answered (the reference has no limit: it builds
        /// arrays as long as it is asked for).
        const MAX_BLOCKS: f64 = 1024.0;
        let n = js::bigint(ps.first())?.to_f64();
        let oldest = (f64::from(view.height()) - n + 1.0).max(0.0);
        let valid = |len: f64| (0.0..=f64::from(u32::MAX)).contains(&len);
        if !valid(n + 1.0) || !valid(n) {
            return Err(thrown("Invalid array length"));
        }
        if n > MAX_BLOCKS {
            return Err(thrown(format!(
                "eth_feeHistory answers at most {MAX_BLOCKS} blocks, not {}",
                js::number_to_string(n)
            )));
        }
        let n = n as usize;
        let pct = ps.get(2);
        let reward = if js::truthy(pct) {
            let Some(Value::Array(pct)) = pct else {
                return Err(thrown("pct.map is not a function"));
            };
            Some(vec![json!(vec!["0x0"; pct.len()]); n])
        } else {
            None
        };
        let mut m = Map::new();
        m.insert("oldestBlock".into(), hexn(oldest as u64));
        m.insert(
            "baseFeePerGas".into(),
            json!(vec![format!("{GWEI:#x}"); n + 1]),
        );
        m.insert("gasUsedRatio".into(), json!(vec![0; n]));
        if let Some(r) = reward {
            m.insert("reward".into(), Value::Array(r));
        }
        Ok(Value::Object(m))
    }

    /// Carriers in the mempool signed by `a` (`evmrpc.mjs pendingFrom`).
    fn pending_from<V: ChainView + ?Sized>(&self, view: &V, a: Address) -> u128 {
        let chain_id = self.chain_id();
        let n = view
            .mempool()
            .iter()
            .flat_map(|tx| tx.output.iter())
            .filter_map(|o| parse_carrier(&o.script_pubkey))
            .filter(|rlp| decode_carrier(rlp, chain_id).is_ok_and(|c| c.sender == a))
            .count();
        n as u128
    }

    /// The call a request's object describes (`evmrpc.mjs callOpts`), run
    /// in the next block; a failure is error 3 with what it returned.
    fn run<V: ChainView + ?Sized>(&self, view: &V, c: Js<'_>) -> Result<Simulation, RpcError> {
        let to = js::prop(c, "to")?;
        let to = if js::truthy(to) {
            Some(js::address(to)?)
        } else {
            None
        };
        let from = js::prop(c, "from")?;
        let from = if js::nullish(from) {
            Address::ZERO
        } else {
            js::address(from)?
        };
        let value = js::prop(c, "value")?;
        let value = if js::truthy(value) {
            let v = js::bigint(value)?;
            if v.negative {
                return Err(thrown("a call's value cannot be negative"));
            }
            v.magnitude
        } else {
            Some(U256::ZERO)
        };
        let data = js::prop(c, "data")?;
        let data = if js::nullish(data) {
            js::prop(c, "input")?
        } else {
            data
        };
        let data = if js::truthy(data) {
            js::hex_to_bytes(data)?
        } else {
            Vec::new()
        };
        let gas = js::prop(c, "gas")?;
        let st = self.rule.state();
        let gas = if js::truthy(gas) {
            let g: BigInt = js::bigint(gas)?;
            if g.negative {
                return Err(thrown("a call's gas cannot be negative"));
            }
            g.magnitude
                .map_or(u64::MAX, |m| u64::try_from(m).unwrap_or(u64::MAX))
        } else {
            st.config().gas_limit
        };
        let height = view.height().saturating_add(1);
        let time = u32::try_from(view.now()).unwrap_or(u32::MAX);
        let sim = match value {
            Some(value) => st.simulate(height, time, from, to, value, Bytes::from(data), gas),
            // more than 256 bits of value: more than any balance
            None if to.is_some() => Ok(Simulation {
                success: false,
                output: Bytes::new(),
                execution_gas: 0,
            }),
            None => Err("insufficient balance".into()),
        }
        .map_err(thrown)?;
        if !sim.success {
            return Err(RpcError {
                code: 3,
                message: "execution reverted".into(),
                data: Some(hexb(&sim.output)),
            });
        }
        Ok(sim)
    }

    /// `eth_estimateGas`: 21,000, 32,000 more for a creation, the calldata
    /// (4 per zero byte, 16 per other), and half as much again as the
    /// execution used plus 10,000 when it used any. A plain transfer is
    /// exactly 21,000; a call under-counts what a transaction pays (cold
    /// accounts, value transfers, first writes), hence the margin. Unused
    /// gas is not charged.
    fn estimate<V: ChainView + ?Sized>(&self, view: &V, c: Js<'_>) -> Answer {
        let sim = self.run(view, c)?;
        let to = js::truthy(js::prop(c, "to")?);
        let data = js::prop(c, "data")?;
        let data = if js::nullish(data) {
            js::prop(c, "input")?
        } else {
            data
        };
        let data = if js::truthy(data) {
            js::hex_to_bytes(data)?
        } else {
            Vec::new()
        };
        let calldata: u128 = data.iter().map(|b| if *b == 0 { 4 } else { 16 }).sum();
        let exec = u128::from(sim.execution_gas);
        let margin = if exec > 0 { exec * 3 / 2 + 10_000 } else { 0 };
        Ok(hexn(
            21_000 + if to { 0 } else { 32_000 } + calldata + margin,
        ))
    }

    fn send_raw<V: ChainView + ?Sized>(&self, view: &mut V, raw: Js<'_>) -> Answer {
        let rlp = js::hex_to_bytes(raw)?;
        let carried = read_raw(&rlp, self.chain_id())?;
        let script = carrier_script(&rlp).map_err(|e| thrown(e.to_string()))?;
        let txid = view.carry(script).map_err(thrown)?;
        let hash = hexb(carried.hash.as_slice());
        let from = hexb(carried.sender.as_slice());
        let txid = txid.to_string();
        view.log(&format!(
            "evm: carried {}… from {}… in {}…",
            &hash[..18],
            &from[..10],
            &txid[..16]
        ));
        Ok(json!(hash))
    }

    fn block_hash<V: ChainView + ?Sized>(view: &V, height: u32) -> String {
        view.block_hash(height)
            .map_or_else(|| ZERO32.to_string(), |h| format!("0x{h}"))
    }

    fn log_json<V: ChainView + ?Sized>(view: &V, r: &Receipt) -> Vec<Value> {
        let block_hash = Self::block_hash(view, r.height);
        r.logs
            .iter()
            .enumerate()
            .map(|(i, l)| {
                json!({
                    "address": hexb(l.address.as_slice()),
                    "topics": l.topics().iter().map(|t| hexb(t.as_slice())).collect::<Vec<_>>(),
                    "data": hexb(&l.data.data),
                    "blockNumber": hexn(r.height),
                    "transactionHash": hexb(r.transaction_hash.as_slice()),
                    "transactionIndex": "0x0",
                    "blockHash": block_hash,
                    "logIndex": hexn(i),
                    "removed": false,
                })
            })
            .collect()
    }

    fn receipt_json<V: ChainView + ?Sized>(&self, view: &V, r: &Receipt) -> Value {
        json!({
            "transactionHash": hexb(r.transaction_hash.as_slice()),
            "transactionIndex": hexn(r.index),
            "blockHash": Self::block_hash(view, r.height),
            "blockNumber": hexn(r.height),
            "from": hexb(r.from.as_slice()),
            "to": r.to.map(|a| hexb(a.as_slice())),
            "cumulativeGasUsed": hexn(r.gas_used),
            "gasUsed": hexn(r.gas_used),
            "contractAddress": r.contract_address.map(|a| hexb(a.as_slice())),
            "logs": Self::log_json(view, r),
            "logsBloom": hexb(r.logs_bloom().as_slice()),
            "status": if r.status { "0x1" } else { "0x0" },
            "effectiveGasPrice": hexn(r.effective_gas_price()),
            "type": "0x0",
        })
    }

    /// The transaction as ethereumjs's `toJSON()` writes it, then the
    /// reference's additions: hash, sender, block, index, `gas`.
    fn tx_json<V: ChainView + ?Sized>(&self, view: &V, r: &Receipt) -> Value {
        let e = &r.envelope;
        let sig = *e.signature();
        let mut m = Map::new();
        m.insert("type".into(), hexn(e.ty()));
        m.insert("nonce".into(), hexn(e.nonce()));
        m.insert("gasLimit".into(), hexn(e.gas_limit()));
        if let Some(to) = e.to() {
            m.insert("to".into(), json!(hexb(to.as_slice())));
        }
        m.insert("value".into(), hexn(e.value()));
        m.insert("data".into(), json!(hexb(e.input())));
        m.insert("v".into(), hexn(v_of(e, &sig)));
        m.insert("r".into(), hexn(sig.r()));
        m.insert("s".into(), hexn(sig.s()));
        m.insert("chainId".into(), hexn(self.chain_id()));
        match e {
            TxEnvelope::Legacy(t) => {
                m.insert("gasPrice".into(), hexn(t.tx().gas_price));
            }
            TxEnvelope::Eip2930(t) => {
                m.insert("yParity".into(), hexn(u8::from(sig.v())));
                m.insert("gasPrice".into(), hexn(t.tx().gas_price));
                m.insert("accessList".into(), access_list_json(&t.tx().access_list));
            }
            TxEnvelope::Eip1559(t) => {
                m.insert("yParity".into(), hexn(u8::from(sig.v())));
                m.insert(
                    "maxPriorityFeePerGas".into(),
                    hexn(t.tx().max_priority_fee_per_gas),
                );
                m.insert("maxFeePerGas".into(), hexn(t.tx().max_fee_per_gas));
                m.insert("accessList".into(), access_list_json(&t.tx().access_list));
            }
            // not carried (`tx::decode_carrier`)
            TxEnvelope::Eip4844(_) | TxEnvelope::Eip7702(_) => {}
        }
        m.insert("hash".into(), json!(hexb(r.transaction_hash.as_slice())));
        m.insert("from".into(), json!(hexb(r.from.as_slice())));
        m.insert("blockHash".into(), json!(Self::block_hash(view, r.height)));
        m.insert("blockNumber".into(), hexn(r.height));
        m.insert("transactionIndex".into(), hexn(r.index));
        m.insert("gas".into(), hexn(e.gas_limit()));
        Value::Object(m)
    }

    /// The block at height `h` (a JavaScript number) as an Ethereum block,
    /// `null` outside the chain.
    fn block_json<V: ChainView + ?Sized>(&self, view: &V, h: f64, full: bool) -> Value {
        if h < 0.0 || h > f64::from(view.height()) {
            return Value::Null;
        }
        let Some(h) = as_height(h) else {
            return Value::Null;
        };
        let st = self.rule.state();
        let b = st.block(h);
        let hashes: &[B256] = b.map_or(&[], |b| &b.hashes);
        let gas_used: u128 = hashes
            .iter()
            .filter_map(|x| st.receipt(x))
            .map(|r| u128::from(r.gas_used))
            .sum();
        let transactions: Vec<Value> = if full {
            hashes
                .iter()
                .map(|x| st.receipt(x).map_or(Value::Null, |r| self.tx_json(view, r)))
                .collect()
        } else {
            hashes.iter().map(|x| json!(hexb(x.as_slice()))).collect()
        };
        json!({
            "number": hexn(h),
            "hash": Self::block_hash(view, h),
            "parentHash": if h > 0 { Self::block_hash(view, h - 1) } else { ZERO32.to_string() },
            "timestamp": hexn(view.header_time(h).unwrap_or(0)),
            "gasLimit": hexn(st.config().gas_limit),
            "gasUsed": hexn(gas_used),
            "baseFeePerGas": hexn(GWEI),
            "miner": ZEROADDR,
            "nonce": "0x0000000000000000",
            "sha3Uncles": ZERO32,
            "logsBloom": zero_bloom(),
            "transactionsRoot": ZERO32,
            "stateRoot": b.map_or_else(|| ZERO32.to_string(), |b| hexb(b.root.as_slice())),
            "receiptsRoot": ZERO32,
            "difficulty": "0x0",
            "totalDifficulty": "0x0",
            "extraData": "0x",
            "size": "0x0",
            "mixHash": ZERO32,
            "uncles": [],
            "transactions": transactions,
        })
    }

    /// `eth_getLogs`: the logs of the receipts in the block range, in chain
    /// order, by address (any of a list, compared in lower case) and by
    /// topic position (`null` or an empty string for any, a list for any of
    /// it, compared as written).
    fn logs<V: ChainView + ?Sized>(&self, view: &V, f: Js<'_>) -> Answer {
        let tip = view.height();
        let from = js::prop(f, "fromBlock")?;
        let from = height_of_tag(if js::nullish(from) { None } else { from }, tip)?;
        let to = js::prop(f, "toBlock")?;
        let to = height_of_tag(if js::nullish(to) { None } else { to }, tip)?;
        let address = js::prop(f, "address")?;
        let want: Option<Vec<String>> = if js::truthy(address) {
            let list: Vec<&Value> = match address {
                Some(Value::Array(a)) => a.iter().collect(),
                Some(v) => vec![v],
                None => Vec::new(),
            };
            Some(
                list.into_iter()
                    .map(|a| match a {
                        Value::String(s) => Ok(s.to_lowercase()),
                        Value::Null => Err(thrown(
                            "Cannot read properties of null (reading 'toLowerCase')",
                        )),
                        _ => Err(thrown("a.toLowerCase is not a function")),
                    })
                    .collect::<Result<_, _>>()?,
            )
        } else {
            None
        };
        let topics = js::prop(f, "topics")?;
        let st = self.rule.state();
        let mut out = Vec::new();
        for r in st.receipts() {
            let h = f64::from(r.height);
            if h < from || h > to {
                continue;
            }
            for l in Self::log_json(view, r) {
                if let Some(want) = &want {
                    if !want
                        .iter()
                        .any(|a| Some(a.as_str()) == l["address"].as_str())
                    {
                        continue;
                    }
                }
                if js::truthy(topics) {
                    let Some(Value::Array(ts)) = topics else {
                        return Err(thrown("f.topics.some is not a function"));
                    };
                    let have = l["topics"].as_array().expect("topics are a list");
                    let excluded = ts.iter().enumerate().any(|(i, t)| {
                        if !js::truthy(Some(t)) {
                            return false;
                        }
                        let topic = have.get(i);
                        match t {
                            Value::Array(alts) => !alts.iter().any(|a| Some(a) == topic),
                            t => topic != Some(t),
                        }
                    });
                    if excluded {
                        continue;
                    }
                }
                out.push(l);
            }
        }
        Ok(Value::Array(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_read_as_heights() {
        let h = |v: Value| height_of_tag(Some(&v), 7).unwrap();
        assert_eq!(height_of_tag(None, 7).unwrap(), 7.0);
        assert_eq!(h(json!("pending")), 7.0);
        assert_eq!(h(json!("earliest")), 0.0);
        assert_eq!(h(json!("0x10")), 16.0);
        assert_eq!(h(json!(true)), 1.0);
        assert_eq!(h(json!("-1")), -1.0);
        assert!(h(json!(format!("0x1{}", "0".repeat(80)))) > 1e70);
        assert_eq!(as_height(3.0), Some(3));
        assert_eq!(as_height(-1.0), None);
    }

    #[test]
    fn hash_keys_are_exact() {
        let k = |s: &str| hash_key(Some(&json!(s)));
        assert!(k(&format!("0x{}", "Ab".repeat(32))).is_some());
        assert!(k(&format!("0X{}", "ab".repeat(32))).is_some());
        assert!(k(&format!("0x{}", "ab".repeat(31))).is_none());
        assert!(k("undefined").is_none());
        assert!(hash_key(None).is_none());
    }
}
