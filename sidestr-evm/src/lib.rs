//! `sidestr-evm` — the `evm` rule for sidestr chains, in Rust: Ethereum
//! transactions ride inside ordinary sidechain transactions, every validator
//! runs them in block order through an EVM and keeps the account state
//! beside the UTXO set, and the coinbase commits the state root so validators
//! agree. Sats and EVM balance meet at a fixed rate: **1 sat = 1 gwei**.
//!
//! This crate is a port of the `evm` rule of **siding**, the reference
//! implementation by Melvin Carvalho (<https://github.com/sidestr/spec>,
//! AGPL-3.0): `siding/lib/overlays/evm.mjs`, the parts of
//! `lib/overlays/index.mjs` and `lib/chain.mjs` that run it, and the
//! Ethereum JSON-RPC over it, `lib/evmrpc.mjs` ([`rpc`]), at
//! `fa86dac83d47b8f70195132e91e9dc083e1d9228` (`@sidestr/spec` 0.0.6), with
//! the design in `proposals/evm.md`. It carries the same licence,
//! AGPL-3.0-only. The reference executes on ethereumjs 10.1.3; this crate on
//! [revm](https://github.com/bluealloy/revm) at the same Cancun rules, with
//! alloy's transaction envelope and alloy-trie's state root. Nothing
//! cryptographic is written here.
//!
//! # The rule (`sidestr:rule-evm`)
//!
//! | record | meaning |
//! |---|---|
//! | an output paying the reserve, then `OP_RETURN evmin:` + 20 bytes | a deposit: the output's sats credit the address × 10⁹ wei |
//! | `OP_RETURN evm:` + a signed Ethereum transaction | executed in output order; a revert is applied, a transaction that cannot be applied (signature, chain id, nonce, funds) makes the block invalid |
//! | an Ethereum transaction to `0x…0501de` with value and 34 bytes of data | a withdrawal: the WITHDRAW account is emptied after it, and the coinbase must pay `floor(value / 10⁹)` sats to that script |
//! | `OP_RETURN evmroot:` + 32 bytes, in the coinbase | the state root after the block, which must be the one execution gives |
//!
//! The coinbase may pay out, beyond fees and claims, exactly the block's
//! withdrawals. Every block runs from the state after the previous one,
//! transactions from index 1, in the environment of [`exec`]: number =
//! height, timestamp = block time, coinbase = the zero address (tips go
//! there), base fee = 1 gwei, the block gas limit not enforced.
//!
//! # Following a chain
//!
//! [`rules_for`] gives the rules a document names — the EVM rule and, as
//! upstream installs it on every chain that names any rule, the assets rule
//! ([`sidestr_core::assets::AssetsRule`]) — and
//! [`sidestr_core::StateOf::from_genesis_with_rules`] carries them from the
//! genesis on. Then [`sidestr_core::StateOf::add_block`] is the whole of
//! validating a block; a clone of the [`EvmRule`] reads balances, code,
//! storage and receipts, and [`rpc::EvmRpc`] answers a wallet's JSON-RPC
//! over it.
//!
//! ```
//! use bitcoin::Amount;
//! use sidestr_core::block::{challenge_for, pubkey_of};
//! use sidestr_core::state::{NextBlock, State};
//! use sidestr_core::ChainDocument;
//! use sidestr_evm::records::deposit_script;
//!
//! let key = bitcoin::secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
//! let me = challenge_for(&pubkey_of(&key));
//! let doc = ChainDocument::from_json_with(&format!(r#"{{
//!   "id": "sidestr:evmdoc", "name": "evmdoc", "parent": "tbtc4", "challenge": "{}", "signer": "{}",
//!   "powLimit": "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
//!   "addressPrefix": "ev", "genesisTime": 1790000000, "rules": ["evm"], "evm": {{ "chainId": 21474 }},
//!   "pegs": [{{ "txid": "{}", "vout": 0, "amount": 100000000, "script": "{}" }}]
//! }}"#, me.to_hex_string(), pubkey_of(&key), "a".repeat(64), me.to_hex_string()), sidestr_evm::KNOWN).unwrap();
//!
//! // the producer carries the rules from the genesis; so does every validator
//! let rules = sidestr_evm::rules_for(&doc).unwrap();
//! let mut state = State::with_key_and_rules(doc.clone(), &key, rules.boxed()).unwrap();
//! let genesis = State::genesis_block_for(&doc, &key).unwrap();
//! let follower_rules = sidestr_evm::rules_for(&doc).unwrap();
//! let mut follower = State::from_genesis_with_rules(doc, &genesis, None, follower_rules.boxed()).unwrap();
//!
//! // every block commits the state root, empty or not
//! let made = rules.produce(&mut state, &key, &NextBlock { time: 1790000100, claims: vec![] }, None).unwrap();
//! follower.add_block(&made.block, None, None).unwrap();
//! let evm = follower_rules.evm.as_ref().unwrap().state();
//! assert_eq!(evm.height(), 1);
//! assert_eq!(evm.root(), sidestr_evm::World::new().root());
//! # let _ = (deposit_script, Amount::ZERO);
//! ```
//!
//! # Where this port departs from siding
//!
//! None of these changes which blocks are valid; `tests/oracle.rs` replays
//! the reference's verdicts on a scripted chain, and every root, byte for
//! byte; `tests/rpc_oracle.rs` replays the reference's JSON-RPC answers.
//!
//! - **The state moves when a block is applied.** The reference's `prepare`
//!   commits the EVM's state as soon as the rule passes, before the kernel's
//!   other checks, and addresses state by height so that a block the kernel
//!   then refuses is simply run over. Here a block's state waits until
//!   `sidestr-core` applies it ([`EvmState::commit`]), as `sidestr-core`
//!   commits its own records; between the two, the state a caller reads is
//!   the applied chain's, never a refused block's.
//! - **State is kept for the tip.** The reference keeps a root per height
//!   and can re-run any block whose parent's root it holds; `sidestr-core`
//!   has no reorganisations, and [`EvmState::prepare`] judges the next
//!   height only.
//! - **The KZG precompile aborts by design.** ethereumjs's point-evaluation
//!   precompile throws without a KZG library, which the reference's
//!   `Common` does not carry, so a transaction reaching `0x0a` invalidates its
//!   block there; [`exec::NoKzg`] does the same deliberately, and blob
//!   transactions are refused when read ([`tx`]), as ethereumjs refuses to
//!   construct them.
//! - **A producer drops a failing transaction whole.** `chain.mjs
//!   sequencedEvm` keeps the effects of a dropped transaction's earlier
//!   records in the root it computes; [`EvmState::sequence`] runs each on a
//!   copy. Only the producer's own blocks differ, and in the direction of
//!   being valid.
//! - **A record longer than 65,535 bytes is not written**
//!   ([`records::push_data`]); the reference writes a wrapped length byte.
//!
//! The JSON-RPC ([`rpc`]) answers as the reference does, byte for byte,
//! with these exceptions:
//!
//! - **Read-only calls start afresh.** ethereumjs's `runCall` starts with
//!   no address warm — not the sender, the target, the precompiles or the
//!   coinbase — and keeps what one call warms (addresses and storage slots)
//!   until the node next runs a transaction, so the reference estimates the
//!   same call differently the second time (a first storage write: 64,303,
//!   then 61,153). revm runs a call as a transaction would run: those four
//!   warm, nothing carried over. `eth_call` answers the same; for code that
//!   reads the sender, itself, a precompile or the coinbase, the execution
//!   `eth_estimateGas` measures is 2,500 gas a first touch cheaper (the
//!   estimate adds half again), which is what the transaction will pay, and
//!   the same every time.
//! - **A reference fault is not reproduced** (sidestr/spec#22). A read-only
//!   creation whose value exceeds the sender's balance makes ethereumjs
//!   throw out of `runCall`: the reference answers `{"code":-32000}` with no
//!   message, and its producer's next block commits a root it then refuses
//!   (as after a call reaching the KZG precompile, whose answer here is the
//!   same `kzg not initialized`). Here the answer is `insufficient balance`,
//!   and every call runs on a copy, so nothing carries over.
//! - **Why a raw transaction does not read** (the text after
//!   `not a transaction: `) is in this crate's words, as in [`tx`]; the code,
//!   -32602 or -32000 (`unsigned or bad signature`), is the reference's for
//!   every case its tests hold. A raw transaction over 65,535 bytes is
//!   refused ([`records::push_data`]); a fee field of 2^128 wei or more does
//!   not read (-32602), where ethereumjs reads it and the mempool refuses it.
//! - **Limits the reference does not have.** A call object's negative
//!   `value` or `gas` is refused (-32000), where ethereumjs runs with it; an
//!   `eth_feeHistory` of more than 1,024 blocks is refused, where the
//!   reference builds arrays as long as asked.
//! - **A batch is answered in order**, one request after another; the
//!   reference starts them all at once (`Promise.all`), so a batch that
//!   sends and reads the same account can interleave there.
//! - **JavaScript's own artefacts.** A method named after a property of
//!   `Object.prototype` (`constructor`, `toString`, …) is -32601, where the
//!   reference calls it; a JSON number beyond the double range or nesting
//!   deeper than 128 levels is a parse error, where `JSON.parse` takes it; a
//!   malformed hex string whose complaint would quote half a UTF-16
//!   surrogate pair quotes U+FFFD.

#![forbid(unsafe_code)]
#![deny(
    missing_docs,
    missing_debug_implementations,
    rustdoc::broken_intra_doc_links
)]

pub mod config;
pub mod error;
pub mod exec;
pub mod records;
pub mod rpc;
pub mod rule;
pub mod state;
pub mod tx;
pub mod world;

pub use config::EvmConfig;
pub use error::{Error, Result};
pub use exec::Simulation;
pub use rule::{rules_for, Built, EvmRule, Produced, Rules, KNOWN, RULE};
pub use state::{BlockRecord, EvmState, Receipt, Sequenced, TxOutcome, Verdict, Withdrawal};
pub use world::World;
