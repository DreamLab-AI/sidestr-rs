//! A teller for [Web Ledgers](https://webledgers.org/) on txbt4: accounts are
//! did:nostr keys, balances a Web Ledger, deposits one taproot address per
//! account, withdrawals and transfers signed requests. A Rust port of
//! [solidpayorg/teller](https://github.com/solidpayorg/teller) `lib/teller.mjs`
//! at `7c00cea` by Melvin Carvalho (AGPL-3.0-or-later); the proposal is
//! [solidpayorg/webledgers#7](https://github.com/solidpayorg/webledgers/issues/7).
//!
//! One operator holds the deposits and writes the ledger; everyone else reads
//! it and signs requests.
//!
//! - **The ledger** ([`ledger`]) is a Web Ledger JSON document with a genesis
//!   (operator, name, currency, confirmations) fixed at creation; its hash is
//!   the SHA-256 of the genesis's JCS and is its identity. The operator
//!   publishes it as a Nostr event of kind [`LEDGER_KIND`], addressable by
//!   `d` = the hash, and replaces it as balances move. Deposits are credited
//!   once by outpoint; transfers and withdrawals once by request id.
//! - **Deposits** ([`deposit`]): each account's address is the operator's
//!   point plus `tagged("webledgers/deposit", ledgerHash ‖ account ‖ nonce)·G`,
//!   added to the full point and never its even-y lift (`sidestr/spec`
//!   `keys.mjs`). Anyone with the operator's did and the ledger's hash
//!   recomputes it; only the operator can spend it.
//! - **Requests** ([`request`]) are Nostr events of kind [`REQUEST_KIND`]
//!   signed by the account's key: `join`, `withdraw`, `transfer`.
//! - **Payouts** ([`payout`]) spend the deposits, each input signed with its
//!   own derived secret, checked under the chain's sighash rules and against
//!   the signed size before anything is returned.
//!
//! What it is not: not private (anyone who knows the operator's point can
//! link a ledger's deposit addresses), not hardware-wallet signable (a plain
//! additive tweak), and custodial (the operator can refuse a withdrawal). It
//! is checkable: every deposit traces to an account from public data, every
//! change is a signed request or a deposit seen on-chain.
//!
//! # Pure
//!
//! No I/O, no clock, no randomness: the caller passes the time (`now`,
//! `created_at`), request ids, the chain's coins and the sighash rules, and
//! publishes and broadcasts what comes back. Signatures use zero BIP 340
//! auxiliary randomness, so every event and payout is a function of its
//! inputs and the key. The crate needs `std` because `sidestr-core` and
//! `sidestr-nostr`, whose sighash, verifier, addresses and Nostr event it
//! uses, are `std` crates.
//!
//! # Example
//!
//! ```
//! use bitcoin::secp256k1::SecretKey;
//! use webledgers_teller::*;
//!
//! let operator = SecretKey::from_slice(&[0x11; 32]).unwrap();
//! let alice = SecretKey::from_slice(&[0x22; 32]).unwrap();
//! let op_did = format!("did:nostr:{}", pubkey_hex(&operator));
//! let a = format!("did:nostr:{}", pubkey_hex(&alice));
//!
//! // a new ledger: its hash is the hash of its genesis
//! let mut l = new_ledger(&LedgerParams::new(&op_did, "Table 7", 1_759_300_000)).unwrap();
//! check_ledger(&l).unwrap();
//!
//! // Alice's deposit address, which anyone can recompute from the operator's did
//! let dep = deposit_address(&op_did, &l.hash, &a, 0, DEFAULT_HRP).unwrap();
//! assert!(dep.address.starts_with("tb1p"));
//!
//! // a deposit seen on-chain is credited once
//! let funding = "ab".repeat(32);
//! let c = Credit { account: a.clone(), txid: funding.clone(), vout: 0, value: 50_000, height: Some(152_100) };
//! assert!(credit(&mut l, &c, 1_759_300_100).unwrap().applied());
//!
//! // Alice signs a withdrawal request; the operator reads it back verified
//! let to = "tb1pfu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4quvla6g";
//! let id = request_id([1; 16]);
//! let ev = request_event(&alice, &RequestParams::withdraw(&l.hash, 20_000, to, &id), 1_759_300_200).unwrap();
//! let req = parse_request(&ev, &l.hash).unwrap();
//! assert_eq!((req.op, req.account.as_str(), req.amount), (Op::Withdraw, a.as_str(), Some(20_000)));
//!
//! // the payout: the deposit is the coin, change to the operator's own deposit address
//! let change = deposit_address(&op_did, &l.hash, &op_did, 0, DEFAULT_HRP).unwrap();
//! let to_script = sidestr_core::address::address_to_script(to).unwrap().to_hex_string();
//! let coins = [Coin::from_deposit(&dep, &funding, 0, 50_000)];
//! let plan = plan_payout(&PayoutParams { coins: &coins, amount: 20_000, rate: 1, to_script: &to_script, change_script: &change.script }).unwrap();
//! let paid = sign_payout(&plan, &operator, TXBT4_RULES).unwrap();
//! assert!(plan.fee >= paid.vsize);
//!
//! // and the ledger debited, the payout's txid the receipt
//! let d = Debit { id: req.id, account: a.clone(), amount: 20_000, to: to.into(), txid: paid.txid };
//! assert!(debit(&mut l, &d, 1_759_300_300).unwrap().applied());
//! assert_eq!(balance(&l, &a).unwrap(), 30_000);
//! ```
//!
//! # What changed in the port
//!
//! - The key rule (`keys.mjs`) is libsecp256k1's arithmetic through
//!   `bitcoin::secp256k1`; the sighash and the script check are
//!   `sidestr-core`'s (Knots' unified sighash for txbt4), and the Nostr event
//!   and its verification `sidestr-nostr`'s. Nothing cryptographic is
//!   hand-rolled.
//! - Time, request ids and the chain's rules are parameters; the teller reads
//!   the clock, draws ids from `crypto.getRandomValues` and loads the chain's
//!   engine.
//! - Fee rates are whole sat/vB (the teller pays at 1 and accepts fractions).
//! - Amounts given as numbers are `u64`, so the refusals of negative and
//!   fractional numbers become the type; amounts read from text ([`sats`])
//!   are refused in the teller's words.
//! - The ledger event (kind 30333) the teller's page writes and reads inline
//!   is here as [`ledger_template`], [`ledger_event`], [`read_ledger_event`]
//!   and [`latest_ledger`].
#![forbid(unsafe_code)]
#![deny(
    missing_docs,
    missing_debug_implementations,
    rustdoc::broken_intra_doc_links
)]

pub mod account;
pub mod deposit;
pub mod error;
mod keys;
pub mod ledger;
pub mod payout;
pub mod request;
mod sign;

pub use account::{account_of, check_sats, sats, x_of, MAX_SATS};
pub use deposit::{deposit_address, deposit_secret, watch_list, DepositAddress, DEFAULT_HRP};
pub use error::{Error, Result};
pub use ledger::{
    balance, check_ledger, credit, debit, jcs, latest_ledger, ledger_event, ledger_hash,
    ledger_template, new_ledger, parse_ledger, read_ledger_event, total, transfer, Credit, Debit,
    Deposit, Entry, Genesis, Ledger, LedgerParams, Outcome, Payout, Transfer,
};
pub use payout::{
    plan_payout, prevouts, sign_payout, sign_payout_txbt4, unsigned_tx, vsize_estimate, vsize_of,
    Coin, PayoutParams, Plan, PlanOutput, SignedPayout,
};
pub use request::{
    parse_request, request_event, request_id, request_tags, request_template, Op, Request,
    RequestParams,
};
pub use sidestr_core::sighash::SighashRules;
pub use sidestr_nostr::event::{Event, UnsignedEvent};
pub use sign::pubkey_hex;

/// The tag a deposit address's tweak is hashed under.
pub const DEPOSIT_TAG: &str = "webledgers/deposit";
/// The ledger's Nostr kind: addressable by `d` = its hash, replaced by the
/// operator as balances move.
pub const LEDGER_KIND: u32 = 30333;
/// A request's Nostr kind (join, withdraw, transfer): regular, signed by the
/// account's key.
pub const REQUEST_KIND: u32 = 3700;
/// The smallest change output a payout makes; less is left to the fee.
pub const DUST: u64 = 330;
/// The smallest withdrawal or payout, in satoshis.
pub const MIN_PAY: u64 = 546;
/// The Web Ledgers JSON-LD context.
pub const CONTEXT: &str = "https://w3id.org/webledgers";
/// The currency a ledger is in unless it says otherwise.
pub const DEFAULT_CURRENCY: &str = "txbt4";
/// The sighash rules of txbt4, the BLAKE2b testnet4 the teller runs on:
/// Knots' unified sighash, hash type `0x21`
/// (`sidestr_core::sighash::rules_for(Family::Blake2b)`).
pub const TXBT4_RULES: SighashRules = SighashRules::KnotsUnified;
