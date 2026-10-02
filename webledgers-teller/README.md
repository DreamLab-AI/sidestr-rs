# webledgers-teller

> Part of [sidestr-rs](https://github.com/DreamLab-AI/sidestr-rs). Rust port of Melvin Carvalho's teller for Web Ledgers, AGPL-3.0-or-later: did:nostr accounts with balances on a public ledger, paid in and out on txbt4.

A teller for [Web Ledgers](https://webledgers.org/), in Rust: accounts are
did:nostr keys, balances a Web Ledger, deposits one taproot address per
account, withdrawals and transfers signed requests. One operator holds the
deposits and writes the ledger; everyone else reads it and signs requests.
The proposal is
[solidpayorg/webledgers#7](https://github.com/solidpayorg/webledgers/issues/7).

```toml
[dependencies]
webledgers-teller = "0.1"
```

- **The ledger** is a Web Ledger JSON document with a genesis (operator,
  name, currency, confirmations) fixed at creation; its hash, the SHA-256 of
  the genesis's JCS, is its identity. The operator publishes it as a Nostr
  event of kind 30333 (addressable by `d` = the hash) and replaces it as
  balances move. A reader accepts only the operator's own signed copy.
  Deposits are credited once by outpoint; transfers and withdrawals once by
  request id; amounts are whole satoshis, written as strings.
- **Deposits.** Each account's deposit address is the operator's point plus
  `tagged("webledgers/deposit", ledgerHash ‖ account ‖ nonce)·G`, added to
  the full point and never its even-y lift (sidestr/spec `keys.mjs`). The
  operator is read as its did (the `02` point of its x) whatever parity it is
  given as, and its secret is normalised to that same point. Anyone with the
  operator's did and the ledger's hash recomputes the address; only the
  operator can spend it.
- **Requests** are Nostr events of kind 3700 signed by the account's key:
  `join` (be watched), `withdraw` (an amount to an address), `transfer` (an
  amount to an account).
- **Payouts** spend the deposits: coins largest first, change of at least 330
  sat back to the operator's own deposit address, less folded into the fee;
  each input signed with its own derived secret under the chain's sighash
  rules (Knots' unified sighash, `0x21`, on txbt4), every input checked, and
  the fee checked against the signed size. The size estimate is 58 vB per
  key-path input, the teller's fix for a payout once refused as
  "min relay fee not met, 154 < 155".

```rust
use bitcoin::secp256k1::SecretKey;
use webledgers_teller::*;

let operator = SecretKey::from_slice(&[0x11; 32])?;
let op_did = format!("did:nostr:{}", pubkey_hex(&operator));
let mut ledger = new_ledger(&LedgerParams::new(&op_did, "Table 7", now))?;

let alice = "did:nostr:…";
let deposit = deposit_address(&op_did, &ledger.hash, alice, 0, DEFAULT_HRP)?;   // tb1p…
credit(&mut ledger, &Credit { account: alice.into(), txid, vout, value, height }, now)?;

let req = parse_request(&event_from_a_relay, &ledger.hash)?;                    // kind 3700, verified
let plan = plan_payout(&PayoutParams { coins: &coins, amount, rate: 1, to_script: &to, change_script: &change.script })?;
let paid = sign_payout(&plan, &operator, TXBT4_RULES)?;                           // broadcast paid.hex
debit(&mut ledger, &Debit { id: req.id, account: req.account, amount, to: to_address, txid: paid.txid }, now)?;
let ev = ledger_event(&operator, &ledger, now)?;                                  // publish (kind 30333)
```

The crate is pure: no I/O, no clock, no randomness. The caller passes the
time, request ids, the coins the chain holds and the sighash rules, and
publishes and broadcasts what comes back. Signatures use zero BIP 340
auxiliary randomness. It needs `std`, as `sidestr-core` and `sidestr-nostr`
do.

What it is not: not private (anyone who knows the operator's point can link
a ledger's deposit addresses), not hardware-wallet signable (a plain additive
tweak), and custodial (the operator can refuse a withdrawal). It is
checkable: every deposit traces to an account from public data, every change
is a signed request or a deposit seen on-chain. txbt4 coins are test coins.

## Attribution

This crate is a port of **teller** by Melvin Carvalho
([github.com/solidpayorg/teller](https://github.com/solidpayorg/teller),
AGPL-3.0-or-later), from commit `7c00ceac4dc37e0526eccd5ae62e1680ac88ec2a`
(`lib/teller.mjs`, `test/teller-test.mjs`, and the ledger event in
`teller.js`). Two parts come from the libraries the teller loads, by the same
author and under the AGPL:

- the key rule (`normalize`, `basePoint`, `tweakPoint`, `tweakSecret`,
  `taggedScalar`, …) from `siding/lib/keys.mjs` in
  [sidestr/spec](https://github.com/sidestr/spec) at `bd1d692` (through
  `e8deb63161c7459ed39c01d2ca9fda3d860b65b6`), with its known answers
  `siding/test/keys-vectors.json` vendored as `tests/vectors/keys-vectors.json`;
- the key-path sighash and the script check (`siding/lib/txsign.mjs`, the
  kernel of [bitcoin-desktop/schema](https://github.com/bitcoin-desktop/schema)),
  through [`sidestr-core`](https://crates.io/crates/sidestr-core).

Every function names its original.

## What changed in the port

- The key arithmetic is libsecp256k1's through `bitcoin::secp256k1`; the
  sighash and script check are `sidestr-core`'s; the Nostr event and its
  verification are `sidestr-nostr`'s. Nothing cryptographic is hand-rolled.
- Time, request ids and the chain's sighash rules are parameters. The teller
  reads the clock, draws ids from `crypto.getRandomValues` and loads the
  chain's engine.
- Fee rates are whole sat/vB. The teller pays at 1 and accepts fractions.
- Amounts given as numbers are `u64`, so negative and fractional numbers
  cannot be passed at all. Amounts read from text are refused in the
  teller's words.
- The ledger event (kind 30333), which the teller's page writes and reads
  inline, is here as `ledger_template`, `ledger_event`, `read_ledger_event`
  and `latest_ledger`.
- JCS covers the plain JSON these documents are. Integers are exact; a
  number with a fraction is outside what the teller writes.

## Tests

`cargo test` runs the teller's 24 checks, named as the teller names them
(`tests/teller.rs`), the `keys-vectors.json` cases, and the edges of each
refusal. With `TELLER` (a teller checkout), `SCHEMA`, `BLAKETESTNODE` and
`SIDESTR_LIB` (or `SIDESTR_SIDING`) set, `tests/oracle.rs` also runs the
teller's own suite against those checkouts and cross-checks this crate
against `lib/teller.mjs` through `tests/xcheck-teller.mjs`. The cross-check
covers JCS, accounts, amounts, ledgers and their hashes, a script of credits,
transfers and debits, deposit addresses for every form of operator key,
secrets, watch lists, payout plans with their unsigned transactions, payouts
signed on each side and checked by the other, and requests signed on each
side and read by the other.

## Licence

AGPL-3.0-or-later, as the teller is. See `LICENSE`.
