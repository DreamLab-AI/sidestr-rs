# sidestr-wallet

> Part of [sidestr-rs](https://github.com/DreamLab-AI/sidestr-rs). Rust port of Melvin Carvalho's sidestr sidechains, AGPL-3.0-only: the economic engine for did:nostr agents. A did:nostr key is a sidechain wallet.

A wallet for [sidestr](https://github.com/sidestr/spec) sidechains, in Rust:
the coin set for a script, the reference coin selection, taproot key-path
spends, peg-out burns and EVM deposits signed behind a signer port, the
parent-side peg-in transaction shape, and delivery as a `POST /tx` body or a
kind-23500 event.

A wallet needs a chain id and a relay, and nothing of the producer's (SPEC 11).
It reads `chain.json` from a mirror, asks a producer `/coins/<script hex>` — or
folds the block file with [`sidestr-core`](https://crates.io/crates/sidestr-core)
and gets the same list — builds a transaction Bitcoin's rules accept with the
fee at the document's `minFeeRate`, and hands it over. The transaction
authorises itself; a producer includes what validates.

```toml
[dependencies]
sidestr-wallet = "0.3"
sidestr-core = "0.3"
```

```rust
use sidestr_wallet::{build_spend, coins, Permissive, PlainKey, SpendRequest};

let chain = sidestr_core::ChainDocument::from_json(&chain_json)?;   // from a mirror
let listed = coins::from_json(&coins_json)?;                        // GET /coins/<my script>
let me = PlainKey::from_hex(&std::fs::read_to_string(key_file)?)?;  // a derived role key, never the identity key
let paid = build_spend(&SpendRequest { chain: &chain, coins: &listed, tip_height, to: "drm1p…", amount: 25_000, fee: None }, &me, &Permissive)?;
let post = sidestr_wallet::deliver::tx_post(producer_url, &paid.hex);   // POST post.body to post.url
```

## Attribution

This crate is a port of **siding**, the reference implementation of sidestr by
Melvin Carvalho — [github.com/sidestr/spec](https://github.com/sidestr/spec),
AGPL-3.0 — ported from commit `2de40bdac4cba01be0864156a553d8287c22e279` and
brought to SPEC 0.0.4 (`@sidestr/spec` 0.0.6) at `fa86dac83d47b8f70195132e91e9dc083e1d9228` (`lib/txsign.mjs`):
`siding/lib/spend.mjs` (`buildSpend`, `resolveTo`, `deliver`),
`lib/address.mjs`, the transaction and marker construction of
`lib/parent.mjs` (`scanPegins`, `payPegout`) and `lib/checkpoint.mjs`
(`sendCheckpoint`), and the `send` and `faucet` commands of `bin/siding.mjs`.
The mempool policy it builds to — maturity, `pegoutMin`, `minFeeRate`, the
key-path signature check — is `siding/lib/chain.mjs Siding.submit()`, which
`sidestr-core` carries as `State::submit`. `SPEC.md` in the sidestr repository
is the design; the crate documentation cites its sections, and every ported
function names its original. Consensus types, markers, addresses and the chain
document come from `sidestr-core` and are not duplicated.

## What changed in the port

- **Signatures name their hash type.** As siding's `lib/txsign.mjs` does
  since SPEC 0.0.3: the key-path signature follows the parent's family,
  `0x01` (BIP 341) beside stock Bitcoin and `0x21` (Knots' unified sighash)
  beside BLAKE2b, always as a 65-byte witness, and the fee is sized for it.
  `PlainKey` signs with zero auxiliary randomness, so a transaction is a pure
  function of its inputs; given the same randomness the reference signs the
  same bytes (`tests/txsign.rs`).
- **Keys behind a port.** A builder computes the sighash and asks a
  `SpendSigner` for the signature; it never holds a secret. `PlainKey` is the
  in-memory implementation (siding's model), and `key::derive_spend_key` is the
  HMAC-SHA256 domain-separated role-key derivation of agentbox ADR-2101, with
  a known-answer vector cross-checked against Node.js.
- **A policy hook.** Every builder consults a `SpendPolicy` (chain, kind,
  script, amount, fee, inputs) before signing. `Permissive` is the default and
  must be named to be used.
- **Dust is refused**, and change under the dust threshold goes to the fee
  rather than into an unspendable coin. siding does not check.
- **A fixed fee is checked against `minFeeRate`** before signing rather than
  by the producer.
- **Zero BIP 340 auxiliary randomness** in `PlainKey`: a spend is a pure
  function of its inputs and the key.
- **No I/O by default.** `deliver` returns URLs, bodies and unsigned event
  templates; feature `client` adds the HTTP calls over `ureq`. Signing and
  publishing a Nostr event is `sidestr-nostr`'s. Nothing here talks to a
  parent node: `pegin` produces the outputs, the unsigned transaction, and
  the `[{address: btc}, {data: hex}]` argument Bitcoin Core's `send` takes,
  as `parent.mjs` does.
- **Parent records are bounded before they are built.** `pegoutMarkerData`
  and the checkpoint go on the parent inside its 80-byte `OP_RETURN` policy,
  and every marker push must fit the one length byte the shared grammar reads
  (255 bytes); `pegin::pegout_payment_outputs` returns
  `Error::MarkerTooLong` past either bound rather than a well-formed
  `OP_PUSHDATA2` output that `parse_pegout_marker` would never read back
  (audit F4, 0.2.1; the checkpoint's 80-byte bound is `sidestr-core`'s
  `checkpoint_data`). The reference does not check; its `send` fails at the
  node.
- **An EVM deposit needs a chain naming the `evm` rule** (`deposit`, since
  0.4.3; siding's `send --evm`). siding pays the reserve on any chain; where
  the rule is not named nothing is credited, so this crate refuses. The
  transaction is otherwise siding's, byte for byte: the reserve
  (`evm.reserve`, else the challenge) paid, then the value-0
  `OP_RETURN evmin:<address>` marker, then change. The marker comes from
  `sidestr-core`, so the wallet does not link revm; `sidestr-evm`'s tests
  hold it to that crate's `records::deposit_script`.
- **Not carried:** the faucet's relay loop and rate state (its payment is
  `build_spend`; the request template is `deliver::faucet_request`).

## Status — 0.3.0

Spend, burn, peg-in shape, delivery data, coin listing and selection, the
signer and policy ports. Signatures follow the parent's family (SPEC 0.0.3):
`0x01` beside stock Bitcoin, `0x21` beside BLAKE2b. Verified independently before release (GPT-6 Astra, 2026-09-23). The pass
re-ran the gates and checked each 0.0.3 change at its layer against the
reference. It found every block with the same claims, burns and UTXO set on
both engines, for both families. Its probes and its four findings, now
fixed, are kept as `tests/audit_regressions_0_0_3.rs`. Proven:

- the signing parity with the reference's `lib/txsign.mjs` on both families:
  the reference re-signs each Rust transaction's inputs with its own
  `keyPathSighash` and zero auxiliary randomness, and the witnesses are
  byte-identical; each engine verifies the other's signatures under the
  chain's rule; a unified signature is refused at a stock chain's mempool,
  a BIP 341 one accepted beside BLAKE2b (`tests/txsign.rs`);

- a two-input spend and a burn built here on a throwaway chain are accepted by
  `sidestr-core`'s `State::submit` and mined, **and** by siding's
  `Siding.submit()` and mined, with the same txid, fee and vsize; a tampered
  signature is refused by both (`tests/oracle.rs`, `tests/xcheck-wallet.mjs`,
  needs the reference checkouts);
- an EVM deposit is byte for byte the transaction siding's own `buildSpend`
  (`evmDeposit: true`) makes from the same coins, tip, fee and key, signing
  with zero auxiliary randomness: one and several inputs, the reserve from
  the challenge and from `evm.reserve`, a fixed fee, beside tbtc4 and
  beside the BLAKE2b txbt4; where siding refuses (too few coins, not a `0x`
  address) this crate refuses in the same words (`tests/deposit_oracle.rs`);
  and mined through `sidestr-evm`'s rule it credits the address
  (`sidestr-evm/tests/wallet_deposit.rs`);
- a peg-in transaction round-trips through rust-bitcoin and its marker parses
  with `sidestr_core::marker`;
- accept and reject for every builder: insufficient funds, dust, below
  `pegoutMin`, wrong parent network, fee below `minFeeRate`, policy refusal
  (`tests/builders.rs`).

Elsewhere in the stack: the relay client and the level-2 peg-out PSBT round
are `sidestr-round`'s. Not yet: a PSBT for the parent-side peg-in, the peg
holders' descriptor (`and_v(v:pk(refund), older(refundBlocks))`) and refund
sweep, script-path spends, hardened BIP-32 custody roles (ADR-2101).

## Running the checks

```sh
cargo test -p sidestr-wallet                       # unit, builders, doctests; the oracle's Rust half
SIDESTR_SIDING=<sidestr/spec>/siding SCHEMA=<bitcoin-desktop/schema> BLAKETESTNODE=<bitcoin-blake/blaketestnode> \
  cargo test -p sidestr-wallet --test oracle --test deposit_oracle   # and siding's verdict, and its deposits
RUSTDOCFLAGS="-D warnings" cargo doc -p sidestr-wallet --no-deps
cargo clippy -p sidestr-wallet --all-targets -- -D warnings && cargo fmt -p sidestr-wallet -- --check
```

Keys are files, never arguments; nothing here prints one. The test keys are
derived from fixed strings and seal throwaway chains whose coins carry no value.

## Licence

AGPL-3.0-only, as the work it derives from. Not dual-licensed. A crate that
links this one is AGPL-3.0 in effect and should say so (agentbox ADR-2106).
