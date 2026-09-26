# Changelog

All notable changes to `sidestr-evm`. The crate follows semantic versioning.

## Unreleased — 0.1.0

The `evm` rule of siding (`lib/overlays/evm.mjs` at `fa86dac`,
`@sidestr/spec` 0.0.6; `proposals/evm.md`), after the owner lifted ADR-2096
decision 5. Not published.

### Added

- `records`: the `evm:`, `evmin:` and `evmroot:` codecs, byte for byte with
  the reference, all three push forms.
- `tx::decode_carrier`: a carried transaction read as `createTxFromRLP` and
  `verifySignature` read it (legacy with or without EIP-155, EIP-2930,
  EIP-1559; blob and EIP-7702 transactions refused), on alloy.
- `EvmState`: the world beside the UTXO set, `prepare` (a block's verdict,
  its state kept until `commit`), `check_tx` (the mempool's check),
  `sequence` (a producer's), `call` (read-only), receipts and per-block
  records; revm at Cancun with the reference's block environment and its
  KZG-less point-evaluation precompile; the state root on alloy-trie.
- `EvmRule`, a `sidestr-core` `BlockRule` (`sidestr:rule-evm`) with the
  withdrawals as its coinbase allowance; `rules_for` (the rules a document
  names, the assets rule included, as `overlays/index.mjs rulesFor` installs
  it) and `Rules::build_next` / `Rules::produce` for a producer.
- `tests/oracle/oracle.mjs`, which writes `tests/fixtures/` from ethereumjs
  10.1.3 driven as `evm.mjs` drives it and cross-checked against the module
  itself: 35 blocks (20 accepted, 15 refused), 25 carrier decodings, 16
  record scripts. Every root is reproduced.
- `tests/wallet_deposit.rs`: `sidestr-wallet`'s EVM deposit against the
  rule. The wallet writes the `evmin:` marker and reads the reserve through
  `sidestr-core` (so it links no revm); the marker is
  `records::deposit_script`'s bytes and `parse_deposit` reads it, the
  reserve is `EvmConfig`'s (and both refuse the same malformed `evm`
  sections), and a deposit the wallet builds passes `check_tx`, is mined and
  credits the address on the producer and on an independent validator,
  with the reserve from the challenge and from `evm.reserve`.
  `sidestr-wallet` is a dev-dependency only.
- CI's `oracle` job regenerates `tests/fixtures/` with `tests/oracle/`
  against the checked-out `evm.mjs` and fails on any drift. The crate is not
  in the wasm32 build: it needs no C beyond secp256k1's, but getrandom 0.2
  (through k256) refuses `wasm32-unknown-unknown` until the application
  selects its `js` backend.
- `rpc`: the Ethereum JSON-RPC of `lib/evmrpc.mjs` (at `fa86dac`) for
  wallets. `EvmRpc::handle` takes a request or batch as JSON, and
  `EvmRpc::handle_body` takes a `POST /evm` body (parse error 400, 1 MiB
  limit 413), writing it byte for byte as `JSON.stringify` does. The host
  supplies a `ChainView`: height, block hashes, header times, mempool,
  `carry` for `eth_sendRawTransaction`, and the clock. It covers every
  method the reference serves, with its error codes (-32601, -32602,
  -32000, and 3 with the revert data) and texts, V8's included.
  The estimate formula is the reference's. No HTTP server is pulled in.
- `EvmState::simulate`: a read-only execution as ethereumjs's `runCall`
  makes one, used by `eth_call` and `eth_estimateGas`. It runs in a given
  block, optionally as a creation, carries value, and reports the
  execution's gas without the intrinsic cost. It also adds
  `EvmState::receipts` (chain order), `Receipt::index`,
  `Receipt::envelope`, `Receipt::effective_gas_price` and
  `Receipt::logs_bloom`.
- `tests/oracle/rpc-oracle.mjs` runs siding's `evmrpc.mjs` and `evm.mjs`
  themselves on ethereumjs 10.1.3 and writes `tests/fixtures/rpc.json`:
  6 blocks, 223 requests and 10 HTTP bodies. `tests/rpc_oracle.rs`
  reproduces every state root and every answer. 215 match byte for byte;
  8 match up to a prefix, because the rest is ethereumjs's own reason text.
  `tests/rpc.rs` is `siding/test/evmrpc-test.mjs` through `sidestr-core`.

### Changed

- revm's `optional_eip3607` feature is on, so a read-only call may come
  from an account with code, as ethereumjs's `runCall` allows. Carried
  transactions still refuse such senders.
- The "No JSON-RPC" departure is gone. The RPC's own departures are listed
  in the crate docs.
