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
