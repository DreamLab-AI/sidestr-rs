# Fid's known answers

Copied verbatim from bitcoin-blake/fidsigner at
`2c4057c9fd65d51001e165b9d2f265c65b3fe4fe` (Melvin Carvalho):

- `unified_sighash.json`: the 166 known answers of Knots' unified opt-in
  sighash (Knots v29.4.1.knots20260508, PR #357), as Fid's `unified.js`
  runs them. `tests/fidsigner.rs` runs every row through
  `sidestr_core::sighash::unified_taproot_sighash` (script types 2 and 3)
  and `unified_legacy_sighash` (script types 0 and 1).
- `vectors.json`: Fid's own vectors (one key, a two-input PSBT signed on
  btc, tbtc, xbt and txbt, a Nostr event), deterministic BIP 340 with zero
  auxiliary randomness. `sidestr-wallet`'s `tests/fidsigner.rs` reproduces
  the four final transactions and `sidestr-nostr` the signed event, byte
  for byte, from this file.

The oracle is Fid itself: `npm ci && node test.mjs` in a checkout at that
commit (201 checks).
