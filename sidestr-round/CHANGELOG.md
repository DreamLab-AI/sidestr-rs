# Changelog

All notable changes to `sidestr-round`. The crate follows semantic versioning.

## 0.2.0 — 2026-09-23

- Follows `sidestr-core` 0.3, `sidestr-header` 0.3 and `sidestr-nostr` 0.3.
- **Peg-in scanning follows SPEC 0.0.3.** With a peg wallet configured, the
  node takes the peg to be the output that wallet owns (the k-of-n descriptor
  it imported), at any position. Without one it takes the first taproot
  output, as the reference's `pegTick` does.
- Interoperates with siding at `722ad42`.

## 0.1.1 — 2026-09-22

Documentation only; no code change.

- docs.rs builds with all features, so `relay` and `node` (features `relay`,
  `bin`) are documented.
- The crate documentation builds without the `relay` feature: three links to
  items behind it are plain code spans, and CI documents both feature sets.
- `missing_docs` is denied, not warned.

## 0.1.0 — 2026-09-22

- First release: the block round (`round::Round`) and the peg-out PSBT round
  (`pegout::PegoutRound`) as pure state machines on upstream's wire
  (23510–23514), the durable vote journal, the `BlockSigner` port, the
  `ChainView`, the tokio relay client and stand-in (feature `relay`), and the
  `cosign` signer (feature `bin`). Interoperates with siding at `2de40bd`;
  audited (GPT-6 Astra, 2026-09-22), findings pinned as
  `tests/audit_regressions_*.rs`.
