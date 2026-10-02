# Changelog

All notable changes to `sidestr-round`. The crate follows semantic versioning.

## Unreleased

SPEC 0.0.5 (sidestr/spec `e8deb63`): the producer announces the chain's
hash. Source-breaking for code that builds `node::Settings` by struct
literal (a new field).

- `cosign` reads `chain-event.json` beside the document (or
  `--chain-event`), verifies it as a chain event of this chain, and
  announces its id with every tip as the `e` tag, as `siding produce` does;
  without one it logs that tips carry no chain hash and announces as before.
  `node::read_chain_hash`, `Settings::chain_event`.
- The in-process relay stand-in honours a filter's `ids`.

## 0.3.0 (2026-10-01)

- `RelayPool` keeps one reconnecting websocket per relay and shares it among
  subscriptions, one-shot fetches and publishes. Subscriptions are replayed
  after reconnect; the socket closes two seconds after its last user.
- The runnable signer announces its peg script, accepts federated announcement
  authors, and uses the issue-15 peg scan: no wallet change, no self-funded
  fallback deposits, and one candidate per parent transaction.
- `/blocks.json` sends an `ETag` derived from the index tip, honours
  `If-None-Match` with 304, and exposes cache and range headers through CORS.
- Follows `sidestr-core` and `sidestr-nostr` 0.4 and interoperates with
  sidestr/spec at `fe689e9`.

## 0.2.1 (2026-09-25)

Additive.

### Added

- `relay::fetch` / `fetch_with`: ask each relay once for a filter and
  collect what it sends until `EOSE`, the one-shot read `announce.mjs
  fetchLatestTip` makes (where `follow` stays open). A dead relay costs only
  its own timeout.
- Interoperates with siding at `fa86dac` (SPEC 0.0.4, `@sidestr/spec`
  0.0.6); the oracle suites run against it.

## 0.2.0 (2026-09-23)

- Follows `sidestr-core` 0.3, `sidestr-header` 0.3 and `sidestr-nostr` 0.3.
- **Peg-in scanning follows SPEC 0.0.3.** With a peg wallet configured, the
  node takes the peg to be the output that wallet owns (the k-of-n descriptor
  it imported), at any position. Without one it takes the first taproot
  output, as the reference's `pegTick` does.
- Interoperates with siding at `722ad42`.
- `tests/interop_pegout.rs` no longer depends on which signer is faster. The
  0.0.3 verification pass saw it fail when the two Rust signers of a
  {Rust, JS, Rust} 2-of-3 completed a Rust proposal before the JS one
  signed. Signer 3 now seals blocks but has no parent wallet, so every
  payment carries the other engine's co-signature. Each burn is timed to
  the wanted payer's slot, and the test judges the proposal that was
  co-signed, not the first one.

## 0.1.1 (2026-09-22)

Documentation only; no code change.

- docs.rs builds with all features, so `relay` and `node` (features `relay`,
  `bin`) are documented.
- The crate documentation builds without the `relay` feature: three links to
  items behind it are plain code spans, and CI documents both feature sets.
- `missing_docs` is denied, not warned.

## 0.1.0 (2026-09-22)

- First release: the block round (`round::Round`) and the peg-out PSBT round
  (`pegout::PegoutRound`) as pure state machines on upstream's wire
  (23510–23514), the durable vote journal, the `BlockSigner` port, the
  `ChainView`, the tokio relay client and stand-in (feature `relay`), and the
  `cosign` signer (feature `bin`). Interoperates with siding at `2de40bd`;
  audited (GPT-6 Astra, 2026-09-22), findings pinned as
  `tests/audit_regressions_*.rs`.
