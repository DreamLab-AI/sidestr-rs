# Changelog

All notable changes to `sidestr-nostr`. The crate follows semantic versioning.

## 0.3.1 — 2026-09-25

SPEC 0.0.4 (`@sidestr/spec` 0.0.6, reference `fa86dac`). Additive.

### Added

- `tip`: the peg script the signer announces with every tip (the `peg`
  tag). `tip_event_with_peg` / `sign_tip_with_peg` build it after the
  mirrors, lower-cased, and refuse anything but 2 to 80 bytes of hex, as
  `announce.mjs tipEvent` does; `peg_script_of` reads the first `peg` tag as
  `parseTip` does (a malformed first tag means none); `newest_peg_script`
  takes the newest announcement's, which wins; `newest_event` is `newest`
  with the event it chose. The built tags match the reference's byte for
  byte (a test vector from `tipEvent` at `fa86dac`).
- `kinds::KIND_PARENT_TRANSACTION` (23503) in the registry, and
  `tx::{parent_transaction_event, sign_parent_transaction_event,
  parse_parent_transaction}`: a signed parent transaction for a producer
  with a node to broadcast if its node's policy accepts it (`relay.mjs
  parentTxEvent`). `REGISTRY` now has 18 rows.
- `tags::TAG_PEG`.

## 0.3.0 — 2026-09-23

- Follows `sidestr-core` 0.3. SPEC 0.0.3 changes nothing on the Nostr plane;
  the oracle suite runs against the reference at `722ad42`.

## 0.2.2 — 2026-09-22

Documentation only; no code change.

- `missing_docs` is denied, not warned.
- The README's dependency line and status are 0.2's: relay I/O and the round
  logic are `sidestr-round`'s, not "not yet".

## 0.2.1 — 2026-09-22

- The tip parser follows upstream's `announce.mjs` at spec 0.0.3
  (`e457737`): the header width is read from the content, bounded to
  `TIP_HEADERS` headers and hex-checked before slicing; both header families
  parse.
- Audit regressions pinned (`tests/audit_regressions.rs`).

## 0.2.0 — 2026-09-22

- The level-2 round envelopes (`round`: kinds 23510–23514, codecs only) and
  the tip announcement for both header families (`tip::parse_tip_as`).
- Depends on `sidestr-core` 0.2.

## 0.1.0 — 2026-09-22

- First release: the owned NIP-01 event with BIP-340 verification, the sealed
  `Signer` port, the tip announcement (33333) with the mirror trust rule,
  transactions and faucet requests (23500/23501), rule and genesis documents
  (33500/33501), the dual-schema 33502 record, the estate's 38420–38425, and
  the pure relay messages behind a `RelayClient` port.
