# Changelog

All notable changes to `sidestr-nostr`. The crate follows semantic versioning.

## Unreleased

### Tests

- Fid's Nostr vector (bitcoin-blake/fidsigner `2c4057c`, `vectors.json`,
  vendored in `tests/fixtures/`): `SecretKeySigner` reproduces its event id
  and signature (zero auxiliary randomness) byte for byte. No API change.
SPEC 0.0.5 (sidestr/spec `e8deb63`): the chain document as an event, its id
the chain's hash. Source-breaking: `Tip`, `TipTemplate` and `relay::Filter`
gain public fields and `kinds::REGISTRY` grows to 19 rows.

### Added

- `chain`: the chain document as a kind-3500 event (`announce.mjs
  chainEvent`): `chain_event` / `sign_chain_event` from the document's JSON
  text, written exactly as `JSON.parse` then `JSON.stringify` write it
  (`js_stringify`: key order with integer-like keys first, JavaScript's
  number printing), `signer` deleted, so the chain's hash is the one siding
  gives for the same file; `chain_event_of` from a parsed `ChainDocument`.
  `parse_chain_event` / `parse_chain_event_value` (`parseChainEvent`):
  verified, the content a document with an alias, a `signer` field or
  `signers` list that includes the author, `signer` filled from the author
  for a level-1 document so `ChainDocument::validate` still checks the
  challenge. `resolve_chain` (`resolveChain`) by alias or hash over injected
  lookups: the tip's `e`, the event from a relay or a mirror's
  `chain-event.json`, the tip's author the chain's signer (or one of its
  signers), a chain made before 0.0.5 resolved by its mirror's `chain.json`
  with `hash: None`, `legacy: true`. `is_alias`, `is_chain_hash`,
  `chain_event_url`, `CHAIN_EVENT_FILE`.
- `tip`: `TipTemplate::chain_hash` and `with_chain_hash` (`tipEvent`
  `chainHash`): `["e", hash, "", "chain"]` after the `peg` tag; a template
  without one builds exactly the 0.0.4 event. `Tip::chain_hash` and
  `chain_hash_of` (`parseTip` `chainHash`: the first `e` tag, 64 hex,
  lower-cased).
- `relay`: `Filter::ids`, `event_filter` (`{ids:[id],limit:1}`),
  `fetch_event` (`fetchEvent`: the first relay with the event ends the
  search) and `resolve_chain` over the `RelayClient` port.
- `kinds`: `KIND_CHAIN_DOCUMENT` (3500, regular, ported) in `REGISTRY`; the
  33333/33500/33501 docs say chain alias, and 33501 is read for chains made
  before 0.0.5. `tags::MARKER_CHAIN`.
- `fixtures/chain-event-vectors.json` and `tests/chain_event.rs`: kind-3500
  events and a tip with a chain hash from siding at `e8deb63`, byte-identical
  here; `tests/oracle/chain-event-oracle.mjs` regenerates them and the test
  requires no drift when the reference checkouts are named. `tests/live.rs`
  resolves the live `sidestr:dreamlab` announcement (no `e` tag) the
  pre-0.0.5 way and refuses another key's tip for it.

### Changed

- `serde_json`'s `float_roundtrip` is on, so a number in a chain document
  parses to the double `JSON.parse` gives.

## 0.4.0 (2026-10-01)

- `MirrorChain` reads level-2 `signers`; `announced_by` and `choose_mirror`
  accept an announcement by the level-1 signer or any federation member, as
  `announce.mjs` does at `fe689e9`.
- Follows `sidestr-core` 0.4. The added `signers` field makes direct
  `MirrorChain` struct construction a source-level breaking change.

## 0.3.1 (2026-09-25)

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

## 0.3.0 (2026-09-23)

- Follows `sidestr-core` 0.3. SPEC 0.0.3 changes nothing on the Nostr plane;
  the oracle suite runs against the reference at `722ad42`.

## 0.2.2 (2026-09-22)

Documentation only; no code change.

- `missing_docs` is denied, not warned.
- The README's dependency line and status are 0.2's: relay I/O and the round
  logic are `sidestr-round`'s, not "not yet".

## 0.2.1 (2026-09-22)

- The tip parser follows upstream's `announce.mjs` at spec 0.0.3
  (`e457737`): the header width is read from the content, bounded to
  `TIP_HEADERS` headers and hex-checked before slicing; both header families
  parse.
- Audit regressions pinned (`tests/audit_regressions.rs`).

## 0.2.0 (2026-09-22)

- The level-2 round envelopes (`round`: kinds 23510–23514, codecs only) and
  the tip announcement for both header families (`tip::parse_tip_as`).
- Depends on `sidestr-core` 0.2.

## 0.1.0 (2026-09-22)

- First release: the owned NIP-01 event with BIP-340 verification, the sealed
  `Signer` port, the tip announcement (33333) with the mirror trust rule,
  transactions and faucet requests (23500/23501), rule and genesis documents
  (33500/33501), the dual-schema 33502 record, the estate's 38420–38425, and
  the pure relay messages behind a `RelayClient` port.
