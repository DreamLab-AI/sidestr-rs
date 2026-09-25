# Changelog

All notable changes to `sidestr-core`. The crate follows semantic versioning.

## 0.3.3 — 2026-09-25

SPEC 0.0.4 (`@sidestr/spec` 0.0.6, reference `fa86dac`). Additive.

### Added

- `parent::find_pegin_announced` and `parent::scan_pegins_announced`: the
  peg script the signer announces with every tip is taken first, so a
  taproot output paying it is the peg wherever it sits (a wallet's change
  may come before it); only when no output pays it does the owner decide,
  and with no owner the first taproot output, as `parent.mjs scanPegins`
  does at `fa86dac`. `find_pegin` and `scan_pegins` are unchanged: they are
  the announced forms with no script.

## 0.3.2 — 2026-09-25

A fix.

### Fixed

- The crate builds without the `std` feature again. `Error::BlockFile` was
  gated on `std`, but the in-memory mirror reader (`mirror`), which needs no
  file system, reports a malformed block file with it; the variant is no
  longer gated. CI now checks `sidestr-core` alone with
  `--no-default-features`, natively and for wasm32: built beside the other
  crates, feature unification had turned `std` back on and hidden this.

## 0.3.1 — 2026-09-24

Additive.

### Added

- `mirror`: a block file held in memory. `records` splits the
  `[u32le height][u32le size][block]` framing without a file system;
  `StateOf::replay` and `StateOf::replay_with` validate a mirror's
  `blocks.dat` into a state, the second calling back with the state before
  each block so a wallet can read its own history. A browser that fetched
  `blocks.dat` replays `sidestr:dreamlab`'s 367 blocks in about 30 ms
  natively. `encode_record` writes one record, for tests and tools.
- `records` (SPEC 12.1, a port of `siding/lib/records.mjs`): `record_text`,
  `record_script`, `records_of`, `parse_issue`, `parse_tally`, `parse_pool`,
  `classify` and `tally_text`.
- `assets` (SPEC 12.2): `AssetView`, the `assets` rule of
  `siding/lib/overlays/assets.mjs` applied as a view, block by block: what
  each unspent output carries, what was issued, and how each transaction
  was read (`Outcome`). On a chain whose document names no rules it is how a
  client reads an asset its holders validate; a transaction that breaks the
  rule is read as carrying nothing rather than refused. `check` judges a
  transaction before it is signed.

### Departure

- `record_text` holds the push length to the data: `6a 03 616263 51` is not
  a record. The reference's `recordText` has its length check after a `//`
  on the same line, so it reads trailing bytes into the text.

## 0.3.0 — 2026-09-23

SPEC 0.0.3, ported from the reference at `722ad42` (Melvin Carvalho). Breaking.

### Changed

- **The peg output is the one the peg holders own, at any position** (SPEC
  6). `parent::find_pegin` and `parent::scan_pegins` take an
  `Option<PegOwner>` (`&dyn Fn(&Script) -> bool`). With an owner, the peg is
  the first taproot output it owns, and a marker beside nothing it owns is
  not a peg-in. With none, the first taproot output is taken, as before and
  as the reference does for a producer with no peg wallet. 0.0.1 and 0.0.2
  took the first taproot output, which misread a wallet's change as the peg
  on the first chain beside stock testnet4.
- `parent::PegWallet` has a new required method, `owns_address`: the
  reference's `ownedByPegWallet`, `getaddressinfo` `ismine || iswatchonly ||
  solvable`, where a failed call reads as not owned. `CoreRpc` implements it.
- `parent::PegOwner` is `&dyn Fn(&Script, Option<&str>) -> bool`: the owner
  is asked about each taproot output with its parent address, or `None`
  when there is none, and an output with no address is never owned by the
  peg wallet.
- `parent::ParentBlock` has `addresses`: what the node reported for each
  output (`getblock … 2`, `scriptPubKey.address`). `scan_pegins` asks the
  owner about the node's address, as `parent.mjs` does, and derives one only
  where the source reported none, as a test double does. The 0.0.3
  verification pass found that an output Core gave no address was still
  asked about by its derived address, where the reference found no peg-in
  (`tests/audit_regressions_0_0_3.rs`, both engines over the same block).
- `parent_live` no longer defaults a cookie path, and asserts ownership
  instead of the absence of peg-ins.

### Added

- `parent::owned_by_peg_wallet(wallet)`: the level-1 owner, which asks the
  peg wallet about each output's parent address.
- `sighash::rules_for(Family)`, `sighash::key_path_hash_type` and
  `sighash::key_path_sighash`: the signing half of `lib/txsign.mjs`. The
  message and hash type (`0x21` beside BLAKE2b, `0x01` beside stock) an
  input's key-path signature commits to under the parent's family.
  `StateOf::submit` already checks under `HeaderFamily::sighash_rules`, the
  block rule's own reading. The new tests pin it.

## 0.2.2 — 2026-09-22

Documentation only; no code change.

- docs.rs builds with `std` and `rpc`, so `parent::rpc` is documented.
  `consensus-oracle` gates no public item and is left out of the docs build.
- The crate builds its documentation without default features: the links to
  `blockfile` and `chain` are allowed to dangle when `std` is off.
- `missing_docs` is denied, not warned.
- The crate docs, `federation` and the README no longer say the co-signing
  round is unported: it is `sidestr-round`.

## 0.2.1 — 2026-09-22

### Fixed

- **A burn whose marker needs `OP_PUSHDATA1` was silently not recorded.**
  `marker::looks_like_pegout` read the `pegout:` prefix at byte 2, where a
  direct push's data starts; for a parent script of 35 to 40 bytes the marker
  is `6a 4c <len> pegout:…`, byte 2 is the length, and the burn rule
  `continue`d past the output. The reference (`siding/lib/overlay.mjs`
  `sidestr:rule-pegouts`) decodes the push first, so it recorded the burn —
  and refused a block whose `OP_PUSHDATA1` marker starts `pegout:` but does
  not parse, which this crate accepted. Neither engine failed loudly: the
  divergence surfaced as an unpaid burn (and, on the malformed case, a chain
  split). `looks_like_pegout` now follows `op_return_data`, so both push forms
  the reference accepts are recorded and refused alike. Found by running the
  reference as an oracle beside `sidestr-round`; pinned in
  `tests/audit_regressions.rs` with the reference replaying the same block.
- **A leading UTF-8 byte-order mark changed what a marker named** (audit
  F1). The reference text-decodes markers with a WHATWG `TextDecoder`, whose
  default drops one leading `EF BB BF`; this crate's `from_utf8` kept it, so
  `EF BB BF pegout:abcd` was a recorded 20 000-sat burn there and nothing
  here, `EF BB BF pegout:abcde` was refused there (`sidestr:rule-pegouts`)
  and accepted here, a BOM-led claim was a claim there and a coinbase-amount
  failure here, and the same parent peg-in named the script `abcd` there and
  `efbbbf61626364` here. Every reader the reference text-decodes now drops
  one leading BOM first — `parse_pegout`, `looks_like_pegout`,
  `parse_claims`, the hex-form decision of `parse_peg_marker` (a raw
  remainder keeps every byte, as the reference's `toHex(rest)` does) and
  `record_text` — and nothing else does: the parent peg-out record and the
  checkpoint are compared as bytes in both engines. Pinned in
  `tests/audit_regressions_records.rs`, whose differential holds every
  marker case and every block of the auditor's corpus to identical derived
  lists in both engines (`tests/xcheck.mjs markers|blocks`).
- `op_return_data` documents precisely what it accepts (the reference's
  grammar: a bare length byte whatever opcode it is, `OP_PUSHDATA1` minimal or
  not) and the departure section records why the encoder writes only the
  canonical form. That encoder is unchanged since 0.2.0 — it already wrote
  `OP_PUSHDATA1` above 75 bytes; 0.2.1's code change is burn recognition,
  the burn-loop guard and the BOM handling above.

### Added

- `marker::try_claim_marker` and `marker::try_pegout_marker` (audit F3):
  the checked forms of `claim_marker` and `pegout_marker`, refusing a txid
  that is not 64 lower-hex characters, a `vout` above `CLAIM_VOUT_MAX`
  (99 999: the reference reads five decimal digits, kept), or a parent script
  outside 2 to 40 bytes of hex — the inputs the parsers would not read back.
  The unchecked forms keep their signatures, document their domain, and no
  longer truncate a payload over 255 bytes to a one-byte length: they emit a
  whole `OP_PUSHDATA2` push that no marker parser matches.

Additive API only.

## 0.2.0 — 2026-09-22

- Blocks generic over the header family (`HeaderFamily`): stock and, through
  `sidestr-header`, Knots' BLAKE2b v2, proven on a live chain.
- Level 2's pure parts: the federation's challenge, `multi_a` script-path
  verification, partial signatures and `template_id`; the round is not here.
- The parent view (`parent`, `parents`), claims checked against it.
- The five audit counter-examples fixed and pinned (`tests/audit_regressions.rs`).

## 0.1.0 — 2026-09-22

- First release: the chain document, block build/sign, the rules, the block
  file and the validating chain for level 1 beside a stock parent.
