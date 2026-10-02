# Changelog

All notable changes to `sidestr-core`. The crate follows semantic versioning.

## 0.4.2 (2026-10-03)

### Added: a sidestr chain as a parent (SPEC 3.1), a recorded departure

SPEC 0.0.5 lets a nested chain's `parent` be a sidestr chain's hash (its
chain event's id). `siding/lib/parents.mjs` at `e8deb63` does not carry
that and refuses the hash as an unknown parent; `resolve_parent`,
`ChainDocument::parent`, `family` and `validate` keep refusing it exactly
as siding does. Additive:

- `parents::resolve_parent_with(id, lookup)`: a table alias as before
  (the lookup is never called); a 64-hex hash is handed to `lookup` for
  that chain's document (read from its verified chain event), whose own
  `parent` is followed down to a table row, at most `MAX_NESTING` (16)
  chains deep, refusing a cycle. Returns `ParentRef`: `Table(&Parent)` or
  `Chain(NestedParent)` (hash, alias, path, root), with `family`, `pow`,
  `mainnet`, `depth`, `chain_hash` and `coinbase_maturity` (a sidestr
  parent's coinbases mature at 100) all inherited from the root.
  `is_chain_hash_parent` names the hash form.
- `ChainDocument::parent_with`, `family_with`, `validate_nested`: the
  same through a document.
- Departure recorded under ADR-0001 D4: `tests/nested_parent.rs` runs
  `parents.mjs` on the same inputs when `SIDESTR_SIDING` is set and holds
  it to its refusal, with `resolve_parent`'s message identical to
  upstream's; the day upstream learns hashes, it fails and the departure
  is re-judged.

A document read back from a chain event already has its `signer` filled
from the event's author (`sidestr-nostr` 0.5.0 `ParsedChain::document`); no
change here.

## 0.4.1 (2026-10-02)

Parity with sidestr/spec `keys.mjs` (`bd1d692`) and `pegtweak.mjs`
(`4c4915f`), Knots' unified sighash for every script type against Fid's
known answers (bitcoin-blake/fidsigner `2c4057c`), and Reef's parent
coinbase maturity (bitcoin-blake/reef `2bd3cb8`). Additive.

### Changed (consensus): Hitch channel leaves on transaction inputs

A Hitch channel's every close spends its funding output by taproot script
path. The reference producer accepts such a block; this crate refused it,
so the first channel close on an estate chain would have frozen every Rust
validator, the forum's member wallets among them, at the block before it.
Owner decision 2026-10-02, SC6: cooperative and force-close both.

- `channel` (new module): `ChannelLeaf`, exactly the seven leaves Hitch
  `62f8e39` / sidestr-hitch 0.2.0 writes — the 2-of-2 funding `multi_a`,
  revocation `pk CHECKSIG`, `to_local` `<d> CSV DROP pk CHECKSIG`, and the
  HTLC success (`SHA256 <h> EQUALVERIFY [<d> CSV DROP] pk CHECKSIG`) and
  timeout (`<e> CLTV DROP [<d> CSV DROP] pk CHECKSIG`) leaves — parsed and
  rendered byte for byte (`parse`, `to_script`; numbers only in Hitch's
  minimal `pushNum` form, a delay at most `0xffff` blocks, an expiry a
  height). `verify_channel_input` checks a script-path spend of one of
  them: annex, control block and its commitment to the output key (rust-
  bitcoin's `ControlBlock`), leaf version `0xc0`, exact witness items, then
  the preimage, BIP 65, BIP 112 and each BIP 340 signature under BIP 341
  or, where the family's rules and the hash type say so, Knots' unified
  sighash; `ChannelError` names each refusal. `earliest_height` gives the
  height an input's BIP 68 lock and its transaction's `nLockTime` allow.
- `sighash::verify_supported_input` judges a taproot witness with two or
  more items after the annex (BIP 341's script path) as a channel leaf, and
  still refuses every other leaf. Its error for a script path now names the
  `ChannelError` (`taproot script path: …`).
- `state::StateOf::submit` refuses a transaction whose BIP 68 relative lock
  or `nLockTime` is not satisfied at the next height ("locked until height
  …"). The block rules were already in force and are unchanged; the
  reference at `fa86dac` admits such a transaction and then cannot produce
  until it leaves the mempool.
- `tests/channel_oracle.rs` (feature `consensus-oracle`): Bitcoin Core
  26.0's interpreter and this crate agree on 436 spends of the seven leaves
  under both parities, and six narrowings (unknown leaf version, four
  non-template scripts, CSV in a negative-version transaction) are asserted
  as such.

### Added

- `keys`: a port of `siding/lib/keys.mjs`, keys as group elements with the
  x-only form only at the edge: `public_key`, `normalize` (once, to the
  even-y point an identifier names), `signing_key` (the same arithmetic,
  applied inside signing only), `base_point` (did:nostr, bare x as `02`,
  Multikey `fe70102…`/`fe70103…` keeping the parity, compressed point),
  `x_only`, `did`, `multikey`, `negate`, `tweak_secret`, `tweak_point` (on
  the full point, never lifted), `chain_secrets`, `chain_points`,
  `tagged_scalar` (and `_hex`), `tap_tweak`, `is_point`, `parse_point`, `N`
  and `KeyError` in upstream's words. Checked against
  `fixtures/keys-vectors.json` (upstream's file, verbatim, regenerated byte
  for byte), the official BIP 340, 341 and 86 vectors (`fixtures/bip/`),
  upstream's property checks, and `keys.mjs` itself when `SIDESTR_SIDING`
  and `SCHEMA` are set (`tests/xcheck-pegtweak.mjs keys`).
- `keys::base_point` lower-cases its input as upstream does, so it reads
  `FE70102…` and `DID:NOSTR:…`, which the did:nostr conformance vectors
  (`error_uppercase_multibase_prefix`) refuse as `InvalidMultibase`. Upstream
  is followed and the difference documented.
- `pegtweak`: the peg-in tweak form (SPEC 6, issue #23): `refund_leaf`,
  `peg_commitment`, `commit_leaf` (`C = NUMS + t·G`), `leaf_hash`,
  `tap_tree` (upstream's left-to-right shape over rust-bitcoin's hashes),
  `peg_output` (output key, parity, address, root, tweak, leaves with
  control blocks, descriptor, normalised reveal; serialises with upstream's
  field names), `peg_matches`, `peg_spend_secret`, `PegReveal`,
  `PegOutput`, `PegError`. The fifteen `pegtweak-test.mjs` checks, with
  rust-bitcoin's `TapTweak`, `TaprootBuilder` and `ControlBlock` as the
  independent engine for the two- and three-leaf trees, and `pegtweak.mjs`
  itself over fixed reveals when the reference is configured
  (`tests/xcheck-pegtweak.mjs pegtweak`; skipped against a siding that
  predates it).
- `sighash::unified_legacy_sighash` and `UnifiedLegacy`: Knots' unified
  message for script types 0 (bare or P2SH) and 1 (segwit v0), beside
  `unified_taproot_sighash`, whose signature and behaviour are unchanged.
  All 166 rows of Knots' `unified_sighash.json` (as Fid vendors it,
  `fixtures/fidsigner/`) pass: 76 + 66 through the new function, 12 + 12
  taproot through the existing one.
- `parents::Parent::coinbase_maturity` and `Parent::is_mature`, with
  `COINBASE_MATURITY` (100) and `TXBT4_COINBASE_MATURITY` (6,705): since
  Knots 29.4.2 every txbt4 node's mempool asks 6,705 confirmations of a
  mined coin (Reef `2bd3cb8`), so a parent coin's spendability is reported
  against that. A fact about parent coins only: the sidechain's own maturity
  (`rules::Params::coinbase_maturity`, 100) is unchanged, and nothing in
  this crate selects parent coins.
Documentation only: SPEC 0.0.5 (sidestr/spec `e8deb63`). The chain
document's `id` is the chain's alias and its identity is the chain's hash,
the id of the document published as a kind-3500 event (`sidestr-nostr`'s
`chain` module); `name` is documented as the alias without `sidestr:`;
`signer` stays for chains made before 0.0.5 and is filled from the event's
author when a document is read back from its event; a `parent` naming a
chain hash (a nested chain) is not resolved by any parents table yet and is
refused as an unknown parent. Marker grammar, validation and serialisation
are unchanged.

## 0.4.0 (2026-10-01)

Parity with sidestr/spec at `fe689e9`. `ChainDocument::rules` now preserves
activation heights, so this release changes its public type from strings to
`RuleEntry`.

### Added

- The SPEC 12 constant-product pool and binary prediction-market rules,
  including integer boundary checks, resolver signatures, expiry/grace
  refunds, activation-height replay, and the records they use.
- Asset traces and per-output carried amounts shared by assets, pools and
  markets; the narrowly scoped `OP_TRUE` pool and market coins are spendable
  only when an adopted overlay accounts for them.
- Session eviction for transactions that pass admission but make a candidate
  block fail. Production tests transactions in order, remembers exact bytes,
  retries without offenders, and admits a witness-only repair with the same
  txid.
- `parent::scan_pegins_with_wallet`, `new_pegins`,
  `claimable_by_transaction` and `StateOf::claimed_tx`: announced scripts win;
  fallback excludes wallet change and wallet-funded transactions; a marker
  transaction supplies at most one claim candidate.

- `BlockRule` gains three default methods: `name` (the document name a rule
  answers to), `coinbase_allowance` (sats `btc:rule-blockctx-coinbase-amount`
  allows beyond `subsidy + fees + claims`: the EVM rule's withdrawals; `None`
  fails the rule, as the reference's version does when the rule's verdict on
  the block is not ok) and `applied` (a rule commits the state it kept for a
  block once the block is applied, the genesis included). A rule that
  implements none of them behaves exactly as before.
- `ChainDocument::validate_with(carried)` and `from_json_with`: a document
  naming a rule is accepted when the validator carries a rule of that name;
  the pool rule still needs the assets rule. `validate()` and `from_json()`
  are `validate_with(&[])` and refuse every named rule, as before.
- `StateOf::from_genesis_with_rules`, `StateOf::with_key_and_rules`,
  `StateOf::replay_with_rules` and `ChainOf::open_with_rules`: a state that
  carries rules from the genesis on, its document checked against their
  names.
- `assets::AssetsRule`: the assets rule as consensus (`sidestr:rule-assets`,
  `overlays/assets.mjs installChecks` without pools). `overlays/index.mjs
  rulesFor` installs it on every chain whose document names any rule, so an
  `evm` chain carries it; it answers to `assets`.
- `marker::evm_deposit_marker` and `marker::EVM_DEPOSIT_PREFIX`: the
  `OP_RETURN evmin:<20-byte address>` an EVM deposit writes (`evm.mjs
  depositScript`), so a wallet builds one without linking revm;
  `sidestr-evm`'s tests hold it to that crate's `records::deposit_script`.
- `ChainDocument::evm_reserve`: the script a deposit pays, `evm.reserve` or
  else the challenge, read as `evm.mjs` and `spend.mjs` read it; what
  `sidestr-evm`'s `EvmConfig` refuses, it refuses.

### Changed

- A rule may be a string or `{ "name": "…", "from": height }`; rule checks
  start at the declared height.
- `bitcoin` enables serde so versioned execution snapshots can include
  consensus primitives without a separate wire format.

## 0.3.3 (2026-09-25)

SPEC 0.0.4 (`@sidestr/spec` 0.0.6, reference `fa86dac`). Additive.

### Added

- `parent::find_pegin_announced` and `parent::scan_pegins_announced`: the
  peg script the signer announces with every tip is taken first, so a
  taproot output paying it is the peg wherever it sits (a wallet's change
  may come before it); only when no output pays it does the owner decide,
  and with no owner the first taproot output, as `parent.mjs scanPegins`
  does at `fa86dac`. `find_pegin` and `scan_pegins` are unchanged: they are
  the announced forms with no script.

## 0.3.2 (2026-09-25)

A fix.

### Fixed

- The crate builds without the `std` feature again. `Error::BlockFile` was
  gated on `std`, but the in-memory mirror reader (`mirror`), which needs no
  file system, reports a malformed block file with it; the variant is no
  longer gated. CI now checks `sidestr-core` alone with
  `--no-default-features`, natively and for wasm32: built beside the other
  crates, feature unification had turned `std` back on and hidden this.

## 0.3.1 (2026-09-24)

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

## 0.3.0 (2026-09-23)

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

## 0.2.2 (2026-09-22)

Documentation only; no code change.

- docs.rs builds with `std` and `rpc`, so `parent::rpc` is documented.
  `consensus-oracle` gates no public item and is left out of the docs build.
- The crate builds its documentation without default features: the links to
  `blockfile` and `chain` are allowed to dangle when `std` is off.
- `missing_docs` is denied, not warned.
- The crate docs, `federation` and the README no longer say the co-signing
  round is unported: it is `sidestr-round`.

## 0.2.1 (2026-09-22)

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
  outside 2 to 40 bytes of hex, which the parsers would not read back.
  Unchecked forms keep their signatures, document their domain, and no
  longer truncate a payload over 255 bytes to a one-byte length: they emit a
  whole `OP_PUSHDATA2` push that no marker parser matches.

Additive API only.

## 0.2.0 (2026-09-22)

- Blocks generic over the header family (`HeaderFamily`): stock and, through
  `sidestr-header`, Knots' BLAKE2b v2, proven on a live chain.
- Level 2's pure parts: the federation's challenge, `multi_a` script-path
  verification, partial signatures and `template_id`; the round is not here.
- The parent view (`parent`, `parents`), claims checked against it.
- The five audit counter-examples fixed and pinned (`tests/audit_regressions.rs`).

## 0.1.0 (2026-09-22)

- First release: the chain document, block build/sign, the rules, the block
  file and the validating chain for level 1 beside a stock parent.
