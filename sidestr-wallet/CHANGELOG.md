# Changelog

All notable changes to `sidestr-wallet`. The crate follows semantic versioning.

## 0.5.2 (2026-10-02)

### Added

- `pegin::build_pegin_tweak` and `PegInTweak` (re-exported at the root):
  the peg-in tweak form (sidestr/spec issue #23, `pegtweak.mjs`) as an
  option beside `build_pegin`: one output to the address
  `sidestr_core::pegtweak::peg_output` derives from the chain's hash, the
  holders' key, the refund key with the document's `refundBlocks` and the
  sidechain script; no marker; the reveal, descriptor and a one-item
  `core_send_outputs`. `build_pegin` and `PegIn` are unchanged, and the
  marker form stays the default everywhere.
- `parent_sign::sign_parent_inputs`: sign a parent transaction's key-path
  inputs that pay the signer and carry no witness, as Fid signs a PSBT:
  `0x21` unified beside BLAKE2b, BIP 341 `SIGHASH_DEFAULT` (64 bytes) beside
  stock Bitcoin; every signature verified. Reproduces Fid's `vectors.json`
  (bitcoin-blake/fidsigner `2c4057c`) final transactions and finalised
  PSBTs on btc, tbtc, xbt and txbt byte for byte (`tests/fidsigner.rs`).
  The sidechain builders still write an explicit `0x01` beside stock
  Bitcoin.
- `Error::PegTweak`.

### Unchanged

- Coin maturity stays the sidechain's 100 (`coins::coinbase_maturity`):
  Reef's 6,705 (`2bd3cb8`) is a parent rule, recorded in
  `sidestr_core::parents::Parent::coinbase_maturity`. The BIP 21 oracle
  passes at Reef `2bd3cb8`, whose parser is unchanged; CI's `REEF_REF`
  moves there.

## 0.5.1 (2026-10-01)

BIP 21 payment requests, read as Reef reads them (bitcoin-blake/reef
`lib/wallet.mjs parsePaymentUri`, commits `91d6eb2` and `648487a`). Additive.

### Added

- `bip21::PaymentRequest` (re-exported at the root): `parse` takes a
  `bitcoin:` URI to the address, the amount in sats and the requester's
  label and message, with Reef's acceptance and refusal rules exactly: not a
  request is `Ok(None)`; the scheme in any case, an all-capitals address in
  lower case; the amount in coins read into sats without floating point (no
  comma, grouping, sign, unit or exponent, at most 8 decimals, not zero, not
  over 21 million coins, not twice); `req-…` refused, other unknown
  parameters ignored; words percent-decoded with `+` as a space and capped
  at 200 UTF-16 code units; a broken `%` escape refused. Refusals are
  `bip21::RequestError`, in Reef's words.
- `PaymentRequest::new`, `with_amount`, `with_label`, `with_message`,
  `to_uri` (and `Display`): a builder that refuses what a reader would refuse
  or cut (not a segwit address, zero or over 21 million coins, words over
  200 code units), so its URI reads back unchanged.
- `PaymentRequest::resolve(hrp)`: the address as a sidechain destination,
  as `spend::resolve_to` judges one (any prefix, with a note).
  `PaymentRequest::parent_address(parent)`: the address on the parent's
  network, as `build_pegin` judges the peg address (`tb1…` beside tbtc4 and
  txbt4). `FromStr` folds "not a request" into `Error::BadDestination`.
- `Error::PaymentRequest` (the enum is `#[non_exhaustive]`).
- `tests/bip21.rs` and `tests/xcheck-bip21.mjs`: with `REEF` naming a Reef
  checkout, Reef's own parser reads every string in a 118-string corpus as
  this crate does, and reads every URI built here back unchanged.

### Changed

- `build_pegin`'s parent-network check and `resolve_to`'s address half are
  each one internal function now, shared with `bip21`; behaviour unchanged.

## 0.5.0 (2026-10-01)

The `--evm` deposit branch of `siding send` (`lib/spend.mjs buildSpend`,
`evmDeposit: true`). Depends on `sidestr-core` 0.4
(`evm_deposit_marker`, `ChainDocument::evm_reserve`, activated rule entries).

### Added

- `deposit::build_evm_deposit` (re-exported with `DepositRequest`): the
  amount pays the chain's reserve (`evm.reserve`, else the challenge), the
  value-0 `OP_RETURN evmin:<address>` marker follows it, then change; the
  fee is sized with the marker in place. The transaction is byte for byte
  the one siding's `buildSpend` makes from the same coins, fee and key
  (`tests/deposit_oracle.rs`, against the reference with zero auxiliary
  randomness on both sides; both parent families). Refused before any coin
  is touched: a chain whose document does not name the `evm` rule (siding
  would pay the reserve and nothing would be credited), and dust, as for
  every payment here. `deposit::parse_evm_address` reads the `0x` address
  as the reference does.
- `Error::Evm` (the enum is `#[non_exhaustive]`).
- `tests/xcheck-wallet.mjs deposit`: siding's own `buildSpend` fed a coin
  list and tip in place of a producer, for the oracle.

### Changed

- Documentation: the note that the branch was not carried is gone; the
  crate docs, README and module table name the deposit. The note no longer
  cites ADR-2096 (its exclusion of the `evm` rule is lifted; the rule is
  `sidestr-evm`), and the stale "assets reserved" is gone, since issue and
  transfer have been here since 0.4.0.

## 0.4.2 (2026-09-25)

Documentation only: the crate now names SPEC 0.0.4 (`@sidestr/spec` 0.0.6,
reference `fa86dac`) as the one it tracks; nothing in the wallet changes
with it.

## 0.4.1 (2026-09-24)

### Added

- Spends signed somewhere else (spec `proposals/browser-signer.md`,
  `window.nostr.sidestr.signTransaction`). `SpendSigner::signs_elsewhere`
  (default `false`): when `true`, every builder lays out, sizes, checks and
  returns the spend with 65-byte placeholder witnesses and signs nothing.
  `external::ExternalSigner` is such a signer for a public key alone;
  `external::unsigned_hex` is the request a browser signer takes; and
  `external::accept_signed` takes the signed transaction back only when its
  txid is the one built and every input verifies under the parent family's
  sighash against the caller's own prevouts.

### Changed

- `build_spend`, `build_outputs` and the builders on them sign through one
  internal step, so the sign-then-verify path is written once.

## 0.4.0 (2026-09-24)

Breaking only in that `Error` gains a variant; `Error` is now
`#[non_exhaustive]`, so later variants will not break.

### Added

- `compose::build_outputs`: a spend laid out as named outputs, then
  `OP_RETURN` records, then change, with coins that must be spent
  (`required`) beside the ones the selector may choose. Selection retries
  with the laid-out fee when records make the transaction larger than the
  plain-spend bound.
- `asset` (SPEC 12): `build_issue` and `build_transfer` (with memo records
  such as `tip:nostr:<event id>`), `sort_coins`, `plain_coins`,
  `balance_of`, and `CARRIER` (330 sats, taproot dust). A transfer spends
  carriers of one asset only, pays the fee from plain coins, and is checked
  against the `AssetView` before it is returned. `tests/assets_on_chain.rs`
  runs issue, tip and plain payment through `State::submit` and replays the
  block file to the same balances.
- `Error::Asset`.

## 0.3.0 (2026-09-23)

SPEC 0.0.3 (`lib/txsign.mjs`, reference `722ad42`). Breaking.

### Changed

- **Signatures follow the parent's family.** A spend or burn signs Knots'
  unified sighash with hash type `0x21` beside a BLAKE2b parent and BIP 341
  with `0x01` beside stock Bitcoin. Each is a 65-byte witness, re-verified
  under that family's rule before it is returned. 0.2 signed
  `SIGHASH_DEFAULT` (64 bytes) on every chain. The fee is sized for the
  65-byte witness, so a one-input spend is one vbyte larger.
- `coins::from_state` takes a state of either family (`&StateOf<F>`).

### Removed

- `pegin::scan_pegin` and `pegin::FoundPegIn`. They duplicated
  `sidestr_core::parent::find_pegin` with the pre-0.0.3 first-taproot rule.
  Use `find_pegin` with the peg holders' owner.

### Added

- `tests/txsign.rs`: the reference's `txsign-test.mjs` cases through the
  wallet and both families' mempools, and byte-identical witnesses with the
  reference's own signer.

## 0.2.2 (2026-09-22)

Documentation only; no code change.

- docs.rs builds with all features, so the `client` HTTP calls in `deliver`
  are documented.
- `missing_docs` is denied, not warned.
- The README's dependency lines are 0.2's; the relay client and the peg-out
  round are named as `sidestr-round`'s.

## 0.2.1 (2026-09-22)

- Parent records are bounded before they are built (audit F4):
  `pegin::pegout_payment_outputs` returns `Error::MarkerTooLong` past the
  parent's 80-byte `OP_RETURN` policy or the marker grammar's one length
  byte, rather than an output no parser reads back.

## 0.2.0 (2026-09-22)

- Follows `sidestr-core` 0.2: the coin fold and the spend builders over the
  generic state; the parent-side peg-in, peg-out payment and checkpoint
  shapes (`pegin`); `SpendPolicy` consulted by every builder.

## 0.1.0 (2026-09-22)

- First release: coins, largest-first selection, taproot key-path spends and
  peg-out burns behind `SpendSigner`, delivery as a `POST /tx` body or a
  kind-23500 template, HTTP behind feature `client`.
