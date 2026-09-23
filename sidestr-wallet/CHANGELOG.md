# Changelog

All notable changes to `sidestr-wallet`. The crate follows semantic versioning.

## 0.3.0 — 2026-09-23

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

## 0.2.2 — 2026-09-22

Documentation only; no code change.

- docs.rs builds with all features, so the `client` HTTP calls in `deliver`
  are documented.
- `missing_docs` is denied, not warned.
- The README's dependency lines are 0.2's; the relay client and the peg-out
  round are named as `sidestr-round`'s.

## 0.2.1 — 2026-09-22

- Parent records are bounded before they are built (audit F4):
  `pegin::pegout_payment_outputs` returns `Error::MarkerTooLong` past the
  parent's 80-byte `OP_RETURN` policy or the marker grammar's one length
  byte, rather than an output no parser reads back.

## 0.2.0 — 2026-09-22

- Follows `sidestr-core` 0.2: the coin fold and the spend builders over the
  generic state; the parent-side peg-in, peg-out payment and checkpoint
  shapes (`pegin`); `SpendPolicy` consulted by every builder.

## 0.1.0 — 2026-09-22

- First release: coins, largest-first selection, taproot key-path spends and
  peg-out burns behind `SpendSigner`, delivery as a `POST /tx` body or a
  kind-23500 template, HTTP behind feature `client`.
