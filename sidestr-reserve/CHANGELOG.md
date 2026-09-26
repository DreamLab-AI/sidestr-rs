# Changelog

All notable changes to `sidestr-reserve`. Unpublished (`publish = false`).

## 0.1.0 — 2026-09-26 (not live)

First version. This is the reserve attestation moved out of
`sidestr-bridge-liquid` 0.1.0 and made independent of the origin (ADR-2117
amendment of 2026-09-26).

- `Origin` (network, asset, decimals), `Tip` (height, hash) and `Credit`
  (replay id, amount), each checked on construction to fit the canonical
  alphabet.
- `attest`: a pure function from an origin, a tip, credits, a source and a
  time to a `ReserveAttestation`. It refuses duplicated credit ids and
  overflowing totals. The amount is a `u128`.
- Canonical sorted-key JSON (`sidestr-reserve/attestation/v1`) and its
  SHA-256 digest.
- `AttestationSigner`, `KeypairSigner`, `SignedAttestation` and
  `verify_digest`: the BIP-340 hook, unchanged from `sidestr-bridge-liquid`
  0.1.0.
