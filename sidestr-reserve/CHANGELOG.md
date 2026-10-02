# Changelog

All notable changes to `sidestr-reserve`. Unpublished (`publish = false`).

## Unreleased

The canonical form is now RFC 8785 (JCS) checked, and the signed digest is
domain-separated. Nothing has been signed or published under the 0.1.0
digest, so this is a breaking change to an unreleased format, not a
migration.

- **Breaking:** the digest is the BIP-340 tagged hash of the canonical bytes
  under the fixed tag `sidestr-reserve/attestation/v1`,
  `SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ bytes)` (as sidestr/spec `keys.mjs`
  `taggedScalar`), no longer their plain SHA-256. New `DIGEST_TAG` and
  `tagged_hash`, held to rust-bitcoin's `TapLeaf` hash. The canonical bytes
  themselves are unchanged.
- **Breaking:** `canonical_json` and `digest` return `Result`: an attestation
  whose public fields were changed after `attest` (a non-canonical `source`,
  a `time` beyond 2⁵³ − 1, a malformed or repeated credit id) is refused
  rather than canonicalised. New `ReserveAttestation::check` and
  `to_value`; `SignedAttestation::verify` reports such an attestation as
  `BadSignature`.
- **Breaking:** `attest` also refuses `"` and `\` in `source`, which the
  canonical subset does not carry.
- `canonicalize`: RFC 8785 over the documented subset (escape-free printable
  ASCII strings and keys, integers of magnitude at most 2⁵³ − 1, `null`,
  booleans, arrays, objects), refusing a float, a non-ASCII or escaped
  character and an out-of-range integer with the new `Error::Canonical`.
- `tests/jcs.rs`: five attestations against `serde_jcs` (always) and the
  JCS of solidpayorg/teller `7c00cea` (with `TELLER` set), byte for byte.
- `serde_json` is re-exported.

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
