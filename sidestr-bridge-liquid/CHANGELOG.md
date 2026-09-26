# Changelog

All notable changes to `sidestr-bridge-liquid`. Unpublished (`publish = false`).

## 0.2.0 — 2026-09-26 (not live)

The attestation is now origin-neutral (ADR-2117 amendment of 2026-09-26).
This crate is the Liquid origin adapter for it.

- **Breaking:** the attestation format moved to the new `sidestr-reserve`
  crate and is re-exported here. It is now `sidestr-reserve/attestation/v1`,
  with keys `amount`, `asset`, `credits`, `decimals`, `network`, `source`,
  `time`, `tip_hash`, `tip_height` and `type`. It replaces
  `sidestr-bridge-liquid/reserve-attestation/v1`, whose `amount_sats`,
  `asset_id`, `liquid_tip_*` and `reserve_outpoints` were specific to
  Liquid. Nothing had been signed or published under v1, so this is the one
  format change before the `bridge` rule is written.
- `credits(snapshot, asset)`: which Liquid outputs count (confirmed at or
  below the tip, reserve asset only), keyed by outpoint. `origin()`:
  `liquid`, the pinned asset, 8 decimals.
- The total is a `u128`. Two maximal outputs are stated exactly rather than
  refused as an overflow.
- `Error::Signing` and `Error::BadSignature` are now
  `sidestr_reserve::Error`, wrapped as `Error::Reserve`.

## 0.1.0 — 2026-09-23 (not live)

First version: the light Liquid reserve wiring for the owner's private USD
unit (ADR-2117 amendment of 2026-09-23). Nothing is funded, sealed or
published.

- `ReserveKey`: a 24-word BIP-39 mnemonic in a file created mode 0400 with
  `O_EXCL`. The file is never overwritten, is refused on load if group or
  others can read it, and is never printed.
- `ReserveWallet`: a watch-only LWK 0.19 wallet on Liquid mainnet
  (`elwpkh`, `m/84'/1776'/0'`, SLIP-77). Addresses, a full-scan sync against
  a public Esplora server, and non-zero balances per asset.
- `RESERVE_ASSET_ID`, verified from Blockstream's asset registry and the
  issuer's supported-protocols page, and recomputed from the issuance prevout
  and contract hash. `verify_registry_entry` and `fetch_registry_entry` repeat
  that check.
- `attest`: a pure function from a wallet snapshot to a `ReserveAttestation`
  (confirmed reserve outputs, total, tip height and hash, time, source), with
  canonical sorted-key JSON and a SHA-256 digest. `AttestationSigner`,
  `KeypairSigner` and `SignedAttestation` form the BIP-340 signing hook,
  exercised with test keys only.
- `validate_proxy_url` and `usd-reserve --proxy`: route every request through
  `socks5h://` or HTTP(S). `socks5://` is refused, and a dead proxy fails
  closed.
- The `usd-reserve` binary: `init`, `address`, `descriptor`, `balance`,
  `attest`, `check-asset`.
