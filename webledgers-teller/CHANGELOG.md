# Changelog

All notable changes to `webledgers-teller`. The crate follows semantic versioning.

## 0.2.0 (2026-10-03)

- Moves to sidestr-nostr 0.6 and sidestr-core 0.4.2. The re-exported `Event` and `UnsignedEvent` now come from sidestr-nostr 0.6, so this is a breaking bump; the teller logic is unchanged.

## 0.1.0 (2026-10-02)

The first release: a port of solidpayorg/teller `lib/teller.mjs` at
`7c00cea` (Melvin Carvalho, AGPL-3.0-or-later), including that commit's two
fixes.

### Added

- The ledger (`ledger`): `new_ledger`, `ledger_hash` (`sha256(JCS(genesis))`),
  `check_ledger`, `parse_ledger`, `balance`, `total`, and the moves applied
  once: `credit` by outpoint, `transfer` and `debit` by request id, refusals
  in the teller's words. `Ledger` serialises field for field as the teller
  writes it, so a ledger written by either side loads and hashes the same on
  the other. `jcs` for the plain JSON these documents are.
- The ledger on Nostr, from the teller's page: `ledger_template` and
  `ledger_event` (kind 30333, `d` = the hash), `read_ledger_event` (the
  operator's own copy only) and `latest_ledger`.
- Accounts and amounts: `account_of`, `x_of`, `sats`, `check_sats`.
- Deposit addresses (`deposit`): `deposit_address`, `deposit_secret` and
  `watch_list`. The operator is read as its did (the `02` point of its x), so
  the address from a point of either parity, from the did and from the
  normalised secret agree (the teller's `7c00cea` fix).
- Requests (`request`, kind 3700): `request_tags`, `request_template`,
  `request_event`, `request_id` and `parse_request`.
- Payouts (`payout`): `plan_payout`, `unsigned_tx`, `prevouts`,
  `sign_payout` (sighash rules as a parameter; `TXBT4_RULES` is Knots'
  unified sighash), `vsize_of` and `vsize_estimate` at 58 vB per key-path
  input (the teller's `7c00cea` fix for a payout refused as
  "min relay fee not met, 154 < 155"); the fee is checked against the signed
  size.
- A private mirror of `sidestr/spec siding/lib/keys.mjs` (`bd1d692`) over
  libsecp256k1, tested against its vendored `keys-vectors.json`, to be
  replaced by a shared `sidestr_core::keys` when that lands.
- Tests: the teller's 24 checks; a live oracle (gated on `TELLER`, with
  `SCHEMA`, `BLAKETESTNODE`, `SIDESTR_LIB`) running the teller's own suite and
  cross-checking 154 results through `tests/xcheck-teller.mjs`.
