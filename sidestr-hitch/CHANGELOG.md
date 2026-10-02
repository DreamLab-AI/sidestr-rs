# Changelog

## Unreleased

- `tests/chain_consensus.rs`: five channels opened by one funding
  transaction on a sidestr chain beside `tbtc4`, then a cooperative close, a
  force-close swept after the CSV delay, a revoked commitment taken by the
  penalty, and HTLCs claimed with the preimage and refunded after expiry on
  both owners' commitments — all seven leaf templates — built by this
  crate's kernel and validated by `sidestr-core`'s `Chain`. With
  `SIDESTR_SIDING`, `SCHEMA` and `BLAKETESTNODE` set, siding replays the
  directory to the same tip hash and refuses the same early, mistimed and
  malformed spends; with feature `consensus-oracle` Bitcoin Core 26.0 judges
  every channel input. A probe records what the reference's mempool does
  with an early `to_local` sweep. `tests/chaincheck.mjs` drives siding.
- Feature `consensus-oracle` (test-only, optional `bitcoinconsensus`
  0.106).
- Each Hitch builder's leaf is checked to be exactly the matching
  `sidestr_core::channel::ChannelLeaf`, and each spend under Knots' unified
  sighash and BIP 341 against the family rules `sidestr-core` applies.

### Added

- `ChannelMachine::resign`: one of this peer's transactions signed again
  with fresh randomness, so the txid is the same and the witness differs.
  It covers a commitment or the cooperative close (this peer's funding
  signature is made again; the other side's is read from the witness and
  checked) and any of this peer's claims, a penalty included (re-signed
  with the punished state's two-party revocation key). Siding from
  `c3b9e7a` refuses, for the rest of its session, bytes it once refused or
  evicted, so a host rebroadcasts these instead. Test
  `a_rebroadcast_is_signed_again_with_a_fresh_witness` checks a forced
  close, its sweep and a penalty against `sidestr-core`'s channel rules.

### Fixed

- A `synced` message carrying `reveals` no longer fails to parse as
  `PeerMessage`. The map's keys are JSON strings, and the untagged enum's
  buffering refused them as `u64`, so a host lost every secret a resync
  sent back. They are now read as canonical decimal strings, whether the
  message is read as `PeerMessage` or as `SyncMessage`. Found by the
  `sidestr-agent hitch` loopback tests (stream S2). Regression test
  `a_synced_with_reveals_round_trips_through_peer_message`.

## 0.2.0 - 2026-10-01

Parity with Hitch at commit `62f8e39` (`lib/channel.mjs`, `lib/peer.mjs`,
`lib/route.mjs`), through the five rounds of Hitch's adversarial review.
Breaking: commitment transactions change, so 0.1 channels cannot be carried
over (see below).

- The revocation key of a commitment is a two-party key: the other side's
  basepoint plus the owner's per-state point (`revocation_pub`), signed for
  with `revocation_key` once the state is revoked. The owner can no longer
  spend its own revocation leaf. `even_secret` lifts a secret to its even
  point, as Hitch's `evenSecret`.
- Every announced revocation point carries a proof of possession
  (`pop_sign`, `pop_verify`: BIP 340 over `tagged_hash("hitch/pop",
  context || point)`), checked before the point is kept: `open` and
  `accept` gain `revBase` and `pop`, `update` and `ack` gain `nextRevPop`.
- `preimage_in` reads a preimage from an HTLC claim's witness.
- Golden vectors from Hitch's channel suite: the two-party key
  `4f355bdc…`, commitment txids `138fe225…`, `56ae7f0f…`, `4cd9bf1f…` and
  the cooperative close `5a31ac74…`.
- The protocol machine is rebuilt on Hitch's peer: a lifecycle
  (`ChannelStatus`), `reject` naming the update's signature, set-aside
  updates remembered as signed alternatives and announced as
  `ChannelEvent::Dropped`, an acknowledgement of a set-aside state adopted,
  `bound` (agreed state, pending, unrevoked alternative, followed close
  output), HTLC ids that never repeat, a state leaving the funder below its
  fee always refused, no secret of a published commitment revealed, the
  cooperative close blocking updates, `tick` (retries with backoff, the
  protective close `delay + CLAIM_MARGIN` before a claimable HTLC's expiry,
  an overdue HTLC to the chain), and the chain half: `on_spend`,
  `un_spend`, `after_close`, `watch_outputs` with penalties, sweeps, claims
  and preimages read from the chain (`ChannelEvent::Preimage`).
- New constants `CLAIM_MARGIN`, `CLOSE_DEPTH`, `FUNDING_TIMEOUT`,
  `PROPOSAL_TIMEOUT`, `UNFUNDED_TIMEOUT`, `MIN_CONF`.
- The opening typestates borrow, so a bad `accept` or `commit` leaves the
  proposal standing, and gain resend and funding-sync accessors.
- `route::Router` replaces the decision functions: `forward_delta` (margin
  + both delays + `CLAIM_MARGIN`), an invoice already paid and a duplicate
  hash refused, forwards recorded before the add, an in-flight set, a
  downstream channel chosen with room, `on_dropped`, `on_preimage`, and the
  tick (lost forwards, the protective close when only a set-aside state
  binds the hash near the upstream deadline, the close past the downstream
  expiry).
- Snapshots are version 2. Version 1 snapshots are refused: their
  single-party revocation keys are the flaw this release fixes; close such
  channels with 0.1.
- Hitch's peer and adversarial suites are ported as Rust tests (21 and 77
  checks). The oracles run against Hitch `62f8e39` and blaketestnode
  `f1da4a6`; the interpreter now also checks every transaction a Rust
  protocol run broadcasts.

## 0.1.1 - 2026-10-01

- Follow `sidestr-core` 0.4. Hitch's scripts, transactions, state machine and
  wire protocol are unchanged.

## 0.1.0 - 2026-09-30

- Port Hitch's consensus-critical channel transaction layer at upstream
  commit `6752e24`: its NUMS key, 2-of-2 funding leaf, revocable delayed
  output, three-path HTLC output, asymmetric commitments, cooperative close,
  delayed sweep, penalty, HTLC claims and direct key-path spend.
- Preserve both Bitcoin BIP 341 and Bitcoin Knots unified sighash signing.
- Pin every script to Hitch's published golden vectors.
- Port the opening handshake, payment and HTLC updates, three-message
  revocation finality, simultaneous-update collision handling, cooperative
  and unilateral closes, bounded resynchronisation and buffered updates.
- Add versioned snapshots that recheck channel accounting, key relationships,
  payment preimages and every retained counterparty signature on restore.
- Port Hitch invoices and one-hop hub routing, including fee and timeout
  deltas, durable forwarding links and the protective-close threshold.
- Cross-check Rust transactions with Hitch and the schema interpreter, and
  pass every Rust wire message through Hitch's own validator in CI.
