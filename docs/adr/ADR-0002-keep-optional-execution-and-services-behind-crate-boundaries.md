---
id: ADR-0002
title: Keep optional execution and services behind explicit crate boundaries
date: 2026-10-01
decision_status: accepted
implementation_status: complete
activation_status: inactive
supersedes: []
superseded_by: []
verified_commit: bcbe30b209f8b5703c614bfa832683ad9094ab33
owner: DreamLab AI
review_trigger: sidestr-core gains an EVM, channel, relay, wallet or reserve dependency; an estate chain activates pools, markets, EVM or Hitch
---

# ADR-0002: Keep optional execution and services behind explicit crate boundaries

## Context

This parity release adds assets, constant-product pools, binary markets, an EVM
overlay and Hitch payment channels. Combining them in one consensus crate would
make the minimal validator depend on an EVM, networking, storage and channel
operations. It would also blur the difference between a released library and an
activated estate capability.

## Decision

1. `sidestr-core` owns deterministic chain validation and the reference's native
   assets, pool and market state transitions.
2. Optional state machines enter validation through ordered rule hooks.
   `sidestr-evm` owns revm, EVM state and RPC; `sidestr-core` has no EVM
   dependency.
3. `sidestr-hitch` may depend on `sidestr-core` for Bitcoin-family scripts and
   sighashes. The consensus core has no channel dependency. Hitch remains a pure
   channel and routing kernel; a host supplies funding, relays, storage, chain
   watches and broadcasting.
4. Wallet construction and signing ports remain outside consensus validation.
   Network clients and producer policy remain outside both.
5. Publication and activation are recorded separately. The seven public crates
   can be released while EVM, Hitch, pools and markets remain inactive in the
   DreamLab chain instance.

## Consequences

Minimal consumers avoid revm and service dependencies, and each optional layer
can be tested against its own reference surface. A host must compose the pieces
explicitly, preserve rule ordering and provide the operational services that pure
state machines omit.

## Verification

At `bcbe30b209f8b5703c614bfa832683ad9094ab33`, the workspace dependency graph
is acyclic: `sidestr-hitch` points to core, `sidestr-evm` composes core, and no
reverse edge exists. The root README records seven published crates, an
unpublished EVM crate and the host services Hitch still requires. The estate's
live `sidestr:dreamlab` instance continues to use the upstream JavaScript
producer and has not activated these optional capabilities.

## Amendment 2026-10-02: channel leaves are a consensus template, not a channel dependency

**Trigger.** Owner decision SC6 (2026-10-02) makes Hitch force-close
mandatory for the sidechain demo. Before this amendment, `sidestr-core`
accepted only taproot key-path spends, so the cooperative close (the 2-of-2
funding leaf) and every force-close path were valid in the JavaScript
producer and invalid in the Rust validators (forum wallets replay the chain
through `sidestr_core::state::State`). The first Hitch close would have forked
them.

**Decision.** Decision 3 stands: `sidestr-core` takes no dependency on
`sidestr-hitch`, and the edge still points from Hitch to core. What core gains
is knowledge of the *script shapes* Hitch 0.2.0 (`lib/channel.mjs` at `62f8e39`)
writes, as consensus data, in `sidestr_core::channel`:

1. Seven leaf templates (`ChannelLeaf`): the funding 2-of-2 `multi_a`; a single
   key (the revocation leaf of `to_local` and of each HTLC); `to_local`'s
   delayed leaf (`<delay> CSV DROP <key> CHECKSIG`); the offered and received
   HTLC success leaves (`SHA256 <hash> EQUALVERIFY <key> CHECKSIG`, received
   with a CSV delay; no `SIZE` check, as Hitch writes none); and the offered and
   received timeout leaves (CLTV `<expiry>`, offered with a CSV delay). Numbers
   must be minimal `CScriptNum` pushes, as Hitch writes them.
2. A script-path input is accepted only if its leaf parses as one of these
   templates byte for byte. The control block, the leaf commitment, the annex,
   tapscript signatures and Schnorr verification come from the `bitcoin` and
   `secp256k1` crates (`ControlBlock::verify_taproot_commitment`, the BIP 341
   sighash). Core does not interpret script: each template is checked by
   matching, plus the exact semantics of its opcodes (CSV and CLTV per BIP 112
   and BIP 65, `SHA256` of a preimage within the 520-byte push limit). Any other leaf, an
   unknown leaf version, or a non-minimal encoding is refused, even where
   Bitcoin Core would accept it.
3. BIP 68 relative locks and `nLockTime` finality are **block** rules
   (`btc:rule-blockctx-sequence-locks`, `btc:rule-blockctx-finality`), as in the
   reference. A script cannot see its coin's depth. `State::submit` now refuses
   a lock-immature transaction at admission. That is producer policy, not
   consensus; it keeps one early sweep from wedging block production.

**Evidence** (branch `s1-hitch-leaf-consensus`, 2026-10-02):

- `sidestr-core/tests/channel_oracle.rs` (feature `consensus-oracle`) runs
  Bitcoin Core 26.0 (`bitcoinconsensus` 0.106) and core over 436 cases, every
  template under both output-key parities, and they agree on all of them.
  Six documented narrowings are cases Core accepts and core refuses (an
  unknown leaf version, four non-template scripts, CSV under a negative
  `i32` version). Hitch cannot emit any of them.
- `sidestr-hitch/tests/chain_consensus.rs` builds a chain beside `tbtc4` with
  open, pay, cooperative close, force-close, `to_remote`, a sweep after CSV,
  a penalty on a revoked state, and HTLC success and timeout claims, covering
  all seven templates. siding at sidestr/spec `fa86dac` (schema `b8cbf63`,
  blaketestnode `de33b34`, the producer's pins) replays it to the same tip
  hash and coin count. Both engines refuse twelve blocks for the same rule
  ids: a one-signature funding spend; early sweep, claim and refund; a sweep
  one block early; a wrong preimage; a flipped control-block parity; a wrong
  internal key; a wrong Merkle path; a tampered leaf; and an uncommitted
  leaf. Core refuses the seven script-level negatives and passes the five
  lock negatives, which the block rules then refuse in both engines.
- The live `sidestr:dreamlab` Pages mirror, replayed by core at 20:39 UTC,
  reached height 946 `49a4e0f1…b881`, the producer's own hash at 946. The
  producer's served block file replays to its tip, 947 `66c47b1b…d00c`.

**Finding (producer liveness, not consensus).** At `fa86dac`, `Siding.submit`
checks context-free rules only, so it admits a lock-immature transaction.
`produce` then fails on `btc:rule-blockctx-sequence-locks` on every tick, and
nothing evicts the transaction: eviction arrives with `c3b9e7a` (issue 13),
which `fa86dac` does not contain. A height-based CSV lock never matures
without new blocks, so one early sweep halts the chain until the producer
restarts. The chain test records this probe. `fa86dac` is an ancestor of
`c3b9e7a` (seven commits later on `gh-pages`). With siding at `c3b9e7a` or at
`e8deb63`, the same probe evicts the sweep and makes the next block (110 to
111, mempool 0), and the dual-engine chain test still passes. All three
commits replay the live producer's block file to the same tip (947
`66c47b1b…d00c`, 67 coins). The remedy is to fast-forward the producer pin to
`c3b9e7a` or later; until then, a host must never broadcast a sweep before its
depth.

**Activation.** The `activation_status` above is unchanged. Recognising
Hitch spends in the validators is what makes activation safe; it does not
activate Hitch on the DreamLab instance.
