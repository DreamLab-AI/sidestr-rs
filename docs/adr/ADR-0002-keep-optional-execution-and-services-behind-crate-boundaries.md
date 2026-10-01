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
