---
id: ADR-0001
title: The pinned reference implementation is the compatibility oracle
date: 2026-10-01
decision_status: accepted
implementation_status: complete
activation_status: live
supersedes: []
superseded_by: []
verified_commit: bcbe30b209f8b5703c614bfa832683ad9094ab33
owner: DreamLab AI
review_trigger: the pinned sidestr, schema, blaketestnode or Hitch revision changes; an intentional wire or consensus departure is proposed
---

# ADR-0001: The pinned reference implementation is the compatibility oracle

## Context

This workspace is an attributed Rust port of `sidestr/spec`, the
`bitcoin-desktop/schema` kernel, `bitcoin-blake/blaketestnode` and Hitch. Prose
alone cannot establish compatibility across consensus serialisation, sighashes,
Nostr events, state roots or payment-channel scripts. Some deliberate Rust
departures are safer than the reference, so source similarity is not the goal.

## Decision

1. CI pins all four reference repositories by commit and runs their executable
   behaviour as the compatibility oracle.
2. Consensus and wire claims require bidirectional or byte-for-byte evidence at
   the narrowest available layer: fixtures, cross-engine acceptance, state-root
   comparison, JavaScript wire validation or the schema interpreter.
3. Oracle fixtures are regenerated in CI before they are consumed. Drift fails
   the workflow instead of silently blessing checked-in output.
4. A deliberate departure is documented beside the implementation and tested as
   a departure. It must not be described as parity for that behaviour.
5. Audit counter-examples become permanent regression tests.

## Consequences

A release can state exactly which reference revision it matches. Upstream changes
become explicit upgrade work, and running the local Rust-only tests is insufficient
for a parity release. CI needs Node.js and full checkouts of the pinned references.

## Verification

At `bcbe30b209f8b5703c614bfa832683ad9094ab33`, GitHub Actions run
`36831527612` passed reference parity, regenerated EVM fixtures with no drift,
and all oracle and interoperability suites. The same run passed both workspace
test modes, the three rustdoc modes, native and wasm32 `no_std` checks and the
library WASM build.
