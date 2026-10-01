---
id: ADR-0003
title: Keep reserve attestations origin-neutral and project-private
date: 2026-10-01
decision_status: accepted
implementation_status: complete
activation_status: inactive
supersedes: []
superseded_by: []
verified_commit: bcbe30b209f8b5703c614bfa832683ad9094ab33
owner: DreamLab AI
review_trigger: a second reserve origin is implemented; the bridge rule consumes the attestation; any proposal to publish the format or fund the Liquid reserve
---

# ADR-0003: Keep reserve attestations origin-neutral and project-private

## Context

Agentbox ADR-2117 scopes an owner-only private USD unit and a possible Liquid
reserve. The chain-facing statement is independent of Liquid: it identifies an
origin, lists replay-keyed credits, fixes the origin tip and signs canonical
bytes. The Liquid wallet, finality assumptions and registry checks belong to one
adapter. The format is project-specific and is not an appropriate reusable
encryption, custody or token standard.

## Decision

1. `sidestr-reserve` owns the origin-neutral attestation, canonical JSON, digest
   and BIP-340 signing port.
2. `sidestr-bridge-liquid` owns Liquid Wallet Kit, wallet sync, finality and the
   reserve-asset registry check. Another origin uses a sibling adapter.
3. Both crates remain unpublished and outside the published sidestr crate graph.
4. Neither crate activates a bridge rule, funds a reserve or deploys a chain.
   Those actions require their own estate evidence and the gates in ADR-2117.
5. Cryptographic operations come from maintained libraries. The code defines no
   new primitive.

## Consequences

A bridge rule can consume one stable statement regardless of reserve network,
while origin-specific dependencies stay isolated. The adapter is easier to
replace, but the attestation remains a private project contract and creates no
interoperability claim.

## Verification

At `bcbe30b209f8b5703c614bfa832683ad9094ab33`, both manifests set
`publish = false`; the Liquid adapter depends on `sidestr-reserve`, and neither
depends on the published crates. Tests cover canonical ordering, duplicate
credit refusal, signature verification, Liquid finality and registry matching.
Repository evidence records the reserve as unfunded and inactive.
