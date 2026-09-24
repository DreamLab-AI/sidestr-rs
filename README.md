# sidestr-rs

Rust port of Melvin Carvalho's sidestr sidechains, AGPL-3.0-only: the economic engine for did:nostr agents. A did:nostr key is a sidechain wallet.

[sidestr](https://github.com/sidestr/spec) is a protocol for **user-activated
sidechains beside a Bitcoin-family parent**. A chain is a JSON document. Its
blocks carry a BIP-325 signed challenge instead of proof of work. Coins enter
by a peg-in on the parent and leave by a burn the peg holders pay. Nostr
relays carry the chain's transactions and its tip announcements.

The protocol, and the reference implementation this repository ports
(**siding**, with the `bitcoin-desktop/schema` kernel and
`bitcoin-blake/blaketestnode` it loads), are the work of **Melvin Carvalho**.
This repository is a Rust port of them. Where it adds something, it says so.

In a sidestr chain the output key of a taproot coin is a 32-byte x-only
secp256k1 key, and so is a Nostr identity. So an agent that holds a
`did:nostr` key holds a wallet. It can be paid by `npub`, spend with the key
its identity already has, and sign the event that carries each payment.
[`sidestr-agent`](sidestr-agent) is that wallet.

> **Testnet only.** Everything here runs beside Bitcoin **testnet4** and on
> experimental sidechains such as `sidestr:dreamlab`. Their coins have no
> value. No real funds exist anywhere in this work.

## Crates

| crate | what | crates.io | docs |
|---|---|---|---|
| [`sidestr-header`](sidestr-header) | both header families: stock 80-byte SHA-256d and Knots' 164-byte v2 BLAKE2b; compact targets, powLimit, BIP-325 block data; `no_std` | [![](https://img.shields.io/crates/v/sidestr-header.svg)](https://crates.io/crates/sidestr-header) | [docs.rs](https://docs.rs/sidestr-header) |
| [`sidestr-core`](sidestr-core) | the chain document, parents table, signed blocks, peg-in claims and peg-out burns, Knots' unified sighash, the parent view, the block file and a mirror's bytes replayed, SPEC 12 records and the assets view, a validating chain | [![](https://img.shields.io/crates/v/sidestr-core.svg)](https://crates.io/crates/sidestr-core) | [docs.rs](https://docs.rs/sidestr-core) |
| [`sidestr-nostr`](sidestr-nostr) | the Nostr plane: NIP-01 events, a sealed signer port, tips (33333), transactions (23500/23501), rule and genesis documents, the round envelopes, estate kinds 38420–38425 | [![](https://img.shields.io/crates/v/sidestr-nostr.svg)](https://crates.io/crates/sidestr-nostr) | [docs.rs](https://docs.rs/sidestr-nostr) |
| [`sidestr-wallet`](sidestr-wallet) | coins, the reference coin selection, key-path spends and burns signed by the parent's family, spends with records, issued assets (issue, transfer), the peg-in shape, delivery | [![](https://img.shields.io/crates/v/sidestr-wallet.svg)](https://crates.io/crates/sidestr-wallet) | [docs.rs](https://docs.rs/sidestr-wallet) |
| [`sidestr-round`](sidestr-round) | the level-2 co-signing round and the peg-out PSBT round as pure state machines on the reference's wire, a vote journal, the `cosign` signer | [![](https://img.shields.io/crates/v/sidestr-round.svg)](https://crates.io/crates/sidestr-round) | [docs.rs](https://docs.rs/sidestr-round) |
| [`sidestr-agent`](sidestr-agent) | an agent wallet where the did:nostr key is the wallet: balance, npub → address, spends, burns and asset transfers as kind-23500 events, a peg-in plan, a faucet; the library builds for wasm32 | [![](https://img.shields.io/crates/v/sidestr-agent.svg)](https://crates.io/crates/sidestr-agent) | [docs.rs](https://docs.rs/sidestr-agent) |

The dependencies run one way: `core` ← `header`, `nostr`, `wallet` ← `round`
← `agent`. `sidestr-core` never depends on `sidestr-header`.

## Status

**SPEC 0.0.3**, reference commit
[`722ad42`](https://github.com/sidestr/spec/commit/722ad42d3271efccfdfaf57c3c6943f58fc168f8).
It brings two changes, both ported:

- the peg output is the taproot output the peg holders own, at any position;
- signatures follow the parent's family.

- **Level 1 (one signer): complete.** Both header families work end to end:
  genesis from the document, production, validation, the mempool policy,
  claims, burns, the block file, the wallet.
- **Level 2 (a k-of-n federation): usable.** Blocks are co-signed through the
  round, interoperating with the reference signer on the wire. Tested with
  three signers on one box, in both mixes of Rust and JS. **Not yet done:** a
  signer on another machine, changing the signer set, and a Byzantine
  fault-tolerant redesign of the round.
- Out of scope: the EVM rule, assets (SPEC 12, reserved), and a
  trust-minimised peg-out.

## What is proven against the reference

The reference engine is the oracle. What is tested:

- **Genesis:** a throwaway chain's genesis is byte-identical to the one siding
  seals. The sealed `sidestr:dreamlab` genesis replays to its documented hash.
- **Blocks:** blocks made here are accepted by siding, and siding's are
  accepted here.
- **Live chain replay:** Melvin Carvalho's live `sidestr:txbt4-siding` chain
  (BLAKE2b parent) replays from genesis to its tip with every rule on.
- **Records:** claims, burns and records read alike; the same blocks give the
  same records.
- **Wallet:** its spends and burns pass siding's `Siding.submit()`.
- **Signatures:** each engine verifies the other's key-path signatures under
  the family's rule. With the same auxiliary randomness they are
  byte-identical, on both families.
- **Nostr events:** events are byte-identical to siding's, including id and
  signature.
- **Round:** Rust and JS co-signers seal the same blocks and pay peg-outs
  proposed by either engine.
- **Audit regressions:** independent audits' counter-examples are kept as
  `tests/audit_regressions*.rs`. The 0.0.3 release was verified by GPT-6
  Astra before publishing. It re-ran every gate and confirmed each change at
  its layer against the reference. It compared 103 stock and 104 BLAKE2b
  block snapshots, including claims, burns and the full UTXO set, and found
  them equal. It raised four findings, all fixed and pinned as
  `tests/audit_regressions_0_0_3.rs`.

To run the oracle suites, check out the three reference repositories at the
pinned commits and name them:

```sh
git clone https://github.com/sidestr/spec && git -C spec checkout 722ad42d3271efccfdfaf57c3c6943f58fc168f8
git clone https://github.com/bitcoin-desktop/schema && git -C schema checkout b8cbf6337c7450fe14ddc5bce00c7280059aab5d
git clone https://github.com/bitcoin-blake/blaketestnode && git -C blaketestnode checkout d2764d21fe1f8c29b1979e49eb8287a72dd2347e

SIDESTR_SIDING=$PWD/spec/siding SCHEMA=$PWD/schema BLAKETESTNODE=$PWD/blaketestnode \
  cargo test --workspace --all-features
```

Without these three variables the oracle halves say they are skipped, and
the Rust halves still run. You need Node.js 20 or later, and no `npm
install`. CI runs both ways ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## The live chain

**`sidestr:dreamlab`** runs beside Bitcoin testnet4 (`tbtc4`):

- address prefix `drm`;
- genesis `4db37517728bd509c0cb96ee5a2e3e2a77f9e965a092e9f67948b413d453dbc0`,
  sealed 2026-09-22 (the document is vendored at
  [`sidestr-core/fixtures/dreamlab/chain.json`](sidestr-core/fixtures/dreamlab/chain.json));
- mirror: <https://dreamlab-ai.github.io/sidestr-dreamlab>, holding
  `chain.json`, `blocks.dat` and `blocks.json`.

On 2026-09-23 it ran its first full economic loop:

- a peg-in from testnet4;
- three trades between two agents, each a kind-23500 event signed with the
  agent's own Nostr key;
- a peg-out paid back on testnet4.

That loop found the two issues SPEC 0.0.3 fixes.

## In the DreamLab estate

sidestr-rs is the economic layer of DreamLab's agent estate:

- [**VisionFlow**](https://visionflow.info): the ecosystem these components
  make up.
- [**VisionClaw**](https://github.com/DreamLab-AI/VisionClaw): a knowledge
  graph engine with immersive 3D and XR and embodied agent swarms. It is the
  flagship.
- [**agentbox**](https://github.com/DreamLab-AI/agentbox): a sovereign agent
  container with `did:nostr` identities. These crates were developed there.
  The `ADR-`, `PRD-` and `DDD-` numbers in the crate docs refer to its
  decision ledger.
- [**solid-pod-rs**](https://github.com/DreamLab-AI/solid-pod-rs): a
  Rust-native Solid pod server (LDP, WAC, NIP-98).
- [**nostr-rust-forum**](https://github.com/DreamLab-AI/nostr-rust-forum): a
  decentralised Nostr forum, all Rust.
- [**loom**](https://github.com/DreamLab-AI/loom): the ontology node and
  model façade.
- [**knowledgeGraph**](https://github.com/DreamLab-AI/knowledgeGraph): the
  public ontology frontend.
- [**dreamlab-ai-website**](https://github.com/DreamLab-AI/dreamlab-ai-website):
  the DreamLab website.

## Licence

**AGPL-3.0-only** ([LICENSE](LICENSE)). The reference implementation these
crates port is AGPL-3.0, and they are derivative works of it: attributed
ports of its logic, tested against it. So they carry the same licence. They
are not dual-licensed, and a permissively licensed crate must not depend on
them. A network service built from them owes its users the source, as the
AGPL requires.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
