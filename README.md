# sidestr-rs

Rust port of Melvin Carvalho's sidestr sidechains, AGPL-3.0-only: the economic engine for did:nostr agents. A did:nostr key is a sidechain wallet.

[sidestr](https://github.com/sidestr/spec) is a protocol for **user-activated
sidechains beside a Bitcoin-family parent**. A chain is a JSON document. Its
blocks carry a BIP-325 signed challenge instead of proof of work. Coins enter
by a peg-in on the parent and leave by a burn the peg holders pay. Nostr
relays carry the chain's transactions and its tip announcements.

Melvin Carvalho designed the protocol and the reference implementation this
repository ports (**siding**, with the `bitcoin-desktop/schema` kernel and
`bitcoin-blake/blaketestnode` it loads). This repository is a Rust port of
them. Where it adds something, it says so.

In a sidestr chain the output key of a taproot coin is a 32-byte x-only
secp256k1 key, and so is a Nostr identity. So an agent that holds a
`did:nostr` key holds a wallet. It can be paid by `npub`, spend with the key
its identity already has, and sign the event that carries each payment.
[`sidestr-agent`](sidestr-agent) is that wallet.

> **Testnet only.** Everything here runs beside Bitcoin **testnet4** and on
> experimental sidechains such as `sidestr:dreamlab`. Their coins have no
> value. No real funds exist anywhere in this work.
>
> One exception is being wired, not live: [`sidestr-bridge-liquid`](sidestr-bridge-liquid)
> watches a **Liquid mainnet** reserve for the owner's private USD unit
> (ADR-2117). It is unfunded; it is funded only on the owner's explicit go.

## Crates

| crate | what | crates.io | docs |
|---|---|---|---|
| [`sidestr-header`](sidestr-header) | both header families: stock 80-byte SHA-256d and Knots' 164-byte v2 BLAKE2b; compact targets, powLimit, BIP-325 block data; `no_std` | [![](https://img.shields.io/crates/v/sidestr-header.svg)](https://crates.io/crates/sidestr-header) | [docs.rs](https://docs.rs/sidestr-header) |
| [`sidestr-core`](sidestr-core) | the chain document, parents table, signed blocks, peg-in claims and peg-out burns, Knots' unified sighash, the parent view, block files, SPEC 12 assets, constant-product pools and prediction markets, a validating chain | [![](https://img.shields.io/crates/v/sidestr-core.svg)](https://crates.io/crates/sidestr-core) | [docs.rs](https://docs.rs/sidestr-core) |
| [`sidestr-nostr`](sidestr-nostr) | the Nostr plane: NIP-01 events, a sealed signer port, tips (33333, with the peg script), transactions (23500/23501/23503), rule and genesis documents, the round envelopes, estate kinds 38420–38425 | [![](https://img.shields.io/crates/v/sidestr-nostr.svg)](https://crates.io/crates/sidestr-nostr) | [docs.rs](https://docs.rs/sidestr-nostr) |
| [`sidestr-wallet`](sidestr-wallet) | coins, the reference coin selection, key-path spends, burns and EVM deposits signed by the parent's family, spends with records, issued assets (issue, transfer), the peg-in shape, delivery | [![](https://img.shields.io/crates/v/sidestr-wallet.svg)](https://crates.io/crates/sidestr-wallet) | [docs.rs](https://docs.rs/sidestr-wallet) |
| [`sidestr-round`](sidestr-round) | the level-2 co-signing round and the peg-out PSBT round as pure state machines on the reference's wire, a vote journal, the `cosign` signer | [![](https://img.shields.io/crates/v/sidestr-round.svg)](https://crates.io/crates/sidestr-round) | [docs.rs](https://docs.rs/sidestr-round) |
| [`sidestr-hitch`](sidestr-hitch) | Hitch's Lightning-shaped channel kernel: 2-of-2 funding, revocable commitments, HTLCs and claims, peer finality/recovery, durable snapshots, invoices and one-hop routing | [![](https://img.shields.io/crates/v/sidestr-hitch.svg)](https://crates.io/crates/sidestr-hitch) | [docs.rs](https://docs.rs/sidestr-hitch) |
| [`sidestr-agent`](sidestr-agent) | an agent wallet where the did:nostr key is the wallet: balance, npub → address, spends, burns, EVM deposits and asset transfers as kind-23500 events, a peg-in plan, a faucet; the library builds for wasm32 | [![](https://img.shields.io/crates/v/sidestr-agent.svg)](https://crates.io/crates/sidestr-agent) | [docs.rs](https://docs.rs/sidestr-agent) |
| [`sidestr-evm`](sidestr-evm) | the `evm` rule: Ethereum transactions carried in sidechain transactions, run through revm (Cancun) beside the UTXO set, deposits and withdrawals at 1 sat = 1 gwei, the state root in the coinbase; every root checked against the reference on ethereumjs | not published | — |

Unpublished (`publish = false`), not live, for the owner's private USD unit
of account (ADR-2117):

- [`sidestr-reserve`](sidestr-reserve): the reserve attestation the `bridge`
  rule will check, independent of the reserve's network. It states the
  origin, the credits keyed by replay id, the final origin tip, canonical
  bytes and a BIP-340 signing hook.
- [`sidestr-bridge-liquid`](sidestr-bridge-liquid): the Liquid origin
  adapter. A watch-only wallet on Blockstream's Liquid Wallet Kit, synced
  from the public Esplora server, read into a `sidestr-reserve` attestation.

Neither depends on the published crates. Another reserve network would be a
sibling adapter.

Dependencies remain acyclic. `sidestr-hitch` depends on `sidestr-core`;
the channel crate does not enter the consensus core. `sidestr-core` never
depends on `sidestr-header`, nor on the EVM: revm and alloy stay in
`sidestr-evm`.

## Status

Reference commit
[`fe689e9`](https://github.com/sidestr/spec/commit/fe689e9c723f9bf43393d2dd5b6f924a701c8a18).
Ported since 0.0.2:

- the peg output is the taproot output the peg holders own, at any position (0.0.3);
- signatures follow the parent's family (0.0.3);
- the signer announces the peg script with every tip (the `peg` tag), and an
  output paying it is the peg wherever it sits (0.0.4);
- kind 23503 carries a signed parent transaction to a producer with a node
  (0.0.4);
- a record is exactly its push: bytes after it or missing refuse it
  (sidestr/spec#17; sidestr-rs always read it so).
- rule activation heights, assets, constant-product pools and binary
  prediction markets;
- producer eviction for a transaction that admission accepted but a block
  cannot carry;
- wallet-change and self-funding exclusions in peg scans, with one claim
  candidate per marker transaction;
- federated tip authors, one relay socket per URL, and `ETag` caching for
  `blocks.json`;
- EVM snapshots restored at any retained height.

- **Level 1 (one signer): complete.** Both header families work end to end:
  genesis from the document, production, validation, the mempool policy,
  claims, burns, the block file, the wallet.
- **Level 2 (a k-of-n federation): usable.** Blocks are co-signed through the
  round, interoperating with the reference signer on the wire. Tested with
  three signers on one box, in both mixes of Rust and JS. **Not yet done:** a
  signer on another machine, changing the signer set, and a Byzantine
  fault-tolerant redesign of the round.
- **The `evm` rule: ported** (`sidestr-evm`, not yet published). A follower
  validates an evm chain end to end, with the assets rule as consensus
  beside it, as the reference installs it on every chain naming a rule. Every
  state root of a scripted chain matches siding on ethereumjs byte for byte.
  The JSON-RPC endpoint (`evmrpc.mjs`) is ported as `sidestr_evm::rpc`.
- **Assets, pools and markets: ported.** Rule activation heights replay from
  the named height. Pools enforce the reference's integer constant-product
  boundary; markets cover open, split, merge, resolve, redeem and refund.
- **Hitch channels: pure channel kernel ported.** The funding output,
  asymmetric commitments, revocable delayed outputs, HTLC success/timeout/
  penalty paths, cooperative and unilateral close produce the reference's
  exact scripts. The Rust peer machine covers opening, update/ack/revoke
  finality, collision handling, recovery, buffered updates and checked
  snapshots. Invoices and one-hop hub routing preserve Hitch's fee and
  timeout rules. A host still supplies wallet funding, Nostr relay I/O,
  chain watches, storage and broadcasting.
- Out of scope: a trust-minimised peg-out and the draft dispute and
  multi-outcome market extensions. Assets are also available as a holders'
  view on chains that do not adopt the rule.

## What is proven against the reference

Reference conformance uses the engine as the oracle. What is tested:

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
- **EVM:** a scripted `evm` chain of 35 blocks, run by siding's `evm.mjs` on
  ethereumjs 10.1.3, is replayed by `sidestr-evm`: every accepted block's
  state root, withdrawals and receipts match byte for byte, and every refused
  block is refused (`sidestr-evm/tests/oracle.rs`).
- **Hitch:** every Rust-built commitment, close, delayed sweep, penalty,
  HTLC success/timeout/revocation claim and direct key-path claim is checked
  by Hitch's JavaScript module and the schema kernel interpreter
  (`sidestr-hitch/tests/oracle.rs`). Every opening, update, acknowledgement,
  revocation, close and sync message also passes Hitch's exact JavaScript
  wire validator (`sidestr-hitch/tests/wire_oracle.rs`).
- **Audit regressions:** independent audits' counter-examples are kept as
  `tests/audit_regressions*.rs`. The 0.0.3 release was verified by GPT-6
  Astra before publishing. It re-ran every gate and confirmed each change at
  its layer against the reference. It compared 103 stock and 104 BLAKE2b
  block snapshots, including claims, burns and the full UTXO set, and found
  them equal. It raised four findings, all fixed and pinned as
  `tests/audit_regressions_0_0_3.rs`.

To run the oracle suites, check out the four reference repositories at the
pinned commits and name them:

```sh
git clone https://github.com/sidestr/spec && git -C spec checkout fe689e9c723f9bf43393d2dd5b6f924a701c8a18
git clone https://github.com/bitcoin-desktop/schema && git -C schema checkout b8cbf6337c7450fe14ddc5bce00c7280059aab5d
git clone https://github.com/bitcoin-blake/blaketestnode && git -C blaketestnode checkout d2764d21fe1f8c29b1979e49eb8287a72dd2347e
git clone https://github.com/bitcoin-blake/hitch && git -C hitch checkout 6752e24041f98dd9260d6be6f3710b29e9664a7f

SIDESTR_SIDING=$PWD/spec/siding SCHEMA=$PWD/schema BLAKETESTNODE=$PWD/blaketestnode HITCH=$PWD/hitch \
  cargo test --workspace --all-features
```

Without these four variables the oracle halves say they are skipped, and
the Rust halves still run. You need Node.js 20 or later, and no `npm
install`. CI runs both ways ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## Live chain

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
