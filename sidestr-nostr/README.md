# sidestr-nostr

> Part of [sidestr-rs](https://github.com/DreamLab-AI/sidestr-rs). Rust port of Melvin Carvalho's sidestr sidechains, AGPL-3.0-only: the economic engine for did:nostr agents. A did:nostr key is a sidechain wallet.

The Nostr plane of [sidestr](https://github.com/sidestr/spec) sidechains, in
Rust: an owned NIP-01 event with BIP-340 verification and a sealed signer port,
the chain document as an event (kind 3500, SPEC 0.0.5: its id is the chain's
hash) and resolving a chain by its alias or its hash, the tip announcement
(kind 33333) with the mirror trust rule, transactions and
faucet requests over a relay (23500, 23501), parent transactions to broadcast (23503), rule and genesis documents (33500,
33501), the dual-schema 33502 record decoded as peg record, pledge or
ambiguous, the level-2 round envelopes (23510–23514), and agentbox's account
binding and settlement events (38420–38425).

A sidestr chain has no peer-to-peer network: blocks are served as a file from
any mirror, and everything else travels as signed events on public relays. The
one rule that makes a relay's answer worth acting on is the announcement's: a
client takes the newest announcement for a chain's alias (`sidestr:<name>`),
reads the chain event its `e` tag names, and accepts it when the event's id is
the hash of its content and its author is the announcement's; a chain made
before spec 0.0.5 is accepted by a mirror's `chain.json` naming the announcer
as the level-1 signer or one of its level-2 signers. The mirror is then held
to the announced tip: it may be behind, never ahead. The alias is a name, not
a proof; the chain's hash is its identity.

```rust
use sidestr_nostr::chain::{parse_chain_event, resolve_chain, sign_chain_event};
use sidestr_nostr::event::{SecretKeySigner, Signer};
use sidestr_nostr::tip::{parse_tip, sign_tip, TipTemplate};

let signer = SecretKeySigner::from_hex(&"07".repeat(32)).unwrap();
let me = signer.pubkey_hex().unwrap();
let doc = format!(r#"{{"id":"sidestr:example","name":"example","parent":"tbtc4","challenge":"5120{me}"}}"#);
let chain = sign_chain_event(&signer, &doc, 1_790_100_000).unwrap();   // its id is the chain's hash
let t = TipTemplate::new("sidestr:example", 0, vec![], vec!["https://mirror.example/x".into()])
    .unwrap()
    .with_chain_hash(&chain.id)
    .unwrap();
let tip = parse_tip(&sign_tip(&signer, &t, 1_790_100_001).unwrap()).unwrap();

let found = resolve_chain(Some("sidestr:example"), None, 1,
    |_| Some(tip.clone()), |_| Some(chain.clone()), |_| Err("404".into())).unwrap();
assert_eq!(found.hash.as_deref(), Some(chain.id.as_str()));
assert_eq!(parse_chain_event(&chain).unwrap().chain["signer"], me.as_str());
```

```toml
[dependencies]
sidestr-nostr = "0.6"
```

```rust
use sidestr_nostr::event::SecretKeySigner;
use sidestr_nostr::tip::{parse_tip, sign_tip, TipTemplate};

let signer = SecretKeySigner::from_hex(&"07".repeat(32)).unwrap();
let header = format!("{:02x}", 1).repeat(80);            // one stock 80-byte header, as hex
let tip = TipTemplate::new("sidestr:example", 0, vec![header], vec!["https://mirror.example/x".into()]).unwrap();
let ev = sign_tip(&signer, &tip, 1_790_100_000).unwrap();
ev.verify().unwrap();
assert_eq!(parse_tip(&ev).unwrap().mirrors, ["https://mirror.example/x"]);
```

## Attribution

This crate is a port of **siding**, the reference implementation of sidestr by
Melvin Carvalho ([github.com/sidestr/spec](https://github.com/sidestr/spec),
AGPL-3.0), ported from commit `2de40bdac4cba01be0864156a553d8287c22e279`
(the tip announcement and transaction events follow `announce.mjs` and
`relay.mjs` through `fe689e9`: the `peg` tag, kind 23503 and federated
announcement authors; the chain document as a kind-3500 event, the tip's `e`
tag and resolution by alias or hash follow `announce.mjs` through
`e8deb63161c7459ed39c01d2ca9fda3d860b65b6`, SPEC 0.0.5)
(`siding/lib/{announce,relay,pledge,round,pegoutround,spend}.mjs`,
`bin/siding.mjs`, `test/announce-test.mjs`). The event id and signature rule
comes from the schema kernel siding loads, by the same author and under the
same licence: [bitcoin-desktop/schema](https://github.com/bitcoin-desktop/schema)
(`codec/nostr.js verifyNostrEvent`). `SPEC.md` in the sidestr repository is
the design; the crate documentation cites its sections, and every ported
function names its original. The announcement and mirror rule in the crate
docs is Melvin Carvalho's wording from `announce.mjs` and SPEC 11, adapted.

Agentbox kinds 38420–38425 are this estate's own (ADR-2098, DDD-022),
not upstream's.

## What changed in the port

- SHA-256 is RustCrypto `sha2`; BIP-340 Schnorr is `secp256k1` through
  `rust-bitcoin`, sharing `sidestr-core`'s context. Nothing cryptographic is
  hand-rolled. The in-memory signer uses zero auxiliary randomness, so an
  event is a pure function of its fields and the key (siding draws random aux;
  both are valid on the wire).
- Keys sit behind a `Signer` port that is driven only through named
  constructors (`sign_tip`, `sign_transaction_event`, `sign_rule`,
  `sign_pledge`, `sign_proposal`, `sign_account_binding`, …); the request type
  has no public constructor, so there is no generic "sign this payload" path.
  siding passes a raw hex key to every function.
- **Both header families parse** (upstream matched at spec 0.0.3). Before
  sidestr/spec PR #7, siding's `parseTip` accepted only content whose length
  divides by 328 (the 164-byte Knots v2 header) and therefore returned `null`
  for every announcement of a chain beside a stock Bitcoin parent (80-byte
  headers, 160 hex characters), including the live `sidestr:dreamlab`
  announcement carried in `fixtures/live-33333.json`. Since 0.0.3
  `headerWidth` reads the width from the content, bounded to `TIP_HEADERS`
  headers and hex-checked before slicing; this crate applies the same bound.
  Its kernel NIP-333 reader (`schema/codec/nostr.js`) uses 160. Here the
  family is inferred from the length, or taken from the chain's parent; a
  length that fits both is refused rather than guessed.
- Refusals are typed errors with the reason, not `null`.
- Kind 33502 is decoded by structure into `PegRecord | Pledge | Ambiguous`,
  never guessed; siding reads every 33502 as a pledge.
- Kinds 33500 and 33501 are conformant to SPEC prose only: upstream has no
  implementing code or wire example for either.
- No socket: siding uses the platform's `WebSocket`. Here the NIP-01 messages,
  the subscriptions and the on-receipt checks are pure, and I/O is a
  `RelayClient` port the caller implements. `resolveChain`'s three lookups
  (the newest tip, an event by id, a mirror's JSON) are closures the caller
  answers.
- The chain event's content is the document's JSON text written as
  `JSON.parse` then `JSON.stringify` would write it (key order, integer-like
  keys first, JavaScript's number printing), so the chain's hash a Rust signer
  gives for a `chain.json` is the one siding gives.

## Status: 0.4.0

Every codec has encode → decode round-trip tests and rejecting tests. Proven
against the reference:

- events built and signed here for the disposable `sidestr:trial` key are
  byte-identical in tags, content, id and signature to siding's `tipEvent`
  and `makeEvents` output over the kernel's hash and curve
  (`tests/oracle.rs`, `fixtures/oracle-vectors.json`; the key is
  `sidestr-core`'s `fixtures/trial/trial.key`, read from the sibling crate when
  present, verify-only otherwise);
- kind-3500 chain events built and signed here from the same document texts
  (the trial chain, the level-2 `fedtest` chain, and a document whose JSON
  exercises key order and number printing) are byte-identical to siding's
  `chainEvent` at sidestr/spec `e8deb63`, read back as its `parseChainEvent`
  reads them, and a tip naming the chain's hash carries exactly its tags
  (`tests/chain_event.rs`, `fixtures/chain-event-vectors.json`, regenerated
  by `tests/oracle/chain-event-oracle.mjs` and compared when the reference
  checkouts are named);
- sixteen live kind-33333 announcements from nine chains, fetched read-only
  from public relays, verify and parse (`tests/live.rs`,
  `fixtures/live-33333.json`, each with the relay and time it was received).
  Nothing was published to any relay;
- the level-2 envelopes (23510–23514) carry a co-signing round between a
  Rust signer and the reference's JS signers on one chain, in both
  directions (`sidestr-round`'s `tests/interop_round.rs` and
  `tests/interop_pegout.rs`).

Elsewhere in the stack, relay I/O (a tokio websocket client behind
`sidestr-round`'s `relay` feature) and the round logic itself (entitlement,
one signature per height and the seal) are `sidestr-round`'s. Not yet: pledge
verification against a parent view, NIP-333's bulk `u`-tag channels, the
assets and pool records.

## Running the checks

```sh
cargo test                                   # unit, oracle vectors, live fixture, doctests
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo clippy --all-targets -- -D warnings && cargo fmt --check
```

## Licence

AGPL-3.0-only, as a derivative work of siding. See [LICENSE](LICENSE). This
crate is **not dual-licensed**: a crate that links it is AGPL-3.0 in effect and
should say so.
