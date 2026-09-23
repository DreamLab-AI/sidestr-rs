# sidestr-agent

Rust port of Melvin Carvalho's sidestr sidechains, AGPL-3.0-only: the economic engine for did:nostr agents. A did:nostr key is a sidechain wallet.

`sidestr-agent` is an agent's wallet on a sidestr sidechain, as a library and
a binary. **The agent's Nostr key is the wallet.** The x-only public key behind
its `npub` and its `did:nostr:<hex>` is the taproot output key its coins pay
(`5120‖pubkey`, used untweaked, as siding's wallet does). Its chain address is
that script in bech32m under the chain's prefix. One key does three jobs:

- it names the agent;
- it signs the agent's spends;
- it signs the kind-23500 event that carries each spend to the producer's
  relays.

The binary generalises the tool that ran the first live loop on
`sidestr:dreamlab`, beside Bitcoin testnet4. That loop was a peg-in, three
trades between Alice and Bob as kind-23500 events each signed with its
agent's own key, and a peg-out. **Testnet4 and experimental chains only.**
Coins on `sidestr:dreamlab` have no value.

## Install

```sh
cargo install sidestr-agent
```

## Commands

```sh
# every name of the agent's key: npub, did:nostr, script, chain address
sidestr-agent --key-file alice.key --url http://127.0.0.1:3450 address
sidestr-agent address --prefix drm npub1…            # anyone's, offline

# coins and balance at the producer's tip
sidestr-agent --key-file alice.key balance

# pay another agent by npub (or did:nostr, a drm1… address, a script hex);
# the kind-23500 event is signed by alice's key and published to the relays
sidestr-agent --key-file alice.key send npub1… 30000
sidestr-agent --key-file alice.key send did:nostr:<hex> 30000 --post   # also POST /tx
sidestr-agent --key-file alice.key send npub1… 30000 --dry-run         # print, deliver nothing

# peg out: burn sats the peg holders owe to a testnet4 address
sidestr-agent --key-file alice.key burn tb1p… 20000

# peg in: what a parent wallet pays (the peg address and its descriptor, the marker)
sidestr-agent --key-file alice.key --chain chain.json pegin-plan --amount 50000
sidestr-agent --chain chain.json pegin-plan --amount 50000 --refund npub1… --to drm1p… \
  --peg-address tb1p…     # an address the producer's peg wallet gave you
```

| flag | meaning | default |
|---|---|---|
| `--url` | the producer (`/coins`, `/tip`, `/chain.json`, `POST /tx`) | `http://127.0.0.1:3450` |
| `--relays` | relays for the kind-23500 event, comma-separated | siding's five defaults |
| `--key-file` | 64 hex characters or an `nsec1…`; a key is never taken on the command line | — |
| `--chain` | read the chain document from a file instead of `<url>/chain.json` | — |

Every command prints one JSON object.

## The peg-in plan

SPEC 6 (0.0.3) makes the peg output the taproot output the peg holders own,
at any position. `pegin-plan` gives the parent wallet what to pay:

- **By default, on a level-1 chain**, the peg address is
  `tr(<the chain's signer>, and_v(v:pk(<refund key>), older(<refundBlocks>)))`.
  The plan prints the checksummed descriptor, built with rust-miniscript.
  The producer imports it into its peg wallet (watch-only is enough) so the
  wallet owns the output. The refund key, the agent's own by default, can
  sweep a peg that is never claimed once `refundBlocks` parent blocks have
  passed. This is the address the first live peg-in paid.
- **`--peg-address`**: the address the peg wallet gave (`getnewaddress`) is
  paid as it is. The refund is then the peg holders' promise.
- **On a level-2 chain**: the chain's challenge address, which the
  federation's peg wallet owns.

The plan also prints the marker `pegin:<chain id>:<script>` and the `send`
outputs for Bitcoin Core.

## Library

```rust
use sidestr_agent::{identity, parse_pubkey};

let bob = parse_pubkey("npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg").unwrap();
let id = identity(&bob, "drm").unwrap();
assert_eq!(id.script, format!("5120{bob}"));
assert!(id.address.starts_with("drm1p"));
```

The docs have a complete offline example: two agents on a chain held in
memory, paying each other by npub.

## Provenance and licence

This crate builds on `sidestr-core`, `sidestr-wallet` and `sidestr-nostr`,
which port **siding**, the reference implementation of sidestr by Melvin
Carvalho ([github.com/sidestr/spec](https://github.com/sidestr/spec),
AGPL-3.0). It is licensed **AGPL-3.0-only**, like everything it derives
from. See [LICENSE](LICENSE). Part of
[sidestr-rs](https://github.com/DreamLab-AI/sidestr-rs).

## Status — 0.1.0

The offline parts are tested without a network (`tests/offline.rs`):

- keys against NIP-19's published vectors;
- the live loop's two agents, from did:nostr key to the `drm1…` address the
  chain paid;
- a loop on a chain held in memory: a spend by npub, one back by did:nostr,
  a peg-out, each event verified as signed by the paying agent;
- the default peg-in plan for Alice on `sidestr:dreamlab` gives the address
  the live peg-in paid on testnet4 (`tb1palk8…`), and its marker byte for
  byte;
- the plan's descriptor address matches an independent build with
  rust-bitcoin's `TaprootBuilder`;
- the binary's offline commands.

Relay publishing and the producer's HTTP calls are `sidestr-round` and
`sidestr-wallet`'s, tested there.
