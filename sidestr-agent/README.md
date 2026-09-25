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

# issued assets (SPEC 12): what exists, what the key holds; issue one; move it
sidestr-agent --key-file alice.key assets
sidestr-agent --key-file alice.key issue DREAM 1000000
sidestr-agent --key-file alice.key send-asset DREAM npub1… 50 --memo tip:nostr:<event id>

# a faucet: answer kind-23501 requests with 2,000 sats and 100 DREAM, once a day per script
sidestr-agent --key-file faucet.key faucet --sats 2000 --asset DREAM --units 100 --state faucet.json

# peg out: burn sats the peg holders owe to a testnet4 address
sidestr-agent --key-file alice.key burn tb1p… 20000

# peg in: what a parent wallet pays (the peg address and its descriptor, the marker);
# level 1 with no flag: the peg script the signer announces with its tip (SPEC 0.0.4)
sidestr-agent --key-file alice.key --chain chain.json pegin-plan --amount 50000
sidestr-agent --key-file alice.key --chain chain.json pegin-plan --amount 50000 \
  --peg-address tb1p…     # or an address the producer's peg wallet gave you
sidestr-agent --chain chain.json pegin-plan --amount 50000 --refund npub1… --to drm1p… \
  --peg-key <hex>         # or a descriptor the peg holders import

# a signed parent transaction (a peg-in) with no node of your own: the parent's
# public explorer, else a kind-23503 event a producer with a node broadcasts
sidestr-agent --chain chain.json publish-parent <hex>
```

| flag | meaning | default |
|---|---|---|
| `--url` | the producer (`/coins`, `/tip`, `/chain.json`, `POST /tx`) | `http://127.0.0.1:3450` |
| `--relays` | relays for the kind-23500 event, comma-separated | siding's five defaults |
| `--key-file` | 64 hex characters or an `nsec1…`; a key is never taken on the command line | — |
| `--chain` | read the chain document from a file instead of `<url>/chain.json` | — |
| `--blocks` | the block file for the assets view: a path or an http(s) URL | `<url>/blocks.dat` |

`send` and `burn` spend only coins that carry no issued asset: every spend
reads the block file first. An asset on a coin a plain payment spent would
be destroyed.

## As a library

```toml
sidestr-agent = { version = "0.3", default-features = false }
```

Without the `cli` feature the crate is pure: no runtime, no network, and it
builds for `wasm32-unknown-unknown`. `ChainView::replay` validates a
mirror's `blocks.dat` you fetched yourself; `prepare`, `prepare_transfer`
and `prepare_issue` return the signed transaction and the signed kind-23500
event for you to deliver.

Every command prints one JSON object.

## The peg-in plan

SPEC 6 (0.0.3) makes the peg output the taproot output the peg holders own,
at any position; since 0.0.4 the signer also announces the script a peg-in
pays (the tip's `peg` tag), and an output paying it is the peg wherever it
sits. Who owns it depends on the level:

- **Level 1: the producer's parent wallet.** With no flag, the plan pays the
  peg script from the signer's newest announcement (only the chain
  document's signer counts), as the JS wallet does. Or pass `--peg-address`
  with an address that wallet gave (`getnewaddress` on its peg wallet). A
  chain whose producer announces none (before 0.0.4) is refused rather than
  guessed.
- **Level 2: the chain's challenge script.** The federation's peg wallet owns
  it. With no flag, the plan pays the challenge address.
- **`--peg-key`, the explicit alternative:** the peg address becomes
  `tr(<key>, and_v(v:pk(<refund key>), older(<refundBlocks>)))`. The plan
  prints its checksummed descriptor, built with rust-miniscript. It counts
  as a peg-in only after the peg holders import the descriptor
  (`importdescriptors`, watch-only is enough). After that, the refund key can
  sweep a peg left unclaimed for `refundBlocks`. The first live peg-in paid
  such an address: `tr(<dreamlab signer>, …)` with Alice's refund key.

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

## Status — 0.2.0

The offline parts are tested without a network (`tests/offline.rs`):

- keys against NIP-19's published vectors;
- the live loop's two agents, from did:nostr key to the `drm1…` address the
  chain paid;
- a loop on a chain held in memory: a spend by npub, one back by did:nostr,
  a peg-out, each event verified as signed by the paying agent;
- a level-1 plan without a peg-wallet address is refused; with
  `--peg-key <signer>`, Alice's plan on `sidestr:dreamlab` gives the address
  the live peg-in paid on testnet4 (`tb1palk8…`), and its marker byte for
  byte;
- the plan's descriptor address matches an independent build with
  rust-bitcoin's `TaprootBuilder`;
- the binary's offline commands.

Secret-shaped text (an `nsec`, or 64 bare hex characters) is never accepted
as a destination or address, and is never echoed. NIP-19 strings are strict
Bech32. Both are pinned in `tests/audit_regressions_0_0_3.rs`, from the
pre-release verification pass. Relay publishing and the producer's HTTP
calls are `sidestr-round` and `sidestr-wallet`'s, tested there.
