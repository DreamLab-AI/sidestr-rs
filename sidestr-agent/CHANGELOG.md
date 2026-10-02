# Changelog

All notable changes to `sidestr-agent`. The crate follows semantic versioning.

## Unreleased

### Added: the Hitch host (stream S2, TODO N-10)

- `hitch` subcommands host `sidestr-hitch` 0.2 channels for an agent:
  `bind`, `open`, `invoice`, `pay`, `close`, `force-close`, `watch` and
  `status`, plus a hidden developer `cheat` (`SIDESTR_HITCH_DEVELOPER=1`).
  A command goes to the running `watch` daemon over `<state>/control.sock`.
  With no daemon running, it takes the state lock and runs the host itself
  until its outcome: open, payment final, close settled at `CLOSE_DEPTH`.
- ADR-2101 D3 (research stage): `hitch bind` mints the spend key `k_spend`
  from OS entropy, never from `k_id`, and has `k_id` sign the kind-38420
  binding that names it (`hitch::binding`). Every channel command checks
  its key against the binding and refuses the identity key ("k_id never
  spends") before it touches the network. A peer named by `did:nostr` is
  resolved through its binding. The known-answer test pins
  `tests/fixtures/hitch-binding-kat.json`, computed independently by
  siding's BIP-340 code.
- `hitch::envelope`: kind-23600 transport over the shared relay pool. A
  message is taken only when it is addressed here and tagged with this
  chain, its signature verifies, and its `ch` tag agrees with its content.
- `hitch::follow`: the chain watch over `blocks.json` and ranged
  `blocks.dat` from the producer, or the mirror when the producer is down.
  Each block's hash, link and solution are checked, for stock headers and
  for BLAKE2b v2 headers beside `txbt4` (`sidestr:dreamlab-txbt4`, its
  live genesis pinned as a fixture). Reorganisations are
  found and measured, and the transactions they undid are listed.
- `hitch::store`: `0600` files written atomically (exclusive temporary
  file, `fsync`, rename, directory `fsync`) in a `0700` directory. A
  secret file readable by others is refused.
- `hitch::host` (feature `cli`, Unix): saves the snapshot before anything is
  sent, and restores it if the save fails. Funding comes from the spend
  key's plain coins. Broadcasts go to `POST /tx`, with a kind-23500
  fallback when the producer cannot be reached. The watch loop confirms
  funding at `MIN_CONF` and publishes the penalty against a revoked
  commitment at once. It sweeps after the CSV delay and refunds HTLCs after
  expiry. Reorganisations are handled: a spend they undo is taken back, and
  this host's undone transactions are published again once their locks
  allow. Everything is journalled in `journal.jsonl` with event ids, txids
  and heights.
- Integration tests on a loopback siding at 2-second blocks, with two
  processes and two key pairs: cooperative close, force-close by either
  side, the penalty, a reorganisation during a close, and an HTLC refunded
  after its expiry. The cooperative close runs on both header families,
  stock and BLAKE2b v2 beside `txbt4`. Every run ends with `sidestr-core`
  replaying the producer's block file to the producer's tip hash (stream
  S1's leaves), so a Rust validator agrees about every channel spend.
- Never early, never the same bytes twice (S1's findings on siding
  `fa86dac` and `c3b9e7a`). Before every `POST /tx`, the host checks each
  input's BIP 68 lock and the `nLockTime` with `sidestr-core`'s
  `earliest_height` against the next block (`hitch::host::premature`). A
  transaction that may not yet be mined is held back and sent when it may,
  so the reference never admits a transaction it then cannot mine. Every
  send is signed afresh: a channel's transactions through
  `ChannelMachine::resign`, a funding of the spend key's own coins on the
  key path. A refused or evicted transaction is therefore resent with the
  same txid and a different witness. An unconfirmed funding is resent
  every 3 blocks. The loopback test
  `a_refused_broadcast_is_resent_with_a_fresh_witness_and_never_early` runs
  behind a proxy that refuses each transaction's first post. The funding,
  the commitment and the sweep are each resent with a new witness, and
  every post is checked against its locks.
- `hitch bind --import <binding.json> --key-file <spend key>` adopts a
  binding agentbox minted (`<spend key>.binding.json`), verified against
  the chain and the spend key, without reading k_id. `--chain-hash` binds
  on a chain sealed at SPEC 0.0.5 or later. Bindings follow the amended
  38420 shape. A binding agentbox minted for `demo-a` on
  `sidestr:dreamlab-txbt4` is a test fixture and verifies.
- New dependencies: `sidestr-hitch` 0.2; `sidestr-header` 0.3.1 (the
  BLAKE2b family); `rustix` (the state lock, under
  `cli`); tokio's `net`, `signal` and `io-util` features under `cli`.

## 0.5.0 (2026-10-02)

### Added

- `pegin-plan --tweak --chain-hash <64 hex>`: an opt-in plan in the peg-in
  tweak form (sidestr/spec issue #23): `pegAddress`, the descriptor with
  checksum (checked with miniscript to derive that address), `reveal`,
  `commitKey`, `outputKey`, the refund leaf and its control block, and
  `coreSend` with one output and no data item. The internal key is
  `--peg-key`, else the level-1 signer's; a level-2 document needs
  `--peg-key`. `--chain-hash` is the chain event's id, not its alias, and
  is given explicitly. Library: `pegin_tweak_plan`, `PeginTweakPlan`.
- `parent_refusal_hint`, and `publish-parent` reads an explorer's refusal:
  a `bad-txns-premature-spend-of-coinbase` refusal now says the parent's
  coinbase maturity (6,705 confirmations on txbt4 since Knots 29.4.2, Reef
  `2bd3cb8`) after the unchanged "the parent explorer refused it (HTTP …)".

### Unchanged

- `pegin-plan` without `--tweak` is byte for byte what it was (pinned in
  `tests/fixtures/pegin-plan-dreamlab-peg-key.json`) and carries no reveal;
  `PegTarget`, `PeginPlan` and the level-1 refusal are untouched.
SPEC 0.0.5 (sidestr/spec `e8deb63`). Additive; follows `sidestr-nostr`'s
unreleased chain module.

### Added

- `chain-event` (as `siding chain-event`): the document at `--chain` as a
  kind-3500 event signed by `--key-file`, which must be the chain's signer
  (level 1: the challenge is `5120‖key`; level 2: one of `signers`), else
  "the key at <path> is not the chain's signer". Written as
  `chain-event.json` beside the document (or `--out`) as siding writes it,
  published only to the relays `--relay` names; prints `hash`, `alias`,
  `signer`, `written`, `published`, `note`.
- `resolve --alias sidestr:<name>` / `resolve --chain-hash <hex>`: the chain
  found as `resolveChain` finds it, over `--relays` and the mirrors' JSON; a
  chain made before 0.0.5, such as `sidestr:dreamlab`, resolves by its
  mirror's `chain.json` with `hash: null` and `legacy: true`.
- `chain` module: `sign_chain_document`, `check_signer`, `event_file_json`,
  `resolved_json`, `KNOWN_RULES`, and `resolve_chain_on` (feature `cli`).

## 0.4.0 (2026-10-01)

EVM deposits (the `evm` rule, proposals/evm.md). Depends on
`sidestr-wallet` 0.5, `sidestr-core` and `sidestr-nostr` 0.4, and
`sidestr-round` 0.3.

### Added

- `send --evm <0x address> <sats>`, as `siding send --evm --to 0x… --amount
  N`: the sats pay the chain's reserve and credit the address in its EVM
  at 1 sat = 1 gwei; a kind-23500 event signed by the agent's key carries
  it, with `--post`, `--dry-run` and `--fee` as for `send`. The chain
  document may name the `assets` and `evm` rules. Coins and tip come from
  the producer's `/coins` and `/tip`, as siding takes them, since this
  crate cannot replay a chain naming `evm`; the block file is still read,
  unvalidated, and no coin carrying an asset is spent.
- Library: `prepare_evm_deposit` (the deposit and its event), and
  `read_assets` (what a block file's outputs carry, read without
  validating the blocks, for a chain `ChainView::replay` cannot replay;
  either header family). Both pure, so the wasm32 build has them.

## 0.3.1 (2026-09-25)

SPEC 0.0.4 (`@sidestr/spec` 0.0.6). Additive.

### Added

- `pegin-plan` at level 1 with no `--peg-address` or `--peg-key` pays the
  peg script the chain's signer announces with its newest tip (the `peg`
  tag; only the chain document's signer counts), as the JS wallet's
  `pegInScript` does; a chain that announces none is refused with the
  reason. Library: `announced_peg_address`, and `fetch_announced_peg_script`
  (feature `cli`).
- `publish-parent <hex>`: a signed parent transaction (a peg-in) with no node
  of your own goes to the parent's public explorer, and if that refuses or
  does not answer, as a kind-23503 event from a throwaway key for a
  producer with a node to broadcast if its policy accepts it (the JS
  wallet's `publishParent`). `--no-explorer`, `--explorer`, `--dry-run`.
  Library: `parent_explorer_api`.

## 0.3.0 (2026-09-24)

### Changed

- The binary's dependencies (clap, tokio, ureq, `sidestr-round`, the
  wallet's HTTP client) are behind the default feature `cli`. With
  `default-features = false` the library is pure and builds for
  `wasm32-unknown-unknown`, so a browser wallet signs with the same code an
  agent does.
- `send` and `burn` spend only coins that carry no asset, read from the
  block file (`--blocks`, a path or URL; `<url>/blocks.dat` by default).
  Before, a plain payment could spend a coin carrying an issued asset and
  destroy it.
- Depends on `sidestr-wallet` 0.4 and `sidestr-core` 0.3.1.

### Added

- `AgentKey::from_secret_bytes`.
- `ChainView`: a block file replayed with the assets view (`coins`,
  `plain_coins`, `asset_balance`, `find_asset`).
- `prepare_transfer` and `prepare_issue`: an asset move or issue and its
  kind-23500 event, both signed by the agent's key.
- Commands `assets`, `issue`, `send-asset` (with `--memo`) and `faucet`,
  which answers kind-23501 requests with plain sats and, optionally, units
  of an asset, one grant per script per window.

## 0.2.0 (2026-09-23)

### Changed

- **Level 1 pegs to the producer's parent wallet.** `pegin_plan` with no
  target now refuses a level-1 chain and asks for `--peg-address`: an address
  the producer's parent wallet gave, which it owns (SPEC 6). 0.1.0 built
  `tr(<signer>, and_v(v:pk(<refund>), older(n)))` by default. That output
  counts as a peg-in only once the peg holders import its descriptor, so it
  is now opt-in through `--peg-key` / `PegTarget::Key`. Level 2 still
  defaults to the challenge address.
- **A secret-shaped destination is refused before anything else.** The
  binary scans its raw arguments for `--to` and `--peg-address` values
  (either form) and the send/burn destination before clap reads them.
  `pegin_plan` checks `side` and an address target before any other work.
  The 0.2.0 verification pass (GPT-6 Astra) found 44 of 50 cases where an
  unrelated error came first. None echoed the secret. The pass's probes are
  kept in `tests/audit_regressions_0_2_0.rs`.

## 0.1.0 (2026-09-23)

First release, generalised from the tool that ran the first live loop on
`sidestr:dreamlab`: a peg-in, three trades between two agents as kind-23500
events each signed with its agent's own Nostr key, and a peg-out.

- `AgentKey`: a key file as 64 hex characters or a NIP-19 `nsec`.
  `parse_pubkey`, `npub`, `identity`: npub, did:nostr, script and chain
  address of one x-only key.
- `destination`: pay an `npub` or a `did:nostr:` as its key's `5120` script.
- `prepare`: a spend or peg-out burn signed by the agent's key, and its
  kind-23500 event signed by the same key.
- `pegin_plan`: the peg address as `tr(<peg key>, and_v(v:pk(<refund>),
  older(<refundBlocks>)))` with its checksummed descriptor (through
  rust-miniscript), or an address the peg wallet gave, or a level-2 chain's
  challenge. Also the `pegin:` marker and Bitcoin Core's `send` outputs.
- `refuse_secret`: secret-shaped text (an `nsec`, or 64 bare hex
  characters) is refused as a destination, a burn target or a peg address,
  with an error that never repeats it. A bare 64-hex destination could
  otherwise be read as a 32-byte script and published on the chain. NIP-19
  strings are decoded as Bech32 only; Bech32m is refused. Both came from the
  pre-release verification pass (`tests/audit_regressions_0_0_3.rs`).
- The `sidestr-agent` binary: `balance`, `address`, `send`, `burn`,
  `pegin-plan`; `--url`, `--relays`, `--key-file`, `--chain`; `--dry-run` and
  `--post` for payments.
