# Changelog

All notable changes to `sidestr-agent`. The crate follows semantic versioning.

## Unreleased — 0.3.2

EVM deposits (the `evm` rule, proposals/evm.md). Additive: a patch release.
Depends on `sidestr-wallet` 0.4.3 and `sidestr-core` 0.3.4.

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

## 0.3.1 — 2026-09-25

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

## 0.3.0 — 2026-09-24

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

## 0.2.0 — 2026-09-23

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

## 0.1.0 — 2026-09-23

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
