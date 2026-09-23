# Changelog

All notable changes to `sidestr-agent`. The crate follows semantic versioning.

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
