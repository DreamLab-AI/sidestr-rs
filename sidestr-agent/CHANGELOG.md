# Changelog

All notable changes to `sidestr-agent`. The crate follows semantic versioning.

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
- The `sidestr-agent` binary: `balance`, `address`, `send`, `burn`,
  `pegin-plan`; `--url`, `--relays`, `--key-file`, `--chain`; `--dry-run` and
  `--post` for payments.
