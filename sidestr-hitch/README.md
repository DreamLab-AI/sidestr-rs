# sidestr-hitch

Rust port of Melvin Carvalho's
[Hitch](https://github.com/bitcoin-blake/hitch), the Lightning-shaped payment
channels for sidestr and Bitcoin-family testnets. It supports ordinary BIP
341 signatures and Bitcoin Knots' unified signatures used by BLAKE2b
testnet4 (`txbt4`).

```toml
[dependencies]
sidestr-hitch = "0.1.1"
```

This crate builds the same Taproot constructions as Hitch:

- a 2-of-2 `multi_a` funding output under an unspendable internal key;
- asymmetric commitment transactions with delayed, revocable `to_local`;
- direct `to_remote` outputs;
- HTLC outputs with success, timeout and revocation paths;
- cooperative closes, delayed sweeps, penalties and HTLC claims;
- the `open`/`accept`/`commit`/`ready` handshake;
- the three-message `update`/`ack`/`revoke` finality boundary, including
  collision handling and buffered updates;
- recovery messages and a versioned, cryptographically checked channel
  snapshot;
- invoices and one-hub forwarding decisions with fee and timeout deltas;
- BIP 341 signatures on stock Bitcoin-family chains and Knots' unified
  `0x21` signatures on BLAKE2b chains.

It is a pure channel kernel. A service using it supplies the Nostr
relay transport, wallet funding, chain watches, atomic snapshot storage and
transaction broadcasting. Snapshots contain the channel key, revocation
secrets and payment preimages and must be protected as wallet key material.

It is testnet software and is not compatible with Lightning peers.

Transaction and wire-oracle suites compare the Rust scripts,
transactions and messages with Hitch at commit `6752e24`. The peer machine
covers open, update, acknowledgement, revocation, collision recovery, close
and restart from a checked snapshot; routing is deliberately one hop.

Its licence is AGPL-3.0-only because it is an attributed port of
Hitch's AGPL implementation.
