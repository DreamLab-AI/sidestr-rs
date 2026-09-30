# sidestr-hitch

Rust port of Melvin Carvalho's
[Hitch](https://github.com/bitcoin-blake/hitch), the Lightning-shaped payment
channels for Bitcoin Knots' BLAKE2b testnet4 (`txbt4`).

The crate builds the same Taproot constructions as Hitch:

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

The crate is a pure channel kernel. A service using it supplies the Nostr
relay transport, wallet funding, chain watches, atomic snapshot storage and
transaction broadcasting. Snapshots contain the channel key, revocation
secrets and payment preimages and must be protected as wallet key material.

It is testnet software and is not compatible with Lightning peers.

The implementation is AGPL-3.0-only because it is an attributed port of
Hitch's AGPL implementation.
