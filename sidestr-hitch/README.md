# sidestr-hitch

Rust port of Melvin Carvalho's
[Hitch](https://github.com/bitcoin-blake/hitch), the Lightning-shaped payment
channels for sidestr and Bitcoin-family testnets. It supports ordinary BIP
341 signatures and Bitcoin Knots' unified signatures used by BLAKE2b
testnet4 (`txbt4`).

```toml
[dependencies]
sidestr-hitch = "0.2.0"
```

This crate builds the same Taproot constructions as Hitch:

- a 2-of-2 `multi_a` funding output under an unspendable internal key;
- asymmetric commitment transactions with delayed, revocable `to_local`,
  whose revocation key needs both peers (the owner can never use it);
- direct `to_remote` outputs;
- HTLC outputs with success, timeout and revocation paths;
- cooperative closes, delayed sweeps, penalties and HTLC claims;
- the `open`/`accept`/`commit`/`ready` handshake, with a proof of
  possession for every revocation point;
- the three-message `update`/`ack`/`revoke` finality boundary, rejects,
  set-aside states that stay binding, collision handling and buffered
  updates;
- recovery messages, the periodic tick, forced and cooperative closes,
  penalties, sweeps and HTLC claims, and a versioned, cryptographically
  checked channel snapshot;
- invoices and one-hub forwarding with fee and timeout deltas, lost and
  set-aside forwards, and protective closes;
- BIP 341 signatures on stock Bitcoin-family chains and Knots' unified
  `0x21` signatures on BLAKE2b chains.

It is a pure channel kernel. A service using it supplies the Nostr
relay transport, wallet funding, chain watches, atomic snapshot storage and
transaction broadcasting. Snapshots contain the channel key, revocation
secrets and payment preimages and must be protected as wallet key material.

It is testnet software and is not compatible with Lightning peers.

Transaction and wire-oracle suites compare the Rust scripts,
transactions and messages with Hitch at commit `62f8e39`, and Hitch's peer
and adversarial suites run as Rust tests. The machine is sans-IO: each call
returns the messages and transactions to send, and queues events where
Hitch calls `io.onDropped`, `io.onPreimage` and `io.onPayment`. Routing is
deliberately one hop.

Its licence is AGPL-3.0-only because it is an attributed port of
Hitch's AGPL implementation.
