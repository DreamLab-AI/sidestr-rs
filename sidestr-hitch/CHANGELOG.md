# Changelog

## 0.1.0 - 2026-09-30

- Port Hitch's consensus-critical channel transaction layer at upstream
  commit `6752e24`: its NUMS key, 2-of-2 funding leaf, revocable delayed
  output, three-path HTLC output, asymmetric commitments, cooperative close,
  delayed sweep, penalty, HTLC claims and direct key-path spend.
- Preserve both Bitcoin BIP 341 and Bitcoin Knots unified sighash signing.
- Pin every script to Hitch's published golden vectors.
- Port the opening handshake, payment and HTLC updates, three-message
  revocation finality, simultaneous-update collision handling, cooperative
  and unilateral closes, bounded resynchronisation and buffered updates.
- Add versioned snapshots that recheck channel accounting, key relationships,
  payment preimages and every retained counterparty signature on restore.
- Port Hitch invoices and one-hop hub routing, including fee and timeout
  deltas, durable forwarding links and the protective-close threshold.
- Cross-check Rust transactions with Hitch and the schema interpreter, and
  pass every Rust wire message through Hitch's own validator in CI.
