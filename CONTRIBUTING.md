# Contributing

Thank you for helping. A few rules keep this port faithful:

- **The reference decides.** sidestr is Melvin Carvalho's protocol
  ([sidestr/spec](https://github.com/sidestr/spec)). A change to consensus,
  records or wire formats follows the spec or the reference implementation,
  and names the upstream commit it follows. Take disagreements with the
  protocol upstream as issues, not local forks.
- **Prove it against the oracle.** A change that touches what the reference
  also computes should be tested both ways: run the suites with
  `SIDESTR_SIDING`, `SCHEMA` and `BLAKETESTNODE` set (see the README).
  Include a test that fails without the change.
- **Never hand-roll cryptography.** Hashes, signatures, sighashes and
  descriptors come from rust-bitcoin, secp256k1, rust-miniscript and
  RustCrypto.
- **Gate before you push:** `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
  `cargo test --workspace --all-features`, and
  `RUSTDOCFLAGS=-D\ warnings cargo doc --workspace --no-deps`, with default,
  all and no default features. Every public item is documented.
- **Testnet only.** Tests and examples use testnet4, throwaway chains and
  disposable keys. Never commit a key that has held anything.

By contributing you agree that your contribution is licensed AGPL-3.0-only,
the licence of this repository.
