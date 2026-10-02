# Fixtures

- `trial/`, `dreamlab/`, `fedtest/`: sealed chains and a level-2 federation
  (see the tests that load them).
- `keys-vectors.json`: `siding/test/keys-vectors.json` from sidestr/spec at
  `bd1d692d90348d16944f7b13cf043197274c436e` (unchanged through `e8deb63`),
  verbatim; `tests/keys.rs` reproduces every field.
- `bip/`: the official BIP 340, 341 and 86 vectors (see its README).
- `fidsigner/`: Fid's unified-sighash and signing known answers (see its
  README).
