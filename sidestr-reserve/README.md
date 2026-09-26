# sidestr-reserve

> **Private USD unit of account of the owner's estate. No value, not
> redeemable, not offered to anyone. Not USD₮ or USDC and not issued, backed
> or endorsed by Tether or Circle. Not live.**

The reserve attestation a sidestr `bridge` rule checks, independent of the
network the reserve sits on (ADR-2117). The rule mints a wrapped unit only
while *circulating + pending ≤ attested reserve*. What it reads is a signed
statement of what a reserve held; this crate is that statement.

An **origin adapter** reads its own network and hands this crate the numbers.
`sidestr-bridge-liquid` is the Liquid adapter. A TRON or EVM adapter would be
another crate producing the same statement, and the rule would not change.

## The statement

| field | meaning |
|---|---|
| `network`, `asset`, `decimals` | the origin: which network, which asset on it, how many base units make one unit. A chain document pins the pair; the rule refuses any other. |
| `amount` | the total of the credits, in base units, as a decimal string (`u128`) |
| `credits` | the ids the rule keys replays by, sorted: `txid:vout` on a UTXO network, `txid:log_index` on an account network |
| `tip_height`, `tip_hash` | the origin block the reading is final at; hash as 64 lower-case hex, no `0x` |
| `time` | Unix seconds, as a decimal string |
| `source` | whose view of the origin the reading came from: a public server or an own node |
| `type` | `sidestr-reserve/attestation/v1` |

The canonical form is compact JSON with keys in byte order. Every string is
restricted to printable ASCII that needs no escaping, and every number stays
below 2⁵³, so any JSON implementation reproduces the bytes. The digest is the
SHA-256 of those bytes, and the signature is BIP-340 Schnorr over the digest
(libsecp256k1 through `secp256k1` 0.29; nothing cryptographic is implemented
here).

## What an adapter owes

1. **Holdings at a final tip.** Only credits of the reserve asset that are
   final at `tip`: confirmed to the chain document's `bridgeConfirmations`,
   or solidified.
2. **Replay-stable credit ids.** Unique within the statement, and the same
   across readings and reorgs.
3. **A named source**, so the trust basis travels with the statement.
4. **The release path.** How funds leave the reserve, behind the ADR-2100
   authority gate. This crate only states holdings.

## Tests

```text
cargo test -p sidestr-reserve
```

Golden canonical bytes, with a digest computed independently with
`sha256sum`, for an account-origin example. Every field changes the digest,
and the same holdings under two origins give two digests. Malformed
identifiers, tips, sources and times are refused, as are duplicated credits
and an overflowing total. BIP-340 test vectors 0 (signing) and 1
(verification), tamper checks, and a faulty-signer check.

## Licence

`AGPL-3.0-only`, like its `sidestr-*` siblings, and `publish = false`. This is
a project-specific signed format, and the estate does not publish bespoke
signed formats as reusable crates.
