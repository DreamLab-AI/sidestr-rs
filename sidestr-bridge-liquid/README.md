# sidestr-bridge-liquid

> **Private USD unit of account of the owner's estate. No value, not
> redeemable, not offered to anyone. Not USD₮ or USDC and not issued, backed
> or endorsed by Tether or Circle. Not live: nothing is funded, and the
> reserve is funded only on the owner's explicit go.**

The Liquid reserve for the owner's private USD unit on a sidestr chain, on the
**light option** of ADR-2117's amendment of 2026-09-23. A sidestr `bridge`
rule will mint the unit only while *circulating + pending ≤ attested reserve*;
this crate is the reserve half of that check.

- **Reserve key.** A 24-word BIP-39 mnemonic in a file outside every
  repository, created mode 0400 with `O_EXCL` (never overwritten, a dangling
  symlink included), refused on load if group or others can read it, never
  printed or `Debug`-formatted.
- **Reserve wallet.** A watch-only wallet on Blockstream's Liquid Wallet Kit:
  single-sig `elwpkh` at `m/84'/1776'/0'`, blinded with the seed's SLIP-77
  key, on Liquid mainnet. It derives addresses, unblinds what it receives,
  and cannot spend.
- **Sync.** A full scan against Blockstream's public Esplora API
  (`https://blockstream.info/liquid/api`), optionally through a proxy:
  `--proxy socks5h://127.0.0.1:9050` for Tor. `socks5://` is refused because
  it resolves names outside the proxy, and a dead proxy fails the sync rather
  than bypassing it (tested).
- **Reserve asset.** Pinned as `RESERVE_ASSET_ID`, verified from two primary
  sources and one computation (below).
- **Attestation.** `attest(snapshot, asset, time)` is pure. It is this
  crate's Liquid reading of the reserve: the confirmed outputs of the reserve
  asset at or below the tip, keyed by outpoint (`txid:vout`), under the
  origin `liquid` / `RESERVE_ASSET_ID` / 8 decimals. The statement itself
  belongs to the origin-neutral `sidestr-reserve` crate: total, credits, tip
  height and hash, time and source in canonical sorted-key JSON, its SHA-256,
  and the `AttestationSigner` hook (BIP-340 Schnorr over the digest). A
  `bridge` rule checks the same statement whichever network holds the
  reserve, so a TRON or EVM adapter would be a sibling of this crate, not a
  change to it. No real key is wired: the binary never signs.

## The `usd-reserve` binary

```text
usd-reserve init        --key-file <path>              # new mnemonic, mode 0400; refuses an existing file
usd-reserve address     --key-file <path> [--index N]  # offline; default index 0
usd-reserve address     --key-file <path> --next       # sync, then the first unused address
usd-reserve descriptor  --key-file <path>              # CT descriptor (sensitive for privacy)
usd-reserve balance     --key-file <path>              # sync, tip, balance per asset
usd-reserve attest      --key-file <path>              # sync, unsigned attestation + sha256
usd-reserve check-asset                                # fetch the registry entry, verify the pin
# global: --esplora-url <url>  --proxy <socks5h://…|http://…>
```

Apart from `init`, which writes the key file, the binary only reads. It never
signs, spends or broadcasts.

The CT descriptor cannot spend. It does hold the blinding key, so anyone with
it sees every amount and asset the wallet receives. Treat it as sensitive for
privacy, not for spending.

## The reserve asset

`RESERVE_ASSET_ID = ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2`,
verified 2026-09-23:

1. Blockstream's asset registry,
   <https://assets.blockstream.info/ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2>,
   lists ticker `USDt`, name "Tether USD", precision 8 and issuer domain
   `tether.to`. The registry accepts an entity domain only with a proof
   served from that domain.
2. The issuer's page, <https://tether.to/en/supported-protocols>: "To
   integrate Tether's Liquid Asset on the Liquid blockchain use the USD₮
   asset: https://blockstream.info/liquid/asset/ce091c99…7bd2".
3. The id is recomputed from the registry's issuance prevout and contract
   hash (Elements issuance entropy, via LWK), so the contract's ticker, name
   and domain are committed to by the id itself. `verify_registry_entry` and
   `usd-reserve check-asset` repeat this. The test fixture is the registry
   entry as fetched.

The identifiers in the code are neutral (`RESERVE_ASSET_ID`, `reserve_asset`).
The issuer's name and ticker appear only as descriptive text and as the values
the registry check compares against (ADR-2117 decision 5).

## Trust basis: the light option

The wallet state comes from a public Esplora server, named in each
attestation's `source` field. The attester unblinds outputs with its own
blinding key, so each listed output's asset and amount are the attester's own
reading. The server is trusted for **completeness and freshness**. It cannot
invent an output that pays the reserve. It could, however, omit a spend, which
would make a spent reserve look unspent. It could also withhold a new output
or report a stale tip. The recorded tip hash lets any other view of Liquid
detect a stale or forked answer. The server also learns the reserve's
addresses and query times.

**Upgrade to an own node.** Syncing from an own `elementsd` (23.3.4 or later,
the release that fixed the 6 September 2026 range-proof caching bug) makes the
attester's own chain validation the basis, and removes the omission risk. The
amendment sets when: before releases are automated, before the reserve
exceeds pocket money, or before anyone outside the estate depends on the unit.
The node must not run beside the mainnet Lightning node.

## The Liquid peg-out suspension does not block this

After the 6 September 2026 exploit, Liquid's BTC peg-outs were suspended. This
design never pegs BTC into or out of Liquid. The reserve is an issued asset
that moves by ordinary Liquid transactions, and Liquid is producing blocks:
the live test synced to height 4,070,405 on 23 September 2026. The suspension
is still a watch item, because the exploit minted unbacked L-BTC: an
independent reserve-versus-supply check before any release remains in the
`bridge` rule's invariants (ADR-2117 decision 4).

## Tests

```text
cargo test -p sidestr-bridge-liquid                  # offline: 22 + the proxy test + doctests
SIDESTR_LIQUID_LIVE=1 cargo test -p sidestr-bridge-liquid --test live -- --ignored --nocapture
```

The offline tests cover these vectors:

- **Descriptor.** The descriptor from the BIP-39 test mnemonic equals LWK
  0.19's own mainnet vector.
- **Addresses.** Its first two addresses are regression values.
- **Attestation.** Golden canonical bytes for the Liquid reading, with a
  digest computed independently with `sha256sum`. The format's own vectors
  (BIP-340 test vectors 0 and 1, field checks) are `sidestr-reserve`'s.

The live test is read-only. It derives a fresh wallet in a temporary
directory, syncs it, expects an empty balance and a current tip, and fetches
and verifies the registry entry.

## Dependencies and licences

Blockstream's Liquid Wallet Kit: `lwk_wollet`, `lwk_signer` and `lwk_common`
0.19.0, each `MIT OR BSD-2-Clause` (from `cargo metadata`). The default
features are off; only `lwk_wollet`'s `esplora` and `registry` features are
on. `reqwest` 0.12 (`MIT OR Apache-2.0`) is named only to enable `socks` in
the copy LWK uses. Signatures come from libsecp256k1 through LWK's re-exported
`secp256k1`. Nothing cryptographic is implemented here.

This crate is `AGPL-3.0-only`, like its `sidestr-*` siblings, and
`publish = false`: it is a project-specific construction that stays private
to this repository.
