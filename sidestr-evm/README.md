# sidestr-evm

Rust port of Melvin Carvalho's sidestr sidechains, AGPL-3.0-only: the `evm`
rule.

A sidestr chain that names the `evm` rule runs Ethereum contracts. Nothing
changes about how its blocks are made or signed. Ethereum transactions ride
inside ordinary sidechain transactions. Every validator runs them in block
order through an EVM and keeps the account state beside the UTXO set. The
coinbase commits the state root, so validators agree. **1 sat = 1 gwei**,
and sats cross only by deposit and withdrawal.

The rule and its design are Melvin Carvalho's: `siding/lib/overlays/evm.mjs`
and `proposals/evm.md` in [sidestr/spec](https://github.com/sidestr/spec),
ported from commit `fa86dac` (`@sidestr/spec` 0.0.6). The reference runs on
ethereumjs 10.1.3. This crate runs on [revm](https://github.com/bluealloy/revm)
at the same Cancun rules, with alloy's transaction envelope and signer
recovery and alloy-trie's state root. Nothing cryptographic is written here.

> **Testnet only, and not published.** The rule is new upstream (its first
> milestone), and no chain runs it yet.

## Records

| record | meaning |
|---|---|
| a payment to the reserve, then `OP_RETURN evmin:` + 20 bytes | a deposit: the payment's sats credit the address × 10⁹ wei |
| `OP_RETURN evm:` + a signed Ethereum transaction | run in output order; a revert is applied, a transaction that cannot be (signature, chain id, nonce, funds) invalidates the block |
| an Ethereum transaction to `0x…0501de` with value and 34 bytes of data | a withdrawal: the coinbase pays `floor(value / 10⁹)` sats to that script |
| `OP_RETURN evmroot:` + 32 bytes, in the coinbase | the state root after the block |

The reserve is the chain's challenge unless the document's `evm.reserve`
says otherwise. The chain id defaults to 21474 and the gas limit to
30,000,000: `{"rules": ["evm"], "evm": {"chainId": 21474}}`.

## Following a chain

```rust,ignore
let rules = sidestr_evm::rules_for(&doc)?;             // the EVM rule, and the assets rule beside it
let mut state = State::from_genesis_with_rules(doc, &genesis, None, rules.boxed())?;
state.add_block(&block, None, None)?;                 // runs the block's carriers; refuses it by rule name
let evm = rules.evm.as_ref().unwrap().state();        // balances, code, storage, receipts, the root
```

A producer uses `Rules::produce`. It sequences the mempool through the EVM,
pays the withdrawals, and writes the `evmroot:` record.

## Against the reference

`tests/oracle/oracle.mjs` drives ethereumjs exactly as `evm.mjs` does. With a
copy of the pinned `evm.mjs` beside it, it also runs the reference module
itself and stops on any difference. It writes `tests/fixtures/`, and
`tests/oracle.rs` replays those fixtures:

- **35 blocks.** 20 are accepted, and each one's state root, withdrawals, hashes and
  receipts come out byte for byte. The accepted blocks cover deposits,
  legacy, EIP-2930 and EIP-1559 transfers, a tip to the zero-address
  coinbase, three deployments, storage writes and a deletion, a revert, a
  contract recording the block environment at two heights, withdrawals of
  one sat and under a gwei, and the emptied WITHDRAW account touched again.
  The other 15 are refused, as the reference refuses them.
- **25 carrier decodings** at the edges.
- **16 record scripts.**
- **The final accounts**, field for field.

`tests/chain.rs` is `siding/test/evm-test.mjs` step by step through
`sidestr-core`, with a producer and an independent validator.

To regenerate the fixtures:

```sh
FIXTURES=$PWD/tests/fixtures
mkdir -p $SCRATCH && cp tests/oracle/{oracle.mjs,package.json,package-lock.json} $SCRATCH
cp $SIDESTR_SIDING/lib/overlays/evm.mjs $SCRATCH/evm.reference.mjs
(cd $SCRATCH && npm ci && node oracle.mjs $FIXTURES)
```

## Where it departs

None of these departures changes which blocks are valid. The crate docs
give the detail.

- The EVM state moves when a block is applied, not when the rule passes.
- The state is kept for the tip only.
- A producer drops a failing transaction whole.
- A record over 65,535 bytes is not written.
- The JSON-RPC endpoint (`evmrpc.mjs`) is not ported.

## Licence

AGPL-3.0-only, as the reference.
