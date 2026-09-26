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

## JSON-RPC for wallets

`rpc::EvmRpc` is siding's `lib/evmrpc.mjs`: the Ethereum JSON-RPC that
MetaMask, ethers and viem speak, over the rule's state. It is
transport-agnostic. The host implements `rpc::ChainView`: the height, block
hashes and header times, the mempool, and `carry`. `carry` wraps a raw
transaction's carrier record in a sidechain transaction paid from the
producer's coins, runs the mempool's EVM check, and submits it.

```rust,ignore
let rpc = EvmRpc::new(rules.evm.clone().unwrap(), doc.id.clone());
let answer = rpc.handle(&mut host, &request);            // a request or a batch, as JSON
let reply = rpc.handle_body(&mut host, body);             // a POST /evm body: status and text
```

`handle_body` gives exactly what `bin/siding.mjs` sends for `POST /evm`,
including the parse error (400) and the 1 MiB limit (413). Send it with
`application/json` and `rpc::CORS_HEADERS`. The crate pulls in no HTTP
server.

| methods | answer |
|---|---|
| `web3_clientVersion`, `net_version`, `eth_chainId`, `eth_syncing`, `eth_mining`, `eth_accounts`, `eth_blockNumber` | the chain |
| `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_feeHistory` | a flat 1 gwei base fee, no tips |
| `eth_getBalance`, `eth_getTransactionCount` (`pending` counts mempool carriers), `eth_getCode`, `eth_getStorageAt` | the applied state |
| `eth_call`, `eth_estimateGas` | a read-only run in the next block (height + 1, now); a failure is error 3 with its data |
| `eth_sendRawTransaction` | read, signature checked, carried |
| `eth_getTransactionReceipt`, `eth_getTransactionByHash`, `eth_getLogs` | receipts, transactions and logs of applied blocks |
| `eth_getBlockByNumber`, `eth_getBlockByHash`, `eth_getBlockTransactionCountByNumber` | the sidechain block as an Ethereum block |

The estimate is the reference's formula: 21,000, plus 32,000 for a
creation, plus the calldata (4 per zero byte, 16 per other), plus half as
much again as the execution used and 10,000 when it used any.

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
`tests/wallet_deposit.rs` holds `sidestr-wallet`'s deposit to this rule: its
marker (written through `sidestr-core`, so the wallet links no revm) is
`records::deposit_script`'s bytes, its reserve is `EvmConfig`'s, and a
deposit it builds is mined and credits the address. CI regenerates the
fixtures below against the pinned `evm.mjs` and fails on any drift.

`tests/oracle/rpc-oracle.mjs` runs siding's own `evmrpc.mjs` over its own
`evm.mjs`, both pinned by SHA-256, with a scripted host and a frozen clock.
It writes `tests/fixtures/rpc.json`, and `tests/rpc_oracle.rs` replays it:

- **6 blocks.** Each state root comes out the same.
- **223 requests.** They cover every method, batches, odd ids and
  malformed params. 215 answers match byte for byte, as `JSON.stringify`
  writes them. In the other 8, the error message is compared up to a fixed
  prefix, because what follows is ethereumjs's own text (why a raw
  transaction does not read, or why its VM refused a carrier).
- **10 `POST /evm` bodies**, matched in status and text.

Nothing is normalised for time, because the clock is frozen on both sides.
`tests/rpc.rs` is `siding/test/evmrpc-test.mjs` step by step through
`sidestr-core`.

To regenerate the fixtures:

```sh
FIXTURES=$PWD/tests/fixtures
mkdir -p $SCRATCH/lib/overlays && cp tests/oracle/{oracle.mjs,rpc-oracle.mjs,package.json,package-lock.json} $SCRATCH
cp $SIDESTR_SIDING/lib/overlays/evm.mjs $SCRATCH/evm.reference.mjs
cp $SIDESTR_SIDING/lib/evmrpc.mjs $SCRATCH/lib/ && cp $SIDESTR_SIDING/lib/overlays/evm.mjs $SCRATCH/lib/overlays/
(cd $SCRATCH && npm ci && node oracle.mjs $FIXTURES && node rpc-oracle.mjs $FIXTURES)
```

The RPC fixtures were written on Node 22. Error texts that come from
JavaScript itself, such as `BigInt` and property reads, are V8's.

## Where it departs

None of these departures changes which blocks are valid. The crate docs
give the detail.

- The EVM state moves when a block is applied, not when the rule passes.
- The state is kept for the tip only.
- A producer drops a failing transaction whole.
- A record over 65,535 bytes is not written.
- JSON-RPC read-only calls start afresh, as a transaction would. They
  start with the sender, target, precompiles and coinbase warm, and keep
  nothing from earlier calls. ethereumjs starts cold and carries warm
  slots over, so its estimate for a repeated call drifts.
- A fault in the reference is not reproduced (sidestr/spec#22). A
  read-only creation whose value exceeds the sender's balance, or a call
  reaching the KZG precompile, makes the reference answer with an error and
  its producer's next block commit a root it then refuses. Here every call
  runs on a copy, so nothing carries over.
- The reason text after `not a transaction: ` is this crate's own. The code
  (-32602 or -32000) is the reference's.
- Some limits are added. A call's negative value or gas is refused.
  `eth_feeHistory` answers at most 1,024 blocks. A raw transaction over
  65,535 bytes is refused. A batch is answered in order, not all at once.

## Licence

AGPL-3.0-only, as the reference.
