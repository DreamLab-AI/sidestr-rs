//! The EVM beside the UTXO set (`evm.mjs evmOverlay`): the world as the
//! applied blocks leave it, a block's verdict worked out on a copy
//! ([`EvmState::prepare`], the reference's `prepare`), kept until the block
//! is applied ([`EvmState::commit`]), and the receipts of what ran.
//!
//! A block is run from the state after the previous one: transactions from
//! index 1 (the coinbase is skipped), each one's outputs in order — a
//! deposit credits, a carrier runs. Then the coinbase must commit the root
//! the block leaves and pay every withdrawal the block made. Any failure is
//! the block's, and leaves the state as it was.

use std::collections::{BTreeMap, HashMap};

use alloy_consensus::TxEnvelope;
use alloy_primitives::{logs_bloom, Address, Bloom, Bytes, Log, B256, U256};
use bitcoin::{BlockHash, ScriptBuf, Transaction, Txid};
use sidestr_core::block::{HeaderFamily, SidestrBlock};

use crate::config::EvmConfig;
use crate::exec::{call, created_address, run, simulate, BlockEnvironment, Simulation};
use crate::records::{parse_carrier, parse_deposit, parse_root, GWEI, WITHDRAW};
use crate::tx::decode_carrier;
use crate::world::World;
use alloy_consensus::Transaction as _;

/// A withdrawal a block made: the coinbase must pay `sats` to `script`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdrawal {
    /// The sidechain output script: the transaction's 34 bytes of data.
    pub script: ScriptBuf,
    /// `floor(value / 10⁹)`, at least 1 (a smaller withdrawal is burned
    /// with nothing to pay). A value whose sats exceed `u64` saturates, and
    /// no output can pay it.
    pub sats: u64,
    /// The Ethereum transaction that withdrew.
    pub hash: B256,
}

/// The rule's verdict on a block (`evm.mjs prepare`'s result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// Whether the block keeps the rule.
    pub ok: bool,
    /// Why not, in this crate's words.
    pub error: Option<String>,
    /// The state root the block's execution gives, as far as it got; `None`
    /// when there was no state to run it on. For a refused block it is
    /// information, not consensus, and it matches the reference's except
    /// where ethereumjs threw from inside execution (the KZG precompile):
    /// its journal then keeps part of the throwing transaction, and this
    /// crate's does not.
    pub root: Option<B256>,
    /// The withdrawals it made, in order.
    pub withdrawals: Vec<Withdrawal>,
    /// Its Ethereum transactions' hashes, in order; none when it is refused.
    pub hashes: Vec<B256>,
}

impl Verdict {
    fn refused(error: String) -> Self {
        Self {
            ok: false,
            error: Some(error),
            root: None,
            withdrawals: Vec::new(),
            hashes: Vec::new(),
        }
    }

    /// The withdrawals' total, what the coinbase may pay beyond fees and
    /// claims; `None` on overflow.
    pub fn withdrawn(&self) -> Option<u64> {
        self.withdrawals
            .iter()
            .try_fold(0u64, |s, w| s.checked_add(w.sats))
    }
}

/// What a carried transaction left, kept for as long as the state is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// Its hash.
    pub transaction_hash: B256,
    /// Whether it succeeded; a reverted transaction is applied too.
    pub status: bool,
    /// Gas it used, after the refund.
    pub gas_used: u64,
    /// The contract a creation deploys to, whether or not it succeeded.
    pub contract_address: Option<Address>,
    /// Its logs; none when it did not succeed.
    pub logs: Vec<Log>,
    /// The sidechain height of its block.
    pub height: u32,
    /// The sidechain transaction that carried it.
    pub sidechain_txid: Txid,
    /// The sender.
    pub from: Address,
    /// The recipient; `None` for a creation.
    pub to: Option<Address>,
    /// Its place among the block's Ethereum transactions, from 0.
    pub index: u32,
    /// The signed transaction itself (`evm.mjs` keeps it beside the receipt
    /// in `txs`, for `eth_getTransactionByHash`).
    pub envelope: TxEnvelope,
}

impl Receipt {
    /// The price per gas it paid (ethereumjs's `amountSpent / totalGasSpent`):
    /// a legacy or EIP-2930 transaction's gas price; an EIP-1559 one's tip,
    /// capped by its fee cap, over the 1 gwei base fee.
    pub fn effective_gas_price(&self) -> u128 {
        self.envelope.effective_gas_price(Some(GWEI))
    }

    /// The bloom filter of its logs (all zero for none).
    pub fn logs_bloom(&self) -> Bloom {
        logs_bloom(self.logs.iter())
    }
}

/// What one sidechain transaction did (`evm.mjs applyTx`'s result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutcome {
    /// Whether every record in it applied.
    pub ok: bool,
    /// The first that did not.
    pub error: Option<String>,
    /// The Ethereum transactions it ran.
    pub hashes: Vec<B256>,
    /// The withdrawals it made.
    pub withdrawals: Vec<Withdrawal>,
    /// Gas its carriers used.
    pub gas_used: u64,
}

/// A block's worth of mempool, run in order for a producer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sequenced {
    /// Indices of the transactions that apply, in order.
    pub kept: Vec<usize>,
    /// Indices of those that do not, and why.
    pub dropped: Vec<(usize, String)>,
    /// The root the kept ones leave: the coinbase's `evmroot:`.
    pub root: B256,
    /// The withdrawals the coinbase must pay.
    pub withdrawals: Vec<Withdrawal>,
    /// The Ethereum transactions the kept ones run.
    pub hashes: Vec<B256>,
}

/// An applied block's Ethereum transactions and the root it left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRecord {
    /// Its Ethereum transactions' hashes, in order.
    pub hashes: Vec<B256>,
    /// The state root after it.
    pub root: B256,
}

#[derive(Debug, Clone)]
struct Pending {
    hash: BlockHash,
    height: u32,
    time: u32,
    world: World,
    receipts: Vec<Receipt>,
    verdict: Verdict,
}

/// The rule's state for one chain.
///
/// ```
/// use sidestr_evm::{EvmConfig, EvmState};
///
/// let state = EvmState::new(EvmConfig { chain_id: 21474, gas_limit: 30_000_000, reserve: Default::default() });
/// assert_eq!((state.height(), state.root().to_string().as_str()),
///            (0, "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"));
/// ```
#[derive(Debug, Clone)]
pub struct EvmState {
    config: EvmConfig,
    world: World,
    height: u32,
    time: u32,
    pending: Vec<Pending>,
    verdicts: HashMap<BlockHash, Verdict>,
    receipts: HashMap<B256, Receipt>,
    blocks: BTreeMap<u32, BlockRecord>,
}

impl EvmState {
    /// The state at the genesis: no accounts. Block 0 runs nothing
    /// (`chain.mjs`: the genesis's root is the empty state's).
    pub fn new(config: EvmConfig) -> Self {
        let world = World::new();
        let blocks = BTreeMap::from([(
            0,
            BlockRecord {
                hashes: Vec::new(),
                root: world.root(),
            },
        )]);
        Self {
            config,
            world,
            height: 0,
            time: 0,
            pending: Vec::new(),
            verdicts: HashMap::new(),
            receipts: HashMap::new(),
            blocks,
        }
    }

    /// The parameters.
    pub fn config(&self) -> &EvmConfig {
        &self.config
    }
    /// The height of the last applied block.
    pub fn height(&self) -> u32 {
        self.height
    }
    /// The state root after it.
    pub fn root(&self) -> B256 {
        self.blocks[&self.height].root
    }
    /// The accounts after it.
    pub fn world(&self) -> &World {
        &self.world
    }
    /// An account's balance in wei; zero for none.
    pub fn balance(&self, address: &Address) -> U256 {
        self.world
            .account(address)
            .map(|a| a.balance)
            .unwrap_or_default()
    }
    /// An account's nonce; zero for none.
    pub fn nonce(&self, address: &Address) -> u64 {
        self.world.account(address).map(|a| a.nonce).unwrap_or(0)
    }
    /// A carried transaction's receipt, once its block is applied.
    pub fn receipt(&self, hash: &B256) -> Option<&Receipt> {
        self.receipts.get(hash)
    }
    /// An applied block's record.
    pub fn block(&self, height: u32) -> Option<&BlockRecord> {
        self.blocks.get(&height)
    }
    /// Every receipt kept, in chain order: by height, then by place in the
    /// block (the order `evm.mjs`'s `receipts` map was filled in).
    pub fn receipts(&self) -> impl Iterator<Item = &Receipt> {
        self.blocks
            .values()
            .flat_map(|b| b.hashes.iter().filter_map(|h| self.receipts.get(h)))
    }
    /// The verdict [`EvmState::prepare`] gave a block, by its hash.
    pub fn verdict(&self, hash: &BlockHash) -> Option<&Verdict> {
        self.verdicts.get(hash)
    }

    /// Apply one sidechain transaction's deposits and carriers to `world`
    /// (`evm.mjs applyTx`). On failure `world` holds what the records before
    /// the failing one did; the caller discards it.
    fn apply_tx(
        &self,
        world: &mut World,
        tx: &Transaction,
        env: &BlockEnvironment,
        receipts: &mut Vec<Receipt>,
    ) -> TxOutcome {
        let mut out = TxOutcome {
            ok: true,
            error: None,
            hashes: Vec::new(),
            withdrawals: Vec::new(),
            gas_used: 0,
        };
        let fail = |mut out: TxOutcome, e: String| {
            out.ok = false;
            out.error = Some(e);
            out
        };
        let txid = tx.compute_txid();
        for (i, o) in tx.output.iter().enumerate() {
            if let Some(to) = parse_deposit(&o.script_pubkey) {
                let paid = i
                    .checked_sub(1)
                    .map(|p| &tx.output[p])
                    .filter(|p| p.script_pubkey == self.config.reserve && p.value.to_sat() >= 1);
                let Some(paid) = paid else {
                    return fail(
                        out,
                        format!("evmin at output {i} has no reserve payment before it"),
                    );
                };
                world.credit(to, U256::from(paid.value.to_sat()) * U256::from(GWEI));
                continue;
            }
            let Some(rlp) = parse_carrier(&o.script_pubkey) else {
                continue;
            };
            let carried = match decode_carrier(rlp, self.config.chain_id) {
                Ok(c) => c,
                Err(e) => return fail(out, format!("carrier at output {i}: {e}")),
            };
            let ran = match run(world, env, &carried) {
                Ok(r) => r,
                Err(e) => return fail(out, format!("carrier at output {i}: {e}")),
            };
            world.commit(ran.changes);
            out.gas_used = out.gas_used.saturating_add(ran.gas_used);
            out.hashes.push(carried.hash);
            let e = &carried.envelope;
            let index = u32::try_from(receipts.len()).unwrap_or(u32::MAX);
            receipts.push(Receipt {
                transaction_hash: carried.hash,
                status: ran.success,
                gas_used: ran.gas_used,
                contract_address: created_address(&carried),
                logs: ran.logs,
                height: env.height,
                sidechain_txid: txid,
                from: carried.sender,
                to: e.to(),
                index,
                envelope: e.clone(),
            });
            // a withdrawal: value sent to WITHDRAW with a 34-byte script as data, and it succeeded
            if e.to() == Some(WITHDRAW)
                && !e.value().is_zero()
                && e.input().len() == 34
                && ran.success
            {
                world.zero_balance(&WITHDRAW);
                let sats = e.value() / U256::from(GWEI);
                if sats >= U256::from(1) {
                    out.withdrawals.push(Withdrawal {
                        script: ScriptBuf::from_bytes(e.input().to_vec()),
                        sats: u64::try_from(sats).unwrap_or(u64::MAX),
                        hash: carried.hash,
                    });
                }
            }
        }
        out
    }

    fn env(&self, height: u32, time: u32) -> BlockEnvironment {
        BlockEnvironment {
            chain_id: self.config.chain_id,
            gas_limit: self.config.gas_limit,
            height,
            time,
        }
    }

    /// The rule's verdict on the block `hash` at `height`, made at `time`,
    /// whose transactions are `txdata` (coinbase first), from the state after
    /// the previous block (`evm.mjs prepare`). The state does not change: an
    /// ok block's resulting state is kept until [`EvmState::commit`]. Asked
    /// again for the same block, the first verdict is returned.
    ///
    /// Only the next height can be judged — the state is kept for the tip,
    /// as `sidestr-core`'s chain has no reorganisations — and height 0 has
    /// nothing to run: either is "no state for height …".
    pub fn prepare(
        &mut self,
        hash: BlockHash,
        height: u32,
        time: u32,
        txdata: &[Transaction],
    ) -> Verdict {
        if let Some(p) = self.pending.iter().find(|p| p.hash == hash) {
            return p.verdict.clone();
        }
        if height == 0 || height - 1 != self.height {
            let v = Verdict::refused(format!("no state for height {}", i64::from(height) - 1));
            self.verdicts.insert(hash, v.clone());
            return v;
        }
        let env = self.env(height, time);
        let mut world = self.world.clone();
        let mut receipts = Vec::new();
        let (mut hashes, mut withdrawals) = (Vec::new(), Vec::new());
        let mut error = None;
        for (i, tx) in txdata.iter().enumerate().skip(1) {
            let r = self.apply_tx(&mut world, tx, &env, &mut receipts);
            if let Some(e) = r.error {
                error = Some(format!("tx {i}: {e}"));
                break;
            }
            hashes.extend(r.hashes);
            withdrawals.extend(r.withdrawals);
        }
        let root = world.root();
        let cb = txdata.first();
        if error.is_none() {
            let committed =
                cb.and_then(|cb| cb.output.iter().find_map(|o| parse_root(&o.script_pubkey)));
            if committed != Some(root) {
                error = Some(format!(
                    "coinbase commits {} state root, the block's execution gives {root}",
                    committed.map_or("no".to_string(), |c| c.to_string())
                ));
            }
        }
        if error.is_none() {
            let outputs = cb.map(|cb| cb.output.as_slice()).unwrap_or_default();
            if let Some(w) = withdrawals.iter().find(|w| {
                !outputs
                    .iter()
                    .any(|o| o.script_pubkey == w.script && o.value.to_sat() == w.sats)
            }) {
                error = Some(format!(
                    "withdrawal of {} sats to {} is not paid by the coinbase",
                    w.sats,
                    w.script.to_hex_string()
                ));
            }
        }
        let v = Verdict {
            ok: error.is_none(),
            // the reference's refusal carries no hashes: nothing of a refused block is kept
            hashes: if error.is_none() { hashes } else { Vec::new() },
            error,
            root: Some(root),
            withdrawals,
        };
        if v.ok {
            self.pending.push(Pending {
                hash,
                height,
                time,
                world,
                receipts,
                verdict: v.clone(),
            });
        }
        self.verdicts.insert(hash, v.clone());
        v
    }

    /// [`EvmState::prepare`] for a block of header family `F`.
    pub fn prepare_block<F: HeaderFamily>(&mut self, block: &F::Block, height: u32) -> Verdict {
        let family = F::default();
        let header = block.header();
        self.prepare(
            family.block_hash(header),
            height,
            family.time(header),
            block.txdata(),
        )
    }

    /// The block `hash`, which [`EvmState::prepare`] passed, was applied:
    /// its state becomes the state, its receipts are kept, and every other
    /// candidate is forgotten. `false`, and nothing changes, for a block
    /// with no ok verdict waiting.
    pub fn commit(&mut self, hash: &BlockHash) -> bool {
        let Some(i) = self.pending.iter().position(|p| p.hash == *hash) else {
            return false;
        };
        let p = self.pending.swap_remove(i);
        self.pending.clear();
        for r in p.receipts {
            self.receipts.insert(r.transaction_hash, r);
        }
        self.blocks.insert(
            p.height,
            BlockRecord {
                hashes: p.verdict.hashes.clone(),
                root: p.verdict.root.unwrap_or_default(),
            },
        );
        self.world = p.world;
        self.height = p.height;
        self.time = p.time;
        true
    }

    /// A read-only call against the state after the last applied block, in
    /// its environment: `data` from `from` to `to`, with `gas_limit` and no
    /// fee (`eth_call`). Whether it succeeded and what it returned; the state
    /// does not change.
    ///
    /// ```
    /// use alloy_primitives::{Address, Bytes};
    /// use sidestr_evm::{EvmConfig, EvmState};
    ///
    /// let state = EvmState::new(EvmConfig { chain_id: 21474, gas_limit: 30_000_000, reserve: Default::default() });
    /// // the identity precompile echoes its input
    /// let (ok, out) = state.call(Address::ZERO, Address::with_last_byte(4), Bytes::from_static(b"hi"), 100_000).unwrap();
    /// assert!(ok && out.as_ref() == b"hi");
    /// ```
    pub fn call(
        &self,
        from: Address,
        to: Address,
        data: Bytes,
        gas_limit: u64,
    ) -> Result<(bool, Bytes), String> {
        call(
            &self.world,
            &self.env(self.height, self.time),
            from,
            to,
            data,
            gas_limit,
        )
    }

    /// A read-only execution against the state after the last applied
    /// block, in the block that would come next (`height`, `time`), as
    /// ethereumjs's `evm.runCall` makes it for `eth_call` and
    /// `eth_estimateGas`: `data` from `from` to `to` (a creation without
    /// one), carrying `value`, with `gas` for the execution itself. The
    /// state does not change. See [`crate::exec`] for what counts as a
    /// failure and what is an `Err`.
    ///
    /// ```
    /// use alloy_primitives::{Address, Bytes, U256};
    /// use sidestr_evm::{EvmConfig, EvmState};
    ///
    /// let state = EvmState::new(EvmConfig { chain_id: 21474, gas_limit: 30_000_000, reserve: Default::default() });
    /// // the identity precompile: 15 + 3 per word of gas, and its input back
    /// let s = state.simulate(1, 1_790_000_000, Address::ZERO, Some(Address::with_last_byte(4)), U256::ZERO, Bytes::from_static(b"hi"), 100_000).unwrap();
    /// assert!(s.success && s.output.as_ref() == b"hi" && s.execution_gas == 18);
    /// // a creation returns the runtime it would deploy
    /// let init = Bytes::from_static(&[0x60, 0x2a, 0x60, 0x00, 0x53, 0x60, 0x01, 0x60, 0x00, 0xf3]);
    /// assert_eq!(state.simulate(1, 0, Address::ZERO, None, U256::ZERO, init, 100_000).unwrap().output.as_ref(), &[0x2a]);
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn simulate(
        &self,
        height: u32,
        time: u32,
        from: Address,
        to: Option<Address>,
        value: U256,
        data: Bytes,
        gas: u64,
    ) -> Result<Simulation, String> {
        simulate(
            &self.world,
            &self.env(height, time),
            from,
            to,
            value,
            data,
            gas,
        )
    }

    /// The mempool's check (`evm.mjs checkTx`): `tx` run on the state after
    /// the last applied block, as if in a block at `height` and `time`, and
    /// the state left as it was. A transaction whose records do not apply is
    /// refused.
    pub fn check_tx(&self, tx: &Transaction, height: u32, time: u32) -> TxOutcome {
        let mut world = self.world.clone();
        self.apply_tx(&mut world, tx, &self.env(height, time), &mut Vec::new())
    }

    /// A producer's sequencing (`chain.mjs sequencedEvm`): `txs` run in
    /// order from the state after the last applied block, each on the state
    /// the ones before it leave; one that does not apply is dropped whole,
    /// and the root and withdrawals are those of the rest. The state is left
    /// as it was.
    pub fn sequence(&self, txs: &[Transaction], height: u32, time: u32) -> Sequenced {
        let env = self.env(height, time);
        let mut world = self.world.clone();
        let mut out = Sequenced {
            kept: Vec::new(),
            dropped: Vec::new(),
            root: B256::ZERO,
            withdrawals: Vec::new(),
            hashes: Vec::new(),
        };
        for (i, tx) in txs.iter().enumerate() {
            let mut scratch = world.clone();
            let r = self.apply_tx(&mut scratch, tx, &env, &mut Vec::new());
            match r.error {
                None => {
                    world = scratch;
                    out.kept.push(i);
                    out.hashes.extend(r.hashes);
                    out.withdrawals.extend(r.withdrawals);
                }
                Some(e) => out.dropped.push((i, e)),
            }
        }
        out.root = world.root();
        out
    }
}
