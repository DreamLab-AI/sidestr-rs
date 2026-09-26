//! One carried transaction through revm, against a [`World`], in the block
//! environment the reference gives every transaction (`evm.mjs applyTx`'s
//! `createBlock`): number = the sidechain height, timestamp = the block's
//! time, gas limit = the document's, coinbase = the zero address, base fee =
//! 1 gwei; Cancun, so `PREVRANDAO` is the header's all-zero mix hash and the
//! blob base fee is 1 wei (no excess blob gas). The per-transaction check
//! against the block gas limit is off (`skipBlockGasLimitValidation`) and no
//! total is kept across a block.
//!
//! One precompile differs from Ethereum's. ethereumjs's point-evaluation
//! precompile (`0x0a`, EIP-4844) throws "kzg not initialized" when the
//! `Common` carries no KZG, which the reference's does not; the throw leaves
//! `runTx`, so any transaction whose execution reaches `0x0a` — at the top or
//! from an inner call — makes its block invalid. [`NoKzg`] stands in for the
//! precompile and aborts the transaction the same way; a call that cannot
//! pay to reach it is an ordinary out-of-gas, as there.

use alloy_consensus::{Transaction as _, TxEnvelope};
use alloy_eips::eip2718::Typed2718;
use alloy_primitives::{Address, Bytes, Log, TxKind, U256};
use revm::context::result::{EVMError, ExecutionResult};
use revm::context::{BlockEnv, Cfg, CfgEnv, Context, ContextTr, TxEnv};
use revm::context_interface::block::BlobExcessGasAndPrice;
use revm::handler::{EthPrecompiles, MainnetContext, PrecompileProvider};
use revm::interpreter::{CallInputs, InterpreterResult};
use revm::primitives::eip4844::BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN;
use revm::primitives::hardfork::SpecId;
use revm::primitives::AddressSet;
use revm::state::EvmState;
use revm::{ExecuteEvm, MainBuilder};

use crate::records::GWEI;
use crate::tx::Carried;
use crate::world::{Db, World};

/// The KZG point-evaluation precompile's address.
pub const KZG_POINT_EVALUATION: Address = Address::new([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a,
]);

/// Ethereum's Cancun precompiles, with the point evaluation at `0x0a`
/// aborting the transaction instead of running (see the module docs). The
/// address stays a precompile: warm from the start, as ethereumjs has it.
#[derive(Debug, Clone)]
pub struct NoKzg {
    inner: EthPrecompiles,
}

impl NoKzg {
    /// The Cancun set.
    pub fn new() -> Self {
        Self {
            inner: EthPrecompiles::new(SpecId::CANCUN),
        }
    }
}

impl Default for NoKzg {
    fn default() -> Self {
        Self::new()
    }
}

impl<CTX: ContextTr<Cfg: Cfg<Spec = SpecId>>> PrecompileProvider<CTX> for NoKzg {
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: SpecId) -> bool {
        <EthPrecompiles as PrecompileProvider<CTX>>::set_spec(&mut self.inner, spec)
    }

    fn run(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Result<Option<InterpreterResult>, String> {
        if inputs.bytecode_address == KZG_POINT_EVALUATION {
            return Err("kzg not initialized".into());
        }
        <EthPrecompiles as PrecompileProvider<CTX>>::run(&mut self.inner, context, inputs)
    }

    fn warm_addresses(&self) -> &AddressSet {
        self.inner.warm_addresses()
    }

    fn contains(&self, address: &Address) -> bool {
        self.inner.contains(address)
    }
}

/// The block a transaction runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockEnvironment {
    /// The chain id.
    pub chain_id: u64,
    /// The document's gas limit.
    pub gas_limit: u64,
    /// The sidechain height.
    pub height: u32,
    /// The sidechain block's time.
    pub time: u32,
}

/// A transaction that ran: whatever its status, it is applied (a revert
/// spends gas and advances the nonce).
#[derive(Debug)]
pub(crate) struct Ran {
    pub(crate) success: bool,
    pub(crate) gas_used: u64,
    pub(crate) logs: Vec<Log>,
    pub(crate) changes: EvmState,
}

fn block_env(env: &BlockEnvironment) -> BlockEnv {
    BlockEnv {
        number: U256::from(env.height),
        beneficiary: Address::ZERO,
        timestamp: U256::from(env.time),
        gas_limit: env.gas_limit,
        basefee: GWEI,
        difficulty: U256::ZERO,
        prevrandao: Some(Default::default()),
        blob_excess_gas_and_price: Some(BlobExcessGasAndPrice::new(
            0,
            BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN,
        )),
        ..BlockEnv::default()
    }
}

fn tx_env(c: &Carried) -> TxEnv {
    let e: &TxEnvelope = &c.envelope;
    let mut tx = TxEnv {
        tx_type: e.ty(),
        caller: c.sender,
        gas_limit: e.gas_limit(),
        kind: e.kind(),
        value: e.value(),
        data: e.input().clone(),
        nonce: e.nonce(),
        chain_id: e.chain_id(),
        ..TxEnv::default()
    };
    match e {
        TxEnvelope::Legacy(t) => tx.gas_price = t.tx().gas_price,
        TxEnvelope::Eip2930(t) => {
            tx.gas_price = t.tx().gas_price;
            tx.access_list = t.tx().access_list.clone();
        }
        TxEnvelope::Eip1559(t) => {
            tx.gas_price = t.tx().max_fee_per_gas;
            tx.gas_priority_fee = Some(t.tx().max_priority_fee_per_gas);
            tx.access_list = t.tx().access_list.clone();
        }
        // refused by `decode_carrier`
        TxEnvelope::Eip4844(_) | TxEnvelope::Eip7702(_) => {}
    }
    tx
}

/// Run `c` against `world` in `env`, without changing `world`: the changes
/// come back to be committed. `Err` is a transaction that cannot be applied
/// (a wrong nonce, too little balance for its gas and value, gas below the
/// intrinsic cost, a fee under the base fee, a contract as sender, `0x0a`
/// reached), which makes its block invalid.
pub(crate) fn run(world: &World, env: &BlockEnvironment, c: &Carried) -> Result<Ran, String> {
    let mut cfg = CfgEnv::new_with_spec(SpecId::CANCUN);
    cfg.chain_id = env.chain_id;
    cfg.disable_block_gas_limit = true;
    let ctx: MainnetContext<Db<'_>> = Context::new(Db(world), SpecId::CANCUN);
    let mut evm = ctx
        .with_cfg(cfg)
        .with_block(block_env(env))
        .build_mainnet()
        .with_precompiles(NoKzg::new());
    let out = evm.transact(tx_env(c)).map_err(|e| match e {
        EVMError::Transaction(t) => t.to_string(),
        EVMError::Header(h) => h.to_string(),
        EVMError::Custom(s) => s,
        other => other.to_string(),
    })?;
    let (success, gas_used, logs) = match out.result {
        ExecutionResult::Success { gas, logs, .. } => (true, gas.tx_gas_used(), logs),
        ExecutionResult::Revert { gas, .. } | ExecutionResult::Halt { gas, .. } => {
            (false, gas.tx_gas_used(), Vec::new())
        }
    };
    Ok(Ran {
        success,
        gas_used,
        logs,
        changes: out.state,
    })
}

/// A read-only call (`eth_call`; ethereumjs's `evm.runCall`, which the
/// reference's test uses): `data` sent from `from` to `to` with `gas_limit`,
/// no fee, no balance or nonce check, against `world`, which does not
/// change. Whether it succeeded, and what it returned (a revert's data too).
pub(crate) fn call(
    world: &World,
    env: &BlockEnvironment,
    from: Address,
    to: Address,
    data: Bytes,
    gas_limit: u64,
) -> Result<(bool, Bytes), String> {
    let mut cfg = CfgEnv::new_with_spec(SpecId::CANCUN);
    cfg.chain_id = env.chain_id;
    cfg.disable_block_gas_limit = true;
    cfg.disable_base_fee = true;
    cfg.disable_balance_check = true;
    cfg.disable_nonce_check = true;
    let ctx: MainnetContext<Db<'_>> = Context::new(Db(world), SpecId::CANCUN);
    let mut evm = ctx
        .with_cfg(cfg)
        .with_block(block_env(env))
        .build_mainnet()
        .with_precompiles(NoKzg::new());
    let tx = TxEnv {
        caller: from,
        gas_limit,
        kind: TxKind::Call(to),
        data,
        chain_id: Some(env.chain_id),
        ..TxEnv::default()
    };
    let out = evm.transact(tx).map_err(|e| e.to_string())?;
    Ok(match out.result {
        ExecutionResult::Success { output, .. } => (true, output.into_data()),
        ExecutionResult::Revert { output, .. } => (false, output),
        ExecutionResult::Halt { .. } => (false, Bytes::new()),
    })
}

/// The address a contract-creating transaction deploys to, whether or not
/// the creation succeeds (ethereumjs reports `createdAddress` either way).
pub(crate) fn created_address(c: &Carried) -> Option<Address> {
    match c.envelope.kind() {
        TxKind::Create => Some(c.sender.create(c.envelope.nonce())),
        TxKind::Call(_) => None,
    }
}
