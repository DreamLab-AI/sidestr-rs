//! The constant-product pool rule (SPEC 12.3).
//!
//! A pool is one `OP_TRUE` coin holding sats and exactly one issued asset.
//! Its transaction recreates that coin as a swap, a proportional liquidity
//! add, or a proportional remove. Liquidity shares use the pool transaction
//! id as their asset id. This is a clean Rust port of
//! `siding/lib/overlays/pool.mjs` from `sidestr/spec`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use bitcoin::{BlockHash, OutPoint, Script, Transaction, Txid};

use crate::assets::{AssetTrace, AssetsRule, Carry};
use crate::block::{HeaderFamily, SidestrBlock};
use crate::records::{classify, AssetRef};
use crate::rules::{BlockContext, BlockRule};

/// The rule id reported in a verdict.
pub const RULE: &str = "sidestr:rule-pool";

/// The exact locking script of a pool coin: `OP_TRUE`.
pub const POOL_SCRIPT: &[u8] = &[0x51];

/// One pool's current derived state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pool {
    /// The opening transaction id and share-asset id.
    pub id: Txid,
    /// The issued asset held by the pool.
    pub asset: Txid,
    /// Sats held as collateral.
    pub sats: u64,
    /// Units of `asset` held.
    pub assets: u64,
    /// Outstanding liquidity shares.
    pub shares: u64,
    /// The current pool coin.
    pub outpoint: OutPoint,
    /// The height at which the pool opened.
    pub opened: u32,
}

/// The pools derived from applied blocks.
#[derive(Debug, Clone, Default)]
pub struct PoolView {
    pools: HashMap<Txid, Pool>,
    by_outpoint: HashMap<OutPoint, Txid>,
}

impl PoolView {
    /// Every pool by id.
    pub fn pools(&self) -> &HashMap<Txid, Pool> {
        &self.pools
    }

    /// A pool by id.
    pub fn get(&self, id: &Txid) -> Option<&Pool> {
        self.pools.get(id)
    }

    /// Whether an asset id is an existing pool's share asset.
    pub fn contains(&self, id: &Txid) -> bool {
        self.pools.contains_key(id)
    }

    pub(crate) fn apply(&mut self, pool: Pool) {
        if let Some(before) = self.pools.insert(pool.id, pool.clone()) {
            self.by_outpoint.remove(&before.outpoint);
        }
        self.by_outpoint.insert(pool.outpoint, pool.id);
    }

    pub(crate) fn check(
        &self,
        tx: &Transaction,
        trace: &AssetTrace,
        height: u32,
        coinbase: bool,
    ) -> Result<Option<Pool>, String> {
        let cls = classify(tx);
        if coinbase {
            return if cls.pools.is_empty() {
                Ok(None)
            } else {
                Err("the coinbase carries no records".into())
            };
        }
        let spent: Vec<Txid> = tx
            .input
            .iter()
            .filter_map(|input| self.by_outpoint.get(&input.previous_output).copied())
            .collect();
        if spent.len() > 1 {
            return Err("a transaction spends at most one pool coin".into());
        }
        if cls.pools.len() > 1 {
            return Err("a transaction carries at most one pool: record".into());
        }
        if spent.is_empty() && cls.pools.is_empty() {
            return Ok(None);
        }
        let opening: Vec<_> = cls
            .pools
            .iter()
            .filter(|(_, record)| record.pool == AssetRef::SelfTx)
            .collect();
        let continuing: Vec<_> = cls
            .pools
            .iter()
            .filter(|(_, record)| record.pool != AssetRef::SelfTx)
            .collect();
        let txid = tx.compute_txid();
        if let Some((_, record)) = opening.first() {
            if !spent.is_empty() {
                return Err("a transaction opens a pool or spends one, not both".into());
            }
            let output = pool_coin(tx, record.vout)
                .ok_or("the pool coin is an OP_TRUE output with value")?;
            let carried = trace.outputs.get(&record.vout).cloned().unwrap_or_default();
            if carried.len() != 1 {
                return Err("a pool coin carries exactly one asset".into());
            }
            let (asset, assets) = carried.into_iter().next().expect("one carried asset");
            if asset == txid {
                return Err("a pool does not hold its own shares".into());
            }
            let shares = isqrt(u128::from(output).saturating_mul(u128::from(assets)));
            let shares = u64::try_from(shares)
                .map_err(|_| "the opening share supply overflows".to_string())?;
            if carry_out(trace, &txid) != shares {
                return Err(format!(
                    "opening tallies exactly {shares} shares (tally:self)"
                ));
            }
            return Ok(Some(Pool {
                id: txid,
                asset,
                sats: output,
                assets,
                shares,
                outpoint: OutPoint {
                    txid,
                    vout: record.vout,
                },
                opened: height,
            }));
        }
        let Some(id) = spent.first().copied() else {
            return Err("pool: names a pool this transaction does not spend".into());
        };
        let before = self.pools.get(&id).ok_or("the spent pool is not known")?;
        let Some((_, record)) = continuing.first() else {
            return Err("a spent pool coin is recreated with pool:<its id>:<vout>".into());
        };
        if record.pool != AssetRef::Id(id) {
            return Err("a spent pool coin is recreated with pool:<its id>:<vout>".into());
        }
        let sats =
            pool_coin(tx, record.vout).ok_or("the pool coin is an OP_TRUE output with value")?;
        let carried = trace.outputs.get(&record.vout).cloned().unwrap_or_default();
        if carried.len() != 1 || !carried.contains_key(&before.asset) {
            return Err("the pool coin carries exactly its asset".into());
        }
        let assets = carried[&before.asset];
        if assets == 0 {
            return Err("a pool is never emptied".into());
        }
        let shares_in = carry_in(trace, &id);
        let shares_out = carry_out(trace, &id);
        let shares = before
            .shares
            .checked_sub(shares_in)
            .and_then(|n| n.checked_add(shares_out))
            .ok_or("more shares destroyed than exist")?;
        check_transition(before, sats, assets, shares)?;
        Ok(Some(Pool {
            id,
            asset: before.asset,
            sats,
            assets,
            shares,
            outpoint: OutPoint {
                txid,
                vout: record.vout,
            },
            opened: before.opened,
        }))
    }
}

fn pool_coin(tx: &Transaction, vout: u32) -> Option<u64> {
    let output = tx.output.get(vout as usize)?;
    (output.script_pubkey.as_script() == Script::from_bytes(POOL_SCRIPT)
        && output.value.to_sat() >= 1)
        .then(|| output.value.to_sat())
}

fn carry_in(trace: &AssetTrace, asset: &Txid) -> u64 {
    sum_carry(trace.inputs.values(), asset)
}

fn carry_out(trace: &AssetTrace, asset: &Txid) -> u64 {
    sum_carry(trace.outputs.values(), asset)
}

fn sum_carry<'a>(carries: impl Iterator<Item = &'a Carry>, asset: &Txid) -> u64 {
    carries.fold(0u64, |sum, carry| {
        sum.saturating_add(carry.get(asset).copied().unwrap_or(0))
    })
}

fn check_transition(before: &Pool, sats: u64, assets: u64, shares: u64) -> Result<(), String> {
    let (x, y, s) = (
        u128::from(before.sats),
        u128::from(before.assets),
        u128::from(before.shares),
    );
    let (x2, y2, s2) = (u128::from(sats), u128::from(assets), u128::from(shares));
    if s2 == s {
        let dx = x2.saturating_sub(x);
        let dy = y2.saturating_sub(y);
        let left = (1000 * x2 - 3 * dx) * (1000 * y2 - 3 * dy);
        let right = 1_000_000 * x * y;
        if left < right {
            return Err("swap: the constant product does not hold after the fee".into());
        }
    } else if s2 > s {
        if x2 < x || y2 < y {
            return Err("add: the pool does not shrink".into());
        }
        let cap = ((x2 - x) * s / x).min((y2 - y) * s / y);
        if s2 - s > cap {
            return Err(format!("add: at most {cap} shares for what was added"));
        }
    } else {
        if x2 > x || y2 > y {
            return Err("remove: the pool does not grow".into());
        }
        let destroyed = s - s2;
        if x - x2 > x * destroyed / s || y - y2 > y * destroyed / s {
            return Err("remove: more than the shares' pro-rata part".into());
        }
    }
    Ok(())
}

fn isqrt(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

#[derive(Debug, Default)]
pub(crate) struct PoolHeld {
    pub(crate) view: PoolView,
    pending: Vec<(BlockHash, PoolView)>,
}

/// The pool rule as consensus state, sharing the candidate asset trace made
/// by [`AssetsRule`].
#[derive(Debug, Clone)]
pub struct PoolRule {
    assets: AssetsRule,
    held: Arc<Mutex<PoolHeld>>,
}

impl PoolRule {
    pub(crate) fn from_parts(assets: AssetsRule, held: Arc<Mutex<PoolHeld>>) -> Self {
        Self { assets, held }
    }

    /// The pools left by applied blocks.
    pub fn view(&self) -> PoolView {
        self.lock().view.clone()
    }

    fn lock(&self) -> MutexGuard<'_, PoolHeld> {
        self.held.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl<F: HeaderFamily> BlockRule<F> for PoolRule {
    fn id(&self) -> &str {
        RULE
    }

    fn name(&self) -> Option<&str> {
        Some("pool")
    }

    fn check(&self, ctx: &BlockContext<F>) -> Option<bool> {
        let hash = F::default().block_hash(ctx.block.header());
        let Some(traces) = self.assets.trace(&hash) else {
            return Some(false);
        };
        if traces.len() != ctx.block.txdata().len() {
            return Some(false);
        }
        let mut held = self.lock();
        let mut next = held.view.clone();
        for (index, (tx, trace)) in ctx.block.txdata().iter().zip(&traces).enumerate() {
            match next.check(tx, trace, ctx.height, index == 0) {
                Ok(Some(effect)) => next.apply(effect),
                Ok(None) => {}
                Err(_) => return Some(false),
            }
        }
        held.pending.retain(|(candidate, _)| *candidate != hash);
        held.pending.push((hash, next));
        Some(true)
    }

    fn applied(&self, block: &F::Block, _height: u32) {
        let hash = F::default().block_hash(block.header());
        let mut held = self.lock();
        let pending = std::mem::take(&mut held.pending);
        if let Some((_, view)) = pending
            .into_iter()
            .find(|(candidate, _)| *candidate == hash)
        {
            held.view = view;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::isqrt;

    #[test]
    fn integer_square_root_matches_the_reference_boundary() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
        assert_eq!(isqrt(599_999_999_999), 774_596);
        assert_eq!(isqrt(600_000_000_000), 774_596);
        assert_eq!(isqrt(600_001_000_000), 774_597);
    }
}
