//! Binary prediction markets backed by sats (`sidestr:rule-markets`).
//!
//! A market coin holds all collateral. A split adds sats and mints equal YES
//! and NO assets, a merge burns pairs, the named resolver chooses the winner,
//! and unresolved claims refund at half par after expiry plus grace. This is
//! a clean Rust port of `siding/lib/overlays/markets.mjs` from
//! `sidestr/spec`.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};

use bitcoin::{BlockHash, OutPoint, Script, Transaction, Txid};
use sha2::{Digest, Sha256};

use crate::assets::{AssetTrace, AssetsRule, Carry};
use crate::block::{HeaderFamily, SidestrBlock};
use crate::records::{classify, AssetRef, MarketOutcome, MarketRecord};
use crate::rules::{BlockContext, BlockRule};

/// The rule id reported in a verdict.
pub const RULE: &str = "sidestr:rule-markets";

/// The exact locking script of a market coin: `OP_TRUE`.
pub const MARKET_SCRIPT: &[u8] = &[0x51];

/// The NO asset id for `market`: single SHA-256 of the UTF-8 text
/// `no:<market-display-txid>`.
pub fn no_id_of(market: &Txid) -> Txid {
    let digest = Sha256::digest(format!("no:{market}").as_bytes());
    Txid::from_str(&hex::encode(digest)).expect("a SHA-256 digest is a txid")
}

/// A market's settlement phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarketStatus {
    /// Waiting for its resolver, or for the refund deadline.
    Open,
    /// Answered by its resolver.
    Resolved,
    /// Unanswered and being refunded at half par.
    Refunding,
}

/// One market's current derived state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Market {
    /// The opening transaction id and YES asset id.
    pub id: Txid,
    /// The current market coin.
    pub coin: OutPoint,
    /// Sats held by the market coin.
    pub collateral: u64,
    /// The resolver's lower-case x-only public key.
    pub resolver: String,
    /// Nominal expiry height.
    pub expiry: u32,
    /// Further blocks during which the resolver may answer.
    pub grace: u32,
    /// Human-readable question.
    pub question: String,
    /// Current settlement phase.
    pub status: MarketStatus,
    /// The resolver's answer once resolved.
    pub winner: Option<MarketOutcome>,
    /// Height at which the market opened.
    pub opened: u32,
}

/// The markets derived from applied blocks.
#[derive(Debug, Clone, Default)]
pub struct MarketView {
    markets: HashMap<Txid, Market>,
    by_outpoint: HashMap<OutPoint, Txid>,
}

impl MarketView {
    /// Every market by id.
    pub fn markets(&self) -> &HashMap<Txid, Market> {
        &self.markets
    }

    /// A market by id.
    pub fn get(&self, id: &Txid) -> Option<&Market> {
        self.markets.get(id)
    }

    /// Whether this market has already opened.
    pub fn contains(&self, id: &Txid) -> bool {
        self.markets.contains_key(id)
    }

    pub(crate) fn apply(&mut self, market: Market) {
        if let Some(before) = self.markets.insert(market.id, market.clone()) {
            self.by_outpoint.remove(&before.coin);
        }
        self.by_outpoint.insert(market.coin, market.id);
    }

    pub(crate) fn check(
        &self,
        tx: &Transaction,
        trace: &AssetTrace,
        height: u32,
        coinbase: bool,
        scripts: &HashMap<usize, Vec<u8>>,
    ) -> Result<Option<Market>, String> {
        let cls = classify(tx);
        if coinbase {
            return if cls.markets.is_empty() && cls.questions.is_empty() {
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
            return Err("a transaction spends at most one market coin".into());
        }
        if cls.markets.len() > 1 {
            return Err("a transaction carries at most one market record".into());
        }
        if spent.is_empty() && cls.markets.is_empty() {
            return if cls.questions.is_empty() {
                Ok(None)
            } else {
                Err("question: belongs to the transaction that opens a market".into())
            };
        }
        let Some((_, record)) = cls.markets.first() else {
            return Err("a spent market coin is recreated with a market record".into());
        };
        let txid = tx.compute_txid();
        if let MarketRecord::Open {
            vout,
            resolver,
            expiry,
            grace,
        } = record
        {
            if !spent.is_empty() {
                return Err("a transaction opens a market or spends one, not both".into());
            }
            let collateral = market_coin(tx, trace, *vout)
                .ok_or("the market coin is an OP_TRUE output with value and no asset")?;
            if cls.questions.len() != 1 {
                return Err("a market has exactly one question:".into());
            }
            if *expiry <= height {
                return Err("expiry is a future height".into());
            }
            if *grace < 1 {
                return Err("grace is at least one block".into());
            }
            if !cls.issues.is_empty()
                || cls
                    .pools
                    .iter()
                    .any(|(_, pool)| pool.pool == AssetRef::SelfTx)
            {
                return Err(
                    "a transaction that opens a market issues nothing and opens no pool".into(),
                );
            }
            return Ok(Some(Market {
                id: txid,
                coin: OutPoint { txid, vout: *vout },
                collateral,
                resolver: resolver.clone(),
                expiry: *expiry,
                grace: *grace,
                question: cls.questions[0].1.text.clone(),
                status: MarketStatus::Open,
                winner: None,
                opened: height,
            }));
        }
        let Some(id) = spent.first().copied() else {
            return Err(format!(
                "{}: names a market this transaction does not spend",
                record.kind()
            ));
        };
        if record.market() != Some(id) {
            return Err(format!(
                "{}: names a market other than the coin spent",
                record.kind()
            ));
        }
        if !cls.questions.is_empty() {
            return Err("question: belongs to the transaction that opens a market".into());
        }
        let before = self
            .markets
            .get(&id)
            .ok_or("the spent market is not known")?;
        let no = no_id_of(&id);
        if let MarketRecord::Resolve { outcome, .. } = record {
            if before.status != MarketStatus::Open {
                return Err("resolve: the market is not open".into());
            }
            if height > before.expiry.saturating_add(before.grace) {
                return Err("resolve: the grace period has passed".into());
            }
            let resolver =
                hex::decode(&before.resolver).expect("a parsed resolver is lower-case 32-byte hex");
            let mut resolver_script = vec![0x51, 0x20];
            resolver_script.extend(resolver);
            if !scripts.values().any(|script| *script == resolver_script) {
                return Err("resolve: no input spends a coin of the resolver".into());
            }
            let coins: Vec<(u32, u64)> = tx
                .output
                .iter()
                .enumerate()
                .filter(|(_, output)| {
                    output.script_pubkey.as_script() == Script::from_bytes(MARKET_SCRIPT)
                })
                .map(|(vout, output)| (vout as u32, output.value.to_sat()))
                .collect();
            if coins.len() != 1
                || coins[0].1 != before.collateral
                || trace.outputs.contains_key(&coins[0].0)
            {
                return Err("resolve: recreates the market coin unchanged".into());
            }
            let mut effect = before.clone();
            effect.coin = OutPoint {
                txid,
                vout: coins[0].0,
            };
            effect.status = MarketStatus::Resolved;
            effect.winner = Some(*outcome);
            return Ok(Some(effect));
        }
        let vout = match record {
            MarketRecord::Split { vout, .. }
            | MarketRecord::Merge { vout, .. }
            | MarketRecord::Redeem { vout, .. } => *vout,
            MarketRecord::Open { .. } | MarketRecord::Resolve { .. } => unreachable!(),
        };
        let collateral = market_coin(tx, trace, vout).ok_or_else(|| {
            format!(
                "{}: the market coin is an OP_TRUE output with value and no asset",
                record.kind()
            )
        })?;
        let yes_in = carry_in(trace, &id);
        let no_in = carry_in(trace, &no);
        let yes_out = carry_out(trace, &id);
        let no_out = carry_out(trace, &no);
        let mut effect = before.clone();
        effect.coin = OutPoint { txid, vout };
        effect.collateral = collateral;
        match record {
            MarketRecord::Split { .. } => {
                let amount = collateral
                    .checked_sub(before.collateral)
                    .filter(|amount| *amount > 0)
                    .ok_or("split: the collateral grows")?;
                if yes_out.checked_sub(yes_in) != Some(amount)
                    || no_out.checked_sub(no_in) != Some(amount)
                {
                    return Err(format!(
                        "split: tallies exactly {amount} YES and {amount} NO beyond what it carries"
                    ));
                }
            }
            MarketRecord::Merge { .. } => {
                let amount = before
                    .collateral
                    .checked_sub(collateral)
                    .filter(|amount| *amount > 0)
                    .ok_or("merge: the collateral shrinks")?;
                if yes_in < amount || no_in < amount {
                    return Err(format!(
                        "merge: carries in at least {amount} YES and {amount} NO"
                    ));
                }
                if yes_out > yes_in - amount || no_out > no_in - amount {
                    return Err(format!("merge: destroys {amount} of each"));
                }
            }
            MarketRecord::Redeem { .. } => {
                let amount = before
                    .collateral
                    .checked_sub(collateral)
                    .filter(|amount| *amount > 0)
                    .ok_or("redeem: the collateral shrinks")?;
                if before.status == MarketStatus::Resolved {
                    let (winner_in, winner_out) = match before.winner {
                        Some(MarketOutcome::Yes) => (yes_in, yes_out),
                        Some(MarketOutcome::No) => (no_in, no_out),
                        None => return Err("resolved market has no winner".into()),
                    };
                    if winner_in < amount || winner_out > winner_in - amount {
                        return Err(format!(
                            "redeem: carries in at least {amount} of the winner and destroys {amount}"
                        ));
                    }
                } else {
                    if height <= before.expiry.saturating_add(before.grace) {
                        return Err("redeem: the market is open until expiry plus grace".into());
                    }
                    let yes_destroyed = yes_in.checked_sub(yes_out);
                    let no_destroyed = no_in.checked_sub(no_out);
                    let enough = yes_destroyed.zip(no_destroyed).is_some_and(|(yes, no)| {
                        u128::from(yes) + u128::from(no) >= 2 * u128::from(amount)
                    });
                    if !enough {
                        return Err(format!(
                            "refund: destroys YES and NO worth {} at half a sat each",
                            2 * u128::from(amount)
                        ));
                    }
                    effect.status = MarketStatus::Refunding;
                }
            }
            MarketRecord::Open { .. } | MarketRecord::Resolve { .. } => unreachable!(),
        }
        Ok(Some(effect))
    }
}

fn market_coin(tx: &Transaction, trace: &AssetTrace, vout: u32) -> Option<u64> {
    let output = tx.output.get(vout as usize)?;
    (output.script_pubkey.as_script() == Script::from_bytes(MARKET_SCRIPT)
        && output.value.to_sat() >= 1
        && !trace.outputs.contains_key(&vout))
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

#[derive(Debug, Default)]
pub(crate) struct MarketHeld {
    pub(crate) view: MarketView,
    pending: Vec<(BlockHash, MarketView, Vec<Txid>)>,
}

/// The markets rule as consensus state.
#[derive(Debug, Clone)]
pub struct MarketsRule {
    assets: AssetsRule,
    held: Arc<Mutex<MarketHeld>>,
    from: u32,
}

impl MarketsRule {
    pub(crate) fn from_parts(assets: AssetsRule, held: Arc<Mutex<MarketHeld>>, from: u32) -> Self {
        Self { assets, held, from }
    }

    /// The markets left by applied blocks.
    pub fn view(&self) -> MarketView {
        self.lock().view.clone()
    }

    /// The first height at which this rule applies.
    pub fn from(&self) -> u32 {
        self.from
    }

    fn lock(&self) -> MutexGuard<'_, MarketHeld> {
        self.held.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl<F: HeaderFamily> BlockRule<F> for MarketsRule {
    fn id(&self) -> &str {
        RULE
    }

    fn name(&self) -> Option<&str> {
        Some("markets")
    }

    fn check(&self, ctx: &BlockContext<F>) -> Option<bool> {
        if ctx.height < self.from {
            return Some(true);
        }
        let hash = F::default().block_hash(ctx.block.header());
        let Some(traces) = self.assets.trace(&hash) else {
            return Some(false);
        };
        if traces.len() != ctx.block.txdata().len() {
            return Some(false);
        }
        let mut scripts: HashMap<usize, HashMap<usize, Vec<u8>>> = HashMap::new();
        for (tx_index, input_index, prevout) in &ctx.spending.resolved {
            scripts
                .entry(*tx_index)
                .or_default()
                .insert(*input_index, prevout.script_pubkey.as_bytes().to_vec());
        }
        let mut held = self.lock();
        let mut next = held.view.clone();
        let mut opened = Vec::new();
        for (index, (tx, trace)) in ctx.block.txdata().iter().zip(&traces).enumerate() {
            let empty = HashMap::new();
            match next.check(
                tx,
                trace,
                ctx.height,
                index == 0,
                scripts.get(&index).unwrap_or(&empty),
            ) {
                Ok(Some(effect)) => {
                    if !next.contains(&effect.id) {
                        opened.push(effect.id);
                    }
                    next.apply(effect);
                }
                Ok(None) => {}
                Err(_) => return Some(false),
            }
        }
        held.pending.retain(|(candidate, _, _)| *candidate != hash);
        held.pending.push((hash, next, opened));
        Some(true)
    }

    fn applied(&self, block: &F::Block, height: u32) {
        if height < self.from {
            return;
        }
        let hash = F::default().block_hash(block.header());
        let mut held = self.lock();
        let pending = std::mem::take(&mut held.pending);
        if let Some((_, view, opened)) = pending
            .into_iter()
            .find(|(candidate, _, _)| *candidate == hash)
        {
            held.view = view;
            drop(held);
            for market in opened {
                self.assets
                    .register_market_assets(market, no_id_of(&market), height);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_asset_id_is_single_sha256_of_the_text() {
        let id: Txid = "ab".repeat(32).parse().unwrap();
        assert_eq!(
            no_id_of(&id).to_string(),
            "4b54df39860c61c4bb3d619b6ea0b5ea0b455241347e54baf351893dd7e50550"
        );
    }
}
