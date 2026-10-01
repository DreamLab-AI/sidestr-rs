//! Construction and ordering of the asset, pool and markets rules.
//!
//! The reference installs these rules in the order assets, pool, markets.
//! That order lets the collateral rules inspect the asset carry trace for
//! the same candidate block while keeping their state independent.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};

use crate::assets::{AssetMintPolicy, AssetTrace, AssetsRule};
use crate::markets::{no_id_of, MarketHeld, MarketsRule};
use crate::pool::{PoolHeld, PoolRule};
use crate::records::{AssetRef, Classified, MarketRecord};
use crate::rules::BlockRule;
use crate::HeaderFamily;

/// The result of ordering transactions through the lightweight overlays.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OverlaySequence {
    /// Indices in the input slice that remain, in order.
    pub kept: Vec<usize>,
    /// Rejected indices and the rule-local reason.
    pub dropped: Vec<(usize, String)>,
}

#[derive(Debug)]
struct MintPolicy {
    pools: Option<Arc<Mutex<PoolHeld>>>,
    markets: Option<Arc<Mutex<MarketHeld>>>,
}

impl AssetMintPolicy for MintPolicy {
    fn allows(&self, asset: &Txid, txid: &Txid, classified: &Classified) -> bool {
        if let Some(pools) = &self.pools {
            let opening = *asset == *txid
                && classified
                    .pools
                    .iter()
                    .any(|(_, pool)| pool.pool == AssetRef::SelfTx);
            let existing = pools
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .view
                .contains(asset);
            if opening || existing {
                return true;
            }
        }
        if let Some(markets) = &self.markets {
            let view = &markets.lock().unwrap_or_else(|e| e.into_inner()).view;
            return classified.markets.iter().any(|(_, record)| {
                if let MarketRecord::Split { market, .. } = record {
                    view.contains(market) && (*asset == *market || *asset == no_id_of(market))
                } else {
                    false
                }
            });
        }
        false
    }
}

/// The lightweight consensus overlays carried by `sidestr-core`.
#[derive(Debug, Clone)]
pub struct OverlayRules {
    /// Asset conservation, installed whenever a document names any rule.
    pub assets: AssetsRule,
    /// Constant-product pools, when named.
    pub pool: Option<PoolRule>,
    /// Binary prediction markets, when named.
    pub markets: Option<MarketsRule>,
}

impl OverlayRules {
    /// Construct the asset rule and its optional collateral rules. `markets`
    /// is the activation height when that rule is named.
    pub fn new(pool: bool, markets: Option<u32>) -> Self {
        let pool_held = pool.then(|| Arc::new(Mutex::new(PoolHeld::default())));
        let market_held = markets.map(|_| Arc::new(Mutex::new(MarketHeld::default())));
        let policy = Arc::new(MintPolicy {
            pools: pool_held.clone(),
            markets: market_held.clone(),
        });
        let assets = AssetsRule::with_mint_policy(policy);
        let pool = pool_held.map(|held| PoolRule::from_parts(assets.clone(), held));
        let markets = market_held
            .zip(markets)
            .map(|(held, from)| MarketsRule::from_parts(assets.clone(), held, from));
        Self {
            assets,
            pool,
            markets,
        }
    }

    /// Asset conservation without a pool or market mint policy.
    pub fn assets_only() -> Self {
        Self {
            assets: AssetsRule::new(),
            pool: None,
            markets: None,
        }
    }

    /// The rules as the validating state takes them, in reference order.
    pub fn boxed<F: HeaderFamily>(&self) -> Vec<Box<dyn BlockRule<F>>> {
        let mut out: Vec<Box<dyn BlockRule<F>>> = vec![Box::new(self.assets.clone())];
        if let Some(pool) = &self.pool {
            out.push(Box::new(pool.clone()));
        }
        if let Some(markets) = &self.markets {
            out.push(Box::new(markets.clone()));
        }
        out
    }

    /// Order a mempool through assets, pools and markets, committing each
    /// accepted transaction only to the temporary views seen by the next.
    /// `script_of` supplies confirmed prevout scripts; outputs of an earlier
    /// accepted transaction are resolved here directly.
    pub fn sequence(
        &self,
        txs: &[Transaction],
        height: u32,
        script_of: impl Fn(&OutPoint) -> Option<ScriptBuf>,
    ) -> OverlaySequence {
        let mut assets = self.assets.view();
        let mut pools = self.pool.as_ref().map(PoolRule::view);
        let mut markets = self.markets.as_ref().map(MarketsRule::view);
        let mut created: HashMap<OutPoint, ScriptBuf> = HashMap::new();
        let mut sequence = OverlaySequence::default();
        for (index, tx) in txs.iter().enumerate() {
            let txid = tx.compute_txid();
            let input_carries = tx
                .input
                .iter()
                .filter_map(|input| {
                    assets
                        .carried(&input.previous_output)
                        .cloned()
                        .map(|carry| (input.previous_output, carry))
                })
                .collect();
            let mut carried = Default::default();
            let outputs = match self.assets.check_transaction(&assets, tx, &mut carried) {
                Ok(outputs) => outputs,
                Err(error) => {
                    sequence.dropped.push((index, format!("assets: {error}")));
                    continue;
                }
            };
            let trace = AssetTrace {
                inputs: input_carries,
                outputs,
            };
            let mut next_pools = pools.clone();
            if let Some(view) = &mut next_pools {
                match view.check(tx, &trace, height, false) {
                    Ok(Some(effect)) => view.apply(effect),
                    Ok(None) => {}
                    Err(error) => {
                        sequence.dropped.push((index, format!("pool: {error}")));
                        continue;
                    }
                }
            }
            let mut next_markets = markets.clone();
            if let (Some(rule), Some(view)) = (&self.markets, &mut next_markets) {
                if height >= rule.from() {
                    let scripts: HashMap<usize, Vec<u8>> = tx
                        .input
                        .iter()
                        .enumerate()
                        .filter_map(|(input_index, input)| {
                            created
                                .get(&input.previous_output)
                                .cloned()
                                .or_else(|| script_of(&input.previous_output))
                                .map(|script| (input_index, script.into_bytes()))
                        })
                        .collect();
                    match view.check(tx, &trace, height, false, &scripts) {
                        Ok(Some(effect)) => view.apply(effect),
                        Ok(None) => {}
                        Err(error) => {
                            sequence.dropped.push((index, format!("markets: {error}")));
                            continue;
                        }
                    }
                }
            }
            self.assets
                .apply_to_view(&mut assets, std::slice::from_ref(tx), height);
            pools = next_pools;
            markets = next_markets;
            for (vout, output) in tx.output.iter().enumerate() {
                created.insert(
                    OutPoint {
                        txid,
                        vout: vout as u32,
                    },
                    output.script_pubkey.clone(),
                );
            }
            sequence.kept.push(index);
        }
        sequence
    }
}
