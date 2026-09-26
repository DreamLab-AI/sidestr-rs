//! The rule inside `sidestr-core`'s validation (`evm.mjs installChecks`),
//! the rules a document names (`overlays/index.mjs rulesFor`), and block
//! production for a chain that carries them (`chain.mjs buildNext`).
//!
//! The reference runs the EVM before the kernel's checks, because
//! ethereumjs is asynchronous and the kernel is not, and the registered rule
//! reads the verdict left for the block. Here execution is synchronous, so
//! [`EvmRule`] runs the block when `sidestr-core` first asks about it — for
//! the coinbase allowance, then for `sidestr:rule-evm` — and both read the
//! same verdict. The result is the same: validating a block is one call,
//! [`sidestr_core::StateOf::add_block`].

use std::sync::{Arc, Mutex, MutexGuard};

use bitcoin::secp256k1::SecretKey;
use bitcoin::{Amount, Transaction, TxOut, Txid};
use sidestr_core::assets::{AssetView, AssetsRule};
use sidestr_core::block::{
    build_block, sign_block, BlockTemplate, HeaderFamily, SidestrBlock, MARKER,
};
use sidestr_core::marker::claim_marker;
use sidestr_core::rules::{BlockContext, BlockRule};
use sidestr_core::state::{Applied, NextBlock, StateOf};
use sidestr_core::ChainDocument;

use crate::config::EvmConfig;
use crate::error::{Error, Result};
use crate::records::root_script;
use crate::state::{EvmState, Verdict};

/// The id the rule reports in a verdict (`evm.mjs RULE`).
pub const RULE: &str = "sidestr:rule-evm";

/// The rules this crate carries, by the names a document gives them
/// (`overlays/index.mjs KNOWN`, less `pool`, which is not carried).
pub const KNOWN: &[&str] = &["assets", "evm"];

/// `sidestr:rule-evm` as a [`BlockRule`], over a shared [`EvmState`].
///
/// A block is valid under it when every carried transaction applies, in
/// order, and the coinbase commits the resulting state root and pays every
/// withdrawal; the rule then allows the coinbase to pay those withdrawals
/// beyond fees and claims ([`BlockRule::coinbase_allowance`]). Height 0 is
/// not judged (the reference applies the genesis without its checks, and a
/// genesis holds exactly the document's pegs). The state moves when
/// `sidestr-core` applies a block ([`BlockRule::applied`]).
///
/// The rule is a handle: clones share one state, so a caller keeps a clone
/// to read balances and receipts while the chain's state holds another.
///
/// ```
/// use sidestr_evm::{EvmConfig, EvmRule};
///
/// let rule = EvmRule::new(EvmConfig { chain_id: 21474, gas_limit: 30_000_000, reserve: Default::default() });
/// let reader = rule.clone();
/// assert_eq!(reader.state().height(), 0);
/// ```
#[derive(Debug, Clone)]
pub struct EvmRule {
    state: Arc<Mutex<EvmState>>,
}

impl EvmRule {
    /// The rule on a fresh state: a chain at its genesis.
    pub fn new(config: EvmConfig) -> Self {
        Self {
            state: Arc::new(Mutex::new(EvmState::new(config))),
        }
    }

    /// The rule for a document's `evm` section ([`EvmConfig::from_document`]).
    pub fn for_document(doc: &ChainDocument) -> Result<Self> {
        Ok(Self::new(EvmConfig::from_document(doc)?))
    }

    /// The state, locked for reading or for a producer's use.
    pub fn state(&self) -> MutexGuard<'_, EvmState> {
        // a panic while the lock was held leaves no half-applied block: prepare works on a copy
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn verdict<F: HeaderFamily>(&self, block: &F::Block, height: u32) -> Verdict {
        self.state().prepare_block::<F>(block, height)
    }
}

impl<F: HeaderFamily> BlockRule<F> for EvmRule {
    fn id(&self) -> &str {
        RULE
    }

    fn name(&self) -> Option<&str> {
        Some("evm")
    }

    fn check(&self, ctx: &BlockContext<F>) -> Option<bool> {
        (ctx.height > 0).then(|| self.verdict::<F>(ctx.block, ctx.height).ok)
    }

    fn coinbase_allowance(&self, ctx: &BlockContext<F>) -> Option<u64> {
        if ctx.height == 0 {
            return Some(0);
        }
        let v = self.verdict::<F>(ctx.block, ctx.height);
        if v.ok {
            v.withdrawn()
        } else {
            None
        }
    }

    fn applied(&self, block: &F::Block, height: u32) {
        if height > 0 {
            let hash = F::default().block_hash(block.header());
            self.state().commit(&hash);
        }
    }
}

/// A block [`Rules::build_next`] made, unsigned.
#[derive(Debug, Clone)]
pub struct Built<B> {
    /// The block.
    pub block: B,
    /// The fees its coinbase collects.
    pub fees: u64,
    /// The claims it makes.
    pub claims: usize,
    /// Mempool transactions left out of it, and why.
    pub dropped: Vec<(Txid, String)>,
}

/// A block [`Rules::produce`] made and applied.
#[derive(Debug, Clone)]
pub struct Produced<B> {
    /// The report `sidestr-core` gave on applying it, with its fees and claims.
    pub applied: Applied,
    /// The sealed block, for the caller to write down.
    pub block: B,
    /// Mempool transactions left out of it, and why.
    pub dropped: Vec<(Txid, String)>,
}

/// The rules a document names, as this crate carries them
/// (`overlays/index.mjs rulesFor`): with any rule named, the assets rule;
/// with `evm` named, the EVM rule too. A name this crate does not carry —
/// `pool` among them — is [`Error::Config`], as the reference refuses a rule
/// it does not have.
#[derive(Debug, Clone, Default)]
pub struct Rules {
    /// The assets rule, on every chain that names a rule.
    pub assets: Option<AssetsRule>,
    /// The EVM rule, when the document names it.
    pub evm: Option<EvmRule>,
}

impl Rules {
    /// The rules as `sidestr-core` takes them, assets first
    /// ([`StateOf::from_genesis_with_rules`]). The handles are shared: this
    /// value still reads what the chain's state does.
    pub fn boxed<F: HeaderFamily>(&self) -> Vec<Box<dyn BlockRule<F>>> {
        let mut out: Vec<Box<dyn BlockRule<F>>> = Vec::new();
        if let Some(a) = &self.assets {
            out.push(Box::new(a.clone()));
        }
        if let Some(e) = &self.evm {
            out.push(Box::new(e.clone()));
        }
        out
    }

    /// The next block, unsigned (`chain.mjs buildNext` with `sequenced` and
    /// `sequencedEvm`): the mempool in order, less what breaks the assets rule
    /// against the transactions before it or does not apply in the EVM; the
    /// fees to the challenge, the withdrawals, the `evmroot:` record, the
    /// claims with their markers. `sidestr-core`'s mempool has no eviction,
    /// so the transactions left out stay in it until their inputs are spent,
    /// and are left out of every block until then.
    pub fn build_next<F: HeaderFamily>(
        &self,
        state: &StateOf<F>,
        next: &NextBlock,
    ) -> Result<Built<F::Block>> {
        let tip = state.tip();
        let height = tip
            .height
            .checked_add(1)
            .ok_or_else(|| Error::Config("the chain is at the last height".into()))?;
        let time = next.time.max(tip.time.saturating_add(1));
        let mut txs: Vec<Transaction> = state.mempool().cloned().collect();
        let mut dropped = Vec::new();
        if let Some(assets) = &self.assets {
            let mut view: AssetView = assets.view();
            txs.retain(|tx| {
                let mut carried = Default::default();
                match view.check(tx, &mut carried) {
                    Ok(_) => {
                        view.apply_transactions(std::slice::from_ref(tx), height);
                        true
                    }
                    Err(e) => {
                        dropped.push((tx.compute_txid(), format!("assets: {e}")));
                        false
                    }
                }
            });
        }
        let mut evm_outputs = Vec::new();
        if let Some(evm) = &self.evm {
            let s = evm.state().sequence(&txs, height, time);
            for (i, e) in &s.dropped {
                dropped.push((txs[*i].compute_txid(), format!("evm: {e}")));
            }
            txs = s.kept.iter().map(|i| txs[*i].clone()).collect();
            for w in &s.withdrawals {
                evm_outputs.push(TxOut {
                    value: Amount::from_sat(w.sats),
                    script_pubkey: w.script.clone(),
                });
            }
            evm_outputs.push(TxOut {
                value: Amount::ZERO,
                script_pubkey: root_script(s.root),
            });
        }
        let fees = txs
            .iter()
            .try_fold(0u64, |s, tx| s.checked_add(state.fees(tx).unwrap_or(0)))
            .ok_or_else(|| Error::Config("the mempool's fees overflow".into()))?;
        let mut outputs = Vec::new();
        if fees > 0 {
            outputs.push(TxOut {
                value: Amount::from_sat(fees),
                script_pubkey: state.challenge().to_owned(),
            });
        }
        outputs.extend(evm_outputs);
        for c in &next.claims {
            if state.claimed(&c.txid, c.vout) {
                return Err(Error::Config(format!(
                    "{}:{} is already claimed",
                    c.txid, c.vout
                )));
            }
            outputs.push(TxOut {
                value: Amount::from_sat(c.amount),
                script_pubkey: c.script.clone(),
            });
            outputs.push(TxOut {
                value: Amount::ZERO,
                script_pubkey: claim_marker(&c.txid, c.vout),
            });
        }
        let block = build_block(
            state.family(),
            &BlockTemplate {
                height,
                prev: tip.hash,
                time,
                transactions: txs,
                outputs,
                bits: state.bits(),
                marker: MARKER.to_string(),
            },
        );
        Ok(Built {
            block,
            fees,
            claims: next.claims.len(),
            dropped,
        })
    }

    /// One signer: build, sign, add (`chain.mjs produce`). A federated chain's
    /// blocks are sealed by its round and enter through
    /// [`StateOf::add_block`]; this refuses one, as `sidestr-core` does.
    pub fn produce<F: HeaderFamily>(
        &self,
        state: &mut StateOf<F>,
        key: &SecretKey,
        next: &NextBlock,
        now: Option<u32>,
    ) -> Result<Produced<F::Block>> {
        if state.federation().is_some() {
            return Err(Error::Core(sidestr_core::Error::Federation(
                "a federated chain makes blocks through the round (proposals/level-2.md), not produce()".into(),
            )));
        }
        let built = self.build_next(state, next)?;
        let signed = sign_block(
            state.family(),
            &built.block,
            state.challenge(),
            key,
            &[0u8; 32],
        )?;
        let mut applied = state.add_block(&signed, None, now)?;
        applied.fees = built.fees;
        applied.claims = built.claims;
        Ok(Produced {
            applied,
            block: signed,
            dropped: built.dropped,
        })
    }
}

/// The rules `doc` names (`overlays/index.mjs rulesFor`). No rules named is
/// no rules; `pool`, `desk` and any other name this crate does not carry is
/// [`Error::Config`].
///
/// ```
/// use sidestr_core::ChainDocument;
///
/// let mut doc: serde_json::Value = serde_json::from_str(include_str!("../../sidestr-core/fixtures/trial/chain.json")).unwrap();
/// doc["rules"] = serde_json::json!(["evm"]);
/// let doc: ChainDocument = serde_json::from_value(doc).unwrap();
/// let rules = sidestr_evm::rules_for(&doc).unwrap();
/// assert!(rules.assets.is_some() && rules.evm.is_some());
/// ```
pub fn rules_for(doc: &ChainDocument) -> Result<Rules> {
    let names = doc.rules.clone().unwrap_or_default();
    let names: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|n| !n.is_empty())
        .collect();
    if let Some(n) = names.iter().find(|n| !KNOWN.contains(n)) {
        return Err(Error::Config(format!(
            "chain {} names rule \"{n}\", which this validator does not have (it carries {})",
            doc.id,
            KNOWN.join(", ")
        )));
    }
    if names.is_empty() {
        return Ok(Rules::default());
    }
    Ok(Rules {
        assets: Some(AssetsRule::new()),
        evm: names
            .contains(&"evm")
            .then(|| EvmRule::for_document(doc))
            .transpose()?,
    })
}
