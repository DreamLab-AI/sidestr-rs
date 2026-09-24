//! The `assets` rule (SPEC 12.2) as a **view**: what each unspent output
//! carries, derived from the chain one block at a time. A port of the check
//! in `siding/lib/overlays/assets.mjs` (AGPL-3.0, Melvin Carvalho), without
//! the pool rule.
//!
//! For every asset in every non-coinbase transaction, what the inputs carry
//! must be at least what the transaction's tallies assign; the difference is
//! destroyed. Issuance (`issue:` with `tally:self:`) is the one creation.
//!
//! # Two ways to hold the rule
//!
//! On a chain whose document names `assets`, the rule is consensus: a
//! transaction that breaks it is refused and so is its block. On a chain
//! that names no rules the records are still mined, as any `OP_RETURN` is,
//! and a client may *read* them under the same rule. That is an asset
//! validated by its holders rather than by the chain's signers, and
//! [`AssetView`] is that reading: a transaction that breaks the rule is
//! kept (the chain kept it), its inputs are spent, and its outputs carry
//! nothing, so what it tried to move is destroyed rather than created. Two
//! clients that replay the same blocks reach the same view. The view never
//! refuses a block; [`Outcome`] says which transactions it read as broken.
//!
//! A wallet that spends a coin carrying an asset without tallying the asset
//! onward destroys it. Only a wallet that knows the view should hold such
//! coins.
//!
//! ```
//! use bitcoin::{absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
//! use sidestr_core::assets::AssetView;
//! use sidestr_core::records::record_script;
//!
//! let me = ScriptBuf::from_hex(&format!("5120{}", "ab".repeat(32))).unwrap();
//! let input = |txid: bitcoin::Txid, vout| TxIn { previous_output: OutPoint { txid, vout }, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() };
//! let out = |script: &ScriptBuf, sats| TxOut { value: Amount::from_sat(sats), script_pubkey: script.clone() };
//! let rec = |t: &str| TxOut { value: Amount::ZERO, script_pubkey: record_script(t).unwrap() };
//!
//! // issue 1000 DREAM onto output 0
//! let issue = Transaction { version: Version::TWO, lock_time: LockTime::ZERO,
//!     input: vec![input("11".repeat(32).parse().unwrap(), 0)],
//!     output: vec![out(&me, 330), rec("issue:DREAM:0"), rec("tally:self:0=1000")] };
//! let id = issue.compute_txid();
//! let mut view = AssetView::new();
//! view.apply_transactions(&[issue], 5);
//! assert_eq!(view.carried(&OutPoint { txid: id, vout: 0 }).unwrap()[&id], 1000);
//! assert_eq!(view.issued()[&id].ticker, "DREAM");
//!
//! // move 300 on, 700 back
//! let send = Transaction { version: Version::TWO, lock_time: LockTime::ZERO,
//!     input: vec![input(id, 0)],
//!     output: vec![out(&me, 330), out(&me, 330), rec(&format!("tally:{id}:0=300,1=700"))] };
//! let sid = send.compute_txid();
//! let outcome = view.apply_transactions(&[send], 6);
//! assert!(outcome[0].error.is_none());
//! assert_eq!(view.carried(&OutPoint { txid: sid, vout: 1 }).unwrap()[&id], 700);
//! assert!(view.carried(&OutPoint { txid: id, vout: 0 }).is_none());
//! ```

use std::collections::{BTreeMap, HashMap};

use bitcoin::{OutPoint, Transaction, Txid};

use crate::records::{classify, AssetRef};

/// What one output carries: asset id → amount.
pub type Carry = BTreeMap<Txid, u64>;

/// An issued asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    /// Its ticker.
    pub ticker: String,
    /// Display decimals.
    pub decimals: u8,
    /// The height of the block that issued it.
    pub height: u32,
    /// The supply created: what `tally:self:` assigned.
    pub supply: u64,
}

/// How the view read one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The transaction.
    pub txid: Txid,
    /// `None` when the transaction keeps the rule; otherwise why its
    /// outputs carry nothing (the reference's `bad-tally` reason).
    pub error: Option<String>,
    /// What its inputs carried, per asset.
    pub carried_in: Carry,
    /// What each output carries now, by vout; empty when `error` is set.
    pub carried_out: BTreeMap<u32, Carry>,
}

/// The assets view over a chain: what each unspent output carries and
/// which assets exist. Feed it every block's transactions in order with
/// [`AssetView::apply_transactions`] (the coinbase included).
#[derive(Debug, Clone, Default)]
pub struct AssetView {
    carried: HashMap<OutPoint, Carry>,
    issued: BTreeMap<Txid, Issued>,
}

fn sum_into(total: &mut Carry, c: &Carry) {
    for (a, n) in c {
        let e = total.entry(*a).or_insert(0);
        *e = e.saturating_add(*n);
    }
}

impl AssetView {
    /// An empty view: a chain before its genesis.
    pub fn new() -> Self {
        Self::default()
    }

    /// What an unspent output carries, or `None` when it carries nothing.
    pub fn carried(&self, outpoint: &OutPoint) -> Option<&Carry> {
        self.carried.get(outpoint)
    }

    /// Every asset issued so far, by id.
    pub fn issued(&self) -> &BTreeMap<Txid, Issued> {
        &self.issued
    }

    /// The asset issued under `ticker`, the earliest when several share it.
    /// A ticker is not unique on a chain; an application that means one
    /// asset pins its id and uses this only to show a name.
    pub fn by_ticker(&self, ticker: &str) -> Option<(&Txid, &Issued)> {
        self.issued
            .iter()
            .filter(|(_, i)| i.ticker == ticker)
            .min_by_key(|(id, i)| (i.height, **id))
    }

    /// Check one transaction against the view as it stands, without
    /// changing it: `Ok(outputs)` is what each output would carry,
    /// `Err(reason)` is why the rule is broken. `carried_in` is filled in
    /// either way. A wallet runs this on what it built before it signs.
    pub fn check(
        &self,
        tx: &Transaction,
        carried_in: &mut Carry,
    ) -> Result<BTreeMap<u32, Carry>, String> {
        let txid = tx.compute_txid();
        let cls = classify(tx);
        if let Some(b) = cls.bad.first() {
            return Err(format!(
                "malformed record: {}",
                b.chars().take(40).collect::<String>()
            ));
        }
        if cls.issues.len() > 1 {
            return Err("at most one issue: per transaction".into());
        }
        let opens_pool = cls.pools.iter().any(|(_, p)| p.pool == AssetRef::SelfTx);
        if !cls.issues.is_empty() && opens_pool {
            return Err("a transaction that opens a pool does not issue".into());
        }
        for i in &tx.input {
            if let Some(c) = self.carried.get(&i.previous_output) {
                sum_into(carried_in, c);
            }
        }
        let mut out: BTreeMap<u32, Carry> = BTreeMap::new();
        let mut assigned: Carry = BTreeMap::new();
        let mut seen: Vec<Txid> = Vec::new();
        for (_, t) in &cls.tallies {
            let asset = match &t.asset {
                AssetRef::SelfTx => {
                    if cls.issues.is_empty() && !opens_pool {
                        return Err("tally:self without issue: or pool:self:".into());
                    }
                    txid
                }
                AssetRef::Id(id) => *id,
            };
            if seen.contains(&asset) {
                return Err(format!("asset {}… tallied twice", &asset.to_string()[..8]));
            }
            seen.push(asset);
            for (vout, amount) in &t.assigns {
                let o = tx
                    .output
                    .get(*vout as usize)
                    .ok_or_else(|| format!("tally names output {vout}, which does not exist"))?;
                if o.script_pubkey.is_op_return() {
                    return Err(format!("tally names output {vout}, an OP_RETURN"));
                }
                if o.value.to_sat() < 1 {
                    return Err(format!("tally names output {vout}, which has no value"));
                }
                out.entry(*vout).or_default().insert(asset, *amount);
                let e = assigned.entry(asset).or_insert(0);
                *e = e
                    .checked_add(*amount)
                    .ok_or_else(|| "a tally's sum overflows".to_string())?;
            }
        }
        for (asset, n) in &assigned {
            if *asset == txid && !cls.issues.is_empty() {
                continue; // issuance: created from nothing
            }
            let have = carried_in.get(asset).copied().unwrap_or(0);
            if *n > have {
                return Err(format!(
                    "assigns {n} of {}… but carries {have}",
                    &asset.to_string()[..8]
                ));
            }
        }
        Ok(out)
    }

    /// Apply one block's transactions, the coinbase first, at `height`.
    /// Returns how each non-coinbase transaction was read. The coinbase
    /// carries nothing: records in it are ignored here, where a chain that
    /// names the rule would refuse the block.
    pub fn apply_transactions(&mut self, txs: &[Transaction], height: u32) -> Vec<Outcome> {
        let mut outcomes = Vec::new();
        for (i, tx) in txs.iter().enumerate() {
            let txid = tx.compute_txid();
            if i == 0 && tx.is_coinbase() {
                continue;
            }
            let mut carried_in = Carry::new();
            let result = self.check(tx, &mut carried_in);
            for inp in &tx.input {
                self.carried.remove(&inp.previous_output);
            }
            match result {
                Ok(out) => {
                    for (vout, c) in &out {
                        self.carried
                            .insert(OutPoint { txid, vout: *vout }, c.clone());
                    }
                    let cls = classify(tx);
                    if let Some((_, issue)) = cls.issues.first() {
                        let supply = out.values().filter_map(|c| c.get(&txid)).sum();
                        self.issued.insert(
                            txid,
                            Issued {
                                ticker: issue.ticker.clone(),
                                decimals: issue.decimals,
                                height,
                                supply,
                            },
                        );
                    }
                    outcomes.push(Outcome {
                        txid,
                        error: None,
                        carried_in,
                        carried_out: out,
                    });
                }
                Err(e) => outcomes.push(Outcome {
                    txid,
                    error: Some(e),
                    carried_in,
                    carried_out: BTreeMap::new(),
                }),
            }
        }
        outcomes
    }

    /// Every unspent output carrying `asset`, with its amount.
    pub fn holdings(&self, asset: &Txid) -> impl Iterator<Item = (&OutPoint, u64)> + '_ {
        let asset = *asset;
        self.carried
            .iter()
            .filter_map(move |(op, c)| c.get(&asset).map(|n| (op, *n)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::record_script;
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness,
    };

    fn me() -> ScriptBuf {
        ScriptBuf::from_hex(&format!("5120{}", "ab".repeat(32))).unwrap()
    }
    fn tx(inputs: Vec<OutPoint>, outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .into_iter()
                .map(|previous_output| TxIn {
                    previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs,
        }
    }
    fn coin(sats: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: me(),
        }
    }
    fn rec(t: &str) -> TxOut {
        TxOut {
            value: Amount::ZERO,
            script_pubkey: record_script(t).unwrap(),
        }
    }
    fn op(txid: Txid, vout: u32) -> OutPoint {
        OutPoint { txid, vout }
    }
    fn funding() -> OutPoint {
        op("11".repeat(32).parse().unwrap(), 0)
    }

    fn issued(view: &mut AssetView, supply: u64) -> Txid {
        let t = tx(
            vec![funding()],
            vec![
                coin(330),
                rec("issue:DREAM:0"),
                rec(&format!("tally:self:0={supply}")),
            ],
        );
        let id = t.compute_txid();
        let o = view.apply_transactions(&[t], 1);
        assert!(o[0].error.is_none(), "{:?}", o[0].error);
        id
    }

    #[test]
    fn issuance_creates_the_supply() {
        let mut v = AssetView::new();
        let id = issued(&mut v, 1_000_000);
        assert_eq!(v.issued()[&id].supply, 1_000_000);
        assert_eq!(v.by_ticker("DREAM").unwrap().0, &id);
        assert_eq!(v.holdings(&id).map(|(_, n)| n).sum::<u64>(), 1_000_000);
    }

    #[test]
    fn over_assigning_is_broken_and_destroys_what_the_inputs_carried() {
        let mut v = AssetView::new();
        let id = issued(&mut v, 100);
        let t = tx(
            vec![op(id, 0)],
            vec![coin(330), rec(&format!("tally:{id}:0=101"))],
        );
        let o = v.apply_transactions(std::slice::from_ref(&t), 2);
        assert!(o[0].error.as_deref().unwrap().starts_with("assigns 101"));
        assert!(v.carried(&op(t.compute_txid(), 0)).is_none());
        assert_eq!(v.holdings(&id).count(), 0);
    }

    #[test]
    fn spending_without_a_tally_burns() {
        let mut v = AssetView::new();
        let id = issued(&mut v, 100);
        let t = tx(vec![op(id, 0)], vec![coin(300)]);
        let o = v.apply_transactions(&[t], 2);
        assert!(o[0].error.is_none());
        assert_eq!(o[0].carried_in[&id], 100);
        assert_eq!(v.holdings(&id).count(), 0);
    }

    #[test]
    fn the_rules_edges_follow_the_reference() {
        let mut v = AssetView::new();
        let id = issued(&mut v, 100);
        let two_issues = tx(
            vec![funding()],
            vec![coin(1), rec("issue:A:0"), rec("issue:B:0")],
        );
        let self_without_issue = tx(vec![funding()], vec![coin(1), rec("tally:self:0=5")]);
        let op_return = tx(
            vec![op(id, 0)],
            vec![rec("x"), rec(&format!("tally:{id}:0=5"))],
        );
        let missing = tx(
            vec![op(id, 0)],
            vec![coin(1), rec(&format!("tally:{id}:7=5"))],
        );
        let twice = tx(
            vec![op(id, 0)],
            vec![
                coin(1),
                rec(&format!("tally:{id}:0=5")),
                rec(&format!("tally:{id}:0=5")),
            ],
        );
        let malformed = tx(vec![funding()], vec![coin(1), rec("tally:nope")]);
        let zero_value = tx(
            vec![op(id, 0)],
            vec![coin(0), rec(&format!("tally:{id}:0=5"))],
        );
        for (t, want) in [
            (two_issues, "at most one issue"),
            (self_without_issue, "tally:self without"),
            (op_return, "an OP_RETURN"),
            (missing, "does not exist"),
            (twice, "tallied twice"),
            (malformed, "malformed record"),
            (zero_value, "has no value"),
        ] {
            let mut c = Carry::new();
            let e = v.check(&t, &mut c).unwrap_err();
            assert!(e.contains(want), "{e} lacks {want}");
        }
    }

    #[test]
    fn a_later_transaction_in_the_block_spends_an_earlier_ones_output() {
        let mut v = AssetView::new();
        let issue = tx(
            vec![funding()],
            vec![coin(330), rec("issue:DREAM:0"), rec("tally:self:0=10")],
        );
        let id = issue.compute_txid();
        let next = tx(
            vec![op(id, 0)],
            vec![coin(330), rec(&format!("tally:{id}:0=10"))],
        );
        let nid = next.compute_txid();
        let o = v.apply_transactions(&[issue, next], 1);
        assert!(o.iter().all(|o| o.error.is_none()));
        assert_eq!(v.carried(&op(nid, 0)).unwrap()[&id], 10);
    }
}
