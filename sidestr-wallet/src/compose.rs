//! A spend with a laid-out body: named outputs first, then `OP_RETURN`
//! records (SPEC 12.1), then change. The general form behind
//! [`crate::asset`]: an asset transfer is outputs that carry, a `tally:`
//! record that says what they carry, and inputs that must be spent because
//! they carry it.
//!
//! The layout is fixed so a record can name an output by index before the
//! transaction exists: output `i` is `outputs[i]`, the records follow in
//! order, and change (when there is any worth an output) is last.
//!
//! ```
//! use bitcoin::secp256k1::SecretKey;
//! use bitcoin::ScriptBuf;
//! use sidestr_core::document::ChainDocument;
//! use sidestr_wallet::coins::Coin;
//! use sidestr_wallet::compose::{build_outputs, OutputsRequest};
//! use sidestr_wallet::key::{script_for, PlainKey};
//! use sidestr_wallet::{Permissive, SpendSigner};
//!
//! let key = PlainKey::new(SecretKey::from_slice(&[3u8; 32]).unwrap());
//! let doc = ChainDocument::from_json(&format!(r#"{{"id":"sidestr:example","name":"example","parent":"tbtc4",
//!   "challenge":"{}","powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
//!   "addressPrefix":"ex","genesisTime":1790000000,"signer":"{}","pegs":[],"minFeeRate":1}}"#,
//!   key.script().to_hex_string(), key.pubkey())).unwrap();
//! let coins = vec![Coin { outpoint: format!("{}:0", "aa".repeat(32)).parse().unwrap(), value: 10_000, height: 1, coinbase: false }];
//! let bob = script_for(&PlainKey::new(SecretKey::from_slice(&[4u8; 32]).unwrap()).pubkey());
//!
//! let s = build_outputs(&OutputsRequest {
//!     chain: &doc, coins: &coins, required: &[], tip_height: 10,
//!     outputs: &[(bob.clone(), 1_000)], records: &["hello".to_string()], fee: None,
//! }, &key, &Permissive).unwrap();
//! assert_eq!(s.tx.output[0].script_pubkey, bob);
//! assert!(s.tx.output[1].script_pubkey.is_op_return());
//! assert_eq!(s.tx.output[2].script_pubkey, key.script()); // change, last
//! ```

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::transaction::Version;
use bitcoin::{absolute::LockTime, Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use sidestr_core::document::ChainDocument;
use sidestr_core::records::record_script;
use sidestr_core::sighash::rules_for;

use crate::coins::{mature, Coin};
use crate::error::{Error, Result};
use crate::key::SpendSigner;
use crate::policy::{Intent, IntentKind, SpendPolicy};
use crate::select::{fee_bound, select};
use crate::spend::{dust_threshold, Spend};

/// What [`build_outputs`] builds.
#[derive(Debug, Clone, Copy)]
pub struct OutputsRequest<'a> {
    /// The chain document: `parent` (for the sighash family) and
    /// `minFeeRate` are read.
    pub chain: &'a ChainDocument,
    /// Coins the builder may choose from for the value and the fee. A
    /// caller that holds coins carrying an asset leaves them out of here,
    /// or they may be spent without a tally.
    pub coins: &'a [Coin],
    /// Coins that are spent whatever the selection does, first, in this
    /// order: the carriers of an asset being moved. Each must be mature.
    pub required: &'a [Coin],
    /// The tip height, for maturity.
    pub tip_height: u32,
    /// `(script, sats)` for outputs `0..n`, in order. Each at least dust for
    /// its script.
    pub outputs: &'a [(ScriptBuf, u64)],
    /// `OP_RETURN` records, one output each, after the named outputs.
    pub records: &'a [String],
    /// A fixed fee, or `None` for `minFeeRate × vsize`.
    pub fee: Option<u64>,
}

/// Build and sign a spend laid out as [`OutputsRequest`] says. Every input
/// pays the signer's script; every input is signed under the chain's
/// parent family and re-verified before the spend is returned. The policy
/// is asked about the first output (`Intent::script`) and the sum of the
/// named outputs (`Intent::amount`).
pub fn build_outputs(
    req: &OutputsRequest<'_>,
    signer: &dyn SpendSigner,
    policy: &dyn SpendPolicy,
) -> Result<Spend> {
    if req.outputs.is_empty() && req.records.is_empty() {
        return Err(Error::BadAmount);
    }
    let mut named = Vec::with_capacity(req.outputs.len() + req.records.len());
    let mut paid = 0u64;
    for (script, value) in req.outputs {
        let dust = dust_threshold(script);
        if *value < dust.max(1) {
            return Err(Error::Dust {
                value: *value,
                min: dust.max(1),
                script: script.to_hex_string(),
            });
        }
        paid = paid.checked_add(*value).ok_or(Error::BadAmount)?;
        named.push(TxOut {
            value: Amount::from_sat(*value),
            script_pubkey: script.clone(),
        });
    }
    for text in req.records {
        named.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: record_script(text)?,
        });
    }
    for c in req.required {
        if !c.is_mature(req.tip_height) {
            return Err(Error::Asset(format!(
                "{} is a coinbase output not yet mature",
                c.outpoint
            )));
        }
    }
    let rules = rules_for(req.chain.parent()?.family);
    let me = signer.script();
    let rate = req.chain.min_fee_rate;
    let change_dust = dust_threshold(&me);
    let required_sum: u64 = req.required.iter().map(|c| c.value).sum();
    let free: Vec<Coin> = mature(req.coins, req.tip_height)
        .into_iter()
        .filter(|c| !req.required.iter().any(|r| r.outpoint == c.outpoint))
        .collect();
    // select for a fee bound; when the laid-out transaction's own fee is
    // more than the bound bought (records make it larger than a plain
    // spend), select again for that fee, a few times at most
    let mut bound = req.fee.unwrap_or(fee_bound(rate));
    let mut attempt = 0;
    let (spent, mut tx, change, fee) = loop {
        let short = paid.saturating_sub(required_sum);
        let extra = if required_sum >= paid.saturating_add(bound) {
            Vec::new()
        } else {
            select(&free, short, bound)?.picked
        };
        let spent: Vec<Coin> = req.required.iter().cloned().chain(extra).collect();
        let sum: u64 = spent.iter().map(|c| c.value).sum();
        let layout = |f: u64| -> Result<(Vec<TxOut>, u64, u64)> {
            let change = sum.checked_sub(paid).and_then(|r| r.checked_sub(f)).ok_or(
                Error::InsufficientForFee {
                    amount: paid,
                    fee: f,
                },
            )?;
            let mut out = named.clone();
            if change > 0 && change >= change_dust {
                out.push(TxOut {
                    value: Amount::from_sat(change),
                    script_pubkey: me.clone(),
                });
                Ok((out, change, f))
            } else {
                Ok((out, 0, f + change))
            }
        };
        // sized as signed, with change: one 64-byte signature and its hash type per input
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: spent
                .iter()
                .map(|c| TxIn {
                    previous_output: c.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence(0xffff_fffd),
                    witness: Witness::from_slice(&[[0u8; 65]]),
                })
                .collect(),
            output: named.clone(),
        };
        tx.output.push(TxOut {
            value: Amount::from_sat(change_dust),
            script_pubkey: me.clone(),
        });
        let vsize = tx.weight().to_wu().div_ceil(4);
        let min_fee = vsize * rate;
        let laid = match req.fee {
            None => layout(min_fee),
            Some(f) if f < min_fee => {
                return Err(Error::FeeBelowMinimum {
                    fee: f,
                    min: min_fee,
                    vsize,
                    rate,
                })
            }
            Some(f) => layout(f),
        };
        match laid {
            Ok((outputs, change, fee)) => {
                tx.output = outputs;
                break (spent, tx, change, fee);
            }
            Err(Error::InsufficientForFee { .. }) if req.fee.is_none() && attempt < 4 => {
                attempt += 1;
                bound = min_fee.saturating_add(fee_bound(rate));
            }
            Err(e) => return Err(e),
        }
    };

    let first = named
        .first()
        .map(|o| o.script_pubkey.clone())
        .unwrap_or_default();
    policy
        .permit(&Intent {
            chain_id: &req.chain.id,
            kind: IntentKind::Spend,
            script: &first,
            amount: paid,
            fee,
            inputs: tx.input.len(),
        })
        .map_err(Error::Policy)?;

    let prevouts: Vec<TxOut> = spent
        .iter()
        .map(|c| TxOut {
            value: Amount::from_sat(c.value),
            script_pubkey: me.clone(),
        })
        .collect();
    crate::spend::sign_inputs(&mut tx, &prevouts, rules, signer)?;
    let vsize = tx.weight().to_wu().div_ceil(4);
    Ok(Spend {
        hex: serialize_hex(&tx),
        txid: tx.compute_txid(),
        inputs: tx.input.len(),
        amount: paid,
        fee,
        vsize,
        change,
        note: None,
        tx,
    })
}
