//! Payouts: the deposits are the coins, and each input is signed with its
//! own derived secret (`teller.mjs planPayout`, `unsignedTx`, `signPayout`,
//! `vsizeOf`, at `7c00cea`).
//!
//! A plan picks coins largest first until they pay the amount and the fee at
//! the rate; change of at least [`DUST`] goes back to `change_script` (a
//! deposit address of the operator's own account), less is left to the fee
//! with one output. Signing computes each input's key-path sighash under the
//! chain's rules, signs it with `normalize(operator) + that coin's tweak`,
//! checks every input under the same rules, and checks the fee against the
//! signed transaction's real size: nothing is returned that would not be
//! paid.
//!
//! The fee is estimated at [`vsize_estimate`]: 11 vB of transaction, 43 vB
//! per taproot output and 58 vB per key-path input. An input is 41 vB plus a
//! 66-byte witness (a 65-byte signature with its hash type, and its length)
//! at a quarter: 57.5 vB on paper, 58 once rounded with the rest. The
//! teller's first estimate was one short, and a payout was refused as
//! "min relay fee not met, 154 < 155" (`7c00cea`).
//!
//! The teller loads the chain's engine to learn its sighash; this crate
//! takes the rules as a parameter. For txbt4 (a BLAKE2b parent) they are
//! [`TXBT4_RULES`]: Knots' unified sighash, hash type `0x21`, 65-byte
//! witnesses. Under [`SighashRules::Bip341`] a payout also signs and checks,
//! for a stock-family chain, but its witnesses are not txbt4's.
//!
//! ```
//! use bitcoin::secp256k1::SecretKey;
//! use webledgers_teller::{deposit_address, plan_payout, pubkey_hex, sign_payout, vsize_estimate, Coin, PayoutParams, DEFAULT_HRP, TXBT4_RULES};
//!
//! let operator = SecretKey::from_slice(&[0x11; 32]).unwrap();
//! let op_did = format!("did:nostr:{}", pubkey_hex(&operator));
//! let ledger = "cd".repeat(32);
//! let alice = format!("did:nostr:{}", "aa".repeat(32));
//! let d = deposit_address(&op_did, &ledger, &alice, 0, DEFAULT_HRP).unwrap();
//! let change = deposit_address(&op_did, &ledger, &op_did, 0, DEFAULT_HRP).unwrap();
//! let coins = [Coin::from_deposit(&d, &"11".repeat(32), 0, 40_000)];
//!
//! let to = format!("5120{}", "33".repeat(32));
//! let plan = plan_payout(&PayoutParams { coins: &coins, amount: 25_000, rate: 1, to_script: &to, change_script: &change.script }).unwrap();
//! assert_eq!(plan.fee, vsize_estimate(1, 2));
//! assert_eq!(plan.change, 40_000 - 25_000 - plan.fee);
//!
//! let paid = sign_payout(&plan, &operator, TXBT4_RULES).unwrap();
//! assert_eq!(paid.tx.input[0].witness.nth(0).unwrap().last(), Some(&0x21));
//! assert!(plan.fee >= paid.vsize);
//! ```

use core::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::secp256k1::{Keypair, Message, SecretKey};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use serde::{Deserialize, Serialize};
use sidestr_core::block::secp;
use sidestr_core::sighash::{key_path_sighash, verify_taproot_key_path, SighashRules};

use crate::account::check_sats;
use crate::deposit::{deposit_secret, DepositAddress};
use crate::error::{Error, Result};
use crate::{DUST, MIN_PAY, TXBT4_RULES};

/// The highest fee rate a plan accepts, in sat/vB.
pub const MAX_RATE: u64 = 1000;

/// A deposit the operator holds, as a coin to spend: the outpoint, its
/// value, its output script and the tweak its secret needs. With serde the
/// field names are the teller's; the other fields of a JavaScript coin (the
/// rest of its deposit address) are ignored when read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coin {
    /// The funding transaction, 64 hex in the usual (display) order.
    pub txid: String,
    /// The output's index.
    pub vout: u32,
    /// Satoshis.
    pub value: u64,
    /// The output script, hex (`5120` + x).
    pub script: String,
    /// The deposit's tweak, 64 hex.
    pub tweak: String,
}

impl Coin {
    /// The coin a deposit address received: `{ ...depositAddress, txid, vout, value }`.
    pub fn from_deposit(d: &DepositAddress, txid: &str, vout: u32, value: u64) -> Self {
        Self {
            txid: txid.to_owned(),
            vout,
            value,
            script: d.script.clone(),
            tweak: d.tweak.clone(),
        }
    }
}

/// One output of a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanOutput {
    /// Satoshis.
    pub value: u64,
    /// The output script, hex.
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: String,
}

/// A payout planned (`planPayout`'s result).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// The coins spent, in input order (largest first).
    pub picked: Vec<Coin>,
    /// The amount to its destination, then the change if there is any.
    pub outputs: Vec<PlanOutput>,
    /// Satoshis left to the fee.
    pub fee: u64,
    /// Satoshis of change, 0 when there is no change output.
    pub change: u64,
    /// The fee rate, sat/vB.
    pub rate: u64,
}

/// What [`plan_payout`] is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayoutParams<'a> {
    /// The coins held.
    pub coins: &'a [Coin],
    /// Satoshis to pay, at least [`MIN_PAY`].
    pub amount: u64,
    /// Fee rate in whole sat/vB, 1 to [`MAX_RATE`] (the teller pays at 1).
    pub rate: u64,
    /// The destination's output script, hex.
    pub to_script: &'a str,
    /// Where change goes, hex: a deposit address of the operator's own account.
    pub change_script: &'a str,
}

/// The estimated virtual size of a payout with `n_in` key-path inputs and
/// `n_out` taproot outputs: `11 + 58·n_in + 43·n_out` vB.
pub fn vsize_estimate(n_in: u64, n_out: u64) -> u64 {
    11 + 58 * n_in + 43 * n_out
}

/// `planPayout`: coins largest first until they pay `amount` and the fee at
/// `rate`; change of at least [`DUST`] back to `change_script`, less folded
/// into the fee with a single output. Refuses an amount below [`MIN_PAY`], a
/// rate outside 1 to [`MAX_RATE`], and coins that cannot cover the amount
/// and the fee.
pub fn plan_payout(p: &PayoutParams<'_>) -> Result<Plan> {
    let v = check_sats(p.amount)?;
    if v < MIN_PAY {
        return Err(Error::PayoutTooSmall);
    }
    if !(1..=MAX_RATE).contains(&p.rate) {
        return Err(Error::Rate);
    }
    let mut sorted: Vec<&Coin> = p.coins.iter().collect();
    sorted.sort_by_key(|c| core::cmp::Reverse(c.value)); // stable, as Array.prototype.sort is
    let mut picked: Vec<Coin> = Vec::new();
    let mut in_sum = 0u64;
    for c in sorted {
        picked.push(c.clone());
        in_sum = in_sum.saturating_add(c.value);
        let n = picked.len() as u64;
        let fee = p.rate * vsize_estimate(n, 2);
        if in_sum >= v + fee {
            let change = in_sum - v - fee;
            if change >= DUST {
                return Ok(Plan {
                    picked,
                    outputs: vec![
                        PlanOutput {
                            value: v,
                            script_pubkey: p.to_script.to_owned(),
                        },
                        PlanOutput {
                            value: change,
                            script_pubkey: p.change_script.to_owned(),
                        },
                    ],
                    fee,
                    change,
                    rate: p.rate,
                });
            }
            let fee1 = p.rate * vsize_estimate(n, 1);
            if in_sum >= v + fee1 {
                return Ok(Plan {
                    picked,
                    outputs: vec![PlanOutput {
                        value: v,
                        script_pubkey: p.to_script.to_owned(),
                    }],
                    fee: in_sum - v,
                    change: 0,
                    rate: p.rate,
                });
            }
        }
    }
    Err(Error::NotCovered {
        held: in_sum,
        amount: v,
    })
}

fn script(what: &'static str, hex: &str) -> Result<ScriptBuf> {
    ScriptBuf::from_hex(hex).map_err(|e| Error::Encoding {
        what,
        reason: e.to_string(),
    })
}

/// The prevouts a plan's inputs spend, in input order.
pub fn prevouts(plan: &Plan) -> Result<Vec<TxOut>> {
    plan.picked
        .iter()
        .map(|c| {
            Ok(TxOut {
                value: Amount::from_sat(c.value),
                script_pubkey: script("coin script", &c.script)?,
            })
        })
        .collect()
}

/// `unsignedTx`: version 2, one input per picked coin (empty `scriptSig`,
/// sequence `0xfffffffd`), the plan's outputs, lock time 0, no witnesses.
pub fn unsigned_tx(plan: &Plan) -> Result<Transaction> {
    let input = plan
        .picked
        .iter()
        .map(|c| {
            Ok(TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(&c.txid).map_err(|e| Error::Encoding {
                        what: "coin txid",
                        reason: e.to_string(),
                    })?,
                    vout: c.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xffff_fffd),
                witness: Witness::new(),
            })
        })
        .collect::<Result<_>>()?;
    let output = plan
        .outputs
        .iter()
        .map(|o| {
            Ok(TxOut {
                value: Amount::from_sat(o.value),
                script_pubkey: script("output script", &o.script_pubkey)?,
            })
        })
        .collect::<Result<_>>()?;
    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input,
        output,
    })
}

/// `vsizeOf`: the transaction's virtual size, `(3 × stripped + full) / 4`
/// rounded up.
pub fn vsize_of(tx: &Transaction) -> u64 {
    tx.vsize() as u64
}

/// A payout signed and checked (`signPayout`'s result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPayout {
    /// The transaction.
    pub tx: Transaction,
    /// Its consensus serialisation, hex: what is broadcast.
    pub hex: String,
    /// Its txid.
    pub txid: String,
    /// Its virtual size.
    pub vsize: u64,
}

/// `signPayout`: every input signed with its deposit's own secret
/// ([`deposit_secret`] of `operator_secret` and the coin's tweak) over its
/// key-path sighash under `rules` (BIP 340, zero auxiliary randomness), then
/// every input checked under the same rules ([`Error::ScriptCheck`]) and the
/// fee checked against the signed size at the plan's rate
/// ([`Error::FeeBelowRate`]). Either check failing means nothing is paid.
pub fn sign_payout(
    plan: &Plan,
    operator_secret: &SecretKey,
    rules: SighashRules,
) -> Result<SignedPayout> {
    let mut tx = unsigned_tx(plan)?;
    let prevouts = prevouts(plan)?;
    let mut witnesses = Vec::with_capacity(tx.input.len());
    for (i, coin) in plan.picked.iter().enumerate() {
        let (m, ht) = key_path_sighash(&tx, i, &prevouts, rules)
            .map_err(|reason| Error::Sighash { input: i, reason })?;
        let d = deposit_secret(operator_secret, &coin.tweak)?;
        let kp = Keypair::from_secret_key(secp(), &d);
        let sig = secp().sign_schnorr_with_aux_rand(&Message::from_digest(m), &kp, &[0u8; 32]);
        let mut w = sig.as_ref().to_vec();
        w.push(ht);
        witnesses.push(Witness::from_slice(&[w]));
    }
    for (input, w) in tx.input.iter_mut().zip(witnesses) {
        input.witness = w;
    }
    for i in 0..tx.input.len() {
        verify_taproot_key_path(&tx, i, &prevouts, rules).map_err(|reason| Error::ScriptCheck {
            input: i,
            reason: reason.to_owned(),
        })?;
    }
    let vsize = vsize_of(&tx);
    if plan.fee < plan.rate * vsize {
        return Err(Error::FeeBelowRate {
            vsize,
            fee: plan.fee,
            rate: plan.rate,
        });
    }
    Ok(SignedPayout {
        hex: serialize_hex(&tx),
        txid: tx.compute_txid().to_string(),
        tx,
        vsize,
    })
}

/// [`sign_payout`] under [`TXBT4_RULES`], the teller's chain.
pub fn sign_payout_txbt4(plan: &Plan, operator_secret: &SecretKey) -> Result<SignedPayout> {
    sign_payout(plan, operator_secret, TXBT4_RULES)
}
