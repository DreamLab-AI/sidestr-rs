//! Deposit addresses: one taproot output per account (and nonce), derived
//! from the operator's point, which anyone can recompute from public data and
//! only the operator can spend (`teller.mjs depositAddress`, `depositSecret`,
//! `watchList`, at `7c00cea`).
//!
//! ```text
//! P = basePoint(did(basePoint(operator)))              the operator's did: the 02 point of its x
//! t = tagged("webledgers/deposit", ledgerHash32 ‖ x(account)32 ‖ nonce as 8 bytes, big-endian)
//! Q = P + t·G                                          added to the full point, never re-lifted
//! output = OP_1 <x(Q)>                                 x-only only here
//! secret = normalize(d) + t                            the sign BIP 340 needs stays inside signing
//! ```
//!
//! The operator is read as its did whatever parity the point it is given has
//! (the `7c00cea` fix): an operator whose secret gives an odd-y point once got
//! addresses from its `03` point while its secret was normalised to the `02`
//! point, and the two disagreed. Reading both through the did makes the
//! address from the point, from the did and from the normalised secret one
//! and the same.
//!
//! This is a plain additive tweak, not BIP 341's script tree, so a hardware
//! wallet cannot sign for it; and anyone who knows the operator's point can
//! link a ledger's deposit addresses.
//!
//! ```
//! use bitcoin::secp256k1::SecretKey;
//! use webledgers_teller::{deposit_address, deposit_secret, pubkey_hex, DEFAULT_HRP};
//!
//! let operator = SecretKey::from_slice(&[0x11; 32]).unwrap();
//! let did = format!("did:nostr:{}", pubkey_hex(&operator));
//! let account = format!("did:nostr:{}", "aa".repeat(32));
//! let ledger_hash = "cd".repeat(32);
//!
//! let a = deposit_address(&did, &ledger_hash, &account, 0, DEFAULT_HRP).unwrap();
//! assert!(a.address.starts_with("tb1p"));
//! assert_eq!(a.script, format!("5120{}", a.x_only));
//!
//! // only the operator can spend it: its secret plus the tweak is the output's key
//! let d = deposit_secret(&operator, &a.tweak).unwrap();
//! assert_eq!(pubkey_hex(&d), a.x_only);
//! ```

use bitcoin::secp256k1::SecretKey;
use bitcoin::ScriptBuf;
use serde::{Deserialize, Serialize};
use sidestr_core::address::script_to_address;

use crate::account::{account_of, x_of};
use crate::error::{Error, Result};
use crate::keys;
use crate::ledger::Ledger;
use crate::DEPOSIT_TAG;

/// The address prefix the teller writes deposit addresses under: `tb`,
/// txbt4's (testnet4's) segwit prefix.
pub const DEFAULT_HRP: &str = "tb";

/// A deposit address and how it was made (`depositAddress`'s result). With
/// serde the field names are the teller's (`xOnly`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositAddress {
    /// The tweak `t`, 64 hex: what the operator adds to its secret to spend.
    pub tweak: String,
    /// The output's full point `Q`, compressed (66 hex).
    pub point: String,
    /// `x(Q)`, 64 hex: the taproot output key.
    pub x_only: String,
    /// The output script, `5120` + `x(Q)`, as hex.
    pub script: String,
    /// The bech32m address of the script under the prefix asked for.
    pub address: String,
    /// The account it is for, `did:nostr:<x>`.
    pub account: String,
    /// The nonce: 0 for an account's first address, another for another.
    pub nonce: u64,
}

impl DepositAddress {
    /// The output script as a script.
    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::from_hex(&self.script).expect("written by deposit_address")
    }
}

pub(crate) fn is_x(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// `depositAddress`: the deposit address of `account` on the ledger
/// `ledger_hash` (64 lowercase hex), from `operator` in any form
/// `keys.mjs basePoint` reads (`did:nostr:<x>`, a bare x, a did:nostr
/// Multikey, a compressed point of either parity), for `nonce`, under the
/// address prefix `hrp` ([`DEFAULT_HRP`] for txbt4).
pub fn deposit_address(
    operator: &str,
    ledger_hash: &str,
    account: &str,
    nonce: u64,
    hrp: &str,
) -> Result<DepositAddress> {
    if !is_x(ledger_hash) {
        return Err(Error::DepositLedgerHash);
    }
    // the operator is its did: the 02 point of its x, whatever parity it was given as
    let p = keys::base_point(&keys::did(&keys::base_point(operator)?)?)?;
    let lh = hex::decode(ledger_hash).expect("checked hex");
    let ax = hex::decode(x_of(account)?).expect("an account's x is hex");
    let t = keys::tagged_scalar(DEPOSIT_TAG, &[&lh, &ax, &nonce.to_be_bytes()])?;
    let q = keys::tweak_point(&p, &t)?;
    let x = keys::x_only(&q)?;
    let script = format!("5120{x}");
    let spk = ScriptBuf::from_hex(&script).expect("hex");
    let address = script_to_address(&spk, hrp).ok_or_else(|| Error::Address(hrp.to_owned()))?;
    Ok(DepositAddress {
        tweak: t,
        point: q,
        x_only: x,
        script,
        address,
        account: account_of(account)?,
        nonce,
    })
}

/// `depositSecret`: the operator's secret for a deposit, `normalize(d) + t`.
/// Its point is the deposit's full point `Q`; the sign a BIP 340 signature of
/// `x(Q)` needs is applied inside the signing, never here.
pub fn deposit_secret(operator_secret: &SecretKey, tweak: &str) -> Result<SecretKey> {
    keys::tweaked_secret(&keys::normalized(operator_secret), &keys::scalar(tweak)?)
}

/// `watchList`: the nonce-0 addresses of every account the ledger knows (its
/// entries, then its deposits) and of any extra account (one that joined but
/// holds nothing yet), each once, in that order, under [`DEFAULT_HRP`].
pub fn watch_list(
    ledger: &Ledger,
    operator: &str,
    extra_accounts: &[&str],
) -> Result<Vec<DepositAddress>> {
    let extra: Vec<String> = extra_accounts
        .iter()
        .map(|a| account_of(a))
        .collect::<Result<_>>()?;
    let mut accounts: Vec<&str> = Vec::new();
    let all = ledger
        .entries
        .iter()
        .map(|e| e.url.as_str())
        .chain(ledger.deposits.iter().map(|d| d.account.as_str()))
        .chain(extra.iter().map(String::as_str));
    for a in all {
        if !accounts.contains(&a) {
            accounts.push(a);
        }
    }
    accounts
        .into_iter()
        .map(|a| deposit_address(operator, &ledger.hash, a, 0, DEFAULT_HRP))
        .collect()
}
