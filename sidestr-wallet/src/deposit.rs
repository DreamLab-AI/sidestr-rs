//! An EVM deposit (the `evm` rule, proposals/evm.md): sats paid to the
//! chain's reserve script, immediately followed by a value-0
//! `OP_RETURN evmin:<20-byte address>`, credit that address in the chain's
//! EVM at 1 sat = 1 gwei. A port of the `evmDeposit` branch of
//! `siding/lib/spend.mjs buildSpend` (`siding send --evm --to 0x… --amount N`).
//!
//! The layout is the reference's, byte for byte for the same coins, fee and
//! key (`tests/oracle.rs` holds it to siding's hex): version 2, lock time 0,
//! the picked coins largest first with sequence `0xfffffffd`, then the
//! payment to the reserve, the marker, and change back to the signer. The
//! reserve is the document's `evm.reserve`, else its challenge
//! ([`sidestr_core::ChainDocument::evm_reserve`]); the marker is
//! [`sidestr_core::marker::evm_deposit_marker`], the same bytes
//! `sidestr-evm`'s `records::deposit_script` writes (its tests check the two
//! agree). The fee is sized with the marker in place.
//!
//! Two checks siding does not make, both before any coin is touched: the
//! chain document must name the `evm` rule (on a chain without it the
//! payment goes to the reserve script and nothing is credited), and the
//! amount must not be dust for the reserve script (330 sats beside a taproot
//! challenge), as for every payment this crate builds.
//!
//! ```
//! use bitcoin::secp256k1::SecretKey;
//! use sidestr_core::document::ChainDocument;
//! use sidestr_core::marker::evm_deposit_marker;
//! use sidestr_wallet::coins::Coin;
//! use sidestr_wallet::deposit::{build_evm_deposit, DepositRequest};
//! use sidestr_wallet::{Error, Permissive, PlainKey};
//!
//! let chain = ChainDocument::from_json_with(r#"{"id":"sidestr:example","name":"example","parent":"tbtc4",
//!   "challenge":"5120aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
//!   "addressPrefix":"ex","genesisTime":1790000000,"pegs":[],"minFeeRate":1,"rules":["evm"]}"#, &["assets", "evm"]).unwrap();
//! let me = PlainKey::new(SecretKey::from_slice(&[9u8; 32]).unwrap());
//! let coins = vec![Coin { outpoint: format!("{}:0", "ab".repeat(32)).parse().unwrap(), value: 100_000, height: 5, coinbase: false }];
//! let to = "0x7777777777777777777777777777777777777777";
//!
//! let req = DepositRequest { chain: &chain, coins: &coins, tip_height: 10, to, amount: 25_000, fee: None };
//! let d = build_evm_deposit(&req, &me, &Permissive).unwrap();
//! // the reserve (the challenge here), then the marker, then change
//! assert_eq!(d.tx.output[0].script_pubkey, chain.evm_reserve().unwrap());
//! assert_eq!(d.tx.output[0].value.to_sat(), 25_000);
//! assert_eq!(d.tx.output[1].script_pubkey, evm_deposit_marker(&[0x77; 20]));
//! assert_eq!(d.tx.output[1].value.to_sat(), 0);
//! assert_eq!(d.change, 100_000 - 25_000 - d.fee);
//! assert_eq!(d.note.as_deref(), Some("deposit: 25000 sats to the reserve, credited as 25000 gwei to 0x7777777777777777777777777777777777777777 in the EVM"));
//!
//! // not a 0x address, or a chain without the rule: refused before anything is signed
//! assert!(matches!(build_evm_deposit(&DepositRequest { to: "0x77", ..req }, &me, &Permissive), Err(Error::Evm(_))));
//! let plain = ChainDocument { rules: None, ..chain.clone() };
//! assert!(matches!(build_evm_deposit(&DepositRequest { chain: &plain, ..req }, &me, &Permissive), Err(Error::Evm(_))));
//! ```

use sidestr_core::document::ChainDocument;
use sidestr_core::marker::evm_deposit_marker;

use crate::coins::Coin;
use crate::error::{Error, Result};
use crate::key::SpendSigner;
use crate::policy::{IntentKind, SpendPolicy};
use crate::spend::{assemble, Plan, Spend};

/// The rule name a chain document lists in `rules` when it credits deposits.
pub const EVM_RULE: &str = "evm";

/// What a deposit is built from.
#[derive(Debug, Clone, Copy)]
pub struct DepositRequest<'a> {
    /// The chain document: `id`, `parent`, `minFeeRate`, `rules`,
    /// `challenge` and `evm.reserve` are read.
    pub chain: &'a ChainDocument,
    /// The signer's coins as listed, immature ones included.
    pub coins: &'a [Coin],
    /// The producer's tip height, for maturity.
    pub tip_height: u32,
    /// The Ethereum address credited: `0x` and 40 hex digits, either case
    /// (no EIP-55 checksum is required, as in the reference).
    pub to: &'a str,
    /// Sats paid to the reserve, credited as as many gwei.
    pub amount: u64,
    /// A fixed fee, or `None` for `minFeeRate × vsize`.
    pub fee: Option<u64>,
}

/// The 20 bytes of a `0x` address, as `spend.mjs` accepts it
/// (`/^0x[0-9a-fA-F]{40}$/`); [`Error::Evm`] otherwise.
///
/// ```
/// use sidestr_wallet::deposit::parse_evm_address;
/// assert_eq!(parse_evm_address("0xAbCdEf0000000000000000000000000000000001").unwrap()[0], 0xab);
/// assert!(parse_evm_address("abcdef0000000000000000000000000000000001").is_err());
/// assert!(parse_evm_address("0x01").is_err());
/// ```
pub fn parse_evm_address(text: &str) -> Result<[u8; 20]> {
    let bad = || Error::Evm(format!("an EVM deposit goes to a 0x address, not {text:?}"));
    let digits = text.strip_prefix("0x").ok_or_else(bad)?;
    if digits.len() != 40 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad());
    }
    let mut out = [0u8; 20];
    hex::decode_to_slice(digits, &mut out).map_err(|_| bad())?;
    Ok(out)
}

/// Build and sign an EVM deposit. [`Error::Evm`] when the document does not
/// name the `evm` rule or `to` is not a `0x` address; a malformed `evm`
/// section is [`Error::Core`]; then the checks of
/// [`crate::spend::build_spend`], with the policy told
/// [`IntentKind::Spend`] and the reserve script.
pub fn build_evm_deposit(
    req: &DepositRequest<'_>,
    signer: &dyn SpendSigner,
    policy: &dyn SpendPolicy,
) -> Result<Spend> {
    let address = parse_evm_address(req.to)?;
    if !req
        .chain
        .rules
        .as_ref()
        .is_some_and(|r| r.iter().any(|n| n == EVM_RULE))
    {
        return Err(Error::Evm(format!(
            "{} does not name the evm rule: a deposit there would pay the reserve and credit nothing",
            req.chain.id
        )));
    }
    let reserve = req.chain.evm_reserve()?;
    let note = format!(
        "deposit: {} sats to the reserve, credited as {} gwei to {} in the EVM",
        req.amount, req.amount, req.to
    );
    assemble(
        req.chain,
        req.coins,
        req.tip_height,
        req.amount,
        req.fee,
        signer,
        policy,
        Plan {
            kind: IntentKind::Spend,
            output_script: reserve.clone(),
            intent_script: reserve,
            marker: Some(evm_deposit_marker(&address)),
            note: Some(note),
        },
    )
}
