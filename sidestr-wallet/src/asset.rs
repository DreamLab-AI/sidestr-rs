//! Issued assets (SPEC 12): issue one, and move it, keeping the `assets`
//! rule as [`sidestr_core::assets::AssetView`] reads it.
//!
//! An asset rides on ordinary coins, its **carriers**. A carrier here is
//! [`CARRIER`] sats, the dust threshold for a taproot output: the least a
//! wallet can economically spend again. A transfer spends enough carriers
//! of the asset, makes one carrier for the recipient and one for the asset
//! change, writes the `tally:` that says so, and pays the fee from coins
//! that carry nothing. It never spends a coin carrying any other asset, and
//! never spends a carrier as plain sats, because a spend that does not
//! tally an asset onward destroys it.
//!
//! Every built transaction is checked against the view before it is
//! returned, so a transfer this module hands back is one the view reads as
//! moving exactly what it says.
//!
//! ```
//! use bitcoin::secp256k1::SecretKey;
//! use sidestr_core::assets::AssetView;
//! use sidestr_core::document::ChainDocument;
//! use sidestr_wallet::asset::{balance_of, build_issue, build_transfer, IssueRequest, TransferRequest};
//! use sidestr_wallet::coins::Coin;
//! use sidestr_wallet::key::{script_for, PlainKey};
//! use sidestr_wallet::{Permissive, SpendSigner};
//!
//! let key = PlainKey::new(SecretKey::from_slice(&[3u8; 32]).unwrap());
//! let doc = ChainDocument::from_json(&format!(r#"{{"id":"sidestr:example","name":"example","parent":"tbtc4",
//!   "challenge":"{}","powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
//!   "addressPrefix":"ex","genesisTime":1790000000,"signer":"{}","pegs":[],"minFeeRate":1}}"#,
//!   key.script().to_hex_string(), key.pubkey())).unwrap();
//! let mut coins = vec![Coin { outpoint: format!("{}:0", "aa".repeat(32)).parse().unwrap(), value: 20_000, height: 1, coinbase: false }];
//! let mut view = AssetView::new();
//!
//! // issue 1,000,000 DREAM to myself
//! let issue = build_issue(&IssueRequest { chain: &doc, coins: &coins, view: &view, tip_height: 10,
//!     ticker: "DREAM", decimals: 0, supply: 1_000_000, to: None, fee: None }, &key, &Permissive).unwrap();
//! let id = issue.txid;
//! view.apply_transactions(&[issue.tx.clone()], 11);
//! coins = issue.tx.output.iter().enumerate()
//!     .filter(|(_, o)| o.script_pubkey == key.script())
//!     .map(|(v, o)| Coin { outpoint: bitcoin::OutPoint { txid: id, vout: v as u32 }, value: o.value.to_sat(), height: 11, coinbase: false })
//!     .collect();
//! assert_eq!(balance_of(&coins, &view, &id), 1_000_000);
//!
//! // tip 50 DREAM to bob, with a note the chain keeps beside the tally
//! let bob = script_for(&PlainKey::new(SecretKey::from_slice(&[4u8; 32]).unwrap()).pubkey());
//! let t = build_transfer(&TransferRequest { chain: &doc, coins: &coins, view: &view, tip_height: 12,
//!     asset: id, to: &bob.to_hex_string(), amount: 50, memos: &["tip:nostr:ab".into()], fee: None }, &key, &Permissive).unwrap();
//! assert_eq!(t.asset_change, 999_950);
//! view.apply_transactions(&[t.spend.tx.clone()], 13);
//! assert_eq!(view.carried(&bitcoin::OutPoint { txid: t.spend.txid, vout: 0 }).unwrap()[&id], 50);
//! ```

use bitcoin::{ScriptBuf, Txid};
use sidestr_core::assets::AssetView;
use sidestr_core::document::ChainDocument;
use sidestr_core::records::tally_text;

use crate::coins::{mature, Coin};
use crate::compose::{build_outputs, OutputsRequest};
use crate::error::{Error, Result};
use crate::key::SpendSigner;
use crate::policy::SpendPolicy;
use crate::spend::{dust_threshold, resolve_to, Spend};

/// The sats each carrier holds: the dust threshold for a taproot output.
pub const CARRIER: u64 = 330;

/// A wallet's coins sorted by what they carry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sorted {
    /// Coins carrying the asset and nothing else, with the amount.
    pub carriers: Vec<(Coin, u64)>,
    /// Coins carrying nothing: free for fees and plain payments.
    pub plain: Vec<Coin>,
    /// Coins carrying another asset, or several: left alone.
    pub other: Vec<Coin>,
}

/// Sort `coins` by what `view` says they carry, for `asset` (`None` sorts
/// only plain from carrying).
pub fn sort_coins(coins: &[Coin], view: &AssetView, asset: Option<&Txid>) -> Sorted {
    let mut s = Sorted::default();
    for c in coins {
        match view.carried(&c.outpoint) {
            None => s.plain.push(c.clone()),
            Some(carry) => match asset {
                Some(a) if carry.len() == 1 && carry.contains_key(a) => {
                    s.carriers.push((c.clone(), carry[a]))
                }
                _ => s.other.push(c.clone()),
            },
        }
    }
    s
}

/// The coins that carry nothing: what a plain payment may spend. A wallet
/// that holds assets passes these, not all its coins, to
/// [`crate::spend::build_spend`].
pub fn plain_coins(coins: &[Coin], view: &AssetView) -> Vec<Coin> {
    sort_coins(coins, view, None).plain
}

/// How much of `asset` these coins carry.
pub fn balance_of(coins: &[Coin], view: &AssetView, asset: &Txid) -> u64 {
    coins
        .iter()
        .filter_map(|c| view.carried(&c.outpoint).and_then(|m| m.get(asset)))
        .sum()
}

/// What [`build_transfer`] builds.
#[derive(Debug, Clone, Copy)]
pub struct TransferRequest<'a> {
    /// The chain document.
    pub chain: &'a ChainDocument,
    /// All the signer's coins; they are sorted here.
    pub coins: &'a [Coin],
    /// The assets view at the tip.
    pub view: &'a AssetView,
    /// The tip height.
    pub tip_height: u32,
    /// The asset's id.
    pub asset: Txid,
    /// A script hex or an address.
    pub to: &'a str,
    /// Units of the asset.
    pub amount: u64,
    /// Further records after the tally, application text (a tip's
    /// `tip:nostr:<event id>`); none may start `issue:`, `tally:` or `pool:`.
    pub memos: &'a [String],
    /// A fixed fee, or `None` for `minFeeRate × vsize`.
    pub fee: Option<u64>,
}

/// A built transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    /// The signed spend: output 0 is the recipient's carrier.
    pub spend: Spend,
    /// Units returned to the signer on output 1 (0 when there is none).
    pub asset_change: u64,
}

fn check_memos(memos: &[String]) -> Result<()> {
    for m in memos {
        if m.starts_with("issue:") || m.starts_with("tally:") || m.starts_with("pool:") {
            return Err(Error::Asset(format!(
                "a memo may not be an assets record: {}",
                m.chars().take(20).collect::<String>()
            )));
        }
    }
    Ok(())
}

/// Move `amount` of `asset` to `to`. Carriers are chosen largest first;
/// the fee comes from plain coins.
pub fn build_transfer(
    req: &TransferRequest<'_>,
    signer: &dyn SpendSigner,
    policy: &dyn SpendPolicy,
) -> Result<Transfer> {
    if req.amount == 0 {
        return Err(Error::BadAmount);
    }
    check_memos(req.memos)?;
    let dest = resolve_to(req.to, &req.chain.address_prefix)?.script;
    let me = signer.script();
    let sorted = sort_coins(req.coins, req.view, Some(&req.asset));
    let mut carriers: Vec<(Coin, u64)> = sorted
        .carriers
        .into_iter()
        .filter(|(c, _)| c.is_mature(req.tip_height))
        .collect();
    carriers.sort_by_key(|(_, n)| core::cmp::Reverse(*n));
    let mut picked = Vec::new();
    let mut have = 0u64;
    for (c, n) in carriers {
        if have >= req.amount {
            break;
        }
        have = have.saturating_add(n);
        picked.push(c);
    }
    if have < req.amount {
        return Err(Error::Asset(format!(
            "holds {have} of the asset, {} asked",
            req.amount
        )));
    }
    let change = have - req.amount;
    let mut outputs = vec![(dest.clone(), CARRIER.max(dust_threshold(&dest)))];
    let mut assigns = vec![(0u32, req.amount)];
    if change > 0 {
        outputs.push((me.clone(), CARRIER));
        assigns.push((1, change));
    }
    let mut records = vec![tally_text(Some(&req.asset), &assigns)?];
    records.extend(req.memos.iter().cloned());
    let spend = build_outputs(
        &OutputsRequest {
            chain: req.chain,
            coins: &sorted.plain,
            required: &picked,
            tip_height: req.tip_height,
            outputs: &outputs,
            records: &records,
            fee: req.fee,
        },
        signer,
        policy,
    )?;
    verify(req.view, &spend, &req.asset, &assigns)?;
    Ok(Transfer {
        spend,
        asset_change: change,
    })
}

/// What [`build_issue`] builds.
#[derive(Debug, Clone, Copy)]
pub struct IssueRequest<'a> {
    /// The chain document.
    pub chain: &'a ChainDocument,
    /// All the signer's coins; only plain ones are spent.
    pub coins: &'a [Coin],
    /// The assets view at the tip.
    pub view: &'a AssetView,
    /// The tip height.
    pub tip_height: u32,
    /// 1 to 8 of `A-Z0-9`.
    pub ticker: &'a str,
    /// 0 to 8, display only.
    pub decimals: u8,
    /// Units created, 1 to `2^53 - 1`.
    pub supply: u64,
    /// Where the supply's carrier goes: the signer's own script when `None`.
    pub to: Option<&'a str>,
    /// A fixed fee, or `None` for `minFeeRate × vsize`.
    pub fee: Option<u64>,
}

/// Issue an asset: output 0 carries the whole supply, then `issue:` and
/// `tally:self:0=<supply>`. The asset's id is the returned spend's txid.
pub fn build_issue(
    req: &IssueRequest<'_>,
    signer: &dyn SpendSigner,
    policy: &dyn SpendPolicy,
) -> Result<Spend> {
    let issue = format!("issue:{}:{}", req.ticker, req.decimals);
    if sidestr_core::records::parse_issue(&issue).is_none() {
        return Err(Error::Asset(format!(
            "{issue} is not an issue record: a ticker is 1 to 8 of A-Z0-9, decimals 0 to 8"
        )));
    }
    let to: ScriptBuf = match req.to {
        Some(t) => resolve_to(t, &req.chain.address_prefix)?.script,
        None => signer.script(),
    };
    let tally = tally_text(None, &[(0, req.supply)])?;
    let plain = plain_coins(&mature(req.coins, req.tip_height), req.view);
    let spend = build_outputs(
        &OutputsRequest {
            chain: req.chain,
            coins: &plain,
            required: &[],
            tip_height: req.tip_height,
            outputs: &[(to, CARRIER)],
            records: &[issue, tally],
            fee: req.fee,
        },
        signer,
        policy,
    )?;
    let mut carried_in = Default::default();
    let out = req
        .view
        .check(&spend.tx, &mut carried_in)
        .map_err(Error::Asset)?;
    if out.get(&0).and_then(|c| c.get(&spend.txid)) != Some(&req.supply) {
        return Err(Error::Asset("the issue does not read back as built".into()));
    }
    Ok(spend)
}

/// The view must read the built spend as assigning exactly `assigns` of
/// `asset` and nothing else: no other asset rode in on its inputs.
fn verify(view: &AssetView, spend: &Spend, asset: &Txid, assigns: &[(u32, u64)]) -> Result<()> {
    let mut carried_in = Default::default();
    let out = view
        .check(&spend.tx, &mut carried_in)
        .map_err(Error::Asset)?;
    if carried_in.keys().any(|a| a != asset) {
        return Err(Error::Asset("an input carries another asset".into()));
    }
    for (v, n) in assigns {
        if out.get(v).and_then(|c| c.get(asset)) != Some(n) {
            return Err(Error::Asset(format!(
                "output {v} does not read back as {n}"
            )));
        }
    }
    Ok(())
}
