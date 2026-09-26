//! The Liquid origin adapter: turns what the reserve wallet unblinded at a
//! Liquid tip into the origin-neutral [`sidestr_reserve`] attestation.
//!
//! This is the statement the sidestr `bridge` rule will check against its own
//! books: *circulating + pending ≤ attested reserve* (ADR-2117 decision 4,
//! ADR-2102). The format, its canonical bytes, digest and signature belong to
//! `sidestr-reserve`, so every origin produces the same kind of statement;
//! this module decides only which Liquid outputs count. On Liquid the credits
//! are the reserve's unspent outputs, keyed by outpoint (`txid:vout`), and
//! the origin is `liquid` with the pinned [`crate::RESERVE_ASSET_ID`] at
//! [`crate::EXPECTED_PRECISION`] decimals.
//!
//! # Trust basis (the light option)
//!
//! The wallet state comes from a public Esplora server
//! ([`DEFAULT_ESPLORA_URL`](crate::DEFAULT_ESPLORA_URL)), named in the
//! attestation's `source` field. The attester unblinds the outputs itself
//! with the wallet's blinding key, so the asset and amount of each listed
//! output are the attester's own reading, not the server's. What the server
//! is trusted for is **completeness and freshness**: it cannot invent an
//! output paying the reserve, but it could omit a spend of one (making a
//! spent reserve look unspent), withhold a new output, or report a stale
//! tip. The tip hash is recorded so a later check against any other view of
//! Liquid can detect a stale or forked answer.
//!
//! Running an own `elementsd` (23.3.4 or later, the release that fixed the
//! 6 September 2026 range-proof caching bug) changes the basis to the
//! attester's own validation of the chain: spends and tips come from a node
//! that checked every block, and the server's omission risk goes away.
//! ADR-2117's amendment sets when that upgrade is due.

use std::collections::BTreeSet;

use lwk_wollet::elements::{AssetId, BlockHash, OutPoint};
use sidestr_reserve::{Credit, Origin, ReserveAttestation, Tip};

use crate::asset::{ensure_reserve_asset, EXPECTED_PRECISION};
use crate::error::{Error, Result};

/// The origin network name Liquid mainnet attests under.
pub const NETWORK: &str = "liquid";

/// A Liquid block the wallet synced to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainTip {
    /// Block height.
    pub height: u32,
    /// Block hash.
    pub hash: BlockHash,
}

/// One unspent output the reserve wallet owns, as it unblinded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReserveUtxo {
    /// The output.
    pub outpoint: OutPoint,
    /// Its asset, unblinded.
    pub asset: AssetId,
    /// Its amount in the asset's base units, unblinded.
    pub value: u64,
    /// The height of the block that confirmed it; `None` while unconfirmed.
    pub height: Option<u32>,
}

/// The wallet state an attestation is made from.
///
/// [`crate::ReserveWallet::snapshot`] builds one from a synced wallet; tests
/// build them by hand, which is what makes [`attest`] testable offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveSnapshot {
    /// The tip the wallet synced to.
    pub tip: ChainTip,
    /// Every unspent output the wallet owns, in any order, any asset.
    pub utxos: Vec<ReserveUtxo>,
    /// The server the state was read from (its base URL).
    pub source: String,
}

/// The Liquid reserve's origin: `liquid`, the pinned reserve asset, 8 decimals.
pub fn origin() -> Origin {
    Origin::new(NETWORK, crate::RESERVE_ASSET_ID, EXPECTED_PRECISION)
        .expect("the pinned reserve asset is a valid origin")
}

/// The credits the reserve holds in `state`: every output of `asset`
/// **confirmed** at or below the snapshot's tip, keyed by outpoint.
///
/// Unconfirmed outputs are not reserve yet. Outputs of other assets (L-BTC
/// for fees, anything sent unasked) are ignored. Refuses any `asset` other
/// than the pinned reserve asset and a snapshot that lists one outpoint
/// twice.
pub fn credits(state: &ReserveSnapshot, asset: &AssetId) -> Result<Vec<Credit>> {
    ensure_reserve_asset(asset)?;
    let mut seen = BTreeSet::new();
    for utxo in &state.utxos {
        if !seen.insert(utxo.outpoint) {
            return Err(Error::State(format!(
                "outpoint {} is listed twice",
                utxo.outpoint
            )));
        }
    }
    state
        .utxos
        .iter()
        .filter(|u| u.asset == *asset)
        .filter(|u| u.height.is_some_and(|h| h <= state.tip.height))
        .map(|u| {
            Credit::new(
                &format!("{}:{}", u.outpoint.txid, u.outpoint.vout),
                u128::from(u.value),
            )
            .map_err(Error::from)
        })
        .collect()
}

/// Attests the reserve held in `state`.
///
/// Pure: the same snapshot, asset and time give the same attestation, and
/// the same bytes. The credits are [`credits`]'s; the tip is the snapshot's,
/// its hash in Liquid's display order; the source is the server the wallet
/// synced from. A zero reserve is a valid statement; the `bridge` rule is
/// what refuses to mint against it.
///
/// `time` is a parameter, not read from the clock, to keep this pure.
pub fn attest(state: &ReserveSnapshot, asset: &AssetId, time: u64) -> Result<ReserveAttestation> {
    let credits = credits(state, asset)?;
    let tip = Tip::new(u64::from(state.tip.height), &state.tip.hash.to_string())?;
    Ok(sidestr_reserve::attest(
        origin(),
        tip,
        &credits,
        &state.source,
        time,
    )?)
}
