//! The reserve asset: pinned by id, verified against its issuance contract.

use std::str::FromStr;

use lwk_wollet::elements::AssetId;
use lwk_wollet::registry::blocking::Registry;
use lwk_wollet::registry::RegistryData;
use lwk_wollet::Network;

use crate::error::{Error, Result};

/// The Liquid asset id of the reserve asset, verified 2026-09-23.
///
/// This is the asset that Blockstream's Liquid asset registry lists with
/// ticker `USDt`, name "Tether USD", precision 8 and issuer domain
/// `tether.to`, and that the issuer's own supported-protocols page names as
/// its Liquid asset. It was verified from two primary sources, plus a
/// computation that needs no one's word:
///
/// 1. The registry entry,
///    <https://assets.blockstream.info/ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2>
///    (issuance prevout `9596d259…8668:0`, issuer key `0337ccee…b904`). The
///    registry accepts an entity domain only with a proof served from that
///    domain.
/// 2. The issuer's page, <https://tether.to/en/supported-protocols>: "To
///    integrate Tether's Liquid Asset on the Liquid blockchain use the USD₮
///    asset: `https://blockstream.info/liquid/asset/ce091c99…7bd2`".
/// 3. The id is recomputed from the registry's issuance prevout and the hash
///    of its contract (the Elements issuance-entropy rule, as LWK implements
///    it) and equals this constant. So the ticker, name and domain in the
///    contract are committed to by the asset id itself, not only asserted by
///    the registry. [`verify_registry_entry`] repeats that check.
///
/// The unit this reserve backs is the owner's private USD unit of account,
/// not this asset and not a stablecoin (ADR-2117 decision 1).
pub const RESERVE_ASSET_ID: &str =
    "ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2";

/// The ticker the reserve asset's issuance contract carries.
pub const EXPECTED_TICKER: &str = "USDt";

/// The issuer domain the reserve asset's issuance contract carries.
pub const EXPECTED_ISSUER_DOMAIN: &str = "tether.to";

/// The reserve asset's precision: amounts are in units of 10⁻⁸.
pub const EXPECTED_PRECISION: u8 = 8;

/// Blockstream's Liquid mainnet asset registry, the first source for [`RESERVE_ASSET_ID`].
pub const REGISTRY_URL: &str = "https://assets.blockstream.info";

/// The issuer's page that names [`RESERVE_ASSET_ID`], the second source.
pub const ISSUER_SOURCE_URL: &str = "https://tether.to/en/supported-protocols";

/// [`RESERVE_ASSET_ID`] as an [`AssetId`].
///
/// ```
/// use sidestr_bridge_liquid::{reserve_asset, RESERVE_ASSET_ID};
/// assert_eq!(reserve_asset().to_string(), RESERVE_ASSET_ID);
/// ```
pub fn reserve_asset() -> AssetId {
    AssetId::from_str(RESERVE_ASSET_ID).expect("RESERVE_ASSET_ID is a valid asset id")
}

/// Refuses any asset other than the pinned reserve asset.
pub fn ensure_reserve_asset(asset: &AssetId) -> Result<()> {
    let expected = reserve_asset();
    if *asset == expected {
        Ok(())
    } else {
        Err(Error::NotReserveAsset {
            found: *asset,
            expected,
        })
    }
}

/// Checks a registry entry against the pin.
///
/// Recomputes the asset id from the entry's issuance prevout and contract
/// hash, requires it to equal [`RESERVE_ASSET_ID`], and requires the
/// contract's ticker, issuer domain and precision to be the expected ones.
/// Pure: the entry may come from [`fetch_registry_entry`] or from a file.
pub fn verify_registry_entry(entry: &RegistryData) -> Result<()> {
    let entropy = entry
        .entropy()
        .map_err(|e| Error::Registry(format!("contract hash: {e}")))?;
    let committed = AssetId::from_entropy(entropy);
    ensure_reserve_asset(&committed).map_err(|_| {
        Error::Registry(format!(
            "the contract and issuance prevout commit to {committed}, not {RESERVE_ASSET_ID}"
        ))
    })?;
    let mismatch = |field: &str, found: &dyn std::fmt::Display, want: &dyn std::fmt::Display| {
        Error::Registry(format!("{field} is {found}, expected {want}"))
    };
    if entry.ticker() != EXPECTED_TICKER {
        return Err(mismatch("ticker", &entry.ticker(), &EXPECTED_TICKER));
    }
    if entry.domain() != EXPECTED_ISSUER_DOMAIN {
        return Err(mismatch(
            "issuer domain",
            &entry.domain(),
            &EXPECTED_ISSUER_DOMAIN,
        ));
    }
    if entry.precision() != EXPECTED_PRECISION {
        return Err(mismatch(
            "precision",
            &entry.precision(),
            &EXPECTED_PRECISION,
        ));
    }
    Ok(())
}

/// Fetches the reserve asset's entry from [`REGISTRY_URL`] and verifies it
/// with [`verify_registry_entry`].
///
/// Network access; follows the process's proxy environment (see
/// [`crate::validate_proxy_url`]).
pub fn fetch_registry_entry() -> Result<RegistryData> {
    let registry = Registry::default_for_network(Network::Liquid)?;
    let entry = registry.fetch(reserve_asset())?;
    verify_registry_entry(&entry)?;
    Ok(entry)
}
