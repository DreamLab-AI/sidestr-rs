//! The watch-only reserve wallet and its sync against a public Esplora server.

use std::collections::BTreeMap;

use lwk_wollet::clients::blocking::BlockchainBackend;
use lwk_wollet::clients::EsploraClientBuilder;
use lwk_wollet::elements::{Address, AssetId};
use lwk_wollet::{Network, Wollet, WolletBuilder, WolletDescriptor};

use crate::attest::{ChainTip, ReserveSnapshot, ReserveUtxo};
use crate::error::{Error, Result};

/// Blockstream's public Liquid mainnet Esplora API: the light option's server.
pub const DEFAULT_ESPLORA_URL: &str = "https://blockstream.info/liquid/api";

/// Seconds before one Esplora request gives up.
pub const REQUEST_TIMEOUT_SECS: u8 = 30;

/// The reserve wallet: a watch-only LWK wallet on Liquid mainnet.
///
/// Built from the CT descriptor alone, so it can derive addresses, unblind
/// what it receives and report balances, and cannot spend. State lives in
/// memory; every process syncs from scratch, which for a reserve of a few
/// outputs is a handful of requests.
pub struct ReserveWallet {
    wollet: Wollet,
    source: Option<String>,
}

impl ReserveWallet {
    /// A wallet for `descriptor` on Liquid mainnet, not yet synced.
    pub fn new(descriptor: WolletDescriptor) -> Result<Self> {
        Ok(Self {
            wollet: WolletBuilder::new(Network::Liquid, descriptor).build()?,
            source: None,
        })
    }

    /// The CT descriptor, with checksum. Holds the blinding key; see
    /// [`crate::ReserveKey::descriptor`].
    pub fn descriptor(&self) -> String {
        self.wollet.wollet_descriptor().to_string()
    }

    /// The confidential receive address at `index` on the external chain,
    /// or, with `None`, the first one the wallet has not seen used (index 0
    /// until a sync finds history).
    pub fn address(&self, index: Option<u32>) -> Result<Address> {
        Ok(self.wollet.address(index)?.address().clone())
    }

    /// Syncs the wallet from the Esplora API at `esplora_url`.
    ///
    /// A full scan to the BIP-44 gap limit on both chains. The server learns
    /// the wallet's scripts and the query times. The HTTP client takes its
    /// proxy from the environment (`HTTPS_PROXY` / `ALL_PROXY`); the
    /// `usd-reserve` binary sets those from `--proxy`.
    pub fn sync(&mut self, esplora_url: &str) -> Result<()> {
        let mut client = EsploraClientBuilder::new(esplora_url, Network::Liquid)
            .timeout(REQUEST_TIMEOUT_SECS)
            .build_blocking()?;
        if let Some(update) = client.full_scan(&self.wollet)? {
            self.wollet.apply_update(update)?;
        }
        self.source = Some(esplora_url.to_owned());
        Ok(())
    }

    /// The Liquid policy asset (L-BTC).
    pub fn policy_asset(&self) -> AssetId {
        self.wollet.policy_asset()
    }

    /// Unspent balance per asset, in base units, confirmed and unconfirmed.
    ///
    /// Only assets the wallet holds: LWK always reports the policy asset,
    /// at zero if need be, and zero entries are dropped here, so an empty
    /// map means an empty wallet.
    pub fn balance(&self) -> Result<BTreeMap<AssetId, u64>> {
        Ok(self
            .wollet
            .balance()?
            .iter()
            .filter(|(_, amount)| **amount > 0)
            .map(|(asset, amount)| (*asset, *amount))
            .collect())
    }

    /// The wallet state an attestation is made from: the tip it synced to
    /// and every unspent output it can unblind.
    ///
    /// Fails if the wallet has not been synced.
    pub fn snapshot(&self) -> Result<ReserveSnapshot> {
        let source = self
            .source
            .clone()
            .ok_or_else(|| Error::State("the wallet has not been synced".into()))?;
        let tip = self.wollet.tip();
        let utxos = self
            .wollet
            .utxos()?
            .into_iter()
            .map(|u| ReserveUtxo {
                outpoint: u.outpoint,
                asset: u.unblinded.asset,
                value: u.unblinded.value,
                height: u.height,
            })
            .collect();
        Ok(ReserveSnapshot {
            tip: ChainTip {
                height: tip.height(),
                hash: tip.hash(),
            },
            utxos,
            source,
        })
    }
}

/// Checks a proxy URL before the binary routes all traffic through it.
///
/// Accepts `socks5h://` (names resolved by the proxy, as Tor needs) and
/// `http://` / `https://` proxies. Refuses `socks5://`, whose client-side
/// name resolution would leak every lookup outside the proxy, and anything
/// else.
///
/// ```
/// use sidestr_bridge_liquid::validate_proxy_url;
/// assert!(validate_proxy_url("socks5h://127.0.0.1:9050").is_ok());
/// assert!(validate_proxy_url("socks5://127.0.0.1:9050").is_err());
/// ```
pub fn validate_proxy_url(url: &str) -> Result<()> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| Error::Proxy(format!("{url} has no scheme")))?;
    match scheme {
        "socks5h" | "http" | "https" if !rest.is_empty() => Ok(()),
        "socks5h" | "http" | "https" => Err(Error::Proxy(format!("{url} has no host"))),
        "socks5" => Err(Error::Proxy(
            "socks5:// resolves names outside the proxy; use socks5h://".into(),
        )),
        other => Err(Error::Proxy(format!("unsupported proxy scheme {other}"))),
    }
}
