//! `sidestr-bridge-liquid`: the Liquid reserve for the owner's private USD
//! unit of account on a sidestr chain, on the light option (ADR-2117 and its
//! amendment of 2026-09-23).
//!
//! > **Private USD unit of account of the owner's estate. No value, not
//! > redeemable, not offered to anyone. Not USD₮ or USDC and not issued,
//! > backed or endorsed by Tether or Circle. Not live: nothing is funded, and
//! > the reserve is funded only on the owner's explicit go.**
//!
//! The unit is minted on a sidestr chain by a `bridge` rule that checks
//! *circulating + pending ≤ attested reserve*. This crate is the reserve
//! side of that check:
//!
//! | item | what |
//! |---|---|
//! | [`ReserveKey`] | the BIP-39 mnemonic in a file outside every repository: created mode 0400, never overwritten, never printed |
//! | [`ReserveWallet`] | a watch-only Liquid Wallet Kit wallet from the key's CT descriptor: addresses, sync from a public Esplora server, balances |
//! | [`RESERVE_ASSET_ID`], [`verify_registry_entry`] | the reserve asset, pinned from primary sources and checked against its issuance contract |
//! | [`attest()`], [`credits`], [`origin`] | the Liquid reading of the reserve: which outputs count, keyed by outpoint, as a [`ReserveAttestation`] |
//!
//! The attestation itself (canonical JSON, SHA-256 digest, the BIP-340
//! [`AttestationSigner`] hook and [`SignedAttestation`]) is the
//! origin-neutral [`sidestr_reserve`] crate's, re-exported here: a `bridge`
//! rule checks the same statement whichever network holds the reserve, and
//! this crate is the Liquid origin adapter that produces it.
//!
//! Everything chain-facing is Blockstream's Liquid Wallet Kit
//! (`lwk_wollet`, `lwk_signer`, `lwk_common` 0.19, `MIT OR BSD-2-Clause`):
//! descriptors, derivation, unblinding, Esplora sync, the registry client.
//! Signatures are libsecp256k1's BIP-340 through the `secp256k1` crate LWK
//! re-exports. Nothing cryptographic is implemented here.
//!
//! The trust basis of an attestation on the light option, and what an own
//! Liquid node changes, is set out in the [`attest`](mod@attest) module.
//!
//! # From a key to an attestation, offline
//!
//! ```
//! use std::str::FromStr;
//! use lwk_wollet::elements::{BlockHash, OutPoint};
//! use sidestr_bridge_liquid::{
//!     attest, reserve_asset, ChainTip, ReserveKey, ReserveSnapshot, ReserveUtxo, ReserveWallet,
//! };
//!
//! // The BIP-39 test mnemonic: never a real reserve key.
//! let key = ReserveKey::from_phrase(
//!     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
//! )?;
//! let wallet = ReserveWallet::new(key.descriptor()?)?;
//! assert!(wallet.address(Some(0))?.to_string().starts_with("lq1"));
//!
//! // A snapshot as a synced wallet would report it.
//! let state = ReserveSnapshot {
//!     tip: ChainTip {
//!         height: 100,
//!         hash: BlockHash::from_str(&"11".repeat(32)).unwrap(),
//!     },
//!     utxos: vec![ReserveUtxo {
//!         outpoint: OutPoint::from_str(&format!("{}:0", "22".repeat(32))).unwrap(),
//!         asset: reserve_asset(),
//!         value: 25_0000_0000,
//!         height: Some(99),
//!     }],
//!     source: "https://blockstream.info/liquid/api".into(),
//! };
//! let attestation = attest(&state, &reserve_asset(), 1_790_000_000)?;
//! assert_eq!(attestation.amount, 25_0000_0000);
//! assert_eq!(attestation.origin.network(), "liquid");
//! assert_eq!(attestation.digest(), attest(&state, &reserve_asset(), 1_790_000_000)?.digest());
//! # Ok::<(), sidestr_bridge_liquid::Error>(())
//! ```
//!
//! It is AGPL-3.0-only like its `sidestr-*` siblings and unpublished
//! (`publish = false`): a project-specific construction, private to this
//! repository.

#![deny(missing_docs)]

#[cfg(not(unix))]
compile_error!(
    "sidestr-bridge-liquid writes its key file with Unix permissions and supports Unix only"
);

mod asset;
pub mod attest;
mod error;
mod key;
mod wallet;

pub use asset::{
    ensure_reserve_asset, fetch_registry_entry, reserve_asset, verify_registry_entry,
    EXPECTED_ISSUER_DOMAIN, EXPECTED_PRECISION, EXPECTED_TICKER, ISSUER_SOURCE_URL, REGISTRY_URL,
    RESERVE_ASSET_ID,
};
pub use attest::{attest, credits, origin, ChainTip, ReserveSnapshot, ReserveUtxo, NETWORK};
pub use error::{Error, Result};
pub use key::{ReserveKey, KEY_FILE_MODE, MNEMONIC_WORDS};
pub use sidestr_reserve::{
    verify_digest, AttestationDigest, AttestationSigner, KeypairSigner, ReserveAttestation,
    SignedAttestation, ATTESTATION_TYPE,
};
pub use wallet::{validate_proxy_url, ReserveWallet, DEFAULT_ESPLORA_URL, REQUEST_TIMEOUT_SECS};
