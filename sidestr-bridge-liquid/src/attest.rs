//! The reserve attestation: what the reserve wallet held, at which Liquid
//! tip, in a canonical form with a digest a key can sign.
//!
//! This is the statement the sidestr `bridge` rule will check against its own
//! books: *circulating + pending ≤ attested reserve* (ADR-2117 decision 4,
//! ADR-2102). The rule sees only the attestation and its signature, so the
//! attestation has to be byte-for-byte reproducible from the same wallet
//! state: [`ReserveAttestation::canonical_json`] is JSON with keys sorted,
//! no whitespace, amounts as decimal strings (so a JavaScript validator reads
//! them exactly), and outpoints sorted.
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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use lwk_wollet::elements::{AssetId, BlockHash, OutPoint};
use lwk_wollet::secp256k1::{schnorr, Keypair, Message, Secp256k1, XOnlyPublicKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::asset::ensure_reserve_asset;
use crate::error::{Error, Result};

/// The `type` field of every attestation: names the format and its version,
/// and, because it is inside the digested bytes, separates this digest from
/// any other SHA-256 the same key might sign.
pub const ATTESTATION_TYPE: &str = "sidestr-bridge-liquid/reserve-attestation/v1";

/// The `network` field: the attestation is about Liquid mainnet.
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

/// What the reserve held: a reserve-asset total and the outputs it is made of.
///
/// Built only by [`attest`]. Serialise it with
/// [`canonical_json`](Self::canonical_json) and digest it with
/// [`digest`](Self::digest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveAttestation {
    /// The reserve asset (always the pinned [`crate::RESERVE_ASSET_ID`]).
    pub asset_id: AssetId,
    /// Sum of the listed outputs, in the asset's base units.
    pub amount_sats: u64,
    /// The confirmed reserve outputs, as `txid:vout`, sorted.
    pub reserve_outpoints: Vec<OutPoint>,
    /// Height of the Liquid tip the state was read at.
    pub liquid_tip_height: u32,
    /// Hash of that tip.
    pub liquid_tip_hash: BlockHash,
    /// When the attestation was made, Unix seconds.
    pub time: u64,
    /// The server the wallet state came from; see the module's trust basis.
    pub source: String,
}

/// Attests the reserve held in `state`.
///
/// Pure: the same snapshot, asset and time give the same attestation, and
/// the same bytes. Counts only outputs of `asset` that are **confirmed** at
/// or below the snapshot's tip; unconfirmed outputs are not reserve yet.
/// Outputs of other assets (L-BTC for fees, anything sent unasked) are
/// ignored.
///
/// Refuses any `asset` other than the pinned reserve asset, a snapshot that
/// lists one outpoint twice, and a total that overflows `u64`. A zero
/// reserve is a valid statement; the `bridge` rule is what refuses to mint
/// against it.
///
/// `time` is a parameter, not read from the clock, to keep this pure.
pub fn attest(state: &ReserveSnapshot, asset: &AssetId, time: u64) -> Result<ReserveAttestation> {
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
    let mut reserve: Vec<&ReserveUtxo> = state
        .utxos
        .iter()
        .filter(|u| u.asset == *asset)
        .filter(|u| u.height.is_some_and(|h| h <= state.tip.height))
        .collect();
    reserve.sort_by_key(|u| u.outpoint);
    let amount_sats = reserve
        .iter()
        .try_fold(0u64, |acc, u| acc.checked_add(u.value))
        .ok_or_else(|| Error::State("reserve total overflows u64".into()))?;
    Ok(ReserveAttestation {
        asset_id: *asset,
        amount_sats,
        reserve_outpoints: reserve.iter().map(|u| u.outpoint).collect(),
        liquid_tip_height: state.tip.height,
        liquid_tip_hash: state.tip.hash,
        time,
        source: state.source.clone(),
    })
}

impl ReserveAttestation {
    /// The canonical serialisation: compact JSON, keys in byte order,
    /// `amount_sats` and `time` as decimal strings, outpoints sorted.
    ///
    /// Keys: `amount_sats`, `asset_id`, `liquid_tip_hash`,
    /// `liquid_tip_height`, `network`, `reserve_outpoints`, `source`, `time`,
    /// `type`. Every value is a string, a number below 2⁵³ or an array of
    /// strings, so any JSON implementation reproduces the bytes.
    pub fn canonical_json(&self) -> String {
        let mut map: BTreeMap<&str, Value> = BTreeMap::new();
        map.insert("amount_sats", Value::String(self.amount_sats.to_string()));
        map.insert("asset_id", Value::String(self.asset_id.to_string()));
        map.insert(
            "liquid_tip_hash",
            Value::String(self.liquid_tip_hash.to_string()),
        );
        map.insert("liquid_tip_height", Value::from(self.liquid_tip_height));
        map.insert("network", Value::String(NETWORK.into()));
        let mut outpoints: Vec<String> = self
            .reserve_outpoints
            .iter()
            .map(|o| format!("{}:{}", o.txid, o.vout))
            .collect();
        outpoints.sort();
        map.insert(
            "reserve_outpoints",
            Value::Array(outpoints.into_iter().map(Value::String).collect()),
        );
        map.insert("source", Value::String(self.source.clone()));
        map.insert("time", Value::String(self.time.to_string()));
        map.insert("type", Value::String(ATTESTATION_TYPE.into()));
        // A BTreeMap serialises in key order whatever serde_json's features.
        serde_json::to_string(&map).expect("a map of strings and numbers serialises")
    }

    /// SHA-256 of [`canonical_json`](Self::canonical_json)'s UTF-8 bytes.
    pub fn digest(&self) -> AttestationDigest {
        AttestationDigest(Sha256::digest(self.canonical_json().as_bytes()).into())
    }
}

/// The 32-byte SHA-256 digest of an attestation's canonical bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttestationDigest(pub [u8; 32]);

impl fmt::Display for AttestationDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

/// The signing hook: whatever holds the attestation key.
///
/// The signature is BIP-340 Schnorr over the 32-byte digest, the scheme
/// sidestr's taproot keys and Nostr events already use, so the key can be
/// the authority-coin key pinned in the chain document (ADR-2117 decision 4).
/// How the signed attestation travels (a Nostr event, or a digest in the
/// authority-coin spend's witness) is ADR-2117 decision (c) and not fixed
/// here. Nothing in this crate wires a real key: the `usd-reserve` binary
/// never signs.
pub trait AttestationSigner {
    /// The x-only public key signatures verify against.
    fn x_only_public_key(&self) -> XOnlyPublicKey;

    /// A BIP-340 signature over `digest`.
    fn sign_digest(&self, digest: &AttestationDigest) -> Result<schnorr::Signature>;
}

/// An [`AttestationSigner`] over an in-memory secp256k1 key pair.
///
/// Signs deterministically (BIP-340 with no auxiliary randomness), which is
/// what makes signatures reproducible in tests. It holds whatever key it is
/// given; the crate's tests give it a test key.
pub struct KeypairSigner {
    keypair: Keypair,
}

impl KeypairSigner {
    /// A signer over `keypair`.
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }
}

impl fmt::Debug for KeypairSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeypairSigner")
            .field("public_key", &self.keypair.x_only_public_key().0)
            .finish_non_exhaustive()
    }
}

impl AttestationSigner for KeypairSigner {
    fn x_only_public_key(&self) -> XOnlyPublicKey {
        self.keypair.x_only_public_key().0
    }

    fn sign_digest(&self, digest: &AttestationDigest) -> Result<schnorr::Signature> {
        let msg = Message::from_digest(digest.0);
        Ok(Secp256k1::signing_only().sign_schnorr_no_aux_rand(&msg, &self.keypair))
    }
}

/// An attestation, its digest and a signature over the digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAttestation {
    /// The attestation.
    pub attestation: ReserveAttestation,
    /// Its digest, as signed.
    pub digest: AttestationDigest,
    /// The key that signed.
    pub public_key: XOnlyPublicKey,
    /// BIP-340 signature over `digest`.
    pub signature: schnorr::Signature,
}

impl SignedAttestation {
    /// Signs `attestation` with `signer`, and checks the signature before
    /// returning it, so a faulty signer cannot hand back a dud.
    pub fn sign(attestation: ReserveAttestation, signer: &dyn AttestationSigner) -> Result<Self> {
        let digest = attestation.digest();
        let signed = Self {
            signature: signer.sign_digest(&digest)?,
            public_key: signer.x_only_public_key(),
            digest,
            attestation,
        };
        signed.verify().map_err(|_| {
            Error::Signing("the signer returned a signature that does not verify".into())
        })?;
        Ok(signed)
    }

    /// Verifies: the digest is the attestation's digest, and the signature
    /// is a valid BIP-340 signature over it by `public_key`.
    pub fn verify(&self) -> Result<()> {
        if self.attestation.digest() != self.digest {
            return Err(Error::BadSignature);
        }
        verify_digest(&self.digest, &self.signature, &self.public_key)
    }
}

/// Verifies a BIP-340 signature over a 32-byte digest.
pub fn verify_digest(
    digest: &AttestationDigest,
    signature: &schnorr::Signature,
    public_key: &XOnlyPublicKey,
) -> Result<()> {
    Secp256k1::verification_only()
        .verify_schnorr(signature, &Message::from_digest(digest.0), public_key)
        .map_err(|_| Error::BadSignature)
}
