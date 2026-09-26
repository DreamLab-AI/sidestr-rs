//! `sidestr-reserve`: the reserve attestation a sidestr `bridge` rule checks,
//! independent of the network the reserve sits on (ADR-2117).
//!
//! > **Private USD unit of account of the owner's estate. No value, not
//! > redeemable, not offered to anyone. Not USD₮ or USDC and not issued,
//! > backed or endorsed by Tether or Circle. Not live.**
//!
//! A `bridge` rule mints a wrapped unit only while *circulating + pending ≤
//! attested reserve* (ADR-2117 decision 4, ADR-2102). What it checks is a
//! signed statement of what a reserve held. This crate is that statement,
//! and nothing about any particular reserve network: an **origin adapter**
//! (`sidestr-bridge-liquid` for Liquid; a TRON or EVM adapter later) reads
//! its own network and hands this crate the numbers.
//!
//! | item | what |
//! |---|---|
//! | [`Origin`] | which reserve: the network, the asset on it, its decimals |
//! | [`Tip`] | the origin block the reading is final at |
//! | [`Credit`] | one inbound credit the reserve holds, under the id the rule keys replays by |
//! | [`attest()`], [`ReserveAttestation`] | the statement, canonical JSON and its SHA-256 |
//! | [`AttestationSigner`], [`SignedAttestation`] | the BIP-340 signing hook and its verification |
//!
//! # What an adapter must supply
//!
//! 1. **Holdings at a final tip.** Only credits the origin treats as final
//!    at `tip` (confirmed to the chain document's `bridgeConfirmations`, or
//!    solidified), of the reserve asset only.
//! 2. **Replay-stable credit ids.** The id the `bridge` rule's `bmint` is
//!    keyed by: an outpoint (`txid:vout`) on a UTXO network, a
//!    `txid:log_index` of the token's transfer event on an account network.
//!    Unique within the attestation, the same across readings and reorgs.
//! 3. **A named source.** Whose view of the origin the reading came from
//!    (a public server or an own node), so the trust basis travels with the
//!    statement.
//!
//! How funds leave the reserve (the release) is the adapter's too, behind
//! the ADR-2100 authority gate; this crate only states holdings.
//!
//! ```
//! use sidestr_reserve::{attest, Credit, Origin, Tip};
//!
//! let origin = Origin::new("liquid", &"ce".repeat(32), 8)?;
//! let tip = Tip::new(4_070_000, &"ab".repeat(32))?;
//! let credits = vec![
//!     Credit::new(&format!("{}:1", "cc".repeat(32)), 10_0000_0000)?,
//!     Credit::new(&format!("{}:0", "aa".repeat(32)), 15_0000_0000)?,
//! ];
//! let a = attest(origin, tip, &credits, "https://blockstream.info/liquid/api", 1_790_000_000)?;
//! assert_eq!(a.amount, 25_0000_0000);
//! assert!(a.canonical_json().starts_with(r#"{"amount":"2500000000","asset":"#));
//! # Ok::<(), sidestr_reserve::Error>(())
//! ```
//!
//! It is AGPL-3.0-only like its `sidestr-*` siblings and unpublished
//! (`publish = false`): a project-specific signed format, private to this
//! repository.

#![deny(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use secp256k1::{schnorr, Keypair, Message, Secp256k1, XOnlyPublicKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub use secp256k1;

/// The `type` field of every attestation: names the format and its version,
/// and, because it is inside the digested bytes, separates this digest from
/// any other SHA-256 the same key might sign.
pub const ATTESTATION_TYPE: &str = "sidestr-reserve/attestation/v1";

/// The largest integer a JSON number carries exactly in every
/// implementation (2⁵³ − 1). Heights above it are refused.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// The most decimals an origin asset may declare (EVM tokens use up to 18).
pub const MAX_DECIMALS: u8 = 18;

/// Everything that can go wrong making or checking an attestation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A field is not in the form the canonical bytes require.
    #[error("{field}: {reason}")]
    Field {
        /// The field.
        field: &'static str,
        /// What is wrong with it.
        reason: String,
    },

    /// The credits are not a set an attestation can be made from.
    #[error("credits: {0}")]
    Credits(String),

    /// The signing hook failed.
    #[error("signing: {0}")]
    Signing(String),

    /// A signed attestation does not verify against its public key.
    #[error("attestation signature does not verify")]
    BadSignature,
}

/// The crate's result type.
pub type Result<T> = std::result::Result<T, Error>;

fn field(field: &'static str, reason: impl Into<String>) -> Error {
    Error::Field {
        field,
        reason: reason.into(),
    }
}

/// An identifier the canonical bytes carry verbatim: non-empty, at most
/// 128 bytes, lower-case ASCII letters, digits and `:._-` only. That keeps
/// every implementation's JSON escaping out of the digest.
fn check_ident(name: &'static str, s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 128 {
        return Err(field(name, "must be 1 to 128 bytes"));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b":._-".contains(&b))
    {
        return Err(field(name, format!("{s:?} is not lower-case [a-z0-9:._-]")));
    }
    Ok(())
}

/// Which reserve: the network it sits on, the asset on that network, and
/// the asset's decimals.
///
/// `network` names the origin (`liquid`, `tron`, `eth`, `arbitrum`, …) and
/// `asset` the reserve asset in that network's own lower-case form (a
/// Liquid asset id, a token contract address). The pair is what a chain
/// document pins, and a `bridge` rule refuses an attestation for any other.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Origin {
    network: String,
    asset: String,
    decimals: u8,
}

impl Origin {
    /// An origin, checked: both identifiers lower-case `[a-z0-9:._-]`,
    /// decimals at most [`MAX_DECIMALS`].
    pub fn new(network: &str, asset: &str, decimals: u8) -> Result<Self> {
        check_ident("network", network)?;
        check_ident("asset", asset)?;
        if decimals > MAX_DECIMALS {
            return Err(field(
                "decimals",
                format!("{decimals} is above {MAX_DECIMALS}"),
            ));
        }
        Ok(Self {
            network: network.to_owned(),
            asset: asset.to_owned(),
            decimals,
        })
    }

    /// The origin network.
    pub fn network(&self) -> &str {
        &self.network
    }

    /// The reserve asset on it.
    pub fn asset(&self) -> &str {
        &self.asset
    }

    /// The asset's decimals: how many base units make one unit.
    pub fn decimals(&self) -> u8 {
        self.decimals
    }
}

/// The origin block a reading is final at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tip {
    height: u64,
    hash: String,
}

impl Tip {
    /// A tip, checked: height at most [`MAX_SAFE_INTEGER`], hash 64
    /// lower-case hex characters without a `0x` prefix, in the order the
    /// origin's own explorers display it.
    pub fn new(height: u64, hash: &str) -> Result<Self> {
        if height > MAX_SAFE_INTEGER {
            return Err(field("tip_height", "above 2^53 - 1"));
        }
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(field(
                "tip_hash",
                "must be 64 lower-case hex characters, no 0x",
            ));
        }
        Ok(Self {
            height,
            hash: hash.to_owned(),
        })
    }

    /// The block height.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// The block hash, lower-case hex.
    pub fn hash(&self) -> &str {
        &self.hash
    }
}

/// One inbound credit the reserve holds, as its adapter read it.
///
/// `id` is the key the `bridge` rule refuses to mint against twice: an
/// outpoint (`txid:vout`) on a UTXO origin, `txid:log_index` on an account
/// origin. `amount` is in the asset's base units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credit {
    id: String,
    amount: u128,
}

impl Credit {
    /// A credit, checked: `id` lower-case `[a-z0-9:._-]`, 1 to 128 bytes.
    pub fn new(id: &str, amount: u128) -> Result<Self> {
        check_ident("credit id", id)?;
        Ok(Self {
            id: id.to_owned(),
            amount,
        })
    }

    /// The replay key.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The amount, in base units.
    pub fn amount(&self) -> u128 {
        self.amount
    }
}

/// What a reserve held: the total, the credits it is made of, the origin
/// tip it was read at, when and from where.
///
/// Built only by [`attest`]. Serialise it with
/// [`canonical_json`](Self::canonical_json) and digest it with
/// [`digest`](Self::digest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveAttestation {
    /// Which reserve.
    pub origin: Origin,
    /// Sum of the credits, in the asset's base units.
    pub amount: u128,
    /// The credit ids, sorted.
    pub credits: Vec<String>,
    /// The origin tip the reading is final at.
    pub tip: Tip,
    /// When the attestation was made, Unix seconds.
    pub time: u64,
    /// Whose view of the origin the reading came from.
    pub source: String,
}

/// Attests that the reserve at `origin` held `credits` at `tip`.
///
/// Pure: the same inputs give the same attestation and the same bytes,
/// whatever the order of `credits`. The adapter has already kept only final
/// credits of the reserve asset. A credit id listed twice is refused, as is
/// a total that overflows `u128`, a `time` above [`MAX_SAFE_INTEGER`] and
/// an empty or multi-line `source`. A zero reserve is a valid statement;
/// the `bridge` rule is what refuses to mint against it.
///
/// `time` is a parameter, not read from the clock, to keep this pure.
pub fn attest(
    origin: Origin,
    tip: Tip,
    credits: &[Credit],
    source: &str,
    time: u64,
) -> Result<ReserveAttestation> {
    if source.is_empty() || source.len() > 256 || !source.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(field(
            "source",
            "must be 1 to 256 printable ASCII bytes, no spaces",
        ));
    }
    if time > MAX_SAFE_INTEGER {
        return Err(field("time", "above 2^53 - 1"));
    }
    let mut ids = BTreeSet::new();
    let mut amount = 0u128;
    for c in credits {
        if !ids.insert(c.id.clone()) {
            return Err(Error::Credits(format!("{} is listed twice", c.id)));
        }
        amount = amount
            .checked_add(c.amount)
            .ok_or_else(|| Error::Credits("total overflows u128".into()))?;
    }
    Ok(ReserveAttestation {
        origin,
        amount,
        credits: ids.into_iter().collect(),
        tip,
        time,
        source: source.to_owned(),
    })
}

impl ReserveAttestation {
    /// The canonical serialisation: compact JSON, keys in byte order,
    /// `amount` and `time` as decimal strings, credits sorted.
    ///
    /// Keys: `amount`, `asset`, `credits`, `decimals`, `network`, `source`,
    /// `time`, `tip_hash`, `tip_height`, `type`. Every value is a string of
    /// printable ASCII needing no escape, a number below 2⁵³ or an array of
    /// such strings, so any JSON implementation reproduces the bytes.
    pub fn canonical_json(&self) -> String {
        let mut map: BTreeMap<&str, Value> = BTreeMap::new();
        map.insert("amount", Value::String(self.amount.to_string()));
        map.insert("asset", Value::String(self.origin.asset.clone()));
        let mut credits = self.credits.clone();
        credits.sort();
        map.insert(
            "credits",
            Value::Array(credits.into_iter().map(Value::String).collect()),
        );
        map.insert("decimals", Value::from(self.origin.decimals));
        map.insert("network", Value::String(self.origin.network.clone()));
        map.insert("source", Value::String(self.source.clone()));
        map.insert("time", Value::String(self.time.to_string()));
        map.insert("tip_hash", Value::String(self.tip.hash.clone()));
        map.insert("tip_height", Value::from(self.tip.height));
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
/// The key signs attestations for every origin the chain pins; the
/// `network` and `asset` inside the digest keep one origin's statement from
/// standing for another's.
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
/// given; the tests give it a test key.
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
