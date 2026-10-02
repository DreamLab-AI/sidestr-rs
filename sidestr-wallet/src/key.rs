//! Keys behind a port: the [`SpendSigner`] every builder signs through, a
//! plain-key implementation for tests and a CLI, the pubkey → script →
//! address chain, and the ADR-2101 spend-key derivation.
//!
//! siding holds one raw key that is at once Nostr identity, taproot spending
//! key and block-sealing key (`siding/lib/sign.mjs`, `~/.sidestr/<name>.key`).
//! ADR-2101 D3 separates them: the identity key never spends; a principal's
//! spend key for a chain is `derive_subkey(root, "sidestr/v1/spend/" ‖ genesis
//! ‖ epoch)`, a one-way HMAC-SHA256 derivation, so a leaked spend key reveals
//! neither its root nor a sibling. The builders in this crate never see a
//! secret: they take a `&dyn SpendSigner` and ask it for a signature over a
//! sighash they computed. [`PlainKey`] is the implementation that holds a
//! `SecretKey` in memory; an HSM, a remote signer or an identity port that
//! permits named operations only (ADR-2101's amendment) implements the same
//! two methods.
//!
//! ```
//! use bitcoin::secp256k1::SecretKey;
//! use sidestr_wallet::key::{address_for, derive_spend_key, script_for, PlainKey, SpendSigner};
//!
//! // a root the principal owns (in the estate: the session's own key, never k_id)
//! let root = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
//! let genesis = "0bdfdb3194f067d15b7a1cfa865de391b7ac00e1970863946d143e7329784402";
//! let spend = PlainKey::new(derive_spend_key(&root, genesis, 0).unwrap());
//!
//! // the same chain at a later epoch, or another chain, is another key
//! let later = PlainKey::new(derive_spend_key(&root, genesis, 1).unwrap());
//! assert_ne!(spend.pubkey(), later.pubkey());
//!
//! // x-only pubkey → `5120‖pubkey` → bech32m under the chain's prefix
//! let script = script_for(&spend.pubkey());
//! assert_eq!(script.len(), 34);
//! assert!(address_for(&spend.pubkey(), "trl").unwrap().starts_with("trl1p"));
//! ```

use bitcoin::key::{Keypair, XOnlyPublicKey};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{Message, SecretKey};
use bitcoin::ScriptBuf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sidestr_core::address::script_to_address;
use sidestr_core::block::{challenge_for, key_from_hex, secp};

use crate::error::{Error, Result};

/// What a builder needs from whoever holds the key: the x-only public key
/// (so it knows which coins are its and what the prevouts' scripts are) and
/// a BIP 340 signature over a 32-byte taproot key-path sighash.
///
/// The sighash is computed by the builder under the chain's family
/// ([`sidestr_core::sighash::key_path_sighash`]: BIP 341 with `SIGHASH_ALL`
/// beside stock Bitcoin, Knots' unified sighash beside BLAKE2b), and the
/// signer signs exactly that digest; the builder appends the hash type. A signer that wants to see what it
/// is signing gets the whole transaction through
/// [`SpendPolicy`](crate::policy::SpendPolicy) first; the port is narrow on
/// purpose (ADR-2101: "a generic sign-this-payload port is a bypass" —
/// this one signs taproot key-path sighashes for coins paying its own key
/// and nothing else).
pub trait SpendSigner {
    /// The x-only public key whose `5120‖key` script the wallet's coins pay.
    fn pubkey(&self) -> XOnlyPublicKey;
    /// Sign a taproot key-path sighash.
    fn sign_key_path(&self, sighash: &[u8; 32]) -> Result<Signature>;
    /// The output script this signer's coins pay: `OP_1 <32-byte key>`.
    fn script(&self) -> ScriptBuf {
        script_for(&self.pubkey())
    }
    /// Whether this key signs somewhere else, later: a browser extension
    /// behind `window.nostr.sidestr` (spec `proposals/browser-signer.md`),
    /// which computes the sighashes itself and signs only after the person
    /// confirms. When `true` a builder lays the transaction out and sizes it
    /// exactly as if signed, never calls [`sign_key_path`](Self::sign_key_path),
    /// and returns it with 65-byte placeholder witnesses;
    /// [`crate::external::accept_signed`] then takes the signed transaction
    /// back and verifies it. `false` for every in-memory key.
    fn signs_elsewhere(&self) -> bool {
        false
    }
}

/// A signer holding its secret key in memory: siding's model, for a test, a
/// faucet or a CLI whose key is a file. `Debug` prints no key material.
#[derive(Clone)]
pub struct PlainKey {
    key: SecretKey,
    keypair: Keypair,
}

impl core::fmt::Debug for PlainKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PlainKey")
            .field("pubkey", &self.pubkey())
            .finish_non_exhaustive()
    }
}

impl PlainKey {
    /// Wrap a secret key.
    pub fn new(key: SecretKey) -> Self {
        Self {
            key,
            keypair: Keypair::from_secret_key(secp(), &key),
        }
    }
    /// From the 32-byte hex a siding key file holds (`~/.sidestr/<name>.key`).
    /// Takes the file's *text*, as [`sidestr_core::block::key_from_hex`]
    /// does: the caller reads the file and nothing logs it.
    pub fn from_hex(text: &str) -> Result<Self> {
        Ok(Self::new(key_from_hex(text)?))
    }
    /// The secret, for a caller that also seals blocks with it (a test
    /// chain's signer that pays itself). Not for logging.
    pub fn secret_key(&self) -> &SecretKey {
        &self.key
    }
}

impl SpendSigner for PlainKey {
    fn pubkey(&self) -> XOnlyPublicKey {
        self.keypair.x_only_public_key().0
    }
    /// BIP 340 with zero auxiliary randomness, as `sidestr-core` seals
    /// blocks and siding seals the genesis: a spend is a pure function of its
    /// inputs and the key, so two wallets with the same key and coins make
    /// the same transaction. Valid BIP 340; only reproducibility differs.
    fn sign_key_path(&self, sighash: &[u8; 32]) -> Result<Signature> {
        Ok(secp().sign_schnorr_with_aux_rand(
            &Message::from_digest(*sighash),
            &self.keypair,
            &[0u8; 32],
        ))
    }
}

/// The output script a key's coins pay: `OP_1 <32-byte x-only key>`, the
/// same bytes as a single-signer chain's challenge (`spend.mjs`: `'5120' +
/// pub`).
pub fn script_for(pubkey: &XOnlyPublicKey) -> ScriptBuf {
    challenge_for(pubkey)
}

/// The key's address under a chain's `addressPrefix`, bech32m
/// (`siding/lib/address.mjs scriptToAddress`); `None` for a prefix bech32
/// cannot carry.
pub fn address_for(pubkey: &XOnlyPublicKey, hrp: &str) -> Option<String> {
    script_to_address(&script_for(pubkey), hrp)
}

/// The estate's keyed derivation (nostr-bbs-core `keys.rs derive_subkey`,
/// ADR-094): `HMAC-SHA256(key = root's 32 bytes, msg = utf8(tag))`, the
/// 32-byte output taken as a secp256k1 scalar. Byte-for-byte the JavaScript
/// `crypto.createHmac('sha256', root).update(tag, 'utf8').digest()`. One-way:
/// the child reveals neither the root nor a sibling. An error only if the
/// output is not a valid scalar, which is astronomically unlikely.
///
/// ```
/// use bitcoin::secp256k1::SecretKey;
/// use sidestr_wallet::key::derive_subkey;
///
/// // nostr-bbs-core's known-answer vector, cross-checked against Node.js
/// let root = SecretKey::from_slice(&[0x01u8; 32]).unwrap();
/// let child = derive_subkey(&root, "agentbox-mirror-v1").unwrap();
/// assert_eq!(hex::encode(child.secret_bytes()), "2d07f2ce93d0361687fdd81d2690082b5d6c35b93e3ece2d44bcf115ef8f695d");
/// ```
pub fn derive_subkey(root: &SecretKey, tag: &str) -> Result<SecretKey> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&root.secret_bytes())
        .map_err(|e| Error::Signer(format!("hmac: {e}")))?;
    mac.update(tag.as_bytes());
    let out = mac.finalize().into_bytes();
    Ok(SecretKey::from_slice(&out)?)
}

/// The derivation tag for a chain's spend key at an epoch (ADR-2101 D3):
/// `sidestr/v1/spend/<genesis hash, 64 lower hex>/<epoch, decimal>`. The
/// namespace carries the protocol version, the genesis (so a chain name
/// reused for a new genesis never reuses a key) and the epoch (rotation
/// without touching the root).
///
/// # The v1 tag is frozen
///
/// Every byte of this tag decides a key, and a key decides the address its
/// coins sit at. The bytes are pinned by known answers computed outside
/// Rust (`tests::spend_key_v1_known_answers`); a change to the prefix, the
/// separator, the case of the genesis or the spelling of the epoch fails
/// them. A different derivation is a new namespace (`sidestr/v2/…`) beside
/// this one, never a reinterpretation of `v1`: keys already derived, and
/// whatever they hold, must keep deriving.
///
/// # A departure, recorded (ADR-0001 D4)
///
/// This derivation is the estate's (ADR-2101 D3), not siding's, and gives a
/// key no reference function gives:
///
/// - siding at `e8deb63` holds one raw key that is at once identity,
///   spending and sealing key (`siding/lib/sign.mjs`); its `keys.mjs`
///   derives a chain of keys by **additive** tagged tweaks (`d + t`,
///   `P + t·G`), which anyone holding the public point can follow. ADR-2101
///   D3 prohibits an additive tweak for a role key, since one leaked role
///   key and the public tweak give back the root; this HMAC is one-way.
/// - agentbox's payment rail does not use it for agents either: since
///   ADR-2097 D3 as amended 2026-10-02, `management-api/lib/sidestr-spend-key.js`
///   mints an agent's `k_spend` from an independent random seed. Both kinds
///   of spend key are bound to the identity the same way, by a kind-38420
///   binding (`sidestr-nostr`'s `estate` module), so a payer never needs to
///   know which one it is paying.
pub fn spend_tag(genesis_hash: &str, epoch: u32) -> String {
    format!(
        "sidestr/v1/spend/{}/{epoch}",
        genesis_hash.trim().to_ascii_lowercase()
    )
}

/// A principal's spend key for one chain and epoch:
/// `derive_subkey(root, spend_tag(genesis, epoch))`. Never derive from the
/// identity key of a process every supervised program can read; the root
/// is the principal's own (ADR-2101's amendment).
///
/// Known answer, cross-checked against Node.js
/// (`crypto.createHmac('sha256', Buffer.alloc(32, 0x11)).update('sidestr/v1/spend/0bdfdb3194f067d15b7a1cfa865de391b7ac00e1970863946d143e7329784402/0').digest('hex')`):
///
/// ```
/// use bitcoin::secp256k1::SecretKey;
/// use sidestr_wallet::key::derive_spend_key;
///
/// let root = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
/// let k = derive_spend_key(&root, "0bdfdb3194f067d15b7a1cfa865de391b7ac00e1970863946d143e7329784402", 0).unwrap();
/// assert_eq!(hex::encode(k.secret_bytes()), "7ad4dc2caa20894f8e07dde385b293b8de7fe8b858d520239f5946ee567849f5");
/// ```
pub fn derive_spend_key(root: &SecretKey, genesis_hash: &str, epoch: u32) -> Result<SecretKey> {
    let g = genesis_hash.trim();
    if g.len() != 64 || !g.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Encoding(
            "a genesis hash is 32 bytes of hex".to_string(),
        ));
    }
    derive_subkey(root, &spend_tag(g, epoch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_key_signs_valid_schnorr() {
        let k = PlainKey::new(SecretKey::from_slice(&[7u8; 32]).unwrap());
        let digest = [0xabu8; 32];
        let sig = k.sign_key_path(&digest).unwrap();
        assert!(secp()
            .verify_schnorr(&sig, &Message::from_digest(digest), &k.pubkey())
            .is_ok());
        // deterministic: zero aux
        assert_eq!(sig, k.sign_key_path(&digest).unwrap());
        assert!(!format!("{k:?}").contains("0707"));
        assert_eq!(k.script().as_bytes()[..2], [0x51, 0x20]);
    }

    /// The v1 derivation, pinned: each answer was computed with Node.js
    /// (`crypto.createHmac('sha256', Buffer.from(root, 'hex')).update(tag,
    /// 'utf8').digest('hex')`, and the public key with nostr-tools
    /// `getPublicKey`), never by this crate. A change to any byte of the
    /// tag fails here.
    #[test]
    fn spend_key_v1_known_answers() {
        // the tag's exact bytes: "sidestr/v1/spend/" ‖ lower-hex genesis ‖ "/" ‖ decimal epoch
        const PREFIX_HEX: &str = "736964657374722f76312f7370656e642f";
        let dreamlab = "4db37517728bd509c0cb96ee5a2e3e2a77f9e965a092e9f67948b413d453dbc0";
        let tag = spend_tag(&dreamlab.to_uppercase(), 7);
        assert_eq!(
            hex::encode(tag.as_bytes()),
            format!("{PREFIX_HEX}{}2f37", hex::encode(dreamlab.as_bytes()))
        );
        assert_eq!(tag, format!("sidestr/v1/spend/{dreamlab}/7"));

        // (seed, genesis hash, epoch) -> spend secret, x-only spend pubkey
        let cases: [(u8, &str, u32, &str, &str); 3] = [
            (
                0x11,
                "0bdfdb3194f067d15b7a1cfa865de391b7ac00e1970863946d143e7329784402",
                0,
                "7ad4dc2caa20894f8e07dde385b293b8de7fe8b858d520239f5946ee567849f5",
                "a00244208bb28dc03ccc31bd4854017be3d4efdce80643d47f2ed2320a6d11b3",
            ),
            (
                0x42,
                dreamlab,
                7,
                "aacf814dcb4c2a3a20a8da1f5b6ee95d1e09f8946f08640387dbc6cce0e5ed78",
                "b81330f4106e959b337c761897fee6f49f84930ac84c927f8d2adadc0047b05c",
            ),
            (
                0x42,
                dreamlab,
                u32::MAX,
                "86196f4fd57bf53623108cc034380eac239690d9b8e2ad469620cb7df8be1aed",
                "",
            ),
        ];
        for (seed, genesis, epoch, secret, pubkey) in cases {
            let root = SecretKey::from_slice(&[seed; 32]).unwrap();
            let k = derive_spend_key(&root, genesis, epoch).unwrap();
            assert_eq!(hex::encode(k.secret_bytes()), secret, "{seed:#x} {epoch}");
            // the same answer through the bare HMAC over the literal tag bytes
            let tag = format!("sidestr/v1/spend/{genesis}/{epoch}");
            assert_eq!(derive_subkey(&root, &tag).unwrap(), k);
            if !pubkey.is_empty() {
                assert_eq!(PlainKey::new(k).pubkey().to_string(), pubkey);
            }
        }
    }

    #[test]
    fn derivation_separates_domains() {
        let root = SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        let g = "a".repeat(64);
        let a = derive_spend_key(&root, &g, 0).unwrap();
        let b = derive_spend_key(&root, &g, 1).unwrap();
        let c = derive_spend_key(&root, &"b".repeat(64), 0).unwrap();
        assert_ne!(a.secret_bytes(), b.secret_bytes());
        assert_ne!(a.secret_bytes(), c.secret_bytes());
        assert_ne!(a.secret_bytes(), root.secret_bytes());
        assert_eq!(
            a.secret_bytes(),
            derive_spend_key(&root, &g.to_uppercase(), 0)
                .unwrap()
                .secret_bytes()
        );
        assert!(derive_spend_key(&root, "abc", 0).is_err());
        assert_eq!(spend_tag(&g, 3), format!("sidestr/v1/spend/{g}/3"));
    }
}
