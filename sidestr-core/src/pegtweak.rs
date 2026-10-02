//! The peg-in tweak form (SPEC 6, sidestr/spec issue #23): the peg output
//! commits to its destination in the taproot tree instead of an `OP_RETURN`
//! beside it. A port of `siding/lib/pegtweak.mjs` (sidestr/spec `4c4915f`,
//! Melvin Carvalho, AGPL-3.0), on top of [`crate::keys`].
//!
//! The output is BIP 341 exactly, so a parent wallet, a descriptor or a
//! hardware wallet reproduces it from the internal key and the tree:
//!
//! | part | what |
//! |---|---|
//! | internal key | the peg holders' point `P` (level 1: the signer's key), used as its even-y lift |
//! | refund leaf | `and_v(v:pk(refund), older(refundBlocks))`: the pegger's way back if never claimed |
//! | commit leaf | `pk(C)`, `C = NUMS + t·G`, `t = tagged("sidestr/peg-in", chainHash ‖ sha256(script))`: an unspendable key that commits to the chain (its hash, SPEC 3) and the sidechain output script, written as `pk()` so a wallet policy accepts it |
//! | output | `Q = P + TapTweak(x(P) ‖ root)·G`, `root` the tree of those leaves (and, at level 2, the challenge's `multi_a` leaf, so the holders spend by script as they do today) |
//!
//! Anyone with the reveal (internal key, refund key and blocks, chain hash,
//! script) rebuilds the output and checks it against the parent transaction;
//! two chains give two outputs from one key.
//!
//! The **chain hash** is the id of the chain's kind-3500 chain event (SPEC
//! 0.0.5), not its alias `sidestr:<name>`: a chain that has not published
//! that event cannot be pegged into in this form yet. Upstream at `e8deb63`
//! has no scanner that claims a tweak-form peg-in; the form is a plan a
//! parent wallet pays and a verifier checks, beside the marker form
//! (`pegin:<chain id>:<script>`), which stays the default everywhere.
//!
//! As upstream, keys are hex text (64 characters x-only or 66 compressed),
//! scripts and hashes hex.
//!
//! ```
//! use sidestr_core::keys::{public_key, x_only};
//! use sidestr_core::pegtweak::{peg_matches, peg_output, PegReveal};
//!
//! let holder = public_key(&"11".repeat(32)).unwrap();
//! let refund = x_only(&public_key(&"22".repeat(32)).unwrap()).unwrap();
//! let reveal = PegReveal {
//!     internal: holder,
//!     refund_key: refund.clone(),
//!     refund_blocks: 10_000,
//!     chain_hash: "aa".repeat(32),
//!     script: format!("5120{}", "11".repeat(32)),
//!     extra_leaves: vec![],
//! };
//! let out = peg_output(&reveal, "tb").unwrap();
//! assert!(out.address.starts_with("tb1p") && out.address.len() == 62);
//! assert_eq!(out.descriptor, format!("tr({},{{and_v(v:pk({refund}),older(10000)),pk({})}})", out.internal_key, out.commit_key));
//! // the reveal alone rebuilds it
//! assert!(peg_matches(&out.reveal, &out.script_pubkey).unwrap());
//! ```

use bitcoin::hashes::{sha256, Hash};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TapNodeHash};
use bitcoin::{Script, ScriptBuf};
use serde::{Deserialize, Serialize};

use crate::address::script_to_address;
use crate::federation::NUMS_X;
use crate::keys::{self, KeyError};

/// The tag of the commitment scalar.
pub const PEG_TAG: &str = "sidestr/peg-in";

/// The tapscript leaf version every leaf here carries (BIP 342).
pub const LEAF_VERSION: u8 = 0xc0;

/// Why a peg output could not be made, in `pegtweak.mjs`'s words.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PegError {
    /// A refund block count of 0 or above `2^31 - 1`.
    #[error("a block count between 1 and 2^31-1")]
    BlockCount,
    /// A chain hash that is not 64 hex characters.
    #[error("chainHash is the chain event's id (64 hex, SPEC 3)")]
    ChainHash,
    /// A destination script (or an extra leaf) that is not hex bytes.
    #[error("script is hex")]
    ScriptHex,
    /// A key that is neither x-only nor compressed hex.
    #[error("a key is an x-only (64 hex) or compressed (66 hex) point")]
    KeyForm,
    /// [`tap_tree`] of no leaves.
    #[error("a tree needs a leaf")]
    EmptyTree,
    /// No bech32m address under that prefix.
    #[error("{0} is not an address prefix")]
    Prefix(String),
    /// The key arithmetic refused.
    #[error(transparent)]
    Key(#[from] KeyError),
}

/// This module's result.
pub type Result<T> = core::result::Result<T, PegError>;

fn is_hex_bytes(s: &str) -> bool {
    !s.is_empty() && s.len() % 2 == 0 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if !is_hex_bytes(s) {
        return Err(PegError::ScriptHex);
    }
    hex::decode(s).map_err(|_| PegError::ScriptHex)
}

/// A key as its x (lowercase): 64 hex as it is, 66 hex (`02`/`03`) without
/// the prefix (`pegtweak.mjs xOnlyOf`). Not checked against the curve here;
/// the arithmetic that uses it is.
pub fn x_only_of(key: &str) -> Result<String> {
    let s = key.to_lowercase();
    let hex64 = |t: &str| t.len() == 64 && t.bytes().all(|c| c.is_ascii_hexdigit());
    if hex64(&s) {
        return Ok(s);
    }
    if s.len() == 66 && (s.starts_with("02") || s.starts_with("03")) && hex64(&s[2..]) {
        return Ok(s[2..].to_string());
    }
    Err(PegError::KeyForm)
}

/// A script number pushed minimally: `OP_1`..`OP_16` for 1..16, else
/// little-endian with a sign byte when the top bit is set.
fn push_num(n: u32) -> Result<String> {
    if n == 0 || n > 0x7fff_ffff {
        return Err(PegError::BlockCount);
    }
    if n <= 16 {
        return Ok(format!("{:02x}", 0x50 + n));
    }
    let mut b = Vec::new();
    let mut v = n;
    while v > 0 {
        b.push((v & 0xff) as u8);
        v >>= 8;
    }
    if b[b.len() - 1] & 0x80 != 0 {
        b.push(0);
    }
    Ok(format!("{:02x}{}", b.len(), hex::encode(b)))
}

/// The refund leaf, hex: `<refund> CHECKSIGVERIFY <refundBlocks>
/// CHECKSEQUENCEVERIFY`, miniscript `and_v(v:pk(refund), older(n))`, the
/// count pushed minimally (`pegtweak.mjs refundLeaf`).
///
/// ```
/// use sidestr_core::pegtweak::refund_leaf;
/// let x = "22".repeat(32);
/// assert_eq!(refund_leaf(&x, 10_000).unwrap(), format!("20{x}ad021027b2"));
/// assert!(refund_leaf(&x, 16).unwrap().ends_with("60b2"));
/// assert!(refund_leaf(&x, 0).is_err());
/// ```
pub fn refund_leaf(refund_key: &str, refund_blocks: u32) -> Result<String> {
    Ok(format!(
        "20{}ad{}b2",
        x_only_of(refund_key)?,
        push_num(refund_blocks)?
    ))
}

/// The commitment scalar, hex: `tagged("sidestr/peg-in", chainHash32 ‖
/// sha256(script))`, fixed widths, no delimiters (`pegtweak.mjs
/// pegCommitment`). `chain_hash` is the chain event's id, 64 hex in either
/// case; `script` the sidechain output script, hex.
pub fn peg_commitment(chain_hash: &str, script: &str) -> Result<String> {
    if chain_hash.len() != 64 || !chain_hash.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(PegError::ChainHash);
    }
    if !is_hex_bytes(script) {
        return Err(PegError::ScriptHex);
    }
    let chain = hex::decode(chain_hash).map_err(|_| PegError::ChainHash)?;
    let script_hash = sha256::Hash::hash(&unhex(script)?).to_byte_array();
    Ok(keys::tagged_scalar(PEG_TAG, &[&chain, &script_hash])?)
}

/// The commitment leaf: the key `C = NUMS + t·G` (unspendable: NUMS has no
/// known secret), its leaf `pk(C)` and the tweak `t`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitLeaf {
    /// `x(C)`, hex.
    pub key: String,
    /// `<x(C)> CHECKSIG`, hex.
    pub script: String,
    /// The commitment scalar `t`, hex.
    pub tweak: String,
}

/// The commitment key and its leaf (`pegtweak.mjs commitLeaf`): `C` is
/// [`NUMS_X`]'s even-y point plus [`peg_commitment`]`·G`, on the full point.
pub fn commit_leaf(chain_hash: &str, script: &str) -> Result<CommitLeaf> {
    let t = peg_commitment(chain_hash, script)?;
    let c = keys::tweak_point(&format!("02{}", hex::encode(NUMS_X)), &t)?;
    let key = keys::x_only(&c)?;
    Ok(CommitLeaf {
        script: format!("20{key}ac"),
        key,
        tweak: t,
    })
}

fn leaf_hash_of(script: &[u8]) -> TapLeafHash {
    TapLeafHash::from_script(Script::from_bytes(script), LeafVersion::TapScript)
}

/// A tapscript leaf's hash, hex: `tagged("TapLeaf", 0xc0 ‖ compact(len) ‖
/// script)` (`pegtweak.mjs leafHash`), by rust-bitcoin.
pub fn leaf_hash(script: &str) -> Result<String> {
    Ok(hex::encode(leaf_hash_of(&unhex(script)?).to_byte_array()))
}

/// A tree of leaves: its root and, per leaf, the path of sibling hashes its
/// control block carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapTree {
    /// The merkle root, hex.
    pub root: String,
    /// Per leaf, in the order given: the sibling hashes from the leaf up, hex.
    pub paths: Vec<Vec<String>>,
}

/// The tree upstream builds (`pegtweak.mjs tapTree`): leaves paired left to
/// right, each branch the BIP 341 `TapBranch` hash of its two children in
/// lexical order, an odd one out carried up unchanged; every leaf gets its
/// path of sibling hashes. The hashes are rust-bitcoin's
/// ([`TapLeafHash`], [`TapNodeHash::from_node_hashes`]); only the shape is
/// upstream's, and the tests hold the root to rust-bitcoin's
/// `TaprootBuilder` for the same shape.
pub fn tap_tree<T: AsRef<str>>(leaf_scripts: &[T]) -> Result<TapTree> {
    if leaf_scripts.is_empty() {
        return Err(PegError::EmptyTree);
    }
    struct Node {
        hash: TapNodeHash,
        leaves: Vec<usize>,
    }
    let mut paths: Vec<Vec<TapNodeHash>> = vec![Vec::new(); leaf_scripts.len()];
    let mut level = leaf_scripts
        .iter()
        .enumerate()
        .map(|(i, s)| {
            Ok(Node {
                hash: TapNodeHash::from(leaf_hash_of(&unhex(s.as_ref())?)),
                leaves: vec![i],
            })
        })
        .collect::<Result<Vec<_>>>()?;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut it = level.into_iter();
        while let Some(a) = it.next() {
            match it.next() {
                None => next.push(a),
                Some(b) => {
                    for &i in &a.leaves {
                        paths[i].push(b.hash);
                    }
                    for &i in &b.leaves {
                        paths[i].push(a.hash);
                    }
                    let mut leaves = a.leaves;
                    leaves.extend(b.leaves);
                    next.push(Node {
                        hash: TapNodeHash::from_node_hashes(a.hash, b.hash),
                        leaves,
                    });
                }
            }
        }
        level = next;
    }
    Ok(TapTree {
        root: hex::encode(level[0].hash.to_byte_array()),
        paths: paths
            .into_iter()
            .map(|p| p.iter().map(|h| hex::encode(h.to_byte_array())).collect())
            .collect(),
    })
}

/// What anyone needs to rebuild a peg output: the claim's reveal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PegReveal {
    /// The peg holders' key, x-only or compressed hex; used as its even-y lift.
    pub internal: String,
    /// The refund key, x-only or compressed hex.
    pub refund_key: String,
    /// Parent blocks after which the refund key may sweep an unclaimed peg.
    pub refund_blocks: u32,
    /// The chain event's id (SPEC 3, 0.0.5), 64 hex.
    pub chain_hash: String,
    /// The sidechain output script the coins appear at, hex.
    pub script: String,
    /// Further leaves after the refund and commit leaves, hex (level 2: the
    /// challenge's `multi_a` leaf).
    #[serde(default)]
    pub extra_leaves: Vec<String>,
}

/// One leaf of the output's tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PegLeaf {
    /// The leaf script, hex.
    pub script: String,
    /// Its TapLeaf hash, hex.
    pub hash: String,
    /// Its control block, hex: `(0xc0 | parity) ‖ x(internal) ‖ path`.
    pub control_block: String,
}

/// Everything the peg output is (`pegtweak.mjs pegOutput`'s object, field
/// for field; it serialises with upstream's camelCase names).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PegOutput {
    /// `x(P)`, hex.
    pub internal_key: String,
    /// `x(Q)`, the taproot output key, hex.
    pub output_key: String,
    /// `Q`'s parity, 0 (even) or 1 (odd), as control blocks carry it.
    pub output_parity: u8,
    /// `5120 ‖ output key` (`scriptPubKey` in JSON, as upstream spells it).
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: String,
    /// Its bech32m address under the prefix asked for.
    pub address: String,
    /// The tree's merkle root, hex.
    pub root: String,
    /// The output tweak `TapTweak(x(P) ‖ root)` as a scalar, hex.
    pub tweak: String,
    /// `x(C)`, the commitment key.
    pub commit_key: String,
    /// The commitment scalar `t`.
    pub commitment: String,
    /// Every leaf: refund, commit, then the extra leaves.
    pub leaves: Vec<PegLeaf>,
    /// The refund leaf (`leaves[0]`).
    pub refund: PegLeaf,
    /// The commit leaf (`leaves[1]`).
    pub commit: PegLeaf,
    /// `tr(<x(P)>,{and_v(v:pk(<refund>),older(<n>)),pk(<C>)})`, with a
    /// literal `,…` before the closing brace when there are extra leaves, as
    /// upstream writes it (a wallet needs the full tree for those).
    pub descriptor: String,
    /// The reveal, normalised: keys x-only, the chain hash and script
    /// lower-cased.
    pub reveal: PegReveal,
}

impl PegOutput {
    /// The output script, typed.
    pub fn script(&self) -> ScriptBuf {
        ScriptBuf::from_hex(&self.script_pubkey).expect("written as hex here")
    }
}

/// Everything the peg output is, from the reveal, so the pegger, the holders
/// and a verifier all compute the same (`pegtweak.mjs pegOutput`). `hrp` is
/// the parent's address prefix (`tb` beside testnet4, `bc` beside mainnet).
///
/// The internal key is used as `02 ‖ x` whatever parity it was given with:
/// BIP 341 lifts the internal key, and the holders' secret is normalised to
/// it ([`keys::normalize`], [`peg_spend_secret`]).
pub fn peg_output(reveal: &PegReveal, hrp: &str) -> Result<PegOutput> {
    let internal = x_only_of(&reveal.internal)?;
    let p = format!("02{internal}");
    let refund_x = x_only_of(&reveal.refund_key)?;
    let refund = refund_leaf(&refund_x, reveal.refund_blocks)?;
    let commit = commit_leaf(&reveal.chain_hash, &reveal.script)?;
    let mut leaf_scripts = vec![refund, commit.script.clone()];
    leaf_scripts.extend(reveal.extra_leaves.iter().cloned());
    let tree = tap_tree(&leaf_scripts)?;
    let t = keys::tap_tweak(&p, Some(&tree.root))?;
    let q = keys::tweak_point(&p, &t)?;
    let output_key = keys::x_only(&q)?;
    let parity = u8::from(q.starts_with("03"));
    let leaves = leaf_scripts
        .iter()
        .enumerate()
        .map(|(i, s)| {
            Ok(PegLeaf {
                script: s.clone(),
                hash: leaf_hash(s)?,
                control_block: format!(
                    "{:02x}{internal}{}",
                    LEAF_VERSION | parity,
                    tree.paths[i].concat()
                ),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let script_pubkey = format!("5120{output_key}");
    let address = script_to_address(
        &ScriptBuf::from_hex(&script_pubkey).expect("hex written here"),
        hrp,
    )
    .ok_or_else(|| PegError::Prefix(hrp.to_string()))?;
    let descriptor = format!(
        "tr({internal},{{and_v(v:pk({refund_x}),older({})),pk({}){}}})",
        reveal.refund_blocks,
        commit.key,
        if reveal.extra_leaves.is_empty() {
            ""
        } else {
            ",…"
        }
    );
    Ok(PegOutput {
        internal_key: internal.clone(),
        output_key,
        output_parity: parity,
        script_pubkey,
        address,
        root: tree.root,
        tweak: t,
        commit_key: commit.key,
        commitment: commit.tweak,
        refund: leaves[0].clone(),
        commit: leaves[1].clone(),
        leaves,
        descriptor,
        reveal: PegReveal {
            internal,
            refund_key: refund_x,
            refund_blocks: reveal.refund_blocks,
            chain_hash: reveal.chain_hash.to_lowercase(),
            script: reveal.script.to_lowercase(),
            extra_leaves: reveal.extra_leaves.clone(),
        },
    })
}

/// Does an output script (hex, either case) pay the peg this reveal
/// describes? A verifier holding the claim's reveal and the parent
/// transaction asks this (`pegtweak.mjs pegMatches`). The address prefix
/// does not enter the script, so none is asked for. A reveal that cannot
/// make an output is an error, as upstream throws.
pub fn peg_matches(reveal: &PegReveal, script_pubkey: &str) -> Result<bool> {
    Ok(peg_output(reveal, "tb")?.script_pubkey == script_pubkey.to_lowercase())
}

/// The holders' key-path spending secret, hex: the normalised secret plus
/// the output tweak (`pegtweak.mjs pegSpendSecret`). The BIP 340 sign is
/// applied inside signing, as [`keys::signing_key`] says.
///
/// ```
/// use bitcoin::secp256k1::{Keypair, Message, SecretKey, XOnlyPublicKey};
/// use sidestr_core::block::secp;
/// use sidestr_core::keys::{public_key, x_only};
/// use sidestr_core::pegtweak::{peg_output, peg_spend_secret, PegReveal};
///
/// // a holder whose point has odd y: the secret is normalised before the tweak
/// let d = "11".repeat(32);
/// assert!(public_key(&d).unwrap().starts_with("03"));
/// let refund = x_only(&public_key(&"22".repeat(32)).unwrap()).unwrap();
/// let out = peg_output(&PegReveal { internal: public_key(&d).unwrap(), refund_key: refund,
///     refund_blocks: 144, chain_hash: "aa".repeat(32), script: "51".into(), extra_leaves: vec![] }, "tb").unwrap();
/// let spend = peg_spend_secret(&d, &out).unwrap();
/// let kp = Keypair::from_secret_key(secp(), &SecretKey::from_slice(&hex::decode(&spend).unwrap()).unwrap());
/// let msg = Message::from_digest([7; 32]);
/// let sig = secp().sign_schnorr_with_aux_rand(&msg, &kp, &[0; 32]);
/// let q = XOnlyPublicKey::from_slice(&hex::decode(&out.output_key).unwrap()).unwrap();
/// assert!(secp().verify_schnorr(&sig, &msg, &q).is_ok());
/// ```
pub fn peg_spend_secret(secret: &str, out: &PegOutput) -> Result<String> {
    Ok(keys::tweak_secret(&keys::normalize(secret)?, &out.tweak)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_pushes() {
        assert_eq!(push_num(1).unwrap(), "51");
        assert_eq!(push_num(16).unwrap(), "60");
        assert_eq!(push_num(17).unwrap(), "0111");
        assert_eq!(push_num(127).unwrap(), "017f");
        assert_eq!(push_num(128).unwrap(), "028000");
        assert_eq!(push_num(10_000).unwrap(), "021027");
        assert_eq!(push_num(0x7fff_ffff).unwrap(), "04ffffff7f");
        assert_eq!(push_num(0), Err(PegError::BlockCount));
        assert_eq!(push_num(0x8000_0000), Err(PegError::BlockCount));
    }

    #[test]
    fn key_forms() {
        let x = "ab".repeat(32);
        assert_eq!(x_only_of(&x.to_uppercase()).unwrap(), x);
        assert_eq!(x_only_of(&format!("03{x}")).unwrap(), x);
        assert_eq!(x_only_of(&format!("04{x}")), Err(PegError::KeyForm));
        assert_eq!(x_only_of("abcd"), Err(PegError::KeyForm));
    }
}
