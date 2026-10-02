//! Keys as group elements, with the x-only form only at the edge: a port of
//! `siding/lib/keys.mjs` (`makeKeys`, sidestr/spec `bd1d692`, Melvin
//! Carvalho, AGPL-3.0).
//!
//! A did:nostr identifier is the x-coordinate of a secp256k1 point; a
//! document's Multikey carries the full compressed point (`02`/`03` + x);
//! BIP 340 signatures and taproot outputs use the x alone. Everything in
//! between (tweaks, chains, derived deposit addresses) is plain arithmetic
//! on full points, which is exact:
//!
//! ```text
//! d + t  <->  P + t·G     for every d, whatever the parity of P or of P + t·G
//! ```
//!
//! The one rule that makes a bare identifier exact too: a holder normalises
//! the secret **once**, to the secret of the even-y (`02`) point the
//! identifier denotes ([`normalize`]); after that nothing is ever lifted or
//! negated again, except the sign a BIP 340 signature needs, which stays
//! inside the signing ([`signing_key`]).
//!
//! As upstream, every key here is lowercase hex text: 64 characters for a
//! secret, a tweak or an x, 66 for a compressed point. A secret or a tweak
//! may be given in any hex length (it is read as a big-endian integer) and
//! must lie in `[1, n-1]`. The refusals carry upstream's words, so a message
//! from this module reads like one from `keys.mjs`.
//!
//! ```
//! use sidestr_core::keys::{base_point, chain_points, chain_secrets, did, normalize, public_key, x_only};
//!
//! // a holder whose point has odd y: normalised once, the identifier names its point exactly
//! let d = format!("{:064x}", 6);
//! assert!(public_key(&d).unwrap().starts_with("03"));
//! let n = normalize(&d).unwrap();
//! let p = public_key(&n).unwrap();
//! assert_eq!(base_point(&did(&p).unwrap()).unwrap(), p);
//!
//! // then tweaks are plain addition on both sides, with no lifting between steps
//! let tweaks = [format!("{:064x}", 1), format!("{:064x}", 2)];
//! let points = chain_points(&p, &tweaks).unwrap();
//! let secrets = chain_secrets(&n, &tweaks).unwrap();
//! for (s, q) in secrets.iter().zip(&points) {
//!     assert_eq!(&public_key(s).unwrap(), q);
//! }
//! assert_eq!(x_only(&points[2]).unwrap().len(), 64);
//! ```
//!
//! # Where this differs from the did:nostr conformance vectors
//!
//! [`base_point`] trims and **lower-cases** its input before reading it, as
//! `keys.mjs basePoint` does, so it accepts `FE70102…` and `DID:NOSTR:…`.
//! The did:nostr conformance vectors (`test-vectors-generated.json`, case
//! `error_uppercase_multibase_prefix`) reject an upper-case multibase prefix
//! as `InvalidMultibase`. This module follows upstream; a caller that must
//! enforce the conformance rule checks the case before calling.
//! `sidestr-agent`'s `parse_pubkey` (npub, did:nostr, bare hex; no Multikey)
//! is a separate reader and is unchanged.

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{PublicKey, Scalar, SecretKey};

use crate::block::secp;

/// The order `n` of the secp256k1 group, big-endian.
pub const N: [u8; 32] = bitcoin::secp256k1::constants::CURVE_ORDER;

/// Why a key, a tweak or an identifier was refused, in `keys.mjs`'s words.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// A secret of 0 or at least `n`.
    #[error("a secret is a scalar in [1, n-1]")]
    Secret,
    /// A tweak of 0 or at least `n`.
    #[error("a tweak is a scalar in [1, n-1]")]
    Tweak,
    /// Text that is not a lowercase compressed point on the curve.
    #[error("not a compressed secp256k1 point (02/03 + x, on the curve)")]
    NotAPoint,
    /// A did:nostr identifier (or bare x) with no point on the curve.
    #[error("that x is not on the curve")]
    OffCurve,
    /// None of the forms [`base_point`] reads.
    #[error("not a did:nostr identifier, a did:nostr Multikey, or a compressed point")]
    NotAnIdentifier,
    /// `d + t = 0 mod n`.
    #[error("the tweak cancels the secret")]
    Cancels,
    /// `P + t·G` is the point at infinity.
    #[error("the tweak lands on infinity")]
    Infinity,
    /// A tagged scalar that reduced to zero.
    #[error("the tweak is zero: refuse this data")]
    ZeroTweak,
    /// A secret, tweak or data chunk that is not hex; names which.
    #[error("{0} is not hex")]
    NotHex(&'static str),
}

/// This module's result.
pub type Result<T> = core::result::Result<T, KeyError>;

/// A hex integer of any length as 32 big-endian bytes, `None` when it does
/// not fit (so it is at least `2^256 > n`).
fn int32(text: &str, what: &'static str) -> Result<Option<[u8; 32]>> {
    let bytes = hex::decode(text).map_err(|_| KeyError::NotHex(what))?;
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let significant = &bytes[first..];
    if significant.len() > 32 {
        return Ok(None);
    }
    let mut out = [0u8; 32];
    out[32 - significant.len()..].copy_from_slice(significant);
    Ok(Some(out))
}

fn secret(d: &str) -> Result<SecretKey> {
    int32(d, "a secret")?
        .and_then(|b| SecretKey::from_slice(&b).ok())
        .ok_or(KeyError::Secret)
}

fn scalar(t: &str) -> Result<Scalar> {
    let b = int32(t, "a tweak")?.ok_or(KeyError::Tweak)?;
    if b == [0u8; 32] {
        return Err(KeyError::Tweak);
    }
    Scalar::from_be_bytes(b).map_err(|_| KeyError::Tweak)
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Whether `p` is a compressed point as this module writes one: `02` or
/// `03` and 64 lowercase hex characters, on the curve (`keys.mjs isPoint`).
pub fn is_point(p: &str) -> bool {
    parse_point(p).is_ok()
}

/// A compressed point (`02`/`03` + x, lowercase hex, on the curve) as a
/// [`PublicKey`]; [`KeyError::NotAPoint`] otherwise (`keys.mjs point`).
pub fn parse_point(p: &str) -> Result<PublicKey> {
    if !is_lower_hex(p, 66) || !(p.starts_with("02") || p.starts_with("03")) {
        return Err(KeyError::NotAPoint);
    }
    let bytes = hex::decode(p).map_err(|_| KeyError::NotAPoint)?;
    PublicKey::from_slice(&bytes).map_err(|_| KeyError::NotAPoint)
}

fn point_hex(p: &PublicKey) -> String {
    hex::encode(p.serialize())
}

// ---- the holder's side

/// The public point of a secret, compressed (`02`/`03` + x)
/// (`keys.mjs publicKey`).
///
/// ```
/// use sidestr_core::keys::{public_key, KeyError};
/// assert_eq!(public_key(&format!("{:064x}", 1)).unwrap(),
///            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
/// assert_eq!(public_key(&"00".repeat(32)), Err(KeyError::Secret));
/// ```
pub fn public_key(d: &str) -> Result<String> {
    Ok(point_hex(&PublicKey::from_secret_key(secp(), &secret(d)?)))
}

/// The secret of the even-y point with the same x: `d` itself (lower-cased,
/// as given) when `d·G` has even y, else `n − d` (`keys.mjs normalize`).
/// Done **once**, so a bare identifier (x only, read as `02`) names exactly
/// this holder's point; after it, nothing is lifted again.
///
/// ```
/// use sidestr_core::keys::{normalize, public_key};
/// let odd = format!("{:064x}", 6);
/// let n = normalize(&odd).unwrap();
/// assert!(public_key(&n).unwrap().starts_with("02"));
/// assert_eq!(normalize(&n).unwrap(), n);
/// ```
pub fn normalize(d: &str) -> Result<String> {
    let sk = secret(d)?;
    if PublicKey::from_secret_key(secp(), &sk).serialize()[0] == 0x03 {
        Ok(hex::encode(sk.negate().secret_bytes()))
    } else {
        Ok(d.to_lowercase())
    }
}

/// The key a BIP 340 signature of this point's x needs: `d`, or `n − d`
/// when the point has odd y (`keys.mjs signingKey`). The same arithmetic as
/// [`normalize`], kept as its own name because it is applied **inside
/// signing only**: it is never the key the next tweak is added to.
///
/// ```
/// use sidestr_core::keys::{normalize, signing_key};
/// let d = format!("{:064x}", 6);
/// assert_eq!(signing_key(&d).unwrap(), normalize(&d).unwrap());
/// ```
pub fn signing_key(d: &str) -> Result<String> {
    normalize(d)
}

// ---- reading and writing keys

/// The full point behind an identifier or encoding (`keys.mjs basePoint`):
///
/// - `did:nostr:<x>` or a bare x, read as the even-y point (`02` + x); the
///   x must lift ([`KeyError::OffCurve`]);
/// - a did:nostr Multikey, `fe70102…` or `fe70103…`, which carries the
///   parity and keeps it;
/// - a compressed point (`02`/`03` + x), as it is.
///
/// The input is trimmed and **lower-cased** first, as upstream does; see the
/// module documentation for how that differs from the did:nostr
/// conformance vectors.
///
/// ```
/// use sidestr_core::keys::{base_point, multikey, KeyError};
/// let x = "124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";
/// let p = base_point(&format!("did:nostr:{x}")).unwrap();
/// assert_eq!(p, format!("02{x}"));
/// assert_eq!(multikey(&p).unwrap(), format!("fe70102{x}"));
/// assert_eq!(base_point(&format!("FE70103{}", x.to_uppercase())).unwrap(), format!("03{x}"));
/// assert_eq!(base_point("npub1abc"), Err(KeyError::NotAnIdentifier));
/// ```
pub fn base_point(id: &str) -> Result<String> {
    let s = id.trim().to_lowercase();
    let x = s.strip_prefix("did:nostr:").unwrap_or(&s);
    if is_lower_hex(x, 64) {
        let even = format!("02{x}");
        let bytes = hex::decode(&even).map_err(|_| KeyError::OffCurve)?;
        PublicKey::from_slice(&bytes).map_err(|_| KeyError::OffCurve)?;
        parse_point(&even)?;
        return Ok(even);
    }
    if let Some(mk) = s.strip_prefix("fe701") {
        if is_lower_hex(mk, 66) && (mk.starts_with("02") || mk.starts_with("03")) {
            parse_point(mk)?;
            return Ok(mk.to_string());
        }
    }
    if is_lower_hex(&s, 66) && (s.starts_with("02") || s.starts_with("03")) {
        parse_point(&s)?;
        return Ok(s);
    }
    Err(KeyError::NotAnIdentifier)
}

/// The x-only form (`keys.mjs xOnly`): a did:nostr identifier, a BIP 340
/// public key, a taproot output key.
pub fn x_only(p: &str) -> Result<String> {
    parse_point(p)?;
    Ok(p[2..].to_string())
}

/// `did:nostr:<x>` for a point (`keys.mjs did`).
pub fn did(p: &str) -> Result<String> {
    Ok(format!("did:nostr:{}", x_only(p)?))
}

/// The did:nostr Multikey (`publicKeyMultibase`): `f` + `e701` + the
/// compressed point, parity kept (`keys.mjs multikey`).
pub fn multikey(p: &str) -> Result<String> {
    parse_point(p)?;
    Ok(format!("fe701{p}"))
}

/// `−P`: the same x, the other parity (`keys.mjs negate`).
///
/// ```
/// use sidestr_core::keys::{negate, x_only};
/// let p = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// assert!(negate(p).unwrap().starts_with("03"));
/// assert_eq!(x_only(&negate(p).unwrap()).unwrap(), x_only(p).unwrap());
/// ```
pub fn negate(p: &str) -> Result<String> {
    parse_point(p)?;
    let prefix = if p.starts_with("02") { "03" } else { "02" };
    Ok(format!("{prefix}{}", &p[2..]))
}

// ---- arithmetic: exact on full points

/// `d + t mod n` (`keys.mjs tweakSecret`); [`KeyError::Cancels`] when the
/// sum is zero.
pub fn tweak_secret(d: &str, t: &str) -> Result<String> {
    let sk = secret(d)?;
    let t = scalar(t)?;
    sk.add_tweak(&t)
        .map(|r| hex::encode(r.secret_bytes()))
        .map_err(|_| KeyError::Cancels)
}

/// `P + t·G` on the **full** point, the point of `d + t` when `P` is the
/// point of `d` (`keys.mjs tweakPoint`). Nothing is lifted: the parity of
/// `P` is used as given. [`KeyError::Infinity`] when the sum is the point
/// at infinity.
///
/// ```
/// use sidestr_core::keys::{public_key, tweak_point, tweak_secret};
/// let d = format!("{:064x}", 6);
/// let t = format!("{:064x}", 7);
/// assert_eq!(tweak_point(&public_key(&d).unwrap(), &t).unwrap(),
///            public_key(&tweak_secret(&d, &t).unwrap()).unwrap());
/// ```
pub fn tweak_point(p: &str, t: &str) -> Result<String> {
    let point = parse_point(p)?;
    let t = scalar(t)?;
    point
        .add_exp_tweak(secp(), &t)
        .map(|q| point_hex(&q))
        .map_err(|_| KeyError::Infinity)
}

/// A chain of points: each tweak added to the point before it, kept whole
/// (never lifted) between steps; every point, the start included
/// (`keys.mjs chainPoints`).
pub fn chain_points<T: AsRef<str>>(p: &str, tweaks: &[T]) -> Result<Vec<String>> {
    parse_point(p)?;
    let mut out = vec![p.to_string()];
    for t in tweaks {
        let next = tweak_point(out.last().expect("never empty"), t.as_ref())?;
        out.push(next);
    }
    Ok(out)
}

/// A chain of secrets matching [`chain_points`]: every secret, the start
/// (lower-cased, as given) included (`keys.mjs chainSecrets`).
pub fn chain_secrets<T: AsRef<str>>(d: &str, tweaks: &[T]) -> Result<Vec<String>> {
    secret(d)?;
    let mut out = vec![d.to_lowercase()];
    for t in tweaks {
        let next = tweak_secret(out.last().expect("never empty"), t.as_ref())?;
        out.push(next);
    }
    Ok(out)
}

// ---- tweaks from data

/// `v mod n` for a 256-bit `v`: since `2^256 < 2n`, at most one
/// subtraction of `n`. Plain integer arithmetic on one value, not a
/// cryptographic primitive.
fn reduce_mod_n(v: [u8; 32]) -> [u8; 32] {
    if Scalar::from_be_bytes(v).is_ok() {
        return v;
    }
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut x = i16::from(v[i]) - i16::from(N[i]) - borrow;
        borrow = 0;
        if x < 0 {
            x += 256;
            borrow = 1;
        }
        out[i] = x as u8;
    }
    out
}

/// A scalar committed to data, with domain separation:
/// `int(taggedHash(tag, chunk₁ ‖ chunk₂ ‖ …)) mod n`, never 0
/// (`keys.mjs taggedScalar`, chunks as bytes). The tagged hash is BIP 340's:
/// `sha256(sha256(tag) ‖ sha256(tag) ‖ data)`.
///
/// ```
/// use sidestr_core::keys::{tagged_scalar, tagged_scalar_hex};
/// let a = tagged_scalar("test/keys", &[&[0xab, 0xcd]]).unwrap();
/// assert_eq!(a, tagged_scalar_hex("test/keys", &["abcd"]).unwrap());
/// assert_ne!(a, tagged_scalar("other", &[&[0xab, 0xcd]]).unwrap());
/// ```
pub fn tagged_scalar(tag: &str, chunks: &[&[u8]]) -> Result<String> {
    let t = sha256::Hash::hash(tag.as_bytes()).to_byte_array();
    let mut e = sha256::Hash::engine();
    e.input(&t);
    e.input(&t);
    for c in chunks {
        e.input(c);
    }
    let n = reduce_mod_n(sha256::Hash::from_engine(e).to_byte_array());
    if n == [0u8; 32] {
        return Err(KeyError::ZeroTweak);
    }
    Ok(hex::encode(n))
}

/// [`tagged_scalar`] with each chunk given as hex, as `keys.mjs` accepts a
/// hex string in place of bytes.
pub fn tagged_scalar_hex<T: AsRef<str>>(tag: &str, chunks: &[T]) -> Result<String> {
    let bytes = chunks
        .iter()
        .map(|c| hex::decode(c.as_ref()).map_err(|_| KeyError::NotHex("a data chunk")))
        .collect::<Result<Vec<_>>>()?;
    let refs: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
    tagged_scalar(tag, &refs)
}

/// BIP 341's tweak for a point and an optional 32-byte hash (a merkle root,
/// or any commitment), hex: `taggedHash("TapTweak", x(P) [‖ h])` as a
/// scalar (`keys.mjs tapTweak`). It hashes the x of `P` **as given**, and
/// [`tweak_point`] adds it to the point as it is (not re-lifted): equal to
/// BIP 341's output key exactly when `P` is even-y.
///
/// ```
/// use sidestr_core::keys::{tap_tweak, tweak_point, x_only};
/// // BIP 341's first wallet vector: no script tree
/// let p = "02d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d";
/// let t = tap_tweak(p, None).unwrap();
/// assert_eq!(t, "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70");
/// assert_eq!(x_only(&tweak_point(p, &t).unwrap()).unwrap(),
///            "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343");
/// ```
pub fn tap_tweak(p: &str, h32: Option<&str>) -> Result<String> {
    let x = x_only(p)?;
    match h32 {
        Some(h) => tagged_scalar_hex("TapTweak", &[x.as_str(), h]),
        None => tagged_scalar_hex("TapTweak", &[x.as_str()]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduction_subtracts_n_once() {
        let mut v = N;
        v[31] += 5;
        let mut five = [0u8; 32];
        five[31] = 5;
        assert_eq!(reduce_mod_n(v), five);
        assert_eq!(reduce_mod_n(N), [0u8; 32]);
        assert_eq!(reduce_mod_n(five), five);
        let max = reduce_mod_n([0xff; 32]);
        assert!(Scalar::from_be_bytes(max).is_ok());
    }

    #[test]
    fn hex_integers_of_any_length() {
        assert_eq!(
            public_key("01").unwrap(),
            public_key(&format!("{:064x}", 1)).unwrap()
        );
        assert_eq!(
            public_key(&format!("00{}", "11".repeat(32))).unwrap(),
            public_key(&"11".repeat(32)).unwrap()
        );
        assert_eq!(public_key(&"ff".repeat(33)), Err(KeyError::Secret));
        assert_eq!(public_key("zz"), Err(KeyError::NotHex("a secret")));
        assert_eq!(
            tweak_point(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "1z"
            ),
            Err(KeyError::NotHex("a tweak"))
        );
    }

    #[test]
    fn infinity_is_refused() {
        // G + (n - 1)·G = n·G = O
        let mut n1 = N;
        n1[31] -= 1;
        let g = public_key("01").unwrap();
        assert_eq!(tweak_point(&g, &hex::encode(n1)), Err(KeyError::Infinity));
    }
}
