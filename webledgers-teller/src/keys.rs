//! Keys as group elements, the x-only form only at the edge: a mirror of
//! `sidestr/spec siding/lib/keys.mjs` at `bd1d692` (Melvin Carvalho,
//! AGPL-3.0), function for function and in its words, for the teller's
//! deposit addresses.
//!
//! A did:nostr identifier is the x-coordinate of a secp256k1 point; a
//! Multikey carries the full compressed point; BIP 340 signatures and taproot
//! outputs use the x alone. Everything in between is plain arithmetic on full
//! points, exact for every parity: `d + t ↔ P + t·G`. The one rule that makes
//! a bare identifier exact too: a holder normalises the secret once, to the
//! secret of the even-y (`02`) point the identifier denotes; after that
//! nothing is lifted or negated again, except the sign a BIP 340 signature
//! needs, which stays inside the signing.
//!
//! The arithmetic is libsecp256k1's through `bitcoin::secp256k1`
//! (`PublicKey::add_exp_tweak`, `SecretKey::add_tweak`, `negate`) and the
//! tagged hash is `bitcoin::hashes::sha256`; nothing here computes on the
//! curve by itself.
//!
//! The whole of `keys.mjs` is mirrored, with the same names, including the
//! functions the teller does not call, so that moving to a shared
//! `sidestr_core::keys` is a path change.
// TODO dedup with sidestr-core::keys once it lands on the merge base.
#![allow(dead_code)]

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{PublicKey, Scalar, SecretKey, XOnlyPublicKey};
use sidestr_core::block::secp;

use crate::error::{Error, Result};

const TWEAK_RANGE: &str = "a tweak is a scalar in [1, n-1]";
const SECRET_RANGE: &str = "a secret is a scalar in [1, n-1]";
const NOT_A_POINT: &str = "not a compressed secp256k1 point (02/03 + x, on the curve)";

/// 32 bytes from 64 hex digits of either case (`hexToBytes`), or `None`.
fn bytes32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(text, &mut out).ok()?;
    Some(out)
}

/// `scalar`: a tweak as a scalar in `[1, n-1]`.
pub(crate) fn scalar(t: &str) -> Result<Scalar> {
    let b = bytes32(t).ok_or(Error::Key(TWEAK_RANGE))?;
    scalar_of(b)
}

/// A 32-byte big-endian scalar in `[1, n-1]`, or the tweak-range refusal.
pub(crate) fn scalar_of(b: [u8; 32]) -> Result<Scalar> {
    // a tweak of 0 is refused, as keys.mjs refuses it; Scalar refuses >= n
    if b == [0u8; 32] {
        return Err(Error::Key(TWEAK_RANGE));
    }
    Scalar::from_be_bytes(b).map_err(|_| Error::Key(TWEAK_RANGE))
}

/// `secret`: a secret key in `[1, n-1]`.
pub(crate) fn secret(d: &str) -> Result<SecretKey> {
    let b = bytes32(d).ok_or(Error::Key(SECRET_RANGE))?;
    SecretKey::from_slice(&b).map_err(|_| Error::Key(SECRET_RANGE))
}

/// `isPoint`: `02`/`03` and 64 lowercase hex digits, on the curve.
pub(crate) fn is_point(p: &str) -> bool {
    parse_point(p).is_some()
}

fn parse_point(p: &str) -> Option<PublicKey> {
    let b = p.as_bytes();
    let shaped = b.len() == 66
        && b[0] == b'0'
        && (b[1] == b'2' || b[1] == b'3')
        && b[2..]
            .iter()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
    if !shaped {
        return None;
    }
    PublicKey::from_slice(&hex::decode(p).ok()?).ok()
}

/// `point`: a compressed point, checked.
pub(crate) fn point(p: &str) -> Result<PublicKey> {
    parse_point(p).ok_or(Error::Key(NOT_A_POINT))
}

fn hex_point(p: &PublicKey) -> String {
    hex::encode(p.serialize())
}

fn hex_secret(d: &SecretKey) -> String {
    hex::encode(d.secret_bytes())
}

fn is_odd(p: &PublicKey) -> bool {
    p.serialize()[0] == 0x03
}

// ---- the holder's side

/// The public point of a secret.
pub(crate) fn point_of(d: &SecretKey) -> PublicKey {
    PublicKey::from_secret_key(secp(), d)
}

/// `publicKey`: the public point of a secret, compressed (`02`/`03` + x).
pub(crate) fn public_key(d: &str) -> Result<String> {
    Ok(hex_point(&point_of(&secret(d)?)))
}

/// The secret of the even-y point with the same x: `d` when `d·G` is even,
/// else `n − d`.
pub(crate) fn normalized(d: &SecretKey) -> SecretKey {
    if is_odd(&point_of(d)) {
        d.negate()
    } else {
        *d
    }
}

/// `normalize`: [`normalized`] on hex. Done once, so a bare identifier (x
/// only, read as `02`) names exactly this holder's point.
pub(crate) fn normalize(d: &str) -> Result<String> {
    let s = secret(d)?;
    Ok(if is_odd(&point_of(&s)) {
        hex_secret(&s.negate())
    } else {
        d.to_lowercase()
    })
}

/// `signingKey`: the key a BIP 340 signature of this point's x needs: `d`, or
/// `n − d` when the point has odd y. Stays inside signing; never the key the
/// next tweak is added to.
pub(crate) fn signing_key(d: &str) -> Result<String> {
    normalize(d)
}

// ---- reading and writing keys

/// `basePoint`: the full point behind `did:nostr:<x>` or a bare x (read as the
/// even-y point, `02`), a did:nostr Multikey (`fe70102…`/`fe70103…`, parity
/// kept) or a compressed point.
pub(crate) fn base_point(id: &str) -> Result<String> {
    let s = crate::account::js_trim(id).to_lowercase();
    let is_hex = |t: &str| t.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
    let bare = s.strip_prefix("did:nostr:").unwrap_or(&s);
    if bare.len() == 64 && is_hex(bare) {
        let x = hex::decode(bare).expect("checked hex");
        if XOnlyPublicKey::from_slice(&x).is_err() {
            return Err(Error::Key("that x is not on the curve"));
        }
        let p = format!("02{bare}");
        point(&p)?;
        return Ok(p);
    }
    if let Some(mk) = s.strip_prefix("fe701") {
        if mk.len() == 66 && (mk.starts_with("02") || mk.starts_with("03")) && is_hex(mk) {
            point(mk)?;
            return Ok(mk.to_owned());
        }
    }
    if s.len() == 66 && (s.starts_with("02") || s.starts_with("03")) && is_hex(&s) {
        point(&s)?;
        return Ok(s);
    }
    Err(Error::Key(
        "not a did:nostr identifier, a did:nostr Multikey, or a compressed point",
    ))
}

/// `xOnly`: the x-only form (a did:nostr identifier, a BIP 340 public key, a
/// taproot output key).
pub(crate) fn x_only(p: &str) -> Result<String> {
    point(p)?;
    Ok(p[2..].to_owned())
}

/// `did`: `did:nostr:` and the x.
pub(crate) fn did(p: &str) -> Result<String> {
    Ok(format!("did:nostr:{}", x_only(p)?))
}

/// `multikey`: `f` + `e701` + the compressed point, parity kept.
pub(crate) fn multikey(p: &str) -> Result<String> {
    Ok(format!("fe701{}", hex_point(&point(p)?)))
}

/// `negate`: the same x, the other parity.
pub(crate) fn negate(p: &str) -> Result<String> {
    Ok(hex_point(&point(p)?.negate(secp())))
}

// ---- arithmetic: exact on full points

/// `d + t mod n`, typed.
pub(crate) fn tweaked_secret(d: &SecretKey, t: &Scalar) -> Result<SecretKey> {
    d.add_tweak(t)
        .map_err(|_| Error::Key("the tweak cancels the secret"))
}

/// `P + t·G`, typed.
pub(crate) fn tweaked_point(p: &PublicKey, t: &Scalar) -> Result<PublicKey> {
    p.add_exp_tweak(secp(), t)
        .map_err(|_| Error::Key("the tweak lands on infinity"))
}

/// `tweakSecret`: `d + t mod n`.
pub(crate) fn tweak_secret(d: &str, t: &str) -> Result<String> {
    let d = secret(d)?;
    Ok(hex_secret(&tweaked_secret(&d, &scalar(t)?)?))
}

/// `tweakPoint`: `P + t·G`, the point of `d + t` when `P` is the point of `d`.
pub(crate) fn tweak_point(p: &str, t: &str) -> Result<String> {
    let p = point(p)?;
    Ok(hex_point(&tweaked_point(&p, &scalar(t)?)?))
}

/// `chainPoints`: each tweak added to the point before it, kept whole
/// between steps; every point, the first included.
pub(crate) fn chain_points(p: &str, tweaks: &[&str]) -> Result<Vec<String>> {
    let mut out = vec![hex_point(&point(p)?)];
    for t in tweaks {
        let next = tweak_point(out.last().expect("non-empty"), t)?;
        out.push(next);
    }
    Ok(out)
}

/// `chainSecrets`: the same chain on the secret.
pub(crate) fn chain_secrets(d: &str, tweaks: &[&str]) -> Result<Vec<String>> {
    secret(d)?;
    let mut out = vec![d.to_lowercase()];
    for t in tweaks {
        let next = tweak_secret(out.last().expect("non-empty"), t)?;
        out.push(next);
    }
    Ok(out)
}

// ---- tweaks from data

/// BIP 340's tagged hash: `sha256(sha256(tag) ‖ sha256(tag) ‖ data…)`.
pub(crate) fn tagged_hash(tag: &str, chunks: &[&[u8]]) -> [u8; 32] {
    let t = sha256::Hash::hash(tag.as_bytes()).to_byte_array();
    let mut e = sha256::Hash::engine();
    e.input(&t);
    e.input(&t);
    for c in chunks {
        e.input(c);
    }
    sha256::Hash::from_engine(e).to_byte_array()
}

/// A 256-bit big-endian integer reduced mod n, or `None` when it is 0 mod n.
///
/// A value below n is itself. A value at or above n is below `2^256 < 2n`,
/// so it is `hi·2^128 + lo` with `hi ≥ 1` (any value ≥ n exceeds `2^255`);
/// libsecp256k1 does the reduction as `hi ⊗ 2^128 ⊕ lo` on secret scalars.
pub(crate) fn reduce(b: [u8; 32]) -> Option<Scalar> {
    if let Ok(s) = Scalar::from_be_bytes(b) {
        return (b != [0u8; 32]).then_some(s);
    }
    let mut hi = [0u8; 32];
    hi[16..].copy_from_slice(&b[..16]);
    let mut lo = [0u8; 32];
    lo[16..].copy_from_slice(&b[16..]);
    let mut two128 = [0u8; 32];
    two128[15] = 1;
    let hi = SecretKey::from_slice(&hi).ok()?;
    let shifted = hi
        .mul_tweak(&Scalar::from_be_bytes(two128).expect("2^128 < n"))
        .ok()?;
    let sum = shifted
        .add_tweak(&Scalar::from_be_bytes(lo).expect("below 2^128"))
        .ok()?;
    Some(Scalar::from(sum))
}

/// `taggedScalar`: a scalar committed to data with domain separation,
/// `int(taggedHash(tag, …chunks)) mod n`, never 0.
pub(crate) fn tagged_scalar(tag: &str, chunks: &[&[u8]]) -> Result<String> {
    let s = reduce(tagged_hash(tag, chunks))
        .ok_or(Error::Key("the tweak is zero: refuse this data"))?;
    Ok(hex::encode(s.to_be_bytes()))
}

/// `tapTweak`: BIP 341's `taggedHash("TapTweak", x ‖ h)`, added to the point
/// as it is (equal to BIP 341's output key exactly when the point is even-y).
pub(crate) fn tap_tweak(p: &str, h32: Option<&[u8; 32]>) -> Result<String> {
    let x = hex::decode(x_only(p)?).expect("hex point");
    match h32 {
        Some(h) => tagged_scalar("TapTweak", &[&x, h]),
        None => tagged_scalar("TapTweak", &[&x]),
    }
}

#[cfg(test)]
mod tests {
    //! `siding/test/keys-vectors.json` at `bd1d692` (unchanged through
    //! `e8deb63`), vendored as `tests/vectors/keys-vectors.json`, and the
    //! limits `keys-test.mjs` checks.
    use super::*;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../tests/vectors/keys-vectors.json");
    const N_HEX: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

    fn strs(v: &Value) -> Vec<&str> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect()
    }

    #[test]
    fn keys_vectors_json_both_cases() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        let cases = v["cases"].as_object().unwrap();
        assert_eq!(cases.len(), 2);
        for (name, c) in cases {
            let s = |k: &str| c[k].as_str().unwrap();
            let d = s("secret");
            let p = public_key(d).unwrap();
            assert_eq!(p, s("point"), "{name}");
            assert_eq!(did(&p).unwrap(), s("did"), "{name}");
            assert_eq!(multikey(&p).unwrap(), s("multikey"), "{name}");
            let n = normalize(d).unwrap();
            assert_eq!(n, s("normalized"), "{name}");
            assert_eq!(public_key(&n).unwrap(), s("normalizedPoint"), "{name}");
            let tws = strs(&c["tweaks"]);
            // the third tweak is taggedScalar('keys-vectors', 'cafe')
            assert_eq!(
                tagged_scalar("keys-vectors", &[&[0xca, 0xfe]]).unwrap(),
                tws[2]
            );
            let secrets = chain_secrets(&n, &tws).unwrap();
            assert_eq!(&secrets[1..], strs(&c["chainFromSecret"]), "{name}");
            let base = base_point(&did(&p).unwrap()).unwrap();
            let points = chain_points(&base, &tws).unwrap();
            assert_eq!(&points[1..], strs(&c["chainPoints"]), "{name}");
            let outs: Vec<String> = points[1..].iter().map(|q| x_only(q).unwrap()).collect();
            assert_eq!(outs, strs(&c["outputs"]), "{name}");
            let signing: Vec<String> = secrets[1..]
                .iter()
                .map(|q| signing_key(q).unwrap())
                .collect();
            assert_eq!(signing, strs(&c["signingKeys"]), "{name}");
            // every point along the chain is the point of the secret along it
            for (q, sk) in points.iter().zip(&secrets) {
                assert_eq!(q, &public_key(sk).unwrap(), "{name}");
            }
        }
        assert_eq!(&cases["oddSecret"]["point"].as_str().unwrap()[..2], "03");
    }

    #[test]
    fn reading_keys_as_keys_test_reads_them() {
        let p = public_key(&"11".repeat(32)).unwrap();
        let x = x_only(&p).unwrap();
        assert_eq!(
            base_point(&format!("did:nostr:{x}")).unwrap(),
            format!("02{x}")
        );
        assert_eq!(base_point(&x.to_uppercase()).unwrap(), format!("02{x}"));
        assert_eq!(
            base_point(&format!("fe70103{x}")).unwrap(),
            format!("03{x}")
        );
        assert_eq!(base_point(&p).unwrap(), p);
        assert_eq!(
            multikey(
                &base_point(
                    "did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2"
                )
                .unwrap()
            )
            .unwrap(),
            "fe70102124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2"
        );
        assert_eq!(
            base_point(&"00".repeat(32)),
            Err(Error::Key("that x is not on the curve"))
        );
        for bad in [format!("04{x}"), x[2..].to_owned(), "npub1abc".into()] {
            assert!(matches!(base_point(&bad), Err(Error::Key(m)) if m.starts_with("not a")));
        }
        assert_eq!(x_only(&negate(&p).unwrap()).unwrap(), x);
        assert_ne!(negate(&p).unwrap(), p);
    }

    #[test]
    fn limits_in_keys_mjs_words() {
        let p = public_key(&"11".repeat(32)).unwrap();
        assert_eq!(
            tweak_point(&p, &"00".repeat(32)),
            Err(Error::Key(TWEAK_RANGE))
        );
        assert_eq!(tweak_point(&p, N_HEX), Err(Error::Key(TWEAK_RANGE)));
        assert_eq!(public_key(&"00".repeat(32)), Err(Error::Key(SECRET_RANGE)));
        // d + (n − d) = 0
        let d = "11".repeat(32);
        let minus = hex_secret(&secret(&d).unwrap().negate());
        assert_eq!(
            tweak_secret(&d, &minus),
            Err(Error::Key("the tweak cancels the secret"))
        );
    }

    #[test]
    fn reduction_mod_n_at_and_above_n() {
        let n: [u8; 32] = hex::decode(N_HEX).unwrap().try_into().unwrap();
        assert_eq!(reduce(n), None);
        assert_eq!(reduce([0u8; 32]), None);
        let mut n5 = n;
        n5[31] += 5;
        let mut five = [0u8; 32];
        five[31] = 5;
        assert_eq!(reduce(n5).unwrap().to_be_bytes(), five);
        // 2^256 − 1 − n = 0x14551231950b75fc4402da1732fc9bebe
        let want = hex::decode("000000000000000000000000000000014551231950b75fc4402da1732fc9bebe")
            .unwrap();
        assert_eq!(reduce([0xff; 32]).unwrap().to_be_bytes().to_vec(), want);
        // below n: itself
        assert_eq!(reduce(five).unwrap().to_be_bytes(), five);
    }

    #[test]
    fn d_plus_t_is_p_plus_tg_for_both_parities() {
        let mut odd = 0;
        for i in 1u8..=40 {
            let d = tagged_hash("test/keys", &[&[i]]);
            let t = tagged_hash("test/tweak", &[&[i]]);
            let (d, t) = (hex::encode(d), hex::encode(t));
            let p = public_key(&d).unwrap();
            if p.starts_with("03") {
                odd += 1;
            }
            assert_eq!(
                tweak_point(&p, &t).unwrap(),
                public_key(&tweak_secret(&d, &t).unwrap()).unwrap()
            );
            let n = normalize(&d).unwrap();
            assert!(public_key(&n).unwrap().starts_with("02"));
            assert_eq!(
                base_point(&did(&p).unwrap()).unwrap(),
                public_key(&n).unwrap()
            );
        }
        assert!(odd > 5 && odd < 35, "{odd}");
    }
}
