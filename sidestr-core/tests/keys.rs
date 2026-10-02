//! `siding/test/keys-test.mjs` (sidestr/spec `bd1d692`) ported: the
//! official BIP 340, 341 and 86 vectors pin the x-only edge; property checks
//! over deterministic pseudo-random keys of both parities pin the arithmetic
//! (`d + t <-> P + t·G`, chains, the normalise-once rule);
//! `fixtures/keys-vectors.json`, upstream's known answers copied verbatim, is
//! regenerated here byte for byte.
//!
//! The live half runs `keys.mjs` itself over the same inputs as this crate
//! (`tests/xcheck-pegtweak.mjs keys`) when `SIDESTR_SIDING` names a siding
//! checkout that carries it (sidestr/spec `bd1d692` or later) and `SCHEMA`
//! the bitcoin-desktop/schema checkout it loads; without them it reports
//! itself skipped.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{schnorr::Signature, Keypair, Message, SecretKey, XOnlyPublicKey};
use serde_json::{json, Value};
use sidestr_core::address::script_to_address;
use sidestr_core::block::secp;
use sidestr_core::keys::{
    base_point, chain_points, chain_secrets, did, multikey, negate, normalize, public_key,
    signing_key, tagged_scalar, tagged_scalar_hex, tap_tweak, tweak_point, tweak_secret, x_only,
    KeyError, N,
};

const KEYS_VECTORS: &str = include_str!("../fixtures/keys-vectors.json");
const BIP340: &str = include_str!("../fixtures/bip/bip340.json");
const BIP341: &str = include_str!("../fixtures/bip/bip341.json");
const BIP86: &str = include_str!("../fixtures/bip/bip86.json");

/// A secret that is the same on every run: `sha256(tag ‖ i)`.
fn rnd(tag: &str, i: usize) -> String {
    hex::encode(sha256::Hash::hash(format!("keys-test {tag} {i}").as_bytes()).to_byte_array())
}

fn hex64(n: u64) -> String {
    format!("{n:064x}")
}

/// `n − d`, hex, by the library's own arithmetic: `d + (n − d) = 0` is what
/// `tweak_secret` refuses, so `n − d` is the secret of `−P`.
fn n_minus(d: &str) -> String {
    hex::encode(
        SecretKey::from_slice(&hex::decode(d).unwrap())
            .unwrap()
            .negate()
            .secret_bytes(),
    )
}

fn sign(msg: &[u8; 32], secret: &str) -> Signature {
    let kp = Keypair::from_secret_key(
        secp(),
        &SecretKey::from_slice(&hex::decode(secret).unwrap()).unwrap(),
    );
    secp().sign_schnorr_with_aux_rand(&Message::from_digest(*msg), &kp, &[0u8; 32])
}

fn verifies(msg: &[u8; 32], sig: &Signature, x: &str) -> bool {
    let pk = XOnlyPublicKey::from_slice(&hex::decode(x).unwrap()).unwrap();
    secp()
        .verify_schnorr(sig, &Message::from_digest(*msg), &pk)
        .is_ok()
}

fn digest(h: &str) -> [u8; 32] {
    sha256::Hash::hash(&hex::decode(h).unwrap()).to_byte_array()
}

// ---- the edge: official vectors

#[test]
fn bip341_output_keys_on_the_even_point_and_not_the_odd() {
    let v: Value = serde_json::from_str(BIP341).unwrap();
    let cases = v["scriptPubKey"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    let (mut even, mut odd) = (0, 0);
    for e in cases {
        let internal = e["given"]["internalPubkey"].as_str().unwrap();
        let root = e["intermediary"]["merkleRoot"].as_str();
        let want = e["intermediary"]["tweakedPubkey"].as_str().unwrap();
        let p = format!("02{internal}");
        let t = tap_tweak(&p, root).unwrap();
        assert_eq!(t, e["intermediary"]["tweak"].as_str().unwrap());
        if x_only(&tweak_point(&p, &t).unwrap()).unwrap() == want {
            even += 1;
        }
        // BIP 341 lifts; this adds to the point as it is
        let q = format!("03{internal}");
        if x_only(&tweak_point(&q, &tap_tweak(&q, root).unwrap()).unwrap()).unwrap() != want {
            odd += 1;
        }
    }
    assert_eq!((even, odd), (7, 7));
}

#[test]
fn bip340_valid_vectors_verify_and_our_signatures_meet_them() {
    let v: Value = serde_json::from_str(BIP340).unwrap();
    let (mut valid, mut ok, mut refused_invalid, mut invalid) = (0, 0, 0, 0);
    for e in v["vectors"].as_array().unwrap() {
        let msg = hex::decode(e["message"].as_str().unwrap()).unwrap();
        let sig = hex::decode(e["signature"].as_str().unwrap()).unwrap();
        let pk = hex::decode(e["pubkey"].as_str().unwrap()).unwrap();
        let verdict = if msg.len() == 32 {
            // the engine this crate signs and verifies with
            match (XOnlyPublicKey::from_slice(&pk), Signature::from_slice(&sig)) {
                (Ok(pk), Ok(sig)) => secp()
                    .verify_schnorr(
                        &sig,
                        &Message::from_digest(msg.clone().try_into().unwrap()),
                        &pk,
                    )
                    .is_ok(),
                _ => false,
            }
        } else {
            // secp256k1 0.29 signs 32-byte digests only; the variable-length
            // vectors are checked by a second engine
            use k256::schnorr::{Signature as KSig, VerifyingKey};
            match (
                VerifyingKey::from_bytes(&pk),
                KSig::try_from(sig.as_slice()),
            ) {
                (Ok(vk), Ok(s)) => vk.verify_raw(&msg, &s).is_ok(),
                _ => false,
            }
        };
        if e["valid"].as_bool().unwrap() {
            valid += 1;
            ok += usize::from(verdict);
        } else {
            invalid += 1;
            refused_invalid += usize::from(!verdict);
        }
    }
    assert_eq!(ok, valid, "every valid official vector verifies");
    assert_eq!(refused_invalid, invalid, "every invalid one is refused");
    assert!(valid >= 9);

    // a signature by a secret verifies against its point's x, for both parities
    let (mut s, mut odd) = (0, 0);
    for i in 0..40 {
        let d = rnd("sign", i);
        let p = public_key(&d).unwrap();
        odd += usize::from(p.starts_with("03"));
        let msg = digest(&d);
        if verifies(&msg, &sign(&msg, &d), &x_only(&p).unwrap()) {
            s += 1;
        }
    }
    assert!(s == 40 && odd > 5 && odd < 35, "{s} {odd}");
}

// ---- the arithmetic: exact on full points, whatever the parity

#[test]
fn additive_tweaks_are_exact_on_full_points() {
    let (mut same, mut odd_base, mut odd_out) = (0, 0, 0);
    for i in 0..500 {
        let (d, t) = (rnd("d", i), rnd("t", i));
        let p = public_key(&d).unwrap();
        odd_base += usize::from(p.starts_with("03"));
        let q = tweak_point(&p, &t).unwrap();
        odd_out += usize::from(q.starts_with("03"));
        same += usize::from(q == public_key(&tweak_secret(&d, &t).unwrap()).unwrap());
    }
    assert_eq!(same, 500);
    assert!(odd_base > 150 && odd_out > 150, "{odd_base} {odd_out}");

    for i in 0..100 {
        let d = rnd("chain", i);
        let tws: Vec<String> = (0..5).map(|j| rnd(&format!("chain {i}"), j)).collect();
        let ps = chain_points(&public_key(&d).unwrap(), &tws).unwrap();
        let ds = chain_secrets(&d, &tws).unwrap();
        assert_eq!(ps.len(), 6);
        assert!(ps
            .iter()
            .zip(&ds)
            .all(|(p, s)| *p == public_key(s).unwrap()));
    }

    let d = rnd("small", 0);
    let small = [hex64(1), hex64(2), hex64(3)];
    let points = chain_points(&public_key(&d).unwrap(), &small).unwrap();
    for (j, s) in chain_secrets(&d, &small).unwrap().iter().enumerate() {
        assert_eq!(public_key(s).unwrap(), points[j]);
    }

    let p = public_key(&d).unwrap();
    assert_eq!(x_only(&negate(&p).unwrap()).unwrap(), x_only(&p).unwrap());
    assert_ne!(negate(&p).unwrap()[..2], p[..2]);
}

// ---- normalise once: a bare identifier (x, read as 02) is exactly the holder's point

#[test]
fn normalise_once() {
    let (mut exact, mut flipped) = (0, 0);
    for i in 0..300 {
        let d = rnd("norm", i);
        let n = normalize(&d).unwrap();
        flipped += usize::from(n != d);
        let p = public_key(&n).unwrap();
        if p.starts_with("02")
            && base_point(&did(&p).unwrap()).unwrap() == p
            && x_only(&p).unwrap() == x_only(&public_key(&d).unwrap()).unwrap()
        {
            exact += 1;
        }
    }
    assert!(
        exact == 300 && flipped > 100 && flipped < 200,
        "{exact} {flipped}"
    );

    // after normalising once, a chain from the bare identifier equals the chain from the
    // secret, through at least one odd-y point, with no further lifting
    let d = normalize(&rnd("chain-did", 0)).unwrap();
    let mut tws = Vec::new();
    let (from_did, from_secret) = loop {
        tws.push(rnd("chain-did-t", tws.len()));
        let from_did = chain_points(
            &base_point(&did(&public_key(&d).unwrap()).unwrap()).unwrap(),
            &tws,
        )
        .unwrap();
        let from_secret: Vec<String> = chain_secrets(&d, &tws)
            .unwrap()
            .iter()
            .map(|s| public_key(s).unwrap())
            .collect();
        if from_did.iter().any(|p| p.starts_with("03")) || tws.len() >= 64 {
            break (from_did, from_secret);
        }
    };
    assert!(from_did.iter().any(|p| p.starts_with("03")));
    assert_eq!(from_did, from_secret);

    // an un-normalised odd-y secret does NOT match the bare identifier
    let raw = rnd("raw", 0);
    let odd = if public_key(&raw).unwrap().starts_with("03") {
        raw
    } else {
        n_minus(&raw)
    };
    assert!(public_key(&odd).unwrap().starts_with("03"));
    assert_ne!(
        tweak_point(
            &base_point(&did(&public_key(&odd).unwrap()).unwrap()).unwrap(),
            &tws[0]
        )
        .unwrap(),
        public_key(&tweak_secret(&odd, &tws[0]).unwrap()).unwrap()
    );
    // signing_key is the normalised secret, and fixed under itself
    assert_eq!(signing_key(&odd).unwrap(), normalize(&odd).unwrap());
    assert_eq!(
        signing_key(&normalize(&odd).unwrap()).unwrap(),
        normalize(&odd).unwrap()
    );
}

// ---- reading keys: identifier, Multikey, compressed point

#[test]
fn reading_and_writing_keys() {
    let d = rnd("read", 0);
    let p = public_key(&d).unwrap();
    let x = x_only(&p).unwrap();
    assert_eq!(
        base_point(&format!("did:nostr:{x}")).unwrap(),
        format!("02{x}")
    );
    // upstream lower-cases first, so an upper-case bare x is read
    assert_eq!(base_point(&x.to_uppercase()).unwrap(), format!("02{x}"));
    assert_eq!(
        base_point(&format!("fe70102{x}")).unwrap(),
        format!("02{x}")
    );
    assert_eq!(
        base_point(&format!("fe70103{x}")).unwrap(),
        format!("03{x}")
    );
    // ... including an upper-case Multikey, which the did:nostr conformance vectors refuse
    assert_eq!(
        base_point(&format!("FE70103{}", x.to_uppercase())).unwrap(),
        format!("03{x}")
    );
    assert_eq!(base_point(&p).unwrap(), p);
    assert_eq!(multikey(&p).unwrap(), format!("fe701{p}"));
    assert_eq!(did(&p).unwrap(), format!("did:nostr:{x}"));
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
    // refused in words
    assert_eq!(base_point(&"00".repeat(32)), Err(KeyError::OffCurve));
    assert!(base_point(&"00".repeat(32))
        .unwrap_err()
        .to_string()
        .contains("curve"));
    for bad in [format!("04{x}"), x[2..].to_string(), "npub1abc".to_string()] {
        let e = base_point(&bad).unwrap_err();
        assert_eq!(e, KeyError::NotAnIdentifier);
        assert!(e.to_string().starts_with("not a"));
    }
    // a Multikey whose point is off the curve is not a point
    assert_eq!(
        base_point(&format!("fe70102{}", "00".repeat(32))),
        Err(KeyError::NotAPoint)
    );
}

// ---- tweaks and their limits

#[test]
fn tweaks_and_their_limits() {
    let d = rnd("limits", 0);
    let p = public_key(&d).unwrap();
    let n = hex::encode(N);
    for e in [
        tweak_point(&p, &hex64(0)).unwrap_err(),
        tweak_point(&p, &n).unwrap_err(),
        public_key(&"00".repeat(32)).unwrap_err(),
    ] {
        assert!(e.to_string().contains("[1, n-1]"), "{e}");
    }
    assert_eq!(
        tweak_secret(&d, &n_minus(&d)),
        Err(KeyError::Cancels),
        "d + (n − d) = 0"
    );
    let s1 = tagged_scalar("test/keys", &[&[0xab, 0xcd]]).unwrap();
    let s2 = tagged_scalar_hex("test/keys", &["abcd"]).unwrap();
    let s3 = tagged_scalar_hex("other", &["abcd"]).unwrap();
    assert!(s1 == s2 && s1 != s3);
    assert!(hex::decode(&s1).unwrap().as_slice() < N.as_slice());
}

#[test]
fn bip86_addresses_from_the_lifted_child_key() {
    let v: Value = serde_json::from_str(BIP86).unwrap();
    let cases = v["addresses"].as_array().unwrap();
    let (mut ok, mut odd) = (0, 0);
    for e in cases {
        let payload = bitcoin::base58::decode_check(e["xpub"].as_str().unwrap()).unwrap();
        let key = hex::encode(&payload[payload.len() - 33..]);
        odd += usize::from(key.starts_with("03"));
        // BIP 86 lifts the child key to x-only: the internal point is the 02 point of its x
        let p = format!("02{}", &key[2..]);
        let q = tweak_point(&p, &tap_tweak(&p, None).unwrap()).unwrap();
        let script = bitcoin::ScriptBuf::from_hex(&format!("5120{}", x_only(&q).unwrap())).unwrap();
        if script_to_address(&script, "bc").as_deref() == e["address"].as_str() {
            ok += 1;
        }
    }
    assert_eq!(ok, cases.len());
    assert!(!cases.is_empty());
    eprintln!("BIP 86: {ok} addresses, {odd} children odd-y");
}

// ---- known answers: keys-vectors.json

fn make(secret: &str, tws: &[String]) -> Value {
    let p = public_key(secret).unwrap();
    let n = normalize(secret).unwrap();
    let from_did =
        chain_points(&base_point(&did(&p).unwrap()).unwrap(), tws).unwrap()[1..].to_vec();
    let from_secret = chain_secrets(&n, tws).unwrap()[1..].to_vec();
    json!({
        "secret": secret,
        "point": p,
        "did": did(&p).unwrap(),
        "multikey": multikey(&p).unwrap(),
        "normalized": n,
        "normalizedPoint": public_key(&n).unwrap(),
        "tweaks": tws,
        "chainFromSecret": from_secret,
        "chainPoints": from_did,
        "outputs": from_did.iter().map(|q| x_only(q).unwrap()).collect::<Vec<_>>(),
        "signingKeys": from_secret.iter().map(|s| signing_key(s).unwrap()).collect::<Vec<_>>(),
    })
}

fn generated() -> Value {
    let d = "11".repeat(32);
    let odd_d = (1u64..)
        .map(hex64)
        .find(|h| public_key(h).unwrap().starts_with("03"))
        .unwrap();
    let tws = vec![
        hex64(1),
        hex64(2),
        tagged_scalar_hex("keys-vectors", &["cafe"]).unwrap(),
    ];
    json!({
        "description": "keys.mjs known answers: a did:nostr identifier read as the 02 point, the secret normalised once, then plain additive tweaks (+1, +2, a tagged scalar) with every intermediate point kept whole; outputs are the x-only forms; signingKeys the key a BIP 340 signature of each output needs",
        "cases": { "evenSecret": make(&d, &tws), "oddSecret": make(&odd_d, &tws) },
    })
}

#[test]
fn keys_vectors_regenerate_byte_for_byte() {
    let g = generated();
    // JSON.stringify(generated, null, 2) + '\n', as `keys-test.mjs --regen` writes it
    assert_eq!(
        format!("{}\n", serde_json::to_string_pretty(&g).unwrap()),
        KEYS_VECTORS
    );
    let odd = &g["cases"]["oddSecret"];
    assert!(odd["point"].as_str().unwrap().starts_with("03"));
    assert_eq!(
        odd["normalized"].as_str().unwrap(),
        n_minus(odd["secret"].as_str().unwrap())
    );
    // each chained secret signs for its output
    let mut s = 0;
    for c in g["cases"].as_object().unwrap().values() {
        for j in 0..3 {
            let out = c["outputs"][j].as_str().unwrap();
            let msg = digest(out);
            if verifies(
                &msg,
                &sign(&msg, c["chainFromSecret"][j].as_str().unwrap()),
                out,
            ) {
                s += 1;
            }
        }
    }
    assert_eq!(s, 6);
}

// ---- the live half: keys.mjs over the same inputs

/// `node xcheck-pegtweak.mjs <mode>` with `input` on stdin, or `None` (and a
/// note) when the reference is not configured or predates the module.
pub fn oracle(mode: &str, module: &str, input: &Value) -> Option<Value> {
    let (Ok(siding), Ok(schema)) = (std::env::var("SIDESTR_SIDING"), std::env::var("SCHEMA"))
    else {
        eprintln!("skipped the {module} oracle: set SIDESTR_SIDING and SCHEMA");
        return None;
    };
    if !PathBuf::from(&siding).join("lib").join(module).exists() {
        eprintln!(
            "skipped the {module} oracle: {siding} predates it (sidestr/spec bd1d692 / 4c4915f)"
        );
        return None;
    }
    let mut child = Command::new("node")
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/xcheck-pegtweak.mjs"))
        .arg(mode)
        .env("SIDESTR_SIDING", siding)
        .env("SCHEMA", schema)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("node on the path");
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "xcheck-pegtweak.mjs {mode} failed");
    Some(serde_json::from_slice(&out.stdout).unwrap())
}

#[test]
fn keys_mjs_agrees() {
    let cases: Vec<Value> = (0..24)
        .map(|i| {
            let d = rnd("oracle", i);
            let tws: Vec<String> = (0..4).map(|j| rnd(&format!("oracle {i}"), j)).collect();
            json!({ "secret": d, "tweaks": tws, "tag": format!("tag {i}"), "data": rnd("data", i) })
        })
        .collect();
    let Some(theirs) = oracle("keys", "keys.mjs", &Value::Array(cases.clone())) else {
        return;
    };
    let theirs = theirs.as_array().unwrap();
    assert_eq!(theirs.len(), cases.len());
    for (c, t) in cases.iter().zip(theirs) {
        let d = c["secret"].as_str().unwrap();
        let tws: Vec<String> = serde_json::from_value(c["tweaks"].clone()).unwrap();
        let p = public_key(d).unwrap();
        let n = normalize(d).unwrap();
        let mine = json!({
            "publicKey": p,
            "normalize": n,
            "signingKey": signing_key(d).unwrap(),
            "did": did(&p).unwrap(),
            "multikey": multikey(&p).unwrap(),
            "negate": negate(&p).unwrap(),
            "basePointMultikey": base_point(&multikey(&p).unwrap()).unwrap(),
            "chainSecrets": chain_secrets(&n, &tws).unwrap(),
            "chainPoints": chain_points(&base_point(&did(&p).unwrap()).unwrap(), &tws).unwrap(),
            "chainFromOwnPoint": chain_points(&p, &tws).unwrap(),
            "taggedScalar": tagged_scalar_hex(c["tag"].as_str().unwrap(), &[c["data"].as_str().unwrap()]).unwrap(),
            "tapTweak": tap_tweak(&p, Some(c["data"].as_str().unwrap())).unwrap(),
            "tapTweakNone": tap_tweak(&p, None).unwrap(),
        });
        assert_eq!(&mine, t, "secret {d}");
    }
    eprintln!("compared {} key cases with keys.mjs", cases.len());
}
