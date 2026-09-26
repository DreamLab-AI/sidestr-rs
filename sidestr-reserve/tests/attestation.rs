//! The origin-neutral attestation: canonical bytes, field checks, origin
//! separation, BIP-340 signing. No network, no origin library.

use std::str::FromStr;

use sidestr_reserve::secp256k1::{schnorr, Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use sidestr_reserve::{
    attest, verify_digest, AttestationDigest, AttestationSigner, Credit, Error, KeypairSigner,
    Origin, ReserveAttestation, SignedAttestation, Tip, ATTESTATION_TYPE, MAX_SAFE_INTEGER,
};

const TIME: u64 = 1_790_000_000;

fn tron() -> Origin {
    // An account origin: a token contract on TRON, 6 decimals.
    Origin::new("tron", "41a614f803b6fd780986a42c78ec9c7f77e6ded13c", 6).unwrap()
}

fn tip() -> Tip {
    Tip::new(75_000_000, &"0f".repeat(32)).unwrap()
}

fn tx_log(byte: &str, log: u32, amount: u128) -> Credit {
    Credit::new(&format!("{}:{log}", byte.repeat(32)), amount).unwrap()
}

fn credits() -> Vec<Credit> {
    vec![
        tx_log("cc", 3, 2_500_000),
        tx_log("aa", 0, 7_500_000),
        tx_log("aa", 12, 1),
    ]
}

fn attestation() -> ReserveAttestation {
    attest(tron(), tip(), &credits(), "https://api.trongrid.io", TIME).unwrap()
}

/// The canonical bytes for [`attestation`]. A golden value: any change to
/// the format changes it, and a JavaScript validator must produce exactly
/// these bytes. Credit ids sort as byte strings, not by log index, which is
/// why `aa…:12` sits between `aa…:0` and `cc…:3`.
const GOLDEN_JSON: &str = r#"{"amount":"10000001","asset":"41a614f803b6fd780986a42c78ec9c7f77e6ded13c","credits":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:12","cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc:3"],"decimals":6,"network":"tron","source":"https://api.trongrid.io","time":"1790000000","tip_hash":"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f","tip_height":75000000,"type":"sidestr-reserve/attestation/v1"}"#;

/// `printf %s "$GOLDEN_JSON" | sha256sum`.
const GOLDEN_DIGEST: &str = "a2c255da688be7c9d3b01451b374386a6e205b3b52ad26bc737ca69cea12059c";

// ------------------------------------------------------------- canonical form

#[test]
fn canonical_bytes_are_golden() {
    assert_eq!(attestation().canonical_json(), GOLDEN_JSON);
}

#[test]
fn digest_is_the_sha256_of_the_golden_bytes() {
    assert_eq!(attestation().digest().to_string(), GOLDEN_DIGEST);
}

#[test]
fn canonical_keys_are_sorted_and_complete() {
    // serde_json keeps document order in this workspace (preserve_order).
    let parsed: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&attestation().canonical_json()).unwrap();
    let keys: Vec<&str> = parsed.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "amount",
            "asset",
            "credits",
            "decimals",
            "network",
            "source",
            "time",
            "tip_hash",
            "tip_height",
            "type"
        ]
    );
    assert_eq!(parsed["type"], ATTESTATION_TYPE);
}

#[test]
fn credit_order_does_not_matter() {
    let mut reversed = credits();
    reversed.reverse();
    let backward = attest(tron(), tip(), &reversed, "https://api.trongrid.io", TIME).unwrap();
    assert_eq!(attestation(), backward);
    assert_eq!(attestation().digest(), backward.digest());
}

#[test]
fn every_field_changes_the_digest() {
    let base = attestation();
    let mut variants = Vec::new();
    let mut a = base.clone();
    a.amount += 1;
    variants.push(a);
    let mut a = base.clone();
    a.credits.pop();
    variants.push(a);
    let mut a = base.clone();
    a.tip = Tip::new(75_000_001, &"0f".repeat(32)).unwrap();
    variants.push(a);
    let mut a = base.clone();
    a.tip = Tip::new(75_000_000, &"0e".repeat(32)).unwrap();
    variants.push(a);
    let mut a = base.clone();
    a.time += 1;
    variants.push(a);
    let mut a = base.clone();
    a.source = "https://example.invalid".into();
    variants.push(a);
    let mut a = base.clone();
    a.origin = Origin::new("tron", "41a614f803b6fd780986a42c78ec9c7f77e6ded13c", 8).unwrap();
    variants.push(a);
    for v in variants {
        assert_ne!(v.digest(), base.digest());
    }
}

#[test]
fn the_same_holdings_on_two_origins_are_two_statements() {
    // One attestation key may sign for every origin a chain pins; the origin
    // inside the digest keeps a TRON reading from standing for an EVM one.
    let evm = Origin::new("arbitrum", "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", 6).unwrap();
    let on_evm = attest(evm, tip(), &credits(), "https://api.trongrid.io", TIME).unwrap();
    assert_eq!(on_evm.amount, attestation().amount);
    assert_ne!(on_evm.digest(), attestation().digest());
}

#[test]
fn an_empty_reserve_attests_zero() {
    let a = attest(tron(), tip(), &[], "https://api.trongrid.io", TIME).unwrap();
    assert_eq!(a.amount, 0);
    assert!(a.canonical_json().contains(r#""credits":[]"#));
}

#[test]
fn amounts_beyond_u64_are_stated_exactly() {
    // An 18-decimal token overflows u64 at about 18.4 units.
    let big = [
        Credit::new("a:0", u128::from(u64::MAX)).unwrap(),
        Credit::new("a:1", 1).unwrap(),
    ];
    let a = attest(tron(), tip(), &big, "https://api.trongrid.io", TIME).unwrap();
    assert!(a
        .canonical_json()
        .contains(r#""amount":"18446744073709551616""#));
}

// ---------------------------------------------------------------- refusals

#[test]
fn a_credit_listed_twice_is_refused() {
    let mut c = credits();
    c.push(c[0].clone());
    let err = attest(tron(), tip(), &c, "https://api.trongrid.io", TIME).unwrap_err();
    assert!(matches!(err, Error::Credits(_)), "{err}");
}

#[test]
fn an_overflowing_total_is_refused() {
    let c = [
        Credit::new("a:0", u128::MAX).unwrap(),
        Credit::new("a:1", 1).unwrap(),
    ];
    let err = attest(tron(), tip(), &c, "https://api.trongrid.io", TIME).unwrap_err();
    assert!(matches!(err, Error::Credits(_)), "{err}");
}

#[test]
fn identifiers_outside_the_canonical_alphabet_are_refused() {
    for (network, asset) in [
        ("", "x"),
        ("Tron", "x"),
        ("tron", "0xFD08"),
        ("tron", "a b"),
        ("tron", "caf\u{e9}"),
        ("tron", "a\"b"),
        ("tron", &"a".repeat(129)),
    ] {
        assert!(
            Origin::new(network, asset, 6).is_err(),
            "{network:?} {asset:?}"
        );
    }
    assert!(Origin::new("tron", "x", 19).is_err());
    assert!(Credit::new("", 1).is_err());
    assert!(Credit::new("AA:0", 1).is_err());
}

#[test]
fn tips_must_be_lower_case_hex_and_safe_heights() {
    assert!(Tip::new(1, &"AB".repeat(32)).is_err());
    assert!(Tip::new(1, &format!("0x{}", "ab".repeat(31))).is_err());
    assert!(Tip::new(1, &"ab".repeat(31)).is_err());
    assert!(Tip::new(MAX_SAFE_INTEGER + 1, &"ab".repeat(32)).is_err());
    assert!(Tip::new(MAX_SAFE_INTEGER, &"ab".repeat(32)).is_ok());
}

#[test]
fn sources_and_times_are_checked() {
    for source in ["", "has space", "line\nbreak"] {
        assert!(
            attest(tron(), tip(), &[], source, TIME).is_err(),
            "{source:?}"
        );
    }
    assert!(attest(tron(), tip(), &[], "x", MAX_SAFE_INTEGER + 1).is_err());
}

// ----------------------------------------------------------------- signing

fn test_signer() -> KeypairSigner {
    // A fixed test key; never a real attestation key.
    let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
    KeypairSigner::new(Keypair::from_secret_key(&Secp256k1::new(), &sk))
}

#[test]
fn signing_reproduces_bip340_test_vector_0() {
    // BIP-340 test-vectors.csv, index 0: secret key 3, aux_rand all zero,
    // message all zero. libsecp256k1 treats absent aux as 32 zero bytes.
    let mut sk = [0u8; 32];
    sk[31] = 3;
    let signer = KeypairSigner::new(Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&sk).unwrap(),
    ));
    assert_eq!(
        signer.x_only_public_key().to_string().to_uppercase(),
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    );
    let sig = signer.sign_digest(&AttestationDigest([0u8; 32])).unwrap();
    assert_eq!(
        hex::encode_upper(sig.serialize()),
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
    );
}

#[test]
fn verification_accepts_bip340_test_vector_1() {
    let pk = XOnlyPublicKey::from_str(
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
    )
    .unwrap();
    let msg: [u8; 32] =
        hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
            .unwrap()
            .try_into()
            .unwrap();
    let sig = schnorr::Signature::from_str(
        "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
    )
    .unwrap();
    verify_digest(&AttestationDigest(msg), &sig, &pk).unwrap();
    let mut wrong = msg;
    wrong[0] ^= 1;
    assert!(verify_digest(&AttestationDigest(wrong), &sig, &pk).is_err());
}

#[test]
fn a_signed_attestation_verifies_and_tampering_breaks_it() {
    let signed = SignedAttestation::sign(attestation(), &test_signer()).unwrap();
    signed.verify().unwrap();

    let mut inflated = signed.clone();
    inflated.attestation.amount += 1;
    assert!(matches!(inflated.verify(), Err(Error::BadSignature)));

    let mut reissued = signed.clone();
    reissued.attestation.amount += 1;
    reissued.digest = reissued.attestation.digest();
    assert!(matches!(reissued.verify(), Err(Error::BadSignature)));

    let mut moved = signed.clone();
    moved.attestation.origin =
        Origin::new("arbitrum", "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", 6).unwrap();
    assert!(matches!(moved.verify(), Err(Error::BadSignature)));

    let mut other_key = signed;
    other_key.public_key = XOnlyPublicKey::from_str(
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
    )
    .unwrap();
    assert!(matches!(other_key.verify(), Err(Error::BadSignature)));
}

#[test]
fn a_faulty_signer_is_caught() {
    struct Liar(KeypairSigner);
    impl AttestationSigner for Liar {
        fn x_only_public_key(&self) -> XOnlyPublicKey {
            self.0.x_only_public_key()
        }
        fn sign_digest(
            &self,
            _: &AttestationDigest,
        ) -> sidestr_reserve::Result<schnorr::Signature> {
            self.0.sign_digest(&AttestationDigest([7; 32]))
        }
    }
    assert!(matches!(
        SignedAttestation::sign(attestation(), &Liar(test_signer())),
        Err(Error::Signing(_))
    ));
}
