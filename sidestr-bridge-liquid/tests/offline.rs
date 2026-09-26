//! Offline tests: key file, descriptor derivation, asset pin, the Liquid
//! reading of the reserve as a `sidestr-reserve` attestation, signing. No
//! network. The format's own vectors (BIP-340, canonical bytes, field
//! checks) are `sidestr-reserve`'s tests.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::str::FromStr;

use lwk_wollet::elements::{AssetId, BlockHash, OutPoint};
use lwk_wollet::registry::RegistryData;
use lwk_wollet::secp256k1::{Keypair, Secp256k1, SecretKey};
use lwk_wollet::WolletDescriptor;
use sidestr_bridge_liquid::{
    attest, credits, origin, reserve_asset, verify_digest, verify_registry_entry,
    AttestationDigest, ChainTip, Error, KeypairSigner, ReserveKey, ReserveSnapshot, ReserveUtxo,
    ReserveWallet, SignedAttestation, KEY_FILE_MODE, MNEMONIC_WORDS, NETWORK, RESERVE_ASSET_ID,
};

/// The BIP-39 reference mnemonic (all-zero entropy). A test key only.
const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// LWK 0.19's own vector for [`ABANDON`] on Liquid mainnet
/// (`lwk_wollet` `descriptor.rs`, `test_dwid`): an independent source for
/// the derivation, written with `h` for hardened steps.
const LWK_MAINNET_VECTOR: &str = "ct(slip77(9c8e4f05c7711a98c838be228bcb84924d4570ca53f35fa1c793e58841d47023),elwpkh([73c5da0a/84h/1776h/0h]xpub6CRFzUgHFDaiDAQFNX7VeV9JNPDRabq6NYSpzVZ8zW8ANUCiDdenkb1gBoEZuXNZb3wPc1SVcDXgD2ww5UBtTb8s8ArAbTkoRQ8qn34KgcY/<0;1>/*))#y8jljyxl";

/// The first two receive addresses of that descriptor. Regression values:
/// recorded from this crate's derivation, which the descriptor vector above
/// pins to LWK's; no second Liquid implementation was available to
/// cross-derive them.
const ABANDON_ADDRESS_0: &str = "lq1qqvxk052kf3qtkxmrakx50a9gc3smqad2ync54hzntjt980kfej9kkfe0247rp5h4yzmdftsahhw64uy8pzfe7cpg4fgykm7cv";
const ABANDON_ADDRESS_1: &str = "lq1qqfk0uw9vlmqlggzs7cxmw49x8ks37l87udspmpt3ssgxjrkqqlww63xvus3c5gaz89r2kd393c4fvurwxf06qj87y2kd3vsln";

// ---------------------------------------------------------------- key file

#[test]
fn descriptor_from_the_test_mnemonic_matches_lwks_vector() {
    let ours = ReserveKey::from_phrase(ABANDON)
        .unwrap()
        .descriptor()
        .unwrap();
    let vector: WolletDescriptor = LWK_MAINNET_VECTOR.parse().unwrap();
    assert_eq!(ours.to_string(), vector.to_string());
    assert!(ours.to_string().contains("[73c5da0a/84'/1776'/0']"));
}

#[test]
fn descriptor_derives_the_known_addresses() {
    let wallet = ReserveWallet::new(
        ReserveKey::from_phrase(ABANDON)
            .unwrap()
            .descriptor()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        wallet.address(Some(0)).unwrap().to_string(),
        ABANDON_ADDRESS_0
    );
    assert_eq!(
        wallet.address(Some(1)).unwrap().to_string(),
        ABANDON_ADDRESS_1
    );
    // Unsynced, the next unused address is index 0.
    assert_eq!(wallet.address(None).unwrap().to_string(), ABANDON_ADDRESS_0);
    // Confidential: the blinding key is part of the address.
    assert!(wallet.address(Some(0)).unwrap().is_blinded());
}

#[test]
fn init_writes_a_24_word_mnemonic_mode_0400() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mnemonic");
    let created = ReserveKey::create(&path).unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, KEY_FILE_MODE);
    let text = fs::read_to_string(&path).unwrap();
    assert_eq!(text.split_whitespace().count(), MNEMONIC_WORDS);
    assert!(text.ends_with('\n'));
    let loaded = ReserveKey::load(&path).unwrap();
    assert_eq!(
        created.descriptor().unwrap().to_string(),
        loaded.descriptor().unwrap().to_string()
    );
}

#[test]
fn init_refuses_to_overwrite_a_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mnemonic");
    fs::write(&path, "existing contents").unwrap();
    let err = ReserveKey::create(&path).unwrap_err();
    assert!(matches!(err, Error::KeyFileExists { .. }), "{err}");
    assert_eq!(fs::read_to_string(&path).unwrap(), "existing contents");
}

#[test]
fn init_refuses_a_dangling_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("elsewhere");
    let path = dir.path().join("mnemonic");
    symlink(&target, &path).unwrap();
    let err = ReserveKey::create(&path).unwrap_err();
    assert!(matches!(err, Error::KeyFileExists { .. }), "{err}");
    assert!(!target.exists());
}

#[test]
fn load_refuses_a_group_or_world_readable_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mnemonic");
    fs::write(&path, ABANDON).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let err = ReserveKey::load(&path).unwrap_err();
    assert!(
        matches!(err, Error::KeyFilePermissions { mode: 0o644, .. }),
        "{err}"
    );
}

#[test]
fn a_bad_mnemonic_is_refused_without_echoing_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mnemonic");
    fs::write(&path, "correct horse battery staple").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let err = ReserveKey::load(&path).unwrap_err();
    assert!(matches!(err, Error::Mnemonic));
    assert!(!err.to_string().contains("horse"));
    assert!(!format!("{err:?}").contains("horse"));
}

#[test]
fn the_key_never_debug_prints() {
    let key = ReserveKey::from_phrase(ABANDON).unwrap();
    assert_eq!(format!("{key:?}"), "ReserveKey(<redacted>)");
}

// ------------------------------------------------------------- asset pin

fn registry_fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/reserve-asset-registry.json")).unwrap()
}

fn entry(value: serde_json::Value) -> RegistryData {
    serde_json::from_value(value).unwrap()
}

#[test]
fn the_pinned_registry_entry_verifies() {
    let fixture = registry_fixture();
    assert_eq!(fixture["asset_id"], RESERVE_ASSET_ID);
    verify_registry_entry(&entry(fixture)).unwrap();
}

#[test]
fn a_contract_that_does_not_commit_to_the_pinned_id_is_refused() {
    // Any change to the contract changes its hash, so the recomputed id.
    let mut fixture = registry_fixture();
    fixture["contract"]["name"] = "Another Dollar".into();
    let err = verify_registry_entry(&entry(fixture)).unwrap_err();
    assert!(err.to_string().contains("commit to"), "{err}");

    let mut fixture = registry_fixture();
    fixture["issuance_prevout"]["vout"] = 1.into();
    let err = verify_registry_entry(&entry(fixture)).unwrap_err();
    assert!(err.to_string().contains("commit to"), "{err}");
}

// ------------------------------------------------------------ attestation

fn hash(byte: &str) -> BlockHash {
    BlockHash::from_str(&byte.repeat(32)).unwrap()
}

fn outpoint(byte: &str, vout: u32) -> OutPoint {
    OutPoint::from_str(&format!("{}:{vout}", byte.repeat(32))).unwrap()
}

fn other_asset() -> AssetId {
    // Liquid's policy asset (L-BTC).
    AssetId::from_str("6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d").unwrap()
}

fn utxo(op: OutPoint, asset: AssetId, value: u64, height: Option<u32>) -> ReserveUtxo {
    ReserveUtxo {
        outpoint: op,
        asset,
        value,
        height,
    }
}

fn snapshot() -> ReserveSnapshot {
    ReserveSnapshot {
        tip: ChainTip {
            height: 4_070_000,
            hash: hash("ab"),
        },
        utxos: vec![
            utxo(
                outpoint("cc", 1),
                reserve_asset(),
                10_0000_0000,
                Some(4_069_000),
            ),
            utxo(
                outpoint("aa", 0),
                reserve_asset(),
                15_0000_0000,
                Some(4_060_000),
            ),
            // L-BTC for fees: not reserve.
            utxo(outpoint("bb", 0), other_asset(), 2_000, Some(4_060_000)),
            // Unconfirmed: not reserve yet.
            utxo(outpoint("dd", 0), reserve_asset(), 99, None),
            // Above the tip the state claims: not counted.
            utxo(outpoint("ee", 0), reserve_asset(), 7, Some(4_070_001)),
        ],
        source: "https://blockstream.info/liquid/api".into(),
    }
}

const TIME: u64 = 1_790_000_000;

/// The canonical bytes for [`snapshot`] at [`TIME`]. A golden value: any
/// change to the Liquid reading or to the `sidestr-reserve` format changes
/// it, and a JavaScript validator must produce exactly these bytes.
const GOLDEN_JSON: &str = r#"{"amount":"2500000000","asset":"ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2","credits":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0","cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc:1"],"decimals":8,"network":"liquid","source":"https://blockstream.info/liquid/api","time":"1790000000","tip_hash":"abababababababababababababababababababababababababababababababab","tip_height":4070000,"type":"sidestr-reserve/attestation/v1"}"#;

#[test]
fn attestation_counts_only_confirmed_reserve_outputs() {
    let a = attest(&snapshot(), &reserve_asset(), TIME).unwrap();
    assert_eq!(a.amount, 25_0000_0000);
    assert_eq!(
        a.credits,
        vec![
            format!("{}:0", "aa".repeat(32)),
            format!("{}:1", "cc".repeat(32))
        ]
    );
    assert_eq!(a.tip.height(), 4_070_000);
    assert_eq!(a.tip.hash(), hash("ab").to_string());
    assert_eq!(a.time, TIME);
}

#[test]
fn the_liquid_origin_is_the_pinned_asset_at_eight_decimals() {
    let a = attest(&snapshot(), &reserve_asset(), TIME).unwrap();
    assert_eq!(a.origin, origin());
    assert_eq!(a.origin.network(), NETWORK);
    assert_eq!(a.origin.asset(), RESERVE_ASSET_ID);
    assert_eq!(a.origin.decimals(), 8);
}

#[test]
fn credits_are_keyed_by_outpoint() {
    let c = credits(&snapshot(), &reserve_asset()).unwrap();
    let mut ids: Vec<&str> = c.iter().map(|c| c.id()).collect();
    ids.sort();
    assert_eq!(
        ids,
        [
            format!("{}:0", "aa".repeat(32)),
            format!("{}:1", "cc".repeat(32))
        ]
    );
}

#[test]
fn attestation_canonical_bytes_are_golden() {
    let a = attest(&snapshot(), &reserve_asset(), TIME).unwrap();
    assert_eq!(a.canonical_json(), GOLDEN_JSON);
}

#[test]
fn attestation_digest_is_stable() {
    let a = attest(&snapshot(), &reserve_asset(), TIME).unwrap();
    // sha256 of GOLDEN_JSON, computed independently with coreutils sha256sum.
    assert_eq!(a.digest().to_string(), GOLDEN_DIGEST);
}

/// `printf %s "$GOLDEN_JSON" | sha256sum`.
const GOLDEN_DIGEST: &str = "17764cf0c39adfea3e2244fed84fcdd11c7a471cd5a552695513017112a4f83e";

#[test]
fn attestation_is_independent_of_utxo_order() {
    let forward = attest(&snapshot(), &reserve_asset(), TIME).unwrap();
    let mut reversed = snapshot();
    reversed.utxos.reverse();
    let backward = attest(&reversed, &reserve_asset(), TIME).unwrap();
    assert_eq!(forward, backward);
    assert_eq!(forward.canonical_json(), backward.canonical_json());
    assert_eq!(forward.digest(), backward.digest());
}

#[test]
fn every_liquid_reading_changes_the_digest() {
    let base = snapshot();
    let digest = |s: &ReserveSnapshot| attest(s, &reserve_asset(), TIME).unwrap().digest();
    let mut variants = Vec::new();
    let mut s = base.clone();
    s.utxos[0].value += 1;
    variants.push(s);
    let mut s = base.clone();
    s.tip.height += 1;
    variants.push(s);
    let mut s = base.clone();
    s.tip.hash = hash("ac");
    variants.push(s);
    let mut s = base.clone();
    s.utxos.remove(0);
    variants.push(s);
    let mut s = base.clone();
    s.source = "https://example.invalid/api".into();
    variants.push(s);
    for v in &variants {
        assert_ne!(digest(v), digest(&base));
    }
    assert_ne!(
        attest(&base, &reserve_asset(), TIME + 1).unwrap().digest(),
        digest(&base)
    );
}

#[test]
fn an_empty_reserve_attests_zero() {
    let mut state = snapshot();
    state.utxos.clear();
    let a = attest(&state, &reserve_asset(), TIME).unwrap();
    assert_eq!(a.amount, 0);
    assert!(a.credits.is_empty());
    assert!(a.canonical_json().contains(r#""credits":[]"#));
}

#[test]
fn attesting_any_other_asset_is_refused() {
    let err = attest(&snapshot(), &other_asset(), TIME).unwrap_err();
    assert!(matches!(err, Error::NotReserveAsset { .. }), "{err}");
}

#[test]
fn a_duplicated_outpoint_is_refused() {
    let mut state = snapshot();
    state.utxos.push(state.utxos[0]);
    let err = attest(&state, &reserve_asset(), TIME).unwrap_err();
    assert!(matches!(err, Error::State(_)), "{err}");
}

#[test]
fn a_total_beyond_u64_is_carried_exactly() {
    // Liquid amounts are u64 each; the neutral total is u128, so the sum of
    // two maximal outputs no longer overflows but is stated exactly.
    let mut state = snapshot();
    state.utxos = vec![
        utxo(outpoint("aa", 0), reserve_asset(), u64::MAX, Some(1)),
        utxo(outpoint("aa", 1), reserve_asset(), 1, Some(1)),
    ];
    let a = attest(&state, &reserve_asset(), TIME).unwrap();
    assert_eq!(a.amount, u128::from(u64::MAX) + 1);
    assert!(a
        .canonical_json()
        .contains(r#""amount":"18446744073709551616""#));
}

// --------------------------------------------------------------- signing

fn test_signer() -> KeypairSigner {
    // A fixed test key; never a real attestation key.
    let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
    KeypairSigner::new(Keypair::from_secret_key(&Secp256k1::new(), &sk))
}

#[test]
fn a_signed_liquid_attestation_verifies_and_tampering_breaks_it() {
    let a = attest(&snapshot(), &reserve_asset(), TIME).unwrap();
    let signed = SignedAttestation::sign(a, &test_signer()).unwrap();
    signed.verify().unwrap();
    verify_digest(&signed.digest, &signed.signature, &signed.public_key).unwrap();

    let mut inflated = signed.clone();
    inflated.attestation.amount += 1;
    assert!(matches!(
        inflated.verify(),
        Err(sidestr_reserve::Error::BadSignature)
    ));

    let mut reissued = signed;
    reissued.attestation.amount += 1;
    reissued.digest = reissued.attestation.digest();
    assert!(matches!(
        reissued.verify(),
        Err(sidestr_reserve::Error::BadSignature)
    ));
    let _: AttestationDigest = reissued.digest;
}
