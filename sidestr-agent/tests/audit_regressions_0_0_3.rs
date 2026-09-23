//! The SPEC 0.0.3 verification pass (GPT-6 Astra, 2026-09-23), findings 2
//! and 3, pinned as fixed. Disposable keys only.
//!
//! - F3: NIP-19 strings are Bech32. A Bech32m `nsec` or `npub` was accepted
//!   and decoded to the same key. Both are now refused.
//! - F2: an `nsec` given where a destination belongs came back whole in the
//!   binary's error. Secret-shaped text (an `nsec`, or 64 bare hex
//!   characters) is now refused as a destination, a burn target or a peg
//!   address, with an error that never repeats it.

use std::process::Command;

use bech32::{Bech32, Bech32m, Hrp};
use sidestr_agent::{destination, parse_pubkey, refuse_secret, AgentKey};

#[test]
fn nip19_is_bech32_not_bech32m() {
    let bytes = [11u8; 32];
    let standard = bech32::encode::<Bech32>(Hrp::parse("nsec").unwrap(), &bytes).unwrap();
    let wrong_variant = bech32::encode::<Bech32m>(Hrp::parse("nsec").unwrap(), &bytes).unwrap();
    let a = AgentKey::parse(&standard).unwrap();
    assert!(AgentKey::parse(&wrong_variant).is_err());
    let npub =
        bech32::encode::<Bech32>(Hrp::parse("npub").unwrap(), &a.pubkey().serialize()).unwrap();
    assert_eq!(parse_pubkey(&npub).unwrap(), a.pubkey());
    let wrong_pub =
        bech32::encode::<Bech32m>(Hrp::parse("npub").unwrap(), &a.pubkey().serialize()).unwrap();
    assert!(parse_pubkey(&wrong_pub).is_err());
    // an npub under the nsec prefix, and the reverse, are refused too
    let crossed =
        bech32::encode::<Bech32>(Hrp::parse("nsec").unwrap(), &a.pubkey().serialize()).unwrap();
    assert!(parse_pubkey(&crossed).is_err());
}

#[test]
fn a_secret_is_never_a_destination_and_never_echoed() {
    let secret = bech32::encode::<Bech32>(Hrp::parse("nsec").unwrap(), &[11u8; 32]).unwrap();
    let hex_secret = hex::encode([11u8; 32]);
    let key = AgentKey::parse(&secret).unwrap();
    assert!(!format!("{key:?}").contains(&secret));
    for s in [&secret, &hex_secret, &secret.to_uppercase()] {
        let e = destination(s).unwrap_err().to_string();
        assert!(!e.contains(s.as_str()), "{e}");
        assert!(refuse_secret(s).is_err());
    }
    // a full script is still a destination
    assert!(destination(&format!("5120{hex_secret}")).is_ok());

    let chain =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dreamlab-chain.json");
    let pubkey = key.pubkey().to_string();
    let chain = chain.to_str().unwrap();
    for args in [
        vec![
            "pegin-plan",
            "--chain",
            chain,
            "--amount",
            "50000",
            "--refund",
            &pubkey,
            "--to",
            &secret,
        ],
        vec![
            "pegin-plan",
            "--chain",
            chain,
            "--amount",
            "50000",
            "--refund",
            &pubkey,
            "--to",
            &hex_secret,
        ],
        vec![
            "pegin-plan",
            "--chain",
            chain,
            "--amount",
            "50000",
            "--refund",
            &pubkey,
            "--to",
            &format!("5120{pubkey}"),
            "--peg-address",
            &secret,
        ],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_sidestr-agent"))
            .args(&args)
            .output()
            .unwrap();
        assert!(!out.status.success(), "{args:?}");
        assert!(out.stdout.is_empty());
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("looks like a secret key"), "{err}");
        assert!(
            !err.contains(&secret) && !err.contains(&hex_secret),
            "{err}"
        );
    }
}
