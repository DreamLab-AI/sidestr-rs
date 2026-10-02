//! ADR-2101 D3, the known-answer test: the spend key is not the identity
//! key, the identity signs the binding that names it, and the host refuses
//! to spend with the identity.
//!
//! The vectors (`fixtures/hitch-binding-kat.json`) come from the estate's
//! own mint: the event id is agentbox's `sidestr-spend-key.js buildBinding`
//! (nostr-tools) for the same keys, chain and time, and the signature (BIP
//! 340, zero auxiliary randomness, so fixed) is verified by nostr-tools
//! `verifyEvent` and agentbox's `verifyBinding`.

use serde_json::Value;
use sidestr_agent::hitch::binding::{sign_binding, verify_binding};
use sidestr_agent::hitch::Error;
use sidestr_agent::AgentKey;

fn kat() -> Value {
    serde_json::from_str(include_str!("fixtures/hitch-binding-kat.json")).unwrap()
}

fn s(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap().to_string()
}

#[test]
fn the_binding_matches_the_independent_vector_byte_for_byte() {
    let v = kat();
    let k_id = AgentKey::parse(&s(&v, "identitySecret")).unwrap();
    let k_spend = AgentKey::parse(&s(&v, "spendSecret")).unwrap();
    assert_eq!(k_id.pubkey().to_string(), s(&v, "identity"));
    assert_eq!(k_spend.pubkey().to_string(), s(&v, "spend"));
    assert_ne!(k_id.pubkey(), k_spend.pubkey(), "k_spend differs from k_id");

    let ev = sign_binding(
        &k_id,
        &k_spend.pubkey(),
        &s(&v, "chain"),
        None,
        &s(&v, "genesis"),
        v["createdAt"].as_u64().unwrap(),
    )
    .unwrap();
    assert_eq!(ev.kind, 38420);
    assert_eq!(ev.pubkey, s(&v, "identity"), "signed by k_id");
    assert_eq!(ev.content, s(&v, "spend"), "names k_spend");
    assert_eq!(ev.id, s(&v, "eventId"));
    assert_eq!(ev.sig, s(&v, "sig"));
    let did = s(&v, "identity");
    assert_eq!(
        ev.tags,
        vec![
            vec!["d".to_string(), format!("{}:{did}", s(&v, "genesis"))],
            vec!["alias".to_string(), s(&v, "chain")],
            vec!["genesis".to_string(), s(&v, "genesis")],
            vec!["legacy".to_string(), "pre-0.0.5".to_string()],
            vec![
                "alt".to_string(),
                format!(
                    "sidestr account binding: the spend key of did:nostr:{did} on {}",
                    s(&v, "chain")
                ),
            ],
        ]
    );
    let b = verify_binding(&ev, &s(&v, "chain"), Some(&s(&v, "genesis"))).unwrap();
    b.check_spender(&k_spend).unwrap();
    assert!(matches!(
        b.check_spender(&k_id),
        Err(Error::SpendIsIdentity)
    ));
}

/// A binding agentbox's mint wrote for a demo agent (S3, `demo-a` on
/// `sidestr:dreamlab-txbt4`) verifies here: the two sides of the estate
/// read the same event.
#[test]
fn an_agentbox_minted_binding_verifies() {
    let ev: sidestr_nostr::event::Event = serde_json::from_str(include_str!(
        "fixtures/agentbox-binding-demo-a-dreamlab-txbt4.json"
    ))
    .unwrap();
    let b = verify_binding(
        &ev,
        "sidestr:dreamlab-txbt4",
        Some("1009aa2984d5c699fe61ef1e5905afe472a49d67551542045726828c8b82d108"),
    )
    .unwrap();
    assert_eq!(
        b.identity,
        "32029837ef5c5b23e271fac22e87e2777183e20eec9ff9c681c641b643e1315d"
    );
    assert_eq!(
        b.spend,
        "add2bae7782fe93369b6a8f5ba0d732fcc74bd665250dc111d7e4b349f0a05e7"
    );
    assert_eq!(b.chain_hash, None);
    assert!(verify_binding(&ev, "sidestr:dreamlab", None).is_err());
}

#[test]
fn the_identity_is_never_bound_as_its_own_spend_key() {
    let v = kat();
    let k_id = AgentKey::parse(&s(&v, "identitySecret")).unwrap();
    assert!(matches!(
        sign_binding(
            &k_id,
            &k_id.pubkey(),
            &s(&v, "chain"),
            None,
            &s(&v, "genesis"),
            1
        ),
        Err(Error::SpendIsIdentity)
    ));
}

/// The binary refuses to run a channel command with the identity key as
/// its spend key, before it reads anything from the network: the producer
/// URL here answers nothing.
#[cfg(all(feature = "cli", unix))]
#[test]
fn the_host_refuses_to_spend_with_k_id() {
    use std::os::unix::fs::PermissionsExt;
    let v = kat();
    let dir = std::env::temp_dir().join(format!("sidestr-hitch-kid-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let state = dir.join("state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let k_id = AgentKey::parse(&s(&v, "identitySecret")).unwrap();
    let k_spend = AgentKey::parse(&s(&v, "spendSecret")).unwrap();
    let ev = sign_binding(
        &k_id,
        &k_spend.pubkey(),
        &s(&v, "chain"),
        None,
        &s(&v, "genesis"),
        v["createdAt"].as_u64().unwrap(),
    )
    .unwrap();
    let binding = state.join("binding.json");
    std::fs::write(&binding, serde_json::to_string(&ev).unwrap()).unwrap();
    std::fs::set_permissions(&binding, std::fs::Permissions::from_mode(0o600)).unwrap();
    let id_file = dir.join("identity.key");
    std::fs::write(&id_file, s(&v, "identitySecret")).unwrap();
    std::fs::set_permissions(&id_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let chain = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dreamlab-txbt4-chain.json"
    );

    for args in [
        vec![
            "open",
            "--peer",
            &"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "--amount",
            "20000",
        ],
        vec!["pay", "--channel", "0011223344556677", "--amount", "1000"],
        vec!["force-close", "--channel", "0011223344556677"],
        vec!["watch"],
    ] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_sidestr-agent"))
            .arg("hitch")
            .args(&args)
            .args([
                "--chain",
                chain,
                "--url",
                "http://127.0.0.1:9",
                "--relays",
                "ws://127.0.0.1:9",
            ])
            .arg("--state")
            .arg(&state)
            .arg("--key-file")
            .arg(&id_file)
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{args:?} ran with k_id");
        assert!(err.contains("k_id never spends"), "{args:?}: {err}");
        // and the secret is never echoed
        assert!(!err.contains(&s(&v, "identitySecret")));
    }
    // `bind` refuses to bind k_id to itself
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sidestr-agent"))
        .args([
            "hitch",
            "bind",
            "--chain",
            chain,
            "--url",
            "http://127.0.0.1:9",
        ])
        .arg("--identity-file")
        .arg(&id_file)
        .arg("--key-file")
        .arg(&id_file)
        .arg("--state")
        .arg(&state)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("k_id never spends"));
    std::fs::remove_dir_all(&dir).unwrap();
}
