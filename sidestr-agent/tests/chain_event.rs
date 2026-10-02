//! SPEC 0.0.5: `sidestr-agent chain-event`, as `siding chain-event`, and
//! finding a chain by its alias or its hash against sidestr-round's
//! in-process relay, so no network. The live `sidestr:dreamlab` document
//! (`fixtures/dreamlab-chain.json`) has not been published as an event; the
//! tests sign a copy whose challenge is rewritten to a throwaway key, and
//! nothing leaves the process.
#![cfg(feature = "cli")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::Value;
use sidestr_agent::chain::resolve_chain_on;
use sidestr_agent::AgentKey;
use sidestr_nostr::chain::parse_chain_event;
use sidestr_nostr::event::Event;
use sidestr_nostr::tip::{sign_tip, TipTemplate};
use sidestr_round::relay::{publish_one, RelayStandIn};

const DREAMLAB: &str = include_str!("fixtures/dreamlab-chain.json");
const THROWAWAY: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "sidestr-agent-chain-event-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn agent(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sidestr-agent"))
        .args(args)
        .output()
        .unwrap()
}

/// The fixture with its challenge (and so its signer) rewritten to `key`.
fn rewritten(key: &AgentKey) -> String {
    let mut v: Value = serde_json::from_str(DREAMLAB).unwrap();
    v["challenge"] = format!("5120{}", key.pubkey()).into();
    v["signer"] = key.pubkey().to_string().into();
    serde_json::to_string_pretty(&v).unwrap() + "\n"
}

fn write_key(dir: &Path) -> PathBuf {
    let p = dir.join("throwaway.key");
    std::fs::write(&p, format!("{THROWAWAY}\n")).unwrap();
    p
}

#[test]
fn chain_event_refuses_a_key_that_is_not_the_chain_s_signer() {
    let dir = scratch("refused");
    let chain = dir.join("chain.json");
    std::fs::write(&chain, DREAMLAB).unwrap();
    let key = write_key(&dir);
    let out = agent(&[
        "--chain",
        chain.to_str().unwrap(),
        "--key-file",
        key.to_str().unwrap(),
        "chain-event",
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(&format!(
            "the key at {} is not the chain's signer",
            key.display()
        )),
        "{err}"
    );
    assert!(!dir.join("chain-event.json").exists(), "nothing is written");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn chain_event_writes_the_event_beside_the_document() {
    let dir = scratch("written");
    let key = AgentKey::parse(THROWAWAY).unwrap();
    let chain = dir.join("chain.json");
    std::fs::write(&chain, rewritten(&key)).unwrap();
    let key_file = write_key(&dir);
    let out = agent(&[
        "--chain",
        chain.to_str().unwrap(),
        "--key-file",
        key_file.to_str().unwrap(),
        "chain-event",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let printed: Value = serde_json::from_slice(&out.stdout).unwrap();
    let written = dir.join("chain-event.json");
    assert_eq!(printed["written"], written.display().to_string());
    assert_eq!(printed["published"], serde_json::json!({}));
    let text = std::fs::read_to_string(&written).unwrap();
    assert!(text.ends_with("}\n"));
    let ev: Event = serde_json::from_str(&text).unwrap();
    let d = parse_chain_event(&ev).unwrap();
    assert_eq!(d.hash, ev.id);
    assert_eq!(d.alias, "sidestr:dreamlab");
    assert_eq!(d.pubkey, key.pubkey().to_string());
    assert_eq!(printed["hash"], ev.id);
    assert_eq!(printed["alias"], "sidestr:dreamlab");
    assert_eq!(printed["signer"], key.pubkey().to_string());
    // --out names another place
    let elsewhere = dir.join("elsewhere.json");
    let out = agent(&[
        "--chain",
        chain.to_str().unwrap(),
        "--key-file",
        key_file.to_str().unwrap(),
        "chain-event",
        "--out",
        elsewhere.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(elsewhere.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The chain event and a tip naming it, on one in-process relay: resolved
/// by alias, by hash, through the `resolve` command, and published by
/// `chain-event --relay`.
#[tokio::test(flavor = "multi_thread")]
async fn a_chain_is_found_by_its_alias_or_its_hash() {
    let relay = RelayStandIn::start("127.0.0.1:0").await.unwrap();
    let relays = vec![relay.url()];
    let wait = Duration::from_secs(5);
    let key = AgentKey::parse(THROWAWAY).unwrap();
    let dir = scratch("resolve");
    let chain = dir.join("chain.json");
    std::fs::write(&chain, rewritten(&key)).unwrap();
    let key_file = write_key(&dir);

    // the binary publishes the event to the relay named
    let (url, c, k) = (
        relays[0].clone(),
        chain.to_str().unwrap().to_string(),
        key_file.to_str().unwrap().to_string(),
    );
    let out = tokio::task::spawn_blocking(move || {
        agent(&[
            "--chain",
            &c,
            "--key-file",
            &k,
            "chain-event",
            "--relay",
            &url,
        ])
    })
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let printed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(printed["published"][&relays[0]], "ok");
    let hash = printed["hash"].as_str().unwrap().to_string();
    assert!(relay.events().iter().any(|e| e.id == hash));

    // the producer announces the hash with its tip
    let t = TipTemplate::new(
        "sidestr:dreamlab",
        0,
        vec!["00".repeat(80)],
        vec!["https://mirror.example/dreamlab".into()],
    )
    .unwrap()
    .with_chain_hash(&hash)
    .unwrap();
    publish_one(
        &relays[0],
        &sign_tip(&key.event_signer(), &t, 1_790_100_000).unwrap(),
        wait,
    )
    .await;

    let no_json = |_: &str| -> Result<Value, String> { Err("404".into()) };
    let by_alias = resolve_chain_on(&relays, Some("sidestr:dreamlab"), None, wait, no_json)
        .await
        .unwrap();
    assert_eq!(by_alias.hash.as_deref(), Some(hash.as_str()));
    assert_eq!(
        by_alias.mirror.as_deref(),
        Some("https://mirror.example/dreamlab")
    );
    assert!(!by_alias.legacy);
    let by_hash = resolve_chain_on(&relays, None, Some(&hash), wait, no_json)
        .await
        .unwrap();
    assert_eq!(by_hash.alias, "sidestr:dreamlab");
    assert_eq!(by_hash.tip.as_ref().map(|t| t.tip), Some(0));
    assert_eq!(by_hash.document().unwrap().address_prefix, "drm");

    // the command prints the same
    let url = relays[0].clone();
    let h = hash.clone();
    let out = tokio::task::spawn_blocking(move || {
        agent(&[
            "--relays",
            &url,
            "resolve",
            "--chain-hash",
            &h,
            "--timeout",
            "5",
        ])
    })
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let printed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(printed["hash"], hash.as_str());
    assert_eq!(printed["alias"], "sidestr:dreamlab");
    assert_eq!(printed["signer"], key.pubkey().to_string());
    assert_eq!(printed["legacy"], false);
    assert_eq!(printed["chain"]["containment"]["parent"], "tbtc4");

    // an alias nobody announced
    let e = resolve_chain_on(&relays, Some("sidestr:nobody"), None, wait, no_json)
        .await
        .unwrap_err();
    assert!(
        e.to_string()
            .contains("no announcement for sidestr:nobody on 1 relay(s)"),
        "{e}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The live chain's way: its tip names no chain event, so resolving by its
/// alias reads a mirror's chain.json by its `signer` field, with no hash.
#[tokio::test(flavor = "multi_thread")]
async fn a_chain_made_before_0_0_5_resolves_by_its_mirror() {
    let relay = RelayStandIn::start("127.0.0.1:0").await.unwrap();
    let relays = vec![relay.url()];
    let wait = Duration::from_secs(5);
    let doc: Value = serde_json::from_str(DREAMLAB).unwrap();
    // a stand-in for the live signer: the fixture is the live document, so
    // its signer's tip is played by a key the test owns and a copy naming it
    let key = AgentKey::parse(THROWAWAY).unwrap();
    let mut served = doc.clone();
    served["challenge"] = format!("5120{}", key.pubkey()).into();
    served["signer"] = key.pubkey().to_string().into();
    let t = TipTemplate::new(
        "sidestr:dreamlab",
        0,
        vec!["00".repeat(80)],
        vec!["https://mirror.example/dreamlab/".into()],
    )
    .unwrap();
    publish_one(
        &relays[0],
        &sign_tip(&key.event_signer(), &t, 1_790_100_000).unwrap(),
        wait,
    )
    .await;
    let fetch = |u: &str| -> Result<Value, String> {
        if u == "https://mirror.example/dreamlab/chain.json" {
            Ok(served.clone())
        } else {
            Err("404".into())
        }
    };
    let r = resolve_chain_on(&relays, Some("sidestr:dreamlab"), None, wait, fetch)
        .await
        .unwrap();
    assert!(r.legacy);
    assert_eq!(r.hash, None);
    assert_eq!(r.mirror.as_deref(), Some("https://mirror.example/dreamlab"));
    // the live document itself names another signer: that mirror does not check out
    let e = resolve_chain_on(&relays, Some("sidestr:dreamlab"), None, wait, |_| {
        Ok(doc.clone())
    })
    .await
    .unwrap_err();
    assert!(
        e.to_string().contains("no mirror it names checks out"),
        "{e}"
    );
}
