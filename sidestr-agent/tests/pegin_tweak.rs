//! `pegin-plan --tweak --chain-hash <hex>`: the opt-in peg-in tweak form.
//! Its address is the one `sidestr_core::pegtweak::peg_output` derives from
//! the plan's reveal; without `--tweak` the marker plan is byte for byte what
//! it was (pinned in `tests/fixtures/pegin-plan-dreamlab-peg-key.json`,
//! the marker plan as it stood at cd177ecc, before the tweak form) and carries
//! no reveal.

use std::process::Command;

use serde_json::Value;
use sidestr_agent::{parse_pubkey, pegin_plan, pegin_tweak_plan, PegTarget};
use sidestr_core::document::ChainDocument;
use sidestr_core::pegtweak::{peg_matches, peg_output, PegReveal};

const CHAIN: &str = include_str!("fixtures/dreamlab-chain.json");
const PINNED: &str = include_str!("fixtures/pegin-plan-dreamlab-peg-key.json");
const REFUND: &str = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg";
const PEG_KEY: &str = "c95b519579bda3b5e29f5dca4a0b8f9f1d04d1979d2e4c3a33483a6b34b61d88";

fn side() -> String {
    format!("5120{}", "ab".repeat(32))
}

fn chain_path() -> String {
    format!(
        "{}/tests/fixtures/dreamlab-chain.json",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn run(extra: &[&str]) -> std::process::Output {
    let side = side();
    let chain = chain_path();
    let mut args = vec![
        "pegin-plan",
        "--relays",
        "ws://127.0.0.1:9",
        "--chain",
        chain.as_str(),
        "--amount",
        "50000",
        "--refund",
        REFUND,
        "--to",
        side.as_str(),
    ];
    args.extend_from_slice(extra);
    Command::new(env!("CARGO_BIN_EXE_sidestr-agent"))
        .args(&args)
        .output()
        .unwrap()
}

fn json(out: &std::process::Output) -> Value {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn the_marker_plan_is_unchanged() {
    let out = run(&["--peg-key", PEG_KEY]);
    assert_eq!(String::from_utf8(out.stdout.clone()).unwrap(), PINNED);
    let plan = json(&out);
    assert!(plan.get("reveal").is_none() && plan.get("form").is_none());
    assert_eq!(plan["coreSend"].as_array().unwrap().len(), 2);
    // and the library says the same
    let doc = ChainDocument::from_json(CHAIN).unwrap();
    let lib = pegin_plan(
        &doc,
        50_000,
        &parse_pubkey(REFUND).unwrap(),
        &side(),
        Some(PegTarget::Key(parse_pubkey(PEG_KEY).unwrap())),
    )
    .unwrap();
    assert_eq!(serde_json::to_value(lib).unwrap(), plan);
}

#[test]
fn the_tweak_plan_pays_what_the_reveal_rebuilds() {
    let hash = "cd".repeat(32);
    let plan = json(&run(&["--tweak", "--chain-hash", &hash]));
    assert_eq!(plan["form"], "tweak");
    let reveal: PegReveal = serde_json::from_value(plan["reveal"].clone()).unwrap();
    let o = peg_output(&reveal, "tb").unwrap();
    assert_eq!(plan["pegAddress"], o.address);
    assert_eq!(plan["commitKey"], o.commit_key);
    assert_eq!(plan["outputKey"], o.output_key);
    assert!(peg_matches(&reveal, &o.script_pubkey).unwrap());
    // level 1 by default: the signer's key is the internal key
    let doc = ChainDocument::from_json(CHAIN).unwrap();
    assert_eq!(
        plan["internalKey"].as_str().unwrap(),
        doc.signer.as_deref().unwrap_or(&doc.challenge[4..])
    );
    // one output, no data item, no marker
    let send = plan["coreSend"].as_array().unwrap();
    assert_eq!(send.len(), 1);
    assert!(send[0].get("data").is_none() && plan.get("marker").is_none());
    // the descriptor carries a checksum and the upstream text before it
    let d = plan["descriptor"].as_str().unwrap();
    assert_eq!(d.split('#').next().unwrap(), o.descriptor);
    // the library gives the same plan
    let lib = pegin_tweak_plan(
        &doc,
        50_000,
        &parse_pubkey(REFUND).unwrap(),
        &side(),
        &hash,
        None,
    )
    .unwrap();
    assert_eq!(serde_json::to_value(lib).unwrap(), plan);

    // --peg-key names another internal key, and so another address
    let keyed = json(&run(&[
        "--tweak",
        "--chain-hash",
        &hash,
        "--peg-key",
        PEG_KEY,
    ]));
    assert_eq!(keyed["internalKey"], PEG_KEY);
    assert_ne!(keyed["pegAddress"], plan["pegAddress"]);
    // another chain, another address from the same key
    let other = json(&run(&["--tweak", "--chain-hash", &"ef".repeat(32)]));
    assert_ne!(other["pegAddress"], plan["pegAddress"]);
}

#[test]
fn the_tweak_form_is_opt_in_and_needs_a_chain_hash() {
    // --tweak without --chain-hash, --chain-hash without --tweak, and with --peg-address: refused by the parser
    for extra in [
        vec!["--tweak"],
        vec!["--chain-hash", "cdcd"],
        vec![
            "--tweak",
            "--chain-hash",
            "cdcd",
            "--peg-address",
            "tb1pjzahmlkk5gr3prglljvdz4ne4ly2jadapuytuj0jwa9f46wtzryqx9kkzg",
        ],
    ] {
        assert!(!run(&extra).status.success(), "{extra:?}");
    }
    // an alias is not a chain hash
    let out = run(&["--tweak", "--chain-hash", "sidestr:dreamlab"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("chain event"));
}
