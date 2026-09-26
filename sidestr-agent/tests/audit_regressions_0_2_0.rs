//! The sidestr-agent 0.2.0 verification pass (GPT-6 Astra, 2026-09-23), its
//! probes kept. Only disposable secrets are used.
//!
//! - Item 1: level 1 needs `--peg-address`.
//! - Item 2: level 2 defaults to the challenge.
//! - Item 3: `--peg-key` is opt-in.
//! - Item 4: a secret-shaped destination is refused before any other check.
//!   The first draft of 0.2.0 failed this for 44 of the 50 cases: parse,
//!   file, key and parent errors all came first. None of them echoed the
//!   secret. The argv pre-scan and the top-of-`pegin_plan` checks fixed it.
//!   The parser-form test below was added with the fix.
//! - Item 5: the live peg-in fixture.

use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use bitcoin::key::XOnlyPublicKey;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{Address, Network};
use serde_json::{json, Value};
use sidestr_agent::{parse_pubkey, pegin_plan, PegTarget};
use sidestr_core::document::ChainDocument;
use sidestr_core::federation::Federation;

const FIXTURE: &str = include_str!("fixtures/dreamlab-chain.json");
const ALICE: &str = "c95b519579bda3b5e29f5dca4a0b8f9f1d04d1979d2e4c3a33483a6b34b61d88";
const BOB: &str = "c082a917c7d9141abd2ec7c8b86e6ed52ac25d85a3b3b40b3dbc03dada92e980";
const PEG: &str = "tb1palk8spjn20q8fa3gu8p30tx4xl0mqyk7t3497540zjkmt4zdvesq07eq2k";
const MARKER: &str = "706567696e3a736964657374723a647265616d6c61623a5120c95b519579bda3b5e29f5dca4a0b8f9f1d04d1979d2e4c3a33483a6b34b61d88";

struct ChainFile(std::path::PathBuf);
impl ChainFile {
    fn new(doc: &ChainDocument) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "sidestr-verify-{}-{}.json",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, serde_json::to_vec(doc).unwrap()).unwrap();
        Self(path)
    }

    /// Runs `pegin-plan` against this document with the relays pointed at a
    /// closed local port, so no announcement from a live producer can stand
    /// in for the `--peg-address` these tests are about. The fixture is
    /// `sidestr:dreamlab`, whose producer does announce its peg script on the
    /// public relays since SPEC 0.0.4.
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sidestr-agent"))
            .args(["pegin-plan", "--relays", "ws://127.0.0.1:9", "--chain"])
            .arg(&self.0)
            .args(args)
            .output()
            .unwrap()
    }
}
impl Drop for ChainFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}

fn doc() -> ChainDocument {
    ChainDocument::from_json(FIXTURE).unwrap()
}

fn json_output(out: Output) -> Value {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stderr.is_empty());
    serde_json::from_slice(&out.stdout).unwrap()
}

// Independent of miniscript and pegin_plan: construct the refund script and tree.
fn independent_address(peg: XOnlyPublicKey, refund: XOnlyPublicKey, blocks: u32) -> String {
    let leaf = bitcoin::script::Builder::new()
        .push_x_only_key(&refund)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
        .push_int(i64::from(blocks))
        .push_opcode(bitcoin::opcodes::all::OP_CSV)
        .into_script();
    let tree = TaprootBuilder::new()
        .add_leaf(0, leaf)
        .unwrap()
        .finalize(sidestr_core::block::secp(), peg)
        .unwrap();
    Address::p2tr_tweaked(tree.output_key(), Network::Testnet4).to_string()
}

#[test]
fn item1_level1_without_signer_requires_and_preserves_explicit_address() {
    // Existing tests use a document with a signer; level 1 also includes this case.
    let mut chain = doc();
    chain.signer = None;
    assert!(chain.signers.is_none() && chain.threshold.is_none());
    let refund = parse_pubkey(ALICE).unwrap();
    let side = format!("did:nostr:{ALICE}");
    let err = pegin_plan(&chain, 50_001, &refund, &side, None).unwrap_err();
    assert!(err.to_string().contains("--peg-address"));
    let file = ChainFile::new(&chain);
    let args = ["--amount", "50001", "--refund", ALICE, "--to", &side];
    let refused = file.run(&args);
    assert!(!refused.status.success() && refused.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--peg-address"));
    let mut explicit = args.to_vec();
    explicit.extend(["--peg-address", PEG]);
    let cli = json_output(file.run(&explicit));
    let api = pegin_plan(
        &chain,
        50_001,
        &refund,
        &side,
        Some(PegTarget::Address(PEG.into())),
    )
    .unwrap();
    assert_eq!(cli, serde_json::to_value(api).unwrap());
    assert_eq!(cli["pegAddress"], PEG);
    assert_eq!(cli["coreSend"][0], json!({PEG: "0.00050001"}));
    assert!(cli["descriptor"].is_null());
}

#[test]
fn item2_federated_cli_default_is_challenge_independent_of_refund() {
    // Existing level-2 coverage only calls the library.
    let mut chain = doc();
    chain.signer = None;
    chain.signers = Some(vec![ALICE.into(), BOB.into()]);
    chain.threshold = Some(2);
    chain.challenge.clear();
    chain.challenge = Federation::for_document(&chain)
        .unwrap()
        .unwrap()
        .challenge()
        .to_hex_string();
    let file = ChainFile::new(&chain);
    let expected = Address::from_script(&chain.challenge_script().unwrap(), Network::Testnet4)
        .unwrap()
        .to_string();
    let side = format!("5120{ALICE}");
    for refund in [ALICE, BOB] {
        let plan = json_output(file.run(&["--amount", "50000", "--refund", refund, "--to", &side]));
        assert_eq!(plan["pegAddress"], expected);
        assert_eq!(plan["coreSend"][0], json!({expected.clone(): "0.00050000"}));
        assert!(plan["descriptor"].is_null());
        assert!(plan["note"].as_str().unwrap().starts_with("level 2"));
    }
}

#[test]
fn item3_opt_in_varied_timelocks_checksum_and_cli_conflict() {
    let mut chain = doc();
    let peg = parse_pubkey(BOB).unwrap();
    let refund = parse_pubkey(ALICE).unwrap();
    let side = format!("5120{ALICE}");
    // Existing coverage uses 10000 and checks only the checksum's length.
    for blocks in [1, 144, 65_535] {
        chain.refund_blocks = blocks;
        let plan = pegin_plan(&chain, 50_000, &refund, &side, Some(PegTarget::Key(peg))).unwrap();
        let text = plan.descriptor.unwrap();
        let (body, checksum) = text.split_once('#').unwrap();
        assert_eq!(
            body,
            format!("tr({BOB},and_v(v:pk({ALICE}),older({blocks})))")
        );
        assert_eq!(
            checksum,
            miniscript::descriptor::checksum::desc_checksum(body).unwrap()
        );
        assert!(text
            .parse::<miniscript::Descriptor<XOnlyPublicKey>>()
            .is_ok());
        let corrupt = format!(
            "{body}#{}{}",
            if &checksum[..1] == "q" { "p" } else { "q" },
            &checksum[1..]
        );
        assert!(corrupt
            .parse::<miniscript::Descriptor<XOnlyPublicKey>>()
            .is_err());
        assert_eq!(plan.peg_address, independent_address(peg, refund, blocks));
    }
    let file = ChainFile::new(&chain);
    let out = file.run(&[
        "--amount",
        "50000",
        "--refund",
        ALICE,
        "--to",
        &side,
        "--peg-key",
        BOB,
        "--peg-address",
        PEG,
    ]);
    assert!(!out.status.success() && out.stdout.is_empty());
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(error.contains("cannot be used with"));
    assert!(error.contains("--peg-key") && error.contains("--peg-address"));
}

#[test]
fn item4_secret_refusal_precedes_other_errors_and_never_echoes() {
    let chain = doc();
    let file = ChainFile::new(&chain);
    let side = format!("5120{ALICE}");
    let nsec =
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("nsec").unwrap(), &[11; 32]).unwrap();
    let bare_hex = hex::encode([11; 32]);
    let mut failures = Vec::new();
    let mut total = 0;
    for (encoding, secret) in [("nsec", nsec.as_str()), ("hex", bare_hex.as_str())] {
        for field in ["--to", "--peg-address"] {
            for case in [
                "normal",
                "missing-refund",
                "invalid-refund",
                "invalid-peg-key",
                "conflicting-targets",
                "missing-amount",
                "invalid-amount",
                "unknown-flag",
                "missing-chain",
                "missing-key-file",
                "invalid-side",
            ] {
                let mut args = vec![
                    "--amount",
                    if case == "invalid-amount" {
                        "bad"
                    } else {
                        "50000"
                    },
                ];
                if case == "missing-amount" {
                    args.clear();
                }
                if case != "missing-refund" {
                    args.extend([
                        "--refund",
                        if case == "invalid-refund" {
                            "bad"
                        } else {
                            ALICE
                        },
                    ]);
                }
                args.extend([
                    "--to",
                    if field == "--to" {
                        secret
                    } else if case == "invalid-side" {
                        "did:nostr:bad"
                    } else {
                        &side
                    },
                ]);
                if field == "--peg-address" {
                    args.extend([field, secret]);
                }
                match case {
                    "invalid-peg-key" => args.extend(["--peg-key", "bad"]),
                    "conflicting-targets" => {
                        args.extend(["--peg-key", BOB]);
                        if field == "--to" {
                            args.extend(["--peg-address", PEG]);
                        }
                    }
                    "unknown-flag" => args.push("--verify-unknown"),
                    "missing-key-file" => args.extend(["--key-file", "/dev/null/verify-key"]),
                    _ => {}
                }
                let out = if case == "missing-chain" {
                    Command::new(env!("CARGO_BIN_EXE_sidestr-agent"))
                        .args(["pegin-plan", "--chain", "/dev/null/verify-chain"])
                        .args(&args)
                        .output()
                        .unwrap()
                } else {
                    file.run(&args)
                };
                total += 1;
                let stderr = String::from_utf8_lossy(&out.stderr);
                let stdout = String::from_utf8_lossy(&out.stdout);
                let echoed = stderr.contains(secret) || stdout.contains(secret);
                let secret_first = stderr.contains("looks like a secret key");
                if out.status.success() || !out.stdout.is_empty() || echoed || !secret_first {
                    // Never put the disposable secret or captured diagnostics in failure logs.
                    failures.push(format!(
                        "{encoding} {field} {case}: secret_first={secret_first}, echoed={echoed}"
                    ));
                }
            }
        }
        // The library must also validate both sensitive fields before other errors.
        for (case, parent, side_input, target) in [
            ("unknown-parent-to", "unknown", secret, None),
            (
                "unknown-parent-address",
                "unknown",
                side.as_str(),
                Some(PegTarget::Address(secret.into())),
            ),
            (
                "bad-side-address",
                "tbtc4",
                "did:nostr:bad",
                Some(PegTarget::Address(secret.into())),
            ),
        ] {
            let mut invalid = chain.clone();
            invalid.parent = parent.into();
            let error = pegin_plan(
                &invalid,
                50_000,
                &parse_pubkey(ALICE).unwrap(),
                side_input,
                target,
            )
            .unwrap_err()
            .to_string();
            total += 1;
            if !error.contains("looks like a secret key") || error.contains(secret) {
                failures.push(format!(
                    "{encoding} library {case}: secret refusal did not precede other errors"
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {total} cases failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn item5_live_fixture_derivation_and_input_sensitivity() {
    let chain = doc();
    let signer = parse_pubkey(chain.signer.as_ref().unwrap()).unwrap();
    let alice = parse_pubkey(ALICE).unwrap();
    assert_eq!(chain.id, "sidestr:dreamlab");
    assert_eq!(chain.parent, "tbtc4");
    assert_eq!(chain.challenge, format!("5120{signer}"));
    assert_eq!(chain.refund_blocks, 10_000);
    assert_eq!(independent_address(signer, alice, chain.refund_blocks), PEG);
    // Construct the payload directly, without destination/marker helpers.
    let mut payload = format!("pegin:{}:", chain.id).into_bytes();
    payload.extend([0x51, 0x20]);
    payload.extend(alice.serialize());
    assert_eq!(payload.len(), 57);
    assert_eq!(hex::encode(payload), MARKER);
    let side = format!("5120{ALICE}");
    let baseline = pegin_plan(&chain, 50_000, &alice, &side, Some(PegTarget::Key(signer))).unwrap();
    assert_eq!(baseline.peg_address, PEG);
    assert_eq!(baseline.marker, MARKER);
    // Existing golden assertions do not show which inputs affect which output.
    let bob = parse_pubkey(BOB).unwrap();
    for (peg, refund, blocks) in [
        (bob, alice, 10_000),
        (signer, bob, 10_000),
        (signer, alice, 9_999),
    ] {
        let mut changed = chain.clone();
        changed.refund_blocks = blocks;
        let plan = pegin_plan(&changed, 50_000, &refund, &side, Some(PegTarget::Key(peg))).unwrap();
        assert_eq!(plan.peg_address, independent_address(peg, refund, blocks));
        assert_ne!(plan.peg_address, PEG);
        assert_eq!(plan.marker, MARKER);
    }
    let amount = pegin_plan(&chain, 60_000, &alice, &side, Some(PegTarget::Key(signer))).unwrap();
    assert_eq!(amount.peg_address, PEG);
    assert_eq!(amount.marker, MARKER);
    assert_eq!(amount.core_send[0][PEG], "0.00060000");
    let other_side = pegin_plan(
        &chain,
        50_000,
        &alice,
        &format!("5120{BOB}"),
        Some(PegTarget::Key(signer)),
    )
    .unwrap();
    assert_eq!(other_side.peg_address, PEG);
    assert_ne!(other_side.marker, MARKER);
}

/// Item 4, parser forms: `--flag=value`, and the positional destination of
/// `send` and `burn` behind other flags. Each is refused before clap, the
/// network or any file is touched, and is never echoed.
#[test]
fn secret_refusal_covers_every_parser_form() {
    let nsec =
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("nsec").unwrap(), &[13u8; 32]).unwrap();
    let hex = "0d".repeat(32);
    for secret in [nsec.as_str(), hex.as_str()] {
        let to_eq = format!("--to={secret}");
        let peg_eq = format!("--peg-address={secret}");
        for args in [
            vec!["pegin-plan", to_eq.as_str()],
            vec!["pegin-plan", "--amount", "1", peg_eq.as_str()],
            vec!["pegin-plan", "--nonsense", "--to", secret],
            vec!["send", "--fee", "5", "--dry-run", secret, "100"],
            vec!["--url", "http://127.0.0.1:9", "burn", secret, "20000"],
            vec!["send", secret],
        ] {
            let out = Command::new(env!("CARGO_BIN_EXE_sidestr-agent"))
                .args(&args)
                .output()
                .unwrap();
            let err = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(1), "{args:?}");
            assert!(out.stdout.is_empty());
            assert!(err.contains("looks like a secret key"), "{err}");
            assert!(!err.contains(secret), "echoed");
        }
    }
}
