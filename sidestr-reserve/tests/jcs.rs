//! The canonical bytes against RFC 8785 implementations: five attestations
//! whose [`ReserveAttestation::canonical_json`] must equal, byte for byte,
//! what `serde_jcs` and the teller's JCS (solidpayorg/teller
//! `lib/teller.mjs` `jcs` at `7c00cea`) write for the same document handed
//! to them with its keys reversed and pretty-printed. Then the subset
//! [`canonicalize`] accepts, and what it refuses.
//!
//! The teller half needs `TELLER` naming a checkout of solidpayorg/teller
//! and `node` on the path; without them it reports itself skipped, and the
//! `serde_jcs` half still runs.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::{json, Map, Value};
use sidestr_reserve::{
    attest, canonicalize, Credit, Error, Origin, ReserveAttestation, Tip, MAX_SAFE_INTEGER,
};

const TIME: u64 = 1_790_000_000;

fn ids(pairs: &[(&str, u32, u128)]) -> Vec<Credit> {
    pairs
        .iter()
        .map(|(b, i, a)| Credit::new(&format!("{}:{i}", b.repeat(32)), *a).unwrap())
        .collect()
}

/// The five fixtures: an account origin with three credits (the golden of
/// `tests/attestation.rs`), the Liquid adapter's golden, an empty reserve,
/// a `u128::MAX` reserve of an 18-decimal EVM token, and the edges of the
/// alphabet and of the safe integers.
fn fixtures() -> Vec<(&'static str, ReserveAttestation)> {
    let tron = Origin::new("tron", "41a614f803b6fd780986a42c78ec9c7f77e6ded13c", 6).unwrap();
    let liquid = Origin::new(
        "liquid",
        "ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2",
        8,
    )
    .unwrap();
    let eth = Origin::new("eth", "0xdac17f958d2ee523a2206206994597c13d831ec7", 18).unwrap();
    let edge = Origin::new("a.b_c-d:0", "z", 0).unwrap();
    vec![
        (
            "tron, three credits",
            attest(
                tron.clone(),
                Tip::new(75_000_000, &"0f".repeat(32)).unwrap(),
                &ids(&[("cc", 3, 2_500_000), ("aa", 0, 7_500_000), ("aa", 12, 1)]),
                "https://api.trongrid.io",
                TIME,
            )
            .unwrap(),
        ),
        (
            "liquid, the adapter's golden",
            attest(
                liquid,
                Tip::new(4_070_000, &"ab".repeat(32)).unwrap(),
                &ids(&[("cc", 1, 10_0000_0000), ("aa", 0, 15_0000_0000)]),
                "https://blockstream.info/liquid/api",
                TIME,
            )
            .unwrap(),
        ),
        (
            "an empty reserve",
            attest(
                tron,
                Tip::new(0, &"00".repeat(32)).unwrap(),
                &[],
                "own-node",
                0,
            )
            .unwrap(),
        ),
        (
            "u128::MAX of an 18-decimal token",
            attest(
                eth,
                Tip::new(20_000_000, &"9e".repeat(32)).unwrap(),
                &ids(&[("de", 255, u128::MAX)]),
                "https://eth.example/rpc?x=1&y=[2]",
                TIME,
            )
            .unwrap(),
        ),
        (
            "the edges: safe-integer maxima, every allowed source byte",
            attest(
                edge,
                Tip::new(MAX_SAFE_INTEGER, &"f0".repeat(32)).unwrap(),
                &[
                    Credit::new("z", 1).unwrap(),
                    Credit::new("0", 2).unwrap(),
                    Credit::new("a-b.c_d:e", 3).unwrap(),
                    Credit::new(":", 4).unwrap(),
                ],
                "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~",
                MAX_SAFE_INTEGER,
            )
            .unwrap(),
        ),
    ]
}

/// `v` with every object's keys in reverse order: what a canonicaliser must
/// put back in order. serde_json keeps document order in this workspace
/// (`preserve_order`), so the reversal survives into the text.
fn reversed(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, x) in m.iter().rev() {
                out.insert(k.clone(), reversed(x));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(reversed).collect()),
        x => x.clone(),
    }
}

/// The documents the implementations are handed: reversed keys,
/// pretty-printed, so nothing about the canonical bytes is given to them.
fn shuffled_documents() -> Vec<(&'static str, String, String)> {
    fixtures()
        .into_iter()
        .map(|(name, a)| {
            let canonical = a.canonical_json().unwrap();
            let doc = serde_json::to_string_pretty(&reversed(&a.to_value().unwrap())).unwrap();
            assert_ne!(doc, canonical);
            (name, canonical, doc)
        })
        .collect()
}

/// The teller's JCS of each document, or `None` when the checkout is not
/// named.
fn teller(docs: &[String]) -> Option<Vec<String>> {
    let dir = std::env::var("TELLER").ok()?;
    let mut child = Command::new("node")
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/xcheck-jcs.mjs"))
        .env("TELLER", dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("node");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(docs).unwrap().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "xcheck-jcs.mjs failed");
    Some(serde_json::from_slice(&out.stdout).unwrap())
}

// ------------------------------------------------------------ the fixtures

#[test]
fn five_fixtures_canonicalise_as_serde_jcs_does() {
    let docs = shuffled_documents();
    assert_eq!(docs.len(), 5);
    for (name, canonical, doc) in docs {
        let parsed: Value = serde_json::from_str(&doc).unwrap();
        assert_eq!(serde_jcs::to_string(&parsed).unwrap(), canonical, "{name}");
        assert_eq!(canonicalize(&parsed).unwrap(), canonical, "{name}");
    }
}

#[test]
fn five_fixtures_canonicalise_as_the_teller_does() {
    let docs = shuffled_documents();
    let texts: Vec<String> = docs.iter().map(|(_, _, d)| d.clone()).collect();
    let Some(theirs) = teller(&texts) else {
        eprintln!("skipped the teller half: set TELLER to a checkout of solidpayorg/teller");
        return;
    };
    assert_eq!(theirs.len(), docs.len());
    for ((name, canonical, _), t) in docs.iter().zip(&theirs) {
        assert_eq!(t, canonical, "{name}");
    }
    eprintln!("compared {} attestations with the teller's JCS", docs.len());
}

#[test]
fn the_tellers_own_jcs_vector() {
    // solidpayorg/teller test/teller-test.mjs at 7c00cea, "JCS: keys sorted
    // at every level, strings and numbers as JSON".
    let v = json!({ "b": 1, "a": { "d": "x", "c": [2, { "f": 0, "e": null }] } });
    let expected = r#"{"a":{"c":[2,{"e":null,"f":0}],"d":"x"},"b":1}"#;
    assert_eq!(canonicalize(&v).unwrap(), expected);
    assert_eq!(serde_jcs::to_string(&v).unwrap(), expected);
}

// ------------------------------------------------------------- the subset

#[test]
fn the_subset_agrees_with_serde_jcs() {
    for v in [
        json!(null),
        json!(true),
        json!(false),
        json!(0),
        json!(-1),
        json!(MAX_SAFE_INTEGER),
        json!(-(MAX_SAFE_INTEGER as i64)),
        json!(""),
        json!(" !#~'"),
        json!([]),
        json!({}),
        json!([[], {}, [null, [true]]]),
        json!({ "B": 1, "a": 2, "_": 3, "A": 4, "~": 5, " ": 6, "10": 7, "9": 8 }),
        json!({ "z": { "y": { "x": [3, 2, 1] } }, "": "empty key" }),
    ] {
        assert_eq!(
            canonicalize(&v).unwrap(),
            serde_jcs::to_string(&v).unwrap(),
            "{v}"
        );
    }
}

fn refused(v: &Value) -> String {
    match canonicalize(v) {
        Err(Error::Canonical { path, reason }) => format!("{path}: {reason}"),
        other => panic!("{v} was not refused: {other:?}"),
    }
}

#[test]
fn a_float_is_refused() {
    for v in [
        json!(0.5),
        json!(1.0),
        json!(-0.0),
        json!(1e300),
        json!({ "amount": 2.5 }),
        serde_json::from_str::<Value>("[1, 2.0]").unwrap(),
    ] {
        assert!(refused(&v).contains("not an integer"), "{v}");
    }
    assert_eq!(
        refused(&json!({ "a": [0, 0.5] })),
        "$.a[1]: 0.5 is not an integer"
    );
}

#[test]
fn a_non_ascii_key_is_refused() {
    for key in ["caf\u{e9}", "\u{20ac}", "\u{1f600}", "\u{7f}", "a\u{0}"] {
        let mut m = Map::new();
        m.insert(key.into(), json!(1));
        assert!(refused(&Value::Object(m)).contains("key"), "{key:?}");
    }
    // nested too, and named by where it is
    let v = json!({ "outer": { "na\u{ef}ve": true } });
    assert!(refused(&v).starts_with("$.outer: key"));
}

#[test]
fn keys_and_strings_needing_an_escape_are_refused() {
    for s in [
        "a\"b",
        "a\\b",
        "line\nbreak",
        "tab\t",
        "\u{1f}",
        "\u{7f}",
        "\u{e9}",
    ] {
        refused(&json!(s));
        refused(&json!([s]));
        let mut m = Map::new();
        m.insert(s.into(), json!(0));
        refused(&Value::Object(m));
    }
}

#[test]
fn integers_beyond_two_to_the_53_are_refused() {
    refused(&json!(MAX_SAFE_INTEGER + 1));
    refused(&json!(u64::MAX));
    refused(&json!(-(MAX_SAFE_INTEGER as i64) - 1));
    refused(&json!(i64::MIN));
    canonicalize(&json!(MAX_SAFE_INTEGER)).unwrap();
}
