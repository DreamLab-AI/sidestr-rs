//! BIP 21 payment requests against Reef (bitcoin-blake/reef `lib/wallet.mjs
//! parsePaymentUri` at `648487a`): every string in the corpus below is read
//! by [`PaymentRequest::parse`] and by Reef's own parser, and the two must
//! agree on whether it is a request, on the address, amount and words, and
//! on the reason for a refusal, word for word (Reef names itself where this
//! crate says "this wallet"). The corpus is Reef's own test cases, the edges
//! of its expressions, and URIs built by [`PaymentRequest::to_uri`], which
//! Reef must also read back to exactly what was built.
//!
//! The Reef half needs `REEF` naming a checkout of bitcoin-blake/reef and
//! `node` on the path; without them it reports itself skipped, and the Rust
//! half (every built URI read back by this crate) still runs.
//!
//! One divergence is deliberate and kept out of the corpus: a label or
//! message cut at 200 UTF-16 code units in the middle of a surrogate pair.
//! Reef keeps the lone half; a Rust `String` cannot hold it, so this crate
//! drops it.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use sidestr_wallet::bip21::{PaymentRequest, MAX_SATS};

const TB1P: &str = "tb1pfu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4quvla6g";
const TB1Q: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
const BC1P: &str = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";

/// `encodeURIComponent`, as Reef's test feeds amounts in.
fn encode_uri_component(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// Strings to read: Reef's tests, then the edges.
fn parse_corpus() -> Vec<String> {
    let a = TB1P;
    let mut v = vec![
        // Reef test/wallet-test.mjs, in order
        format!("bitcoin:{a}?amount=0.001&label=Table%207&message=buy-in+for+seat+3"),
        format!("bitcoin:{a}"),
        format!("BITCOIN:{}?AMOUNT=1.00000001", a.to_uppercase()),
        a.to_string(),
        "lightning:x".into(),
        String::new(),
        format!("bitcoin:{a}?amount=0.5&lightning=lnbc1&foo=bar"),
        format!("bitcoin:{a}?req-pop=x"),
        format!("bitcoin:{a}?amount=0.0"),
        format!("bitcoin:{a}?amount=1&amount=2"),
        "bitcoin:?amount=1".into(),
        format!("bitcoin:{a}?label=%E0%A4%A"),
        format!("bitcoin:{a}?label={}", "x".repeat(500)),
        // the shape
        format!("bitcoin:{a}#x"),
        format!("bitcoin:{a}?amount=1#x"),
        "bitcoin".into(),
        "bitcoin:".into(),
        " bitcoin ".into(),
        format!("\u{feff}\n bitcoin:{a}\t\u{3000}"),
        format!("\u{85}bitcoin:{a}"),
        format!("BitCoin:{a}"),
        format!("bitcoın:{a}"),
        format!("bitcoin:{a}?&&amount=1&"),
        "bitcoin:TB1Q?amount=1.".into(),
        "bitcoin:Tb1Q".into(),
        "bitcoin:12".into(),
        format!("bitcoin:{TB1Q}?amount=21000000"),
        format!("bitcoin:{BC1P}?message=%F0%9F%90%9F"),
        // words
        format!("bitcoin:{a}?LABEL=a&label=caf%C3%A9+%2B+%26&message=%F0%9F%90%9F"),
        format!("bitcoin:{a}?foo=%zz"),
        format!("bitcoin:{a}?label={}", "é".repeat(300)),
        format!("bitcoin:{a}?label={}", "🐟".repeat(150)),
        format!("bitcoin:{a}?REQ-Foo"),
        format!("bitcoin:{a}?req-{}=1", "y".repeat(60)),
        format!("bitcoin:{a}?req=1"),
        format!("bitcoin:{a}?amount"),
        format!("bitcoin:{a}?amount={}", "x".repeat(60)),
        format!("bitcoin:{a}?amount=99999999999.123456789"),
    ];
    for bad in [
        "%",
        "%4",
        "%4g",
        "abc%",
        "%C0%AF",
        "%ED%A0%80",
        "%80",
        "%E2%82",
    ] {
        v.push(format!("bitcoin:{a}?label={bad}"));
    }
    for amount in [
        "1,5",
        "1 000",
        "-1",
        "0.001BTC",
        "1e-3",
        "0.000000001",
        "1",
        "1.",
        ".5",
        "00.00000001",
        "21000000",
        "21000000.00000000",
        "21000000.00000001",
        "0000000000000000000000000001",
        "99999999999999999999999999",
        "",
        ".",
        "1..2",
        "+1",
        " 1",
        "1_000",
        "١",
        "0",
        ".00000000",
        "1.123456789",
    ] {
        v.push(format!(
            "bitcoin:{a}?amount={}",
            encode_uri_component(amount)
        ));
        v.push(format!("bitcoin:{a}?amount={amount}"));
    }
    v
}

/// Requests built here, each of which Reef must read back unchanged.
fn built() -> Vec<PaymentRequest> {
    let words = [
        "",
        "Table 7",
        "buy-in for seat 3 + tip: 100% & more",
        "a=b&c=d?e#f",
        "!'()*~._-",
        "café, naïve, Œuvre",
        "🐟 and 🦀",
        "line one\nline two\ttab",
        "plus+plus%2B",
    ];
    let mut out = Vec::new();
    for (i, address) in [TB1P, TB1Q, BC1P, &TB1P.to_uppercase()]
        .into_iter()
        .enumerate()
    {
        for (j, sats) in [
            None,
            Some(1),
            Some(100_000),
            Some(123_456_789),
            Some(MAX_SATS),
        ]
        .into_iter()
        .enumerate()
        {
            let label = words[(i + j) % words.len()];
            let message = words[(i * 3 + j + 1) % words.len()];
            let mut r = PaymentRequest::new(address)
                .unwrap()
                .with_label(label)
                .unwrap()
                .with_message(message)
                .unwrap();
            if let Some(s) = sats {
                r = r.with_amount(s).unwrap();
            }
            out.push(r);
        }
    }
    let r = PaymentRequest::new(TB1P).unwrap();
    out.push(r.clone().with_label(&"x".repeat(200)).unwrap());
    out.push(r.with_message(&"🐟".repeat(100)).unwrap());
    out
}

/// This crate's reading, in the shape Reef's parser returns.
fn ours(uri: &str) -> Value {
    match PaymentRequest::parse(uri) {
        Ok(None) => json!({ "ok": null }),
        Ok(Some(r)) => json!({ "ok": {
            "address": r.address(), "sats": r.sats(), "label": r.label(), "message": r.message(),
        } }),
        Err(e) => json!({ "error": e.to_string() }),
    }
}

/// Reef's readings, or `None` when the checkout is not named.
fn reef(uris: &[String]) -> Option<Vec<Value>> {
    let dir = std::env::var("REEF").ok()?;
    let mut child = Command::new("node")
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/xcheck-bip21.mjs"))
        .env("REEF", dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("node");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(uris).unwrap().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "xcheck-bip21.mjs failed");
    let mut v: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    for r in &mut v {
        if let Some(Value::String(e)) = r.get_mut("error") {
            *e = e.replace("Reef does not support", "this wallet does not support");
        }
    }
    Some(v)
}

#[test]
fn built_requests_read_back_here() {
    for r in built() {
        let uri = r.to_uri();
        assert_eq!(
            PaymentRequest::parse(&uri).unwrap().as_ref(),
            Some(&r),
            "{uri}"
        );
    }
}

#[test]
fn reef_reads_every_string_as_this_crate_does() {
    let built = built();
    let mut uris = parse_corpus();
    uris.extend(built.iter().map(PaymentRequest::to_uri));
    let Some(theirs) = reef(&uris) else {
        eprintln!("skipped the Reef half: set REEF to a checkout of bitcoin-blake/reef");
        return;
    };
    assert_eq!(theirs.len(), uris.len());
    for (uri, t) in uris.iter().zip(&theirs) {
        assert_eq!(&ours(uri), t, "{uri:?}");
    }
    // and what was built is what Reef read
    for (r, t) in built.iter().zip(&theirs[uris.len() - built.len()..]) {
        assert_eq!(
            t["ok"],
            json!({ "address": r.address(), "sats": r.sats(), "label": r.label(), "message": r.message() }),
            "{}",
            r.to_uri()
        );
    }
    eprintln!("compared {} strings with Reef", uris.len());
}
