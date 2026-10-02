//! A sidestr chain as a parent (SPEC 3, 3.1): the recorded departure from
//! `siding/lib/parents.mjs` at sidestr/spec `e8deb63` (ADR-0001 D4).
//!
//! SPEC 0.0.5 says a nested chain's `parent` may be a sidestr chain's hash,
//! the id of its kind-3500 chain event. The reference does not carry it:
//! `resolveParent` knows the table alone and throws "unknown parent" for a
//! hash. This file holds both halves:
//!
//! - **parity**: [`resolve_parent`], which every existing validator path
//!   uses, refuses the hash with upstream's words, so no document siding
//!   refuses is accepted there;
//! - **departure**: [`resolve_parent_with`] accepts the same hash and
//!   resolves the family through the parent's document, which the reference
//!   cannot do. The live half runs `parents.mjs` on the very same inputs and
//!   asserts it refuses them, so the day upstream learns hashes this test
//!   fails and the departure is re-judged against its behaviour.
//!
//! The live half needs `SIDESTR_SIDING` (a siding checkout; `parents.mjs`
//! imports nothing, so `SCHEMA` is not needed); without it, it reports
//! itself skipped.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;
use sidestr_core::document::ChainDocument;
use sidestr_core::error::Error;
use sidestr_core::parents::{resolve_parent, resolve_parent_with, Family, ParentRef};

const TRIAL: &str = include_str!("../fixtures/trial/chain.json");

/// The hashes a nested chain might name: a chain event id as a relay serves
/// it (lower case) and as `/^[0-9a-f]{64}$/i` also admits (upper case).
fn hashes() -> Vec<String> {
    vec![
        "5d".repeat(32),
        "0123456789abcdef".repeat(4),
        "0123456789ABCDEF".repeat(4),
    ]
}

/// The siding the child sits beside: a level-1 chain beside `txbt4`.
fn siding() -> ChainDocument {
    let d: ChainDocument = serde_json::from_str(TRIAL).unwrap();
    ChainDocument {
        id: "sidestr:siding".into(),
        name: "siding".into(),
        parent: "txbt4".into(),
        ..d
    }
}

#[test]
fn resolve_parent_refuses_a_chain_hash_with_upstream_s_words() {
    for h in hashes() {
        let e = resolve_parent(&h).unwrap_err();
        assert!(matches!(e, Error::UnknownParent(ref id) if *id == h));
        assert_eq!(
            e.to_string(),
            format!("unknown parent \"{h}\": one of btc, tbtc4, xbt, txbt4, ltc, vtc (SPEC 3.2)")
        );
    }
}

#[test]
fn resolve_parent_with_accepts_the_hash_through_the_parent_s_document() {
    for h in hashes() {
        let p = resolve_parent_with(&h, |asked| {
            assert_eq!(asked, h.to_ascii_lowercase());
            Ok(siding())
        })
        .unwrap();
        assert_eq!(p.family(), Family::Blake2b);
        assert_eq!(p.root().alias, "txbt4");
        assert_eq!(p.depth(), 1);
        let ParentRef::Chain(n) = p else {
            panic!("a hash is a nested parent")
        };
        assert_eq!(n.hash, h.to_ascii_lowercase());
        assert_eq!(n.alias, "sidestr:siding");
    }
}

/// What `parents.mjs` says to each input: `{ ok: true, alias, family }` or
/// `{ ok: false, error }`.
fn reference(siding: &str, inputs: &[String]) -> Vec<Value> {
    let module = PathBuf::from(siding).join("lib").join("parents.mjs");
    let script = r#"
const { pathToFileURL } = await import('node:url');
const { resolveParent } = await import(pathToFileURL(process.argv[1]).href);
const out = JSON.parse(process.argv[2]).map((id) => {
  try { const p = resolveParent(id); return { ok: true, alias: p.alias, family: p.family }; }
  catch (e) { return { ok: false, error: e.message }; }
});
process.stdout.write(JSON.stringify(out));
"#;
    let out = Command::new("node")
        .arg("--input-type=module")
        .arg("-e")
        .arg(script)
        .arg(&module)
        .arg(serde_json::to_string(inputs).unwrap())
        .output()
        .expect("node on the path");
    assert!(
        out.status.success(),
        "node: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

/// The departure, documented: the reference refuses every hash this crate's
/// `resolve_parent_with` accepts, with the same message `resolve_parent`
/// gives; for the table it answers as both do.
#[test]
fn parents_mjs_at_e8deb63_refuses_the_hash_resolve_parent_with_accepts() {
    let Ok(siding_dir) = std::env::var("SIDESTR_SIDING") else {
        eprintln!("skipped the parents.mjs oracle: set SIDESTR_SIDING");
        return;
    };
    let mut inputs = hashes();
    inputs.extend(["txbt4", "btc:testnet4", "xbt"].map(String::from));
    let answers = reference(&siding_dir, &inputs);
    assert_eq!(answers.len(), inputs.len());
    for (id, js) in inputs.iter().zip(&answers) {
        match resolve_parent(id) {
            Err(e) => {
                assert_eq!(js["ok"], false, "{id}: {js}");
                assert_eq!(js["error"], e.to_string(), "{id}");
                // ...and the departure: this port resolves it through the parent's document
                assert_eq!(
                    resolve_parent_with(id, |_| Ok(siding())).unwrap().family(),
                    Family::Blake2b
                );
            }
            Ok(p) => {
                assert_eq!(js["ok"], true, "{id}: {js}");
                assert_eq!(js["alias"], p.alias);
                let family = match p.family {
                    Family::Stock => "stock",
                    Family::Blake2b => "blake2b",
                };
                assert_eq!(js["family"], family);
                assert_eq!(
                    resolve_parent_with(id, |_| unreachable!()).unwrap(),
                    ParentRef::Table(p)
                );
            }
        }
    }
}
