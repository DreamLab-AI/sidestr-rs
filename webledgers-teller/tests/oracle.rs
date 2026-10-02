//! The teller itself as the oracle (solidpayorg/teller at `7c00cea`).
//!
//! Two halves, both gated on `TELLER` naming a checkout of the teller, with
//! `SCHEMA` (bitcoin-desktop/schema), `BLAKETESTNODE` (bitcoin-blake/
//! blaketestnode) and `SIDESTR_LIB` (sidestr/spec `siding/lib`, at `bd1d692`
//! or later for `keys.mjs`; `SIDESTR_SIDING` + `/lib` when `SIDESTR_LIB` is
//! unset) and `node` on the path. Without `TELLER` each reports itself
//! skipped.
//!
//! - The teller's own suite, `test/teller-test.mjs`, against those
//!   checkouts: 24 passed.
//! - `tests/xcheck-teller.mjs` runs the same cases through `lib/teller.mjs`
//!   and this crate and the two must agree: JCS, accounts, amounts, new
//!   ledgers and their hashes, scripts of credits, transfers and debits
//!   (outcomes, refusals word for word, the final ledger JSON), deposit
//!   addresses for every form of operator key (both parities) and account,
//!   deposit secrets, watch lists, payout plans with their unsigned
//!   transactions and txids, payouts signed here checked by the teller's
//!   kernel and payouts signed by the teller checked here, request tags, and
//!   requests signed on each side read back by the other.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::Transaction;
use serde_json::{json, Value};
use sidestr_core::block::secp;
use sidestr_core::sighash::verify_taproot_key_path;
use webledgers_teller::*;

struct Oracle {
    teller: String,
    schema: String,
    btn: String,
    lib: String,
}

fn oracle() -> Option<Oracle> {
    let teller = std::env::var("TELLER").ok()?;
    let need = |k: &str| {
        std::env::var(k).unwrap_or_else(|_| panic!("TELLER is set, so {k} must name its checkout"))
    };
    let lib = std::env::var("SIDESTR_LIB")
        .ok()
        .or_else(|| {
            std::env::var("SIDESTR_SIDING")
                .ok()
                .map(|s| format!("{s}/lib"))
        })
        .expect("TELLER is set, so SIDESTR_LIB (or SIDESTR_SIDING) must name siding's lib");
    assert!(
        Path::new(&lib).join("keys.mjs").exists(),
        "{lib} has no keys.mjs: the teller needs sidestr/spec at bd1d692 or later"
    );
    Some(Oracle {
        teller,
        schema: need("SCHEMA"),
        btn: need("BLAKETESTNODE"),
        lib,
    })
}

fn node(o: &Oracle, script: &Path, stdin: &str) -> std::process::Output {
    let mut child = Command::new("node")
        .arg(script)
        .env("TELLER", &o.teller)
        .env("SCHEMA", &o.schema)
        .env("BLAKETESTNODE", &o.btn)
        .env("SIDESTR_LIB", &o.lib)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("node");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn the_tellers_own_suite_passes() {
    let Some(o) = oracle() else {
        eprintln!("skipped the teller's suite: set TELLER to a checkout of solidpayorg/teller");
        return;
    };
    let out = node(&o, &Path::new(&o.teller).join("test/teller-test.mjs"), "");
    let text = String::from_utf8_lossy(&out.stdout);
    eprintln!("{text}");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("24 passed, 0 failed"), "{text}");
}

// ---- the cross-check

fn key(label: &str) -> SecretKey {
    SecretKey::from_slice(&sha256::Hash::hash(label.as_bytes()).to_byte_array()).unwrap()
}
fn point(d: &SecretKey) -> String {
    hex::encode(PublicKey::from_secret_key(secp(), d).serialize())
}
fn sk_hex(d: &SecretKey) -> String {
    hex::encode(d.secret_bytes())
}
fn key_of_parity(label: &str, odd: bool) -> SecretKey {
    (0u32..)
        .map(|i| key(&format!("{label}/{i}")))
        .find(|k| point(k).starts_with(if odd { "03" } else { "02" }))
        .unwrap()
}
fn did(d: &SecretKey) -> String {
    format!("did:nostr:{}", pubkey_hex(d))
}

fn res<T>(r: Result<T>, f: impl FnOnce(T) -> Value) -> Value {
    match r {
        Ok(v) => json!({ "ok": f(v) }),
        Err(e) => json!({ "error": e.to_string() }),
    }
}
fn outcome(o: Outcome) -> Value {
    match o {
        Outcome::Applied => json!({ "applied": true }),
        Outcome::Skipped(why) => json!({ "applied": false, "why": why }),
    }
}
fn s(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}
fn plan_view(p: &Plan) -> Value {
    json!({
        "picked": p.picked.iter().map(|c| format!("{}:{}", c.txid, c.vout)).collect::<Vec<_>>(),
        "outputs": p.outputs, "fee": p.fee, "change": p.change, "rate": p.rate,
    })
}
fn payout_params(v: &Value) -> (Vec<Coin>, u64, u64, String, String) {
    (
        serde_json::from_value(v["coins"].clone()).unwrap(),
        v["amount"].as_u64().unwrap(),
        v["rate"].as_u64().unwrap(),
        s(&v["toScript"]),
        s(&v["changeScript"]),
    )
}
fn plan_of(v: &Value) -> Result<Plan> {
    let (coins, amount, rate, to, change) = payout_params(v);
    plan_payout(&PayoutParams {
        coins: &coins,
        amount,
        rate,
        to_script: &to,
        change_script: &change,
    })
}
fn ledger_params(v: &Value) -> LedgerParams<'_> {
    let mut p = LedgerParams::new(
        v["operator"].as_str().unwrap(),
        v["name"].as_str().unwrap(),
        v["created"].as_u64().unwrap(),
    );
    if let Some(c) = v.get("currency").and_then(Value::as_str) {
        p.currency = c;
    }
    if let Some(c) = v.get("confirmations").and_then(Value::as_u64) {
        p.confirmations = c;
    }
    p
}
fn op_of(v: &Value) -> Result<Op> {
    s(v).parse()
}

#[test]
fn the_teller_and_this_crate_agree() {
    let Some(o) = oracle() else {
        eprintln!("skipped the teller cross-check: set TELLER to a checkout of solidpayorg/teller");
        return;
    };
    let op_even = key_of_parity("xcheck/operator/even", false);
    let op_odd = key_of_parity("xcheck/operator/odd", true);
    let alice = key_of_parity("xcheck/alice", true);
    let bob = key_of_parity("xcheck/bob", false);
    let (a, b) = (did(&alice), did(&bob));
    let ax = pubkey_hex(&alice);

    let ledger =
        json!({ "operator": did(&op_odd), "name": "Table 7", "created": 1_759_300_000u64 });
    let l = new_ledger(&ledger_params(&ledger)).unwrap();
    let lh = l.hash.clone();
    let l2h = new_ledger(&LedgerParams::new(&did(&op_odd), "Table 8", 1_759_300_000))
        .unwrap()
        .hash;

    let jcs_cases = vec![
        json!({ "b": 1, "a": { "d": "x", "c": [2, { "f": 0, "e": null }] } }),
        json!({ "é": 1, "e": 2, "\u{10000}": 3, "\u{ffff}": 4, "a\"b": "\u{1}\n\u{2028}<>&", "t": true, "n": [] }),
        json!([{ "z": { "y": { "x": [1, -2, 0] } } }, "", false, 2_100_000_000_000_000u64]),
        serde_json::to_value(&l.genesis).unwrap(),
    ];
    let accounts = vec![
        a.clone(),
        ax.clone(),
        ax.to_uppercase(),
        format!("  DID:NOSTR:{ax}\n"),
        format!("fe70102{ax}"),
        format!("fe70103{ax}"),
        format!("\u{feff}{ax}\u{3000}"),
        format!("fe70104{ax}"),
        format!("did:nostr:{}", &ax[1..]),
        format!("did:nostr:02{ax}"),
        "npub1x".into(),
        String::new(),
    ];
    let sats_cases = [
        "0",
        "123",
        " 0042 ",
        "2100000000000000",
        "2100000000000001",
        "1.5",
        "-1",
        "1e3",
        "",
        "0x10",
        "99999999999999999999",
    ];
    let ledgers = vec![
        ledger.clone(),
        json!({ "operator": ax, "name": "é".repeat(80), "created": 1, "currency": "tbtc4", "confirmations": 6 }),
        json!({ "operator": format!("fe70103{}", pubkey_hex(&op_even)), "name": "a\"b\\c\u{1}", "created": 1_759_300_000u64 }),
        json!({ "operator": did(&op_even), "name": "x".repeat(81), "created": 1 }),
        json!({ "operator": did(&op_even), "name": "", "created": 1 }),
        json!({ "operator": "npub1", "name": "x", "created": 1 }),
    ];
    let ab = |id: &str, from: &str, to: &str, amount: u64| json!({ "id": id, "from": from, "to": to, "amount": amount });
    let ops = vec![
        json!({ "fn": "credit", "arg": { "account": a, "txid": "ab".repeat(32), "vout": 0, "value": 50_000, "height": 152_100 }, "now": 1_759_300_010u64 }),
        json!({ "fn": "credit", "arg": { "account": ax, "txid": "ab".repeat(32), "vout": 0, "value": 50_000 }, "now": 1_759_300_011u64 }),
        json!({ "fn": "credit", "arg": { "account": format!("fe70102{}", pubkey_hex(&bob)), "txid": "ab".repeat(32), "vout": 1, "value": 7 }, "now": 1_759_300_005u64 }),
        json!({ "fn": "credit", "arg": { "account": a, "txid": "AB".repeat(32), "vout": 2, "value": 1 }, "now": 1_759_300_012u64 }),
        json!({ "fn": "transfer", "arg": ab("r1", &a, &b, 20_000), "now": 1_759_300_020u64 }),
        json!({ "fn": "transfer", "arg": ab("r1", &a, &b, 20_000), "now": 1_759_300_021u64 }),
        json!({ "fn": "transfer", "arg": ab("r2", &b, &a, 20_008), "now": 1_759_300_022u64 }),
        json!({ "fn": "transfer", "arg": ab("r3", &b, &a, 0), "now": 1_759_300_023u64 }),
        json!({ "fn": "transfer", "arg": ab("r4", &a, &a, 100), "now": 1_759_300_024u64 }),
        json!({ "fn": "debit", "arg": { "id": "w1", "account": b, "amount": 20_007, "to": "tb1p…", "txid": "cd".repeat(32) }, "now": 1_759_300_030u64 }),
        json!({ "fn": "debit", "arg": { "id": "w1", "account": b, "amount": 20_007, "to": "tb1p…", "txid": "cd".repeat(32) }, "now": 1_759_300_031u64 }),
        json!({ "fn": "debit", "arg": { "id": "w2", "account": a, "amount": 545, "to": "x", "txid": "ef".repeat(32) }, "now": 1_759_300_032u64 }),
        json!({ "fn": "debit", "arg": { "id": "w3", "account": a, "amount": 30_001, "to": "x", "txid": "ef".repeat(32) }, "now": 1_759_300_033u64 }),
        json!({ "fn": "debit", "arg": { "id": "w4", "account": a, "amount": 546, "to": "x", "txid": "ef".repeat(32) }, "now": 1_759_300_001u64 }),
    ];
    let ledger_scripts = vec![json!({ "ledger": ledger, "ops": ops })];

    let operators = [
        did(&op_odd),
        pubkey_hex(&op_odd),
        point(&op_odd),
        format!("fe701{}", point(&op_odd)),
        format!("02{}", pubkey_hex(&op_odd)),
        point(&op_even),
        point(&op_even).to_uppercase(),
        format!("did:nostr:{}", "00".repeat(32)),
        "04".to_owned() + &pubkey_hex(&op_even),
    ];
    let mut deposits = Vec::new();
    for op in &operators {
        for (acct, nonce, hrp) in [
            (a.as_str(), 0u64, "tb"),
            (ax.as_str(), 1, "tb"),
            (b.as_str(), 9_007_199_254_740_991, "bc"),
            (b.as_str(), 0, "ts"),
        ] {
            deposits.push(json!({ "operatorPoint": op, "ledgerHash": lh, "account": acct, "nonce": nonce, "hrp": hrp }));
        }
    }
    deposits.push(json!({ "operatorPoint": did(&op_even), "ledgerHash": l2h, "account": a, "nonce": 0, "hrp": "tb" }));
    deposits.push(json!({ "operatorPoint": did(&op_even), "ledgerHash": lh.to_uppercase(), "account": a, "nonce": 0, "hrp": "tb" }));
    deposits.push(json!({ "operatorPoint": did(&op_even), "ledgerHash": lh, "account": "npub1", "nonce": 0, "hrp": "tb" }));

    let da = deposit_address(&did(&op_odd), &lh, &a, 0, DEFAULT_HRP).unwrap();
    let db = deposit_address(&did(&op_odd), &lh, &b, 0, DEFAULT_HRP).unwrap();
    let dop = deposit_address(&did(&op_odd), &lh, &did(&op_odd), 0, DEFAULT_HRP).unwrap();
    let secrets: Vec<Value> = [&op_odd, &op_even]
        .iter()
        .flat_map(|k| {
            [&da, &db, &dop].map(|d| json!({ "operatorSecret": sk_hex(k), "tweak": d.tweak }))
        })
        .collect();

    let coins = vec![
        Coin::from_deposit(&da, &"11".repeat(32), 0, 40_000),
        Coin::from_deposit(&db, &"22".repeat(32), 1, 30_000),
        Coin::from_deposit(&da, &"33".repeat(32), 7, 30_000),
        Coin::from_deposit(&dop, &format!("{}01", "fe".repeat(31)), 3, 600),
    ];
    let to = format!("5120{}", "33".repeat(32));
    let plan_case = |coins: &[Coin], amount: u64, rate: u64| json!({ "coins": coins, "amount": amount, "rate": rate, "toScript": to, "changeScript": dop.script });
    let mut plans = Vec::new();
    for (amount, rate) in [
        (50_000, 1),
        (40_000, 1),
        (99_000, 3),
        (100_000, 1),
        (100_440, 1),
        (99_000, 1000),
        (545, 1),
        (1000, 0),
        (1000, 1001),
        (39_800, 1),
    ] {
        plans.push(plan_case(&coins, amount, rate));
    }
    plans.push(plan_case(&coins[..1], 40_000 - 200, 1));
    plans.push(plan_case(&coins[..1], 40_000 - 160 - 330, 1));
    plans.push(plan_case(&[], 1000, 1));

    let payable: Vec<Value> = vec![
        plan_case(&coins, 50_000, 1),
        plan_case(&coins, 90_000, 2),
        plan_case(&coins[..1], 39_800, 1),
    ];
    let js_payouts: Vec<Value> = payable
        .iter()
        .map(|p| json!({ "plan": p, "operatorSecret": sk_hex(&op_odd) }))
        .chain([json!({ "plan": payable[0], "operatorSecret": sk_hex(&op_even) })])
        .collect();
    let rust_signed: Vec<(Plan, SignedPayout)> = payable
        .iter()
        .map(|p| {
            let plan = plan_of(p).unwrap();
            let s = sign_payout(&plan, &op_odd, TXBT4_RULES).unwrap();
            (plan, s)
        })
        .collect();
    let rust_payouts: Vec<Value> = rust_signed
        .iter()
        .map(|(p, s)| {
            let prevouts: Vec<Value> = p
                .picked
                .iter()
                .map(|c| json!({ "value": c.value, "scriptPubKey": c.script }))
                .collect();
            json!({ "hex": s.hex, "prevouts": prevouts })
        })
        .collect();

    let tb1p = "tb1pfu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4quvla6g";
    let request_tag_cases = vec![
        json!({ "ledgerHash": lh, "op": "join", "amount": null, "to": null, "id": "00112233" }),
        json!({ "ledgerHash": lh, "op": "join", "amount": 5, "to": "x", "id": "00112233" }),
        json!({ "ledgerHash": lh, "op": "withdraw", "amount": 1000, "to": format!("  {tb1p}\t"), "id": "deadbeef01" }),
        json!({ "ledgerHash": lh, "op": "transfer", "amount": 5, "to": ax.to_uppercase(), "id": "deadbeef02" }),
        json!({ "ledgerHash": lh, "op": "transfer", "amount": 5, "to": "npub1", "id": "deadbeef03" }),
        json!({ "ledgerHash": lh, "op": "withdraw", "amount": null, "to": tb1p, "id": "deadbeef04" }),
        json!({ "ledgerHash": lh, "op": "withdraw", "amount": 10, "to": null, "id": "deadbeef05" }),
        json!({ "ledgerHash": lh, "op": "withdraw", "amount": 10, "to": "", "id": "deadbeef06" }),
        json!({ "ledgerHash": lh, "op": "withdraw", "amount": 2_100_000_000_000_001u64, "to": tb1p, "id": "deadbeef07" }),
        json!({ "ledgerHash": lh.to_uppercase(), "op": "join", "amount": null, "to": null, "id": "deadbeef08" }),
        json!({ "ledgerHash": lh, "op": "pay", "amount": null, "to": null, "id": "deadbeef09" }),
    ];
    let rust_events: Vec<(Event, String)> = vec![
        (
            request_event(
                &alice,
                &RequestParams::join(&lh, &request_id([5; 16])),
                1_759_300_100,
            )
            .unwrap(),
            lh.clone(),
        ),
        (
            request_event(
                &bob,
                &RequestParams::withdraw(&lh, 1000, tb1p, "deadbeef01"),
                1_759_300_101,
            )
            .unwrap(),
            lh.clone(),
        ),
        (
            request_event(
                &alice,
                &RequestParams::transfer(&lh, 5, &b, "deadbeef02"),
                1_759_300_102,
            )
            .unwrap(),
            lh.clone(),
        ),
        (
            request_event(
                &alice,
                &RequestParams::transfer(&lh, 5, &b, "deadbeef02"),
                1_759_300_102,
            )
            .unwrap(),
            l2h.clone(),
        ),
        (
            request_event(&alice, &RequestParams::join(&lh, "short"), 1_759_300_103).unwrap(),
            lh.clone(),
        ),
        (
            request_event(
                &alice,
                &RequestParams::join(&lh, &"A".repeat(32)),
                1_759_300_104,
            )
            .unwrap(),
            lh.clone(),
        ),
        (
            Event {
                content: "x".into(),
                ..request_event(&bob, &RequestParams::join(&lh, "deadbeef03"), 1_759_300_105)
                    .unwrap()
            },
            lh.clone(),
        ),
        (
            Event {
                kind: 3701,
                ..request_event(&bob, &RequestParams::join(&lh, "deadbeef04"), 1_759_300_106)
                    .unwrap()
            },
            lh.clone(),
        ),
    ];
    let rust_requests: Vec<Value> = rust_events
        .iter()
        .map(|(ev, h)| json!({ "event": ev, "ledgerHash": h }))
        .collect();
    let js_requests = vec![
        json!({ "key": sk_hex(&alice), "req": { "ledgerHash": lh, "op": "join", "id": "cafebabe00" } }),
        json!({ "key": sk_hex(&bob), "req": { "ledgerHash": lh, "op": "withdraw", "amount": "1000", "to": tb1p } }),
        json!({ "key": sk_hex(&alice), "req": { "ledgerHash": lh, "op": "transfer", "amount": 5, "to": format!("fe70103{}", pubkey_hex(&bob)), "id": "cafebabe02" } }),
    ];

    // the script, run here, gives the ledger the watch list reads
    let mut lscript = new_ledger(&ledger_params(&ledger)).unwrap();
    let mut script_results = Vec::new();
    for op in ledger_scripts[0]["ops"].as_array().unwrap() {
        let (arg, now) = (&op["arg"], op["now"].as_u64().unwrap());
        let r = match op["fn"].as_str().unwrap() {
            "credit" => credit(
                &mut lscript,
                &Credit {
                    account: s(&arg["account"]),
                    txid: s(&arg["txid"]),
                    vout: arg["vout"].as_u64().unwrap() as u32,
                    value: arg["value"].as_u64().unwrap(),
                    height: arg["height"].as_u64(),
                },
                now,
            ),
            "transfer" => transfer(
                &mut lscript,
                &Transfer {
                    id: s(&arg["id"]),
                    from: s(&arg["from"]),
                    to: s(&arg["to"]),
                    amount: arg["amount"].as_u64().unwrap(),
                },
                now,
            ),
            "debit" => debit(
                &mut lscript,
                &Debit {
                    id: s(&arg["id"]),
                    account: s(&arg["account"]),
                    amount: arg["amount"].as_u64().unwrap(),
                    to: s(&arg["to"]),
                    txid: s(&arg["txid"]),
                },
                now,
            ),
            other => panic!("{other}"),
        };
        script_results.push(res(r, outcome));
    }
    let watch = vec![
        json!({ "ledger": lscript, "operatorPoint": point(&op_odd), "extra": [did(&key("xcheck/carol")), a] }),
        json!({ "ledger": lscript, "operatorPoint": did(&op_odd), "extra": ["npub1"] }),
    ];

    let cases = json!({
        "jcs": jcs_cases, "accounts": accounts, "sats": sats_cases, "ledgers": ledgers,
        "ledgerScripts": ledger_scripts, "deposits": deposits, "secrets": secrets, "watch": watch,
        "plans": plans, "jsPayouts": js_payouts, "rustPayouts": rust_payouts,
        "requestTags": request_tag_cases, "rustRequests": rust_requests, "jsRequests": js_requests,
    });
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/xcheck-teller.mjs");
    let out = node(&o, &script, &cases.to_string());
    assert!(
        out.status.success(),
        "xcheck-teller.mjs: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let js: Value = serde_json::from_slice(&out.stdout).unwrap();
    let mut compared = 0usize;
    let mut same = |what: &str, ours: Value, theirs: &Value| {
        assert_eq!(&ours, theirs, "{what}");
        compared += 1;
    };

    for (v, t) in jcs_cases.iter().zip(js["jcs"].as_array().unwrap()) {
        same("jcs", json!(jcs(v)), t);
    }
    for (x, t) in accounts.iter().zip(js["accounts"].as_array().unwrap()) {
        same(
            &format!("accountOf {x:?}"),
            res(account_of(x), |v| json!(v)),
            t,
        );
    }
    for (x, t) in sats_cases.iter().zip(js["sats"].as_array().unwrap()) {
        same(&format!("sats {x:?}"), res(sats(x), |v| json!(v)), t);
    }
    for (p, t) in ledgers.iter().zip(js["ledgers"].as_array().unwrap()) {
        let ours = res(new_ledger(&ledger_params(p)), |l| {
            serde_json::to_value(l).unwrap()
        });
        same(&format!("newLedger {p}"), ours, t);
        if let Some(theirs) = t.get("ok") {
            // a ledger the teller wrote loads here and is the same ledger
            let l: Ledger = parse_ledger(&theirs.to_string()).unwrap();
            assert_eq!(ledger_hash(&l), s(&theirs["hash"]));
        }
    }
    {
        let t = &js["ledgerScripts"][0];
        for (i, (r, tr)) in script_results
            .iter()
            .zip(t["results"].as_array().unwrap())
            .enumerate()
        {
            same(&format!("ledger op {i}"), r.clone(), tr);
        }
        same(
            "ledger after the script",
            serde_json::to_value(&lscript).unwrap(),
            &t["ledger"],
        );
        same("total", json!(total(&lscript).unwrap()), &t["total"]);
        let balances: Vec<u64> = lscript
            .entries
            .iter()
            .map(|e| balance(&lscript, &e.url).unwrap())
            .collect();
        same("balances", json!(balances), &t["balances"]);
        parse_ledger(&t["ledger"].to_string()).unwrap();
    }
    for (d, t) in deposits.iter().zip(js["deposits"].as_array().unwrap()) {
        let ours = res(
            deposit_address(
                &s(&d["operatorPoint"]),
                &s(&d["ledgerHash"]),
                &s(&d["account"]),
                d["nonce"].as_u64().unwrap(),
                &s(&d["hrp"]),
            ),
            |v| serde_json::to_value(v).unwrap(),
        );
        same(&format!("depositAddress {d}"), ours, t);
    }
    for (c, t) in secrets.iter().zip(js["secrets"].as_array().unwrap()) {
        let sk = SecretKey::from_slice(&hex::decode(s(&c["operatorSecret"])).unwrap()).unwrap();
        same(
            "depositSecret",
            res(deposit_secret(&sk, &s(&c["tweak"])), |d| json!(sk_hex(&d))),
            t,
        );
    }
    for (c, t) in watch.iter().zip(js["watch"].as_array().unwrap()) {
        let l: Ledger = serde_json::from_value(c["ledger"].clone()).unwrap();
        let extra: Vec<String> = serde_json::from_value(c["extra"].clone()).unwrap();
        let extra: Vec<&str> = extra.iter().map(String::as_str).collect();
        let ours = res(watch_list(&l, &s(&c["operatorPoint"]), &extra), |v| {
            json!(v.iter().map(|d| d.address.clone()).collect::<Vec<_>>())
        });
        same("watchList", ours, t);
    }
    for (p, t) in plans.iter().zip(js["plans"].as_array().unwrap()) {
        let ours = res(plan_of(p), |plan| {
            let tx = unsigned_tx(&plan).unwrap();
            json!({ "plan": plan_view(&plan), "unsignedHex": bitcoin::consensus::encode::serialize_hex(&tx), "txid": tx.compute_txid().to_string() })
        });
        same(
            &format!("planPayout amount {} rate {}", p["amount"], p["rate"]),
            ours,
            t,
        );
    }
    for (c, t) in js_payouts.iter().zip(js["jsPayouts"].as_array().unwrap()) {
        let plan = plan_of(&c["plan"]).unwrap();
        let op = SecretKey::from_slice(&hex::decode(s(&c["operatorSecret"])).unwrap()).unwrap();
        let Some(theirs) = t.get("ok") else {
            // refused there (the wrong operator's secret): refused here in the same words
            same(
                "a payout refused",
                res(sign_payout(&plan, &op, TXBT4_RULES), |_| Value::Null),
                t,
            );
            continue;
        };
        same(
            "the teller's payout plan",
            plan_view(&plan),
            &theirs["plan"],
        );
        let tx: Transaction = deserialize_hex(&s(&theirs["hex"])).unwrap();
        let pv = prevouts(&plan).unwrap();
        for i in 0..tx.input.len() {
            verify_taproot_key_path(&tx, i, &pv, TXBT4_RULES)
                .unwrap_or_else(|e| panic!("the teller's input {i}: {e}"));
            assert_eq!(tx.input[i].witness.nth(0).unwrap()[64], 0x21);
        }
        same(
            "the teller's payout txid",
            json!(tx.compute_txid().to_string()),
            &theirs["txid"],
        );
        same(
            "the teller's payout vsize",
            json!(vsize_of(&tx)),
            &theirs["vsize"],
        );
        // the same plan signed here: the same transaction but for the signatures' randomness
        let ours = sign_payout(&plan, &op, TXBT4_RULES).unwrap();
        assert_eq!(ours.txid, s(&theirs["txid"]));
        assert_eq!(ours.vsize, theirs["vsize"].as_u64().unwrap());
    }
    for ((_, sgn), t) in rust_signed
        .iter()
        .zip(js["rustPayouts"].as_array().unwrap())
    {
        let theirs = t
            .get("ok")
            .unwrap_or_else(|| panic!("the teller's kernel: {t}"));
        let checks = theirs["checks"].as_array().unwrap();
        assert_eq!(checks.len(), sgn.tx.input.len());
        same(
            "this crate's payout, by the teller's kernel",
            json!(vec!["ok"; checks.len()]),
            &theirs["checks"],
        );
        same("vsizeOf", json!(sgn.vsize), &theirs["vsize"]);
        same("txid", json!(sgn.txid), &theirs["txid"]);
        same("hex", json!(sgn.hex), &theirs["hex"]);
    }
    for (c, t) in request_tag_cases
        .iter()
        .zip(js["requestTags"].as_array().unwrap())
    {
        let ours = match op_of(&c["op"]) {
            Ok(op) => {
                let to = c["to"].as_str();
                let p = RequestParams {
                    ledger_hash: c["ledgerHash"].as_str().unwrap(),
                    op,
                    amount: c["amount"].as_u64(),
                    to,
                    id: c["id"].as_str().unwrap(),
                };
                res(request_tags(&p), |v| json!(v))
            }
            Err(e) => json!({ "error": e.to_string() }),
        };
        same(&format!("requestTags {c}"), ours, t);
    }
    for ((ev, h), t) in rust_events
        .iter()
        .zip(js["rustRequests"].as_array().unwrap())
    {
        let ours = res(parse_request(ev, h), |r| {
            let mut v = json!({ "id": r.id, "op": r.op.as_str(), "account": r.account, "created_at": r.created_at });
            if let Some(amount) = r.amount {
                v["amount"] = json!(amount);
            }
            if let Some(to) = r.to {
                v["to"] = json!(to);
            }
            v
        });
        same("parseRequest of a request signed here", ours, t);
    }
    let want = [
        (Op::Join, a.clone(), None, None),
        (Op::Withdraw, b.clone(), Some(1000), Some(tb1p.to_owned())),
        (Op::Transfer, a.clone(), Some(5), Some(b.clone())),
    ];
    for (t, (op, account, amount, to)) in js["jsRequests"].as_array().unwrap().iter().zip(want) {
        let ev: Event = serde_json::from_value(t["ok"].clone()).unwrap();
        let r = parse_request(&ev, &lh).unwrap();
        assert_eq!((r.op, r.account, r.amount, r.to), (op, account, amount, to));
        compared += 1;
    }
    eprintln!("compared {compared} results with the teller");
}
