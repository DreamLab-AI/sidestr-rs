//! `send --evm` end to end, offline: a producer's `/chain.json`, `/tip`,
//! `/coins` and `/blocks.dat` served from loopback for a chain naming the
//! `evm` rule, and the binary asked for a dry run. The deposit pays the
//! reserve, the next output is the `evmin:` marker for the address, every
//! input verifies, and the coin carrying an issued asset is never spent,
//! though the producer lists it: the block file says what it carries.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::Command;

use bitcoin::consensus::encode::{deserialize_hex, serialize};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Amount, Transaction, TxOut};
use sidestr_agent::{prepare_evm_deposit, prepare_issue, read_assets, AgentKey, ChainView};
use sidestr_core::block::{challenge_for, pubkey_of, verify_key_path_input};
use sidestr_core::document::{ChainDocument, Peg};
use sidestr_core::marker::evm_deposit_marker;
use sidestr_core::mirror::encode_record;
use sidestr_core::state::{NextBlock, State};
use sidestr_wallet::asset::plain_coins;
use sidestr_wallet::coins::{from_state, Coin};

const TO: &str = "0x4242424242424242424242424242424242424242";

struct Fixture {
    alice: AgentKey,
    /// The document as a producer of the `evm` chain serves it.
    evm_doc: ChainDocument,
    dat: Vec<u8>,
    coins: Vec<Coin>,
    tip: u32,
    /// The coin carrying the issued asset.
    carrier: bitcoin::OutPoint,
}

/// A chain whose genesis pegs two coins to alice, on which she issues an
/// asset. The chain is run by `sidestr-core` without rules; the document a
/// producer serves names `evm` besides (this crate cannot replay that one,
/// which is the point: the deposit reads the assets from the block file).
fn fixture() -> Fixture {
    let producer = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let alice = AgentKey::parse(&"11".repeat(32)).unwrap();
    let mut doc = ChainDocument::from_json(&format!(
        r#"{{"id":"sidestr:agentevm","name":"agentevm","parent":"tbtc4","challenge":"{}",
        "powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","addressPrefix":"ae",
        "genesisTime":1790150000,"signer":"{}","minFeeRate":1,"pegs":[]}}"#,
        challenge_for(&pubkey_of(&producer)).to_hex_string(),
        pubkey_of(&producer)
    ))
    .unwrap();
    for (vout, amount) in [(0u32, 300_000u64), (1, 200_000)] {
        doc.pegs.push(Peg {
            txid: "a".repeat(64),
            vout,
            amount,
            script: alice.script().to_hex_string(),
            extra: Default::default(),
        });
    }
    let mut chain = State::with_key(doc.clone(), &producer).unwrap();
    let mut dat = encode_record(
        0,
        &serialize(&State::genesis_block_for(&doc, &producer).unwrap()),
    );
    let mut t = doc.genesis_time;
    let mut mine = |chain: &mut State, dat: &mut Vec<u8>| {
        t += 1;
        let (m, block) = chain
            .produce(
                &producer,
                &NextBlock {
                    time: t,
                    claims: vec![],
                },
                None,
            )
            .unwrap();
        dat.extend(encode_record(m.height, &serialize(&block)));
    };
    for _ in 0..100 {
        mine(&mut chain, &mut dat);
    }
    let view = ChainView::replay(doc.clone(), &dat, None).unwrap();
    let issue = prepare_issue(&alice, &view, "DEP", 0, 1_000, None, None, 1_790_200_000).unwrap();
    chain.submit(issue.spend.tx.clone()).unwrap();
    mine(&mut chain, &mut dat);
    let view = ChainView::replay(doc.clone(), &dat, None).unwrap();
    let coins = from_state(&chain, &alice.script());
    let carriers: Vec<_> = coins
        .iter()
        .filter(|c| view.assets.carried(&c.outpoint).is_some())
        .map(|c| c.outpoint)
        .collect();
    assert_eq!(carriers.len(), 1);

    let mut v = serde_json::to_value(&doc).unwrap();
    v["rules"] = serde_json::json!(["evm"]);
    v["evm"] = serde_json::json!({ "chainId": 21474 });
    let evm_doc = ChainDocument::from_json_with(&v.to_string(), &["assets", "evm"]).unwrap();
    Fixture {
        alice,
        evm_doc,
        dat,
        coins,
        tip: chain.height(),
        carrier: carriers[0],
    }
}

#[test]
fn the_library_keeps_the_deposit_off_an_asset() {
    let f = fixture();
    // an evm document is not one this crate can replay
    assert!(ChainView::replay(f.evm_doc.clone(), &f.dat, None).is_err());
    let assets = read_assets(&f.evm_doc, &f.dat).unwrap();
    assert!(assets.carried(&f.carrier).is_some());
    let plain = plain_coins(&f.coins, &assets);
    assert_eq!(plain.len(), f.coins.len() - 1);
    let everything: u64 = plain.iter().map(|c| c.value).sum();
    let p = prepare_evm_deposit(
        &f.alice,
        &f.evm_doc,
        &plain,
        f.tip,
        TO,
        everything - 2_000,
        None,
        1_790_300_000,
    )
    .unwrap();
    assert!(p
        .spend
        .tx
        .input
        .iter()
        .all(|i| i.previous_output != f.carrier));
    assert_eq!(p.spend.inputs, plain.len());
}

/// Serve `routes` (path, body) on loopback until the listener is dropped
/// with the process; the base URL.
fn serve(routes: Vec<(String, Vec<u8>)>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut line = String::new();
            let mut reader = BufReader::new(s.try_clone().unwrap());
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            // drain the headers
            let mut h = String::new();
            while reader.read_line(&mut h).is_ok_and(|n| n > 2) {
                h.clear();
            }
            let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
            let (status, body) = routes
                .iter()
                .find(|(p, _)| *p == path)
                .map(|(_, b)| ("200 OK", b.clone()))
                .unwrap_or(("404 Not Found", b"{}".to_vec()));
            let _ = write!(
                s,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(&body);
        }
    });
    base
}

#[test]
fn send_evm_dry_run() {
    let f = fixture();
    let dir = std::env::temp_dir().join(format!("sidestr-agent-evm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("alice.key");
    std::fs::write(&key, format!("{}\n", "11".repeat(32))).unwrap();
    let script = f.alice.script().to_hex_string();
    let url = serve(vec![
        (
            "/chain.json".into(),
            f.evm_doc.to_json().unwrap().into_bytes(),
        ),
        (
            "/tip".into(),
            serde_json::json!({ "height": f.tip, "hash": "00".repeat(32), "time": 1_790_150_101u32 })
                .to_string()
                .into_bytes(),
        ),
        (
            format!("/coins/{script}"),
            serde_json::to_vec(&f.coins).unwrap(),
        ),
        ("/blocks.dat".into(), f.dat.clone()),
    ]);
    let everything: u64 = f
        .coins
        .iter()
        .filter(|c| c.outpoint != f.carrier)
        .map(|c| c.value)
        .sum();
    let amount = (everything - 2_000).to_string();
    let run = |to: &str, amount: &str| {
        Command::new(env!("CARGO_BIN_EXE_sidestr-agent"))
            .args([
                "send",
                "--evm",
                to,
                amount,
                "--dry-run",
                "--url",
                &url,
                "--key-file",
                key.to_str().unwrap(),
            ])
            .output()
            .unwrap()
    };
    let out = run(TO, &amount);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["cmd"], "evm-deposit");
    assert_eq!(v["to"], TO);
    let tx: Transaction = deserialize_hex(v["hex"].as_str().unwrap()).unwrap();
    assert_eq!(tx.output[0].script_pubkey, f.evm_doc.evm_reserve().unwrap());
    assert_eq!(tx.output[0].value.to_sat().to_string(), amount);
    assert_eq!(tx.output[1].script_pubkey, evm_deposit_marker(&[0x42; 20]));
    assert!(tx.input.iter().all(|i| i.previous_output != f.carrier));
    let prevouts: Vec<TxOut> = tx
        .input
        .iter()
        .map(|i| TxOut {
            value: Amount::from_sat(
                f.coins
                    .iter()
                    .find(|c| c.outpoint == i.previous_output)
                    .unwrap()
                    .value,
            ),
            script_pubkey: f.alice.script(),
        })
        .collect();
    for i in 0..tx.input.len() {
        verify_key_path_input(&tx, i, &prevouts).unwrap();
    }
    assert_eq!(v["signedEvent"]["kind"], 23500);
    assert_eq!(v["signedEvent"]["content"], v["hex"]);

    // what only the asset-carrying coin would cover is refused, not taken from it
    let out = run(TO, &(everything + 1).to_string());
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("insufficient"));
    // and a destination that is not a 0x address
    let out = run("0x42", "1000");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("goes to a 0x address"));
    let _ = std::fs::remove_dir_all(&dir);
}
