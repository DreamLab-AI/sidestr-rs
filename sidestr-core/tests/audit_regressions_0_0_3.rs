//! The SPEC 0.0.3 verification pass (GPT-6 Astra, 2026-09-23), finding 1,
//! pinned as fixed. The reference's `scanPegins` asks the peg wallet about
//! an output only by the address the node reported
//! (`o.scriptPubKey.address && await ownedByPegWallet(…)`). The Rust
//! parent view used to decode each transaction from its hex and derive the
//! address from the script. So an output the node gave no address was still
//! asked about, and could be claimed, where the reference found no peg-in.
//! `ParentBlock::addresses` now carries what the node said.
//!
//! The same verbosity-2 block is served to `CoreRpc` over HTTP by a
//! stand-in, and handed to the reference's `scanPegins` in Node, twice:
//! - with the peg output's `address` omitted, neither engine finds a peg-in,
//!   and neither asks the wallet;
//! - with it present, both find the peg at the same output, amount and
//!   address, each after one `getaddressinfo`.
//!
//! Needs `SIDESTR_SIDING`; reports itself skipped without it.
#![cfg(feature = "rpc")]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant};

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::script::PushBytesBuf;
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, Network, Transaction, TxIn, TxOut,
};
use serde_json::{json, Value};
use sidestr_core::marker::peg_marker_data;
use sidestr_core::parent::{owned_by_peg_wallet, rpc::CoreRpc, scan_pegins, FoundPegin};

/// A Core stand-in serving `block` until it has been idle for two seconds.
/// Returns the URL and a handle yielding the methods it was asked.
fn serve(block: Value) -> (String, std::thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let mut methods = Vec::new();
        let mut last = Instant::now();
        while last.elapsed() < Duration::from_secs(2) {
            let Ok((mut stream, _)) = listener.accept() else {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some((k, v)) = line.split_once(':') {
                    if k.eq_ignore_ascii_case("content-length") {
                        length = v.trim().parse().unwrap();
                    }
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let request: Value = serde_json::from_slice(&body).unwrap();
            let method = request["method"].as_str().unwrap().to_string();
            let result = match method.as_str() {
                "getblockhash" => json!("00".repeat(32)),
                "getblock" => block.clone(),
                "getaddressinfo" => json!({ "iswatchonly": true }),
                other => panic!("unexpected method {other}"),
            };
            methods.push(method);
            let body = json!({ "result": result, "error": null, "id": "sidestr" }).to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            last = Instant::now();
        }
        methods
    });
    (url, handle)
}

/// The reference's `scanPegins` over the same block, with a watch-only peg
/// wallet: what it found, and how many wallet calls it made.
fn reference(siding: &str, block: &Value) -> Value {
    let js = Command::new("node")
        .args([
            "--input-type=module",
            "-e",
            r#"
        const {scanPegins} = await import(process.argv[1] + '/lib/parent.mjs');
        const block = JSON.parse(process.argv[2]); let calls = 0;
        const parent = {rpc: async m => m === 'getblockhash' ? block.hash : block,
          walletRpc: async () => { calls++; return {iswatchonly:true}; }};
        const found = await scanPegins(parent, {chainId:'sidestr:verify',from:1,to:1});
        console.log(JSON.stringify({found,calls}));
    "#,
            siding,
            &block.to_string(),
        ])
        .output()
        .unwrap();
    assert!(
        js.status.success(),
        "{}",
        String::from_utf8_lossy(&js.stderr)
    );
    serde_json::from_slice(&js.stdout).unwrap()
}

fn rust(block: &Value) -> (Vec<FoundPegin>, Vec<String>) {
    let (url, server) = serve(block.clone());
    let dir = common::TempDir::new("audit-0-0-3-parent");
    let cookie = dir.0.join("cookie");
    std::fs::write(&cookie, "test:test").unwrap();
    let rpc = CoreRpc::new(&url, cookie, Some("peg"));
    let owner = owned_by_peg_wallet(&rpc);
    let found = scan_pegins(
        &rpc,
        "sidestr:verify",
        1,
        1,
        Some(Network::Testnet4),
        Some(&owner),
        |_| {},
    )
    .unwrap();
    (found, server.join().unwrap())
}

#[test]
fn an_output_the_node_gives_no_address_is_not_owned_on_either_engine() {
    let Ok(siding) = std::env::var("SIDESTR_SIDING") else {
        eprintln!("skipped: set SIDESTR_SIDING (and SCHEMA, BLAKETESTNODE) to run the reference");
        return;
    };
    let script = common::challenge(&common::signer("metadata"));
    let marker = bitcoin::ScriptBuf::new_op_return(
        PushBytesBuf::try_from(peg_marker_data("sidestr:verify", &script)).unwrap(),
    );
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: script.clone(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: marker.clone(),
            },
        ],
    };
    let address = bitcoin::Address::from_script(&script, Network::Testnet4)
        .unwrap()
        .to_string();
    let block = |with_address: bool| {
        let mut peg = json!({"hex": script.to_hex_string(), "type": "witness_v1_taproot"});
        if with_address {
            peg["address"] = json!(address);
        }
        json!({"height":1,"hash":"00".repeat(32),"time":1790150000,"tx":[{
            "txid":tx.compute_txid().to_string(),"hex":serialize_hex(&tx),"vout":[
                {"n":0,"value":0.0005,"scriptPubKey":peg},
                {"n":1,"value":0,"scriptPubKey":{"hex":marker.to_hex_string(),"type":"nulldata"}}
            ]
        }]})
    };

    // the node omitted the peg output's address: no peg-in, no wallet call, on both engines
    let quiet = block(false);
    let (found, methods) = rust(&quiet);
    let js = reference(&siding, &quiet);
    assert_eq!(js["found"], json!([]), "{js}");
    assert_eq!(js["calls"], 0, "{js}");
    assert!(found.is_empty(), "{found:?}");
    assert_eq!(methods, ["getblockhash", "getblock"], "{methods:?}");

    // the node gave the address: the same peg-in on both engines, one wallet call each
    let told = block(true);
    let (found, methods) = rust(&told);
    let js = reference(&siding, &told);
    assert_eq!(js["calls"], 1, "{js}");
    assert_eq!(found.len(), 1);
    let (r, j) = (&found[0], &js["found"][0]);
    assert_eq!(r.txid, j["txid"].as_str().unwrap());
    assert_eq!(u64::from(r.vout), j["vout"].as_u64().unwrap());
    assert_eq!(r.amount, j["amount"].as_u64().unwrap());
    assert_eq!(r.script.to_hex_string(), j["script"].as_str().unwrap());
    assert_eq!(r.parent_address.as_deref(), j["parentAddress"].as_str());
    assert_eq!(methods, ["getblockhash", "getblock", "getaddressinfo"]);
}
