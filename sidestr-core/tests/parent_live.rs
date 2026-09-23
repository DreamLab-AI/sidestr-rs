//! The parent view against a real Bitcoin Core testnet4 node (feature `rpc`,
//! `#[ignore]`): read-only, every call a query. Nothing here sends, signs,
//! locks or spends on the parent.
//!
//! Enabled by `SIDESTR_PARENT_RPC` (the node's JSON-RPC URL) and
//! `SIDESTR_PARENT_COOKIE` (its cookie file); the peg wallet is
//! `SIDESTR_PARENT_WALLET` or `sidestr-peg`; the scan starts at
//! `SIDESTR_PARENT_FROM` or 153500, the height before the wallet was funded.
//!
//! ```sh
//! SIDESTR_PARENT_RPC=http://<node>:48332/ SIDESTR_PARENT_COOKIE=<datadir>/testnet4/.cookie \
//!   cargo test -p sidestr-core --features rpc --test parent_live -- --ignored
//! ```
#![cfg(feature = "rpc")]

use bitcoin::Txid;
use sidestr_core::parent::rpc::CoreRpc;
use sidestr_core::parent::{
    find_payments, owned_by_peg_wallet, paid_pegouts_in, peg_status, scan_pegins,
    sent_checkpoints_in, ParentRpc, PegWallet,
};

#[test]
#[ignore = "set SIDESTR_PARENT_RPC to the testnet4 node's JSON-RPC URL (LAN); read-only"]
fn the_peg_wallets_funding_is_found_from_the_parent_side() {
    let Ok(url) = std::env::var("SIDESTR_PARENT_RPC") else {
        eprintln!("skipped: SIDESTR_PARENT_RPC is not set");
        return;
    };
    let Ok(cookie) = std::env::var("SIDESTR_PARENT_COOKIE") else {
        eprintln!("skipped: SIDESTR_PARENT_COOKIE (the node's .cookie file) is not set");
        return;
    };
    let wallet = std::env::var("SIDESTR_PARENT_WALLET").unwrap_or_else(|_| "sidestr-peg".into());
    let from: u32 = std::env::var("SIDESTR_PARENT_FROM")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(153_500);
    let rpc = CoreRpc::new(&url, cookie, Some(&wallet));

    let tip = rpc.block_count().unwrap();
    assert!(tip >= from, "tip {tip} is before the scan start {from}");
    // what the wallet holds: its unspent outputs, from the wallet's own view
    let unspent = rpc
        .wallet_call("listunspent", serde_json::json!([0]))
        .unwrap();
    let utxos = unspent.as_array().unwrap();
    let funding = utxos
        .iter()
        .find(|u| u["amount"].as_f64() == Some(0.001))
        .expect("the 0.001 tBTC funding of the peg wallet");
    let txid: Txid = funding["txid"].as_str().unwrap().parse().unwrap();
    let vout = funding["vout"].as_u64().unwrap() as u32;
    let script = bitcoin::ScriptBuf::from_hex(funding["scriptPubKey"].as_str().unwrap()).unwrap();
    assert!(script.is_p2tr(), "the peg wallet is a taproot wallet");

    // the chain's view: gettxout agrees it is unspent, and says how deep
    let status = peg_status(&rpc, &txid, vout).unwrap();
    assert!(status.unspent);
    assert!(status.confirmations.unwrap() >= 1);
    let out = rpc.tx_out(&txid, vout).unwrap().unwrap();
    assert_eq!((out.value, &out.script_pubkey), (100_000, &script));

    // and the scan from the funding height finds the payment in its block, transactions decoded from hex
    let mut where_found = None;
    let mut scanned = 0;
    // SPEC 6 (0.0.3): the peg is the output the peg wallet owns, at any position
    let owner = owned_by_peg_wallet(&rpc, Some(bitcoin::Network::Testnet4));
    assert!(owner(&script), "the wallet owns its own funding output");
    let found = scan_pegins(
        &rpc,
        "sidestr:dreamlab",
        from,
        tip,
        Some(bitcoin::Network::Testnet4),
        Some(&owner),
        |b| {
            scanned += 1;
            for tx in &b.txs {
                if tx.compute_txid() == txid {
                    where_found = Some((b.height, find_payments(tx, &script)));
                }
            }
        },
    )
    .unwrap();
    let (height, payments) = where_found.expect("the funding transaction in a scanned block");
    assert_eq!(payments, vec![(vout, 100_000)]);
    assert!(height > from && height <= tip);
    // every peg-in found pays an address the peg wallet owns; the bare funding carries no marker
    for p in &found {
        let a = p.parent_address.as_deref().expect("an address on testnet4");
        assert!(rpc.owns_address(a), "{p:?}");
        assert_ne!(p.txid, txid.to_string(), "the funding is not a peg-in");
    }
    // the wallet's own history reads back: burns paid and checkpoints sent
    let sent = rpc.sent_transactions().unwrap();
    let paid = paid_pegouts_in(&sent, "sidestr:dreamlab").len();
    let ckpts = sent_checkpoints_in(&sent, "sidestr:dreamlab").len();
    let st = rpc.transaction_status(&txid).unwrap();
    assert_eq!(st.block_height, Some(height));
    eprintln!(
        "{}:{vout} — 0.001 tBTC to the peg wallet at parent height {height}, {} confirmations at tip {tip}; {scanned} blocks scanned, {} peg-ins owned, {paid} burns paid, {ckpts} checkpoints",
        txid,
        status.confirmations.unwrap(),
        found.len()
    );
}
