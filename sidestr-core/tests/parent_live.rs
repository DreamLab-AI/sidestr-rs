//! The parent view against a real Bitcoin Core testnet4 node (feature `rpc`,
//! `#[ignore]`): read-only, every call a query. Nothing here sends, signs,
//! locks or spends on the parent.
//!
//! It asserts only facts that stay true however the peg wallet is used
//! later: confirmed history, never the wallet's current unspent set. The
//! facts come from the first live loop on `sidestr:dreamlab`.
//!
//! - **Funding.** The peg wallet was funded by `c61a7ad3…:0` with 0.001 tBTC
//!   at height 153511. It is in the wallet's history, confirmed, and paid in
//!   that block.
//! - **The live peg-in.** `2c4c5941…:0` paid 50,000 sats to
//!   `tr(<dreamlab signer>, <Alice's refund leaf>)` at height 153653, with
//!   the marker `pegin:sidestr:dreamlab:5120c95b…` (Alice's script).
//!   - **With no owner view** (a read-only producer, the reference's
//!     fallback), the scan finds it as a peg-in.
//!   - **With the peg wallet as owner** (SPEC 6 as of 0.0.3, level 1), the
//!     wallet does not own the 50,000-sat output: it never imported the
//!     descriptor, and lists the payment as its own `send`. But the peg
//!     wallet also *funded* this peg-in, and its 49,000-sat change at vout 2
//!     is a taproot output it owns. So the 0.0.3 rule, "the first taproot
//!     output the peg holders own", reads that change as the peg. The
//!     reference's `scanPegins` at `722ad42` gives the same answer against
//!     this node: vout 2, 49,000 sats. Both are pinned here, as a fact about
//!     the rule; it is reported upstream as a spec question. A peg-in paid
//!     from the peg wallet itself makes its own change look like the peg.
//! - **The peg-out.** The wallet's history pays one burn of the chain, in
//!   parent transaction `0ceb01d3…`.
//!
//! Enabled by `SIDESTR_PARENT_RPC` (the node's JSON-RPC URL) and
//! `SIDESTR_PARENT_COOKIE` (its cookie file). The peg wallet is
//! `SIDESTR_PARENT_WALLET`, or `sidestr-peg` if unset.
//!
//! ```sh
//! SIDESTR_PARENT_RPC=http://<node>:48332/ SIDESTR_PARENT_COOKIE=<datadir>/testnet4/.cookie \
//!   cargo test -p sidestr-core --features rpc --test parent_live -- --ignored
//! ```
#![cfg(feature = "rpc")]

use bitcoin::{Address, Network, Txid};
use sidestr_core::parent::rpc::CoreRpc;
use sidestr_core::parent::{
    find_payments, owned_by_peg_wallet, paid_pegouts_in, scan_pegins, ParentRpc, PegWallet,
};

const CHAIN: &str = "sidestr:dreamlab";
const FUNDING: &str = "c61a7ad38da6d61b33ed9f8793373f1f1c0e397c36a9aa2d5544db6ffceb36ea";
const FUNDING_HEIGHT: u32 = 153_511;
const PEGIN: &str = "2c4c5941a980f9e2aaf3a2097d5c1faf78fa58a4b9c6c32c6c4f7129e8e4a57d";
const PEGIN_HEIGHT: u32 = 153_653;
const PEG_ADDRESS: &str = "tb1palk8spjn20q8fa3gu8p30tx4xl0mqyk7t3497540zjkmt4zdvesq07eq2k";
const ALICE_SCRIPT: &str = "5120c95b519579bda3b5e29f5dca4a0b8f9f1d04d1979d2e4c3a33483a6b34b61d88";
/// The peg wallet's change in the live peg-in (vout 2).
const CHANGE_ADDRESS: &str = "tb1pdzc60d82swe6fwla68up7wgkquxuv8dt5p9t0cseug9xhcvxz2hsywyy0z";
const PEGOUT: &str = "0ceb01d3865f0da5a6baef800c6e98d1fe85c05ad2f425614840814bba2c8f98";

fn node() -> Option<CoreRpc> {
    let (Ok(url), Ok(cookie)) = (
        std::env::var("SIDESTR_PARENT_RPC"),
        std::env::var("SIDESTR_PARENT_COOKIE"),
    ) else {
        eprintln!("skipped: set SIDESTR_PARENT_RPC and SIDESTR_PARENT_COOKIE (the node's .cookie)");
        return None;
    };
    let wallet = std::env::var("SIDESTR_PARENT_WALLET").unwrap_or_else(|_| "sidestr-peg".into());
    Some(CoreRpc::new(&url, cookie, Some(&wallet)))
}

#[test]
#[ignore = "set SIDESTR_PARENT_RPC and SIDESTR_PARENT_COOKIE (testnet4 node, LAN); read-only"]
fn the_funding_is_in_the_wallets_confirmed_history() {
    let Some(rpc) = node() else { return };
    let txid: Txid = FUNDING.parse().unwrap();
    let st = rpc.transaction_status(&txid).unwrap();
    assert!(st.confirmations >= 1, "{st:?}");
    assert_eq!(st.block_height, Some(FUNDING_HEIGHT));
    // the wallet's own record: a receive of 0.001 tBTC to one of its addresses
    let g = rpc
        .wallet_call("gettransaction", serde_json::json!([FUNDING]))
        .unwrap();
    let receive = g["details"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["category"] == "receive")
        .expect("a receive detail");
    let address = receive["address"].as_str().unwrap();
    assert!(
        rpc.owns_address(address),
        "the wallet owns its funding address"
    );
    // and the parent's block pays that address 100 000 sats, decoded from hex
    let block = rpc.block_at(FUNDING_HEIGHT).unwrap();
    let tx = block
        .txs
        .iter()
        .find(|t| t.compute_txid() == txid)
        .expect("the funding in its block");
    let script = address
        .parse::<Address<_>>()
        .unwrap()
        .require_network(Network::Testnet4)
        .unwrap()
        .script_pubkey();
    assert_eq!(find_payments(tx, &script), vec![(0, 100_000)]);
    eprintln!(
        "{FUNDING}:0: 0.001 tBTC at {FUNDING_HEIGHT}, {} confirmations",
        st.confirmations
    );
}

#[test]
#[ignore = "set SIDESTR_PARENT_RPC and SIDESTR_PARENT_COOKIE (testnet4 node, LAN); read-only"]
fn the_live_pegin_as_read_with_and_without_the_peg_wallet() {
    let Some(rpc) = node() else { return };
    let (from, to) = (153_650, 153_655);
    let net = Some(Network::Testnet4);

    // no owner view: the first taproot output beside the marker, as a read-only producer reads it
    let found = scan_pegins(&rpc, CHAIN, from, to, net, None, |_| {}).unwrap();
    let p = found
        .iter()
        .find(|p| p.txid == PEGIN)
        .unwrap_or_else(|| panic!("the live peg-in in {from}..={to}: {found:?}"));
    assert_eq!(
        (p.vout, p.amount, p.height),
        (0, 50_000, PEGIN_HEIGHT),
        "{p:?}"
    );
    assert_eq!(p.script.to_hex_string(), ALICE_SCRIPT);
    assert_eq!(p.parent_address.as_deref(), Some(PEG_ADDRESS));

    // the peg wallet as owner (SPEC 6, 0.0.3, level 1): it does not own the signer-key output ...
    assert!(!rpc.owns_address(PEG_ADDRESS));
    let owner = owned_by_peg_wallet(&rpc);
    let owned = scan_pegins(&rpc, CHAIN, from, to, net, Some(&owner), |_| {}).unwrap();
    // ... so vout 0 is not the peg; but the wallet funded the peg-in, and the first taproot output
    // it owns is its own change, which the rule (and the reference, at 722ad42) takes as the peg
    let q = owned
        .iter()
        .find(|q| q.txid == PEGIN)
        .unwrap_or_else(|| panic!("{owned:?}"));
    assert_ne!(q.vout, 0);
    assert_eq!(
        (q.vout, q.amount, q.height),
        (2, 49_000, PEGIN_HEIGHT),
        "{q:?}"
    );
    assert_eq!(q.script.to_hex_string(), ALICE_SCRIPT);
    assert_eq!(q.parent_address.as_deref(), Some(CHANGE_ADDRESS));
    assert!(rpc.owns_address(CHANGE_ADDRESS));
    eprintln!(
        "{PEGIN}: no owner view -> vout 0 (50 000 sats to {PEG_ADDRESS}); peg wallet as owner -> \
         vout 2 (49 000 sats, the wallet's own change {CHANGE_ADDRESS}), as the reference reads it"
    );
}

#[test]
#[ignore = "set SIDESTR_PARENT_RPC and SIDESTR_PARENT_COOKIE (testnet4 node, LAN); read-only"]
fn the_wallets_history_pays_the_chains_burn() {
    let Some(rpc) = node() else { return };
    let sent = rpc.sent_transactions().unwrap();
    let paid = paid_pegouts_in(&sent, CHAIN);
    let pegout: Txid = PEGOUT.parse().unwrap();
    let burns: Vec<_> = paid
        .iter()
        .filter(|(_, parent)| **parent == pegout)
        .collect();
    assert_eq!(burns.len(), 1, "{paid:?}");
    eprintln!("burn {} paid on the parent by {PEGOUT}", burns[0].0);
}
