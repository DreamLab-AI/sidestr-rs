//! The one live test: read-only, against Blockstream's public Liquid
//! servers. Ignored by default, and a no-op unless `SIDESTR_LIQUID_LIVE=1`:
//!
//! ```text
//! SIDESTR_LIQUID_LIVE=1 cargo test -p sidestr-bridge-liquid --test live -- --ignored --nocapture
//! ```
//!
//! It derives a fresh wallet in a temporary directory (the key is discarded
//! when the test ends), syncs it, expects nothing in it, and fetches and
//! verifies the reserve asset's registry entry. It never sends, signs a
//! transaction or broadcasts.

use sidestr_bridge_liquid::{
    attest, fetch_registry_entry, reserve_asset, ReserveKey, ReserveWallet, DEFAULT_ESPLORA_URL,
    RESERVE_ASSET_ID,
};

fn live() -> bool {
    let on = std::env::var("SIDESTR_LIQUID_LIVE").is_ok_and(|v| v == "1");
    if !on {
        eprintln!("skipped: set SIDESTR_LIQUID_LIVE=1 to run against the public Liquid servers");
    }
    on
}

#[test]
#[ignore = "network: set SIDESTR_LIQUID_LIVE=1 and pass --ignored"]
fn an_empty_wallet_syncs_to_the_live_tip_and_the_registry_matches_the_pin() {
    if !live() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let key = ReserveKey::create(&dir.path().join("mnemonic")).unwrap();
    let mut wallet = ReserveWallet::new(key.descriptor().unwrap()).unwrap();
    println!("fresh address  {}", wallet.address(Some(0)).unwrap());

    wallet.sync(DEFAULT_ESPLORA_URL).unwrap();
    let snapshot = wallet.snapshot().unwrap();
    println!("server         {}", snapshot.source);
    println!("tip height     {}", snapshot.tip.height);
    println!("tip hash       {}", snapshot.tip.hash);
    // Liquid passed 4,000,000 blocks in 2026 (one a minute).
    assert!(
        snapshot.tip.height > 4_000_000,
        "stale or wrong-network tip"
    );
    let balance = wallet.balance().unwrap();
    println!("balance        {balance:?}");
    assert!(balance.is_empty(), "a fresh wallet holds nothing");
    assert!(snapshot.utxos.is_empty());

    let attestation = attest(&snapshot, &reserve_asset(), 0).unwrap();
    assert_eq!(attestation.amount, 0);
    assert!(attestation.credits.is_empty());
    println!("attestation    {}", attestation.canonical_json());
    println!("digest         {}", attestation.digest());

    let entry = fetch_registry_entry().unwrap();
    println!(
        "registry       {RESERVE_ASSET_ID}: ticker {}, name {:?}, domain {}, precision {} (contract commits to the id)",
        entry.ticker(),
        entry.name(),
        entry.domain(),
        entry.precision()
    );
}
