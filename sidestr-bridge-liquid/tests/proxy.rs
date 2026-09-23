//! The sync goes through the proxy the environment names, and fails closed
//! when the proxy does not answer.
//!
//! A local listener stands in for a SOCKS5 proxy: it records the first byte
//! of the first connection (a SOCKS5 greeting starts with 0x05) and hangs
//! up. No request reaches the network, so this runs offline. It is the only
//! test in its binary because it sets process-wide environment variables.

use std::io::Read;
use std::net::TcpListener;
use std::sync::mpsc;
use std::time::Duration;

use sidestr_bridge_liquid::{validate_proxy_url, ReserveKey, ReserveWallet, DEFAULT_ESPLORA_URL};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn sync_goes_through_the_socks_proxy_and_fails_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = format!("socks5h://{}", listener.local_addr().unwrap());
    validate_proxy_url(&proxy).unwrap();

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut first = [0u8; 1];
            let _ = stream.read_exact(&mut first);
            let _ = tx.send(first[0]);
        }
    });

    // What `usd-reserve --proxy` does, before any client is built.
    for var in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"] {
        std::env::set_var(var, &proxy);
    }
    for var in [
        "https_proxy",
        "http_proxy",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        std::env::remove_var(var);
    }

    let key = ReserveKey::from_phrase(ABANDON).unwrap();
    let mut wallet = ReserveWallet::new(key.descriptor().unwrap()).unwrap();
    let result = wallet.sync(DEFAULT_ESPLORA_URL);

    let first = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("the sync never connected to the proxy");
    assert_eq!(first, 0x05, "the proxy did not receive a SOCKS5 greeting");
    assert!(
        result.is_err(),
        "a dead proxy must fail the sync, not bypass it"
    );
    assert!(
        wallet.snapshot().is_err(),
        "an unsynced wallet has no snapshot"
    );
}
