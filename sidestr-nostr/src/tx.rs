//! Transactions, faucet requests and parent transactions over a relay, kinds
//! 23500, 23501 and 23503 (SPEC 11; `siding/lib/relay.mjs`).
//!
//! From `relay.mjs`: a signed transaction travels as a kind 23500 event whose
//! content is the transaction hex and whose `chain` tag names the chain. The
//! event's key is anyone's — the transaction authorises itself — so a wallet
//! signs the event with a throwaway key and never needs an identity. Kind
//! 23501 asks for coins: content an address (or script hex), tagged the same
//! way; a faucet that follows the relay may answer with a payment, at its
//! own limits (`bin/siding.mjs faucet`). Kind 23503 (SPEC 0.0.4) carries a
//! signed *parent* transaction from a wallet with no node: a producer with a
//! parent node broadcasts it if and only if that node's mempool policy
//! accepts it as it stands, and never retries a refusal
//! (`parent.mjs relayParentTx`). This is how a peg-in built without a node
//! reaches the parent.
//!
//! Nothing here decodes the transaction: a producer's mempool judges it
//! (`sidestr_core::state::State::submit`), and a faucet resolves the address
//! (`sidestr_core::address`). These codecs carry hex and text and check the
//! tag. The `chain` tag is not relay-indexed, so a subscriber filters by
//! kind and checks it on receipt: pass the expected chain to the parsers
//! and an event for another chain is [`crate::Error::Chain`].
//!
//! ```
//! use sidestr_nostr::event::SecretKeySigner;
//! use sidestr_nostr::tx::{parse_faucet_request, parse_transaction, sign_faucet_request, sign_transaction_event};
//!
//! let throwaway = SecretKeySigner::from_bytes(&[42u8; 32]).unwrap();
//! let ev = sign_transaction_event(&throwaway, "sidestr:example", "02000000000101ab", 1_790_100_000).unwrap();
//! let t = parse_transaction(&ev, Some("sidestr:example")).unwrap();
//! assert_eq!(t.tx_hex, "02000000000101ab");
//! assert!(parse_transaction(&ev, Some("sidestr:other")).is_err());   // another chain's
//!
//! let ask = sign_faucet_request(&throwaway, "sidestr:example", "ex1p…", 1_790_100_000).unwrap();
//! assert_eq!(parse_faucet_request(&ask, None).unwrap().destination, "ex1p…");
//!
//! // a peg-in from a wallet with no node: the parent transaction rides kind 23503
//! use sidestr_nostr::tx::{parse_parent_transaction, sign_parent_transaction_event};
//! let up = sign_parent_transaction_event(&throwaway, "sidestr:example", "02000000000101CD", 1_790_100_000).unwrap();
//! assert_eq!(up.kind, 23503);
//! assert_eq!(parse_parent_transaction(&up, Some("sidestr:example")).unwrap().tx_hex, "02000000000101cd");
//! ```

use crate::error::{any_hex, Error, Result};
use crate::event::{sign, Event, Signer, UnsignedEvent};
use crate::kinds::{expect_kind, KIND_FAUCET_REQUEST, KIND_PARENT_TRANSACTION, KIND_TRANSACTION};
use crate::tags::{chain_tag, tag, TAG_CHAIN};

/// A transaction as an event carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionEvent {
    /// The chain it is for.
    pub chain_id: String,
    /// The transaction, lowercase hex, whitespace trimmed (`bin/siding.mjs`
    /// trims the content before `submit`).
    pub tx_hex: String,
}

/// The unsigned kind-23500 event (`relay.mjs txEvent`): `chain` tag, content
/// the hex.
pub fn transaction_event(chain_id: &str, tx_hex: &str, created_at: u64) -> Result<UnsignedEvent> {
    Ok(UnsignedEvent {
        pubkey: String::new(),
        created_at,
        kind: KIND_TRANSACTION,
        tags: vec![tag(TAG_CHAIN, chain_id)],
        content: any_hex("transaction", tx_hex)?,
    })
}

/// Sign a transaction event — with a throwaway key, in a wallet, since the
/// transaction authorises itself (`spend.mjs deliver` uses `randomKey()`).
pub fn sign_transaction_event(
    signer: &dyn Signer,
    chain_id: &str,
    tx_hex: &str,
    created_at: u64,
) -> Result<Event> {
    sign(signer, transaction_event(chain_id, tx_hex, created_at)?)
}

/// Decode a kind-23500 event; `expect` is the chain a producer follows.
/// Does not verify the signature: a producer verifies first
/// (`relay.mjs subscribe`), then this, then the mempool.
pub fn parse_transaction(ev: &Event, expect: Option<&str>) -> Result<TransactionEvent> {
    expect_kind(ev.kind, KIND_TRANSACTION, "transaction")?;
    Ok(TransactionEvent {
        chain_id: chain_tag(&ev.tags, expect)?.to_string(),
        tx_hex: any_hex("transaction", &ev.content)?,
    })
}

/// The unsigned kind-23503 event (`relay.mjs parentTxEvent`, SPEC 0.0.4):
/// `chain` tag, content a signed parent transaction as hex (trimmed and
/// lower-cased, as the kind-23500 event's is). Sign it with a throwaway key:
/// the transaction authorises itself.
pub fn parent_transaction_event(
    chain_id: &str,
    tx_hex: &str,
    created_at: u64,
) -> Result<UnsignedEvent> {
    Ok(UnsignedEvent {
        pubkey: String::new(),
        created_at,
        kind: KIND_PARENT_TRANSACTION,
        tags: vec![tag(TAG_CHAIN, chain_id)],
        content: any_hex("parent transaction", tx_hex)?,
    })
}

/// Sign a kind-23503 event.
pub fn sign_parent_transaction_event(
    signer: &dyn Signer,
    chain_id: &str,
    tx_hex: &str,
    created_at: u64,
) -> Result<Event> {
    sign(
        signer,
        parent_transaction_event(chain_id, tx_hex, created_at)?,
    )
}

/// Decode a kind-23503 event; `expect` is the chain a producer follows. The
/// hex comes back lowercase (`relayParentTx` lower-cases it) and is not
/// decoded here: the producer's parent node is the judge.
pub fn parse_parent_transaction(ev: &Event, expect: Option<&str>) -> Result<TransactionEvent> {
    expect_kind(ev.kind, KIND_PARENT_TRANSACTION, "parent transaction")?;
    Ok(TransactionEvent {
        chain_id: chain_tag(&ev.tags, expect)?.to_string(),
        tx_hex: any_hex("parent transaction", &ev.content)?,
    })
}

/// A faucet request as an event carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaucetRequest {
    /// The chain it asks on.
    pub chain_id: String,
    /// An address under any prefix, or a script hex; the faucet resolves it
    /// (`spend.mjs resolveTo`) and pays the script.
    pub destination: String,
}

/// The unsigned kind-23501 event: `chain` tag, content the destination.
pub fn faucet_request(chain_id: &str, destination: &str, created_at: u64) -> Result<UnsignedEvent> {
    let destination = destination.trim();
    if destination.is_empty() {
        return Err(Error::Content("a faucet request names an address".into()));
    }
    Ok(UnsignedEvent {
        pubkey: String::new(),
        created_at,
        kind: KIND_FAUCET_REQUEST,
        tags: vec![tag(TAG_CHAIN, chain_id)],
        content: destination.to_string(),
    })
}

/// Sign a faucet request; any key will do.
pub fn sign_faucet_request(
    signer: &dyn Signer,
    chain_id: &str,
    destination: &str,
    created_at: u64,
) -> Result<Event> {
    sign(signer, faucet_request(chain_id, destination, created_at)?)
}

/// Decode a kind-23501 event; `expect` is the chain the faucet serves.
pub fn parse_faucet_request(ev: &Event, expect: Option<&str>) -> Result<FaucetRequest> {
    expect_kind(ev.kind, KIND_FAUCET_REQUEST, "faucet request")?;
    let destination = ev.content.trim();
    if destination.is_empty() {
        return Err(Error::Content("a faucet request names an address".into()));
    }
    Ok(FaucetRequest {
        chain_id: chain_tag(&ev.tags, expect)?.to_string(),
        destination: destination.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::SecretKeySigner;

    fn signer() -> SecretKeySigner {
        SecretKeySigner::from_bytes(&[42u8; 32]).unwrap()
    }

    #[test]
    fn parent_transaction_round_trip_and_rejections() {
        let ev =
            sign_parent_transaction_event(&signer(), "sidestr:t", " 02000000CD \n", 1).unwrap();
        assert_eq!(ev.kind, 23503);
        assert_eq!(ev.tags, vec![vec!["chain", "sidestr:t"]]);
        assert_eq!(ev.content, "02000000cd");
        ev.verify().unwrap();
        let t = parse_parent_transaction(&ev, Some("sidestr:t")).unwrap();
        assert_eq!(
            (t.chain_id.as_str(), t.tx_hex.as_str()),
            ("sidestr:t", "02000000cd")
        );
        assert!(parse_parent_transaction(&ev, Some("sidestr:other")).is_err());
        // a kind-23500 event is not a parent transaction, nor the reverse
        let child = sign_transaction_event(&signer(), "sidestr:t", "02000000ab", 1).unwrap();
        assert!(parse_parent_transaction(&child, None).is_err());
        assert!(parse_transaction(&ev, None).is_err());
        assert!(parent_transaction_event("sidestr:t", "xyz", 1).is_err());
    }

    #[test]
    fn transaction_round_trip_and_rejections() {
        let ev = sign_transaction_event(&signer(), "sidestr:t", " 02000000AB \n", 1).unwrap();
        assert_eq!(ev.kind, 23500);
        assert_eq!(ev.tags, vec![vec!["chain", "sidestr:t"]]);
        assert_eq!(ev.content, "02000000ab");
        let t = parse_transaction(&ev, Some("sidestr:t")).unwrap();
        assert_eq!(
            t,
            TransactionEvent {
                chain_id: "sidestr:t".into(),
                tx_hex: "02000000ab".into()
            }
        );
        assert!(matches!(
            parse_transaction(&ev, Some("sidestr:u")),
            Err(Error::Chain(_))
        ));
        assert!(transaction_event("sidestr:t", "abc", 1).is_err());
        assert!(transaction_event("sidestr:t", "", 1).is_err());
        let mut untagged = ev.clone();
        untagged.tags.clear();
        assert!(matches!(
            parse_transaction(&untagged, None),
            Err(Error::MissingTag("chain"))
        ));
        let mut bad = ev.clone();
        bad.content = "xyz".into();
        assert!(matches!(
            parse_transaction(&bad, None),
            Err(Error::Hex { .. })
        ));
        let mut kind = ev;
        kind.kind = 23501;
        assert!(matches!(
            parse_transaction(&kind, None),
            Err(Error::Kind {
                expected: 23500,
                found: 23501,
                ..
            })
        ));
    }

    #[test]
    fn faucet_round_trip_and_rejections() {
        let ev = sign_faucet_request(&signer(), "sidestr:t", " trl1pabc ", 1).unwrap();
        assert_eq!((ev.kind, ev.content.as_str()), (23501, "trl1pabc"));
        assert_eq!(
            parse_faucet_request(&ev, Some("sidestr:t"))
                .unwrap()
                .destination,
            "trl1pabc"
        );
        assert!(faucet_request("sidestr:t", "  ", 1).is_err());
        let mut blank = ev.clone();
        blank.content = " ".into();
        assert!(matches!(
            parse_faucet_request(&blank, None),
            Err(Error::Content(_))
        ));
        assert!(parse_faucet_request(&ev, Some("sidestr:u")).is_err());
    }
}
