//! Hitch's channel messages as Nostr events, kind 23600
//! (`hitch/hitch.js send`, `bin/hub.mjs send`; Melvin Carvalho's Hitch at
//! `62f8e39`).
//!
//! A Hitch peer carries every channel message (`open`, `accept`, `update`,
//! `close`, …) as one event. It is **signed, not encrypted**. The tags are
//! `chain` (the chain the channel's coins are on), `p` (the recipient's
//! x-only key) and `ch` (the sixteen-hex channel id). The content is the
//! message as JSON. The author is the sender's channel key: Hitch's `open`
//! and `accept` name both peers, and a receiver refuses a message whose
//! author is not the peer it names. So the event's signature is the
//! message's authentication.
//!
//! This module is only the envelope. It treats the content as opaque JSON,
//! and the messages themselves are `sidestr-hitch`'s.
//!
//! ```
//! use sidestr_nostr::event::{SecretKeySigner, Signer};
//! use sidestr_nostr::hitch::{parse_message, sign_message};
//!
//! let alice = SecretKeySigner::from_bytes(&[11u8; 32]).unwrap();
//! let bob = SecretKeySigner::from_bytes(&[12u8; 32]).unwrap().pubkey_hex().unwrap();
//! let ev = sign_message(&alice, "sidestr:example", &bob, "0123456789abcdef",
//!     r#"{"t":"ready","id":"0123456789abcdef"}"#, 1_790_100_000).unwrap();
//! assert_eq!(ev.kind, 23600);
//! let m = parse_message(&ev, Some("sidestr:example")).unwrap();
//! assert_eq!((m.peer.as_str(), m.channel.as_str()), (bob.as_str(), "0123456789abcdef"));
//! assert!(parse_message(&ev, Some("sidestr:other")).is_err());
//! ```

use crate::error::{hex_of, Error, Result};
use crate::event::{sign, Event, Signer, UnsignedEvent};
use crate::kinds::{expect_kind, KIND_HITCH_MESSAGE};
use crate::tags::{chain_tag, required, tag, TAG_CHAIN};

/// The recipient tag: the x-only key the message is for.
pub const TAG_P: &str = "p";
/// The channel tag: Hitch's sixteen-hex channel id.
pub const TAG_CH: &str = "ch";

/// A kind-23600 event's envelope, read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEvent {
    /// The chain the channel's coins are on (`chain` tag).
    pub chain_id: String,
    /// The recipient's x-only key, 64 lowercase hex (`p` tag).
    pub peer: String,
    /// The channel id, 16 lowercase hex (`ch` tag).
    pub channel: String,
    /// The message, JSON text; `sidestr-hitch` parses it.
    pub content: String,
}

/// The unsigned kind-23600 event: `chain`, `p` and `ch` tags, with the
/// message JSON as content, in Hitch's tag order. The content must be a
/// JSON object. The author is filled in by the signer.
pub fn message_event(
    chain_id: &str,
    peer_hex: &str,
    channel_hex: &str,
    content_json: &str,
    created_at: u64,
) -> Result<UnsignedEvent> {
    let peer = hex_of("recipient", peer_hex, 32)?;
    let channel = hex_of("channel id", channel_hex, 8)?;
    object(content_json)?;
    Ok(UnsignedEvent {
        pubkey: String::new(),
        created_at,
        kind: KIND_HITCH_MESSAGE,
        tags: vec![
            tag(TAG_CHAIN, chain_id),
            tag(TAG_P, peer),
            tag(TAG_CH, channel),
        ],
        content: content_json.to_string(),
    })
}

/// Sign a channel message with the sender's channel key.
pub fn sign_message(
    signer: &dyn Signer,
    chain_id: &str,
    peer_hex: &str,
    channel_hex: &str,
    content_json: &str,
    created_at: u64,
) -> Result<Event> {
    sign(
        signer,
        message_event(chain_id, peer_hex, channel_hex, content_json, created_at)?,
    )
}

/// Decode a kind-23600 envelope; `expect` is the chain the reader follows,
/// since a relay cannot filter on the `chain` tag. This does not verify the
/// signature: verify first ([`Event::verify`]), then read, then hand the
/// content and the author to the channel.
pub fn parse_message(ev: &Event, expect: Option<&str>) -> Result<MessageEvent> {
    expect_kind(ev.kind, KIND_HITCH_MESSAGE, "hitch message")?;
    let chain_id = chain_tag(&ev.tags, expect)?.to_string();
    let peer = hex_of("recipient", required(&ev.tags, TAG_P)?, 32).map_err(|e| Error::Tag {
        tag: TAG_P,
        reason: e.to_string(),
    })?;
    let channel = hex_of("channel id", required(&ev.tags, TAG_CH)?, 8).map_err(|e| Error::Tag {
        tag: TAG_CH,
        reason: e.to_string(),
    })?;
    object(&ev.content)?;
    Ok(MessageEvent {
        chain_id,
        peer,
        channel,
        content: ev.content.clone(),
    })
}

fn object(text: &str) -> Result<()> {
    match serde_json::from_str::<serde_json::Value>(text)? {
        serde_json::Value::Object(_) => Ok(()),
        _ => Err(Error::Content("a hitch message is a JSON object".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::SecretKeySigner;

    fn alice() -> SecretKeySigner {
        SecretKeySigner::from_bytes(&[11u8; 32]).unwrap()
    }

    const BOB: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    #[test]
    fn the_envelope_is_hitch_s() {
        let ev = sign_message(
            &alice(),
            "sidestr:t",
            BOB,
            "00112233445566aa",
            "{\"t\":\"ready\",\"id\":\"00112233445566aa\"}",
            7,
        )
        .unwrap();
        ev.verify().unwrap();
        assert_eq!(ev.tags[0], vec!["chain", "sidestr:t"]);
        assert_eq!(ev.tags[1], vec!["p", BOB]);
        assert_eq!(ev.tags[2], vec!["ch", "00112233445566aa"]);
        let m = parse_message(&ev, None).unwrap();
        assert_eq!(m.chain_id, "sidestr:t");
        assert_eq!(m.content, ev.content);
    }

    #[test]
    fn bad_envelopes_are_refused() {
        assert!(message_event("sidestr:t", "zz", "00112233445566aa", "{}", 1).is_err());
        assert!(message_event("sidestr:t", BOB, "0011", "{}", 1).is_err());
        assert!(message_event("sidestr:t", BOB, "00112233445566aa", "[1]", 1).is_err());
        assert!(message_event("sidestr:t", BOB, "00112233445566aa", "nope", 1).is_err());
        let mut ev = sign_message(&alice(), "sidestr:t", BOB, "00112233445566aa", "{}", 1).unwrap();
        ev.tags.retain(|t| t[0] != "p");
        assert!(matches!(
            parse_message(&ev, None),
            Err(Error::MissingTag("p"))
        ));
        let mut other =
            sign_message(&alice(), "sidestr:t", BOB, "00112233445566aa", "{}", 1).unwrap();
        other.kind = 23500;
        assert!(matches!(
            parse_message(&other, None),
            Err(Error::Kind { .. })
        ));
    }
}
