//! Hitch's relay transport: a [`PeerMessage`] as a kind-23600 event signed
//! by the sender's channel key, and the checks a receiver makes before a
//! message reaches the channel.
//!
//! On receipt, a message is taken only if it is addressed to this key (`p`)
//! and tagged with this chain, its signature verifies, and the channel id
//! its `ch` tag carries is the one its content names. The verified author
//! then goes to the kernel as the authenticated sender: the kernel's `open`
//! and `accept` refuse a message whose author is not the peer it names.
//!
//! ```
//! use sidestr_agent::hitch::envelope::{message_event, read_message};
//! use sidestr_agent::AgentKey;
//! use sidestr_hitch::protocol::{ChannelId, PeerMessage, ReadyMessage, ReadyTag};
//!
//! let a = AgentKey::parse(&"0a".repeat(32)).unwrap();
//! let b = AgentKey::parse(&"0b".repeat(32)).unwrap();
//! let ready = PeerMessage::Ready(ReadyMessage { t: ReadyTag::Ready, id: ChannelId([7; 8]) });
//! let ev = message_event(&a, "sidestr:example", &b.pubkey(), &ready, 1_790_100_000).unwrap();
//! let got = read_message(&ev, &b.pubkey(), "sidestr:example").unwrap().unwrap();
//! assert_eq!((got.sender, got.message), (a.pubkey(), ready));
//! // not for a, and not on another chain
//! assert!(read_message(&ev, &a.pubkey(), "sidestr:example").unwrap().is_none());
//! assert!(read_message(&ev, &b.pubkey(), "sidestr:other").unwrap().is_none());
//! ```

use bitcoin::key::XOnlyPublicKey;
use sidestr_hitch::protocol::PeerMessage;
use sidestr_nostr::event::Event;
use sidestr_nostr::hitch::{parse_message, sign_message, TAG_P};
use sidestr_nostr::kinds::KIND_HITCH_MESSAGE;
use sidestr_nostr::tags::{first, is_for_chain};

use super::{Error, Result};
use crate::AgentKey;

/// A message taken from a relay: who sent it (the verified author) and
/// what it says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    /// The sender's channel key: the event's verified author.
    pub sender: XOnlyPublicKey,
    /// The message.
    pub message: PeerMessage,
    /// The carrying event's id, for the journal.
    pub event_id: String,
    /// The carrying event's time.
    pub created_at: u64,
}

/// The kind-23600 event carrying `message` to `peer` on `chain_id`,
/// signed by `key` (the sender's channel key).
pub fn message_event(
    key: &AgentKey,
    chain_id: &str,
    peer: &XOnlyPublicKey,
    message: &PeerMessage,
    created_at: u64,
) -> Result<Event> {
    let content = serde_json::to_string(message)?;
    Ok(sign_message(
        &key.event_signer(),
        chain_id,
        &peer.to_string(),
        &message.channel().to_hex(),
        &content,
        created_at,
    )?)
}

/// Read a relay's event for `me` on `chain_id`. `Ok(None)` means the event
/// is not for this reader: another kind, recipient or chain. `Err` means it
/// was addressed here and refused, because its signature fails, its
/// envelope is malformed, its content is not a Hitch message, or its `ch`
/// tag disagrees with the channel the message names.
pub fn read_message(ev: &Event, me: &XOnlyPublicKey, chain_id: &str) -> Result<Option<Inbound>> {
    if ev.kind != KIND_HITCH_MESSAGE
        || !is_for_chain(&ev.tags, chain_id)
        || !first(&ev.tags, TAG_P).is_some_and(|p| p.eq_ignore_ascii_case(&me.to_string()))
    {
        return Ok(None);
    }
    ev.verify()?;
    let envelope = parse_message(ev, Some(chain_id))?;
    let message: PeerMessage = serde_json::from_str(&envelope.content)?;
    if message.channel().to_hex() != envelope.channel {
        return Err(Error::Host(format!(
            "the ch tag {} disagrees with the message's channel {}",
            envelope.channel,
            message.channel()
        )));
    }
    let sender: XOnlyPublicKey = ev
        .pubkey
        .parse()
        .map_err(|_| Error::Host("the author is not an x-only key".into()))?;
    Ok(Some(Inbound {
        sender,
        message,
        event_id: ev.id.clone(),
        created_at: ev.created_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sidestr_hitch::protocol::{ChannelId, ReadyMessage, ReadyTag};

    fn pair() -> (AgentKey, AgentKey) {
        (
            AgentKey::parse(&"0a".repeat(32)).unwrap(),
            AgentKey::parse(&"0b".repeat(32)).unwrap(),
        )
    }

    fn ready(id: u8) -> PeerMessage {
        PeerMessage::Ready(ReadyMessage {
            t: ReadyTag::Ready,
            id: ChannelId([id; 8]),
        })
    }

    #[test]
    fn a_tampered_or_mislabelled_message_is_refused() {
        let (a, b) = pair();
        let mut ev = message_event(&a, "sidestr:t", &b.pubkey(), &ready(1), 5).unwrap();
        ev.content = serde_json::to_string(&ready(2)).unwrap();
        assert!(read_message(&ev, &b.pubkey(), "sidestr:t").is_err());
        // a correctly signed event whose ch tag names another channel
        let signed = sign_message(
            &a.event_signer(),
            "sidestr:t",
            &b.pubkey().to_string(),
            &ChannelId([9; 8]).to_hex(),
            &serde_json::to_string(&ready(1)).unwrap(),
            5,
        )
        .unwrap();
        assert!(matches!(
            read_message(&signed, &b.pubkey(), "sidestr:t"),
            Err(Error::Host(_))
        ));
        // content that is JSON but not a Hitch message
        let junk = sign_message(
            &a.event_signer(),
            "sidestr:t",
            &b.pubkey().to_string(),
            &ChannelId([1; 8]).to_hex(),
            r#"{"t":"nonsense","id":"0101010101010101"}"#,
            5,
        )
        .unwrap();
        assert!(read_message(&junk, &b.pubkey(), "sidestr:t").is_err());
    }
}
