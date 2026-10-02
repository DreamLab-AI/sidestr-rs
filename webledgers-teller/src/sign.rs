//! Signing a Nostr event with a secret key held in memory.
//!
//! `sidestr-nostr`'s signer port seals its [`SignRequest`] to that crate's
//! own kinds, so an event of a kind it does not know (3700, 30333) is signed
//! here, by the route that crate leaves open for any outside signer: compute
//! the template's NIP-01 id, sign it, and hand the signature to
//! [`UnsignedEvent::with_signature`], which verifies the pair before it
//! returns the event.
//!
//! [`SignRequest`]: sidestr_nostr::event::SignRequest

use bitcoin::secp256k1::{Keypair, Message, SecretKey};
use sidestr_core::block::secp;
use sidestr_nostr::event::{Event, UnsignedEvent};

use crate::error::{Error, Result};

/// The x-only public key of a secret, as 64 lowercase hex digits: a Nostr
/// pubkey and the x of a did:nostr account.
pub fn pubkey_hex(secret: &SecretKey) -> String {
    hex::encode(secret.x_only_public_key(secp()).0.serialize())
}

/// Sign `event` with `secret` (its `pubkey` is set to the secret's), BIP 340
/// with zero auxiliary randomness as `sidestr-nostr` signs, so an event is a
/// pure function of its fields and the key.
pub(crate) fn sign_event(secret: &SecretKey, mut event: UnsignedEvent) -> Result<Event> {
    event.pubkey = pubkey_hex(secret);
    let kp = Keypair::from_secret_key(secp(), secret);
    let msg = Message::from_digest(event.id_bytes());
    let sig = secp().sign_schnorr_with_aux_rand(&msg, &kp, &[0u8; 32]);
    event
        .with_signature(&hex::encode(sig.as_ref()))
        .map_err(|e| Error::Event(e.to_string()))
}
