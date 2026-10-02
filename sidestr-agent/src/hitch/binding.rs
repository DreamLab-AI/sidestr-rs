//! ADR-2101 D3, research stage: the key that spends is not the key that
//! identifies.
//!
//! An agent's identity key `k_id` is its `did:nostr`, and every supervised
//! program can reach it, so it never spends. Coins and channels are held by
//! a spend key `k_spend`. That key is minted from fresh OS entropy, so it
//! is not derived from `k_id`: one cannot be recovered from the other, and
//! a leaked spend key reveals nothing about the identity. The link between
//! them is public and explicit. `k_id` signs a kind-38420
//! `sidestr-account-binding` (ADR-2098 D2 as amended), where `d` is `<chain
//! hash>:<did hex>` (the genesis hash for a chain sealed before SPEC 0.0.5,
//! tagged `legacy`), the content is the spend key, and the `genesis` tag pins
//! the chain. It is the event agentbox's mint writes
//! (`management-api/lib/sidestr-spend-key.js`), tag for tag. A peer that
//! knows only the `did:nostr` finds the spend key through that event and
//! checks the identity signed it.
//!
//! A Hitch channel key signs the channel's 23600 events and its 2-of-2
//! funding leaf, so it is a spend key. A host built on this module refuses
//! a channel key equal to `k_id` ([`SpendBinding::check_spender`]).
//!
//! ```
//! use sidestr_agent::hitch::binding::{sign_binding, verify_binding};
//! use sidestr_agent::AgentKey;
//!
//! let k_id = AgentKey::parse(&"01".repeat(32)).unwrap();
//! let k_spend = AgentKey::parse(&"02".repeat(32)).unwrap();
//! let genesis = "4db37517728bd509c0cb96ee5a2e3e2a77f9e965a092e9f67948b413d453dbc0";
//! let ev = sign_binding(&k_id, &k_spend.pubkey(), "sidestr:dreamlab", None, genesis, 1_790_200_000).unwrap();
//! let b = verify_binding(&ev, "sidestr:dreamlab", Some(genesis)).unwrap();
//! assert_eq!(b.spend_key(), k_spend.pubkey());
//! b.check_spender(&k_spend).unwrap();
//! assert!(b.check_spender(&k_id).is_err()); // k_id never spends
//! // and a binding of the identity to itself is never made
//! assert!(sign_binding(&k_id, &k_id.pubkey(), "sidestr:dreamlab", None, genesis, 1).is_err());
//! ```

use bitcoin::key::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use sidestr_nostr::estate::{parse_account_binding, sign_account_binding, AccountBinding};
use sidestr_nostr::event::Event;

use super::{Error, Result};
use crate::AgentKey;

/// A spend key from 32 bytes of fresh entropy. The caller draws them from
/// the operating system (`getrandom`), never from the identity key, so
/// `k_spend` is independent of `k_id`. The error does not echo the bytes.
pub fn mint_spend_key(entropy: &[u8; 32]) -> Result<AgentKey> {
    Ok(AgentKey::from_secret_bytes(entropy)?)
}

/// The identity signs the binding of `spend` on the chain `alias`, whose
/// hash is `chain_hash` (its kind-3500 event id; `None` for a chain sealed
/// before SPEC 0.0.5) and whose genesis is `genesis_hash`. A binding of the
/// identity key to itself is refused before it is made.
pub fn sign_binding(
    identity: &AgentKey,
    spend: &XOnlyPublicKey,
    alias: &str,
    chain_hash: Option<&str>,
    genesis_hash: &str,
    created_at: u64,
) -> Result<Event> {
    if identity.pubkey() == *spend {
        return Err(Error::SpendIsIdentity);
    }
    let b = AccountBinding {
        alias: alias.to_string(),
        chain_hash: chain_hash.map(str::to_string),
        genesis_hash: genesis_hash.to_string(),
        did_hex: identity.pubkey().to_string(),
        spend_pubkey: spend.to_string(),
    };
    Ok(sign_account_binding(
        &identity.event_signer(),
        &b,
        created_at,
    )?)
}

/// A verified binding: on `chain_id`, the identity spends with `spend`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendBinding {
    /// The chain's alias, `sidestr:<name>`.
    pub chain_id: String,
    /// The chain's hash, or `None` for a pre-0.0.5 chain (keyed by genesis).
    pub chain_hash: Option<String>,
    /// The chain's genesis hash, 64 hex.
    pub genesis_hash: String,
    /// The identity key, `k_id` (the `did:nostr`), 64 hex.
    pub identity: String,
    /// The spend key, `k_spend`, 64 hex.
    pub spend: String,
    /// The signed kind-38420 event.
    pub event: Event,
}

impl SpendBinding {
    /// The identity key.
    pub fn identity_key(&self) -> XOnlyPublicKey {
        self.identity.parse().expect("checked when verified")
    }

    /// The spend key.
    pub fn spend_key(&self) -> XOnlyPublicKey {
        self.spend.parse().expect("checked when verified")
    }

    /// Whether `key` may spend under this binding. The identity key is
    /// refused ([`Error::SpendIsIdentity`]), and so is any key the binding
    /// does not name.
    pub fn check_spender(&self, key: &AgentKey) -> Result<()> {
        let k = key.pubkey();
        if k == self.identity_key() {
            return Err(Error::SpendIsIdentity);
        }
        if k != self.spend_key() {
            return Err(Error::Binding(format!(
                "the key {k} is not the spend key {} the identity bound on {}",
                self.spend, self.chain_id
            )));
        }
        Ok(())
    }
}

/// Read and check a kind-38420 event. Its signature must verify and its
/// author must be the DID it names. Its alias must be `chain_id`, its
/// genesis `genesis_hash` when given (the genesis, not the name, is the
/// chain's identity), and its spend key must not be its identity.
pub fn verify_binding(
    ev: &Event,
    chain_id: &str,
    genesis_hash: Option<&str>,
) -> Result<SpendBinding> {
    ev.verify()?;
    let b = parse_account_binding(ev)?;
    if b.alias != chain_id {
        return Err(Error::Binding(format!(
            "the binding is for {}, not {chain_id}",
            b.alias
        )));
    }
    if let Some(g) = genesis_hash {
        if !b.genesis_hash.eq_ignore_ascii_case(g) {
            return Err(Error::Binding(format!(
                "the binding pins genesis {}, not {g}: a chain re-sealed under the same name is another chain",
                b.genesis_hash
            )));
        }
    }
    let identity: XOnlyPublicKey = b
        .did_hex
        .parse()
        .map_err(|_| Error::Binding("the DID is not an x-only key".into()))?;
    let spend: XOnlyPublicKey = b
        .spend_pubkey
        .parse()
        .map_err(|_| Error::Binding("the spend key is not an x-only key".into()))?;
    if identity == spend {
        return Err(Error::SpendIsIdentity);
    }
    Ok(SpendBinding {
        chain_id: b.alias,
        chain_hash: b.chain_hash,
        genesis_hash: b.genesis_hash,
        identity: identity.to_string(),
        spend: spend.to_string(),
        event: ev.clone(),
    })
}

/// Of the events a relay returned, the newest binding by `identity` that
/// verifies for this chain (and genesis, when given). Events that do not
/// verify are skipped, not trusted.
pub fn newest_binding(
    events: &[Event],
    identity: &XOnlyPublicKey,
    chain_id: &str,
    genesis_hash: Option<&str>,
) -> Option<SpendBinding> {
    events
        .iter()
        .filter_map(|ev| {
            verify_binding(ev, chain_id, genesis_hash)
                .ok()
                .map(|b| (ev.created_at, b))
        })
        .filter(|(_, b)| b.identity_key() == *identity)
        .max_by_key(|(at, _)| *at)
        .map(|(_, b)| b)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENESIS: &str = "4db37517728bd509c0cb96ee5a2e3e2a77f9e965a092e9f67948b413d453dbc0";

    fn keys() -> (AgentKey, AgentKey) {
        (
            AgentKey::parse(&"01".repeat(32)).unwrap(),
            AgentKey::parse(&"02".repeat(32)).unwrap(),
        )
    }

    #[test]
    fn a_binding_for_another_chain_or_genesis_is_refused() {
        let (id, spend) = keys();
        let ev = sign_binding(&id, &spend.pubkey(), "sidestr:dreamlab", None, GENESIS, 1).unwrap();
        assert!(matches!(
            verify_binding(&ev, "sidestr:other", None),
            Err(Error::Binding(_))
        ));
        assert!(matches!(
            verify_binding(&ev, "sidestr:dreamlab", Some(&"00".repeat(32))),
            Err(Error::Binding(_))
        ));
        let mut forged = ev.clone();
        forged.content = "03".repeat(32);
        assert!(verify_binding(&forged, "sidestr:dreamlab", None).is_err());
    }

    #[test]
    fn the_newest_valid_binding_wins() {
        let (id, spend) = keys();
        let other = AgentKey::parse(&"03".repeat(32)).unwrap();
        let old = sign_binding(&id, &other.pubkey(), "sidestr:dreamlab", None, GENESIS, 1).unwrap();
        let new = sign_binding(&id, &spend.pubkey(), "sidestr:dreamlab", None, GENESIS, 2).unwrap();
        let mut bad =
            sign_binding(&id, &other.pubkey(), "sidestr:dreamlab", None, GENESIS, 3).unwrap();
        bad.sig = "00".repeat(64);
        let b = newest_binding(&[old, new, bad], &id.pubkey(), "sidestr:dreamlab", None).unwrap();
        assert_eq!(b.spend_key(), spend.pubkey());
        let stranger = AgentKey::parse(&"04".repeat(32)).unwrap();
        b.check_spender(&spend).unwrap();
        assert!(matches!(b.check_spender(&id), Err(Error::SpendIsIdentity)));
        assert!(matches!(b.check_spender(&stranger), Err(Error::Binding(_))));
    }

    #[test]
    fn a_minted_spend_key_is_the_entropy_given() {
        let k = mint_spend_key(&[0x02; 32]).unwrap();
        assert_eq!(k.pubkey(), keys().1.pubkey());
        assert!(mint_spend_key(&[0u8; 32]).is_err());
    }
}
