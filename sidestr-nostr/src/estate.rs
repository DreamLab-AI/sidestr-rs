//! agentbox's own kinds: the account binding (38420) and the five
//! settlement domain events (38421–38425), from the 38400–38499 band
//! (ADR-2098 D2 and amendments, ADR-2105, DDD-022 "Domain Events").
//!
//! # The account binding, 38420
//!
//! `sidestr-account-binding`: addressable, **signed by the identity key**,
//! content the spend pubkey. It says "on this chain, this principal spends
//! with this key". The shape follows ADR-2098 as amended for SPEC 0.0.5
//! ("38420–38425 carry the chain hash, never the alias") and the estate's
//! own mint (agentbox `management-api/lib/sidestr-spend-key.js`
//! `buildBinding`), tag for tag:
//!
//! | tag | value |
//! |---|---|
//! | `d` | `<chain key>:<did hex>`: the chain key is the chain's hash (its kind-3500 event id), or its genesis hash for a chain sealed before 0.0.5 |
//! | `alias` | the chain's alias, `sidestr:<name>`, a name for people only |
//! | `genesis` | the genesis hash |
//! | `chain` or `legacy` | the chain hash, or `legacy` = `pre-0.0.5` when there is none |
//! | `alt` | NIP-31 text |
//!
//! The DID in `d` must be the event's author ([`parse_account_binding`]
//! refuses otherwise). A name is never monetary identity: a chain re-sealed
//! under the same alias has another genesis and another hash, so a binding
//! to the old one does not carry over.
//!
//! The form this crate wrote through 0.5.0, the alias in `d`
//! (`sidestr:<name>:<did hex>`, tags `chain` = the alias and `genesis`), is
//! the live `sidestr:dreamlab` binding's. [`parse_account_binding`] refuses
//! it; [`parse_binding`] reads every form and says which ([`BindingForm`]),
//! flagging both pre-hash forms legacy, and [`legacy_alias_binding_event`]
//! makes an old binding again byte for byte. [`check_binding_chain`] holds a
//! binding to the chain's verified kind-3500 event.
//!
//! # The domain events, 38421–38425
//!
//! DDD-022 names the five facts upstream has no event for, and what each is
//! for. They are **regular** events — evidence accretes, nothing replaces
//! it — and their content is JSON with the chain id inside it (content is
//! authoritative; the `chain` tag is an index, and [`Error::Disagree`] is the
//! answer to a mismatch). For a chain with a chain event the `chain` tag
//! carries its hash and an `alias` tag the alias ([`domain_event_on`]); the
//! alias-only form ([`domain_event`]) stays readable and is flagged legacy
//! ([`parse_domain_event_of`]), and [`check_domain_event_chain`] holds an
//! event to the chain event. Every URN they carry was minted by the estate's sole
//! mint (`management-api/lib/uris.js`, ADR-013): this crate takes [`Urn`]s as
//! given and refuses only what is plainly not one.
//!
//! | kind | event | trigger (DDD-022) |
//! |---|---|---|
//! | 38421 | [`PegOutDefaulted`] | `pegoutBlocks` elapsed unpaid; upstream has no such fact |
//! | 38422 | [`ChildChainOpened`] | a child chain sealed and bound at `phase=create` |
//! | 38423 | [`ChildChainClosing`] | the `closePolicy` boundary reached |
//! | 38424 | [`ChainTombstoned`] | the closing hash checkpointed into the parent |
//! | 38425 | [`SettlementRecorded`] | a settlement finalised, if receipts federate (PRD-024 decides) |
//!
//! ```
//! use sidestr_nostr::estate::{parse_account_binding, sign_account_binding, AccountBinding};
//! use sidestr_nostr::event::{SecretKeySigner, Signer};
//!
//! let identity = SecretKeySigner::from_bytes(&[11u8; 32]).unwrap();
//! let b = AccountBinding {
//!     alias: "sidestr:dreamlab-txbt4".into(),
//!     chain_hash: None, // sealed before 0.0.5: keyed by its genesis
//!     genesis_hash: "1009aa2984d5c699fe61ef1e5905afe472a49d67551542045726828c8b82d108".into(),
//!     did_hex: identity.pubkey_hex().unwrap(),
//!     spend_pubkey: "ab".repeat(32),
//! };
//! let ev = sign_account_binding(&identity, &b, 1_790_100_000).unwrap();
//! assert_eq!(ev.tags[0][1], format!("{}:{}", b.genesis_hash, b.did_hex));
//! assert_eq!(ev.tags[3], vec!["legacy", "pre-0.0.5"]);
//! assert_eq!(parse_account_binding(&ev).unwrap(), b);
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::chain::{is_chain_hash, ParsedChain};
use crate::error::{hex_of, Error, Result};
use crate::event::{sign, Event, Signer, UnsignedEvent};
use crate::kinds::{
    expect_kind, KIND_ACCOUNT_BINDING, KIND_CHAIN_TOMBSTONED, KIND_CHILD_CHAIN_CLOSING,
    KIND_CHILD_CHAIN_OPENED, KIND_PEGOUT_DEFAULTED, KIND_SETTLEMENT_RECORDED,
};
use crate::tags::{first, required, tag, Outpoint, TAG_ALT, TAG_CHAIN, TAG_D, TAG_GENESIS};

/// An `urn:agentbox:` identifier minted elsewhere (ADR-013). This crate
/// never composes one; it checks the prefix and carries the string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Urn(String);

impl Urn {
    /// Accept a minted URN: `urn:agentbox:<kind>:…`, nothing else.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let rest = s
            .strip_prefix("urn:agentbox:")
            .ok_or_else(|| Error::Urn(format!("{s:?} is not an urn:agentbox: identifier")))?;
        if rest.is_empty() || rest.starts_with(':') || !rest.contains(':') {
            return Err(Error::Urn(format!("{s:?} has no kind and local part")));
        }
        Ok(Self(s.to_string()))
    }

    /// The string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Urn {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::parse(&s)
    }
}
impl From<Urn> for String {
    fn from(u: Urn) -> String {
        u.0
    }
}
impl core::fmt::Display for Urn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The 38420 binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountBinding {
    /// The chain's alias, `sidestr:<name>` (`alias` tag): a name, not the key.
    pub alias: String,
    /// The chain's hash, its kind-3500 event id (`chain` tag), 64 hex; `None`
    /// for a chain sealed before SPEC 0.0.5 (`legacy` tag), which is keyed by
    /// its genesis hash instead.
    pub chain_hash: Option<String>,
    /// The chain's genesis hash, 64 hex.
    pub genesis_hash: String,
    /// The principal's identity pubkey, 64 hex — the event's author.
    pub did_hex: String,
    /// The spend pubkey on this chain, 64 hex (ADR-2101 D3: never the identity key).
    pub spend_pubkey: String,
}

impl AccountBinding {
    /// The chain key the `d` tag carries: the chain hash, else the genesis hash.
    pub fn chain_key(&self) -> &str {
        self.chain_hash.as_deref().unwrap_or(&self.genesis_hash)
    }
}

/// The value of `legacy` on a binding to a chain without a chain hash.
pub const LEGACY: &str = "pre-0.0.5";
/// The tag naming the chain's alias.
pub const TAG_ALIAS: &str = "alias";
/// The tag a binding to a pre-0.0.5 chain carries instead of `chain`.
pub const TAG_LEGACY: &str = "legacy";

/// The `d` value of a binding: `<chain key>:<did hex>`, where the chain key
/// is the chain hash, or the genesis hash for a pre-0.0.5 chain
/// (agentbox `pay402.js sidestrBindingD`).
pub fn binding_address(chain_key: &str, did_hex: &str) -> String {
    format!("{chain_key}:{did_hex}")
}

/// Split a binding `d` into its chain key and DID, both 64 hex.
pub fn parse_binding_address(d: &str) -> Result<(String, String)> {
    let bad = |reason: String| Error::Tag { tag: TAG_D, reason };
    let (key, did) = d
        .split_once(':')
        .ok_or_else(|| bad(format!("{d:?} is not <chain key>:<did hex>")))?;
    let key = hex_of("chain key", key, 32).map_err(|e| bad(e.to_string()))?;
    let did = hex_of("did hex", did, 32).map_err(|e| bad(e.to_string()))?;
    Ok((key, did))
}

/// The unsigned 38420, in the estate mint's tag order: `d`, `alias`,
/// `genesis`, `chain` or `legacy`, `alt`; content the spend pubkey.
pub fn account_binding_event(b: &AccountBinding, created_at: u64) -> Result<UnsignedEvent> {
    let did = hex_of("did hex", &b.did_hex, 32)?;
    let genesis = hex_of("genesis hash", &b.genesis_hash, 32)?;
    let chain = b
        .chain_hash
        .as_deref()
        .map(|h| hex_of("chain hash", h, 32))
        .transpose()?;
    let key = chain.clone().unwrap_or_else(|| genesis.clone());
    Ok(UnsignedEvent {
        pubkey: did.clone(),
        created_at,
        kind: KIND_ACCOUNT_BINDING,
        tags: vec![
            tag(TAG_D, binding_address(&key, &did)),
            tag(TAG_ALIAS, &b.alias),
            tag(TAG_GENESIS, genesis),
            match chain {
                Some(h) => tag(TAG_CHAIN, h),
                None => tag(TAG_LEGACY, LEGACY),
            },
            tag(
                TAG_ALT,
                format!(
                    "sidestr account binding: the spend key of did:nostr:{did} on {}",
                    b.alias
                ),
            ),
        ],
        content: hex_of("spend pubkey", &b.spend_pubkey, 32)?,
    })
}

/// Sign a binding with the identity key. The signer must *be* `did_hex`:
/// a binding signed by any other key is refused before it is made.
pub fn sign_account_binding(
    signer: &dyn Signer,
    b: &AccountBinding,
    created_at: u64,
) -> Result<Event> {
    let me = signer.pubkey_hex()?;
    if !me.eq_ignore_ascii_case(b.did_hex.trim()) {
        return Err(Error::Key(
            "a binding is signed by the identity key it names".into(),
        ));
    }
    sign(signer, account_binding_event(b, created_at)?)
}

/// Decode a 38420. The `d` DID must be the author, and the `d` chain key
/// must be the `chain` tag's hash, or the genesis hash under `legacy`. Does
/// not verify the signature.
pub fn parse_account_binding(ev: &Event) -> Result<AccountBinding> {
    expect_kind(ev.kind, KIND_ACCOUNT_BINDING, "sidestr-account-binding")?;
    let (key, did_hex) = parse_binding_address(required(&ev.tags, TAG_D)?)?;
    if !ev.pubkey.eq_ignore_ascii_case(&did_hex) {
        return Err(Error::Chain(format!(
            "binding for {did_hex} is signed by {}: not the identity key",
            ev.pubkey
        )));
    }
    let genesis_hash = hex_of("genesis hash", required(&ev.tags, TAG_GENESIS)?, 32)?;
    let chain_hash = first(&ev.tags, TAG_CHAIN)
        .map(|h| hex_of("chain hash", h, 32))
        .transpose()?;
    let expected = match (&chain_hash, first(&ev.tags, TAG_LEGACY)) {
        (Some(h), None) => h.clone(),
        (None, Some(_)) => genesis_hash.clone(),
        (Some(_), Some(_)) => {
            return Err(Error::Content(
                "a binding carries a chain hash or legacy, not both".into(),
            ))
        }
        (None, None) => return Err(Error::MissingTag(TAG_CHAIN)),
    };
    if key != expected {
        return Err(Error::Disagree {
            tag: TAG_D,
            tag_value: key,
            content_value: expected,
        });
    }
    Ok(AccountBinding {
        alias: required(&ev.tags, TAG_ALIAS)?.to_string(),
        chain_hash,
        genesis_hash,
        did_hex,
        spend_pubkey: hex_of("spend pubkey", &ev.content, 32)?,
    })
}

/// How a 38420 read by [`parse_binding`] named its chain in `d`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingForm {
    /// `d` keyed by the chain hash, with a `chain` tag (SPEC 0.0.5): the
    /// current form, [`account_binding_event`] with a `chain_hash`.
    Hash,
    /// Legacy: `d` keyed by the genesis hash, with a `legacy` tag, for a
    /// chain sealed before 0.0.5: [`account_binding_event`] without one.
    Genesis,
    /// Legacy: this crate's form through 0.5.0, `d` = `<alias>:<did hex>`
    /// with tags `chain` = the alias and `genesis`, and no `alt`
    /// ([`legacy_alias_binding_event`]). The live `sidestr:dreamlab` binding
    /// was signed in it.
    Alias,
}

impl BindingForm {
    /// Whether the binding names its chain by something other than its hash.
    pub fn is_legacy(self) -> bool {
        self != BindingForm::Hash
    }
}

/// A 38420 read back with the form it was written in ([`parse_binding`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedBinding {
    /// The binding. In the [`BindingForm::Alias`] form `chain_hash` is
    /// `None` and `alias` is the alias `d` carried.
    pub binding: AccountBinding,
    /// How `d` named the chain.
    pub form: BindingForm,
}

impl ParsedBinding {
    /// Whether the binding is in a legacy form ([`BindingForm::is_legacy`]).
    pub fn legacy(&self) -> bool {
        self.form.is_legacy()
    }
}

/// Decode a 38420 in any form this crate has written, and say which.
/// Does not verify the signature.
///
/// A `d` whose chain key is 64 hex is read by [`parse_account_binding`],
/// unchanged: [`BindingForm::Hash`] with a `chain` tag,
/// [`BindingForm::Genesis`] under `legacy`. Anything else is the alias form
/// this crate wrote through 0.5.0 ([`BindingForm::Alias`]), read as 0.5.0
/// read it: the DID after the last colon is the author, a `chain` tag (and
/// an `alias` tag, if one is present) must be the alias, and `genesis` and
/// the content are 64 hex. [`parse_account_binding`] refuses that form.
///
/// ```
/// use sidestr_nostr::estate::{
///     parse_account_binding, parse_binding, sign_legacy_alias_binding, AccountBinding, BindingForm,
/// };
/// use sidestr_nostr::event::{SecretKeySigner, Signer};
///
/// let identity = SecretKeySigner::from_bytes(&[11u8; 32]).unwrap();
/// let b = AccountBinding {
///     alias: "sidestr:dreamlab".into(),
///     chain_hash: None,
///     genesis_hash: "4d".repeat(32),
///     did_hex: identity.pubkey_hex().unwrap(),
///     spend_pubkey: "ab".repeat(32),
/// };
/// let ev = sign_legacy_alias_binding(&identity, &b, 1).unwrap();
/// assert!(parse_account_binding(&ev).is_err());
/// let p = parse_binding(&ev).unwrap();
/// assert_eq!((p.form, p.legacy()), (BindingForm::Alias, true));
/// assert_eq!(p.binding, b);
/// ```
pub fn parse_binding(ev: &Event) -> Result<ParsedBinding> {
    expect_kind(ev.kind, KIND_ACCOUNT_BINDING, "sidestr-account-binding")?;
    let d = required(&ev.tags, TAG_D)?;
    let keyed = d.split_once(':').is_some_and(|(k, _)| is_chain_hash(k));
    if keyed {
        let binding = parse_account_binding(ev)?;
        let form = match binding.chain_hash {
            Some(_) => BindingForm::Hash,
            None => BindingForm::Genesis,
        };
        return Ok(ParsedBinding { binding, form });
    }
    let bad = |reason: String| Error::Tag { tag: TAG_D, reason };
    let (alias, did) = d
        .rsplit_once(':')
        .ok_or_else(|| bad(format!("{d:?} is not <chain>:<did hex>")))?;
    if alias.is_empty() {
        return Err(bad(format!("{d:?} names no chain")));
    }
    let did_hex = hex_of("did hex", did, 32).map_err(|e| bad(e.to_string()))?;
    if !ev.pubkey.eq_ignore_ascii_case(&did_hex) {
        return Err(Error::Chain(format!(
            "binding for {did_hex} is signed by {}: not the identity key",
            ev.pubkey
        )));
    }
    for name in [TAG_CHAIN, TAG_ALIAS] {
        if let Some(v) = first(&ev.tags, name).filter(|v| *v != alias) {
            return Err(Error::Disagree {
                tag: name,
                tag_value: v.to_string(),
                content_value: alias.to_string(),
            });
        }
    }
    Ok(ParsedBinding {
        binding: AccountBinding {
            alias: alias.to_string(),
            chain_hash: None,
            genesis_hash: hex_of("genesis hash", required(&ev.tags, TAG_GENESIS)?, 32)?,
            did_hex,
            spend_pubkey: hex_of("spend pubkey", &ev.content, 32)?,
        },
        form: BindingForm::Alias,
    })
}

/// The unsigned 38420 in the alias form this crate wrote through 0.5.0
/// ([`BindingForm::Alias`]): `d` = `<alias>:<did hex>`, `chain` = the
/// alias, `genesis`; content the spend pubkey. Byte for byte what 0.5.0's
/// `account_binding_event` made, so a binding signed then (the live
/// `sidestr:dreamlab`'s) is made again to the same id. Only for
/// re-publishing such a binding at its own address; a new binding is
/// [`account_binding_event`]'s. Refuses a `chain_hash`: a chain with one is
/// never bound by alias.
pub fn legacy_alias_binding_event(b: &AccountBinding, created_at: u64) -> Result<UnsignedEvent> {
    if b.chain_hash.is_some() {
        return Err(Error::Chain(
            "a chain with a chain hash is bound by its hash, not its alias".into(),
        ));
    }
    if b.alias.is_empty() || is_chain_hash(&b.alias) {
        return Err(Error::Tag {
            tag: TAG_ALIAS,
            reason: format!("{:?} is not a chain alias", b.alias),
        });
    }
    let did = hex_of("did hex", &b.did_hex, 32)?;
    Ok(UnsignedEvent {
        pubkey: did.clone(),
        created_at,
        kind: KIND_ACCOUNT_BINDING,
        tags: vec![
            tag(TAG_D, format!("{}:{did}", b.alias)),
            tag(TAG_CHAIN, &b.alias),
            tag(TAG_GENESIS, hex_of("genesis hash", &b.genesis_hash, 32)?),
        ],
        content: hex_of("spend pubkey", &b.spend_pubkey, 32)?,
    })
}

/// Sign [`legacy_alias_binding_event`] with the identity key, which must be
/// `did_hex`, as [`sign_account_binding`] requires.
pub fn sign_legacy_alias_binding(
    signer: &dyn Signer,
    b: &AccountBinding,
    created_at: u64,
) -> Result<Event> {
    let me = signer.pubkey_hex()?;
    if !me.eq_ignore_ascii_case(b.did_hex.trim()) {
        return Err(Error::Key(
            "a binding is signed by the identity key it names".into(),
        ));
    }
    sign(signer, legacy_alias_binding_event(b, created_at)?)
}

/// Hold a binding to the chain it names, read from the chain's verified
/// kind-3500 event ([`parse_chain_event`](crate::chain::parse_chain_event)
/// or [`resolve_chain`](crate::chain::resolve_chain)): a `chain_hash` must
/// be the event's id; the alias must be the document's `id`; and the
/// genesis hash must be the document's `genesisHash` when the document
/// carries one (SPEC 5, 0.0.5: a cross-check, never the identity). A
/// binding without a chain hash passes on alias and genesis; whether to
/// accept one for a chain that has a chain event is the caller's choice
/// ([`ParsedBinding::legacy`]).
pub fn check_binding_chain(b: &AccountBinding, chain: &ParsedChain) -> Result<()> {
    if let Some(h) = &b.chain_hash {
        if !h.eq_ignore_ascii_case(&chain.hash) {
            return Err(Error::Chain(format!(
                "the binding names chain {h}, not the chain event {}",
                chain.hash
            )));
        }
    }
    if b.alias != chain.alias {
        return Err(Error::Chain(format!(
            "the binding is for {}, the chain event for {}",
            b.alias, chain.alias
        )));
    }
    if let Some(g) = chain.chain.get("genesisHash").and_then(Value::as_str) {
        if !g.eq_ignore_ascii_case(&b.genesis_hash) {
            return Err(Error::Chain(format!(
                "the binding pins genesis {}, the chain document {g}",
                b.genesis_hash
            )));
        }
    }
    Ok(())
}

/// A child chain's close boundary (DDD-022 `closePolicy`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ClosePolicy {
    /// Close at a sidechain height.
    Height(u32),
    /// Close at a unix time.
    Time(u64),
}

/// 38421: a burn the peg holders did not pay within `pegoutBlocks`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PegOutDefaulted {
    /// The chain URN (pins the genesis).
    pub chain: Urn,
    /// The chain id on the wire.
    pub chain_id: String,
    /// The burn, sidechain txid : vout.
    pub burn: Outpoint,
    /// What was burned, sats.
    pub value: u64,
    /// The parent script it was owed to, hex.
    pub script: String,
    /// The sidechain height of the burn.
    pub burn_height: u32,
    /// The parent height by which it was due.
    pub due_parent_height: u32,
}

/// 38422: a child chain sealed and bound to a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChildChainOpened {
    /// The child's chain URN.
    pub chain: Urn,
    /// The child's id, `sidestr:dl-s-<sha12>`.
    pub chain_id: String,
    /// The parent (root) chain id.
    pub parent_chain_id: String,
    /// The child's genesis hash, 64 hex.
    pub genesis_hash: String,
    /// The session URN it settles for (`boundTo`).
    pub bound_to: Urn,
    /// When it closes.
    pub close_policy: ClosePolicy,
}

/// 38423: the close boundary reached; no new blocks past it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChildChainClosing {
    /// The child's chain URN.
    pub chain: Urn,
    /// The child's id.
    pub chain_id: String,
    /// The boundary that was reached.
    pub close_policy: ClosePolicy,
    /// The child's height at the boundary.
    pub height: u32,
}

/// 38424: the closing hash checkpointed into the parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainTombstoned {
    /// The chain URN.
    pub chain: Urn,
    /// The chain id.
    pub chain_id: String,
    /// The closing height.
    pub height: u32,
    /// The closing block hash, 64 hex.
    pub hash: String,
    /// The parent transaction carrying the `ckpt:` record, 64 hex.
    pub parent_txid: String,
}

/// 38425: a settlement finalised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementRecorded {
    /// The chain URN.
    pub chain: Urn,
    /// The chain id.
    pub chain_id: String,
    /// The settling transaction, 64 hex.
    pub txid: String,
    /// The amount, sats or asset units.
    pub amount: u64,
    /// The asset URN, `None` for the pegged coin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<Urn>,
    /// The `SettlementReceipt` URN.
    pub receipt: Urn,
    /// The height at which it became final.
    pub final_height: u32,
}

/// One of the five, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainEvent {
    /// 38421.
    PegOutDefaulted(PegOutDefaulted),
    /// 38422.
    ChildChainOpened(ChildChainOpened),
    /// 38423.
    ChildChainClosing(ChildChainClosing),
    /// 38424.
    ChainTombstoned(ChainTombstoned),
    /// 38425.
    SettlementRecorded(SettlementRecorded),
}

impl DomainEvent {
    /// The kind this event is published as.
    pub fn kind(&self) -> u32 {
        match self {
            DomainEvent::PegOutDefaulted(_) => KIND_PEGOUT_DEFAULTED,
            DomainEvent::ChildChainOpened(_) => KIND_CHILD_CHAIN_OPENED,
            DomainEvent::ChildChainClosing(_) => KIND_CHILD_CHAIN_CLOSING,
            DomainEvent::ChainTombstoned(_) => KIND_CHAIN_TOMBSTONED,
            DomainEvent::SettlementRecorded(_) => KIND_SETTLEMENT_RECORDED,
        }
    }

    /// The chain id the content names.
    pub fn chain_id(&self) -> &str {
        match self {
            DomainEvent::PegOutDefaulted(e) => &e.chain_id,
            DomainEvent::ChildChainOpened(e) => &e.chain_id,
            DomainEvent::ChildChainClosing(e) => &e.chain_id,
            DomainEvent::ChainTombstoned(e) => &e.chain_id,
            DomainEvent::SettlementRecorded(e) => &e.chain_id,
        }
    }

    fn check(&self) -> Result<()> {
        match self {
            DomainEvent::PegOutDefaulted(e) => {
                hex_of("script", &e.script, e.script.len() / 2).map(drop)
            }
            DomainEvent::ChildChainOpened(e) => {
                hex_of("genesis hash", &e.genesis_hash, 32).map(drop)
            }
            DomainEvent::ChildChainClosing(_) => Ok(()),
            DomainEvent::ChainTombstoned(e) => {
                hex_of("hash", &e.hash, 32)?;
                hex_of("parent txid", &e.parent_txid, 32).map(drop)
            }
            DomainEvent::SettlementRecorded(e) => hex_of("txid", &e.txid, 32).map(drop),
        }
    }

    fn content(&self) -> Result<String> {
        Ok(match self {
            DomainEvent::PegOutDefaulted(e) => serde_json::to_string(e)?,
            DomainEvent::ChildChainOpened(e) => serde_json::to_string(e)?,
            DomainEvent::ChildChainClosing(e) => serde_json::to_string(e)?,
            DomainEvent::ChainTombstoned(e) => serde_json::to_string(e)?,
            DomainEvent::SettlementRecorded(e) => serde_json::to_string(e)?,
        })
    }
}

/// The unsigned event for a domain event in the legacy form: `chain` tag =
/// the alias, as an index; content the JSON. A chain with a chain event
/// uses [`domain_event_on`].
pub fn domain_event(e: &DomainEvent, created_at: u64) -> Result<UnsignedEvent> {
    e.check()?;
    if e.chain_id().is_empty() {
        return Err(Error::Chain("empty chain id".into()));
    }
    Ok(UnsignedEvent {
        pubkey: String::new(),
        created_at,
        kind: e.kind(),
        tags: vec![tag(TAG_CHAIN, e.chain_id())],
        content: e.content()?,
    })
}

/// The unsigned event for a domain event on a chain with a chain event
/// (ADR-2098 as amended: 38420–38425 carry the chain hash, never the
/// alias): `chain` = the chain hash, `alias` = the alias the content names;
/// content the same JSON as [`domain_event`]'s. The content stays
/// authoritative for the alias; the tag is the only place the hash appears.
///
/// ```
/// use sidestr_nostr::estate::{domain_event_on, ChainTombstoned, DomainEvent, Urn};
///
/// let e = DomainEvent::ChainTombstoned(ChainTombstoned {
///     chain: Urn::parse("urn:agentbox:chain:poker:0123456789ab").unwrap(),
///     chain_id: "sidestr:poker".into(),
///     height: 500,
///     hash: "dd".repeat(32),
///     parent_txid: "ee".repeat(32),
/// });
/// let ev = domain_event_on(&e, &"9f".repeat(32), 1).unwrap();
/// assert_eq!(ev.tags[0], ["chain".to_string(), "9f".repeat(32)]);
/// assert_eq!(ev.tags[1], ["alias", "sidestr:poker"]);
/// ```
pub fn domain_event_on(
    e: &DomainEvent,
    chain_hash: &str,
    created_at: u64,
) -> Result<UnsignedEvent> {
    let hash = hex_of("chain hash", chain_hash, 32)?;
    let mut ev = domain_event(e, created_at)?;
    ev.tags = vec![tag(TAG_CHAIN, hash), tag(TAG_ALIAS, e.chain_id())];
    Ok(ev)
}

/// Sign a domain event in the legacy form ([`domain_event`]) with the
/// estate's publishing key for the chain plane.
pub fn sign_domain_event(signer: &dyn Signer, e: &DomainEvent, created_at: u64) -> Result<Event> {
    sign(signer, domain_event(e, created_at)?)
}

/// Sign a domain event naming its chain by hash ([`domain_event_on`]).
pub fn sign_domain_event_on(
    signer: &dyn Signer,
    e: &DomainEvent,
    chain_hash: &str,
    created_at: u64,
) -> Result<Event> {
    sign(signer, domain_event_on(e, chain_hash, created_at)?)
}

/// A domain event read back with the chain hash it names, if any
/// ([`parse_domain_event_of`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDomainEvent {
    /// The event.
    pub event: DomainEvent,
    /// The chain hash its `chain` tag carries, lower case; `None` in the
    /// legacy form, where the tag is the alias.
    pub chain_hash: Option<String>,
}

impl ParsedDomainEvent {
    /// Whether the event names its chain by alias only.
    pub fn legacy(&self) -> bool {
        self.chain_hash.is_none()
    }
}

/// Decode any of 38421–38425 in either form. Any other kind is
/// [`Error::Kind`] against 38421. Does not verify the signature.
/// [`parse_domain_event_of`] also returns the chain hash.
pub fn parse_domain_event(ev: &Event) -> Result<DomainEvent> {
    parse_domain_event_of(ev).map(|p| p.event)
}

/// Decode any of 38421–38425 and the chain hash it names. A `chain` tag of
/// 64 hex is the chain hash ([`domain_event_on`]), and an `alias` tag, when
/// present, must be the content's chain id; any other `chain` tag must be
/// the content's chain id (the legacy form, read as 0.5.0 read it).
pub fn parse_domain_event_of(ev: &Event) -> Result<ParsedDomainEvent> {
    let e = match ev.kind {
        KIND_PEGOUT_DEFAULTED => DomainEvent::PegOutDefaulted(serde_json::from_str(&ev.content)?),
        KIND_CHILD_CHAIN_OPENED => {
            DomainEvent::ChildChainOpened(serde_json::from_str(&ev.content)?)
        }
        KIND_CHILD_CHAIN_CLOSING => {
            DomainEvent::ChildChainClosing(serde_json::from_str(&ev.content)?)
        }
        KIND_CHAIN_TOMBSTONED => DomainEvent::ChainTombstoned(serde_json::from_str(&ev.content)?),
        KIND_SETTLEMENT_RECORDED => {
            DomainEvent::SettlementRecorded(serde_json::from_str(&ev.content)?)
        }
        other => {
            return Err(Error::Kind {
                expected: KIND_PEGOUT_DEFAULTED,
                found: other,
                what: "a settlement domain event (38421-38425)",
            })
        }
    };
    e.check()?;
    let disagree = |name: &'static str, v: &str| Error::Disagree {
        tag: name,
        tag_value: v.to_string(),
        content_value: e.chain_id().to_string(),
    };
    let mut chain_hash = None;
    match first(&ev.tags, TAG_CHAIN) {
        Some(c) if is_chain_hash(c) => {
            if let Some(a) = first(&ev.tags, TAG_ALIAS).filter(|a| *a != e.chain_id()) {
                return Err(disagree(TAG_ALIAS, a));
            }
            chain_hash = Some(c.to_ascii_lowercase());
        }
        Some(c) if c != e.chain_id() => return Err(disagree(TAG_CHAIN, c)),
        _ => {}
    }
    Ok(ParsedDomainEvent {
        event: e,
        chain_hash,
    })
}

/// Hold a domain event to the chain it names, read from the chain's
/// verified kind-3500 event: the hash, when the event carries one, must be
/// the chain event's id, and the content's chain id its alias.
pub fn check_domain_event_chain(e: &ParsedDomainEvent, chain: &ParsedChain) -> Result<()> {
    if let Some(h) = &e.chain_hash {
        if !h.eq_ignore_ascii_case(&chain.hash) {
            return Err(Error::Chain(format!(
                "the event names chain {h}, not the chain event {}",
                chain.hash
            )));
        }
    }
    if e.event.chain_id() != chain.alias {
        return Err(Error::Chain(format!(
            "the event is for {}, the chain event for {}",
            e.event.chain_id(),
            chain.alias
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::SecretKeySigner;

    fn identity() -> SecretKeySigner {
        SecretKeySigner::from_bytes(&[11u8; 32]).unwrap()
    }
    fn urn(s: &str) -> Urn {
        Urn::parse(s).unwrap()
    }
    fn binding() -> AccountBinding {
        AccountBinding {
            alias: "sidestr:dreamlab".into(),
            chain_hash: Some("cd".repeat(32)),
            genesis_hash: "4D".repeat(32),
            did_hex: identity().pubkey_hex().unwrap(),
            spend_pubkey: "ab".repeat(32),
        }
    }

    #[test]
    fn urn_is_checked_not_minted() {
        assert!(Urn::parse("urn:agentbox:chain:dreamlab:4db3751772").is_ok());
        for bad in [
            "urn:visionclaw:chain:x",
            "urn:agentbox:",
            "urn:agentbox:chain",
            "urn:agentbox::x",
            "chain:x",
        ] {
            assert!(matches!(Urn::parse(bad), Err(Error::Urn(_))), "{bad}");
        }
        let u: Urn = serde_json::from_str("\"urn:agentbox:session:abc\"").unwrap();
        assert_eq!(u.to_string(), "urn:agentbox:session:abc");
        assert!(serde_json::from_str::<Urn>("\"nope\"").is_err());
    }

    #[test]
    fn binding_round_trip() {
        let ev = sign_account_binding(&identity(), &binding(), 1).unwrap();
        assert_eq!(ev.kind, 38420);
        let did = identity().pubkey_hex().unwrap();
        assert_eq!(
            ev.tags[0],
            vec!["d".to_string(), format!("{}:{did}", "cd".repeat(32))]
        );
        assert_eq!(ev.tags[1], vec!["alias", "sidestr:dreamlab"]);
        assert_eq!(ev.tags[2], vec!["genesis", &"4d".repeat(32)]);
        assert_eq!(ev.tags[3], vec!["chain", &"cd".repeat(32)]);
        assert_eq!(ev.tags[4][0], "alt");
        let b = parse_account_binding(&ev).unwrap();
        assert_eq!(b.genesis_hash, "4d".repeat(32));
        assert_eq!(b.chain_key(), "cd".repeat(32));
        assert_eq!(b.alias, "sidestr:dreamlab");
        // a pre-0.0.5 chain is keyed by its genesis and tagged legacy
        let legacy = AccountBinding {
            chain_hash: None,
            ..binding()
        };
        let ev = sign_account_binding(&identity(), &legacy, 1).unwrap();
        assert_eq!(
            parse_binding_address(&ev.tags[0][1]).unwrap().0,
            "4d".repeat(32)
        );
        assert_eq!(ev.tags[3], vec!["legacy", "pre-0.0.5"]);
        assert_eq!(parse_account_binding(&ev).unwrap().chain_hash, None);
    }

    #[test]
    fn a_binding_is_signed_by_the_identity_it_names() {
        let other = SecretKeySigner::from_bytes(&[12u8; 32]).unwrap();
        assert!(matches!(
            sign_account_binding(&other, &binding(), 1),
            Err(Error::Key(_))
        ));
        let mut b = binding();
        b.did_hex = other.pubkey_hex().unwrap();
        let ev = sign_account_binding(&other, &b, 1).unwrap();
        let mut forged = ev.clone();
        forged.pubkey = identity().pubkey_hex().unwrap();
        assert!(matches!(
            parse_account_binding(&forged),
            Err(Error::Chain(_))
        ));
        // d keyed by something other than the chain tag's hash
        let mut moved = ev.clone();
        moved.tags[3][1] = "ef".repeat(32);
        assert!(matches!(
            parse_account_binding(&moved),
            Err(Error::Disagree { tag: "d", .. })
        ));
        let mut both = ev.clone();
        both.tags.push(vec!["legacy".into(), LEGACY.into()]);
        assert!(matches!(
            parse_account_binding(&both),
            Err(Error::Content(_))
        ));
        let mut neither = ev.clone();
        neither.tags.remove(3);
        assert!(matches!(
            parse_account_binding(&neither),
            Err(Error::MissingTag("chain"))
        ));
        let mut nog = ev.clone();
        nog.tags.remove(2);
        assert!(matches!(
            parse_account_binding(&nog),
            Err(Error::MissingTag("genesis"))
        ));
        let mut short = ev;
        short.content = "ab".into();
        assert!(matches!(
            parse_account_binding(&short),
            Err(Error::Hex { .. })
        ));
        // the alias is never a chain key
        assert!(parse_binding_address(&format!("sidestr:x:{}", "ab".repeat(32))).is_err());
        assert!(parse_binding_address(&format!(":{}", "ab".repeat(32))).is_err());
        assert!(account_binding_event(
            &AccountBinding {
                genesis_hash: "x".into(),
                ..binding()
            },
            1
        )
        .is_err());
    }

    fn all_five() -> Vec<DomainEvent> {
        vec![
            DomainEvent::PegOutDefaulted(PegOutDefaulted {
                chain: urn("urn:agentbox:chain:dreamlab:4db3751772"),
                chain_id: "sidestr:dreamlab".into(),
                burn: Outpoint {
                    txid: "aa".repeat(32),
                    vout: 1,
                },
                value: 20_000,
                script: "0014".to_string() + &"bb".repeat(20),
                burn_height: 40,
                due_parent_height: 153_700,
            }),
            DomainEvent::ChildChainOpened(ChildChainOpened {
                chain: urn("urn:agentbox:chain:dl-s-abcdef012345:0123456789ab"),
                chain_id: "sidestr:dl-s-abcdef012345".into(),
                parent_chain_id: "sidestr:dreamlab".into(),
                genesis_hash: "cc".repeat(32),
                bound_to: urn("urn:agentbox:session:abc"),
                close_policy: ClosePolicy::Height(500),
            }),
            DomainEvent::ChildChainClosing(ChildChainClosing {
                chain: urn("urn:agentbox:chain:dl-s-abcdef012345:0123456789ab"),
                chain_id: "sidestr:dl-s-abcdef012345".into(),
                close_policy: ClosePolicy::Time(1_790_200_000),
                height: 500,
            }),
            DomainEvent::ChainTombstoned(ChainTombstoned {
                chain: urn("urn:agentbox:chain:dl-s-abcdef012345:0123456789ab"),
                chain_id: "sidestr:dl-s-abcdef012345".into(),
                height: 500,
                hash: "dd".repeat(32),
                parent_txid: "ee".repeat(32),
            }),
            DomainEvent::SettlementRecorded(SettlementRecorded {
                chain: urn("urn:agentbox:chain:dreamlab:4db3751772"),
                chain_id: "sidestr:dreamlab".into(),
                txid: "ff".repeat(32),
                amount: 1234,
                asset: None,
                receipt: urn("urn:agentbox:receipt:abc:sha256-12-0123456789ab"),
                final_height: 41,
            }),
        ]
    }

    #[test]
    fn the_five_round_trip_with_content_authoritative() {
        let s = identity();
        for (i, e) in all_five().into_iter().enumerate() {
            let ev = sign_domain_event(&s, &e, 1).unwrap();
            assert_eq!(ev.kind, 38421 + i as u32);
            assert_eq!(ev.tags, vec![vec!["chain", e.chain_id()]]);
            assert_eq!(parse_domain_event(&ev).unwrap(), e);
            let mut c = ev.clone();
            c.tags[0][1] = "sidestr:elsewhere".into();
            assert!(matches!(
                parse_domain_event(&c),
                Err(Error::Disagree { .. })
            ));
            let mut junk = ev;
            junk.content = "{}".into();
            assert!(matches!(parse_domain_event(&junk), Err(Error::Json(_))));
        }
        let v: serde_json::Value =
            serde_json::from_str(&sign_domain_event(&s, &all_five()[1], 1).unwrap().content)
                .unwrap();
        assert_eq!(v["closePolicy"], serde_json::json!({"height": 500}));
        assert_eq!(v["boundTo"], "urn:agentbox:session:abc");
    }

    #[test]
    fn parse_binding_reads_every_form_and_flags_the_legacy_ones() {
        let did = identity().pubkey_hex().unwrap();
        let hash = sign_account_binding(&identity(), &binding(), 1).unwrap();
        let p = parse_binding(&hash).unwrap();
        assert_eq!((p.form, p.legacy()), (BindingForm::Hash, false));
        assert_eq!(p.binding, parse_account_binding(&hash).unwrap());
        let gen = AccountBinding {
            chain_hash: None,
            genesis_hash: "4d".repeat(32),
            ..binding()
        };
        let g = sign_account_binding(&identity(), &gen, 1).unwrap();
        let p = parse_binding(&g).unwrap();
        assert_eq!((p.form, p.legacy()), (BindingForm::Genesis, true));
        // the keyed forms are refused exactly as parse_account_binding refuses them
        let mut moved = hash.clone();
        moved.tags[3][1] = "ef".repeat(32);
        assert!(matches!(
            parse_binding(&moved),
            Err(Error::Disagree { tag: "d", .. })
        ));

        // the alias form: what 0.5.0 wrote, read as 0.5.0 read it
        let a = sign_legacy_alias_binding(&identity(), &gen, 1).unwrap();
        assert_eq!(a.tags[0][1], format!("sidestr:dreamlab:{did}"));
        assert_eq!(a.tags[1], vec!["chain", "sidestr:dreamlab"]);
        assert!(parse_account_binding(&a).is_err());
        let p = parse_binding(&a).unwrap();
        assert_eq!((p.form, p.legacy()), (BindingForm::Alias, true));
        assert_eq!(p.binding, gen);
        let mut other_chain = a.clone();
        other_chain.tags[1][1] = "sidestr:other".into();
        assert!(matches!(
            parse_binding(&other_chain),
            Err(Error::Disagree { tag: "chain", .. })
        ));
        let mut other_alias = a.clone();
        other_alias.tags.push(tag(TAG_ALIAS, "sidestr:other"));
        assert!(matches!(
            parse_binding(&other_alias),
            Err(Error::Disagree { tag: "alias", .. })
        ));
        let mut forged = a.clone();
        forged.pubkey = "ab".repeat(32);
        assert!(matches!(parse_binding(&forged), Err(Error::Chain(_))));
        let mut nameless = a.clone();
        nameless.tags[0][1] = format!(":{did}");
        assert!(matches!(
            parse_binding(&nameless),
            Err(Error::Tag { tag: "d", .. })
        ));
        let mut nog = a.clone();
        nog.tags.remove(2);
        assert!(matches!(
            parse_binding(&nog),
            Err(Error::MissingTag("genesis"))
        ));
        let mut wrong_kind = a;
        wrong_kind.kind = 38421;
        assert!(matches!(
            parse_binding(&wrong_kind),
            Err(Error::Kind { .. })
        ));

        // the alias form is never written for a chain with a hash, nor with a hash as alias
        assert!(matches!(
            legacy_alias_binding_event(&binding(), 1),
            Err(Error::Chain(_))
        ));
        for alias in [String::new(), "cd".repeat(32)] {
            assert!(matches!(
                legacy_alias_binding_event(
                    &AccountBinding {
                        alias,
                        ..gen.clone()
                    },
                    1
                ),
                Err(Error::Tag { tag: "alias", .. })
            ));
        }
    }

    #[test]
    fn the_five_name_their_chain_by_hash_and_the_alias_form_stays_legacy() {
        let s = identity();
        let h = "9f".repeat(32);
        for e in all_five() {
            let ev = sign_domain_event_on(&s, &e, &h.to_uppercase(), 1).unwrap();
            assert_eq!(
                ev.tags,
                vec![vec!["chain", h.as_str()], vec!["alias", e.chain_id()]]
            );
            let p = parse_domain_event_of(&ev).unwrap();
            assert_eq!(p.event, e);
            assert_eq!(p.chain_hash.as_deref(), Some(h.as_str()));
            assert!(!p.legacy());
            assert_eq!(parse_domain_event(&ev).unwrap(), e);
            // the content's alias is authoritative over the alias tag
            let mut a = ev.clone();
            a.tags[1][1] = "sidestr:elsewhere".into();
            assert!(matches!(
                parse_domain_event_of(&a),
                Err(Error::Disagree { tag: "alias", .. })
            ));
            // the content is the legacy form's, byte for byte
            let legacy = sign_domain_event(&s, &e, 1).unwrap();
            assert_eq!(legacy.content, ev.content);
            let p = parse_domain_event_of(&legacy).unwrap();
            assert!(p.legacy() && p.chain_hash.is_none());
            assert_eq!(p.event, e);
        }
        assert!(matches!(
            domain_event_on(&all_five()[0], "abc", 1),
            Err(Error::Hex { .. })
        ));
    }

    #[test]
    fn a_domain_event_is_held_to_its_chain_event() {
        let chain_key = SecretKeySigner::from_bytes(&[0x31u8; 32]).unwrap();
        let me = chain_key.pubkey_hex().unwrap();
        let doc = format!(
            r#"{{"id":"sidestr:dreamlab","name":"dreamlab","parent":"tbtc4","challenge":"5120{me}","genesisTime":1}}"#
        );
        let chain = crate::chain::parse_chain_event(
            &crate::chain::sign_chain_event(&chain_key, &doc, 1).unwrap(),
        )
        .unwrap();
        let e = all_five()[4].clone();
        let on = |h: &str| {
            parse_domain_event_of(&sign_domain_event_on(&identity(), &e, h, 1).unwrap()).unwrap()
        };
        check_domain_event_chain(&on(&chain.hash), &chain).unwrap();
        assert!(check_domain_event_chain(&on(&"9f".repeat(32)), &chain).is_err());
        let legacy =
            parse_domain_event_of(&sign_domain_event(&identity(), &e, 1).unwrap()).unwrap();
        check_domain_event_chain(&legacy, &chain).unwrap();
        let child = parse_domain_event_of(
            &sign_domain_event_on(&identity(), &all_five()[1], &chain.hash, 1).unwrap(),
        )
        .unwrap();
        assert!(check_domain_event_chain(&child, &chain).is_err());
    }

    #[test]
    fn domain_event_rejections() {
        let mut ev = sign_domain_event(&identity(), &all_five()[4], 1).unwrap();
        ev.kind = 38420;
        assert!(matches!(
            parse_domain_event(&ev),
            Err(Error::Kind { found: 38420, .. })
        ));
        let DomainEvent::ChainTombstoned(mut t) = all_five()[3].clone() else {
            panic!()
        };
        t.hash = "dd".into();
        assert!(matches!(
            domain_event(&DomainEvent::ChainTombstoned(t.clone()), 1),
            Err(Error::Hex { .. })
        ));
        let bad_urn = serde_json::json!({"chain":"urn:x","chainId":"sidestr:d","height":1,"hash":"dd".repeat(32),"parentTxid":"ee".repeat(32)});
        let mut e = sign_domain_event(&identity(), &all_five()[3], 1).unwrap();
        e.content = bad_urn.to_string();
        assert!(matches!(parse_domain_event(&e), Err(Error::Json(_))));
        let DomainEvent::PegOutDefaulted(mut p) = all_five()[0].clone() else {
            panic!()
        };
        p.chain_id = String::new();
        assert!(matches!(
            domain_event(&DomainEvent::PegOutDefaulted(p), 1),
            Err(Error::Chain(_))
        ));
    }
}
