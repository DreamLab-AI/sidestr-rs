//! agentbox's own kinds: the account binding (38420) and the five
//! settlement domain events (38421–38425), from the 38400–38499 band
//! (ADR-2098 D2 and amendments, ADR-2105, DDD-022 "Domain Events").
//!
//! # The account binding, 38420
//!
//! `sidestr-account-binding`: addressable, `d` = `<chain>:<did hex>`,
//! content = the spend pubkey, **signed by the identity key**. The binding
//! says "on this chain, this principal spends with this key"; because the
//! identity key signs it, the `did hex` in `d` must be the event's author
//! ([`parse_account_binding`] refuses otherwise), and because "a name is
//! never monetary identity" (ADR-2098 amendment) it pins the genesis hash in a
//! `genesis` tag. Re-sealing a chain under the same name is a different
//! genesis, so a binding to the old one does not carry over.
//!
//! What `<chain>` is depends on the chain ([`BindingForm`]). Since SPEC
//! 0.0.5 a chain is named by its **hash**, the id of its kind-3500 event,
//! and the agentbox registry (amended 2026-10-02) puts that hash in `d`,
//! with the alias in an `alias` tag and `genesis` as a cross-check
//! ([`check_binding_chain`] holds a binding to the chain event). A chain
//! sealed before 0.0.5 has no hash: the registry's form puts its genesis
//! hash in `d` and tags it `legacy`. Both are written byte for byte as
//! agentbox's `buildBinding` writes them ([`account_binding_event_as`]).
//! The form this crate wrote through 0.5.0, the alias in `d`, is still read
//! and still written by [`account_binding_event`] unchanged, flagged legacy
//! when read ([`parse_binding`]): the live `sidestr:dreamlab` has no chain
//! event, and nothing already signed moves.
//!
//! # The domain events, 38421–38425
//!
//! DDD-022 names the five facts upstream has no event for, and what each is
//! for. They are **regular** events — evidence accretes, nothing replaces
//! it — and their content is JSON with the chain id inside it (content is
//! authoritative; the `chain` tag is an index, and [`Error::Disagree`] is the
//! answer to a mismatch). For a chain with a chain event the `chain` tag
//! carries its hash and an `alias` tag the alias ([`domain_event_on`]); the
//! alias-only form stays readable and is flagged legacy
//! ([`parse_domain_event_of`]). Every URN they carry was minted by the estate's sole
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
//!     chain_id: "sidestr:dreamlab".into(),
//!     genesis_hash: "4d".repeat(32),
//!     did_hex: identity.pubkey_hex().unwrap(),
//!     spend_pubkey: "ab".repeat(32),
//! };
//! let ev = sign_account_binding(&identity, &b, 1_790_100_000).unwrap();
//! assert_eq!(ev.tags[0][1], format!("sidestr:dreamlab:{}", b.did_hex));
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

/// The tag naming the chain's alias on a binding in the estate's hash and
/// genesis forms ([`BindingForm`]), and on a domain event that names its
/// chain by hash.
pub const TAG_ALIAS: &str = "alias";
/// The tag marking a binding for a chain sealed before sidestr 0.0.5,
/// which has no chain hash: `["legacy", "pre-0.0.5"]`.
pub const TAG_LEGACY: &str = "legacy";
/// The value [`account_binding_event_as`] writes in the [`TAG_LEGACY`] tag.
pub const LEGACY_PRE_005: &str = "pre-0.0.5";

/// The 38420 binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountBinding {
    /// The chain's alias, `sidestr:<name>`: a name, not a proof.
    pub chain_id: String,
    /// The chain's genesis hash, 64 hex: the monetary identity the name alone is not.
    pub genesis_hash: String,
    /// The principal's identity pubkey, 64 hex — the event's author.
    pub did_hex: String,
    /// The derived spend pubkey on this chain, 64 hex (ADR-2101 D3: never the identity key).
    pub spend_pubkey: String,
}

/// How a 38420 binding names its chain in `d`.
///
/// The agentbox registry (`docs/PROTOCOL-registry.md`, amended 2026-10-02
/// for SPEC 0.0.5) has `d` carry the 64-hex **chain hash**, the id of the
/// chain's kind-3500 event, and for a chain sealed before 0.0.5, which has
/// none, its genesis hash and a `legacy` tag. The forms are written
/// byte for byte as agentbox's `management-api/lib/sidestr-spend-key.js`
/// `buildBinding` writes them (`tests/binding_forms.rs` holds a binding
/// that module signed to the same id). This crate wrote the third form,
/// with the alias in `d`, through 0.5.0; it stays readable and
/// [`account_binding_event`] still writes it unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingForm {
    /// `d` = `<chain hash>:<did hex>`; tags `alias` (the chain's alias),
    /// `genesis` (a cross-check, never the identity), `chain` = the hash
    /// and a NIP-31 `alt`. For a chain with a chain event (SPEC 0.0.5).
    Hash(String),
    /// Legacy: `d` = `<genesis hash>:<did hex>`; tags `alias`, `genesis`,
    /// `legacy` = `pre-0.0.5` and `alt`. The registry's form for a chain
    /// sealed before 0.0.5 (the live `sidestr:dreamlab` among them).
    Genesis,
    /// Legacy: `d` = `<chain alias>:<did hex>`; tags `chain` = the alias and
    /// `genesis`. This crate's form through 0.5.0.
    Alias,
}

impl BindingForm {
    /// Whether the binding names its chain by something other than its
    /// hash: a chain made before 0.0.5, or a binding made before the
    /// registry's amendment.
    pub fn is_legacy(&self) -> bool {
        !matches!(self, BindingForm::Hash(_))
    }

    /// The chain hash the binding names, in the hash form.
    pub fn chain_hash(&self) -> Option<&str> {
        match self {
            BindingForm::Hash(h) => Some(h),
            _ => None,
        }
    }
}

/// A 38420 read back with the form it was written in ([`parse_binding`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedBinding {
    /// The binding; `chain_id` is the alias whatever the form.
    pub binding: AccountBinding,
    /// How `d` named the chain.
    pub form: BindingForm,
}

impl ParsedBinding {
    /// Whether the binding is in a legacy form ([`BindingForm::is_legacy`]).
    pub fn legacy(&self) -> bool {
        self.form.is_legacy()
    }

    /// The chain hash, in the hash form.
    pub fn chain_hash(&self) -> Option<&str> {
        self.form.chain_hash()
    }
}

/// The `d` value of a binding: `<chain>:<did hex>`, where `<chain>` is the
/// chain hash ([`BindingForm::Hash`]), the genesis hash
/// ([`BindingForm::Genesis`]) or the alias ([`BindingForm::Alias`]).
pub fn binding_address(chain_id: &str, did_hex: &str) -> String {
    format!("{chain_id}:{did_hex}")
}

/// Split a binding `d`. A chain alias contains a colon, so the DID is what
/// follows the last one and must be 64 hex.
pub fn parse_binding_address(d: &str) -> Result<(String, String)> {
    let (chain, did) = d.rsplit_once(':').ok_or_else(|| Error::Tag {
        tag: TAG_D,
        reason: format!("{d:?} is not <chain id>:<did hex>"),
    })?;
    if chain.is_empty() {
        return Err(Error::Tag {
            tag: TAG_D,
            reason: format!("{d:?} names no chain"),
        });
    }
    let did = hex_of("did hex", did, 32).map_err(|e| Error::Tag {
        tag: TAG_D,
        reason: e.to_string(),
    })?;
    Ok((chain.to_string(), did))
}

/// The unsigned 38420 in the legacy alias form ([`BindingForm::Alias`]):
/// `d` = `<alias>:<did hex>`, `chain`, `genesis`; content the spend pubkey.
/// Unchanged since 0.5.0, so a binding made before the registry's amendment
/// is made again to the same id; new bindings use
/// [`account_binding_event_as`].
pub fn account_binding_event(b: &AccountBinding, created_at: u64) -> Result<UnsignedEvent> {
    Ok(UnsignedEvent {
        pubkey: hex_of("did hex", &b.did_hex, 32)?,
        created_at,
        kind: KIND_ACCOUNT_BINDING,
        tags: vec![
            tag(
                TAG_D,
                binding_address(&b.chain_id, &b.did_hex.to_ascii_lowercase()),
            ),
            tag(TAG_CHAIN, &b.chain_id),
            tag(TAG_GENESIS, hex_of("genesis hash", &b.genesis_hash, 32)?),
        ],
        content: hex_of("spend pubkey", &b.spend_pubkey, 32)?,
    })
}

/// The unsigned 38420 in the given form. [`BindingForm::Alias`] is
/// [`account_binding_event`]. The two estate forms are agentbox's
/// `buildBinding`'s, tag for tag (`d`, `alias`, `genesis`, then `chain` =
/// the hash or `legacy` = `pre-0.0.5`, then `alt`), so the same inputs give
/// the same event id in either language; like `buildBinding` they refuse a
/// spend key equal to the identity key (ADR-2101 D3) and an empty alias.
///
/// ```
/// use sidestr_nostr::estate::{account_binding_event_as, AccountBinding, BindingForm};
///
/// let b = AccountBinding {
///     chain_id: "sidestr:poker".into(),
///     genesis_hash: "4d".repeat(32),
///     did_hex: "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa".into(),
///     spend_pubkey: "ab".repeat(32),
/// };
/// let hash = "9f".repeat(32);
/// let ev = account_binding_event_as(&b, &BindingForm::Hash(hash.clone()), 1).unwrap();
/// assert_eq!(ev.tags[0][1], format!("{hash}:{}", b.did_hex));
/// assert_eq!(ev.tags[3], ["chain", hash.as_str()]);
/// let old = account_binding_event_as(&b, &BindingForm::Genesis, 1).unwrap();
/// assert_eq!(old.tags[0][1], format!("{}:{}", b.genesis_hash, b.did_hex));
/// assert_eq!(old.tags[3], ["legacy", "pre-0.0.5"]);
/// ```
pub fn account_binding_event_as(
    b: &AccountBinding,
    form: &BindingForm,
    created_at: u64,
) -> Result<UnsignedEvent> {
    let key = match form {
        BindingForm::Alias => return account_binding_event(b, created_at),
        BindingForm::Hash(h) => Some(hex_of("chain hash", h, 32)?),
        BindingForm::Genesis => None,
    };
    let did = hex_of("did hex", &b.did_hex, 32)?;
    let genesis = hex_of("genesis hash", &b.genesis_hash, 32)?;
    let spend = hex_of("spend pubkey", &b.spend_pubkey, 32)?;
    if spend == did {
        return Err(Error::Key(
            "the spend key must differ from the identity key (ADR-2101 D3)".into(),
        ));
    }
    if b.chain_id.is_empty() {
        return Err(Error::Chain("empty chain id".into()));
    }
    let (d, last) = match &key {
        Some(h) => (binding_address(h, &did), tag(TAG_CHAIN, h)),
        None => (
            binding_address(&genesis, &did),
            tag(TAG_LEGACY, LEGACY_PRE_005),
        ),
    };
    let alt = format!(
        "sidestr account binding: the spend key of did:nostr:{did} on {}",
        b.chain_id
    );
    Ok(UnsignedEvent {
        pubkey: did,
        created_at,
        kind: KIND_ACCOUNT_BINDING,
        tags: vec![
            tag(TAG_D, d),
            tag(TAG_ALIAS, &b.chain_id),
            tag(TAG_GENESIS, genesis),
            last,
            tag(TAG_ALT, alt),
        ],
        content: spend,
    })
}

/// Sign a binding in the legacy alias form with the identity key. The
/// signer must *be* `did_hex`: a binding signed by any other key is refused
/// before it is made.
pub fn sign_account_binding(
    signer: &dyn Signer,
    b: &AccountBinding,
    created_at: u64,
) -> Result<Event> {
    sign_account_binding_as(signer, b, &BindingForm::Alias, created_at)
}

/// Sign a binding in the given form ([`account_binding_event_as`]) with the
/// identity key, which must be `did_hex`.
pub fn sign_account_binding_as(
    signer: &dyn Signer,
    b: &AccountBinding,
    form: &BindingForm,
    created_at: u64,
) -> Result<Event> {
    let me = signer.pubkey_hex()?;
    if !me.eq_ignore_ascii_case(b.did_hex.trim()) {
        return Err(Error::Key(
            "a binding is signed by the identity key it names".into(),
        ));
    }
    sign(signer, account_binding_event_as(b, form, created_at)?)
}

/// Decode a 38420 in any form. The `d` DID must be the author. Does not
/// verify the signature. [`parse_binding`] also says which form it was.
pub fn parse_account_binding(ev: &Event) -> Result<AccountBinding> {
    parse_binding(ev).map(|p| p.binding)
}

/// Decode a 38420 and say how it names its chain. Does not verify the
/// signature.
///
/// - `d` = `<64 hex>:<did>` with a `legacy` tag: [`BindingForm::Genesis`];
///   the hex must be the `genesis` tag, and a `chain` tag is refused (a
///   legacy binding names no chain hash). The alias is the `alias` tag.
/// - `d` = `<64 hex>:<did>` without one: [`BindingForm::Hash`]; a `chain`
///   tag, when present, must be the same hash. The alias is the `alias` tag.
/// - anything else, `<alias>:<did>`: [`BindingForm::Alias`], read exactly as
///   0.5.0 read it (a `chain` tag must be the alias); an `alias` tag, when
///   present, must be too.
///
/// Every form needs the `genesis` tag and content of 64 hex; the DID in `d`
/// must be the author.
pub fn parse_binding(ev: &Event) -> Result<ParsedBinding> {
    expect_kind(ev.kind, KIND_ACCOUNT_BINDING, "sidestr-account-binding")?;
    let (chain, did_hex) = parse_binding_address(required(&ev.tags, TAG_D)?)?;
    if !ev.pubkey.eq_ignore_ascii_case(&did_hex) {
        return Err(Error::Chain(format!(
            "binding for {did_hex} is signed by {}: not the identity key",
            ev.pubkey
        )));
    }
    let agree = |name: &'static str, want: &str| -> Result<()> {
        match first(&ev.tags, name) {
            Some(v) if v != want => Err(Error::Disagree {
                tag: name,
                tag_value: v.to_string(),
                content_value: want.to_string(),
            }),
            _ => Ok(()),
        }
    };
    let (chain_id, form) = if is_chain_hash(&chain) {
        let key = chain.to_ascii_lowercase();
        let alias = required(&ev.tags, TAG_ALIAS)?;
        if alias.is_empty() {
            return Err(Error::Tag {
                tag: TAG_ALIAS,
                reason: "names no chain".into(),
            });
        }
        let form = if first(&ev.tags, TAG_LEGACY).is_some() {
            if first(&ev.tags, TAG_CHAIN).is_some() {
                return Err(Error::Tag {
                    tag: TAG_CHAIN,
                    reason: "a legacy binding names no chain hash".into(),
                });
            }
            let g = hex_of("genesis hash", required(&ev.tags, TAG_GENESIS)?, 32)?;
            if g != key {
                return Err(Error::Disagree {
                    tag: TAG_GENESIS,
                    tag_value: g,
                    content_value: key,
                });
            }
            BindingForm::Genesis
        } else {
            if let Some(c) = first(&ev.tags, TAG_CHAIN) {
                if !c.eq_ignore_ascii_case(&key) {
                    return Err(Error::Disagree {
                        tag: TAG_CHAIN,
                        tag_value: c.to_string(),
                        content_value: key,
                    });
                }
            }
            BindingForm::Hash(key)
        };
        (alias.to_string(), form)
    } else {
        agree(TAG_CHAIN, &chain)?;
        agree(TAG_ALIAS, &chain)?;
        (chain, BindingForm::Alias)
    };
    Ok(ParsedBinding {
        binding: AccountBinding {
            chain_id,
            genesis_hash: hex_of("genesis hash", required(&ev.tags, TAG_GENESIS)?, 32)?,
            did_hex,
            spend_pubkey: hex_of("spend pubkey", &ev.content, 32)?,
        },
        form,
    })
}

/// Hold a binding to the chain it names, read from the chain's verified
/// kind-3500 event ([`parse_chain_event`](crate::chain::parse_chain_event)
/// or [`resolve_chain`](crate::chain::resolve_chain)): in the hash form the
/// hash must be the event's id; in every form the alias must be the
/// document's `id`, and the `genesis` tag the document's `genesisHash` when
/// the document carries one (SPEC 5, 0.0.5: a cross-check, never the
/// identity). A legacy binding passes when alias and genesis agree; whether
/// to accept a legacy binding for a chain that has a chain event is the
/// caller's choice ([`ParsedBinding::legacy`]).
pub fn check_binding_chain(b: &ParsedBinding, chain: &ParsedChain) -> Result<()> {
    if let Some(h) = b.chain_hash() {
        if !h.eq_ignore_ascii_case(&chain.hash) {
            return Err(Error::Chain(format!(
                "the binding names chain {h}, not the chain event {}",
                chain.hash
            )));
        }
    }
    if b.binding.chain_id != chain.alias {
        return Err(Error::Chain(format!(
            "the binding is for {}, the chain event for {}",
            b.binding.chain_id, chain.alias
        )));
    }
    if let Some(g) = chain.chain.get("genesisHash").and_then(Value::as_str) {
        if !g.eq_ignore_ascii_case(&b.binding.genesis_hash) {
            return Err(Error::Chain(format!(
                "the binding pins genesis {}, the chain document {g}",
                b.binding.genesis_hash
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
/// the alias, as an index; content the JSON. Unchanged since 0.5.0; a chain
/// with a chain event uses [`domain_event_on`].
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
/// (the agentbox registry, amended 2026-10-02: 38420–38425 carry the chain
/// hash, never the alias): `chain` = the chain hash, `alias` = the alias
/// the content names; content the same JSON as [`domain_event`]'s. The
/// content stays authoritative for the alias, the tag is the only place the
/// hash appears.
///
/// ```
/// use sidestr_nostr::estate::{domain_event_on, parse_domain_event_of, ChainTombstoned, DomainEvent, Urn};
///
/// let e = DomainEvent::ChainTombstoned(ChainTombstoned {
///     chain: Urn::parse("urn:agentbox:chain:poker:0123456789ab").unwrap(),
///     chain_id: "sidestr:poker".into(),
///     height: 500,
///     hash: "dd".repeat(32),
///     parent_txid: "ee".repeat(32),
/// });
/// let ev = domain_event_on(&e, &"9f".repeat(32), 1).unwrap();
/// assert_eq!(ev.tags, vec![vec!["chain".to_string(), "9f".repeat(32)], vec!["alias".into(), "sidestr:poker".into()]]);
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

/// Sign a domain event in the legacy form with the estate's publishing key
/// for the chain plane.
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
    /// The chain hash its `chain` tag carries; `None` in the legacy form,
    /// where the tag is the alias.
    pub chain_hash: Option<String>,
}

impl ParsedDomainEvent {
    /// Whether the event names its chain by alias only.
    pub fn legacy(&self) -> bool {
        self.chain_hash.is_none()
    }
}

/// Decode any of 38421–38425. Any other kind is [`Error::Kind`] against
/// 38421. Does not verify the signature. [`parse_domain_event_of`] also
/// returns the chain hash.
pub fn parse_domain_event(ev: &Event) -> Result<DomainEvent> {
    parse_domain_event_of(ev).map(|p| p.event)
}

/// Decode any of 38421–38425 in either form. A `chain` tag of 64 hex is the
/// chain hash ([`domain_event_on`]), and an `alias` tag, when present, must
/// be the content's chain id; any other `chain` tag must be the content's
/// chain id (the legacy form, read exactly as 0.5.0 read it).
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
            chain_id: "sidestr:dreamlab".into(),
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
        assert_eq!(ev.tags[2], vec!["genesis", &"4d".repeat(32)]);
        let b = parse_account_binding(&ev).unwrap();
        assert_eq!(b.genesis_hash, "4d".repeat(32));
        assert_eq!(b.chain_id, "sidestr:dreamlab");
        assert_eq!(
            parse_binding_address(&ev.tags[0][1]).unwrap().0,
            "sidestr:dreamlab"
        );
    }

    #[test]
    fn a_binding_is_signed_by_the_identity_it_names() {
        let other = SecretKeySigner::from_bytes(&[12u8; 32]).unwrap();
        assert!(matches!(
            sign_account_binding(&other, &binding(), 1),
            Err(Error::Key(_))
        ));
        // an event whose d names a DID other than its author
        let mut b = binding();
        b.did_hex = other.pubkey_hex().unwrap();
        let ev = sign_account_binding(&other, &b, 1).unwrap();
        let mut forged = ev.clone();
        forged.pubkey = identity().pubkey_hex().unwrap();
        assert!(matches!(
            parse_account_binding(&forged),
            Err(Error::Chain(_))
        ));
        let mut chain = ev.clone();
        chain.tags[1][1] = "sidestr:other".into();
        assert!(matches!(
            parse_account_binding(&chain),
            Err(Error::Disagree { tag: "chain", .. })
        ));
        let mut nog = ev.clone();
        nog.tags.pop();
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
        assert!(parse_binding_address("sidestr:x:zz").is_err());
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

    fn hash_binding(form: BindingForm) -> Event {
        sign_account_binding_as(&identity(), &binding(), &form, 1).unwrap()
    }

    #[test]
    fn binding_forms_and_their_refusals() {
        let h = "9F".repeat(32);
        let ev = hash_binding(BindingForm::Hash(h.clone()));
        // d carries the chain hash, lower case, when one is supplied
        let did = identity().pubkey_hex().unwrap();
        assert_eq!(ev.tags[0][1], format!("{}:{did}", h.to_ascii_lowercase()));
        let p = parse_binding(&ev).unwrap();
        assert_eq!(p.chain_hash(), Some("9f".repeat(32).as_str()));
        assert_eq!(p.binding.chain_id, "sidestr:dreamlab");
        assert_eq!(p.binding.genesis_hash, "4d".repeat(32));

        // the hash form: a chain tag naming another hash, a missing alias
        let mut other = ev.clone();
        other.tags[3][1] = "aa".repeat(32);
        assert!(matches!(
            parse_binding(&other),
            Err(Error::Disagree { tag: "chain", .. })
        ));
        let mut no_alias = ev.clone();
        no_alias.tags.remove(1);
        assert!(matches!(
            parse_binding(&no_alias),
            Err(Error::MissingTag("alias"))
        ));
        let mut empty_alias = ev.clone();
        empty_alias.tags[1][1] = String::new();
        assert!(matches!(
            parse_binding(&empty_alias),
            Err(Error::Tag { tag: "alias", .. })
        ));
        // a chain tag is optional in the hash form
        let mut bare = ev.clone();
        bare.tags.remove(3);
        assert_eq!(parse_binding(&bare).unwrap(), p);

        // the genesis form: d's hex must be the genesis, and it names no chain hash
        let g = hash_binding(BindingForm::Genesis);
        assert_eq!(g.tags[0][1], format!("{}:{did}", "4d".repeat(32)));
        let pg = parse_binding(&g).unwrap();
        assert_eq!(pg.form, BindingForm::Genesis);
        assert!(pg.legacy() && pg.chain_hash().is_none());
        let mut mismatch = g.clone();
        mismatch.tags[2][1] = "5e".repeat(32);
        assert!(matches!(
            parse_binding(&mismatch),
            Err(Error::Disagree { tag: "genesis", .. })
        ));
        let mut both = g.clone();
        both.tags.push(tag(TAG_CHAIN, "4d".repeat(32)));
        assert!(matches!(
            parse_binding(&both),
            Err(Error::Tag { tag: "chain", .. })
        ));

        // the alias form: an alias tag, when present, must agree
        let mut a = sign_account_binding(&identity(), &binding(), 1).unwrap();
        assert!(parse_binding(&a).unwrap().legacy());
        a.tags.push(tag(TAG_ALIAS, "sidestr:other"));
        assert!(matches!(
            parse_binding(&a),
            Err(Error::Disagree { tag: "alias", .. })
        ));

        // the estate forms refuse what buildBinding refuses
        let same = AccountBinding {
            spend_pubkey: identity().pubkey_hex().unwrap(),
            ..binding()
        };
        for form in [BindingForm::Hash(h.clone()), BindingForm::Genesis] {
            assert!(matches!(
                account_binding_event_as(&same, &form, 1),
                Err(Error::Key(_))
            ));
            let nameless = AccountBinding {
                chain_id: String::new(),
                ..binding()
            };
            assert!(matches!(
                account_binding_event_as(&nameless, &form, 1),
                Err(Error::Chain(_))
            ));
        }
        assert!(matches!(
            account_binding_event_as(&binding(), &BindingForm::Hash("ab".into()), 1),
            Err(Error::Hex { .. })
        ));
        // and only the identity key signs any form
        let other_key = SecretKeySigner::from_bytes(&[12u8; 32]).unwrap();
        assert!(matches!(
            sign_account_binding_as(&other_key, &binding(), &BindingForm::Genesis, 1),
            Err(Error::Key(_))
        ));
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
            // the alias-only form reads as before, flagged legacy
            let legacy = sign_domain_event(&s, &e, 1).unwrap();
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
