//! The chain document (SPEC 3, 5): the overlay that defines a sidestr chain
//! beside its parent, and the chain's identity.
//!
//! The document is what `siding new` writes and what every validator reads.
//! It is the chain's identity: `genesisHash` is derived from it (the genesis
//! commits to the chain's alias, the pegs, `genesisTime` and the signer's
//! witness), and a validator refuses to proceed past a block 0 that does not
//! hash to it. Changing any sealed field is a new chain, never a
//! configuration edit.
//!
//! # Two names (SPEC 3 and 11, 0.0.5)
//!
//! Since spec 0.0.5 the document is published as a Nostr event of kind 3500,
//! regular and immutable, and **its event id is the chain's hash**: the one
//! value that names this chain and no other, which a tip announcement points
//! at, a client verifies the document against, and anything that must commit
//! to a chain uses (a peg-in tweak; a nested chain's `parent`). The event's
//! author is the signer, so the published document carries no `signer`
//! field; `genesisHash` stays as a cross-check, never the identity. A
//! document cannot contain its own hash, so inside it (the genesis's `chain`
//! field) and in everything written before the hash exists (tags, the
//! `pegin:` and `pegout:` `OP_RETURN`s, a rule document's `d`) the chain is
//! named by its **alias**, `id` = `sidestr:<name>`, which is a name for
//! people and not a proof. Building, reading and resolving the event is
//! `sidestr-nostr`'s `chain` module; this type is the document either way.
//!
//! A chain made before 0.0.5 (the live `sidestr:dreamlab` among them) keeps
//! its `chain.json` with `signer` and is resolved as before until its signer
//! publishes the event; [`ChainDocument::signer`] is therefore kept, and a
//! document read back from an event has it filled from the event's author,
//! so [`ChainDocument::validate`] still checks the challenge against it.
//!
//! Every field siding reads is parsed and checked here. Fields siding does not
//! read (an operator's `depth`, `containment`, `containmentDigest`, a
//! `comment`, a peg's `parentAddress`) are carried through untouched in
//! [`ChainDocument::extra`] so a document round-trips, and none of them alter
//! the genesis.
//!
//! ```
//! use sidestr_core::document::{ChainDocument, magic_for};
//!
//! let doc = ChainDocument::from_json(r#"{
//!   "id": "sidestr:trial", "name": "trial", "parent": "tbtc4",
//!   "challenge": "512098b4e74305dac5ce76d5bee8e57a71549a27618a0e51b3bada3074fcba02325b",
//!   "powLimit": "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
//!   "addressPrefix": "trl", "magic": "a8f6706f", "genesisTime": 1790076612, "pegs": [],
//!   "signer": "98b4e74305dac5ce76d5bee8e57a71549a27618a0e51b3bada3074fcba02325b",
//!   "depth": 0
//! }"#).unwrap();
//! assert_eq!(doc.parent().unwrap().alias, "tbtc4");
//! assert_eq!(doc.peg_confirmations, 6);           // the SPEC default
//! assert_eq!(magic_for("trial"), "a8f6706f");     // what `siding new` derived
//! assert_eq!(doc.extra["depth"], 0);              // an estate field, carried through
//! ```

use std::collections::BTreeMap;

use bitcoin::{CompactTarget, ScriptBuf, Target};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::federation::Federation;
use crate::parents::{resolve_parent, Family, Parent};

/// One optional consensus rule named by a chain document.
///
/// The wire form is either the original string (`"assets"`) or an object
/// (`{"name":"markets","from":120}`) when a running chain adopts a rule
/// from a particular height.  The object form is preserved when the document
/// is serialised again, including when `from` is zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RuleEntry {
    /// A rule active from genesis.
    Name(String),
    /// A rule adopted from `from` (inclusive).
    Activated {
        /// The rule's registered name.
        name: String,
        /// The first height at which the rule applies.
        #[serde(default)]
        from: u32,
    },
}

impl RuleEntry {
    /// The registered rule name.
    pub fn name(&self) -> &str {
        match self {
            Self::Name(name) | Self::Activated { name, .. } => name,
        }
    }

    /// The first height at which the rule applies; string entries start at
    /// genesis.
    pub fn from(&self) -> u32 {
        match self {
            Self::Name(_) => 0,
            Self::Activated { from, .. } => *from,
        }
    }
}

impl From<&str> for RuleEntry {
    fn from(value: &str) -> Self {
        Self::Name(value.to_owned())
    }
}

impl From<String> for RuleEntry {
    fn from(value: String) -> Self {
        Self::Name(value)
    }
}

impl PartialEq<str> for RuleEntry {
    fn eq(&self, other: &str) -> bool {
        self.name() == other
    }
}

impl PartialEq<&str> for RuleEntry {
    fn eq(&self, other: &&str) -> bool {
        self.name() == *other
    }
}

impl core::fmt::Display for RuleEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// A peg output the chain starts from (SPEC 5): the genesis coinbase pays
/// `script` exactly `amount`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peg {
    /// Parent txid of the peg output, display order.
    pub txid: String,
    /// Output index on the parent.
    pub vout: u32,
    /// Amount in sats.
    pub amount: u64,
    /// The sidechain output script (hex) the coins appear on.
    pub script: String,
    /// Anything else the document says about the peg (`parentAddress`, …).
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// The chain document (SPEC 3). Field names are the wire names.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainDocument {
    /// The chain's alias, `sidestr:<name>`: what tags, `OP_RETURN`s, rule
    /// documents and the genesis name the chain by. Not its identity, which
    /// is the chain's hash, the id of the document's kind-3500 event (SPEC
    /// 0.0.5).
    pub id: String,
    /// The short name, the alias without `sidestr:` (SPEC 3, 0.0.5: "a short
    /// alias for people and tags; not an identity"); the key file and state
    /// directory are named after it.
    pub name: String,
    /// The parent: a SPEC 3.2 alias or an accepted long id. SPEC 0.0.5 lets
    /// a nested chain name a sidestr chain's hash here; no parents table
    /// (here or upstream's `parents.mjs`) resolves one yet, so such a
    /// document is refused as [`Error::UnknownParent`].
    pub parent: String,
    /// The challenge script (hex); a block is valid when its witness satisfies it.
    pub challenge: String,
    /// The proof-of-work limit as 64 hex characters; no retarget.
    pub pow_limit: String,
    /// The bech32m prefix, distinct from the parent's.
    pub address_prefix: String,
    /// The network magic `siding new` derives from the name; absent on the very first chains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic: Option<String>,
    /// Parent confirmations before a peg-in may be claimed.
    #[serde(default = "default_peg_confirmations")]
    pub peg_confirmations: u32,
    /// The relative timelock on every peg output's refund path.
    #[serde(default = "default_refund_blocks")]
    pub refund_blocks: u32,
    /// Parent blocks within which a burn must be paid.
    #[serde(default = "default_pegout_blocks")]
    pub pegout_blocks: u32,
    /// The least a burn may carry, in sats.
    #[serde(default = "default_pegout_min")]
    pub pegout_min: u64,
    /// Producer policy, published so a wallet can compute it: sat/vB.
    #[serde(default = "default_min_fee_rate")]
    pub min_fee_rate: u64,
    /// The genesis block's time.
    pub genesis_time: u32,
    /// The peg outputs the chain starts from.
    #[serde(default)]
    pub pegs: Vec<Peg>,
    /// The signer's x-only public key (level 1). A document published as a
    /// chain event (SPEC 0.0.5) carries none, its event's author being the
    /// signer; read back from the event, it is filled from that author. A
    /// `chain.json` made before 0.0.5 carries it, and that is how such a
    /// chain is still resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// The genesis hash, set once the genesis is sealed: a cross-check, not
    /// the chain's identity (SPEC 5, 0.0.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_hash: Option<String>,
    /// Rules the chain names beyond the core (`assets`, `pool`, `markets`,
    /// `evm`), optionally with an activation height; a validator must carry
    /// every one ([`ChainDocument::validate_with`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<RuleEntry>>,
    /// Level 2: the signers' x-only public keys, in leaf order. With
    /// `threshold`, they derive the challenge ([`Federation::for_document`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signers: Option<Vec<String>>,
    /// Level 2: how many signers a block needs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<u32>,
    /// Everything else, carried through untouched.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

fn default_peg_confirmations() -> u32 {
    6
}
fn default_refund_blocks() -> u32 {
    10_000
}
fn default_pegout_blocks() -> u32 {
    144
}
fn default_pegout_min() -> u64 {
    10_000
}
fn default_min_fee_rate() -> u64 {
    1
}

/// The network magic `siding new` derives from a chain name
/// (`siding/bin/siding.mjs`): a 32-bit polynomial hash of `sidestr:<name>`,
/// seed 7, multiplier 31, as eight hex characters.
pub fn magic_for(name: &str) -> String {
    let h = format!("sidestr:{name}")
        .bytes()
        .fold(7u32, |h, b| h.wrapping_mul(31).wrapping_add(u32::from(b)));
    format!("{h:08x}")
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

impl ChainDocument {
    /// Parse and validate a document from its JSON text.
    pub fn from_json(text: &str) -> Result<Self> {
        Self::from_json_with(text, &[])
    }

    /// [`ChainDocument::from_json`] for a validator that carries the rules
    /// named in `carried` ([`ChainDocument::validate_with`]).
    pub fn from_json_with(text: &str, carried: &[&str]) -> Result<Self> {
        let doc: Self = serde_json::from_str(text)?;
        doc.validate_with(carried)?;
        Ok(doc)
    }

    /// The document as JSON, one-space indented as `siding new` writes it.
    pub fn to_json(&self) -> Result<String> {
        let mut out = Vec::new();
        let fmt = serde_json::ser::PrettyFormatter::with_indent(b" ");
        let mut ser = serde_json::Serializer::with_formatter(&mut out, fmt);
        self.serialize(&mut ser)?;
        let mut s = String::from_utf8(out).map_err(|e| Error::Encoding(e.to_string()))?;
        s.push('\n');
        Ok(s)
    }

    /// Check every field this validator reads. A document naming a rule or a
    /// level this crate does not carry is refused here, as `loadEngine` refuses
    /// it, so a validator never runs a chain it would misjudge. The parent's
    /// header family is not judged here: both families are carried, and a
    /// state instantiated for the other one refuses the document itself.
    ///
    /// The core rules are all this crate carries, so a document naming any
    /// rule is refused; [`ChainDocument::validate_with`] is the same check
    /// for a validator that carries further rules.
    pub fn validate(&self) -> Result<()> {
        self.validate_with(&[])
    }

    /// [`ChainDocument::validate`] for a validator that carries the rules
    /// named in `carried` beside the core (`["assets", "evm"]` with
    /// `sidestr-evm`): every rule the document names must be one of them
    /// (`siding/lib/overlays/index.mjs rulesFor`), and the pool rule needs the
    /// assets rule. A state built with rules
    /// ([`crate::state::StateOf::from_genesis_with_rules`]) checks its
    /// document this way with the names its rules answer to
    /// ([`crate::rules::BlockRule::name`]).
    ///
    /// ```
    /// use sidestr_core::document::ChainDocument;
    ///
    /// let mut doc: serde_json::Value = serde_json::from_str(include_str!("../fixtures/trial/chain.json")).unwrap();
    /// doc["rules"] = serde_json::json!(["evm"]);
    /// let doc: ChainDocument = serde_json::from_value(doc).unwrap();
    /// assert!(doc.validate().unwrap_err().to_string().contains("does not have"));
    /// assert!(doc.validate_with(&["assets", "evm"]).is_ok());
    /// ```
    pub fn validate_with(&self, carried: &[&str]) -> Result<()> {
        let bad = |m: String| Err(Error::Document(m));
        self.parent()?;
        if self.id.is_empty() || self.name.is_empty() {
            return bad("id and name are required".into());
        }
        if self.challenge.len() < 2
            || self.challenge.len() % 2 != 0
            || !is_hex(&self.challenge, self.challenge.len())
        {
            return bad("challenge must be a non-empty hex script".into());
        }
        if !is_hex(&self.pow_limit, 64) {
            return bad("powLimit must be 64 hex characters".into());
        }
        if self.address_prefix.is_empty()
            || self.address_prefix.len() > 8
            || !self.address_prefix.bytes().all(|b| b.is_ascii_lowercase())
        {
            return bad("addressPrefix is 1 to 8 lower-case letters".into());
        }
        if let Some(m) = &self.magic {
            if !is_hex(m, 8) {
                return bad("magic must be 8 hex characters".into());
            }
        }
        if let Some(h) = &self.genesis_hash {
            if !is_hex(h, 64) {
                return bad("genesisHash must be 64 hex characters".into());
            }
        }
        for (i, p) in self.pegs.iter().enumerate() {
            if !is_hex(&p.txid, 64)
                || p.script.is_empty()
                || p.script.len() % 2 != 0
                || !is_hex(&p.script, p.script.len())
            {
                return bad(format!(
                    "peg {i}: txid must be 64 hex characters and script a hex script"
                ));
            }
        }
        if let Some(s) = &self.signer {
            if !is_hex(s, 64) {
                return bad("signer must be a 64-hex x-only public key".into());
            }
            let c = self.challenge.to_ascii_lowercase();
            if c.starts_with("5120") && c.len() == 68 && c[4..] != s.to_ascii_lowercase() {
                return bad("signer is not the key the challenge names".into());
            }
        }
        if let Some(rules) = &self.rules {
            if let Some(r) = rules
                .iter()
                .find(|r| !r.name().is_empty() && !carried.contains(&r.name()))
            {
                return bad(if carried.is_empty() {
                    format!("chain {} names rule \"{r}\", which this validator does not have (sidestr-core carries the core rules only)", self.id)
                } else {
                    format!(
                        "chain {} names rule \"{r}\", which this validator does not have (it carries {})",
                        self.id,
                        carried.join(", ")
                    )
                });
            }
            if rules.iter().any(|r| r == "pool") && !rules.iter().any(|r| r == "assets") {
                return bad("the pool rule needs the assets rule".into());
            }
            if rules.iter().any(|r| r == "markets") && !rules.iter().any(|r| r == "assets") {
                return bad("the markets rule needs the assets rule".into());
            }
        }
        // level 2: the challenge is named only through signers and threshold (overlay.mjs checkFederation)
        Federation::for_document(self)?;
        Ok(())
    }

    /// The parent's table row.
    pub fn parent(&self) -> Result<&'static Parent> {
        resolve_parent(&self.parent)
    }

    /// The header family the chain inherits.
    pub fn family(&self) -> Result<Family> {
        Ok(self.parent()?.family)
    }

    /// The challenge as a script.
    pub fn challenge_script(&self) -> Result<ScriptBuf> {
        Ok(ScriptBuf::from_bytes(
            hex::decode(&self.challenge).map_err(|e| Error::Encoding(e.to_string()))?,
        ))
    }

    /// The script an EVM deposit pays (the `evm` rule, proposals/evm.md):
    /// the document's `evm.reserve`, else the challenge, as
    /// `siding/lib/overlays/evm.mjs` reads it
    /// (`(cfg.reserve ?? chain.challenge)`). An `evm` section that is not an
    /// object, or a `reserve` that is not a hex string, is
    /// [`Error::Document`]. The document need not name the rule for this to
    /// answer; whether a chain credits deposits is [`ChainDocument::rules`].
    ///
    /// ```
    /// use sidestr_core::document::ChainDocument;
    ///
    /// let mut doc: serde_json::Value = serde_json::from_str(include_str!("../fixtures/trial/chain.json")).unwrap();
    /// let challenge = doc["challenge"].as_str().unwrap().to_string();
    /// let read = |v: &serde_json::Value| serde_json::from_value::<ChainDocument>(v.clone()).unwrap().evm_reserve();
    /// assert_eq!(read(&doc).unwrap().to_hex_string(), challenge);
    /// doc["evm"] = serde_json::json!({ "chainId": 777, "reserve": "5120ABCD" });
    /// assert_eq!(read(&doc).unwrap().to_hex_string(), "5120abcd");
    /// doc["evm"] = serde_json::json!({ "reserve": 5 });
    /// assert!(read(&doc).is_err());
    /// ```
    pub fn evm_reserve(&self) -> Result<ScriptBuf> {
        let reserve = match self.extra.get("evm") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::Object(m)) => m.get("reserve").filter(|v| !v.is_null()),
            Some(v) => return Err(Error::Document(format!("evm must be an object, not {v}"))),
        };
        match reserve {
            None => self.challenge_script(),
            Some(serde_json::Value::String(h)) => hex::decode(h)
                .map(ScriptBuf::from_bytes)
                .map_err(|e| Error::Document(format!("evm.reserve is not a hex script: {e}"))),
            Some(v) => Err(Error::Document(format!(
                "evm.reserve must be a hex script, not {v}"
            ))),
        }
    }

    /// `powLimit` as a 256-bit target.
    pub fn pow_limit_target(&self) -> Result<Target> {
        let bytes: [u8; 32] = hex::decode(&self.pow_limit)
            .map_err(|e| Error::Encoding(e.to_string()))?
            .try_into()
            .map_err(|_| Error::Document("powLimit must be 32 bytes".into()))?;
        Ok(Target::from_be_bytes(bytes))
    }

    /// The compact `bits` every block carries: `powLimit` encoded as Bitcoin
    /// Core's `GetCompact` does (`siding/lib/chain.mjs` sets it once per chain).
    pub fn bits(&self) -> Result<CompactTarget> {
        Ok(self.pow_limit_target()?.to_compact_lossy())
    }

    /// The magic the name derives to, whether or not the document carries it.
    pub fn derived_magic(&self) -> String {
        magic_for(&self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRIAL: &str = include_str!("../fixtures/trial/chain.json");
    const DREAMLAB: &str = include_str!("../fixtures/dreamlab/chain.json");

    #[test]
    fn fixtures_parse_and_round_trip() {
        for (text, name, magic) in [
            (TRIAL, "trial", "a8f6706f"),
            (DREAMLAB, "dreamlab", "d981eab1"),
        ] {
            let doc = ChainDocument::from_json(text).unwrap();
            assert_eq!(doc.name, name);
            assert_eq!(doc.magic.as_deref(), Some(magic));
            assert_eq!(doc.derived_magic(), magic);
            assert_eq!(doc.bits().unwrap().to_consensus(), 0x207f_ffff);
            let again: serde_json::Value = serde_json::from_str(&doc.to_json().unwrap()).unwrap();
            assert_eq!(
                again,
                serde_json::from_str::<serde_json::Value>(text).unwrap()
            );
        }
        let d = ChainDocument::from_json(DREAMLAB).unwrap();
        assert_eq!(d.extra["containment"]["parent"], "tbtc4");
    }

    #[test]
    fn refusals() {
        let base: serde_json::Value = serde_json::from_str(TRIAL).unwrap();
        let with = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut v = base.clone();
            f(&mut v);
            ChainDocument::from_json(&v.to_string())
        };
        // siding/test/rules-test.mjs: a document naming a rule this validator lacks is refused
        let e = with(&|v| v["rules"] = serde_json::json!(["assets", "oracle"]))
            .unwrap_err()
            .to_string();
        assert!(e.contains("does not have"), "{e}");
        // a validator carrying further rules accepts exactly the names it carries
        let named = |rules: serde_json::Value| {
            let mut v = base.clone();
            v["rules"] = rules;
            serde_json::from_value::<ChainDocument>(v).unwrap()
        };
        assert!(named(serde_json::json!(["evm"]))
            .validate_with(&["assets", "evm"])
            .is_ok());
        assert!(named(serde_json::json!(["assets", "evm"]))
            .validate_with(&["assets", "evm"])
            .is_ok());
        for (rules, want) in [
            (
                serde_json::json!(["evm", "pool"]),
                "\"pool\", which this validator does not have (it carries assets, evm)",
            ),
            (serde_json::json!(["desk"]), "\"desk\""),
            (serde_json::json!(["evm"]), "carries the core rules only"),
        ] {
            let carried: &[&str] = if want.contains("core rules") {
                &[]
            } else {
                &["assets", "evm"]
            };
            let e = named(rules).validate_with(carried).unwrap_err().to_string();
            assert!(e.contains(want), "{e}");
        }
        assert!(named(serde_json::json!(["pool"]))
            .validate_with(&["pool"])
            .unwrap_err()
            .to_string()
            .contains("needs the assets rule"));
        // a BLAKE2b parent is a valid document; which family a validator carries is the state's concern
        assert_eq!(
            with(&|v| v["parent"] = "txbt4".into())
                .unwrap()
                .family()
                .unwrap(),
            Family::Blake2b
        );
        assert!(matches!(
            with(&|v| v["parent"] = "doge".into()),
            Err(Error::UnknownParent(_))
        ));
        assert!(with(&|v| v["signers"] = serde_json::json!(["aa"])).is_err());
        assert!(with(&|v| {
            v["signers"] = serde_json::json!(["aa".repeat(32)]);
            v["threshold"] = serde_json::json!(1);
        })
        .unwrap_err()
        .to_string()
        .contains("is not the one 1 signers"));
        assert!(with(&|v| v["signer"] = serde_json::json!("00".repeat(32))).is_err());
        assert!(with(&|v| v["powLimit"] = serde_json::json!("ff")).is_err());
        assert!(with(&|v| v["addressPrefix"] = serde_json::json!("TRL")).is_err());
        assert!(with(&|v| v["genesisHash"] = serde_json::json!("zz")).is_err());
    }
}
