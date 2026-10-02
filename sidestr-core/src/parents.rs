//! The parents a chain can sit beside (SPEC 3.2): a short alias per chain,
//! the long kernel id it resolves to, and the header family the chain inherits.
//!
//! A port of `siding/lib/parents.mjs`. Old spellings (the kernel's long ids
//! such as `btc:testnet4-blake2b`) stay accepted, so no running chain's
//! document changes. `mainnet` picks the key and address encodings a node
//! expects (WIF `0x80` vs `0xef`).
//!
//! The alias resolves to the block that fixes which chain is meant: the
//! genesis, and for a fork, the first block on the fork's side, since a fork
//! shares its origin's genesis. A validator that does not know an alias
//! refuses the chain by name.
//!
//! ```
//! use sidestr_core::parents::{resolve_parent, parent_alias, Family};
//!
//! let p = resolve_parent("btc:testnet4").unwrap();
//! assert_eq!(p.alias, "tbtc4");
//! assert_eq!(p.family, Family::Stock);
//! assert_eq!(parent_alias("doge"), None);
//! assert!(resolve_parent("ltc").is_err()); // reserved until a validator carries it
//! ```
//!
//! # A sidestr chain as a parent (SPEC 3, 3.1): a departure
//!
//! SPEC 0.0.5 lets a nested chain's `parent` be a sidestr chain's **hash**,
//! the id of its kind-3500 chain event, and says the child inherits the
//! siding's rules as the siding inherits its parent's. The reference does
//! not carry that yet: `parents.mjs` at `e8deb63` knows the table alone, and
//! `resolveParent` throws "unknown parent" for a hash. [`resolve_parent`]
//! keeps that behaviour exactly, so a validator built on it judges every
//! document as siding does.
//!
//! [`resolve_parent_with`] is this port's addition, recorded as a departure
//! under ADR-0001 D4 and tested as one (`tests/nested_parent.rs` runs
//! `parents.mjs` on the same input and holds it to its refusal): given a
//! hash, it asks the caller for the parent chain's document (which the caller
//! reads from the chain event whose id is that hash, as `sidestr-nostr`'s
//! `chain::resolve_nested_parent` does), and follows `parent` down until it
//! reaches a row of the table. The header family, the proof of work and the
//! key encodings are the root's ([`ParentRef`]); nothing in a document names
//! them. It follows the SPEC's prose, which no executable reference pins yet:
//! when upstream's `parents.mjs` learns hashes, this is held to it.
//!
//! ```
//! use sidestr_core::document::ChainDocument;
//! use sidestr_core::parents::{resolve_parent, resolve_parent_with, Family, ParentRef};
//!
//! // a siding beside txbt4, published as a chain event whose id is `hash`
//! let siding = ChainDocument::from_json(include_str!("../fixtures/trial/chain.json")).unwrap();
//! let siding = ChainDocument { parent: "txbt4".into(), ..siding };
//! let hash = "5d".repeat(32);
//!
//! assert!(resolve_parent(&hash).is_err()); // the reference's answer, unchanged
//! let p = resolve_parent_with(&hash, |h| {
//!     assert_eq!(h, hash);
//!     Ok(siding.clone())
//! })
//! .unwrap();
//! assert_eq!(p.family(), Family::Blake2b); // inherited from txbt4 through the siding
//! assert_eq!(p.depth(), 1);
//! assert!(matches!(p, ParentRef::Chain(ref n) if n.alias == siding.id));
//! ```

use crate::document::ChainDocument;
use crate::error::{Error, Result};

/// The header family a chain inherits from its parent (SPEC 3): nothing in
/// the document names a header format or a hash; the parent decides both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// The stock 80-byte Bitcoin header, hashed with SHA256d.
    Stock,
    /// Knots' 164-byte v2 header with BLAKE2b proof of work (`sidestr-header`).
    Blake2b,
}

/// The proof-of-work hash the parent uses; informational for the reserved
/// parents, load-bearing for the two families this table carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pow {
    /// Double SHA-256 (Bitcoin).
    Sha256d,
    /// BLAKE2b over the v2 header (Knots).
    Blake2b,
    /// scrypt (Litecoin; reserved).
    Scrypt,
    /// verthash (Vertcoin; reserved).
    Verthash,
}

/// The block that fixes a fork's identity: the first block on the fork's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fork {
    /// Height of the fork block.
    pub height: u32,
    /// Display-order hash of the fork block.
    pub hash: &'static str,
}

/// One row of the SPEC 3.2 table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parent {
    /// The short alias new documents use.
    pub alias: &'static str,
    /// The kernel's long network id, accepted as an old spelling; `None` when reserved.
    pub network: Option<&'static str>,
    /// Human label.
    pub label: &'static str,
    /// Header family the chain inherits.
    pub family: Family,
    /// The parent's proof-of-work hash.
    pub pow: Pow,
    /// Whether keys and addresses use mainnet encodings.
    pub mainnet: bool,
    /// The parent's genesis hash, display order; `None` when reserved.
    pub genesis: Option<&'static str>,
    /// The fork block, for a fork of another chain in the table.
    pub fork: Option<Fork>,
    /// Reserved: in the table so the name is taken, refused until a validator carries its rules.
    pub reserved: bool,
}

/// Bitcoin's coinbase maturity: a mined coin is spendable at 100
/// confirmations. Every parent but `txbt4` asks this, and so does every
/// sidestr chain for its own coinbases ([`crate::rules::Params`]).
pub const COINBASE_MATURITY: u32 = 100;

/// The coinbase maturity a `txbt4` (BLAKE2b testnet4) node asks since Knots
/// 29.4.2: 6,705 confirmations (bitcoin-blake/reef `2bd3cb8`,
/// `lib/wallet.mjs COINBASE_MATURITY`).
pub const TXBT4_COINBASE_MATURITY: u32 = 6_705;

impl Parent {
    /// How deep a coin mined on this **parent** must be before a payment
    /// spending it leaves: [`TXBT4_COINBASE_MATURITY`] beside `txbt4`,
    /// [`COINBASE_MATURITY`] elsewhere.
    ///
    /// Why `txbt4` differs (Reef `2bd3cb8`): by consensus a reward mined at
    /// 151,406 or later needs 6,705 confirmations in blocks 151,550 to
    /// 158,110 (100 before and after, and for older rewards), but the mempool
    /// of every node upgraded to Knots 29.4.2 asks 6,705 of **every** reward,
    /// whatever its height, so a payment spending a younger one is refused
    /// (`bad-txns-premature-spend-of-coinbase`) by the node that relays it
    /// and never leaves. A wallet counts what lets a payment leave. Reef
    /// speaks only of testnet4; `xbt` keeps Bitcoin's 100 until a Knots
    /// release says otherwise for mainnet.
    ///
    /// This is a fact about parent coins, for whatever reports or selects
    /// them. It is not the sidechain's own maturity, which stays 100
    /// ([`crate::rules::Params::coinbase_maturity`]).
    ///
    /// ```
    /// use sidestr_core::parents::resolve_parent;
    /// assert_eq!(resolve_parent("txbt4").unwrap().coinbase_maturity(), 6_705);
    /// assert_eq!(resolve_parent("tbtc4").unwrap().coinbase_maturity(), 100);
    /// ```
    pub const fn coinbase_maturity(&self) -> u32 {
        if matches!(self.family, Family::Blake2b) && !self.mainnet {
            TXBT4_COINBASE_MATURITY
        } else {
            COINBASE_MATURITY
        }
    }

    /// Whether a coin on this parent, mined (or confirmed) at `coin_height`,
    /// is spendable with the parent's tip at `tip`: not a coinbase, or at
    /// least [`Self::coinbase_maturity`] confirmations deep, counting its own
    /// block (`tip − coin_height + 1`; Reef `isMature`).
    ///
    /// ```
    /// use sidestr_core::parents::resolve_parent;
    /// let txbt4 = resolve_parent("txbt4").unwrap();
    /// // the reward of block 152,079: refused at 152,201 (123 deep), spendable at 158,783
    /// assert!(!txbt4.is_mature(152_079, true, 152_201));
    /// assert!(txbt4.is_mature(152_079, true, 158_783));
    /// assert!(txbt4.is_mature(152_079, false, 152_079));
    /// ```
    pub const fn is_mature(&self, coin_height: u32, coinbase: bool, tip: u32) -> bool {
        !coinbase || (tip >= coin_height && tip - coin_height + 1 >= self.coinbase_maturity())
    }
}

/// The table itself (SPEC 3.2), in the order the spec lists it.
pub const PARENTS: [Parent; 6] = [
    Parent {
        alias: "btc",
        network: Some("btc:mainnet"),
        label: "Bitcoin mainnet",
        family: Family::Stock,
        pow: Pow::Sha256d,
        mainnet: true,
        genesis: Some("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
        fork: None,
        reserved: false,
    },
    Parent {
        alias: "tbtc4",
        network: Some("btc:testnet4"),
        label: "Bitcoin testnet4",
        family: Family::Stock,
        pow: Pow::Sha256d,
        mainnet: false,
        genesis: Some("00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"),
        fork: None,
        reserved: false,
    },
    Parent {
        alias: "xbt",
        network: Some("btc:mainnet-blake2b"),
        label: "BLAKE2b mainnet (Knots)",
        family: Family::Blake2b,
        pow: Pow::Blake2b,
        mainnet: true,
        genesis: Some("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
        fork: Some(Fork {
            height: 961_640,
            hash: "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb",
        }),
        reserved: false,
    },
    Parent {
        alias: "txbt4",
        network: Some("btc:testnet4-blake2b"),
        label: "BLAKE2b testnet4 (Knots)",
        family: Family::Blake2b,
        pow: Pow::Blake2b,
        mainnet: false,
        genesis: Some("00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"),
        fork: Some(Fork {
            height: 150_308,
            hash: "000000000000b9d1b7e1bb0e77215ee92c6ef7ec8f4473e23908380649e779b6",
        }),
        reserved: false,
    },
    Parent {
        alias: "ltc",
        network: None,
        label: "Litecoin mainnet",
        family: Family::Stock,
        pow: Pow::Scrypt,
        mainnet: true,
        genesis: None,
        fork: None,
        reserved: true,
    },
    Parent {
        alias: "vtc",
        network: None,
        label: "Vertcoin mainnet",
        family: Family::Stock,
        pow: Pow::Verthash,
        mainnet: true,
        genesis: None,
        fork: None,
        reserved: true,
    },
];

/// Alias or long id → the alias; `None` when neither (`siding/lib/parents.mjs parentAlias`).
pub fn parent_alias(id: &str) -> Option<&'static str> {
    PARENTS
        .iter()
        .find(|p| p.alias == id || p.network == Some(id))
        .map(|p| p.alias)
}

/// Alias or long id → the table row; an error for a reserved or unknown parent
/// (`siding/lib/parents.mjs resolveParent`).
pub fn resolve_parent(id: &str) -> Result<&'static Parent> {
    let alias = parent_alias(id).ok_or_else(|| Error::UnknownParent(id.to_string()))?;
    let p = PARENTS
        .iter()
        .find(|p| p.alias == alias)
        .expect("alias came from the table");
    if p.reserved {
        return Err(Error::ReservedParent {
            alias: p.alias,
            label: p.label,
        });
    }
    Ok(p)
}

/// Whether the parent hands down the BLAKE2b header family.
pub fn is_blake2b(id: &str) -> Result<bool> {
    Ok(resolve_parent(id)?.family == Family::Blake2b)
}

/// How many sidestr chains [`resolve_parent_with`] follows from a child to
/// the proof-of-work root before it gives up. SPEC 3.1 sets no bound, but
/// trust compounds with depth ("a reason to keep value near the root"), and
/// a lookup that never reaches a table row must not loop.
pub const MAX_NESTING: u32 = 16;

/// Whether `id` names a sidestr chain by its hash: 64 hex characters, either
/// case, as `announce.mjs` reads a chain hash (`/^[0-9a-f]{64}$/i`). No row
/// of the table is spelt so, so the two forms never collide.
///
/// ```
/// use sidestr_core::parents::is_chain_hash_parent;
/// assert!(is_chain_hash_parent(&"ab".repeat(32)));
/// assert!(!is_chain_hash_parent("txbt4") && !is_chain_hash_parent(&"ab".repeat(31)));
/// ```
pub fn is_chain_hash_parent(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A parent that is itself a sidestr chain (SPEC 3.1), resolved down to the
/// row of the table its family comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedParent {
    /// The parent chain's hash, lower-case hex: the id of its chain event.
    pub hash: String,
    /// The parent chain's alias, its document's `id` (a name, not a proof).
    pub alias: String,
    /// The hashes followed, from the parent outwards to the chain that sits
    /// beside [`NestedParent::root`]; `path[0] == hash`.
    pub path: Vec<String>,
    /// The table row at the bottom: the proof-of-work chain whose header
    /// family, proof of work and key encodings every level inherits.
    pub root: &'static Parent,
}

/// What a document's `parent` names: a row of the table, or a sidestr chain
/// by its hash. [`resolve_parent`] gives only the first; [`resolve_parent_with`]
/// both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentRef {
    /// A row of the SPEC 3.2 table (an alias or an accepted long id).
    Table(&'static Parent),
    /// A sidestr chain, named by its chain event's id (SPEC 3, 3.1). A
    /// departure from the reference at `e8deb63`, which refuses it.
    Chain(NestedParent),
}

impl ParentRef {
    /// The proof-of-work chain at the bottom: the row itself, or the row a
    /// nested parent resolved to.
    pub fn root(&self) -> &'static Parent {
        match self {
            ParentRef::Table(p) => p,
            ParentRef::Chain(n) => n.root,
        }
    }

    /// The header family the chain inherits: always the root's (SPEC 3:
    /// "the parent decides both", and a siding decides as its parent did).
    pub fn family(&self) -> Family {
        self.root().family
    }

    /// The proof of work of the root.
    pub fn pow(&self) -> Pow {
        self.root().pow
    }

    /// Whether keys and addresses use mainnet encodings: the root's.
    pub fn mainnet(&self) -> bool {
        self.root().mainnet
    }

    /// The chain's depth as the estate's documents count it: 0 beside a row
    /// of the table, 1 beside a siding that sits beside one, and so on (the
    /// number of sidestr chains whose signers a validator of this chain
    /// trusts besides its own, SPEC 3.1).
    pub fn depth(&self) -> u32 {
        match self {
            ParentRef::Table(_) => 0,
            ParentRef::Chain(n) => n.path.len() as u32,
        }
    }

    /// The parent chain's hash, for a nested parent.
    pub fn chain_hash(&self) -> Option<&str> {
        match self {
            ParentRef::Table(_) => None,
            ParentRef::Chain(n) => Some(&n.hash),
        }
    }

    /// How deep a coin mined on the **parent** must be before it may be
    /// spent: the table's answer for a row ([`Parent::coinbase_maturity`]),
    /// and for a sidestr parent that chain's own coinbase rule,
    /// [`COINBASE_MATURITY`] ([`crate::rules::Params::coinbase_maturity`]).
    pub fn coinbase_maturity(&self) -> u32 {
        match self {
            ParentRef::Table(p) => p.coinbase_maturity(),
            ParentRef::Chain(_) => COINBASE_MATURITY,
        }
    }
}

/// [`resolve_parent`], and a sidestr chain's hash besides (SPEC 3, 3.1).
///
/// An alias or long id resolves through the table exactly as
/// [`resolve_parent`] resolves it, and `lookup` is never called. A 64-hex
/// hash ([`is_chain_hash_parent`]) is handed, lower-cased, to `lookup`, which
/// answers with that chain's document; the caller is trusted to have read it
/// from the chain event **whose id is the hash** and to have verified that
/// event (`sidestr-nostr`'s `chain::resolve_nested_parent` does both). The
/// document's own `parent` is then followed the same way until a row of the
/// table answers, at most [`MAX_NESTING`] chains deep.
///
/// Refused: an unknown or reserved root, as [`resolve_parent`] refuses it; a
/// hash that comes round again; a chain nested deeper than [`MAX_NESTING`];
/// and whatever `lookup` refuses.
///
/// This is a departure from `siding/lib/parents.mjs` at `e8deb63`, whose
/// `resolveParent` refuses every hash (module docs; ADR-0001 D4).
pub fn resolve_parent_with<F>(id: &str, mut lookup: F) -> Result<ParentRef>
where
    F: FnMut(&str) -> Result<ChainDocument>,
{
    if !is_chain_hash_parent(id) {
        return resolve_parent(id).map(ParentRef::Table);
    }
    let hash = id.to_ascii_lowercase();
    let mut path: Vec<String> = Vec::new();
    let mut alias = None;
    let mut next = hash.clone();
    while (path.len() as u32) < MAX_NESTING {
        if path.contains(&next) {
            return Err(Error::Document(format!(
                "parent chain {next} names itself among its own parents"
            )));
        }
        let doc = lookup(&next)?;
        alias.get_or_insert_with(|| doc.id.clone());
        path.push(next);
        if !is_chain_hash_parent(&doc.parent) {
            let root = resolve_parent(&doc.parent)?;
            return Ok(ParentRef::Chain(NestedParent {
                hash,
                alias: alias.expect("set on the first document"),
                path,
                root,
            }));
        }
        next = doc.parent.to_ascii_lowercase();
    }
    Err(Error::Document(format!(
        "parent chain {hash} is nested more than {MAX_NESTING} chains deep"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    // siding/test/parents-test.mjs
    #[test]
    fn table() {
        assert_eq!(
            resolve_parent("txbt4").unwrap().network,
            Some("btc:testnet4-blake2b")
        );
        assert_eq!(
            resolve_parent("btc:testnet4-blake2b").unwrap().alias,
            "txbt4"
        );
        assert_eq!(
            resolve_parent("xbt").unwrap().network,
            Some("btc:mainnet-blake2b")
        );
        assert_eq!(resolve_parent("btc:mainnet-blake2b").unwrap().alias, "xbt");
        let by = |a: &str| PARENTS.iter().find(|p| p.alias == a).unwrap();
        assert_eq!(by("xbt").genesis, by("btc").genesis);
        assert_eq!(by("txbt4").genesis, by("tbtc4").genesis);
        assert_eq!(by("txbt4").fork.unwrap().height, 150_308);
        assert_eq!(by("xbt").fork.unwrap().height, 961_640);
        assert!(is_blake2b("txbt4").unwrap() && is_blake2b("xbt").unwrap());
        assert!(!is_blake2b("btc").unwrap() && !is_blake2b("tbtc4").unwrap());
        assert_eq!(parent_alias("xbt4"), None);
        assert!(matches!(
            resolve_parent("ltc"),
            Err(Error::ReservedParent { alias: "ltc", .. })
        ));
        let e = resolve_parent("doge").unwrap_err().to_string();
        assert!(e.contains("unknown parent \"doge\"") && e.contains("txbt4"));
        assert!(resolve_parent("xbt").unwrap().mainnet && resolve_parent("btc").unwrap().mainnet);
        assert!(
            !resolve_parent("txbt4").unwrap().mainnet
                && !resolve_parent("btc:testnet4-blake2b").unwrap().mainnet
        );
        for name in ["__proto__", "constructor", "toString", ""] {
            assert_eq!(parent_alias(name), None);
        }
    }

    fn doc_beside(parent: &str, name: &str) -> ChainDocument {
        let d = ChainDocument::from_json(include_str!("../fixtures/trial/chain.json")).unwrap();
        ChainDocument {
            id: format!("sidestr:{name}"),
            name: name.into(),
            parent: parent.into(),
            ..d
        }
    }

    // SPEC 3.1 prose; parents.mjs at e8deb63 refuses every case here (tests/nested_parent.rs)
    #[test]
    fn a_chain_hash_resolves_through_the_parent_chain_s_document() {
        let (a, b) = ("aa".repeat(32), "BB".repeat(32));
        // b sits beside txbt4; a sits beside b; the child names a
        let docs = |h: &str| -> Result<ChainDocument> {
            match h {
                x if x == "aa".repeat(32) => Ok(doc_beside(&"BB".repeat(32), "a")),
                x if x == "bb".repeat(32) => Ok(doc_beside("btc:testnet4-blake2b", "b")),
                other => Err(Error::Document(format!("no chain event {other}"))),
            }
        };
        let p = resolve_parent_with(&a, docs).unwrap();
        assert_eq!(p.family(), Family::Blake2b);
        assert_eq!(p.pow(), Pow::Blake2b);
        assert!(!p.mainnet());
        assert_eq!(p.root().alias, "txbt4");
        assert_eq!(p.depth(), 2);
        assert_eq!(p.chain_hash(), Some(a.as_str()));
        assert_eq!(p.coinbase_maturity(), COINBASE_MATURITY);
        let ParentRef::Chain(n) = &p else { panic!() };
        assert_eq!(n.alias, "sidestr:a");
        assert_eq!(n.path, vec![a.clone(), b.to_ascii_lowercase()]);
        // an upper-case hash is the same chain
        assert_eq!(resolve_parent_with(&a.to_uppercase(), docs).unwrap(), p);
        // a stock root hands down the stock family
        let stock = resolve_parent_with(&a, |_| Ok(doc_beside("tbtc4", "s"))).unwrap();
        assert_eq!(stock.family(), Family::Stock);
        assert_eq!(stock.depth(), 1);
        // a missing event is the lookup's refusal, carried through
        let e = resolve_parent_with(&"cc".repeat(32), docs).unwrap_err();
        assert!(e.to_string().contains("no chain event"), "{e}");
    }

    #[test]
    fn a_table_parent_never_asks_the_lookup_and_answers_as_resolve_parent() {
        for id in ["btc", "tbtc4", "xbt", "txbt4", "btc:testnet4-blake2b"] {
            let p = resolve_parent_with(id, |_| panic!("no lookup for {id}")).unwrap();
            assert_eq!(p, ParentRef::Table(resolve_parent(id).unwrap()));
            assert_eq!(p.depth(), 0);
            assert_eq!(p.chain_hash(), None);
            assert_eq!(
                p.coinbase_maturity(),
                resolve_parent(id).unwrap().coinbase_maturity()
            );
        }
        for id in ["ltc", "doge", "", &"ab".repeat(31)] {
            assert_eq!(
                resolve_parent_with(id, |_| panic!("no lookup"))
                    .unwrap_err()
                    .to_string(),
                resolve_parent(id).unwrap_err().to_string()
            );
        }
    }

    #[test]
    fn nesting_refuses_a_cycle_a_bad_root_and_unbounded_depth() {
        let (a, b) = ("aa".repeat(32), "bb".repeat(32));
        let cyc = resolve_parent_with(&a, |h| Ok(doc_beside(if h == a { &b } else { &a }, "c")))
            .unwrap_err();
        assert!(cyc.to_string().contains("names itself"), "{cyc}");
        let reserved = resolve_parent_with(&a, |_| Ok(doc_beside("ltc", "l"))).unwrap_err();
        assert!(matches!(
            reserved,
            Error::ReservedParent { alias: "ltc", .. }
        ));
        let unknown = resolve_parent_with(&a, |_| Ok(doc_beside("doge", "d"))).unwrap_err();
        assert!(matches!(unknown, Error::UnknownParent(_)));
        // every lookup names a fresh hash: stops at MAX_NESTING
        let mut n = 0u32;
        let deep = resolve_parent_with(&a, |_| {
            n += 1;
            Ok(doc_beside(&format!("{n:064x}"), "deep"))
        })
        .unwrap_err();
        assert!(deep.to_string().contains("more than 16"), "{deep}");
        assert_eq!(n, MAX_NESTING);
        // exactly MAX_NESTING deep is accepted
        let mut m = 0u32;
        let edge = resolve_parent_with(&a, |_| {
            m += 1;
            Ok(if m == MAX_NESTING {
                doc_beside("tbtc4", "edge")
            } else {
                doc_beside(&format!("{m:064x}"), "edge")
            })
        })
        .unwrap();
        assert_eq!(edge.depth(), MAX_NESTING);
    }

    // bitcoin-blake/reef test/wallet-test.mjs at 2bd3cb8, counted against the parent's fact
    #[test]
    fn parent_coinbase_maturity() {
        let txbt4 = resolve_parent("txbt4").unwrap();
        assert_eq!(txbt4.coinbase_maturity(), 6_705);
        // mature at exactly 6,705 confirmations, not 6,704
        assert!(txbt4.is_mature(100, true, 6_804));
        assert!(!txbt4.is_mature(100, true, 6_803));
        // the reward of block 152,079 is not spendable at 152,201 and is at 158,783
        assert!(!txbt4.is_mature(152_079, true, 152_201));
        assert!(txbt4.is_mature(152_079, true, 158_783));
        assert!(!txbt4.is_mature(152_079, true, 158_782));
        // a coin that is not a reward is spendable when confirmed; a tip below the coin is not
        assert!(txbt4.is_mature(152_079, false, 152_079));
        assert!(!txbt4.is_mature(152_079, true, 152_000));
        for alias in ["btc", "tbtc4", "xbt"] {
            let p = resolve_parent(alias).unwrap();
            assert_eq!(p.coinbase_maturity(), 100, "{alias}");
            assert!(p.is_mature(100, true, 199) && !p.is_mature(100, true, 198));
        }
        // the sidechain's own rule is untouched
        assert_eq!(crate::rules::Params::default().coinbase_maturity, 100);
    }
}
