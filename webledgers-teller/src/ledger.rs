//! The ledger: a Web Ledger document whose identity is the hash of its
//! genesis, and the three moves that change its balances, each applied once
//! (`teller.mjs newLedger`, `ledgerHash`, `checkLedger`, `balance`, `credit`,
//! `transfer`, `debit`, `total`, `jcs`).
//!
//! The genesis (operator, name, currency, created, confirmations) is fixed at
//! creation, and the ledger's hash is `sha256(JCS(genesis))`: balances move,
//! the hash does not. Amounts are integers inside and strings of digits in
//! the document, as Web Ledgers writes them. Every move takes the time from
//! the caller (`now`, Unix seconds): the crate reads no clock.
//!
//! ```
//! use webledgers_teller::ledger::{balance, check_ledger, credit, new_ledger, transfer, Credit, LedgerParams, Transfer};
//!
//! let alice = format!("did:nostr:{}", "aa".repeat(32));
//! let bob = format!("did:nostr:{}", "bb".repeat(32));
//! let mut l = new_ledger(&LedgerParams::new(&alice, "Table 7", 1_759_300_000)).unwrap();
//! check_ledger(&l).unwrap();
//!
//! let deposit = Credit { account: alice.clone(), txid: "ab".repeat(32), vout: 0, value: 50_000, height: Some(152_100) };
//! assert!(credit(&mut l, &deposit, 1_759_300_001).unwrap().applied());
//! assert!(!credit(&mut l, &deposit, 1_759_300_002).unwrap().applied()); // the outpoint is the receipt
//!
//! let t = Transfer { id: "r1".into(), from: alice.clone(), to: bob.clone(), amount: 20_000 };
//! assert!(transfer(&mut l, &t, 1_759_300_003).unwrap().applied());
//! assert_eq!((balance(&l, &alice).unwrap(), balance(&l, &bob).unwrap()), (30_000, 20_000));
//! assert_eq!(l.entries[0].amount, "30000");
//! check_ledger(&l).unwrap(); // the hash did not move
//! ```

use bitcoin::secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use sidestr_nostr::event::{Event, UnsignedEvent};

use crate::account::{account_of, check_sats, sats, x_of};
use crate::error::{Error, Result};
use crate::{CONTEXT, DEFAULT_CURRENCY, LEDGER_KIND};

/// The longest name a ledger may have, in UTF-16 code units (JavaScript's
/// `length`).
pub const MAX_NAME: usize = 80;

/// What the teller's page tags a ledger event with (`t`), beside `d` = the
/// ledger's hash.
pub const LEDGER_TOPIC: &str = "webledgers";

/// JCS (RFC 8785) for the plain JSON these documents are (`teller.mjs
/// jcs`): object keys sorted at every level by UTF-16 code units, arrays in
/// order, strings and other scalars as `JSON.stringify` writes them.
///
/// Integers are exact. A number with a fraction is outside what the teller
/// writes; it is printed as an integer when it is one below `1e21`, and
/// otherwise as `serde_json` prints it, which is not guaranteed to be
/// ECMAScript's form.
///
/// ```
/// use webledgers_teller::ledger::jcs;
///
/// let v = serde_json::json!({ "b": 1, "a": { "d": "x", "c": [2, { "f": 0, "e": null }] } });
/// assert_eq!(jcs(&v), r#"{"a":{"c":[2,{"e":null,"f":0}],"d":"x"},"b":1}"#);
/// ```
pub fn jcs(v: &Value) -> String {
    let mut out = String::new();
    write_jcs(v, &mut out);
    out
}

fn write_jcs(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("a string serialises"));
                out.push(':');
                write_jcs(&m[k], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs(x, out);
            }
            out.push(']');
        }
        Value::Number(n) if n.as_u64().is_none() && n.as_i64().is_none() => {
            let f = n.as_f64().expect("a JSON number is finite");
            if f.fract() == 0.0 && f.abs() < 1e21 {
                out.push_str(&(f as i128).to_string());
            } else {
                out.push_str(&n.to_string());
            }
        }
        other => out.push_str(&serde_json::to_string(other).expect("a scalar serialises")),
    }
}

/// A ledger's genesis: what is fixed at creation and hashed into its
/// identity. Fields another writer adds are kept in `extra`, so a ledger
/// written elsewhere hashes here as it hashes there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Genesis {
    /// The operator's account, `did:nostr:<x>`: who holds the deposits and
    /// writes the ledger.
    pub operator: String,
    /// The ledger's name, 1 to [`MAX_NAME`] characters.
    pub name: String,
    /// The chain the amounts are on (`txbt4`).
    pub currency: String,
    /// Unix seconds at creation.
    pub created: u64,
    /// How deep a deposit must be before it is credited.
    pub confirmations: u64,
    /// Fields this crate does not name, kept for the hash.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One account's balance: `{ "type": "Entry", "url": <account>, "amount": "<sats>" }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// `"Entry"`.
    pub r#type: String,
    /// The account, `did:nostr:<x>`.
    pub url: String,
    /// The balance in satoshis, as a string of digits.
    pub amount: String,
    /// Fields this crate does not name, kept.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A deposit credited: its outpoint is the receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deposit {
    /// `<txid>:<vout>`.
    pub outpoint: String,
    /// The account credited.
    pub account: String,
    /// Satoshis.
    pub value: u64,
    /// The block height it was seen at, or `null`.
    #[serde(default)]
    pub height: Option<u64>,
    /// Unix seconds when it was credited.
    pub at: u64,
}

/// A withdrawal paid out: the payout's txid is the receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payout {
    /// The request's id.
    pub id: String,
    /// The account debited.
    pub account: String,
    /// Satoshis.
    pub value: u64,
    /// Where it was paid (an address).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// The payout transaction's id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
    /// Unix seconds when it was debited.
    pub at: u64,
}

/// A Web Ledger as the teller writes it, field for field and in its order:
/// `@context`, `type`, `id`, `hash`, `name`, `defaultCurrency`, `genesis`,
/// `updated`, `entries`, `deposits`, `applied`, `payouts`. A ledger the
/// JavaScript teller wrote reads into this and serialises back to the same
/// JSON, and its genesis hashes the same.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    /// [`CONTEXT`].
    #[serde(rename = "@context")]
    pub context: String,
    /// `"WebLedger"`.
    pub r#type: String,
    /// `urn:webledgers:<hash>`.
    pub id: String,
    /// `hex(sha256(JCS(genesis)))`.
    pub hash: String,
    /// The genesis's name.
    pub name: String,
    /// The genesis's currency.
    #[serde(rename = "defaultCurrency")]
    pub default_currency: String,
    /// What the hash is of.
    pub genesis: Genesis,
    /// Unix seconds of the last change.
    pub updated: u64,
    /// Balances, one per account.
    pub entries: Vec<Entry>,
    /// Every deposit credited.
    pub deposits: Vec<Deposit>,
    /// The ids of every request applied (transfers and withdrawals).
    pub applied: Vec<String>,
    /// Every withdrawal paid.
    pub payouts: Vec<Payout>,
    /// Fields this crate does not name, kept.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What [`new_ledger`] is given (`newLedger`'s second argument). The
/// defaults are the teller's: currency `txbt4`, one confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerParams<'a> {
    /// The operator, any form [`account_of`] reads.
    pub operator: &'a str,
    /// The name, 1 to [`MAX_NAME`] characters.
    pub name: &'a str,
    /// The currency.
    pub currency: &'a str,
    /// Unix seconds at creation (the teller takes the clock; this crate
    /// takes it from the caller).
    pub created: u64,
    /// Confirmations before a deposit is credited.
    pub confirmations: u64,
}

impl<'a> LedgerParams<'a> {
    /// The teller's defaults: currency [`DEFAULT_CURRENCY`], one confirmation.
    pub fn new(operator: &'a str, name: &'a str, created: u64) -> Self {
        Self {
            operator,
            name,
            currency: DEFAULT_CURRENCY,
            created,
            confirmations: 1,
        }
    }
}

/// `hex(sha256(utf8(JCS(genesis))))`.
pub fn genesis_hash(genesis: &Genesis) -> String {
    let v = serde_json::to_value(genesis).expect("a genesis serialises");
    hex::encode(Sha256::digest(jcs(&v).as_bytes()))
}

/// `newLedger`: a ledger with its genesis fixed and no balances.
///
/// Refuses an operator that is not an account ([`Error::Account`]) and a
/// name that is empty or longer than [`MAX_NAME`] ([`Error::Name`]).
pub fn new_ledger(p: &LedgerParams<'_>) -> Result<Ledger> {
    let genesis = Genesis {
        operator: account_of(p.operator)?,
        name: p.name.to_owned(),
        currency: p.currency.to_owned(),
        created: p.created,
        confirmations: p.confirmations,
        extra: Map::new(),
    };
    if genesis.name.is_empty() || genesis.name.encode_utf16().count() > MAX_NAME {
        return Err(Error::Name);
    }
    let h = genesis_hash(&genesis);
    Ok(Ledger {
        context: CONTEXT.to_owned(),
        r#type: "WebLedger".to_owned(),
        id: format!("urn:webledgers:{h}"),
        hash: h,
        name: genesis.name.clone(),
        default_currency: genesis.currency.clone(),
        updated: genesis.created,
        genesis,
        entries: Vec::new(),
        deposits: Vec::new(),
        applied: Vec::new(),
        payouts: Vec::new(),
        extra: Map::new(),
    })
}

/// `ledgerHash`: the hash recomputed from the genesis.
pub fn ledger_hash(ledger: &Ledger) -> String {
    genesis_hash(&ledger.genesis)
}

/// `checkLedger`: a `WebLedger` whose stored hash is its genesis's hash, or
/// [`Error::NotALedger`] / [`Error::HashMismatch`].
pub fn check_ledger(ledger: &Ledger) -> Result<()> {
    if ledger.r#type != "WebLedger" {
        return Err(Error::NotALedger);
    }
    if ledger_hash(ledger) != ledger.hash {
        return Err(Error::HashMismatch);
    }
    Ok(())
}

/// A ledger document read from JSON and checked: [`Error::NotALedger`] for
/// anything that is not an object of type `WebLedger` with a genesis,
/// [`Error::LedgerContent`] for one whose fields do not fit, then
/// [`check_ledger`].
pub fn parse_ledger(json: &str) -> Result<Ledger> {
    let v: Value = serde_json::from_str(json).map_err(|_| Error::NotALedger)?;
    if v.get("type").and_then(Value::as_str) != Some("WebLedger")
        || v.get("genesis").is_none_or(Value::is_null)
    {
        return Err(Error::NotALedger);
    }
    let ledger: Ledger =
        serde_json::from_value(v).map_err(|e| Error::LedgerContent(e.to_string()))?;
    check_ledger(&ledger)?;
    Ok(ledger)
}

fn entry_index(ledger: &Ledger, account: &str) -> Option<usize> {
    ledger.entries.iter().position(|e| e.url == account)
}

/// `balance`: the account's satoshis, 0 if it has no entry.
pub fn balance(ledger: &Ledger, account: &str) -> Result<u64> {
    let a = account_of(account)?;
    match entry_index(ledger, &a) {
        Some(i) => sats(&ledger.entries[i].amount),
        None => Ok(0),
    }
}

fn set_balance(ledger: &mut Ledger, account: &str, n: u64) {
    match entry_index(ledger, account) {
        Some(i) => ledger.entries[i].amount = n.to_string(),
        None => ledger.entries.push(Entry {
            r#type: "Entry".to_owned(),
            url: account.to_owned(),
            amount: n.to_string(),
            extra: Map::new(),
        }),
    }
}

fn touch(ledger: &mut Ledger, now: u64) {
    ledger.updated = ledger.updated.max(now);
}

/// `total`: every balance added up.
pub fn total(ledger: &Ledger) -> Result<u64> {
    ledger.entries.iter().try_fold(0u64, |s, e| {
        s.checked_add(sats(&e.amount)?).ok_or(Error::Amount)
    })
}

/// Whether a move changed the ledger (`{ applied, why }`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// It was applied.
    Applied,
    /// It had been applied before and changed nothing; why, in the teller's
    /// words (`"already credited"`, `"already applied"`).
    Skipped(&'static str),
}

impl Outcome {
    /// `applied`.
    pub fn applied(&self) -> bool {
        matches!(self, Outcome::Applied)
    }

    /// `why`, for a move that changed nothing.
    pub fn why(&self) -> Option<&'static str> {
        match self {
            Outcome::Applied => None,
            Outcome::Skipped(w) => Some(w),
        }
    }
}

/// A deposit seen on-chain (`credit`'s second argument).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credit {
    /// The account whose deposit address it paid.
    pub account: String,
    /// The paying transaction, 64 lowercase hex.
    pub txid: String,
    /// The output's index.
    pub vout: u32,
    /// Satoshis.
    pub value: u64,
    /// The block height it was seen at.
    pub height: Option<u64>,
}

/// `credit`: a deposit credits its account once; the outpoint is the
/// receipt. A second credit of the same outpoint is
/// `Skipped("already credited")`.
pub fn credit(ledger: &mut Ledger, c: &Credit, now: u64) -> Result<Outcome> {
    let a = account_of(&c.account)?;
    let key = format!("{}:{}", c.txid, c.vout);
    let lower_hex = c.txid.len() == 64
        && c.txid
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !lower_hex {
        return Err(Error::Outpoint);
    }
    if ledger.deposits.iter().any(|d| d.outpoint == key) {
        return Ok(Outcome::Skipped("already credited"));
    }
    let v = check_sats(c.value)?;
    let b = balance(ledger, &a)?;
    set_balance(ledger, &a, b + v);
    ledger.deposits.push(Deposit {
        outpoint: key,
        account: a,
        value: v,
        height: c.height,
        at: now,
    });
    touch(ledger, now);
    Ok(Outcome::Applied)
}

/// A transfer between accounts, from a request already verified
/// ([`crate::parse_request`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    /// The request's id: the transfer is applied once by it.
    pub id: String,
    /// The paying account.
    pub from: String,
    /// The receiving account.
    pub to: String,
    /// Satoshis, at least one.
    pub amount: u64,
}

fn short(account: &str) -> String {
    account.chars().take(20).collect()
}

/// `transfer`: whole satoshis between accounts, applied once by the
/// request's id, never overdrawing ([`Error::Insufficient`]).
pub fn transfer(ledger: &mut Ledger, t: &Transfer, now: u64) -> Result<Outcome> {
    let f = account_of(&t.from)?;
    let to = account_of(&t.to)?;
    let v = check_sats(t.amount)?;
    if v == 0 {
        return Err(Error::ZeroTransfer);
    }
    if ledger.applied.contains(&t.id) {
        return Ok(Outcome::Skipped("already applied"));
    }
    let has = balance(ledger, &f)?;
    if has < v {
        return Err(Error::Insufficient {
            account: short(&f),
            has,
            wanted: v,
        });
    }
    set_balance(ledger, &f, has - v);
    let b = balance(ledger, &to)?;
    set_balance(ledger, &to, b + v);
    ledger.applied.push(t.id.clone());
    touch(ledger, now);
    Ok(Outcome::Applied)
}

/// A withdrawal paid out (`debit`'s second argument).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Debit {
    /// The request's id: the debit is applied once by it.
    pub id: String,
    /// The account debited.
    pub account: String,
    /// Satoshis, at least [`crate::MIN_PAY`].
    pub amount: u64,
    /// Where it was paid.
    pub to: String,
    /// The payout transaction's id.
    pub txid: String,
}

/// `debit`: a withdrawal debits the account when the operator pays it out;
/// at least [`crate::MIN_PAY`], once by its id, never overdrawing. The payout
/// is recorded with its txid as the receipt.
pub fn debit(ledger: &mut Ledger, d: &Debit, now: u64) -> Result<Outcome> {
    let a = account_of(&d.account)?;
    let v = check_sats(d.amount)?;
    if v < crate::MIN_PAY {
        return Err(Error::WithdrawalTooSmall);
    }
    if ledger.applied.contains(&d.id) {
        return Ok(Outcome::Skipped("already applied"));
    }
    let has = balance(ledger, &a)?;
    if has < v {
        return Err(Error::Insufficient {
            account: short(&a),
            has,
            wanted: v,
        });
    }
    set_balance(ledger, &a, has - v);
    ledger.applied.push(d.id.clone());
    ledger.payouts.push(Payout {
        id: d.id.clone(),
        account: a,
        value: v,
        to: Some(d.to.clone()),
        txid: Some(d.txid.clone()),
        at: now,
    });
    touch(ledger, now);
    Ok(Outcome::Applied)
}

// ---- the ledger on Nostr (the teller's page: teller.js ledgerEvent and the reader beside it)

/// The ledger as an addressable Nostr event template (kind
/// [`LEDGER_KIND`], `d` = its hash), as the teller's page publishes it:
/// tags `d`, `t` = [`LEDGER_TOPIC`], `name`, `alt`; content the ledger's
/// JSON. `pubkey` is filled in by the signer.
pub fn ledger_template(ledger: &Ledger, created_at: u64) -> UnsignedEvent {
    UnsignedEvent {
        pubkey: String::new(),
        created_at,
        kind: LEDGER_KIND,
        tags: vec![
            vec!["d".into(), ledger.hash.clone()],
            vec!["t".into(), LEDGER_TOPIC.into()],
            vec!["name".into(), ledger.name.clone()],
            vec![
                "alt".into(),
                format!("Web Ledger {} ({})", ledger.name, ledger.default_currency),
            ],
        ],
        content: serde_json::to_string(ledger).expect("a ledger serialises"),
    }
}

/// [`ledger_template`] signed with the operator's secret.
pub fn ledger_event(
    operator_secret: &SecretKey,
    ledger: &Ledger,
    created_at: u64,
) -> Result<Event> {
    crate::sign::sign_event(operator_secret, ledger_template(ledger, created_at))
}

/// A ledger event read back as the teller's page reads one: kind
/// [`LEDGER_KIND`], verified, its content a ledger that passes
/// [`check_ledger`], for the ledger `hash`, and signed by that ledger's
/// operator — "the operator's own word only".
pub fn read_ledger_event(ev: &Event, hash: &str) -> Result<Ledger> {
    if ev.kind != LEDGER_KIND {
        return Err(Error::NotALedgerEvent);
    }
    ev.verify().map_err(|e| Error::Event(e.to_string()))?;
    let doc = parse_ledger(&ev.content).map_err(|e| match e {
        Error::HashMismatch => e,
        other => Error::LedgerContent(other.to_string()),
    })?;
    if doc.hash != hash || x_of(&doc.genesis.operator)? != ev.pubkey {
        return Err(Error::NotTheOperators);
    }
    Ok(doc)
}

/// Of several ledger events, the newest the operator signed for ledger
/// `hash` (the page's choice: the greatest `created_at`, the first seen on a
/// tie); events that do not pass [`read_ledger_event`] are passed over.
pub fn latest_ledger<'e>(
    events: impl IntoIterator<Item = &'e Event>,
    hash: &str,
) -> Option<(Ledger, &'e Event)> {
    let mut best: Option<(Ledger, &'e Event)> = None;
    for ev in events {
        let Ok(doc) = read_ledger_event(ev, hash) else {
            continue;
        };
        if best
            .as_ref()
            .is_none_or(|(_, b)| ev.created_at > b.created_at)
        {
            best = Some((doc, ev));
        }
    }
    best
}
