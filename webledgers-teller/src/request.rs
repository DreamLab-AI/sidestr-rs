//! Requests: Nostr events of kind [`REQUEST_KIND`] signed by an account's
//! key, each applied at most once by its id (`teller.mjs requestTags`,
//! `requestEvent`, `parseRequest`).
//!
//! - `join`: be watched (the operator derives the account's deposit address);
//! - `withdraw`: an amount to an address, paid out by the operator;
//! - `transfer`: an amount to another account, applied on sight.
//!
//! The tags are `ledger` (the ledger's hash), `op`, `id`, and for a
//! withdrawal or transfer `amount` (whole satoshis as a string) and `to`. The
//! content is empty. The teller draws a missing id from the browser's random
//! source; this crate does no I/O, so the caller supplies the id
//! ([`request_id`] writes 16 random bytes the teller's way).
//!
//! ```
//! use bitcoin::secp256k1::SecretKey;
//! use webledgers_teller::{parse_request, pubkey_hex, request_event, request_id, Op, RequestParams};
//!
//! let alice = SecretKey::from_slice(&[0x22; 32]).unwrap();
//! let ledger = "cd".repeat(32);
//! let id = request_id([7; 16]);
//! let ev = request_event(&alice, &RequestParams::transfer(&ledger, 5, "bb".repeat(32).as_str(), &id), 1_759_300_000).unwrap();
//!
//! let r = parse_request(&ev, &ledger).unwrap();
//! assert_eq!(r.op, Op::Transfer);
//! assert_eq!(r.account, format!("did:nostr:{}", pubkey_hex(&alice)));
//! assert_eq!(r.amount, Some(5));
//! assert_eq!(r.to.as_deref(), Some(format!("did:nostr:{}", "bb".repeat(32)).as_str()));
//! ```

use core::fmt;
use core::str::FromStr;

use bitcoin::secp256k1::SecretKey;
use sidestr_nostr::event::{Event, UnsignedEvent};

use crate::account::{account_of, check_sats, js_trim, sats};
use crate::deposit::is_x;
use crate::error::{Error, Result};
use crate::REQUEST_KIND;

/// What a request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    /// Be watched: the operator derives the account's deposit address.
    Join,
    /// An amount to an address, paid out by the operator.
    Withdraw,
    /// An amount to another account.
    Transfer,
}

impl Op {
    /// The tag value: `join`, `withdraw` or `transfer`.
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Join => "join",
            Op::Withdraw => "withdraw",
            Op::Transfer => "transfer",
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Op {
    type Err = Error;

    /// `join`, `withdraw` or `transfer` exactly, else [`Error::Op`].
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "join" => Ok(Op::Join),
            "withdraw" => Ok(Op::Withdraw),
            "transfer" => Ok(Op::Transfer),
            _ => Err(Error::Op),
        }
    }
}

/// What a request carries (`requestTags`' argument).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestParams<'a> {
    /// The ledger's hash, 64 lowercase hex.
    pub ledger_hash: &'a str,
    /// What is asked.
    pub op: Op,
    /// Satoshis, for a withdrawal or transfer.
    pub amount: Option<u64>,
    /// An address for a withdrawal, an account for a transfer.
    pub to: Option<&'a str>,
    /// The request's id. [`parse_request`] reads back only 8 to 64 lowercase
    /// hex digits; the teller writes 32 ([`request_id`]).
    pub id: &'a str,
}

impl<'a> RequestParams<'a> {
    /// A `join`.
    pub fn join(ledger_hash: &'a str, id: &'a str) -> Self {
        Self {
            ledger_hash,
            op: Op::Join,
            amount: None,
            to: None,
            id,
        }
    }

    /// A `withdraw` of `amount` to the address `to`.
    pub fn withdraw(ledger_hash: &'a str, amount: u64, to: &'a str, id: &'a str) -> Self {
        Self {
            ledger_hash,
            op: Op::Withdraw,
            amount: Some(amount),
            to: Some(to),
            id,
        }
    }

    /// A `transfer` of `amount` to the account `to`.
    pub fn transfer(ledger_hash: &'a str, amount: u64, to: &'a str, id: &'a str) -> Self {
        Self {
            ledger_hash,
            op: Op::Transfer,
            amount: Some(amount),
            to: Some(to),
            id,
        }
    }
}

/// A request id the teller's way: 16 bytes (from the caller's random
/// source) as 32 lowercase hex digits.
pub fn request_id(random: [u8; 16]) -> String {
    hex::encode(random)
}

/// `requestTags`: `ledger`, `op`, `id`, and for a withdrawal or transfer
/// `amount` and `to` (a transfer's `to` read as an account, a withdrawal's
/// trimmed). Refuses a ledger hash that is not 64 lowercase hex
/// ([`Error::RequestLedgerHash`]), a withdrawal or transfer with no amount
/// or one beyond 21 million coins ([`Error::Amount`]) and one with no `to`
/// ([`Error::NoDestination`]).
pub fn request_tags(p: &RequestParams<'_>) -> Result<Vec<Vec<String>>> {
    if !is_x(p.ledger_hash) {
        return Err(Error::RequestLedgerHash);
    }
    let mut tags = vec![
        vec!["ledger".to_owned(), p.ledger_hash.to_owned()],
        vec!["op".to_owned(), p.op.as_str().to_owned()],
        vec!["id".to_owned(), p.id.to_owned()],
    ];
    if p.op != Op::Join {
        let amount = check_sats(p.amount.ok_or(Error::Amount)?)?;
        tags.push(vec!["amount".to_owned(), amount.to_string()]);
        let to = p.to.filter(|t| !t.is_empty()).ok_or(Error::NoDestination)?;
        let to = if p.op == Op::Transfer {
            account_of(to)?
        } else {
            js_trim(to).to_owned()
        };
        tags.push(vec!["to".to_owned(), to]);
    }
    Ok(tags)
}

/// The unsigned request (kind [`REQUEST_KIND`], empty content); its pubkey
/// is the signer's, filled in when it is signed. For a key held elsewhere:
/// sign [`UnsignedEvent::id_bytes`] and attach it with
/// [`UnsignedEvent::with_signature`].
pub fn request_template(p: &RequestParams<'_>, created_at: u64) -> Result<UnsignedEvent> {
    Ok(UnsignedEvent {
        pubkey: String::new(),
        created_at,
        kind: REQUEST_KIND,
        tags: request_tags(p)?,
        content: String::new(),
    })
}

/// `requestEvent`: the request signed by the account's key (BIP 340, zero
/// auxiliary randomness).
pub fn request_event(
    account_secret: &SecretKey,
    p: &RequestParams<'_>,
    created_at: u64,
) -> Result<Event> {
    crate::sign::sign_event(account_secret, request_template(p, created_at)?)
}

/// A request read back and verified (`parseRequest`'s result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The request's id.
    pub id: String,
    /// What it asks.
    pub op: Op,
    /// Its author, `did:nostr:<pubkey>`: the account it acts for.
    pub account: String,
    /// The event's `created_at`.
    pub created_at: u64,
    /// Satoshis, for a withdrawal or transfer.
    pub amount: Option<u64>,
    /// The address (withdrawal) or account (transfer).
    pub to: Option<String>,
    /// The event it was read from.
    pub event: Event,
}

/// `parseRequest`: a request for the ledger `ledger_hash`, verified, its
/// account its author. Refusals in the teller's words: not kind 3700, does
/// not verify, for another ledger, no valid op or id (8 to 64 lowercase
/// hex), a bad amount, no destination; a transfer's `to` must be an account.
pub fn parse_request(ev: &Event, ledger_hash: &str) -> Result<Request> {
    if ev.kind != REQUEST_KIND {
        return Err(Error::NotARequest);
    }
    if ev.verify().is_err() {
        return Err(Error::Unverified);
    }
    let tag = |n: &str| {
        ev.tags
            .iter()
            .find(|t| t.first().map(String::as_str) == Some(n))
            .and_then(|t| t.get(1))
            .map(String::as_str)
    };
    if tag("ledger") != Some(ledger_hash) {
        return Err(Error::OtherLedger);
    }
    let op = tag("op").and_then(|o| o.parse::<Op>().ok());
    let id = tag("id").filter(|id| {
        (8..=64).contains(&id.len()) && id.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    });
    let (Some(op), Some(id)) = (op, id) else {
        return Err(Error::OpAndId);
    };
    let mut r = Request {
        id: id.to_owned(),
        op,
        account: format!("did:nostr:{}", ev.pubkey),
        created_at: ev.created_at,
        amount: None,
        to: None,
        event: ev.clone(),
    };
    if op != Op::Join {
        r.amount = Some(sats(tag("amount").ok_or(Error::Amount)?)?);
        let to = tag("to")
            .filter(|t| !t.is_empty())
            .ok_or(Error::NoDestination)?;
        r.to = Some(if op == Op::Transfer {
            account_of(to)?
        } else {
            to.to_owned()
        });
    }
    Ok(r)
}
