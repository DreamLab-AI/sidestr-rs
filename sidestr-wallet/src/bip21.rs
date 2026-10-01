//! BIP 21 payment requests: `bitcoin:<address>?amount=<coins>&label=…&message=…`,
//! read and written with the rules of Reef, the BLAKE2b testnet4 browser
//! wallet by Melvin Carvalho (`bitcoin-blake/reef` `lib/wallet.mjs
//! parsePaymentUri`, commits `91d6eb2` and `648487a`, AGPL-3.0).
//!
//! A request is something a person is asked to pay. It names an address and
//! may name an amount and the requester's words (a label, a message). Reading
//! one decides nothing: the address is judged by the same rules as any other
//! destination ([`PaymentRequest::resolve`] on a sidechain,
//! [`PaymentRequest::parent_address`] on the parent chain, txbt4 included),
//! and the amount and words are shown, never trusted.
//!
//! [`PaymentRequest::parse`] accepts and refuses exactly what Reef does:
//!
//! - text that is not a `bitcoin:` URI (a plain address, `lightning:…`,
//!   nothing) is not a request: `Ok(None)`;
//! - the scheme is read in any case, and an address written all in capitals
//!   (a QR code's alphanumeric mode) is read in lower case;
//! - the amount is in whole coins with a dot, read exactly into sats with no
//!   floating point: no grouping, no comma, no sign, no unit, no exponent, at
//!   most 8 decimals, never zero, never more than 21 million coins, never
//!   named twice;
//! - a parameter the request *requires* (`req-…`) is not supported, so the
//!   request is refused, as BIP 21 asks; other unknown parameters are ignored;
//! - `label` and `message` are percent-decoded (`+` is a space), capped at
//!   200 UTF-16 code units as Reef caps them, and a broken `%` escape refuses
//!   the request.
//!
//! Every refusal is a sentence a person can act on ([`RequestError`]).
//!
//! [`PaymentRequest::new`] and its `with_*` methods build a request whose
//! [`to_uri`](PaymentRequest::to_uri) Reef's parser reads back to the same
//! address, amount and words (`tests/bip21.rs` runs Reef's own parser over
//! them when `REEF` names a checkout).
//!
//! ```
//! use sidestr_wallet::bip21::{PaymentRequest, RequestError};
//!
//! let a = "tb1pfu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4quvla6g";
//! let r = PaymentRequest::parse(&format!("bitcoin:{a}?amount=0.001&label=Table%207&message=buy-in+for+seat+3"))
//!     .unwrap()
//!     .unwrap();
//! assert_eq!((r.address(), r.sats(), r.label(), r.message()), (a, Some(100_000), "Table 7", "buy-in for seat 3"));
//!
//! // not a request at all, and requests refused in words
//! assert_eq!(PaymentRequest::parse(a).unwrap(), None);
//! assert_eq!(PaymentRequest::parse(&format!("bitcoin:{a}?amount=1,5")).unwrap_err().to_string(),
//!            "this payment request's amount \"1,5\" is not a number of coins like 0.001");
//! assert!(matches!(PaymentRequest::parse(&format!("bitcoin:{a}?req-pop=x")), Err(RequestError::Required(k)) if k == "req-pop"));
//!
//! // built, and read back
//! let built = PaymentRequest::new(a).unwrap().with_amount(250_000).unwrap().with_label("Table 7 & co").unwrap();
//! assert_eq!(built.to_uri(), format!("bitcoin:{a}?amount=0.0025&label=Table%207%20%26%20co"));
//! assert_eq!(PaymentRequest::parse(&built.to_uri()).unwrap(), Some(built));
//! ```

use core::fmt;
use std::str::FromStr;

use bitcoin::Address;
use sidestr_core::address::decode_address;
use sidestr_core::parents::Parent;

use crate::error::{Error, Result};
use crate::spend::{resolve_address, Resolved};

/// Sats in a coin: the amount is written in coins with 8 decimals.
pub const SATS_PER_COIN: u64 = 100_000_000;

/// The most an amount may be: 21 million coins, in sats (Reef's `MAX_SATS`).
pub const MAX_SATS: u64 = 21_000_000 * SATS_PER_COIN;

/// The longest a label or a message is kept, in UTF-16 code units: Reef
/// cuts the requester's words there (`val.slice(0, 200)`).
pub const MAX_WORDS: usize = 200;

/// Why a payment request is refused: Reef's sentences, so a person reads the
/// same reason in either wallet. Matching on the variant is the stable
/// contract; the wording may be improved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RequestError {
    /// `bitcoin:` with nothing before the `?`.
    #[error("this payment request has no address")]
    NoAddress,
    /// A `%` not followed by two hex digits, or escapes that do not decode
    /// as UTF-8 (JavaScript's `decodeURIComponent` refuses the same).
    #[error("this payment request is not written correctly (a broken % escape)")]
    BrokenEscape,
    /// `amount` given more than once.
    #[error("this payment request names the amount twice")]
    AmountTwice,
    /// An amount that is not plain digits with at most one dot: a comma,
    /// grouping, a sign, a unit, an exponent. Carries the first 40 UTF-16
    /// code units of what was written.
    #[error("this payment request's amount \"{0}\" is not a number of coins like 0.001")]
    NotCoins(String),
    /// More than 8 decimals: less than a sat.
    #[error("at most 8 decimals in tBTC")]
    TooManyDecimals,
    /// More than 21 million coins.
    #[error("more than 21 million coins")]
    TooLarge,
    /// An amount of zero.
    #[error("this payment request asks for nothing (an amount of 0)")]
    Zero,
    /// A `req-` parameter, which this wallet does not know and so cannot
    /// honour (BIP 21: such a request must be refused). Carries the key,
    /// lower case, at most 40 UTF-16 code units.
    #[error("this payment request needs something this wallet does not support ({0}): it cannot be paid here")]
    Required(String),
    /// Building: the text is not a segwit address under any prefix.
    #[error("{0} is not an address a payment request can name")]
    NotAnAddress(String),
    /// Building: a label or message longer than [`MAX_WORDS`] UTF-16 code
    /// units, which a reader would cut.
    #[error("the {field} is {len} characters long; a payment request carries at most 200")]
    WordsTooLong {
        /// `"label"` or `"message"`.
        field: &'static str,
        /// Its length in UTF-16 code units.
        len: usize,
    },
}

/// A BIP 21 payment request: an address, perhaps an amount, and the
/// requester's words. Read one with [`parse`](Self::parse), make one with
/// [`new`](Self::new); write it with [`to_uri`](Self::to_uri) (or
/// `Display`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentRequest {
    address: String,
    sats: Option<u64>,
    label: String,
    message: String,
}

impl PaymentRequest {
    /// Read `text` as a payment request (Reef's `parsePaymentUri`).
    /// `Ok(None)` when it is not one: anything not of the form
    /// `bitcoin:<address>[?<query>]` once surrounding whitespace is trimmed
    /// (a `#` anywhere after the scheme makes it not one too). `Err` when it
    /// is one that cannot be paid as written (see [`RequestError`]).
    ///
    /// The address is returned as written (lower-cased when all capitals)
    /// and is not judged here: [`resolve`](Self::resolve) and
    /// [`parent_address`](Self::parent_address) judge it.
    ///
    /// ```
    /// use sidestr_wallet::bip21::PaymentRequest;
    /// let a = "tb1pfu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4quvla6g";
    /// let r = PaymentRequest::parse(&format!("BITCOIN:{}?AMOUNT=1.00000001", a.to_uppercase())).unwrap().unwrap();
    /// assert_eq!((r.address(), r.sats()), (a, Some(100_000_001)));
    /// assert_eq!(PaymentRequest::parse(&format!("bitcoin:{a}?amount=0.5&lightning=lnbc1")).unwrap().unwrap().sats(), Some(50_000_000));
    /// assert_eq!(PaymentRequest::parse("lightning:x").unwrap(), None);
    /// ```
    pub fn parse(text: &str) -> core::result::Result<Option<Self>, RequestError> {
        let text = js_trim(text);
        let Some(rest) = strip_scheme(text) else {
            return Ok(None);
        };
        if rest.contains('#') {
            return Ok(None);
        }
        let (raw_address, query) = match rest.split_once('?') {
            Some((a, q)) => (a, q),
            None => (rest, ""),
        };
        let upper = raw_address.to_uppercase();
        let address = if raw_address == upper {
            raw_address.to_lowercase()
        } else {
            raw_address.to_string()
        };
        if address.is_empty() {
            return Err(RequestError::NoAddress);
        }
        let mut out = PaymentRequest {
            address,
            sats: None,
            label: String::new(),
            message: String::new(),
        };
        for part in query.split('&').filter(|p| !p.is_empty()) {
            let (key, raw) = part.split_once('=').unwrap_or((part, ""));
            let key = key.to_lowercase();
            let val = percent_decode(raw)?;
            match key.as_str() {
                "amount" => {
                    if out.sats.is_some() {
                        return Err(RequestError::AmountTwice);
                    }
                    let sats = coins_to_sats(&val)?;
                    if sats == 0 {
                        return Err(RequestError::Zero);
                    }
                    out.sats = Some(sats);
                }
                "label" => out.label = cap_utf16(&val, MAX_WORDS).to_string(),
                "message" => out.message = cap_utf16(&val, MAX_WORDS).to_string(),
                _ if key.starts_with("req-") => {
                    return Err(RequestError::Required(cap_utf16(&key, 40).to_string()))
                }
                _ => {}
            }
        }
        Ok(Some(out))
    }

    /// A request to pay `address`, with no amount and no words yet. The
    /// address must be a segwit address under some prefix (a parent's `tb1…`
    /// or `bc1…`, or a sidechain's own); written all in capitals it is
    /// stored in lower case. Surrounding whitespace is ignored.
    ///
    /// ```
    /// use sidestr_wallet::bip21::PaymentRequest;
    /// assert!(PaymentRequest::new("tb1pfu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4quvla6g").is_ok());
    /// assert!(PaymentRequest::new("tb1notanaddress").is_err());
    /// ```
    pub fn new(address: &str) -> core::result::Result<Self, RequestError> {
        let address = address.trim();
        if decode_address(address).is_none() {
            return Err(RequestError::NotAnAddress(address.into()));
        }
        Ok(PaymentRequest {
            address: address.to_lowercase(),
            sats: None,
            label: String::new(),
            message: String::new(),
        })
    }

    /// Ask for `sats` (written in coins in the URI). Refused when zero or
    /// more than [`MAX_SATS`], which a reader would refuse.
    pub fn with_amount(mut self, sats: u64) -> core::result::Result<Self, RequestError> {
        if sats == 0 {
            return Err(RequestError::Zero);
        }
        if sats > MAX_SATS {
            return Err(RequestError::TooLarge);
        }
        self.sats = Some(sats);
        Ok(self)
    }

    /// Name the requester (BIP 21 `label`): any text, percent-encoded in the
    /// URI. Refused when longer than [`MAX_WORDS`] UTF-16 code units.
    pub fn with_label(mut self, label: &str) -> core::result::Result<Self, RequestError> {
        self.label = words("label", label)?;
        Ok(self)
    }

    /// Say what the payment is for (BIP 21 `message`): any text,
    /// percent-encoded in the URI. Refused when longer than [`MAX_WORDS`]
    /// UTF-16 code units.
    pub fn with_message(mut self, message: &str) -> core::result::Result<Self, RequestError> {
        self.message = words("message", message)?;
        Ok(self)
    }

    /// The address to pay, as the request wrote it (lower case when it was
    /// all capitals). Not yet judged; see [`resolve`](Self::resolve).
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The amount asked for, in sats; `None` leaves it to the person paying.
    pub fn sats(&self) -> Option<u64> {
        self.sats
    }

    /// The requester's name for themselves; empty when not given. Show it
    /// as text, never as markup, and never trust it.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// What the requester says the payment is for; empty when not given.
    /// Show it as text, never as markup, and never trust it.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The URI: `bitcoin:<address>`, then `amount` in coins (exact, without
    /// trailing zeros), `label` and `message`, each present only when set.
    /// Words are percent-encoded byte by byte, everything but the RFC 3986
    /// unreserved characters, so a space is `%20` and a `+` is `%2B`.
    pub fn to_uri(&self) -> String {
        let mut uri = format!("bitcoin:{}", self.address);
        let mut sep = '?';
        let mut push = |key: &str, val: &str| {
            uri.push(sep);
            uri.push_str(key);
            uri.push('=');
            uri.push_str(val);
            sep = '&';
        };
        if let Some(sats) = self.sats {
            push("amount", &sats_to_coins(sats));
        }
        if !self.label.is_empty() {
            push("label", &percent_encode(&self.label));
        }
        if !self.message.is_empty() {
            push("message", &percent_encode(&self.message));
        }
        uri
    }

    /// The address as a sidechain destination, judged as every destination
    /// in this crate is ([`crate::spend::resolve_to`]): a segwit address
    /// under any prefix names a script, and one whose prefix is not `hrp`
    /// (the document's `addressPrefix`) is accepted with a note saying so.
    /// A script hex, which `resolve_to` would take, is not an address and
    /// is refused here: [`Error::BadDestination`].
    ///
    /// ```
    /// use sidestr_wallet::bip21::PaymentRequest;
    /// let r = PaymentRequest::parse("bitcoin:tb1pfu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4quvla6g").unwrap().unwrap();
    /// let to = r.resolve("ts").unwrap();
    /// assert!(to.script.is_p2tr());
    /// assert!(to.note.unwrap().contains("this chain's is 'ts'"));
    /// assert!(r.resolve("tb").unwrap().note.is_none());
    /// ```
    pub fn resolve(&self, hrp: &str) -> Result<Resolved> {
        resolve_address(&self.address, hrp)
            .ok_or_else(|| Error::BadDestination(self.address.clone()))
    }

    /// The address as one on `parent`'s network (SPEC 3.2), judged as a
    /// peg-in's peg address is: [`Error::WrongNetwork`] for a `bc1…` request
    /// beside tbtc4 or txbt4 (the BLAKE2b testnet4 shares testnet4's
    /// encodings, `tb1…`), or a `tb1…` one beside btc or xbt;
    /// [`Error::Core`] for a reserved parent; [`Error::BadDestination`] for
    /// what is no address at all.
    ///
    /// ```
    /// use sidestr_core::parents::resolve_parent;
    /// use sidestr_wallet::bip21::PaymentRequest;
    /// use sidestr_wallet::Error;
    /// let r = PaymentRequest::parse("bitcoin:tb1pfu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4quvla6g?amount=0.001").unwrap().unwrap();
    /// assert!(r.parent_address(resolve_parent("txbt4").unwrap()).unwrap().script_pubkey().is_p2tr());
    /// assert!(matches!(r.parent_address(resolve_parent("xbt").unwrap()), Err(Error::WrongNetwork { .. })));
    /// ```
    pub fn parent_address(&self, parent: &Parent) -> Result<Address> {
        crate::pegin::parent_address(parent, &self.address)
    }
}

impl fmt::Display for PaymentRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_uri())
    }
}

impl FromStr for PaymentRequest {
    type Err = Error;

    /// [`PaymentRequest::parse`], with text that is not a request refused as
    /// [`Error::BadDestination`] and a refused request as
    /// [`Error::PaymentRequest`].
    fn from_str(text: &str) -> Result<Self> {
        PaymentRequest::parse(text)?.ok_or_else(|| Error::BadDestination(text.to_string()))
    }
}

/// A label or message for building: kept whole, or refused.
fn words(field: &'static str, text: &str) -> core::result::Result<String, RequestError> {
    let len = text.encode_utf16().count();
    if len > MAX_WORDS {
        return Err(RequestError::WordsTooLong { field, len });
    }
    Ok(text.to_string())
}

/// What follows `bitcoin:` (the scheme in any ASCII case), or `None`.
fn strip_scheme(text: &str) -> Option<&str> {
    const SCHEME: &str = "bitcoin:";
    let head = text.get(..SCHEME.len())?;
    head.eq_ignore_ascii_case(SCHEME)
        .then(|| &text[SCHEME.len()..])
}

/// JavaScript's `String.prototype.trim`: its WhiteSpace and LineTerminator
/// sets, which differ from Rust's `char::is_whitespace` (U+FEFF is trimmed,
/// U+0085 is not).
fn js_trim(text: &str) -> &str {
    fn js_space(c: char) -> bool {
        const SINGLES: [char; 14] = [
            '\u{9}', '\u{a}', '\u{b}', '\u{c}', '\u{d}', ' ', '\u{a0}', '\u{1680}', '\u{2028}',
            '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}', '\u{feff}',
        ];
        SINGLES.contains(&c) || ('\u{2000}'..='\u{200a}').contains(&c)
    }
    text.trim_matches(js_space)
}

/// The longest prefix of `text` at most `max` UTF-16 code units long (as
/// JavaScript's `slice(0, max)` counts), never splitting a surrogate pair:
/// where JavaScript would keep half a pair, this keeps neither half.
fn cap_utf16(text: &str, max: usize) -> &str {
    let mut units = 0;
    for (i, c) in text.char_indices() {
        units += c.len_utf16();
        if units > max {
            return &text[..i];
        }
    }
    text
}

/// A query value as Reef decodes it: `+` is a space, then
/// `decodeURIComponent`: `%XX` escapes to bytes that must be UTF-8 as a whole.
fn percent_decode(raw: &str) -> core::result::Result<String, RequestError> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                let hex = bytes.get(i + 1..i + 3).ok_or(RequestError::BrokenEscape)?;
                let hi = (hex[0] as char)
                    .to_digit(16)
                    .ok_or(RequestError::BrokenEscape)?;
                let lo = (hex[1] as char)
                    .to_digit(16)
                    .ok_or(RequestError::BrokenEscape)?;
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| RequestError::BrokenEscape)
}

/// Every byte but RFC 3986's unreserved characters as `%XX`.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for &b in text.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A decoded `amount` → sats, exactly (Reef: `/^(\d+\.?\d*|\.\d+)$/`, then
/// `parseAmount(val, 'tbtc')`). Zero is returned for the caller to refuse.
fn coins_to_sats(val: &str) -> core::result::Result<u64, RequestError> {
    let (int, frac) = val.split_once('.').unwrap_or((val, ""));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if !digits(int) || !digits(frac) || (int.is_empty() && frac.is_empty()) {
        return Err(RequestError::NotCoins(cap_utf16(val, 40).to_string()));
    }
    if frac.len() > 8 {
        return Err(RequestError::TooManyDecimals);
    }
    let mut coins: u64 = 0;
    for b in int.bytes() {
        coins = coins
            .checked_mul(10)
            .and_then(|c| c.checked_add(u64::from(b - b'0')))
            .filter(|&c| c <= MAX_SATS / SATS_PER_COIN)
            .ok_or(RequestError::TooLarge)?;
    }
    let frac_sats: u64 = format!("{frac:0<8}").parse().unwrap_or(0);
    let sats = coins * SATS_PER_COIN + frac_sats;
    if sats > MAX_SATS {
        return Err(RequestError::TooLarge);
    }
    Ok(sats)
}

/// Sats → coins, exact, without trailing zeros: `100_000` → `"0.001"`,
/// `100_000_000` → `"1"`.
fn sats_to_coins(sats: u64) -> String {
    let whole = sats / SATS_PER_COIN;
    let frac = sats % SATS_PER_COIN;
    if frac == 0 {
        return whole.to_string();
    }
    let frac = format!("{frac:08}");
    format!("{whole}.{}", frac.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The taproot address of the test key 11…11 (Reef `648487a`).
    const A: &str = "tb1pfu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4quvla6g";

    fn parse(text: &str) -> core::result::Result<Option<PaymentRequest>, RequestError> {
        PaymentRequest::parse(text)
    }

    fn ok(text: &str) -> PaymentRequest {
        parse(text).unwrap().unwrap()
    }

    /// `encodeURIComponent` for the ASCII the tests feed it.
    fn encode_uri_component(s: &str) -> String {
        s.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    }

    // ---- Reef test/wallet-test.mjs, "payment requests (BIP 21)", case for case

    #[test]
    fn a_request_gives_the_address_the_amount_exactly_and_its_words() {
        let r = ok(&format!(
            "bitcoin:{A}?amount=0.001&label=Table%207&message=buy-in+for+seat+3"
        ));
        assert_eq!(r.address(), A);
        assert_eq!(r.sats(), Some(100_000));
        assert_eq!(r.label(), "Table 7");
        assert_eq!(r.message(), "buy-in for seat 3");
    }

    #[test]
    fn a_request_with_no_amount_leaves_the_amount_to_the_person() {
        assert_eq!(ok(&format!("bitcoin:{A}")).sats(), None);
    }

    #[test]
    fn the_scheme_in_any_case_and_an_address_in_capitals_read_in_lower_case() {
        let r = ok(&format!("BITCOIN:{}?AMOUNT=1.00000001", A.to_uppercase()));
        assert_eq!(r.address(), A);
        assert_eq!(r.sats(), Some(100_000_001));
    }

    #[test]
    fn a_plain_address_or_other_text_is_not_a_request() {
        assert_eq!(parse(A).unwrap(), None);
        assert_eq!(parse("lightning:x").unwrap(), None);
        assert_eq!(parse("").unwrap(), None);
    }

    #[test]
    fn an_unknown_optional_parameter_is_ignored() {
        let r = ok(&format!("bitcoin:{A}?amount=0.5&lightning=lnbc1&foo=bar"));
        assert_eq!(r.sats(), Some(50_000_000));
    }

    #[test]
    fn a_required_parameter_this_wallet_does_not_know_refuses_the_request() {
        let e = parse(&format!("bitcoin:{A}?req-pop=x")).unwrap_err();
        assert_eq!(e, RequestError::Required("req-pop".into()));
        assert!(e.to_string().contains("req-pop"));
    }

    #[test]
    fn an_amount_with_a_comma_grouping_a_sign_a_unit_or_too_many_decimals_is_refused() {
        for a in ["1,5", "1 000", "-1", "0.001BTC", "1e-3", "0.000000001"] {
            let uri = format!("bitcoin:{A}?amount={}", encode_uri_component(a));
            assert!(parse(&uri).is_err(), "{a} was accepted");
        }
        assert_eq!(
            parse(&format!("bitcoin:{A}?amount=0.000000001")).unwrap_err(),
            RequestError::TooManyDecimals
        );
        assert_eq!(
            parse(&format!("bitcoin:{A}?amount=1%2C5")).unwrap_err(),
            RequestError::NotCoins("1,5".into())
        );
    }

    #[test]
    fn an_amount_of_0_is_refused() {
        let e = parse(&format!("bitcoin:{A}?amount=0.0")).unwrap_err();
        assert_eq!(e, RequestError::Zero);
        assert!(e.to_string().contains("nothing"));
    }

    #[test]
    fn the_amount_named_twice_is_refused() {
        let e = parse(&format!("bitcoin:{A}?amount=1&amount=2")).unwrap_err();
        assert_eq!(e, RequestError::AmountTwice);
        assert!(e.to_string().contains("twice"));
    }

    #[test]
    fn no_address_is_refused() {
        let e = parse("bitcoin:?amount=1").unwrap_err();
        assert_eq!(e, RequestError::NoAddress);
        assert!(e.to_string().contains("no address"));
    }

    #[test]
    fn a_broken_percent_escape_is_refused_in_words() {
        let e = parse(&format!("bitcoin:{A}?label=%E0%A4%A")).unwrap_err();
        assert_eq!(e, RequestError::BrokenEscape);
        assert!(e.to_string().contains("escape"));
    }

    #[test]
    fn the_words_are_capped() {
        let r = ok(&format!("bitcoin:{A}?label={}", "x".repeat(500)));
        assert_eq!(r.label().len(), 200);
    }

    // ---- the edges of Reef's expressions, read as JavaScript reads them

    #[test]
    fn amount_forms_reef_accepts() {
        for (a, sats) in [
            ("1", 100_000_000),
            ("1.", 100_000_000),
            (".5", 50_000_000),
            ("00.00000001", 1),
            ("21000000", MAX_SATS),
            ("21000000.00000000", MAX_SATS),
            ("0000000000000000000000000001", 100_000_000),
        ] {
            assert_eq!(
                ok(&format!("bitcoin:{A}?amount={a}")).sats(),
                Some(sats),
                "{a}"
            );
        }
    }

    #[test]
    fn amount_forms_reef_refuses() {
        for (a, e) in [
            ("", RequestError::NotCoins(String::new())),
            (".", RequestError::NotCoins(".".into())),
            ("1..2", RequestError::NotCoins("1..2".into())),
            ("+1", RequestError::NotCoins(" 1".into())),
            ("%201", RequestError::NotCoins(" 1".into())),
            ("1_000", RequestError::NotCoins("1_000".into())),
            ("١", RequestError::NotCoins("١".into())),
            ("21000000.00000001", RequestError::TooLarge),
            ("99999999999999999999999999", RequestError::TooLarge),
            ("0", RequestError::Zero),
            (".00000000", RequestError::Zero),
            ("1.123456789", RequestError::TooManyDecimals),
        ] {
            assert_eq!(
                parse(&format!("bitcoin:{A}?amount={a}")).unwrap_err(),
                e,
                "{a}"
            );
        }
        // the bare key is an empty amount
        assert_eq!(
            parse(&format!("bitcoin:{A}?amount")).unwrap_err(),
            RequestError::NotCoins(String::new())
        );
        // what is quoted back is cut at 40
        let long = "x".repeat(60);
        assert_eq!(
            parse(&format!("bitcoin:{A}?amount={long}")).unwrap_err(),
            RequestError::NotCoins("x".repeat(40))
        );
    }

    #[test]
    fn decimals_are_judged_before_size() {
        assert_eq!(
            parse(&format!("bitcoin:{A}?amount=99999999999.123456789")).unwrap_err(),
            RequestError::TooManyDecimals
        );
    }

    #[test]
    fn the_shape_of_the_uri() {
        // a fragment anywhere makes it not a request; so does no colon
        assert_eq!(parse(&format!("bitcoin:{A}#x")).unwrap(), None);
        assert_eq!(parse(&format!("bitcoin:{A}?amount=1#x")).unwrap(), None);
        assert_eq!(parse("bitcoin").unwrap(), None);
        assert_eq!(parse(" bitcoin ").unwrap(), None);
        // surrounding whitespace, JavaScript's: U+FEFF trimmed, U+0085 kept
        assert_eq!(
            ok(&format!("\u{feff}\n bitcoin:{A}\t\u{3000}")).address(),
            A
        );
        assert_eq!(parse(&format!("\u{85}bitcoin:{A}")).unwrap(), None);
        // only `bitcoin`, in any ASCII case
        assert_eq!(ok(&format!("BitCoin:{A}")).address(), A);
        assert_eq!(parse(&format!("bitcoın:{A}")).unwrap(), None);
        // empty parts are skipped; the address is taken as written
        let r = ok(&format!("bitcoin:{A}?&&amount=1&"));
        assert_eq!(r.sats(), Some(100_000_000));
        assert_eq!(ok("bitcoin:TB1Q?amount=1.").address(), "tb1q");
        assert_eq!(ok("bitcoin:Tb1Q").address(), "Tb1Q");
        assert_eq!(ok("bitcoin:12").address(), "12");
        assert_eq!(parse("bitcoin:").unwrap_err(), RequestError::NoAddress);
    }

    #[test]
    fn words_are_decoded_and_the_last_one_counts() {
        let r = ok(&format!(
            "bitcoin:{A}?LABEL=a&label=caf%C3%A9+%2B+%26&message=%F0%9F%90%9F"
        ));
        assert_eq!(r.label(), "café + &");
        assert_eq!(r.message(), "🐟");
        // ... except that a broken escape in an ignored key still refuses (Reef decodes first)
        assert_eq!(
            parse(&format!("bitcoin:{A}?foo=%zz")).unwrap_err(),
            RequestError::BrokenEscape
        );
        // a `%` with fewer than two hex digits after it
        for bad in ["%", "%4", "%4g", "abc%"] {
            assert_eq!(
                parse(&format!("bitcoin:{A}?label={bad}")).unwrap_err(),
                RequestError::BrokenEscape,
                "{bad}"
            );
        }
        // UTF-8 that is not: an overlong, a surrogate, a lone continuation
        for bad in ["%C0%AF", "%ED%A0%80", "%80", "%E2%82"] {
            assert_eq!(
                parse(&format!("bitcoin:{A}?label={bad}")).unwrap_err(),
                RequestError::BrokenEscape,
                "{bad}"
            );
        }
        // the cap counts UTF-16 code units, and never splits a pair
        let r = ok(&format!("bitcoin:{A}?label={}", "é".repeat(300)));
        assert_eq!(r.label().chars().count(), 200);
        let r = ok(&format!("bitcoin:{A}?label=x{}", "🐟".repeat(150)));
        assert_eq!(r.label().encode_utf16().count(), 199);
    }

    #[test]
    fn req_keys_are_read_in_lower_case_and_quoted_short() {
        assert_eq!(
            parse(&format!("bitcoin:{A}?REQ-Foo")).unwrap_err(),
            RequestError::Required("req-foo".into())
        );
        let long = format!("req-{}", "y".repeat(60));
        assert_eq!(
            parse(&format!("bitcoin:{A}?{long}=1")).unwrap_err(),
            RequestError::Required(long[..40].to_string())
        );
        // `req` alone is not a required parameter
        assert!(parse(&format!("bitcoin:{A}?req=1")).is_ok());
    }

    // ---- the builder

    #[test]
    fn built_requests_read_back() {
        let r = PaymentRequest::new(A).unwrap();
        assert_eq!(r.to_uri(), format!("bitcoin:{A}"));
        let r = r
            .with_amount(1)
            .unwrap()
            .with_label("Table 7")
            .unwrap()
            .with_message("buy-in for seat 3 + tip: 100% & more")
            .unwrap();
        assert_eq!(
            r.to_uri(),
            format!("bitcoin:{A}?amount=0.00000001&label=Table%207&message=buy-in%20for%20seat%203%20%2B%20tip%3A%20100%25%20%26%20more")
        );
        assert_eq!(r.to_string(), r.to_uri());
        assert_eq!(parse(&r.to_uri()).unwrap().as_ref(), Some(&r));
        for sats in [1, 100_000, 100_000_000, 123_456_789, MAX_SATS] {
            let r = PaymentRequest::new(A).unwrap().with_amount(sats).unwrap();
            assert_eq!(ok(&r.to_uri()).sats(), Some(sats));
        }
        let fish = "🐟".repeat(100);
        let r = PaymentRequest::new(A).unwrap().with_label(&fish).unwrap();
        assert_eq!(ok(&r.to_uri()).label(), fish);
    }

    #[test]
    fn the_builder_refuses_what_a_reader_would_refuse_or_cut() {
        assert!(matches!(
            PaymentRequest::new("tb1notanaddress"),
            Err(RequestError::NotAnAddress(_))
        ));
        assert!(matches!(
            PaymentRequest::new(""),
            Err(RequestError::NotAnAddress(_))
        ));
        let r = PaymentRequest::new(&A.to_uppercase()).unwrap();
        assert_eq!(r.address(), A);
        assert_eq!(r.clone().with_amount(0).unwrap_err(), RequestError::Zero);
        assert_eq!(
            r.clone().with_amount(MAX_SATS + 1).unwrap_err(),
            RequestError::TooLarge
        );
        assert_eq!(
            r.clone().with_label(&"x".repeat(201)).unwrap_err(),
            RequestError::WordsTooLong {
                field: "label",
                len: 201
            }
        );
        assert_eq!(
            r.with_message(&"🐟".repeat(101)).unwrap_err(),
            RequestError::WordsTooLong {
                field: "message",
                len: 202
            }
        );
    }

    #[test]
    fn coins_are_written_exactly() {
        assert_eq!(sats_to_coins(1), "0.00000001");
        assert_eq!(sats_to_coins(100_000), "0.001");
        assert_eq!(sats_to_coins(150_000_000), "1.5");
        assert_eq!(sats_to_coins(MAX_SATS), "21000000");
    }

    // ---- judging the address

    #[test]
    fn the_address_is_judged_as_every_destination_is() {
        let r = ok(&format!("bitcoin:{A}"));
        let to = r.resolve("tb").unwrap();
        assert!(to.script.is_p2tr() && to.note.is_none());
        assert!(r.resolve("ts").unwrap().note.is_some());
        // a script hex is a destination elsewhere, but not an address
        let hex = format!("bitcoin:5120{}", "ab".repeat(32));
        assert!(matches!(
            ok(&hex).resolve("tb"),
            Err(Error::BadDestination(_))
        ));
        assert!(matches!(
            ok("bitcoin:12").resolve("tb"),
            Err(Error::BadDestination(_))
        ));
    }

    #[test]
    fn the_parent_network_is_the_parents() {
        use sidestr_core::parents::{resolve_parent, PARENTS};
        let r = ok(&format!("bitcoin:{A}?amount=0.001"));
        for p in ["tbtc4", "txbt4"] {
            assert!(r.parent_address(resolve_parent(p).unwrap()).is_ok(), "{p}");
        }
        for p in ["btc", "xbt"] {
            assert!(
                matches!(
                    r.parent_address(resolve_parent(p).unwrap()),
                    Err(Error::WrongNetwork { .. })
                ),
                "{p}"
            );
        }
        assert!(matches!(
            r.parent_address(PARENTS.iter().find(|p| p.alias == "ltc").unwrap()),
            Err(Error::Core(_))
        ));
        assert!(matches!(
            ok("bitcoin:12").parent_address(resolve_parent("txbt4").unwrap()),
            Err(Error::BadDestination(_))
        ));
    }

    #[test]
    fn from_str_folds_not_a_request_into_an_error() {
        assert!(format!("bitcoin:{A}").parse::<PaymentRequest>().is_ok());
        assert!(matches!(
            A.parse::<PaymentRequest>(),
            Err(Error::BadDestination(_))
        ));
        assert!(matches!(
            "bitcoin:?amount=1".parse::<PaymentRequest>(),
            Err(Error::PaymentRequest(RequestError::NoAddress))
        ));
    }
}
