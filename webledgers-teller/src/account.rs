//! Accounts and amounts: the two values every other part of the teller reads
//! first (`teller.mjs accountOf`, `xOf`, `sats`).
//!
//! An account is a did:nostr identifier, `did:nostr:<64 lowercase hex>`, read
//! from the did itself, a bare x, or a did:nostr Multikey (`fe70102…` or
//! `fe70103…`, whose parity an account does not keep). An amount is a whole
//! number of satoshis from 0 to 21 million coins: an integer inside, a string
//! of digits in the ledger, never a float.
//!
//! ```
//! use webledgers_teller::{account_of, sats, x_of, Error};
//!
//! let x = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
//! let did = format!("did:nostr:{x}");
//! assert_eq!(account_of(&did).unwrap(), did);
//! assert_eq!(account_of(&format!("  {}  ", x.to_uppercase())).unwrap(), did);
//! assert_eq!(account_of(&format!("fe70103{x}")).unwrap(), did);
//! assert_eq!(x_of(&did).unwrap(), x);
//! assert_eq!(account_of("npub1x"), Err(Error::Account));
//!
//! assert_eq!(sats(" 123 ").unwrap(), 123);
//! assert_eq!(sats("1.5"), Err(Error::Amount));
//! assert_eq!(sats("2100000000000001"), Err(Error::Amount));
//! ```

use crate::error::{Error, Result};

/// The most satoshis there can be: 21 million coins (`21e14`).
pub const MAX_SATS: u64 = 2_100_000_000_000_000;

/// `String.prototype.trim`: ECMAScript's WhiteSpace and LineTerminator,
/// which differ from Rust's `char::is_whitespace` at U+FEFF (trimmed here)
/// and U+0085 (kept here).
pub(crate) fn js_trim(s: &str) -> &str {
    s.trim_matches(|c: char| {
        matches!(
            c,
            '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
                ..='\u{200a}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202f}'
                    | '\u{205f}'
                    | '\u{3000}'
                    | '\u{feff}'
        )
    })
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// `accountOf`: `did:nostr:<x>` from a did, a bare x or a did:nostr Multikey,
/// trimmed and in lower case; anything else is [`Error::Account`]. The x is
/// not checked against the curve (the teller does not; a deposit address for
/// an x off the curve is refused when it is derived).
pub fn account_of(id: &str) -> Result<String> {
    let s = js_trim(id).to_lowercase();
    let bare = s.strip_prefix("did:nostr:").unwrap_or(&s);
    let x = if is_hex64(bare) {
        bare
    } else if let Some(x) = s
        .strip_prefix("fe70102")
        .or_else(|| s.strip_prefix("fe70103"))
        .filter(|x| is_hex64(x))
    {
        x
    } else {
        return Err(Error::Account);
    };
    Ok(format!("did:nostr:{x}"))
}

/// `xOf`: the 64-hex x of an account (whatever [`account_of`] reads).
pub fn x_of(account: &str) -> Result<String> {
    Ok(account_of(account)?["did:nostr:".len()..].to_owned())
}

/// `sats` on text: a string of ASCII digits (surrounding whitespace ignored)
/// naming 0 to [`MAX_SATS`], or [`Error::Amount`]. The ledger writes amounts
/// this way.
pub fn sats(text: &str) -> Result<u64> {
    let t = js_trim(text);
    if t.is_empty() || !t.bytes().all(|c| c.is_ascii_digit()) {
        return Err(Error::Amount);
    }
    // more than 16 significant digits is beyond 21e14 whatever follows
    let digits = t.trim_start_matches('0');
    if digits.len() > 16 {
        return Err(Error::Amount);
    }
    let n: u64 = if digits.is_empty() {
        0
    } else {
        digits.parse().map_err(|_| Error::Amount)?
    };
    check_sats(n)
}

/// `sats` on a number: `n` itself when it is at most [`MAX_SATS`], else
/// [`Error::Amount`]. (A `u64` is never negative or fractional, the other two
/// refusals `sats` makes of a JavaScript number.)
pub fn check_sats(n: u64) -> Result<u64> {
    if n > MAX_SATS {
        Err(Error::Amount)
    } else {
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_trim_is_ecmascript_trim() {
        assert_eq!(js_trim("\u{feff}\u{3000} 7\t\n"), "7");
        assert_eq!(js_trim("\u{85}7"), "\u{85}7");
    }

    #[test]
    fn sats_reads_digits_only() {
        assert_eq!(sats("0").unwrap(), 0);
        assert_eq!(sats("000123").unwrap(), 123);
        assert_eq!(sats("2100000000000000").unwrap(), MAX_SATS);
        for bad in [
            "",
            " ",
            "-1",
            "+1",
            "1e3",
            "0x10",
            "1_000",
            "１",
            "99999999999999999999999",
        ] {
            assert_eq!(sats(bad), Err(Error::Amount), "{bad:?}");
        }
    }

    #[test]
    fn multikey_and_did_forms() {
        let x = "ab".repeat(32);
        assert_eq!(
            account_of(&format!("fe70102{x}")).unwrap(),
            format!("did:nostr:{x}")
        );
        assert_eq!(
            account_of(&format!("DID:NOSTR:{x}")).unwrap(),
            format!("did:nostr:{x}")
        );
        assert_eq!(account_of(&format!("fe70104{x}")), Err(Error::Account));
        assert_eq!(
            account_of(&format!("did:nostr:fe70102{x}")),
            Err(Error::Account)
        );
        assert_eq!(account_of(&x[1..]), Err(Error::Account));
    }
}
