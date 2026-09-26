//! JavaScript's reading of a JSON value, as far as `evmrpc.mjs` leans on it:
//! a missing member is `undefined` (here `None`), truthiness, `String(…)`,
//! `BigInt(…)`, array destructuring of the params, property reads that throw
//! on `null` and `undefined`, the number formatting of `Number#toString`
//! (which `JSON.stringify` shares), and the few helpers of
//! `@ethereumjs/util` the handler calls (`hexToBytes`, `setLengthLeft`,
//! `createAddressFromString`). The error texts are V8's (Node 22) and
//! ethereumjs's, so an answer reads as the reference's does.

use alloy_primitives::{Address, U256};
use serde_json::Value;

use super::RpcError;

/// A JavaScript value as the handler sees it: `None` is `undefined`.
pub(crate) type Js<'a> = Option<&'a Value>;

/// A thrown error without a code, answered as -32000.
pub(crate) fn thrown(message: impl Into<String>) -> RpcError {
    RpcError::new(-32000, message)
}

/// `!!v`.
pub(crate) fn truthy(v: Js<'_>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(_) | Value::Object(_)) => true,
    }
}

/// `v === undefined || v === null`, the left of `??`.
pub(crate) fn nullish(v: Js<'_>) -> bool {
    matches!(v, None | Some(Value::Null))
}

/// `Number#toString()` and `JSON.stringify` of a number: the shortest digits
/// that read back the same, positional from 1e-7 up to 1e21, exponential
/// outside, `-0` as `0`.
pub(crate) fn number_to_string(x: f64) -> String {
    if x.is_nan() {
        return "NaN".into();
    }
    if x == 0.0 {
        return "0".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    let sign = if x < 0.0 { "-" } else { "" };
    // Rust's `{:e}` prints the shortest round-trip digits: d[.ddd]e<exp>
    let sci = format!("{:e}", x.abs());
    let (mantissa, exp) = sci.split_once('e').expect("LowerExp has an exponent");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i64;
    let n = exp.parse::<i64>().expect("an integer exponent") + 1;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let e = if e < 0 {
            format!("-{}", -e)
        } else {
            format!("+{e}")
        };
        if k == 1 {
            format!("{digits}e{e}")
        } else {
            format!("{}.{}e{e}", &digits[..1], &digits[1..])
        }
    };
    format!("{sign}{body}")
}

/// `String(v)` (and a template literal's `${v}`).
pub(crate) fn to_string(v: Js<'_>) -> String {
    match v {
        None => "undefined".into(),
        Some(v) => value_to_string(v),
    }
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => number_to_string(n.as_f64().unwrap_or(f64::NAN)),
        Value::String(s) => s.clone(),
        // Array#join: null and undefined are empty
        Value::Array(a) => a
            .iter()
            .map(|e| match e {
                Value::Null => String::new(),
                e => value_to_string(e),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

/// `v.<key>`: `undefined` for a primitive or a missing member; a
/// `TypeError` on `null` and `undefined`.
pub(crate) fn prop<'a>(v: Js<'a>, key: &str) -> Result<Js<'a>, RpcError> {
    match v {
        None => Err(thrown(format!(
            "Cannot read properties of undefined (reading '{key}')"
        ))),
        Some(Value::Null) => Err(thrown(format!(
            "Cannot read properties of null (reading '{key}')"
        ))),
        Some(Value::Object(m)) => Ok(m.get(key)),
        Some(_) => Ok(None),
    }
}

/// The params as `([a, b]) => …` destructures them: an array's elements, a
/// string's characters (by code point, as the string iterator yields them),
/// nothing for `undefined` (the handler's `params = []`), and V8's
/// `TypeError` for anything else.
pub(crate) fn params(v: Js<'_>) -> Result<Vec<Value>, RpcError> {
    let not = |what: String| {
        thrown(format!(
            "{what} is not iterable (cannot read property Symbol(Symbol.iterator))"
        ))
    };
    match v {
        None => Ok(Vec::new()),
        Some(Value::Array(a)) => Ok(a.clone()),
        Some(Value::String(s)) => Ok(s.chars().map(|c| Value::String(c.into())).collect()),
        Some(Value::Null) => Err(not("object null".into())),
        Some(Value::Object(_)) => Err(not("object".into())),
        Some(Value::Number(n)) => Err(not(format!(
            "number {}",
            number_to_string(n.as_f64().unwrap_or(f64::NAN))
        ))),
        Some(Value::Bool(b)) => Err(not(format!("boolean {b}"))),
    }
}

/// A `BigInt`: its sign and magnitude, the magnitude `None` when it needs
/// more than 256 bits (more than any balance, gas or height).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BigInt {
    pub(crate) negative: bool,
    pub(crate) magnitude: Option<U256>,
}

impl BigInt {
    fn positive(magnitude: Option<U256>) -> Self {
        Self {
            negative: false,
            magnitude,
        }
    }

    /// `Number(b)`, closely enough for comparisons with heights and for
    /// array lengths: exact up to 2^128, infinite beyond 256 bits.
    pub(crate) fn to_f64(self) -> f64 {
        let m = match self.magnitude {
            None => f64::INFINITY,
            Some(m) => match u128::try_from(m) {
                Ok(v) => v as f64,
                Err(_) => {
                    // the leading 128 bits, scaled: more precision than an f64 holds
                    let shift = m.bit_len() - 128;
                    (u128::try_from(m >> shift).unwrap_or(u128::MAX) as f64)
                        * 2f64.powi(shift as i32)
                }
            },
        };
        if self.negative {
            -m
        } else {
            m
        }
    }
}

/// JavaScript's white space and line terminators, which `BigInt("…")` trims.
fn js_space(c: char) -> bool {
    const SPACES: &[char] = &[
        '\u{9}', '\u{a}', '\u{b}', '\u{c}', '\u{d}', ' ', '\u{a0}', '\u{1680}', '\u{2028}',
        '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}', '\u{feff}',
    ];
    SPACES.contains(&c) || ('\u{2000}'..='\u{200a}').contains(&c)
}

/// Digits in `radix`, at least one, into 256 bits (`None` past them).
fn digits(s: &str, radix: u64) -> Option<Option<U256>> {
    if s.is_empty() {
        return None;
    }
    let mut acc = Some(U256::ZERO);
    for c in s.chars() {
        let d = c.to_digit(radix as u32)?;
        acc = acc
            .and_then(|a| a.checked_mul(U256::from(radix)))
            .and_then(|a| a.checked_add(U256::from(d)));
    }
    Some(acc)
}

/// `StringToBigInt`: trimmed; empty is 0; `0x`, `0o`, `0b` without a sign;
/// otherwise decimal with an optional sign.
fn string_to_bigint(original: &str) -> Result<BigInt, RpcError> {
    let bad = || thrown(format!("Cannot convert {original} to a BigInt"));
    let s = original.trim_matches(js_space);
    if s.is_empty() {
        return Ok(BigInt::positive(Some(U256::ZERO)));
    }
    let prefixed = |p: [&str; 2], radix| {
        p.iter()
            .find_map(|p| s.strip_prefix(p))
            .map(|rest| digits(rest, radix))
    };
    for (p, radix) in [(["0x", "0X"], 16), (["0o", "0O"], 8), (["0b", "0B"], 2)] {
        if let Some(m) = prefixed(p, radix) {
            return m.map(BigInt::positive).ok_or_else(bad);
        }
    }
    let (negative, rest) = match s.as_bytes()[0] {
        b'-' => (true, &s[1..]),
        b'+' => (false, &s[1..]),
        _ => (false, s),
    };
    let magnitude = digits(rest, 10).ok_or_else(bad)?;
    Ok(BigInt {
        negative: negative && magnitude != Some(U256::ZERO),
        magnitude,
    })
}

/// An integral `f64` as a `U256`, `None` from 2^256 up.
fn f64_to_u256(x: f64) -> Option<U256> {
    if x < 1.0 {
        return Some(U256::ZERO);
    }
    let bits = x.to_bits();
    let exp = ((bits >> 52) & 0x7ff) as i64 - 1075;
    let mantissa = (bits & ((1 << 52) - 1)) | (1 << 52);
    if exp < 0 {
        return Some(U256::from(mantissa >> (-exp)));
    }
    let m = U256::from(mantissa);
    (m.bit_len() as i64 + exp <= 256).then(|| m << (exp as usize))
}

/// `BigInt(v)`, with V8's errors.
pub(crate) fn bigint(v: Js<'_>) -> Result<BigInt, RpcError> {
    match v {
        None => Err(thrown("Cannot convert undefined to a BigInt")),
        Some(Value::Null) => Err(thrown("Cannot convert null to a BigInt")),
        Some(Value::Bool(b)) => Ok(BigInt::positive(Some(U256::from(u8::from(*b))))),
        Some(Value::Number(n)) => {
            let x = n.as_f64().unwrap_or(f64::NAN);
            if !x.is_finite() || x.fract() != 0.0 {
                return Err(thrown(format!(
                    "The number {} cannot be converted to a BigInt because it is not an integer",
                    number_to_string(x)
                )));
            }
            Ok(BigInt {
                negative: x < 0.0,
                magnitude: f64_to_u256(x.abs()),
            })
        }
        Some(Value::String(s)) => string_to_bigint(s),
        // ToPrimitive: an array or object is read through its string
        Some(v @ (Value::Array(_) | Value::Object(_))) => string_to_bigint(&value_to_string(v)),
    }
}

/// `@ethereumjs/util` `hexToBytes`: `0x` required; the prefix stripped only
/// when the rest is hex, an odd length padded with a leading `0`, then read
/// in pairs by noble's decoder (Node 22 has no `Uint8Array.fromHex`), whose
/// complaint names the first pair that is not hex and its index.
pub(crate) fn hex_to_bytes(v: Js<'_>) -> Result<Vec<u8>, RpcError> {
    let s = match v {
        Some(Value::String(s)) => s.as_str(),
        None => {
            return Err(thrown(
                "Cannot read properties of undefined (reading 'startsWith')",
            ))
        }
        Some(Value::Null) => {
            return Err(thrown(
                "Cannot read properties of null (reading 'startsWith')",
            ))
        }
        Some(_) => return Err(thrown("hex.startsWith is not a function")),
    };
    if !s.starts_with("0x") {
        return Err(thrown("input string must be 0x prefixed"));
    }
    let rest = &s[2..];
    let body = if rest.bytes().all(|b| b.is_ascii_hexdigit()) {
        rest
    } else {
        s
    };
    let mut units: Vec<u16> = body.encode_utf16().collect();
    if units.len() % 2 == 1 {
        units.insert(0, u16::from(b'0'));
    }
    let nibble = |u: u16| char::from_u32(u32::from(u)).and_then(|c| c.to_digit(16));
    let mut out = Vec::with_capacity(units.len() / 2);
    for (i, pair) in units.chunks(2).enumerate() {
        match (nibble(pair[0]), nibble(pair[1])) {
            (Some(hi), Some(lo)) => out.push((hi * 16 + lo) as u8),
            _ => {
                return Err(thrown(format!(
                    "hex string expected, got non-hex character \"{}\" at index {}",
                    String::from_utf16_lossy(pair),
                    i * 2
                )))
            }
        }
    }
    Ok(out)
}

/// `setLengthLeft(bytes, 32)` without `allowTruncate`: zeros in front, and
/// more than 32 bytes refused.
pub(crate) fn set_length_left_32(bytes: &[u8]) -> Result<[u8; 32], RpcError> {
    if bytes.len() > 32 {
        return Err(thrown(format!(
            "Input length {} exceeds target length 32. Use allowTruncate option to truncate.",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

/// `evmrpc.mjs addr`: `createAddressFromString(String(a).toLowerCase())`.
pub(crate) fn address(v: Js<'_>) -> Result<Address, RpcError> {
    let s = to_string(v).to_lowercase();
    let body = s
        .strip_prefix("0x")
        .filter(|b| b.len() == 40 && b.bytes().all(|c| c.is_ascii_hexdigit()));
    match body {
        Some(b) => Ok(Address::from_slice(&hex::decode(b).expect("40 hex digits"))),
        None => Err(thrown(format!("Invalid address input={s}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn numbers_print_as_javascript_prints_them() {
        for (x, s) in [
            (1e21, "1e+21"),
            (1.5e-7, "1.5e-7"),
            (123456789012345680000.0, "123456789012345680000"),
            (-0.0, "0"),
            (0.1, "0.1"),
            (1e-7, "1e-7"),
            (1e-6, "0.000001"),
            (9007199254740994.0, "9007199254740994"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (12345678901234567890.0, "12345678901234567000"),
            (-1.5, "-1.5"),
            (100.0, "100"),
            (123.456, "123.456"),
        ] {
            assert_eq!(number_to_string(x), s, "{x}");
        }
    }

    #[test]
    fn bigint_reads_as_v8_does() {
        let ok = |v: Value| bigint(Some(&v)).unwrap();
        let err = |v: Value| bigint(Some(&v)).unwrap_err().message;
        assert_eq!(ok(json!(" 0x10 ")).magnitude, Some(U256::from(16)));
        assert_eq!(ok(json!("")).magnitude, Some(U256::ZERO));
        assert_eq!(ok(json!([])).magnitude, Some(U256::ZERO));
        assert_eq!(ok(json!(["0x5"])).magnitude, Some(U256::from(5)));
        assert_eq!(ok(json!(true)).magnitude, Some(U256::from(1)));
        assert_eq!(ok(json!("0b101")).magnitude, Some(U256::from(5)));
        assert_eq!(ok(json!("0o17")).magnitude, Some(U256::from(15)));
        assert_eq!(ok(json!("\u{a0} 7\n")).magnitude, Some(U256::from(7)));
        assert!(ok(json!("-7")).negative);
        assert!(!ok(json!("-0")).negative);
        assert_eq!(ok(json!(1e21)).magnitude, Some(U256::from(10u128.pow(21))));
        assert_eq!(
            ok(json!("0x1".to_string() + &"0".repeat(64))).magnitude,
            None
        );
        assert_eq!(err(json!("abc")), "Cannot convert abc to a BigInt");
        assert_eq!(err(json!("-0x5")), "Cannot convert -0x5 to a BigInt");
        assert_eq!(err(json!("1e3")), "Cannot convert 1e3 to a BigInt");
        assert_eq!(err(json!({})), "Cannot convert [object Object] to a BigInt");
        assert_eq!(err(json!(null)), "Cannot convert null to a BigInt");
        assert_eq!(
            err(json!(1.5)),
            "The number 1.5 cannot be converted to a BigInt because it is not an integer"
        );
        assert_eq!(
            bigint(None).unwrap_err().message,
            "Cannot convert undefined to a BigInt"
        );
    }

    #[test]
    fn hex_reads_as_ethereumjs_does() {
        let h = |s: &str| hex_to_bytes(Some(&json!(s)));
        assert_eq!(h("0x").unwrap(), Vec::<u8>::new());
        assert_eq!(h("0x123").unwrap(), vec![0x01, 0x23]);
        assert_eq!(h("0xAb").unwrap(), vec![0xab]);
        let m = |s: &str| h(s).unwrap_err().message;
        assert_eq!(m("1234"), "input string must be 0x prefixed");
        assert_eq!(
            m("0xzz"),
            "hex string expected, got non-hex character \"0x\" at index 0"
        );
        assert_eq!(
            m("0xzz1"),
            "hex string expected, got non-hex character \"xz\" at index 2"
        );
        assert_eq!(
            hex_to_bytes(Some(&json!(5))).unwrap_err().message,
            "hex.startsWith is not a function"
        );
    }

    #[test]
    fn strings_as_javascript_makes_them() {
        assert_eq!(
            to_string(Some(&json!([null, ["a", 1.5], true]))),
            ",a,1.5,true"
        );
        assert_eq!(to_string(Some(&json!({"a": 1}))), "[object Object]");
        assert_eq!(to_string(None), "undefined");
        assert!(
            !truthy(Some(&json!(""))) && truthy(Some(&json!("false"))) && !truthy(Some(&json!(0)))
        );
    }
}
