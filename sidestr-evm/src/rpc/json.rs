//! `JSON.stringify` of a JSON value, byte for byte: numbers as JavaScript
//! doubles print (`1e+21`, `12345678901234567000`, `0` for `-0`), an
//! object's array-index keys first in ascending order and then the rest as
//! inserted (the order a JavaScript object keeps), and no white space.
//! Strings escape as `serde_json` escapes them, which is what
//! `JSON.stringify` does for well-formed text.

use serde_json::{Map, Value};

use super::js::number_to_string;

/// The text `JSON.stringify(value)` makes.
pub(crate) fn stringify(value: &Value) -> String {
    let mut out = String::new();
    write(value, &mut out);
    out
}

fn write(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => match n.as_f64() {
            Some(x) if x.is_finite() => out.push_str(&number_to_string(x)),
            _ => out.push_str("null"),
        },
        Value::String(s) => out.push_str(&serde_json::to_string(s).expect("a string serialises")),
        Value::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(e, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, e)) in ordered(m).into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("a string serialises"));
                out.push(':');
                write(e, out);
            }
            out.push('}');
        }
    }
}

/// A canonical array index: `0`, or digits without a leading zero, below
/// 2^32 − 1.
fn array_index(k: &str) -> Option<u32> {
    if k.is_empty() || (k.len() > 1 && k.starts_with('0')) || !k.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    k.parse::<u32>().ok().filter(|i| *i < u32::MAX)
}

/// The keys in the order a JavaScript object enumerates them.
fn ordered(m: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut indices: Vec<(u32, &String, &Value)> = m
        .iter()
        .filter_map(|(k, v)| array_index(k).map(|i| (i, k, v)))
        .collect();
    indices.sort_by_key(|(i, _, _)| *i);
    let mut out: Vec<(&String, &Value)> = indices.into_iter().map(|(_, k, v)| (k, v)).collect();
    out.extend(m.iter().filter(|(k, _)| array_index(k).is_none()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_javascript_writes_it() {
        let v: Value = serde_json::from_str(
            r#"{"b":1,"2":2,"1":3,"01":4,"a":5,"4294967295":6,"4294967294":7,"n":[12345678901234567890,1e21,-0,1.0,1e-7,"x\u0001 "]}"#,
        )
        .unwrap();
        assert_eq!(
            stringify(&v),
            "{\"1\":3,\"2\":2,\"4294967294\":7,\"b\":1,\"01\":4,\"a\":5,\"4294967295\":6,\"n\":[12345678901234567000,1e+21,0,1,1e-7,\"x\\u0001\u{2028}\"]}"
        );
    }
}
