//! The rule's records (proposals/evm.md "Records"): `OP_RETURN` outputs whose
//! one push starts `evm:`, `evmin:` or `evmroot:`. A port of the codecs in
//! `siding/lib/overlays/evm.mjs` (`pushData`, `opReturnBytes`, `withPrefix`,
//! `carrierScript`, `depositScript`, `rootScript` and the `parse*`
//! functions), byte for byte.
//!
//! | record | where | what it says |
//! |---|---|---|
//! | `evm:` + RLP | any output of a non-coinbase transaction | a signed Ethereum transaction, run in output order |
//! | `evmin:` + 20 bytes | right after an output paying the reserve | a deposit: that output's sats credit the address × 10⁹ wei |
//! | `evmroot:` + 32 bytes | the coinbase | the state root after the block |
//!
//! The reader takes `6a`, then `4c` and a length byte, or `4d` and a
//! little-endian length word, or any other single byte as the length, and
//! exactly that many bytes after it: the reference's grammar, so a short push
//! written with `OP_PUSHDATA1` is read, as there, and a script with anything
//! after the push is not a record.
//!
//! ```
//! use sidestr_evm::records::{carrier_script, parse_carrier, parse_root, root_script};
//!
//! let rlp = [0xc0u8; 300];
//! let script = carrier_script(&rlp).unwrap();
//! assert_eq!(&script.as_bytes()[..4], &[0x6a, 0x4d, 0x30, 0x01]); // OP_PUSHDATA2, 304 bytes
//! assert_eq!(parse_carrier(&script), Some(&rlp[..]));
//!
//! let root = alloy_primitives::B256::repeat_byte(0x5a);
//! assert_eq!(parse_root(&root_script(root)), Some(root));
//! ```

use alloy_primitives::{address, Address, B256};
use bitcoin::{Script, ScriptBuf};

use crate::error::{Error, Result};

/// The withdrawal address (`evm.mjs WITHDRAW`, "sidestr"): value sent to it
/// with a 34-byte script as data leaves the EVM and is paid by the coinbase.
pub const WITHDRAW: Address = address!("00000000000000000000000000000000000501de");

/// Wei in one gwei, and so in one sat: the rule's fixed rate (`evm.mjs GWEI`).
pub const GWEI: u64 = 1_000_000_000;

/// The carrier record's prefix.
pub const CARRIER_PREFIX: &[u8] = b"evm:";
/// The deposit record's prefix.
pub const DEPOSIT_PREFIX: &[u8] = b"evmin:";
/// The root record's prefix.
pub const ROOT_PREFIX: &[u8] = b"evmroot:";

/// `OP_RETURN` and one push of `data`, in the form `evm.mjs pushData`
/// writes: a direct push up to 75 bytes, `OP_PUSHDATA1` up to 255,
/// `OP_PUSHDATA2` above. Longer than 65,535 bytes is [`Error::Record`]: the
/// reference writes a length byte that has wrapped there.
pub fn push_data(data: &[u8]) -> Result<ScriptBuf> {
    let n = data.len();
    let mut out = Vec::with_capacity(n + 4);
    out.push(0x6a);
    match n {
        0..=75 => out.push(n as u8),
        76..=255 => out.extend_from_slice(&[0x4c, n as u8]),
        256..=65_535 => out.extend_from_slice(&[0x4d, (n & 0xff) as u8, (n >> 8) as u8]),
        _ => {
            return Err(Error::Record(format!(
                "a record carries at most 65,535 bytes, not {n}"
            )))
        }
    }
    out.extend_from_slice(data);
    Ok(ScriptBuf::from_bytes(out))
}

/// The pushed bytes of an `OP_RETURN` output as `evm.mjs opReturnBytes`
/// reads them, or `None`.
pub fn op_return_bytes(script: &Script) -> Option<&[u8]> {
    let (n, data) = match script.as_bytes() {
        [0x6a, 0x4c, n, rest @ ..] => (usize::from(*n), rest),
        [0x6a, 0x4d, lo, hi, rest @ ..] => (usize::from(*lo) | usize::from(*hi) << 8, rest),
        [0x6a, n, rest @ ..] => (usize::from(*n), rest),
        _ => return None,
    };
    (data.len() == n).then_some(data)
}

/// The bytes after `prefix`, when `data` starts with it and has more
/// (`evm.mjs withPrefix`: a bare prefix is not a record).
fn with_prefix<'a>(data: Option<&'a [u8]>, prefix: &[u8]) -> Option<&'a [u8]> {
    let data = data?;
    (data.len() > prefix.len() && data.starts_with(prefix)).then(|| &data[prefix.len()..])
}

fn record(prefix: &[u8], body: &[u8]) -> Result<ScriptBuf> {
    let mut data = Vec::with_capacity(prefix.len() + body.len());
    data.extend_from_slice(prefix);
    data.extend_from_slice(body);
    push_data(&data)
}

/// A carrier: `OP_RETURN evm:<rlp>`, `rlp` being a signed Ethereum
/// transaction as it is broadcast (`evm.mjs carrierScript`).
pub fn carrier_script(rlp: &[u8]) -> Result<ScriptBuf> {
    record(CARRIER_PREFIX, rlp)
}

/// A deposit marker: `OP_RETURN evmin:<address>` (`evm.mjs depositScript`).
/// It credits `address` only when the output before it pays the reserve.
pub fn deposit_script(address: Address) -> ScriptBuf {
    record(DEPOSIT_PREFIX, address.as_slice()).expect("26 bytes")
}

/// The root record: `OP_RETURN evmroot:<root>` (`evm.mjs rootScript`).
pub fn root_script(root: B256) -> ScriptBuf {
    record(ROOT_PREFIX, root.as_slice()).expect("40 bytes")
}

/// The transaction bytes a carrier holds (`evm.mjs parseCarrier`).
pub fn parse_carrier(script: &Script) -> Option<&[u8]> {
    with_prefix(op_return_bytes(script), CARRIER_PREFIX)
}

/// The address a deposit marker credits: exactly 20 bytes after the prefix
/// (`evm.mjs parseDeposit`).
pub fn parse_deposit(script: &Script) -> Option<Address> {
    with_prefix(op_return_bytes(script), DEPOSIT_PREFIX)
        .filter(|b| b.len() == 20)
        .map(Address::from_slice)
}

/// The state root a root record commits: exactly 32 bytes after the prefix
/// (`evm.mjs parseRoot`).
pub fn parse_root(script: &Script) -> Option<B256> {
    with_prefix(op_return_bytes(script), ROOT_PREFIX)
        .filter(|b| b.len() == 32)
        .map(B256::from_slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_forms() {
        for (n, head) in [
            (0usize, vec![0x6a, 0x00]),
            (75, vec![0x6a, 75]),
            (76, vec![0x6a, 0x4c, 76]),
            (255, vec![0x6a, 0x4c, 255]),
            (256, vec![0x6a, 0x4d, 0x00, 0x01]),
            (65_535, vec![0x6a, 0x4d, 0xff, 0xff]),
        ] {
            let data = vec![7u8; n];
            let s = push_data(&data).unwrap();
            assert_eq!(&s.as_bytes()[..head.len()], &head[..], "{n}");
            assert_eq!(op_return_bytes(&s), Some(&data[..]), "{n}");
        }
        assert!(push_data(&vec![0u8; 65_536]).is_err());
    }

    #[test]
    fn reading_follows_the_reference() {
        let s = |b: &[u8]| ScriptBuf::from_bytes(b.to_vec());
        // a short push through OP_PUSHDATA1 is read
        assert_eq!(parse_carrier(&s(b"\x6a\x4c\x05evm:x")), Some(&b"x"[..]));
        // nothing after the prefix, a length one short, trailing bytes, OP_PUSHDATA4: not records
        assert_eq!(parse_carrier(&s(b"\x6a\x04evm:")), None);
        assert_eq!(parse_carrier(&s(b"\x6a\x05evm:")), None);
        assert_eq!(parse_carrier(&s(b"\x6a\x05evm:xy")), None);
        assert_eq!(parse_carrier(&s(b"\x6a\x4e\x05\x00\x00\x00evm:x")), None);
        assert_eq!(op_return_bytes(&s(b"\x6a")), None);
        assert_eq!(op_return_bytes(&s(b"\x6a\x4c")), None);
        assert_eq!(op_return_bytes(&s(b"\x6a\x00")), Some(&b""[..]));
        // a deposit is exactly 20 bytes, a root exactly 32
        let mut d = b"evmin:".to_vec();
        d.extend_from_slice(&[1u8; 21]);
        assert_eq!(parse_deposit(&push_data(&d).unwrap()), None);
        let a = Address::repeat_byte(3);
        assert_eq!(parse_deposit(&deposit_script(a)), Some(a));
        // `evmin:` and `evmroot:` are not carriers: the byte after `evm` is not `:`
        assert_eq!(parse_carrier(&deposit_script(a)), None);
        assert_eq!(parse_carrier(&root_script(B256::ZERO)), None);
    }
}
