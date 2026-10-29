//! Witness for the compact-truncation boundary of SPEC 4 step 1
//! (`check_pow`): `bits` is pinned to `powLimit.to_compact()` and the
//! hash is compared against `Target::from_compact(bits)` — the powLimit
//! truncated to its three most significant bytes — never against the
//! document's full `powLimit`, and the comparison is inclusive.
//!
//! For the usual `7fff…ff` limit the enforced target is `7fffff00…00`: a
//! hash equal to it meets the limit and a hash one LSB above it does not,
//! even though that hash is still below the full `powLimit`. If `meets`
//! were exclusive, or if the comparator were the full `powLimit`, the two
//! `check_pow` assertions below would flip.

use sidestr_header::{check_pow, BlockHash, Error, Target};

/// The `powLimit` of the dreamlab chain document (SPEC 3).
const POW_LIMIT_HEX: &str = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// `expandCompact` of those bits: powLimit cut to three significant bytes.
const TRUNCATED_HEX: &str = "7fffff0000000000000000000000000000000000000000000000000000000000";

#[test]
fn check_pow_enforces_the_truncated_compact_target() {
    let lim = Target::from_hex(POW_LIMIT_HEX).unwrap();
    // SPEC 4 step 1: every block carries the compact form of powLimit.
    assert_eq!(lim.to_compact(), 0x207f_ffff);
    // The comparator that compact form expands back to.
    let enforced = Target::from_compact(0x207f_ffff).unwrap();
    assert_eq!(enforced.to_string(), TRUNCATED_HEX);

    // On the boundary: the hash equals the enforced target, and the
    // comparison is `<=`, so it passes.
    let on_boundary = BlockHash::from_hex(TRUNCATED_HEX).unwrap();
    assert!(check_pow(0x207f_ffff, on_boundary, &lim).is_ok());

    // One LSB above the enforced target is still below the full powLimit,
    // so only the comparator decides: the truncated target refuses it.
    let above_hex = "7fffff0000000000000000000000000000000000000000000000000000000001";
    let just_above = BlockHash::from_hex(above_hex).unwrap();
    assert!(just_above.meets(&lim));
    let verdict = check_pow(0x207f_ffff, just_above, &lim);
    assert!(matches!(verdict, Err(Error::TargetNotMet)));
}
