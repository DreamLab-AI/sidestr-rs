//! The tapscript leaves of a Hitch payment channel, accepted on transaction
//! inputs by exact template.
//!
//! [Hitch](https://github.com/bitcoin-blake/hitch) (Melvin Carvalho,
//! `lib/channel.mjs` at `62f8e39`; ported as `sidestr-hitch` 0.2.0) locks a
//! channel in a taproot output whose internal key is unspendable, so every
//! spend of a channel coin goes by script path: the cooperative close and
//! each commitment spend the 2-of-2 funding leaf; a force-close's outputs are
//! swept through a delayed leaf, taken through a revocation leaf, or claimed
//! through an HTLC's success or timeout leaf. The reference kernel executes
//! any tapscript. This crate has no script interpreter: it recognises exactly
//! the seven leaf shapes Hitch writes ([`ChannelLeaf`]), byte for byte, and
//! checks each one's meaning with the primitives the `bitcoin` and
//! `secp256k1` crates provide — the control block's commitment to the output
//! key, the TapLeaf hash, the signature hash and BIP 340 — plus the three
//! comparisons BIP 65, BIP 112 and `OP_SHA256 … OP_EQUALVERIFY` make. Any
//! other leaf is refused by name ([`ChannelError::NotATemplate`]).
//!
//! | leaf | bytes | Hitch role |
//! |---|---|---|
//! | [`ChannelLeaf::Funding`] | `<k1> CHECKSIG <k2> CHECKSIGADD 2 NUMEQUAL` | the funding output: every commitment and the cooperative close |
//! | [`ChannelLeaf::Key`] | `<k> CHECKSIG` | revocation: the penalty on a revoked `to_local` or HTLC output |
//! | [`ChannelLeaf::Delayed`] | `<d> CSV DROP <k> CHECKSIG` | `to_local`: the owner's sweep after the channel delay |
//! | [`ChannelLeaf::HashLock`] | `SHA256 <h> EQUALVERIFY <k> CHECKSIG` | an HTLC the owner offered: the receiver's success claim |
//! | [`ChannelLeaf::HashLockDelayed`] | `SHA256 <h> EQUALVERIFY <d> CSV DROP <k> CHECKSIG` | an HTLC the owner received: the owner's success claim |
//! | [`ChannelLeaf::Timeout`] | `<e> CLTV DROP <k> CHECKSIG` | an HTLC the owner received: the offerer's refund |
//! | [`ChannelLeaf::TimeoutDelayed`] | `<e> CLTV DROP <d> CSV DROP <k> CHECKSIG` | an HTLC the owner offered: the owner's refund |
//!
//! Numbers are written as Hitch's `pushNum` writes them: `OP_0`, `OP_1` to
//! `OP_16`, or the shortest little-endian push with a sign byte when the top
//! bit is set; a delay is a block count of at most `0xffff`, an expiry a block
//! height below [`LOCKTIME_THRESHOLD`]. A non-minimal push, a time-based lock
//! or a delay with BIP 68's type flag is not the template: the reference
//! engine cannot judge a time-based lock without median-time-past and skips
//! it, so this crate refuses it rather than accept an unenforced lock.
//!
//! # What the script checks and what the block checks
//!
//! `OP_CHECKSEQUENCEVERIFY` compares the script's delay with the *input's*
//! `nSequence`; it does not know how deep the coin is. That is BIP 68's rule
//! at the block, `btc:rule-blockctx-sequence-locks`
//! ([`crate::rules::resolve_spending`]): an input whose `nSequence` asks for
//! `d` blocks is valid only in a block at least `d` above the coin's. In the
//! same way `OP_CHECKLOCKTIMEVERIFY` compares the expiry with the
//! transaction's `nLockTime`, and `btc:rule-blockctx-finality` holds that to
//! the block's height. Both block rules are in force here and in the
//! reference kernel for every input, so a sweep before the delay passes this
//! module and is refused by the block — and by
//! [`crate::state::StateOf::submit`], which judges the two locks against the
//! next height before a transaction enters the mempool.
//!
//! ```
//! use bitcoin::secp256k1::{Keypair, SecretKey};
//! use sidestr_core::block::secp;
//! use sidestr_core::channel::ChannelLeaf;
//!
//! let key = Keypair::from_secret_key(secp(), &SecretKey::from_slice(&[7; 32]).unwrap())
//!     .x_only_public_key()
//!     .0;
//! let delayed = ChannelLeaf::Delayed { delay: 6, key };
//! let script = delayed.to_script();
//! assert_eq!(&script.as_bytes()[..3], &[0x56, 0xb2, 0x75]); // OP_6 CSV DROP
//! assert_eq!(ChannelLeaf::parse(&script), Some(delayed));
//!
//! // one byte more and it is not the template
//! let mut longer = script.to_bytes();
//! longer.push(0x51);
//! assert_eq!(ChannelLeaf::parse(bitcoin::Script::from_bytes(&longer)), None);
//! ```

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::sighash::{Annex, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use bitcoin::{Script, ScriptBuf, Transaction, TxOut};

use crate::block::{schnorr_verify, secp};
use crate::sighash::{unified_taproot_sighash, SighashRules, UnifiedTaproot, SIGHASH_UNIFIED};

/// `nLockTime` values below this are block heights, at or above it times
/// (`LOCKTIME_THRESHOLD` in Bitcoin Core). An expiry in a channel leaf is a
/// height, so it is below this.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// BIP 342's limit on a stack element, which Bitcoin Core applies to every
/// item of a tapscript's initial stack (`MAX_SCRIPT_ELEMENT_SIZE`).
pub const MAX_STACK_ELEMENT: usize = 520;

/// BIP 68's disable flag in `nSequence`: set, the input has no relative lock.
pub const SEQUENCE_DISABLE: u32 = 0x8000_0000;

/// BIP 68's type flag in `nSequence`: set, the relative lock counts 512-second
/// units rather than blocks.
pub const SEQUENCE_TYPE: u32 = 0x0040_0000;

/// BIP 68's value mask in `nSequence`.
pub const SEQUENCE_MASK: u32 = 0x0000_ffff;

/// One of the seven leaves Hitch writes, with the values it carries. The
/// table in the [module documentation](crate::channel) gives each one's bytes and role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelLeaf {
    /// The 2-of-2 funding leaf, `multi_a(2, k1, k2)`. Hitch sorts the keys
    /// lexicographically; either order is the template, since the signatures
    /// it demands are the same.
    Funding {
        /// The keys in leaf order: `k1` checks the top signature slot.
        keys: [XOnlyPublicKey; 2],
    },
    /// One key and nothing else: a revocation leaf.
    Key {
        /// The key whose signature spends.
        key: XOnlyPublicKey,
    },
    /// A key after a relative delay in blocks: the `to_local` owner's leaf.
    Delayed {
        /// Blocks the coin must be buried before the spend (BIP 68 / 112).
        delay: u16,
        /// The key whose signature spends.
        key: XOnlyPublicKey,
    },
    /// A key with the SHA-256 preimage of `hash`: an offered HTLC's success leaf.
    HashLock {
        /// SHA-256 of the payment preimage.
        hash: [u8; 32],
        /// The key whose signature spends.
        key: XOnlyPublicKey,
    },
    /// A key with the preimage and after a relative delay: a received
    /// HTLC's success leaf.
    HashLockDelayed {
        /// SHA-256 of the payment preimage.
        hash: [u8; 32],
        /// Blocks the coin must be buried before the spend.
        delay: u16,
        /// The key whose signature spends.
        key: XOnlyPublicKey,
    },
    /// A key after an absolute height: a received HTLC's timeout leaf.
    Timeout {
        /// The height `nLockTime` must reach (BIP 65), below [`LOCKTIME_THRESHOLD`].
        expiry: u32,
        /// The key whose signature spends.
        key: XOnlyPublicKey,
    },
    /// A key after an absolute height and a relative delay: an offered
    /// HTLC's timeout leaf.
    TimeoutDelayed {
        /// The height `nLockTime` must reach.
        expiry: u32,
        /// Blocks the coin must be buried before the spend.
        delay: u16,
        /// The key whose signature spends.
        key: XOnlyPublicKey,
    },
}

const OP_0: u8 = 0x00;
const OP_2: u8 = 0x52;
const OP_DROP: u8 = 0x75;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_NUMEQUAL: u8 = 0x9c;
const OP_SHA256: u8 = 0xa8;
const OP_CHECKSIG: u8 = 0xac;
const OP_CLTV: u8 = 0xb1;
const OP_CSV: u8 = 0xb2;
const OP_CHECKSIGADD: u8 = 0xba;

/// Hitch's `pushNum`: the minimal push of a non-negative number.
fn push_num(out: &mut Vec<u8>, n: u32) {
    if n == 0 {
        out.push(OP_0);
        return;
    }
    if n <= 16 {
        out.push(0x50 + n as u8);
        return;
    }
    let mut bytes = Vec::with_capacity(5);
    let mut v = n;
    while v > 0 {
        bytes.push((v & 0xff) as u8);
        v >>= 8;
    }
    if bytes.last().is_some_and(|b| b & 0x80 != 0) {
        bytes.push(0);
    }
    out.push(bytes.len() as u8);
    out.extend_from_slice(&bytes);
}

fn push_key(out: &mut Vec<u8>, key: &XOnlyPublicKey) {
    out.push(0x20);
    out.extend_from_slice(&key.serialize());
}

/// A cursor over a leaf's bytes that reads only the pieces the templates use.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn op(&mut self, op: u8) -> Option<()> {
        (self.bytes.get(self.at) == Some(&op)).then(|| self.at += 1)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn push32(&mut self) -> Option<&'a [u8]> {
        self.op(0x20)?;
        let b = self.bytes.get(self.at..self.at + 32)?;
        self.at += 32;
        Some(b)
    }

    fn key(&mut self) -> Option<XOnlyPublicKey> {
        XOnlyPublicKey::from_slice(self.push32()?).ok()
    }

    /// A number in exactly `push_num`'s encoding, or `None`.
    fn num(&mut self) -> Option<u32> {
        let first = self.peek()?;
        let n = match first {
            OP_0 => {
                self.at += 1;
                return Some(0);
            }
            0x51..=0x60 => {
                self.at += 1;
                return Some(u32::from(first - 0x50));
            }
            1..=5 => {
                let len = usize::from(first);
                let b = self.bytes.get(self.at + 1..self.at + 1 + len)?;
                if b.last().is_some_and(|x| x & 0x80 != 0) {
                    return None; // negative
                }
                let v = b
                    .iter()
                    .rev()
                    .try_fold(0u64, |acc, x| Some((acc << 8) | u64::from(*x)))?;
                u32::try_from(v).ok()?
            }
            _ => return None,
        };
        let mut canon = Vec::with_capacity(6);
        push_num(&mut canon, n);
        let len = canon.len();
        if self.bytes.get(self.at..self.at + len) != Some(canon.as_slice()) {
            return None;
        }
        self.at += len;
        Some(n)
    }

    fn done(&self) -> bool {
        self.at == self.bytes.len()
    }
}

impl ChannelLeaf {
    /// The leaf's script, exactly as Hitch writes it.
    pub fn to_script(&self) -> ScriptBuf {
        let mut s = Vec::with_capacity(80);
        let (hash, expiry, delay, key) = match *self {
            ChannelLeaf::Funding { keys } => {
                push_key(&mut s, &keys[0]);
                s.push(OP_CHECKSIG);
                push_key(&mut s, &keys[1]);
                s.extend_from_slice(&[OP_CHECKSIGADD, OP_2, OP_NUMEQUAL]);
                return ScriptBuf::from_bytes(s);
            }
            ChannelLeaf::Key { key } => (None, None, None, key),
            ChannelLeaf::Delayed { delay, key } => (None, None, Some(delay), key),
            ChannelLeaf::HashLock { hash, key } => (Some(hash), None, None, key),
            ChannelLeaf::HashLockDelayed { hash, delay, key } => {
                (Some(hash), None, Some(delay), key)
            }
            ChannelLeaf::Timeout { expiry, key } => (None, Some(expiry), None, key),
            ChannelLeaf::TimeoutDelayed { expiry, delay, key } => {
                (None, Some(expiry), Some(delay), key)
            }
        };
        if let Some(h) = hash {
            s.extend_from_slice(&[OP_SHA256, 0x20]);
            s.extend_from_slice(&h);
            s.push(OP_EQUALVERIFY);
        }
        if let Some(e) = expiry {
            push_num(&mut s, e);
            s.extend_from_slice(&[OP_CLTV, OP_DROP]);
        }
        if let Some(d) = delay {
            push_num(&mut s, u32::from(d));
            s.extend_from_slice(&[OP_CSV, OP_DROP]);
        }
        push_key(&mut s, &key);
        s.push(OP_CHECKSIG);
        ScriptBuf::from_bytes(s)
    }

    /// The template `script` is, with its values, or `None` when it is not
    /// exactly one of the seven: [`ChannelLeaf::to_script`] of the result is
    /// `script` byte for byte. An expiry at or above [`LOCKTIME_THRESHOLD`]
    /// or a delay above `0xffff` is not a template.
    pub fn parse(script: &Script) -> Option<Self> {
        let mut r = Reader {
            bytes: script.as_bytes(),
            at: 0,
        };
        // funding: <k1> CHECKSIG <k2> CHECKSIGADD 2 NUMEQUAL
        if script.len() == 70 && r.peek() == Some(0x20) && script.as_bytes()[33] == OP_CHECKSIG {
            let k1 = r.key()?;
            r.op(OP_CHECKSIG)?;
            let k2 = r.key()?;
            r.op(OP_CHECKSIGADD)?;
            r.op(OP_2)?;
            r.op(OP_NUMEQUAL)?;
            return r.done().then_some(ChannelLeaf::Funding { keys: [k1, k2] });
        }
        let hash = if r.op(OP_SHA256).is_some() {
            let h: [u8; 32] = r.push32()?.try_into().ok()?;
            r.op(OP_EQUALVERIFY)?;
            Some(h)
        } else {
            None
        };
        // a number then CLTV is an expiry; a number then CSV a delay
        let mut expiry = None;
        let mut delay = None;
        if r.peek() != Some(0x20) {
            let n = r.num()?;
            if r.op(OP_CLTV).is_some() {
                r.op(OP_DROP)?;
                expiry = Some(n);
                if r.peek() != Some(0x20) {
                    let d = r.num()?;
                    r.op(OP_CSV)?;
                    r.op(OP_DROP)?;
                    delay = Some(d);
                }
            } else {
                r.op(OP_CSV)?;
                r.op(OP_DROP)?;
                delay = Some(n);
            }
        }
        let key = r.key()?;
        r.op(OP_CHECKSIG)?;
        if !r.done() {
            return None;
        }
        if expiry.is_some_and(|e| e >= LOCKTIME_THRESHOLD) {
            return None;
        }
        let delay = match delay {
            Some(d) => Some(u16::try_from(d).ok()?),
            None => None,
        };
        let leaf = match (hash, expiry, delay) {
            (None, None, None) => ChannelLeaf::Key { key },
            (None, None, Some(delay)) => ChannelLeaf::Delayed { delay, key },
            (Some(hash), None, None) => ChannelLeaf::HashLock { hash, key },
            (Some(hash), None, Some(delay)) => ChannelLeaf::HashLockDelayed { hash, delay, key },
            (None, Some(expiry), None) => ChannelLeaf::Timeout { expiry, key },
            (None, Some(expiry), Some(delay)) => ChannelLeaf::TimeoutDelayed { expiry, delay, key },
            // a hash lock with an absolute timeout: Hitch writes no such leaf
            (Some(_), Some(_), _) => return None,
        };
        Some(leaf)
    }

    /// The relative delay in blocks the leaf demands, if any.
    pub fn delay(&self) -> Option<u16> {
        match *self {
            ChannelLeaf::Delayed { delay, .. }
            | ChannelLeaf::HashLockDelayed { delay, .. }
            | ChannelLeaf::TimeoutDelayed { delay, .. } => Some(delay),
            _ => None,
        }
    }

    /// The absolute expiry height the leaf demands, if any.
    pub fn expiry(&self) -> Option<u32> {
        match *self {
            ChannelLeaf::Timeout { expiry, .. } | ChannelLeaf::TimeoutDelayed { expiry, .. } => {
                Some(expiry)
            }
            _ => None,
        }
    }

    /// The payment hash the leaf demands a preimage of, if any.
    pub fn hash_lock(&self) -> Option<[u8; 32]> {
        match *self {
            ChannelLeaf::HashLock { hash, .. } | ChannelLeaf::HashLockDelayed { hash, .. } => {
                Some(hash)
            }
            _ => None,
        }
    }

    /// The witness items the leaf consumes below the script and control
    /// block: two signature slots for the funding leaf, a signature and the
    /// preimage for a hash lock, one signature otherwise.
    pub fn stack_items(&self) -> usize {
        match self {
            ChannelLeaf::Funding { .. }
            | ChannelLeaf::HashLock { .. }
            | ChannelLeaf::HashLockDelayed { .. } => 2,
            _ => 1,
        }
    }
}

/// Why a taproot script-path spend of a channel coin was refused. Each
/// variant names the check, so a refusal is never just "script failed".
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
    /// The prevout is not a taproot output, or the input does not exist.
    #[error("unsupported script type: not a taproot output")]
    ScriptType,
    /// A taproot input's scriptSig must be empty.
    #[error("WITNESS_MALLEATED: taproot scriptSig is not empty")]
    ScriptSig,
    /// Fewer than two items after the annex: not a script-path spend.
    #[error("a script-path witness has at least a script and a control block")]
    TooFewItems,
    /// An annex that is not a valid BIP 341 annex.
    #[error("bad annex")]
    Annex,
    /// The control block is not `33 + 32·m` bytes with a valid internal key.
    #[error("bad control block")]
    ControlBlock,
    /// The control block does not commit this leaf to the output key: a
    /// wrong internal key, merkle path or parity, or a tampered leaf.
    #[error("control block commitment mismatch")]
    Commitment,
    /// A leaf version other than tapscript's `0xc0`. Bitcoin Core and the
    /// reference kernel treat an unknown version as a success; this crate
    /// refuses it.
    #[error("unknown tapleaf version {0:#04x}: not verified, refused")]
    LeafVersion(u8),
    /// The leaf is not one of Hitch's seven templates.
    #[error(
        "the leaf is not a Hitch channel template; only those are verified on transaction inputs"
    )]
    NotATemplate,
    /// The witness does not carry exactly the items the template consumes:
    /// fewer fail the script, more fail BIP 342's clean stack.
    #[error("{have} witness items for a leaf that consumes {need}")]
    StackItems {
        /// Items below the script.
        have: usize,
        /// Items the template consumes.
        need: usize,
    },
    /// A witness item above [`MAX_STACK_ELEMENT`] bytes.
    #[error("a witness item is larger than 520 bytes")]
    StackItemSize,
    /// The item under the signature is not the preimage of the leaf's hash.
    #[error("the preimage does not hash to the leaf's payment hash")]
    HashLock,
    /// `OP_CHECKLOCKTIMEVERIFY` fails: `nLockTime` is a time, or below the
    /// expiry, or the input's `nSequence` is final.
    #[error("CHECKLOCKTIMEVERIFY: nLockTime below the leaf's expiry, a time, or a final input")]
    LockTime,
    /// `OP_CHECKSEQUENCEVERIFY` fails: a version-1 transaction, or the
    /// input's `nSequence` disables or is shorter than the delay, or counts
    /// time.
    #[error(
        "CHECKSEQUENCEVERIFY: the input's nSequence does not carry the leaf's delay in blocks"
    )]
    Sequence,
    /// A non-empty slot that is not a 64-byte signature or a 65-byte one
    /// with a defined, non-zero hash type.
    #[error("slot {slot}: bad tapscript signature encoding")]
    BadSignatureEncoding {
        /// The slot, in leaf order.
        slot: usize,
    },
    /// The signatures-operations budget of BIP 342 ran out.
    #[error("tapscript sigops budget exceeded")]
    Budget,
    /// A non-empty signature that does not verify: the script fails (BIP 342).
    #[error("slot {slot}: invalid schnorr signature")]
    InvalidSignature {
        /// The slot, in leaf order.
        slot: usize,
    },
    /// An empty signature where the leaf needs one: `CHECKSIG` leaves false,
    /// or `NUMEQUAL` counts fewer than two.
    #[error("slot {slot}: no signature where the leaf needs one")]
    MissingSignature {
        /// The slot, in leaf order.
        slot: usize,
    },
}

/// What a verified channel spend showed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelSpend {
    /// The leaf that was executed.
    pub leaf: ChannelLeaf,
    /// Its TapLeaf hash.
    pub leaf_hash: TapLeafHash,
    /// The preimage revealed by a hash-lock spend.
    pub preimage: Option<Vec<u8>>,
}

fn compact_len(n: usize) -> i64 {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        _ => 5,
    }
}

/// One `CHECKSIG` or `CHECKSIGADD` on a non-empty signature, BIP 342: 64
/// bytes for `SIGHASH_DEFAULT`, 65 with a defined explicit type; under
/// [`SighashRules::KnotsUnified`] a type with [`SIGHASH_UNIFIED`] reads the
/// unified message (script type 3). A signature that does not verify fails
/// the script; it never counts as false.
#[allow(clippy::too_many_arguments)]
fn check_signature(
    tx: &Transaction,
    index: usize,
    prevouts: &[TxOut],
    annex: Option<&[u8]>,
    leaf_hash: TapLeafHash,
    raw: &[u8],
    key: &XOnlyPublicKey,
    rules: SighashRules,
    slot: usize,
) -> Result<(), ChannelError> {
    let bad = ChannelError::BadSignatureEncoding { slot };
    let (sig, hash_type) = match raw.len() {
        64 => (raw, 0u8),
        65 if raw[64] != 0 => (&raw[..64], raw[64]),
        _ => return Err(bad),
    };
    let msg = if rules == SighashRules::KnotsUnified && hash_type & SIGHASH_UNIFIED != 0 {
        let leaf = leaf_hash.to_byte_array();
        unified_taproot_sighash(
            tx,
            index,
            prevouts,
            hash_type,
            annex,
            UnifiedTaproot::ScriptPath {
                leaf_hash: &leaf,
                codesep_pos: 0xffff_ffff,
            },
        )
        .map_err(|_| bad)?
    } else {
        let ty = TapSighashType::from_consensus_u8(hash_type).map_err(|_| bad)?;
        if prevouts.len() != tx.input.len() {
            return Err(ChannelError::ScriptType);
        }
        SighashCache::new(tx)
            .taproot_signature_hash(
                index,
                &Prevouts::All(prevouts),
                annex.map(|a| Annex::new(a).expect("checked by the caller")),
                Some((leaf_hash, 0xffff_ffff)),
                ty,
            )
            .map_err(|_| bad)?
            .to_byte_array()
    };
    if schnorr_verify(&msg, sig, &key.serialize()) {
        Ok(())
    } else {
        Err(ChannelError::InvalidSignature { slot })
    }
}

/// BIP 112 for a delay the template guarantees is a block count of at most
/// `0xffff`: a version-2 transaction (read signed, as the reference kernel's
/// `i32le` reads it), an input with the disable and type flags clear and at
/// least `delay` blocks in its low sixteen bits. Whether the coin is that deep
/// is BIP 68's question, asked by the block ([`crate::rules::resolve_spending`]).
fn check_sequence(tx: &Transaction, index: usize, delay: u16) -> Result<(), ChannelError> {
    let seq = tx.input[index].sequence.0;
    if tx.version.0 < 2
        || seq & SEQUENCE_DISABLE != 0
        || seq & SEQUENCE_TYPE != 0
        || seq & SEQUENCE_MASK < u32::from(delay)
    {
        return Err(ChannelError::Sequence);
    }
    Ok(())
}

/// BIP 65 for an expiry the template guarantees is a height: `nLockTime` a
/// height of at least the expiry and the input not final. Whether the block
/// is above `nLockTime` is `btc:rule-blockctx-finality`'s question.
fn check_lock_time(tx: &Transaction, index: usize, expiry: u32) -> Result<(), ChannelError> {
    let lt = tx.lock_time.to_consensus_u32();
    if lt >= LOCKTIME_THRESHOLD || expiry > lt || tx.input[index].sequence.0 == 0xffff_ffff {
        return Err(ChannelError::LockTime);
    }
    Ok(())
}

/// Verify input `index` as a taproot script-path spend of one of Hitch's
/// leaves under `rules` (BIP 341 and 342; Knots' unified sighash where the
/// rules and the hash type say so).
///
/// In order: the prevout is taproot and the scriptSig empty; an annex is
/// split off; the control block decodes and commits the leaf to the output
/// key ([`ControlBlock::verify_taproot_commitment`]); the leaf version is
/// tapscript; the leaf is a [`ChannelLeaf`]; the witness carries exactly the
/// items it consumes, none above 520 bytes; then, as the script runs, the
/// preimage, the expiry, the delay and each signature. `prevouts` is every
/// input's, in order. This is the whole meaning of those seven scripts and no
/// more: it claims no general tapscript compatibility.
///
/// ```
/// use bitcoin::hashes::Hash;
/// use bitcoin::key::TapTweak;
/// use bitcoin::secp256k1::{Keypair, Message, SecretKey};
/// use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
/// use bitcoin::taproot::{LeafVersion, TapLeafHash, TapNodeHash};
/// use bitcoin::{absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence,
///     Transaction, TxIn, TxOut, Txid, Witness};
/// use sidestr_core::block::{challenge_for_output_key, secp};
/// use sidestr_core::channel::{verify_channel_input, ChannelError, ChannelLeaf};
/// use sidestr_core::sighash::SighashRules;
///
/// let kp = Keypair::from_secret_key(secp(), &SecretKey::from_slice(&[5; 32]).unwrap());
/// let leaf = ChannelLeaf::Delayed { delay: 6, key: kp.x_only_public_key().0 };
/// let script = leaf.to_script();
/// let internal = Keypair::from_secret_key(secp(), &SecretKey::from_slice(&[9; 32]).unwrap())
///     .x_only_public_key().0;
/// let (output_key, parity) =
///     internal.tap_tweak(secp(), Some(TapNodeHash::from_script(&script, LeafVersion::TapScript)));
/// let prevouts = vec![TxOut { value: Amount::from_sat(20_000), script_pubkey: challenge_for_output_key(&output_key) }];
/// let mut tx = Transaction { version: Version::TWO, lock_time: LockTime::ZERO,
///     input: vec![TxIn { previous_output: OutPoint { txid: Txid::all_zeros(), vout: 0 },
///         script_sig: ScriptBuf::new(), sequence: Sequence(6), witness: Witness::new() }],
///     output: vec![TxOut { value: Amount::from_sat(19_000), script_pubkey: ScriptBuf::new() }] };
/// let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
/// let msg = SighashCache::new(&tx)
///     .taproot_script_spend_signature_hash(0, &Prevouts::All(&prevouts), leaf_hash, TapSighashType::Default)
///     .unwrap();
/// let sig = secp().sign_schnorr_with_aux_rand(&Message::from_digest(msg.to_byte_array()), &kp, &[0; 32]);
/// let mut control = vec![0xc0 | u8::from(parity)];
/// control.extend_from_slice(&internal.serialize());
/// tx.input[0].witness = Witness::from_slice(&[sig.serialize().to_vec(), script.to_bytes(), control]);
///
/// let spend = verify_channel_input(&tx, 0, &prevouts, SighashRules::Bip341).unwrap();
/// assert_eq!(spend.leaf, leaf);
///
/// // a sequence shorter than the delay fails CHECKSEQUENCEVERIFY (and changes the sighash,
/// // so the check that names it must come before the signature's)
/// tx.input[0].sequence = Sequence(5);
/// assert_eq!(verify_channel_input(&tx, 0, &prevouts, SighashRules::Bip341), Err(ChannelError::Sequence));
/// ```
pub fn verify_channel_input(
    tx: &Transaction,
    index: usize,
    prevouts: &[TxOut],
    rules: SighashRules,
) -> Result<ChannelSpend, ChannelError> {
    let prevout = prevouts.get(index).ok_or(ChannelError::ScriptType)?;
    let input = tx.input.get(index).ok_or(ChannelError::ScriptType)?;
    if !prevout.script_pubkey.is_p2tr() {
        return Err(ChannelError::ScriptType);
    }
    if !input.script_sig.is_empty() {
        return Err(ChannelError::ScriptSig);
    }
    let mut items: Vec<&[u8]> = input.witness.iter().collect();
    // BIP 342: the budget counts the whole serialised witness, annex included
    let witness_size: i64 = items
        .iter()
        .map(|w| w.len() as i64 + compact_len(w.len()))
        .sum::<i64>()
        + compact_len(items.len());
    let annex: Option<&[u8]> =
        if items.len() >= 2 && items.last().is_some_and(|a| a.first() == Some(&0x50)) {
            let raw = items.pop().expect("checked");
            Annex::new(raw).map_err(|_| ChannelError::Annex)?;
            Some(raw)
        } else {
            None
        };
    if items.len() < 2 {
        return Err(ChannelError::TooFewItems);
    }
    let control = items.pop().expect("checked");
    let script = Script::from_bytes(items.pop().expect("checked"));
    let cb = ControlBlock::decode(control).map_err(|_| ChannelError::ControlBlock)?;
    let output_key = XOnlyPublicKey::from_slice(&prevout.script_pubkey.as_bytes()[2..34])
        .map_err(|_| ChannelError::ScriptType)?;
    if !cb.verify_taproot_commitment(secp(), output_key, script) {
        return Err(ChannelError::Commitment);
    }
    if cb.leaf_version != LeafVersion::TapScript {
        return Err(ChannelError::LeafVersion(cb.leaf_version.to_consensus()));
    }
    let leaf = ChannelLeaf::parse(script).ok_or(ChannelError::NotATemplate)?;
    if items.len() != leaf.stack_items() {
        return Err(ChannelError::StackItems {
            have: items.len(),
            need: leaf.stack_items(),
        });
    }
    if items.iter().any(|i| i.len() > MAX_STACK_ELEMENT) {
        return Err(ChannelError::StackItemSize);
    }
    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
    let mut budget = 50 + witness_size;
    let mut sig = |raw: &[u8], key: &XOnlyPublicKey, slot: usize| -> Result<(), ChannelError> {
        if raw.is_empty() {
            return Err(ChannelError::MissingSignature { slot });
        }
        budget -= 50;
        if budget < 0 {
            return Err(ChannelError::Budget);
        }
        check_signature(tx, index, prevouts, annex, leaf_hash, raw, key, rules, slot)
    };
    let mut preimage = None;
    match leaf {
        ChannelLeaf::Funding { keys } => {
            // k1 consumes the top of the stack, the last item. BIP 342 runs
            // both checks before NUMEQUAL: an invalid non-empty signature in
            // either slot fails the script whatever the other holds.
            let top = items[1];
            let under = items[0];
            for (slot, raw) in [top, under].into_iter().enumerate() {
                if !raw.is_empty() && raw.len() != 64 && !(raw.len() == 65 && raw[64] != 0) {
                    return Err(ChannelError::BadSignatureEncoding { slot });
                }
            }
            sig(top, &keys[0], 0)?;
            sig(under, &keys[1], 1)?;
        }
        _ => {
            // the stack, bottom to top: signature, then the preimage if the leaf takes one
            if let Some(hash) = leaf.hash_lock() {
                let p = items[1];
                if sha256::Hash::hash(p).to_byte_array() != hash {
                    return Err(ChannelError::HashLock);
                }
                preimage = Some(p.to_vec());
            }
            if let Some(expiry) = leaf.expiry() {
                check_lock_time(tx, index, expiry)?;
            }
            if let Some(delay) = leaf.delay() {
                check_sequence(tx, index, delay)?;
            }
            let key = match leaf {
                ChannelLeaf::Key { key }
                | ChannelLeaf::Delayed { key, .. }
                | ChannelLeaf::HashLock { key, .. }
                | ChannelLeaf::HashLockDelayed { key, .. }
                | ChannelLeaf::Timeout { key, .. }
                | ChannelLeaf::TimeoutDelayed { key, .. } => key,
                ChannelLeaf::Funding { .. } => unreachable!("handled above"),
            };
            sig(items[0], &key, 0)?;
        }
    }
    Ok(ChannelSpend {
        leaf,
        leaf_hash,
        preimage,
    })
}

/// The block height from which input `index`'s relative lock (BIP 68) and
/// its transaction's `nLockTime` allow it, given the height its coin was
/// confirmed at: the least `h` with `h ≥ coin_height + (nSequence & 0xffff)`
/// when the lock is on and counts blocks, and `h > nLockTime` when that is a
/// height and some input is not final. `None` when the input carries a
/// time-based lock or the transaction a time `nLockTime`, which this crate
/// does not judge without median-time-past and the block rules skip.
///
/// [`crate::state::StateOf::submit`] refuses a transaction while the next
/// height is below this, so a sweep made before its delay is turned away at
/// the door rather than wedging a block.
///
/// ```
/// use bitcoin::hashes::Hash;
/// use bitcoin::{absolute::LockTime, transaction::Version, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, Txid, Witness};
/// use sidestr_core::channel::earliest_height;
///
/// let tx = |version, sequence, lock| Transaction { version: Version(version), lock_time: LockTime::from_consensus(lock),
///     input: vec![TxIn { previous_output: OutPoint { txid: Txid::all_zeros(), vout: 0 }, script_sig: ScriptBuf::new(),
///         sequence: Sequence(sequence), witness: Witness::new() }], output: vec![] };
/// assert_eq!(earliest_height(&tx(2, 6, 0), 0, 100), Some(106));           // six blocks after the coin
/// assert_eq!(earliest_height(&tx(1, 6, 0), 0, 100), Some(0));             // version 1: no relative lock
/// assert_eq!(earliest_height(&tx(2, 0xffff_fffd, 120), 0, 100), Some(121)); // nLockTime 120: from 121
/// assert_eq!(earliest_height(&tx(2, 6 | 1 << 22, 0), 0, 100), None);      // a time-based lock
/// ```
pub fn earliest_height(tx: &Transaction, index: usize, coin_height: u32) -> Option<u32> {
    let mut from = 0u32;
    let seq = tx.input.get(index)?.sequence.0;
    if tx.version.0 >= 2 && seq & SEQUENCE_DISABLE == 0 {
        let value = seq & SEQUENCE_MASK;
        if value > 0 {
            if seq & SEQUENCE_TYPE != 0 {
                return None;
            }
            from = from.max(coin_height.saturating_add(value));
        }
    }
    let lt = tx.lock_time.to_consensus_u32();
    if lt != 0 && !tx.input.iter().all(|i| i.sequence.0 == 0xffff_ffff) {
        if lt >= LOCKTIME_THRESHOLD {
            return None;
        }
        from = from.max(lt.saturating_add(1));
    }
    Some(from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, SecretKey};

    fn key(b: u8) -> XOnlyPublicKey {
        Keypair::from_secret_key(secp(), &SecretKey::from_slice(&[b; 32]).unwrap())
            .x_only_public_key()
            .0
    }

    fn all() -> Vec<ChannelLeaf> {
        let (a, b) = (key(1), key(2));
        let mut v = vec![
            ChannelLeaf::Funding { keys: [a, b] },
            ChannelLeaf::Key { key: a },
        ];
        for delay in [
            0u16, 1, 3, 6, 16, 17, 127, 128, 144, 255, 256, 0x7fff, 0x8000, 0xffff,
        ] {
            v.push(ChannelLeaf::Delayed { delay, key: a });
            v.push(ChannelLeaf::HashLockDelayed {
                hash: [7; 32],
                delay,
                key: b,
            });
            for expiry in [
                0u32,
                1,
                16,
                17,
                1_000,
                0x7f_ffff,
                0x80_0000,
                LOCKTIME_THRESHOLD - 1,
            ] {
                v.push(ChannelLeaf::TimeoutDelayed {
                    expiry,
                    delay,
                    key: a,
                });
            }
        }
        for expiry in [
            0u32,
            1,
            16,
            17,
            1_000,
            0x7f_ffff,
            0x80_0000,
            LOCKTIME_THRESHOLD - 1,
        ] {
            v.push(ChannelLeaf::Timeout { expiry, key: b });
        }
        v.push(ChannelLeaf::HashLock {
            hash: [9; 32],
            key: b,
        });
        v
    }

    #[test]
    fn every_template_round_trips_exactly() {
        for leaf in all() {
            let s = leaf.to_script();
            assert_eq!(ChannelLeaf::parse(&s), Some(leaf), "{s:?}");
        }
    }

    #[test]
    fn near_misses_are_not_templates() {
        let a = key(1);
        let refuse = |bytes: Vec<u8>, why: &str| {
            assert_eq!(
                ChannelLeaf::parse(Script::from_bytes(&bytes)),
                None,
                "{why}"
            );
        };
        let delayed = ChannelLeaf::Delayed { delay: 6, key: a }
            .to_script()
            .to_bytes();
        // non-minimal pushes of 6: a one-byte push, and a two-byte one
        let mut v = vec![0x01, 0x06];
        v.extend_from_slice(&delayed[1..]);
        refuse(v, "push of 6 as data");
        let mut v = vec![0x02, 0x06, 0x00];
        v.extend_from_slice(&delayed[1..]);
        refuse(v, "padded push");
        // negative zero, and a negative delay
        let mut v = vec![0x01, 0x80];
        v.extend_from_slice(&delayed[1..]);
        refuse(v, "negative zero");
        let mut v = vec![0x4f];
        v.extend_from_slice(&delayed[1..]);
        refuse(v, "OP_1NEGATE");
        // a delay of 0x10000 is a valid number, but not a u16 block count
        let mut v = vec![0x03, 0x00, 0x00, 0x01];
        v.extend_from_slice(&delayed[1..]);
        refuse(v, "delay above 0xffff");
        // CSV with the type flag (time-based)
        let mut v = vec![0x03, 0x06, 0x00, 0x40];
        v.extend_from_slice(&delayed[1..]);
        refuse(v, "time-based delay");
        // VERIFY instead of DROP, CHECKSIGVERIFY instead of CHECKSIG, a trailing op
        let mut v = delayed.clone();
        v[2] = 0x69;
        refuse(v, "CSV VERIFY");
        let mut v = delayed.clone();
        *v.last_mut().unwrap() = 0xad;
        refuse(v, "CHECKSIGVERIFY");
        let mut v = delayed.clone();
        v.push(0x51);
        refuse(v, "trailing OP_1");
        // a time-based expiry
        let mut t = Vec::new();
        push_num(&mut t, LOCKTIME_THRESHOLD);
        t.extend_from_slice(&[OP_CLTV, OP_DROP]);
        push_key(&mut t, &a);
        t.push(OP_CHECKSIG);
        refuse(t, "time-based expiry");
        // a hash lock with a timeout: not a Hitch leaf
        let mut h = vec![OP_SHA256, 0x20];
        h.extend_from_slice(&[1; 32]);
        h.push(OP_EQUALVERIFY);
        push_num(&mut h, 100);
        h.extend_from_slice(&[OP_CLTV, OP_DROP]);
        push_key(&mut h, &a);
        h.push(OP_CHECKSIG);
        refuse(h, "hash lock and timeout");
        // CSV before CLTV: the order is the template
        let mut o = Vec::new();
        push_num(&mut o, 6);
        o.extend_from_slice(&[OP_CSV, OP_DROP]);
        push_num(&mut o, 100);
        o.extend_from_slice(&[OP_CLTV, OP_DROP]);
        push_key(&mut o, &a);
        o.push(OP_CHECKSIG);
        refuse(o, "CSV then CLTV");
        // multi_a with another threshold, three keys, or a 1-of-2
        let f = ChannelLeaf::Funding { keys: [a, key(2)] }
            .to_script()
            .to_bytes();
        let mut v = f.clone();
        v[68] = 0x51;
        refuse(v, "1-of-2");
        let mut v = f[..68].to_vec();
        push_key(&mut v, &key(3));
        v.extend_from_slice(&[OP_CHECKSIGADD, 0x52, OP_NUMEQUAL]);
        refuse(v, "2-of-3");
        refuse(vec![0x51], "OP_TRUE");
        refuse(vec![], "empty");
        // an x coordinate that is not on the curve
        let mut v = vec![0x20];
        v.extend_from_slice(&[0xff; 32]);
        v.push(OP_CHECKSIG);
        refuse(v, "invalid key");
    }

    #[test]
    fn hitch_numbers_match_script_num_encoding() {
        // the pushes Hitch's pushNum writes for the edges of each byte length
        let cases: [(u32, &[u8]); 9] = [
            (0, &[0x00]),
            (16, &[0x60]),
            (17, &[0x01, 0x11]),
            (127, &[0x01, 0x7f]),
            (128, &[0x02, 0x80, 0x00]),
            (144, &[0x02, 0x90, 0x00]),
            (0x7fff, &[0x02, 0xff, 0x7f]),
            (0x8000, &[0x03, 0x00, 0x80, 0x00]),
            (LOCKTIME_THRESHOLD - 1, &[0x04, 0xff, 0x64, 0xcd, 0x1d]),
        ];
        for (n, want) in cases {
            let mut got = Vec::new();
            push_num(&mut got, n);
            assert_eq!(got, want, "{n}");
            let mut r = Reader { bytes: &got, at: 0 };
            assert_eq!(r.num(), Some(n));
            assert!(r.done());
        }
    }
}
