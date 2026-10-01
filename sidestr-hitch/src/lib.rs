//! Lightning-shaped payment-channel transactions for sidestr and
//! Bitcoin-family testnets.
//!
//! This is an attributed Rust port of `lib/channel.mjs` in Melvin Carvalho's
//! [Hitch](https://github.com/bitcoin-blake/hitch), at commit `62f8e39`.
//! Hitch is the Lightning construction without the Lightning network: two
//! peers lock a coin in a 2-of-2 Taproot leaf, hold asymmetric revocable
//! commitments, and update them off chain. Optional HTLC outputs add a
//! preimage success path, an absolute timeout and a revocation path.
//!
//! A commitment's revocation key is a two-party key: the counterparty's
//! basepoint plus the owner's per-state point ([`revocation_pub`]). The owner
//! never holds its secret, so it cannot use its own revocation leaf; the
//! counterparty learns the per-state secret when the state is revoked and
//! then signs with [`revocation_key`]. Every announced point carries a proof
//! of possession ([`pop_sign`]), so neither side can choose a point that
//! cancels the other's.
//!
//! The transaction builders are paired with a pure peer state machine in
//! [`protocol`] and the one-hop invoice decisions in [`route`]. Hosts provide
//! relay transport, wallet funding, atomic snapshot storage, chain watches
//! and broadcasting. Every builder supports both ordinary BIP 341 sighashes
//! and Bitcoin Knots' unified sighash used by `txbt4`. This is a channel
//! kernel, not a Lightning node, and it does not speak to Lightning peers.
//!
//! ```
//! use bitcoin::hashes::Hash;
//! use bitcoin::secp256k1::{Keypair, SecretKey};
//! use bitcoin::{Amount, OutPoint, Txid};
//! use sidestr_core::block::secp;
//! use sidestr_hitch::{Balances, Channel, ChannelState, RevocationKeys, Side};
//!
//! let key_a = SecretKey::from_slice(&[0x11; 32]).unwrap();
//! let key_b = SecretKey::from_slice(&[0x22; 32]).unwrap();
//! let pub_a = Keypair::from_secret_key(secp(), &key_a).x_only_public_key().0;
//! let pub_b = Keypair::from_secret_key(secp(), &key_b).x_only_public_key().0;
//! let channel = Channel::new(
//!     pub_a,
//!     pub_b,
//!     OutPoint { txid: Txid::all_zeros(), vout: 0 },
//!     Amount::from_sat(100_000),
//!     Amount::from_sat(300),
//!     6,
//! ).unwrap();
//! let state = ChannelState {
//!     balances: Balances { a: Amount::from_sat(60_000), b: Amount::from_sat(40_000) },
//!     revocation: RevocationKeys { a: pub_a, b: pub_b },
//!     htlcs: vec![],
//! };
//! let commitment = channel.commitment(1, Side::A, &state).unwrap();
//! assert_eq!(commitment.local_value, Amount::from_sat(59_700));
//! assert_eq!(commitment.remote_value, Amount::from_sat(40_000));
//! ```

#![deny(missing_docs)]

use std::collections::BTreeMap;

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::key::{TapTweak, TweakedPublicKey};
use bitcoin::secp256k1::{
    schnorr::Signature, Keypair, Message, Parity, PublicKey, Scalar, SecretKey, XOnlyPublicKey,
};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TapNodeHash};
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Witness,
};
use sidestr_core::block::secp;
use sidestr_core::federation::NUMS_X;
use sidestr_core::sighash::{
    key_path_hash_type, key_path_sighash, unified_taproot_sighash, SighashRules, UnifiedTaproot,
};

pub mod protocol;
pub mod route;

/// Outputs below this value are omitted from commitments, as in Hitch.
pub const DUST: u64 = 330;
/// Hitch's default per-transaction channel fee, in satoshis.
pub const DEFAULT_FEE: u64 = 300;
/// Hitch's default relative delay, in blocks.
pub const DEFAULT_DELAY: u16 = 6;
/// The shortest relative delay Hitch accepts.
pub const MIN_DELAY: u16 = 3;
/// The longest relative delay Hitch accepts.
pub const MAX_DELAY: u16 = 144;
/// The smallest per-transaction channel fee Hitch accepts, in satoshis.
pub const MIN_FEE: u64 = 100;
/// The largest per-transaction channel fee Hitch accepts, in satoshis.
pub const MAX_FEE: u64 = 10_000;
/// Values below this are block heights rather than timestamps in `nLockTime`.
pub const MAX_EXPIRY: u32 = 500_000_000;

const SIGHASH_ALL: u8 = 0x01;
const INPUT_SEQUENCE: u32 = 0xffff_fffd;
const LOCKTIME_SEQUENCE: u32 = 0xffff_fffe;

/// An error while deriving scripts, building a state or signing a spend.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The channel fee lies outside Hitch's accepted bounds.
    #[error("fee must be between {MIN_FEE} and {MAX_FEE} sats")]
    Fee,
    /// The CSV delay lies outside Hitch's accepted bounds.
    #[error("delay must be between {MIN_DELAY} and {MAX_DELAY} blocks")]
    Delay,
    /// An HTLC expiry is not an absolute block height.
    #[error("HTLC expiry must be below {MAX_EXPIRY}")]
    Expiry,
    /// Free balances and HTLCs do not account for the funding output.
    #[error("channel state accounts for {state} sats but funding holds {funding} sats")]
    Unbalanced {
        /// Value represented by free balances plus HTLCs.
        state: u64,
        /// Value locked in the funding output.
        funding: u64,
    },
    /// A value sum overflowed a Bitcoin amount.
    #[error("channel amount overflow")]
    AmountOverflow,
    /// No non-dust output remained after applying the fee.
    #[error("nothing to pay out")]
    NothingToPay,
    /// A cooperative close was requested with an HTLC still in flight.
    #[error("HTLCs in flight: settle or fail them first")]
    HtlcsInFlight,
    /// A claim would itself be dust after its fee.
    #[error("the output is not worth claiming after the fee")]
    DustClaim,
    /// The requested commitment does not contain the output being claimed.
    #[error("the commitment has no {0} output")]
    MissingOutput(&'static str),
    /// A success claim was requested without the 32-byte preimage.
    #[error("an HTLC success claim needs its 32-byte preimage")]
    MissingPreimage,
    /// A script number was outside the non-negative 31-bit range Hitch uses.
    #[error("script number out of range: {0}")]
    ScriptNumber(u32),
    /// Taproot's internal-key derivation failed.
    #[error("NUMS derivation failed")]
    Nums,
    /// The signature hash could not be constructed.
    #[error("signature hash failed: {0}")]
    Sighash(&'static str),
    /// A required funding signature was absent.
    #[error("both funding signatures are needed")]
    MissingSignature,
    /// A Schnorr signature had the wrong encoding or hash type.
    #[error("invalid leaf signature")]
    InvalidSignature,
    /// A two-party revocation key summed to the point at infinity or to zero.
    #[error("bad revocation key")]
    RevocationKey,
    /// A secp256k1 key or tweak was invalid.
    #[error(transparent)]
    Secp(#[from] bitcoin::secp256k1::Error),
}

/// Result type returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// One of the two channel peers. `A` is the funder and pays channel fees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Side {
    /// The funder.
    A,
    /// The other peer.
    B,
}

impl Side {
    /// The other peer.
    pub const fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

/// The two free balances in a channel state. HTLC values are separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Balances {
    /// Peer A's free balance.
    pub a: Amount,
    /// Peer B's free balance.
    pub b: Amount,
}

impl Balances {
    fn get(self, side: Side) -> Amount {
        match side {
            Side::A => self.a,
            Side::B => self.b,
        }
    }
}

/// The revocation public key each owner put into this state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationKeys {
    /// Revocation key for A's commitment.
    pub a: XOnlyPublicKey,
    /// Revocation key for B's commitment.
    pub b: XOnlyPublicKey,
}

impl RevocationKeys {
    fn get(self, side: Side) -> XOnlyPublicKey {
        match side {
            Side::A => self.a,
            Side::B => self.b,
        }
    }
}

/// An HTLC carried by a channel state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Htlc {
    /// Monotonically increasing identifier within the channel.
    pub id: u64,
    /// The peer offering the payment.
    pub from: Side,
    /// Value locked by the HTLC.
    pub amount: Amount,
    /// SHA-256 of the payment preimage.
    pub payment_hash: [u8; 32],
    /// Absolute block height after which the offerer may take the value back.
    pub expiry: u32,
}

/// Free balances, revocation keys and outstanding HTLCs at one state number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelState {
    /// Balances not locked in HTLCs.
    pub balances: Balances,
    /// Per-owner revocation keys for this state.
    pub revocation: RevocationKeys,
    /// Outstanding HTLCs. Builders order them by `id` on the wire.
    pub htlcs: Vec<Htlc>,
}

/// One Taproot leaf and the control block that proves it to its output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafSpend {
    /// The exact tapscript bytes.
    pub script: ScriptBuf,
    /// `TapLeaf` hash of `script` under tapscript leaf version `0xc0`.
    pub leaf_hash: TapLeafHash,
    /// BIP 341 control block for this leaf.
    pub control_block: Vec<u8>,
    /// Whether a claim through this leaf must use the channel's CSV delay.
    pub csv: bool,
}

/// Hitch's 2-of-2 funding output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingScript {
    /// The unspendable x-only internal key.
    pub internal_key: XOnlyPublicKey,
    /// The tweaked Taproot output key.
    pub output_key: TweakedPublicKey,
    /// `OP_1 <output_key>`.
    pub script_pubkey: ScriptBuf,
    /// Keys in lexicographic leaf order.
    pub signers: [XOnlyPublicKey; 2],
    /// The `multi_a(2, a, b)` leaf and its control block.
    pub leaf: LeafSpend,
}

/// A revocable delayed output in one commitment transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToLocalScript {
    /// The tweaked Taproot output key.
    pub output_key: TweakedPublicKey,
    /// `OP_1 <output_key>`.
    pub script_pubkey: ScriptBuf,
    /// The owner's `CHECKSEQUENCEVERIFY` path.
    pub delayed: LeafSpend,
    /// The counterparty's immediate revocation path.
    pub revocation: LeafSpend,
}

/// A three-path HTLC output in one commitment transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HtlcScript {
    /// The tweaked Taproot output key.
    pub output_key: TweakedPublicKey,
    /// `OP_1 <output_key>`.
    pub script_pubkey: ScriptBuf,
    /// Receiver claim with the payment preimage.
    pub success: LeafSpend,
    /// Offerer refund after the absolute expiry.
    pub timeout: LeafSpend,
    /// Counterparty claim with the revoked state's secret.
    pub revocation: LeafSpend,
}

/// An output's role in a commitment transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputKind {
    /// Delayed and revocable value of the commitment owner.
    ToLocal,
    /// Immediate key-path value of the other peer.
    ToRemote,
    /// Hash-and-time-locked value.
    Htlc,
}

/// An HTLC after its exact output index and scripts have been derived for a
/// particular commitment owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentHtlc {
    /// Logical HTLC shared by the two asymmetric commitments.
    pub htlc: Htlc,
    /// Output index in this commitment.
    pub vout: u32,
    /// The three script paths for this commitment owner.
    pub scripts: HtlcScript,
    /// Whether this commitment's owner offered the HTLC.
    pub offered_by_owner: bool,
}

/// One peer's fully derived commitment transaction for a state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    /// Unsigned transaction until both funding signatures are installed.
    pub tx: Transaction,
    /// Scripts for the owner's delayed output, whether or not it was dust.
    pub to_local: ToLocalScript,
    /// Output roles in transaction order.
    pub kinds: Vec<OutputKind>,
    /// HTLC metadata with final output positions.
    pub htlcs: Vec<CommitmentHtlc>,
    /// Owner payout after the funder's channel fee, or zero when omitted.
    pub local_value: Amount,
    /// Counterparty payout after the funder's channel fee, or zero when omitted.
    pub remote_value: Amount,
    /// Position of the `to_local` output when it is not dust.
    pub to_local_vout: Option<u32>,
    /// State number authorised by this transaction.
    pub number: u64,
    /// Peer who can broadcast this asymmetric commitment.
    pub owner: Side,
    /// CSV delay copied from the channel.
    pub delay: u16,
}

/// A 65-byte tapscript signature: BIP-340 signature followed by its explicit
/// sighash type (`0x01` or Knots' `0x21`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafSignature([u8; 65]);

impl LeafSignature {
    /// Parse exactly 65 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 65] = bytes.try_into().map_err(|_| Error::InvalidSignature)?;
        Signature::from_slice(&bytes[..64]).map_err(|_| Error::InvalidSignature)?;
        Ok(Self(bytes))
    }

    /// Borrow the witness encoding.
    pub fn as_bytes(&self) -> &[u8; 65] {
        &self.0
    }

    /// Encode the signature and explicit hash type as lower-case hex.
    pub fn to_hex(self) -> String {
        hex_bytes(&self.0)
    }

    /// Parse the 130-character wire form Hitch carries in messages.
    pub fn from_hex(text: &str) -> Result<Self> {
        if text.len() != 130 {
            return Err(Error::InvalidSignature);
        }
        let mut bytes = [0u8; 65];
        decode_hex_into(text, &mut bytes).ok_or(Error::InvalidSignature)?;
        Self::from_slice(&bytes)
    }
}

/// A 64-byte BIP 340 proof of possession of a revocation secret, carried as
/// 128 lower-case hex characters on Hitch's wire.
///
/// See [`pop_sign`] and [`pop_verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PopSignature([u8; 64]);

impl PopSignature {
    /// Wrap exactly 64 signature bytes.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Borrow the signature bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Encode as lower-case hex.
    pub fn to_hex(self) -> String {
        hex_bytes(&self.0)
    }

    /// Parse the 128-character lower-case wire form.
    pub fn from_hex(text: &str) -> Result<Self> {
        let mut bytes = [0u8; 64];
        decode_hex_into(text, &mut bytes).ok_or(Error::InvalidSignature)?;
        Ok(Self(bytes))
    }
}

/// A funded channel and its invariant parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channel {
    /// A's public key followed by B's; this order defines roles, not the leaf.
    pub keys: [XOnlyPublicKey; 2],
    /// Confirmed funding outpoint.
    pub funding_outpoint: OutPoint,
    /// Value of the funding output.
    pub funding_value: Amount,
    /// Exact funding output construction.
    pub funding_script: FundingScript,
    /// Fee charged to A in every commitment or close.
    pub fee: Amount,
    /// Relative delay on commitment-owner claims.
    pub delay: u16,
}

impl Channel {
    /// Construct a channel after checking Hitch's fee and delay bounds.
    pub fn new(
        a: XOnlyPublicKey,
        b: XOnlyPublicKey,
        funding_outpoint: OutPoint,
        funding_value: Amount,
        fee: Amount,
        delay: u16,
    ) -> Result<Self> {
        if !(MIN_FEE..=MAX_FEE).contains(&fee.to_sat()) {
            return Err(Error::Fee);
        }
        if !(MIN_DELAY..=MAX_DELAY).contains(&delay) {
            return Err(Error::Delay);
        }
        Ok(Self {
            keys: [a, b],
            funding_outpoint,
            funding_value,
            funding_script: funding_script(a, b)?,
            fee,
            delay,
        })
    }

    /// A or B's public key by protocol role.
    pub fn key(&self, side: Side) -> XOnlyPublicKey {
        match side {
            Side::A => self.keys[0],
            Side::B => self.keys[1],
        }
    }

    /// Funding output as a previous output for signature hashing.
    pub fn funding_prevout(&self) -> TxOut {
        TxOut {
            value: self.funding_value,
            script_pubkey: self.funding_script.script_pubkey.clone(),
        }
    }

    /// Derive one peer's asymmetric commitment for `state`.
    pub fn commitment(&self, number: u64, owner: Side, state: &ChannelState) -> Result<Commitment> {
        self.check_state(state)?;
        let remote_side = owner.other();
        let owner_pub = self.key(owner);
        let remote_pub = self.key(remote_side);
        let local = payout_after_fee(state.balances.get(owner), owner, self.fee);
        let remote = payout_after_fee(state.balances.get(remote_side), remote_side, self.fee);
        let to_local = to_local_script(owner_pub, state.revocation.get(owner), self.delay)?;
        let mut output = Vec::new();
        let mut kinds = Vec::new();
        let mut to_local_vout = None;
        if local.to_sat() >= DUST {
            to_local_vout = Some(output.len() as u32);
            output.push(TxOut {
                value: local,
                script_pubkey: to_local.script_pubkey.clone(),
            });
            kinds.push(OutputKind::ToLocal);
        }
        if remote.to_sat() >= DUST {
            output.push(TxOut {
                value: remote,
                script_pubkey: to_remote_script(remote_pub),
            });
            kinds.push(OutputKind::ToRemote);
        }

        let mut sorted = state.htlcs.clone();
        sorted.sort_by_key(|h| h.id);
        let mut htlcs = Vec::new();
        for htlc in sorted {
            if htlc.expiry >= MAX_EXPIRY {
                return Err(Error::Expiry);
            }
            if htlc.amount.to_sat() < DUST {
                continue;
            }
            let offered_by_owner = htlc.from == owner;
            let scripts = htlc_script(HtlcScriptArgs {
                owner_pub,
                remote_pub,
                revocation_pub: state.revocation.get(owner),
                delay: self.delay,
                payment_hash: htlc.payment_hash,
                expiry: htlc.expiry,
                offered_by_owner,
            })?;
            let vout = output.len() as u32;
            output.push(TxOut {
                value: htlc.amount,
                script_pubkey: scripts.script_pubkey.clone(),
            });
            kinds.push(OutputKind::Htlc);
            htlcs.push(CommitmentHtlc {
                htlc,
                vout,
                scripts,
                offered_by_owner,
            });
        }
        if output.is_empty() {
            return Err(Error::NothingToPay);
        }
        Ok(Commitment {
            tx: one_input_tx(
                self.funding_outpoint,
                INPUT_SEQUENCE,
                LockTime::ZERO,
                output,
            ),
            to_local,
            kinds,
            htlcs,
            local_value: local,
            remote_value: remote,
            to_local_vout,
            number,
            owner,
            delay: self.delay,
        })
    }

    /// Cooperative close paying both free balances directly to their keys.
    pub fn cooperative_close(&self, state: &ChannelState) -> Result<Transaction> {
        if !state.htlcs.is_empty() {
            return Err(Error::HtlcsInFlight);
        }
        self.check_state(state)?;
        let mut output = Vec::new();
        let a = payout_after_fee(state.balances.a, Side::A, self.fee);
        if a.to_sat() >= DUST {
            output.push(TxOut {
                value: a,
                script_pubkey: to_remote_script(self.keys[0]),
            });
        }
        if state.balances.b.to_sat() >= DUST {
            output.push(TxOut {
                value: state.balances.b,
                script_pubkey: to_remote_script(self.keys[1]),
            });
        }
        if output.is_empty() {
            return Err(Error::NothingToPay);
        }
        Ok(one_input_tx(
            self.funding_outpoint,
            INPUT_SEQUENCE,
            LockTime::ZERO,
            output,
        ))
    }

    /// Sign a commitment or close through the 2-of-2 funding leaf.
    pub fn sign_funding(
        &self,
        tx: &Transaction,
        key: &SecretKey,
        rules: SighashRules,
        aux: &[u8; 32],
    ) -> Result<LeafSignature> {
        sign_leaf(
            tx,
            0,
            &[self.funding_prevout()],
            self.funding_script.leaf.leaf_hash,
            key,
            rules,
            aux,
        )
    }

    /// Check one peer's signature on a commitment or close.
    pub fn verify_funding(
        &self,
        tx: &Transaction,
        pubkey: &XOnlyPublicKey,
        signature: &LeafSignature,
        rules: SighashRules,
    ) -> bool {
        verify_leaf_signature(
            tx,
            0,
            &[self.funding_prevout()],
            self.funding_script.leaf.leaf_hash,
            pubkey,
            signature,
            rules,
        )
    }

    /// Assemble the funding witness. Slots are reversed from leaf order so
    /// the first key's signature is on top of the tapscript stack.
    pub fn funding_witness(
        &self,
        signatures: &BTreeMap<XOnlyPublicKey, LeafSignature>,
    ) -> Result<Witness> {
        let mut slots = self
            .funding_script
            .signers
            .iter()
            .map(|key| {
                signatures
                    .get(key)
                    .map(|signature| signature.as_bytes().to_vec())
                    .ok_or(Error::MissingSignature)
            })
            .collect::<Result<Vec<_>>>()?;
        slots.reverse();
        slots.push(self.funding_script.leaf.script.to_bytes());
        slots.push(self.funding_script.leaf.control_block.clone());
        Ok(Witness::from_slice(&slots))
    }

    fn check_state(&self, state: &ChannelState) -> Result<()> {
        let total = state.htlcs.iter().try_fold(
            state
                .balances
                .a
                .to_sat()
                .checked_add(state.balances.b.to_sat())
                .ok_or(Error::AmountOverflow)?,
            |sum, htlc| {
                sum.checked_add(htlc.amount.to_sat())
                    .ok_or(Error::AmountOverflow)
            },
        )?;
        if total != self.funding_value.to_sat() {
            return Err(Error::Unbalanced {
                state: total,
                funding: self.funding_value.to_sat(),
            });
        }
        Ok(())
    }
}

/// Arguments needed to derive one commitment owner's HTLC scripts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HtlcScriptArgs {
    /// Commitment owner's key.
    pub owner_pub: XOnlyPublicKey,
    /// Other peer's key.
    pub remote_pub: XOnlyPublicKey,
    /// Revocation key for this commitment owner and state.
    pub revocation_pub: XOnlyPublicKey,
    /// Channel CSV delay.
    pub delay: u16,
    /// SHA-256 of the payment preimage.
    pub payment_hash: [u8; 32],
    /// Absolute timeout height.
    pub expiry: u32,
    /// Whether the commitment owner offered this HTLC.
    pub offered_by_owner: bool,
}

/// Derive Hitch's fixed unspendable internal key: BIP 341's `H` tweaked by
/// `tagged_hash("hitch/nums", "hitch")`.
pub fn internal_key() -> Result<XOnlyPublicKey> {
    let tweak = tagged_sha256(b"hitch/nums", b"hitch");
    let mut encoded = [0u8; 33];
    encoded[0] = 0x02;
    encoded[1..].copy_from_slice(&NUMS_X);
    let point = PublicKey::from_slice(&encoded)?;
    let scalar = Scalar::from_be_bytes(tweak).map_err(|_| Error::Nums)?;
    Ok(point.add_exp_tweak(secp(), &scalar)?.x_only_public_key().0)
}

/// Negate `secret` when its public point has an odd y coordinate, so the
/// result's point is the even lift of the same x-only key. This is Hitch's
/// `evenSecret`.
pub fn even_secret(secret: &SecretKey) -> SecretKey {
    let (_, parity) = secret.x_only_public_key(secp());
    if parity == Parity::Odd {
        secret.negate()
    } else {
        *secret
    }
}

/// The public half of a two-party revocation key: `lift_x(point) +
/// even(scalar)·G`, as an x-only key. This is Hitch's `revocationPub`.
///
/// A commitment's revocation key combines the counterparty's basepoint `R`
/// with the owner's per-state point `S_i`. The owner computes it as
/// `revocation_pub(R, s_i)`, the counterparty as `revocation_pub(S_i, r)`,
/// and both obtain `R + S_i`. Neither side alone knows its discrete
/// logarithm; the counterparty learns it only when the owner reveals `s_i`
/// to revoke the state (see [`revocation_key`]).
///
/// ```
/// use bitcoin::secp256k1::{Keypair, SecretKey};
/// use sidestr_core::block::secp;
/// use sidestr_hitch::{revocation_key, revocation_pub};
///
/// let r = SecretKey::from_slice(&[0x33; 32]).unwrap();
/// let s = SecretKey::from_slice(&[0x44; 32]).unwrap();
/// let big_r = Keypair::from_secret_key(secp(), &r).x_only_public_key().0;
/// let big_s = Keypair::from_secret_key(secp(), &s).x_only_public_key().0;
/// let owner_view = revocation_pub(big_r, &s).unwrap();
/// assert_eq!(owner_view, revocation_pub(big_s, &r).unwrap());
/// let key = revocation_key(&r, &s).unwrap();
/// assert_eq!(Keypair::from_secret_key(secp(), &key).x_only_public_key().0, owner_view);
/// ```
pub fn revocation_pub(point: XOnlyPublicKey, scalar: &SecretKey) -> Result<XOnlyPublicKey> {
    let lifted = point.public_key(Parity::Even);
    let tweak = Scalar::from(even_secret(scalar));
    let combined = lifted
        .add_exp_tweak(secp(), &tweak)
        .map_err(|_| Error::RevocationKey)?;
    Ok(combined.x_only_public_key().0)
}

/// The secret of a two-party revocation key: `even(basepoint_secret) +
/// even(per_state_secret) mod n`. This is Hitch's `revocationKey`; it signs
/// the revocation leaves of a commitment whose public key is
/// [`revocation_pub`].
pub fn revocation_key(basepoint_secret: &SecretKey, per_state: &SecretKey) -> Result<SecretKey> {
    even_secret(basepoint_secret)
        .add_tweak(&Scalar::from(even_secret(per_state)))
        .map_err(|_| Error::RevocationKey)
}

fn pop_message(point: &XOnlyPublicKey, context: &str) -> [u8; 32] {
    let mut message = Vec::with_capacity(context.len() + 32);
    message.extend_from_slice(context.as_bytes());
    message.extend_from_slice(&point.serialize());
    tagged_sha256(b"hitch/pop", &message)
}

/// Prove possession of a revocation secret: a BIP 340 signature by `secret`
/// over `tagged_hash("hitch/pop", context || point)`. Hitch's `context` is
/// `"<channel id>/<owner role>/<base or state number>"`.
///
/// A plain sum of points is open to a rogue key: a peer could announce
/// `k·G − R` and hold `k`. Every announced revocation point therefore
/// carries this proof, and [`pop_verify`] runs before the point is kept.
pub fn pop_sign(secret: &SecretKey, context: &str, aux: &[u8; 32]) -> PopSignature {
    let keypair = Keypair::from_secret_key(secp(), secret);
    let point = keypair.x_only_public_key().0;
    let message = Message::from_digest(pop_message(&point, context));
    let signature = secp().sign_schnorr_with_aux_rand(&message, &keypair, aux);
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(signature.as_ref());
    PopSignature(bytes)
}

/// Check a proof of possession made by [`pop_sign`] for `point` in
/// `context`. Malformed signatures verify as `false`.
pub fn pop_verify(point: &XOnlyPublicKey, signature: &PopSignature, context: &str) -> bool {
    let Ok(signature) = Signature::from_slice(&signature.0) else {
        return false;
    };
    let message = Message::from_digest(pop_message(point, context));
    secp().verify_schnorr(&signature, &message, point).is_ok()
}

/// The payment preimage revealed by a spend of an HTLC output, if any
/// 32-byte witness item hashes to `payment_hash` under SHA-256. This is
/// Hitch's `preimageIn`, used to carry a preimage the counterparty revealed
/// on the chain back upstream.
pub fn preimage_in(tx: &Transaction, payment_hash: &[u8; 32]) -> Option<[u8; 32]> {
    tx.input
        .iter()
        .flat_map(|input| input.witness.iter())
        .filter(|item| item.len() == 32)
        .find(|item| sha256::Hash::hash(item).to_byte_array() == *payment_hash)
        .map(|item| item.try_into().expect("a 32-byte witness item"))
}

/// Construct the 2-of-2 funding script. Keys are sorted lexicographically in
/// the leaf, independently of their A/B protocol roles.
pub fn funding_script(a: XOnlyPublicKey, b: XOnlyPublicKey) -> Result<FundingScript> {
    let mut signers = [a, b];
    signers.sort_by_key(XOnlyPublicKey::serialize);
    let mut bytes = Vec::with_capacity(70);
    push_key(&mut bytes, signers[0]);
    bytes.push(0xac); // CHECKSIG
    push_key(&mut bytes, signers[1]);
    bytes.extend_from_slice(&[0xba, 0x52, 0x9c]); // CHECKSIGADD 2 NUMEQUAL
    let script = ScriptBuf::from_bytes(bytes);
    let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
    let internal_key = internal_key()?;
    let (output_key, parity, script_pubkey) = taproot_output(internal_key, leaf_hash.into());
    Ok(FundingScript {
        internal_key,
        output_key,
        script_pubkey,
        signers,
        leaf: LeafSpend {
            script,
            leaf_hash,
            control_block: control_block(internal_key, parity, &[]),
            csv: false,
        },
    })
}

/// Construct the owner's delayed leaf and the counterparty's revocation
/// leaf, rooted as `branch(delayed, revocation)`.
pub fn to_local_script(
    owner_pub: XOnlyPublicKey,
    revocation_pub: XOnlyPublicKey,
    delay: u16,
) -> Result<ToLocalScript> {
    let mut delayed = Vec::new();
    push_num(&mut delayed, u32::from(delay))?;
    delayed.extend_from_slice(&[0xb2, 0x75]); // CSV DROP
    push_key(&mut delayed, owner_pub);
    delayed.push(0xac);
    let delayed = ScriptBuf::from_bytes(delayed);

    let mut revocation = Vec::new();
    push_key(&mut revocation, revocation_pub);
    revocation.push(0xac);
    let revocation = ScriptBuf::from_bytes(revocation);

    let delayed_hash = TapLeafHash::from_script(&delayed, LeafVersion::TapScript);
    let revocation_hash = TapLeafHash::from_script(&revocation, LeafVersion::TapScript);
    let root = TapNodeHash::from_node_hashes(delayed_hash.into(), revocation_hash.into());
    let internal_key = internal_key()?;
    let (output_key, parity, script_pubkey) = taproot_output(internal_key, root);
    Ok(ToLocalScript {
        output_key,
        script_pubkey,
        delayed: LeafSpend {
            script: delayed,
            leaf_hash: delayed_hash,
            control_block: control_block(internal_key, parity, &[revocation_hash.into()]),
            csv: true,
        },
        revocation: LeafSpend {
            script: revocation,
            leaf_hash: revocation_hash,
            control_block: control_block(internal_key, parity, &[delayed_hash.into()]),
            csv: false,
        },
    })
}

/// A direct key-path output using Hitch's x-only channel key literally.
pub fn to_remote_script(pubkey: XOnlyPublicKey) -> ScriptBuf {
    let mut script = Vec::with_capacity(34);
    script.extend_from_slice(&[0x51, 0x20]);
    script.extend_from_slice(&pubkey.serialize());
    ScriptBuf::from_bytes(script)
}

/// Construct the success, timeout and revocation leaves for an HTLC. The
/// tree is `branch(branch(success, timeout), revocation)`.
pub fn htlc_script(args: HtlcScriptArgs) -> Result<HtlcScript> {
    if args.expiry >= MAX_EXPIRY {
        return Err(Error::Expiry);
    }
    let mut success = Vec::new();
    success.extend_from_slice(&[0xa8, 0x20]); // SHA256 PUSH32
    success.extend_from_slice(&args.payment_hash);
    success.push(0x88); // EQUALVERIFY
    if !args.offered_by_owner {
        push_num(&mut success, u32::from(args.delay))?;
        success.extend_from_slice(&[0xb2, 0x75]); // CSV DROP
    }
    push_key(
        &mut success,
        if args.offered_by_owner {
            args.remote_pub
        } else {
            args.owner_pub
        },
    );
    success.push(0xac);
    let success = ScriptBuf::from_bytes(success);

    let mut timeout = Vec::new();
    push_num(&mut timeout, args.expiry)?;
    timeout.extend_from_slice(&[0xb1, 0x75]); // CLTV DROP
    if args.offered_by_owner {
        push_num(&mut timeout, u32::from(args.delay))?;
        timeout.extend_from_slice(&[0xb2, 0x75]); // CSV DROP
    }
    push_key(
        &mut timeout,
        if args.offered_by_owner {
            args.owner_pub
        } else {
            args.remote_pub
        },
    );
    timeout.push(0xac);
    let timeout = ScriptBuf::from_bytes(timeout);

    let mut revocation = Vec::new();
    push_key(&mut revocation, args.revocation_pub);
    revocation.push(0xac);
    let revocation = ScriptBuf::from_bytes(revocation);

    let success_hash = TapLeafHash::from_script(&success, LeafVersion::TapScript);
    let timeout_hash = TapLeafHash::from_script(&timeout, LeafVersion::TapScript);
    let revocation_hash = TapLeafHash::from_script(&revocation, LeafVersion::TapScript);
    let inner = TapNodeHash::from_node_hashes(success_hash.into(), timeout_hash.into());
    let root = TapNodeHash::from_node_hashes(inner, revocation_hash.into());
    let internal_key = internal_key()?;
    let (output_key, parity, script_pubkey) = taproot_output(internal_key, root);
    Ok(HtlcScript {
        output_key,
        script_pubkey,
        success: LeafSpend {
            script: success,
            leaf_hash: success_hash,
            control_block: control_block(
                internal_key,
                parity,
                &[timeout_hash.into(), revocation_hash.into()],
            ),
            csv: !args.offered_by_owner,
        },
        timeout: LeafSpend {
            script: timeout,
            leaf_hash: timeout_hash,
            control_block: control_block(
                internal_key,
                parity,
                &[success_hash.into(), revocation_hash.into()],
            ),
            csv: args.offered_by_owner,
        },
        revocation: LeafSpend {
            script: revocation,
            leaf_hash: revocation_hash,
            control_block: control_block(internal_key, parity, &[inner]),
            csv: false,
        },
    })
}

/// Compute a tapscript signature hash and its explicit wire hash type.
pub fn script_path_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    leaf_hash: TapLeafHash,
    rules: SighashRules,
) -> Result<([u8; 32], u8)> {
    let hash_type = SIGHASH_ALL
        | if rules == SighashRules::KnotsUnified {
            sidestr_core::sighash::SIGHASH_UNIFIED
        } else {
            0
        };
    let leaf_hash_bytes = leaf_hash.to_byte_array();
    let message = match rules {
        SighashRules::KnotsUnified => unified_taproot_sighash(
            tx,
            input_index,
            prevouts,
            hash_type,
            None,
            UnifiedTaproot::ScriptPath {
                leaf_hash: &leaf_hash_bytes,
                codesep_pos: u32::MAX,
            },
        )
        .map_err(Error::Sighash)?,
        SighashRules::Bip341 => SighashCache::new(tx)
            .taproot_script_spend_signature_hash(
                input_index,
                &Prevouts::All(prevouts),
                leaf_hash,
                TapSighashType::All,
            )
            .map_err(|_| Error::Sighash("taproot script-path sighash"))?
            .to_byte_array(),
    };
    Ok((message, hash_type))
}

/// Sign one tapscript leaf with an explicit hash type byte.
pub fn sign_leaf(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    leaf_hash: TapLeafHash,
    key: &SecretKey,
    rules: SighashRules,
    aux: &[u8; 32],
) -> Result<LeafSignature> {
    let (message, hash_type) = script_path_sighash(tx, input_index, prevouts, leaf_hash, rules)?;
    let keypair = Keypair::from_secret_key(secp(), key);
    let signature =
        secp().sign_schnorr_with_aux_rand(&Message::from_digest(message), &keypair, aux);
    let mut wire = [0u8; 65];
    wire[..64].copy_from_slice(signature.as_ref());
    wire[64] = hash_type;
    Ok(LeafSignature(wire))
}

/// Verify one tapscript signature under the same family rules used to sign.
pub fn verify_leaf_signature(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    leaf_hash: TapLeafHash,
    pubkey: &XOnlyPublicKey,
    signature: &LeafSignature,
    rules: SighashRules,
) -> bool {
    let Ok((message, hash_type)) = script_path_sighash(tx, input_index, prevouts, leaf_hash, rules)
    else {
        return false;
    };
    if signature.0[64] != hash_type {
        return false;
    }
    let Ok(signature) = Signature::from_slice(&signature.0[..64]) else {
        return false;
    };
    secp()
        .verify_schnorr(&signature, &Message::from_digest(message), pubkey)
        .is_ok()
}

/// Which `to_local` leaf a sweep uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepPath {
    /// Owner claim after the channel delay.
    Delayed,
    /// Counterparty penalty with the revoked state's secret.
    Revocation,
}

/// Spend a commitment's `to_local` output through its delayed or revocation
/// leaf and install the complete witness.
pub fn sweep_to_local(
    commitment: &Commitment,
    path: SweepPath,
    destination: ScriptBuf,
    fee: Amount,
    key: &SecretKey,
    rules: SighashRules,
    aux: &[u8; 32],
) -> Result<Transaction> {
    let vout = commitment
        .to_local_vout
        .ok_or(Error::MissingOutput("to_local"))?;
    let value = commitment.local_value;
    let output_value = claim_value(value, fee)?;
    let (leaf, sequence) = match path {
        SweepPath::Delayed => (&commitment.to_local.delayed, u32::from(commitment.delay)),
        SweepPath::Revocation => (&commitment.to_local.revocation, INPUT_SEQUENCE),
    };
    let mut tx = one_input_tx(
        OutPoint {
            txid: commitment.tx.compute_txid(),
            vout,
        },
        sequence,
        LockTime::ZERO,
        vec![TxOut {
            value: output_value,
            script_pubkey: destination,
        }],
    );
    let prevouts = [TxOut {
        value,
        script_pubkey: commitment.to_local.script_pubkey.clone(),
    }];
    let signature = sign_leaf(&tx, 0, &prevouts, leaf.leaf_hash, key, rules, aux)?;
    tx.input[0].witness = Witness::from_slice(&[
        signature.as_bytes().as_slice(),
        leaf.script.as_bytes(),
        &leaf.control_block,
    ]);
    Ok(tx)
}

/// Which leaf claims an HTLC output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HtlcClaimPath {
    /// Receiver claim with the preimage.
    Success,
    /// Offerer refund after expiry.
    Timeout,
    /// Counterparty penalty against a revoked commitment.
    Revocation,
}

/// Output and witness choices for an HTLC claim transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HtlcClaim {
    /// Script leaf used to spend the HTLC.
    pub path: HtlcClaimPath,
    /// Script receiving the claimed value.
    pub destination: ScriptBuf,
    /// Absolute miner fee subtracted from the HTLC value.
    pub fee: Amount,
    /// Payment preimage, required only for [`HtlcClaimPath::Success`].
    pub preimage: Option<[u8; 32]>,
}

/// Spend one HTLC output through its success, timeout or revocation leaf.
pub fn claim_htlc(
    commitment: &Commitment,
    htlc: &CommitmentHtlc,
    claim: HtlcClaim,
    key: &SecretKey,
    rules: SighashRules,
    aux: &[u8; 32],
) -> Result<Transaction> {
    let (leaf, lock_time) = match claim.path {
        HtlcClaimPath::Success => (&htlc.scripts.success, LockTime::ZERO),
        HtlcClaimPath::Timeout => (
            &htlc.scripts.timeout,
            LockTime::from_consensus(htlc.htlc.expiry),
        ),
        HtlcClaimPath::Revocation => (&htlc.scripts.revocation, LockTime::ZERO),
    };
    let sequence = if claim.path == HtlcClaimPath::Revocation {
        INPUT_SEQUENCE
    } else if leaf.csv {
        u32::from(commitment.delay)
    } else {
        LOCKTIME_SEQUENCE
    };
    let output_value = claim_value(htlc.htlc.amount, claim.fee)?;
    let mut tx = one_input_tx(
        OutPoint {
            txid: commitment.tx.compute_txid(),
            vout: htlc.vout,
        },
        sequence,
        lock_time,
        vec![TxOut {
            value: output_value,
            script_pubkey: claim.destination,
        }],
    );
    let prevouts = [TxOut {
        value: htlc.htlc.amount,
        script_pubkey: htlc.scripts.script_pubkey.clone(),
    }];
    let signature = sign_leaf(&tx, 0, &prevouts, leaf.leaf_hash, key, rules, aux)?;
    let mut witness = vec![signature.as_bytes().to_vec()];
    if claim.path == HtlcClaimPath::Success {
        witness.push(claim.preimage.ok_or(Error::MissingPreimage)?.to_vec());
    }
    witness.push(leaf.script.to_bytes());
    witness.push(leaf.control_block.clone());
    tx.input[0].witness = Witness::from_slice(&witness);
    Ok(tx)
}

/// Spend a plain `to_remote` output by its literal x-only key path.
pub fn key_path_spend(
    outpoint: OutPoint,
    prevout: TxOut,
    destination: ScriptBuf,
    fee: Amount,
    key: &SecretKey,
    rules: SighashRules,
    aux: &[u8; 32],
) -> Result<Transaction> {
    let output_value = claim_value(prevout.value, fee)?;
    let mut tx = one_input_tx(
        outpoint,
        INPUT_SEQUENCE,
        LockTime::ZERO,
        vec![TxOut {
            value: output_value,
            script_pubkey: destination,
        }],
    );
    let hash_type = key_path_hash_type(rules);
    let (message, returned_type) =
        key_path_sighash(&tx, 0, &[prevout], rules).map_err(Error::Sighash)?;
    debug_assert_eq!(hash_type, returned_type);
    let keypair = Keypair::from_secret_key(secp(), key);
    let signature =
        secp().sign_schnorr_with_aux_rand(&Message::from_digest(message), &keypair, aux);
    let mut wire = signature.as_ref().to_vec();
    wire.push(hash_type);
    tx.input[0].witness = Witness::from_slice(&[wire]);
    Ok(tx)
}

fn payout_after_fee(balance: Amount, side: Side, fee: Amount) -> Amount {
    if side == Side::A {
        Amount::from_sat(balance.to_sat().saturating_sub(fee.to_sat()))
    } else {
        balance
    }
}

fn claim_value(value: Amount, fee: Amount) -> Result<Amount> {
    let value = value
        .to_sat()
        .checked_sub(fee.to_sat())
        .filter(|value| *value >= DUST)
        .ok_or(Error::DustClaim)?;
    Ok(Amount::from_sat(value))
}

fn tagged_sha256(tag: &[u8], message: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag).to_byte_array();
    let mut engine = sha256::Hash::engine();
    engine.input(&tag_hash);
    engine.input(&tag_hash);
    engine.input(message);
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn decode_hex_into(text: &str, out: &mut [u8]) -> Option<()> {
    if text.len() != out.len() * 2 {
        return None;
    }
    for (target, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *target = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(())
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn taproot_output(
    internal_key: XOnlyPublicKey,
    root: TapNodeHash,
) -> (TweakedPublicKey, Parity, ScriptBuf) {
    let (output_key, parity) = internal_key.tap_tweak(secp(), Some(root));
    let mut script = Vec::with_capacity(34);
    script.extend_from_slice(&[0x51, 0x20]);
    script.extend_from_slice(&output_key.serialize());
    (output_key, parity, ScriptBuf::from_bytes(script))
}

fn control_block(
    internal_key: XOnlyPublicKey,
    parity: Parity,
    merkle_path: &[TapNodeHash],
) -> Vec<u8> {
    let mut control = Vec::with_capacity(33 + merkle_path.len() * 32);
    control.push(LeafVersion::TapScript.to_consensus() | u8::from(parity));
    control.extend_from_slice(&internal_key.serialize());
    for node in merkle_path {
        control.extend_from_slice(node.as_ref());
    }
    control
}

fn push_key(script: &mut Vec<u8>, key: XOnlyPublicKey) {
    script.push(0x20);
    script.extend_from_slice(&key.serialize());
}

fn push_num(script: &mut Vec<u8>, n: u32) -> Result<()> {
    if n > 0x7fff_ffff {
        return Err(Error::ScriptNumber(n));
    }
    if n == 0 {
        script.push(0x00);
        return Ok(());
    }
    if n <= 16 {
        script.push(0x50 + n as u8);
        return Ok(());
    }
    let mut value = n;
    let mut bytes = Vec::new();
    while value > 0 {
        bytes.push((value & 0xff) as u8);
        value >>= 8;
    }
    if bytes.last().is_some_and(|byte| byte & 0x80 != 0) {
        bytes.push(0);
    }
    script.push(bytes.len() as u8);
    script.extend_from_slice(&bytes);
    Ok(())
}

fn one_input_tx(
    outpoint: OutPoint,
    sequence: u32,
    lock_time: LockTime,
    output: Vec<TxOut>,
) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        }],
        output,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::{deserialize, serialize};
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn public(key: &SecretKey) -> XOnlyPublicKey {
        Keypair::from_secret_key(secp(), key).x_only_public_key().0
    }

    fn channel() -> (Channel, SecretKey, SecretKey) {
        let a = key(0x11);
        let b = key(0x22);
        let channel = Channel::new(
            public(&a),
            public(&b),
            OutPoint {
                txid: Txid::from_byte_array([0xab; 32]),
                vout: 1,
            },
            Amount::from_sat(100_000),
            Amount::from_sat(DEFAULT_FEE),
            DEFAULT_DELAY,
        )
        .unwrap();
        (channel, a, b)
    }

    #[test]
    fn scripts_match_hitch_golden_vectors() {
        let (channel, a, b) = channel();
        assert_eq!(
            internal_key().unwrap().to_string(),
            "257ea3139d352eb3705808452e5268c6b932af03a03e09bfe9017bb8be3b3ece"
        );
        assert_eq!(
            channel.funding_script.script_pubkey.to_hex_string(),
            "51201c17bc9ec453913ba2e233ea77bab2fb84e8091fd232568b3eef046717dbed72"
        );
        assert_eq!(
            channel.funding_script.leaf.script.to_hex_string(),
            "20466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27ac204f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aaba529c"
        );
        let local = to_local_script(public(&a), public(&b), 6).unwrap();
        assert_eq!(
            local.script_pubkey.to_hex_string(),
            "5120cc7c54c2ace9c757d114cc18cb05b3865580ced8004519f72dbb104fdbc7bbc1"
        );
        assert_eq!(
            local.delayed.script.to_hex_string(),
            "56b275204f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aaac"
        );
        let htlc = htlc_script(HtlcScriptArgs {
            owner_pub: public(&a),
            remote_pub: public(&b),
            revocation_pub: public(&b),
            delay: 6,
            payment_hash: [0xab; 32],
            expiry: 152_200,
            offered_by_owner: true,
        })
        .unwrap();
        assert_eq!(
            htlc.script_pubkey.to_hex_string(),
            "5120cf2924765a12e11e9fed368d5251a591d40159e95c9d4da98066232542956a20"
        );
        assert_eq!(
            htlc.success.script.to_hex_string(),
            "a820abababababababababababababababababababababababababababababababab8820466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27ac"
        );
        assert_eq!(
            htlc.timeout.script.to_hex_string(),
            "03885202b17556b275204f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aaac"
        );
    }

    #[test]
    fn commitments_and_close_match_hitch_shape() {
        let (channel, _, _) = channel();
        let state = ChannelState {
            balances: Balances {
                a: Amount::from_sat(60_000),
                b: Amount::from_sat(40_000),
            },
            revocation: RevocationKeys {
                a: public(&key(0x33)),
                b: public(&key(0x44)),
            },
            htlcs: vec![],
        };
        let a = channel.commitment(1, Side::A, &state).unwrap();
        let b = channel.commitment(1, Side::B, &state).unwrap();
        assert_eq!(a.kinds, [OutputKind::ToLocal, OutputKind::ToRemote]);
        assert_eq!(a.local_value, Amount::from_sat(59_700));
        assert_eq!(a.remote_value, Amount::from_sat(40_000));
        assert_eq!(b.local_value, Amount::from_sat(40_000));
        assert_eq!(b.remote_value, Amount::from_sat(59_700));
        assert_ne!(a.tx.compute_txid(), b.tx.compute_txid());
        let close = channel.cooperative_close(&state).unwrap();
        assert_eq!(close.output.len(), 2);
        assert_eq!(
            close.output.iter().map(|o| o.value.to_sat()).sum::<u64>(),
            99_700
        );
        let encoded = serialize(&a.tx);
        let decoded: Transaction = deserialize(&encoded).unwrap();
        assert_eq!(decoded.compute_txid(), a.tx.compute_txid());
    }

    #[test]
    fn both_sighash_families_sign_the_funding_leaf() {
        let (channel, a, b) = channel();
        let state = ChannelState {
            balances: Balances {
                a: Amount::from_sat(60_000),
                b: Amount::from_sat(40_000),
            },
            revocation: RevocationKeys {
                a: public(&key(0x33)),
                b: public(&key(0x44)),
            },
            htlcs: vec![],
        };
        for rules in [SighashRules::Bip341, SighashRules::KnotsUnified] {
            let mut commitment = channel.commitment(1, Side::A, &state).unwrap();
            let sig_a = channel
                .sign_funding(&commitment.tx, &a, rules, &[0; 32])
                .unwrap();
            let sig_b = channel
                .sign_funding(&commitment.tx, &b, rules, &[0; 32])
                .unwrap();
            assert!(channel.verify_funding(&commitment.tx, &public(&a), &sig_a, rules));
            assert!(channel.verify_funding(&commitment.tx, &public(&b), &sig_b, rules));
            assert!(!channel.verify_funding(&commitment.tx, &public(&a), &sig_b, rules));
            let signatures = BTreeMap::from([(public(&a), sig_a), (public(&b), sig_b)]);
            commitment.tx.input[0].witness = channel.funding_witness(&signatures).unwrap();
            assert_eq!(commitment.tx.input[0].witness.len(), 4);
            let expected_type = if rules == SighashRules::KnotsUnified {
                0x21
            } else {
                0x01
            };
            assert_eq!(commitment.tx.input[0].witness[0][64], expected_type);
            assert_eq!(commitment.tx.input[0].witness[1][64], expected_type);
        }
    }

    #[test]
    fn every_htlc_claim_path_has_the_reference_sequence_and_locktime() {
        let (channel, a, b) = channel();
        let preimage = [0x55; 32];
        let state = ChannelState {
            balances: Balances {
                a: Amount::from_sat(40_000),
                b: Amount::from_sat(40_000),
            },
            revocation: RevocationKeys {
                a: public(&key(0x33)),
                b: public(&key(0x44)),
            },
            htlcs: vec![Htlc {
                id: 1,
                from: Side::A,
                amount: Amount::from_sat(20_000),
                payment_hash: sha256::Hash::hash(&preimage).to_byte_array(),
                expiry: 152_200,
            }],
        };
        let owner_a = channel.commitment(2, Side::A, &state).unwrap();
        let owner_b = channel.commitment(2, Side::B, &state).unwrap();
        let destination_b = to_remote_script(public(&b));
        let success_a = claim_htlc(
            &owner_a,
            &owner_a.htlcs[0],
            HtlcClaim {
                path: HtlcClaimPath::Success,
                destination: destination_b.clone(),
                fee: Amount::from_sat(200),
                preimage: Some(preimage),
            },
            &b,
            SighashRules::KnotsUnified,
            &[0; 32],
        )
        .unwrap();
        assert_eq!(
            success_a.input[0].sequence.to_consensus_u32(),
            LOCKTIME_SEQUENCE
        );
        assert_eq!(success_a.lock_time, LockTime::ZERO);

        let timeout_a = claim_htlc(
            &owner_a,
            &owner_a.htlcs[0],
            HtlcClaim {
                path: HtlcClaimPath::Timeout,
                destination: to_remote_script(public(&a)),
                fee: Amount::from_sat(200),
                preimage: None,
            },
            &a,
            SighashRules::KnotsUnified,
            &[0; 32],
        )
        .unwrap();
        assert_eq!(timeout_a.input[0].sequence.to_consensus_u32(), 6);
        assert_eq!(timeout_a.lock_time.to_consensus_u32(), 152_200);

        let success_b = claim_htlc(
            &owner_b,
            &owner_b.htlcs[0],
            HtlcClaim {
                path: HtlcClaimPath::Success,
                destination: destination_b,
                fee: Amount::from_sat(200),
                preimage: Some(preimage),
            },
            &b,
            SighashRules::KnotsUnified,
            &[0; 32],
        )
        .unwrap();
        assert_eq!(success_b.input[0].sequence.to_consensus_u32(), 6);
        let revocation = claim_htlc(
            &owner_a,
            &owner_a.htlcs[0],
            HtlcClaim {
                path: HtlcClaimPath::Revocation,
                destination: to_remote_script(public(&b)),
                fee: Amount::from_sat(200),
                preimage: None,
            },
            &key(0x33),
            SighashRules::KnotsUnified,
            &[0; 32],
        )
        .unwrap();
        assert_eq!(
            revocation.input[0].sequence.to_consensus_u32(),
            INPUT_SEQUENCE
        );
    }

    /// Hitch `test/channel-test.mjs`, the two-party revocation section.
    #[test]
    fn two_party_revocation_key_matches_hitch_golden_vectors() {
        let r = key(0x33);
        let s = key(0x44);
        let p1 = revocation_pub(public(&r), &s).unwrap();
        let p2 = revocation_pub(public(&s), &r).unwrap();
        assert_eq!(p1, p2, "R + s·G = S + r·G");
        assert_eq!(
            p1.to_string(),
            "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
        );
        let combined = revocation_key(&r, &s).unwrap();
        assert_eq!(public(&combined), p1);

        // Hitch draws the channel keys at random here; fixed 0x11 would equal
        // the combined key of these vectors (-0x33.. + 0x44.. = 0x11..).
        let a = key(0x12);
        let b = key(0x23);
        let channel = Channel::new(
            public(&a),
            public(&b),
            OutPoint {
                txid: Txid::from_byte_array([0xab; 32]),
                vout: 1,
            },
            Amount::from_sat(100_000),
            Amount::from_sat(DEFAULT_FEE),
            DEFAULT_DELAY,
        )
        .unwrap();
        let local = to_local_script(public(&a), p1, 6).unwrap();
        let state = ChannelState {
            balances: Balances {
                a: Amount::from_sat(60_000),
                b: Amount::from_sat(40_000),
            },
            revocation: RevocationKeys { a: p1, b: p1 },
            htlcs: vec![],
        };
        let commitment = channel.commitment(1, Side::A, &state).unwrap();
        assert_eq!(commitment.to_local, local);
        let prevouts = [TxOut {
            value: commitment.local_value,
            script_pubkey: local.script_pubkey.clone(),
        }];
        for rules in [SighashRules::Bip341, SighashRules::KnotsUnified] {
            let both = sweep_to_local(
                &commitment,
                SweepPath::Revocation,
                to_remote_script(public(&b)),
                Amount::from_sat(200),
                &combined,
                rules,
                &[0; 32],
            )
            .unwrap();
            let sig = LeafSignature::from_slice(&both.input[0].witness[0]).unwrap();
            assert!(verify_leaf_signature(
                &both,
                0,
                &prevouts,
                local.revocation.leaf_hash,
                &p1,
                &sig,
                rules
            ));
            // Neither secret alone, nor the owner's channel key, opens the leaf.
            for alone in [s, r, a] {
                let one = sweep_to_local(
                    &commitment,
                    SweepPath::Revocation,
                    to_remote_script(public(&b)),
                    Amount::from_sat(200),
                    &alone,
                    rules,
                    &[0; 32],
                )
                .unwrap();
                let sig = LeafSignature::from_slice(&one.input[0].witness[0]).unwrap();
                assert!(!verify_leaf_signature(
                    &one,
                    0,
                    &prevouts,
                    local.revocation.leaf_hash,
                    &p1,
                    &sig,
                    rules
                ));
            }
        }
    }

    /// Hitch `test/channel-test.mjs`: fixed keys, fixed funding and fixed
    /// revocation points give transaction ids that must never change, or
    /// funded channels are stranded.
    #[test]
    fn commitment_and_close_txids_match_hitch_golden_vectors() {
        let (channel, _, _) = channel();
        let p1 = revocation_pub(public(&key(0x33)), &key(0x44)).unwrap();
        let revocation = RevocationKeys { a: p1, b: p1 };
        let state = ChannelState {
            balances: Balances {
                a: Amount::from_sat(60_000),
                b: Amount::from_sat(40_000),
            },
            revocation,
            htlcs: vec![],
        };
        assert_eq!(
            channel
                .commitment(1, Side::A, &state)
                .unwrap()
                .tx
                .compute_txid()
                .to_string(),
            "138fe22589d87f2f363907ad877a25f73d20d5415f233c7dcc0dbd9ac2f03c13"
        );
        assert_eq!(
            channel
                .commitment(1, Side::B, &state)
                .unwrap()
                .tx
                .compute_txid()
                .to_string(),
            "56ae7f0fb0b450356387a552da8a952eae772286320e2a94f36ee7c07ce05152"
        );
        let with_htlc = ChannelState {
            balances: Balances {
                a: Amount::from_sat(40_000),
                b: Amount::from_sat(40_000),
            },
            revocation,
            htlcs: vec![Htlc {
                id: 1,
                from: Side::A,
                amount: Amount::from_sat(20_000),
                payment_hash: [0xab; 32],
                expiry: 152_200,
            }],
        };
        assert_eq!(
            channel
                .commitment(2, Side::A, &with_htlc)
                .unwrap()
                .tx
                .compute_txid()
                .to_string(),
            "4cd9bf1f440e682fcfae5d1bb0e0dd11ff9ce71d738d9ad60e8b6f3e4fe30110"
        );
        assert_eq!(
            channel
                .cooperative_close(&state)
                .unwrap()
                .compute_txid()
                .to_string(),
            "5a31ac748e2e364b1c11f21b32b85d8e539dbf9baa9f4a8c41c596a41065d1b7"
        );
    }

    #[test]
    fn htlc_revocation_leaf_needs_both_secrets_and_preimage_is_read_back() {
        let (channel, a, b) = channel();
        let r = key(0x33);
        let s = key(0x44);
        let p1 = revocation_pub(public(&r), &s).unwrap();
        let preimage = [0x55; 32];
        let payment_hash = sha256::Hash::hash(&preimage).to_byte_array();
        let state = ChannelState {
            balances: Balances {
                a: Amount::from_sat(40_000),
                b: Amount::from_sat(40_000),
            },
            revocation: RevocationKeys { a: p1, b: p1 },
            htlcs: vec![Htlc {
                id: 1,
                from: Side::B,
                amount: Amount::from_sat(20_000),
                payment_hash,
                expiry: 152_200,
            }],
        };
        let commitment = channel.commitment(2, Side::A, &state).unwrap();
        let htlc = &commitment.htlcs[0];
        let prevouts = [TxOut {
            value: htlc.htlc.amount,
            script_pubkey: htlc.scripts.script_pubkey.clone(),
        }];
        let claim = |key: &SecretKey, path, preimage| {
            claim_htlc(
                &commitment,
                htlc,
                HtlcClaim {
                    path,
                    destination: to_remote_script(public(&b)),
                    fee: Amount::from_sat(200),
                    preimage,
                },
                key,
                SighashRules::KnotsUnified,
                &[0; 32],
            )
            .unwrap()
        };
        let verifies = |tx: &Transaction, leaf: TapLeafHash, pubkey: XOnlyPublicKey| {
            let sig = LeafSignature::from_slice(&tx.input[0].witness[0]).unwrap();
            verify_leaf_signature(
                tx,
                0,
                &prevouts,
                leaf,
                &pubkey,
                &sig,
                SighashRules::KnotsUnified,
            )
        };
        let leaf = htlc.scripts.revocation.leaf_hash;
        let combined = revocation_key(&r, &s).unwrap();
        assert!(verifies(
            &claim(&combined, HtlcClaimPath::Revocation, None),
            leaf,
            p1
        ));
        assert!(!verifies(
            &claim(&s, HtlcClaimPath::Revocation, None),
            leaf,
            p1
        ));

        // A success claim by A (the receiver on its own commitment) carries
        // the preimage; a timeout claim carries none.
        let success = claim(&a, HtlcClaimPath::Success, Some(preimage));
        assert_eq!(preimage_in(&success, &payment_hash), Some(preimage));
        let timeout = claim(&b, HtlcClaimPath::Timeout, None);
        assert_eq!(preimage_in(&timeout, &payment_hash), None);
    }

    #[test]
    fn proof_of_possession_binds_the_point_and_its_place() {
        let secret = key(0x51);
        let point = public(&secret);
        let proof = pop_sign(&secret, "abababababababab/a/base", &[7; 32]);
        assert!(pop_verify(&point, &proof, "abababababababab/a/base"));
        assert!(!pop_verify(&point, &proof, "abababababababab/a/0"));
        assert!(!pop_verify(
            &public(&key(0x52)),
            &proof,
            "abababababababab/a/base"
        ));
        // A proof made with another secret does not cover a chosen point.
        let forged = pop_sign(&key(0x54), "abababababababab/a/base", &[7; 32]);
        assert!(!pop_verify(&point, &forged, "abababababababab/a/base"));
        assert_eq!(PopSignature::from_hex(&proof.to_hex()).unwrap(), proof);
        assert!(PopSignature::from_hex("ab").is_err());
    }

    #[test]
    fn even_secret_lifts_to_the_even_point() {
        for byte in 1..=40u8 {
            let k = key(byte);
            let even = even_secret(&k);
            assert_eq!(public(&even), public(&k));
            assert_eq!(even.x_only_public_key(secp()).1, Parity::Even);
        }
    }

    #[test]
    fn state_value_and_policy_bounds_are_checked() {
        let (channel, _, _) = channel();
        let bad = ChannelState {
            balances: Balances {
                a: Amount::from_sat(100_001),
                b: Amount::ZERO,
            },
            revocation: RevocationKeys {
                a: channel.keys[0],
                b: channel.keys[1],
            },
            htlcs: vec![],
        };
        assert!(matches!(
            channel.commitment(0, Side::A, &bad),
            Err(Error::Unbalanced { .. })
        ));
        assert!(Channel::new(
            channel.keys[0],
            channel.keys[1],
            channel.funding_outpoint,
            channel.funding_value,
            Amount::from_sat(99),
            6,
        )
        .is_err());
    }
}
