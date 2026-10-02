//! Signing a **parent** transaction's taproot key-path inputs, as Fid
//! (bitcoin-blake/fidsigner `2c4057c`, `fid.js signPsbt`, Melvin Carvalho)
//! signs a PSBT: the inputs that pay the signer's own `5120‖key` and carry
//! no witness yet are signed, every other input is left as it is.
//!
//! The parent's family picks the message, as it does for a sidechain spend
//! ([`sidestr_core::sighash::rules_for`]):
//!
//! - beside a BLAKE2b parent (`xbt`, `txbt4`), Knots' unified sighash with
//!   hash type `0x21`: a 65-byte witness ending in `0x21`, which a node
//!   without the fork cannot replay onto the SHA-256d chain;
//! - beside stock Bitcoin (`btc`, `tbtc4`), BIP 341 with `SIGHASH_DEFAULT`:
//!   a 64-byte witness, as every taproot wallet writes one.
//!
//! The second differs on purpose from this crate's sidechain builders,
//! which always write an explicit `0x01` beside stock Bitcoin
//! ([`sidestr_core::sighash::key_path_hash_type`]) so that every sidechain
//! witness names its rule; on the parent the bytes are Fid's, so a
//! transaction signed here matches Fid's published vectors byte for byte
//! (`tests/fidsigner.rs`).
//!
//! Signatures go through the [`SpendSigner`] port, so the secret stays
//! wherever the signer keeps it. No [`SpendPolicy`](crate::policy::SpendPolicy)
//! is consulted: the caller already holds the whole parent transaction (a
//! peg-in it planned, a PSBT it was handed), and the port signs only
//! key-path sighashes for coins paying its own key.

use bitcoin::hashes::Hash;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{Transaction, TxOut, Witness};
use sidestr_core::sighash::{
    unified_taproot_sighash, verify_taproot_key_path, SighashRules, UnifiedTaproot, SIGHASH_UNIFIED,
};

use crate::error::{Error, Result};
use crate::key::SpendSigner;

/// Sign every input of `tx` that pays `signer`'s script and has no witness
/// yet, over all of `prevouts` (one per input, in order), under the parent's
/// `rules`; then verify each signature as a node would. Returns the indices
/// signed, in order (none when no input is the signer's).
///
/// ```
/// use bitcoin::secp256k1::SecretKey;
/// use bitcoin::{absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
/// use bitcoin::hashes::Hash;
/// use sidestr_core::sighash::SighashRules;
/// use sidestr_wallet::parent_sign::sign_parent_inputs;
/// use sidestr_wallet::{PlainKey, SpendSigner};
///
/// let key = PlainKey::new(SecretKey::from_slice(&[0x11; 32]).unwrap());
/// let prevouts = vec![TxOut { value: Amount::from_sat(50_000), script_pubkey: key.script() }];
/// let unsigned = Transaction { version: Version::TWO, lock_time: LockTime::ZERO,
///     input: vec![TxIn { previous_output: OutPoint { txid: Txid::all_zeros(), vout: 0 }, script_sig: ScriptBuf::new(),
///                        sequence: Sequence(0xffff_fffd), witness: Witness::new() }],
///     output: vec![TxOut { value: Amount::from_sat(49_000), script_pubkey: key.script() }] };
///
/// // beside txbt4: 0x21, 65 bytes; beside tbtc4: SIGHASH_DEFAULT, 64 bytes
/// let mut tx = unsigned.clone();
/// assert_eq!(sign_parent_inputs(&mut tx, &prevouts, SighashRules::KnotsUnified, &key).unwrap(), vec![0]);
/// assert_eq!((tx.input[0].witness[0].len(), tx.input[0].witness[0][64]), (65, 0x21));
/// let mut tx = unsigned.clone();
/// sign_parent_inputs(&mut tx, &prevouts, SighashRules::Bip341, &key).unwrap();
/// assert_eq!(tx.input[0].witness[0].len(), 64);
/// ```
pub fn sign_parent_inputs(
    tx: &mut Transaction,
    prevouts: &[TxOut],
    rules: SighashRules,
    signer: &dyn SpendSigner,
) -> Result<Vec<usize>> {
    if prevouts.len() != tx.input.len() {
        return Err(Error::Signer(
            "every input needs its spent output to sign".into(),
        ));
    }
    if signer.signs_elsewhere() {
        return Err(Error::Signer(
            "this key signs elsewhere: hand it the transaction instead".into(),
        ));
    }
    let ours = signer.script();
    let mine: Vec<usize> = (0..tx.input.len())
        .filter(|&i| prevouts[i].script_pubkey == ours && tx.input[i].witness.is_empty())
        .collect();
    let mut witnesses = Vec::with_capacity(mine.len());
    for &i in &mine {
        let item = match rules {
            SighashRules::KnotsUnified => {
                let hash_type = 0x01 | SIGHASH_UNIFIED;
                let msg = unified_taproot_sighash(
                    tx,
                    i,
                    prevouts,
                    hash_type,
                    None,
                    UnifiedTaproot::KeyPath,
                )
                .map_err(|e| Error::Signer(format!("sighash: {e}")))?;
                let mut sig = signer.sign_key_path(&msg)?.serialize().to_vec();
                sig.push(hash_type);
                sig
            }
            SighashRules::Bip341 => {
                let msg = SighashCache::new(&*tx)
                    .taproot_key_spend_signature_hash(
                        i,
                        &Prevouts::All(prevouts),
                        TapSighashType::Default,
                    )
                    .map_err(|e| Error::Signer(format!("sighash: {e}")))?
                    .to_byte_array();
                signer.sign_key_path(&msg)?.serialize().to_vec()
            }
        };
        witnesses.push(item);
    }
    for (&i, item) in mine.iter().zip(witnesses) {
        tx.input[i].witness = Witness::from_slice(&[item]);
    }
    for &i in &mine {
        verify_taproot_key_path(tx, i, prevouts, rules)
            .map_err(|e| Error::Signer(format!("input {i} does not verify after signing: {e}")))?;
    }
    Ok(mine)
}
