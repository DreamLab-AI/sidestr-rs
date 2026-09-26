//! A carrier's Ethereum transaction, read as the reference reads it
//! (`evm.mjs applyTx`: `createTxFromRLP`, then `isSigned()` and
//! `verifySignature()`), with alloy's envelope, EIP-2718 decoding and
//! signer recovery.
//!
//! What is carried: legacy transactions (EIP-155 for the chain's id, or the
//! unprotected `v` of 27 or 28), EIP-2930 and EIP-1559 transactions for the
//! chain's id. What is not, as there: a blob transaction (EIP-4844) — the
//! reference's `Common` has no KZG, and ethereumjs will not even construct
//! one without it — and an EIP-7702 one, which Cancun does not have. The
//! bytes must be exactly one transaction, canonically encoded; the signature
//! must have a low `s` (EIP-2) and recover. `tests/fixtures/decode.json`
//! holds the reference's answers at the edges.

use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{Transaction as _, TxEnvelope};
use alloy_eips::eip2718::{Decodable2718, Typed2718};
use alloy_primitives::{Address, B256};

/// A carried transaction that reads and whose signature recovers.
#[derive(Debug, Clone, PartialEq)]
pub struct Carried {
    /// The signed transaction.
    pub envelope: TxEnvelope,
    /// Who signed it.
    pub sender: Address,
    /// Its hash, as Ethereum names it.
    pub hash: B256,
}

/// Read a carrier's bytes as a signed transaction for chain `chain_id`, or
/// say why they are not one. The reasons are this crate's words; the
/// reference's differ, and only whether a carrier reads is consensus.
///
/// ```
/// use sidestr_evm::tx::decode_carrier;
///
/// assert!(decode_carrier(&[1, 2, 3, 4], 21474).unwrap_err().starts_with("not an Ethereum transaction"));
/// ```
pub fn decode_carrier(rlp: &[u8], chain_id: u64) -> Result<Carried, String> {
    let envelope = TxEnvelope::decode_2718_exact(rlp)
        .map_err(|e| format!("not an Ethereum transaction ({e})"))?;
    match envelope.ty() {
        0..=2 => {}
        3 => return Err("a blob transaction (EIP-4844): the rule has no KZG".into()),
        t => return Err(format!("transaction type {t} is not carried at Cancun")),
    }
    match envelope.chain_id() {
        Some(id) if id != chain_id => {
            return Err(format!("signed for chain {id}, not {chain_id}"));
        }
        // only a legacy transaction may leave the chain out (v = 27 or 28)
        None if !envelope.is_legacy() => return Err("no chain id".into()),
        _ => {}
    }
    let sender = envelope
        .recover_signer()
        .map_err(|_| "unsigned or bad signature".to_string())?;
    let hash = *envelope.tx_hash();
    Ok(Carried {
        envelope,
        sender,
        hash,
    })
}
