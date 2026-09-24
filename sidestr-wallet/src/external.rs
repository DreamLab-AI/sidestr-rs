//! Spends signed somewhere else: a browser extension behind
//! `window.nostr.sidestr.signTransaction` (spec `proposals/browser-signer.md`).
//!
//! The page builds the spend with an [`ExternalSigner`] — the member's public
//! key and nothing else — so every builder lays it out, sizes it and checks
//! it exactly as it would a signed one, and leaves 65-byte placeholders where
//! the witnesses go. [`unsigned_hex`] is what the page hands the extension.
//! The extension resolves the chain itself, shows the person what the spend
//! does, computes each sighash and signs. [`accept_signed`] takes the answer
//! back and trusts none of it: the transaction must be the one that was
//! built (same txid, so the same inputs, outputs, version and lock time),
//! and every input must verify under the chain's rules against the prevouts
//! the page built from.
//!
//! ```
//! use bitcoin::secp256k1::{Keypair, Message, SecretKey};
//! use bitcoin::hashes::Hash;
//! use bitcoin::{Amount, OutPoint, TxOut, Txid, Witness};
//! use sidestr_core::block::secp;
//! use sidestr_core::document::ChainDocument;
//! use sidestr_core::sighash::{key_path_sighash, SighashRules};
//! use sidestr_wallet::external::{accept_signed, unsigned_hex, ExternalSigner};
//! use sidestr_wallet::{build_spend, Coin, Permissive, SpendRequest, SpendSigner};
//!
//! let chain: ChainDocument = serde_json::from_str(r#"{"id":"sidestr:ex","name":"ex","parent":"tbtc4",
//!   "challenge":"5120aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
//!   "powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
//!   "addressPrefix":"ex","genesisTime":1790000000,"pegs":[],"minFeeRate":1}"#).unwrap();
//! // the extension's key; the page knows only its public half
//! let kp = Keypair::from_secret_key(secp(), &SecretKey::from_slice(&[7; 32]).unwrap());
//! let member = ExternalSigner::new(kp.x_only_public_key().0);
//! let coin = Coin { outpoint: OutPoint { txid: Txid::from_byte_array([1; 32]), vout: 0 },
//!                   value: 20_000, height: 1, coinbase: false };
//! let bob = "5120".to_string() + &"bb".repeat(32);
//! let built = build_spend(&SpendRequest { chain: &chain, coins: &[coin], tip_height: 10,
//!     to: &bob, amount: 5_000, fee: None }, &member, &Permissive).unwrap();
//!
//! // what goes to window.nostr.sidestr.signTransaction: no witnesses
//! assert!(!unsigned_hex(&built.tx).is_empty());
//!
//! // the extension signs (here, by hand) ...
//! let prevouts = vec![TxOut { value: Amount::from_sat(20_000), script_pubkey: member.script() }];
//! let mut signed = built.tx.clone();
//! let (msg, ht) = key_path_sighash(&signed, 0, &prevouts, SighashRules::Bip341).unwrap();
//! let sig = secp().sign_schnorr_with_aux_rand(&Message::from_digest(msg), &kp, &[0; 32]);
//! signed.input[0].witness = Witness::from_slice(&[[sig.serialize().as_slice(), &[ht]].concat()]);
//! let answer = bitcoin::consensus::encode::serialize_hex(&signed);
//!
//! // ... and the page takes it back only if it is the same spend, validly signed
//! let spend = accept_signed(&built, &answer, &prevouts, &chain).unwrap();
//! assert_eq!(spend.txid, built.txid);
//! ```

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::key::XOnlyPublicKey;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::{Transaction, TxOut, Witness};
use sidestr_core::document::ChainDocument;
use sidestr_core::parents::resolve_parent;
use sidestr_core::sighash::{rules_for, verify_taproot_key_path};

use crate::error::{Error, Result};
use crate::key::SpendSigner;
use crate::spend::Spend;

/// A member's key held by someone else: it names the public key, so the
/// builders know which coins and scripts are the member's, and it
/// [signs elsewhere](SpendSigner::signs_elsewhere). Its
/// [`sign_key_path`](SpendSigner::sign_key_path) always refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalSigner {
    pubkey: XOnlyPublicKey,
}

impl ExternalSigner {
    /// The signer for the x-only key `pubkey` (a Nostr public key).
    pub fn new(pubkey: XOnlyPublicKey) -> Self {
        Self { pubkey }
    }
}

impl SpendSigner for ExternalSigner {
    fn pubkey(&self) -> XOnlyPublicKey {
        self.pubkey
    }
    fn sign_key_path(&self, _sighash: &[u8; 32]) -> Result<Signature> {
        Err(Error::Signer(
            "this key signs elsewhere: send the unsigned transaction to its signer".into(),
        ))
    }
    fn signs_elsewhere(&self) -> bool {
        true
    }
}

/// `tx` as hex with every witness removed: the request a browser signer
/// takes. The txid is unchanged, since a txid never covers witnesses.
pub fn unsigned_hex(tx: &Transaction) -> String {
    let mut bare = tx.clone();
    for i in &mut bare.input {
        i.witness = Witness::new();
    }
    serialize_hex(&bare)
}

/// Take a transaction an external signer returned for `built` and check it:
/// it decodes; its txid is `built`'s (so it spends the same coins to the same
/// outputs); and every input verifies on the key path under the sighash rules
/// of `chain`'s parent family against `prevouts`, the outputs `built` spends
/// in input order, which the caller read from its own chain state. Returns
/// `built` with the signed transaction, its hex and its size.
pub fn accept_signed(
    built: &Spend,
    signed_hex: &str,
    prevouts: &[TxOut],
    chain: &ChainDocument,
) -> Result<Spend> {
    let tx: Transaction = deserialize_hex(signed_hex.trim()).map_err(|_| {
        Error::Signer("the signer returned something that is not a transaction".into())
    })?;
    if tx.compute_txid() != built.txid {
        return Err(Error::Signer(
            "the signer returned a different transaction from the one asked for".into(),
        ));
    }
    if prevouts.len() != tx.input.len() {
        return Err(Error::Signer(format!(
            "{} prevouts for {} inputs",
            prevouts.len(),
            tx.input.len()
        )));
    }
    let parent = resolve_parent(&chain.parent)
        .map_err(|_| Error::Signer(format!("unknown parent {}", chain.parent)))?;
    let rules = rules_for(parent.family);
    for i in 0..tx.input.len() {
        verify_taproot_key_path(&tx, i, prevouts, rules)
            .map_err(|e| Error::Signer(format!("input {i} is not validly signed: {e}")))?;
    }
    Ok(Spend {
        hex: serialize_hex(&tx),
        vsize: tx.weight().to_wu().div_ceil(4),
        tx,
        note: built.note.clone(),
        ..*built
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose::{build_outputs, OutputsRequest};
    use crate::{build_spend, Coin, Permissive, PlainKey, SpendRequest};
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Message, SecretKey};
    use bitcoin::{Amount, OutPoint, ScriptBuf, Txid};
    use sidestr_core::block::secp;
    use sidestr_core::sighash::{key_path_sighash, SighashRules};

    fn chain() -> ChainDocument {
        ChainDocument::from_json(
            r#"{"id":"sidestr:ex","name":"ex","parent":"tbtc4",
            "challenge":"5120aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "addressPrefix":"ex","genesisTime":1790000000,"pegs":[],"minFeeRate":1}"#,
        )
        .unwrap()
    }
    fn kp(b: u8) -> Keypair {
        Keypair::from_secret_key(secp(), &SecretKey::from_slice(&[b; 32]).unwrap())
    }
    fn coins() -> Vec<Coin> {
        (0..2u8)
            .map(|i| Coin {
                outpoint: OutPoint {
                    txid: Txid::from_byte_array([i + 1; 32]),
                    vout: 0,
                },
                value: 3_000,
                height: 1,
                coinbase: false,
            })
            .collect()
    }
    fn bob() -> String {
        format!("5120{}", "bb".repeat(32))
    }
    fn prevouts(s: &Spend, me: &ScriptBuf) -> Vec<TxOut> {
        s.tx.input
            .iter()
            .map(|i| {
                let c = coins()
                    .into_iter()
                    .find(|c| c.outpoint == i.previous_output)
                    .unwrap();
                TxOut {
                    value: Amount::from_sat(c.value),
                    script_pubkey: me.clone(),
                }
            })
            .collect()
    }
    fn sign_with(tx: &Transaction, prevouts: &[TxOut], k: &Keypair) -> Transaction {
        let mut t = tx.clone();
        for i in 0..t.input.len() {
            let (m, ht) = key_path_sighash(&t, i, prevouts, SighashRules::Bip341).unwrap();
            let sig = secp().sign_schnorr_with_aux_rand(&Message::from_digest(m), k, &[0; 32]);
            t.input[i].witness =
                Witness::from_slice(&[[sig.serialize().as_slice(), &[ht]].concat()]);
        }
        t
    }
    fn build(ext: &ExternalSigner) -> Spend {
        build_spend(
            &SpendRequest {
                chain: &chain(),
                coins: &coins(),
                tip_height: 10,
                to: &bob(),
                amount: 4_000,
                fee: None,
            },
            ext,
            &Permissive,
        )
        .unwrap()
    }

    #[test]
    fn unsigned_build_matches_a_signed_one_in_layout_and_size() {
        let k = kp(7);
        let ext = ExternalSigner::new(k.x_only_public_key().0);
        let unsigned = build(&ext);
        let signed = build_spend(
            &SpendRequest {
                chain: &chain(),
                coins: &coins(),
                tip_height: 10,
                to: &bob(),
                amount: 4_000,
                fee: None,
            },
            &PlainKey::new(SecretKey::from_slice(&[7; 32]).unwrap()),
            &Permissive,
        )
        .unwrap();
        assert_eq!(unsigned.txid, signed.txid);
        assert_eq!(unsigned.vsize, signed.vsize);
        assert_eq!(unsigned.fee, signed.fee);
        assert_eq!(unsigned.inputs, 2);
        // the request carries no witness at all
        let bare: Transaction = deserialize_hex(&unsigned_hex(&unsigned.tx)).unwrap();
        assert!(bare.input.iter().all(|i| i.witness.is_empty()));
        assert_eq!(bare.compute_txid(), unsigned.txid);
    }

    #[test]
    fn a_correct_signature_is_accepted() {
        let k = kp(7);
        let ext = ExternalSigner::new(k.x_only_public_key().0);
        let built = build(&ext);
        let pv = prevouts(&built, &ext.script());
        let answer = serialize_hex(&sign_with(&built.tx, &pv, &k));
        let s = accept_signed(&built, &answer, &pv, &chain()).unwrap();
        assert_eq!(s.txid, built.txid);
        assert_eq!(s.vsize, built.vsize);
    }

    #[test]
    fn another_keys_signature_is_refused() {
        let k = kp(7);
        let ext = ExternalSigner::new(k.x_only_public_key().0);
        let built = build(&ext);
        let pv = prevouts(&built, &ext.script());
        let answer = serialize_hex(&sign_with(&built.tx, &pv, &kp(8)));
        let e = accept_signed(&built, &answer, &pv, &chain()).unwrap_err();
        assert!(e.to_string().contains("not validly signed"), "{e}");
    }

    #[test]
    fn swapped_signatures_are_refused() {
        let k = kp(7);
        let ext = ExternalSigner::new(k.x_only_public_key().0);
        let built = build(&ext);
        let pv = prevouts(&built, &ext.script());
        let mut t = sign_with(&built.tx, &pv, &k);
        let w0 = t.input[0].witness.clone();
        t.input[0].witness = t.input[1].witness.clone();
        t.input[1].witness = w0;
        assert!(accept_signed(&built, &serialize_hex(&t), &pv, &chain()).is_err());
    }

    #[test]
    fn a_different_transaction_is_refused_even_if_signed() {
        let k = kp(7);
        let ext = ExternalSigner::new(k.x_only_public_key().0);
        let built = build(&ext);
        let pv = prevouts(&built, &ext.script());
        let mut other = built.tx.clone();
        other.output[0].script_pubkey =
            ScriptBuf::from_hex(&format!("5120{}", "cc".repeat(32))).unwrap();
        let answer = serialize_hex(&sign_with(&other, &pv, &k));
        let e = accept_signed(&built, &answer, &pv, &chain()).unwrap_err();
        assert!(e.to_string().contains("different transaction"), "{e}");
        assert!(accept_signed(&built, "zz", &pv, &chain()).is_err());
        // an unsigned answer is refused too
        assert!(accept_signed(&built, &unsigned_hex(&built.tx), &pv, &chain()).is_err());
    }

    #[test]
    fn the_signer_never_signs_in_place() {
        let ext = ExternalSigner::new(kp(7).x_only_public_key().0);
        assert!(ext.signs_elsewhere());
        assert!(ext.sign_key_path(&[0; 32]).is_err());
    }

    #[test]
    fn compose_defers_too() {
        let k = kp(7);
        let ext = ExternalSigner::new(k.x_only_public_key().0);
        let to = ScriptBuf::from_hex(&bob()).unwrap();
        let built = build_outputs(
            &OutputsRequest {
                chain: &chain(),
                coins: &coins(),
                required: &[],
                tip_height: 10,
                outputs: &[(to, 1_000)],
                records: &["hello".to_string()],
                fee: None,
            },
            &ext,
            &Permissive,
        )
        .unwrap();
        let pv = prevouts(&built, &ext.script());
        let answer = serialize_hex(&sign_with(&built.tx, &pv, &k));
        assert!(accept_signed(&built, &answer, &pv, &chain()).is_ok());
    }
}
