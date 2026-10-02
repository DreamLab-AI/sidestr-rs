//! Bitcoin Core's script interpreter as a differential oracle for the Hitch
//! channel leaves (feature `consensus-oracle`; sidestr-rs ADR-0002, the
//! 2026-10-02 amendment): `bitcoinconsensus 0.106.0+26.0` and
//! [`verify_supported_input`] judge the same spend of each of the seven
//! [`ChannelLeaf`] templates, under both output-key parities, and must agree
//! on every case — valid spends with each hash type and an annex; a wrong
//! control block, a wrong internal key, a tampered leaf, a sibling's control
//! block; missing, invalid, misplaced and badly encoded signatures; wrong
//! and oversized preimages; and every way `nSequence`, `nVersion` and
//! `nLockTime` can fail `CHECKSEQUENCEVERIFY` and `CHECKLOCKTIMEVERIFY`.
//!
//! Where Core says valid and this crate refuses, the case is listed as a
//! known narrowing and asserted as one: an unknown leaf version, a leaf that
//! is not a template (an `OP_TRUE`, a non-minimal push, a 2-of-3, a hash lock
//! with a timeout) and a CSV spend in a transaction whose version is negative
//! as an `i32` (Core reads the version unsigned; the reference kernel, like
//! this crate, signed).
//!
//! A script cannot see how deep its coin is: BIP 68 is a block rule
//! (`tests/chain_consensus.rs` in sidestr-hitch holds both chain engines to
//! it), so nothing here asks Core about depth.
//!
//! ```sh
//! cargo test -p sidestr-core --features consensus-oracle --test channel_oracle
//! ```
#![cfg(feature = "consensus-oracle")]

use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Keypair, Message, Parity, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Annex, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TapNodeHash};
use bitcoin::transaction::Version;
use bitcoin::{
    absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use sidestr_core::block::{challenge_for_output_key, secp};
use sidestr_core::channel::ChannelLeaf;
use sidestr_core::sighash::{verify_supported_input, SighashRules};

fn sk(i: u8) -> SecretKey {
    SecretKey::from_slice(&sha256::Hash::hash(&[0xc4, i]).to_byte_array()).unwrap()
}

fn xonly(k: &SecretKey) -> XOnlyPublicKey {
    Keypair::from_secret_key(secp(), k).x_only_public_key().0
}

const PREIMAGE: [u8; 32] = [0x5a; 32];
const DELAY: u16 = 144;
const EXPIRY: u32 = 152_200;
const VALUE: u64 = 50_000;

/// One leaf in a two-leaf tree beside a sibling, under an internal key whose
/// output has the wanted parity.
struct Output {
    leaf: ChannelLeaf,
    script: ScriptBuf,
    sibling: ScriptBuf,
    internal: XOnlyPublicKey,
    parity: Parity,
    prevout: TxOut,
}

impl Output {
    fn new(leaf: ChannelLeaf, parity: Parity) -> Self {
        Self::with_script(leaf, leaf.to_script(), LeafVersion::TapScript, parity)
    }

    fn with_script(
        leaf: ChannelLeaf,
        script: ScriptBuf,
        version: LeafVersion,
        parity: Parity,
    ) -> Self {
        let sibling = ChannelLeaf::Key {
            key: xonly(&sk(99)),
        }
        .to_script();
        let root = TapNodeHash::from_node_hashes(
            TapNodeHash::from_script(&script, version),
            TapNodeHash::from_script(&sibling, LeafVersion::TapScript),
        );
        let (internal, (output, p)) = (100u8..=255)
            .map(|i| {
                let k = xonly(&sk(i));
                (k, k.tap_tweak(secp(), Some(root)))
            })
            .find(|(_, (_, p))| *p == parity)
            .expect("an internal key of each parity");
        Self {
            leaf,
            script,
            sibling,
            internal,
            parity: p,
            prevout: TxOut {
                value: Amount::from_sat(VALUE),
                script_pubkey: challenge_for_output_key(&output),
            },
        }
    }

    fn control(&self, version: LeafVersion) -> Vec<u8> {
        let mut c = vec![version.to_consensus() | u8::from(self.parity)];
        c.extend_from_slice(&self.internal.serialize());
        c.extend_from_slice(
            TapNodeHash::from_script(&self.sibling, LeafVersion::TapScript).as_ref(),
        );
        c
    }
}

/// The spend the leaf's own semantics want: sequence, lock time, version.
fn spend_tx(leaf: &ChannelLeaf) -> Transaction {
    let (sequence, lock) = match (leaf.delay(), leaf.expiry()) {
        (Some(d), Some(e)) => (u32::from(d), e),
        (Some(d), None) => (u32::from(d), 0),
        (None, Some(e)) => (0xffff_fffe, e),
        (None, None) => (0xffff_fffd, 0),
    };
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(lock),
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0x77; 32]),
                vout: 3,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(sequence),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(VALUE - 1_000),
            script_pubkey: ScriptBuf::from_bytes(
                vec![0x51, 0x20].into_iter().chain([0x33; 32]).collect(),
            ),
        }],
    }
}

fn sign(
    tx: &Transaction,
    o: &Output,
    k: &SecretKey,
    hash_type: u8,
    annex: Option<&[u8]>,
) -> Vec<u8> {
    let leaf_hash = TapLeafHash::from_script(&o.script, LeafVersion::TapScript);
    let msg = SighashCache::new(tx)
        .taproot_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&o.prevout)),
            annex.map(|a| Annex::new(a).unwrap()),
            Some((leaf_hash, 0xffff_ffff)),
            TapSighashType::from_consensus_u8(hash_type).unwrap(),
        )
        .unwrap();
    let s = secp()
        .sign_schnorr_with_aux_rand(
            &Message::from_digest(msg.to_byte_array()),
            &Keypair::from_secret_key(secp(), k),
            &[0; 32],
        )
        .serialize()
        .to_vec();
    if hash_type == 0 {
        s
    } else {
        [s, vec![hash_type]].concat()
    }
}

/// The items below the script: signature slots (bottom first) and the preimage.
fn stack(
    tx: &Transaction,
    o: &Output,
    keys: &[SecretKey],
    hash_type: u8,
    annex: Option<&[u8]>,
) -> Vec<Vec<u8>> {
    match o.leaf {
        // k2's slot under k1's
        ChannelLeaf::Funding { .. } => vec![
            sign(tx, o, &keys[1], hash_type, annex),
            sign(tx, o, &keys[0], hash_type, annex),
        ],
        l if l.hash_lock().is_some() => {
            vec![sign(tx, o, &keys[0], hash_type, annex), PREIMAGE.to_vec()]
        }
        _ => vec![sign(tx, o, &keys[0], hash_type, annex)],
    }
}

fn with_witness(tx: &Transaction, items: Vec<Vec<u8>>) -> Transaction {
    let mut t = tx.clone();
    t.input[0].witness = Witness::from_slice(&items);
    t
}

fn full(o: &Output, stack: Vec<Vec<u8>>, annex: Option<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut w = stack;
    w.push(o.script.to_bytes());
    w.push(o.control(LeafVersion::TapScript));
    w.extend(annex);
    w
}

fn core(tx: &Transaction, prevout: &TxOut) -> bool {
    let spk = prevout.script_pubkey.as_bytes();
    let utxo = bitcoinconsensus::Utxo {
        script_pubkey: spk.as_ptr(),
        script_pubkey_len: spk.len() as u32,
        value: prevout.value.to_sat() as i64,
    };
    bitcoinconsensus::verify_with_flags(
        spk,
        prevout.value.to_sat(),
        &serialize(tx),
        Some(&[utxo]),
        0,
        bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT | bitcoinconsensus::VERIFY_TAPROOT,
    )
    .is_ok()
}

fn ours(tx: &Transaction, prevout: &TxOut) -> Result<(), String> {
    verify_supported_input(tx, 0, std::slice::from_ref(prevout), SighashRules::Bip341)
}

/// Every leaf, with the keys that sign it.
fn leaves() -> Vec<(&'static str, ChannelLeaf, Vec<SecretKey>)> {
    let (k1, k2) = (sk(1), sk(2));
    let hash = sha256::Hash::hash(&PREIMAGE).to_byte_array();
    let key = xonly(&k1);
    vec![
        (
            "funding",
            ChannelLeaf::Funding {
                keys: [xonly(&k1), xonly(&k2)],
            },
            vec![k1, k2],
        ),
        ("revocation", ChannelLeaf::Key { key }, vec![k1]),
        (
            "to_local delayed",
            ChannelLeaf::Delayed { delay: DELAY, key },
            vec![k1],
        ),
        (
            "offered HTLC success",
            ChannelLeaf::HashLock { hash, key },
            vec![k1],
        ),
        (
            "received HTLC success",
            ChannelLeaf::HashLockDelayed {
                hash,
                delay: DELAY,
                key,
            },
            vec![k1],
        ),
        (
            "received HTLC timeout",
            ChannelLeaf::Timeout {
                expiry: EXPIRY,
                key,
            },
            vec![k1],
        ),
        (
            "offered HTLC timeout",
            ChannelLeaf::TimeoutDelayed {
                expiry: EXPIRY,
                delay: DELAY,
                key,
            },
            vec![k1],
        ),
    ]
}

#[test]
fn core_and_this_crate_agree_on_every_channel_leaf() {
    let mut cases = 0usize;
    let mut agree = |name: String, tx: &Transaction, prevout: &TxOut, want: bool| {
        let (c, o) = (core(tx, prevout), ours(tx, prevout));
        assert_eq!(c, o.is_ok(), "{name}: Core {c}, sidestr-core {o:?}");
        assert_eq!(c, want, "{name}: expected {want}, both said {c} ({o:?})");
        cases += 1;
    };
    let wrong = sk(50);
    for (label, leaf, keys) in leaves() {
        for parity in [Parity::Even, Parity::Odd] {
            let o = Output::new(leaf, parity);
            let tx = spend_tx(&leaf);
            let name = |what: &str| format!("{label} {parity:?}: {what}");
            let good = full(&o, stack(&tx, &o, &keys, 0, None), None);

            // valid: each hash type, and an annex the signatures commit to
            for ht in [0x00u8, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83] {
                let w = full(&o, stack(&tx, &o, &keys, ht, None), None);
                agree(
                    name(&format!("hash type {ht:#04x}")),
                    &with_witness(&tx, w),
                    &o.prevout,
                    true,
                );
            }
            let annex = vec![0x50, 0xa1, 0xa2];
            let w = full(
                &o,
                stack(&tx, &o, &keys, 0, Some(&annex)),
                Some(annex.clone()),
            );
            agree(
                name("annex"),
                &with_witness(&tx, w.clone()),
                &o.prevout,
                true,
            );
            let mut dropped = w;
            dropped.pop();
            agree(
                name("annex dropped"),
                &with_witness(&tx, dropped),
                &o.prevout,
                false,
            );

            // the control block
            let n = good.len();
            let mutate = |f: &dyn Fn(&mut Vec<Vec<u8>>)| {
                let mut w = good.clone();
                f(&mut w);
                with_witness(&tx, w)
            };
            agree(
                name("parity flipped"),
                &mutate(&|w| w[n - 1][0] ^= 1),
                &o.prevout,
                false,
            );
            agree(
                name("control block truncated"),
                &mutate(&|w| w[n - 1].truncate(33 + 31)),
                &o.prevout,
                false,
            );
            agree(
                name("merkle node altered"),
                &mutate(&|w| w[n - 1][40] ^= 1),
                &o.prevout,
                false,
            );
            agree(
                name("merkle path dropped"),
                &mutate(&|w| w[n - 1].truncate(33)),
                &o.prevout,
                false,
            );
            agree(
                name("wrong internal key"),
                &mutate(&|w| w[n - 1][1..33].copy_from_slice(&xonly(&wrong).serialize())),
                &o.prevout,
                false,
            );
            // the leaf
            agree(
                name("leaf byte flipped"),
                &mutate(&|w| w[n - 2][1] ^= 1),
                &o.prevout,
                false,
            );
            agree(
                name("leaf truncated"),
                &mutate(&|w| {
                    w[n - 2].pop();
                }),
                &o.prevout,
                false,
            );
            agree(
                name("sibling leaf with this control block"),
                &mutate(&|w| w[n - 2] = o.sibling.to_bytes()),
                &o.prevout,
                false,
            );
            // the stack
            agree(
                name("an extra item"),
                &mutate(&|w| w.insert(0, vec![1])),
                &o.prevout,
                false,
            );
            agree(
                name("an item short"),
                &mutate(&|w| {
                    w.remove(0);
                }),
                &o.prevout,
                false,
            );
            let top = n - 3; // the top stack item: the preimage, k1's slot, or the signature
            let sig_slot = if leaf.hash_lock().is_some() {
                top - 1
            } else {
                top
            };
            agree(
                name("signature emptied"),
                &mutate(&|w| w[sig_slot].clear()),
                &o.prevout,
                false,
            );
            agree(
                name("signature garbage"),
                &mutate(&|w| w[sig_slot] = vec![9; 64]),
                &o.prevout,
                false,
            );
            agree(
                name("signature 63 bytes"),
                &mutate(&|w| w[sig_slot].truncate(63)),
                &o.prevout,
                false,
            );
            agree(
                name("explicit SIGHASH_DEFAULT"),
                &mutate(&|w| w[sig_slot].push(0)),
                &o.prevout,
                false,
            );
            agree(
                name("undefined hash type"),
                &mutate(&|w| w[sig_slot].push(0x04)),
                &o.prevout,
                false,
            );
            let other = sign(&tx, &o, &wrong, 0, None);
            agree(
                name("another key's signature"),
                &mutate(&|w| w[sig_slot] = other.clone()),
                &o.prevout,
                false,
            );
            if let ChannelLeaf::Funding { .. } = leaf {
                agree(
                    name("slots swapped"),
                    &mutate(&|w| w.swap(0, 1)),
                    &o.prevout,
                    false,
                );
                agree(
                    name("k2's slot emptied"),
                    &mutate(&|w| w[0].clear()),
                    &o.prevout,
                    false,
                );
                agree(
                    name("both slots emptied"),
                    &mutate(&|w| {
                        w[0].clear();
                        w[1].clear();
                    }),
                    &o.prevout,
                    false,
                );
            }
            if leaf.hash_lock().is_some() {
                agree(
                    name("wrong preimage"),
                    &mutate(&|w| w[top] = vec![0x5b; 32]),
                    &o.prevout,
                    false,
                );
                agree(
                    name("empty preimage"),
                    &mutate(&|w| w[top].clear()),
                    &o.prevout,
                    false,
                );
                agree(
                    name("521-byte preimage"),
                    &mutate(&|w| w[top] = vec![0x5a; 521]),
                    &o.prevout,
                    false,
                );
            }
            // sequence and lock time: re-signed, since both are in the sighash
            let resigned = |f: &dyn Fn(&mut Transaction)| {
                let mut t = tx.clone();
                f(&mut t);
                let w = full(&o, stack(&t, &o, &keys, 0, None), None);
                with_witness(&t, w)
            };
            if leaf.delay().is_some() {
                let d = u32::from(DELAY);
                agree(
                    name("sequence = delay"),
                    &resigned(&|t| t.input[0].sequence = Sequence(d)),
                    &o.prevout,
                    true,
                );
                agree(
                    name("sequence above delay"),
                    &resigned(&|t| t.input[0].sequence = Sequence(d + 1)),
                    &o.prevout,
                    true,
                );
                agree(
                    name("sequence one short"),
                    &resigned(&|t| t.input[0].sequence = Sequence(d - 1)),
                    &o.prevout,
                    false,
                );
                agree(
                    name("sequence disabled"),
                    &resigned(&|t| t.input[0].sequence = Sequence(d | 1 << 31)),
                    &o.prevout,
                    false,
                );
                agree(
                    name("sequence counts time"),
                    &resigned(&|t| t.input[0].sequence = Sequence(d | 1 << 22)),
                    &o.prevout,
                    false,
                );
                agree(
                    name("ignored sequence bits set"),
                    &resigned(&|t| t.input[0].sequence = Sequence(d | 0x0001_0000)),
                    &o.prevout,
                    true,
                );
                agree(
                    name("version 1"),
                    &resigned(&|t| t.version = Version::ONE),
                    &o.prevout,
                    false,
                );
                agree(
                    name("version 3"),
                    &resigned(&|t| t.version = Version(3)),
                    &o.prevout,
                    true,
                );
            }
            if leaf.expiry().is_some() {
                agree(
                    name("lock time = expiry"),
                    &resigned(&|t| t.lock_time = LockTime::from_consensus(EXPIRY)),
                    &o.prevout,
                    true,
                );
                agree(
                    name("lock time one short"),
                    &resigned(&|t| t.lock_time = LockTime::from_consensus(EXPIRY - 1)),
                    &o.prevout,
                    false,
                );
                agree(
                    name("lock time zero"),
                    &resigned(&|t| t.lock_time = LockTime::ZERO),
                    &o.prevout,
                    false,
                );
                agree(
                    name("lock time a timestamp"),
                    &resigned(&|t| t.lock_time = LockTime::from_consensus(1_790_000_000)),
                    &o.prevout,
                    false,
                );
                agree(
                    name("final input"),
                    &resigned(&|t| t.input[0].sequence = Sequence::MAX),
                    &o.prevout,
                    false,
                );
            }
        }
    }

    // known narrowings: Core says valid, this crate refuses, by design
    let k1 = sk(1);
    let key = xonly(&k1);
    let mut narrowings = 0;
    let mut narrowing = |what: &str, tx: &Transaction, prevout: &TxOut| {
        assert!(core(tx, prevout), "{what}: Core refused it");
        assert!(
            ours(tx, prevout).is_err(),
            "{what}: sidestr-core accepted it"
        );
        narrowings += 1;
    };
    // an unknown leaf version: Core skips execution, this crate refuses
    let leaf = ChannelLeaf::Key { key };
    let v = LeafVersion::from_consensus(0xc2).unwrap();
    let o = Output::with_script(leaf, leaf.to_script(), v, Parity::Even);
    let tx = spend_tx(&leaf);
    let mut w = vec![vec![], o.script.to_bytes(), o.control(v)];
    w[0] = sign(&tx, &o, &k1, 0, None); // signed over the 0xc0 leaf hash: never checked by Core
    narrowing(
        "unknown leaf version 0xc2",
        &with_witness(&tx, w),
        &o.prevout,
    );
    // scripts that are not templates
    let mut csv_pushdata = vec![0x01, 0x06, 0xb2, 0x75, 0x20];
    csv_pushdata.extend_from_slice(&key.serialize());
    csv_pushdata.push(0xac);
    let mut two_of_three = ChannelLeaf::Funding {
        keys: [key, xonly(&sk(2))],
    }
    .to_script()
    .to_bytes();
    two_of_three.truncate(68);
    two_of_three.extend_from_slice(&[0x20]);
    two_of_three.extend_from_slice(&xonly(&sk(3)).serialize());
    two_of_three.extend_from_slice(&[0xba, 0x52, 0x9c]);
    let mut hash_cltv = vec![0xa8, 0x20];
    hash_cltv.extend_from_slice(&sha256::Hash::hash(&PREIMAGE).to_byte_array());
    hash_cltv.extend_from_slice(&[0x88, 0x51, 0xb1, 0x75, 0x20]);
    hash_cltv.extend_from_slice(&key.serialize());
    hash_cltv.push(0xac);
    for (what, script, items) in [
        ("an OP_TRUE leaf", vec![0x51], 0usize),
        ("a non-minimal CSV push", csv_pushdata, 1),
        ("a 2-of-3 multi_a", two_of_three, 3),
        ("a hash lock with a timeout", hash_cltv, 2),
    ] {
        let script = ScriptBuf::from_bytes(script);
        let o = Output::with_script(leaf, script.clone(), LeafVersion::TapScript, Parity::Odd);
        let mut tx = spend_tx(&leaf);
        tx.input[0].sequence = Sequence(6);
        tx.lock_time = LockTime::from_consensus(1);
        let ks = [sk(1), sk(2), sk(3)];
        let mut w: Vec<Vec<u8>> = match items {
            0 => vec![],
            1 => vec![sign(&tx, &o, &ks[0], 0, None)],
            2 => vec![sign(&tx, &o, &ks[0], 0, None), PREIMAGE.to_vec()],
            _ => vec![
                vec![],
                sign(&tx, &o, &ks[1], 0, None),
                sign(&tx, &o, &ks[0], 0, None),
            ],
        };
        w.push(script.to_bytes());
        w.push(o.control(LeafVersion::TapScript));
        narrowing(what, &with_witness(&tx, w), &o.prevout);
    }
    // a CSV spend in a transaction whose version is negative as an i32
    let leaf = ChannelLeaf::Delayed { delay: DELAY, key };
    let o = Output::new(leaf, Parity::Even);
    let mut tx = spend_tx(&leaf);
    tx.version = Version(-1);
    let w = full(&o, stack(&tx, &o, &[k1], 0, None), None);
    narrowing(
        "CSV in version 0xffffffff",
        &with_witness(&tx, w),
        &o.prevout,
    );

    eprintln!("{cases} differential cases agreed, plus {narrowings} documented narrowings");
    assert!(cases > 400, "{cases}");
    assert_eq!(narrowings, 6);
}
