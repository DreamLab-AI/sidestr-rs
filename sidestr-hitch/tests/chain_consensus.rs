//! Hitch channels on a sidestr chain, judged by every engine that has a say
//! (sidestr-rs ADR-0002, 2026-10-02 amendment; sprint stream S1).
//!
//! A chain beside `tbtc4` (stock headers, BIP 341 sighash, the family of
//! `sidestr:dreamlab`) is built block by block with `sidestr-core`'s
//! [`Chain`], and every channel transaction on it is made by this crate's
//! kernel: one funding transaction opens five channels; the off-chain `pay`
//! moves the balance to a second state, revoking the first; then
//!
//! - **X** closes cooperatively through the 2-of-2 funding leaf;
//! - **Y** is force-closed by A on the latest state; B takes `to_remote` at
//!   once, A sweeps `to_local` through the delayed leaf after the CSV delay;
//! - **Z** is force-closed by A on the *revoked* state, and B takes the whole
//!   `to_local` at once through the revocation leaf (the penalty);
//! - **W** is force-closed by A with two HTLCs A offered: B claims one with
//!   the preimage, A refunds the other after its expiry and the delay;
//! - **V** is force-closed by B with two HTLCs A offered: B claims one with
//!   the preimage after the delay, A refunds the other after its expiry.
//!
//! That puts all seven [`ChannelLeaf`] templates on the chain. Refused at
//! the height they were tried, by `sidestr-core` (admission and block) and by
//! the reference: every early sweep, claim and refund (BIP 68 and
//! `nLockTime` are block rules), a sweep one block early, a wrong control
//! block, a wrong internal key, a tampered leaf, a wrong preimage and a
//! funding spend with one signature.
//!
//! The reference half runs when `SIDESTR_SIDING`, `SCHEMA` and
//! `BLAKETESTNODE` name checkouts (the producer's pin is sidestr/spec
//! `fa86dac`): siding replays the directory to the same tip hash and refuses
//! the same blocks. Under feature `consensus-oracle`, Bitcoin Core's
//! interpreter (`bitcoinconsensus` 0.106, Core 26.0) judges every channel
//! input too: it accepts each spend the chain carries and refuses each
//! script-level negative, and it *accepts* the early sweeps, because a
//! script cannot see a coin's depth — which is why both chain engines'
//! block rules must, and do.
//!
//! ```sh
//! SIDESTR_SIDING=… SCHEMA=… BLAKETESTNODE=… \
//!   cargo test -p sidestr-hitch --features consensus-oracle --test chain_consensus -- --nocapture
//! ```

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use bitcoin::consensus::encode::{serialize, serialize_hex};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, SecretKey, XOnlyPublicKey};
use bitcoin::transaction::Version;
use bitcoin::{
    absolute::LockTime, Amount, Block, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};
use serde_json::json;
use sidestr_core::block::{build_block, challenge_for, secp, sign_block, BlockTemplate, Stock};
use sidestr_core::chain::Chain;
use sidestr_core::channel::{verify_channel_input, ChannelError, ChannelLeaf};
use sidestr_core::document::{ChainDocument, Peg};
use sidestr_core::sighash::{key_path_sighash, verify_supported_input, SighashRules};
use sidestr_hitch::{
    claim_htlc, key_path_spend, revocation_key, revocation_pub, sweep_to_local, to_remote_script,
    Balances, Channel, ChannelState, Commitment, Htlc, HtlcClaim, HtlcClaimPath, OutputKind,
    RevocationKeys, Side, SweepPath,
};

/// A throwaway document beside testnet4, one signer, like siding's `trial`.
const DOCUMENT: &str = r#"{
 "id": "sidestr:hitchtest",
 "name": "hitchtest",
 "parent": "tbtc4",
 "comment": "Throwaway: Hitch channels judged by both engines. Coins with no value.",
 "challenge": "512098b4e74305dac5ce76d5bee8e57a71549a27618a0e51b3bada3074fcba02325b",
 "powLimit": "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
 "addressPrefix": "htt",
 "magic": "a8f6706f",
 "pegConfirmations": 6,
 "refundBlocks": 10000,
 "pegoutBlocks": 144,
 "pegoutMin": 10000,
 "minFeeRate": 1,
 "genesisTime": 1790076612,
 "pegs": []
}"#;

const RULES: SighashRules = SighashRules::Bip341;
const VALUE: u64 = 100_000;
const DELAY: u16 = 6;
const AUX: [u8; 32] = [0; 32];

fn key(tag: &str) -> SecretKey {
    SecretKey::from_slice(
        &sha256::Hash::hash(format!("sidestr-hitch chain test {tag}").as_bytes()).to_byte_array(),
    )
    .unwrap()
}

fn public(k: &SecretKey) -> XOnlyPublicKey {
    Keypair::from_secret_key(secp(), k).x_only_public_key().0
}

struct Peers {
    a: SecretKey,
    b: SecretKey,
    /// Each peer's revocation basepoint secret.
    base_a: SecretKey,
    base_b: SecretKey,
}

impl Peers {
    fn per_state(side: Side, n: u64) -> SecretKey {
        key(&format!("{side:?} per-state {n}"))
    }

    /// Both owners' revocation keys at state `n`: the counterparty's
    /// basepoint plus the owner's per-state point.
    fn revocation(&self, n: u64) -> RevocationKeys {
        RevocationKeys {
            a: revocation_pub(public(&self.base_b), &Self::per_state(Side::A, n)).unwrap(),
            b: revocation_pub(public(&self.base_a), &Self::per_state(Side::B, n)).unwrap(),
        }
    }

    /// The penalty key the counterparty holds once `owner` revoked state `n`.
    fn penalty(&self, owner: Side, n: u64) -> SecretKey {
        let base = match owner {
            Side::A => &self.base_b,
            Side::B => &self.base_a,
        };
        revocation_key(base, &Self::per_state(owner, n)).unwrap()
    }
}

/// The commitment for `owner` at `n`, signed by both through the funding leaf.
fn commit(
    ch: &Channel,
    p: &Peers,
    n: u64,
    owner: Side,
    state: &ChannelState,
) -> (Commitment, Transaction) {
    let c = ch.commitment(n, owner, state).unwrap();
    let tx = funded(ch, p, c.tx.clone());
    (c, tx)
}

/// `tx` (a commitment or close) with both funding signatures installed.
fn funded(ch: &Channel, p: &Peers, mut tx: Transaction) -> Transaction {
    let sigs = BTreeMap::from([
        (
            public(&p.a),
            ch.sign_funding(&tx, &p.a, RULES, &AUX).unwrap(),
        ),
        (
            public(&p.b),
            ch.sign_funding(&tx, &p.b, RULES, &AUX).unwrap(),
        ),
    ]);
    tx.input[0].witness = ch.funding_witness(&sigs).unwrap();
    tx
}

fn vout_of(c: &Commitment, kind: OutputKind) -> u32 {
    c.kinds.iter().position(|k| *k == kind).unwrap() as u32
}

/// A key-path spend of `prev` at `outpoint`, as a wallet makes one.
fn wallet_spend(
    outpoint: OutPoint,
    prev: TxOut,
    outputs: Vec<TxOut>,
    k: &SecretKey,
) -> Transaction {
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xffff_fffd),
            witness: Witness::new(),
        }],
        output: outputs,
    };
    let (msg, ht) = key_path_sighash(&tx, 0, &[prev], RULES).unwrap();
    let sig = secp().sign_schnorr_with_aux_rand(
        &bitcoin::secp256k1::Message::from_digest(msg),
        &Keypair::from_secret_key(secp(), k),
        &AUX,
    );
    tx.input[0].witness = Witness::from_slice(&[[sig.serialize().as_slice(), &[ht]].concat()]);
    tx
}

/// A block on the tip carrying `txs`, signed, not added.
fn candidate(chain: &Chain, producer: &SecretKey, txs: Vec<Transaction>) -> Block {
    let tip = chain.state().tip();
    let b = build_block(
        &Stock,
        &BlockTemplate {
            height: tip.height + 1,
            prev: tip.hash,
            time: tip.time + 1,
            transactions: txs,
            outputs: vec![],
            bits: chain.state().bits(),
            marker: "sidestr".into(),
        },
    );
    sign_block(&Stock, &b, chain.state().challenge(), producer, &AUX).unwrap()
}

/// The prevout every input of `tx` spends, from the chain's UTXO set.
fn prevouts(chain: &Chain, tx: &Transaction) -> Vec<TxOut> {
    tx.input
        .iter()
        .map(|i| {
            chain
                .state()
                .output(&i.previous_output)
                .cloned()
                .expect("a prevout")
        })
        .collect()
}

/// What `sidestr-core` and (when present) the reference and Core say.
struct Judges {
    reference: Option<Reference>,
    /// Channel inputs the chain carries, for Core: (tx, prevouts).
    carried: Vec<(String, Transaction, Vec<TxOut>)>,
    /// Refused blocks: (name, tx, prevouts, script-level?) for Core.
    refused: Vec<(String, Transaction, Vec<TxOut>, bool)>,
}

struct Reference {
    script: PathBuf,
    doc: PathBuf,
    dir: PathBuf,
}

impl Reference {
    fn run(&self, args: &[&OsStr]) -> serde_json::Value {
        let out = Command::new("node")
            .arg(&self.script)
            .args(args)
            .output()
            .expect("node");
        assert!(
            out.status.success(),
            "reference engine failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).expect("json from the reference engine")
    }
}

impl Judges {
    /// Offer each case's block to both engines at the tip; each must refuse,
    /// `sidestr-core` naming `rule`.
    fn refuse(
        &mut self,
        chain: &Chain,
        producer: &SecretKey,
        cases: Vec<(&str, Transaction, &str, bool)>,
    ) {
        let next = chain.state().height() + 1;
        let mut js = Vec::new();
        for (name, tx, rule, script_level) in cases {
            let block = candidate(chain, producer, vec![tx.clone()]);
            let (verdict, _) = chain.state().judge(next, &block, None);
            assert!(!verdict.ok(), "{name}: sidestr-core accepted it");
            assert!(
                verdict.failed().iter().any(|r| r == rule),
                "{name}: sidestr-core refused it for {:?}, not {rule}",
                verdict.failed()
            );
            eprintln!(
                "refused at {next}: {name} — sidestr-core: {:?}",
                verdict.failed()
            );
            js.push(json!({ "name": name, "hex": serialize_hex(&block), "rule": rule }));
            let p = prevouts(chain, &tx);
            self.refused.push((name.to_string(), tx, p, script_level));
        }
        if let Some(r) = &self.reference {
            let file = r.dir.with_extension(format!("cases-{next}.json"));
            std::fs::write(&file, serde_json::to_string(&js).unwrap()).unwrap();
            let v = r.run(&[
                OsStr::new("judge"),
                r.doc.as_os_str(),
                r.dir.as_os_str(),
                file.as_os_str(),
            ]);
            for (verdict, case) in v.as_array().unwrap().iter().zip(&js) {
                assert_eq!(verdict["ok"], false, "the reference accepted {verdict}");
                let error = verdict["error"].as_str().unwrap_or_default();
                let rule = case["rule"].as_str().unwrap();
                assert!(
                    error.contains(rule),
                    "{}: the reference refused it, but not for {rule}: {error}",
                    case["name"]
                );
                eprintln!("  reference: {error}");
            }
            std::fs::remove_file(file).unwrap();
        }
    }

    fn carry(&mut self, chain: &Chain, name: &str, tx: &Transaction) {
        self.carried
            .push((name.to_string(), tx.clone(), prevouts(chain, tx)));
    }
}

#[cfg(feature = "consensus-oracle")]
fn core_accepts(tx: &Transaction, prevouts: &[TxOut]) -> bool {
    let spks: Vec<Vec<u8>> = prevouts
        .iter()
        .map(|p| p.script_pubkey.to_bytes())
        .collect();
    let utxos: Vec<bitcoinconsensus::Utxo> = spks
        .iter()
        .zip(prevouts)
        .map(|(s, p)| bitcoinconsensus::Utxo {
            script_pubkey: s.as_ptr(),
            script_pubkey_len: s.len() as u32,
            value: p.value.to_sat() as i64,
        })
        .collect();
    let bytes = serialize(tx);
    (0..tx.input.len()).all(|i| {
        bitcoinconsensus::verify_with_flags(
            &spks[i],
            prevouts[i].value.to_sat(),
            &bytes,
            Some(&utxos),
            i,
            bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT | bitcoinconsensus::VERIFY_TAPROOT,
        )
        .is_ok()
    })
}

fn submit(chain: &mut Chain, name: &str, tx: &Transaction) {
    if let Err(e) = chain.submit(&serialize(tx)) {
        panic!("{name}: sidestr-core refused it: {e}");
    }
}

fn submit_refused(chain: &mut Chain, name: &str, tx: &Transaction, says: &str) {
    match chain.submit(&serialize(tx)) {
        Ok(_) => panic!("{name}: sidestr-core admitted it"),
        Err(e) => assert!(e.to_string().contains(says), "{name}: {e}"),
    }
}

fn produce(chain: &mut Chain, producer: &SecretKey, txs: usize) -> u32 {
    let r = chain.produce(producer, vec![]).unwrap();
    assert_eq!(
        r.txs,
        txs + 1,
        "block {} carried {} transactions",
        r.height,
        r.txs - 1
    );
    r.height
}

#[test]
fn hitch_open_pay_close_force_close_sweep_and_penalty_replay_on_both_engines() {
    let producer = key("producer");
    let p = Peers {
        a: key("alice"),
        b: key("bob"),
        base_a: key("alice basepoint"),
        base_b: key("bob basepoint"),
    };
    let (pa, pb) = (public(&p.a), public(&p.b));
    let alice = challenge_for(&pa);
    let bob = challenge_for(&pb);

    let mut doc = ChainDocument::from_json(DOCUMENT).unwrap();
    doc.challenge = challenge_for(&public(&producer)).to_hex_string();
    doc.signer = Some(public(&producer).to_string());
    doc.pegs = vec![Peg {
        txid: "11".repeat(32),
        vout: 0,
        amount: 600_000,
        script: alice.to_hex_string(),
        extra: Default::default(),
    }];
    let dir = std::env::temp_dir().join(format!(
        "sidestr-hitch-chain-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut chain = Chain::open(doc.clone(), &dir, Some(&producer)).unwrap();
    doc.genesis_hash = Some(chain.state().genesis_hash().to_string());

    let reference = ["SIDESTR_SIDING", "SCHEMA", "BLAKETESTNODE"]
        .iter()
        .all(|v| std::env::var(v).is_ok())
        .then(|| {
            let d = dir.with_extension("chain.json");
            std::fs::write(&d, doc.to_json().unwrap()).unwrap();
            Reference {
                script: Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/chaincheck.mjs"),
                doc: d,
                dir: dir.clone(),
            }
        });
    if reference.is_none() {
        eprintln!("the reference half is skipped: set SIDESTR_SIDING, SCHEMA and BLAKETESTNODE");
    }
    let mut judges = Judges {
        reference,
        carried: Vec::new(),
        refused: Vec::new(),
    };

    // the peg is the genesis coinbase: mature at 100
    while chain.state().height() < 100 {
        produce(&mut chain, &producer, 0);
    }

    // open: one funding transaction, five channels of VALUE each
    let names = ["X", "Y", "Z", "W", "V"];
    let peg = chain.state().coins(&alice)[0].clone();
    let funding_spk = sidestr_hitch::funding_script(pa, pb).unwrap().script_pubkey;
    let mut outputs: Vec<TxOut> = names
        .iter()
        .map(|_| TxOut {
            value: Amount::from_sat(VALUE),
            script_pubkey: funding_spk.clone(),
        })
        .collect();
    outputs.push(TxOut {
        value: Amount::from_sat(peg.value - 5 * VALUE - 1_000),
        script_pubkey: alice.clone(),
    });
    let fund = wallet_spend(
        peg.outpoint,
        chain.state().output(&peg.outpoint).unwrap().clone(),
        outputs,
        &p.a,
    );
    submit(&mut chain, "funding", &fund);
    let funded_at = produce(&mut chain, &producer, 1);
    let channel = |i: usize| {
        Channel::new(
            pa,
            pb,
            OutPoint {
                txid: fund.compute_txid(),
                vout: i as u32,
            },
            Amount::from_sat(VALUE),
            Amount::from_sat(300),
            DELAY,
        )
        .unwrap()
    };
    let (x, y, z, w, v) = (channel(0), channel(1), channel(2), channel(3), channel(4));

    // pay, off chain: state 1 is the opening (all A's), state 2 after A pays B 30,000; A
    // revokes state 1 by handing B its per-state secret
    let state = |n: u64, a: u64, b: u64, htlcs: Vec<Htlc>| ChannelState {
        balances: Balances {
            a: Amount::from_sat(a),
            b: Amount::from_sat(b),
        },
        revocation: p.revocation(n),
        htlcs,
    };
    let opening = state(1, VALUE, 0, vec![]);
    let paid = state(2, 70_000, 30_000, vec![]);
    let preimage = |i: u8| [i; 32];
    let hash = |i: u8| sha256::Hash::hash(&preimage(i)).to_byte_array();
    let commit_height = funded_at + 1;
    let expiry = commit_height + 3;
    let htlc = |id: u64| Htlc {
        id,
        from: Side::A,
        amount: Amount::from_sat(20_000),
        payment_hash: hash(id as u8),
        expiry,
    };
    let with_htlcs = |ids: [u64; 2]| state(3, 50_000, 10_000, vec![htlc(ids[0]), htlc(ids[1])]);

    // close X cooperatively; force-close Y on the latest state, Z on the revoked one, W and V with HTLCs
    let close_x = funded(&x, &p, x.cooperative_close(&paid).unwrap());
    let (cy, ty) = commit(&y, &p, 2, Side::A, &paid);
    let (cz, tz) = commit(&z, &p, 1, Side::A, &opening);
    let (cw, tw) = commit(&w, &p, 3, Side::A, &with_htlcs([1, 2]));
    let (cv, tv) = commit(&v, &p, 3, Side::B, &with_htlcs([3, 4]));

    // a funding spend with one signature is refused by both
    let mut one_sig = ty.clone();
    let mut items: Vec<Vec<u8>> = one_sig.input[0]
        .witness
        .iter()
        .map(<[u8]>::to_vec)
        .collect();
    items[0].clear();
    one_sig.input[0].witness = Witness::from_slice(&items);
    assert!(matches!(
        verify_channel_input(&one_sig, 0, &prevouts(&chain, &one_sig), RULES),
        Err(ChannelError::MissingSignature { .. })
    ));
    judges.refuse(
        &chain,
        &producer,
        vec![(
            "funding leaf with one signature",
            one_sig,
            "btc:rule-blockctx-scripts",
            true,
        )],
    );

    // each funding spend is the 2-of-2 template (checked while its coin is unspent)
    for tx in [&close_x, &ty, &tz, &tw, &tv] {
        assert!(matches!(
            verify_channel_input(tx, 0, &prevouts(&chain, tx), RULES).map(|s| s.leaf),
            Ok(ChannelLeaf::Funding { .. })
        ));
    }
    for (name, tx) in [
        ("X cooperative close", &close_x),
        ("Y commitment (A, state 2)", &ty),
        ("Z commitment (A, revoked state 1)", &tz),
        ("W commitment (A, HTLCs 1 and 2)", &tw),
        ("V commitment (B, HTLCs 3 and 4)", &tv),
    ] {
        judges.carry(&chain, name, tx);
        submit(&mut chain, name, tx);
    }
    assert_eq!(produce(&mut chain, &producer, 5), commit_height);

    // the outputs each commitment left
    let out = |tx: &Transaction, vout: u32| {
        (
            OutPoint {
                txid: tx.compute_txid(),
                vout,
            },
            tx.output[vout as usize].clone(),
        )
    };
    let fee = Amount::from_sat(300);
    let y_sweep = sweep_to_local(
        &cy,
        SweepPath::Delayed,
        alice.clone(),
        fee,
        &p.a,
        RULES,
        &AUX,
    )
    .unwrap();
    let z_penalty = sweep_to_local(
        &cz,
        SweepPath::Revocation,
        bob.clone(),
        fee,
        &p.penalty(Side::A, 1),
        RULES,
        &AUX,
    )
    .unwrap();
    let (y_remote_at, y_remote) = out(&ty, vout_of(&cy, OutputKind::ToRemote));
    let y_remote_take =
        key_path_spend(y_remote_at, y_remote, bob.clone(), fee, &p.b, RULES, &AUX).unwrap();
    let claim = |c: &Commitment,
                 i: usize,
                 path: HtlcClaimPath,
                 to: &ScriptBuf,
                 k: &SecretKey,
                 pre: Option<[u8; 32]>| {
        claim_htlc(
            c,
            &c.htlcs[i],
            HtlcClaim {
                path,
                destination: to.clone(),
                fee,
                preimage: pre,
            },
            k,
            RULES,
            &AUX,
        )
        .unwrap()
    };
    let w1_success = claim(
        &cw,
        0,
        HtlcClaimPath::Success,
        &bob,
        &p.b,
        Some(preimage(1)),
    );
    let w2_timeout = claim(&cw, 1, HtlcClaimPath::Timeout, &alice, &p.a, None);
    let v3_success = claim(
        &cv,
        0,
        HtlcClaimPath::Success,
        &bob,
        &p.b,
        Some(preimage(3)),
    );
    let v4_timeout = claim(&cv, 1, HtlcClaimPath::Timeout, &alice, &p.a, None);

    // every leaf is the template it should be
    let leaf_of = |tx: &Transaction| {
        verify_channel_input(tx, 0, &prevouts(&chain, tx), RULES).map(|s| s.leaf)
    };
    assert!(matches!(leaf_of(&z_penalty), Ok(ChannelLeaf::Key { .. })));
    assert!(matches!(
        leaf_of(&w1_success),
        Ok(ChannelLeaf::HashLock { .. })
    ));
    // the delayed ones pass the script: the depth is the block's question
    assert!(matches!(
        leaf_of(&y_sweep),
        Ok(ChannelLeaf::Delayed { delay: DELAY, .. })
    ));
    assert!(matches!(
        leaf_of(&w2_timeout),
        Ok(ChannelLeaf::TimeoutDelayed { delay: DELAY, .. })
    ));
    assert!(matches!(
        leaf_of(&v3_success),
        Ok(ChannelLeaf::HashLockDelayed { delay: DELAY, .. })
    ));
    assert!(matches!(
        leaf_of(&v4_timeout),
        Ok(ChannelLeaf::Timeout { .. })
    ));

    // one block after the commitments: early sweeps, claims and refunds are refused by both
    let mut wrong_preimage = w1_success.clone();
    let mut items: Vec<Vec<u8>> = wrong_preimage.input[0]
        .witness
        .iter()
        .map(<[u8]>::to_vec)
        .collect();
    items[1] = preimage(9).to_vec();
    wrong_preimage.input[0].witness = Witness::from_slice(&items);
    for (name, tx, says) in [
        (
            "Y to_local sweep before CSV",
            &y_sweep,
            "locked until height",
        ),
        (
            "W HTLC 2 refund before expiry",
            &w2_timeout,
            "locked until height",
        ),
        (
            "V HTLC 3 claim before CSV",
            &v3_success,
            "locked until height",
        ),
        (
            "V HTLC 4 refund before expiry",
            &v4_timeout,
            "locked until height",
        ),
        (
            "W HTLC 1 claim, wrong preimage",
            &wrong_preimage,
            "preimage",
        ),
    ] {
        submit_refused(&mut chain, name, tx, says);
    }
    judges.refuse(
        &chain,
        &producer,
        vec![
            (
                "Y to_local sweep before CSV",
                y_sweep.clone(),
                "btc:rule-blockctx-sequence-locks",
                false,
            ),
            (
                "W HTLC 2 refund before expiry",
                w2_timeout.clone(),
                "btc:rule-blockctx-finality",
                false,
            ),
            (
                "V HTLC 3 claim before CSV",
                v3_success.clone(),
                "btc:rule-blockctx-sequence-locks",
                false,
            ),
            (
                "V HTLC 4 refund before expiry",
                v4_timeout.clone(),
                "btc:rule-blockctx-finality",
                false,
            ),
            (
                "W HTLC 1 claim, wrong preimage",
                wrong_preimage,
                "btc:rule-blockctx-scripts",
                true,
            ),
        ],
    );

    // the penalty, B's to_remote and B's preimage claim go through at once
    for (name, tx) in [
        ("Z penalty through the revocation leaf", &z_penalty),
        ("Y to_remote, key path", &y_remote_take),
        ("W HTLC 1 claim with the preimage", &w1_success),
    ] {
        judges.carry(&chain, name, tx);
        submit(&mut chain, name, tx);
    }
    produce(&mut chain, &producer, 3);

    // one block before the delay: still refused by both
    while chain.state().height() < commit_height + u32::from(DELAY) - 2 {
        produce(&mut chain, &producer, 0);
    }
    submit_refused(
        &mut chain,
        "Y sweep one block early",
        &y_sweep,
        "locked until height",
    );
    judges.refuse(
        &chain,
        &producer,
        vec![(
            "Y to_local sweep one block early",
            y_sweep.clone(),
            "btc:rule-blockctx-sequence-locks",
            false,
        )],
    );
    produce(&mut chain, &producer, 0);
    assert_eq!(chain.state().height() + 1, commit_height + u32::from(DELAY));

    // the delay has passed: a wrong control block, a wrong internal key and a tampered leaf are
    // refused by both, for the script alone
    let mutate = |f: &dyn Fn(&mut Vec<Vec<u8>>)| {
        let mut tx = y_sweep.clone();
        let mut items: Vec<Vec<u8>> = tx.input[0].witness.iter().map(<[u8]>::to_vec).collect();
        f(&mut items);
        tx.input[0].witness = Witness::from_slice(&items);
        tx
    };
    let parity_flipped = mutate(&|w| w[2][0] ^= 1);
    let wrong_internal_key = mutate(&|w| w[2][1..33].copy_from_slice(&pb.serialize()));
    let wrong_path = mutate(&|w| w[2][33] ^= 1);
    let tampered_leaf = mutate(&|w| {
        w[1] = ChannelLeaf::Delayed { delay: 1, key: pa }
            .to_script()
            .to_bytes();
    });
    let unknown_leaf = mutate(&|w| w[1] = vec![0x51]);
    for (tx, want) in [
        (&parity_flipped, ChannelError::Commitment),
        (&wrong_internal_key, ChannelError::Commitment),
        (&wrong_path, ChannelError::Commitment),
        (&tampered_leaf, ChannelError::Commitment),
        (&unknown_leaf, ChannelError::Commitment),
    ] {
        assert_eq!(
            verify_channel_input(tx, 0, &prevouts(&chain, tx), RULES).map(|s| s.leaf),
            Err(want)
        );
        assert!(chain.submit(&serialize(tx)).is_err());
    }
    judges.refuse(
        &chain,
        &producer,
        vec![
            (
                "Y sweep, control block parity flipped",
                parity_flipped,
                "btc:rule-blockctx-scripts",
                true,
            ),
            (
                "Y sweep, wrong internal key",
                wrong_internal_key,
                "btc:rule-blockctx-scripts",
                true,
            ),
            (
                "Y sweep, wrong merkle path",
                wrong_path,
                "btc:rule-blockctx-scripts",
                true,
            ),
            (
                "Y sweep, tampered leaf (delay 1)",
                tampered_leaf,
                "btc:rule-blockctx-scripts",
                true,
            ),
            (
                "Y sweep, uncommitted OP_TRUE leaf",
                unknown_leaf,
                "btc:rule-blockctx-scripts",
                true,
            ),
        ],
    );

    // and the sweep, the refunds and the delayed claim go through
    for (name, tx) in [
        ("Y to_local sweep after CSV", &y_sweep),
        ("W HTLC 2 refund after expiry and CSV", &w2_timeout),
        ("V HTLC 3 claim with the preimage after CSV", &v3_success),
        ("V HTLC 4 refund after expiry", &v4_timeout),
    ] {
        judges.carry(&chain, name, tx);
        submit(&mut chain, name, tx);
    }
    let last = produce(&mut chain, &producer, 4);
    let tip = chain.state().tip();
    assert_eq!(tip.height, last);
    // every output a script path spent is gone: Y's and Z's to_local and the four HTLCs
    let spent: Vec<OutPoint> = [
        &y_sweep,
        &z_penalty,
        &w1_success,
        &w2_timeout,
        &v3_success,
        &v4_timeout,
    ]
    .iter()
    .map(|t| t.input[0].previous_output)
    .collect();
    assert_eq!(spent.len(), 6);
    assert!(spent.iter().all(|o| chain.state().output(o).is_none()));
    assert!(chain
        .state()
        .utxo()
        .keys()
        .all(|o| o.txid != fund.compute_txid() || o.vout == 5));
    eprintln!(
        "sidestr-core: tip {} at {}, {} coins; {} channel spends carried, {} blocks refused",
        tip.hash,
        tip.height,
        chain.state().utxo().len(),
        judges.carried.len(),
        judges.refused.len()
    );

    if let Some(r) = &judges.reference {
        let v = r.run(&[OsStr::new("replay"), r.doc.as_os_str(), r.dir.as_os_str()]);
        assert_eq!(v["height"], tip.height, "{v}");
        assert_eq!(v["tip"], tip.hash.to_string(), "{v}");
        assert_eq!(v["coins"], chain.state().utxo().len(), "{v}");
        eprintln!(
            "reference: replayed to the same tip {} at {}",
            v["tip"], v["height"]
        );
    }

    #[cfg(feature = "consensus-oracle")]
    {
        for (name, tx, prev) in &judges.carried {
            assert!(
                core_accepts(tx, prev),
                "Core refused a carried spend: {name}"
            );
            for i in 0..tx.input.len() {
                verify_supported_input(tx, i, prev, RULES).unwrap();
            }
        }
        for (name, tx, prev, script_level) in &judges.refused {
            let core = core_accepts(tx, prev);
            let ours =
                (0..tx.input.len()).all(|i| verify_supported_input(tx, i, prev, RULES).is_ok());
            assert_eq!(
                core, ours,
                "{name}: Core {core}, sidestr-core's script check {ours}"
            );
            assert_eq!(
                core, !script_level,
                "{name}: Core says {core}; a lock negative passes the script, a script negative fails it"
            );
        }
        eprintln!(
            "Core 26.0: {} carried spends accepted; {} script negatives refused; {} lock negatives pass the script (the block refuses them)",
            judges.carried.len(),
            judges.refused.iter().filter(|r| r.3).count(),
            judges.refused.iter().filter(|r| !r.3).count()
        );
    }

    // the BIP 68 admission probe on the reference: what its mempool does with an early sweep
    if let Some(r) = &judges.reference {
        let probe = probe_reference_mempool(&mut chain, &producer, &p, r);
        eprintln!("reference mempool probe (early to_local sweep): {probe}");
    }
    let _ = std::fs::remove_dir_all(&dir);
    if let Some(r) = &judges.reference {
        let _ = std::fs::remove_file(&r.doc);
    }
}

/// Open one more channel, force-close it, and hand the reference's mempool
/// the `to_local` sweep a block after the commitment: report what `submit`
/// and the next `produce` do. Recorded, not asserted beyond the consensus
/// verdict: at sidestr/spec `fa86dac` the mempool admits it and every
/// produce then fails on `btc:rule-blockctx-sequence-locks`. No block is
/// made, so a height-based lock never matures, and the chain halts until the
/// producer restarts (observed 2026-10-02: `after == before`, `mempool: 1`).
/// From `c3b9e7a` (issue 13, not in `fa86dac`) the producer evicts it.
fn probe_reference_mempool(
    chain: &mut Chain,
    producer: &SecretKey,
    p: &Peers,
    r: &Reference,
) -> serde_json::Value {
    let (pa, pb) = (public(&p.a), public(&p.b));
    let alice = challenge_for(&pa);
    let coin = chain
        .state()
        .coins(&alice)
        .into_iter()
        .max_by_key(|c| c.value)
        .unwrap();
    let funding_spk = sidestr_hitch::funding_script(pa, pb).unwrap().script_pubkey;
    let fund = wallet_spend(
        coin.outpoint,
        chain.state().output(&coin.outpoint).unwrap().clone(),
        vec![TxOut {
            value: Amount::from_sat(coin.value - 500),
            script_pubkey: funding_spk,
        }],
        &p.a,
    );
    submit(chain, "probe funding", &fund);
    produce(chain, producer, 1);
    let ch = Channel::new(
        pa,
        pb,
        OutPoint {
            txid: fund.compute_txid(),
            vout: 0,
        },
        Amount::from_sat(coin.value - 500),
        Amount::from_sat(300),
        DELAY,
    )
    .unwrap();
    let st = ChannelState {
        balances: Balances {
            a: Amount::from_sat(coin.value - 500),
            b: Amount::ZERO,
        },
        revocation: p.revocation(1),
        htlcs: vec![],
    };
    let (c, tx) = commit(&ch, p, 1, Side::A, &st);
    submit(chain, "probe commitment", &tx);
    produce(chain, producer, 1);
    let early = sweep_to_local(
        &c,
        SweepPath::Delayed,
        alice,
        Amount::from_sat(300),
        &p.a,
        RULES,
        &AUX,
    )
    .unwrap();
    submit_refused(chain, "probe early sweep", &early, "locked until height");
    let key_file = r.dir.with_extension("producer.key");
    let tx_file = r.dir.with_extension("early.hex");
    std::fs::write(&key_file, hex::encode(producer.secret_bytes())).unwrap();
    std::fs::write(&tx_file, serialize_hex(&early)).unwrap();
    let v = r.run(&[
        OsStr::new("mempool"),
        r.doc.as_os_str(),
        r.dir.as_os_str(),
        key_file.as_os_str(),
        tx_file.as_os_str(),
    ]);
    std::fs::remove_file(key_file).unwrap();
    std::fs::remove_file(tx_file).unwrap();
    // consensus, at any pin: no block carrying the early sweep is made
    if let Some(produced) = v["produced"].as_object() {
        assert!(
            produced["evicted"]
                .as_array()
                .is_some_and(|e| !e.is_empty())
                || produced["txs"] == 1,
            "the reference made a block with the early sweep: {v}"
        );
    } else {
        assert!(
            v["produceError"]
                .as_str()
                .is_some_and(|e| e.contains("sequence-locks")),
            "{v}"
        );
    }
    v
}

#[test]
fn hitch_builders_write_exactly_the_core_templates() {
    let a = key("alice");
    let b = key("bob");
    let (pa, pb) = (public(&a), public(&b));
    let f = sidestr_hitch::funding_script(pa, pb).unwrap();
    assert_eq!(
        ChannelLeaf::parse(&f.leaf.script),
        Some(ChannelLeaf::Funding { keys: f.signers })
    );
    let rev = public(&key("revocation"));
    for delay in [
        sidestr_hitch::MIN_DELAY,
        DELAY,
        16,
        17,
        127,
        128,
        sidestr_hitch::MAX_DELAY,
    ] {
        let t = sidestr_hitch::to_local_script(pa, rev, delay).unwrap();
        assert_eq!(
            ChannelLeaf::parse(&t.delayed.script),
            Some(ChannelLeaf::Delayed { delay, key: pa })
        );
        assert_eq!(
            ChannelLeaf::parse(&t.revocation.script),
            Some(ChannelLeaf::Key { key: rev })
        );
        for expiry in [
            0u32,
            16,
            17,
            255,
            256,
            152_200,
            0x80_0000,
            sidestr_hitch::MAX_EXPIRY - 1,
        ] {
            let hash = [0x42; 32];
            for offered_by_owner in [true, false] {
                let h = sidestr_hitch::htlc_script(sidestr_hitch::HtlcScriptArgs {
                    owner_pub: pa,
                    remote_pub: pb,
                    revocation_pub: rev,
                    delay,
                    payment_hash: hash,
                    expiry,
                    offered_by_owner,
                })
                .unwrap();
                let (success, timeout) = if offered_by_owner {
                    (
                        ChannelLeaf::HashLock { hash, key: pb },
                        ChannelLeaf::TimeoutDelayed {
                            expiry,
                            delay,
                            key: pa,
                        },
                    )
                } else {
                    (
                        ChannelLeaf::HashLockDelayed {
                            hash,
                            delay,
                            key: pa,
                        },
                        ChannelLeaf::Timeout { expiry, key: pb },
                    )
                };
                assert_eq!(ChannelLeaf::parse(&h.success.script), Some(success));
                assert_eq!(ChannelLeaf::parse(&h.timeout.script), Some(timeout));
                assert_eq!(
                    ChannelLeaf::parse(&h.revocation.script),
                    Some(ChannelLeaf::Key { key: rev })
                );
                // and the core's rendering is Hitch's bytes
                assert_eq!(success.to_script(), h.success.script);
                assert_eq!(timeout.to_script(), h.timeout.script);
            }
        }
    }
}

/// Beside a BLAKE2b parent (`txbt4`, owner decision SC1) every Hitch spend
/// signs Knots' unified sighash (`0x21`); `sidestr-core` must read it there,
/// refuse it beside a stock parent, and still read a BIP 341 signature.
#[test]
fn unified_sighash_channel_spends_are_judged_by_the_family_rules() {
    let a = key("alice");
    let b = key("bob");
    let rev = key("revocation");
    let ch = Channel::new(
        public(&a),
        public(&b),
        OutPoint {
            txid: bitcoin::Txid::from_byte_array([0xab; 32]),
            vout: 1,
        },
        Amount::from_sat(VALUE),
        Amount::from_sat(300),
        DELAY,
    )
    .unwrap();
    let st = ChannelState {
        balances: Balances {
            a: Amount::from_sat(70_000),
            b: Amount::from_sat(30_000),
        },
        revocation: RevocationKeys {
            a: public(&rev),
            b: public(&b),
        },
        htlcs: vec![],
    };
    for rules in [SighashRules::KnotsUnified, SighashRules::Bip341] {
        let c = ch.commitment(1, Side::A, &st).unwrap();
        let mut tx = c.tx.clone();
        let sigs = BTreeMap::from([
            (public(&a), ch.sign_funding(&tx, &a, rules, &AUX).unwrap()),
            (public(&b), ch.sign_funding(&tx, &b, rules, &AUX).unwrap()),
        ]);
        tx.input[0].witness = ch.funding_witness(&sigs).unwrap();
        let prev = [ch.funding_prevout()];
        let sweep = sweep_to_local(
            &c,
            SweepPath::Delayed,
            to_remote_script(public(&a)),
            Amount::from_sat(200),
            &a,
            rules,
            &AUX,
        )
        .unwrap();
        let penalty = sweep_to_local(
            &c,
            SweepPath::Revocation,
            to_remote_script(public(&b)),
            Amount::from_sat(200),
            &rev,
            rules,
            &AUX,
        )
        .unwrap();
        let local_prev = [TxOut {
            value: c.local_value,
            script_pubkey: c.to_local.script_pubkey.clone(),
        }];
        for (name, t, p) in [
            ("commitment", &tx, &prev[..]),
            ("sweep", &sweep, &local_prev[..]),
            ("penalty", &penalty, &local_prev[..]),
        ] {
            assert!(
                verify_supported_input(t, 0, p, SighashRules::KnotsUnified).is_ok(),
                "{name} {rules:?} beside BLAKE2b"
            );
            let stock = verify_supported_input(t, 0, p, SighashRules::Bip341);
            assert_eq!(
                stock.is_ok(),
                rules == SighashRules::Bip341,
                "{name} {rules:?} beside stock: {stock:?}"
            );
        }
    }
}
