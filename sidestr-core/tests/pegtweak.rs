//! `siding/test/pegtweak-test.mjs` (sidestr/spec `4c4915f`) ported, all
//! fifteen checks, with rust-bitcoin's taproot (`TapTweak`,
//! `TaprootBuilder`, `ControlBlock`) as the independent engine where
//! upstream uses the schema kernel's `tapOutputKey`/`checkTapTweak`: the
//! output is BIP 341 exactly; two chains give two addresses from one key;
//! the reveal rebuilds the output; every leaf's control block proves its
//! path; the holders' key-path secret signs for the output.
//!
//! The live half runs `pegtweak.mjs` itself over fixed reveals
//! (`tests/xcheck-pegtweak.mjs pegtweak`) when `SIDESTR_SIDING` names a
//! siding checkout that carries it (sidestr/spec `4c4915f` or later) and
//! `SCHEMA` the bitcoin-desktop/schema checkout; otherwise it reports itself
//! skipped.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Keypair, Message, Parity, Scalar, SecretKey, XOnlyPublicKey};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TapNodeHash, TaprootBuilder};
use bitcoin::ScriptBuf;
use serde_json::{json, Value};
use sidestr_core::block::secp;
use sidestr_core::federation::{leaf_script, NUMS_X};
use sidestr_core::keys::{negate, normalize, public_key, tagged_scalar, tweak_point, x_only};
use sidestr_core::pegtweak::{
    commit_leaf, leaf_hash, peg_commitment, peg_matches, peg_output, peg_spend_secret, refund_leaf,
    tap_tree, PegError, PegOutput, PegReveal, PEG_TAG,
};

const HOLDER: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const PEGGER: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn chain_a() -> String {
    "aa".repeat(32)
}
fn chain_b() -> String {
    "bb".repeat(32)
}
fn script() -> String {
    format!("5120{}", "11".repeat(32))
}
fn refund() -> String {
    x_only(&public_key(PEGGER).unwrap()).unwrap()
}

fn reveal(internal: &str, chain_hash: &str, script: &str) -> PegReveal {
    PegReveal {
        internal: internal.to_string(),
        refund_key: refund(),
        refund_blocks: 10_000,
        chain_hash: chain_hash.to_string(),
        script: script.to_string(),
        extra_leaves: vec![],
    }
}

fn out() -> PegOutput {
    peg_output(
        &reveal(&public_key(HOLDER).unwrap(), &chain_a(), &script()),
        "tb",
    )
    .unwrap()
}

fn xonly(h: &str) -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&hex::decode(h).unwrap()).unwrap()
}

fn node(h: &str) -> TapNodeHash {
    TapNodeHash::from_byte_array(hex::decode(h).unwrap().try_into().unwrap())
}

fn script_of(h: &str) -> ScriptBuf {
    ScriptBuf::from_hex(h).unwrap()
}

/// rust-bitcoin's output key and parity for an internal x and a root.
fn bip341(internal: &str, root: &str) -> (String, Parity) {
    let (q, parity) = xonly(internal).tap_tweak(secp(), Some(node(root)));
    (hex::encode(q.to_x_only_public_key().serialize()), parity)
}

/// The control block's path walked from the leaf to the root.
fn walk(leaf: &str, control: &str) -> String {
    let mut h = node(&leaf_hash(leaf).unwrap());
    for sib in control.as_bytes()[2 + 64..].chunks(64) {
        h = TapNodeHash::from_node_hashes(h, node(std::str::from_utf8(sib).unwrap()));
    }
    hex::encode(h.to_byte_array())
}

// ---- BIP 341 exactly

#[test]
fn output_key_is_bip341s_for_the_internal_key_and_root() {
    let o = out();
    let (q, parity) = bip341(&o.internal_key, &o.root);
    assert_eq!(o.output_key, q);
    assert_eq!(o.output_parity, parity.to_u8());
}

#[test]
fn control_block_parity_is_the_output_keys() {
    let o = out();
    let t = Scalar::from_be_bytes(hex::decode(&o.tweak).unwrap().try_into().unwrap()).unwrap();
    let p = Parity::from_u8(o.output_parity).unwrap();
    let internal = xonly(&o.internal_key);
    assert!(internal.tweak_add_check(secp(), &xonly(&o.output_key), p, t));
    assert!(!internal.tweak_add_check(
        secp(),
        &xonly(&o.output_key),
        Parity::from_u8(1 - o.output_parity).unwrap(),
        t
    ));
}

#[test]
fn script_and_address_shape() {
    let o = out();
    assert_eq!(o.script_pubkey, format!("5120{}", o.output_key));
    assert!(o.address.starts_with("tb1p") && o.address.len() == 62);
    assert!(o.address[4..]
        .chars()
        .all(|c| "qpzry9x8gf2tvdw0s3jn54khce6mua7l".contains(c)));
    assert_eq!(o.script(), script_of(&o.script_pubkey));
}

#[test]
fn internal_key_is_its_even_lift_whatever_the_holders_parity() {
    let p = public_key(HOLDER).unwrap();
    let flipped = peg_output(&reveal(&negate(&p).unwrap(), &chain_a(), &script()), "tb").unwrap();
    assert_eq!(flipped.output_key, out().output_key);
    let bare = peg_output(&reveal(&x_only(&p).unwrap(), &chain_a(), &script()), "tb").unwrap();
    assert_eq!(bare, out());
}

// ---- the leaves

#[test]
fn refund_leaf_is_and_v_pk_older() {
    let o = out();
    let r = refund();
    assert_eq!(o.refund.script, format!("20{r}ad021027b2"));
    assert!(refund_leaf(&r, 16).unwrap().ends_with("60b2"));
    assert!(refund_leaf(&r, 128).unwrap().ends_with("028000b2"));
    assert_eq!(refund_leaf(&r, 0), Err(PegError::BlockCount));
}

#[test]
fn commitment_leaf_is_pk_of_nums_plus_t() {
    let o = out();
    let c = commit_leaf(&chain_a(), &script()).unwrap();
    let script_hash = sha256::Hash::hash(&hex::decode(script()).unwrap()).to_byte_array();
    let t = tagged_scalar(PEG_TAG, &[&hex::decode(chain_a()).unwrap(), &script_hash]).unwrap();
    assert_eq!(o.commit.script, format!("20{}ac", c.key));
    assert_eq!(
        c.key,
        x_only(&tweak_point(&format!("02{}", hex::encode(NUMS_X)), &t).unwrap()).unwrap()
    );
    assert_eq!(o.commitment, peg_commitment(&chain_a(), &script()).unwrap());
    assert_eq!(o.commitment, t);
}

#[test]
fn bad_chain_hash_and_script_are_refused_in_words() {
    let e = peg_commitment("sidestr:poker", &script()).unwrap_err();
    assert!(e.to_string().contains("chain event"), "{e}");
    let e = peg_commitment(&chain_a(), "zz").unwrap_err();
    assert!(e.to_string().contains("hex"), "{e}");
    // a chain hash in capitals is the same hash
    assert_eq!(
        peg_commitment(&chain_a().to_uppercase(), &script()).unwrap(),
        peg_commitment(&chain_a(), &script()).unwrap()
    );
}

// ---- distinct outputs

#[test]
fn two_chains_two_addresses_from_one_key() {
    let p = public_key(HOLDER).unwrap();
    let b = peg_output(&reveal(&p, &chain_b(), &script()), "tb").unwrap();
    assert_ne!(b.address, out().address);
    assert_ne!(b.commit_key, out().commit_key);
}

#[test]
fn two_scripts_two_addresses() {
    let p = public_key(HOLDER).unwrap();
    let s = peg_output(
        &reveal(&p, &chain_a(), &format!("5120{}", "22".repeat(32))),
        "tb",
    )
    .unwrap();
    assert_ne!(s.address, out().address);
}

#[test]
fn the_reveal_rebuilds_the_output() {
    let o = out();
    let b = peg_output(
        &reveal(&public_key(HOLDER).unwrap(), &chain_b(), &script()),
        "tb",
    )
    .unwrap();
    assert_eq!(peg_output(&o.reveal, "tb").unwrap().address, o.address);
    assert!(peg_matches(&o.reveal, &o.script_pubkey).unwrap());
    assert!(peg_matches(&o.reveal, &o.script_pubkey.to_uppercase()).unwrap());
    assert!(!peg_matches(&b.reveal, &o.script_pubkey).unwrap());
    // the reveal travels as upstream's JSON
    let j = serde_json::to_value(&o.reveal).unwrap();
    assert_eq!(
        j.as_object().unwrap().keys().collect::<Vec<_>>(),
        [
            "internal",
            "refundKey",
            "refundBlocks",
            "chainHash",
            "script",
            "extraLeaves"
        ]
    );
    let back: PegReveal = serde_json::from_value(j).unwrap();
    assert_eq!(back, o.reveal);
}

// ---- control blocks

#[test]
fn control_blocks_walk_to_the_root() {
    let o = out();
    let prefix = format!("{:02x}", 0xc0 | o.output_parity);
    for l in &o.leaves {
        assert_eq!(walk(&l.script, &l.control_block), o.root);
        assert_eq!(l.control_block.len(), 2 + 64 + 64);
        assert!(l.control_block.starts_with(&prefix));
        // and rust-bitcoin reads each as a proof of its leaf in this output
        let cb = ControlBlock::decode(&hex::decode(&l.control_block).unwrap()).unwrap();
        assert!(cb.verify_taproot_commitment(secp(), xonly(&o.output_key), &script_of(&l.script)));
    }
}

#[test]
fn two_leaf_tree_matches_rust_bitcoins_builder() {
    let o = out();
    let info = TaprootBuilder::new()
        .add_leaf(1, script_of(&o.refund.script))
        .unwrap()
        .add_leaf(1, script_of(&o.commit.script))
        .unwrap()
        .finalize(secp(), xonly(&o.internal_key))
        .unwrap();
    assert_eq!(
        hex::encode(info.merkle_root().unwrap().to_byte_array()),
        o.root
    );
    assert_eq!(
        hex::encode(info.output_key().to_x_only_public_key().serialize()),
        o.output_key
    );
    for l in &o.leaves {
        let cb = info
            .control_block(&(script_of(&l.script), LeafVersion::TapScript))
            .unwrap();
        assert_eq!(hex::encode(cb.serialize()), l.control_block);
    }
}

fn signers() -> Vec<XOnlyPublicKey> {
    (1..=3)
        .map(|i| xonly(&x_only(&public_key(&format!("{:064x}", 1000 + i)).unwrap()).unwrap()))
        .collect()
}

#[test]
fn three_leaf_tree_every_path_valid_and_bip341() {
    let multi = leaf_script(&signers(), 2).unwrap().to_hex_string();
    let mut r = reveal(&format!("02{}", hex::encode(NUMS_X)), &chain_a(), &script());
    r.extra_leaves = vec![multi.clone()];
    let o3 = peg_output(&r, "tb").unwrap();
    assert_eq!(o3.leaves.len(), 3);
    for l in &o3.leaves {
        assert_eq!(walk(&l.script, &l.control_block), o3.root);
    }
    assert_eq!(bip341(&hex::encode(NUMS_X), &o3.root).0, o3.output_key);
    // upstream's shape, (refund, commit) then multi: depths 2, 2, 1
    let info = TaprootBuilder::new()
        .add_leaf(2, script_of(&o3.refund.script))
        .unwrap()
        .add_leaf(2, script_of(&o3.commit.script))
        .unwrap()
        .add_leaf(1, script_of(&multi))
        .unwrap()
        .finalize(secp(), xonly(&hex::encode(NUMS_X)))
        .unwrap();
    assert_eq!(
        hex::encode(info.merkle_root().unwrap().to_byte_array()),
        o3.root
    );
    assert_eq!(
        hex::encode(info.output_key().to_x_only_public_key().serialize()),
        o3.output_key
    );
    for l in &o3.leaves {
        let cb = info
            .control_block(&(script_of(&l.script), LeafVersion::TapScript))
            .unwrap();
        assert_eq!(hex::encode(cb.serialize()), l.control_block);
    }
    assert!(o3.descriptor.ends_with(",…})"));
}

#[test]
fn single_leaf_tree_is_its_leaf() {
    let multi = leaf_script(&signers(), 2).unwrap().to_hex_string();
    let tr = tap_tree(&[multi.as_str()]).unwrap();
    assert_eq!(tr.root, leaf_hash(&multi).unwrap());
    assert!(tr.paths[0].is_empty());
    assert_eq!(
        tr.root,
        hex::encode(
            TapLeafHash::from_script(&script_of(&multi), LeafVersion::TapScript).to_byte_array()
        )
    );
    assert_eq!(tap_tree::<&str>(&[]), Err(PegError::EmptyTree));
}

// ---- the holders spend by key path

fn signs_for(secret: &str, output_key: &str) -> bool {
    let kp = Keypair::from_secret_key(
        secp(),
        &SecretKey::from_slice(&hex::decode(secret).unwrap()).unwrap(),
    );
    let msg =
        Message::from_digest(sha256::Hash::hash(&hex::decode(output_key).unwrap()).to_byte_array());
    let sig = secp().sign_schnorr_with_aux_rand(&msg, &kp, &[0u8; 32]);
    secp()
        .verify_schnorr(&sig, &msg, &xonly(output_key))
        .is_ok()
}

#[test]
fn key_path_secret_signs_for_the_output_even_and_odd_holders() {
    let o = out();
    assert!(signs_for(
        &peg_spend_secret(HOLDER, &o).unwrap(),
        &o.output_key
    ));
    // the other sign: the holder whose point has the other parity
    let other = normalize(HOLDER).unwrap();
    let other = if other == HOLDER {
        hex::encode(
            SecretKey::from_slice(&hex::decode(HOLDER).unwrap())
                .unwrap()
                .negate()
                .secret_bytes(),
        )
    } else {
        other
    };
    assert_ne!(
        public_key(&other).unwrap()[..2],
        public_key(HOLDER).unwrap()[..2]
    );
    let o2 = peg_output(
        &reveal(&public_key(&other).unwrap(), &chain_a(), &script()),
        "tb",
    )
    .unwrap();
    assert!(signs_for(
        &peg_spend_secret(&other, &o2).unwrap(),
        &o2.output_key
    ));
    // and rust-bitcoin's key-path tweak of the holder's keypair is the same key
    let kp = Keypair::from_secret_key(
        secp(),
        &SecretKey::from_slice(&hex::decode(HOLDER).unwrap()).unwrap(),
    );
    let tweaked = kp.tap_tweak(secp(), Some(node(&o.root)));
    assert_eq!(
        hex::encode(tweaked.to_keypair().secret_bytes()),
        peg_spend_secret(HOLDER, &o).unwrap()
    );
}

#[test]
fn descriptor_names_internal_refund_and_commit() {
    let o = out();
    assert_eq!(
        o.descriptor,
        format!(
            "tr({},{{and_v(v:pk({}),older(10000)),pk({})}})",
            o.internal_key,
            refund(),
            o.commit_key
        )
    );
}

// ---- the live half: pegtweak.mjs over fixed reveals

fn oracle(input: &Value) -> Option<Value> {
    let (Ok(siding), Ok(schema)) = (std::env::var("SIDESTR_SIDING"), std::env::var("SCHEMA"))
    else {
        eprintln!("skipped the pegtweak.mjs oracle: set SIDESTR_SIDING and SCHEMA");
        return None;
    };
    if !PathBuf::from(&siding).join("lib/pegtweak.mjs").exists() {
        eprintln!("skipped the pegtweak.mjs oracle: {siding} predates it (sidestr/spec 4c4915f)");
        return None;
    }
    let mut child = Command::new("node")
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/xcheck-pegtweak.mjs"))
        .arg("pegtweak")
        .env("SIDESTR_SIDING", siding)
        .env("SCHEMA", schema)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("node on the path");
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "xcheck-pegtweak.mjs pegtweak failed");
    Some(serde_json::from_slice(&out.stdout).unwrap())
}

#[test]
fn pegtweak_mjs_agrees() {
    let holder = public_key(HOLDER).unwrap();
    let multi = leaf_script(&signers(), 2).unwrap().to_hex_string();
    let odd_holder = (1u64..)
        .map(|i| format!("{i:064x}"))
        .find(|h| public_key(h).unwrap().starts_with("03"))
        .unwrap();
    let mut cases = vec![
        json!({ "internal": holder, "refundKey": refund(), "refundBlocks": 10000, "chainHash": chain_a(), "script": script(), "extraLeaves": [], "hrp": "tb", "holder": HOLDER }),
        json!({ "internal": x_only(&holder).unwrap(), "refundKey": public_key(PEGGER).unwrap(), "refundBlocks": 16, "chainHash": chain_b().to_uppercase(), "script": script().to_uppercase(), "extraLeaves": [], "hrp": "bc", "holder": HOLDER }),
        json!({ "internal": format!("02{}", hex::encode(NUMS_X)), "refundKey": refund(), "refundBlocks": 128, "chainHash": chain_a(), "script": script(), "extraLeaves": [multi], "hrp": "tb" }),
        json!({ "internal": public_key(&odd_holder).unwrap(), "refundKey": refund(), "refundBlocks": 0x7fff_ffff, "chainHash": chain_a(), "script": "6a", "extraLeaves": [], "hrp": "tb", "holder": odd_holder }),
        json!({ "internal": holder, "refundKey": refund(), "refundBlocks": 144, "chainHash": chain_a(), "script": script(), "extraLeaves": [multi, format!("20{}ac", refund())], "hrp": "tb" }),
    ];
    // the refusals, in upstream's words
    for (blocks, chain, s) in [
        (0, chain_a(), script()),
        (10, "sidestr:poker".into(), script()),
        (10, chain_a(), "zz".into()),
    ] {
        cases.push(json!({ "internal": holder, "refundKey": refund(), "refundBlocks": blocks, "chainHash": chain, "script": s, "extraLeaves": [], "hrp": "tb" }));
    }
    let Some(theirs) = oracle(&Value::Array(cases.clone())) else {
        return;
    };
    let theirs = theirs.as_array().unwrap();
    assert_eq!(theirs.len(), cases.len());
    for (c, t) in cases.iter().zip(theirs) {
        let r: PegReveal = serde_json::from_value(c.clone()).unwrap();
        let hrp = c["hrp"].as_str().unwrap();
        match peg_output(&r, hrp) {
            Ok(o) => {
                assert_eq!(serde_json::to_value(&o).unwrap(), t["ok"], "{c}");
                assert_eq!(t["matches"], json!(true));
                if let Some(h) = c["holder"].as_str() {
                    assert_eq!(json!(peg_spend_secret(h, &o).unwrap()), t["spend"], "{c}");
                }
            }
            Err(e) => assert_eq!(json!(e.to_string()), t["error"], "{c}"),
        }
    }
    eprintln!("compared {} reveals with pegtweak.mjs", cases.len());
}
