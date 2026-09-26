//! Everything the agent does without a network: keys, names, a full loop
//! between two agents on a chain held in memory (a spend by npub, one back
//! by did:nostr, a peg-out), the peg-in plan, and the binary's offline
//! commands. The live loop on `sidestr:dreamlab` (2026-09-23) supplies the
//! golden values: the two agents' public keys and chain addresses, and the
//! marker hex the peg-in paid.

use std::process::Command;

use bitcoin::key::XOnlyPublicKey;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::SecretKey;
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{
    absolute::LockTime, Address, Amount, Network, Script, ScriptBuf, Transaction, TxOut,
};
use sidestr_agent::{
    destination, identity, level1_peg_key, npub, parse_pubkey, pegin_plan, prepare, AgentKey,
    Error, Payment, PegTarget,
};
use sidestr_core::block::{challenge_for, pubkey_of};
use sidestr_core::document::{ChainDocument, Peg};
use sidestr_core::marker::parse_peg_marker;
use sidestr_core::parent::find_pegin;
use sidestr_core::state::{NextBlock, State};
use sidestr_nostr::tx::parse_transaction;
use sidestr_wallet::coins::from_state;

const DREAMLAB: &str = include_str!("fixtures/dreamlab-chain.json");
/// The live loop's agents (public halves only), from `sidestr-agent address`.
const ALICE: &str = "c95b519579bda3b5e29f5dca4a0b8f9f1d04d1979d2e4c3a33483a6b34b61d88";
const ALICE_DRM: &str = "drm1pe9d4r9tehk3mtc5lth9y5zu0nuwsf5vhn5hycw3nfqaxkd9krkyqtc7grc";
const BOB: &str = "c082a917c7d9141abd2ec7c8b86e6ed52ac25d85a3b3b40b3dbc03dada92e980";
const BOB_DRM: &str = "drm1pczp2j978my2p40fwclytsmnw654vyhv95wemgzeahspa4k5jaxqqvj6v6t";
/// The live peg-in's peg address and marker (`agents/pegin.plan`).
const LIVE_PEG: &str = "tb1palk8spjn20q8fa3gu8p30tx4xl0mqyk7t3497540zjkmt4zdvesq07eq2k";
const LIVE_MARKER: &str = "706567696e3a736964657374723a647265616d6c61623a5120c95b519579bda3b5e29f5dca4a0b8f9f1d04d1979d2e4c3a33483a6b34b61d88";

#[test]
fn keys_and_names() {
    // NIP-19's published vectors
    let k =
        AgentKey::parse("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5").unwrap();
    let h = AgentKey::parse("67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa")
        .unwrap();
    assert_eq!(k.pubkey(), h.pubkey());
    let p =
        parse_pubkey("npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg").unwrap();
    assert_eq!(
        p.to_string(),
        "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"
    );
    assert_eq!(
        npub(&p),
        "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"
    );
    // refusals never echo the text (it may be a secret)
    for bad in [
        "",
        "abc",
        "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg",
        "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe6",
        "…é…é…",
        &"00".repeat(32),
    ] {
        let e = AgentKey::parse(bad).unwrap_err();
        assert!(matches!(e, Error::Key(_)), "{bad:?}: {e}");
        if bad.len() > 8 {
            assert!(!e.to_string().contains(bad), "{e}");
        }
    }
    assert!(parse_pubkey("did:nostr:zz").is_err());
    assert!(
        parse_pubkey("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5").is_err()
    );

    // the live loop's agents: did:nostr key → the drm address the chain paid
    for (hex, drm) in [(ALICE, ALICE_DRM), (BOB, BOB_DRM)] {
        let key = parse_pubkey(hex).unwrap();
        let id = identity(&key, "drm").unwrap();
        assert_eq!(id.address, drm);
        assert_eq!(id.did, format!("did:nostr:{hex}"));
        assert_eq!(id.script, format!("5120{hex}"));
        // every name goes back to the same script
        for name in [&id.npub, &id.did, &id.pubkey] {
            assert_eq!(parse_pubkey(name).unwrap(), key);
        }
        assert_eq!(destination(&id.npub).unwrap(), id.script);
        assert_eq!(destination(&id.did).unwrap(), id.script);
    }
    assert_eq!(destination(ALICE_DRM).unwrap(), ALICE_DRM);
    assert!(destination("  ").is_err());
    assert!(identity(&parse_pubkey(ALICE).unwrap(), "UPPER lower").is_none());
}

fn agent(seed: u8) -> AgentKey {
    AgentKey::parse(&hex::encode([seed; 32])).unwrap()
}

#[test]
fn two_agents_trade_and_one_pegs_out() {
    let producer = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let (alice, bob) = (agent(0x11), agent(0x22));
    let mut doc = ChainDocument::from_json(&format!(
        r#"{{"id":"sidestr:agentloop","name":"agentloop","parent":"tbtc4","challenge":"{}",
        "powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","addressPrefix":"al",
        "genesisTime":1790150000,"signer":"{}","minFeeRate":1,"pegoutMin":10000,"pegs":[]}}"#,
        challenge_for(&pubkey_of(&producer)).to_hex_string(),
        pubkey_of(&producer)
    ))
    .unwrap();
    doc.pegs.push(Peg {
        txid: "a".repeat(64),
        vout: 0,
        amount: 100_000,
        script: alice.script().to_hex_string(),
        extra: Default::default(),
    });
    let mut chain = State::with_key(doc.clone(), &producer).unwrap();
    let mut t = doc.genesis_time;
    let mut mine = |chain: &mut State| {
        t += 1;
        chain
            .produce(
                &producer,
                &NextBlock {
                    time: t,
                    claims: vec![],
                },
                None,
            )
            .unwrap()
            .0
    };
    for _ in 0..100 {
        mine(&mut chain);
    }

    // alice → bob, by npub
    let bob_npub = identity(&bob.pubkey(), "al").unwrap().npub;
    let coins = from_state(&chain, &alice.script());
    let p = prepare(
        &alice,
        &doc,
        &coins,
        chain.height(),
        Payment::Send,
        &destination(&bob_npub).unwrap(),
        30_000,
        None,
        1_790_150_200,
    )
    .unwrap();
    // the event is the transaction, signed by the agent that pays
    p.event.verify().unwrap();
    assert_eq!(p.event.pubkey, alice.pubkey().to_string());
    let carried = parse_transaction(&p.event, Some(&doc.id)).unwrap();
    assert_eq!(carried.tx_hex, p.spend.hex);
    assert_eq!(chain.submit(p.spend.tx.clone()).unwrap().txid, p.spend.txid);
    assert_eq!(mine(&mut chain).fees, p.spend.fee);
    let bobs = from_state(&chain, &bob.script());
    assert_eq!(bobs[0].value, 30_000);

    // bob → alice, by did:nostr
    let back = prepare(
        &bob,
        &doc,
        &bobs,
        chain.height(),
        Payment::Send,
        &destination(&format!("did:nostr:{}", alice.pubkey())).unwrap(),
        10_000,
        None,
        1_790_150_300,
    )
    .unwrap();
    assert_eq!(back.event.pubkey, bob.pubkey().to_string());
    chain.submit(back.spend.tx.clone()).unwrap();
    mine(&mut chain);

    // alice pegs out to a testnet4 address: the burn is on the chain's record
    let parent = "tb1pvts4e2zcrujj9zey3kadyfgh2xs93v8va8ae9ldhukpxy2n3848qyqurhc";
    let coins = from_state(&chain, &alice.script());
    let out = prepare(
        &alice,
        &doc,
        &coins,
        chain.height(),
        Payment::Burn,
        parent,
        20_000,
        None,
        1_790_150_400,
    )
    .unwrap();
    assert!(out.spend.note.as_deref().unwrap().starts_with("peg-out"));
    chain.submit(out.spend.tx.clone()).unwrap();
    mine(&mut chain);
    let burns = chain.pegouts();
    assert_eq!(burns.len(), 1);
    assert_eq!(burns[0].value, 20_000);
    // below pegoutMin is refused before signing
    let coins = from_state(&chain, &alice.script());
    assert!(matches!(
        prepare(
            &alice,
            &doc,
            &coins,
            chain.height(),
            Payment::Burn,
            parent,
            9_999,
            None,
            1
        ),
        Err(Error::Wallet(_))
    ));
}

fn marker_tx(plan_marker: &str, outputs_before: Vec<TxOut>, peg: TxOut) -> Transaction {
    let data = hex::decode(plan_marker).unwrap();
    let mut output = outputs_before;
    output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_op_return(PushBytesBuf::try_from(data).unwrap()),
    });
    output.push(peg);
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output,
    }
}

#[test]
fn the_pegin_plan() {
    let doc = ChainDocument::from_json(DREAMLAB).unwrap();
    let alice = parse_pubkey(ALICE).unwrap();

    // the live loop's plan, to the address the peg wallet gave: the same marker, byte for byte
    let live = pegin_plan(
        &doc,
        50_000,
        &alice,
        ALICE_DRM,
        Some(PegTarget::Address(LIVE_PEG.into())),
    )
    .unwrap();
    assert_eq!(live.marker, LIVE_MARKER);
    assert_eq!(live.peg_address, LIVE_PEG);
    assert!(live.descriptor.is_none());
    assert_eq!(live.core_send[0][LIVE_PEG], "0.00050000");

    // the default: dreamlab's signer holds the key path, alice the refund
    let signer = level1_peg_key(&doc).unwrap().unwrap();
    assert_eq!(signer.to_string(), doc.signer.clone().unwrap());
    // level 1 without a target is refused: the peg is what the producer's wallet owns
    let e = pegin_plan(&doc, 50_000, &alice, ALICE_DRM, None).unwrap_err();
    assert!(e.to_string().contains("level 1"), "{e}");
    let plan = pegin_plan(
        &doc,
        50_000,
        &alice,
        ALICE_DRM,
        Some(PegTarget::Key(signer)),
    )
    .unwrap();
    let d = plan.descriptor.clone().unwrap();
    assert!(
        d.starts_with(&format!("tr({signer},and_v(v:pk({ALICE}),older(10000)))#")),
        "{d}"
    );
    assert_eq!(
        d.rsplit('#').next().unwrap().len(),
        8,
        "a descriptor checksum"
    );
    // the address, rebuilt independently with rust-bitcoin's taproot builder:
    // leaf `<refund> OP_CHECKSIGVERIFY <10000> OP_CHECKSEQUENCEVERIFY`, internal key the signer
    let leaf = bitcoin::script::Builder::new()
        .push_x_only_key(&alice)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
        .push_int(10_000)
        .push_opcode(bitcoin::opcodes::all::OP_CSV)
        .into_script();
    let info = TaprootBuilder::new()
        .add_leaf(0, leaf)
        .unwrap()
        .finalize(sidestr_core::block::secp(), signer)
        .unwrap();
    let expect = Address::p2tr_tweaked(info.output_key(), Network::Testnet4);
    assert_eq!(plan.peg_address, expect.to_string());
    // and it is the address the live peg-in paid on testnet4: the plan is that plan
    assert_eq!(plan.peg_address, LIVE_PEG);
    assert_eq!(plan.marker, LIVE_MARKER);
    assert!(info
        .script_map()
        .keys()
        .all(|(_, v)| *v == LeafVersion::TapScript));

    // the marker names alice's script; the producer, owning the peg, finds it even behind change
    let peg_script = expect.script_pubkey();
    let tx = marker_tx(
        &plan.marker,
        vec![TxOut {
            value: Amount::from_sat(70_000),
            script_pubkey: ScriptBuf::from_hex(&format!("5120{}", "aa".repeat(32))).unwrap(),
        }],
        TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: peg_script.clone(),
        },
    );
    assert_eq!(
        parse_peg_marker(&tx.output[1].script_pubkey, &doc.id)
            .unwrap()
            .to_hex_string(),
        format!("5120{ALICE}")
    );
    let owns = |s: &Script, _: Option<&str>| s == peg_script.as_script();
    let found = find_pegin(&tx, &doc.id, 1, Some(Network::Testnet4), Some(&owns)).unwrap();
    assert_eq!((found.vout, found.amount), (2, 50_000));
    assert_eq!(found.parent_address.unwrap(), plan.peg_address);

    // an explicit key; a wrong-network address; a level-2 document pays its challenge
    let other = parse_pubkey(BOB).unwrap();
    let k = pegin_plan(&doc, 50_000, &alice, ALICE_DRM, Some(PegTarget::Key(other))).unwrap();
    assert!(k.descriptor.unwrap().starts_with(&format!("tr({BOB},")));
    assert!(pegin_plan(
        &doc,
        50_000,
        &alice,
        ALICE_DRM,
        Some(PegTarget::Address(
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0".into()
        ))
    )
    .is_err());
    let keys: Vec<XOnlyPublicKey> = (1u8..=3)
        .map(|i| pubkey_of(&SecretKey::from_slice(&[i; 32]).unwrap()))
        .collect();
    let mut fed = doc.clone();
    fed.id = "sidestr:fedplan".into();
    fed.signer = None;
    fed.challenge = String::new();
    fed.signers = Some(keys.iter().map(ToString::to_string).collect());
    fed.threshold = Some(2);
    let challenge = sidestr_core::federation::Federation::for_document(&fed)
        .unwrap()
        .unwrap()
        .challenge();
    fed.challenge = challenge.to_hex_string();
    assert!(level1_peg_key(&fed).unwrap().is_none());
    let l2 = pegin_plan(&fed, 50_000, &alice, ALICE_DRM, None).unwrap();
    assert_eq!(
        l2.peg_address,
        Address::from_script(&challenge, Network::Testnet4)
            .unwrap()
            .to_string()
    );
    assert!(l2.descriptor.is_none() && l2.note.starts_with("level 2"));
}

fn bin(args: &[&str]) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_sidestr-agent"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn the_binary_offline() {
    let dir = std::env::temp_dir().join(format!("sidestr-agent-bin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let chain = dir.join("chain.json");
    std::fs::write(&chain, DREAMLAB).unwrap();
    let key = dir.join("agent.key");
    // NIP-19's published nsec: a public test key, nothing is ever paid to it
    std::fs::write(
        &key,
        "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5\n",
    )
    .unwrap();
    let (c, k) = (chain.to_str().unwrap(), key.to_str().unwrap());

    let a = bin(&["address", "--prefix", "drm", ALICE]);
    assert_eq!(a["address"], ALICE_DRM);
    let npub = a["npub"].as_str().unwrap().to_string();
    assert_eq!(bin(&["address", "--chain", c, &npub])["address"], ALICE_DRM);
    let me = bin(&["address", "--chain", c, "--key-file", k]);
    assert_eq!(
        me["pubkey"],
        AgentKey::parse(&std::fs::read_to_string(&key).unwrap())
            .unwrap()
            .pubkey()
            .to_string()
    );

    let plan = bin(&[
        "pegin-plan",
        "--chain",
        c,
        "--amount",
        "50000",
        "--refund",
        ALICE,
        "--to",
        ALICE_DRM,
        "--peg-address",
        LIVE_PEG,
    ]);
    assert_eq!(plan["marker"], LIVE_MARKER);
    let own = bin(&[
        "pegin-plan",
        "--chain",
        c,
        "--key-file",
        k,
        "--amount",
        "50000",
        "--peg-address",
        LIVE_PEG,
    ]);
    assert_eq!(own["sideScript"], me["script"]);
    assert!(own["descriptor"].is_null());
    let desc = bin(&[
        "pegin-plan",
        "--chain",
        c,
        "--key-file",
        k,
        "--amount",
        "50000",
        "--peg-key",
        ALICE,
    ]);
    assert!(desc["descriptor"]
        .as_str()
        .unwrap()
        .starts_with(&format!("tr({ALICE},")));
    // relays at a closed local port: dreamlab's live producer announces its
    // peg script since SPEC 0.0.4, and this refusal is about the flag
    let out = Command::new(env!("CARGO_BIN_EXE_sidestr-agent"))
        .args([
            "pegin-plan",
            "--relays",
            "ws://127.0.0.1:9",
            "--chain",
            c,
            "--key-file",
            k,
            "--amount",
            "50000",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--peg-address"));

    // refusals exit non-zero with a reason
    let out = Command::new(env!("CARGO_BIN_EXE_sidestr-agent"))
        .args(["balance"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--key-file"));
    let _ = std::fs::remove_dir_all(&dir);
}
