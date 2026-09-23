//! The SPEC 0.0.3 verification pass (GPT-6 Astra, 2026-09-23), its probes
//! kept: multi-input signing parity, the mempool/block differential for both
//! hash types and a corrupted second input, and complete record parity —
//! a peg-in whose change precedes the peg, its claim, spends under both
//! families' rules and a burn, with every block's claims, burns and UTXO set
//! compared between the engines. They drive the reference, so they need
//! `SIDESTR_SIDING`, `SCHEMA` and `BLAKETESTNODE`, and report themselves
//! skipped without them, as every oracle suite here does.
use std::io::Write;
use std::process::{Command, Stdio};

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{Keypair, Message, SecretKey};
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, Network, Script, ScriptBuf, Transaction,
    TxIn, TxOut, Witness,
};
use serde_json::{json, Value};
use sidestr_core::block::{
    build_block, challenge_for, pubkey_of, secp, sign_block, BlockTemplate, HeaderFamily,
    SidestrBlock,
};
use sidestr_core::document::ChainDocument;
use sidestr_core::marker::peg_marker_data;
use sidestr_core::parent::{claimable, find_pegin};
use sidestr_core::sighash::{key_path_sighash, SighashRules};
use sidestr_core::state::{NextBlock, StateOf};
use sidestr_core::Stock;
use sidestr_header::Blake2bV2;
use sidestr_wallet::burn::{build_burn, BurnRequest};
use sidestr_wallet::coins::{from_state, Coin};
use sidestr_wallet::spend::{build_spend, SpendRequest};
use sidestr_wallet::{Permissive, PlainKey, SpendSigner};

/// Whether the reference checkouts are named; says so when they are not.
fn reference() -> bool {
    let present = ["SIDESTR_SIDING", "SCHEMA", "BLAKETESTNODE"]
        .iter()
        .all(|v| std::env::var(v).is_ok());
    if !present {
        eprintln!("skipped: set SIDESTR_SIDING, SCHEMA and BLAKETESTNODE");
    }
    present
}

fn oracle(script: &str, input: &Value) -> Value {
    let mut child = Command::new("node")
        .args(["--input-type=module", "-e", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "reference: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("reference JSON")
}

fn key(n: u8) -> SecretKey {
    SecretKey::from_slice(&[n; 32]).unwrap()
}
fn doc(parent: &str) -> ChainDocument {
    ChainDocument::from_json(
        &json!({
            "id":"sidestr:verify","name":"verify","parent":parent,
            "challenge":challenge_for(&pubkey_of(&key(7))).to_hex_string(),
            "signer":pubkey_of(&key(7)).to_string(),"genesisTime":1790150000,
            "powLimit":"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "addressPrefix":"vf","minFeeRate":2,"pegoutMin":10000,"pegConfirmations":6,"pegs":[]
        })
        .to_string(),
    )
    .unwrap()
}

#[test]
fn multi_input_wallet_bytes_and_fee_match_both_families() {
    if !reference() {
        return;
    }
    let wallet = PlainKey::new(key(11));
    let coins: Vec<Coin> = [("aa", 60_000), ("bb", 50_000), ("cc", 40_000)]
        .into_iter()
        .map(|(h, value)| Coin {
            outpoint: format!("{}:2", h.repeat(32)).parse().unwrap(),
            value,
            height: 3,
            coinbase: false,
        })
        .collect();
    for parent in ["tbtc4", "txbt4"] {
        let doc = doc(parent);
        let to = challenge_for(&pubkey_of(&key(12))).to_hex_string();
        let rust = build_spend(
            &SpendRequest {
                chain: &doc,
                coins: &coins,
                tip_height: 10,
                to: &to,
                amount: 130_000,
                fee: None,
            },
            &wallet,
            &Permissive,
        )
        .unwrap();
        assert_eq!(rust.inputs, 3);
        let js = oracle(
            r#"
            import {readFileSync} from 'node:fs';
            const x = JSON.parse(readFileSync(0,'utf8')), root = process.env.SIDESTR_SIDING;
            const {loadEngine} = await import(root+'/lib/engine.mjs');
            const {makeSigner} = await import(root+'/lib/sign.mjs');
            const {buildSpend} = await import(root+'/lib/spend.mjs');
            const engine = await loadEngine(x.doc), original = makeSigner(engine);
            const signer = {...original, schnorrSign:(m,k)=>original.schnorrSign(m,k,new Uint8Array(32))};
            globalThis.fetch = async url => ({json:async()=>url.endsWith('/tip')?{height:10}:x.coins});
            const s = await buildSpend({engine,chain:x.doc,signer,key:x.key,url:'http://fixture',to:x.to,amount:130000});
            console.log(JSON.stringify({hex:s.hex,fee:s.fee,vsize:s.vsize,change:s.change}));
        "#,
            &json!({"doc":serde_json::from_str::<Value>(&doc.to_json().unwrap()).unwrap(), "key":hex::encode(key(11).secret_bytes()),"to":to,
            "coins":coins.iter().map(|c| json!({"outpoint":c.outpoint.to_string(),"value":c.value,"height":c.height,"coinbase":c.coinbase})).collect::<Vec<_>>() }),
        );
        assert_eq!(
            js,
            json!({"hex":rust.hex,"fee":rust.fee,"vsize":rust.vsize,"change":rust.change})
        );
        for i in &rust.tx.input {
            assert_eq!(i.witness.nth(0).unwrap().len(), 65);
        }
        eprintln!(
            "{parent}: 3 input witnesses byte-identical; fee={} vsize={} change={}",
            rust.fee, rust.vsize, rust.change
        );
    }
}

fn snapshot<F: HeaderFamily>(s: &StateOf<F>) -> Value {
    let mut coins: Vec<_> = s.utxo().iter().map(|(op,c)| json!({"outpoint":op.to_string(),"value":c.output.value.to_sat(),"script":c.output.script_pubkey.to_hex_string(),"height":c.height,"coinbase":c.coinbase})).collect();
    coins.sort_by_key(|c| c["outpoint"].as_str().unwrap().to_owned());
    let mut claims: Vec<_> = s
        .records()
        .claims
        .iter()
        .map(|((t, v), h)| json!([format!("{t}:{v}"), h]))
        .collect();
    claims.sort_by_key(|c| c[0].as_str().unwrap().to_owned());
    let burns: Vec<_> = s.pegouts().iter().map(|b| json!({"txid":b.txid,"vout":b.vout,"script":b.script,"value":b.value,"height":b.height})).collect();
    json!({"height":s.height(),"tip":s.tip().hash.to_string(),"claims":claims,"burns":burns,"coins":coins})
}

fn candidate<F: HeaderFamily>(s: &StateOf<F>, tx: Transaction) -> F::Block {
    let b = build_block(
        s.family(),
        &BlockTemplate {
            height: s.height() + 1,
            prev: s.tip().hash,
            time: s.tip().time + 1,
            transactions: vec![tx],
            outputs: vec![],
            bits: s.bits(),
            marker: "sidestr".into(),
        },
    );
    sign_block(s.family(), &b, s.challenge(), &key(7), &[0; 32]).unwrap()
}

fn replay<F: HeaderFamily>(doc: &ChainDocument, blocks: &[String]) -> StateOf<F> {
    let mut s = StateOf::<F>::with_key(doc.clone(), &key(7)).unwrap();
    for b in blocks {
        s.add_block_bytes(&hex::decode(b).unwrap(), None, None)
            .unwrap();
    }
    s
}

fn parity<F: HeaderFamily>(parent: &str) {
    let doc = doc(parent);
    let wallet = PlainKey::new(key(11));
    let peg = challenge_for(&pubkey_of(&key(8)));
    let marker = ScriptBuf::new_op_return(
        PushBytesBuf::try_from(peg_marker_data(&doc.id, &wallet.script())).unwrap(),
    );
    let parent_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![
            TxOut {
                value: Amount::from_sat(9_000_000),
                script_pubkey: challenge_for(&pubkey_of(&key(9))),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: marker,
            },
            TxOut {
                value: Amount::from_sat(500_000),
                script_pubkey: peg.clone(),
            },
        ],
    };
    let owns = |s: &Script, _: Option<&str>| s == peg.as_script();
    let found = find_pegin(
        &parent_tx,
        &doc.id,
        42,
        Some(Network::Testnet4),
        Some(&owns),
    )
    .unwrap();
    assert_eq!(found.vout, 2);
    let parent_json = json!({"txid":parent_tx.compute_txid().to_string(),"vout":parent_tx.output.iter().enumerate().map(|(n,o)|json!({
        "n":n,"value":o.value.to_sat() as f64/1e8,"scriptPubKey":{"hex":o.script_pubkey.to_hex_string(),"type":if o.script_pubkey.is_p2tr(){"witness_v1_taproot"}else{"nulldata"},
        "address":bitcoin::Address::from_script(&o.script_pubkey,Network::Testnet4).ok().map(|a|a.to_string())}
    })).collect::<Vec<_>>()});
    let mut s = StateOf::<F>::with_key(doc.clone(), &key(7)).unwrap();
    let genesis = hex::encode(
        StateOf::<F>::genesis_block_for(&doc, &key(7))
            .unwrap()
            .encode(),
    );
    let mut blocks = Vec::new();
    let mut snapshots = Vec::new();
    for h in 1..=100 {
        let claims = if h == 1 {
            claimable(std::slice::from_ref(&found), 47, 6, |_, _| false)
        } else {
            vec![]
        };
        let (_, b) = s
            .produce(
                &key(7),
                &NextBlock {
                    time: doc.genesis_time + h,
                    claims,
                },
                None,
            )
            .unwrap();
        blocks.push(hex::encode(b.encode()));
        snapshots.push(snapshot(&s));
    }
    // Spend the matured claim back to this wallet, creating two unequal outputs.
    let split = build_spend(
        &SpendRequest {
            chain: &doc,
            coins: &from_state(&s, &wallet.script()),
            tip_height: s.height(),
            to: &wallet.script().to_hex_string(),
            amount: 200_000,
            fee: None,
        },
        &wallet,
        &Permissive,
    )
    .unwrap();
    s.submit(split.tx).unwrap();
    let (_, b) = s
        .produce(
            &key(7),
            &NextBlock {
                time: s.tip().time + 1,
                claims: vec![],
            },
            None,
        )
        .unwrap();
    blocks.push(hex::encode(b.encode()));
    snapshots.push(snapshot(&s));
    let baseline = blocks.len();
    let coins = from_state(&s, &wallet.script());
    let spend = build_spend(
        &SpendRequest {
            chain: &doc,
            coins: &coins,
            tip_height: s.height(),
            to: &wallet.script().to_hex_string(),
            amount: 400_000,
            fee: None,
        },
        &wallet,
        &Permissive,
    )
    .unwrap();
    assert_eq!(spend.inputs, 2);
    let prevouts: Vec<_> = spend
        .tx
        .input
        .iter()
        .map(|i| s.utxo()[&i.previous_output].output.clone())
        .collect();
    let mut cases = Vec::new();
    for rules in [SighashRules::Bip341, SighashRules::KnotsUnified] {
        for corrupt in [false, true] {
            let mut tx = spend.tx.clone();
            for i in 0..tx.input.len() {
                let (digest, ht) = key_path_sighash(&tx, i, &prevouts, rules).unwrap();
                let mut sig = secp()
                    .sign_schnorr_with_aux_rand(
                        &Message::from_digest(digest),
                        &Keypair::from_secret_key(secp(), &key(11)),
                        &[0; 32],
                    )
                    .serialize()
                    .to_vec();
                sig.push(ht);
                if corrupt && i == 1 {
                    sig[10] ^= 1;
                }
                tx.input[i].witness = Witness::from_slice(&[sig]);
            }
            let block = candidate(&s, tx.clone());
            let mut fresh = replay::<F>(&doc, &blocks);
            let mempool = fresh.submit(tx.clone()).is_ok();
            let block_ok = fresh.judge(s.height() + 1, &block, None).0.ok();
            let expected = !corrupt && (parent == "txbt4" || rules == SighashRules::Bip341);
            assert_eq!((mempool, block_ok), (expected, expected));
            cases.push(json!({"name":format!("{rules:?}/corrupt-second={corrupt}"),"tx":serialize_hex(&tx),"block":hex::encode(block.encode()),"mempool":mempool,"blockOk":block_ok}));
        }
    }
    s.submit(spend.tx).unwrap();
    let (_, b) = s
        .produce(
            &key(7),
            &NextBlock {
                time: s.tip().time + 1,
                claims: vec![],
            },
            None,
        )
        .unwrap();
    blocks.push(hex::encode(b.encode()));
    snapshots.push(snapshot(&s));
    if parent == "txbt4" {
        // Also carry a BIP 341 spend in the same BLAKE2b chain: the flag
        // selects the rule, so both signature families are accepted here.
        let mut stock_doc = doc.clone();
        stock_doc.parent = "tbtc4".into();
        let plain = build_spend(
            &SpendRequest {
                chain: &stock_doc,
                coins: &from_state(&s, &wallet.script()),
                tip_height: s.height(),
                to: &wallet.script().to_hex_string(),
                amount: 50_000,
                fee: None,
            },
            &wallet,
            &Permissive,
        )
        .unwrap();
        assert_eq!(plain.tx.input[0].witness.nth(0).unwrap()[64], 1);
        s.submit(plain.tx).unwrap();
        let (_, b) = s
            .produce(
                &key(7),
                &NextBlock {
                    time: s.tip().time + 1,
                    claims: vec![],
                },
                None,
            )
            .unwrap();
        blocks.push(hex::encode(b.encode()));
        snapshots.push(snapshot(&s));
    }
    let burn = build_burn(
        &BurnRequest {
            chain: &doc,
            coins: &from_state(&s, &wallet.script()),
            tip_height: s.height(),
            to: &peg.to_hex_string(),
            amount: 30_000,
            fee: None,
        },
        &wallet,
        &Permissive,
    )
    .unwrap();
    s.submit(burn.tx).unwrap();
    let (_, b) = s
        .produce(
            &key(7),
            &NextBlock {
                time: s.tip().time + 1,
                claims: vec![],
            },
            None,
        )
        .unwrap();
    blocks.push(hex::encode(b.encode()));
    snapshots.push(snapshot(&s));
    let js = oracle(
        r#"
        import {readFileSync} from 'node:fs';
        import {mkdtemp,mkdir,rm,cp} from 'node:fs/promises';
        import {tmpdir} from 'node:os';
        const x=JSON.parse(readFileSync(0,'utf8')),root=process.env.SIDESTR_SIDING;
        const {loadEngine}=await import(root+'/lib/engine.mjs');
        const {makeSigner}=await import(root+'/lib/sign.mjs');
        const {Siding}=await import(root+'/lib/chain.mjs');
        const {scanPegins}=await import(root+'/lib/parent.mjs');
        const dir=await mkdtemp(tmpdir()+'/verify-parity-');
        const open=async d=>{await mkdir(d,{recursive:true});const engine=await loadEngine(x.doc);return new Siding({engine,chain:x.doc,dir:d,signer:makeSigner(engine)}).open(null,{seal:()=>engine.k.codec.decode('Block',x.genesis)});};
        const snap=s=>({height:s.height(),tip:s.tip().hash,claims:[...s.engine.sidestr.claims].sort((a,b)=>a[0].localeCompare(b[0])),burns:s.pegouts(),
            coins:[...s.utxo].map(([outpoint,c])=>({outpoint,value:c.output.value,script:c.output.scriptPubKey,height:c.height,coinbase:c.coinbase})).sort((a,b)=>a.outpoint.localeCompare(b.outpoint))});
        try {
            const parent={rpc:async m=>m==='getblockhash'?'00':{tx:[x.parentTx]},walletRpc:async(m,[a])=>({solvable:a===x.pegAddress})};
            const found=await scanPegins(parent,{chainId:x.doc.id,from:42,to:42});
            const s=await open(dir+'/base'), snapshots=[], verdicts=[];
            for(let i=0;i<x.blocks.length;i++) {
                if(i===x.baseline) for(const [n,c] of x.cases.entries()) {
                    const d=dir+'/case'+n;await cp(dir+'/base',d,{recursive:true});const f=await open(d);
                    let mempool=true,blockOk=true,memError=null,blockError=null;
                    try{await f.submit(c.tx);}catch(e){mempool=false;memError=e.message;}
                    try{await f.addBlock(c.block);}catch(e){blockOk=false;blockError=e.message;}
                    verdicts.push({name:c.name,mempool,blockOk,memError,blockError});
                }
                await s.addBlock(x.blocks[i]);snapshots.push(snap(s));
            }
            console.log(JSON.stringify({found,snapshots,verdicts}));
        } finally {await rm(dir,{recursive:true,force:true});}
    "#,
        &json!({"doc":serde_json::from_str::<Value>(&doc.to_json().unwrap()).unwrap(),"genesis":genesis,"blocks":blocks,"baseline":baseline,"cases":cases,"parentTx":parent_json,"pegAddress":found.parent_address}),
    );
    assert_eq!(js["found"][0]["vout"], 2);
    assert_eq!(js["found"][0]["amount"], found.amount);
    assert_eq!(js["found"][0]["script"], found.script.to_hex_string());
    for (i, expected) in snapshots.iter().enumerate() {
        assert_eq!(
            &js["snapshots"][i],
            expected,
            "{parent}: snapshot at height {}",
            i + 1
        );
    }
    for (i, c) in cases.iter().enumerate() {
        assert_eq!(
            js["verdicts"][i]["mempool"], c["mempool"],
            "{}",
            js["verdicts"][i]
        );
        assert_eq!(
            js["verdicts"][i]["blockOk"], c["blockOk"],
            "{}",
            js["verdicts"][i]
        );
    }
    assert_eq!(s.records().claims.len(), 1);
    assert_eq!(s.pegouts().len(), 1);
    eprintln!("{parent}: {} identical block snapshots (complete claims, burns, UTXOs); 4 two-input mempool/block cases agree; final UTXOs={}",snapshots.len(),s.utxo().len());
}

#[test]
fn mempool_block_and_records_match_stock() {
    if reference() {
        parity::<Stock>("tbtc4");
    }
}
#[test]
fn mempool_block_and_records_match_blake2b() {
    if reference() {
        parity::<Blake2bV2>("txbt4");
    }
}
