//! `test/teller-test.mjs` (solidpayorg/teller `7c00cea`), check for check: the
//! ledger's arithmetic (8), deposit addresses (6), signed requests (4) and a
//! payout signed per input and checked under txbt4's rules (6) — 24 checks,
//! named as the teller names them. Where the teller draws random keys, these
//! derive fixed ones from a label, so a failure reproduces; the odd-y
//! operator is searched for as the teller searches for it.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, Message, PublicKey, Scalar, SecretKey, XOnlyPublicKey};
use sidestr_core::block::secp;
use sidestr_core::parents::Family;
use sidestr_core::sighash::rules_for;
use webledgers_teller::*;

/// Named checks, counted: every one must pass and the group must have the
/// number the teller has.
struct Checks {
    group: &'static str,
    ran: Vec<&'static str>,
    failed: Vec<&'static str>,
}

impl Checks {
    fn new(group: &'static str) -> Self {
        Self {
            group,
            ran: Vec::new(),
            failed: Vec::new(),
        }
    }
    fn t(&mut self, name: &'static str, ok: bool) {
        eprintln!("  {}  {name}", if ok { "PASS" } else { "FAIL" });
        self.ran.push(name);
        if !ok {
            self.failed.push(name);
        }
    }
    fn done(self, expected: usize) {
        assert!(
            self.failed.is_empty(),
            "{}: failed {:?}",
            self.group,
            self.failed
        );
        assert_eq!(
            self.ran.len(),
            expected,
            "{}: the teller has {expected} checks here",
            self.group
        );
    }
}

fn key(label: &str) -> SecretKey {
    SecretKey::from_slice(&sha256::Hash::hash(label.as_bytes()).to_byte_array()).unwrap()
}
fn point(d: &SecretKey) -> String {
    hex::encode(PublicKey::from_secret_key(secp(), d).serialize())
}
fn did_of(d: &SecretKey) -> String {
    format!("did:nostr:{}", pubkey_hex(d))
}
fn verify_sig(msg: [u8; 32], d: &SecretKey, x_only_hex: &str) -> bool {
    let kp = Keypair::from_secret_key(secp(), d);
    let sig = secp().sign_schnorr_with_aux_rand(&Message::from_digest(msg), &kp, &[9; 32]);
    let x = XOnlyPublicKey::from_slice(&hex::decode(x_only_hex).unwrap()).unwrap();
    secp()
        .verify_schnorr(&sig, &Message::from_digest(msg), &x)
        .is_ok()
}
/// `P + t·G` straight from libsecp256k1, beside the crate's own derivation.
fn add_tweak(p_hex: &str, t_hex: &str) -> String {
    let p = PublicKey::from_slice(&hex::decode(p_hex).unwrap()).unwrap();
    let t = Scalar::from_be_bytes(hex::decode(t_hex).unwrap().try_into().unwrap()).unwrap();
    hex::encode(p.add_exp_tweak(secp(), &t).unwrap().serialize())
}

struct World {
    op_key: SecretKey,
    op_point: String,
    op_did: String,
    alice: SecretKey,
    bob: SecretKey,
    a: String,
    b: String,
    l: Ledger,
    l2: Ledger,
}

fn world() -> World {
    let op_key = key("teller/operator");
    let alice = key("teller/alice");
    let bob = key("teller/bob");
    let op_did = did_of(&op_key);
    World {
        op_point: point(&op_key),
        l: new_ledger(&LedgerParams::new(&op_did, "Table 7", 1_759_300_000)).unwrap(),
        l2: new_ledger(&LedgerParams::new(&op_did, "Table 8", 1_759_300_000)).unwrap(),
        op_did,
        a: did_of(&alice),
        b: did_of(&bob),
        op_key,
        alice,
        bob,
    }
}

/// The ledger as the teller's checks leave it: 30 000 with A, a payout to B.
fn ledger_checks(w: &mut World, c: &mut Checks) {
    let (a, b) = (w.a.clone(), w.b.clone());
    let l = &mut w.l;
    c.t(
        "a new ledger is a Web Ledger with a genesis, its hash the sha256 of the genesis JCS, no balances",
        l.r#type == "WebLedger"
            && l.context == CONTEXT
            && l.hash == ledger_hash(l)
            && l.id == format!("urn:webledgers:{}", l.hash)
            && l.entries.is_empty()
            && check_ledger(l).is_ok(),
    );
    c.t(
        "the hash is of the genesis only: balances move, the hash does not; a tampered genesis is caught",
        {
            let mut t = l.clone();
            t.genesis.name = "Table 8".into();
            check_ledger(&t) == Err(Error::HashMismatch)
        },
    );
    c.t(
        "JCS: keys sorted at every level, strings and numbers as JSON",
        jcs(&serde_json::json!({ "b": 1, "a": { "d": "x", "c": [2, { "f": 0, "e": null }] } }))
            == r#"{"a":{"c":[2,{"e":null,"f":0}],"d":"x"},"b":1}"#,
    );
    c.t(
        "accounts are did:nostr identifiers, read from a did, a bare x or a Multikey",
        account_of(&a).unwrap() == a
            && account_of(&a[10..]).unwrap() == a
            && account_of(&format!("fe70102{}", &a[10..])).unwrap() == a
            && account_of("npub1x") == Err(Error::Account),
    );
    let txid = "ab".repeat(32);
    let dep = Credit {
        account: a.clone(),
        txid: txid.clone(),
        vout: 0,
        value: 50_000,
        height: Some(152_100),
    };
    c.t(
        "a deposit credits its account once: the outpoint is the receipt",
        credit(l, &dep, 1_759_300_001).unwrap().applied()
            && balance(l, &a).unwrap() == 50_000
            && credit(
                l,
                &Credit {
                    height: None,
                    ..dep.clone()
                },
                1_759_300_002,
            )
            .unwrap()
                == Outcome::Skipped("already credited")
            && balance(l, &a).unwrap() == 50_000
            && l.entries[0].amount == "50000",
    );
    let r1 = Transfer {
        id: "r1".into(),
        from: a.clone(),
        to: b.clone(),
        amount: 20_000,
    };
    c.t(
        "a transfer moves whole satoshis between accounts and is applied once by its id; it never overdraws",
        transfer(l, &r1, 1_759_300_003).unwrap().applied()
            && balance(l, &a).unwrap() == 30_000
            && balance(l, &b).unwrap() == 20_000
            && transfer(l, &r1, 1_759_300_004).unwrap() == Outcome::Skipped("already applied")
            && matches!(
                transfer(l, &Transfer { id: "r2".into(), from: b.clone(), to: a.clone(), amount: 20_001 }, 1_759_300_005),
                Err(e) if e.to_string().contains("has 20000 sat")
            )
            && total(l).unwrap() == 50_000,
    );
    let w1 = Debit {
        id: "w1".into(),
        account: b.clone(),
        amount: 20_000,
        to: "tb1p…".into(),
        txid: "cd".repeat(32),
    };
    c.t(
        "a withdrawal debits when paid out, at least 546 sat, once by its id",
        debit(l, &w1, 1_759_300_006).unwrap().applied()
            && balance(l, &b).unwrap() == 0
            && !debit(l, &w1, 1_759_300_007).unwrap().applied()
            && matches!(
                debit(l, &Debit { id: "w2".into(), account: a.clone(), amount: 100, to: "x".into(), txid: txid.clone() }, 1_759_300_008),
                Err(e) if e.to_string().contains("at least 546")
            )
            && l.payouts.len() == 1
            && total(l).unwrap() == 30_000,
    );
    c.t(
        "amounts are whole satoshis, as strings in the ledger, never floats or negatives",
        sats("123") == Ok(123)
            && sats("1.5").is_err()
            && sats("-1").is_err()
            && check_sats(MAX_SATS + 1).is_err()
            && l.entries
                .iter()
                .all(|e| !e.amount.is_empty() && e.amount.bytes().all(|c| c.is_ascii_digit())),
    );
}

#[test]
fn the_ledger() {
    let mut w = world();
    let mut c = Checks::new("the ledger");
    ledger_checks(&mut w, &mut c);
    c.done(8);
}

#[test]
fn deposit_addresses() {
    let mut w = world();
    ledger_checks(&mut w, &mut Checks::new("setup"));
    let mut c = Checks::new("deposit addresses");
    let (l, a, b) = (&w.l, &w.a, &w.b);
    let da = deposit_address(&w.op_point, &l.hash, a, 0, DEFAULT_HRP).unwrap();
    c.t(
        "a deposit address: a taproot output of the operator's point tweaked by tagged(ledgerHash || account || nonce)",
        da.script == format!("5120{}", da.x_only)
            && da.address.starts_with("tb1p")
            && da.point == add_tweak(&format!("02{}", &w.op_point[2..]), &da.tweak)
            && &da.account == a,
    );
    let normalised = if w.op_point.starts_with("03") {
        w.op_key.negate()
    } else {
        w.op_key
    };
    c.t(
        "anyone recomputes it from the operator's did alone (the 02 point): the same address",
        deposit_address(&w.op_did, &l.hash, a, 0, DEFAULT_HRP)
            .unwrap()
            .address
            == deposit_address(&point(&normalised), &l.hash, a, 0, DEFAULT_HRP)
                .unwrap()
                .address,
    );
    c.t(
        "two ledgers give two addresses for the same account from the same operator; two accounts on one ledger likewise; nonce 1 another again",
        deposit_address(&w.op_point, &w.l2.hash, a, 0, DEFAULT_HRP).unwrap().address != da.address
            && deposit_address(&w.op_point, &l.hash, b, 0, DEFAULT_HRP).unwrap().address != da.address
            && deposit_address(&w.op_point, &l.hash, a, 1, DEFAULT_HRP).unwrap().address != da.address,
    );
    c.t(
        "the operator's secret for a deposit signs for its output (normalise once, add the tweak, the sign inside the signing)",
        {
            let d = deposit_secret(&w.op_key, &da.tweak).unwrap();
            let msg = sha256::Hash::hash(&hex::decode(&da.x_only).unwrap()).to_byte_array();
            verify_sig(msg, &d, &da.x_only)
        },
    );
    {
        let mut i = 0u32;
        let odd_key = loop {
            let k = key(&format!("teller/odd/{i}"));
            if point(&k).starts_with("03") {
                break k;
            }
            i += 1;
        };
        let odd_point = point(&odd_key);
        let d_odd = deposit_address(&odd_point, &l.hash, a, 0, DEFAULT_HRP).unwrap();
        let msg = sha256::Hash::hash(&hex::decode(&d_odd.x_only).unwrap()).to_byte_array();
        let s_odd = deposit_secret(&odd_key, &d_odd.tweak).unwrap();
        c.t(
            "an odd-y operator point: the deposit address from the point, from the did and from the normalised secret all agree, and the secret signs for it",
            d_odd.address == deposit_address(&did_of(&odd_key), &l.hash, a, 0, DEFAULT_HRP).unwrap().address
                && point(&s_odd) == d_odd.point
                && verify_sig(msg, &s_odd, &d_odd.x_only),
        );
        // the bug 7c00cea fixed: the 03 point taken as given lands elsewhere
        assert_ne!(add_tweak(&odd_point, &d_odd.tweak), d_odd.point);
    }
    let extra = did_of(&key("teller/carol"));
    c.t(
        "the watch list covers every account the ledger knows and any that joined",
        watch_list(l, &w.op_point, &[&extra]).unwrap().len() == 3,
    );
    c.done(6);
}

#[test]
fn requests() {
    let mut w = world();
    ledger_checks(&mut w, &mut Checks::new("setup"));
    let mut c = Checks::new("requests");
    let (l, a, b) = (&w.l, &w.a, &w.b);
    let id = request_id(*b"sixteen bytes!!!");
    let r_join =
        request_event(&w.alice, &RequestParams::join(&l.hash, &id), 1_759_300_100).unwrap();
    let pj = parse_request(&r_join, &l.hash).unwrap();
    c.t(
        "a join request: kind 3700, for this ledger, the account its author, an id",
        r_join.kind == REQUEST_KIND
            && pj.op == Op::Join
            && &pj.account == a
            && pj.id.len() == 32
            && pj
                .id
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
    );
    let to = "tb1pfu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4quvla6g";
    let r_w = request_event(
        &w.bob,
        &RequestParams::withdraw(&l.hash, 1000, to, "deadbeef01"),
        1_759_300_101,
    )
    .unwrap();
    let pw = parse_request(&r_w, &l.hash).unwrap();
    c.t(
        "a withdrawal request carries the amount and the address, and parses back verified",
        pw.op == Op::Withdraw
            && pw.amount == Some(1000)
            && pw.to.as_deref().is_some_and(|t| t.starts_with("tb1p"))
            && &pw.account == b
            && pw.id == "deadbeef01",
    );
    let id_t = request_id([3; 16]);
    let rt = parse_request(
        &request_event(
            &w.alice,
            &RequestParams::transfer(&l.hash, 5, b, &id_t),
            1_759_300_102,
        )
        .unwrap(),
        &l.hash,
    )
    .unwrap();
    c.t(
        "a transfer request names an account",
        rt.op == Op::Transfer && rt.to.as_deref() == Some(b.as_str()) && rt.amount == Some(5),
    );
    // an amount of "1.5" cannot be built from a u64; it is refused in the
    // teller's words where it can arise: as text, and in a signed event
    let mut bad = request_template(
        &RequestParams::withdraw(&l.hash, 1, "tb1p", "deadbeef02"),
        1_759_300_103,
    )
    .unwrap();
    bad.tags[3][1] = "1.5".into();
    bad.pubkey = pubkey_hex(&w.bob);
    let kp = Keypair::from_secret_key(secp(), &w.bob);
    let sig =
        secp().sign_schnorr_with_aux_rand(&Message::from_digest(bad.id_bytes()), &kp, &[0; 32]);
    let bad = bad.with_signature(&hex::encode(sig.as_ref())).unwrap();
    c.t(
        "a tampered request, one for another ledger, a bad amount, or a withdrawal with no destination is refused in words",
        matches!(parse_request(&Event { content: "x".into(), ..r_w.clone() }, &l.hash), Err(e) if e.to_string().contains("verify"))
            && matches!(parse_request(&r_w, &w.l2.hash), Err(e) if e.to_string().contains("another ledger"))
            && matches!(sats("1.5"), Err(e) if e.to_string().contains("whole number"))
            && matches!(parse_request(&bad, &l.hash), Err(e) if e.to_string().contains("whole number"))
            && matches!(
                request_event(&w.bob, &RequestParams { to: None, ..RequestParams::withdraw(&l.hash, 10, "", "deadbeef03") }, 1_759_300_104),
                Err(e) if e.to_string().contains("names where")
            ),
    );
    c.done(4);
}

#[test]
fn a_payout() {
    let mut w = world();
    ledger_checks(&mut w, &mut Checks::new("setup"));
    let mut c = Checks::new("a payout");
    let l = &w.l;
    let da = deposit_address(&w.op_point, &l.hash, &w.a, 0, DEFAULT_HRP).unwrap();
    let db = deposit_address(&w.op_point, &l.hash, &w.b, 0, DEFAULT_HRP).unwrap();
    let coins = [
        Coin::from_deposit(&da, &"11".repeat(32), 0, 40_000),
        Coin::from_deposit(&db, &"22".repeat(32), 1, 30_000),
    ];
    let d_op = deposit_address(&w.op_point, &l.hash, &w.op_did, 0, DEFAULT_HRP).unwrap();
    let to_script = format!("5120{}", "33".repeat(32));
    let params = |amount| PayoutParams {
        coins: &coins,
        amount,
        rate: 1,
        to_script: &to_script,
        change_script: &d_op.script,
    };
    let p = plan_payout(&params(50_000)).unwrap();
    c.t(
        "planPayout picks enough deposits, pays the amount, returns change above dust, fee at the rate",
        p.picked.len() == 2
            && p.outputs[0].value == 50_000
            && p.outputs[1].script_pubkey == d_op.script
            && p.change == 70_000 - 50_000 - p.fee
            && p.fee >= 1
            && p.fee < 400,
    );
    let s = sign_payout(&p, &w.op_key, TXBT4_RULES).unwrap();
    c.t(
        "the planned fee covers the signed transaction's real size at the rate (the estimate is not short: a payout refused as \"154 < 155\" taught this)",
        p.fee >= s.vsize && s.vsize == vsize_of(&s.tx) && 11 + 58 * 2 + 43 * 2 >= s.vsize,
    );
    let w0 = s.tx.input[0].witness.to_vec();
    let w1 = s.tx.input[1].witness.to_vec();
    c.t(
        "signPayout signs input 0 with A's deposit secret and input 1 with B's (two different keys), and every input passes the chain's script check (unified sighash beside BLAKE2b)",
        s.tx.input.len() == 2
            && w0 != w1
            && [&w0, &w1].iter().all(|w| w.len() == 1 && w[0].len() == 65 && w[0][64] == 0x21)
            && s.txid.len() == 64
            && s.txid.bytes().all(|c| c.is_ascii_hexdigit())
            && s.hex.len() > 200
            && TXBT4_RULES == rules_for(Family::Blake2b),
    );
    c.t(
        "a payout signed with the wrong operator secret fails the script check and nothing is paid",
        matches!(sign_payout(&p, &key("teller/mallory"), TXBT4_RULES), Err(e) if e.to_string().contains("script check")),
    );
    c.t(
        "a payout beyond the deposits held, or below 546 sat, is refused in words",
        matches!(plan_payout(&params(70_000)), Err(e) if e.to_string().contains("do not cover"))
            && matches!(
                plan_payout(&PayoutParams { coins: &coins, amount: 100, rate: 1, to_script: "00", change_script: "00" }),
                Err(e) if e.to_string().contains("at least 546")
            ),
    );
    c.t(
        "a payout that leaves dust folds it into the fee (one output)",
        {
            let q = plan_payout(&PayoutParams {
                coins: &coins[..1],
                amount: 40_000 - 200,
                rate: 1,
                to_script: &to_script,
                change_script: &d_op.script,
            })
            .unwrap();
            q.outputs.len() == 1 && q.fee == 200
        },
    );
    c.done(6);
}

// ---- beyond the teller's checks

#[test]
fn a_two_in_two_out_payout_is_within_the_estimate_and_pays_its_rate() {
    let w = world();
    for rate in [1, 2, 7, 25] {
        let coins: Vec<Coin> = [&w.a, &w.b]
            .iter()
            .enumerate()
            .map(|(i, acct)| {
                let d = deposit_address(&w.op_did, &w.l.hash, acct, 0, DEFAULT_HRP).unwrap();
                Coin::from_deposit(&d, &format!("{:02x}", i + 1).repeat(32), i as u32, 40_000)
            })
            .collect();
        let change = deposit_address(&w.op_did, &w.l.hash, &w.op_did, 0, DEFAULT_HRP).unwrap();
        let to = format!("5120{}", "44".repeat(32));
        let p = plan_payout(&PayoutParams {
            coins: &coins,
            amount: 60_000,
            rate,
            to_script: &to,
            change_script: &change.script,
        })
        .unwrap();
        assert_eq!((p.picked.len(), p.outputs.len()), (2, 2));
        for rules in [TXBT4_RULES, SighashRules::Bip341] {
            let s = sign_payout(&p, &w.op_key, rules).unwrap();
            assert!(
                s.vsize <= vsize_estimate(2, 2),
                "{} > {}",
                s.vsize,
                vsize_estimate(2, 2)
            );
            assert!(p.fee >= rate * s.vsize);
        }
    }
    // the estimate the teller fixed: 58 vB per input, not 57
    assert_eq!(vsize_estimate(2, 2), 11 + 58 * 2 + 43 * 2);
}

#[test]
fn a_payout_signed_for_one_family_does_not_pass_the_other() {
    let w = world();
    let d = deposit_address(&w.op_did, &w.l.hash, &w.a, 0, DEFAULT_HRP).unwrap();
    let coins = [Coin::from_deposit(&d, &"11".repeat(32), 0, 10_000)];
    let to = format!("5120{}", "33".repeat(32));
    let p = plan_payout(&PayoutParams {
        coins: &coins,
        amount: 5_000,
        rate: 1,
        to_script: &to,
        change_script: &d.script,
    })
    .unwrap();
    let s = sign_payout(&p, &w.op_key, SighashRules::Bip341).unwrap();
    assert_eq!(s.tx.input[0].witness.nth(0).unwrap()[64], 0x01);
    let pv = prevouts(&p).unwrap();
    assert!(
        sidestr_core::sighash::verify_taproot_key_path(&s.tx, 0, &pv, SighashRules::Bip341).is_ok()
    );
    let s = sign_payout(&p, &w.op_key, TXBT4_RULES).unwrap();
    assert!(
        sidestr_core::sighash::verify_taproot_key_path(&s.tx, 0, &pv, SighashRules::Bip341)
            .is_err()
    );
}

#[test]
fn refusals_in_the_tellers_words() {
    let w = world();
    let insufficient = Error::Insufficient {
        account: w.a[..20].to_owned(),
        has: 3,
        wanted: 4,
    };
    assert_eq!(
        insufficient.to_string(),
        format!("{}… has 3 sat, not 4", &w.a[..20])
    );
    assert_eq!(
        Error::NotCovered {
            held: 70_000,
            amount: 70_000
        }
        .to_string(),
        "the deposits held (70000 sat) do not cover 70000 sat and the fee"
    );
    assert_eq!(
        Error::FeeBelowRate {
            vsize: 155,
            fee: 154,
            rate: 1
        }
        .to_string(),
        "the signed payout is 155 vB, so its fee of 154 sat is below 1 sat/vB; nothing was paid"
    );
    assert_eq!(
        new_ledger(&LedgerParams::new(&w.op_did, "", 1)),
        Err(Error::Name)
    );
    assert_eq!(
        new_ledger(&LedgerParams::new(&w.op_did, &"x".repeat(81), 1)),
        Err(Error::Name)
    );
    assert!(new_ledger(&LedgerParams::new(&w.op_did, &"é".repeat(80), 1)).is_ok());
    assert_eq!(
        deposit_address(&w.op_did, "AB", &w.a, 0, DEFAULT_HRP),
        Err(Error::DepositLedgerHash)
    );
    assert_eq!(
        request_tags(&RequestParams::join(&"AB".repeat(32), "deadbeef")),
        Err(Error::RequestLedgerHash)
    );
    assert_eq!("pay".parse::<Op>(), Err(Error::Op));
    let mut l = w.l.clone();
    let bad = Credit {
        account: w.a.clone(),
        txid: "AB".repeat(32),
        vout: 0,
        value: 1,
        height: None,
    };
    assert_eq!(credit(&mut l, &bad, 1), Err(Error::Outpoint));
    let zero = Transfer {
        id: "z".into(),
        from: w.a.clone(),
        to: w.b.clone(),
        amount: 0,
    };
    assert_eq!(transfer(&mut l, &zero, 1), Err(Error::ZeroTransfer));
    let to = "00";
    assert_eq!(
        plan_payout(&PayoutParams {
            coins: &[],
            amount: 1000,
            rate: 0,
            to_script: to,
            change_script: to
        }),
        Err(Error::Rate)
    );
    assert_eq!(
        plan_payout(&PayoutParams {
            coins: &[],
            amount: 1000,
            rate: 1001,
            to_script: to,
            change_script: to
        }),
        Err(Error::Rate)
    );
}

#[test]
fn a_ledger_round_trips_through_json_and_its_event() {
    let mut w = world();
    ledger_checks(&mut w, &mut Checks::new("setup"));
    let json = serde_json::to_string(&w.l).unwrap();
    // the teller's field order
    let keys: Vec<String> =
        serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&json)
            .unwrap()
            .keys()
            .cloned()
            .collect();
    assert_eq!(
        keys,
        [
            "@context",
            "type",
            "id",
            "hash",
            "name",
            "defaultCurrency",
            "genesis",
            "updated",
            "entries",
            "deposits",
            "applied",
            "payouts"
        ]
    );
    assert_eq!(parse_ledger(&json).unwrap(), w.l);
    assert_eq!(parse_ledger(r#"{"type":"Ledger"}"#), Err(Error::NotALedger));
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    v["genesis"]["confirmations"] = 6.into();
    assert_eq!(parse_ledger(&v.to_string()), Err(Error::HashMismatch));
    // a genesis field this crate does not name is kept and hashed
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    v["genesis"]["note"] = "x".into();
    let mut with_note: Ledger = serde_json::from_value(v).unwrap();
    assert_ne!(ledger_hash(&with_note), w.l.hash);
    with_note.hash = ledger_hash(&with_note);
    assert!(serde_json::to_string(&with_note)
        .unwrap()
        .contains(r#""note":"x""#));

    let ev = ledger_event(&w.op_key, &w.l, 1_759_300_500).unwrap();
    assert_eq!(ev.kind, LEDGER_KIND);
    assert_eq!(ev.tags[0], ["d", w.l.hash.as_str()]);
    assert_eq!(ev.tags[3], ["alt", "Web Ledger Table 7 (txbt4)"]);
    assert_eq!(read_ledger_event(&ev, &w.l.hash).unwrap(), w.l);
    assert_eq!(
        read_ledger_event(&ev, &w.l2.hash),
        Err(Error::NotTheOperators)
    );
    // only the operator's own copy counts
    let forged = ledger_event(&w.alice, &w.l, 1_759_300_600).unwrap();
    assert_eq!(
        read_ledger_event(&forged, &w.l.hash),
        Err(Error::NotTheOperators)
    );
    let mut newer = w.l.clone();
    newer.updated += 10;
    let ev2 = ledger_event(&w.op_key, &newer, 1_759_300_510).unwrap();
    let got = latest_ledger([&ev, &forged, &ev2], &w.l.hash).unwrap();
    assert_eq!(
        (got.0.updated, got.1.id.as_str()),
        (newer.updated, ev2.id.as_str())
    );
}
