//! Hitch `test/adversarial-test.mjs` at 62f8e39, ported: hostile and unlucky
//! inputs against the protocol, through all five rounds of the adversarial
//! review. Where Hitch's test edits a channel document by hand, the port
//! reaches the same situation through the public API, and says how.

mod support;

use bitcoin::{Amount, TxOut};
use serde_json::json;
use sidestr_hitch::protocol::{
    Bound, Bytes32, ChannelStatus, ClaimKind, PeerMessage, Update, UpdateMessage, UpdateTag,
    CLAIM_MARGIN, CLOSE_DEPTH, EXPIRY_MARGIN,
};
use sidestr_hitch::protocol::{NodeId, ProtocolState};
use sidestr_hitch::{pop_sign, sweep_to_local, SweepPath};
use support::{public, secret, verify_tx, Checks, HostOptions, Net, RULES};

fn hub() -> HostOptions {
    HostOptions {
        hub: true,
        ..HostOptions::default()
    }
}

fn is_wellformed(body: &serde_json::Value) -> bool {
    serde_json::from_value::<PeerMessage>(body.clone()).is_ok_and(|m| m.well_formed().is_ok())
}

fn pk(byte: u8) -> String {
    public(&secret(&[byte])).to_string()
}

#[test]
fn adversarial_test() {
    let mut net = Net::new();
    let mut c = Checks::default();
    let a = net.host("A", HostOptions::default());
    let hb = net.host("hub", hub());
    let b = net.host("B", HostOptions::default());
    let ch_a = net.channel(a, hb, 100_000, 0);
    let (pa, ph, pb) = (net.pub_key(a), net.pub_key(hb), net.pub_key(b));

    // ---- malformed and hostile messages leave nothing behind
    let before = net.fingerprint(hb);
    let id = ch_a.to_hex();
    let evil = [
        json!({ "t": "open", "id": "zz", "funding": {} }),
        json!(null),
        json!(1),
        json!("x"),
        json!([]),
        json!({ "t": "update", "id": id, "n": 2, "kind": "pay", "amount": 1.5, "sig": "ab", "nextRev": "x" }),
        json!({ "t": "update", "id": id, "n": 2, "kind": "add", "htlc": { "id": 1, "amount": 5000, "hash": "zz", "expiry": 1 }, "sig": "ab".repeat(65), "nextRev": "ab".repeat(32) }),
        json!({ "t": "open", "id": "0".repeat(16), "funding": { "txid": "0".repeat(64), "vout": 0, "value": 100000 }, "push": 0, "delay": 2u64.pow(31), "fee": 300, "a": pa.to_string(), "b": ph.to_string(), "rev": [pk(1), pk(2)] }),
        json!({ "t": "open", "id": "1".repeat(16), "funding": { "txid": "1".repeat(64), "vout": 0, "value": 100000 }, "push": 0, "delay": 1, "fee": 300, "a": pa.to_string(), "b": ph.to_string(), "rev": [pk(1), pk(2)] }),
        json!({ "t": "ack", "id": id, "n": 1, "sig": "ab".repeat(65), "reveal": "zz", "nextRev": "ab".repeat(32) }),
        json!({ "t": "revoke", "id": id, "n": 1, "reveal": "ab".repeat(32) }),
        json!({ "t": "sync", "id": id, "n": 999, "status": "open", "pendingN": 5 }),
        json!({ "t": "close", "id": id, "n": 7, "sig": "ab".repeat(65) }),
    ];
    for body in &evil {
        net.deliver_raw(pa, hb, &body.to_string());
    }
    c.t(
        "13 malformed or hostile messages are dropped without a panic and without touching the channel",
        net.fingerprint(hb) == before && net.hosts[hb].machines.len() == 1,
    );
    net.deliver_raw(
        pb,
        hb,
        &json!({ "t": "sync", "id": id, "n": 0, "status": "open" }).to_string(),
    );
    c.t(
        "a well-formed message from the wrong sender is ignored",
        net.fingerprint(hb) == before,
    );
    // Rust parses points at the boundary, so the "good" open names real points
    // where Hitch's test uses arbitrary hex (Hitch rejects those later, at the
    // proof-of-possession check).
    let good = json!({ "t": "open", "id": "0".repeat(16), "funding": { "txid": "0".repeat(64), "vout": 0, "value": 100000 }, "push": 0, "delay": 6, "fee": 300, "a": pa.to_string(), "b": ph.to_string(), "rev": [pk(1), pk(2)], "revBase": pk(3), "pop": { "base": "ab".repeat(64), "rev": ["ab".repeat(64), "ab".repeat(64)] } });
    let upd = json!({ "t": "update", "id": id, "n": 1, "kind": "pay", "amount": 10, "sig": "ab".repeat(65), "nextRev": pk(4), "nextRevPop": "ab".repeat(64) });
    let with = |base: &serde_json::Value, key: &str, value: serde_json::Value| {
        let mut out = base.clone();
        out[key] = value;
        out
    };
    let mut fractional = good.clone();
    fractional["funding"]["value"] = json!(100000.5);
    c.t(
        "the delay floor and the integer rule are enforced at the boundary",
        is_wellformed(&good)
            && !is_wellformed(&fractional)
            && !is_wellformed(&with(&good, "delay", json!(2)))
            && is_wellformed(&upd)
            && !is_wellformed(&with(&upd, "memo", json!("x".repeat(200)))),
    );

    // ---- a payment is final only on the payer's revoke; a withheld revoke blocks further updates both ways
    net.drop_all();
    net.pay(a, ch_a, 1_000).unwrap();
    net.step();
    net.step();
    net.drop_all();
    let blocked = net
        .pay(hb, ch_a, 10)
        .is_err_and(|e| e.contains("revocation"));
    let m = net.hosts[hb].channel(ch_a);
    c.t(
        "without the payer's revoke the receiver holds state 1 signed but not final, and refuses to move on",
        m.state_number() == 1 && m.awaiting_revoke().map(|w| w.n) == Some(1) && blocked,
    );
    net.resync_all(a, true);
    net.pump();
    let finalised = net.hosts[hb].channel(ch_a).awaiting_revoke().is_none()
        && net.hosts[hb].channel(ch_a).has_their_revocation(0);
    net.pay(hb, ch_a, 10).unwrap();
    net.pump();
    c.t(
        "the payer's resync carries the secret; the state becomes final and updates flow again",
        finalised
            && net.hosts[hb].channel(ch_a).state_number() == 2
            && net.hosts[a].channel(ch_a).state_number() == 2,
    );

    // ---- the double-signed state: a collision loser's signature is tracked and punished once that state number is revoked
    net.pay(a, ch_a, 100).unwrap();
    net.pay(hb, ch_a, 200).unwrap();
    net.pump();
    let a_lower = pa.serialize() < ph.serialize();
    let (loser, winner) = if a_lower { (hb, a) } else { (a, hb) };
    let alt = net.hosts[loser]
        .channel(ch_a)
        .signed_alternatives(3)
        .first()
        .cloned();
    c.t(
        "the loser remembers the alternative state 3 it signed for the winner",
        alt.is_some()
            && net.hosts[a].channel(ch_a).state_number() == 3
            && net.hosts[hb].channel(ch_a).state_number() == 3,
    );
    {
        let alt = alt.unwrap();
        let alt_tx = net.hosts[loser]
            .channel(ch_a)
            .their_commitment(3, &alt.state)
            .unwrap()
            .tx;
        let height = net.chain.height + 1;
        net.on_spend(loser, ch_a, alt_tx.compute_txid(), height);
        let m = net.hosts[loser].channel(ch_a);
        c.t(
            "if the winner publishes that alternative before revoking state 3, the loser accepts it as a close it had signed",
            matches!(m.status(), ChannelStatus::ClosedTheirsAlt | ChannelStatus::Closed)
                && m.close_state() == Some(3)
                && m.close_state_alternative() == Some(&alt.state),
        );
        // Hitch's test puts the document back to 'open'; a reorganisation does that here.
        net.un_spend(loser, ch_a);
        net.hosts[loser].unsent.clear();
        net.pay(winner, ch_a, 50).unwrap();
        net.pump();
        let nb = net.chain.broadcasts.len();
        net.on_spend(loser, ch_a, alt_tx.compute_txid(), height);
        let m = net.hosts[loser].channel(ch_a);
        c.t(
            "once state 3 is revoked the same alternative is punished with the penalty",
            m.status() == ChannelStatus::Punishing
                && net.chain.broadcasts.len() == nb + 1
                && m.has_their_revocation(3),
        );
        net.un_spend(loser, ch_a);
        net.hosts[loser].unsent.clear();
    }

    // ---- HTLC expiry rules: settle refused after the expiry, fail refused while the receiver holds the preimage
    let ch_b = net.channel(b, hb, 100_000, 50_000);
    let (preimage, inv) = net.hosts[b].invoice(5_000, "x", &[ph]);
    net.hosts[b].keep(preimage, &inv);
    let expiry = net.chain.height + 60;
    net.add_htlc(a, ch_a, 5_010, inv.h, expiry, Some(pb))
        .unwrap();
    net.pump();
    net.settle();
    c.t(
        "a routed payment with the new finality still settles end to end",
        net.balance(b, ch_b, 'a') == 55_000 && net.htlc_count(a, ch_a) == 0,
    );
    let (p2, i2) = net.hosts[b].invoice(5_000, "late", &[ph]);
    net.hosts[b].keep(p2, &i2);
    let expiry = net.chain.height + 60;
    net.add_htlc(a, ch_a, 5_010, i2.h, expiry, Some(pb))
        .unwrap();
    net.three_steps();
    // the hub has forwarded to B (pending in the inbox); B is offline: drain its messages
    net.drop_all();
    c.t(
        "the hub forwarded the HTLC downstream and holds it against the upstream one",
        net.hosts[hb]
            .channel(ch_b)
            .pending()
            .is_some_and(|p| matches!(p.update, Update::Add { .. }))
            && net.hosts[hb]
                .channel(ch_a)
                .htlcs()
                .iter()
                .any(|h| h.hash == i2.h),
    );
    net.chain.height += 65;
    // Hitch's test clears the hub's pending forward by hand; the hub's own
    // tick sets it aside here, the HTLC now expiring before it could be added.
    net.tick(hb);
    net.drop_all();
    let up_id = net.hosts[hb]
        .channel(ch_a)
        .htlcs()
        .iter()
        .find(|h| h.hash == i2.h)
        .unwrap()
        .id;
    let failed = net.fail_htlc(a, ch_a, up_id, "expired");
    net.pump();
    let m = net.hosts[a].channel(ch_a);
    let previous = m.state_at(m.state_number() - 1).unwrap().balance_a;
    c.t(
        "after the expiry the offerer can fail the upstream HTLC when the hub has no preimage, and the amount returns",
        failed.is_ok()
            && net.hosts[hb].channel(ch_a).htlcs().iter().all(|h| h.hash != i2.h)
            && m.current_state().balance_a == previous + 5_010,
    );
    {
        // Hitch's test plants an expired HTLC in both documents by hand; here a
        // passive payee lets a real one expire, then tries to settle it late.
        let x = net.host("late-X", HostOptions::default());
        let y = net.host("late-Y", HostOptions::default());
        net.hosts[y].passive = true;
        let ch = net.channel(x, y, 50_000, 0);
        let (pl, il) = net.hosts[y].invoice(2_000, "late", &[]);
        let expiry = net.chain.height + 40;
        net.add_htlc(x, ch, 2_000, il.h, expiry, None).unwrap();
        net.pump();
        let id = net.hosts[y].channel(ch).htlcs()[0].id;
        net.chain.height = expiry;
        let refused = net.settle_htlc(y, ch, id, pl);
        net.chain.height -= 40;
        c.t(
            "a settle after the expiry is refused on the sender side",
            refused.is_err_and(|e| e.contains("expired")),
        );
    }

    // ---- the receiver of an HTLC who knows the preimage refuses a fail from the offerer
    {
        net.chain.height += 65; // where Hitch's sequence stands at this point
        let (p3, i3) = net.hosts[hb].invoice(2_000, "direct", &[]);
        net.hosts[hb].keep(p3, &i3);
        let expiry = net.chain.height + 40;
        net.add_htlc(a, ch_a, 2_000, i3.h, expiry, None).unwrap();
        net.three_steps();
        net.drop_all();
        let hm = net.hosts[hb].channel(ch_a);
        let id = hm.htlcs().iter().find(|h| h.hash == i3.h).unwrap().id;
        let n = hm.state_number();
        net.chain.height += 65;
        let s0 = net.fingerprint(hb);
        let current = hm.current_state().clone();
        let fail_state = ProtocolState {
            balance_a: current.balance_a + 2_000,
            balance_b: current.balance_b,
            htlcs: current
                .htlcs
                .iter()
                .filter(|h| h.id != id)
                .cloned()
                .collect(),
        };
        let am = net.hosts[a].channel(ch_a);
        let theirs = am.their_commitment(n + 1, &fail_state).unwrap();
        let sig = am
            .channel()
            .sign_funding(&theirs.tx, &net.hosts[a].key, RULES, &[1; 32])
            .unwrap();
        let next = secret(&[0x71]);
        let fail_message = UpdateMessage {
            t: UpdateTag::Update,
            id: ch_a,
            n: n + 1,
            update: Update::Fail {
                htlc_id: id,
                reason: None,
            },
            sig,
            next_rev: NodeId(public(&next)),
            next_rev_pop: pop_sign(&next, &format!("{ch_a}/a/{}", n + 2), &[2; 32]),
        };
        net.deliver_raw(pa, hb, &serde_json::to_string(&fail_message).unwrap());
        c.t(
            "a well-formed, well-signed fail for an HTLC whose preimage the receiver holds is refused for that reason, even after the expiry",
            net.fingerprint(hb) == s0
                && net.hosts[hb].channel(ch_a).htlcs().iter().any(|h| h.id == id)
                && net.inbox.iter().any(|e| {
                    let m = e.message();
                    m["t"] == "reject" && m["reason"].as_str().unwrap_or("").contains("preimage")
                }),
        );
        net.drop_all();
    }

    // ---- a hub restart between the forward and the settle: the forward is kept, so the settle still comes back
    {
        let (p4, i4) = net.hosts[b].invoice(3_000, "restart", &[ph]);
        net.hosts[b].keep(p4, &i4);
        net.chain.height -= 130;
        // the hub's own settle of the direct HTLC was pending; the tick sends it again
        net.tick(hb);
        net.pump();
        let expiry = net.chain.height + 60;
        net.add_htlc(a, ch_a, 3_010, i4.h, expiry, Some(pb))
            .unwrap();
        net.three_steps();
        let forwarded = net.inbox.iter().any(|e| {
            let m = e.message();
            m["t"] == "update" && m["kind"] == "add"
        });
        c.t("the hub forwarded downstream before the restart", forwarded);
        let hub_b_before = net.balance(hb, ch_a, 'b');
        net.restart(hb);
        net.pump();
        net.settle();
        c.t(
            "after the restart the downstream settle is carried upstream: B is paid, the hub keeps its fee, A's HTLC is gone",
            net.balance(b, ch_b, 'a') == 55_000 + 3_000
                && net.htlc_count(hb, ch_a) == 0
                && net.balance(hb, ch_a, 'b') == hub_b_before + 3_010,
        );
    }

    // ---- a forced close with an HTLC in flight: the receiver claims with the preimage on the chain
    {
        let (p5, i5) = net.hosts[hb].invoice(2_500, "onchain", &[]);
        net.hosts[hb].keep(p5, &i5);
        let expiry = net.chain.height + 40;
        net.add_htlc(a, ch_a, 2_500, i5.h, expiry, None).unwrap();
        net.three_steps();
        net.drop_all();
        net.force_close(a, ch_a, None).unwrap();
        let fc = net.chain.last().tx.clone();
        let nb = net.chain.broadcasts.len();
        let height = net.chain.height;
        net.on_spend(hb, ch_a, fc.compute_txid(), height);
        let hm = net.hosts[hb].channel(ch_a);
        let theirs = hm
            .their_commitment(hm.state_number(), hm.current_state())
            .unwrap();
        let htlc = &theirs.htlcs[0];
        let claim = net
            .broadcasts_from(nb)
            .iter()
            .find(|p| p.label.contains("claim of htlc"));
        c.t(
            "the receiver claims the in-flight HTLC with the preimage from the closer's commitment, and the claim verifies",
            claim.is_some_and(|p| {
                verify_tx(
                    &p.tx,
                    &[TxOut {
                        value: htlc.htlc.amount,
                        script_pubkey: htlc.scripts.script_pubkey.clone(),
                    }],
                )
                .is_ok()
            }),
        );
        net.on_spend(a, ch_a, fc.compute_txid(), height);
        net.chain.height += 6;
        net.after_close(a, ch_a);
        let am = net.hosts[a].channel(ch_a);
        c.t(
            "the closer sweeps its to_local after the delay and, its HTLC unresolved, does not call the channel settled",
            am.claims().iter().any(|claim| claim.kind == ClaimKind::SweepToLocal)
                && am.status() == ChannelStatus::ClosedMine,
        );
    }

    // ---- a failed broadcast is kept and sent again
    {
        let ch_x = net.channel(a, hb, 20_000, 0);
        net.pay(a, ch_x, 100).unwrap();
        net.pump();
        net.chain.refuse = true;
        net.force_close(a, ch_x, None).unwrap();
        c.t(
            "a close that reached no relay is kept as unsent",
            net.hosts[a].unsent.len() == 1
                && net.hosts[a].channel(ch_x).status() == ChannelStatus::ForceClosing,
        );
        net.chain.refuse = false;
        let nb = net.chain.broadcasts.len();
        net.tick(a);
        c.t(
            "the next tick sends it",
            net.chain.broadcasts.len() == nb + 1 && net.hosts[a].unsent.is_empty(),
        );
    }

    // ---- peers with different fee settings agree, because the channel's fee is the one that counts
    {
        let z = net.host(
            "Z",
            HostOptions {
                fee: 900,
                ..HostOptions::default()
            },
        );
        let ch_z = net.channel(a, z, 20_000, 0);
        net.pay(a, ch_z, 19_000).unwrap();
        net.pump();
        c.t(
            "a state leaving the funder between the two peers' fee settings is accepted by both, since the channel's fee rules",
            net.hosts[a].channel(ch_z).state_number() == 1
                && net.hosts[z].channel(ch_z).state_number() == 1
                && net.balance(z, ch_z, 'a') == 1_000,
        );
    }

    // ---- a sync exchange terminates
    {
        net.drop_all();
        net.resync(a, ch_a, true);
        let messages = net.pump_limit(50);
        c.t("a resync is a bounded exchange, not a storm", messages < 6);
    }

    // ================= round two =================
    // ---- the two-party revocation key on a live channel: the owner's own per-state secret does not open its commitment's revocation leaf
    {
        let am = net.hosts[a].channel(ch_a);
        let n = am.state_number();
        let commitment = am.my_commitment(n).unwrap();
        let own = net.hosts[a].secret_of(am.my_revocation_point(n).unwrap());
        let prevout = [TxOut {
            value: commitment.local_value,
            script_pubkey: commitment.to_local.script_pubkey.clone(),
        }];
        let script = net.hosts[a].script();
        let spend = |key| {
            sweep_to_local(
                &commitment,
                SweepPath::Revocation,
                script.clone(),
                Amount::from_sat(300),
                key,
                RULES,
                &[0; 32],
            )
            .unwrap()
        };
        c.t(
            "the owner cannot take its own to_local at once: neither its per-state secret nor its channel key opens the revocation leaf",
            verify_tx(&spend(&own), &prevout).is_err()
                && verify_tx(&spend(&net.hosts[a].key), &prevout).is_err(),
        );
    }

    // ---- a revoked state carrying an HTLC: the penalty takes the to_local and the HTLC output, and the channel ends punished once they confirm
    {
        let p = net.host("P", HostOptions::default());
        let q = net.host("Q", HostOptions::default());
        let ch = net.channel(p, q, 100_000, 30_000);
        let (pp, ii) = net.hosts[q].invoice(4_000, "h", &[]);
        net.hosts[q].keep(pp, &ii);
        let expiry = net.chain.height + 40;
        net.add_htlc(p, ch, 4_000, ii.h, expiry, None).unwrap();
        net.settle();
        let (mp, mq) = (net.hosts[p].channel(ch), net.hosts[q].channel(ch));
        c.t(
            "the HTLC was added at state 1 and settled at state 2; state 1 is revoked both ways",
            mp.state_number() == 2
                && mq.state_number() == 2
                && mq.has_their_revocation(1)
                && mp.has_their_revocation(1)
                && mq.current_state().balance_b == 34_000,
        );
        let old = mp.signed_commitment(1, &[3; 32]).unwrap();
        let old_commitment = mp.my_commitment(1).unwrap();
        c.t(
            "the revoked commitment carries the HTLC output and would be accepted by the chain",
            !old_commitment.htlcs.is_empty()
                && verify_tx(&old, &[mp.channel().funding_prevout()]).is_ok(),
        );
        let nb = net.chain.broadcasts.len();
        let height = net.chain.height;
        net.on_spend(q, ch, old.compute_txid(), height);
        let penalties = net.broadcasts_from(nb);
        let q_script = net.hosts[q].script();
        let all_verify = penalties.iter().all(|published| {
            let vout = published.tx.input[0].previous_output.vout;
            let spk = if Some(vout) == old_commitment.to_local_vout {
                old_commitment.to_local.script_pubkey.clone()
            } else {
                old_commitment
                    .htlcs
                    .iter()
                    .find(|h| h.vout == vout)
                    .unwrap()
                    .scripts
                    .script_pubkey
                    .clone()
            };
            let prevout = TxOut {
                value: old.output[vout as usize].value,
                script_pubkey: spk,
            };
            verify_tx(&published.tx, &[prevout]).is_ok()
                && published.tx.output[0].script_pubkey == q_script
        });
        c.t(
            "two penalties go out, on the to_local and on the HTLC output, and both verify",
            net.hosts[q].channel(ch).status() == ChannelStatus::Punishing
                && penalties.len() == 2
                && all_verify,
        );
        net.after_close(q, ch);
        c.t(
            "until the penalties are in a block the channel stays punishing",
            net.hosts[q].channel(ch).status() == ChannelStatus::Punishing,
        );
        net.chain.mine();
        net.after_close(q, ch);
        c.t(
            "once both penalties are in a block the channel is punished",
            net.hosts[q].channel(ch).status() == ChannelStatus::Punished
                && net.hosts[q].noted("Penalty confirmed"),
        );
    }

    // ---- the state of my pending update, published by the other side after a lost acknowledgement, is recognised as a close I signed
    {
        let x = net.host("X", HostOptions::default());
        let y = net.host("Y", HostOptions::default());
        let ch = net.channel(x, y, 50_000, 0);
        net.pay(x, ch, 1_000).unwrap();
        net.step();
        net.drop_all();
        c.t(
            "with the acknowledgement lost X is pending at 1 and Y is at 1",
            net.hosts[x].channel(ch).pending().map(|p| p.n) == Some(1)
                && net.hosts[y].channel(ch).state_number() == 1,
        );
        net.force_close(y, ch, None).unwrap();
        let fc = net.chain.last().tx.clone();
        let height = net.chain.height;
        net.on_spend(x, ch, fc.compute_txid(), height);
        let m = net.hosts[x].channel(ch);
        c.t(
            "X recognises the close as the state it had signed for its pending update, not as an unknown spend",
            matches!(
                m.status(),
                ChannelStatus::ClosedTheirs | ChannelStatus::Settling | ChannelStatus::Closed
            ) && m.close_state() == Some(1),
        );
    }

    // ---- a state leaving the funder no fee is refused and rejected; an out-of-range secret is dropped, not thrown
    {
        let x = net.host("X2", HostOptions::default());
        let y = net.host("Y2", HostOptions::default());
        let ch = net.channel(x, y, 50_000, 0);
        let (px, py) = (net.pub_key(x), net.pub_key(y));
        let s = ProtocolState {
            balance_a: 0,
            balance_b: 50_000,
            htlcs: vec![],
        };
        let xm = net.hosts[x].channel(ch);
        let theirs = xm.their_commitment(1, &s).unwrap();
        let sig = xm
            .channel()
            .sign_funding(&theirs.tx, &net.hosts[x].key, RULES, &[1; 32])
            .unwrap();
        let s0 = net.fingerprint(y);
        let next = secret(&[0x77]);
        let update = UpdateMessage {
            t: UpdateTag::Update,
            id: ch,
            n: 1,
            update: Update::Pay {
                amount: 50_000,
                memo: None,
            },
            sig,
            next_rev: NodeId(public(&next)),
            next_rev_pop: pop_sign(&next, &format!("{ch}/a/2"), &[2; 32]),
        };
        net.deliver_raw(px, y, &serde_json::to_string(&update).unwrap());
        c.t(
            "a hand-signed state that leaves the funder no fee is refused, the channel untouched, and a reject sent back",
            net.fingerprint(y) == s0 && net.inbox.iter().any(|e| e.t() == "reject" && e.to == px),
        );
        net.drop_all();
        let id = ch.to_hex();
        for body in [
            json!({ "t": "revoke", "id": id, "n": 1, "reveal": "ff".repeat(32) }),
            json!({ "t": "sync", "id": id, "n": 1, "reveal": "ff".repeat(32), "status": "open" }),
            json!({ "t": "ack", "id": id, "n": 1, "sig": "ab".repeat(65), "reveal": "ff".repeat(32), "nextRev": pk(5), "nextRevPop": "ab".repeat(64) }),
        ] {
            net.deliver_raw(px, y, &body.to_string());
        }
        c.t(
            "an out-of-range revocation secret in a revoke, a sync or an ack is dropped without a panic",
            net.hosts[y].channel(ch).state_number() == 0,
        );
        net.drop_all();
        // a rejected update of mine: set aside, its signed state remembered, and I am told.
        // Hitch's test forges X's HTLC counter; here Y's chain view runs 30 blocks
        // ahead, so Y finds the expiry too close and refuses the add on its own.
        net.hosts[y].height_skew = 30;
        let (_, iv) = net.hosts[x].invoice(2_000, "r", &[]);
        let expiry = net.chain.height + 40;
        net.add_htlc(x, ch, 2_000, iv.h, expiry, None).unwrap();
        net.pump();
        net.hosts[y].height_skew = 0;
        let xm = net.hosts[x].channel(ch);
        c.t(
            "an update the other side refuses comes back as a reject: the sender sets it aside, remembers the state it signed, and is told the payment was not made",
            xm.pending().is_none()
                && xm.signed_alternatives(1).len() == 1
                && net.hosts[x].noted("Payment not made")
                && xm.state_number() == 0
                && net.hosts[y].channel(ch).state_number() == 0,
        );
        // a save that fails withholds the signature: nothing is sent
        net.drop_all();
        net.hosts[x].save_fails = true;
        let error = net.pay(x, ch, 100);
        net.hosts[x].save_fails = false;
        c.t(
            "when the state cannot be saved the update is not sent and the caller is told",
            error.is_err_and(|e| e.contains("saved"))
                && net.hosts[x].channel(ch).pending().is_none()
                && net.inbox.is_empty(),
        );
        let _ = py;
    }

    // ---- the protective close comes delay + 3 blocks before the expiry and is not held up by a pending settle
    {
        let x = net.host("X3", HostOptions::default());
        let y = net.host("Y3", HostOptions::default());
        let ch = net.channel(x, y, 50_000, 0);
        let (py, iy) = net.hosts[y].invoice(3_000, "p", &[]);
        net.hosts[y].keep(py, &iy);
        let expiry = net.chain.height + 40;
        net.add_htlc(x, ch, 3_000, iy.h, expiry, None).unwrap();
        net.three_steps();
        net.drop_all();
        let ym = net.hosts[y].channel(ch);
        c.t(
            "Y holds the preimage with its settle unacknowledged (X has gone quiet)",
            ym.pending()
                .is_some_and(|p| matches!(p.update, Update::Settle { .. }))
                && ym.known_preimage(&iy.h).is_some(),
        );
        net.chain.height = expiry - 6 - CLAIM_MARGIN - 1;
        net.tick(y);
        c.t(
            "one block before the deadline nothing closes",
            net.hosts[y].channel(ch).status() == ChannelStatus::Open,
        );
        net.chain.height = expiry - 6 - CLAIM_MARGIN;
        net.tick(y);
        c.t(
            "at delay + 3 blocks before the expiry Y closes to claim on the chain, despite its pending settle",
            net.hosts[y].channel(ch).status() == ChannelStatus::ForceClosing,
        );
        let fc = net.chain.last().tx.clone();
        let height = net.chain.height;
        net.on_spend(y, ch, fc.compute_txid(), height);
        let nb = net.chain.broadcasts.len();
        net.chain.height += 6;
        net.after_close(y, ch);
        let ym = net.hosts[y].channel(ch);
        let mine = ym
            .my_commitment(ym.close_state().unwrap_or(ym.state_number()))
            .unwrap();
        let htlc = &mine.htlcs[0];
        let claim = net
            .broadcasts_from(nb)
            .iter()
            .find(|p| p.label.contains("claim of htlc"));
        c.t(
            "after the delay Y claims the HTLC with the preimage from its own commitment, before the expiry",
            claim.is_some_and(|p| {
                verify_tx(
                    &p.tx,
                    &[TxOut {
                        value: htlc.htlc.amount,
                        script_pubkey: htlc.scripts.script_pubkey.clone(),
                    }],
                )
                .is_ok()
            }) && net.chain.height < expiry,
        );
        net.drop_all();
    }

    // ---- a preimage revealed on the chain reaches the hub, which settles upstream; HTLC ids never repeat; a resent update is acknowledged again
    {
        let h2 = net.host("hub2b", hub());
        let u = net.host("U", HostOptions::default());
        let v = net.host("V", HostOptions::default());
        let ch_u = net.channel(u, h2, 100_000, 0);
        let ch_v = net.channel(v, h2, 100_000, 50_000);
        let ph2 = net.pub_key(h2);
        let pv = net.pub_key(v);
        let (pre, inv) = net.hosts[v].invoice(5_000, "v", &[ph2]);
        net.hosts[v].keep(pre, &inv);
        let expiry = net.chain.height + 60;
        net.add_htlc(u, ch_u, 5_010, inv.h, expiry, Some(pv))
            .unwrap();
        net.three_steps();
        let fwd = net.shift();
        let body = fwd.message();
        c.t(
            "the hub forwards with the expiry cut by margin + both delays + 3",
            body["kind"] == "add"
                && body["htlc"]["expiry"] == json!(expiry - (EXPIRY_MARGIN + 6 + CLAIM_MARGIN + 6)),
        );
        net.deliver(fwd);
        net.step();
        net.step();
        net.drop_all();
        let hm = net.hosts[h2].channel(ch_v);
        c.t(
            "V holds the preimage and its settle to the hub is lost; the hub still has the HTLC downstream and upstream",
            net.hosts[v]
                .channel(ch_v)
                .pending()
                .is_some_and(|p| matches!(p.update, Update::Settle { .. }))
                && hm.htlcs().iter().any(|h| h.hash == inv.h)
                && net.hosts[h2].channel(ch_u).htlcs().iter().any(|h| h.hash == inv.h),
        );
        net.force_close(v, ch_v, None).unwrap();
        let fc = net.chain.last().tx.clone();
        let height = net.chain.height;
        net.on_spend(h2, ch_v, fc.compute_txid(), height);
        let hm = net.hosts[h2].channel(ch_v);
        c.t(
            "the hub sees V's close as the current state and waits: its offered HTLC is not expired and it has no preimage",
            hm.status() == ChannelStatus::ClosedTheirs && hm.known_preimage(&inv.h).is_none(),
        );
        net.on_spend(v, ch_v, fc.compute_txid(), height);
        net.chain.height += 6;
        net.after_close(v, ch_v);
        c.t(
            "V claims the HTLC on the chain with the preimage",
            net.chain.last().label.contains("claim of htlc"),
        );
        net.chain.mine();
        net.after_close(h2, ch_v);
        net.settle();
        let um = net.hosts[u].channel(ch_u);
        c.t(
            "the hub reads the preimage from V's claim and settles upstream: U's HTLC is gone, the hub is paid, U was told",
            net.hosts[h2].channel(ch_v).known_preimage(&inv.h).is_some()
                && net.htlc_count(h2, ch_u) == 0
                && net.balance(h2, ch_u, 'b') == 5_010
                && um.current_state().balance_a == 100_000 - 5_010
                && net.hosts[u].noted("Payment sent"),
        );
        // ids never repeat: the next HTLC on U's channel is 2, not 1 again
        let (pi2, i2) = net.hosts[h2].invoice(1_000, "id", &[]);
        net.hosts[h2].keep(pi2, &i2);
        let expiry = net.chain.height + 40;
        let id = net.add_htlc(u, ch_u, 1_000, i2.h, expiry, None).unwrap();
        c.t(
            "HTLC ids never repeat on a channel: the second HTLC is 2 although the first is gone",
            id == 2,
        );
        net.step();
        // the ack is lost; U's tick sends the update again; the hub acknowledges again rather than ignoring it
        net.drop_all();
        net.now += 1_000;
        net.tick(u);
        net.pump();
        net.settle();
        let (um, hm) = (net.hosts[u].channel(ch_u), net.hosts[h2].channel(ch_u));
        c.t(
            "an update sent again is acknowledged again: both sides reach the state",
            um.pending().is_none()
                && um.state_number() == hm.state_number()
                && um.state_number() >= 3
                && hm
                    .state_at(3)
                    .is_some_and(|s| s.htlcs.iter().any(|h| h.id == 2)),
        );
        net.drop_all();
    }

    // ================= round three =================
    // ---- rogue keys: a revocation point without a proof of its secret is refused, in an open and in an update
    {
        let x = net.host("X4", HostOptions::default());
        let y = net.host("Y4", HostOptions::default());
        let ch = net.channel(x, y, 50_000, 0);
        let (px, py) = (net.pub_key(x), net.pub_key(y));
        let rogue = "2".repeat(16);
        let s = |byte: u8| secret(&[byte]);
        let open = json!({
            "t": "open", "id": rogue, "funding": { "txid": "2".repeat(64), "vout": 0, "value": 50000 },
            "push": 0, "delay": 6, "fee": 300, "a": px.to_string(), "b": py.to_string(),
            "rev": [public(&s(0x51)).to_string(), public(&s(0x52)).to_string()],
            "revBase": public(&s(0x53)).to_string(),
            "pop": {
                "base": pop_sign(&s(0x54), &format!("{rogue}/a/base"), &[0; 32]).to_hex(),
                "rev": [
                    pop_sign(&s(0x51), &format!("{rogue}/a/0"), &[0; 32]).to_hex(),
                    pop_sign(&s(0x52), &format!("{rogue}/a/1"), &[0; 32]).to_hex()
                ]
            }
        });
        let n0 = net.fingerprint(y);
        net.deliver_raw(px, y, &open.to_string());
        c.t(
            "an open whose basepoint comes with a proof by another secret is refused",
            net.fingerprint(y) == n0 && net.inbox.is_empty(),
        );
        let s1 = ProtocolState {
            balance_a: 49_000,
            balance_b: 1_000,
            htlcs: vec![],
        };
        let xm = net.hosts[x].channel(ch);
        let theirs = xm.their_commitment(1, &s1).unwrap();
        let sig = xm
            .channel()
            .sign_funding(&theirs.tx, &net.hosts[x].key, RULES, &[1; 32])
            .unwrap();
        let rogue_update = UpdateMessage {
            t: UpdateTag::Update,
            id: ch,
            n: 1,
            update: Update::Pay {
                amount: 1_000,
                memo: None,
            },
            sig,
            next_rev: NodeId(public(&s(0x61))),
            next_rev_pop: pop_sign(&s(0x62), &format!("{ch}/a/2"), &[0; 32]),
        };
        net.drop_all();
        net.deliver_raw(px, y, &serde_json::to_string(&rogue_update).unwrap());
        c.t(
            "an update whose next revocation point lacks a valid proof is rejected and nothing is kept",
            net.fingerprint(y) == n0
                && net.inbox.iter().any(|e| {
                    let m = e.message();
                    m["t"] == "reject" && m["reason"].as_str().unwrap_or("").contains("proof")
                }),
        );
        let mut off_curve = serde_json::to_value(&rogue_update).unwrap();
        off_curve["nextRev"] = json!("00".repeat(32));
        net.deliver_raw(px, y, &off_curve.to_string());
        c.t(
            "a point off the curve is refused the same way (no panic)",
            net.hosts[y].channel(ch).state_number() == 0,
        );
        net.drop_all();
        // the delay floor: a host that wants 6 refuses an open at 3, and the shape check refuses below the protocol minimum
        let z = net.host(
            "Z4",
            HostOptions {
                min_delay: 6,
                ..HostOptions::default()
            },
        );
        let pz = net.pub_key(z);
        let xm = net.hosts[x].channel(ch);
        let r0 = net.hosts[x].secret_of(xm.my_revocation_point(0).unwrap());
        let r1 = net.hosts[x].secret_of(xm.my_revocation_point(1).unwrap());
        let base = net.hosts[x].secret_of(xm.my_revocation_basepoint());
        let three = "3".repeat(16);
        let open_z = json!({
            "t": "open", "id": three, "funding": { "txid": "3".repeat(64), "vout": 0, "value": 50000 },
            "push": 0, "delay": 3, "fee": 300, "a": px.to_string(), "b": pz.to_string(),
            "rev": [public(&r0).to_string(), public(&r1).to_string()],
            "revBase": public(&base).to_string(),
            "pop": {
                "base": pop_sign(&base, &format!("{three}/a/base"), &[0; 32]).to_hex(),
                "rev": [
                    pop_sign(&r0, &format!("{three}/a/0"), &[0; 32]).to_hex(),
                    pop_sign(&r1, &format!("{three}/a/1"), &[0; 32]).to_hex()
                ]
            }
        });
        net.deliver_raw(px, z, &open_z.to_string());
        c.t(
            "the delay floor is enforced: a host wanting 6 refuses an open at 3, and delay 2 is malformed",
            net.hosts[z].receivers.is_empty()
                && net.inbox.is_empty()
                && !is_wellformed(&with(&open_z, "delay", json!(2)))
                && is_wellformed(&open_z),
        );
        net.drop_all();
    }

    // ---- after a force close no acknowledgement can draw a revocation out of me; a reorganised close of mine goes back to the mempool, not to 'open'
    {
        let x = net.host("X5", HostOptions::default());
        let y = net.host("Y5", HostOptions::default());
        let ch = net.channel(x, y, 50_000, 0);
        let py = net.pub_key(y);
        net.pay(x, ch, 1_000).unwrap();
        net.pump();
        net.pay(x, ch, 500).unwrap();
        net.step(); // Y acks 2; the ack is still in flight
        net.force_close(x, ch, Some(1)).unwrap();
        let xm = net.hosts[x].channel(ch);
        c.t(
            "a force close with an update pending sets the pending aside and remembers the signed state",
            xm.pending().is_none()
                && xm.signed_alternatives(2).len() == 1
                && xm.status() == ChannelStatus::ForceClosing,
        );
        let ack = net.take("ack");
        net.drop_all();
        net.deliver(ack);
        c.t(
            "the late acknowledgement is ignored: state 1 stays, no revocation of it goes out",
            net.hosts[x].channel(ch).state_number() == 1
                && net.inbox.is_empty()
                && !net.hosts[y].channel(ch).has_their_revocation(1),
        );
        let sync = json!({ "t": "sync", "id": ch.to_hex(), "n": 2, "status": "open", "pendingN": null, "missing": [1] });
        net.deliver_raw(py, x, &sync.to_string());
        let xm = net.hosts[x].channel(ch);
        let s0 = Bytes32(
            net.hosts[x]
                .secret_of(xm.my_revocation_point(0).unwrap())
                .secret_bytes(),
        );
        let s1 = Bytes32(
            net.hosts[x]
                .secret_of(xm.my_revocation_point(1).unwrap())
                .secret_bytes(),
        );
        let carries = |text: &str, secret: &Bytes32| {
            text.contains(
                &secret
                    .0
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
            )
        };
        c.t(
            "a sync asking for the secret of the published state 1 gets state 0's (revoked, harmless) and never state 1's",
            net.inbox.iter().any(|e| e.to == py && e.t() == "synced" && carries(&e.body, &s0))
                && !net.inbox.iter().any(|e| carries(&e.body, &s1)),
        );
        net.drop_all();
        let fc = net.chain.last().tx.clone();
        let height = net.chain.height;
        net.on_spend(x, ch, fc.compute_txid(), height);
        c.t(
            "my commitment in a block: closed-mine",
            net.hosts[x].channel(ch).status() == ChannelStatus::ClosedMine,
        );
        net.un_spend(x, ch);
        let xm = net.hosts[x].channel(ch);
        c.t(
            "the block is reorganised away: back to force-closing with the commitment queued for sending again, never to open",
            xm.status() == ChannelStatus::ForceClosing
                && net.hosts[x].unsent.iter().any(|u| u.tx.compute_txid() == fc.compute_txid())
                && xm.spent_by().is_none(),
        );
        net.tick(x);
        net.on_spend(x, ch, fc.compute_txid(), height + 1);
        let xm = net.hosts[x].channel(ch);
        c.t(
            "when it is mined again the close is recognised as mine",
            xm.status() == ChannelStatus::ClosedMine
                && xm.spent_by().map(|s| s.1) == Some(height + 1),
        );
    }

    // ---- a reject answers one attempt: a stale one is ignored; an acknowledgement of a state I set aside is adopted, since my signature was binding
    {
        let x = net.host("X6", HostOptions::default());
        let y = net.host("Y6", HostOptions::default());
        let ch = net.channel(x, y, 50_000, 0);
        let py = net.pub_key(y);
        net.pay(x, ch, 100).unwrap();
        let first = net.take("update");
        let sig_a = net.hosts[x].channel(ch).pending().unwrap().message.sig;
        net.drop_all();
        let stale = json!({ "t": "reject", "id": ch.to_hex(), "n": 1, "sig": "ab".repeat(65), "reason": "stale" });
        net.deliver_raw(py, x, &stale.to_string());
        c.t(
            "a reject that does not carry my update's signature is ignored",
            net.hosts[x].channel(ch).pending().map(|p| p.message.sig) == Some(sig_a),
        );
        let honest = json!({ "t": "reject", "id": ch.to_hex(), "n": 1, "sig": sig_a.to_hex(), "reason": "test" });
        net.deliver_raw(py, x, &honest.to_string());
        let xm = net.hosts[x].channel(ch);
        c.t(
            "the reject for this attempt sets it aside",
            xm.pending().is_none() && xm.signed_alternatives(1).len() == 1,
        );
        // Y meanwhile did accept the update (the reject was a lie or a race): its ack arrives for a state X has set aside
        net.drop_all();
        net.deliver(first);
        let ack = net.take("ack");
        net.drop_all();
        net.deliver(ack);
        net.pump();
        let (xm, ym) = (net.hosts[x].channel(ch), net.hosts[y].channel(ch));
        c.t(
            "the acknowledgement of the set-aside state is adopted, the revocation sent, both sides at state 1 with the same balances",
            xm.state_number() == 1
                && ym.state_number() == 1
                && xm.current_state().balance_a == ym.current_state().balance_a
                && ym.has_their_revocation(0)
                && net.hosts[x].noted("applied after all"),
        );
    }

    // ---- a cooperative close crossing an update: the update is rejected, the close is answered on the resync; a force close after a close asked still recognises the cooperative one
    {
        let x = net.host("X7", HostOptions::default());
        let y = net.host("Y7", HostOptions::default());
        let ch = net.channel(x, y, 50_000, 5_000);
        net.close(x, ch).unwrap();
        net.pay(y, ch, 1_000).unwrap();
        net.pump();
        net.pump();
        let funding = net.hosts[x].channel(ch).channel().funding_prevout();
        let coop = net
            .chain
            .broadcasts
            .iter()
            .find(|p| {
                p.label.starts_with("cooperative close")
                    && verify_tx(&p.tx, std::slice::from_ref(&funding)).is_ok()
            })
            .map(|p| p.tx.clone());
        c.t(
            "the update is rejected because a close is signed, Y sets it aside, and the close goes through on the resync",
            matches!(net.hosts[y].channel(ch).status(), ChannelStatus::Closing | ChannelStatus::Closed)
                && matches!(
                    net.hosts[x].channel(ch).status(),
                    ChannelStatus::ClosingAsked | ChannelStatus::Closing | ChannelStatus::Closed
                )
                && net.hosts[y].channel(ch).pending().is_none()
                && coop.is_some(),
        );
        net.force_close(x, ch, None).unwrap();
        c.t(
            "a force close after the close was asked is allowed (the other side may be gone)",
            net.hosts[x].channel(ch).status() == ChannelStatus::ForceClosing,
        );
        let coop = coop.unwrap();
        let height = net.chain.height;
        net.on_spend(x, ch, coop.compute_txid(), height);
        let coop_seen = net.hosts[x].channel(ch).status() == ChannelStatus::ClosedCoop;
        net.chain.height += 6;
        net.after_close(x, ch);
        c.t(
            "when the cooperative close lands instead, it is recognised as the close, not as an unknown spend, and is final at depth",
            coop_seen && net.hosts[x].channel(ch).status() == ChannelStatus::Closed,
        );
    }

    // ---- the hub closes a downstream channel past its expiry even while its own fail is pending, so the payee cannot claim late with the preimage
    {
        let h3 = net.host("hub3c", hub());
        let u = net.host("U3", HostOptions::default());
        let v = net.host("V3", HostOptions::default());
        let ch_u = net.channel(u, h3, 100_000, 0);
        let ch_v = net.channel(v, h3, 100_000, 50_000);
        let (ph3, pv) = (net.pub_key(h3), net.pub_key(v));
        let (_, inv) = net.hosts[v].invoice(5_000, "v", &[ph3]);
        let expiry = net.chain.height + 60;
        net.add_htlc(u, ch_u, 5_010, inv.h, expiry, Some(pv))
            .unwrap();
        net.three_steps();
        net.three_steps();
        net.drop_all();
        c.t(
            "V holds the HTLC without an invoice for it and goes quiet",
            net.hosts[h3]
                .channel(ch_v)
                .htlcs()
                .iter()
                .any(|h| h.hash == inv.h)
                && !net.hosts[v].invoices.contains_key(&inv.h),
        );
        let down_expiry = net.hosts[h3]
            .channel(ch_v)
            .htlcs()
            .iter()
            .find(|h| h.hash == inv.h)
            .unwrap()
            .expiry;
        net.chain.height = down_expiry + 1;
        net.tick(h3);
        c.t(
            "past the downstream expiry the hub's fail is pending, unanswered",
            net.hosts[h3]
                .channel(ch_v)
                .pending()
                .is_some_and(|p| matches!(p.update, Update::Fail { .. })),
        );
        net.router_tick(h3);
        c.t(
            "the router still closes the downstream channel so the chain decides",
            net.hosts[h3].channel(ch_v).status() == ChannelStatus::ForceClosing,
        );
        net.drop_all();
    }

    // ================= round four =================
    // ---- a set-aside forward is not dead: the hub keeps the upstream HTLC until nothing binds the hash, and kills the alternative by closing before its deadline
    {
        let h4 = net.host("hub4", hub());
        let u = net.host("U4", HostOptions::default());
        let v = net.host("V4", HostOptions::default());
        let ch_u = net.channel(u, h4, 100_000, 0);
        let ch_v = net.channel(v, h4, 100_000, 50_000);
        let (ph4, pv) = (net.pub_key(h4), net.pub_key(v));
        let (pre, inv) = net.hosts[v].invoice(5_000, "v", &[ph4]);
        net.hosts[v].keep(pre, &inv);
        let expiry = net.chain.height + 60;
        net.add_htlc(u, ch_u, 5_010, inv.h, expiry, Some(pv))
            .unwrap();
        net.three_steps();
        let fwd = net.shift();
        c.t(
            "the hub forwarded to V (pending)",
            fwd.message()["kind"] == "add"
                && net.hosts[h4].channel(ch_v).pending().map(|p| p.n) == Some(1),
        );
        // V rejects the forward, naming its signature; the hub sets it aside
        let reject = json!({ "t": "reject", "id": ch_v.to_hex(), "n": 1, "sig": fwd.message()["sig"], "reason": "no thanks" });
        net.deliver_raw(pv, h4, &reject.to_string());
        net.settle();
        let hm = net.hosts[h4].channel(ch_v);
        let height = net.chain.height;
        c.t(
            "the hub set the forward aside but the hash is still bound by the state V holds a signature on, so the upstream HTLC stays",
            hm.pending().is_none()
                && hm.bound(&inv.h, height) == Some(Bound::Alt)
                && net.hosts[h4].channel(ch_u).htlcs().iter().any(|h| h.hash == inv.h)
                && net.hosts[h4].router.forward(ch_v, &inv.h).is_some(),
        );
        net.router_tick(h4);
        c.t(
            "a tick well before the upstream deadline changes nothing",
            net.hosts[h4].channel(ch_v).status() == ChannelStatus::Open
                && net.hosts[h4]
                    .channel(ch_u)
                    .htlcs()
                    .iter()
                    .any(|h| h.hash == inv.h),
        );
        // V acknowledges the set-aside state late after all: the hub adopts it
        net.drop_all();
        net.deliver(fwd);
        let ack = net.take("ack");
        net.drop_all();
        net.deliver(ack);
        let hm = net.hosts[h4].channel(ch_v);
        c.t(
            "V acknowledged the set-aside state late; the hub adopted it and the forward is in the agreed state",
            hm.state_number() == 1
                && hm.htlcs().iter().any(|h| h.hash == inv.h)
                && hm.bound(&inv.h, height) == Some(Bound::State),
        );
        net.settle();
        c.t(
            "V settles with the preimage and the hub carries it upstream: U paid, the hub kept its fee",
            net.htlc_count(h4, ch_u) == 0
                && net.balance(h4, ch_u, 'b') == 5_010
                && net.balance(v, ch_v, 'a') == 55_000,
        );
        // the same again, but V never acks: near the upstream deadline the hub
        // closes the downstream channel, and only once that close is final is
        // the upstream failed
        let (_, i2) = net.hosts[v].invoice(4_000, "w", &[ph4]);
        let e2 = net.chain.height + 60;
        net.add_htlc(u, ch_u, 4_010, i2.h, e2, Some(pv)).unwrap();
        net.three_steps();
        let fwd2 = net.shift();
        let n = net.hosts[h4].channel(ch_v).state_number() + 1;
        let reject = json!({ "t": "reject", "id": ch_v.to_hex(), "n": n, "sig": fwd2.message()["sig"], "reason": "no" });
        net.deliver_raw(pv, h4, &reject.to_string());
        net.drop_all();
        net.chain.height = e2 - 6 - CLAIM_MARGIN - CLOSE_DEPTH;
        net.router_tick(h4);
        c.t(
            "at the deadline the hub closes the downstream channel to kill the set-aside state",
            net.hosts[h4].channel(ch_v).status() == ChannelStatus::ForceClosing,
        );
        let fc = net.chain.last().tx.clone();
        let height = net.chain.height;
        net.on_spend(h4, ch_v, fc.compute_txid(), height);
        net.router_tick(h4);
        net.settle();
        c.t(
            "one block deep the close could still be reorganised away: the upstream HTLC is still held",
            net.htlc_count(h4, ch_u) == 1,
        );
        net.chain.height += 6;
        net.router_tick(h4);
        net.settle();
        c.t(
            "with its close six blocks deep nothing binds the hash: the upstream HTLC is failed and U refunded",
            net.htlc_count(h4, ch_u) == 0 && net.balance(u, ch_u, 'a') == 100_000 - 5_010,
        );
        net.drop_all();
    }

    // ---- a reject that names a resent update is honoured; an acknowledgement of an earlier attempt at the same state is adopted over the newer pending
    {
        let x = net.host("X8", HostOptions::default());
        let y = net.host("Y8", HostOptions::default());
        let ch = net.channel(x, y, 50_000, 0);
        let py = net.pub_key(y);
        net.pay(x, ch, 100).unwrap();
        let first = net.shift();
        net.now += 1_000;
        net.tick(x);
        let again = net.take("update");
        net.drop_all();
        c.t(
            "a resent update carries the same signature",
            again.message()["sig"] == first.message()["sig"],
        );
        let reject = json!({ "t": "reject", "id": ch.to_hex(), "n": 1, "sig": again.message()["sig"], "reason": "later" });
        net.deliver_raw(py, x, &reject.to_string());
        c.t(
            "a reject naming the resent signature clears the pending",
            net.hosts[x].channel(ch).pending().is_none(),
        );
        net.drop_all();
        net.pay(x, ch, 200).unwrap(); // a second attempt at state 1
        net.drop_all();
        net.deliver(first); // Y in fact took the first attempt
        let ack = net.take("ack");
        net.drop_all();
        net.deliver(ack);
        net.pump();
        let (xm, ym) = (net.hosts[x].channel(ch), net.hosts[y].channel(ch));
        c.t(
            "the acknowledgement of the first attempt does not fit the second pending: the second is set aside and the first adopted; both sides agree on 100 sat",
            xm.pending().is_none()
                && xm.state_number() == 1
                && ym.state_number() == 1
                && xm.current_state().balance_a == 49_900
                && ym.current_state().balance_a == 49_900
                && xm.signed_alternatives(1).len() == 1,
        );
        // a late acknowledgement cannot be adopted while a cooperative close is asked
        net.pay(x, ch, 50).unwrap();
        let upd = net.shift();
        net.drop_all();
        let sig = upd.message()["sig"].clone();
        net.deliver(upd);
        let ack2 = net.take("ack");
        net.drop_all();
        let reject = json!({ "t": "reject", "id": ch.to_hex(), "n": 2, "sig": sig, "reason": "x" });
        net.deliver_raw(py, x, &reject.to_string());
        net.close(x, ch).unwrap();
        net.drop_all();
        net.deliver(ack2);
        c.t(
            "with a close asked at state 1 an acknowledgement of a set-aside state 2 is not adopted",
            net.hosts[x].channel(ch).state_number() == 1
                && net.hosts[x].channel(ch).status() == ChannelStatus::ClosingAsked,
        );
        net.drop_all();
    }

    // ---- an open whose accept was lost is accepted again on the retry; a proposal the acceptor dropped is taken afresh
    {
        let x = net.host("X9", HostOptions::default());
        let y = net.host("Y9", HostOptions::default());
        let ch = net.open(x, y, 50_000, 0);
        let open = net.shift();
        let open_body = open.body.clone();
        let px = open.from;
        net.deliver(open);
        net.drop_all(); // the accept is lost
        net.now += 100;
        net.tick(x);
        let sent = net.inbox.iter().any(|e| e.t() == "open");
        net.pump();
        c.t(
            "the proposal is sent again, the accept comes again, and the channel reaches funding on both sides",
            sent && net.hosts[x].has(ch)
                && net.hosts[x].channel(ch).status() == ChannelStatus::Funding
                && net.hosts[y].channel(ch).status() == ChannelStatus::Funding,
        );
        net.abandon(y, ch);
        net.deliver_raw(px, y, &open_body);
        c.t(
            "after the acceptor dropped the proposal, the same open starts it afresh",
            !net.hosts[y].has(ch) && net.hosts[y].receivers.iter().any(|r| r.id() == ch),
        );
        net.drop_all();
    }
    let passed = c.finish();
    assert_eq!(passed, 77, "every check of Hitch's adversarial suite");
}

#[test]
fn the_verifier_rejects_what_the_chain_would() {
    // The scenario suites lean on support::verify_tx; prove it refuses a
    // tampered spend rather than passing everything.
    let mut net = Net::new();
    let a = net.host("va", HostOptions::default());
    let b = net.host("vb", HostOptions::default());
    let ch = net.channel(a, b, 50_000, 0);
    let tx = net.hosts[a]
        .channel(ch)
        .signed_commitment(0, &[0; 32])
        .unwrap();
    let funding = net.hosts[a].channel(ch).channel().funding_prevout();
    assert!(verify_tx(&tx, std::slice::from_ref(&funding)).is_ok());
    let mut tampered = tx.clone();
    tampered.output[0].value = Amount::from_sat(tampered.output[0].value.to_sat() - 1);
    assert!(verify_tx(&tampered, std::slice::from_ref(&funding)).is_err());
    let mut wrong_key = TxOut {
        value: funding.value,
        script_pubkey: net.hosts[a].script(),
    };
    assert!(verify_tx(&tx, &[wrong_key.clone()]).is_err());
    wrong_key.value = Amount::from_sat(1);
    assert!(verify_tx(&tx, &[wrong_key]).is_err());
}
