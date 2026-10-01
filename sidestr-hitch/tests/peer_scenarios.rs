//! Hitch `test/peer-test.mjs` at 62f8e39, ported: three hosts, two channels
//! through a hub, a routed payment, a cooperative close, a punished cheat, a
//! forced close with its sweep, and lost messages recovered by resync.

mod support;

use bitcoin::TxOut;
use sidestr_hitch::protocol::ChannelStatus;
use support::{public, secret, verify_tx, Checks, HostOptions, Net};

#[test]
fn peer_test() {
    let mut net = Net::new();
    let mut c = Checks::default();
    let a = net.host("A", HostOptions::default());
    let hub = net.host(
        "hub",
        HostOptions {
            hub: true,
            ..HostOptions::default()
        },
    );
    let b = net.host("B", HostOptions::default());

    // open A→hub 100,000 and B→hub 100,000 with 50,000 pushed to the hub
    let ch_a = net.open(a, hub, 100_000, 0);
    net.pump();
    let ch_b = net.open(b, hub, 100_000, 50_000);
    net.pump();
    c.t(
        "both channels reach funding on both sides, the push credited",
        net.hosts[a].channel(ch_a).status() == ChannelStatus::Funding
            && net.hosts[b].channel(ch_b).status() == ChannelStatus::Funding
            && net.hosts[hub].machines.len() == 2
            && net.balance(hub, ch_b, 'b') == 50_000
            && net.balance(b, ch_b, 'a') == 50_000,
    );
    let all = [(a, ch_a), (hub, ch_a), (b, ch_b), (hub, ch_b)];
    c.t(
        "the first commitments verify on both sides",
        all.iter()
            .all(|(h, id)| net.commitment_verifies(*h, *id, 0)),
    );
    net.confirm(ch_a);
    net.confirm(ch_b);

    // a direct payment A → hub
    net.pay(a, ch_a, 1_000).unwrap();
    net.pump();
    let (ma, mh) = (net.hosts[a].channel(ch_a), net.hosts[hub].channel(ch_a));
    c.t(
        "a direct payment moves the balance on both sides and revokes state 0 both ways",
        ma.state_number() == 1
            && mh.state_number() == 1
            && ma.current_state().balance_a == 99_000
            && mh.current_state().balance_b == 1_000
            && ma.has_their_revocation(0)
            && mh.has_their_revocation(0),
    );

    // B issues an invoice routed via the hub; A pays it with an HTLC
    let hub_key = net.pub_key(hub);
    let (preimage, invoice) = net.hosts[b].invoice(20_000, "coffee", &[hub_key]);
    net.hosts[b].keep(preimage, &invoice);
    let expiry = net.chain.height + 60;
    net.add_htlc(
        a,
        ch_a,
        invoice.a + invoice.f,
        invoice.h,
        expiry,
        Some(invoice.p.0),
    )
    .unwrap();
    net.pump();
    net.settle();
    c.t(
        "the HTLC crossed the hub, B settled it with the preimage, the hub settled upstream: B gained 20,000, the hub kept its fee",
        net.balance(b, ch_b, 'a') == 70_000
            && net.balance(hub, ch_b, 'b') == 30_000
            && net.balance(a, ch_a, 'a') == 99_000 - 20_010
            && net.balance(hub, ch_a, 'b') == 1_000 + 20_010
            && net.htlc_count(a, ch_a) == 0
            && net.htlc_count(b, ch_b) == 0,
    );
    c.t(
        "every commitment along the way still verifies",
        all.iter().all(|(h, id)| {
            let n = net.hosts[*h].channel(*id).state_number();
            net.commitment_verifies(*h, *id, n)
        }),
    );

    // an invoice for a node the hub has no channel to fails back, and A's balance returns
    let stranger = public(&secret(b"stranger"));
    let before = net.balance(a, ch_a, 'a');
    let hash = sidestr_hitch::protocol::Bytes32(support::sha(b"no such preimage"));
    let expiry = net.chain.height + 60;
    net.add_htlc(a, ch_a, 5_000, hash, expiry, Some(stranger))
        .unwrap();
    net.pump();
    net.settle();
    c.t(
        "an HTLC with no route is failed by the hub and the amount returns to A",
        net.balance(a, ch_a, 'a') == before && net.htlc_count(a, ch_a) == 0,
    );

    // cooperative close of B's channel
    net.close(b, ch_b).unwrap();
    net.pump();
    let coop = net
        .chain
        .broadcasts
        .iter()
        .find(|p| p.label.starts_with("cooperative close"));
    c.t(
        "a cooperative close is signed by both and reaches the chain",
        net.hosts[b].channel(ch_b).status() == ChannelStatus::ClosingAsked
            && net.hosts[hub].channel(ch_b).status() == ChannelStatus::Closing
            && coop.is_some_and(|p| {
                verify_tx(
                    &p.tx,
                    &[net.hosts[b].channel(ch_b).channel().funding_prevout()],
                )
                .is_ok()
            }),
    );

    // the hub cheats on A's channel with its state-1 commitment (A has the secret); A punishes
    let aux = [9; 32];
    let old_hub = net.hosts[hub]
        .channel(ch_a)
        .signed_commitment(1, &aux)
        .unwrap();
    let old_commitment = net.hosts[hub].channel(ch_a).my_commitment(1).unwrap();
    let start = net.chain.broadcasts.len();
    let height = net.chain.height + 1;
    net.on_spend(a, ch_a, old_hub.compute_txid(), height);
    let penalties = net.broadcasts_from(start);
    let vout = old_commitment.to_local_vout.unwrap();
    let prevout = TxOut {
        value: old_hub.output[vout as usize].value,
        script_pubkey: old_commitment.to_local.script_pubkey.clone(),
    };
    c.t(
        "a revoked commitment from the hub is punished: the penalty spends its to_local to A and verifies",
        net.hosts[a].channel(ch_a).status() == ChannelStatus::Punishing
            && penalties.len() == 1
            && verify_tx(&penalties[0].tx, &[prevout]).is_ok()
            && penalties[0].tx.output[0].script_pubkey == net.hosts[a].script(),
    );

    // a force close by A at the current state, then the sweep after the delay
    let ch_a2 = net.channel(a, hub, 50_000, 0);
    net.pay(a, ch_a2, 2_000).unwrap();
    net.pump();
    net.force_close(a, ch_a2, None).unwrap();
    let fc = net.chain.last().tx.clone();
    let funding = net.hosts[a].channel(ch_a2).channel().funding_prevout();
    c.t(
        "a forced close publishes my latest commitment, valid against the funding output",
        verify_tx(&fc, &[funding]).is_ok()
            && net.hosts[a].channel(ch_a2).status() == ChannelStatus::ForceClosing,
    );
    let height = net.chain.height;
    net.on_spend(a, ch_a2, fc.compute_txid(), height);
    let n1 = net.chain.broadcasts.len();
    net.chain.height += 6;
    net.after_close(a, ch_a2);
    let m = net.hosts[a].channel(ch_a2);
    let commitment = m.my_commitment(m.state_number()).unwrap();
    let sweep_ok = verify_tx(
        &net.chain.last().tx,
        &[TxOut {
            value: commitment.local_value,
            script_pubkey: commitment.to_local.script_pubkey.clone(),
        }],
    );
    c.t(
        "after the delay the to_local is swept to my key; the channel is settling until the sweep confirms",
        net.chain.broadcasts.len() == n1 + 1 && m.status() == ChannelStatus::Settling && sweep_ok.is_ok(),
    );
    net.chain.mine();

    // ---- resync: lost messages and a collision, on a fresh channel between A and the hub
    let ch_r = net.channel(a, hub, 60_000, 20_000);
    net.pay(a, ch_r, 1_000).unwrap();
    net.pump();
    net.pay(a, ch_r, 1_000).unwrap();
    net.step();
    net.drop_first("ack");
    c.t(
        "with the acknowledgement lost, A is pending at 2 and the hub is at 2",
        net.hosts[a].channel(ch_r).state_number() == 1
            && net.hosts[a].channel(ch_r).pending().map(|p| p.n) == Some(2)
            && net.hosts[hub].channel(ch_r).state_number() == 2,
    );
    net.resync_all(a, true);
    net.pump();
    c.t(
        "a resync brings the acknowledgement again and A catches up, the revocation exchanged",
        net.hosts[a].channel(ch_r).state_number() == 2
            && net.hosts[a].channel(ch_r).pending().is_none()
            && net.hosts[hub].channel(ch_r).state_number() == 2
            && net.hosts[a].channel(ch_r).has_their_revocation(1)
            && net.hosts[hub].channel(ch_r).has_their_revocation(1),
    );

    // the update is lost: the tick sends it again
    net.pay(a, ch_r, 500).unwrap();
    net.drop_first("update");
    net.pump();
    c.t(
        "with the update lost the hub knows nothing and A is pending",
        net.hosts[hub].channel(ch_r).state_number() == 2
            && net.hosts[a].channel(ch_r).pending().map(|p| p.n) == Some(3),
    );
    net.now += 1_000;
    net.tick(a);
    net.pump();
    c.t(
        "the tick sends the update again and it completes",
        net.hosts[a].channel(ch_r).state_number() == 3
            && net.hosts[hub].channel(ch_r).state_number() == 3
            && net.hosts[a].channel(ch_r).pending().is_none(),
    );

    // the revoke is lost: the next resync carries the secret
    net.pay(a, ch_r, 500).unwrap();
    net.step();
    net.step();
    net.drop_first("revoke");
    c.t(
        "with the revoke lost the hub lacks A's secret for state 3",
        net.hosts[a].channel(ch_r).state_number() == 4
            && net.hosts[hub].channel(ch_r).state_number() == 4
            && !net.hosts[hub].channel(ch_r).has_their_revocation(3),
    );
    net.resync_all(a, true);
    net.pump();
    c.t(
        "a resync carries the secret; the hub can now punish state 3",
        net.hosts[hub].channel(ch_r).has_their_revocation(3),
    );

    // a collision: both propose state 5 at once; the lower key's stands
    let before_a = net.balance(a, ch_r, 'a');
    net.pay(a, ch_r, 100).unwrap();
    net.pay(hub, ch_r, 200).unwrap();
    net.pump();
    let a_lower = net.pub_key(a).serialize() < net.pub_key(hub).serialize();
    let (ma, mh) = (net.hosts[a].channel(ch_r), net.hosts[hub].channel(ch_r));
    c.t(
        "both proposed at once: the lower key's update stood and the other side dropped its own",
        ma.state_number() == 5
            && mh.state_number() == 5
            && ma.current_state().balance_a == mh.current_state().balance_a
            && ma.current_state().balance_a
                == if a_lower {
                    before_a - 100
                } else {
                    before_a + 200
                }
            && ma.pending().is_none()
            && mh.pending().is_none(),
    );
    let loser = if a_lower { hub } else { a };
    let loser_ch = net.hosts[loser].channel(ch_r);
    c.t(
        "the loser's signed state is remembered as an alternative the winner might publish, and the loser is told at once that its payment was not made",
        loser_ch.signed_alternatives(5).len() == 1
            && loser_ch.dropped().is_none()
            && net.hosts[loser].noted("Payment not made"),
    );
    net.tick(a);
    net.tick(hub);
    net.pump();
    c.t(
        "a tick changes nothing: the states stay at 5 with nothing pending",
        net.hosts[a].channel(ch_r).state_number() == 5
            && net.hosts[hub].channel(ch_r).state_number() == 5
            && net.hosts[a].channel(ch_r).pending().is_none()
            && net.hosts[hub].channel(ch_r).pending().is_none(),
    );
    net.after_close(a, ch_a2);
    c.t(
        "once the sweep is in a block the channel is closed",
        net.hosts[a].channel(ch_a2).status() == ChannelStatus::Closed,
    );
    let n_a = net.hosts[a].channel(ch_r).state_number();
    let n_h = net.hosts[hub].channel(ch_r).state_number();
    c.t(
        "every commitment still verifies after the resyncs",
        net.commitment_verifies(a, ch_r, n_a) && net.commitment_verifies(hub, ch_r, n_h),
    );
    c.finish();
}
