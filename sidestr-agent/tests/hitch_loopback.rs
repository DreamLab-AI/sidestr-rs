//! The Hitch host end to end, on a loopback sidechain at 2-second blocks:
//! two agents, two `sidestr-agent` processes, two distinct key pairs
//! (`k_id` ≠ `k_spend` each), talking over a relay.
//!
//! - open → pay → cooperative close, final at `CLOSE_DEPTH`;
//! - open → pay → force-close by A, and by B; the closer sweeps its own
//!   output only after the CSV delay, the other side is paid directly;
//! - open → pay twice → A publishes a revoked commitment; B's watch
//!   publishes the penalty inside the CSV window and takes everything;
//! - a reorganisation shallower than `CLOSE_DEPTH` during a cooperative
//!   close: the close is undone, published again, and settles;
//! - an HTLC the payee holds and never answers: the payer closes after its
//!   expiry and refunds itself on the chain.
//!
//! Each needs the reference producer; see `hitch_support`.

#![cfg(all(feature = "cli", unix))]

mod hitch_support;

use hitch_support::*;
use serde_json::Value;
use sidestr_round::relay::RelayStandIn;

const CLOSE_DEPTH: u64 = 6;
const DELAY: u64 = 3;

struct World {
    _rt: tokio::runtime::Runtime,
    _relay: RelayStandIn,
    producer: Producer,
    proxy: Option<RefusingProxy>,
    a: Agent,
    b: Agent,
    dir: std::path::PathBuf,
}

/// A chain pegging 60,000 sats to A's spend key; both agents bound and
/// watching. B accepts A by A's `did:nostr` (through A's binding).
fn world(u: &Upstream, tag: &str, b_flags: &[&str]) -> World {
    world_on(u, tag, "tbtc4", b_flags, false)
}

/// [`world`] on a chain beside `parent`; with `refusing`, the agents reach
/// the producer through a [`RefusingProxy`].
fn world_on(u: &Upstream, tag: &str, parent: &str, b_flags: &[&str], refusing: bool) -> World {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let relay = rt.block_on(RelayStandIn::start("127.0.0.1:0")).unwrap();
    let relay_url = relay.url();
    let dir = scratch(tag);
    let mut a = Agent::with_spend_key(&dir, "a");
    let mut b = Agent::minting(&dir, "b");
    let producer = Producer::seed(u, &dir, parent, &[(a.script(), 60_000)], &relay_url);
    let proxy = refusing.then(|| RefusingProxy::start(producer.port));
    let url = proxy
        .as_ref()
        .map_or_else(|| producer.url(), RefusingProxy::url);
    a.bind(&url, &relay_url);
    b.bind(&url, &relay_url);
    let accept = format!("--accept-from={}", a.did);
    let mut flags = vec![accept.as_str()];
    flags.extend_from_slice(b_flags);
    b.watch(&flags);
    a.watch(&[]);
    World {
        _rt: rt,
        _relay: relay,
        producer,
        proxy,
        a,
        b,
        dir,
    }
}

/// A opens 50,000 to B (by B's did) and the channel is open on both sides.
fn open(w: &World) -> String {
    let v =
        w.a.hitch(&[
            "open",
            "--peer",
            &w.b.did,
            "--amount",
            "50000",
            "--delay",
            &DELAY.to_string(),
            "--timeout",
            "90",
        ])
        .unwrap_or_else(|e| {
            panic!(
                "open: {e}\nA:\n{}\nB:\n{}",
                w.a.log_tail(30),
                w.b.log_tail(30)
            )
        });
    let id = v["channel"].as_str().unwrap().to_string();
    assert_eq!(v["status"]["status"], "open", "{v}");
    assert!(
        wait_until(30, || w.b.channel_status(&id) == "open"),
        "B never saw the channel open: {}",
        w.b.status()
    );
    id
}

fn pay(w: &World, id: &str, amount: u64) -> Value {
    w.a.hitch(&[
        "pay",
        "--channel",
        id,
        "--amount",
        &amount.to_string(),
        "--timeout",
        "60",
    ])
    .unwrap_or_else(|e| panic!("pay: {e}\nA:\n{}", w.a.log_tail(30)))
}

fn settled(a: &Agent, id: &str, status: &str) -> bool {
    a.channel(id)
        .is_some_and(|c| c["status"] == status && c["final"] == Value::Bool(true))
}

#[test]
fn open_pay_and_close_cooperatively() {
    let Some(u) = skip_unless_upstream() else {
        return;
    };
    coop(world(&u, "coop", &[]));
}

/// The demo chain's family: BLAKE2b v2 headers beside `txbt4`, Knots'
/// unified sighash on every channel signature.
#[test]
fn open_pay_and_close_cooperatively_beside_txbt4() {
    let Some(u) = skip_unless_upstream() else {
        return;
    };
    coop(world_on(&u, "coop-txbt4", "txbt4", &[], false));
}

fn coop(w: World) {
    let id = open(&w);
    let p = pay(&w, &id, 7_000);
    assert_eq!(p["status"]["mine"], 43_000, "{p}");
    assert!(wait_until(20, || w
        .b
        .channel(&id)
        .is_some_and(|c| c["mine"] == 7_000)));

    let c =
        w.a.hitch(&["close", "--channel", &id, "--timeout", "120"])
            .unwrap_or_else(|e| {
                panic!(
                    "close: {e}\nA:\n{}\nB:\n{}",
                    w.a.log_tail(40),
                    w.b.log_tail(40)
                )
            });
    assert_eq!(c["status"]["status"], "closed", "{c}");
    assert!(
        wait_until(60, || settled(&w.b, &id, "closed")),
        "{}",
        w.b.status()
    );

    // the close paid both spend keys directly; A paid the channel fee
    let close = w.a.channel(&id).unwrap()["spentBy"]["txid"]
        .as_str()
        .unwrap()
        .to_string();
    let b_coins = w.producer.coins(&w.b.script());
    assert!(
        b_coins
            .iter()
            .any(|c| c["value"] == 7_000 && c["outpoint"].as_str().unwrap().starts_with(&close)),
        "{b_coins:?}"
    );
    let a_coins = w.producer.coins(&w.a.script());
    assert!(
        a_coins
            .iter()
            .any(|c| c["value"] == 42_700 && c["outpoint"].as_str().unwrap().starts_with(&close)),
        "{a_coins:?}"
    );
    // both pubkeys signed 23600 events; the depth rule held
    let spent_at = w.a.channel(&id).unwrap()["spentBy"]["height"]
        .as_u64()
        .unwrap();
    assert!(w.producer.height() as u64 + 1 - spent_at >= CLOSE_DEPTH);
    assert!(!w.a.journal_of("sent").is_empty() && !w.b.journal_of("sent").is_empty());
    replays_in_rust(&w.producer);
    receipt("cooperative", &[&w.a, &w.b], &id);
}

fn force_close_by(closer_is_a: bool) {
    let Some(u) = skip_unless_upstream() else {
        return;
    };
    let w = world(&u, if closer_is_a { "force-a" } else { "force-b" }, &[]);
    let id = open(&w);
    pay(&w, &id, 7_000);
    assert!(wait_until(20, || w
        .b
        .channel(&id)
        .is_some_and(|c| c["mine"] == 7_000)));
    let (closer, other) = if closer_is_a {
        (&w.a, &w.b)
    } else {
        (&w.b, &w.a)
    };

    let fc = closer
        .hitch(&["force-close", "--channel", &id, "--timeout", "150"])
        .unwrap_or_else(|e| panic!("force-close: {e}\n{}", closer.log_tail(40)));
    assert_eq!(fc["status"]["status"], "closed", "{fc}");
    assert!(
        wait_until(60, || settled(other, &id, "closed")),
        "{}",
        other.status()
    );

    // the closer's own output waited out the CSV delay
    let ch = closer.channel(&id).unwrap();
    let commitment_at = ch["spentBy"]["height"].as_u64().unwrap();
    let sweep = ch["claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"] == "sweep of to_local")
        .unwrap_or_else(|| panic!("no sweep: {ch}"))
        .clone();
    let swept_at = sweep["confirmed"].as_u64().unwrap();
    assert!(
        swept_at - commitment_at >= DELAY,
        "swept at {swept_at}, commitment at {commitment_at}: CSV {DELAY} not respected"
    );
    // and no sweep was even published before the delay
    for b in closer.journal_of("broadcast") {
        if b["label"] == "sweep of to_local" {
            assert!(
                b["height"].as_u64().unwrap() + 1 - commitment_at >= DELAY,
                "{b}"
            );
        }
    }
    // the other side's to_remote is its at once, on its spend key
    let theirs = if closer_is_a { 7_000 } else { 42_700 };
    let coins = w.producer.coins(&other.script());
    assert!(coins.iter().any(|c| c["value"] == theirs), "{coins:?}");
    let sweep_coin = w.producer.coins(&closer.script());
    assert!(
        sweep_coin.iter().any(|c| c["outpoint"]
            .as_str()
            .unwrap()
            .starts_with(sweep["txid"].as_str().unwrap())),
        "{sweep_coin:?}"
    );
    replays_in_rust(&w.producer);
    receipt(
        if closer_is_a {
            "force-close by A"
        } else {
            "force-close by B"
        },
        &[&w.a, &w.b],
        &id,
    );
}

#[test]
fn a_force_closes_and_sweeps_after_the_delay() {
    force_close_by(true);
}

#[test]
fn b_force_closes_and_sweeps_after_the_delay() {
    force_close_by(false);
}

#[test]
fn a_revoked_commitment_is_punished_within_the_csv_window() {
    let Some(u) = skip_unless_upstream() else {
        return;
    };
    let w = world(&u, "penalty", &[]);
    let id = open(&w);
    pay(&w, &id, 7_000);
    pay(&w, &id, 3_000);
    assert!(wait_until(20, || w
        .b
        .channel(&id)
        .is_some_and(|c| c["mine"] == 10_000 && c["state"] == 2)));

    // A publishes state 0, where it held everything
    let cheat =
        w.a.hitch(&["cheat", "--channel", &id, "--revoked-state", "0"])
            .unwrap_or_else(|e| panic!("cheat: {e}"));
    let revoked = cheat["commitment"].as_str().unwrap().to_string();
    assert!(
        wait_until(120, || settled(&w.b, &id, "punished")),
        "B did not punish: {}\n{}",
        w.b.status(),
        w.b.log_tail(40)
    );
    let ch = w.b.channel(&id).unwrap();
    assert_eq!(ch["spentBy"]["txid"], revoked.as_str());
    let commitment_at = ch["spentBy"]["height"].as_u64().unwrap();
    let penalty = ch["claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"] == "penalty on to_local")
        .unwrap_or_else(|| panic!("no penalty: {ch}"))
        .clone();
    let punished_at = penalty["confirmed"].as_u64().unwrap();
    assert!(
        punished_at - commitment_at < DELAY,
        "penalty at {punished_at}, commitment at {commitment_at}: outside the CSV window {DELAY}"
    );
    // everything went to B: 50,000 less the commitment fee, less the penalty's fee
    let coins = w.producer.coins(&w.b.script());
    assert!(
        coins.iter().any(|c| c["value"] == 49_400
            && c["outpoint"]
                .as_str()
                .unwrap()
                .starts_with(penalty["txid"].as_str().unwrap())),
        "{coins:?}"
    );
    // A's own sweep, if it tried, never confirmed
    let a_ch = w.a.channel(&id).unwrap();
    assert!(
        a_ch["claims"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["confirmed"].is_null()),
        "{a_ch}"
    );
    replays_in_rust(&w.producer);
    receipt("penalty", &[&w.a, &w.b], &id);
}

#[test]
fn a_reorganisation_during_a_cooperative_close_is_survived() {
    let Some(u) = skip_unless_upstream() else {
        return;
    };
    let mut w = world(&u, "reorg", &[]);
    let id = open(&w);
    pay(&w, &id, 7_000);
    assert!(wait_until(20, || w
        .b
        .channel(&id)
        .is_some_and(|c| c["mine"] == 7_000)));

    let before = w.dir.join("before-close");
    w.producer.snapshot(&before);
    let forked_from = w.producer.height();
    w.a.hitch(&["close", "--channel", &id, "--no-wait"])
        .unwrap();
    assert!(
        wait_until(30, || w.a.channel_status(&id) == "closed-coop"
            && w.b.channel_status(&id) == "closed-coop"),
        "the close did not confirm: {} {}",
        w.a.status(),
        w.b.status()
    );
    let first_close = w.a.channel(&id).unwrap()["spentBy"].clone();
    w.producer.pause();
    let replaced = w.producer.disk_height() - forked_from;
    assert!(
        (replaced as u64) < CLOSE_DEPTH,
        "the reorg would be {replaced} deep, not below CLOSE_DEPTH; the test is too slow on this box"
    );
    w.producer.restart_from(&before);

    assert!(
        wait_until(60, || !w.a.journal_of("reorg").is_empty()
            && !w.b.journal_of("reorg").is_empty()),
        "no reorg seen"
    );
    for agent in [&w.a, &w.b] {
        let r = &agent.journal_of("reorg")[0];
        assert!(r["depth"].as_u64().unwrap() < CLOSE_DEPTH, "{r}");
        assert!(
            !agent.journal_of("spend-undone").is_empty(),
            "{} did not undo the spend",
            agent.name
        );
    }
    assert!(
        wait_until(90, || settled(&w.a, &id, "closed")
            && settled(&w.b, &id, "closed")),
        "after the reorg: {} {}\nA:\n{}\nB:\n{}",
        w.a.status(),
        w.b.status(),
        w.a.log_tail(30),
        w.b.log_tail(30)
    );
    let final_close = w.a.channel(&id).unwrap()["spentBy"].clone();
    assert_eq!(
        final_close["txid"], first_close["txid"],
        "the same close, mined again"
    );
    assert!(final_close["height"].as_u64().unwrap() > forked_from as u64);
    assert!(w
        .producer
        .coins(&w.b.script())
        .iter()
        .any(|c| c["value"] == 7_000));
    replays_in_rust(&w.producer);
    receipt("reorg during close", &[&w.a, &w.b], &id);
}

#[test]
fn an_unanswered_htlc_is_refunded_on_the_chain_after_its_expiry() {
    let Some(u) = skip_unless_upstream() else {
        return;
    };
    let mut w = world(&u, "htlc", &["--hold-htlcs"]);
    let id = open(&w);
    let inv =
        w.b.hitch(&["invoice", "--amount", "5000", "--memo", "held"])
            .unwrap();
    let inv_text = inv.to_string();
    let p =
        w.a.hitch(&[
            "pay",
            "--channel",
            &id,
            "--invoice",
            &inv_text,
            "--expiry-blocks",
            "18",
            "--no-wait",
        ])
        .unwrap_or_else(|e| panic!("pay invoice: {e}"));
    let expiry = p["expiry"].as_u64().unwrap();
    // the HTLC is locked on both sides, then the payee goes silent
    assert!(wait_until(30, || {
        w.b.channel(&id)
            .is_some_and(|c| c["htlcs"].as_array().is_some_and(|h| h.len() == 1) && c["state"] == 1)
            && w.a.channel(&id).is_some_and(|c| c["state"] == 1)
    }));
    w.b.kill();

    assert!(
        wait_until(240, || settled(&w.a, &id, "closed")),
        "A did not take the HTLC back: {}\n{}",
        w.a.status(),
        w.a.log_tail(40)
    );
    let ch = w.a.channel(&id).unwrap();
    let refund = ch["claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"].as_str().unwrap().starts_with("refund of htlc"))
        .unwrap_or_else(|| panic!("no refund: {ch}"))
        .clone();
    assert!(
        refund["confirmed"].as_u64().unwrap() >= expiry,
        "refunded before the expiry: {refund}"
    );
    let commitment_at = ch["spentBy"]["height"].as_u64().unwrap();
    assert!(commitment_at >= expiry, "closed before the expiry: {ch}");
    assert!(refund["confirmed"].as_u64().unwrap() - commitment_at >= DELAY);
    replays_in_rust(&w.producer);
    receipt("htlc expiry", &[&w.a, &w.b], &id);
}

/// The producer (siding from `c3b9e7a`) refuses for the rest of its session
/// any bytes it once refused or evicted. Behind a proxy that refuses the
/// first `POST /tx` of every transaction, the funding, the commitment of a
/// forced close and the sweep each go out again, signed afresh: the same
/// txid with a different witness, every time. And no transaction reaches
/// the producer before its locks allow: every post is checked with
/// `sidestr-core`'s `earliest_height` against the producer's tip at that
/// moment.
#[test]
fn a_refused_broadcast_is_resent_with_a_fresh_witness_and_never_early() {
    let Some(u) = skip_unless_upstream() else {
        return;
    };
    let w = world_on(&u, "refused", "tbtc4", &[], true);
    let id = open(&w);
    pay(&w, &id, 7_000);
    assert!(wait_until(30, || w
        .b
        .channel(&id)
        .is_some_and(|c| c["mine"] == 7_000)));
    let fc =
        w.a.hitch(&["force-close", "--channel", &id, "--timeout", "240"])
            .unwrap_or_else(|e| panic!("force-close: {e}\n{}", w.a.log_tail(40)));
    assert_eq!(fc["status"]["status"], "closed", "{fc}");
    replays_in_rust(&w.producer);

    let posts = w.proxy.as_ref().unwrap().posts.lock().unwrap().clone();
    let mut by_txid: std::collections::BTreeMap<bitcoin::Txid, Vec<&Posted>> = Default::default();
    for p in &posts {
        by_txid.entry(p.tx.compute_txid()).or_default().push(p);
    }
    let mut resent = 0;
    for (txid, sends) in &by_txid {
        assert!(
            sends[0].refused,
            "{txid}: the first send is the refused one"
        );
        let wtxids: std::collections::HashSet<_> =
            sends.iter().map(|p| p.tx.compute_wtxid()).collect();
        assert_eq!(
            wtxids.len(),
            sends.len(),
            "{txid}: a resend repeated a witness"
        );
        if sends.len() > 1 {
            resent += 1;
        }
    }
    // the funding, the commitment and the sweep at least
    assert!(
        resent >= 3,
        "{resent} transactions were resent: {by_txid:?}"
    );

    // nothing reached the producer early
    let heights = heights(&w.producer);
    for p in &posts {
        for (i, input) in p.tx.input.iter().enumerate() {
            let coin = heights
                .get(&input.previous_output.txid)
                .copied()
                .filter(|h| *h <= p.tip)
                .unwrap_or(p.tip + 1);
            let from =
                sidestr_core::channel::earliest_height(&p.tx, i, coin).expect("a height lock");
            assert!(
                from <= p.tip + 1,
                "{} input {i} was posted at tip {} but may be in a block only from {from}",
                p.tx.compute_txid(),
                p.tip
            );
        }
    }
    receipt("refused and resent", &[&w.a, &w.b], &id);
}
