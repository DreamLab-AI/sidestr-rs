use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Txid};
use sidestr_core::sighash::SighashRules;

use super::*;
use crate::{pop_sign, revocation_key, revocation_pub, Side};

fn key(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).unwrap()
}

fn ctx(height: u32) -> Context {
    Context::new(height, 1_800_000_000, [7; 32])
}

const H: u32 = 152_100;

/// Open, accept, commit and ready between A (0x11) and B (0x22), then confirm.
fn open_pair(push: u64) -> (ChannelMachine, ChannelMachine, OpenMessage, AcceptMessage) {
    let channel_a = key(0x11);
    let channel_b = key(0x22);
    let params = OpenParams {
        funding: OutPoint {
            txid: Txid::from_byte_array([0xab; 32]),
            vout: 1,
        },
        funding_value: Amount::from_sat(100_000),
        push: Amount::from_sat(push),
        delay: 6,
        fee: Amount::from_sat(300),
        hub_fee: None,
    };
    let (funder, open) = FunderOpening::propose(
        params,
        OpeningKeys {
            channel: channel_a,
            revocation_base: key(0x30),
            revocation: [key(0x31), key(0x32)],
        },
        public(&channel_b),
        SighashRules::KnotsUnified,
        &[0; 32],
    )
    .unwrap();
    let (receiver, accept) = ReceiverOpening::accept(
        open.clone(),
        public(&channel_a),
        OpeningKeys {
            channel: channel_b,
            revocation_base: key(0x40),
            revocation: [key(0x41), key(0x42)],
        },
        SighashRules::KnotsUnified,
        AcceptPolicy::default(),
        &[0; 32],
    )
    .unwrap();
    let (funder, commit) = funder.accept(accept.clone(), &[0; 32]).unwrap();
    let (mut b, ready) = receiver.commit(commit).unwrap();
    let mut a = funder.ready(ready).unwrap();
    assert_eq!(a.status(), ChannelStatus::Funding);
    a.confirm_funding(H);
    b.confirm_funding(H);
    (a, b, open, accept)
}

fn acknowledge(result: ReceiveUpdate) -> AckMessage {
    match result {
        ReceiveUpdate::Acknowledge(ack) => ack,
        other => panic!("unexpected {other:?}"),
    }
}

/// Pay `amount` from `from` to `to` through all three messages.
fn pay(from: &mut ChannelMachine, to: &mut ChannelMachine, amount: u64, seed: u8) {
    let update = from.pay(amount, None, key(seed), &ctx(H)).unwrap();
    let ack = acknowledge(to.receive_update(update, key(seed + 1), &ctx(H)).unwrap());
    let outcome = from.receive_ack(ack).unwrap();
    assert!(to.receive_revoke(outcome.revoke).unwrap().is_some());
}

#[test]
fn opening_carries_basepoints_with_proofs_and_both_sides_agree() {
    let (a, b, open, accept) = open_pair(20_000);
    let wire = serde_json::to_value(&open).unwrap();
    assert_eq!(wire["t"], "open");
    assert_eq!(wire["id"], "abababababababab");
    assert_eq!(wire["revBase"], public(&key(0x30)).to_string());
    assert_eq!(wire["pop"]["base"].as_str().unwrap().len(), 128);
    assert_eq!(wire["pop"]["rev"].as_array().unwrap().len(), 2);
    assert!(wire.get("hubFee").is_none());
    assert_eq!(
        serde_json::to_value(&accept).unwrap()["revBase"],
        public(&key(0x40)).to_string()
    );
    assert_eq!(a.current_state(), b.current_state());
    assert_eq!(a.current_state().balance_a, 80_000);
    // Each side computes the same two-party key for each commitment.
    for owner in [Side::A, Side::B] {
        assert_eq!(
            a.revocation_for(owner, 0).unwrap(),
            b.revocation_for(owner, 0).unwrap()
        );
    }
    // A's commitment key is B's basepoint plus A's state-zero point.
    assert_eq!(
        a.revocation_for(Side::A, 0).unwrap(),
        revocation_pub(public(&key(0x40)), &key(0x31)).unwrap()
    );
    assert!(a.signed_commitment(0, &[0; 32]).is_ok());
    assert!(b.signed_commitment(0, &[0; 32]).is_ok());
}

#[test]
fn a_rogue_basepoint_without_its_secret_is_refused_at_the_opening() {
    let (funder, mut open) = FunderOpening::propose(
        OpenParams {
            funding: OutPoint {
                txid: Txid::from_byte_array([0xab; 32]),
                vout: 1,
            },
            funding_value: Amount::from_sat(100_000),
            push: Amount::ZERO,
            delay: 6,
            fee: Amount::from_sat(300),
            hub_fee: None,
        },
        OpeningKeys {
            channel: key(0x11),
            revocation_base: key(0x30),
            revocation: [key(0x31), key(0x32)],
        },
        public(&key(0x22)),
        SighashRules::KnotsUnified,
        &[0; 32],
    )
    .unwrap();
    // A point announced with a proof made by another secret.
    open.rev_base = NodeId(public(&key(0x53)));
    open.pop.base = pop_sign(&key(0x54), "abababababababab/a/base", &[0; 32]);
    let refused = ReceiverOpening::accept(
        open,
        public(&key(0x11)),
        OpeningKeys {
            channel: key(0x22),
            revocation_base: key(0x40),
            revocation: [key(0x41), key(0x42)],
        },
        SighashRules::KnotsUnified,
        AcceptPolicy::default(),
        &[0; 32],
    );
    assert!(matches!(refused, Err(ProtocolError::MissingProof)));
    // The proposal stands after a refused acceptance.
    assert_eq!(funder.message().t, OpenTag::Open);
}

#[test]
fn update_ack_revoke_crosses_finality_only_on_the_last_message() {
    let (mut a, mut b, _, _) = open_pair(0);
    let update = a
        .pay(40_000, Some("first".into()), key(0x33), &ctx(H))
        .unwrap();
    let ack = acknowledge(b.receive_update(update, key(0x43), &ctx(H)).unwrap());
    assert_eq!(b.state_number(), 1);
    assert!(b.awaiting_revoke().is_some());
    assert!(!b.has_their_revocation(0));
    assert!(matches!(
        b.pay(1, None, key(0x44), &ctx(H)),
        Err(ProtocolError::AwaitingRevocation)
    ));
    let outcome = a.receive_ack(ack).unwrap();
    assert_eq!(outcome.update.n, 1);
    assert!(!outcome.adopted);
    assert!(a.has_their_revocation(0));
    let next = a.pay(1, None, key(0x34), &ctx(H)).unwrap();
    assert_eq!(
        b.receive_update(next, key(0x44), &ctx(H)).unwrap(),
        ReceiveUpdate::Buffered
    );
    let finalised = b.receive_revoke(outcome.revoke).unwrap().unwrap();
    assert_eq!(finalised.n, 1);
    assert_eq!(finalised.sender, Side::A);
    assert!(b.awaiting_revoke().is_none());
    assert!(b.take_buffered_update().is_some());
    assert_eq!(a.current_state().balance_a, 60_000);
    assert_eq!(b.current_state().balance_b, 40_000);
}

#[test]
fn sync_repeats_a_lost_revoke_and_crosses_finality() {
    let (mut a, mut b, _, _) = open_pair(0);
    let update = a.pay(1_000, None, key(0x33), &ctx(H)).unwrap();
    let ack = acknowledge(b.receive_update(update, key(0x43), &ctx(H)).unwrap());
    let _lost_revoke = a.receive_ack(ack).unwrap();
    let sync = a.resync(&ctx(H), true).unwrap();
    let wire = serde_json::to_value(&sync).unwrap();
    assert_eq!(wire["t"], "sync");
    assert_eq!(wire["status"], "open");
    assert_eq!(wire["pendingN"], serde_json::Value::Null);
    assert_eq!(wire["missing"], serde_json::json!([]));
    assert!(a.resync(&ctx(H), false).is_none(), "rate-limited");
    let outcome = b.receive_sync(&sync, &ctx(H)).unwrap();
    assert!(outcome.finalised.is_some());
    assert!(b.awaiting_revoke().is_none());
    let PeerMessage::Sync(synced) = &outcome.replies[0] else {
        panic!("a synced answer first")
    };
    assert_eq!(synced.t, SyncTag::Synced);
    assert_eq!(synced.reveals, Some(BTreeMap::new()));
}

use std::collections::BTreeMap;

#[test]
fn no_secret_of_a_published_commitment_leaves_by_sync_or_acknowledgement() {
    let (mut a, mut b, _, _) = open_pair(0);
    pay(&mut a, &mut b, 1_000, 0x50);
    pay(&mut a, &mut b, 1_000, 0x52);
    pay(&mut a, &mut b, 1_000, 0x54);
    assert_eq!(a.state_number(), 3);
    // A publishes its old state-1 commitment (from a stale backup, say).
    a.force_close(Some(1), "forced", &ctx(H)).unwrap();
    let request = SyncMessage {
        t: SyncTag::Sync,
        id: a.id(),
        n: 3,
        status: Some("open".into()),
        pending_n: None,
        reveal: None,
        missing: vec![0, 1, 2],
        reveals: None,
    };
    let outcome = a.receive_sync(&request, &ctx(H)).unwrap();
    let PeerMessage::Sync(synced) = &outcome.replies[0] else {
        panic!("a synced answer")
    };
    let reveals = synced.reveals.clone().unwrap();
    assert!(reveals.contains_key(&0));
    assert!(!reveals.contains_key(&1), "the published state's secret");
    assert!(!reveals.contains_key(&2));
    assert_eq!(synced.reveal, None, "state 2 is above the published one");
    assert!(a.acknowledgement(&ctx(H)).unwrap().is_none());
}

#[test]
fn snapshot_round_trip_preserves_everything_and_rejects_damage_and_version_one() {
    let (mut a, _, _, _) = open_pair(20_000);
    a.remember_preimage([0x77; 32]);
    a.pay(1_000, Some("persist me".into()), key(0x33), &ctx(H))
        .unwrap();
    let snapshot = a.snapshot();
    let json = serde_json::to_vec(&snapshot).unwrap();
    let decoded: ChannelSnapshot = serde_json::from_slice(&json).unwrap();
    let restored = ChannelMachine::restore(decoded).unwrap();
    assert_eq!(restored.snapshot(), snapshot);
    assert_eq!(restored.pending().unwrap().n, 1);
    assert_eq!(restored.status(), ChannelStatus::Open);

    let mut value = serde_json::to_value(&snapshot).unwrap();
    value["signatures"].as_object_mut().unwrap().remove("0");
    let damaged: ChannelSnapshot = serde_json::from_value(value).unwrap();
    assert!(matches!(
        ChannelMachine::restore(damaged),
        Err(ProtocolError::MissingSignature(0))
    ));

    let mut value = serde_json::to_value(&snapshot).unwrap();
    value["version"] = 1.into();
    let old: ChannelSnapshot = serde_json::from_value(value).unwrap();
    assert!(matches!(
        ChannelMachine::restore(old),
        Err(ProtocolError::SnapshotVersion(1))
    ));

    let mut value = serde_json::to_value(&snapshot).unwrap();
    value["their_revocation_base"] = serde_json::Value::String(public(&key(0x99)).to_string());
    let swapped: ChannelSnapshot = serde_json::from_value(value).unwrap();
    assert!(
        ChannelMachine::restore(swapped).is_err(),
        "signatures no longer verify"
    );
}

#[test]
fn a_revoked_commitment_is_punished_with_the_two_party_key() {
    let (mut a, mut b, _, _) = open_pair(20_000);
    let old = b.signed_commitment(0, &[0; 32]).unwrap();
    pay(&mut a, &mut b, 1_000, 0x60);
    let destination = crate::to_remote_script(public(&key(0x11)));
    let outcome = a
        .on_spend(
            ChainSpend {
                txid: old.compute_txid(),
                height: H + 1,
            },
            &destination,
            &ctx(H + 1),
            |_, _| OutputLookup::Unspent,
        )
        .unwrap();
    assert_eq!(
        outcome.kind,
        FundingSpend::RemoteCommitment {
            state: 0,
            alternative: false,
            revoked: true,
        }
    );
    assert_eq!(a.status(), ChannelStatus::Punishing);
    assert_eq!(outcome.broadcasts.len(), 1);
    let penalty = &outcome.broadcasts[0].tx;
    assert_eq!(penalty.input[0].witness.len(), 3);
    // The penalty is signed by A's basepoint secret plus B's revealed state-0
    // secret; neither alone would do.
    let commitment = a.their_commitment(0, a.state_at(0).unwrap()).unwrap();
    let combined = revocation_key(&key(0x30), &key(0x41)).unwrap();
    assert_eq!(
        public(&combined),
        b.revocation_for(Side::B, 0).unwrap(),
        "B's state-0 revocation key"
    );
    let signature = crate::LeafSignature::from_slice(&penalty.input[0].witness[0]).unwrap();
    assert!(crate::verify_leaf_signature(
        penalty,
        0,
        &[bitcoin::TxOut {
            value: commitment.local_value,
            script_pubkey: commitment.to_local.script_pubkey.clone(),
        }],
        commitment.to_local.revocation.leaf_hash,
        &public(&combined),
        &signature,
        SighashRules::KnotsUnified,
    ));
}

#[test]
fn the_lower_node_id_wins_a_collision_and_the_loser_keeps_its_signed_state() {
    let (mut a, mut b, _, _) = open_pair(20_000);
    let from_a = a.pay(10, None, key(0x34), &ctx(H)).unwrap();
    let from_b = b.pay(20, None, key(0x44), &ctx(H)).unwrap();
    let a_lower = node_less(public(&key(0x11)), public(&key(0x22)));
    let at_a = a.receive_update(from_b, key(0x35), &ctx(H)).unwrap();
    let at_b = b.receive_update(from_a, key(0x45), &ctx(H)).unwrap();
    let (winner_view, loser_view, loser) = if a_lower {
        (at_a, at_b, &mut b)
    } else {
        (at_b, at_a, &mut a)
    };
    assert!(
        matches!(winner_view, ReceiveUpdate::LocalProposalWins(ref r) if r.reason.as_deref() == Some("collision: the lower key's update stands"))
    );
    assert!(matches!(loser_view, ReceiveUpdate::Acknowledge(_)));
    assert_eq!(loser.signed_alternatives(1).len(), 1);
    assert!(loser.pending().is_none());
    // Announced once nothing is pending or awaited.
    assert!(loser.dropped().is_some());
}

#[test]
fn htlc_rules_match_hitch() {
    let (mut a, mut b, _, _) = open_pair(0);
    let preimage = [0x55; 32];
    let hash = Bytes32(sha(&preimage));
    assert!(matches!(
        a.add_htlc(2_000, hash, H + 18, None, None, key(0x33), &ctx(H)),
        Err(ProtocolError::ExpiryTooSoon)
    ));
    let stale = Context {
        stale: true,
        ..ctx(H)
    };
    assert!(matches!(
        a.add_htlc(2_000, hash, H + 40, None, None, key(0x33), &stale),
        Err(ProtocolError::StaleChain)
    ));
    let add = a
        .add_htlc(2_000, hash, H + 40, None, None, key(0x34), &ctx(H))
        .unwrap();
    let ack = acknowledge(b.receive_update(add, key(0x43), &ctx(H)).unwrap());
    let outcome = a.receive_ack(ack).unwrap();
    b.receive_revoke(outcome.revoke).unwrap();
    assert_eq!(a.bound(&hash, H), Some(Bound::State));
    assert!(matches!(
        a.add_htlc(2_000, hash, H + 40, None, None, key(0x35), &ctx(H)),
        Err(ProtocolError::HashBound(Bound::State))
    ));
    b.remember_preimage(preimage);
    let current = b.current_state().clone();
    let fail = Update::Fail {
        htlc_id: 1,
        reason: Some("expired".into()),
    };
    assert!(matches!(
        b.next_state(&current, &fail, Side::A, H + 41),
        Err(ProtocolError::KnownPreimage)
    ));
    let settle = Update::Settle {
        htlc_id: 1,
        preimage: Bytes32(preimage),
    };
    assert!(matches!(
        b.next_state(&current, &settle, Side::B, H + 40),
        Err(ProtocolError::HtlcExpired)
    ));
    // Settle, then the next HTLC is id 2: ids never repeat.
    let settle = b
        .settle_htlc(1, Bytes32(preimage), key(0x46), &ctx(H))
        .unwrap();
    let ack = acknowledge(a.receive_update(settle, key(0x36), &ctx(H)).unwrap());
    let outcome = b.receive_ack(ack).unwrap();
    a.receive_revoke(outcome.revoke).unwrap();
    assert!(a.htlcs().is_empty());
    let next = a
        .add_htlc(
            2_000,
            Bytes32([1; 32]),
            H + 40,
            None,
            None,
            key(0x37),
            &ctx(H),
        )
        .unwrap();
    assert!(matches!(next.update, Update::Add { ref htlc, .. } if htlc.id == 2));
}

#[test]
fn a_state_leaving_the_funder_below_its_fee_is_never_signed() {
    let (mut a, _, _, _) = open_pair(0);
    // Before 0.2 a zero funder balance was exempt; Hitch now refuses it.
    let current = a.current_state().clone();
    let all = Update::Pay {
        amount: 100_000,
        memo: None,
    };
    assert!(matches!(
        a.next_state(&current, &all, Side::A, H),
        Err(ProtocolError::FunderFee)
    ));
    assert!(matches!(
        a.pay(99_701, None, key(0x33), &ctx(H)),
        Err(ProtocolError::TooMuch(99_700))
    ));
}

#[test]
fn a_reject_names_the_signature_and_sets_the_update_aside() {
    let (mut a, mut b, _, _) = open_pair(0);
    let update = a.pay(100, None, key(0x33), &ctx(H)).unwrap();
    let mut wrong = RejectMessage {
        t: RejectTag::Reject,
        id: a.id(),
        n: 1,
        sig: crate::LeafSignature::from_hex(&"ab".repeat(65)).unwrap(),
        reason: Some("stale".into()),
    };
    assert!(matches!(
        a.receive_reject(wrong.clone(), &ctx(H)),
        Err(ProtocolError::NoPending)
    ));
    assert!(a.pending().is_some());
    wrong.sig = update.sig;
    let sync = a.receive_reject(wrong, &ctx(H)).unwrap();
    assert!(sync.is_some(), "a resync follows a reject");
    assert!(a.pending().is_none());
    assert_eq!(a.signed_alternatives(1).len(), 1);
    let events = a.drain_events();
    assert!(
        matches!(&events[..], [ChannelEvent::Dropped(d)] if d.reason == "they refused it: stale")
    );
    // b took it after all: the acknowledgement adopts the set-aside state.
    let ack = acknowledge(b.receive_update(update, key(0x43), &ctx(H)).unwrap());
    let outcome = a.receive_ack(ack).unwrap();
    assert!(outcome.adopted);
    assert_eq!(a.state_number(), 1);
    assert!(a.signed_alternatives(1).is_empty());
}

#[test]
fn a_closing_asked_channel_rejects_updates_and_a_coop_close_is_final_at_depth() {
    let (mut a, mut b, _, _) = open_pair(5_000);
    let close = a.close_channel(&ctx(H)).unwrap();
    let update = b.pay(1_000, None, key(0x43), &ctx(H)).unwrap();
    let ReceiveUpdate::Rejected(reject) = a.receive_update(update, key(0x33), &ctx(H)).unwrap()
    else {
        panic!("rejected")
    };
    assert!(reject
        .reason
        .as_deref()
        .unwrap()
        .contains("cooperative close"));
    assert!(matches!(
        b.receive_close(close.clone(), &ctx(H)),
        Err(ProtocolError::InFlight)
    ));
    let sync = b.receive_reject(reject, &ctx(H)).unwrap().unwrap();
    let outcome = a.receive_sync(&sync, &ctx(H)).unwrap();
    let close = outcome
        .replies
        .iter()
        .find_map(|m| match m {
            PeerMessage::Close(close) => Some(close.clone()),
            _ => None,
        })
        .expect("the close again");
    let broadcast = b.receive_close(close, &ctx(H)).unwrap();
    assert_eq!(b.status(), ChannelStatus::Closing);
    let txid = broadcast.tx.compute_txid();
    let destination = ScriptBuf::new();
    a.on_spend(
        ChainSpend { txid, height: H },
        &destination,
        &ctx(H),
        |_, _| OutputLookup::Unspent,
    )
    .unwrap();
    assert_eq!(a.status(), ChannelStatus::ClosedCoop);
    a.after_close(&destination, &ctx(H + 4), |_, _| OutputLookup::Unspent);
    assert_eq!(a.status(), ChannelStatus::ClosedCoop);
    a.after_close(&destination, &ctx(H + 5), |_, _| OutputLookup::Unspent);
    assert_eq!(a.status(), ChannelStatus::Closed);
}

#[test]
fn every_message_round_trips_through_the_wire_enum() {
    let (mut a, mut b, open, accept) = open_pair(20_000);
    let update = a
        .pay(1_000, Some("rent".into()), key(0x33), &ctx(H))
        .unwrap();
    let value = serde_json::to_value(&update).unwrap();
    assert_eq!(value["kind"], "pay");
    assert_eq!(value["memo"], "rent");
    assert_eq!(value["sig"].as_str().unwrap().len(), 130);
    assert_eq!(value["nextRev"].as_str().unwrap().len(), 64);
    assert_eq!(value["nextRevPop"].as_str().unwrap().len(), 128);
    let ack = acknowledge(
        b.receive_update(update.clone(), key(0x43), &ctx(H))
            .unwrap(),
    );
    let outcome = a.receive_ack(ack.clone()).unwrap();
    let reject = RejectMessage {
        t: RejectTag::Reject,
        id: a.id(),
        n: 1,
        sig: update.sig,
        reason: None,
    };
    let messages: Vec<PeerMessage> = vec![
        open.into(),
        accept.into(),
        update.into(),
        ack.into(),
        outcome.revoke.into(),
        reject.into(),
        a.close_channel(&ctx(H)).unwrap().into(),
        a.sync_message(SyncTag::Sync).into(),
    ];
    for message in messages {
        let json = serde_json::to_string(&message).unwrap();
        let back: PeerMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message, "{json}");
        assert!(back.well_formed().is_ok());
    }
    assert!(serde_json::from_str::<PeerMessage>(
        r#"{"t":"update","id":"zz","n":1,"kind":"pay","amount":1,"sig":"00","nextRev":"00","nextRevPop":"00"}"#
    )
    .is_err());
}

#[test]
fn reasons_are_cut_in_javascript_string_units() {
    assert_eq!(
        wire::truncate_utf16(&"é".repeat(200), MEMO_MAX)
            .chars()
            .count(),
        140
    );
    assert_eq!(
        wire::truncate_utf16(&"😀".repeat(100), MEMO_MAX)
            .chars()
            .count(),
        70
    );
    let (mut a, mut b, _, _) = open_pair(0);
    let hash = Bytes32([2; 32]);
    let add = a
        .add_htlc(2_000, hash, H + 40, None, None, key(0x33), &ctx(H))
        .unwrap();
    let ack = acknowledge(b.receive_update(add, key(0x43), &ctx(H)).unwrap());
    let outcome = a.receive_ack(ack).unwrap();
    b.receive_revoke(outcome.revoke).unwrap();
    let fail = b
        .fail_htlc(1, Some(&"x".repeat(300)), key(0x44), &ctx(H))
        .unwrap();
    assert!(matches!(fail.update, Update::Fail { reason: Some(ref r), .. } if r.len() == MEMO_MAX));
}

#[test]
fn the_tick_takes_a_claimable_htlc_to_the_chain_before_its_deadline() {
    let (mut a, mut b, _, _) = open_pair(0);
    let preimage = [0x66; 32];
    let hash = Bytes32(sha(&preimage));
    let expiry = H + 40;
    let add = a
        .add_htlc(3_000, hash, expiry, None, None, key(0x33), &ctx(H))
        .unwrap();
    let ack = acknowledge(b.receive_update(add, key(0x43), &ctx(H)).unwrap());
    let outcome = a.receive_ack(ack).unwrap();
    b.receive_revoke(outcome.revoke).unwrap();
    b.remember_preimage(preimage);
    // With nothing pending, the tick proposes the settle first.
    let actions = b.tick(&ctx(H), &TickOptions::default());
    assert!(matches!(
        &actions[..],
        [TickAction::Settle { htlc_id: 1, .. }]
    ));
    let deadline = expiry - 6 - CLAIM_MARGIN;
    assert!(!b
        .tick(&ctx(deadline - 1), &TickOptions::default())
        .iter()
        .any(|a| matches!(a, TickAction::Broadcast(_))));
    let actions = b.tick(&ctx(deadline), &TickOptions::default());
    assert!(matches!(&actions[..], [TickAction::Broadcast(b)] if b.label == "protective close"));
    assert_eq!(b.status(), ChannelStatus::ForceClosing);
}

#[test]
fn bound_follows_an_htlc_output_of_a_close_until_it_settles() {
    let (mut a, mut b, _, _) = open_pair(0);
    let hash = Bytes32([3; 32]);
    let add = a
        .add_htlc(3_000, hash, H + 40, None, None, key(0x33), &ctx(H))
        .unwrap();
    let ack = acknowledge(b.receive_update(add, key(0x43), &ctx(H)).unwrap());
    let outcome = a.receive_ack(ack).unwrap();
    b.receive_revoke(outcome.revoke).unwrap();
    let close = b.force_close(None, "forced", &ctx(H)).unwrap();
    let destination = ScriptBuf::new();
    a.on_spend(
        ChainSpend {
            txid: close.tx.compute_txid(),
            height: H,
        },
        &destination,
        &ctx(H),
        |_, _| OutputLookup::Unspent,
    )
    .unwrap();
    assert_eq!(a.status(), ChannelStatus::ClosedTheirs);
    // The agreed state still names the HTLC, so it binds as `state` first.
    assert_eq!(a.bound(&hash, H), Some(Bound::State));
    let output = a
        .followed_outputs()
        .values()
        .find(|o| o.hash == Some(hash))
        .unwrap();
    assert!(output.offered_by_me);
}
