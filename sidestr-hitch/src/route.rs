//! Hitch's one-hop invoice and HTLC routing decisions.
//!
//! The asynchronous host owns channel lookup, retries, persistence and user
//! notifications. This module keeps the money-bearing decision pure: settle
//! a matching invoice, forward through one hub channel with the required fee
//! and timeout delta, or fail the incoming HTLC. A host records
//! [`ForwardRecord`] before acting on the downstream channel so a restart can
//! carry a later settle or failure back upstream.

use bitcoin::hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};

use crate::protocol::{
    Bytes32, ChannelId, NodeId, OfferedHtlc, ProtocolHtlc, EXPIRY_MARGIN, MEMO_MAX, MIN_HTLC,
};

/// Portable Hitch invoice carried out of band by the payer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invoice {
    /// Payee node id.
    pub p: NodeId,
    /// Requested amount in satoshis.
    pub a: u64,
    /// Optional human-readable memo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub m: Option<String>,
    /// SHA-256 payment hash.
    pub h: Bytes32,
    /// Suggested hub node ids.
    pub r: Vec<NodeId>,
    /// Fee hint in satoshis per hop.
    pub f: u64,
    /// Unix expiry time.
    pub x: u64,
    /// First sixteen hex characters of the payment hash.
    pub i: ChannelId,
}

impl Invoice {
    /// Create an invoice and return the preimage that must remain private
    /// until an incoming HTLC is final.
    pub fn new(
        payee: NodeId,
        amount: u64,
        memo: Option<String>,
        hops: Vec<NodeId>,
        fee_hint: u64,
        expires_at: u64,
        preimage: [u8; 32],
    ) -> Result<(Bytes32, Self), RouteError> {
        if memo
            .as_ref()
            .is_some_and(|value| value.encode_utf16().count() > MEMO_MAX)
        {
            return Err(RouteError::MemoTooLong);
        }
        let hash = sha256::Hash::hash(&preimage).to_byte_array();
        let mut id = [0u8; 8];
        id.copy_from_slice(&hash[..8]);
        Ok((
            Bytes32(preimage),
            Self {
                p: payee,
                a: amount,
                m: memo,
                h: Bytes32(hash),
                r: hops,
                f: fee_hint,
                x: expires_at,
                i: ChannelId(id),
            },
        ))
    }
}

/// Locally retained invoice secret and expected amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvoiceRecord {
    /// Preimage whose SHA-256 digest is the invoice hash.
    pub preimage: Bytes32,
    /// Smallest acceptable amount.
    pub amount: u64,
}

/// Capacity data for the channel selected by a route hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Downstream {
    /// Downstream channel id.
    pub channel: ChannelId,
    /// Spendable balance after the funder's fee reserve.
    pub room: u64,
    /// Downstream commitment delay.
    pub delay: u16,
}

/// Final incoming HTLC and the channel parameters relevant to routing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncomingAdd<'a> {
    /// Channel on which the HTLC arrived.
    pub channel: ChannelId,
    /// Incoming channel's commitment delay.
    pub delay: u16,
    /// Final HTLC state.
    pub htlc: &'a ProtocolHtlc,
}

/// Current hub capacity and chain height used for a routing decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterContext {
    /// Whether forwarding is enabled.
    pub hub: bool,
    /// Fee retained by this hub.
    pub hub_fee: u64,
    /// Channel selected for the route target, when available.
    pub downstream: Option<Downstream>,
    /// Current parent-chain height.
    pub height: u32,
}

/// Durable link between upstream and downstream HTLCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardRecord {
    /// Payment hash indexing the record.
    pub hash: Bytes32,
    /// Channel on which the HTLC arrived.
    pub upstream_channel: ChannelId,
    /// Incoming HTLC id.
    pub upstream_htlc_id: u64,
    /// Channel on which the reduced HTLC was offered.
    pub downstream_channel: ChannelId,
}

/// Action for the host to submit through a channel state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteAction {
    /// Settle an incoming HTLC with a retained preimage.
    Settle {
        /// Channel containing the HTLC.
        channel: ChannelId,
        /// HTLC id on that channel.
        htlc_id: u64,
        /// Payment preimage.
        preimage: Bytes32,
    },
    /// Fail an incoming or upstream HTLC.
    Fail {
        /// Channel containing the HTLC.
        channel: ChannelId,
        /// HTLC id on that channel.
        htlc_id: u64,
        /// Hitch-compatible display reason.
        reason: String,
    },
    /// Offer a fee- and timeout-adjusted HTLC downstream, then persist the
    /// accompanying record.
    Forward {
        /// Downstream channel.
        channel: ChannelId,
        /// New downstream offer.
        htlc: OfferedHtlc,
        /// Recovery link to persist after the offer is accepted.
        record: ForwardRecord,
    },
}

/// Decide what to do after an incoming `add` update has become final.
pub fn decide_add(
    incoming: IncomingAdd<'_>,
    invoice: Option<InvoiceRecord>,
    context: RouterContext,
) -> RouteAction {
    let htlc = incoming.htlc;
    if let Some(invoice) = invoice {
        if htlc.amount < invoice.amount {
            return fail(incoming.channel, htlc.id, "amount below the invoice");
        }
        if htlc.expiry
            < context
                .height
                .saturating_add(u32::from(incoming.delay) + EXPIRY_MARGIN)
        {
            return fail(incoming.channel, htlc.id, "expiry too close");
        }
        return RouteAction::Settle {
            channel: incoming.channel,
            htlc_id: htlc.id,
            preimage: invoice.preimage,
        };
    }

    if context.hub && htlc.route.is_some() {
        let amount = htlc.amount.checked_sub(context.hub_fee);
        let expiry = htlc.expiry.checked_sub(EXPIRY_MARGIN);
        if let (Some(amount), Some(expiry), Some(downstream)) = (amount, expiry, context.downstream)
        {
            let enough_time = expiry
                > context
                    .height
                    .saturating_add(u32::from(downstream.delay) + EXPIRY_MARGIN);
            if amount >= MIN_HTLC && downstream.room >= amount && enough_time {
                return RouteAction::Forward {
                    channel: downstream.channel,
                    htlc: OfferedHtlc {
                        id: 0,
                        amount,
                        hash: htlc.hash,
                        expiry,
                        route: None,
                    },
                    record: ForwardRecord {
                        hash: htlc.hash,
                        upstream_channel: incoming.channel,
                        upstream_htlc_id: htlc.id,
                        downstream_channel: downstream.channel,
                    },
                };
            }
        }
        return fail(incoming.channel, htlc.id, "no route");
    }

    fail(incoming.channel, htlc.id, "unknown hash")
}

/// Carry a final downstream settle back to the recorded upstream HTLC.
pub fn settle_upstream(record: ForwardRecord, preimage: Bytes32) -> RouteAction {
    RouteAction::Settle {
        channel: record.upstream_channel,
        htlc_id: record.upstream_htlc_id,
        preimage,
    }
}

/// Carry a final downstream failure back to the recorded upstream HTLC.
pub fn fail_upstream(record: ForwardRecord, reason: Option<&str>) -> RouteAction {
    fail(
        record.upstream_channel,
        record.upstream_htlc_id,
        reason.unwrap_or("downstream failed"),
    )
}

/// Whether a hub should force-close the downstream channel to protect a
/// forwarded payment as the upstream expiry approaches.
pub fn needs_protective_close(
    height: u32,
    upstream_expiry: u32,
    downstream_still_in_flight: bool,
) -> bool {
    downstream_still_in_flight && height >= upstream_expiry.saturating_sub(EXPIRY_MARGIN / 2)
}

fn fail(channel: ChannelId, htlc_id: u64, reason: &str) -> RouteAction {
    RouteAction::Fail {
        channel,
        htlc_id,
        reason: reason.into(),
    }
}

/// Invalid invoice construction.
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    /// Invoice memo exceeded Hitch's wire limit.
    #[error("invoice memo is longer than {MEMO_MAX} characters")]
    MemoTooLong,
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Keypair, SecretKey};
    use sidestr_core::block::secp;

    use super::*;
    use crate::protocol::{Route, WireSide};

    fn node(byte: u8) -> NodeId {
        let key = SecretKey::from_slice(&[byte; 32]).unwrap();
        NodeId(Keypair::from_secret_key(secp(), &key).x_only_public_key().0)
    }

    fn incoming(route: Option<Route>) -> ProtocolHtlc {
        ProtocolHtlc {
            id: 7,
            from: WireSide::A,
            amount: 5_010,
            hash: Bytes32([0x55; 32]),
            expiry: 1_040,
            route,
        }
    }

    #[test]
    fn invoice_shape_and_direct_settlement_match_hitch() {
        let preimage = [0x44; 32];
        let (secret, invoice) = Invoice::new(
            node(1),
            5_000,
            Some("coffee".into()),
            vec![node(2)],
            10,
            2_000,
            preimage,
        )
        .unwrap();
        assert_eq!(invoice.h.0, sha256::Hash::hash(&preimage).to_byte_array());
        assert_eq!(invoice.i.0, invoice.h.0[..8]);
        let action = decide_add(
            IncomingAdd {
                channel: ChannelId([1; 8]),
                delay: 6,
                htlc: &incoming(None),
            },
            Some(InvoiceRecord {
                preimage: secret,
                amount: invoice.a,
            }),
            RouterContext {
                hub: false,
                hub_fee: 10,
                downstream: None,
                height: 1_000,
            },
        );
        assert!(matches!(action, RouteAction::Settle { htlc_id: 7, .. }));
    }

    #[test]
    fn hub_subtracts_fee_and_timeout_delta_and_records_the_link() {
        let target = node(3);
        let downstream = Downstream {
            channel: ChannelId([2; 8]),
            room: 10_000,
            delay: 6,
        };
        let action = decide_add(
            IncomingAdd {
                channel: ChannelId([1; 8]),
                delay: 6,
                htlc: &incoming(Some(Route { to: target })),
            },
            None,
            RouterContext {
                hub: true,
                hub_fee: 10,
                downstream: Some(downstream),
                height: 1_000,
            },
        );
        let RouteAction::Forward {
            channel,
            htlc,
            record,
        } = action
        else {
            panic!("expected a forward")
        };
        assert_eq!(channel, downstream.channel);
        assert_eq!(htlc.amount, 5_000);
        assert_eq!(htlc.expiry, 1_028);
        assert_eq!(record.upstream_htlc_id, 7);
        assert_eq!(
            settle_upstream(record, Bytes32([9; 32])),
            RouteAction::Settle {
                channel: ChannelId([1; 8]),
                htlc_id: 7,
                preimage: Bytes32([9; 32]),
            }
        );
    }

    #[test]
    fn unsafe_or_unknown_htlcs_fail_and_near_expiry_forces_close() {
        let no_route = decide_add(
            IncomingAdd {
                channel: ChannelId([1; 8]),
                delay: 6,
                htlc: &incoming(Some(Route { to: node(3) })),
            },
            None,
            RouterContext {
                hub: true,
                hub_fee: 10,
                downstream: None,
                height: 1_000,
            },
        );
        assert!(matches!(no_route, RouteAction::Fail { ref reason, .. } if reason == "no route"));
        assert!(needs_protective_close(1_034, 1_040, true));
        assert!(!needs_protective_close(1_033, 1_040, true));
    }
}
