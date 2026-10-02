//! A host for Hitch payment channels ([`sidestr_hitch`] 0.2): what the
//! sans-IO channel kernel leaves to its caller, for one agent.
//!
//! `sidestr-hitch` is a pure state machine. Each call returns the messages to
//! send and the transactions to broadcast, and the caller supplies
//! everything else. This module supplies it for an agent on a sidestr
//! chain:
//!
//! | module | what it supplies |
//! |---|---|
//! | [`binding`] | ADR-2101 D3: the spend key `k_spend` minted apart from the identity key `k_id`, and the `k_id`-signed kind-38420 event that names it; a host refuses to spend with `k_id` |
//! | [`envelope`] | the relay transport: each [`PeerMessage`] as a kind-23600 event signed by the channel key, and the checks on receipt |
//! | [`follow`] | the chain watch: blocks from a producer or a mirror, each linked and signature-checked; reorganisations found and measured |
//! | [`store`] | durable snapshots: wallet-grade secrets in `0600` files, written atomically (temporary file, `fsync`, rename, directory `fsync`) |
//! | `host` (feature `cli`, Unix) | the engine: relay I/O over the shared pool, funding from the wallet, broadcast to `POST /tx` with a kind-23500 fallback, and the watch loop (penalties, sweeps, HTLC timeouts, reorganisations) |
//!
//! The chain watch reads blocks **without validating their transactions**:
//! a watch must see a spend the moment it is in a block, and it trusts the
//! producer for transaction validity, as the coin list does. Validating is
//! `sidestr-core`'s, which judges every Hitch leaf (`sidestr_core::channel`):
//! a wallet that must not trust the producer replays the block file with
//! `sidestr_core::state::StateOf`, as the loopback tests do after every
//! channel run. The follower does check every block's hash, its link to the block
//! before it and the signer's solution against the chain's challenge, so a
//! mirror cannot forge a block. Both header families are followed: stock
//! 80-byte headers, and Knots' 164-byte BLAKE2b v2 headers beside `txbt4`
//! (`sidestr_header::Blake2bV2`), the family of `sidestr:dreamlab-txbt4`.
//!
//! [`PeerMessage`]: sidestr_hitch::protocol::PeerMessage

pub mod binding;
pub mod envelope;
pub mod follow;
#[cfg(all(feature = "cli", unix))]
pub mod host;
#[cfg(unix)]
pub mod store;

/// What can go wrong in the host.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The spend key and the identity key are the same key (ADR-2101 D3:
    /// `k_id` never spends).
    #[error("the spend key is the identity key: k_id never spends; mint a separate k_spend with `hitch bind` (ADR-2101 D3)")]
    SpendIsIdentity,
    /// A binding is missing, does not verify, or names another key or chain.
    #[error("binding: {0}")]
    Binding(String),
    /// The chain watch refused what a producer or mirror served.
    #[error("chain watch: {0}")]
    Chain(String),
    /// A channel protocol refusal.
    #[error(transparent)]
    Protocol(#[from] sidestr_hitch::protocol::ProtocolError),
    /// A channel transaction could not be built.
    #[error(transparent)]
    Channel(#[from] sidestr_hitch::Error),
    /// The agent wallet refused.
    #[error(transparent)]
    Agent(#[from] crate::Error),
    /// An event could not be made or read.
    #[error(transparent)]
    Nostr(#[from] sidestr_nostr::Error),
    /// A consensus or document error.
    #[error(transparent)]
    Core(#[from] sidestr_core::Error),
    /// JSON that does not parse or fit.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Storage.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Anything else the host refuses, said in words.
    #[error("{0}")]
    Host(String),
}

/// This module's result.
pub type Result<T> = core::result::Result<T, Error>;
