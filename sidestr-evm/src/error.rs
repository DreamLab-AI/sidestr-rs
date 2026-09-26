//! The crate's error type.

/// What can go wrong outside a block's verdict: a record that cannot be
/// written, a chain document whose `evm` section cannot be read, or a
/// refusal from `sidestr-core` while producing. A block the rule refuses is
/// not an error here: it is a [`crate::Verdict`] that is not ok, and
/// `sidestr-core` reports it as `sidestr:rule-evm`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A record that cannot be written.
    #[error("record: {0}")]
    Record(String),
    /// The document's `evm` section, or its `rules`.
    #[error("evm rule: {0}")]
    Config(String),
    /// A refusal from `sidestr-core`.
    #[error(transparent)]
    Core(#[from] sidestr_core::Error),
}

/// The crate's result type.
pub type Result<T> = core::result::Result<T, Error>;
