//! The crate's one error type.

use std::path::PathBuf;

use lwk_wollet::elements::AssetId;

/// Everything that can go wrong in the reserve wiring.
///
/// No variant ever carries key material: a key file that fails to parse is
/// reported as [`Error::Mnemonic`] without echoing its content.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `init` found a file at the key path and left it untouched.
    #[error("key file {} already exists; refusing to overwrite a reserve key", path.display())]
    KeyFileExists {
        /// The path that already exists.
        path: PathBuf,
    },

    /// The key file is readable or writable by group or others.
    #[error(
        "key file {} has mode {mode:o}; a reserve key must be private to its owner (chmod 0400)",
        path.display()
    )]
    KeyFilePermissions {
        /// The key file.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },

    /// Reading or writing the key file failed.
    #[error("key file {}: {source}", path.display())]
    Io {
        /// The key file.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// The key material is not a valid BIP-39 mnemonic. The content is never echoed.
    #[error("the key file does not hold a valid BIP-39 mnemonic")]
    Mnemonic,

    /// Building the descriptor from the signer failed.
    #[error("descriptor: {0}")]
    Descriptor(String),

    /// An error from the Liquid Wallet Kit (wallet, sync or registry client).
    #[error("liquid wallet kit: {0}")]
    Lwk(#[from] lwk_wollet::Error),

    /// An asset other than the pinned reserve asset was offered for attestation.
    #[error("asset {found} is not the reserve asset {expected}; refusing to attest it")]
    NotReserveAsset {
        /// The asset that was offered.
        found: AssetId,
        /// The pinned reserve asset.
        expected: AssetId,
    },

    /// The registry entry does not match the pinned reserve asset.
    #[error("registry entry does not match the pinned reserve asset: {0}")]
    Registry(String),

    /// The wallet state is not one an attestation can be made from.
    #[error("wallet state: {0}")]
    State(String),

    /// The proxy URL is refused (unsupported scheme, or one that resolves names locally).
    #[error("proxy: {0}")]
    Proxy(String),

    /// The origin-neutral attestation refused its inputs, or a signature
    /// failed ([`sidestr_reserve::Error`]).
    #[error("attestation: {0}")]
    Reserve(#[from] sidestr_reserve::Error),
}

/// The crate's result type.
pub type Result<T> = std::result::Result<T, Error>;
