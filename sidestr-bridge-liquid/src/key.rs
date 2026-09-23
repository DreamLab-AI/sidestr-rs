//! The reserve key: a BIP-39 mnemonic held in a file outside every repository.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use lwk_common::{singlesig_desc, DescriptorBlindingKey, Singlesig};
use lwk_signer::bip39::Mnemonic;
use lwk_signer::SwSigner;
use lwk_wollet::WolletDescriptor;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Words in a mnemonic that [`ReserveKey::create`] generates: 24, so 256 bits of entropy.
pub const MNEMONIC_WORDS: usize = 24;

/// The mode a new key file is created with: owner read-only.
pub const KEY_FILE_MODE: u32 = 0o400;

/// The reserve wallet's secret: a BIP-39 mnemonic (no passphrase).
///
/// The phrase is held in a zeroising buffer and never printed: [`fmt::Debug`]
/// is redacted, and no method returns it. The key only ever leaves this type
/// as the public [`descriptor`](Self::descriptor), which the watch-only
/// wallet, the sync and the attestation all work from.
///
/// # Example
///
/// ```
/// use sidestr_bridge_liquid::ReserveKey;
///
/// let dir = tempfile::tempdir().unwrap();
/// let path = dir.path().join("mnemonic");
/// let key = ReserveKey::create(&path).unwrap();
/// // A second `init` against the same path is refused, never overwritten.
/// assert!(ReserveKey::create(&path).is_err());
/// // The same file loads back to the same wallet.
/// let loaded = ReserveKey::load(&path).unwrap();
/// assert_eq!(key.descriptor().unwrap(), loaded.descriptor().unwrap());
/// ```
pub struct ReserveKey {
    phrase: Zeroizing<String>,
}

impl fmt::Debug for ReserveKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReserveKey(<redacted>)")
    }
}

impl ReserveKey {
    /// A key from a mnemonic phrase. Surrounding whitespace is ignored.
    ///
    /// Fails with [`Error::Mnemonic`] if the phrase is not valid BIP-39; the
    /// phrase is not echoed.
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        let phrase = Zeroizing::new(phrase.trim().to_owned());
        let _: Mnemonic = phrase.parse().map_err(|_| Error::Mnemonic)?;
        Ok(Self { phrase })
    }

    /// Generates a fresh mnemonic of [`MNEMONIC_WORDS`] words (bip39's
    /// generator, seeded from the operating system) and writes it to `path`
    /// with mode [`KEY_FILE_MODE`].
    ///
    /// The file is opened with `O_CREAT | O_EXCL`, so an existing file, a
    /// dangling symlink included, is never overwritten: the call fails with
    /// [`Error::KeyFileExists`] and the file is untouched. The parent
    /// directory must exist; creating it (mode 0700) is the operator's job.
    pub fn create(path: &Path) -> Result<Self> {
        let mnemonic = Mnemonic::generate(MNEMONIC_WORDS).map_err(|_| Error::Mnemonic)?;
        let key = Self {
            phrase: Zeroizing::new(mnemonic.to_string()),
        };
        let io = |source| Error::Io {
            path: path.to_owned(),
            source,
        };
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(KEY_FILE_MODE)
            .open(path)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => Error::KeyFileExists {
                    path: path.to_owned(),
                },
                _ => io(e),
            })?;
        let mut contents = Zeroizing::new(key.phrase.as_bytes().to_vec());
        contents.push(b'\n');
        file.write_all(&contents).map_err(io)?;
        file.sync_all().map_err(io)?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            File::open(parent).and_then(|d| d.sync_all()).map_err(io)?;
        }
        Ok(key)
    }

    /// Loads the mnemonic from `path`.
    ///
    /// Refuses a file that group or others can read or write
    /// ([`Error::KeyFilePermissions`]), and a file whose content is not a
    /// valid mnemonic ([`Error::Mnemonic`], content not echoed).
    pub fn load(path: &Path) -> Result<Self> {
        let io = |source| Error::Io {
            path: path.to_owned(),
            source,
        };
        let mut file = File::open(path).map_err(io)?;
        let mode = file.metadata().map_err(io)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(Error::KeyFilePermissions {
                path: path.to_owned(),
                mode,
            });
        }
        let mut raw = Zeroizing::new(String::new());
        file.read_to_string(&mut raw).map_err(io)?;
        Self::from_phrase(&raw)
    }

    /// The LWK software signer for Liquid mainnet (BIP-32 xpub version bytes).
    fn signer(&self) -> Result<SwSigner> {
        SwSigner::new(&self.phrase, true).map_err(|_| Error::Mnemonic)
    }

    /// The reserve wallet's confidential (CT) descriptor on Liquid mainnet.
    ///
    /// Single-sig native segwit, `elwpkh` at BIP-84 path `m/84'/1776'/0'`
    /// (1776 is Liquid's SLIP-44 coin type), blinded with the SLIP-77 master
    /// blinding key derived from the same seed. This is LWK's own
    /// construction (`lwk_common::singlesig_desc`), the one Blockstream's
    /// wallets use for a single-sig Liquid account.
    ///
    /// The descriptor cannot spend, but it holds the blinding key: anyone
    /// with it sees every amount and asset the wallet receives. Treat it as
    /// sensitive for privacy.
    pub fn descriptor(&self) -> Result<WolletDescriptor> {
        let text = singlesig_desc(
            &self.signer()?,
            Singlesig::Wpkh,
            DescriptorBlindingKey::Slip77,
        )
        .map_err(Error::Descriptor)?;
        text.parse()
            .map_err(|e: lwk_wollet::Error| Error::Descriptor(e.to_string()))
    }
}
