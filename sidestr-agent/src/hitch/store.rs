//! Durable state for a Hitch host: wallet-grade secrets in owner-only
//! files, written atomically.
//!
//! A channel snapshot holds the channel key, the revocation basepoint, every
//! per-state revocation secret and every payment preimage. Losing one can
//! cost the channel. A stale one can be worse: publishing a revoked state
//! hands the counterparty everything. So the kernel's rule is "save, then
//! send", and a save here is all-or-nothing:
//!
//! 1. write to a fresh temporary file created `0600` in the same directory
//!    (`O_CREAT|O_EXCL`, so a stale temporary is never reused);
//! 2. `fsync` it;
//! 3. rename it over the target (atomic on POSIX);
//! 4. `fsync` the directory, so the rename itself survives a crash.
//!
//! The directory is created `0700`. A secret file found readable by group
//! or others is refused on read rather than trusted.
//!
//! ```text
//! <state>/                       0700
//!   spend.key                    0600  k_spend, 64 hex
//!   binding.json                 0600  the k_id-signed kind-38420 event
//!   lock                         0600  held (flock) by the running host
//!   control.sock                 0600  the watch daemon's command socket
//!   status.json                  0600  the host's last view, no secrets
//!   journal.jsonl                0600  append-only: events, txids, heights
//!   channels/<id>.json           0600  ChannelSnapshot and the host's notes
//!   openings/<id>.json           0600  a handshake in progress (its secrets)
//!   invoices/<hash>.json         0600  an invoice and its preimage
//! ```
//!
//! ```
//! use sidestr_agent::hitch::store::Store;
//! # let dir = std::env::temp_dir().join(format!("sidestr-store-doc-{}", std::process::id()));
//! let store = Store::open(&dir).unwrap();
//! store.write("channels/0011223344556677.json", b"{}").unwrap();
//! assert_eq!(store.read("channels/0011223344556677.json").unwrap().unwrap(), b"{}");
//! assert_eq!(store.list("channels").unwrap(), vec!["0011223344556677.json".to_string()]);
//! # std::fs::remove_dir_all(&dir).unwrap();
//! ```

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::{Error, Result};

/// The key file's name inside the state directory.
pub const SPEND_KEY: &str = "spend.key";
/// The binding's file name.
pub const BINDING: &str = "binding.json";
/// The lock file a running host holds.
pub const LOCK: &str = "lock";
/// The watch daemon's command socket.
pub const CONTROL: &str = "control.sock";
/// The host's last view, for `hitch status`.
pub const STATUS: &str = "status.json";
/// The append-only journal.
pub const JOURNAL: &str = "journal.jsonl";
/// Channel snapshots.
pub const CHANNELS: &str = "channels";
/// Handshakes in progress.
pub const OPENINGS: &str = "openings";
/// Invoices and their preimages.
pub const INVOICES: &str = "invoices";

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A state directory.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// Open (creating, `0700`) a state directory and its subdirectories.
    /// An existing directory that group or others can enter is tightened to
    /// `0700`.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        for d in [
            dir.clone(),
            dir.join(CHANNELS),
            dir.join(OPENINGS),
            dir.join(INVOICES),
        ] {
            match fs::create_dir(&d) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
                Err(e) if e.kind() == ErrorKind::NotFound => fs::create_dir_all(&d)?,
                Err(e) => return Err(e.into()),
            }
            let meta = fs::metadata(&d)?;
            if !meta.is_dir() {
                return Err(Error::Host(format!("{} is not a directory", d.display())));
            }
            if meta.permissions().mode() & 0o077 != 0 {
                fs::set_permissions(&d, fs::Permissions::from_mode(0o700))?;
            }
        }
        Ok(Self { dir })
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The path of `rel` inside the directory. Absolute paths and `..` are
    /// refused.
    pub fn path(&self, rel: &str) -> Result<PathBuf> {
        let p = Path::new(rel);
        if p.components().any(|c| !matches!(c, Component::Normal(_))) {
            return Err(Error::Host(format!("{rel:?} is not a plain relative path")));
        }
        Ok(self.dir.join(p))
    }

    /// Write `bytes` to `rel` atomically, owner-only: temporary file
    /// (`0600`, exclusive), `fsync`, rename, directory `fsync`.
    pub fn write(&self, rel: &str, bytes: &[u8]) -> Result<()> {
        let target = self.path(rel)?;
        let parent = target
            .parent()
            .ok_or_else(|| Error::Host(format!("{rel:?} has no directory")))?
            .to_path_buf();
        let name = target
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| Error::Host(format!("{rel:?} has no file name")))?;
        let tmp = parent.join(format!(
            ".{name}.{}.{}.tmp",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let written = (|| -> std::io::Result<()> {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            drop(f);
            fs::rename(&tmp, &target)?;
            File::open(&parent)?.sync_all()
        })();
        if written.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        Ok(written?)
    }

    /// Write the spend key to [`SPEND_KEY`] as 64 hex and a newline, `0600`
    /// and atomically. It refuses to replace a different key already there:
    /// that key may hold coins and channels.
    pub fn write_spend_key(&self, key: &crate::AgentKey) -> Result<()> {
        if let Some(existing) = self.read(SPEND_KEY)? {
            let held = crate::AgentKey::parse(&String::from_utf8_lossy(&existing))?;
            if held.pubkey() != key.pubkey() {
                return Err(Error::Host(format!(
                    "{} already holds another spend key; it may hold coins and channels",
                    self.path(SPEND_KEY)?.display()
                )));
            }
            return Ok(());
        }
        let mut text = hex_lower(&key.secret_key().secret_bytes());
        text.push('\n');
        self.write(SPEND_KEY, text.as_bytes())
    }

    /// Read `rel`; `None` if it does not exist. A file group or others can
    /// read is refused: it may have leaked, and is not trusted silently.
    pub fn read(&self, rel: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path(rel)?;
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::Host(format!(
                "{} is readable by others (mode {:o}); it holds wallet secrets: chmod 600 it after checking it was not copied",
                path.display(),
                meta.permissions().mode() & 0o777
            )));
        }
        Ok(Some(fs::read(&path)?))
    }

    /// Whether `rel` exists.
    pub fn exists(&self, rel: &str) -> bool {
        self.path(rel).is_ok_and(|p| p.exists())
    }

    /// Remove `rel` if present, then `fsync` its directory.
    pub fn remove(&self, rel: &str) -> Result<()> {
        let path = self.path(rel)?;
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    /// The `.json` file names in a subdirectory, sorted; temporary files
    /// are skipped.
    pub fn list(&self, sub: &str) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for e in fs::read_dir(self.path(sub)?)? {
            let name = e?.file_name().to_string_lossy().to_string();
            if name.ends_with(".json") && !name.starts_with('.') {
                out.push(name);
            }
        }
        out.sort();
        Ok(out)
    }

    /// Append one line of JSON to the journal (`0600`), and `fsync` it.
    pub fn journal(&self, entry: &serde_json::Value) -> Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(self.path(JOURNAL)?)?;
        let mut line = serde_json::to_vec(entry)?;
        line.push(b'\n');
        f.write_all(&line)?;
        f.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sidestr-store-{tag}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn files_are_owner_only_and_replaced_whole() {
        let d = scratch("perm");
        let s = Store::open(&d).unwrap();
        assert_eq!(
            fs::metadata(&d).unwrap().permissions().mode() & 0o777,
            0o700
        );
        s.write(SPEND_KEY, b"one").unwrap();
        s.write(SPEND_KEY, b"two").unwrap();
        let meta = fs::metadata(d.join(SPEND_KEY)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(s.read(SPEND_KEY).unwrap().unwrap(), b"two");
        // no temporary is left behind
        let leftovers: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
        s.journal(&serde_json::json!({"ev": "x"})).unwrap();
        s.journal(&serde_json::json!({"ev": "y"})).unwrap();
        let j = fs::read_to_string(d.join(JOURNAL)).unwrap();
        assert_eq!(j.lines().count(), 2);
        assert_eq!(
            fs::metadata(d.join(JOURNAL)).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_spend_key_is_written_once_and_never_replaced() {
        let d = scratch("key");
        let s = Store::open(&d).unwrap();
        let k = crate::AgentKey::parse(&"02".repeat(32)).unwrap();
        s.write_spend_key(&k).unwrap();
        s.write_spend_key(&k).unwrap();
        let back = crate::AgentKey::parse(
            &String::from_utf8(s.read(SPEND_KEY).unwrap().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(back.pubkey(), k.pubkey());
        let other = crate::AgentKey::parse(&"03".repeat(32)).unwrap();
        assert!(s.write_spend_key(&other).is_err());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_leaky_file_or_a_path_outside_is_refused() {
        let d = scratch("leak");
        let s = Store::open(&d).unwrap();
        s.write("channels/a.json", b"{}").unwrap();
        fs::set_permissions(d.join("channels/a.json"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(s.read("channels/a.json"), Err(Error::Host(_))));
        assert!(s.write("../escape", b"x").is_err());
        assert!(s.write("/etc/passwd", b"x").is_err());
        assert!(s.read("missing.json").unwrap().is_none());
        // a loose directory is tightened on open
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        Store::open(&d).unwrap();
        assert_eq!(
            fs::metadata(&d).unwrap().permissions().mode() & 0o777,
            0o700
        );
        fs::remove_dir_all(&d).unwrap();
    }
}
