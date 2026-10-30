//! The dirty marker, `node/dirty` (design 0008, "Reconciliation"): that the
//! home may hold a partial mutation, and which identities may have left
//! one.
//!
//! - **Its form** is the core's (0008, "The switch"): JSON,
//!   `{"node_ids": [<node ID>, …]}`, each node ID in its `z6Mk…` form,
//!   sorted, each once. A marker that doesn't read as that, or names
//!   something that isn't a node ID, is an error: nothing is touched, and
//!   `rad.reconcile` answers `recovery_failed`.
//! - **What is read is bounded:** a marker larger than [`MAX_LEN`] is an
//!   error, before it is read. It names one identity after every completed
//!   reconciliation, and grows only by the starts that didn't complete.
//! - **It is written durably:** to a temporary file beside it, flushed,
//!   renamed into place, and then its directory flushed (on Unix: Windows
//!   has no directory flush, as the core's journal has none there).
//! - **Only a regular file is a marker.** A symlink, or a directory, at
//!   `node/dirty` is an error, and is never followed.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use radicle::prelude::NodeId;
use serde::{Deserialize, Serialize};

/// The largest marker read: about 20,000 node IDs.
pub const MAX_LEN: u64 = 1 << 20;

/// The marker's path in a Radicle home.
pub fn path(home: &Path) -> PathBuf {
    home.join("node").join("dirty")
}

/// The temporary file a write goes through.
fn staging(home: &Path) -> PathBuf {
    home.join("node").join("dirty.tmp")
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Form {
    node_ids: Vec<String>,
}

/// Why the marker couldn't be read or written.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    NotAFile,
    TooLarge,
    Malformed,
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for Error {
    /// No path: the kind of I/O error alone.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "the dirty marker: {}", e.kind()),
            Self::NotAFile => f.write_str("the dirty marker isn't a file"),
            Self::TooLarge => write!(f, "the dirty marker is larger than {MAX_LEN} bytes"),
            Self::Malformed => f.write_str("the dirty marker doesn't read as one"),
        }
    }
}

impl std::error::Error for Error {}

/// The identities a marker names, in their `z6Mk…` order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Names(BTreeSet<String>);

impl Names {
    /// A marker naming `ids`.
    pub fn of(ids: impl IntoIterator<Item = NodeId>) -> Self {
        Self(ids.into_iter().map(|id| id.to_human()).collect())
    }

    /// These names, and `id`.
    pub fn with(mut self, id: NodeId) -> Self {
        self.0.insert(id.to_human());
        self
    }

    /// The node IDs named, for the reconciliation driver.
    pub fn node_ids(&self) -> BTreeSet<NodeId> {
        // Every name was parsed as a node ID when it was read or added.
        self.0
            .iter()
            .filter_map(|name| NodeId::from_str(name).ok())
            .collect()
    }

    fn encode(&self) -> Vec<u8> {
        // A list of strings always serializes.
        serde_json::to_vec(&Form {
            node_ids: self.0.iter().cloned().collect(),
        })
        .unwrap_or_default()
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let form: Form = serde_json::from_slice(bytes).map_err(|_| Error::Malformed)?;
        let mut names = BTreeSet::new();
        for name in form.node_ids {
            let id = NodeId::from_str(&name).map_err(|_| Error::Malformed)?;
            // The canonical form, so that a name is named once.
            if id.to_human() != name {
                return Err(Error::Malformed);
            }
            names.insert(name);
        }
        Ok(Self(names))
    }
}

/// The marker in `home`, if there is one.
pub fn read(home: &Path) -> Result<Option<Names>, Error> {
    let path = path(home);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if !metadata.file_type().is_file() {
        return Err(Error::NotAFile);
    }
    if metadata.len() > MAX_LEN {
        return Err(Error::TooLarge);
    }
    let mut bytes = Vec::new();
    // Bounded again as it is read: the file may have grown since.
    File::open(&path)?
        .take(MAX_LEN + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_LEN {
        return Err(Error::TooLarge);
    }
    Names::decode(&bytes).map(Some)
}

/// Writes the marker in `home`, naming `names`, durably: once this returns,
/// it is on disk. Its directory, `node/`, is made if there is none.
pub fn write(home: &Path, names: &Names) -> Result<(), Error> {
    let node = home.join("node");
    make_dir(&node)?;
    let staging = staging(home);
    // A staging file left by a killed write is replaced: it was never the
    // marker.
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&staging)?;
    file.write_all(&names.encode())?;
    file.sync_all()?;
    drop(file);
    fs::rename(&staging, path(home))?;
    sync_dir(&node)?;
    Ok(())
}

/// Makes `dir` if it isn't there, and flushes its parent once it is made.
fn make_dir(dir: &Path) -> io::Result<()> {
    match fs::create_dir(dir) {
        Ok(()) => match dir.parent() {
            Some(parent) => sync_dir(parent),
            None => Ok(()),
        },
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn id(byte: u8) -> NodeId {
        let public = ed25519_dalek::SigningKey::from_bytes(&[byte; 32])
            .verifying_key()
            .to_bytes();
        NodeId::from(public)
    }

    #[test]
    fn no_marker_is_none() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(read(home.path()).unwrap(), None);
    }

    #[test]
    fn a_written_marker_reads_back_sorted_and_once() {
        let home = tempfile::tempdir().unwrap();
        let names = Names::of([id(2), id(1)]).with(id(2));
        write(home.path(), &names).unwrap();
        let bytes = fs::read(path(home.path())).unwrap();
        let mut sorted = vec![id(1).to_human(), id(2).to_human()];
        sorted.sort();
        assert_eq!(
            bytes,
            serde_json::to_vec(&serde_json::json!({ "node_ids": sorted })).unwrap()
        );
        assert_eq!(read(home.path()).unwrap(), Some(names));
        assert!(!staging(home.path()).exists());
    }

    #[test]
    fn the_cores_marker_reads() {
        // As the core's switch writes it (`nodes.rs`).
        let home = tempfile::tempdir().unwrap();
        fs::create_dir(home.path().join("node")).unwrap();
        let name = id(7).to_human();
        fs::write(path(home.path()), format!(r#"{{"node_ids":["{name}"]}}"#)).unwrap();
        let names = read(home.path()).unwrap().unwrap();
        assert_eq!(names.node_ids(), [id(7)].into());
    }

    #[test]
    fn what_isnt_a_marker_is_refused_and_left() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir(home.path().join("node")).unwrap();
        for bytes in [
            &b"{not json"[..],
            br#"{"node_ids":["not a node id"]}"#,
            br#"{"node_ids":[],"more":1}"#,
            br#"{"node_ids":"z6Mk"}"#,
            b"[]",
        ] {
            fs::write(path(home.path()), bytes).unwrap();
            assert!(
                matches!(read(home.path()), Err(Error::Malformed)),
                "{}",
                String::from_utf8_lossy(bytes)
            );
            assert_eq!(fs::read(path(home.path())).unwrap(), bytes);
        }
    }

    #[test]
    fn a_marker_past_its_bound_is_refused_before_it_is_read() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir(home.path().join("node")).unwrap();
        let file = File::create(path(home.path())).unwrap();
        file.set_len(MAX_LEN + 1).unwrap();
        assert!(matches!(read(home.path()), Err(Error::TooLarge)));
    }

    #[test]
    fn only_a_regular_file_is_a_marker() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir_all(path(home.path())).unwrap();
        assert!(matches!(read(home.path()), Err(Error::NotAFile)));
        #[cfg(unix)]
        {
            let home = tempfile::tempdir().unwrap();
            fs::create_dir(home.path().join("node")).unwrap();
            let elsewhere = home.path().join("elsewhere");
            fs::write(&elsewhere, br#"{"node_ids":[]}"#).unwrap();
            std::os::unix::fs::symlink(&elsewhere, path(home.path())).unwrap();
            assert!(matches!(read(home.path()), Err(Error::NotAFile)));
        }
    }

    #[test]
    fn a_write_replaces_a_killed_writes_staging_and_the_marker() {
        let home = tempfile::tempdir().unwrap();
        write(home.path(), &Names::of([id(1)])).unwrap();
        fs::write(staging(home.path()), b"half a marker").unwrap();
        write(home.path(), &Names::of([id(3)])).unwrap();
        assert_eq!(read(home.path()).unwrap(), Some(Names::of([id(3)])));
        assert!(!staging(home.path()).exists());
    }
}
