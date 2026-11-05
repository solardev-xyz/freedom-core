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
//! - **It is written durably:** to a temporary file beside it,
//!   `node/dirty.tmp`, flushed, renamed into place, and then its directory
//!   flushed (on Unix: Windows has no directory flush, as the core's journal
//!   has none there).
//! - **The temporary file is made new by every write.** Whatever a killed
//!   write left at its path (a file, a symlink, a FIFO) is unlinked, never
//!   opened, so a symlink's target is never touched; a directory there is an
//!   error, and is left. The file is then created exclusively
//!   (`create_new`, which fails on any entry, a dangling symlink too), never
//!   following a symlink (`O_NOFOLLOW`; on Windows,
//!   `FILE_FLAG_OPEN_REPARSE_POINT`).
//! - **Only a regular file is a marker.** A symlink, a directory, a FIFO or
//!   any other entry at `node/dirty` is an error, and is never followed or
//!   read. It is judged on the handle opened: the open never follows a
//!   symlink (as above) and never waits (`O_NONBLOCK`: a FIFO opens at once,
//!   and is then refused); on Windows, a reparse point is refused.

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
    let file = match open_marker(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(refused(&path, e)),
    };
    // Judged on the handle, so nothing swapped in at the path since the
    // open is read.
    let metadata = file.metadata()?;
    if !is_regular(&metadata) {
        return Err(Error::NotAFile);
    }
    if metadata.len() > MAX_LEN {
        return Err(Error::TooLarge);
    }
    let mut bytes = Vec::new();
    // Bounded again as it is read: the file may have grown since.
    file.take(MAX_LEN + 1).read_to_end(&mut bytes)?;
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
    clear_staging(&staging)?;
    let mut file = create_staging(&staging).map_err(|e| refused(&staging, e))?;
    file.write_all(&names.encode())?;
    file.sync_all()?;
    drop(file);
    fs::rename(&staging, path(home))?;
    sync_dir(&node)?;
    Ok(())
}

/// Removes the marker from `home`, durably: once this returns, it is gone
/// from disk (0008: "It is cleared only after a proven clean stop", which
/// the caller proves). The entry is unlinked, never opened, so a symlink's
/// target is untouched; a directory there is an error, and is left, as is
/// anything when the removal fails. No marker is no error.
pub fn remove(home: &Path) -> Result<(), Error> {
    let path = path(home);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_dir() => return Err(Error::NotAFile),
        Ok(_) => match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    sync_dir(&home.join("node"))?;
    Ok(())
}

/// Removes what a killed write left at `staging`, which was never the
/// marker, without opening it: a symlink is unlinked, and its target is
/// untouched. A directory there is an error, and is left.
fn clear_staging(staging: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(staging) {
        Ok(metadata) if metadata.file_type().is_dir() => Err(Error::NotAFile),
        Ok(_) => match fs::remove_file(staging) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// `FILE_FLAG_OPEN_REPARSE_POINT`: open a symlink (or another reparse point)
/// itself, never its target.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// `FILE_ATTRIBUTE_REPARSE_POINT`: a symlink, a junction or another
/// reparse point.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

/// Opens the marker for reading, never following a symlink at `path` and
/// never waiting: on Unix `O_NOFOLLOW` and `O_NONBLOCK` (a FIFO opens at
/// once, and its handle is then refused); on Windows a reparse point is
/// opened itself, and its handle then refused.
fn open_marker(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

/// Creates the staging file, new and regular: `create_new` fails on any
/// entry at `path`, a dangling symlink too, and the open never follows one.
fn create_staging(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

/// An open refused for what is at `path`, without following it: a symlink
/// (`O_NOFOLLOW`'s `ELOOP`), or a directory Windows won't open as a file, is
/// [`Error::NotAFile`]. Anything else is the open's own error.
fn refused(path: &Path, e: io::Error) -> Error {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !is_regular(&metadata) => Error::NotAFile,
        _ => e.into(),
    }
}

/// Whether `metadata` is a regular file's: on Windows, not a reparse point.
fn is_regular(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return false;
        }
    }
    metadata.file_type().is_file()
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

    /// Makes a FIFO at `at`.
    #[cfg(unix)]
    fn fifo(at: &Path) {
        let made = std::process::Command::new("mkfifo")
            .arg(at)
            .status()
            .unwrap();
        assert!(made.success());
    }

    /// `f`'s answer, which must come within 10 s: an open of a FIFO that
    /// waited for its other end would never answer.
    #[cfg(unix)]
    fn without_waiting<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(f());
        });
        finished
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("waited on a FIFO")
    }

    #[test]
    fn only_a_regular_file_is_a_marker() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir_all(path(home.path())).unwrap();
        assert!(matches!(read(home.path()), Err(Error::NotAFile)));
        assert!(path(home.path()).is_dir());
        #[cfg(unix)]
        {
            // A symlink, to a marker or to nothing, is refused, not followed.
            let home = tempfile::tempdir().unwrap();
            fs::create_dir(home.path().join("node")).unwrap();
            let elsewhere = home.path().join("elsewhere");
            fs::write(&elsewhere, br#"{"node_ids":[]}"#).unwrap();
            std::os::unix::fs::symlink(&elsewhere, path(home.path())).unwrap();
            assert!(matches!(read(home.path()), Err(Error::NotAFile)));
            fs::remove_file(path(home.path())).unwrap();
            std::os::unix::fs::symlink(home.path().join("nothing"), path(home.path())).unwrap();
            assert!(matches!(read(home.path()), Err(Error::NotAFile)));

            // A FIFO is refused at once, with no writer at its other end.
            let home = tempfile::tempdir().unwrap();
            fs::create_dir(home.path().join("node")).unwrap();
            fifo(&path(home.path()));
            let at = home.path().to_path_buf();
            assert!(without_waiting(move || matches!(
                read(&at),
                Err(Error::NotAFile)
            )));
        }
    }

    /// Review of #243: a write never opens what a killed write left at the
    /// staging path, so a symlink there can't redirect the write, and the
    /// marker it renames into place is a regular file.
    #[cfg(unix)]
    #[test]
    fn a_staging_symlink_does_not_overwrite_its_target() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir(home.path().join("node")).unwrap();
        let target = home.path().join("target");
        fs::write(&target, b"keep me").unwrap();
        std::os::unix::fs::symlink(&target, staging(home.path())).unwrap();
        write(home.path(), &Names::of([id(1)])).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"keep me");
        assert!(
            fs::symlink_metadata(path(home.path()))
                .unwrap()
                .file_type()
                .is_file()
        );
        assert_eq!(read(home.path()).unwrap(), Some(Names::of([id(1)])));
        assert!(fs::symlink_metadata(staging(home.path())).is_err());

        // A dangling one: nothing is made where it points.
        let nothing = home.path().join("nothing");
        std::os::unix::fs::symlink(&nothing, staging(home.path())).unwrap();
        write(home.path(), &Names::of([id(2)])).unwrap();
        assert!(fs::symlink_metadata(&nothing).is_err());
        assert_eq!(read(home.path()).unwrap(), Some(Names::of([id(2)])));
    }

    /// A FIFO left at the staging path is unlinked, never opened: an open
    /// for writing would wait for a reader.
    #[cfg(unix)]
    #[test]
    fn a_staging_fifo_is_unlinked_without_waiting() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir(home.path().join("node")).unwrap();
        fifo(&staging(home.path()));
        let at = home.path().to_path_buf();
        without_waiting(move || write(&at, &Names::of([id(1)]))).unwrap();
        assert_eq!(read(home.path()).unwrap(), Some(Names::of([id(1)])));
        assert!(fs::symlink_metadata(staging(home.path())).is_err());
    }

    /// A directory at the staging path is refused, and it and the marker
    /// are left as they were.
    #[test]
    fn a_staging_directory_is_refused_and_left() {
        let home = tempfile::tempdir().unwrap();
        write(home.path(), &Names::of([id(1)])).unwrap();
        fs::create_dir(staging(home.path())).unwrap();
        fs::write(staging(home.path()).join("inside"), b"keep me").unwrap();
        assert!(matches!(
            write(home.path(), &Names::of([id(3)])),
            Err(Error::NotAFile)
        ));
        assert_eq!(
            fs::read(staging(home.path()).join("inside")).unwrap(),
            b"keep me"
        );
        assert_eq!(read(home.path()).unwrap(), Some(Names::of([id(1)])));
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

    #[test]
    fn a_removed_marker_is_gone_and_removing_none_is_fine() {
        let home = tempfile::tempdir().unwrap();
        remove(home.path()).unwrap();
        write(home.path(), &Names::of([id(1)])).unwrap();
        remove(home.path()).unwrap();
        assert_eq!(read(home.path()).unwrap(), None);
        assert!(home.path().join("node").is_dir(), "its directory stays");
        remove(home.path()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_marker_symlink_is_unlinked_and_its_target_kept() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir_all(home.path().join("node")).unwrap();
        let target = home.path().join("elsewhere");
        fs::write(&target, b"keep me").unwrap();
        std::os::unix::fs::symlink(&target, path(home.path())).unwrap();
        remove(home.path()).unwrap();
        assert!(fs::symlink_metadata(path(home.path())).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"keep me");
    }

    #[test]
    fn a_marker_directory_is_refused_and_left() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir_all(path(home.path())).unwrap();
        assert!(matches!(remove(home.path()), Err(Error::NotAFile)));
        assert!(path(home.path()).is_dir());
    }
}
