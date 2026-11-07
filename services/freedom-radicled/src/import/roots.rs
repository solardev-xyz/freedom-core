//! The import's roots (design 0010, "The Radicle import (D5)"): the
//! directories libgit2 reads a working copy's repository from, found before
//! confinement from the source's own files, without libgit2, each
//! canonical; and main's check of them.
//!
//! **The roots,** as libgit2 1.9 opens a repository at a path, without
//! searching upward (`git_repository_open`), and reads its objects:
//! 1. the source, a directory;
//! 2. its git directory: `.git`, a directory, or the one a `.git` file
//!    names (`gitdir: <path>`, after optional spaces, relative to the
//!    file's directory, the file's trailing whitespace trimmed); with no
//!    `.git`, the source itself, a bare repository;
//! 3. for a linked worktree, the common directory the git directory's
//!    `commondir` file names (relative to the git directory, trimmed);
//! 4. each objects directory `objects/info/alternates` lists, from the
//!    common directory's `objects`: a line per directory, `\r` or `\n`
//!    ending it, empty lines and those starting with `#` skipped, one that
//!    starts with `.` relative to the objects directory listing it, and
//!    recursively, as libgit2 reads them: the alternates of an objects
//!    directory at depth 5 or less ([`ALTERNATES_DEPTH`]). A listed
//!    directory that doesn't exist is skipped, as libgit2 skips it.
//!
//! A root inside another is dropped: the other's grant covers it.
//!
//! **Each root is held open** ([`OpenDir`]): its canonical path opened as a
//! directory, never following a symlink at its last component (on Linux,
//! at any), with its identity (device and inode; on Windows, volume serial
//! number and file ID). Landlock's rules are made from these handles, and
//! the import process finds the roots again once confined, just before the
//! import, and compares them ([`Found::same`]): the decision is bound to
//! the directories, not to their names.
//!
//! **The files read** (a `.git` file, `commondir`, an alternates file) are
//! read before confinement, before any watchdog, so none may block: each
//! must be a regular file, as `symlink_metadata` shows it (a final symlink
//! isn't followed), then is opened never following a final symlink
//! (`O_NOFOLLOW`; on Windows, the reparse point itself) and never waiting
//! (`O_NONBLOCK`: a FIFO opens at once), and must still be a regular file
//! as the handle shows it, and is read to [`MAX_FILE`] at most.
//!
//! **Refused** (`unsupported_layout`), before anything changes:
//! - a source that isn't a directory, or a path that isn't valid Unicode
//!   (main names it in JSON, and libgit2's local transport takes a string);
//! - a `.git` file or a `commondir` that doesn't read as above, or one of
//!   these files, or an alternates file, larger than [`MAX_FILE`], or that
//!   isn't a regular file (a symlink, a FIFO, a directory, a device; a
//!   `.git` may be a symlink to a directory);
//! - a root that can't be opened as above;
//! - an alternate that is relative without a leading `.`: libgit2 reads it
//!   from the process's working directory;
//! - alternates nested deeper than libgit2 reads them: an objects directory
//!   past depth 5 that lists any;
//! - more than [`MAX_ROOTS`] roots;
//! - a root that fails main's check ([`check`]).
//!
//! **What libgit2 reads beyond these** (a configuration `include`, a file
//! the git directory links to outside them) isn't granted: the source's
//! open fails on it, or the import, confined.

use std::collections::BTreeSet;
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

pub use fc_service::confine::{Identity, OpenDir};

/// The most roots an import grants.
pub const MAX_ROOTS: usize = 16;

/// libgit2's `GIT_ALTERNATES_MAX_DEPTH`: it reads the alternates of an
/// objects directory at this depth or less, the repository's own at 0.
pub const ALTERNATES_DEPTH: usize = 5;

/// The largest `.git` file, `commondir` or alternates file read.
pub const MAX_FILE: u64 = 64 * 1024;

/// Why the source's layout isn't supported: `unsupported_layout`'s message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported(pub String);

impl std::fmt::Display for Unsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn unsupported(what: impl Into<String>) -> Unsupported {
    Unsupported(what.into())
}

/// What [`find`] found.
#[derive(Debug)]
pub struct Found {
    /// The source, canonical, and its identity: what `Import::prepare`
    /// opens. It is a root too, unless it lies inside another.
    pub source: (PathBuf, Identity),
    /// The roots, each held open, the source's first unless it lies inside
    /// another.
    pub roots: Vec<OpenDir>,
}

impl Found {
    /// The roots' canonical paths.
    pub fn paths(&self) -> Vec<PathBuf> {
        self.roots.iter().map(|r| r.path().to_path_buf()).collect()
    }

    /// Whether `other` found the same directories: the same source, and the
    /// same roots in the same order, each by its canonical path and its
    /// identity.
    pub fn same(&self, other: &Found) -> bool {
        self.source.0 == other.source.0
            && self.source.1 == other.source.1
            && self.roots.len() == other.roots.len()
            && self
                .roots
                .iter()
                .zip(&other.roots)
                .all(|(a, b)| a.path() == b.path() && a.identity() == b.identity())
    }
}

/// The roots of the working copy at `source`, each canonical and held
/// open. Reads only the source's own files, following symlinks to
/// directories, never to the files it reads.
pub fn find(source: &Path) -> Result<Found, Unsupported> {
    let source = canonical_dir(source, "the source")?;
    let found_source = (source.path().to_path_buf(), source.identity());
    let source_path = found_source.0.clone();
    let mut roots = Roots::default();
    roots.add(source.clone())?;
    let dot_git = source_path.join(".git");
    let git_dir = match std::fs::symlink_metadata(&dot_git) {
        Ok(meta) if meta.is_dir() => canonical_dir(&dot_git, "the git directory")?,
        // A symlinked git directory, as libgit2 follows it. A symlink to
        // anything else is no `.git` file: `read_small` refuses it.
        Ok(meta)
            if meta.file_type().is_symlink()
                && std::fs::metadata(&dot_git).is_ok_and(|target| target.is_dir()) =>
        {
            canonical_dir(&dot_git, "the git directory")?
        }
        Ok(_) => {
            let named = gitdir(&read_small(&dot_git, "the `.git` file")?)?;
            canonical_dir(
                &source_path.join(named),
                "the git directory the `.git` file names",
            )?
        }
        // No `.git`: the source is a bare repository, or nothing libgit2
        // opens.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => source,
        Err(e) => return Err(unsupported(format!("the source's `.git`: {}", e.kind()))),
    };
    let git_path = git_dir.path().to_path_buf();
    roots.add(git_dir)?;
    let commondir = git_path.join("commondir");
    let common = match std::fs::symlink_metadata(&commondir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => git_path,
        Err(e) => return Err(unsupported(format!("`commondir`: {}", e.kind()))),
        Ok(_) => {
            let text = read_small(&commondir, "`commondir`")?;
            let named = trimmed(&text)?;
            if named.is_empty() {
                return Err(unsupported("`commondir` is empty"));
            }
            let common = canonical_dir(&git_path.join(named), "the common directory")?;
            let path = common.path().to_path_buf();
            roots.add(common)?;
            path
        }
    };
    let mut visited = BTreeSet::new();
    alternates(&common.join("objects"), 0, &mut roots, &mut visited)?;
    Ok(Found {
        source: found_source,
        roots: roots.0,
    })
}

/// The roots so far, none inside another.
#[derive(Default)]
struct Roots(Vec<OpenDir>);

impl Roots {
    fn add(&mut self, root: OpenDir) -> Result<(), Unsupported> {
        if self.0.iter().any(|r| root.path().starts_with(r.path())) {
            return Ok(());
        }
        self.0.retain(|r| !r.path().starts_with(root.path()));
        self.0.push(root);
        if self.0.len() > MAX_ROOTS {
            return Err(unsupported(format!(
                "the repository's directories are more than {MAX_ROOTS}"
            )));
        }
        Ok(())
    }
}

/// The alternates of the objects directory `objects`, at `depth`.
fn alternates(
    objects: &Path,
    depth: usize,
    roots: &mut Roots,
    visited: &mut BTreeSet<PathBuf>,
) -> Result<(), Unsupported> {
    let file = objects.join("info").join("alternates");
    match std::fs::symlink_metadata(&file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(unsupported(format!("an alternates file: {}", e.kind()))),
        Ok(_) => {}
    }
    let listed: Vec<String> = read_small(&file, "an alternates file")?
        .split(['\r', '\n'])
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect();
    if listed.is_empty() {
        return Ok(());
    }
    if depth > ALTERNATES_DEPTH {
        return Err(unsupported(format!(
            "the alternates are nested deeper than libgit2 reads them ({ALTERNATES_DEPTH})"
        )));
    }
    for line in listed {
        let path = if line.starts_with('.') {
            objects.join(&line)
        } else if Path::new(&line).is_absolute() {
            PathBuf::from(&line)
        } else {
            return Err(unsupported(
                "an alternate is relative without a leading `.`: libgit2 reads it from the process's working directory",
            ));
        };
        // A listed directory that doesn't exist: libgit2 skips it.
        if !path.is_dir() {
            continue;
        }
        let dir = canonical_dir(&path, "an alternate")?;
        let path = dir.path().to_path_buf();
        if !visited.insert(path.clone()) {
            continue;
        }
        roots.add(dir)?;
        alternates(&path, depth + 1, roots, visited)?;
    }
    Ok(())
}

/// `path`, canonical, held open as a directory ([`OpenDir`]), which must
/// be named in valid Unicode.
fn canonical_dir(path: &Path, what: &str) -> Result<OpenDir, Unsupported> {
    let canonical =
        std::fs::canonicalize(path).map_err(|e| unsupported(format!("{what}: {}", e.kind())))?;
    if canonical.to_str().is_none() {
        return Err(unsupported(format!("{what}'s path isn't valid Unicode")));
    }
    OpenDir::open(&canonical).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotADirectory => unsupported(format!("{what} isn't a directory")),
        kind => unsupported(format!("{what}: {kind}")),
    })
}

/// The file at `path`, a regular file of at most [`MAX_FILE`] bytes of
/// UTF-8, read without following a final symlink and without waiting.
fn read_small(path: &Path, what: &str) -> Result<String, Unsupported> {
    // Never open what isn't a regular file: a FIFO would wait for a writer,
    // before confinement and before any watchdog.
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| unsupported(format!("{what}: {}", e.kind())))?;
    if !is_regular(&metadata) {
        return Err(unsupported(format!("{what} isn't a regular file")));
    }
    let file = open_no_wait(path).map_err(|e| unsupported(format!("{what}: {}", e.kind())))?;
    read_opened(file, what)
}

/// What [`read_small`] reads from `file`, once opened: refused unless the
/// handle shows a regular file (it was replaced since its check), bounded.
fn read_opened(file: File, what: &str) -> Result<String, Unsupported> {
    let metadata = file
        .metadata()
        .map_err(|e| unsupported(format!("{what}: {}", e.kind())))?;
    if !is_regular(&metadata) {
        return Err(unsupported(format!(
            "{what} wasn't a regular file when opened"
        )));
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| unsupported(format!("{what}: {}", e.kind())))?;
    if bytes.len() as u64 > MAX_FILE {
        return Err(unsupported(format!(
            "{what} is larger than {MAX_FILE} bytes"
        )));
    }
    String::from_utf8(bytes).map_err(|_| unsupported(format!("{what} isn't valid UTF-8")))
}

/// `FILE_FLAG_OPEN_REPARSE_POINT`: a symlink (or another reparse point) is
/// opened itself, never its target.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// `FILE_ATTRIBUTE_REPARSE_POINT`: a symlink, a junction or another reparse
/// point.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

/// Opens `path` for reading, never following a symlink at it and never
/// waiting: on Unix `O_NOFOLLOW` and `O_NONBLOCK` (a FIFO opens at once);
/// on Windows a reparse point is opened itself.
fn open_no_wait(path: &Path) -> std::io::Result<File> {
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

/// Whether `metadata` is a regular file's: on Windows, not a reparse
/// point.
fn is_regular(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return false;
        }
    }
    metadata.file_type().is_file()
}

/// `text` with its trailing whitespace trimmed, as libgit2 trims it; empty
/// is refused by the caller.
fn trimmed(text: &str) -> Result<&str, Unsupported> {
    Ok(text.trim_end_matches(|c: char| c.is_ascii_whitespace()))
}

/// The path a `.git` file names.
fn gitdir(text: &str) -> Result<PathBuf, Unsupported> {
    const PREFIX: &str = "gitdir:";
    let text = trimmed(text)?;
    match text.strip_prefix(PREFIX) {
        Some(rest) if !rest.is_empty() => {
            let named = rest.trim_start_matches(|c: char| c.is_ascii_whitespace());
            if named.is_empty() {
                return Err(unsupported("the `.git` file names no directory"));
            }
            Ok(PathBuf::from(named))
        }
        _ => Err(unsupported("the `.git` file isn't `gitdir: <path>`")),
    }
}

/// Main's check of the roots (design 0010, "The recommendation", step 7):
/// none is, contains, or lies inside a protected root. Each protected root
/// is compared canonical: symlinks resolved, and, for one that doesn't
/// exist yet, its longest existing ancestor resolved and the rest appended
/// as named. On macOS and Windows, whose volumes usually fold case, the
/// comparison folds it too.
pub fn check(roots: &[PathBuf], protected: &[PathBuf]) -> Result<(), Unsupported> {
    let protected: Vec<PathBuf> = protected.iter().map(|p| resolved(p)).collect();
    for root in roots {
        let root_folded = fold(root);
        for p in &protected {
            let p = fold(p);
            if root_folded.starts_with(&p) || p.starts_with(&root_folded) {
                return Err(unsupported(
                    "the repository is, contains, or lies inside a directory of Freedom's own",
                ));
            }
        }
    }
    Ok(())
}

/// `path` as the check compares it: canonical as far as it exists, then
/// the rest of its components as named (a `..` among them dropping the one
/// before), absolute.
fn resolved(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let mut existing = absolute.as_path();
    let mut rest = Vec::new();
    loop {
        if let Ok(canonical) = std::fs::canonicalize(existing) {
            let mut out = canonical;
            for component in rest.iter().rev() {
                match component {
                    Component::ParentDir => {
                        out.pop();
                    }
                    Component::CurDir => {}
                    other => out.push(other.as_os_str()),
                }
            }
            return out;
        }
        match (existing.parent(), existing.components().next_back()) {
            (Some(parent), Some(last)) => {
                rest.push(last);
                existing = parent;
            }
            _ => return absolute,
        }
    }
}

/// `path` for comparison: as it is on Linux, case folded on macOS and
/// Windows.
fn fold(path: &Path) -> PathBuf {
    if cfg!(any(target_os = "macos", windows)) {
        PathBuf::from(path.to_string_lossy().to_lowercase())
    } else {
        path.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn dir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(dir.path()).unwrap();
        (dir, path)
    }

    fn mkdir(path: &Path) -> PathBuf {
        std::fs::create_dir_all(path).unwrap();
        std::fs::canonicalize(path).unwrap()
    }

    #[test]
    fn a_working_copy_is_its_source_alone() {
        let (_t, root) = dir();
        let source = mkdir(&root.join("work"));
        mkdir(&source.join(".git/objects"));
        assert_eq!(find(&source).unwrap().paths(), vec![source]);
    }

    #[test]
    fn a_separate_git_directory_and_a_linked_worktree() {
        let (_t, root) = dir();
        let source = mkdir(&root.join("work"));
        let main = mkdir(&root.join("main.git"));
        mkdir(&main.join("objects"));
        let linked = mkdir(&main.join("worktrees/linked"));
        // Relative, with spaces after the prefix and trailing whitespace.
        std::fs::write(
            source.join(".git"),
            "gitdir:  ../main.git/worktrees/linked \r\n",
        )
        .unwrap();
        std::fs::write(linked.join("commondir"), "../..\n").unwrap();
        // The linked git directory lies inside the common one: one root.
        assert_eq!(
            find(&source).unwrap().paths(),
            vec![source.clone(), main.clone()]
        );
        // A git directory outside both the source and its common
        // directory: three roots.
        let apart = mkdir(&root.join("apart"));
        std::fs::write(apart.join("commondir"), format!("{}\n", main.display())).unwrap();
        std::fs::write(source.join(".git"), "gitdir: ../apart\n").unwrap();
        assert_eq!(
            find(&source).unwrap().paths(),
            vec![source.clone(), apart.clone(), main.clone()]
        );
        // An absolute `gitdir:` naming the common directory itself.
        std::fs::write(source.join(".git"), format!("gitdir: {}\n", main.display())).unwrap();
        assert_eq!(find(&source).unwrap().paths(), vec![source, main]);
    }

    #[test]
    fn alternates_recursively_to_libgit2s_depth() {
        let (_t, root) = dir();
        let source = mkdir(&root.join("work"));
        let objects = mkdir(&source.join(".git/objects"));
        // A chain: objects → a1 → … → a6, each listing the next; a6 is read
        // (depth 6), but its own list isn't.
        let mut chain = Vec::new();
        for n in 1..=6 {
            chain.push(mkdir(&root.join(format!("a{n}"))));
        }
        let list = |dir: &Path, line: &str| {
            mkdir(&dir.join("info"));
            std::fs::write(
                dir.join("info/alternates"),
                format!("# a comment\n\n{line}\r\n"),
            )
            .unwrap();
        };
        list(&objects, chain[0].to_str().unwrap());
        for n in 0..5 {
            list(&chain[n], chain[n + 1].to_str().unwrap());
        }
        let mut expected = vec![source.clone()];
        expected.extend(chain.iter().cloned());
        assert_eq!(find(&source).unwrap().paths(), expected);
        // a6 listing one more: deeper than libgit2 reads.
        let a7 = mkdir(&root.join("a7"));
        list(&chain[5], a7.to_str().unwrap());
        let refused = find(&source).unwrap_err();
        assert!(refused.0.contains("nested deeper"), "{refused}");
        // One that doesn't exist is skipped, as libgit2 skips it.
        std::fs::remove_file(chain[5].join("info/alternates")).unwrap();
        list(
            &objects,
            &format!("{}\n{}", root.join("gone").display(), chain[0].display()),
        );
        assert_eq!(find(&source).unwrap().paths(), expected);
    }

    #[test]
    fn a_relative_alternate_and_a_loop() {
        let (_t, root) = dir();
        let source = mkdir(&root.join("work"));
        let objects = mkdir(&source.join(".git/objects"));
        let other = mkdir(&root.join("other/objects"));
        mkdir(&objects.join("info"));
        // `.`-relative to the objects directory listing it.
        std::fs::write(objects.join("info/alternates"), "../../../other/objects\n").unwrap();
        mkdir(&other.join("info"));
        // A loop back to the first: read once.
        std::fs::write(
            other.join("info/alternates"),
            format!("{}\n", objects.display()),
        )
        .unwrap();
        assert_eq!(find(&source).unwrap().paths(), vec![source.clone(), other]);
        // Relative without a `.`: from the working directory, refused.
        std::fs::write(objects.join("info/alternates"), "other/objects\n").unwrap();
        assert!(find(&source).unwrap_err().0.contains("relative"));
    }

    #[test]
    fn layouts_refused() {
        let (_t, root) = dir();
        // Not a directory.
        std::fs::write(root.join("file"), "x").unwrap();
        assert!(find(&root.join("file")).is_err());
        assert!(find(&root.join("missing")).is_err());
        let source = mkdir(&root.join("work"));
        // A malformed `.git` file, and one naming nothing.
        for text in ["not a gitdir", "gitdir:", "gitdir:   \n", ""] {
            std::fs::write(source.join(".git"), text).unwrap();
            assert!(find(&source).is_err(), "{text:?}");
        }
        // Too large.
        std::fs::write(source.join(".git"), "x".repeat(MAX_FILE as usize + 1)).unwrap();
        assert!(find(&source).unwrap_err().0.contains("larger"));
        // More roots than the bound.
        std::fs::remove_file(source.join(".git")).unwrap();
        let objects = mkdir(&source.join(".git/objects"));
        mkdir(&objects.join("info"));
        // 16 roots pass: the source and 15 alternates; 17 don't.
        assert_eq!(MAX_ROOTS, 16);
        let many: Vec<String> = (0..16)
            .map(|n| mkdir(&root.join(format!("m{n}"))).display().to_string())
            .collect();
        std::fs::write(objects.join("info/alternates"), many[..15].join("\n")).unwrap();
        assert_eq!(find(&source).unwrap().roots.len(), 16);
        std::fs::write(objects.join("info/alternates"), many.join("\n")).unwrap();
        assert!(find(&source).unwrap_err().0.contains("more than"));
    }

    /// `f`'s result, or a failure if it hasn't returned within 10 s: what
    /// blocks on a FIFO waits for a writer that never comes.
    fn promptly<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("it waited: a FIFO was opened to be read")
    }

    #[cfg(unix)]
    fn fifo(at: &Path) {
        let made = std::process::Command::new("mkfifo")
            .arg(at)
            .status()
            .unwrap();
        assert!(made.success());
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_or_a_symlink_to_one_at_any_file_read_is_refused_at_once() {
        // Each file discovery reads: the `.git` file, `commondir` and an
        // alternates file, in a layout that reaches it.
        let (_t, root) = dir();
        let source = mkdir(&root.join("work"));
        let main = mkdir(&root.join("main.git"));
        let objects = mkdir(&main.join("objects"));
        mkdir(&objects.join("info"));
        let linked = mkdir(&main.join("worktrees/linked"));
        let files = [
            source.join(".git"),
            linked.join("commondir"),
            objects.join("info/alternates"),
        ];
        let regular = |files: &[PathBuf]| {
            std::fs::write(&files[0], "gitdir: ../main.git/worktrees/linked\n").unwrap();
            std::fs::write(&files[1], "../..\n").unwrap();
            std::fs::write(&files[2], "").unwrap();
        };
        regular(&files);
        assert_eq!(find(&source).unwrap().paths(), vec![source.clone(), main]);
        let elsewhere = root.join("elsewhere");
        for file in &files {
            for linked in [false, true] {
                regular(&files);
                std::fs::remove_file(file).unwrap();
                if linked {
                    let _ = std::fs::remove_file(&elsewhere);
                    fifo(&elsewhere);
                    std::os::unix::fs::symlink(&elsewhere, file).unwrap();
                } else {
                    fifo(file);
                }
                let source = source.clone();
                let refused = promptly(move || find(&source)).unwrap_err();
                assert!(
                    refused.0.contains("isn't a regular file"),
                    "{file:?} (a symlink: {linked}): {refused}"
                );
                // Removed, never written through: a write would wait for a
                // reader.
                std::fs::remove_file(file).unwrap();
            }
        }
        // A symlink to a regular file is refused too: never followed.
        regular(&files);
        let text = root.join("commondir-elsewhere");
        std::fs::write(&text, "../..\n").unwrap();
        std::fs::remove_file(&files[1]).unwrap();
        std::os::unix::fs::symlink(&text, &files[1]).unwrap();
        assert!(
            find(&source)
                .unwrap_err()
                .0
                .contains("isn't a regular file")
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_open_never_waits_and_the_handle_is_checked_again() {
        let (_t, root) = dir();
        let at = root.join("fifo");
        fifo(&at);
        // The FIFO opens at once (no writer is waited for), and the handle
        // shows what it is: refused, as a file replaced after its check is.
        let opened = {
            let at = at.clone();
            promptly(move || open_no_wait(&at))
        };
        let refused = read_opened(opened.unwrap(), "the file").unwrap_err();
        assert!(
            refused.0.contains("wasn't a regular file when opened"),
            "{refused}"
        );
        // A final symlink isn't followed.
        let file = root.join("file");
        std::fs::write(&file, "text").unwrap();
        std::os::unix::fs::symlink(&file, root.join("link")).unwrap();
        assert!(open_no_wait(&root.join("link")).is_err());
        assert_eq!(
            read_opened(open_no_wait(&file).unwrap(), "the file").unwrap(),
            "text"
        );
    }

    #[test]
    fn found_again_is_the_same_only_for_the_same_directories() {
        let (_t, root) = dir();
        let source = mkdir(&root.join("work"));
        mkdir(&source.join(".git/objects"));
        let first = find(&source).unwrap();
        assert!(first.same(&find(&source).unwrap()));
        assert_eq!(first.source.0, source);
        // Another directory at the same path: the same names, not the same
        // directories.
        std::fs::rename(&source, root.join("moved")).unwrap();
        mkdir(&source.join(".git/objects"));
        let again = find(&source).unwrap();
        assert_eq!(again.paths(), first.paths());
        assert!(!first.same(&again));
        // A root more, or fewer.
        let other = mkdir(&root.join("other"));
        mkdir(&source.join(".git/objects/info"));
        std::fs::write(
            source.join(".git/objects/info/alternates"),
            format!("{}\n", other.display()),
        )
        .unwrap();
        let more = find(&source).unwrap();
        assert!(!again.same(&more) && !more.same(&again));
    }

    #[test]
    fn main_check_refuses_a_root_that_is_contains_or_lies_inside_a_protected_one() {
        let (_t, root) = dir();
        let data = mkdir(&root.join("data"));
        let inside = mkdir(&data.join("inside"));
        let sibling = mkdir(&root.join("datas"));
        let protected = vec![data.clone()];
        assert!(check(std::slice::from_ref(&data), &protected).is_err());
        assert!(check(&[inside], &protected).is_err());
        assert!(check(std::slice::from_ref(&root), &protected).is_err());
        // A name that only begins like it is another directory.
        assert!(check(std::slice::from_ref(&sibling), &protected).is_ok());
        // A protected root that doesn't exist yet, and one named through a
        // symlink and a `..`.
        let future = root.join("future/deeper");
        assert!(check(std::slice::from_ref(&root), &[future]).is_err());
        assert!(check(std::slice::from_ref(&sibling), &[root.join("future")]).is_ok());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&data, root.join("link")).unwrap();
            assert!(check(std::slice::from_ref(&data), &[root.join("link")]).is_err());
            assert!(check(&[data.join("x")], &[root.join("datas/../link")]).is_err());
            assert!(check(&[sibling], &[root.join("link")]).is_ok());
        }
    }
}
