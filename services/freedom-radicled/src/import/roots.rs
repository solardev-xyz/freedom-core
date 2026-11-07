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
//! **Refused** (`unsupported_layout`), before anything changes:
//! - a source that isn't a directory, or a path that isn't valid Unicode
//!   (main names it in JSON, and libgit2's local transport takes a string);
//! - a `.git` file or a `commondir` that doesn't read as above, or one of
//!   these files, or an alternates file, larger than [`MAX_FILE`];
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
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

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

/// The roots of the working copy at `source`, each canonical, the source
/// first. Reads only the source's own files, following symlinks.
pub fn find(source: &Path) -> Result<Vec<PathBuf>, Unsupported> {
    let source = canonical_dir(source, "the source")?;
    let mut roots = Roots::default();
    roots.add(source.clone())?;
    let dot_git = source.join(".git");
    let git_dir = match std::fs::metadata(&dot_git) {
        Ok(meta) if meta.is_dir() => canonical_dir(&dot_git, "the git directory")?,
        Ok(meta) if meta.is_file() => {
            let named = gitdir(&read_small(&dot_git, "the `.git` file")?)?;
            canonical_dir(
                &source.join(named),
                "the git directory the `.git` file names",
            )?
        }
        Ok(_) => {
            return Err(unsupported(
                "the source's `.git` isn't a file or a directory",
            ));
        }
        // No `.git`: the source is a bare repository, or nothing libgit2
        // opens.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => source.clone(),
        Err(e) => return Err(unsupported(format!("the source's `.git`: {}", e.kind()))),
    };
    roots.add(git_dir.clone())?;
    let commondir = git_dir.join("commondir");
    let common = if commondir.is_file() {
        let text = read_small(&commondir, "`commondir`")?;
        let named = trimmed(&text)?;
        if named.is_empty() {
            return Err(unsupported("`commondir` is empty"));
        }
        canonical_dir(&git_dir.join(named), "the common directory")?
    } else {
        git_dir
    };
    roots.add(common.clone())?;
    let mut visited = BTreeSet::new();
    alternates(&common.join("objects"), 0, &mut roots, &mut visited)?;
    Ok(roots.0)
}

/// The roots so far, none inside another.
#[derive(Default)]
struct Roots(Vec<PathBuf>);

impl Roots {
    fn add(&mut self, root: PathBuf) -> Result<(), Unsupported> {
        if self.0.iter().any(|r| root.starts_with(r)) {
            return Ok(());
        }
        self.0.retain(|r| !r.starts_with(&root));
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
    if !file.exists() {
        return Ok(());
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
        let path = canonical_dir(&path, "an alternate")?;
        if !visited.insert(path.clone()) {
            continue;
        }
        roots.add(path.clone())?;
        alternates(&path, depth + 1, roots, visited)?;
    }
    Ok(())
}

/// `path`, canonical, which must be a directory named in valid Unicode.
fn canonical_dir(path: &Path, what: &str) -> Result<PathBuf, Unsupported> {
    let canonical =
        std::fs::canonicalize(path).map_err(|e| unsupported(format!("{what}: {}", e.kind())))?;
    if !canonical.is_dir() {
        return Err(unsupported(format!("{what} isn't a directory")));
    }
    if canonical.to_str().is_none() {
        return Err(unsupported(format!("{what}'s path isn't valid Unicode")));
    }
    Ok(canonical)
}

/// The file at `path`, at most [`MAX_FILE`] bytes of UTF-8.
fn read_small(path: &Path, what: &str) -> Result<String, Unsupported> {
    let file =
        std::fs::File::open(path).map_err(|e| unsupported(format!("{what}: {}", e.kind())))?;
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
        assert_eq!(find(&source).unwrap(), vec![source]);
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
        assert_eq!(find(&source).unwrap(), vec![source.clone(), main.clone()]);
        // A git directory outside both the source and its common
        // directory: three roots.
        let apart = mkdir(&root.join("apart"));
        std::fs::write(apart.join("commondir"), format!("{}\n", main.display())).unwrap();
        std::fs::write(source.join(".git"), "gitdir: ../apart\n").unwrap();
        assert_eq!(
            find(&source).unwrap(),
            vec![source.clone(), apart.clone(), main.clone()]
        );
        // An absolute `gitdir:` naming the common directory itself.
        std::fs::write(source.join(".git"), format!("gitdir: {}\n", main.display())).unwrap();
        assert_eq!(find(&source).unwrap(), vec![source, main]);
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
        assert_eq!(find(&source).unwrap(), expected);
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
        assert_eq!(find(&source).unwrap(), expected);
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
        assert_eq!(find(&source).unwrap(), vec![source.clone(), other]);
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
        assert_eq!(find(&source).unwrap().len(), 16);
        std::fs::write(objects.join("info/alternates"), many.join("\n")).unwrap();
        assert!(find(&source).unwrap_err().0.contains("more than"));
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
