#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

/// `root`, opened as a writer opens Bee's.
fn top(root: &Path) -> Dir {
    Dir::open_root(root, Resolve::Follow).unwrap().unwrap()
}

#[test]
fn directories_below_the_root_are_reached_through_no_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(root.join("keys")).unwrap();
    std::fs::write(root.join("keys/radicle"), b"key").unwrap();
    let (dir, name) = top(&root)
        .under(&root.join("keys/radicle"), false)
        .unwrap()
        .unwrap();
    assert_eq!(name, "radicle");
    assert_eq!(dir.kind(&name).unwrap(), Kind::File);
    // A missing directory: nothing under it, unless a write makes it.
    assert!(
        top(&root)
            .under(&root.join("node/dirty"), false)
            .unwrap()
            .is_none()
    );
    let (made, _) = top(&root)
        .under(&root.join("node/dirty"), true)
        .unwrap()
        .unwrap();
    assert!(root.join("node").is_dir());
    drop(made);
    // A path outside the root, or with `..`, is refused.
    assert!(
        top(&root)
            .under(&tmp.path().join("other/file"), false)
            .is_err()
    );
    assert!(
        top(&root)
            .under(&root.join("keys/../keys/radicle"), false)
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_directory_below_the_root_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let elsewhere = tmp.path().join("elsewhere");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("radicle"), b"another home's key").unwrap();
    std::os::unix::fs::symlink(&elsewhere, root.join("keys")).unwrap();
    for create in [false, true] {
        assert!(
            top(&root)
                .under(&root.join("keys/radicle"), create)
                .is_err(),
            "create {create}"
        );
    }
    // A file where a directory should be is refused too.
    std::fs::write(root.join("node"), b"not a directory").unwrap();
    assert!(top(&root).under(&root.join("node/dirty"), true).is_err());
    assert_eq!(
        std::fs::read(elsewhere.join("radicle")).unwrap(),
        b"another home's key"
    );
}

#[test]
fn files_are_judged_and_changed_through_the_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (dir, _) = top(root)
        .under(&root.join("a/file"), true)
        .unwrap()
        .unwrap();
    let name = std::ffi::OsStr::new("file");
    assert_eq!(dir.kind(name).unwrap(), Kind::Missing);
    assert!(matches!(
        dir.open_regular(name, false).unwrap(),
        Regular::Missing
    ));
    {
        use std::io::Write as _;
        let mut file = dir.create_new(name).unwrap();
        file.write_all(b"contents").unwrap();
    }
    assert!(dir.create_new(name).is_err(), "create_new replaced a file");
    let Regular::File(handle) = dir.open_regular(name, false).unwrap() else {
        panic!("not opened");
    };
    assert!(dir.same_file(&handle, name).unwrap());
    dir.rename(name, std::ffi::OsStr::new("moved")).unwrap();
    assert!(
        dir.same_file(&handle, std::ffi::OsStr::new("moved"))
            .unwrap()
    );
    assert!(dir.unlink(std::ffi::OsStr::new("moved")).unwrap());
    assert!(!dir.unlink(std::ffi::OsStr::new("moved")).unwrap());
    dir.sync().unwrap();
    // A directory isn't unlinked; a tree is removed whole.
    std::fs::create_dir_all(root.join("a/tree/deep")).unwrap();
    std::fs::write(root.join("a/tree/deep/file"), b"x").unwrap();
    assert!(dir.unlink(std::ffi::OsStr::new("tree")).is_err());
    assert!(dir.remove_tree(std::ffi::OsStr::new("tree")).unwrap());
    assert!(!root.join("a/tree").exists());
    assert!(!dir.remove_tree(std::ffi::OsStr::new("tree")).unwrap());
}

#[cfg(unix)]
#[test]
fn symlinks_are_removed_never_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("keep"), b"keep").unwrap();
    std::os::unix::fs::symlink(outside.join("keep"), root.join("file-link")).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("dir-link")).unwrap();
    let dir = Dir::open_root(&root, Resolve::Follow).unwrap().unwrap();
    assert_eq!(
        dir.kind(std::ffi::OsStr::new("file-link")).unwrap(),
        Kind::Other
    );
    assert!(matches!(
        dir.open_regular(std::ffi::OsStr::new("file-link"), false)
            .unwrap(),
        Regular::Other
    ));
    assert!(dir.unlink(std::ffi::OsStr::new("file-link")).unwrap());
    assert!(dir.remove_tree(std::ffi::OsStr::new("dir-link")).unwrap());
    assert_eq!(std::fs::read(outside.join("keep")).unwrap(), b"keep");
}

/// Review of #177, round 2 (M2): the wipe walks the tree from the held
/// root's handle. The root renamed, with a symlink to another directory
/// holding its own `storage` in its place, the wipe removes the held root's
/// `storage`, never the other's.
#[cfg(unix)]
#[test]
fn the_wipe_stays_in_the_open_root_after_its_path_is_replaced() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let moved = tmp.path().join("moved");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(root.join("storage/deep")).unwrap();
    std::fs::create_dir_all(outside.join("storage")).unwrap();
    std::fs::write(root.join("storage/deep/owned"), b"owned").unwrap();
    std::fs::write(outside.join("storage/keep"), b"keep").unwrap();
    let dir = top(&root);
    std::fs::rename(&root, &moved).unwrap();
    std::os::unix::fs::symlink(&outside, &root).unwrap();
    assert!(dir.remove_tree(std::ffi::OsStr::new("storage")).unwrap());
    assert_eq!(
        std::fs::read(outside.join("storage/keep")).unwrap(),
        b"keep"
    );
    assert!(!moved.join("storage").exists());
}

/// A tree is removed through its own handles: a symlink in it, to a
/// directory or a file outside, is removed itself, and what it points at
/// stays.
#[cfg(unix)]
#[test]
fn a_tree_is_removed_through_its_handles_following_no_link() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(root.join("tree/a/b/c")).unwrap();
    std::fs::create_dir_all(outside.join("inner")).unwrap();
    std::fs::write(outside.join("inner/keep"), b"keep").unwrap();
    std::fs::write(root.join("tree/a/b/c/file"), b"x").unwrap();
    std::fs::write(root.join("tree/top-file"), b"y").unwrap();
    std::os::unix::fs::symlink(&outside, root.join("tree/link-dir")).unwrap();
    std::os::unix::fs::symlink(outside.join("inner"), root.join("tree/a/b/link-dir")).unwrap();
    std::os::unix::fs::symlink(outside.join("inner/keep"), root.join("tree/a/link-file")).unwrap();
    let dir = top(&root);
    assert!(dir.remove_tree(std::ffi::OsStr::new("tree")).unwrap());
    assert!(!root.join("tree").exists());
    assert_eq!(std::fs::read(outside.join("inner/keep")).unwrap(), b"keep");
    assert!(!dir.remove_tree(std::ffi::OsStr::new("tree")).unwrap());
    // A file in the tree's place is removed itself.
    std::fs::write(root.join("tree"), b"z").unwrap();
    assert!(dir.remove_tree(std::ffi::OsStr::new("tree")).unwrap());
    assert!(!root.join("tree").exists());
}

/// Review of #177, round 2 (M1): what a directory opened under the held
/// root does stays in it after its path is replaced by a symlink elsewhere.
#[cfg(unix)]
#[test]
fn file_operations_stay_in_the_directory_opened() {
    use std::ffi::OsStr;
    use std::io::{Read as _, Write as _};
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(root.join("keys")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(root.join("keys/key"), b"original").unwrap();
    std::fs::write(outside.join("key"), b"outside").unwrap();
    let (dir, name) = top(&root)
        .under(&root.join("keys/key"), false)
        .unwrap()
        .unwrap();
    std::fs::rename(root.join("keys"), root.join("old-keys")).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("keys")).unwrap();
    let Regular::File(mut read) = dir.open_regular(&name, false).unwrap() else {
        panic!("missing");
    };
    let mut text = String::new();
    read.read_to_string(&mut text).unwrap();
    assert_eq!(text, "original");
    assert!(dir.same_file(&read, &name).unwrap());
    let mut staged = dir.create_new(OsStr::new("staged")).unwrap();
    staged.write_all(b"new").unwrap();
    drop(staged);
    dir.rename(OsStr::new("staged"), &name).unwrap();
    assert_eq!(std::fs::read(root.join("old-keys/key")).unwrap(), b"new");
    assert!(dir.unlink(&name).unwrap());
    assert_eq!(std::fs::read(outside.join("key")).unwrap(), b"outside");
}

/// A canonical root (a Radicle home's) is the directory at its path, and
/// only that: missing is no target; a file, a symlink in its place, or a
/// symlink above it is refused. Followed (Bee's), a symlink is fine.
#[test]
fn a_canonical_root_is_the_directory_at_its_path() {
    let tmp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(tmp.path()).unwrap();
    let real = base.join("real");
    std::fs::create_dir_all(real.join("inner")).unwrap();
    std::fs::write(base.join("file"), b"x").unwrap();
    let opened = Dir::open_root(&real, Resolve::Canonical(None))
        .unwrap()
        .unwrap();
    assert_eq!(opened.location(), real);
    assert!(
        Dir::open_root(&base.join("missing"), Resolve::Canonical(None))
            .unwrap()
            .is_none()
    );
    assert!(Dir::open_root(&base.join("file"), Resolve::Canonical(None)).is_err());
    assert!(Dir::open_root(&base.join("file"), Resolve::Follow).is_err());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&real, base.join("link")).unwrap();
        assert!(Dir::open_root(&base.join("link"), Resolve::Canonical(None)).is_err());
        assert!(Dir::open_root(&base.join("link/inner"), Resolve::Canonical(None)).is_err());
        assert!(
            Dir::open_root(&base.join("link"), Resolve::Follow)
                .unwrap()
                .is_some()
        );
    }
}

/// Review of #177, round 3 (m1): a canonical root opened with its gate's
/// recorded identity must be that directory.
#[cfg(unix)]
#[test]
fn a_canonical_root_must_be_its_gates_directory() {
    use std::os::unix::fs::MetadataExt;
    let tmp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(tmp.path()).unwrap();
    let real = base.join("real");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::create_dir_all(base.join("other")).unwrap();
    let metadata = std::fs::metadata(&real).unwrap();
    let identity = DirIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    };
    assert!(
        Dir::open_root(&real, Resolve::Canonical(Some(identity)))
            .unwrap()
            .is_some()
    );
    std::fs::rename(&real, base.join("away")).unwrap();
    std::fs::rename(base.join("other"), &real).unwrap();
    assert!(Dir::open_root(&real, Resolve::Canonical(Some(identity))).is_err());
    assert!(
        Dir::open_root(&real, Resolve::Canonical(None))
            .unwrap()
            .is_some()
    );
}

/// Review of #177, round 3 (m2): the wipe holds a bounded number of
/// handles, so a tree deeper than the process may hold descriptors is
/// still removed whole. The removal runs in a child of this test binary
/// whose descriptor limit is 64; the tree is 300 directories deep, with
/// files and a symlink along the way.
#[cfg(unix)]
#[test]
fn a_deep_tree_is_removed_within_a_small_descriptor_limit() {
    const CHILD: &str = "FREEDOM_CORED_TEST_DEEP_TREE";
    if let Some(root) = std::env::var_os(CHILD) {
        use rustix::process::{Resource, Rlimit, setrlimit};
        setrlimit(
            Resource::Nofile,
            Rlimit {
                current: Some(64),
                maximum: Some(64),
            },
        )
        .unwrap();
        let root = PathBuf::from(root);
        assert!(
            top(&root)
                .remove_tree(std::ffi::OsStr::new("tree"))
                .unwrap()
        );
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("keep"), b"keep").unwrap();
    let mut deep = root.join("tree");
    for level in 0..300 {
        deep.push("d");
        std::fs::create_dir_all(&deep).unwrap();
        if level % 50 == 0 {
            std::fs::write(deep.join("file"), b"x").unwrap();
            std::os::unix::fs::symlink(&outside, deep.join("link")).unwrap();
        }
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "anchor::tests::a_deep_tree_is_removed_within_a_small_descriptor_limit",
            "--test-threads=1",
        ])
        .env(CHILD, &root)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "{status}");
    assert!(!root.join("tree").exists());
    assert_eq!(std::fs::read(outside.join("keep")).unwrap(), b"keep");
}
