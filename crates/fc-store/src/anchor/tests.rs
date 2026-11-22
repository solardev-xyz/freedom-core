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

/// A junction at `link` to `target` (`mklink /J`), which an unprivileged
/// process can make, unlike a symlink. Both paths are rebuilt from their
/// components, so that a `/` joined in doesn't read to cmd as a switch.
#[cfg(windows)]
fn junction(link: &Path, target: &Path) {
    let native = |path: &Path| path.components().collect::<PathBuf>();
    let status = std::process::Command::new("cmd")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(native(link))
        .arg(native(target))
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "mklink /J");
}

#[cfg(windows)]
fn sorted(mut names: Vec<OsString>) -> Vec<OsString> {
    names.sort();
    names
}

/// Design 0013, PRF-5i (#963): a directory swapped for a junction between
/// its open and the write redirects nothing. What is read, written, renamed,
/// checked, listed and deleted through the handle stays in the directory
/// opened, nothing lands in the junction's target, and the path walked again
/// meets the junction and refuses it.
#[cfg(windows)]
#[test]
fn a_directory_swapped_for_a_junction_after_its_open_redirects_nothing() {
    use std::ffi::OsStr;
    use std::io::{Read as _, Write as _};
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(root.join("keys")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(root.join("keys/key"), b"original").unwrap();
    std::fs::write(outside.join("key"), b"outside").unwrap();
    let top = top(&root);
    let (dir, name) = top.under(&root.join("keys/key"), true).unwrap().unwrap();
    std::fs::rename(root.join("keys"), root.join("old-keys")).unwrap();
    junction(&root.join("keys"), &outside);
    let Regular::File(mut read) = dir.open_regular(&name, false).unwrap() else {
        panic!("missing");
    };
    let mut text = String::new();
    read.read_to_string(&mut text).unwrap();
    assert_eq!(text, "original");
    assert!(dir.same_file(&read, &name).unwrap());
    let mut staged = dir.create_new(OsStr::new("staged")).unwrap();
    staged.write_all(b"new").unwrap();
    staged.sync_all().unwrap();
    assert!(!dir.same_file(&read, OsStr::new("staged")).unwrap());
    assert!(dir.same_file(&staged, OsStr::new("staged")).unwrap());
    drop((read, staged));
    assert_eq!(dir.kind(OsStr::new("staged")).unwrap(), Kind::File);
    dir.rename(OsStr::new("staged"), &name).unwrap();
    assert_eq!(std::fs::read(root.join("old-keys/key")).unwrap(), b"new");
    assert_eq!(dir.names().unwrap(), std::slice::from_ref(&name));
    // Nothing reached the junction's target, and nothing else is anywhere.
    assert_eq!(std::fs::read(outside.join("key")).unwrap(), b"outside");
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1);
    assert_eq!(
        sorted(top.names().unwrap()),
        [OsString::from("keys"), OsString::from("old-keys")]
    );
    // The path walked again: the junction is refused, writing or not.
    assert!(top.under(&root.join("keys/key"), false).is_err());
    assert!(top.under(&root.join("keys/key"), true).is_err());
    assert_eq!(top.kind(OsStr::new("keys")).unwrap(), Kind::Other);
    assert_eq!(top.subdirs().unwrap(), [OsString::from("old-keys")]);
    // Deleted through the handle, still in the directory opened.
    assert!(dir.unlink(&name).unwrap());
    assert!(!root.join("old-keys/key").exists());
    assert_eq!(std::fs::read(outside.join("key")).unwrap(), b"outside");
    // The directory's identity is its handle's, not the path's.
    let moved = Dir::open_root(&root.join("old-keys"), Resolve::Follow)
        .unwrap()
        .unwrap();
    assert_eq!(dir.identity().unwrap(), moved.identity().unwrap());
}

/// Design 0013, PRF-5i: a reparse point at a child's name is opened itself
/// and refused, never followed, and nothing is made through it. Junctions,
/// which any user can make; a file symlink too where the runner may make
/// one (it needs a privilege or developer mode).
#[cfg(windows)]
#[test]
fn a_reparse_point_at_a_childs_name_is_refused() {
    use std::ffi::OsStr;
    let tmp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(tmp.path()).unwrap();
    let root = base.join("root");
    let outside = base.join("outside");
    std::fs::create_dir_all(root.join("real")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("keep"), b"keep").unwrap();
    junction(&root.join("link"), &outside);
    let top = top(&root);
    let link = OsStr::new("link");
    assert!(top.child(link, false).is_err());
    assert!(top.child(link, true).is_err());
    assert!(top.under(&root.join("link/keep"), false).is_err());
    assert!(top.under(&root.join("link/new/file"), true).is_err());
    assert_eq!(top.kind(link).unwrap(), Kind::Other);
    assert!(matches!(
        top.open_regular(link, false).unwrap(),
        Regular::Other
    ));
    assert!(matches!(
        top.open_regular(link, true).unwrap(),
        Regular::Other
    ));
    assert!(top.create_new(link).is_err());
    assert!(!top.remove_empty(link).unwrap());
    assert_eq!(top.subdirs().unwrap(), [OsString::from("real")]);
    assert_eq!(
        sorted(top.names().unwrap()),
        [OsString::from("link"), OsString::from("real")]
    );
    // Nothing was made through it.
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1);
    // A canonical root may not be one; a followed root may.
    assert!(Dir::open_root(&root.join("link"), Resolve::Canonical(None)).is_err());
    assert!(
        Dir::open_root(&root.join("link"), Resolve::Follow)
            .unwrap()
            .is_some()
    );
    // A file symlink, where one can be made: opened itself and refused.
    let file_link = OsStr::new("file-link");
    if std::os::windows::fs::symlink_file(outside.join("keep"), root.join(file_link)).is_ok() {
        assert_eq!(top.kind(file_link).unwrap(), Kind::Other);
        assert!(matches!(
            top.open_regular(file_link, false).unwrap(),
            Regular::Other
        ));
        assert!(top.child(file_link, true).is_err());
        assert!(top.unlink(file_link).unwrap());
    }
    // Removed, a junction goes itself; its target's files stay.
    assert!(top.unlink(link).unwrap());
    assert_eq!(top.kind(link).unwrap(), Kind::Missing);
    assert_eq!(std::fs::read(outside.join("keep")).unwrap(), b"keep");
}

/// Design 0013, PRF-5i: renames and deletes go by handle, POSIX semantics
/// included (Windows 10 1607 and NTFS, as the runner has): both
/// directories moved after their open, each rename still lands in the one
/// its handle holds, a file open elsewhere is replaced, and a deleted
/// file's name goes at once though a handle is still open on it.
#[cfg(windows)]
#[test]
fn renames_and_deletes_go_by_handle() {
    use std::ffi::OsStr;
    use std::io::Read as _;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(root.join("a")).unwrap();
    std::fs::create_dir_all(root.join("b")).unwrap();
    std::fs::write(root.join("a/one"), b"one").unwrap();
    std::fs::write(root.join("a/two"), b"two").unwrap();
    let top = top(&root);
    let a = top.child(OsStr::new("a"), false).unwrap().unwrap();
    let b = top.child(OsStr::new("b"), false).unwrap().unwrap();
    std::fs::rename(root.join("a"), root.join("a2")).unwrap();
    std::fs::rename(root.join("b"), root.join("b2")).unwrap();
    let mut held = std::fs::File::open(root.join("a2/two")).unwrap();
    a.rename(OsStr::new("one"), OsStr::new("two")).unwrap();
    assert_eq!(std::fs::read(root.join("a2/two")).unwrap(), b"one");
    let mut text = String::new();
    held.read_to_string(&mut text).unwrap();
    assert_eq!(text, "two");
    drop(held);
    a.rename_into(OsStr::new("two"), &b, OsStr::new("three"))
        .unwrap();
    assert!(!root.join("a2/two").exists());
    assert_eq!(std::fs::read(root.join("b2/three")).unwrap(), b"one");
    // A read-only file is deleted, as unlink ignores a file's mode.
    let mut permissions = std::fs::metadata(root.join("b2/three"))
        .unwrap()
        .permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(root.join("b2/three"), permissions).unwrap();
    let held = std::fs::File::open(root.join("b2/three")).unwrap();
    assert!(b.unlink(OsStr::new("three")).unwrap());
    assert!(!root.join("b2/three").exists());
    assert_eq!(b.kind(OsStr::new("three")).unwrap(), Kind::Missing);
    drop(held);
    assert!(!b.unlink(OsStr::new("three")).unwrap());
    // A missing source is an error; nothing is made.
    assert!(a.rename(OsStr::new("gone"), OsStr::new("x")).is_err());
    // A directory isn't replaced by a rename, nor unlinked.
    std::fs::write(root.join("a2/file"), b"x").unwrap();
    std::fs::create_dir(root.join("a2/sub")).unwrap();
    assert!(a.rename(OsStr::new("file"), OsStr::new("sub")).is_err());
    assert!(a.unlink(OsStr::new("sub")).is_err());
    assert!(root.join("a2/sub").is_dir());
    // An empty directory is removed by handle; a full one isn't.
    std::fs::write(root.join("a2/sub/inner"), b"x").unwrap();
    assert!(!a.remove_empty(OsStr::new("sub")).unwrap());
    std::fs::remove_file(root.join("a2/sub/inner")).unwrap();
    assert!(a.remove_empty(OsStr::new("sub")).unwrap());
    assert!(!root.join("a2/sub").exists());
    assert!(!a.remove_empty(OsStr::new("file")).unwrap());
    assert!(!a.remove_empty(OsStr::new("sub")).unwrap());
}

/// Design 0013, PRF-5i: a tree is removed from handle to handle after its
/// path moved, a junction in it removed itself and its target left whole;
/// a junction in the tree's place is removed itself.
#[cfg(windows)]
#[test]
fn a_tree_is_removed_by_handle_leaving_a_junctions_target() {
    use std::ffi::OsStr;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(root.join("parent/tree/a/b")).unwrap();
    std::fs::create_dir_all(outside.join("inner")).unwrap();
    std::fs::write(outside.join("inner/keep"), b"keep").unwrap();
    std::fs::write(root.join("parent/tree/a/b/file"), b"x").unwrap();
    std::fs::write(root.join("parent/tree/top"), b"x").unwrap();
    junction(&root.join("parent/tree/a/link"), &outside);
    let parent = top(&root)
        .child(OsStr::new("parent"), false)
        .unwrap()
        .unwrap();
    std::fs::rename(root.join("parent"), root.join("moved")).unwrap();
    assert!(parent.remove_tree(OsStr::new("tree")).unwrap());
    assert!(!root.join("moved/tree").exists());
    assert_eq!(std::fs::read(outside.join("inner/keep")).unwrap(), b"keep");
    junction(&root.join("moved/tree"), &outside);
    assert!(parent.remove_tree(OsStr::new("tree")).unwrap());
    assert!(!root.join("moved/tree").exists());
    assert_eq!(std::fs::read(outside.join("inner/keep")).unwrap(), b"keep");
    assert!(!parent.remove_tree(OsStr::new("tree")).unwrap());
}

// PRF-9c: a tree walked, copied and removed within one mount (tree.rs).

fn nodes(dir: &Dir, name: &str) -> Vec<(String, Node)> {
    let mut seen = Vec::new();
    dir.walk(OsStr::new(name), &mut |path, node| {
        seen.push((path.to_string_lossy().replace('\\', "/"), node));
        std::ops::ControlFlow::Continue(())
    })
    .unwrap();
    seen.sort_by(|one, two| one.0.cmp(&two.0));
    seen
}

fn nothing() -> io::Result<()> {
    Ok(())
}

#[test]
fn a_walk_visits_each_node_and_follows_no_link() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(root.join("tree/sub")).unwrap();
    std::fs::write(root.join("tree/a"), b"abc").unwrap();
    std::fs::write(root.join("tree/sub/b"), b"").unwrap();
    let dir = top(&root);
    let usable = Node::Dir { usable: true };
    let file = |len| Node::File {
        len,
        readable: true,
    };
    assert_eq!(
        nodes(&dir, "tree"),
        [
            ("tree".to_owned(), usable),
            ("tree/a".to_owned(), file(3)),
            ("tree/sub".to_owned(), usable),
            ("tree/sub/b".to_owned(), file(0)),
        ]
    );
    assert!(nodes(&dir, "missing").is_empty());
    // A break stops it.
    let mut count = 0;
    dir.walk(OsStr::new("tree"), &mut |_, _| {
        count += 1;
        std::ops::ControlFlow::Break(())
    })
    .unwrap();
    assert_eq!(count, 1);
    // A link is visited, never followed; a socket is never opened.
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(tmp.path(), root.join("tree/link")).unwrap();
        let _socket = std::os::unix::net::UnixListener::bind(root.join("tree/sock")).unwrap();
        let seen = nodes(&dir, "tree");
        assert!(seen.contains(&("tree/link".to_owned(), Node::Link)));
        assert!(seen.contains(&("tree/sock".to_owned(), Node::Special)));
        assert_eq!(seen.len(), 6, "{seen:?}");
    }
    #[cfg(windows)]
    {
        junction(&root.join("tree/link"), tmp.path());
        let seen = nodes(&dir, "tree");
        assert!(seen.contains(&("tree/link".to_owned(), Node::Link)));
        assert_eq!(seen.len(), 5, "{seen:?}");
    }
}

/// A directory this process can't use is reported and not entered; a file
/// it can't read is reported. Root may use anything, so this checks only
/// where the modes bind.
#[cfg(unix)]
#[test]
fn a_walk_says_what_this_process_cant_use() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(root.join("tree/shut")).unwrap();
    std::fs::write(root.join("tree/shut/inside"), b"x").unwrap();
    std::fs::write(root.join("tree/secret"), b"x").unwrap();
    let mode = |path: &str, mode| {
        std::fs::set_permissions(root.join(path), std::fs::Permissions::from_mode(mode)).unwrap();
    };
    mode("tree/secret", 0o000);
    mode("tree/shut", 0o500);
    if std::fs::read(root.join("tree/secret")).is_ok() {
        mode("tree/shut", 0o700);
        return;
    }
    let seen = nodes(&top(&root), "tree");
    assert!(seen.contains(&(
        "tree/secret".to_owned(),
        Node::File {
            len: 1,
            readable: false
        }
    )));
    assert!(seen.contains(&("tree/shut".to_owned(), Node::Dir { usable: false })));
    assert!(!seen.iter().any(|(path, _)| path == "tree/shut/inside"));
    mode("tree/shut", 0o700);
}

#[test]
fn a_copy_makes_the_tree_again_and_stops_where_told() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let into = tmp.path().join("into");
    std::fs::create_dir_all(root.join("tree/sub/deeper")).unwrap();
    std::fs::create_dir_all(&into).unwrap();
    std::fs::write(root.join("tree/a"), b"abc").unwrap();
    std::fs::write(root.join("tree/sub/b"), vec![7u8; 200_000]).unwrap();
    std::fs::write(root.join("file"), b"one").unwrap();
    let (dir, target) = (top(&root), top(&into));
    let mut made = 0;
    dir.copy_tree(
        OsStr::new("tree"),
        &target,
        OsStr::new("tree.moving"),
        &mut || {
            made += 1;
            Ok(())
        },
    )
    .unwrap();
    let copy = into.join("tree.moving");
    assert_eq!(std::fs::read(copy.join("a")).unwrap(), b"abc");
    assert_eq!(
        std::fs::read(copy.join("sub/b")).unwrap(),
        vec![7u8; 200_000]
    );
    assert!(copy.join("sub/deeper").is_dir());
    assert_eq!(made, 5, "each entry made");
    assert_eq!(std::fs::read(root.join("tree/a")).unwrap(), b"abc");
    // A file alone; never over what is there.
    dir.copy_tree(
        OsStr::new("file"),
        &target,
        OsStr::new("file.moving"),
        &mut nothing,
    )
    .unwrap();
    assert_eq!(std::fs::read(into.join("file.moving")).unwrap(), b"one");
    let error = dir
        .copy_tree(
            OsStr::new("file"),
            &target,
            OsStr::new("file.moving"),
            &mut nothing,
        )
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    // An error from `each` stops it, and what was made stays.
    let mut calls = 0;
    let error = dir
        .copy_tree(
            OsStr::new("tree"),
            &target,
            OsStr::new("again"),
            &mut || {
                calls += 1;
                if calls == 2 {
                    Err(io::Error::from(io::ErrorKind::StorageFull))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::StorageFull);
    assert!(into.join("again").is_dir());
    // A link is refused on Windows, before anything is made at its name.
    #[cfg(windows)]
    {
        junction(&root.join("tree/link"), tmp.path());
        assert!(
            dir.copy_tree(
                OsStr::new("tree"),
                &target,
                OsStr::new("linked"),
                &mut nothing
            )
            .is_err()
        );
        assert!(!into.join("linked/link").exists());
    }
}

/// On Unix a copy keeps permission bits (the umask applied) and makes a
/// symlink as the link, whatever it points at; a socket stops it.
#[cfg(unix)]
#[test]
fn a_copy_keeps_modes_and_links_and_refuses_a_special_file() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let into = tmp.path().join("into");
    std::fs::create_dir_all(root.join("tree/sub")).unwrap();
    std::fs::create_dir_all(&into).unwrap();
    std::fs::write(root.join("tree/vault"), b"v").unwrap();
    std::fs::write(root.join("tree/sub/shared"), b"s").unwrap();
    let mode = |path: &Path, mode| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    mode(&root.join("tree/vault"), 0o600);
    mode(&root.join("tree/sub/shared"), 0o640);
    mode(&root.join("tree/sub"), 0o750);
    std::os::unix::fs::symlink("sub/shared", root.join("tree/relative")).unwrap();
    std::os::unix::fs::symlink(tmp.path(), root.join("tree/absolute")).unwrap();
    std::os::unix::fs::symlink("nowhere", root.join("tree/dangling")).unwrap();
    std::os::unix::fs::symlink(root.join("tree/sub"), root.join("link")).unwrap();
    let (dir, target) = (top(&root), top(&into));
    dir.copy_tree(
        OsStr::new("tree"),
        &target,
        OsStr::new("copy"),
        &mut nothing,
    )
    .unwrap();
    let copy = into.join("copy");
    let bits = |path: &Path| {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(bits(&copy.join("vault")), 0o600);
    assert_eq!(bits(&copy.join("sub/shared")), 0o640);
    assert_eq!(bits(&copy.join("sub")), 0o750);
    for (name, to) in [
        ("relative", PathBuf::from("sub/shared")),
        ("absolute", tmp.path().to_owned()),
        ("dangling", PathBuf::from("nowhere")),
    ] {
        let link = copy.join(name);
        assert!(
            std::fs::symlink_metadata(&link).unwrap().is_symlink(),
            "{name}"
        );
        assert_eq!(std::fs::read_link(&link).unwrap(), to, "{name}");
    }
    // A symlink at the top is made as the link.
    dir.copy_tree(
        OsStr::new("link"),
        &target,
        OsStr::new("link"),
        &mut nothing,
    )
    .unwrap();
    assert_eq!(
        std::fs::read_link(into.join("link")).unwrap(),
        root.join("tree/sub")
    );
    // A socket inside stops the copy, never opened.
    let _socket = std::os::unix::net::UnixListener::bind(root.join("tree/sub/sock")).unwrap();
    let error = dir
        .copy_tree(
            OsStr::new("tree"),
            &target,
            OsStr::new("again"),
            &mut nothing,
        )
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Other, "{error}");
    assert!(!into.join("again/sub/sock").exists());
}

#[test]
fn a_removal_within_its_mount_calls_back_for_each_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(root.join("tree/sub")).unwrap();
    std::fs::write(root.join("tree/a"), b"a").unwrap();
    std::fs::write(root.join("tree/sub/b"), b"b").unwrap();
    std::fs::write(root.join("file"), b"f").unwrap();
    let dir = top(&root);
    let mut removed = 0;
    let mut count = || {
        removed += 1;
        Ok(())
    };
    assert!(
        dir.remove_tree_within(OsStr::new("tree"), &mut count)
            .unwrap()
    );
    assert!(
        dir.remove_tree_within(OsStr::new("file"), &mut count)
            .unwrap()
    );
    assert!(
        !dir.remove_tree_within(OsStr::new("tree"), &mut count)
            .unwrap()
    );
    assert_eq!(removed, 5);
    assert!(!root.join("tree").exists() && !root.join("file").exists());
    // An error from `each` stops it.
    std::fs::create_dir_all(root.join("tree/sub")).unwrap();
    std::fs::write(root.join("tree/sub/b"), b"b").unwrap();
    let error = dir
        .remove_tree_within(OsStr::new("tree"), &mut || Err(io::Error::other("stop")))
        .unwrap_err();
    assert_eq!(error.to_string(), "stop");
    assert!(root.join("tree/sub").is_dir());
}

#[test]
fn a_directory_s_volume_and_mount_are_read_from_its_handle() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("sub")).unwrap();
    let dir = top(tmp.path());
    let space = dir.space().unwrap();
    assert!(space.block >= 512, "{space:?}");
    assert!(space.available > 0, "{space:?}");
    let sub = dir.child(OsStr::new("sub"), false).unwrap().unwrap();
    assert!(dir.mount().unwrap().same(sub.mount().unwrap()));
}

/// A mount made with `sudo -n` while `FREEDOM_TEST_MOUNTS` is set (CI's
/// Linux step, design 0013's PRF-9c), and unmounted when dropped: a tmpfs
/// owned by this process's user, or a bind mount. `None` without the
/// variable: the test that asks for one then checks nothing.
#[cfg(target_os = "linux")]
struct Mounted(PathBuf);

#[cfg(target_os = "linux")]
impl Mounted {
    fn tmpfs(at: &Path, size: &str) -> Option<Mounted> {
        use std::os::unix::fs::MetadataExt;
        let owner = std::fs::metadata(at).unwrap();
        let options = format!(
            "size={size},mode=0700,uid={},gid={}",
            owner.uid(),
            owner.gid()
        );
        Mounted::run(at, &["-t", "tmpfs", "-o", &options, "tmpfs"])
    }

    /// `from` mounted again at `at` (`mount --bind`): the same file system,
    /// so the same device, on another mount.
    fn bind(from: &Path, at: &Path) -> Option<Mounted> {
        Mounted::run(at, &["--bind", from.to_str().unwrap()])
    }

    fn run(at: &Path, args: &[&str]) -> Option<Mounted> {
        std::env::var_os("FREEDOM_TEST_MOUNTS")?;
        let status = std::process::Command::new("sudo")
            .args(["-n", "mount"])
            .args(args)
            .arg(at)
            .status()
            .unwrap();
        assert!(status.success(), "sudo -n mount {args:?}: {status}");
        Some(Mounted(at.to_owned()))
    }
}

#[cfg(target_os = "linux")]
impl Drop for Mounted {
    fn drop(&mut self) {
        let _ = std::process::Command::new("sudo")
            .args(["-n", "umount", "-l"])
            .arg(&self.0)
            .status();
    }
}

/// A mount point inside a tree: the walk reports it and doesn't enter it,
/// a copy stops there with nothing of the mounted volume copied, and a
/// removal stops there with the volume's file kept; a mount point at the
/// name itself is refused too.
#[cfg(target_os = "linux")]
#[test]
fn mounted_tmpfs_inside_a_tree_is_never_crossed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let into = tmp.path().join("into");
    std::fs::create_dir_all(root.join("tree/mnt")).unwrap();
    std::fs::create_dir_all(&into).unwrap();
    std::fs::write(root.join("tree/file"), b"x").unwrap();
    let Some(_mounted) = Mounted::tmpfs(&root.join("tree/mnt"), "1m") else {
        return;
    };
    std::fs::write(root.join("tree/mnt/kept"), b"kept").unwrap();
    let (dir, target) = (top(&root), top(&into));
    let seen = nodes(&dir, "tree");
    assert!(
        seen.contains(&("tree/mnt".to_owned(), Node::Mount)),
        "{seen:?}"
    );
    assert!(!seen.iter().any(|(path, _)| path.starts_with("tree/mnt/")));
    assert!(
        dir.copy_tree(
            OsStr::new("tree"),
            &target,
            OsStr::new("copy"),
            &mut nothing
        )
        .is_err()
    );
    assert!(!into.join("copy/mnt").exists());
    assert!(
        dir.remove_tree_within(OsStr::new("tree"), &mut nothing)
            .is_err()
    );
    assert_eq!(std::fs::read(root.join("tree/mnt/kept")).unwrap(), b"kept");
    let parent = dir.child(OsStr::new("tree"), false).unwrap().unwrap();
    assert!(
        parent
            .remove_tree_within(OsStr::new("mnt"), &mut nothing)
            .is_err()
    );
    assert_eq!(std::fs::read(root.join("tree/mnt/kept")).unwrap(), b"kept");
    let mounted = parent.child(OsStr::new("mnt"), false).unwrap().unwrap();
    assert!(!mounted.mount().unwrap().same(parent.mount().unwrap()));
}

/// The case `STATX_MNT_ID` is for: a bind mount of the same file system,
/// whose device is its parent's. The walk still reports it as a mount, a
/// copy and a removal refuse it, and the file reached through it survives.
#[cfg(target_os = "linux")]
#[test]
fn mounted_bind_inside_a_tree_is_never_crossed() {
    use std::os::unix::fs::MetadataExt;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let into = tmp.path().join("into");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(root.join("tree/bound")).unwrap();
    std::fs::create_dir_all(&into).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("kept"), b"kept").unwrap();
    std::fs::write(root.join("tree/file"), b"x").unwrap();
    let Some(_mounted) = Mounted::bind(&outside, &root.join("tree/bound")) else {
        return;
    };
    let device = |path: &Path| std::fs::metadata(path).unwrap().dev();
    assert_eq!(device(&root.join("tree/bound")), device(&root.join("tree")));
    let (dir, target) = (top(&root), top(&into));
    let seen = nodes(&dir, "tree");
    assert!(
        seen.contains(&("tree/bound".to_owned(), Node::Mount)),
        "{seen:?}"
    );
    assert!(!seen.iter().any(|(path, _)| path.starts_with("tree/bound/")));
    assert!(
        dir.copy_tree(
            OsStr::new("tree"),
            &target,
            OsStr::new("copy"),
            &mut nothing
        )
        .is_err()
    );
    assert!(!into.join("copy/bound/kept").exists());
    assert!(
        dir.remove_tree_within(OsStr::new("tree"), &mut nothing)
            .is_err()
    );
    let parent = dir.child(OsStr::new("tree"), false).unwrap().unwrap();
    assert!(
        parent
            .remove_tree_within(OsStr::new("bound"), &mut nothing)
            .is_err()
    );
    assert_eq!(std::fs::read(outside.join("kept")).unwrap(), b"kept");
}

/// A directory this process can't change (write and search) can't lose an
/// entry: `may_change` says so. Root may change anything, so this checks
/// only where the modes bind.
#[cfg(unix)]
#[test]
fn a_directory_s_rights_to_change_are_read_from_its_handle() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let shut = tmp.path().join("shut");
    std::fs::create_dir(&shut).unwrap();
    let dir = top(&shut);
    assert!(dir.may_change());
    std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o500)).unwrap();
    let bound = std::fs::write(shut.join("probe"), b"x").is_err();
    if bound {
        assert!(!dir.may_change());
    }
    std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o700)).unwrap();
}

// Races (review of #451): a directory swapped for a link or for another
// directory between its look and its open, and one renamed out of its path
// once opened. The walk, the copy and a bounded removal go from handle to
// handle, so none reaches what the swap put at the name. A path-based
// recursion would.

/// `root/tree/sub/inner` inside, `outside/secret` beyond it, `stash` and
/// `into` beside them.
struct Race {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    outside: PathBuf,
    stash: PathBuf,
    into: PathBuf,
}

fn race() -> Race {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().to_owned();
    let root = base.join("root");
    std::fs::create_dir_all(root.join("tree/sub")).unwrap();
    std::fs::write(root.join("tree/sub/inner"), b"inner").unwrap();
    std::fs::write(root.join("tree/file"), b"file").unwrap();
    std::fs::create_dir_all(base.join("outside")).unwrap();
    std::fs::write(base.join("outside/secret"), b"secret").unwrap();
    std::fs::create_dir_all(base.join("stash")).unwrap();
    std::fs::create_dir_all(base.join("into")).unwrap();
    Race {
        root,
        outside: base.join("outside"),
        stash: base.join("stash"),
        into: base.join("into"),
        _tmp: tmp,
    }
}

/// What a swap puts at `tree/sub` once the original is moved out: a link
/// to `outside` (on Windows a junction), or `outside` itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Swap {
    Link,
    Dir,
}

/// At `point` for `sub`, once: `tree/sub` moved to `stash/sub`, and `swap`
/// put in its place.
fn swap_at(race: &Race, point: &'static str, swap: Swap) {
    let (sub, stash, outside) = (
        race.root.join("tree/sub"),
        race.stash.join("sub"),
        race.outside.clone(),
    );
    let mut done = false;
    super::tree::pause::set(Some(Box::new(move |at, name| {
        if done || at != point || name != "sub" {
            return;
        }
        done = true;
        std::fs::rename(&sub, &stash).unwrap();
        match swap {
            #[cfg(unix)]
            Swap::Link => std::os::unix::fs::symlink(&outside, &sub).unwrap(),
            #[cfg(windows)]
            Swap::Link => junction(&sub, &outside),
            Swap::Dir => std::fs::rename(&outside, &sub).unwrap(),
        }
    })));
}

fn walked(race: &Race) -> (io::Result<()>, Vec<String>) {
    let mut seen = Vec::new();
    let result = top(&race.root).walk(OsStr::new("tree"), &mut |path, _| {
        seen.push(path.to_string_lossy().replace('\\', "/"));
        std::ops::ControlFlow::Continue(())
    });
    super::tree::pause::set(None);
    (result, seen)
}

/// Where `secret` is after the swap: still outside for a link, inside the
/// tree's `sub` for a directory moved in.
#[cfg(unix)]
fn secret(race: &Race, swap: Swap) -> PathBuf {
    match swap {
        Swap::Link => race.outside.join("secret"),
        Swap::Dir => race.root.join("tree/sub/secret"),
    }
}

#[test]
fn a_directory_swapped_between_its_look_and_its_open_is_never_entered() {
    for swap in [Swap::Link, Swap::Dir] {
        let r = race();
        swap_at(&r, "classified", swap);
        let (result, seen) = walked(&r);
        assert!(result.is_err(), "{swap:?}: {seen:?}");
        assert!(
            !seen.iter().any(|path| path.ends_with("secret")),
            "{swap:?}"
        );

        let r = race();
        swap_at(&r, "classified", swap);
        let result = top(&r.root).copy_tree(
            OsStr::new("tree"),
            &top(&r.into),
            OsStr::new("copy"),
            &mut nothing,
        );
        super::tree::pause::set(None);
        assert!(result.is_err(), "{swap:?}");
        assert!(!r.into.join("copy/sub/secret").exists(), "{swap:?}");

        // A bounded removal looks before it opens on Unix (Windows opens
        // each entry once, by handle, and judges that handle).
        #[cfg(unix)]
        {
            let r = race();
            swap_at(&r, "classified", swap);
            let result = top(&r.root).remove_tree_within(OsStr::new("tree"), &mut nothing);
            super::tree::pause::set(None);
            assert_eq!(
                std::fs::read(secret(&r, swap)).unwrap(),
                b"secret",
                "{swap:?}"
            );
            assert_eq!(std::fs::read(r.stash.join("sub/inner")).unwrap(), b"inner");
            if swap == Swap::Dir {
                assert!(result.is_err(), "{swap:?}");
            }
        }
    }
}

#[test]
fn a_directory_renamed_out_once_opened_is_still_the_one_read() {
    let r = race();
    swap_at(&r, "opened", Swap::Link);
    let (result, seen) = walked(&r);
    result.unwrap();
    assert!(seen.contains(&"tree/sub/inner".to_owned()), "{seen:?}");
    assert!(
        !seen.iter().any(|path| path.ends_with("secret")),
        "{seen:?}"
    );

    let r = race();
    swap_at(&r, "opened", Swap::Link);
    let result = top(&r.root).copy_tree(
        OsStr::new("tree"),
        &top(&r.into),
        OsStr::new("copy"),
        &mut nothing,
    );
    super::tree::pause::set(None);
    result.unwrap();
    assert_eq!(
        std::fs::read(r.into.join("copy/sub/inner")).unwrap(),
        b"inner"
    );
    assert!(!r.into.join("copy/sub/secret").exists());

    // The removal empties the directory it opened, wherever it now is, and
    // stops at the link in its old place.
    let r = race();
    swap_at(&r, "opened", Swap::Link);
    let result = top(&r.root).remove_tree_within(OsStr::new("tree"), &mut nothing);
    super::tree::pause::set(None);
    assert!(result.is_err());
    assert_eq!(std::fs::read(r.outside.join("secret")).unwrap(), b"secret");
    assert!(
        !r.stash.join("sub/inner").exists(),
        "the opened directory emptied"
    );
}

/// Windows has no modes: the walk probes the rights a copy and its
/// source's removal take by opening with them. A file whose data can't be
/// read, and a directory that can't be deleted (no `DELETE` on it, and no
/// `FILE_DELETE_CHILD` on its parent), are reported unusable; once the
/// denials go, both are usable.
#[cfg(windows)]
#[test]
fn a_walk_probes_the_rights_a_copy_and_its_removal_take() {
    let icacls = |path: &Path, args: &[&str]| {
        let output = std::process::Command::new("icacls")
            .arg(path)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "icacls {args:?}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    };
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(root.join("tree/kept")).unwrap();
    std::fs::write(root.join("tree/kept/inner"), b"x").unwrap();
    std::fs::write(root.join("tree/secret"), b"abc").unwrap();
    let (tree, kept, secret) = (
        root.join("tree"),
        root.join("tree/kept"),
        root.join("tree/secret"),
    );
    icacls(&secret, &["/deny", "*S-1-1-0:(RD)"]);
    icacls(&kept, &["/deny", "*S-1-1-0:(DE)"]);
    icacls(&tree, &["/deny", "*S-1-1-0:(DC)"]);
    let seen = nodes(&top(&root), "tree");
    for path in [&secret, &kept, &tree] {
        icacls(path, &["/remove:d", "*S-1-1-0"]);
    }
    assert!(
        seen.contains(&(
            "tree/secret".to_owned(),
            Node::File {
                len: 3,
                readable: false
            }
        )),
        "{seen:?}"
    );
    assert!(seen.contains(&("tree/kept".to_owned(), Node::Dir { usable: false })));
    assert!(!seen.iter().any(|(path, _)| path == "tree/kept/inner"));
    let seen = nodes(&top(&root), "tree");
    assert!(seen.contains(&(
        "tree/secret".to_owned(),
        Node::File {
            len: 3,
            readable: true
        }
    )));
    assert!(seen.contains(&("tree/kept".to_owned(), Node::Dir { usable: true })));
}
