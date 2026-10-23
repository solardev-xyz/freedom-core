#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

#[test]
fn directories_below_the_root_are_reached_through_no_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(root.join("keys")).unwrap();
    std::fs::write(root.join("keys/radicle"), b"key").unwrap();
    let (dir, name) = Dir::under(&root, &root.join("keys/radicle"), false)
        .unwrap()
        .unwrap();
    assert_eq!(name, "radicle");
    assert_eq!(dir.kind(&name).unwrap(), Kind::File);
    // A missing directory: nothing under it, unless a write makes it.
    assert!(
        Dir::under(&root, &root.join("node/dirty"), false)
            .unwrap()
            .is_none()
    );
    let (made, _) = Dir::under(&root, &root.join("node/dirty"), true)
        .unwrap()
        .unwrap();
    assert!(root.join("node").is_dir());
    drop(made);
    // A path outside the root, or with `..`, is refused.
    assert!(Dir::under(&root, &tmp.path().join("other/file"), false).is_err());
    assert!(Dir::under(&root, &root.join("keys/../keys/radicle"), false).is_err());
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
            Dir::under(&root, &root.join("keys/radicle"), create).is_err(),
            "create {create}"
        );
    }
    // A file where a directory should be is refused too.
    std::fs::write(root.join("node"), b"not a directory").unwrap();
    assert!(Dir::under(&root, &root.join("node/dirty"), true).is_err());
    assert_eq!(
        std::fs::read(elsewhere.join("radicle")).unwrap(),
        b"another home's key"
    );
}

#[test]
fn files_are_judged_and_changed_through_the_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (dir, _) = Dir::under(root, &root.join("a/file"), true)
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
    let dir = Dir::root(&root).unwrap();
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
