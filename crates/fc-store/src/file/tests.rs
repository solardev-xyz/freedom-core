use std::cell::RefCell;
use std::path::PathBuf;

use super::*;
use crate::{NoHooks, Step};

/// Fails one step, and records each temp file `checked` saw.
struct Hooked {
    fail: Option<Step>,
    checked: RefCell<Vec<PathBuf>>,
}

impl Hooked {
    fn failing(step: Step) -> Self {
        Hooked {
            fail: Some(step),
            checked: RefCell::new(Vec::new()),
        }
    }

    fn watching() -> Self {
        Hooked {
            fail: None,
            checked: RefCell::new(Vec::new()),
        }
    }
}

impl Hooks for Hooked {
    fn fails(&self, step: Step) -> bool {
        self.fail == Some(step)
    }

    fn checked(&self, temp: &Path) {
        self.checked.borrow_mut().push(temp.to_owned());
    }
}

/// Every name in `dir` but `keep`.
fn others(dir: &Path, keep: &[&str]) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| !keep.contains(&n.as_str()))
        .collect();
    names.sort();
    names
}

fn store(dir: &Path) -> PathBuf {
    let target = dir.join("dapp-permissions.json");
    std::fs::write(&target, b"old").unwrap();
    target
}

#[test]
fn a_write_replaces_the_file_privately_and_leaves_no_temp() {
    let dir = tempfile::tempdir().unwrap();
    let target = store(dir.path());
    let hooks = Hooked::watching();
    assert_eq!(write_file(&target, b"new", &hooks).unwrap(), Done::Durable);
    assert_eq!(std::fs::read(&target).unwrap(), b"new");
    assert!(others(dir.path(), &["dapp-permissions.json"]).is_empty());
    // `checked` ran once, on the temp file, before its rename.
    let seen = hooks.checked.borrow();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].parent(), Some(dir.path()));
    assert!(!seen[0].exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // A file that isn't there yet is made.
    let fresh = dir.path().join("x402-permissions.json");
    assert_eq!(write_file(&fresh, b"{}", &NoHooks).unwrap(), Done::Durable);
    assert_eq!(std::fs::read(&fresh).unwrap(), b"{}");
}

/// Design 0012, "The files": a write that fails before the rename leaves
/// the file as it was, and no temp file.
#[test]
fn a_failure_before_the_rename_leaves_the_file_as_it_was() {
    for step in [Step::Write, Step::Fsync, Step::Rename] {
        let dir = tempfile::tempdir().unwrap();
        let target = store(dir.path());
        let hooks = Hooked::failing(step);
        let error = write_file(&target, b"new", &hooks).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("test hook: {} fails", step.name()),
            "{step:?}"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"old", "{step:?}");
        assert!(
            others(dir.path(), &["dapp-permissions.json"]).is_empty(),
            "{step:?}"
        );
        // Failed before the temp file was compared with its name.
        assert!(hooks.checked.borrow().is_empty(), "{step:?}");
    }
}

/// The write hook fires before any byte reaches the temp file: a hook that
/// looks in the directory at that point sees an empty temp file.
#[test]
fn the_write_hook_fires_before_the_bytes_are_written() {
    struct Peeking {
        dir: PathBuf,
        sizes: RefCell<Vec<u64>>,
    }
    impl Hooks for Peeking {
        fn fails(&self, step: Step) -> bool {
            if step != Step::Write {
                return false;
            }
            for entry in std::fs::read_dir(&self.dir).unwrap() {
                let entry = entry.unwrap();
                if entry.file_name() != "dapp-permissions.json" {
                    self.sizes
                        .borrow_mut()
                        .push(entry.metadata().unwrap().len());
                }
            }
            true
        }
        fn checked(&self, _temp: &Path) {}
    }
    let dir = tempfile::tempdir().unwrap();
    let target = store(dir.path());
    let hooks = Peeking {
        dir: dir.path().to_owned(),
        sizes: RefCell::new(Vec::new()),
    };
    assert!(write_file(&target, b"new", &hooks).is_err());
    assert_eq!(*hooks.sizes.borrow(), vec![0], "one temp file, still empty");
    assert_eq!(std::fs::read(&target).unwrap(), b"old");
    assert!(others(dir.path(), &["dapp-permissions.json"]).is_empty());
}

/// A failed flush after the rename: the change is in place, not durable,
/// and the failure reported.
#[test]
fn a_failed_flush_is_in_place_and_not_durable() {
    static REPORTED: std::sync::Mutex<Vec<io::ErrorKind>> = std::sync::Mutex::new(Vec::new());
    fn report(kind: io::ErrorKind) {
        REPORTED.lock().unwrap().push(kind);
    }
    // The one test that installs it: no other test's flush fails.
    assert!(fsx::report_flush_failures(report));
    assert!(!fsx::report_flush_failures(|_| {}), "installed once");

    let dir = tempfile::tempdir().unwrap();
    let target = store(dir.path());
    let hooks = Hooked::failing(Step::Flush);
    assert_eq!(
        write_file(&target, b"new", &hooks).unwrap(),
        Done::NotDurable
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"new");
    assert!(others(dir.path(), &["dapp-permissions.json"]).is_empty());
    assert_eq!(hooks.checked.borrow().len(), 1);
    assert_eq!(*REPORTED.lock().unwrap(), [io::ErrorKind::Other]);
}

/// The rename moves only the file written: one swapped in under the temp
/// file's name (at `checked`) is never committed (review of #114). Windows
/// exposes no file identity there (`fsx::same_file`).
#[cfg(unix)]
#[test]
fn a_temp_file_swapped_before_the_rename_is_refused() {
    struct Swap(PathBuf);
    impl Hooks for Swap {
        fn checked(&self, temp: &Path) {
            std::fs::rename(&self.0, temp).unwrap();
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let target = store(dir.path());
    let planted = dir.path().join("planted");
    std::fs::write(&planted, b"planted").unwrap();
    let error = write_file(&target, b"new", &Swap(planted)).unwrap_err();
    assert_eq!(
        error.to_string(),
        "the temp file was replaced before its rename"
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"old");
    assert!(others(dir.path(), &["dapp-permissions.json"]).is_empty());
}

/// A crash between the temp file's creation and its rename leaves it; the
/// next start removes it ([`fsx::remove_temps`] matches the names a write
/// makes), and nothing else.
#[test]
fn a_crashed_writes_temp_file_is_removed_at_start() {
    let dir = tempfile::tempdir().unwrap();
    let target = store(dir.path());
    let hooks = Hooked::watching();
    assert_eq!(write_file(&target, b"new", &hooks).unwrap(), Done::Durable);
    // The temp file's own name, as a process killed before the rename
    // would have left it.
    let temp = hooks.checked.borrow()[0].clone();
    std::fs::write(&temp, b"half").unwrap();
    std::fs::write(dir.path().join("dapp-permissions.json.unreadable"), b"x").unwrap();
    std::fs::write(dir.path().join(".swarm-permissions.json.1.0.tmp"), b"x").unwrap();
    assert_eq!(
        fsx::remove_temps(dir.path(), "dapp-permissions.json").unwrap(),
        1
    );
    assert!(!temp.exists());
    assert_eq!(std::fs::read(&target).unwrap(), b"new");
    assert_eq!(
        others(dir.path(), &["dapp-permissions.json"]),
        [
            ".swarm-permissions.json.1.0.tmp",
            "dapp-permissions.json.unreadable"
        ]
    );
}

#[test]
fn a_bounded_read_takes_a_regular_file_up_to_its_bound() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("phone-payments.json");
    assert_eq!(read_file(&path, 5), Read::Missing);
    std::fs::write(&path, b"12345").unwrap();
    assert_eq!(read_file(&path, 5), Read::Bytes(b"12345".to_vec()));
    assert_eq!(read_file(&path, 6), Read::Bytes(b"12345".to_vec()));
    // One byte past the bound.
    assert_eq!(read_file(&path, 4), Read::Unreadable);
    std::fs::write(&path, b"").unwrap();
    assert_eq!(read_file(&path, 0), Read::Bytes(Vec::new()));
    // A directory is no file.
    assert_eq!(read_file(dir.path(), 5), Read::Unreadable);
}

/// The secret read keeps the plain read's rules.
#[test]
fn a_secret_read_keeps_the_rules() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rpc-api-keys.json");
    assert!(matches!(read_secret_file(&path, 5), SecretRead::Missing));
    std::fs::write(&path, b"12345").unwrap();
    assert!(matches!(read_secret_file(&path, 5), SecretRead::Bytes(b) if &b[..] == b"12345"));
    assert!(matches!(read_secret_file(&path, 4), SecretRead::Unreadable));
    assert!(matches!(
        read_secret_file(dir.path(), 5),
        SecretRead::Unreadable
    ));
    #[cfg(unix)]
    {
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(matches!(read_secret_file(&link, 5), SecretRead::Unreadable));
    }
}

/// #83: a FIFO is refused at once (a blocking open of one with no writer
/// would wait forever), and a symlink is never followed, even to a regular
/// file the user owns.
#[cfg(unix)]
#[test]
fn a_bounded_read_refuses_a_fifo_and_a_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("dapp-permissions.json");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(made.success());
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(read_file(&fifo, 1024));
    });
    assert_eq!(
        finished
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("read_file blocked on a FIFO"),
        Read::Unreadable
    );

    let real = dir.path().join("real.json");
    std::fs::write(&real, b"{}").unwrap();
    let link = dir.path().join("swarm-permissions.json");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(read_file(&link, 1024), Read::Unreadable);
    let dangling = dir.path().join("radicle-permissions.json");
    std::os::unix::fs::symlink(dir.path().join("nothing"), &dangling).unwrap();
    assert_eq!(read_file(&dangling, 1024), Read::Unreadable);
    assert_eq!(read_file(&real, 1024), Read::Bytes(b"{}".to_vec()));
}

/// A file another user owns is unreadable. Giving one away takes root, so
/// this runs only where the test can (not on CI's runners).
#[cfg(unix)]
#[test]
fn a_bounded_read_refuses_a_file_another_user_owns() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dapp-permissions.json");
    std::fs::write(&path, b"{}").unwrap();
    let other = rustix::process::getuid().as_raw().wrapping_add(1);
    if std::os::unix::fs::chown(&path, Some(other), None).is_err() {
        return;
    }
    assert_eq!(read_file(&path, 1024), Read::Unreadable);
}

#[test]
fn an_unreadable_file_is_renamed_aside() {
    let dir = tempfile::tempdir().unwrap();
    let name = "dapp-permissions.json";
    std::fs::write(dir.path().join(name), b"not json").unwrap();
    assert_eq!(set_aside(dir.path(), name).unwrap(), Done::Durable);
    assert!(!dir.path().join(name).exists());
    let aside = dir.path().join("dapp-permissions.json.unreadable");
    assert_eq!(std::fs::read(&aside).unwrap(), b"not json");
    // A later one replaces the earlier.
    std::fs::write(dir.path().join(name), b"again").unwrap();
    assert_eq!(set_aside(dir.path(), name).unwrap(), Done::Durable);
    assert_eq!(std::fs::read(&aside).unwrap(), b"again");
    // Nothing there: an error, and nothing moved.
    assert!(set_aside(dir.path(), name).is_err());
    assert_eq!(std::fs::read(&aside).unwrap(), b"again");
    assert_eq!(
        others(dir.path(), &[]),
        ["dapp-permissions.json.unreadable"]
    );
}
