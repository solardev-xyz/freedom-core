//! The profile subcommands (design 0013, PRF-3), run as main runs them:
//! `profile open` and the catalog's operations on disk, their exits, the
//! catalog's write lock against another holder, and the profile gate through
//! `hold-profile` and `profile status`. `profile open`'s time is
//! profile_gate.rs's.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime};

const BIN: &str = env!("CARGO_BIN_EXE_freedom-cored");

struct Dirs {
    _root: tempfile::TempDir,
    app: PathBuf,
    locks: PathBuf,
}

fn dirs() -> Dirs {
    let root = tempfile::tempdir().unwrap();
    // Resolved on Unix (macOS's temp directory is under a symlink); as it is
    // on Windows, where resolving gives a `\\?\` path main never passes.
    let base = if cfg!(windows) {
        root.path().to_path_buf()
    } else {
        std::fs::canonicalize(root.path()).unwrap()
    };
    Dirs {
        app: base.join("app"),
        locks: base.join("locks"),
        _root: root,
    }
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn run(args: &[&str]) -> Output {
    run_env(args, &[])
}

fn run_env(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(BIN);
    command.args(args).stdin(Stdio::null());
    for (key, value) in env {
        command.env(key, value);
    }
    command.output().unwrap()
}

fn json(output: &Output) -> serde_json::Value {
    let text = String::from_utf8(output.stdout.clone()).unwrap();
    serde_json::from_str(text.trim()).unwrap_or_else(|e| panic!("{e}: {text:?}"))
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn open(d: &Dirs, extra: &[&str]) -> Output {
    let mut args = vec![
        "profile",
        "open",
        "--app-root",
        s(&d.app),
        "--lock-dir",
        s(&d.locks),
    ];
    args.extend_from_slice(extra);
    run(&args)
}

/// Sets a directory's mtime `age` before now.
fn backdate(dir: &Path, age: Duration) {
    let time = SystemTime::now() - age;
    let times = std::fs::FileTimes::new()
        .set_accessed(time)
        .set_modified(time);
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .access_mode(0x0100)
            .custom_flags(0x0200_0000)
            .open(dir)
            .unwrap()
    };
    #[cfg(not(windows))]
    let file = std::fs::File::open(dir).unwrap();
    file.set_times(times).unwrap();
}

/// A profile lock as an older build leaves it: the target and the lock
/// directory, its mtime `age` old.
fn profile_lock(dir: &Path, age: Duration) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("profile-open"), "Freedom profile lock target").unwrap();
    let lock = dir.join("profile-open.lock");
    let _ = std::fs::create_dir(&lock);
    backdate(&lock, age);
}

#[test]
fn open_and_the_catalog_operations_on_disk() {
    let d = dirs();
    let out = open(&d, &[]);
    assert_eq!(code(&out), 0, "{out:?}");
    let opened = json(&out);
    assert_eq!(opened["outcome"], "opened");
    assert_eq!(opened["id"], "default");
    // Packaged: the default profile is the app root.
    assert_eq!(opened["user_data_dir"], s(&d.app));
    assert_eq!(opened["slot"], 0);
    assert_eq!(opened["layout"], "root");
    assert_eq!(opened["forget_pending"], 0);
    assert_eq!(opened["lock_fresh"], false);
    assert_eq!(opened["gate_held"], false);
    assert!(opened.get("switch_only").is_none());
    let catalog = std::fs::read_to_string(d.app.join("profile-registry.json")).unwrap();
    assert!(
        catalog.starts_with(
            "{\n  \"version\": 1,\n  \"profiles\": [\n    {\n      \"id\": \"default\""
        )
    );
    assert!(
        !catalog.ends_with('\n'),
        "JSON.stringify's text, no newline"
    );
    // No lock left behind, and no temp file.
    assert!(!d.app.join("profile-registry.write.lock").exists());
    let names: Vec<String> = std::fs::read_dir(&d.app)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(!names.iter().any(|n| n.ends_with(".tmp")), "{names:?}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(d.app.join("profile-registry.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let app = s(&d.app);
    let out = run(&[
        "profile",
        "create",
        "--app-root",
        app,
        "--display-name",
        " Work ",
    ]);
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(json(&out)["record"]["id"], "work");
    assert_eq!(json(&out)["record"]["slot"], 1);
    let out = run(&[
        "profile",
        "create",
        "--app-root",
        app,
        "--display-name",
        "Work",
    ]);
    assert_eq!(code(&out), 65);
    assert_eq!(
        json(&out),
        serde_json::json!({ "error": "refused", "message": "Profile already exists: work" })
    );
    let out = run(&[
        "profile",
        "rename",
        "--app-root",
        app,
        "--id",
        "work",
        "--display-name",
        "Job",
    ]);
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(json(&out)["metadata"]["displayName"], "Job");
    std::fs::create_dir_all(d.app.join("Profiles").join("stray")).unwrap();
    let out = run(&["profile", "list", "--app-root", app, "--active", "work"]);
    let list = json(&out);
    assert_eq!(list.as_array().unwrap().len(), 3);
    assert_eq!(list[1]["isActive"], true);
    assert_eq!(list[2]["isUnregistered"], true);
    let out = run(&["profile", "import", "--app-root", app, "--id", "stray"]);
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(json(&out)["record"]["slot"], 2);
    let out = run(&[
        "profile",
        "reserved-ports",
        "--app-root",
        app,
        "--exclude",
        "work",
    ]);
    assert_eq!(
        json(&out),
        serde_json::json!([11633, 12633, 19150, 11635, 12635, 19152])
    );
    let work = d.app.join("Profiles").join("work");
    let out = run(&[
        "profile",
        "update-nodes",
        "--app-root",
        app,
        "--id",
        "work",
        "--user-data-dir",
        s(&work),
        "--protocol",
        "bee",
        "--updates",
        r#"{"mode":"external","externalApi":"http://127.0.0.1:1633"}"#,
        "--metadata",
        "{}",
    ]);
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(json(&out)["record"]["nodes"]["bee"]["mode"], "external");
    let out = run(&[
        "profile",
        "update-nodes",
        "--app-root",
        app,
        "--id",
        "work",
        "--user-data-dir",
        s(&work),
        "--protocol",
        "swarm",
        "--updates",
        "{}",
        "--metadata",
        "{}",
    ]);
    assert_eq!(code(&out), 65);

    // The profile opened last is what a bare launch opens.
    let out = open(&d, &["--profile", "work"]);
    assert_eq!(json(&out)["id"], "work");
    assert_eq!(json(&open(&d, &[]))["id"], "work");

    // Bad arguments.
    assert_eq!(
        code(&run(&[
            "profile",
            "open",
            "--app-root",
            "relative",
            "--lock-dir",
            s(&d.locks)
        ])),
        64
    );
    assert_eq!(code(&run(&["profile", "create", "--app-root", app])), 64);
    assert_eq!(code(&run(&["profile", "nope", "--app-root", app])), 64);
    assert_eq!(
        code(&run(&[
            "profile",
            "create",
            "--app-root",
            app,
            "--display-name",
            "x",
            "--checkout-hash",
            "XYZ"
        ])),
        64
    );

    // An unsupported catalog: 74, nothing changed.
    std::fs::write(
        d.app.join("profile-registry.json"),
        r#"{"version":2,"profiles":[]}"#,
    )
    .unwrap();
    let out = open(&d, &[]);
    assert_eq!(code(&out), 74);
    assert_eq!(json(&out)["error"], "unsupported");
    assert_eq!(
        std::fs::read_to_string(d.app.join("profile-registry.json")).unwrap(),
        r#"{"version":2,"profiles":[]}"#
    );
}

/// A launch with a new `--profile` registers it (the reference's
/// `ensureProfile`), after `default` on a first run.
#[test]
fn a_new_profile_named_at_launch_is_registered() {
    let d = dirs();
    let out = open(&d, &["--profile", "Job Search"]);
    assert_eq!(code(&out), 0, "{out:?}");
    let opened = json(&out);
    assert_eq!(opened["id"], "job-search");
    assert_eq!(opened["display_name"], "Job Search");
    assert!(
        d.app
            .join("Profiles")
            .join("job-search")
            .join("profile.json")
            .exists()
    );
    // `default` first, at slot 0.
    let catalog: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(d.app.join("profile-registry.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(catalog["profiles"][0]["id"], "default");
    assert_eq!(catalog["profiles"][1]["slot"], 1);
}

/// A subcommand holding the catalog's write lock (the test hook), and a
/// lock an older build left: fresh, they hold off every writer, which gives
/// up with 75 after the reference's retries; stale (past 30 s), it is taken
/// over; and a crashed writer's temp file goes.
#[test]
fn the_catalog_write_lock_against_other_holders() {
    let d = dirs();
    assert_eq!(code(&open(&d, &[])), 0);
    let app = s(&d.app);
    let lock = d.app.join("profile-registry.write.lock");

    // An older build's live lock.
    std::fs::create_dir(&lock).unwrap();
    backdate(&lock, Duration::from_secs(25));
    let started = Instant::now();
    let out = run(&[
        "profile",
        "create",
        "--app-root",
        app,
        "--display-name",
        "A",
    ]);
    assert_eq!(code(&out), 75, "{out:?}");
    assert_eq!(json(&out)["error"], "busy");
    assert!(
        started.elapsed() >= Duration::from_millis(700),
        "five retries, 750 ms"
    );
    assert!(lock.exists(), "a live lock is never taken over");
    // Past the stale time: taken over, then let go.
    backdate(&lock, Duration::from_secs(31));
    std::fs::write(d.app.join("profile-registry.json.4242.tmp"), "torn").unwrap();
    let out = run(&[
        "profile",
        "create",
        "--app-root",
        app,
        "--display-name",
        "A",
    ]);
    assert_eq!(code(&out), 0, "{out:?}");
    assert!(!lock.exists());
    assert!(!d.app.join("profile-registry.json.4242.tmp").exists());

    // A subcommand of ours, held under the lock.
    let marker = d.app.join("held");
    let release = d.app.join("release");
    let hold = format!("{}={}", marker.display(), release.display());
    let mut holder = Command::new(BIN)
        .args([
            "profile",
            "create",
            "--app-root",
            app,
            "--display-name",
            "B",
        ])
        .env("FREEDOM_CORED_TEST_PROFILE_HOLD", &hold)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for(&marker);
    let out = run(&[
        "profile",
        "rename",
        "--app-root",
        app,
        "--id",
        "a",
        "--display-name",
        "C",
    ]);
    assert_eq!(code(&out), 75, "{out:?}");
    let out = open(&d, &[]);
    assert_eq!(code(&out), 75, "{out:?}");
    // Reads take no lock.
    assert_eq!(code(&run(&["profile", "list", "--app-root", app])), 0);
    std::fs::write(&release, "").unwrap();
    let status = holder.wait().unwrap();
    assert_eq!(status.code(), Some(0));
    assert_eq!(
        code(&run(&[
            "profile",
            "rename",
            "--app-root",
            app,
            "--id",
            "a",
            "--display-name",
            "C"
        ])),
        0
    );
}

/// A holder past the update period keeps its lock fresh: the refresher
/// sets the mtime again at 10 s, so another build never sees it stale.
#[test]
fn a_long_holder_refreshes_the_lock() {
    let d = dirs();
    assert_eq!(code(&open(&d, &[])), 0);
    let lock = d.app.join("profile-registry.write.lock");
    let marker = d.app.join("held");
    let release = d.app.join("release");
    let mut holder = Command::new(BIN)
        .args([
            "profile",
            "create",
            "--app-root",
            s(&d.app),
            "--display-name",
            "Long",
        ])
        .env(
            "FREEDOM_CORED_TEST_PROFILE_HOLD",
            format!("{}={}", marker.display(), release.display()),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for(&marker);
    let first = std::fs::metadata(&lock).unwrap().modified().unwrap();
    std::thread::sleep(Duration::from_millis(11_500));
    let later = std::fs::metadata(&lock).unwrap().modified().unwrap();
    assert_ne!(first, later, "refreshed");
    let age = SystemTime::now().duration_since(later).unwrap_or_default();
    assert!(age < Duration::from_secs(5), "fresh: {age:?}");
    std::fs::write(&release, "").unwrap();
    assert_eq!(holder.wait().unwrap().code(), Some(0));
    assert!(!lock.exists());
}

/// A run that loses the catalog's write lock changes nothing, and leaves no
/// directory behind to refuse the next run (review of #336): `profile open`
/// of a new profile, held under the lock while another holder takes it
/// over, exits `lock_lost` with no `Profiles/<id>`, and a retry opens it.
#[test]
fn a_run_that_lost_the_lock_leaves_no_directory() {
    let d = dirs();
    assert_eq!(code(&open(&d, &[])), 0);
    let catalog = std::fs::read(d.app.join("profile-registry.json")).unwrap();
    let lock = d.app.join("profile-registry.write.lock");
    let marker = d.app.join("held");
    let release = d.app.join("release");
    let holder = Command::new(BIN)
        .args([
            "profile",
            "open",
            "--app-root",
            s(&d.app),
            "--lock-dir",
            s(&d.locks),
            "--profile",
            "lost",
        ])
        .env(
            "FREEDOM_CORED_TEST_PROFILE_HOLD",
            format!("{}={}", marker.display(), release.display()),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for(&marker);
    // Another holder's takeover, as the refresher sees it: the mtime isn't
    // the one it set. At its first refresh, 10 s after the lock was taken,
    // it finds the lock lost and sets the mtime no more.
    backdate(&lock, Duration::from_secs(60));
    let taken_over = std::fs::metadata(&lock).unwrap().modified().unwrap();
    std::thread::sleep(Duration::from_millis(11_500));
    assert_eq!(
        std::fs::metadata(&lock).unwrap().modified().unwrap(),
        taken_over,
        "the refresher found the lock lost"
    );
    std::fs::write(&release, "").unwrap();
    let out = holder.wait_with_output().unwrap();
    assert_eq!(code(&out), 74, "{out:?}");
    assert_eq!(json(&out)["error"], "lock_lost");
    let lost = d.app.join("Profiles").join("lost");
    assert!(!lost.exists(), "a directory made under a lost lock");
    assert_eq!(
        std::fs::read(d.app.join("profile-registry.json")).unwrap(),
        catalog
    );
    assert!(lock.exists(), "a lost lock is the new holder's to remove");

    // The other holder lets go; a retry registers and makes the profile.
    std::fs::remove_dir(&lock).unwrap();
    let out = open(&d, &["--profile", "lost"]);
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(json(&out)["id"], "lost");
    assert!(lost.join("profile.json").exists());
}

/// A directory symlink at `link` to `target`; on Windows a junction, which
/// needs no privilege, and which the core refuses as it does a symlink.
fn dir_link(target: &Path, link: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
    #[cfg(windows)]
    {
        let status = Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J");
    }
}

/// Every file in `dir` and below, with its contents.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(at) = stack.pop() {
        for entry in std::fs::read_dir(&at).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let bytes = std::fs::read(&path).unwrap();
                out.push((path, bytes));
            }
        }
    }
    out.sort();
    out
}

/// A symlinked profile directory takes no read or write to its target
/// (review of #336): `Profiles/alias`, a link to another profile's
/// directory, is refused by `import`, `open`, `create` and `update-nodes`
/// (exit 74, `symlink`), and neither the target nor the catalog changes.
/// `profile list` leaves it out, as before.
#[test]
fn a_symlinked_profile_directory_is_refused() {
    let d = dirs();
    let app = s(&d.app);
    assert_eq!(code(&open(&d, &[])), 0);
    let out = run(&[
        "profile",
        "create",
        "--app-root",
        app,
        "--display-name",
        "Victim",
    ]);
    assert_eq!(code(&out), 0, "{out:?}");
    let profiles = d.app.join("Profiles");
    let victim = profiles.join("victim");
    let alias = profiles.join("alias");
    dir_link(&victim, &alias);
    let before = (snapshot(&victim), snapshot(&d.app));
    let refusals = [
        run(&["profile", "import", "--app-root", app, "--id", "alias"]),
        open(&d, &["--profile", "alias"]),
        run(&[
            "profile",
            "create",
            "--app-root",
            app,
            "--display-name",
            "Alias",
        ]),
        run(&[
            "profile",
            "update-nodes",
            "--app-root",
            app,
            "--id",
            "alias",
            "--user-data-dir",
            s(&alias),
            "--protocol",
            "bee",
            "--updates",
            r#"{"mode":"disabled"}"#,
            "--metadata",
            "{}",
        ]),
    ];
    for out in &refusals {
        assert_eq!(code(out), 74, "{out:?}");
        assert_eq!(json(out)["error"], "symlink", "{out:?}");
    }
    assert_eq!((snapshot(&victim), snapshot(&d.app)), before);
    let listed = json(&run(&["profile", "list", "--app-root", app]));
    let ids: Vec<&str> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["default", "victim"]);
}

/// The app root's `Profiles` entry itself a symlink to elsewhere: a new
/// profile is refused (exit 74, `symlink`) and nothing is made there
/// (review of #336).
#[test]
fn a_symlinked_profiles_directory_is_refused() {
    let d = dirs();
    let app = s(&d.app);
    assert_eq!(code(&open(&d, &[])), 0);
    let profiles = d.app.join("Profiles");
    assert!(
        !profiles.exists(),
        "the packaged default lives at the app root"
    );
    let elsewhere = d.app.parent().unwrap().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    dir_link(&elsewhere, &profiles);
    let catalog = std::fs::read(d.app.join("profile-registry.json")).unwrap();
    let refusals = [
        open(&d, &["--profile", "work"]),
        run(&[
            "profile",
            "create",
            "--app-root",
            app,
            "--display-name",
            "Work",
        ]),
        run(&["profile", "list", "--app-root", app]),
    ];
    for out in &refusals {
        assert_eq!(code(out), 74, "{out:?}");
        assert_eq!(json(out)["error"], "symlink", "{out:?}");
    }
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    assert_eq!(
        std::fs::read(d.app.join("profile-registry.json")).unwrap(),
        catalog
    );
    // The default profile, at the app root itself, still opens.
    assert_eq!(code(&open(&d, &[])), 0);
}

fn wait_for(path: &Path) {
    let until = Instant::now() + Duration::from_secs(30);
    while !path.exists() {
        assert!(Instant::now() < until, "{} never appeared", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// `hold-profile`, started as main starts it: `locked` once the gate is
/// held, held until stdin closes.
fn hold_profile(
    user_data_dir: &Path,
    lock_dir: &Path,
    catalog: Option<(&Path, &str)>,
) -> (Child, String) {
    let mut command = Command::new(BIN);
    command.args([
        "hold-profile",
        "--user-data-dir",
        s(user_data_dir),
        "--lock-dir",
        s(lock_dir),
    ]);
    if let Some((app, id)) = catalog {
        command.args(["--app-root", s(app), "--id", id]);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    (child, line)
}

fn status(d: &Dirs, dirs: &[&Path]) -> serde_json::Value {
    let mut args = vec!["profile", "status", "--lock-dir", s(&d.locks)];
    for dir in dirs {
        args.extend_from_slice(&["--user-data-dir", s(dir)]);
    }
    let out = run(&args);
    assert_eq!(code(&out), 0, "{out:?}");
    json(&out)
}

/// "Open" in a new build: a fresh lock, or a held profile gate. The
/// stale-lease case: a lock backdated 31 s reads open while the gate is
/// held, and free once it isn't.
#[test]
fn the_profile_gate_and_status() {
    let d = dirs();
    assert_eq!(code(&open(&d, &["--profile", "work"])), 0);
    let work = d.app.join("Profiles").join("work");
    std::fs::create_dir_all(&d.locks).unwrap();

    let answer = status(&d, &[&work]);
    assert_eq!(answer[0]["open"], false);

    profile_lock(&work, Duration::from_secs(1));
    let answer = status(&d, &[&work]);
    assert_eq!(answer[0]["lock_fresh"], true);
    assert_eq!(answer[0]["open"], true);

    profile_lock(&work, Duration::from_secs(31));
    let answer = status(&d, &[&work]);
    assert_eq!(answer[0]["lock_fresh"], false);
    assert_eq!(answer[0]["open"], false);

    let (mut holder, line) = hold_profile(&work, &d.locks, Some((&d.app, "work")));
    assert_eq!(line, "locked\n");
    let answer = status(&d, &[&work, &d.app]);
    assert_eq!(answer[0]["gate_held"], true);
    assert_eq!(answer[0]["lock_fresh"], false);
    assert_eq!(
        answer[0]["open"], true,
        "a stale lock with the gate held is open"
    );
    assert_eq!(answer[1]["open"], false);
    // `profile open` reports it too.
    let opened = json(&open(&d, &["--profile", "work"]));
    assert_eq!(opened["gate_held"], true);
    // A switch to it is let through, and doesn't mark it opened.
    let before = std::fs::read_to_string(work.join("profile.json")).unwrap();
    let switched = json(&open(&d, &["--switch", "work"]));
    assert_eq!(switched["switch_only"], true);
    assert_eq!(
        std::fs::read_to_string(work.join("profile.json")).unwrap(),
        before
    );
    // A second holder waits out the contention retry, then 75.
    let started = Instant::now();
    let (mut second, line) = hold_profile(&work, &d.locks, None);
    assert_eq!(line, "");
    assert_eq!(second.wait().unwrap().code(), Some(75));
    assert!(started.elapsed() >= Duration::from_secs(4));

    drop(holder.stdin.take());
    assert_eq!(holder.wait().unwrap().code(), Some(0));
    let answer = status(&d, &[&work]);
    assert_eq!(answer[0]["gate_held"], false);
    let refused = json(&open(&d, &["--switch", "work"]));
    assert_eq!(refused["outcome"], "switch_refused");
    assert_eq!(
        refused["message"],
        "Refused an x-freedom-profile switch to \"work\", which is not open"
    );
}

/// `hold-profile` for a catalog profile checks the catalog still lists it at
/// that directory, so a launch that raced a delete fails; and the packaged
/// default profile's gate works with the lock directory inside its app root.
#[test]
fn hold_profile_checks_the_catalog() {
    let d = dirs();
    assert_eq!(code(&open(&d, &["--profile", "work"])), 0);
    let work = d.app.join("Profiles").join("work");
    std::fs::create_dir_all(&d.locks).unwrap();
    let (mut child, line) = hold_profile(&work, &d.locks, Some((&d.app, "gone")));
    assert!(line.contains("no longer in the catalog"), "{line:?}");
    assert_eq!(child.wait().unwrap().code(), Some(65));
    let other = d.app.join("Profiles").join("other");
    std::fs::create_dir_all(&other).unwrap();
    let (mut child, line) = hold_profile(&other, &d.locks, Some((&d.app, "work")));
    assert!(line.contains("no longer in the catalog"), "{line:?}");
    assert_eq!(child.wait().unwrap().code(), Some(65));
    // A directory that isn't there is never made.
    let missing = d.app.join("Profiles").join("missing");
    let (mut child, line) = hold_profile(&missing, &d.locks, None);
    assert_eq!(line, "");
    assert_eq!(child.wait().unwrap().code(), Some(74));
    assert!(!missing.exists());

    // The packaged default profile: its userData is the app root, which
    // holds the lock directory on macOS and Windows.
    let inner = d.app.join("locks");
    std::fs::create_dir_all(&inner).unwrap();
    let (mut child, line) = hold_profile(&d.app, &inner, Some((&d.app, "default")));
    assert_eq!(line, "locked\n");
    let answer = run(&[
        "profile",
        "status",
        "--lock-dir",
        s(&inner),
        "--user-data-dir",
        s(&d.app),
    ]);
    assert_eq!(json(&answer)[0]["gate_held"], true);
    child.stdin.take().unwrap().write_all(b"").unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(0));
}

/// `hold-profile` makes a missing lock directory, as `hold-lock` does: on a
/// machine no new build has run on, nothing else makes it before the first
/// launch's gate. A profile directory that isn't there makes nothing.
#[test]
fn hold_profile_makes_its_lock_directory() {
    let d = dirs();
    assert_eq!(code(&open(&d, &["--profile", "work"])), 0);
    let work = d.app.join("Profiles").join("work");
    let locks = d.locks.join("Freedom").join("locks");
    assert!(!d.locks.exists());

    let missing = d.app.join("Profiles").join("missing");
    let (mut child, line) = hold_profile(&missing, &locks, None);
    assert_eq!(line, "");
    assert_eq!(child.wait().unwrap().code(), Some(74));
    assert!(!missing.exists());
    assert!(!d.locks.exists(), "nothing made for a missing profile");

    let (mut holder, line) = hold_profile(&work, &locks, Some((&d.app, "work")));
    assert_eq!(line, "locked\n");
    assert!(locks.is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for dir in [&d.locks.join("Freedom"), &locks] {
            let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode & 0o077, 0, "{}: {mode:o}", dir.display());
        }
    }
    let answer = run(&[
        "profile",
        "status",
        "--lock-dir",
        s(&locks),
        "--user-data-dir",
        s(&work),
    ]);
    assert_eq!(json(&answer)[0]["gate_held"], true);
    drop(holder.stdin.take());
    assert_eq!(holder.wait().unwrap().code(), Some(0));

    // The packaged default profile's, inside its app root.
    let inner = d.app.join("locks");
    assert!(!inner.exists());
    let (mut child, line) = hold_profile(&d.app, &inner, Some((&d.app, "default")));
    assert_eq!(line, "locked\n");
    assert!(inner.is_dir());
    drop(child.stdin.take());
    assert_eq!(child.wait().unwrap().code(), Some(0));
}
