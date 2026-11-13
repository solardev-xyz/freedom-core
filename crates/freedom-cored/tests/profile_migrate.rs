//! `profile migrate --finish-only` (design 0013, 5.4b; PRF-3): the move's
//! recovery, which starts no move, run as main runs it. Before the marker it
//! rolls back, after it rolls forward; an unreadable or ambiguous journal is
//! `corrupt` with nothing changed; any of the move's exclusion held by
//! another is `busy`; a lock taken over mid-run is `lock_lost`; a kill at
//! each step is finished by the next run; and the profile's directory must
//! overlap no other profile and no shared root. A test binary of its own.

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
    base: PathBuf,
    profile: PathBuf,
    locks: PathBuf,
}

fn dirs() -> Dirs {
    let root = tempfile::tempdir().unwrap();
    let base = if cfg!(windows) {
        root.path().to_path_buf()
    } else {
        std::fs::canonicalize(root.path()).unwrap()
    };
    let profile = base.join("profile");
    std::fs::create_dir_all(&profile).unwrap();
    Dirs {
        locks: base.join("locks"),
        profile,
        base,
        _root: root,
    }
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn migrate_env(profile: &Path, locks: &Path, extra: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(BIN);
    command
        .args([
            "profile",
            "migrate",
            "--profile-dir",
            s(profile),
            "--lock-dir",
            s(locks),
            "--finish-only",
        ])
        .args(extra)
        .stdin(Stdio::null());
    for (key, value) in env {
        command.env(key, value);
    }
    command.output().unwrap()
}

fn migrate(d: &Dirs) -> Output {
    migrate_env(&d.profile, &d.locks, &[], &[])
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn said(output: &Output) -> String {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .trim()
        .to_owned()
}

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

/// Every file under `dir`, with its text, sorted: what a refused run must
/// leave as it was. The lock's own files aside.
fn snapshot(dir: &Path) -> Vec<(String, String)> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            let name = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if name.starts_with("profile-open") {
                continue;
            }
            let meta = std::fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                out.push((format!("{name}/"), String::new()));
                walk(&path, base, out);
            } else {
                out.push((name, std::fs::read_to_string(&path).unwrap_or_default()));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn journal(profile: &Path, entries: &[&str]) {
    let names: Vec<String> = entries.iter().map(|e| format!("{e:?}")).collect();
    write(
        &profile.join("freedom").join(".move.json"),
        &format!(r#"{{"version":1,"entries":[{}]}}"#, names.join(",")),
    );
}

fn marker(profile: &Path) {
    write(
        &profile.join("freedom").join("layout.json"),
        r#"{"version":1,"moved_at":"2026-11-13T00:00:00.000Z","by":"test"}"#,
    );
}

/// A move cut short before its marker: `identity` moved with its
/// placeholder left in its place, `ipfs-data` moved, `ant-data` copied
/// across devices and cut short, `settings.json` not moved yet. Beside them
/// the shell's own files, which never move.
fn cut_short(profile: &Path) {
    let freedom = profile.join("freedom");
    write(&freedom.join("identity").join("vault.json"), "vault");
    write(&profile.join("identity"), "moved to freedom/identity");
    write(
        &freedom.join("ipfs-data").join("freedom-ipfs").join("b"),
        "block",
    );
    write(&profile.join("ant-data").join("config.yaml"), "ant");
    write(&freedom.join("ant-data.moving").join("config.yaml"), "an");
    write(&profile.join("settings.json"), "{}");
    write(&profile.join("Cookies"), "cookies");
    write(&profile.join("profile.json"), "{}");
    journal(
        profile,
        &["settings.json", "identity", "ipfs-data", "ant-data"],
    );
}

/// The profile as it was before the move.
fn assert_old_layout(profile: &Path) {
    assert_eq!(
        std::fs::read_to_string(profile.join("identity").join("vault.json")).unwrap(),
        "vault"
    );
    assert_eq!(
        std::fs::read_to_string(profile.join("ipfs-data").join("freedom-ipfs").join("b")).unwrap(),
        "block"
    );
    assert_eq!(
        std::fs::read_to_string(profile.join("ant-data").join("config.yaml")).unwrap(),
        "ant"
    );
    assert_eq!(
        std::fs::read_to_string(profile.join("settings.json")).unwrap(),
        "{}"
    );
    assert_eq!(
        std::fs::read_to_string(profile.join("Cookies")).unwrap(),
        "cookies"
    );
    assert!(!profile.join("freedom").exists(), "freedom/ removed, empty");
}

fn hold_profile(user_data_dir: &Path, lock_dir: &Path) -> Child {
    std::fs::create_dir_all(lock_dir).unwrap();
    let mut child = Command::new(BIN)
        .args([
            "hold-profile",
            "--user-data-dir",
            s(user_data_dir),
            "--lock-dir",
            s(lock_dir),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line, "locked\n");
    child
}

fn hold_lock(data_dir: &Path, lock_dir: &Path) -> Child {
    let mut child = Command::new(BIN)
        .args([
            "hold-lock",
            "--data-dir",
            s(data_dir),
            "--lock-dir",
            s(lock_dir),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line, "locked\n");
    child
}

fn let_go(mut child: Child) {
    child.stdin.take().unwrap().write_all(b"").unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(0));
}

fn wait_for(path: &Path) {
    let until = Instant::now() + Duration::from_secs(20);
    while !path.exists() {
        assert!(Instant::now() < until, "{} never appeared", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn finish_only_is_required_and_nothing_is_nothing() {
    let d = dirs();
    let out = Command::new(BIN)
        .args([
            "profile",
            "migrate",
            "--profile-dir",
            s(&d.profile),
            "--lock-dir",
            s(&d.locks),
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(code(&out), 64, "a move is PRF-9's");

    // No journal: nothing, and the run's lock let go. Its target is left,
    // as main's own lock leaves it.
    let out = migrate(&d);
    assert_eq!((code(&out), said(&out)), (0, "nothing".into()), "{out:?}");
    assert!(!d.profile.join("profile-open.lock").exists());
    assert!(d.profile.join("profile-open").is_file());
    // A marker alone: the move is done.
    marker(&d.profile);
    let out = migrate(&d);
    assert_eq!(said(&out), "nothing");
    // No profile directory at all.
    let out = migrate_env(&d.base.join("missing"), &d.locks, &[], &[]);
    assert_eq!((code(&out), said(&out)), (0, "nothing".into()));
    assert!(!d.base.join("missing").exists());
}

#[test]
fn before_the_marker_it_rolls_back() {
    let d = dirs();
    cut_short(&d.profile);
    let out = migrate(&d);
    assert_eq!(
        (code(&out), said(&out)),
        (0, "rolled_back".into()),
        "{out:?}"
    );
    assert_old_layout(&d.profile);
    // Again: nothing left to do.
    assert_eq!(said(&migrate(&d)), "nothing");
}

#[test]
fn after_the_marker_it_rolls_forward_and_removes_nothing_at_the_root() {
    let d = dirs();
    let freedom = d.profile.join("freedom");
    write(&freedom.join("identity").join("vault.json"), "vault");
    write(&d.profile.join("identity"), "moved to freedom/identity");
    write(&freedom.join("settings.json"), "{}");
    // A cross-device entry's source, or one an older build made since:
    // names can't tell, so it stays for PRF-9's set-aside.
    write(&freedom.join("ant-data").join("config.yaml"), "ant");
    write(&d.profile.join("ant-data").join("config.yaml"), "ant");
    journal(
        &d.profile,
        &["identity", "settings.json", "ant-data", "run"],
    );
    marker(&d.profile);
    let out = migrate(&d);
    assert_eq!((code(&out), said(&out)), (0, "migrated".into()), "{out:?}");
    assert!(!freedom.join(".move.json").exists());
    assert!(freedom.join("layout.json").is_file());
    assert_eq!(
        std::fs::read_to_string(freedom.join("identity").join("vault.json")).unwrap(),
        "vault"
    );
    assert!(
        d.profile.join("identity").is_file(),
        "the placeholder stays"
    );
    assert!(d.profile.join("ant-data").join("config.yaml").is_file());
    assert_eq!(said(&migrate(&d)), "nothing");
}

#[test]
fn a_journal_it_cant_read_or_settle_is_corrupt_with_nothing_changed() {
    let journals = [
        "not json".to_owned(),
        r#"{"version":2,"entries":[]}"#.to_owned(),
        // A shared entry of the app root, and the shell's own.
        r#"{"version":1,"entries":["Profiles"]}"#.to_owned(),
        r#"{"version":1,"entries":["locks"]}"#.to_owned(),
        r#"{"version":1,"entries":["profile.json"]}"#.to_owned(),
        r#"{"version":1,"entries":["../identity"]}"#.to_owned(),
        "x".repeat(20_000),
    ];
    for text in &journals {
        let d = dirs();
        cut_short(&d.profile);
        write(&d.profile.join("freedom").join(".move.json"), text);
        let before = snapshot(&d.profile);
        let out = migrate(&d);
        assert_eq!(
            (code(&out), said(&out)),
            (74, "corrupt".into()),
            "{text:.40}: {out:?}"
        );
        assert_eq!(snapshot(&d.profile), before, "{text:.40}");
        assert!(!d.profile.join("profile-open.lock").exists());
    }

    // Ambiguous before the marker: an entry at both places (a finished
    // copy and its source, or a root entry made since).
    let d = dirs();
    cut_short(&d.profile);
    write(&d.profile.join("freedom").join("settings.json"), "{}");
    let before = snapshot(&d.profile);
    let out = migrate(&d);
    assert_eq!((code(&out), said(&out)), (74, "corrupt".into()), "{out:?}");
    assert_eq!(snapshot(&d.profile), before);
    // A copy cut short whose source is gone.
    let d = dirs();
    journal(&d.profile, &["ant-data"]);
    write(
        &d.profile.join("freedom").join("ant-data.moving").join("x"),
        "x",
    );
    let before = snapshot(&d.profile);
    assert_eq!(said(&migrate(&d)), "corrupt");
    assert_eq!(snapshot(&d.profile), before);
    // After the marker: an entry still at the root alone, or a copy still in
    // progress.
    for setup in [
        |p: &Path| write(&p.join("settings.json"), "{}"),
        |p: &Path| {
            write(&p.join("freedom").join("settings.json"), "{}");
            write(&p.join("freedom").join("settings.json.moving"), "{");
        },
    ] {
        let d = dirs();
        setup(&d.profile);
        journal(&d.profile, &["settings.json"]);
        marker(&d.profile);
        let before = snapshot(&d.profile);
        assert_eq!(said(&migrate(&d)), "corrupt");
        assert_eq!(snapshot(&d.profile), before);
    }
}

#[test]
fn any_of_its_exclusion_held_by_another_is_busy() {
    // The profile gate, held by a new build's holder.
    let d = dirs();
    cut_short(&d.profile);
    let before = snapshot(&d.profile);
    let holder = hold_profile(&d.profile, &d.locks);
    let out = migrate(&d);
    assert_eq!((code(&out), said(&out)), (75, "busy".into()), "{out:?}");
    assert_eq!(snapshot(&d.profile), before);
    let_go(holder);

    // A fresh profile lock: an older build has the profile.
    std::fs::create_dir(d.profile.join("profile-open.lock")).unwrap();
    backdate(
        &d.profile.join("profile-open.lock"),
        Duration::from_secs(20),
    );
    let out = migrate(&d);
    assert_eq!((code(&out), said(&out)), (75, "busy".into()), "{out:?}");
    assert_eq!(snapshot(&d.profile), before);
    assert!(
        d.profile.join("profile-open.lock").is_dir(),
        "another's lock stays"
    );

    // The core's gate on the identity's new path, and on its old one
    // (where the placeholder is a file, gated at its path), and
    // freedom-ipfsd's.
    std::fs::remove_dir(d.profile.join("profile-open.lock")).unwrap();
    let core = hold_lock(&d.profile.join("freedom").join("identity"), &d.locks);
    let out = migrate(&d);
    assert_eq!((code(&out), said(&out)), (75, "busy".into()), "{out:?}");
    assert_eq!(snapshot(&d.profile), before);
    let_go(core);
    let ipfs_dir = d
        .profile
        .join("freedom")
        .join("ipfs-data")
        .join("freedom-ipfs");
    let ipfs_gate = d.locks.join(fc_service_lock_name("ipfs", &ipfs_dir));
    let ipfs = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&ipfs_gate)
        .unwrap();
    ipfs.lock().unwrap();
    let out = migrate(&d);
    assert_eq!((code(&out), said(&out)), (75, "busy".into()), "{out:?}");
    assert_eq!(snapshot(&d.profile), before);
    ipfs.unlock().unwrap();

    // A stale lock with every gate free: a crashed process's, taken over.
    std::fs::create_dir(d.profile.join("profile-open.lock")).unwrap();
    backdate(
        &d.profile.join("profile-open.lock"),
        Duration::from_secs(31),
    );
    let out = migrate(&d);
    assert_eq!(
        (code(&out), said(&out)),
        (0, "rolled_back".into()),
        "{out:?}"
    );
    assert_old_layout(&d.profile);
    assert!(!d.profile.join("profile-open.lock").exists());
}

/// `<namespace>-<sha256(canonical dir)>.lock`, fc-service's gate name.
fn fc_service_lock_name(namespace: &str, dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(dir.as_os_str().as_encoded_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("{namespace}-{hex}.lock")
}

#[test]
fn it_holds_the_profile_lock_while_it_runs_and_stops_once_it_is_lost() {
    let d = dirs();
    cut_short(&d.profile);
    let before = snapshot(&d.profile);
    let lock = d.profile.join("profile-open.lock");
    let marker_file = d.base.join("held");
    let release = d.base.join("release");
    let hold = format!("{}={}", marker_file.display(), release.display());
    // A dev build's timings: 5 s stale, refreshed every second.
    let child = Command::new(BIN)
        .args([
            "profile",
            "migrate",
            "--profile-dir",
            s(&d.profile),
            "--lock-dir",
            s(&d.locks),
            "--dev",
            "--finish-only",
        ])
        .env("FREEDOM_CORED_TEST_PROFILE_HOLD", &hold)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for(&marker_file);
    let first = std::fs::metadata(&lock).unwrap().modified().unwrap();
    std::thread::sleep(Duration::from_millis(2_500));
    let later = std::fs::metadata(&lock).unwrap().modified().unwrap();
    assert_ne!(first, later, "refreshed past the update period");
    // Another build takes the lock over: the mtime isn't the run's.
    backdate(&lock, Duration::from_secs(60));
    std::thread::sleep(Duration::from_millis(1_500));
    std::fs::write(&release, "").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        (code(&out), said(&out)),
        (74, "lock_lost".into()),
        "{out:?}"
    );
    assert_eq!(
        snapshot(&d.profile),
        before,
        "nothing changed, journal kept"
    );
    assert!(lock.is_dir(), "the other's lock stays");

    // The next start, once that lock is stale, finishes it.
    backdate(&lock, Duration::from_secs(60));
    let out = migrate_env(&d.profile, &d.locks, &["--dev"], &[]);
    assert_eq!(said(&out), "rolled_back", "{out:?}");
    assert_old_layout(&d.profile);
}

#[test]
fn a_kill_at_each_step_is_finished_by_the_next_run() {
    for step in ["after-exclusion", "mid-recovery", "before-journal-removed"] {
        let d = dirs();
        cut_short(&d.profile);
        let out = migrate_env(
            &d.profile,
            &d.locks,
            &[],
            &[("FREEDOM_CORED_TEST_PROFILE_MIGRATE_CRASH", step)],
        );
        assert_eq!(code(&out), 99, "{step}: {out:?}");
        assert!(
            d.profile.join("freedom").join(".move.json").is_file(),
            "{step}"
        );
        // Its lock left fresh, as a killed process leaves it: the next start
        // waits it out.
        backdate(
            &d.profile.join("profile-open.lock"),
            Duration::from_secs(31),
        );
        let out = migrate(&d);
        assert_eq!(said(&out), "rolled_back", "{step}: {out:?}");
        assert_old_layout(&d.profile);
    }
    // After the marker.
    let d = dirs();
    write(&d.profile.join("freedom").join("settings.json"), "{}");
    journal(&d.profile, &["settings.json"]);
    marker(&d.profile);
    let out = migrate_env(
        &d.profile,
        &d.locks,
        &[],
        &[(
            "FREEDOM_CORED_TEST_PROFILE_MIGRATE_CRASH",
            "before-journal-removed",
        )],
    );
    assert_eq!(code(&out), 99);
    backdate(
        &d.profile.join("profile-open.lock"),
        Duration::from_secs(31),
    );
    assert_eq!(said(&migrate(&d)), "migrated");
}

#[test]
fn it_acts_only_on_a_profiles_own_directory() {
    let d = dirs();
    let app = d.base.join("app");
    let work = app.join("Profiles").join("work");
    let catalog = |extra: &str| {
        format!(
            r#"{{"version":1,"profiles":[{{"id":"default","dir":{:?}}},{{"id":"work","dir":{:?}}}{extra}]}}"#,
            s(&app),
            s(&work)
        )
    };
    write(&app.join("profile-registry.json"), &catalog(""));
    cut_short(&work);
    // By a delete's overlap rule: `Profiles` itself, the Radicle homes, the
    // lock directory, a directory inside another profile's, and one among
    // the default profile's entries: refused before anything is taken.
    for dir in [
        app.join("Profiles"),
        app.join("R"),
        app.join("locks"),
        work.join("identity-sub"),
        app.join("loose"),
    ] {
        std::fs::create_dir_all(&dir).unwrap();
        journal(&dir, &["settings.json"]);
        write(&dir.join("freedom").join("settings.json"), "{}");
        let before = snapshot(&app);
        let out = migrate_env(&dir, &d.locks, &[], &[]);
        assert_eq!(code(&out), 74, "{}: {out:?}", dir.display());
        assert!(said(&out).contains("overlap"), "{out:?}");
        assert_eq!(snapshot(&app), before);
        std::fs::remove_dir_all(dir.join("freedom")).unwrap();
    }
    // A catalog it can't read proves nothing.
    write(&app.join("profile-registry.json"), "{");
    let out = migrate_env(&work, &d.locks, &[], &[]);
    assert_eq!(
        (code(&out), said(&out)),
        (74, r#"{"error":"unreadable"}"#.into())
    );
    // A profile's own directory, and the app root itself (the packaged
    // default profile, whose directory holds every other).
    write(&app.join("profile-registry.json"), &catalog(""));
    let out = migrate_env(&work, &d.locks, &[], &[]);
    assert_eq!(said(&out), "rolled_back", "{out:?}");
    assert_old_layout(&work);
    cut_short(&app);
    let out = migrate_env(&app, &app.join("locks"), &[], &[]);
    assert_eq!(said(&out), "rolled_back", "{out:?}");
    assert_old_layout(&app);
    assert!(app.join("profile-registry.json").is_file());
    assert!(work.join("identity").join("vault.json").is_file());
    // Not while another record lies among the app root's own entries.
    let loose = app.join("loose");
    write(
        &app.join("profile-registry.json"),
        &catalog(&format!(r#",{{"id":"loose","dir":{:?}}}"#, s(&loose))),
    );
    for moved in ["identity", "ipfs-data", "ant-data"] {
        std::fs::remove_dir_all(app.join(moved)).unwrap();
    }
    cut_short(&app);
    let before = snapshot(&app);
    let out = migrate_env(&app, &app.join("locks"), &[], &[]);
    assert_eq!(code(&out), 74, "{out:?}");
    assert!(said(&out).contains("overlap"), "{out:?}");
    assert_eq!(snapshot(&app), before);
}
