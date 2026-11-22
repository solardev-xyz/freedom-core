//! `profile migrate --finish-only` (design 0013, 5.4b; PRF-3): the move's
//! recovery, which starts no move, run as main runs it. Before the marker it
//! rolls back, after it rolls forward, a copied entry (journal version 2)
//! settled by its copy or its source and the placeholder written after the
//! marker where nothing is; an unreadable or ambiguous journal is
//! `corrupt` with nothing changed; any of the move's exclusion held by
//! another is `busy`; a lock taken over mid-run is `lock_lost`; a kill at
//! each step is finished by the next run; and the profile's directory must
//! overlap no other profile and no shared root. Without `--finish-only`
//! (PRF-9b) a run starts the move: every entry present renamed into
//! `freedom/` under a journal, then the marker, the placeholder and the
//! journal removed; a new profile's empty move; each precondition a
//! `deferred` with nothing changed; a kill at each step settled by
//! `--finish-only`; the held phases seen by a probe, a second run and a
//! delete; a frozen run's lock taken over. The cross-device copy (PRF-9c):
//! an entry on another device than `freedom/` copied, its source kept until
//! the marker; a kill at each of its steps settled by `--finish-only`; a
//! full volume and the free-space check; symlinks copied as links; what a
//! copy can't move deferring the move; and on real tmpfs mounts (CI's
//! Linux step, `FREEDOM_TEST_MOUNTS`) a genuine `EXDEV`, a full volume, and
//! nested mount points. A test binary of its own.

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

/// A starting run: `profile migrate` without `--finish-only`.
fn start_env(profile: &Path, locks: &Path, extra: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(BIN);
    command
        .args([
            "profile",
            "migrate",
            "--profile-dir",
            s(profile),
            "--lock-dir",
            s(locks),
        ])
        .args(extra)
        .stdin(Stdio::null());
    for (key, value) in env {
        command.env(key, value);
    }
    command.output().unwrap()
}

fn start(d: &Dirs) -> Output {
    start_env(&d.profile, &d.locks, &[], &[])
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

/// A version 2 journal: `copied` names entries copied across devices.
fn journal_v2(profile: &Path, entries: &[&str], copied: &[&str]) {
    let list = |names: &[&str]| {
        names
            .iter()
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    write(
        &profile.join("freedom").join(".move.json"),
        &format!(
            r#"{{"version":2,"entries":[{}],"copied":[{}]}}"#,
            list(entries),
            list(copied)
        ),
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
fn finish_only_settles_and_nothing_is_nothing() {
    let d = dirs();
    // No journal: nothing, and the run's lock let go. Its target is left,
    // as main's own lock leaves it.
    let out = migrate(&d);
    assert_eq!((code(&out), said(&out)), (0, "nothing".into()), "{out:?}");
    assert!(!d.profile.join("profile-open.lock").exists());
    assert!(d.profile.join("profile-open").is_file());
    // A marker alone: the move is done, and the placeholder written where
    // nothing is (MD9), once.
    marker(&d.profile);
    let out = migrate(&d);
    assert_eq!(said(&out), "nothing");
    assert!(placeholder_text(&d.profile).contains("freedom/"));
    let out = start(&d);
    assert_eq!(said(&out), "nothing", "{out:?}");
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
    journal(&d.profile, &["identity", "settings.json", "ant-data"]);
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
    // Named from the canonical path, as the gate names it (Windows'
    // verbatim form included).
    let ipfs_gate = d.locks.join(fc_service_lock_name(
        "ipfs",
        &std::fs::canonicalize(&ipfs_dir).unwrap(),
    ));
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
            r#"{{"version":1,"profiles":[{{"id":"default","dir":{:?},"slot":0}},{{"id":"work","dir":{:?},"slot":1}}{extra}]}}"#,
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
    // Another record at the profile's directory, in another case (one
    // directory on macOS and Windows), or sharing its Radicle slot.
    for extra in [
        format!(
            r#",{{"id":"twin","dir":{:?}}}"#,
            s(&app.join("Profiles").join("WORK"))
        ),
        format!(
            r#",{{"id":"other","dir":{:?},"slot":1}}"#,
            s(&app.join("Profiles").join("other"))
        ),
    ] {
        write(&app.join("profile-registry.json"), &catalog(&extra));
        let before = snapshot(&app);
        let out = migrate_env(&work, &d.locks, &[], &[]);
        assert_eq!(code(&out), 74, "{extra}: {out:?}");
        assert!(said(&out).contains("overlap"), "{out:?}");
        assert_eq!(snapshot(&app), before);
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

#[test]
fn a_journal_key_twice_is_corrupt_with_nothing_changed() {
    // JavaScript keeps a duplicate key's last value; the journal's keys are
    // exact, so neither of two is trusted, in either order.
    const ALL: &str = r#"["settings.json","identity","ipfs-data","ant-data"]"#;
    for text in [
        format!(r#"{{"version":1,"entries":{ALL},"entries":[]}}"#),
        format!(r#"{{"version":1,"entries":[],"entries":{ALL}}}"#),
        format!(r#"{{"version":2,"entries":{ALL},"version":1}}"#),
        format!(r#"{{"version":1,"entries":{ALL},"version":2}}"#),
    ] {
        let d = dirs();
        cut_short(&d.profile);
        write(&d.profile.join("freedom").join(".move.json"), &text);
        let before = snapshot(&d.profile);
        let out = migrate(&d);
        assert_eq!(
            (code(&out), said(&out)),
            (74, "corrupt".into()),
            "{text}: {out:?}"
        );
        assert_eq!(snapshot(&d.profile), before, "{text}");
    }
}

/// A journal naming `tor-data`, which is in no place at all: `corrupt`,
/// nothing changed, the journal kept. The journal lists only entries
/// present, and no step of the move removes every copy of one.
fn assert_in_no_place_is_corrupt(d: &Dirs) {
    assert!(!d.profile.join("tor-data").exists());
    let before = snapshot(&d.profile);
    let out = migrate(d);
    assert_eq!((code(&out), said(&out)), (74, "corrupt".into()), "{out:?}");
    assert_eq!(snapshot(&d.profile), before);
    assert!(d.profile.join("freedom").join(".move.json").is_file());
}

#[test]
fn an_entry_in_no_place_is_corrupt_before_the_marker() {
    let d = dirs();
    cut_short(&d.profile);
    journal(
        &d.profile,
        &[
            "settings.json",
            "identity",
            "tor-data",
            "ipfs-data",
            "ant-data",
        ],
    );
    assert_in_no_place_is_corrupt(&d);
}

#[test]
fn an_entry_in_no_place_is_corrupt_after_the_marker() {
    let d = dirs();
    write(&d.profile.join("freedom").join("settings.json"), "{}");
    journal(&d.profile, &["settings.json", "tor-data"]);
    marker(&d.profile);
    assert_in_no_place_is_corrupt(&d);
}

/// A profile inside an app root whose catalog, `catalog`, is made by
/// `make`: `unreadable`, refused before anything is taken, with nothing
/// changed. Only a missing catalog is none. With the catalog a regular
/// file again, the same profile is recovered.
fn assert_catalog_unreadable(make: impl FnOnce(&Path, &Path)) {
    let d = dirs();
    let app = d.base.join("app");
    let work = app.join("Profiles").join("work");
    let elsewhere = d.base.join("elsewhere.json");
    write(
        &elsewhere,
        &format!(
            r#"{{"version":1,"profiles":[{{"id":"work","dir":{:?},"slot":1}}]}}"#,
            s(&work)
        ),
    );
    cut_short(&work);
    let catalog = app.join("profile-registry.json");
    make(&catalog, &elsewhere);
    let before = snapshot(&app);
    let out = migrate_env(&work, &d.locks, &[], &[]);
    assert_eq!(
        (code(&out), said(&out)),
        (74, r#"{"error":"unreadable"}"#.into()),
        "{out:?}"
    );
    assert_eq!(snapshot(&app), before);
    assert!(!work.join("profile-open.lock").exists());
    assert!(!d.locks.exists(), "no gate taken");
    if std::fs::symlink_metadata(&catalog).unwrap().is_dir() {
        std::fs::remove_dir_all(&catalog).unwrap();
    } else {
        std::fs::remove_file(&catalog).unwrap();
    }
    std::fs::copy(&elsewhere, &catalog).unwrap();
    let out = migrate_env(&work, &d.locks, &[], &[]);
    assert_eq!(said(&out), "rolled_back", "{out:?}");
    assert_old_layout(&work);
}

#[test]
fn a_directory_at_the_catalogs_name_is_unreadable() {
    assert_catalog_unreadable(|catalog, _| std::fs::create_dir_all(catalog.join("x")).unwrap());
}

#[cfg(unix)]
#[test]
fn a_symlink_at_the_catalogs_name_is_unreadable() {
    // Even to a catalog that would allow the recovery.
    assert_catalog_unreadable(|catalog, elsewhere| {
        std::os::unix::fs::symlink(elsewhere, catalog).unwrap();
    });
}

fn placeholder_text(profile: &Path) -> String {
    let placeholder = profile.join("identity");
    assert!(
        std::fs::symlink_metadata(&placeholder)
            .unwrap()
            .file_type()
            .is_file(),
        "the placeholder is a regular file"
    );
    std::fs::read_to_string(placeholder).unwrap()
}

/// Before the marker, a copied entry's finished copy goes while its source
/// is at the root (MG1): the crash came after the copy's rename. A renamed
/// entry beside it goes back.
#[test]
fn a_copied_entry_before_the_marker_keeps_its_source_and_loses_its_copy() {
    let d = dirs();
    let freedom = d.profile.join("freedom");
    write(&d.profile.join("ant-data").join("config.yaml"), "ant");
    write(&freedom.join("ant-data").join("config.yaml"), "ant");
    write(&freedom.join("tor-data.moving").join("state"), "to");
    write(&d.profile.join("tor-data").join("state"), "tor");
    write(&freedom.join("settings.json"), "{}");
    journal_v2(
        &d.profile,
        &["settings.json", "ant-data", "tor-data"],
        &["ant-data", "tor-data"],
    );
    let out = migrate(&d);
    assert_eq!(
        (code(&out), said(&out)),
        (0, "rolled_back".into()),
        "{out:?}"
    );
    // Every source kept, every copy gone, `freedom/` removed empty, and no
    // placeholder.
    let entry = |name: &str, text: &str| (name.to_owned(), text.to_owned());
    assert_eq!(
        snapshot(&d.profile),
        [
            entry("ant-data/", ""),
            entry("ant-data/config.yaml", "ant"),
            entry("settings.json", "{}"),
            entry("tor-data/", ""),
            entry("tor-data/state", "tor"),
        ]
    );
    assert_eq!(said(&migrate(&d)), "nothing");
}

/// Before the marker, a copied entry whose source is gone, or replaced by
/// another kind of entry, is `corrupt` with nothing changed: nothing shows
/// the copy is whole.
#[test]
fn a_copied_entry_whose_source_is_gone_is_corrupt_before_the_marker() {
    for replaced in [false, true] {
        let d = dirs();
        write(
            &d.profile
                .join("freedom")
                .join("ant-data")
                .join("config.yaml"),
            "ant",
        );
        if replaced {
            write(&d.profile.join("ant-data"), "a file");
        }
        journal_v2(&d.profile, &["ant-data"], &["ant-data"]);
        let before = snapshot(&d.profile);
        let out = migrate(&d);
        assert_eq!(
            (code(&out), said(&out)),
            (74, "corrupt".into()),
            "{replaced}: {out:?}"
        );
        assert_eq!(snapshot(&d.profile), before, "{replaced}");
    }
}

/// After the marker, a copied entry's source, half removed when the
/// cleanup was cut short, goes; a renamed entry's residue stays; and the
/// placeholder is written where nothing is (MG2, MD9).
#[test]
fn after_the_marker_a_copied_source_goes_and_the_placeholder_is_written() {
    let d = dirs();
    let freedom = d.profile.join("freedom");
    write(&freedom.join("identity").join("vault.json"), "vault");
    write(&freedom.join("ant-data").join("a"), "a");
    write(&freedom.join("ant-data").join("b"), "b");
    // Half removed.
    write(&d.profile.join("ant-data").join("b"), "b");
    write(&freedom.join("settings.json"), "{}");
    write(&d.profile.join("settings.json"), "made since");
    journal_v2(
        &d.profile,
        &["identity", "settings.json", "ant-data"],
        &["ant-data"],
    );
    marker(&d.profile);
    let out = migrate(&d);
    assert_eq!((code(&out), said(&out)), (0, "migrated".into()), "{out:?}");
    assert!(!d.profile.join("ant-data").exists(), "the source removed");
    assert_eq!(
        std::fs::read_to_string(freedom.join("ant-data").join("a")).unwrap(),
        "a"
    );
    assert_eq!(
        std::fs::read_to_string(d.profile.join("settings.json")).unwrap(),
        "made since"
    );
    assert_eq!(
        placeholder_text(&d.profile),
        fc_profile::layout::PLACEHOLDER_TEXT
    );
    assert!(!freedom.join(".move.json").exists());
    assert_eq!(said(&migrate(&d)), "nothing");
}

/// A profile that never had an `identity/` gets the placeholder after the
/// marker too, and one already there, or anything else at that name, stays
/// as it is.
#[test]
fn the_placeholder_is_written_only_where_nothing_is() {
    let d = dirs();
    write(&d.profile.join("freedom").join("settings.json"), "{}");
    journal_v2(&d.profile, &["settings.json"], &[]);
    marker(&d.profile);
    assert_eq!(said(&migrate(&d)), "migrated");
    assert_eq!(
        placeholder_text(&d.profile),
        fc_profile::layout::PLACEHOLDER_TEXT
    );

    for kept in [
        |p: &Path| write(&p.join("identity"), "an older placeholder"),
        |p: &Path| write(&p.join("identity").join("vault.json"), "made since"),
    ] {
        let d = dirs();
        kept(&d.profile);
        write(&d.profile.join("freedom").join("settings.json"), "{}");
        journal(&d.profile, &["settings.json"]);
        marker(&d.profile);
        let before: Vec<_> = snapshot(&d.profile)
            .into_iter()
            .filter(|(name, _)| name.starts_with("identity"))
            .collect();
        assert_eq!(said(&migrate(&d)), "migrated");
        let after: Vec<_> = snapshot(&d.profile)
            .into_iter()
            .filter(|(name, _)| name.starts_with("identity"))
            .collect();
        assert_eq!(after, before);
    }
}

// The starting move (PRF-9b): `profile migrate` without `--finish-only`.

/// A used profile in the root layout: entries of each kind, among them
/// arti's state lock, antd's instance lock and Myotis's lease (not held),
/// and the shell's own files, which never move.
fn seeded(profile: &Path) {
    write(&profile.join("identity").join("vault.json"), "vault");
    write(
        &profile.join("ipfs-data").join("freedom-ipfs").join("b"),
        "block",
    );
    write(&profile.join("ant-data").join("config.yaml"), "ant");
    write(&profile.join("ant-data").join("antd.lock"), "4242\n");
    write(&profile.join("settings.json"), "{}");
    write(
        &profile
            .join("tor-data")
            .join("state")
            .join("state")
            .join("state.lock"),
        "",
    );
    write(&profile.join("myotis").join(".freedom-myotis-lifetime"), "");
    write(
        &profile
            .join("myotis")
            .join("gnosis")
            .join(".freedom-myotis-lifetime"),
        "",
    );
    write(&profile.join("Cookies"), "cookies");
    if !profile.join("profile.json").exists() {
        write(&profile.join("profile.json"), "{}");
    }
}

/// The entries `seeded` makes, in the list's order.
const SEEDED: &[&str] = &[
    "identity",
    "settings.json",
    "ant-data",
    "ipfs-data",
    "tor-data",
    "myotis",
];

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn there(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// The seeded profile once moved: each entry in `freedom/`, none at the
/// root but the placeholder, the marker there and the journal gone, the
/// shell's files where they were.
fn assert_new_layout(profile: &Path) {
    let freedom = profile.join("freedom");
    assert_eq!(read(&freedom.join("identity").join("vault.json")), "vault");
    assert_eq!(
        read(&freedom.join("ipfs-data").join("freedom-ipfs").join("b")),
        "block"
    );
    assert_eq!(read(&freedom.join("ant-data").join("config.yaml")), "ant");
    assert_eq!(read(&freedom.join("settings.json")), "{}");
    assert!(
        freedom
            .join("tor-data")
            .join("state")
            .join("state")
            .join("state.lock")
            .is_file()
    );
    assert!(freedom.join("myotis").join("gnosis").is_dir());
    for name in &SEEDED[1..] {
        assert!(!there(&profile.join(name)), "{name} left at the root");
    }
    assert!(placeholder_text(profile).contains("freedom/"));
    assert!(freedom.join("layout.json").is_file());
    assert!(!there(&freedom.join(".move.json")), "the journal removed");
    assert!(!there(&freedom.join(".move.json.freedom-new")));
    assert_eq!(read(&profile.join("Cookies")), "cookies");
    assert!(profile.join("profile.json").is_file());
}

/// The seeded profile as it was, whatever is in `freedom/`.
fn assert_entries_at_the_root(profile: &Path) {
    assert_eq!(read(&profile.join("identity").join("vault.json")), "vault");
    assert_eq!(read(&profile.join("settings.json")), "{}");
    assert_eq!(read(&profile.join("ant-data").join("config.yaml")), "ant");
    assert_eq!(
        read(&profile.join("ipfs-data").join("freedom-ipfs").join("b")),
        "block"
    );
    assert!(profile.join("tor-data").is_dir() && profile.join("myotis").is_dir());
    assert!(!there(&profile.join("freedom").join("layout.json")));
    assert!(!there(&profile.join("freedom").join(".move.json")));
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn a_starting_move_moves_every_entry_present_then_writes_the_marker() {
    let d = dirs();
    seeded(&d.profile);
    let out = start(&d);
    assert_eq!((code(&out), said(&out)), (0, "migrated".into()), "{out:?}");
    assert_new_layout(&d.profile);
    assert!(
        !d.profile.join("profile-open.lock").exists(),
        "its lock let go"
    );
    let marker: serde_json::Value =
        serde_json::from_str(&read(&d.profile.join("freedom").join("layout.json"))).unwrap();
    assert_eq!(marker["version"], 1);
    assert!(marker["moved_at"].as_str().unwrap().ends_with('Z'));
    assert!(marker["by"].as_str().unwrap().starts_with("freedom-cored "));
    // Done: either kind of run finds nothing to do.
    assert_eq!(said(&start(&d)), "nothing");
    assert_eq!(said(&migrate(&d)), "nothing");
    assert_new_layout(&d.profile);
}

/// MD5: a profile with none of the entries starts in the new layout:
/// `freedom/` with the marker alone, the placeholder, no journal.
#[test]
fn a_new_profile_takes_the_empty_move() {
    let d = dirs();
    write(&d.profile.join("Cookies"), "cookies");
    let out = start(&d);
    assert_eq!((code(&out), said(&out)), (0, "migrated".into()), "{out:?}");
    assert_eq!(names(&d.profile.join("freedom")), ["layout.json"]);
    assert!(placeholder_text(&d.profile).contains("freedom/"));
    assert_eq!(read(&d.profile.join("Cookies")), "cookies");
    assert_eq!(said(&start(&d)), "nothing");
}

#[test]
fn a_kill_at_each_step_of_a_starting_move_is_settled_by_finish_only() {
    for (step, journaled, marked) in [
        ("after-exclusion", false, false),
        ("after-freedom-dir", false, false),
        ("after-journal", true, false),
        ("mid-move", true, false),
        ("after-renames", true, false),
        ("after-marker", true, true),
        ("after-placeholder", true, true),
        ("before-journal-removed", true, true),
    ] {
        let d = dirs();
        seeded(&d.profile);
        let out = start_env(
            &d.profile,
            &d.locks,
            &[],
            &[("FREEDOM_CORED_TEST_PROFILE_MIGRATE_CRASH", step)],
        );
        assert_eq!(code(&out), 99, "{step}: {out:?}");
        assert_eq!(
            there(&d.profile.join("freedom").join(".move.json")),
            journaled,
            "{step}"
        );
        // Its lock left fresh, as a killed process leaves it.
        backdate(
            &d.profile.join("profile-open.lock"),
            Duration::from_secs(31),
        );
        let out = migrate(&d);
        if marked {
            assert_eq!(said(&out), "migrated", "{step}: {out:?}");
            assert_new_layout(&d.profile);
            continue;
        }
        let expected = if journaled { "rolled_back" } else { "nothing" };
        assert_eq!(said(&out), expected, "{step}: {out:?}");
        assert_entries_at_the_root(&d.profile);
        assert!(
            !there(&d.profile.join("freedom").join("identity")),
            "{step}"
        );
        // The next start moves it.
        let out = start(&d);
        assert_eq!(said(&out), "migrated", "{step}: {out:?}");
        assert_new_layout(&d.profile);
    }

    // The empty move, killed between its marker and its placeholder: the
    // next run, either kind, writes the placeholder.
    let d = dirs();
    let out = start_env(
        &d.profile,
        &d.locks,
        &[],
        &[("FREEDOM_CORED_TEST_PROFILE_MIGRATE_CRASH", "after-marker")],
    );
    assert_eq!(code(&out), 99, "{out:?}");
    assert!(!there(&d.profile.join("identity")));
    backdate(
        &d.profile.join("profile-open.lock"),
        Duration::from_secs(31),
    );
    assert_eq!(said(&migrate(&d)), "nothing");
    assert!(placeholder_text(&d.profile).contains("freedom/"));
}

/// The preconditions (0013, "The move", 2): each ends the run with
/// `deferred`, exit 0, nothing changed and its lock let go; the move
/// starts once it is gone.
#[test]
fn each_precondition_defers_with_nothing_changed() {
    fn deferred(d: &Dirs, what: &str) {
        let before = snapshot(&d.profile);
        let out = start(d);
        assert_eq!(
            (code(&out), said(&out)),
            (0, "deferred".into()),
            "{what}: {out:?}"
        );
        assert_eq!(snapshot(&d.profile), before, "{what}: nothing changed");
        assert!(
            !d.profile.join("profile-open.lock").exists(),
            "{what}: its lock let go"
        );
    }

    // A node identity journal or its staging file (MG3).
    for name in ["node-identity-journal.json", "node-identity-staging.json"] {
        let d = dirs();
        seeded(&d.profile);
        write(&d.profile.join("identity").join(name), "{}");
        deferred(&d, name);
        std::fs::remove_file(d.profile.join("identity").join(name)).unwrap();
        assert_eq!(said(&start(&d)), "migrated", "{name}");
    }

    // A `freedom/` the move didn't make: a file, a symlink to a directory,
    // or a directory holding a name the move writes (folded).
    let d = dirs();
    seeded(&d.profile);
    write(&d.profile.join("freedom"), "a file");
    deferred(&d, "freedom/ a file");
    // A symlink (or on Windows a junction) at `freedom` to a directory
    // holding the new paths' gated directories: deferred before any gate is
    // named through it, so nothing there changes, its modes included.
    {
        let d = dirs();
        seeded(&d.profile);
        let elsewhere = d.base.join("elsewhere");
        write(&elsewhere.join("identity").join("vault.json"), "theirs");
        write(
            &elsewhere.join("ipfs-data").join("freedom-ipfs").join("b"),
            "theirs",
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for dir in [
                elsewhere.join("identity"),
                elsewhere.join("ipfs-data").join("freedom-ipfs"),
            ] {
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        link_dir(&elsewhere, &d.profile.join("freedom"));
        let theirs = snapshot(&elsewhere);
        let their_modes = modes(&elsewhere);
        deferred(&d, "freedom/ a link");
        assert_eq!(snapshot(&elsewhere), theirs, "the link's target");
        assert_eq!(modes(&elsewhere), their_modes, "the target's modes");
    }
    for name in ["Settings.JSON", "ant-data.moving", "layout.json "] {
        if cfg!(windows) && name.ends_with(' ') {
            continue;
        }
        let d = dirs();
        seeded(&d.profile);
        write(&d.profile.join("freedom").join(name), "x");
        deferred(&d, name);
    }
    // Other names in it stay, and the move goes on.
    let d = dirs();
    seeded(&d.profile);
    write(&d.profile.join("freedom").join("notes.txt"), "mine");
    assert_eq!(said(&start(&d)), "migrated");
    assert_eq!(read(&d.profile.join("freedom").join("notes.txt")), "mine");
    assert_new_layout(&d.profile);

    // arti running: its state lock held (flock; LockFileEx on Windows).
    let d = dirs();
    seeded(&d.profile);
    let state_lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(
            d.profile
                .join("tor-data")
                .join("state")
                .join("state")
                .join("state.lock"),
        )
        .unwrap();
    state_lock.lock().unwrap();
    deferred(&d, "arti's state lock");
    state_lock.unlock().unwrap();
    drop(state_lock);
    assert_eq!(said(&start(&d)), "migrated");

    // antd running, an orphan included: its instance lock held (fs4's
    // try_lock, flock; LockFileEx on Windows), whatever ant-process.json
    // says or whether it exists.
    let d = dirs();
    seeded(&d.profile);
    let antd_lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(d.profile.join("ant-data").join("antd.lock"))
        .unwrap();
    antd_lock.lock().unwrap();
    deferred(&d, "antd's instance lock");
    antd_lock.unlock().unwrap();
    drop(antd_lock);
    assert_eq!(said(&start(&d)), "migrated");

    // Myotis running (an orphaned execution child holds its lifetime
    // lease too), for each network.
    for network in [None, Some("gnosis")] {
        let d = dirs();
        seeded(&d.profile);
        let mut lease = d.profile.join("myotis");
        lease.extend(network);
        lease.push(".freedom-myotis-lifetime");
        let held = hold_lease(&lease);
        deferred(&d, &format!("Myotis's lease {network:?}"));
        drop(held);
        assert_eq!(said(&start(&d)), "migrated", "{network:?}");
    }
}

/// A link to the directory `target` at `link`: a symlink on Unix, a
/// junction on Windows (which needs no privilege).
fn link_dir(target: &Path, link: &Path) {
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

/// A symlink at `path`, or on Windows any reparse point (a junction).
fn is_link_at(path: &Path) -> bool {
    let meta = std::fs::symlink_metadata(path).unwrap();
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

/// Each directory's mode under `dir` (Unix; nothing elsewhere).
fn modes(dir: &Path) -> Vec<(PathBuf, u32)> {
    let mut out = Vec::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut stack = vec![dir.to_path_buf()];
        while let Some(next) = stack.pop() {
            let meta = std::fs::symlink_metadata(&next).unwrap();
            out.push((next.clone(), meta.permissions().mode()));
            if meta.is_dir() {
                for entry in std::fs::read_dir(&next).unwrap() {
                    stack.push(entry.unwrap().path());
                }
            }
        }
        out.sort();
    }
    let _ = dir;
    out
}

/// A link among the entries whose target is relative, or absolute inside
/// the profile, defers (`link_inside_profile`): moved one directory deeper,
/// a relative link names another place, and one into the profile may name
/// an entry the move takes elsewhere. A link to an absolute path outside
/// the profile moves as the link.
#[test]
fn a_link_among_the_entries_into_the_profile_defers() {
    let assert_deferred = |d: &Dirs, what: &str| {
        let before = snapshot(&d.profile);
        let out = start(d);
        assert_eq!(
            (code(&out), said(&out)),
            (0, "deferred".into()),
            "{what}: {out:?}"
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("link_inside_profile"),
            "{what}: {out:?}"
        );
        assert_eq!(snapshot(&d.profile), before, "{what}");
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        // `identity`, relative: `../wallet` names a sibling of the profile
        // now, and `<profile>/wallet` once moved.
        let d = dirs();
        seeded(&d.profile);
        std::fs::remove_dir_all(d.profile.join("identity")).unwrap();
        write(&d.base.join("wallet").join("vault.json"), "vault");
        symlink("../wallet", d.profile.join("identity")).unwrap();
        assert_deferred(&d, "identity, relative");
        // A node's directory, relative and inside.
        let d = dirs();
        seeded(&d.profile);
        std::fs::rename(d.profile.join("ant-data"), d.profile.join("ant-real")).unwrap();
        symlink("ant-real", d.profile.join("ant-data")).unwrap();
        assert_deferred(&d, "ant-data, relative");
        // Absolute, inside the profile: `identity` naming another entry,
        // and a node's directory naming another node's.
        let d = dirs();
        seeded(&d.profile);
        std::fs::rename(d.profile.join("identity"), d.profile.join("wallet")).unwrap();
        symlink(d.profile.join("wallet"), d.profile.join("identity")).unwrap();
        assert_deferred(&d, "identity, absolute inside");
        let d = dirs();
        seeded(&d.profile);
        std::fs::remove_dir_all(d.profile.join("ipfs-data")).unwrap();
        symlink(d.profile.join("ant-data"), d.profile.join("ipfs-data")).unwrap();
        assert_deferred(&d, "ipfs-data, absolute inside");
    }
    // A junction (Windows) or symlink to a directory inside the profile.
    let d = dirs();
    seeded(&d.profile);
    std::fs::rename(d.profile.join("ant-data"), d.profile.join("ant-real")).unwrap();
    link_dir(&d.profile.join("ant-real"), &d.profile.join("ant-data"));
    assert_deferred(&d, "ant-data, a link to a directory inside");
    // To an absolute path outside the profile: moved as the link.
    let d = dirs();
    seeded(&d.profile);
    let outside = d.base.join("outside-ant");
    std::fs::rename(d.profile.join("ant-data"), &outside).unwrap();
    link_dir(&outside, &d.profile.join("ant-data"));
    let out = start(&d);
    assert_eq!(said(&out), "migrated", "{out:?}");
    let moved = d.profile.join("freedom").join("ant-data");
    assert!(is_link_at(&moved));
    assert_eq!(read(&moved.join("config.yaml")), "ant");
    assert_new_layout(&d.profile);
}

/// On Linux names are exact: a link into a sibling whose name differs from
/// the profile's only by case (`WORK` beside `work`) points outside the
/// profile, and moves as the link.
#[cfg(target_os = "linux")]
#[test]
fn a_link_into_a_case_distinct_sibling_moves_on_linux() {
    let d = dirs();
    let work = d.base.join("work");
    seeded(&work);
    let target = d.base.join("WORK").join("ant");
    write(&target.join("config.yaml"), "ant");
    std::fs::remove_dir_all(work.join("ant-data")).unwrap();
    std::os::unix::fs::symlink(&target, work.join("ant-data")).unwrap();
    let out = start_env(&work, &d.locks, &[], &[]);
    assert_eq!(said(&out), "migrated", "{out:?}");
    assert_eq!(
        std::fs::read_link(work.join("freedom").join("ant-data")).unwrap(),
        target
    );
    assert_new_layout(&work);
}

/// A node's directory (`tor-data/`, `myotis/`) that is a link (a symlink,
/// or on Windows a junction), even to an absolute path outside, defers
/// (`node_lock_unknown`): its lock can't be looked up without following
/// the link to storage the core hasn't qualified, and whether the node
/// still runs there isn't guessed. The profile keeps its old layout.
#[test]
fn a_node_directory_that_is_a_link_defers() {
    for entry in ["tor-data", "myotis"] {
        let d = dirs();
        seeded(&d.profile);
        let outside = d.base.join(format!("outside-{entry}"));
        std::fs::rename(d.profile.join(entry), &outside).unwrap();
        link_dir(&outside, &d.profile.join(entry));
        let before = snapshot(&d.profile);
        let out = start(&d);
        assert_eq!(
            (code(&out), said(&out)),
            (0, "deferred".into()),
            "{entry}: {out:?}"
        );
        let log = String::from_utf8_lossy(&out.stderr);
        assert!(log.contains("node_lock_unknown"), "{entry}: {log}");
        assert_eq!(snapshot(&d.profile), before, "{entry}");
    }
}

/// proper-lockfile's takeover of a stale lock, as another build makes it:
/// the old directory gone from its name (moved aside here, so a Windows
/// handle on it doesn't leave a pending delete) and a new one made.
fn take_over_lock(lock: &Path) {
    std::fs::rename(lock, lock.with_extension("old")).unwrap();
    std::fs::create_dir(lock).unwrap();
}

/// Taken over between its taking and its keeping (a run stalled past the
/// stale time before it got there): `keep`'s own refresh finds it before
/// anything is written, and the run ends `lock_lost` with nothing changed,
/// the successor's lock left. A finish-only recovery, and a starting move
/// (after its refresh before confinement).
#[test]
fn a_lock_taken_over_before_it_is_kept_changes_nothing() {
    for finish_only in [true, false] {
        let d = dirs();
        if finish_only {
            cut_short(&d.profile);
        } else {
            seeded(&d.profile);
        }
        let before = snapshot(&d.profile);
        let paused = d.base.join("paused");
        let release = d.base.join("release");
        let mut command = Command::new(BIN);
        command
            .args([
                "profile",
                "migrate",
                "--profile-dir",
                s(&d.profile),
                "--lock-dir",
                s(&d.locks),
            ])
            .env(
                "FREEDOM_CORED_TEST_PROFILE_MIGRATE_PAUSE",
                format!("before-keep={}={}", paused.display(), release.display()),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if finish_only {
            command.arg("--finish-only");
        }
        let child = command.spawn().unwrap();
        wait_for(&paused);
        let lock = d.profile.join("profile-open.lock");
        take_over_lock(&lock);
        std::fs::write(&release, "").unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(
            (code(&out), said(&out)),
            (74, "lock_lost".into()),
            "finish-only {finish_only}: {out:?}"
        );
        assert_eq!(snapshot(&d.profile), before, "finish-only {finish_only}");
        assert!(lock.is_dir(), "the successor's lock stays");
    }
}

/// An `identity` that is a link to an absolute path outside holds no
/// journal of this profile's: a node identity journal behind it doesn't
/// defer, and is never read; the link moves as itself.
#[cfg(unix)]
#[test]
fn an_identity_link_is_not_followed_for_a_node_journal() {
    let d = dirs();
    seeded(&d.profile);
    let outside = d.base.join("outside-identity");
    std::fs::rename(d.profile.join("identity"), &outside).unwrap();
    write(&outside.join("node-identity-journal.json"), "{}");
    std::os::unix::fs::symlink(&outside, d.profile.join("identity")).unwrap();
    let out = start(&d);
    assert_eq!(said(&out), "migrated", "{out:?}");
    let moved = d.profile.join("freedom").join("identity");
    assert_eq!(std::fs::read_link(&moved).unwrap(), outside);
    assert!(outside.join("node-identity-journal.json").is_file());
}

/// Myotis's lease as its supervisor holds it: `flock` on Unix; on Windows a
/// handle that shares reading only.
fn hold_lease(path: &Path) -> std::fs::File {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x1)
            .open(path)
            .unwrap()
    }
    #[cfg(not(windows))]
    {
        let file = std::fs::File::open(path).unwrap();
        file.lock().unwrap();
        file
    }
}

/// A symlink is moved as the link, its target untouched: here one on
/// another device where the test has one (`/dev/shm`), as a user's
/// `ant-data` on another disk would be.
#[cfg(unix)]
#[test]
fn a_symlinked_entry_moves_as_the_link() {
    use std::os::unix::fs::MetadataExt;
    let d = dirs();
    seeded(&d.profile);
    let device = |path: &Path| std::fs::metadata(path).unwrap().dev();
    let other = tempfile::tempdir_in("/dev/shm")
        .ok()
        .filter(|t| device(t.path()) != device(&d.base))
        .unwrap_or_else(|| tempfile::tempdir().unwrap());
    let target = other.path().join("ant");
    write(&target.join("config.yaml"), "ant");
    std::fs::remove_dir_all(d.profile.join("ant-data")).unwrap();
    std::os::unix::fs::symlink(&target, d.profile.join("ant-data")).unwrap();
    let out = start(&d);
    assert_eq!(said(&out), "migrated", "{out:?}");
    let moved = d.profile.join("freedom").join("ant-data");
    assert!(std::fs::symlink_metadata(&moved).unwrap().is_symlink());
    assert_eq!(std::fs::read_link(&moved).unwrap(), target);
    assert_eq!(read(&target.join("config.yaml")), "ant");
    assert_new_layout(&d.profile);
}

/// MD8: no checkpoint. A database left as a crash leaves it, its committed
/// rows (the table too) in its `-wal` alone, moves with its `-wal` and
/// `-shm`, and every row reads back from `freedom/`.
#[test]
fn committed_rows_only_in_a_wal_read_back_after_the_move() {
    fn copy(from: &Path, to: &Path) {
        // Read through std's sharing open: SQLite's handles stay open.
        let mut source = std::fs::File::open(from).unwrap();
        let mut target = std::fs::File::create(to).unwrap();
        std::io::copy(&mut source, &mut target).unwrap();
    }
    let d = dirs();
    let scratch = d.base.join("scratch");
    std::fs::create_dir(&scratch).unwrap();
    let db = scratch.join("p.sqlite");
    let conn = rusqlite::Connection::open(&db).unwrap();
    let mode: String = conn
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    conn.execute_batch("PRAGMA wal_autocheckpoint=0; CREATE TABLE t (n INTEGER);")
        .unwrap();
    for n in 0..100 {
        conn.execute("INSERT INTO t VALUES (?1)", [n]).unwrap();
    }
    let name = "payment-history.sqlite";
    for suffix in ["", "-wal", "-shm"] {
        copy(
            &scratch.join(format!("p.sqlite{suffix}")),
            &d.profile.join(format!("{name}{suffix}")),
        );
    }
    drop(conn);
    assert!(
        std::fs::metadata(d.profile.join(format!("{name}-wal")))
            .unwrap()
            .len()
            > 0
    );
    // The database alone holds none of it.
    let alone = d.base.join("alone.sqlite");
    copy(&d.profile.join(name), &alone);
    let conn = rusqlite::Connection::open(&alone).unwrap();
    assert!(
        conn.query_row("SELECT count(*) FROM t", [], |row| row.get::<_, i64>(0))
            .is_err()
    );
    drop(conn);

    let out = start(&d);
    assert_eq!(said(&out), "migrated", "{out:?}");
    let freedom = d.profile.join("freedom");
    for suffix in ["", "-wal", "-shm"] {
        assert!(
            freedom.join(format!("{name}{suffix}")).is_file(),
            "{suffix}"
        );
        assert!(
            !there(&d.profile.join(format!("{name}{suffix}"))),
            "{suffix}"
        );
    }
    let conn = rusqlite::Connection::open(freedom.join(name)).unwrap();
    let (count, sum): (i64, i64) = conn
        .query_row("SELECT count(*), sum(n) FROM t", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!((count, sum), (100, 4950));
}

/// MD3, on Windows: an entry another handle holds (here opened sharing
/// nothing, as an indexer might) is tried again, 30 times 100 ms apart. Let
/// go within them, the move goes on; held past them, the move is rolled
/// back and the old layout is as it was.
#[cfg(windows)]
#[test]
fn a_held_entry_on_windows_is_tried_again_then_rolled_back() {
    use std::os::windows::fs::OpenOptionsExt;
    let hold = |path: &Path| {
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(path)
            .unwrap()
    };
    let d = dirs();
    seeded(&d.profile);
    let held = hold(&d.profile.join("settings.json"));
    let child = Command::new(BIN)
        .args([
            "profile",
            "migrate",
            "--profile-dir",
            s(&d.profile),
            "--lock-dir",
            s(&d.locks),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(1_000));
    drop(held);
    let out = child.wait_with_output().unwrap();
    assert_eq!(said(&out), "migrated", "{out:?}");
    assert_new_layout(&d.profile);

    let d = dirs();
    seeded(&d.profile);
    let held = hold(&d.profile.join("settings.json"));
    let out = start(&d);
    assert_eq!(
        (code(&out), said(&out)),
        (0, "rolled_back".into()),
        "{out:?}"
    );
    drop(held);
    assert_old_layout(&d.profile);
}

/// On Windows, the lock is checked before every retry of a held rename: a
/// run whose lock is taken over while it waits out a held entry changes
/// nothing more (`lock_lost`), even once the entry is let go. Both the
/// starting move's renames and a rollback's renames back.
#[cfg(windows)]
#[test]
fn a_lock_taken_over_between_windows_retries_stops_the_run() {
    use std::os::windows::fs::OpenOptionsExt;
    let hold = |path: &Path| {
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(path)
            .unwrap()
    };
    // Pauses at `step` (after a refused try), takes the lock over, lets the
    // entry go and the run on: `lock_lost`, nothing more changed.
    let lose_at = |d: &Dirs, step: &str, held: std::fs::File, extra: &[&str]| {
        let paused = d.base.join("paused");
        let release = d.base.join("release");
        let child = Command::new(BIN)
            .args([
                "profile",
                "migrate",
                "--profile-dir",
                s(&d.profile),
                "--lock-dir",
                s(&d.locks),
                "--dev",
            ])
            .args(extra)
            .env(
                "FREEDOM_CORED_TEST_PROFILE_MIGRATE_PAUSE",
                format!("{step}={}={}", paused.display(), release.display()),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        wait_for(&paused);
        // Another build's takeover: the mtime isn't the run's any more, and
        // its refresher (every second in a dev build) finds it.
        backdate(
            &d.profile.join("profile-open.lock"),
            Duration::from_secs(60),
        );
        std::thread::sleep(Duration::from_millis(2_500));
        // The entry let go: a try now would succeed.
        drop(held);
        let before = snapshot(&d.profile);
        std::fs::write(&release, "").unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(
            (code(&out), said(&out)),
            (74, "lock_lost".into()),
            "{step}: {out:?}"
        );
        assert_eq!(snapshot(&d.profile), before, "{step}: nothing more changed");
    };

    // The starting move: `settings.json` held; the entries before it moved.
    let d = dirs();
    seeded(&d.profile);
    let held = hold(&d.profile.join("settings.json"));
    lose_at(&d, "rename-retry", held, &[]);
    assert!(
        d.profile.join("settings.json").is_file(),
        "not moved after the loss"
    );
    assert!(
        d.profile.join("freedom").join(".move.json").is_file(),
        "journal kept"
    );
    backdate(
        &d.profile.join("profile-open.lock"),
        Duration::from_secs(60),
    );
    let out = migrate_env(&d.profile, &d.locks, &["--dev"], &[]);
    assert_eq!(said(&out), "rolled_back", "{out:?}");
    assert_old_layout(&d.profile);

    // A rollback: `settings.json`, moved before the marker, held in
    // `freedom/`.
    let d = dirs();
    write(&d.profile.join("freedom").join("settings.json"), "{}");
    write(&d.profile.join("Cookies"), "cookies");
    journal(&d.profile, &["settings.json"]);
    let held = hold(&d.profile.join("freedom").join("settings.json"));
    lose_at(&d, "rename-back-retry", held, &["--finish-only"]);
    assert!(
        d.profile.join("freedom").join("settings.json").is_file(),
        "not renamed back after the loss"
    );
    assert!(!d.profile.join("settings.json").exists());
    backdate(
        &d.profile.join("profile-open.lock"),
        Duration::from_secs(60),
    );
    let out = migrate_env(&d.profile, &d.locks, &["--dev"], &[]);
    assert_eq!(said(&out), "rolled_back", "{out:?}");
    assert_eq!(read(&d.profile.join("settings.json")), "{}");
    assert!(!d.profile.join("freedom").exists());
}

/// MD3, on Windows: under a long user name, the deepest paths the nodes
/// write under `ant-data\` and `ipfs-data\` still open under `freedom\`,
/// one of them past `MAX_PATH`.
#[cfg(windows)]
#[test]
fn the_nodes_deepest_paths_still_open_after_the_move_under_a_long_user_name() {
    let root = tempfile::tempdir().unwrap();
    let profile = root
        .path()
        .join("Users")
        .join("u".repeat(64))
        .join("AppData")
        .join("Roaming")
        .join("Freedom")
        .join("Profiles")
        .join("0123456789abcdef0123456789abcdef");
    let locks = root.path().join("locks");
    let deep: Vec<Vec<String>> = vec![
        vec!["ant-data", "localstore", "indexstore", "MANIFEST-000001"],
        vec!["ant-data", "localstore", "sharky", "free_000"],
        vec!["ant-data", "statestore", "000001.ldb"],
        vec!["ant-data", "keys", "swarm.key"],
        vec!["ipfs-data", "freedom-ipfs", "blocks.sqlite-wal"],
    ]
    .into_iter()
    .map(|parts| parts.into_iter().map(str::to_owned).collect())
    .chain([vec![
        "ipfs-data".to_owned(),
        "freedom-ipfs".to_owned(),
        "d".repeat(100),
        "e".repeat(40),
    ]])
    .collect();
    for parts in &deep {
        let mut path = profile.clone();
        path.extend(parts);
        write(&path, &parts.join("/"));
    }
    let out = start_env(&profile, &locks, &[], &[]);
    assert_eq!(said(&out), "migrated", "{out:?}");
    let mut longest = 0;
    let mut paths = Vec::new();
    for parts in &deep {
        let mut path = profile.join("freedom");
        path.extend(parts);
        longest = longest.max(path.as_os_str().len());
        assert_eq!(read(&path), parts.join("/"), "Rust");
        paths.push(path.display().to_string());
    }
    assert!(longest > 260, "{longest}");
    let expected: Vec<String> = deep.iter().map(|parts| parts.join("/")).collect();
    let expected = expected.join("\n");
    let list = paths.join("\n");

    // Node's fs (main's) and Go's os (antd's): each prints every file's text.
    let node = Command::new("node")
        .args([
            "-e",
            "const fs = require('fs'); process.stdout.write(process.env.FREEDOM_TEST_PATHS.split('\\n').map((p) => fs.readFileSync(p, 'utf8')).join('\\n'));",
        ])
        .env("FREEDOM_TEST_PATHS", &list)
        .output();
    check_runtime("node", node, &expected);

    let go_dir = tempfile::tempdir().unwrap();
    let program = go_dir.path().join("main.go");
    std::fs::write(
        &program,
        "package main\n\nimport (\n\t\"os\"\n\t\"strings\"\n)\n\nfunc main() {\n\tvar texts []string\n\tfor _, p := range strings.Split(os.Getenv(\"FREEDOM_TEST_PATHS\"), \"\\n\") {\n\t\tb, err := os.ReadFile(p)\n\t\tif err != nil {\n\t\t\tos.Stderr.WriteString(err.Error())\n\t\t\tos.Exit(1)\n\t\t}\n\t\ttexts = append(texts, string(b))\n\t}\n\tos.Stdout.WriteString(strings.Join(texts, \"\\n\"))\n}\n",
    )
    .unwrap();
    let go = Command::new("go")
        .arg("run")
        .arg(&program)
        .env("FREEDOM_TEST_PATHS", &list)
        .output();
    check_runtime("go", go, &expected);
}

/// A runtime's reading of the deepest paths. A runtime that isn't installed
/// fails the test under CI (`CI`, which GitHub Actions sets), where
/// windows-latest has Node and Go, and is skipped elsewhere.
#[cfg(windows)]
fn check_runtime(name: &str, output: std::io::Result<Output>, expected: &str) {
    match output {
        Ok(out) => {
            assert!(out.status.success(), "{name}: {out:?}");
            assert_eq!(String::from_utf8_lossy(&out.stdout), expected, "{name}");
        }
        Err(e) if std::env::var_os("CI").is_some() => panic!("{name} under CI: {e}"),
        Err(e) => eprintln!("{name} not run: {e}"),
    }
}

/// Each held phase, on a dev build's timings: a probe reads the profile
/// open, its lock's mtime advances, a second run is `busy`, and a delete
/// is refused (the profile is open) with nothing removed; released, the
/// move ends `migrated`.
#[test]
fn each_held_phase_reads_open_and_refuses_a_second_run_and_a_delete() {
    for step in [
        "after-exclusion",
        "after-freedom-dir",
        "after-journal",
        "mid-move",
        "after-renames",
        "after-marker",
        "after-placeholder",
        "before-journal-removed",
    ] {
        let d = dirs();
        let app = d.base.join("app");
        let run = |args: &[&str]| {
            Command::new(BIN)
                .args(args)
                .stdin(Stdio::null())
                .output()
                .unwrap()
        };
        for extra in [&[][..], &["--profile", "work"][..]] {
            let mut args = vec![
                "profile",
                "open",
                "--app-root",
                s(&app),
                "--lock-dir",
                s(&d.locks),
            ];
            args.extend_from_slice(extra);
            assert_eq!(code(&run(&args)), 0);
        }
        let work = app.join("Profiles").join("work");
        seeded(&work);
        let paused = d.base.join("paused");
        let release = d.base.join("release");
        let child = Command::new(BIN)
            .args([
                "profile",
                "migrate",
                "--profile-dir",
                s(&work),
                "--lock-dir",
                s(&d.locks),
                "--dev",
            ])
            .env(
                "FREEDOM_CORED_TEST_PROFILE_MIGRATE_PAUSE",
                format!("{step}={}={}", paused.display(), release.display()),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        wait_for(&paused);

        let out = run(&[
            "profile",
            "status",
            "--lock-dir",
            s(&d.locks),
            "--dev",
            "--user-data-dir",
            s(&work),
        ]);
        let status: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(status[0]["open"], true, "{step}: {status}");
        assert_eq!(status[0]["gate_held"], true, "{step}: {status}");

        let lock = work.join("profile-open.lock");
        let first = std::fs::metadata(&lock).unwrap().modified().unwrap();
        std::thread::sleep(Duration::from_millis(2_500));
        let later = std::fs::metadata(&lock).unwrap().modified().unwrap();
        assert_ne!(first, later, "{step}: refreshed past the update period");

        let out = start_env(&work, &d.locks, &["--dev"], &[]);
        assert_eq!((code(&out), said(&out)), (75, "busy".into()), "{step}");

        let out = run(&[
            "profile",
            "delete",
            "--app-root",
            s(&app),
            "--lock-dir",
            s(&d.locks),
            "--id",
            "work",
            "--confirm-display-name",
            "Work",
        ]);
        // The move's lock is fresh: the reference's refusal, before any gate
        // is tried (a stale lease with the gate held would be `lock_held`).
        assert_eq!(code(&out), 65, "{step}: {out:?}");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["message"],
            "Profile is currently open: Work",
            "{step}"
        );
        assert!(work.join("profile.json").is_file(), "{step}: not deleted");

        std::fs::write(&release, "").unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(said(&out), "migrated", "{step}: {out:?}");
        assert_new_layout(&work);
    }
}

/// A run frozen (SIGSTOP) past the stale time while a proper-lockfile
/// client takes its stale lock over: once thawed it changes nothing more
/// and ends with `lock_lost`, the journal kept and the other's lock left;
/// the next start settles the move.
#[cfg(unix)]
#[test]
fn a_frozen_run_whose_lock_is_taken_over_changes_nothing_more() {
    let signal = |name: &str, pid: u32| {
        let status = Command::new("kill")
            .args([name, &pid.to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    };
    let d = dirs();
    seeded(&d.profile);
    let paused = d.base.join("paused");
    let release = d.base.join("release");
    let child = Command::new(BIN)
        .args([
            "profile",
            "migrate",
            "--profile-dir",
            s(&d.profile),
            "--lock-dir",
            s(&d.locks),
            "--dev",
        ])
        .env(
            "FREEDOM_CORED_TEST_PROFILE_MIGRATE_PAUSE",
            format!("mid-move={}={}", paused.display(), release.display()),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for(&paused);
    let before = snapshot(&d.profile);
    assert!(d.profile.join("freedom").join("identity").is_dir());
    signal("-STOP", child.id());
    // Past a dev build's 5 s stale time.
    std::thread::sleep(Duration::from_millis(6_500));
    let lock = d.profile.join("profile-open.lock");
    let age = SystemTime::now()
        .duration_since(std::fs::metadata(&lock).unwrap().modified().unwrap())
        .unwrap();
    assert!(age > Duration::from_secs(5), "{age:?}");
    // proper-lockfile's stale takeover: removed, then made again.
    std::fs::remove_dir(&lock).unwrap();
    std::fs::create_dir(&lock).unwrap();
    signal("-CONT", child.id());
    // Its refresher finds the mtime isn't its own before the run goes on.
    std::thread::sleep(Duration::from_millis(2_000));
    std::fs::write(&release, "").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        (code(&out), said(&out)),
        (74, "lock_lost".into()),
        "{out:?}"
    );
    assert_eq!(snapshot(&d.profile), before, "nothing more changed");
    assert!(lock.is_dir(), "the other's lock stays");

    backdate(&lock, Duration::from_secs(60));
    let out = migrate_env(&d.profile, &d.locks, &["--dev"], &[]);
    assert_eq!(said(&out), "rolled_back", "{out:?}");
    assert_old_layout(&d.profile);
}

// The cross-device copy (PRF-9c): an entry on another device than
// `freedom/` copied in place of its rename.
// `FREEDOM_CORED_TEST_PROFILE_MIGRATE_EXDEV` stands for a `freedom/` on
// another volume, on one file system; the `mounted_` tests mount real
// ones (a tmpfs, a bind mount).

const EXDEV: &str = "FREEDOM_CORED_TEST_PROFILE_MIGRATE_EXDEV";
const CRASH: &str = "FREEDOM_CORED_TEST_PROFILE_MIGRATE_CRASH";
const PAUSE: &str = "FREEDOM_CORED_TEST_PROFILE_MIGRATE_PAUSE";
const FREE: &str = "FREEDOM_CORED_TEST_PROFILE_MIGRATE_FREE";
const ENOSPC: &str = "FREEDOM_CORED_TEST_PROFILE_MIGRATE_ENOSPC";

/// The seeded entries the hook copies: a directory, a file and a node's
/// tree, beside the others, renamed as before.
const COPIED: &str = "identity,settings.json,tor-data";

/// The journal's `copied`, as written.
fn copied_names(profile: &Path) -> Vec<String> {
    let journal: serde_json::Value =
        serde_json::from_str(&read(&profile.join("freedom").join(".move.json"))).unwrap();
    journal["copied"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap().to_owned())
        .collect()
}

/// A starting run in the background, paused at `step` until `release`.
fn start_paused(
    profile: &Path,
    locks: &Path,
    step: &str,
    paused: &Path,
    release: &Path,
    env: &[(&str, &str)],
) -> Child {
    let mut command = Command::new(BIN);
    command
        .args([
            "profile",
            "migrate",
            "--profile-dir",
            s(profile),
            "--lock-dir",
            s(locks),
        ])
        .env(
            PAUSE,
            format!("{step}={}={}", paused.display(), release.display()),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }
    command.spawn().unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Before the marker every copied entry is at both places, named in the
/// journal's `copied`, with no `.moving` left; the renamed ones are in
/// `freedom/` alone. After it, the sources are gone and the profile is in
/// the new layout, a copied file keeping its permission bits.
#[test]
fn an_entry_on_another_device_is_copied_and_its_source_kept_until_the_marker() {
    let d = dirs();
    seeded(&d.profile);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let vault = d.profile.join("identity").join("vault.json");
        std::fs::set_permissions(&vault, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (paused, release) = (d.base.join("paused"), d.base.join("release"));
    let child = start_paused(
        &d.profile,
        &d.locks,
        "after-renames",
        &paused,
        &release,
        &[(EXDEV, COPIED)],
    );
    wait_for(&paused);
    let freedom = d.profile.join("freedom");
    assert_eq!(
        copied_names(&d.profile),
        ["identity", "settings.json", "tor-data"]
    );
    for path in [
        Path::new("identity").join("vault.json"),
        PathBuf::from("settings.json"),
        Path::new("tor-data")
            .join("state")
            .join("state")
            .join("state.lock"),
    ] {
        assert!(d.profile.join(&path).is_file(), "{path:?}: its source kept");
        assert!(freedom.join(&path).is_file(), "{path:?}: its copy");
    }
    for name in ["identity", "settings.json", "tor-data"] {
        assert!(!there(&freedom.join(format!("{name}.moving"))), "{name}");
    }
    for name in ["ant-data", "ipfs-data", "myotis"] {
        assert!(!there(&d.profile.join(name)) && there(&freedom.join(name)));
    }
    assert!(!there(&freedom.join("layout.json")));
    std::fs::write(&release, "").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!((code(&out), said(&out)), (0, "migrated".into()), "{out:?}");
    assert!(stderr(&out).contains("it is copied"), "{out:?}");
    assert_new_layout(&d.profile);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let vault = freedom.join("identity").join("vault.json");
        let mode = std::fs::metadata(vault).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert_eq!(said(&start(&d)), "nothing");
}

/// A kill at each step of a copy, then `--finish-only`: before the marker
/// the old layout opens, with no copy or `.moving` left (a kill after the
/// copy's rename, with the entry at both places, is MG1's case); after it
/// the new one, the sources removed by the roll-forward, a half-removed
/// one too.
#[test]
fn a_kill_at_each_step_of_a_copy_is_settled_by_finish_only() {
    for (step, marked) in [
        ("before-copy", false),
        ("mid-copy", false),
        ("after-copy", false),
        ("after-renames", false),
        ("after-marker", true),
        ("mid-cleanup", true),
        ("after-cleanup", true),
    ] {
        let d = dirs();
        seeded(&d.profile);
        let out = start_env(&d.profile, &d.locks, &[], &[(EXDEV, COPIED), (CRASH, step)]);
        assert_eq!(code(&out), 99, "{step}: {out:?}");
        let freedom = d.profile.join("freedom");
        let vault = Path::new("identity").join("vault.json");
        match step {
            "before-copy" => {
                assert_eq!(copied_names(&d.profile), ["identity"], "{step}");
                assert!(!there(&freedom.join("identity.moving")));
            }
            "mid-copy" => {
                assert!(freedom.join("identity.moving").is_dir(), "{step}");
                assert!(!there(&freedom.join("identity")));
            }
            "after-copy" => {
                assert!(freedom.join(&vault).is_file(), "{step}");
                assert!(d.profile.join(&vault).is_file(), "{step}");
                assert!(!there(&freedom.join("identity.moving")));
            }
            "mid-cleanup" => {
                assert!(d.profile.join("identity").is_dir(), "{step}");
                assert!(!there(&d.profile.join(&vault)), "{step}: half removed");
            }
            _ => {}
        }
        backdate(
            &d.profile.join("profile-open.lock"),
            Duration::from_secs(31),
        );
        let out = migrate(&d);
        if marked {
            assert_eq!(said(&out), "migrated", "{step}: {out:?}");
            assert_new_layout(&d.profile);
            continue;
        }
        assert_eq!(said(&out), "rolled_back", "{step}: {out:?}");
        assert_entries_at_the_root(&d.profile);
        assert!(!there(&freedom), "{step}: no copy left, freedom/ removed");
        let out = start_env(&d.profile, &d.locks, &[], &[(EXDEV, COPIED)]);
        assert_eq!(said(&out), "migrated", "{step}: {out:?}");
        assert_new_layout(&d.profile);
    }
}

/// A volume that fills mid-copy (`StorageFull` after the copy has made two
/// entries): rolled back, an entry copied whole and one cut short both
/// gone, the old layout as it was. The next start moves it.
#[test]
fn a_full_volume_mid_copy_rolls_back() {
    let d = dirs();
    seeded(&d.profile);
    let out = start_env(
        &d.profile,
        &d.locks,
        &[],
        &[(EXDEV, "ant-data,tor-data"), (ENOSPC, "2")],
    );
    assert_eq!(
        (code(&out), said(&out)),
        (0, "rolled_back".into()),
        "{out:?}"
    );
    assert!(stderr(&out).contains("no storage space"), "{out:?}");
    assert_entries_at_the_root(&d.profile);
    assert!(!there(&d.profile.join("freedom")));
    assert_eq!(said(&start(&d)), "migrated");
    assert_new_layout(&d.profile);
}

/// The free-space check: too little before anything changes defers the
/// move with nothing changed; room then, but too little at the copy (the
/// volume filled meanwhile), rolls it back; room throughout moves it.
#[test]
fn the_free_space_check_defers_or_rolls_back() {
    let d = dirs();
    seeded(&d.profile);
    let free = d.base.join("free");
    write(&free, "1000");
    let before = snapshot(&d.profile);
    let out = start_env(&d.profile, &d.locks, &[], &[(EXDEV, "*"), (FREE, s(&free))]);
    assert_eq!((code(&out), said(&out)), (0, "deferred".into()), "{out:?}");
    assert!(stderr(&out).contains("no_space"), "{out:?}");
    assert_eq!(snapshot(&d.profile), before, "nothing changed");

    write(&free, "1000000000000");
    let (paused, release) = (d.base.join("paused"), d.base.join("release"));
    let child = start_paused(
        &d.profile,
        &d.locks,
        "after-exclusion",
        &paused,
        &release,
        &[(EXDEV, "*"), (FREE, s(&free))],
    );
    wait_for(&paused);
    write(&free, "1000");
    std::fs::write(&release, "").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(said(&out), "rolled_back", "{out:?}");
    assert!(stderr(&out).contains("no_space"), "{out:?}");
    assert_entries_at_the_root(&d.profile);
    assert!(!there(&d.profile.join("freedom")));

    write(&free, "1000000000000");
    let out = start_env(&d.profile, &d.locks, &[], &[(EXDEV, "*"), (FREE, s(&free))]);
    assert_eq!(said(&out), "migrated", "{out:?}");
    assert_new_layout(&d.profile);
}

/// Symlinks inside a copied entry are copied as links, whatever they point
/// at; an entry that is a symlink is copied as the link, its target left
/// where it is.
#[cfg(unix)]
#[test]
fn symlinks_in_a_copied_entry_are_copied_as_links() {
    use std::os::unix::fs::symlink;
    let d = dirs();
    seeded(&d.profile);
    let ant = d.profile.join("ant-data");
    let elsewhere = d.base.join("elsewhere");
    write(&elsewhere.join("freedom-ipfs").join("b"), "block");
    symlink("config.yaml", ant.join("relative")).unwrap();
    symlink(&elsewhere, ant.join("absolute")).unwrap();
    symlink("nowhere", ant.join("dangling")).unwrap();
    std::fs::remove_dir_all(d.profile.join("ipfs-data")).unwrap();
    symlink(&elsewhere, d.profile.join("ipfs-data")).unwrap();
    let out = start_env(&d.profile, &d.locks, &[], &[(EXDEV, "ant-data,ipfs-data")]);
    assert_eq!(said(&out), "migrated", "{out:?}");
    let freedom = d.profile.join("freedom");
    for (name, target) in [
        ("relative", PathBuf::from("config.yaml")),
        ("absolute", elsewhere.clone()),
        ("dangling", PathBuf::from("nowhere")),
    ] {
        let link = freedom.join("ant-data").join(name);
        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(std::fs::read_link(&link).unwrap(), target, "{name}");
    }
    let moved = freedom.join("ipfs-data");
    assert!(std::fs::symlink_metadata(&moved).unwrap().is_symlink());
    assert_eq!(std::fs::read_link(&moved).unwrap(), elsewhere);
    assert_eq!(read(&elsewhere.join("freedom-ipfs").join("b")), "block");
    assert_new_layout(&d.profile);
}

/// What a copy can't move defers the move before anything changes: a
/// socket or a FIFO inside a copied entry (never opened, so never waited
/// on), a file this process can't read, a tree deeper than a copy goes.
/// Renamed instead, the same entry moves.
#[cfg(unix)]
#[test]
fn what_a_copy_cant_move_defers_the_move_with_nothing_changed() {
    use std::os::unix::fs::PermissionsExt;
    let deferred = |d: &Dirs, why: &str| {
        let out = start_env(&d.profile, &d.locks, &[], &[(EXDEV, "*")]);
        assert_eq!(
            (code(&out), said(&out)),
            (0, "deferred".into()),
            "{why}: {out:?}"
        );
        assert!(stderr(&out).contains(why), "{why}: {out:?}");
        assert_entries_at_the_root(&d.profile);
        assert!(!there(&d.profile.join("freedom")), "{why}");
        assert!(!d.profile.join("profile-open.lock").exists(), "{why}");
        assert_eq!(said(&start(d)), "migrated", "{why}: renamed instead");
        assert_new_layout(&d.profile);
    };

    let d = dirs();
    seeded(&d.profile);
    let _socket =
        std::os::unix::net::UnixListener::bind(d.profile.join("ant-data").join("s")).unwrap();
    deferred(&d, "special_file");

    let d = dirs();
    seeded(&d.profile);
    let fifo = d.profile.join("tor-data").join("fifo");
    let made = Command::new("mkfifo").arg(&fifo).status().unwrap();
    assert!(made.success());
    deferred(&d, "special_file");

    let d = dirs();
    seeded(&d.profile);
    let mut deep = d.profile.join("ipfs-data");
    for _ in 0..=fc_store::anchor::MAX_DEPTH {
        deep.push("d");
    }
    std::fs::create_dir_all(&deep).unwrap();
    deferred(&d, "too_deep");

    // Root reads and removes anything: the modes bind only another user.
    // A file that can't be read can't be copied; one in a directory without
    // write permission can't be removed after the marker.
    let d = dirs();
    seeded(&d.profile);
    let secret = d.profile.join("ant-data").join("config.yaml");
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&secret).is_err() {
        let out = start_env(&d.profile, &d.locks, &[], &[(EXDEV, "*")]);
        assert_eq!(said(&out), "deferred", "{out:?}");
        assert!(stderr(&out).contains("no_access"), "{out:?}");
        assert!(!there(&d.profile.join("freedom")));
    }
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();

    let d = dirs();
    seeded(&d.profile);
    let shut = d.profile.join("tor-data").join("state");
    std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::write(shut.join("probe"), "x").is_err() {
        let out = start_env(&d.profile, &d.locks, &[], &[(EXDEV, "*")]);
        assert_eq!(said(&out), "deferred", "{out:?}");
        assert!(stderr(&out).contains("no_access"), "{out:?}");
        assert!(stderr(&out).contains("tor-data/state"), "{out:?}");
        assert!(!there(&d.profile.join("freedom")));
    }
    std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// On Windows a reparse point (here a junction) inside a copied entry
/// defers the move: making one again takes a privilege a user lacks.
#[cfg(windows)]
#[test]
fn a_reparse_point_in_an_entry_to_copy_defers_the_move() {
    let d = dirs();
    seeded(&d.profile);
    let target = d.base.join("elsewhere");
    std::fs::create_dir_all(&target).unwrap();
    let native = |path: &Path| path.components().collect::<PathBuf>();
    let status = Command::new("cmd")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(native(&d.profile.join("ant-data").join("link")))
        .arg(native(&target))
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "mklink /J");
    let before = snapshot(&d.profile);
    let out = start_env(&d.profile, &d.locks, &[], &[(EXDEV, "*")]);
    assert_eq!((code(&out), said(&out)), (0, "deferred".into()), "{out:?}");
    assert!(stderr(&out).contains("reparse_point"), "{out:?}");
    assert_eq!(snapshot(&d.profile), before);
    assert_eq!(said(&start(&d)), "migrated", "renamed instead");
}

/// A mount made with `sudo -n` while `FREEDOM_TEST_MOUNTS` is set (CI's
/// Linux step), unmounted when dropped (at the path it was moved to, if it
/// was): a tmpfs owned by this process's user, or a bind mount. `None`
/// without the variable: the test then checks nothing.
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

    /// `from` mounted again at `at`: the same file system and device, on
    /// another mount.
    fn bind(from: &Path, at: &Path) -> Option<Mounted> {
        Mounted::run(at, &["--bind", s(from)])
    }

    fn run(at: &Path, args: &[&str]) -> Option<Mounted> {
        std::env::var_os("FREEDOM_TEST_MOUNTS")?;
        let status = Command::new("sudo")
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
        let _ = Command::new("sudo")
            .args(["-n", "umount", "-l"])
            .arg(&self.0)
            .status();
    }
}

#[cfg(target_os = "linux")]
fn device(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).unwrap().dev()
}

/// A genuine `EXDEV`: `freedom/` is a tmpfs mounted before the move, so
/// every entry (a symlinked one included) is copied, each source kept until
/// the marker and removed after it. `freedom/` stays the mount.
#[cfg(target_os = "linux")]
#[test]
fn mounted_tmpfs_freedom_dir_on_another_volume_takes_the_copy() {
    let d = dirs();
    seeded(&d.profile);
    let elsewhere = d.base.join("elsewhere");
    write(&elsewhere.join("config.yaml"), "ant");
    std::fs::remove_dir_all(d.profile.join("ant-data")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, d.profile.join("ant-data")).unwrap();
    let freedom = d.profile.join("freedom");
    std::fs::create_dir(&freedom).unwrap();
    let Some(_mounted) = Mounted::tmpfs(&freedom, "256m") else {
        return;
    };
    assert_ne!(device(&freedom), device(&d.profile));
    let (paused, release) = (d.base.join("paused"), d.base.join("release"));
    let child = start_paused(
        &d.profile,
        &d.locks,
        "after-renames",
        &paused,
        &release,
        &[],
    );
    wait_for(&paused);
    assert_eq!(copied_names(&d.profile), SEEDED);
    for name in SEEDED {
        assert!(there(&d.profile.join(name)), "{name}: its source kept");
        assert!(there(&freedom.join(name)), "{name}: its copy");
    }
    std::fs::write(&release, "").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!((code(&out), said(&out)), (0, "migrated".into()), "{out:?}");
    assert_new_layout(&d.profile);
    let link = freedom.join("ant-data");
    assert_eq!(std::fs::read_link(&link).unwrap(), elsewhere);
    assert_eq!(read(&elsewhere.join("config.yaml")), "ant");
    assert_ne!(device(&freedom), device(&d.profile), "still the mount");
    assert_eq!(said(&start(&d)), "nothing");
}

/// A `freedom/` volume too small for the copy's margin defers the move
/// before anything changes.
#[cfg(target_os = "linux")]
#[test]
fn mounted_tmpfs_too_small_for_the_copy_defers_it() {
    let d = dirs();
    seeded(&d.profile);
    let freedom = d.profile.join("freedom");
    std::fs::create_dir(&freedom).unwrap();
    let Some(_mounted) = Mounted::tmpfs(&freedom, "16m") else {
        return;
    };
    let before = snapshot(&d.profile);
    let out = start(&d);
    assert_eq!((code(&out), said(&out)), (0, "deferred".into()), "{out:?}");
    assert!(stderr(&out).contains("no_space"), "{out:?}");
    assert_eq!(snapshot(&d.profile), before);
}

/// A genuine `ENOSPC`: the volume fills after the free-space check, while
/// the run is paused before its first copy. The copy fails and the move
/// rolls back: no `.moving` left, the journal gone, the sources intact, the
/// filler and the mount where they were. With room again, it moves.
#[cfg(target_os = "linux")]
#[test]
fn mounted_tmpfs_that_fills_mid_move_rolls_back() {
    use std::io::Write as _;
    let d = dirs();
    seeded(&d.profile);
    write(
        &d.profile.join("ant-data").join("bulk"),
        &"x".repeat(1 << 20),
    );
    let freedom = d.profile.join("freedom");
    std::fs::create_dir(&freedom).unwrap();
    let Some(_mounted) = Mounted::tmpfs(&freedom, "80m") else {
        return;
    };
    let (paused, release) = (d.base.join("paused"), d.base.join("release"));
    let child = start_paused(&d.profile, &d.locks, "before-copy", &paused, &release, &[]);
    wait_for(&paused);
    let mut filler = std::fs::File::create(freedom.join("filler")).unwrap();
    let chunk = vec![0u8; 1 << 20];
    let full = loop {
        if let Err(e) = filler.write_all(&chunk).and_then(|()| filler.sync_all()) {
            break e;
        }
    };
    assert_eq!(full.kind(), std::io::ErrorKind::StorageFull);
    drop(filler);
    std::fs::write(&release, "").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        (code(&out), said(&out)),
        (0, "rolled_back".into()),
        "{out:?}"
    );
    assert_entries_at_the_root(&d.profile);
    assert_eq!(
        names(&freedom),
        ["filler"],
        "no copy, no .moving, no journal"
    );
    std::fs::remove_file(freedom.join("filler")).unwrap();
    assert_eq!(said(&start(&d)), "migrated");
    assert_new_layout(&d.profile);
}

/// A mount point inside an entry: with `freedom/` on another volume, the
/// move is deferred before anything changes, the mounted volume untouched
/// (a copy would pull it across, and the source's removal would empty it).
/// With `freedom/` on the profile's own volume the entry is renamed, and
/// the mount goes along with it, whole.
#[cfg(target_os = "linux")]
#[test]
fn mounted_tmpfs_nested_in_an_entry_is_never_crossed() {
    let d = dirs();
    seeded(&d.profile);
    let inner = d.profile.join("ant-data").join("mnt");
    std::fs::create_dir(&inner).unwrap();
    let freedom = d.profile.join("freedom");
    std::fs::create_dir(&freedom).unwrap();
    let Some(_freedom) = Mounted::tmpfs(&freedom, "256m") else {
        return;
    };
    let Some(_inner) = Mounted::tmpfs(&inner, "1m") else {
        return;
    };
    write(&inner.join("kept"), "kept");
    let before = snapshot(&d.profile);
    let out = start(&d);
    assert_eq!((code(&out), said(&out)), (0, "deferred".into()), "{out:?}");
    assert!(stderr(&out).contains("nested_mount"), "{out:?}");
    assert!(stderr(&out).contains("ant-data/mnt"), "{out:?}");
    assert_eq!(snapshot(&d.profile), before);

    let d = dirs();
    seeded(&d.profile);
    let inner = d.profile.join("ant-data").join("mnt");
    std::fs::create_dir(&inner).unwrap();
    let Some(mut mounted) = Mounted::tmpfs(&inner, "1m") else {
        return;
    };
    write(&inner.join("kept"), "kept");
    let out = start(&d);
    let moved = d.profile.join("freedom").join("ant-data").join("mnt");
    if said(&out) == "migrated" {
        mounted.0 = moved.clone();
    }
    assert_eq!(said(&out), "migrated", "{out:?}");
    assert_new_layout(&d.profile);
    assert_eq!(read(&moved.join("kept")), "kept");
    assert_ne!(device(&moved), device(&d.profile), "still the mount");
}

/// After the marker, the cleanup removes a copied entry's source only while
/// it is of its copy's kind (`roll_forward`'s rule), judged right before
/// the removal: a copied directory replaced by a file, or a copied file
/// replaced by a directory, while the run is paused at the marker, isn't
/// its source, and stays. The other copied sources go.
#[test]
fn after_the_marker_a_replaced_source_stays() {
    type Replace = fn(&Path);
    let cases: [(&str, Replace, Replace); 2] = [
        (
            "identity",
            |profile| {
                std::fs::remove_dir_all(profile.join("identity")).unwrap();
                write(&profile.join("identity"), "made since");
            },
            |profile| assert_eq!(read(&profile.join("identity")), "made since"),
        ),
        (
            "settings.json",
            |profile| {
                std::fs::remove_file(profile.join("settings.json")).unwrap();
                write(&profile.join("settings.json").join("kept"), "made since");
            },
            |profile| {
                assert_eq!(
                    read(&profile.join("settings.json").join("kept")),
                    "made since"
                );
            },
        ),
    ];
    for (name, replace, kept) in cases {
        let d = dirs();
        seeded(&d.profile);
        let (paused, release) = (d.base.join("paused"), d.base.join("release"));
        let child = start_paused(
            &d.profile,
            &d.locks,
            "after-marker",
            &paused,
            &release,
            &[(EXDEV, COPIED)],
        );
        wait_for(&paused);
        replace(&d.profile);
        std::fs::write(&release, "").unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(
            (code(&out), said(&out)),
            (0, "migrated".into()),
            "{name}: {out:?}"
        );
        kept(&d.profile);
        let freedom = d.profile.join("freedom");
        assert_eq!(read(&freedom.join("identity").join("vault.json")), "vault");
        assert_eq!(read(&freedom.join("settings.json")), "{}");
        assert!(
            !there(&d.profile.join("tor-data")),
            "{name}: a source of its kind goes"
        );
        assert!(!there(&freedom.join(".move.json")), "{name}");
    }
}

/// A same-file-system bind mount inside an entry to copy (the case
/// `STATX_MNT_ID` is for: its device is its parent's): the move is
/// deferred before anything changes, the file reached through it kept.
#[cfg(target_os = "linux")]
#[test]
fn mounted_bind_in_an_entry_to_copy_defers_the_move() {
    use std::os::unix::fs::MetadataExt;
    let d = dirs();
    seeded(&d.profile);
    let outside = d.base.join("outside");
    write(&outside.join("kept"), "kept");
    let bound = d.profile.join("ant-data").join("bound");
    std::fs::create_dir(&bound).unwrap();
    let Some(_bound) = Mounted::bind(&outside, &bound) else {
        return;
    };
    let dev = |path: &Path| std::fs::metadata(path).unwrap().dev();
    assert_eq!(dev(&bound), dev(&d.profile.join("ant-data")));
    let out = start_env(&d.profile, &d.locks, &[], &[(EXDEV, "*")]);
    assert_eq!((code(&out), said(&out)), (0, "deferred".into()), "{out:?}");
    assert!(stderr(&out).contains("nested_mount"), "{out:?}");
    assert!(stderr(&out).contains("ant-data/bound"), "{out:?}");
    assert!(!there(&d.profile.join("freedom")));
    assert_entries_at_the_root(&d.profile);
    assert_eq!(read(&outside.join("kept")), "kept");
}

/// The cap: a move copies at most 2 GiB in all. Past it in the
/// preconditions, the move is deferred with nothing changed; past it at a
/// copy's survey (an entry grown since, while the run was paused), it rolls
/// back; and a file added after that survey too (at `before-copy`) is
/// refused by the copy's own budget, before any of it is copied: rolled
/// back, the source intact, no `.moving` left. The files are sparse: their
/// length counts, not their blocks.
#[cfg(unix)]
#[test]
fn a_copy_past_the_cap_defers_or_rolls_back() {
    const CAP: u64 = 2 * 1024 * 1024 * 1024;
    let big = |profile: &Path| {
        let file = std::fs::File::create(profile.join("ant-data").join("big")).unwrap();
        file.set_len(CAP + 1).unwrap();
    };
    let room = |d: &Dirs| {
        let free = d.base.join("free");
        write(&free, "100000000000000");
        free
    };
    let d = dirs();
    seeded(&d.profile);
    big(&d.profile);
    let free = room(&d);
    let out = start_env(
        &d.profile,
        &d.locks,
        &[],
        &[(EXDEV, "ant-data"), (FREE, s(&free))],
    );
    assert_eq!((code(&out), said(&out)), (0, "deferred".into()), "{out:?}");
    assert!(stderr(&out).contains("copy_too_large"), "{out:?}");
    assert_entries_at_the_root(&d.profile);
    assert!(!there(&d.profile.join("freedom")));

    let d = dirs();
    seeded(&d.profile);
    let free = room(&d);
    let (paused, release) = (d.base.join("paused"), d.base.join("release"));
    let child = start_paused(
        &d.profile,
        &d.locks,
        "after-exclusion",
        &paused,
        &release,
        &[(EXDEV, "ant-data"), (FREE, s(&free))],
    );
    wait_for(&paused);
    big(&d.profile);
    std::fs::write(&release, "").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        (code(&out), said(&out)),
        (0, "rolled_back".into()),
        "{out:?}"
    );
    assert!(stderr(&out).contains("copy_too_large"), "{out:?}");
    assert_entries_at_the_root(&d.profile);
    assert!(!there(&d.profile.join("freedom")));

    let d = dirs();
    seeded(&d.profile);
    let free = room(&d);
    let (paused, release) = (d.base.join("paused"), d.base.join("release"));
    let child = start_paused(
        &d.profile,
        &d.locks,
        "before-copy",
        &paused,
        &release,
        &[(EXDEV, "ant-data"), (FREE, s(&free))],
    );
    wait_for(&paused);
    assert_eq!(copied_names(&d.profile), ["ant-data"]);
    big(&d.profile);
    let started = Instant::now();
    std::fs::write(&release, "").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        (code(&out), said(&out)),
        (0, "rolled_back".into()),
        "{out:?}"
    );
    assert!(stderr(&out).contains("past its budget"), "{out:?}");
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "nothing copied past the budget"
    );
    assert_entries_at_the_root(&d.profile);
    assert!(!there(&d.profile.join("freedom")), "no .moving left");
}

/// Windows: the survey probes the rights a copy and its source's removal
/// take. A file whose data can't be read defers the move with nothing
/// changed; once readable, it moves.
#[cfg(windows)]
#[test]
fn a_file_the_core_cant_read_defers_the_copy_on_windows() {
    let icacls = |path: &Path, args: &[&str]| {
        let output = Command::new("icacls")
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
    let d = dirs();
    seeded(&d.profile);
    let secret = d.profile.join("ant-data").join("config.yaml");
    icacls(&secret, &["/deny", "*S-1-1-0:(RD)"]);
    let out = start_env(&d.profile, &d.locks, &[], &[(EXDEV, "*")]);
    icacls(&secret, &["/remove:d", "*S-1-1-0"]);
    assert_eq!((code(&out), said(&out)), (0, "deferred".into()), "{out:?}");
    assert!(stderr(&out).contains("no_access"), "{out:?}");
    assert!(!there(&d.profile.join("freedom")));
    assert_entries_at_the_root(&d.profile);
    let out = start_env(&d.profile, &d.locks, &[], &[(EXDEV, "*")]);
    assert_eq!(said(&out), "migrated", "{out:?}");
    assert_new_layout(&d.profile);
}

/// The cap across copies (review of #451, round 3): each finished copy is
/// charged at least the bytes it wrote. `ant-data` surveys small and
/// `ipfs-data` at 1.2 GiB, within the cap together. At `ant-data`'s
/// `before-copy` pause a 1.2 GiB file is added to it: its copy, within its
/// own budget, goes through, and then `ipfs-data` would take the move past
/// 2 GiB, so it is refused and the move rolls back, both sources intact and
/// no `.moving` left. The files are sparse.
#[cfg(unix)]
#[test]
fn a_copy_grown_since_its_survey_counts_against_the_next() {
    const PART: u64 = 1200 * 1024 * 1024;
    let sparse = |path: &Path| {
        std::fs::File::create(path).unwrap().set_len(PART).unwrap();
    };
    let d = dirs();
    seeded(&d.profile);
    write(&d.profile.join("ipfs-data").join("big"), "");
    sparse(&d.profile.join("ipfs-data").join("big"));
    let free = d.base.join("free");
    write(&free, "100000000000000");
    let (paused, release) = (d.base.join("paused"), d.base.join("release"));
    let child = start_paused(
        &d.profile,
        &d.locks,
        "before-copy",
        &paused,
        &release,
        &[(EXDEV, "ant-data,ipfs-data"), (FREE, s(&free))],
    );
    wait_for(&paused);
    assert_eq!(copied_names(&d.profile), ["ant-data"]);
    sparse(&d.profile.join("ant-data").join("grown"));
    std::fs::write(&release, "").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        (code(&out), said(&out)),
        (0, "rolled_back".into()),
        "{out:?}"
    );
    let log = stderr(&out);
    assert!(
        log.contains("copy_too_large") || log.contains("past its budget"),
        "{out:?}"
    );
    assert_entries_at_the_root(&d.profile);
    for path in [
        d.profile.join("ant-data").join("grown"),
        d.profile.join("ipfs-data").join("big"),
    ] {
        assert_eq!(std::fs::metadata(&path).unwrap().len(), PART, "{path:?}");
    }
    assert!(
        !there(&d.profile.join("freedom")),
        "no copy or .moving left"
    );
}
