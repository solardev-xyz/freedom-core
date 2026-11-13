//! `profile delete`, `forget-list` and `forget-done` (design 0013, PRF-3),
//! run as main runs them: the delete under every gate (the stale-lease
//! case), the packaged default profile's shared entries, the forget file
//! through a crash at each step, its bounds, and links refused. A test
//! binary of its own, so its processes don't slow `profile open`'s latency
//! gate in `profiles.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, SystemTime};

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_freedom-cored");

struct Dirs {
    _root: tempfile::TempDir,
    base: PathBuf,
    app: PathBuf,
    locks: PathBuf,
}

fn dirs() -> Dirs {
    let root = tempfile::tempdir().unwrap();
    let base = if cfg!(windows) {
        root.path().to_path_buf()
    } else {
        std::fs::canonicalize(root.path()).unwrap()
    };
    Dirs {
        app: base.join("app"),
        locks: base.join("locks"),
        base,
        _root: root,
    }
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn run_env(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(BIN);
    command.args(args).stdin(Stdio::null());
    for (key, value) in env {
        command.env(key, value);
    }
    command.output().unwrap()
}

fn run(args: &[&str]) -> Output {
    run_env(args, &[])
}

fn json_of(output: &Output) -> Value {
    let text = String::from_utf8(output.stdout.clone()).unwrap();
    serde_json::from_str(text.trim()).unwrap_or_else(|e| panic!("{e}: {text:?}"))
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
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

/// A profile lock as main leaves it, its mtime `age` old.
fn profile_lock(dir: &Path, age: Duration) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("profile-open"), "Freedom profile lock target").unwrap();
    let lock = dir.join("profile-open.lock");
    let _ = std::fs::create_dir(&lock);
    backdate(&lock, age);
}

/// The backend a secrets file names on this OS, and whether a deleted
/// profile's items of it are recorded (not DPAPI's).
fn backend() -> (&'static str, bool) {
    if cfg!(target_os = "macos") {
        ("macos-keychain", true)
    } else if cfg!(windows) {
        ("dpapi", false)
    } else {
        ("secret-service", true)
    }
}

fn hex(c: char) -> String {
    c.to_string().repeat(32)
}

/// A secrets file naming `ids` (the first the unattended key in use, the
/// rest in its `forget` list), as PRF-1 will write it.
fn secrets(ids: &[String]) -> String {
    let (backend, _) = backend();
    let forget: Vec<Value> = ids[1..]
        .iter()
        .map(|id| json!({ "backend": backend, "policy": "user_presence", "item": id }))
        .collect();
    json!({
        "version": 1,
        "keys": { "unattended": { "backend": backend, "item": ids[0], "sealed": null, "pending": null } },
        "forget": forget,
        "entries": {}
    })
    .to_string()
}

/// What a delete or `forget-list` gives for `ids`, as `secrets` names them:
/// none where the backend's items aren't recorded.
fn listed(ids: &[String]) -> Value {
    if !backend().1 {
        return json!([]);
    }
    Value::Array(
        ids.iter()
            .enumerate()
            .map(|(n, id)| {
                json!({ "policy": if n == 0 { "unattended" } else { "user_presence" }, "item": id })
            })
            .collect(),
    )
}

fn open(d: &Dirs, extra: &[&str]) {
    let mut args = vec![
        "profile",
        "open",
        "--app-root",
        s(&d.app),
        "--lock-dir",
        s(&d.locks),
    ];
    args.extend_from_slice(extra);
    let out = run(&args);
    assert_eq!(code(&out), 0, "{out:?}");
}

fn catalog_ids(d: &Dirs) -> Vec<String> {
    let text = std::fs::read_to_string(d.app.join("profile-registry.json")).unwrap();
    let catalog: Value = serde_json::from_str(&text).unwrap();
    catalog["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_str().unwrap().to_owned())
        .collect()
}

/// A used profile `work` beside the default one: its identity (with a
/// secrets file naming `ids`), its IPFS data, other files, and its Radicle
/// home `R/1` with a staging sibling. Returns the profile's directory and
/// its home.
fn setup(d: &Dirs, ids: &[String]) -> (PathBuf, PathBuf) {
    open(d, &[]);
    open(d, &["--profile", "work"]);
    let work = d.app.join("Profiles").join("work");
    std::fs::create_dir_all(work.join("identity")).unwrap();
    std::fs::write(work.join("identity").join("vault.json"), "vault").unwrap();
    std::fs::write(work.join("identity").join("secrets.json"), secrets(ids)).unwrap();
    std::fs::create_dir_all(work.join("ipfs-data").join("freedom-ipfs").join("blocks")).unwrap();
    std::fs::write(
        work.join("ipfs-data")
            .join("freedom-ipfs")
            .join("blocks")
            .join("b"),
        "b",
    )
    .unwrap();
    std::fs::write(work.join("ipfs-data").join("other"), "o").unwrap();
    std::fs::write(work.join("Cookies"), "c").unwrap();
    let home = d.app.join("R").join("1");
    std::fs::create_dir_all(home.join("node")).unwrap();
    std::fs::write(home.join("node").join("n"), "n").unwrap();
    std::fs::create_dir_all(d.app.join("R").join("1.migrating-1-2")).unwrap();
    std::fs::create_dir_all(&d.locks).unwrap();
    (work, home)
}

/// Every file (with its text) and directory under `root`, but the lock
/// directory's lock files, which a gate tried leaves behind.
fn snapshot(d: &Dirs) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![d.base.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path == d.locks || path.parent() == Some(d.locks.as_path()) {
                continue;
            }
            let rel = path
                .strip_prefix(&d.base)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let kind = entry.file_type().unwrap();
            if kind.is_symlink() {
                out.insert(
                    rel,
                    format!("-> {}", std::fs::read_link(&path).unwrap().display()),
                );
            } else if kind.is_dir() {
                out.insert(format!("{rel}/"), String::new());
                stack.push(path);
            } else {
                out.insert(rel, std::fs::read_to_string(&path).unwrap_or_default());
            }
        }
    }
    out
}

fn delete(d: &Dirs, id: &str, confirm: &str, env: &[(&str, &str)]) -> Output {
    run_env(
        &[
            "profile",
            "delete",
            "--app-root",
            s(&d.app),
            "--lock-dir",
            s(&d.locks),
            "--id",
            id,
            "--confirm-display-name",
            confirm,
        ],
        env,
    )
}

fn forget_list(d: &Dirs) -> Value {
    let out = run(&["profile", "forget-list", "--app-root", s(&d.app)]);
    assert_eq!(code(&out), 0, "{out:?}");
    json_of(&out)
}

/// A child that holds a gate until its stdin closes.
fn holder(args: &[&str]) -> Child {
    let mut child = Command::new(BIN)
        .args(args)
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

fn release(mut child: Child) {
    drop(child.stdin.take());
    assert_eq!(child.wait().unwrap().code(), Some(0));
}

/// A gate held for the test.
enum Hold {
    Child(Child),
    Gate(fc_service::gate::Gate),
}

/// **The stale-lease case** (0013, PRF-3's acceptance): with the profile's
/// lock backdated 31 s, any one of its profile, core, IPFS or Radicle gate
/// held refuses the delete with `lock_held`, and nothing changes. With
/// none held, it goes, the Radicle home and its staging copy with it.
#[test]
fn a_stale_lease_with_any_gate_held_refuses_the_delete() {
    let d = dirs();
    let ids = [hex('a'), hex('b')];
    let (work, home) = setup(&d, &ids);
    profile_lock(&work, Duration::from_secs(31));
    let before = snapshot(&d);
    for gate in ["profile", "core", "ipfs", "radicle"] {
        let hold = match gate {
            "profile" => Hold::Child(holder(&[
                "hold-profile",
                "--user-data-dir",
                s(&work),
                "--lock-dir",
                s(&d.locks),
                "--app-root",
                s(&d.app),
                "--id",
                "work",
            ])),
            "core" => Hold::Child(holder(&[
                "hold-lock",
                "--data-dir",
                s(&work.join("identity")),
                "--lock-dir",
                s(&d.locks),
            ])),
            "ipfs" => Hold::Gate(
                fc_service::gate::acquire(
                    &work.join("ipfs-data").join("freedom-ipfs"),
                    &d.locks,
                    "ipfs",
                    Duration::ZERO,
                )
                .unwrap(),
            ),
            _ => Hold::Gate(
                fc_service::gate::acquire(&home, &d.locks, "radicle", Duration::ZERO).unwrap(),
            ),
        };
        let out = delete(&d, "work", "Work", &[]);
        assert_eq!(code(&out), 75, "{gate}: {out:?}");
        assert_eq!(json_of(&out), json!({ "error": "lock_held", "gate": gate }));
        assert_eq!(snapshot(&d), before, "{gate}: nothing changed");
        match hold {
            Hold::Child(child) => release(child),
            Hold::Gate(gate) => drop(gate),
        }
    }

    // A fresh lock: open, as `isProfileLocked` reads it.
    profile_lock(&work, Duration::from_secs(1));
    let out = delete(&d, "work", "Work", &[]);
    assert_eq!(code(&out), 65, "{out:?}");
    assert_eq!(
        json_of(&out),
        json!({ "error": "refused", "message": "Profile is currently open: Work" })
    );
    profile_lock(&work, Duration::from_secs(31));
    assert_eq!(snapshot(&d), before);

    // The reference's refusals, first.
    let out = delete(&d, "work", "work", &[]);
    assert_eq!(
        json_of(&out)["message"],
        "Profile display name confirmation did not match"
    );

    // No gate held: the delete goes.
    let out = delete(&d, "work", "Work", &[]);
    assert_eq!(code(&out), 0, "{out:?}");
    let result = json_of(&out);
    assert_eq!(result["record"]["id"], "work");
    assert_eq!(result["forget"], listed(&ids));
    assert!(result.get("forget_unknown").is_none());
    assert_eq!(catalog_ids(&d), ["default"]);
    assert_eq!(result["catalog"]["profiles"].as_array().unwrap().len(), 1);
    assert!(!work.exists());
    assert!(!home.exists());
    assert!(!d.app.join("R").join("1.migrating-1-2").exists());
    assert!(d.app.join("R").is_dir());
    // Nothing else at the app root went, and the catalog lock is let go.
    assert!(d.app.join("profile.json").exists());
    assert!(d.app.join("Profiles").is_dir());
    assert!(!d.app.join("profile-registry.write.lock").exists());
    assert_eq!(forget_list(&d)["items"], listed(&ids));
}

/// The packaged default profile's delete removes its entries at the app
/// root and keeps every shared one: `locks/` (the lock directory here), the
/// catalog, the forget file, the other profiles, the Radicle homes'
/// directory, the updater lock and `logs/`.
#[test]
fn the_default_profiles_delete_keeps_the_shared_entries() {
    let d = dirs();
    let locks = d.app.join("locks");
    let open_in = |extra: &[&str]| {
        let mut args = vec![
            "profile",
            "open",
            "--app-root",
            s(&d.app),
            "--lock-dir",
            s(&locks),
        ];
        args.extend_from_slice(extra);
        assert_eq!(code(&run(&args)), 0);
    };
    open_in(&[]);
    open_in(&["--profile", "work"]);
    let ids = [hex('c')];
    std::fs::create_dir_all(d.app.join("identity")).unwrap();
    std::fs::write(d.app.join("identity").join("secrets.json"), secrets(&ids)).unwrap();
    std::fs::create_dir_all(d.app.join("ipfs-data").join("freedom-ipfs")).unwrap();
    std::fs::write(d.app.join("Cookies"), "c").unwrap();
    std::fs::create_dir_all(d.app.join("Local Storage")).unwrap();
    std::fs::create_dir_all(&locks).unwrap();
    std::fs::write(locks.join("other.lock"), "").unwrap();
    std::fs::create_dir_all(d.app.join("logs")).unwrap();
    std::fs::write(d.app.join("logs").join("main.log"), "l").unwrap();
    std::fs::write(d.app.join("updater-owner"), "u").unwrap();
    std::fs::create_dir_all(d.app.join("updater-owner.lock")).unwrap();
    std::fs::create_dir_all(d.app.join("R").join("0")).unwrap();
    std::fs::create_dir_all(d.app.join("R").join("1")).unwrap();
    // A record of a profile deleted earlier.
    let (backend, recorded) = backend();
    let earlier = json!({ "version": 1, "deleted": [{ "id": "old", "dir": s(&d.app.join("Profiles").join("old")),
        "items": [{ "backend": backend, "policy": "unattended", "item": hex('d') }] }] });
    std::fs::write(
        d.app.join("profile-registry.json.forget"),
        serde_json::to_string_pretty(&earlier).unwrap(),
    )
    .unwrap();

    let out = run(&[
        "profile",
        "delete",
        "--app-root",
        s(&d.app),
        "--lock-dir",
        s(&locks),
        "--id",
        "default",
        "--confirm-display-name",
        "My Profile",
    ]);
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(json_of(&out)["forget"], listed(&ids));
    let mut names: Vec<String> = std::fs::read_dir(&d.app)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "Profiles",
            "R",
            "locks",
            "logs",
            "profile-registry.json",
            "profile-registry.json.forget",
            "profile-registry.write-lock-target",
            "updater-owner",
            "updater-owner.lock",
        ]
    );
    assert!(locks.join("other.lock").exists());
    assert!(d.app.join("logs").join("main.log").exists());
    assert!(
        d.app
            .join("Profiles")
            .join("work")
            .join("profile.json")
            .exists()
    );
    assert!(!d.app.join("R").join("0").exists());
    assert!(d.app.join("R").join("1").exists());
    assert_eq!(catalog_ids(&d), ["work"]);
    // The earlier record is kept; this delete's follows it.
    let items = forget_list(&d)["items"].clone();
    if recorded {
        assert_eq!(
            items,
            json!([{ "policy": "unattended", "item": hex('d') }, { "policy": "unattended", "item": hex('c') }])
        );
    } else {
        assert_eq!(items, json!([]));
    }
}

/// **The forget file, killed at each step of a delete** (0013, PRF-3):
/// before the catalog changes, the next `forget-list` drops the record and
/// the profile's own secrets file still names its items, and the profile is
/// still there; after it, `forget-list` returns every item, and
/// `forget-done` removes them.
#[test]
fn a_delete_killed_at_each_step() {
    let ids = [hex('a'), hex('b')];
    let recorded = backend().1;
    for step in [
        "before-record",
        "after-record",
        "after-catalog",
        "mid-removal",
        "before-result",
    ] {
        let d = dirs();
        let (work, _home) = setup(&d, &ids);
        let out = delete(
            &d,
            "work",
            "Work",
            &[("FREEDOM_CORED_TEST_PROFILE_DELETE_CRASH", step)],
        );
        assert_eq!(code(&out), 99, "{step}: {out:?}");
        assert!(out.stdout.is_empty(), "{step}: no result");
        // Killed: its catalog lock is left, and another holder takes it
        // over once stale.
        let lock = d.app.join("profile-registry.write.lock");
        assert!(lock.exists(), "{step}");
        backdate(&lock, Duration::from_secs(31));
        let file = d.app.join("profile-registry.json.forget");
        let before_catalog = matches!(step, "before-record" | "after-record");
        if step == "before-record" || !recorded {
            assert!(!file.exists(), "{step}");
        } else {
            assert!(
                std::fs::read_to_string(&file).unwrap().contains(&ids[1]),
                "{step}"
            );
        }
        if before_catalog {
            assert_eq!(catalog_ids(&d), ["default", "work"], "{step}");
            assert_eq!(forget_list(&d)["items"], json!([]), "{step}");
            // The profile's own file still names its items, and its data is
            // all there.
            assert_eq!(
                std::fs::read_to_string(work.join("identity").join("secrets.json")).unwrap(),
                secrets(&ids)
            );
            assert!(
                work.join("ipfs-data")
                    .join("freedom-ipfs")
                    .join("blocks")
                    .join("b")
                    .exists()
            );
            assert!(work.join("Cookies").exists());
            if recorded && step == "after-record" {
                assert!(
                    !std::fs::read_to_string(&file).unwrap().contains(&ids[0]),
                    "{step}: dropped"
                );
            }
            // It can be deleted again, and then its items are forgotten.
            let out = delete(&d, "work", "Work", &[]);
            assert_eq!(code(&out), 0, "{step}: {out:?}");
        } else {
            assert_eq!(catalog_ids(&d), ["default"], "{step}");
        }
        assert_eq!(forget_list(&d)["items"], listed(&ids), "{step}");
        let done = run(&[
            "profile",
            "forget-done",
            "--app-root",
            s(&d.app),
            "--item",
            &ids[0],
            "--item",
            &ids[1],
        ]);
        assert_eq!(code(&done), 0, "{done:?}");
        assert_eq!(json_of(&done)["removed"], if recorded { 2 } else { 0 });
        assert_eq!(forget_list(&d)["items"], json!([]), "{step}");
    }
}

/// The forget file's rules: a record still named by a profile imported
/// again from its directory is dropped, and one whose id was created again
/// isn't; a full file refuses the delete with nothing changed; a malformed
/// file is set aside and nothing it names is forgotten; a secrets file
/// that can't be read lets the delete go on, with `forget_unknown`.
#[test]
fn the_forget_files_rules() {
    let (backend, recorded) = backend();
    let d = dirs();
    let (work, _home) = setup(&d, &[hex('a')]);
    let record = |id: &str, item: &str| {
        json!({ "id": id, "dir": s(&d.app.join("Profiles").join(id)),
                "items": [{ "backend": backend, "policy": "unattended", "item": item }] })
    };
    let write_file = |records: Vec<Value>| {
        std::fs::write(
            d.app.join("profile-registry.json.forget"),
            serde_json::to_string_pretty(&json!({ "version": 1, "deleted": records })).unwrap(),
        )
        .unwrap();
    };

    // Imported again from a leftover directory whose secrets file survived:
    // kept. Created again under the same id: the old item is forgotten.
    let old = d.app.join("Profiles").join("old");
    std::fs::create_dir_all(old.join("identity")).unwrap();
    std::fs::write(
        old.join("identity").join("secrets.json"),
        secrets(&[hex('e')]),
    )
    .unwrap();
    write_file(vec![record("old", &hex('e')), record("again", &hex('f'))]);
    let out = run(&["profile", "import", "--app-root", s(&d.app), "--id", "old"]);
    assert_eq!(code(&out), 0, "{out:?}");
    let out = run(&[
        "profile",
        "create",
        "--app-root",
        s(&d.app),
        "--display-name",
        "Again",
    ]);
    assert_eq!(code(&out), 0, "{out:?}");
    let again = d.app.join("Profiles").join("again");
    std::fs::create_dir_all(again.join("identity")).unwrap();
    std::fs::write(
        again.join("identity").join("secrets.json"),
        secrets(&[hex('9')]),
    )
    .unwrap();
    let expected = if recorded {
        json!([{ "policy": "unattended", "item": hex('f') }])
    } else {
        json!([])
    };
    assert_eq!(forget_list(&d)["items"], expected);

    // A full file: 16 profiles' records. The delete is refused, nothing
    // changed (where the backend's items are recorded).
    if recorded {
        write_file(
            (0..16)
                .map(|n| record(&format!("gone{n}"), &format!("{n:032x}")))
                .collect(),
        );
        profile_lock(&work, Duration::from_secs(31));
        let before = snapshot(&d);
        let out = delete(&d, "work", "Work", &[]);
        assert_eq!(code(&out), 75, "{out:?}");
        assert_eq!(json_of(&out), json!({ "error": "forget_backlog" }));
        assert_eq!(snapshot(&d), before);
        assert_eq!(forget_list(&d)["items"].as_array().unwrap().len(), 16);
    }

    // A malformed file: set aside, nothing it names forgotten.
    std::fs::write(
        d.app.join("profile-registry.json.forget"),
        "{\"version\":1,",
    )
    .unwrap();
    let opened = run(&[
        "profile",
        "open",
        "--app-root",
        s(&d.app),
        "--lock-dir",
        s(&d.locks),
    ]);
    assert_eq!(json_of(&opened)["forget_pending"], 1);
    let listed_now = forget_list(&d);
    assert_eq!(listed_now, json!({ "items": [], "set_aside": true }));
    assert_eq!(
        std::fs::read_to_string(d.app.join("profile-registry.json.forget.unreadable")).unwrap(),
        "{\"version\":1,"
    );
    let opened = run(&[
        "profile",
        "open",
        "--app-root",
        s(&d.app),
        "--lock-dir",
        s(&d.locks),
    ]);
    assert_eq!(json_of(&opened)["forget_pending"], 0);

    // A secrets file that can't be read: the delete goes on.
    std::fs::write(work.join("identity").join("secrets.json"), "{not json").unwrap();
    let out = delete(&d, "work", "Work", &[]);
    assert_eq!(code(&out), 0, "{out:?}");
    let result = json_of(&out);
    assert_eq!(result["forget"], json!([]));
    assert_eq!(result["forget_unknown"], true);
    assert!(!work.exists());

    // forget-done takes only item ids.
    let out = run(&[
        "profile",
        "forget-done",
        "--app-root",
        s(&d.app),
        "--item",
        "nope",
    ]);
    assert_eq!(code(&out), 64);
    let out = run(&["profile", "forget-done", "--app-root", s(&d.app)]);
    assert_eq!(code(&out), 64);
}

/// The profile's data reached through a link is refused before anything
/// changes: the profile's directory itself, a step above it, or a gated
/// directory inside it.
#[cfg(unix)]
#[test]
fn links_are_refused_with_nothing_changed() {
    let d = dirs();
    let (work, _home) = setup(&d, &[hex('a')]);
    let elsewhere = d.base.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    // A gated directory through a link.
    std::fs::rename(work.join("identity"), elsewhere.join("identity")).unwrap();
    std::os::unix::fs::symlink(elsewhere.join("identity"), work.join("identity")).unwrap();
    let before = snapshot(&d);
    let out = delete(&d, "work", "Work", &[]);
    assert_eq!(code(&out), 65, "{out:?}");
    let message = json_of(&out)["message"].as_str().unwrap().to_owned();
    assert!(
        message.starts_with("The profile's identity data is reached through a link"),
        "{message}"
    );
    assert_eq!(snapshot(&d), before);
    // The profile's directory through a link.
    std::fs::remove_file(work.join("identity")).unwrap();
    std::fs::rename(&work, elsewhere.join("work")).unwrap();
    std::os::unix::fs::symlink(elsewhere.join("work"), &work).unwrap();
    let before = snapshot(&d);
    let out = delete(&d, "work", "Work", &[]);
    assert_eq!(code(&out), 65, "{out:?}");
    let message = json_of(&out)["message"].as_str().unwrap().to_owned();
    assert!(
        message.starts_with("The profile's data is reached through a link"),
        "{message}"
    );
    assert_eq!(snapshot(&d), before);
    // A step above it: `Profiles` through a link.
    std::fs::remove_file(&work).unwrap();
    std::fs::rename(elsewhere.join("work"), &work).unwrap();
    let profiles = d.app.join("Profiles");
    std::fs::rename(&profiles, elsewhere.join("Profiles")).unwrap();
    std::os::unix::fs::symlink(elsewhere.join("Profiles"), &profiles).unwrap();
    let before = snapshot(&d);
    let out = delete(&d, "work", "Work", &[]);
    assert_eq!(code(&out), 65, "{out:?}");
    let message = json_of(&out)["message"].as_str().unwrap().to_owned();
    assert!(message.contains("reached through a link"), "{message}");
    assert_eq!(snapshot(&d), before);
    assert!(
        elsewhere
            .join("Profiles")
            .join("work")
            .join("Cookies")
            .exists()
    );
}

/// A secrets file reached through a link in the moved layout may be
/// another profile's: the delete goes on, records none of its items, and
/// says `forget_unknown`.
#[cfg(unix)]
#[test]
fn a_secrets_file_through_a_link_is_unknown() {
    let d = dirs();
    let (work, _home) = setup(&d, &[hex('a')]);
    std::fs::remove_file(work.join("identity").join("secrets.json")).unwrap();
    let other = d.base.join("other");
    std::fs::create_dir_all(other.join("identity")).unwrap();
    std::fs::write(
        other.join("identity").join("secrets.json"),
        secrets(&[hex('7')]),
    )
    .unwrap();
    std::os::unix::fs::symlink(&other, work.join("freedom")).unwrap();
    let out = delete(&d, "work", "Work", &[]);
    assert_eq!(code(&out), 0, "{out:?}");
    let result = json_of(&out);
    assert_eq!(result["forget"], json!([]));
    assert_eq!(result["forget_unknown"], true);
    assert!(!work.exists());
    // The link went as a link.
    assert!(other.join("identity").join("secrets.json").exists());
    assert_eq!(forget_list(&d)["items"], json!([]));
}

/// The lock directory's entries: a gate tried leaves its lock file there.
fn lock_files(d: &Dirs) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(&d.locks)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// **A record whose directory overlaps another profile's** (review of
/// #337): the profiles root, a directory above another profile's, and one
/// inside another profile's are each refused before any gate is tried or
/// anything changes, where the reference's check (inside the app root)
/// would let the delete remove the other profiles' data
/// (`profile-delete-overlap`).
#[test]
fn a_record_overlapping_another_profiles_directory_is_refused() {
    let d = dirs();
    let (work, _home) = setup(&d, &[hex('a')]);
    profile_lock(&work, Duration::from_secs(31));
    let path = d.app.join("profile-registry.json");
    let mut catalog: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let records = catalog["profiles"].as_array_mut().unwrap();
    records.push(
        json!({ "id": "all", "displayName": "All", "dir": s(&d.app.join("Profiles")), "slot": 7 }),
    );
    records.push(json!({ "id": "inner", "displayName": "Inner", "dir": s(&work.join("identity")), "slot": 8 }));
    std::fs::write(&path, serde_json::to_string_pretty(&catalog).unwrap()).unwrap();
    // The profiles root; `work`, above `inner`'s directory; `inner`, inside
    // `work`'s.
    for (id, confirm) in [("all", "All"), ("work", "Work"), ("inner", "Inner")] {
        let before = snapshot(&d);
        let locks = lock_files(&d);
        let out = delete(&d, id, confirm, &[]);
        assert_eq!(code(&out), 65, "{id}: {out:?}");
        assert_eq!(
            json_of(&out)["message"],
            "Refusing to delete a profile whose directory overlaps another profile's or the \
             app's own data",
            "{id}"
        );
        assert_eq!(snapshot(&d), before, "{id}");
        assert_eq!(lock_files(&d), locks, "{id}: no gate tried");
    }
    assert_eq!(catalog_ids(&d), ["default", "work", "all", "inner"]);
}

/// Adds `records` to the catalog as they are.
fn add_records(d: &Dirs, records: &[Value]) {
    let path = d.app.join("profile-registry.json");
    let mut catalog: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    catalog["profiles"]
        .as_array_mut()
        .unwrap()
        .extend_from_slice(records);
    std::fs::write(&path, serde_json::to_string_pretty(&catalog).unwrap()).unwrap();
}

/// Each delete of `ids` refused with `message`, nothing changed and no gate
/// tried.
fn refused_untouched(d: &Dirs, ids: &[(&str, &str)], message: &str) {
    for (id, confirm) in ids {
        let before = snapshot(d);
        let locks = lock_files(d);
        let out = delete(d, id, confirm, &[]);
        assert_eq!(code(&out), 65, "{id}: {out:?}");
        assert_eq!(json_of(&out)["message"], message, "{id}");
        assert_eq!(snapshot(d), before, "{id}");
        assert_eq!(lock_files(d), locks, "{id}: no gate tried");
    }
}

/// **Unicode-equivalent directories** (review of #337): macOS's volumes
/// ignore normalization, and its default ones case, so `café` composed and
/// decomposed, or `Été` and `été`, are one directory there. Either record's
/// delete would remove the other's data: refused on every OS, nothing
/// changed, no gate tried.
#[test]
fn unicode_equivalent_directories_are_refused() {
    let d = dirs();
    let (work, _home) = setup(&d, &[hex('a')]);
    profile_lock(&work, Duration::from_secs(31));
    let profiles = d.app.join("Profiles");
    let nfc = profiles.join("caf\u{e9}");
    let nfd = profiles.join("cafe\u{301}");
    let upper = profiles.join("\u{c9}t\u{e9}");
    let lower = profiles.join("\u{e9}t\u{e9}");
    std::fs::create_dir_all(nfc.join("identity")).unwrap();
    std::fs::write(nfc.join("identity").join("vault.json"), "vault").unwrap();
    std::fs::create_dir_all(&upper).unwrap();
    std::fs::write(upper.join("Cookies"), "c").unwrap();
    if cfg!(target_os = "macos") {
        // Both spellings reach the one directory on APFS.
        assert_eq!(
            std::fs::read_to_string(nfd.join("identity").join("vault.json")).unwrap(),
            "vault"
        );
    }
    if cfg!(windows) {
        // NTFS ignores case.
        assert_eq!(std::fs::read_to_string(lower.join("Cookies")).unwrap(), "c");
    }
    add_records(
        &d,
        &[
            json!({ "id": "nfc", "displayName": "NFC", "dir": s(&nfc), "slot": 7 }),
            json!({ "id": "nfd", "displayName": "NFD", "dir": s(&nfd), "slot": 8 }),
            json!({ "id": "upper", "displayName": "Upper", "dir": s(&upper), "slot": 9 }),
            json!({ "id": "lower", "displayName": "Lower", "dir": s(&lower), "slot": 10 }),
        ],
    );
    refused_untouched(
        &d,
        &[
            ("nfc", "NFC"),
            ("nfd", "NFD"),
            ("upper", "Upper"),
            ("lower", "Lower"),
        ],
        "Refusing to delete a profile whose directory overlaps another profile's or the app's \
         own data",
    );
    assert_eq!(
        catalog_ids(&d),
        ["default", "work", "nfc", "nfd", "upper", "lower"]
    );
}

/// **A Radicle slot two records share** (review of #337): both have the
/// home `R/<slot>`, so either's delete would remove the other's Radicle
/// data. Refused before the confirmation and any gate, nothing changed.
#[test]
fn a_radicle_slot_another_record_shares_is_refused() {
    let d = dirs();
    let (work, home) = setup(&d, &[hex('a')]);
    profile_lock(&work, Duration::from_secs(31));
    let path = d.app.join("profile-registry.json");
    let catalog: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let slot = catalog["profiles"][1]["slot"].clone();
    assert_eq!(slot, json!(1), "work's home is R/1");
    let copy = d.app.join("Profiles").join("copy");
    std::fs::create_dir_all(&copy).unwrap();
    add_records(
        &d,
        &[json!({ "id": "copy", "displayName": "Copy", "dir": s(&copy), "slot": slot })],
    );
    refused_untouched(
        &d,
        &[("work", "Work"), ("copy", "Copy"), ("copy", "wrong")],
        "Refusing to delete a profile whose Radicle slot another profile also uses",
    );
    assert!(home.join("node").join("n").exists());
    assert_eq!(catalog_ids(&d), ["default", "work", "copy"]);
}

/// **A Radicle home made after the layout check** (review of #337): with
/// `R/` missing when the delete checks its layout, a service start made
/// `R/1` meanwhile and waits on the Radicle gate the delete holds (a gate's
/// `acquire` makes its directory before it locks). The delete reaches the
/// home from the app root still, and removes it under that gate, so the
/// start finds its directory gone once the gate is released, and no `R/1`
/// is left for a later profile with that slot.
#[test]
fn a_radicle_home_made_after_the_layout_check_goes_with_the_profile() {
    let d = dirs();
    let (work, home) = setup(&d, &[hex('a')]);
    std::fs::remove_dir_all(d.app.join("R")).unwrap();
    profile_lock(&work, Duration::from_secs(31));
    let marker = d.base.join("paused");
    let release = d.base.join("release");
    let pause = format!("before-record={}={}", s(&marker), s(&release));
    let child = Command::new(BIN)
        .args([
            "profile",
            "delete",
            "--app-root",
            s(&d.app),
            "--lock-dir",
            s(&d.locks),
            "--id",
            "work",
            "--confirm-display-name",
            "Work",
        ])
        .env("FREEDOM_CORED_TEST_PROFILE_DELETE_PAUSE", &pause)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let until = std::time::Instant::now() + Duration::from_secs(60);
    while !marker.exists() {
        assert!(std::time::Instant::now() < until, "the delete never paused");
        std::thread::sleep(Duration::from_millis(10));
    }
    // The layout is checked and every gate held: a start makes the home and
    // waits.
    let start = {
        let (home, locks) = (home.clone(), d.locks.clone());
        std::thread::spawn(move || {
            fc_service::gate::acquire(&home, &locks, "radicle", Duration::from_secs(60))
        })
    };
    while !home.exists() {
        assert!(
            std::time::Instant::now() < until,
            "the start never made its home"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    std::fs::write(&release, "").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(code(&out), 0, "{out:?}");
    assert_eq!(catalog_ids(&d), ["default"]);
    assert!(!work.exists());
    assert!(
        !home.exists(),
        "the home made after the layout check is gone"
    );
    match start.join().unwrap() {
        Err(fc_service::gate::GateError::Storage(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
        }
        other => panic!("the start that waited went on: {other:?}"),
    }
    assert!(!home.exists(), "no orphan once the gate is released");
}
