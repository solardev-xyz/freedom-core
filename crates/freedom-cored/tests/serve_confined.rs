//! `serve`, `hold-lock` and `recover` confined (design 0017).
//!
//! A moved profile beside another, as 0013 lays them out, with main's
//! arguments (C1): the Freedom root, the profile's root and both node roots.
//! From inside the confined `serve`, the test method `test.probe` tries what
//! the design's "Outside the grant" tests list, and the controls inside the
//! grant; the hello's `confinement` is the report; and what `serve` does at
//! its start (the receipts' hand-over, a pending record's recovery, the
//! vault's tightening) and later (node writes, a wipe, SQLite's first open)
//! works confined. `hold-lock` and `recover` read what the hook
//! `FREEDOM_CORED_TEST_CORE_CONFINED` names right after confining
//! themselves. On Windows only the job confines (0010's D4): files, IPC and
//! the network aren't checked there, and a child process is refused.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::{BIN, Core, spawn_env};
use serde_json::{Value, json};
use sha2::Digest;

const TEST_METHODS: (&str, &str) = ("FREEDOM_CORED_TEST_METHODS", "1");
const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Where files, IPC and the network are confined (0017, "Per OS").
const CONFINES_FILES: bool = cfg!(any(target_os = "linux", target_os = "macos"));

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// A moved profile `work` and another, `other`, under one app root, with
/// the user's lock directory beside it.
struct World {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    /// The app root: the catalog, and `Profiles/`.
    app: PathBuf,
    /// `work`'s `userData`, Electron's data at its root.
    profile: PathBuf,
    /// `work`'s Freedom root (`--grant-root`).
    freedom: PathBuf,
    /// `work`'s identity directory, inside its Freedom root.
    identity: PathBuf,
    locks: PathBuf,
    /// `work`'s node roots, missing until `serve` makes them (C2).
    bee: PathBuf,
    radicle: PathBuf,
    /// Another profile, and its gate in the lock directory.
    other: PathBuf,
    other_lock: PathBuf,
}

fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    // Canonical, as the gates resolve it (macOS's `/var` is a link).
    let base = if cfg!(windows) {
        tmp.path().to_path_buf()
    } else {
        std::fs::canonicalize(tmp.path()).unwrap()
    };
    let app = base.join("app");
    let profile = app.join("Profiles").join("work");
    let freedom = profile.join("freedom");
    let other = app.join("Profiles").join("other");
    let locks = base.join("locks");
    for dir in [&freedom, &other.join("freedom"), &locks] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(app.join("profile-registry.json"), "{}").unwrap();
    std::fs::write(profile.join("Cookies"), "electron's").unwrap();
    std::fs::write(other.join("freedom").join("wallet-intents.jsonl"), "").unwrap();
    let other_lock = locks.join(format!("{}.lock", "0".repeat(64)));
    std::fs::write(&other_lock, "").unwrap();
    World {
        identity: freedom.join("identity"),
        bee: profile.join("bee-data"),
        radicle: app.join("R").join("work").join("radicle"),
        _tmp: tmp,
        base,
        app,
        profile,
        freedom,
        locks,
        other,
        other_lock,
    }
}

impl World {
    /// Main's arguments (C1).
    fn args(&self) -> Vec<String> {
        vec![
            "--grant-root".into(),
            s(&self.freedom).into(),
            "--user-data-dir".into(),
            s(&self.profile).into(),
            "--node-root".into(),
            format!("bee={}", s(&self.bee)),
            "--node-root".into(),
            format!("radicle={}", s(&self.radicle)),
        ]
    }

    fn spawn(&self, env: &[(&str, &str)]) -> Core {
        let args = self.args();
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        spawn_env("serve", &self.identity, &self.locks, &args, env)
    }

    /// The hello main sends, naming the arguments' directories.
    fn hello(&self, core: &mut Core, stores: &[&str]) -> Value {
        let hello = core.call_shell(
            1,
            "core.hello",
            json!({
                "protocol": 2, "shell_version": "test", "auto_lock_ms": 900_000,
                "frames": ["stream"], "grant_root": self.freedom,
                "user_data_dir": self.profile, "store_moved": stores,
            }),
        );
        assert_eq!(hello["result"]["protocol"], 2, "{hello}");
        hello
    }
}

/// The report `confine` gave, as the hello carries it, checked against
/// what each OS's mechanisms give `serve`'s policy (0017, "Tests").
fn check_report(report: &Value) {
    let status = |property: &str| report[property].as_str().unwrap_or_default().to_owned();
    let gaps: Vec<&str> = report["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|gap| gap.as_str().unwrap())
        .collect();
    if cfg!(target_os = "linux") {
        let mechanism = report["mechanism"].as_str().unwrap();
        let Some(abi) = mechanism
            .strip_prefix("landlock-")
            .and_then(|rest| rest.strip_suffix("+seccomp"))
            .and_then(|abi| abi.parse::<u32>().ok())
        else {
            // A kernel without Landlock: the report says why files aren't.
            assert!(
                ["unavailable", "blocked"].contains(&status("files").as_str()),
                "{report}"
            );
            return;
        };
        for property in ["files", "exec", "network"] {
            assert_eq!(status(property), "enforced", "{property}: {report}");
        }
        // Signals are Landlock's from ABI 6; sockets are seccomp's.
        if abi >= 6 {
            assert_eq!(status("ipc"), "enforced", "{report}");
            assert!(gaps.is_empty(), "{report}");
        } else {
            assert_eq!(status("ipc"), "partial", "{report}");
            assert_eq!(gaps, ["signals"], "{report}");
        }
    } else if cfg!(target_os = "macos") {
        // Modes change in the read-write grants (C4); and Seatbelt leaves
        // another process's arguments readable, as for every service
        // (0010, "macOS").
        assert_eq!(report["mechanism"], "seatbelt", "{report}");
        assert_eq!(status("files"), "partial", "{report}");
        assert_eq!(status("ipc"), "partial", "{report}");
        let mut gaps = gaps.clone();
        gaps.sort_unstable();
        assert_eq!(gaps, ["modes", "process_args"], "{report}");
        for property in ["exec", "network"] {
            assert_eq!(status(property), "enforced", "{property}: {report}");
        }
    } else if cfg!(windows) {
        assert_eq!(report["mechanism"], "job", "{report}");
        assert_eq!(status("exec"), "partial", "{report}");
        assert!(gaps.contains(&"parent_process"), "{report}");
        for property in ["files", "ipc", "network"] {
            assert_eq!(status(property), "unavailable", "{property}: {report}");
        }
        for mitigation in ["dynamic_code", "image_load", "extension_points"] {
            assert_eq!(report["mitigations"][mitigation], "set", "{report}");
        }
    }
}

#[test]
fn the_hello_reports_the_confinement() {
    let w = world();
    let mut core = w.spawn(&[]);
    let hello = w.hello(&mut core, &[]);
    check_report(&hello["result"]["confinement"]);
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
    assert!(core.stderr().contains("serve confined"));
}

/// A `--node-root bee=` that can't be made fails the start with exit 74,
/// before `confine` and before any hello (design 0017, C2): a regular file
/// at the root, a regular file as one of its ancestors, and (Unix, as
/// another user than root, whom modes don't stop) a parent without write
/// permission.
#[test]
fn a_bee_root_that_cant_be_made_fails_the_start() {
    let w = world();
    let file = w.base.join("not-a-dir");
    std::fs::write(&file, "x").unwrap();
    // Unix adds a case below.
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut roots = vec![file.clone(), file.join("bee")];
    #[cfg(unix)]
    let locked = {
        use std::os::unix::fs::PermissionsExt;
        let locked = w.base.join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
        if !rustix::process::getuid().is_root() {
            roots.push(locked.join("bee"));
        }
        locked
    };
    for root in roots {
        let bee = format!("bee={}", s(&root));
        let args = ["--grant-root", s(&w.freedom), "--node-root", &bee];
        let mut core = spawn_env("serve", &w.identity, &w.locks, &args, &[]);
        assert_eq!(core.exit_code(Duration::from_secs(10)), 74, "{root:?}");
        let stderr = core.stderr();
        assert!(stderr.contains("cannot make a node root"), "{stderr}");
        assert!(!stderr.contains("serve confined"), "{stderr}");
    }
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "x");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert!(!locked.join("bee").exists());
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

/// A start's exit and its log, when it ends before any hello.
#[cfg(unix)]
fn start_ending(data: &Path, w: &World, args: &[&str]) -> (i32, String) {
    let mut core = spawn_env("serve", data, &w.locks, args, &[]);
    let code = core.exit_code(Duration::from_secs(10));
    (code, core.stderr())
}

/// A start that serves: the hello answered, then a clean exit.
#[cfg(unix)]
fn start_serving(data: &Path, w: &World, args: &[&str]) {
    let mut core = spawn_env("serve", data, &w.locks, args, &[]);
    assert_eq!(core.hello()["result"]["protocol"], 2);
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
}

/// A directory `mode` makes `0300`: written and searched, not read, so a
/// directory is made in it but it can't be opened to flush the new entry.
/// Root reads it anyway (modes don't stop root), so these cases need
/// another user, as CI's runners are.
#[cfg(unix)]
fn unreadable_parent(w: &World, name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    if rustix::process::getuid().is_root() {
        return None;
    }
    let parent = w.base.join(name);
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o300)).unwrap();
    Some(parent)
}

#[cfg(unix)]
fn make_readable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// A `--node-root bee=` whose parent can't be flushed once it is made
/// (design 0017, C2): every start is exit 74, the root removed again so
/// the next makes and flushes it anew, and none confines; once the parent
/// can be read, the start serves.
#[cfg(unix)]
#[test]
fn a_bee_root_whose_entry_cant_be_flushed_is_retried_at_each_start() {
    let w = world();
    let Some(parent) = unreadable_parent(&w, "write-only") else {
        return;
    };
    let root = parent.join("bee");
    let bee = format!("bee={}", s(&root));
    let args = ["--grant-root", s(&w.freedom), "--node-root", &bee];
    for start in 0..3 {
        let (code, stderr) = start_ending(&w.identity, &w, &args);
        assert_eq!(code, 74, "start {start}: {stderr}");
        assert!(stderr.contains("cannot make a node root"), "{stderr}");
        assert!(!stderr.contains("serve confined"), "{stderr}");
        assert!(!root.exists(), "start {start}: the root stayed");
    }
    make_readable(&parent);
    start_serving(&w.identity, &w, &args);
    assert!(root.is_dir());
}

/// A missing Freedom root whose parent can't be flushed once it is made:
/// every start is exit 74 before the gate (nothing made in the lock
/// directory, the identity directory not made, nothing confined), the root
/// removed again; once the parent can be read, the start serves.
#[cfg(unix)]
#[test]
fn a_freedom_root_whose_entry_cant_be_flushed_fails_before_the_gate() {
    let w = world();
    let Some(parent) = unreadable_parent(&w, "write-only") else {
        return;
    };
    let grant = parent.join("freedom");
    let data = grant.join("identity");
    let args = ["--grant-root", s(&grant)];
    let locks_before = std::fs::read_dir(&w.locks).unwrap().count();
    for start in 0..3 {
        let (code, stderr) = start_ending(&data, &w, &args);
        assert_eq!(code, 74, "start {start}: {stderr}");
        assert!(stderr.contains("cannot make the Freedom root"), "{stderr}");
        assert!(!stderr.contains("gate taken"), "{stderr}");
        assert!(!stderr.contains("serve confined"), "{stderr}");
        assert!(!grant.exists(), "start {start}: the root stayed");
        assert_eq!(std::fs::read_dir(&w.locks).unwrap().count(), locks_before);
    }
    make_readable(&parent);
    start_serving(&data, &w, &args);
    assert!(data.is_dir());
}

/// A probe's answer: whether it worked, and the OS's error number.
fn probe(core: &mut Core, id: u64, params: Value) -> (bool, Option<i64>) {
    let reply = core.call(id, "test.probe", params.clone());
    let result = &reply["result"];
    assert!(result["ok"].is_boolean(), "{params}: {reply}");
    (result["ok"].as_bool().unwrap(), result["errno"].as_i64())
}

/// Design 0017, "Outside the grant": another profile's directory and
/// files, the catalog, Electron's file at the profile's root and the lock
/// directory can't be read; nothing can be made in the lock directory, nor
/// another profile's gate removed (C3); a TCP connect, a Unix-socket
/// connect and an exec all fail. Inside the grant, each control works:
/// the Freedom root, the identity directory and both node roots are read
/// and written.
#[test]
fn a_confined_serve_reaches_nothing_outside_its_grant() {
    let w = world();
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tcp.local_addr().unwrap().to_string();
    // A session bus's stand-in, outside the grant.
    let bus = w.base.join("bus");
    std::fs::create_dir_all(&bus).unwrap();
    #[cfg(unix)]
    let _listener = std::os::unix::net::UnixListener::bind(bus.join("socket")).unwrap();
    let mut core = w.spawn(&[TEST_METHODS]);
    w.hello(&mut core, &[]);
    let mut id = 1;
    let mut next = || {
        id += 1;
        id
    };

    let inside = [
        json!({ "op": "read", "path": w.freedom }),
        json!({ "op": "read", "path": w.identity }),
        json!({ "op": "create", "path": w.freedom.join("probe") }),
        json!({ "op": "read", "path": w.freedom.join("probe") }),
        json!({ "op": "create", "path": w.bee.join("probe") }),
        json!({ "op": "create", "path": w.radicle.join("probe") }),
        json!({ "op": "remove", "path": w.radicle.join("probe") }),
    ];
    for params in inside {
        let (ok, errno) = probe(&mut core, next(), params.clone());
        assert!(ok, "inside the grant: {params}: errno {errno:?}");
    }

    let outside = [
        json!({ "op": "read", "path": w.other }),
        json!({ "op": "read", "path": w.other.join("freedom").join("wallet-intents.jsonl") }),
        json!({ "op": "read", "path": w.app.join("profile-registry.json") }),
        json!({ "op": "read", "path": w.app }),
        json!({ "op": "read", "path": w.profile.join("Cookies") }),
        json!({ "op": "read", "path": w.profile }),
        json!({ "op": "read", "path": w.locks }),
        json!({ "op": "create", "path": w.locks.join("made.lock") }),
        json!({ "op": "create", "path": w.profile.join("made") }),
        json!({ "op": "remove", "path": w.other_lock }),
        json!({ "op": "tcp", "addr": addr }),
        json!({ "op": "unix", "path": bus.join("socket") }),
    ];
    for params in outside {
        if params["op"] == "unix" && cfg!(not(unix)) {
            continue;
        }
        let (ok, errno) = probe(&mut core, next(), params.clone());
        if CONFINES_FILES {
            assert!(!ok, "outside the grant: {params}");
            assert!(errno.is_some(), "{params}");
        }
    }
    // No process of its own, on every OS: the job refuses it on Windows.
    let (ok, _) = probe(&mut core, next(), json!({ "op": "exec", "path": BIN }));
    assert!(!ok, "an exec worked");
    if CONFINES_FILES {
        assert!(w.other_lock.exists());
        assert!(!w.locks.join("made.lock").exists());
        assert!(!w.profile.join("made").exists());
    }
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
}

/// C4 on Linux: `fchmod` to an owner-only mode works on a file in the
/// grant; any group, other, setuid, setgid or sticky bit is `EPERM`.
#[cfg(target_os = "linux")]
#[test]
fn only_an_owner_only_mode_is_set() {
    let w = world();
    let file = w.freedom.join("moded");
    std::fs::write(&file, "").unwrap();
    let mut core = w.spawn(&[TEST_METHODS]);
    w.hello(&mut core, &[]);
    let mut id = 1;
    for (mode, allowed) in [
        (0o600, true),
        (0o700, true),
        (0o644, false),
        (0o755, false),
        (0o4700, false),
        (0o2700, false),
        (0o1700, false),
    ] {
        id += 1;
        let (ok, errno) = probe(
            &mut core,
            id,
            json!({ "op": "chmod", "path": file, "mode": mode }),
        );
        assert_eq!(ok, allowed, "{mode:o}");
        if !allowed {
            assert_eq!(errno, Some(1), "{mode:o}: EPERM");
        }
    }
}

/// The gate's and the vault's tightening at start (C4): a lock file and a
/// vault file the umask left wide are `0600` once the confined `serve` has
/// answered the hello, the vault's tightened on the snapshot thread, after
/// `confine`.
#[cfg(unix)]
#[test]
fn the_gate_and_the_vault_are_tightened_confined() {
    use std::os::unix::fs::PermissionsExt;
    let w = world();
    std::fs::create_dir_all(&w.identity).unwrap();
    let vault = w.identity.join("identity-vault.json");
    std::fs::write(&vault, "{}").unwrap();
    std::fs::set_permissions(&vault, std::fs::Permissions::from_mode(0o644)).unwrap();
    let canonical = std::fs::canonicalize(&w.identity).unwrap();
    let digest = sha2::Sha256::digest(canonical.as_os_str().as_encoded_bytes());
    let name: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    let lock = w.locks.join(format!("{name}.lock"));
    std::fs::write(&lock, "").unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut core = w.spawn(&[]);
    w.hello(&mut core, &[]);
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode(&vault), 0o600);
    assert_eq!(mode(&lock), 0o600);
}

fn b64(text: &str) -> String {
    STANDARD.encode(text)
}

/// `nodes.write_identity` for Bee and Radicle, into the node roots `serve`
/// made before `confine` (C2), and a Radicle wipe, all confined.
#[test]
fn node_writes_and_a_wipe_work_confined() {
    let w = world();
    let mut core = w.spawn(&[]);
    w.hello(&mut core, &[]);
    // C2: both made, empty, before the hello's answer.
    assert!(w.bee.is_dir() && w.radicle.is_dir());
    let imported = core.call(
        2,
        "vault.import",
        json!({ "password_b64": b64("testpass1"), "mnemonic_b64": b64(ABANDON) }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    let bee = core.call(
        3,
        "nodes.write_identity",
        json!({ "op_id": "op-bee", "node": "bee", "data_dir": w.bee, "api_port": 1733, "p2p_port": 1734 }),
    );
    assert_eq!(bee["result"]["status"], "installed", "{bee}");
    assert!(w.bee.join("keys/swarm.key").is_file());
    assert!(w.bee.join("config.yaml").is_file());
    let radicle = core.call(
        4,
        "nodes.write_identity",
        json!({ "op_id": "op-rad", "node": "radicle", "home": w.radicle, "alias": "FreedomBrowser" }),
    );
    assert_eq!(radicle["result"]["status"], "installed", "{radicle}");
    assert!(w.radicle.join("keys/radicle.pub").is_file());
    for dir in ["node", "cobs", "storage/rid"] {
        std::fs::create_dir_all(w.radicle.join(dir)).unwrap();
    }
    std::fs::write(w.radicle.join("node/node.db"), "db").unwrap();
    let wiped = core.call(
        5,
        "nodes.write_identity",
        json!({
            "op_id": "op-wipe", "node": "radicle", "home": w.radicle,
            "alias": "FreedomBrowser", "custody": "sealed", "wipe": true,
        }),
    );
    assert_eq!(wiped["result"]["status"], "installed", "{wiped}");
    for dir in ["node", "cobs", "storage"] {
        assert!(!w.radicle.join(dir).exists(), "{dir} survived the wipe");
    }
    assert!(!w.radicle.join("keys/radicle").exists());
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
}

/// A committed Bee journal an earlier run left, as a crash after its
/// commit does: staged files and the journal, the targets still old.
fn interrupted_bee_write(identity: &Path, root: &Path, op_id: &str) {
    std::fs::create_dir_all(root.join("keys")).unwrap();
    std::fs::create_dir_all(identity).unwrap();
    let mut files = Vec::new();
    for (target, contents) in [
        (root.join("keys").join("swarm.key"), "new key"),
        (root.join("config.yaml"), "new config"),
    ] {
        std::fs::write(&target, "old").unwrap();
        let staged = PathBuf::from(format!("{}.freedom-new", target.display()));
        std::fs::write(&staged, contents).unwrap();
        let digest: String = sha2::Sha256::digest(contents)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        files.push(json!({ "target": target, "staged": staged, "sha256": digest }));
    }
    let journal = json!({ "op_id": op_id, "node": "bee", "root": root, "files": files });
    std::fs::write(
        identity.join("node-identity-journal.json"),
        journal.to_string(),
    )
    .unwrap();
}

/// C6: a committed journal whose root isn't among the arguments (an
/// override moved since) is planned, granted, and replayed before the
/// hello's answer, by a confined `serve`.
#[test]
fn startup_recovery_reaches_a_root_not_among_the_arguments() {
    let w = world();
    let old = w.base.join("old-bee");
    interrupted_bee_write(&w.identity, &old, "op-old");
    let mut core = w.spawn(&[]);
    let hello = w.hello(&mut core, &[]);
    assert_eq!(hello["result"]["node_recovery"], Value::Null, "{hello}");
    assert_eq!(
        std::fs::read_to_string(old.join("keys/swarm.key")).unwrap(),
        "new key"
    );
    assert_eq!(
        std::fs::read_to_string(old.join("config.yaml")).unwrap(),
        "new config"
    );
    assert!(!w.identity.join("node-identity-journal.json").exists());
    let status = core.call_shell(2, "nodes.op_status", json!({ "op_id": "op-old" }));
    assert_eq!(status["result"]["status"], "installed", "{status}");
}

const RECEIPTS: &str = r#"[{"id":"r1","settledAt":1699000000,"status":"settled","chainId":8453,"amount":"500","origin":"https://x.example","url":"https://x.example/a"}]"#;

/// C5 and C7: the legacy receipts at the profile's root, outside the grant,
/// are copied into the Freedom root before `confine`, whatever the hello's
/// `store_moved` says. Once `payments` is named, the database's first open
/// (made and switched to WAL, confined) imports the copy; at the next
/// start, the original goes.
#[test]
fn the_receipts_are_handed_over_before_confine() {
    let w = world();
    std::fs::write(w.profile.join("x402-receipts.json"), RECEIPTS).unwrap();
    let mut core = w.spawn(&[]);
    w.hello(&mut core, &[]);
    // Copied at the start, with `payments` not named.
    assert_eq!(
        std::fs::read_to_string(w.freedom.join("x402-receipts.json")).unwrap(),
        RECEIPTS
    );
    assert!(w.profile.join("x402-receipts.json").exists());
    assert!(!w.freedom.join("payment-history.sqlite").exists());
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);

    let mut core = w.spawn(&[]);
    w.hello(&mut core, &["payments"]);
    let reply = core.call(2, "payments.get_recent", json!({}));
    let payments = reply["result"]["payments"].as_array().unwrap();
    assert_eq!(payments.len(), 1, "{reply}");
    assert_eq!(payments[0]["metadata"]["legacyId"], "r1");
    let database = w.freedom.join("payment-history.sqlite");
    assert!(database.is_file());
    // The switch to WAL: its file beside the database while it is open.
    assert!(w.freedom.join("payment-history.sqlite-wal").exists());
    assert!(w.freedom.join("x402-receipts.json.migrated").exists());
    assert!(!w.freedom.join("x402-receipts.json").exists());
    // The original stays until the next start sees the copy's `.migrated`.
    assert!(w.profile.join("x402-receipts.json").exists());
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);

    let mut core = w.spawn(&[]);
    w.hello(&mut core, &["payments"]);
    assert!(!w.profile.join("x402-receipts.json").exists());
    let count = core.call(2, "payments.get_count", json!({}));
    assert_eq!(count["result"], json!({ "count": 1 }), "{count}");
}

/// The hook's line from a confined `hold-lock` or `recover`: the report,
/// and whether each path read.
fn confined_reads(stderr: &str) -> (Value, Vec<bool>) {
    let line = stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|line| line["msg"] == "test: confined")
        .unwrap_or_else(|| panic!("no confinement: {stderr}"));
    let reads = line["reads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|read| read["ok"].as_bool().unwrap())
        .collect();
    (line["confinement"].clone(), reads)
}

/// `hold-lock` gets the identity directory and its gate alone; `recover`
/// also what C6's plan names, here a committed journal's root outside
/// both, which it replays confined. Each reads its identity directory, and
/// neither the lock directory nor another profile's files.
#[test]
fn hold_lock_and_recover_are_confined() {
    let w = world();
    std::fs::create_dir_all(&w.identity).unwrap();
    let reads = std::env::join_paths([
        w.identity.clone(),
        w.locks.clone(),
        w.other.join("freedom").join("wallet-intents.jsonl"),
        w.profile.join("Cookies"),
    ])
    .unwrap();
    let reads = reads.to_str().unwrap();
    let env = [("FREEDOM_CORED_TEST_CORE_CONFINED", reads)];
    let mut hold = spawn_env("hold-lock", &w.identity, &w.locks, &[], &env);
    assert_eq!(hold.line(), "locked");
    hold.close_stdin();
    assert_eq!(hold.exit_code(Duration::from_secs(5)), 0);
    let stderr = hold.stderr();
    assert!(stderr.contains("hold-lock confined"), "{stderr}");
    let (report, read) = confined_reads(&stderr);
    assert!(read[0], "{stderr}");
    if CONFINES_FILES {
        assert!(report["files"] == "enforced" || report["files"] == "partial");
        assert_eq!(read[1..], [false, false, false], "{stderr}");
    }

    let old = w.base.join("old-bee");
    interrupted_bee_write(&w.identity, &old, "op-old");
    let mut recover = spawn_env("recover", &w.identity, &w.locks, &[], &env);
    assert_eq!(recover.line(), "recovered");
    assert_eq!(recover.exit_code(Duration::from_secs(5)), 0);
    let stderr = recover.stderr();
    assert!(stderr.contains("recover confined"), "{stderr}");
    let (report, read) = confined_reads(&stderr);
    assert!(read[0], "{stderr}");
    if CONFINES_FILES {
        assert!(report["files"] == "enforced" || report["files"] == "partial");
        assert_eq!(read[1..], [false, false, false], "{stderr}");
    }
    assert_eq!(
        std::fs::read_to_string(old.join("keys/swarm.key")).unwrap(),
        "new key"
    );
}
