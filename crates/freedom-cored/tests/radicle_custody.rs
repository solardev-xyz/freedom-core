//! The Radicle identity write with `custody: "sealed"` through the real
//! binary (design 0008, "The switch" and "Identity changes"): no key file is
//! written, any is removed after the identity it names is added to the
//! dirty marker, `wipe` wipes the home's state, and every write and
//! recovery holds the home's gate, the Radicle service's own.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};
use sha2::Digest;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// From vectors/fixtures/radicle-openssh.json (abandon-12).
const RADICLE_NID: &str = "z6Mkgb93MjdiDEUrHVCY2X4EfaSwzoFCorViqqPnjoQX8gAn";

fn b64(s: &str) -> String {
    STANDARD.encode(s)
}

/// A core with the abandon...about wallet imported (unlocked); next ID 3.
fn unlocked(data: &Path, locks: &Path) -> Core {
    let mut core = spawn("serve", data, locks, &[]);
    core.hello();
    let imported = core.call(
        2,
        "vault.import",
        json!({ "password_b64": b64("testpass1"), "mnemonic_b64": b64(ABANDON) }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    core
}

fn sealed(op_id: &str, home: &Path, wipe: Option<bool>) -> Value {
    let mut params = json!({
        "op_id": op_id, "node": "radicle", "home": home,
        "alias": "FreedomBrowser", "custody": "sealed",
    });
    if let Some(wipe) = wipe {
        params["wipe"] = wipe.into();
    }
    params
}

fn marker(home: &Path) -> Option<Value> {
    std::fs::read(home.join("node").join("dirty"))
        .ok()
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
}

fn alias(home: &Path) -> String {
    let config: Value =
        serde_json::from_slice(&std::fs::read(home.join("config.json")).unwrap()).unwrap();
    config["node"]["alias"].as_str().unwrap().to_owned()
}

fn keys_gone(home: &Path) {
    for name in ["radicle", "radicle.pub"] {
        assert!(
            std::fs::symlink_metadata(home.join("keys").join(name)).is_err(),
            "keys/{name} is still there"
        );
    }
}

/// Writes today's key files for the abandon wallet into `home`, through the
/// core's own today's form.
fn legacy_write(core: &mut Core, id: u64, home: &Path) {
    let reply = core.call(
        id,
        "nodes.write_identity",
        json!({ "op_id": format!("legacy-{id}"), "node": "radicle", "home": home, "alias": "old" }),
    );
    assert_eq!(reply["result"]["status"], "installed", "{reply}");
    assert!(home.join("keys/radicle").exists());
}

#[test]
fn the_sealed_form_needs_no_vault_and_writes_no_key() {
    let (root, data, locks) = dirs();
    let home = root.path().join("radicle");
    // No vault at all.
    let mut core = spawn("serve", &data, &locks, &[]);
    core.hello();
    let reply = core.call(2, "nodes.write_identity", sealed("op-1", &home, None));
    assert_eq!(reply["result"], json!({ "status": "installed" }), "{reply}");
    assert_eq!(alias(&home), "FreedomBrowser");
    keys_gone(&home);
    assert_eq!(marker(&home), None, "no key file, so no identity to check");
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
    // Locked: still no vault needed.
    let mut core = unlocked(&data, &locks);
    assert_eq!(core.call(3, "vault.lock", json!({}))["result"], json!({}));
    let reply = core.call(4, "nodes.write_identity", sealed("op-2", &home, None));
    assert_eq!(reply["result"]["status"], "installed", "{reply}");
    let status = core.call_shell(5, "nodes.op_status", json!({ "op_id": "op-2" }));
    assert_eq!(status["result"]["status"], "installed");
}

/// The switch: the key file the core wrote goes, after the identity it
/// names is in the marker, read from the file's public part.
#[test]
fn the_switch_removes_the_key_file_and_names_its_identity() {
    let (root, data, locks) = dirs();
    let home = root.path().join("radicle");
    let mut core = unlocked(&data, &locks);
    legacy_write(&mut core, 3, &home);
    assert_eq!(core.call(4, "vault.lock", json!({}))["result"], json!({}));
    let reply = core.call(5, "nodes.write_identity", sealed("switch", &home, None));
    assert_eq!(reply["result"]["status"], "installed", "{reply}");
    keys_gone(&home);
    assert_eq!(marker(&home), Some(json!({ "node_ids": [RADICLE_NID] })));
    assert_eq!(alias(&home), "FreedomBrowser");
    // Again, with nothing left to remove: nothing changes in the marker.
    let reply = core.call(6, "nodes.write_identity", sealed("again", &home, None));
    assert_eq!(reply["result"]["status"], "installed", "{reply}");
    assert_eq!(marker(&home), Some(json!({ "node_ids": [RADICLE_NID] })));
}

/// The node ID comes from the private file's public part, or from the
/// `.pub` file; an existing marker keeps its names; neither file readable is
/// `node_identity_corrupt`, with nothing touched.
#[test]
fn the_switch_reads_either_file_and_keeps_the_markers_names() {
    let (root, data, locks) = dirs();
    let mut core = unlocked(&data, &locks);

    // A private key file that names no key; the .pub file names it.
    let home = root.path().join("pub-only");
    legacy_write(&mut core, 3, &home);
    std::fs::write(home.join("keys/radicle"), b"not a key file").unwrap();
    std::fs::create_dir_all(home.join("node")).unwrap();
    std::fs::write(home.join("node/dirty"), br#"{"node_ids":["z6MkEarlier"]}"#).unwrap();
    let reply = core.call(4, "nodes.write_identity", sealed("pub", &home, None));
    assert_eq!(reply["result"]["status"], "installed", "{reply}");
    keys_gone(&home);
    assert_eq!(
        marker(&home),
        // Sorted, each once.
        Some(json!({ "node_ids": ["z6MkEarlier", RADICLE_NID] }))
    );

    // Neither file names a key: refused, nothing touched.
    let home = root.path().join("unreadable");
    legacy_write(&mut core, 5, &home);
    std::fs::write(home.join("keys/radicle"), b"not a key file").unwrap();
    std::fs::write(home.join("keys/radicle.pub"), b"not a key line").unwrap();
    let before = walk_contents(&home);
    let reply = core.call(6, "nodes.write_identity", sealed("bad", &home, None));
    assert_eq!(reply["error"]["code"], "node_identity_corrupt", "{reply}");
    assert_eq!(walk_contents(&home), before);
    let status = core.call_shell(7, "nodes.op_status", json!({ "op_id": "bad" }));
    assert_eq!(status["result"]["status"], "not_committed");

    // A marker the core can't read: refused, nothing touched.
    let home = root.path().join("bad-marker");
    legacy_write(&mut core, 8, &home);
    std::fs::create_dir_all(home.join("node")).unwrap();
    std::fs::write(home.join("node/dirty"), b"{not json").unwrap();
    let before = walk_contents(&home);
    let reply = core.call(9, "nodes.write_identity", sealed("bad-marker", &home, None));
    assert_eq!(reply["error"]["code"], "node_identity_corrupt", "{reply}");
    assert_eq!(walk_contents(&home), before);
}

/// `wipe`: the home's state and the key files go, no marker is written, and
/// nothing outside the home is followed into.
#[test]
fn wipe_removes_the_state_and_follows_no_symlink() {
    let (root, data, locks) = dirs();
    let home = root.path().join("radicle");
    let mut core = unlocked(&data, &locks);
    legacy_write(&mut core, 3, &home);
    let outside = root.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("precious"), b"keep me").unwrap();
    for dir in ["node", "cobs", "storage/rid/refs"] {
        std::fs::create_dir_all(home.join(dir)).unwrap();
    }
    std::fs::write(home.join("node/node.db"), b"db").unwrap();
    std::fs::write(home.join("cobs/cache.db"), b"cache").unwrap();
    std::fs::write(home.join("storage/rid/refs/head"), b"ref").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, home.join("storage/link")).unwrap();
    let reply = core.call(4, "nodes.write_identity", sealed("wipe", &home, Some(true)));
    assert_eq!(reply["result"]["status"], "installed", "{reply}");
    for dir in ["node", "cobs", "storage"] {
        assert!(!home.join(dir).exists(), "{dir} survived the wipe");
    }
    keys_gone(&home);
    assert_eq!(marker(&home), None);
    assert_eq!(alias(&home), "FreedomBrowser");
    assert_eq!(std::fs::read(outside.join("precious")).unwrap(), b"keep me");
}

#[test]
fn the_selector_is_checked() {
    let (root, data, locks) = dirs();
    let home = root.path().join("radicle");
    let mut core = unlocked(&data, &locks);
    for (i, params) in [
        json!({ "op_id": "a", "node": "radicle", "home": home, "alias": "x", "custody": "file" }),
        json!({ "op_id": "b", "node": "radicle", "home": home, "alias": "x", "wipe": true }),
        json!({ "op_id": "c", "node": "bee", "data_dir": home, "api_port": 1, "p2p_port": 2, "custody": "sealed" }),
        json!({ "op_id": "d", "node": "radicle", "home": "relative", "alias": "x", "custody": "sealed" }),
    ]
    .into_iter()
    .enumerate()
    {
        let reply = core.call(10 + i as u64, "nodes.write_identity", params.clone());
        assert_eq!(reply["error"]["code"], "invalid_argument", "{params}: {reply}");
    }
}

/// A held gate (a running Radicle service, or `hold-lock`): the write gives
/// up after 0001's 5 s with `lock_held`, and touches nothing.
#[test]
fn a_held_gate_refuses_the_write_and_touches_nothing() {
    let (root, data, locks) = dirs();
    let home = root.path().join("radicle");
    let mut core = unlocked(&data, &locks);
    legacy_write(&mut core, 3, &home);
    let before = walk_contents(&home);
    let gate = fc_service::gate::acquire(&home, &locks, "radicle", Duration::ZERO).unwrap();
    let started = Instant::now();
    for (id, params) in [
        (4, sealed("held", &home, None)),
        (
            5,
            json!({ "op_id": "held-legacy", "node": "radicle", "home": home, "alias": "x" }),
        ),
    ] {
        let reply = core.call(id, "nodes.write_identity", params);
        assert_eq!(reply["error"]["code"], "lock_held", "{reply}");
    }
    assert!(started.elapsed() >= Duration::from_secs(5));
    assert_eq!(walk_contents(&home), before);
    drop(gate);
    let reply = core.call(6, "nodes.write_identity", sealed("free", &home, None));
    assert_eq!(reply["result"]["status"], "installed", "{reply}");
}

/// The journal of a switch interrupted after its commit, at `stage` (0: just
/// committed, 1: the marker installed, 2: the private key file removed).
fn interrupted_switch(identity: &Path, home: &Path, op_id: &str, stage: u8) {
    std::fs::create_dir_all(identity).unwrap();
    // A writer's journal names the gate's canonical home (on macOS, /var
    // is a symlink to /private/var).
    let home = &std::fs::canonicalize(home).unwrap();
    let marker = format!(r#"{{"node_ids":["{RADICLE_NID}"]}}"#);
    let config = "{\n  \"node\": {\n    \"alias\": \"FreedomBrowser\"\n  }\n}";
    let staged = |target: &Path, contents: &str| -> Value {
        let staged = PathBuf::from(format!("{}.freedom-new", target.display()));
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&staged, contents).unwrap();
        let sha: String = sha2::Sha256::digest(contents)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        json!({ "target": target, "staged": staged, "sha256": sha })
    };
    let dirty = home.join("node/dirty");
    let files = vec![
        staged(&dirty, &marker),
        json!({ "target": home.join("keys/radicle"), "remove": true }),
        json!({ "target": home.join("keys/radicle.pub"), "remove": true }),
        staged(&home.join("config.json"), config),
    ];
    if stage >= 1 {
        std::fs::rename(format!("{}.freedom-new", dirty.display()), &dirty).unwrap();
    }
    if stage >= 2 {
        std::fs::remove_file(home.join("keys/radicle")).unwrap();
    }
    let journal = json!({ "op_id": op_id, "node": "radicle", "root": home, "files": files });
    std::fs::write(
        identity.join("node-identity-journal.json"),
        journal.to_string(),
    )
    .unwrap();
}

/// A switch cut off after its commit, at each step: startup recovery
/// finishes it, so the key file is gone and the marker names its identity.
#[test]
fn recovery_finishes_an_interrupted_switch_at_every_step() {
    let (root, data, locks) = dirs();
    let mut writer = unlocked(&data, &locks);
    let homes: Vec<PathBuf> = (0..3)
        .map(|stage| root.path().join(format!("radicle-{stage}")))
        .collect();
    for (stage, home) in homes.iter().enumerate() {
        legacy_write(&mut writer, 10 + stage as u64, home);
    }
    writer.close_stdin();
    assert_eq!(writer.exit_code(Duration::from_secs(5)), 0);
    for (stage, home) in homes.iter().enumerate() {
        let op_id = format!("cut-{stage}");
        interrupted_switch(&data, home, &op_id, stage as u8);
        let mut core = spawn("serve", &data, &locks, &[]);
        let hello = core.hello();
        assert_eq!(
            hello["result"]["node_recovery"],
            Value::Null,
            "stage {stage}"
        );
        let status = core.call_shell(2, "nodes.op_status", json!({ "op_id": op_id }));
        assert_eq!(status["result"]["status"], "installed", "stage {stage}");
        keys_gone(home);
        assert_eq!(
            marker(home),
            Some(json!({ "node_ids": [RADICLE_NID] })),
            "stage {stage}"
        );
        assert_eq!(alias(home), "FreedomBrowser");
        core.close_stdin();
        assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
    }
}

/// Recovery holds the home's gate too: held, the journal stays, the core
/// reports Radicle pending without holding up core.hello, and `recover`
/// exits 75. Released, the next start finishes it.
#[test]
fn recovery_waits_for_the_homes_gate() {
    let (root, data, locks) = dirs();
    let home = root.path().join("radicle");
    let mut writer = unlocked(&data, &locks);
    legacy_write(&mut writer, 3, &home);
    writer.close_stdin();
    assert_eq!(writer.exit_code(Duration::from_secs(5)), 0);
    interrupted_switch(&data, &home, "waiting", 0);
    let gate = fc_service::gate::acquire(&home, &locks, "radicle", Duration::ZERO).unwrap();

    let started = Instant::now();
    let mut core = spawn("serve", &data, &locks, &[]);
    let hello = core.hello();
    assert!(started.elapsed() < Duration::from_secs(5), "hello waited");
    assert_eq!(
        hello["result"]["node_recovery"],
        json!({ "status": "pending_recovery", "node": "radicle", "op_id": "waiting" })
    );
    assert!(home.join("keys/radicle").exists());
    assert!(data.join("node-identity-journal.json").exists());
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);

    let mut recover = spawn("recover", &data, &locks, &[]);
    assert_eq!(recover.exit_code(Duration::from_secs(15)), 75);
    assert!(home.join("keys/radicle").exists());

    drop(gate);
    let mut core = spawn("serve", &data, &locks, &[]);
    let hello = core.hello();
    assert_eq!(hello["result"]["node_recovery"], Value::Null);
    keys_gone(&home);
    assert_eq!(marker(&home), Some(json!({ "node_ids": [RADICLE_NID] })));
}

/// A journal naming anything else to remove or wipe is never acted on.
#[test]
fn removals_and_wipes_a_writer_never_produces_are_set_aside() {
    let (root, data, locks) = dirs();
    let home = root.path().join("radicle");
    std::fs::create_dir_all(home.join("keys")).unwrap();
    std::fs::create_dir_all(&data).unwrap();
    let precious = root.path().join("precious");
    std::fs::write(&precious, b"keep").unwrap();
    std::fs::write(home.join("config.json"), b"{}").unwrap();
    let config_entry = || {
        let staged = PathBuf::from(format!(
            "{}.freedom-new",
            home.join("config.json").display()
        ));
        std::fs::write(&staged, "{}").unwrap();
        let sha: String = sha2::Sha256::digest("{}")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        json!({ "target": home.join("config.json"), "staged": staged, "sha256": sha })
    };
    let removals = || {
        vec![
            json!({ "target": home.join("keys/radicle"), "remove": true }),
            json!({ "target": home.join("keys/radicle.pub"), "remove": true }),
        ]
    };
    let mut cases = Vec::new();
    // Another file removed.
    let mut files = removals();
    files[0] = json!({ "target": precious, "remove": true });
    files.push(config_entry());
    cases.push(json!({ "op_id": "x1", "node": "radicle", "root": home, "files": files }));
    // A wipe of something else.
    let mut files = removals();
    files.push(config_entry());
    cases.push(
        json!({ "op_id": "x2", "node": "radicle", "root": home, "files": files,
        "wipe": [root.path()] }),
    );
    // A removal with a staged file.
    let mut files = removals();
    files[0]["staged"] = json!(precious);
    files.push(config_entry());
    cases.push(json!({ "op_id": "x3", "node": "radicle", "root": home, "files": files }));
    // A Bee journal with a removal.
    cases.push(json!({ "op_id": "x4", "node": "bee", "root": home,
        "files": [{ "target": precious, "remove": true }] }));
    for (i, journal) in cases.into_iter().enumerate() {
        std::fs::write(data.join("node-identity-journal.json"), journal.to_string()).unwrap();
        let mut recover = spawn("recover", &data, &locks, &[]);
        assert_eq!(recover.line(), "corrupt -", "case {i}");
        assert_eq!(recover.exit_code(Duration::from_secs(5)), 0);
        assert_eq!(std::fs::read(&precious).unwrap(), b"keep", "case {i}");
        assert!(root.path().exists());
        let _ = std::fs::remove_file(data.join("node-identity-journal.json.corrupt"));
    }
}

/// A home's `keys` symlinked to another home's: the write is refused, and
/// neither home's files change (review of #177).
#[cfg(unix)]
#[test]
fn a_symlinked_keys_directory_cannot_reach_outside_the_home() {
    let (root, data, locks) = dirs();
    let mut core = unlocked(&data, &locks);
    let other = root.path().join("other-home");
    legacy_write(&mut core, 3, &other);
    let home = root.path().join("radicle");
    std::fs::create_dir_all(&home).unwrap();
    std::os::unix::fs::symlink(other.join("keys"), home.join("keys")).unwrap();
    let before = (walk_contents(&other), walk_contents(&home));
    let reply = core.call(4, "nodes.write_identity", sealed("keys-link", &home, None));
    assert!(reply["error"].is_object(), "{reply}");
    assert_eq!((walk_contents(&other), walk_contents(&home)), before);
    assert!(other.join("keys/radicle").exists());
    assert!(other.join("keys/radicle.pub").exists());
}

/// A home's `node` symlinked out: no marker is written there (review of
/// #177).
#[cfg(unix)]
#[test]
fn a_symlinked_node_directory_cannot_write_outside_the_home() {
    let (root, data, locks) = dirs();
    let mut core = unlocked(&data, &locks);
    let home = root.path().join("radicle");
    legacy_write(&mut core, 3, &home);
    let outside = root.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, home.join("node")).unwrap();
    let before = walk_contents(&home);
    for (id, wipe) in [(4, None), (5, Some(true))] {
        let reply = core.call(
            id,
            "nodes.write_identity",
            sealed(&format!("node-{id}"), &home, wipe),
        );
        assert!(reply["error"].is_object(), "{reply}");
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
        assert_eq!(walk_contents(&home), before);
    }
}

/// The write works under the gate's canonical home: a home named through a
/// symlink is switched where it really is, and its journal names that
/// path. A journal whose root has since become a symlink elsewhere is never
/// acted on (review of #177).
#[cfg(unix)]
#[test]
fn the_home_is_its_canonical_path_and_a_retargeted_root_is_refused() {
    let (root, data, locks) = dirs();
    let mut core = unlocked(&data, &locks);
    let real = root.path().join("real-home");
    legacy_write(&mut core, 3, &real);
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let reply = core.call(4, "nodes.write_identity", sealed("via-alias", &alias, None));
    assert_eq!(reply["result"]["status"], "installed", "{reply}");
    keys_gone(&real);
    assert_eq!(marker(&real), Some(json!({ "node_ids": [RADICLE_NID] })));

    // A switch interrupted after its commit, then its home replaced by a
    // symlink to another home: recovery leaves both alone.
    let home = root.path().join("radicle");
    let victim = root.path().join("victim");
    legacy_write(&mut core, 10, &home);
    legacy_write(&mut core, 11, &victim);
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
    interrupted_switch(&data, &home, "retargeted", 0);
    std::fs::rename(&home, root.path().join("moved-away")).unwrap();
    std::os::unix::fs::symlink(&victim, &home).unwrap();
    let before = walk_contents(&victim);
    let mut core = spawn("serve", &data, &locks, &[]);
    let hello = core.hello();
    assert_eq!(
        hello["result"]["node_recovery"]["status"], "pending_recovery",
        "{hello}"
    );
    assert_eq!(walk_contents(&victim), before);
    assert!(data.join("node-identity-journal.json").exists());
}

/// Review of #177, round 2 (M1): the home is opened once, after its gate,
/// and everything the write does reaches it through that handle. Held at
/// its commit, after staging, the home is renamed and a symlink to another
/// home (whose gate its service holds) put in its place. Released, the
/// switch lands in the home it planned and staged in, now moved; the other
/// home is untouched.
#[cfg(unix)]
#[test]
fn a_home_replaced_during_its_write_is_written_where_it_was_staged() {
    let (root, data, locks) = dirs();
    let home = root.path().join("home");
    let moved = root.path().join("moved");
    let other = root.path().join("other");
    let mut core = unlocked(&data, &locks);
    legacy_write(&mut core, 3, &home);
    legacy_write(&mut core, 4, &other);
    core.close_stdin();
    assert_eq!(core.exit_code(Duration::from_secs(5)), 0);
    let _other_gate = fc_service::gate::acquire(&other, &locks, "radicle", Duration::ZERO).unwrap();
    let before = walk_contents(&other);

    let (claimed, release) = (root.path().join("claimed"), root.path().join("release"));
    let mut core = spawn_env(
        "serve",
        &data,
        &locks,
        &[],
        &[
            (
                "FREEDOM_CORED_TEST_COMMIT_MARKER",
                claimed.to_str().unwrap(),
            ),
            ("FREEDOM_CORED_TEST_COMMIT_HOLD", release.to_str().unwrap()),
        ],
    );
    core.hello();
    core.send(&request(
        2,
        "nodes.write_identity",
        sealed("swapped", &home, None),
    ));
    let until = Instant::now() + Duration::from_secs(30);
    while !claimed.exists() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(claimed.exists(), "the write never reached its commit");
    std::fs::rename(&home, &moved).unwrap();
    std::os::unix::fs::symlink(&other, &home).unwrap();
    std::fs::write(&release, b"go").unwrap();
    let reply = core.response(2);
    assert_eq!(reply["result"]["status"], "installed", "{reply}");
    assert_eq!(walk_contents(&other), before);
    keys_gone(&moved);
    assert_eq!(marker(&moved), Some(json!({ "node_ids": [RADICLE_NID] })));
    assert_eq!(alias(&moved), "FreedomBrowser");
}

/// Review of #177, round 4: two cores with identity directories of their
/// own share a Radicle home. B holds the home's gate, its sealed config
/// staged, held at its commit. A, with an intent of its own for that home
/// left from an operation that died before its commit, asks for another
/// write: its recovery waits for the gate, so A answers `lock_held` and
/// B's staged config stays. Released, B installs.
#[test]
fn a_cores_recovery_never_removes_another_cores_staged_files() {
    let (root, data_a, locks) = dirs();
    let data_b = root.path().join("identity-b");
    let home = root.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("config.json"), b"{\"old\":true}").unwrap();
    let mut a = spawn("serve", &data_a, &locks, &[]);
    a.hello();
    let (claimed, release) = (root.path().join("claimed"), root.path().join("release"));
    let mut b = spawn_env(
        "serve",
        &data_b,
        &locks,
        &[],
        &[
            (
                "FREEDOM_CORED_TEST_COMMIT_MARKER",
                claimed.to_str().unwrap(),
            ),
            ("FREEDOM_CORED_TEST_COMMIT_HOLD", release.to_str().unwrap()),
        ],
    );
    b.hello();
    // A's intent, from an operation that died before its commit, for the
    // home's canonical path.
    let canonical = std::fs::canonicalize(&home).unwrap();
    std::fs::write(
        data_a.join("node-identity-staging.json"),
        json!({ "op_id": "earlier-a", "node": "radicle", "root": canonical }).to_string(),
    )
    .unwrap();
    b.send(&request(
        2,
        "nodes.write_identity",
        sealed("live-b", &home, None),
    ));
    let until = Instant::now() + Duration::from_secs(30);
    while !claimed.exists() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(claimed.exists(), "B never reached its commit");
    let staged = home.join("config.json.freedom-new");
    assert!(staged.exists());
    let reply = a.call(2, "nodes.write_identity", sealed("new-a", &home, None));
    assert_eq!(reply["error"]["code"], "lock_held", "{reply}");
    assert!(staged.exists(), "A's recovery removed B's staged config");
    assert!(data_a.join("node-identity-staging.json").exists());
    std::fs::write(&release, b"go").unwrap();
    let reply = b.response(2);
    assert_eq!(reply["result"]["status"], "installed", "{reply}");
    assert_eq!(alias(&home), "FreedomBrowser");
}

/// The switch reads only the private key file's public part: a key whose
/// private section is corrupt still names its identity (review of #177).
#[test]
fn the_switch_needs_only_the_private_files_public_prefix() {
    let (root, data, locks) = dirs();
    let mut core = unlocked(&data, &locks);
    let home = root.path().join("radicle");
    legacy_write(&mut core, 3, &home);
    std::fs::remove_file(home.join("keys/radicle.pub")).unwrap();
    let key = std::fs::read_to_string(home.join("keys/radicle")).unwrap();
    let lines: Vec<&str> = key.lines().collect();
    let last_body = lines[lines.len() - 2];
    let corrupt = key.replace(last_body, &"!".repeat(last_body.len()));
    std::fs::write(home.join("keys/radicle"), corrupt).unwrap();
    let reply = core.call(4, "nodes.write_identity", sealed("prefix", &home, None));
    assert_eq!(reply["result"]["status"], "installed", "{reply}");
    keys_gone(&home);
    assert_eq!(marker(&home), Some(json!({ "node_ids": [RADICLE_NID] })));
}

/// A journal with a member no writer writes, at the top or in an entry, is
/// set aside, never acted on (review of #177).
#[test]
fn a_journal_with_unknown_members_is_not_a_writer_shape() {
    let (root, data, locks) = dirs();
    let mut writer = unlocked(&data, &locks);
    let homes: Vec<PathBuf> = (0..2)
        .map(|i| root.path().join(format!("radicle-{i}")))
        .collect();
    for (i, home) in homes.iter().enumerate() {
        legacy_write(&mut writer, 10 + i as u64, home);
    }
    writer.close_stdin();
    assert_eq!(writer.exit_code(Duration::from_secs(5)), 0);
    for (i, home) in homes.iter().enumerate() {
        interrupted_switch(&data, home, &format!("extra-{i}"), 0);
        let path = data.join("node-identity-journal.json");
        let mut journal: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        if i == 0 {
            journal["unexpected"] = true.into();
        } else {
            journal["files"][1]["unexpected"] = true.into();
        }
        std::fs::write(&path, journal.to_string()).unwrap();
        let mut recover = spawn("recover", &data, &locks, &[]);
        assert_eq!(recover.line(), "corrupt -", "case {i}");
        assert_eq!(recover.exit_code(Duration::from_secs(5)), 0);
        assert!(home.join("keys/radicle").exists(), "case {i}");
        let _ = std::fs::remove_file(data.join("node-identity-journal.json.corrupt"));
    }
}

/// Every file under `dir` with its contents, symlinks as their targets.
fn walk_contents(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            for entry in std::fs::read_dir(&path).unwrap() {
                stack.push(entry.unwrap().path());
            }
        } else if metadata.file_type().is_symlink() {
            out.push((
                path.clone(),
                std::fs::read_link(&path)
                    .unwrap()
                    .into_os_string()
                    .into_encoded_bytes(),
            ));
        } else {
            out.push((path.clone(), std::fs::read(&path).unwrap()));
        }
    }
    out.sort();
    out
}
