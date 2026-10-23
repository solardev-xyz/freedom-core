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
