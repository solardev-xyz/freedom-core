//! Quick unlock in the core, and forgetting its key-store items (design
//! 0013, "The re-wrap" and "Forgetting an item"; PRF-1c).
//!
//! The test plays main: it answers the core's `shell.keystore` requests
//! from a keychain of its own (items by id, each key sealed to the
//! request's `reply_key` for its op and item, as the helper seals it), so
//! the core runs here as it runs on macOS, with
//! `FREEDOM_CORED_TEST_KEYSTORE_BACKEND` offering the Keychain's
//! `Unattended` on every OS. The test's keychain outlives each core, so a
//! crash hook's exit and a restart show what the file and the keychain
//! hold at each step.
//!
//! - **Quick unlock:** enroll checks the password (refused when wrong, and
//!   throttled with `vault.unlock`), unlock works locked and unlocked, the
//!   exports, status, disable, the callers, and no key store at all.
//! - **Forgetting, killed at each step:** for an enroll's new key, a
//!   replace, a disable and a vault delete, a crash hook before and after
//!   each write, and main holding a `create` or a `forget` past the core's
//!   deadline or killing the helper after the store. After a restart at
//!   each point the file names every item the keychain holds, the entry is
//!   the old one or the new, and after the next open the keychain holds
//!   only the key in use and the file no record.
//! - **The rest of the row:** `forget_backlog` with `forget` made to fail;
//!   a record whose item was removed by hand, or whose backend this OS
//!   doesn't have, dropped without an error; an entry naming no vault
//!   removed at start.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use fc_keystore::{Backend, ItemId, Policy, SecretsFile};
use serde_json::{Value, json};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASSWORD: &str = "testpass1";
const BACKEND: (&str, &str) = ("FREEDOM_CORED_TEST_KEYSTORE_BACKEND", "macos-keychain");
/// How long the core waits for main's answer to a `shell.keystore`, here.
const DEADLINE: (&str, &str) = ("FREEDOM_CORED_TEST_KEYSTORE_DEADLINE_MS", "1500");

fn b64(text: &str) -> String {
    STANDARD.encode(text)
}

/// The OS's RNG, for the test keychain's keys and seals.
struct OsRng;

impl rand_core::TryRng for OsRng {
    type Error = std::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst).unwrap();
        Ok(())
    }
}

impl rand_core::TryCryptoRng for OsRng {}

/// How main answers an op, instead of from the keychain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// No answer: the core's deadline runs out.
    Hold,
    /// `unavailable` (`timeout`), as main answers a helper it killed.
    Timeout,
    /// The item is stored, then `unavailable` (`timeout`): a helper killed
    /// after the OS stored it and before it answered.
    KilledAfterStore,
}

/// Main's keychain.
#[derive(Default)]
struct Keychain {
    items: BTreeMap<String, [u8; 32]>,
    faults: BTreeMap<&'static str, Fault>,
    /// Every op asked, in order.
    calls: Vec<String>,
}

impl Keychain {
    fn ids(&self) -> BTreeSet<String> {
        self.items.keys().cloned().collect()
    }

    /// Main's answer to one `shell.keystore` request, or none.
    fn answer(&mut self, params: &Value) -> Option<Value> {
        let op = params["op"].as_str().unwrap().to_owned();
        let item = params["item"].as_str().unwrap().to_owned();
        assert_eq!(params["policy"], "unattended", "{params}");
        assert!(params.get("sealed").is_none(), "{params}");
        self.calls.push(op.clone());
        let fault = self.faults.get(op.as_str()).copied();
        let timeout = json!({ "ok": false, "error": "unavailable", "reason": "timeout" });
        match (op.as_str(), fault) {
            (_, Some(Fault::Hold)) => None,
            ("create", Some(Fault::KilledAfterStore)) => {
                let mut key = [0u8; 32];
                getrandom::fill(&mut key).unwrap();
                self.items.insert(item, key);
                Some(timeout)
            }
            (_, Some(Fault::Timeout | Fault::KilledAfterStore)) => Some(timeout),
            ("create", None) => {
                assert!(!self.items.contains_key(&item), "a create of a named item");
                let mut key = [0u8; 32];
                getrandom::fill(&mut key).unwrap();
                self.items.insert(item.clone(), key);
                Some(sealed(params, "create", &item, &key))
            }
            ("open", None) => match self.items.get(&item) {
                Some(key) => Some(sealed(params, "open", &item, key)),
                None => Some(json!({ "ok": false, "error": "not_found" })),
            },
            ("forget", None) => Some(match self.items.remove(&item) {
                Some(_) => json!({ "ok": true }),
                None => json!({ "ok": false, "error": "not_found" }),
            }),
            (other, _) => panic!("op {other}"),
        }
    }
}

/// `key` sealed to the request's `reply_key`, bound to its op and item, as
/// the helper answers.
fn sealed(params: &Value, op: &str, item: &str, key: &[u8; 32]) -> Value {
    let reply: [u8; 32] = STANDARD
        .decode(params["reply_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let mut aad = b"freedom-keystore/1\0".to_vec();
    aad.extend_from_slice(op.as_bytes());
    aad.push(0);
    aad.extend_from_slice(item.as_bytes());
    let seal = fc_seal::seal_with(&reply, key, b"freedom-keystore/1", &aad, &mut OsRng).unwrap();
    let mut bytes = seal.enc.to_vec();
    bytes.extend_from_slice(&seal.ciphertext);
    json!({ "ok": true, "key": STANDARD.encode(bytes) })
}

/// A profile, its keychain, and the core running on it, if one is.
struct Main {
    _root: tempfile::TempDir,
    data: PathBuf,
    locks: PathBuf,
    keychain: Keychain,
    core: Option<common::Core>,
    next_id: u64,
    /// Events the calls set aside.
    events: Vec<Value>,
}

impl Main {
    fn new() -> Main {
        let (root, data, locks) = common::dirs();
        Main {
            _root: root,
            data,
            locks,
            keychain: Keychain::default(),
            core: None,
            next_id: 10,
            events: Vec::new(),
        }
    }

    /// Starts a core with the backend hook and `env`, and says hello.
    fn start(&mut self, env: &[(&str, &str)]) {
        let mut all = vec![BACKEND, DEADLINE];
        all.extend_from_slice(env);
        self.start_with(&all);
    }

    /// Starts a core with exactly `env`.
    fn start_with(&mut self, env: &[(&str, &str)]) {
        self.stop();
        let mut core = common::spawn_env("serve", &self.data, &self.locks, &[], env);
        core.hello();
        self.core = Some(core);
    }

    fn stop(&mut self) {
        self.core = None;
    }

    fn core(&mut self) -> &mut common::Core {
        self.core.as_mut().expect("a core runs")
    }

    /// Serves one message: a `shell.keystore` request is answered from the
    /// keychain. Returns it unless it was such a request; `Err` once the core
    /// has exited.
    fn serve_one(&mut self, within: Duration) -> Result<Option<Value>, ()> {
        let Some(message) = self.core().recv_or_closed(within)? else {
            return Ok(None);
        };
        if message["type"] == "request" && message["method"] == "shell.keystore" {
            let id = message["id"].as_u64().unwrap();
            if let Some(result) = self.keychain.answer(&message["params"]) {
                self.core()
                    .send(&json!({ "type": "response", "id": id, "result": result }));
            }
            return Ok(None);
        }
        Ok(Some(message))
    }

    /// Sends `method` from `caller` and serves the keychain until its
    /// response; `None` if the core exited first.
    fn try_call(&mut self, caller: &str, method: &str, params: Value) -> Option<Value> {
        let id = self.next_id;
        self.next_id += 1;
        self.core().send(&json!({
            "type": "request", "id": id, "method": method, "params": params,
            "context": { "caller": caller },
        }));
        let until = Instant::now() + Duration::from_secs(60);
        while Instant::now() < until {
            match self.serve_one(Duration::from_millis(200)) {
                Err(()) => return None,
                Ok(Some(message)) if message["type"] == "response" && message["id"] == id => {
                    return Some(message);
                }
                Ok(Some(message)) if message["type"] == "event" => self.events.push(message),
                Ok(_) => {}
            }
        }
        panic!("no response to {method}");
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        self.try_call("chrome", method, params)
            .unwrap_or_else(|| panic!("the core exited during {method}"))
    }

    fn shell(&mut self, method: &str, params: Value) -> Value {
        self.try_call("shell", method, params)
            .unwrap_or_else(|| panic!("the core exited during {method}"))
    }

    /// Serves the keychain until the core exits, as a crash hook makes it:
    /// its exit code.
    fn until_exit(&mut self) -> i32 {
        let until = Instant::now() + Duration::from_secs(30);
        while Instant::now() < until {
            if self.serve_one(Duration::from_millis(200)).is_err() {
                let code = self.core().exit_code(Duration::from_secs(10));
                self.core = None;
                return code;
            }
        }
        panic!("the core didn't exit");
    }

    /// The events' names since the last look.
    fn events(&mut self) -> Vec<String> {
        std::mem::take(&mut self.events)
            .iter()
            .map(|e| e["event"].as_str().unwrap().to_owned())
            .collect()
    }

    fn import(&mut self) {
        let imported = self.call(
            "vault.import",
            json!({ "password_b64": b64(PASSWORD), "mnemonic_b64": b64(ABANDON), "overwrite": true }),
        );
        assert!(imported["result"].is_object(), "{imported}");
    }

    fn enroll(&mut self) -> Value {
        self.shell(
            "quick_unlock.enroll",
            json!({ "password_b64": b64(PASSWORD) }),
        )
    }

    fn status(&mut self) -> Value {
        let status = self.call("quick_unlock.status", json!({}));
        status["result"].clone()
    }

    fn secrets_path(&self) -> PathBuf {
        self.data.join("secrets.json")
    }

    /// The secrets file, as the core wrote it (empty if none).
    fn file(&self) -> SecretsFile {
        match std::fs::read(self.secrets_path()) {
            Ok(bytes) => SecretsFile::parse(&bytes).unwrap(),
            Err(_) => SecretsFile::new(),
        }
    }

    /// Serves the keychain until the file holds no `forget` record.
    fn drained(&mut self) {
        let until = Instant::now() + Duration::from_secs(20);
        while !self.file().forget_list().is_empty() {
            assert!(
                Instant::now() < until,
                "records left: {:?}",
                self.file().items()
            );
            self.serve_one(Duration::from_millis(100)).unwrap();
        }
    }

    /// The file names every item the keychain holds.
    fn file_names_the_keychain(&self) {
        let named: BTreeSet<String> = self.file().items().iter().map(|i| i.item.hex()).collect();
        let held = self.keychain.ids();
        assert!(held.is_subset(&named), "held {held:?}, named {named:?}");
    }

    /// The keychain holds only the file's key in use (none if its item was
    /// removed by hand), and the file no record and no pending item.
    fn only_the_key_in_use(&self) {
        let file = self.file();
        assert!(file.forget_list().is_empty());
        let in_use: BTreeSet<String> = Policy::ALL
            .iter()
            .filter_map(|policy| file.key(*policy))
            .map(|sealed| sealed.item().hex())
            .collect();
        assert_eq!(file.items().len(), in_use.len(), "{:?}", file.items());
        let held = self.keychain.ids();
        assert!(held.is_subset(&in_use), "held {held:?}, in use {in_use:?}");
    }

    fn enrolled(&self) -> bool {
        self.file()
            .entry_names()
            .any(|name| name.as_str() == "quick-unlock")
    }
}

fn error_code(response: &Value) -> &str {
    response["error"]["code"].as_str().unwrap_or("")
}

/// A profile with a vault and quick unlock enrolled.
fn enrolled() -> Main {
    let mut main = Main::new();
    main.start(&[]);
    main.import();
    let enrolled = main.enroll();
    assert_eq!(enrolled["result"], json!({}), "{enrolled}");
    main
}

// ----- Quick unlock

#[test]
fn enroll_unlock_export_and_disable() {
    let mut main = Main::new();
    main.start(&[]);
    assert_eq!(
        main.status(),
        json!({ "enabled": false, "policy": null, "available": true })
    );
    // No vault yet.
    assert_eq!(error_code(&main.enroll()), "no_vault");
    main.import();
    assert_eq!(main.enroll()["result"], json!({}));
    assert_eq!(
        main.status(),
        json!({ "enabled": true, "policy": "unattended", "available": true })
    );
    assert_eq!(main.keychain.calls, ["create"]);
    // The entry is bound to the vault file's digest.
    let vault = std::fs::read(main.data.join("identity-vault.json")).unwrap();
    let digest: String = <sha2::Sha256 as sha2::Digest>::digest(&vault)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let file = main.file();
    let name = fc_keystore::EntryName::new("quick-unlock").unwrap();
    assert_eq!(
        file.binding(&name).unwrap().get("vault_fingerprint"),
        Some(digest.as_str())
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(main.secrets_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // Unlock, unlocked and then locked: the vault unlocks again each time.
    main.events();
    for _ in 0..2 {
        let unlocked = main.call("quick_unlock.unlock", json!({}));
        assert!(
            unlocked["result"]["addresses"]["user_wallet"].is_string(),
            "{unlocked}"
        );
        assert_eq!(main.events(), ["vault.unlocked"]);
        assert_eq!(main.call("vault.lock", json!({}))["result"], json!({}));
        assert_eq!(main.events(), ["vault.locked"]);
    }
    let unlocked = main.call("quick_unlock.unlock", json!({}));
    assert!(unlocked["result"].is_object(), "{unlocked}");
    assert_eq!(main.events(), ["vault.unlocked"]);
    // The exports, locked: they unlock first, as the Touch ID path does.
    main.call("vault.lock", json!({}));
    let phrase = main.call("quick_unlock.export_mnemonic", json!({}));
    let phrase = STANDARD
        .decode(phrase["result"]["mnemonic_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(phrase, ABANDON.as_bytes());
    let key = main.call("quick_unlock.export_private_key", json!({ "account": 0 }));
    let by_password = main.call(
        "vault.export_private_key",
        json!({ "password_b64": b64(PASSWORD), "account": 0 }),
    );
    assert_eq!(
        key["result"]["private_key_hex"], by_password["result"]["private_key_hex"],
        "{key}"
    );
    // Every open came through the keychain; one key in all.
    assert_eq!(
        main.keychain
            .calls
            .iter()
            .filter(|c| *c == "create")
            .count(),
        1
    );
    // Enrolling again puts the entry under the same key.
    assert_eq!(main.enroll()["result"], json!({}));
    assert_eq!(main.keychain.items.len(), 1);
    // Disable: the entry goes, the key is forgotten.
    assert_eq!(
        main.call("quick_unlock.disable", json!({}))["result"],
        json!({})
    );
    main.drained();
    assert!(!main.enrolled());
    assert!(main.keychain.items.is_empty());
    assert_eq!(main.status()["enabled"], false);
    assert_eq!(
        error_code(&main.call("quick_unlock.unlock", json!({}))),
        "not_found"
    );
    // A second disable has nothing to do.
    assert_eq!(
        main.call("quick_unlock.disable", json!({}))["result"],
        json!({})
    );
}

#[test]
fn enroll_checks_the_password_and_shares_the_throttle() {
    let mut main = Main::new();
    main.start(&[]);
    main.import();
    let wrong = main.shell(
        "quick_unlock.enroll",
        json!({ "password_b64": b64("wrongpass") }),
    );
    assert_eq!(error_code(&wrong), "incorrect_password", "{wrong}");
    assert!(main.keychain.calls.is_empty(), "no key-store call");
    assert!(!main.secrets_path().exists());
    // Four more wrong ones: five failures are free, then vault.unlock waits.
    for _ in 0..4 {
        let wrong = main.shell(
            "quick_unlock.enroll",
            json!({ "password_b64": b64("wrongpass") }),
        );
        assert_eq!(error_code(&wrong), "incorrect_password");
    }
    let unlock = main.call("vault.unlock", json!({ "password_b64": b64(PASSWORD) }));
    assert_eq!(error_code(&unlock), "throttled", "{unlock}");
    // And the other way: enroll waits too, with the right password.
    assert_eq!(error_code(&main.enroll()), "throttled");
    assert!(main.keychain.calls.is_empty());
}

#[test]
fn callers_and_no_key_store() {
    let mut main = Main::new();
    main.start(&[]);
    main.import();
    // Enroll is main's own.
    let forbidden = main.call(
        "quick_unlock.enroll",
        json!({ "password_b64": b64(PASSWORD) }),
    );
    assert_eq!(error_code(&forbidden), "forbidden");
    if cfg!(target_os = "macos") {
        return;
    }
    // Without the hook this OS has no backend: nothing is asked of main.
    main.start_with(&[]);
    assert_eq!(
        main.status(),
        json!({ "enabled": false, "policy": null, "available": false })
    );
    let refused = main.enroll();
    assert_eq!(error_code(&refused), "key_store_unavailable", "{refused}");
    assert_eq!(refused["error"]["data"]["reason"], "unsupported");
    assert!(main.keychain.calls.is_empty());
    assert!(!main.secrets_path().exists());
}

#[test]
fn a_failed_open_deletes_nothing() {
    let mut main = enrolled();
    // The item gone from the keychain, as by hand: unlock fails, the entry
    // stays.
    main.keychain.items.clear();
    let unlock = main.call("quick_unlock.unlock", json!({}));
    assert_eq!(error_code(&unlock), "key_store_unavailable", "{unlock}");
    assert_eq!(unlock["error"]["data"]["reason"], "not_found");
    assert!(main.enrolled());
    // Main not answering in time: `timeout`, and nothing changes.
    main.keychain.faults.insert("open", Fault::Hold);
    let unlock = main.call("quick_unlock.unlock", json!({}));
    assert_eq!(unlock["error"]["data"]["reason"], "timeout", "{unlock}");
    main.keychain.faults.insert("open", Fault::Timeout);
    let unlock = main.call("quick_unlock.unlock", json!({}));
    assert_eq!(unlock["error"]["data"]["reason"], "timeout", "{unlock}");
    assert!(main.enrolled());
}

// ----- Forgetting, killed at each step

/// What quick unlock is after the crash, the restart and the drain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum After {
    /// No entry.
    Off,
    /// The entry, and unlock works.
    Works,
    /// The entry, its key's item gone (a replace killed before it began).
    Dead,
}

/// Runs `op` on `main` with the crash hook `hook` (exit 99) or main failing
/// one op with `fault`; then restarts, and checks the file against the
/// keychain before and after the next open's drain.
fn killed(
    mut main: Main,
    op: fn(&mut Main) -> Option<Value>,
    hook: Option<&str>,
    fault: Option<(&'static str, Fault)>,
    after: After,
) {
    let crash = hook.map(|step| ("FREEDOM_CORED_TEST_SECRETS_CRASH", step));
    main.start(crash.as_slice());
    if let Some((op, fault)) = fault {
        main.keychain.faults.insert(op, fault);
    }
    let response = op(&mut main);
    if hook.is_some() {
        if response.is_some() {
            // The hook is in the drain, after the reply.
            assert_eq!(main.until_exit(), 99, "{hook:?}");
        } else {
            assert_eq!(main.core().exit_code(Duration::from_secs(10)), 99);
            main.core = None;
        }
    } else {
        // The drain tries once, and its record stays.
        let until = Instant::now() + Duration::from_millis(2500);
        while Instant::now() < until {
            main.serve_one(Duration::from_millis(100)).unwrap();
        }
        main.stop();
    }
    main.file_names_the_keychain();
    main.keychain.faults.clear();
    main.start(&[]);
    main.file_names_the_keychain();
    main.drained();
    main.only_the_key_in_use();
    let entry = main.enrolled();
    assert_eq!(entry, after != After::Off, "{hook:?} {fault:?}");
    let unlock = main.call("quick_unlock.unlock", json!({}));
    match after {
        After::Works => assert!(unlock["result"].is_object(), "{hook:?} {fault:?}: {unlock}"),
        // `no_vault` after a vault delete.
        After::Off => assert!(
            matches!(error_code(&unlock), "not_found" | "no_vault"),
            "{hook:?} {fault:?}: {unlock}"
        ),
        After::Dead => assert_eq!(
            unlock["error"]["data"]["reason"], "not_found",
            "{hook:?} {fault:?}: {unlock}"
        ),
    }
}

fn enroll_op(main: &mut Main) -> Option<Value> {
    main.try_call(
        "shell",
        "quick_unlock.enroll",
        json!({ "password_b64": b64(PASSWORD) }),
    )
}

fn disable_op(main: &mut Main) -> Option<Value> {
    main.try_call("chrome", "quick_unlock.disable", json!({}))
}

fn delete_op(main: &mut Main) -> Option<Value> {
    main.try_call(
        "chrome",
        "vault.delete",
        json!({ "password_b64": b64(PASSWORD) }),
    )
}

/// A profile with a vault, no quick unlock, and no core running.
fn with_vault() -> Main {
    let mut main = Main::new();
    main.start(&[]);
    main.import();
    main.stop();
    main
}

fn enrolled_stopped() -> Main {
    let mut main = enrolled();
    main.stop();
    main
}

#[test]
fn an_enroll_killed_at_each_step() {
    for (hook, after) in [
        ("before-pending", After::Off),
        ("after-pending", After::Off),
        ("before-commit", After::Off),
        ("after-commit", After::Works),
    ] {
        killed(with_vault(), enroll_op, Some(hook), None, after);
    }
    for fault in [Fault::Hold, Fault::Timeout, Fault::KilledAfterStore] {
        killed(
            with_vault(),
            enroll_op,
            None,
            Some(("create", fault)),
            After::Off,
        );
    }
}

/// The committed key's item is gone (removed by hand): enroll replaces the
/// key. Its pending write takes the dead entry off and moves the old key
/// into `forget`; the commit writes the entry under the new key.
#[test]
fn a_replace_killed_at_each_step() {
    let replace = || {
        let mut main = enrolled_stopped();
        main.keychain.items.clear();
        main
    };
    for (hook, after) in [
        ("before-pending", After::Dead),
        ("after-pending", After::Off),
        ("before-commit", After::Off),
        ("after-commit", After::Works),
        ("before-forgotten", After::Works),
        ("after-forgotten", After::Works),
    ] {
        killed(replace(), enroll_op, Some(hook), None, after);
    }
    for (op, fault, after) in [
        ("create", Fault::Hold, After::Off),
        ("create", Fault::KilledAfterStore, After::Off),
        ("forget", Fault::Hold, After::Works),
        ("forget", Fault::Timeout, After::Works),
    ] {
        killed(replace(), enroll_op, None, Some((op, fault)), after);
    }
}

#[test]
fn a_disable_killed_at_each_step() {
    for (hook, after) in [
        ("before-remove", After::Works),
        ("after-remove", After::Off),
        ("before-forgotten", After::Off),
        ("after-forgotten", After::Off),
    ] {
        killed(enrolled_stopped(), disable_op, Some(hook), None, after);
    }
    for fault in [Fault::Hold, Fault::Timeout] {
        killed(
            enrolled_stopped(),
            disable_op,
            None,
            Some(("forget", fault)),
            After::Off,
        );
    }
}

/// Before or after the removal the vault is gone: a removal the crash
/// prevented is the next start's (an entry naming no vault).
#[test]
fn a_vault_delete_killed_at_each_step() {
    for hook in [
        "before-remove",
        "after-remove",
        "before-forgotten",
        "after-forgotten",
    ] {
        killed(enrolled_stopped(), delete_op, Some(hook), None, After::Off);
    }
    for fault in [Fault::Hold, Fault::Timeout] {
        killed(
            enrolled_stopped(),
            delete_op,
            None,
            Some(("forget", fault)),
            After::Off,
        );
    }
}

// ----- The rest of the row

#[test]
fn forget_backlog_with_forget_failing() {
    let mut main = Main::new();
    main.start(&[]);
    main.import();
    main.keychain.faults.insert("forget", Fault::Timeout);
    // Four keys made and given up, none forgotten: four records.
    for _ in 0..4 {
        assert_eq!(main.enroll()["result"], json!({}));
        assert_eq!(
            main.call("quick_unlock.disable", json!({}))["result"],
            json!({})
        );
    }
    assert_eq!(main.file().forget_list().len(), 4);
    let before = std::fs::read(main.secrets_path()).unwrap();
    let creates = main
        .keychain
        .calls
        .iter()
        .filter(|c| *c == "create")
        .count();
    // A fifth: the list is tried again, fails, and the create is refused.
    let refused = main.enroll();
    assert_eq!(error_code(&refused), "key_store_unavailable", "{refused}");
    assert_eq!(refused["error"]["data"]["reason"], "forget_backlog");
    assert_eq!(std::fs::read(main.secrets_path()).unwrap(), before);
    assert_eq!(
        main.keychain
            .calls
            .iter()
            .filter(|c| *c == "create")
            .count(),
        creates
    );
    // Once a forget works, so does the enroll.
    main.keychain.faults.clear();
    assert_eq!(main.enroll()["result"], json!({}));
    main.drained();
    main.only_the_key_in_use();
    assert_eq!(main.keychain.items.len(), 1);
}

#[test]
fn records_gone_by_hand_or_foreign_are_dropped() {
    let mut main = enrolled();
    // A record whose item was removed by hand: `not_found`, dropped.
    main.keychain.faults.insert("forget", Fault::Timeout);
    assert_eq!(
        main.call("quick_unlock.disable", json!({}))["result"],
        json!({})
    );
    assert_eq!(main.file().forget_list().len(), 1);
    main.stop();
    main.keychain.items.clear();
    main.keychain.faults.clear();
    main.start(&[]);
    main.drained();
    assert_eq!(
        main.keychain.calls.last().map(String::as_str),
        Some("forget")
    );
    // A record of a backend this OS doesn't have: dropped at start, with no
    // call.
    main.stop();
    let foreign = ItemId::parse("0123456789abcdef0123456789abcdef").unwrap();
    let file = SecretsFile::new()
        .begin_create(Policy::Unattended, Backend::SecretService, foreign)
        .unwrap()
        .settle();
    assert_eq!(file.forget_list().len(), 1);
    std::fs::write(main.secrets_path(), file.text()).unwrap();
    let calls = main.keychain.calls.len();
    main.start(&[]);
    assert!(main.file().items().is_empty());
    assert_eq!(main.status()["enabled"], false);
    assert_eq!(main.keychain.calls.len(), calls);
}

#[test]
fn an_entry_naming_no_vault_is_removed_at_start() {
    // The vault deleted by hand, or by an older build.
    let mut main = enrolled_stopped();
    std::fs::remove_file(main.data.join("identity-vault.json")).unwrap();
    main.start(&[]);
    main.drained();
    assert!(!main.enrolled());
    main.only_the_key_in_use();
    assert!(main.keychain.items.is_empty());
    // Another vault in its place: off at once, removed at the next start.
    let mut main = enrolled();
    let imported = main.call(
        "vault.import",
        json!({ "password_b64": b64("testpass2"), "mnemonic_b64": b64(ABANDON), "overwrite": true }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    assert_eq!(main.status()["enabled"], false);
    assert_eq!(
        error_code(&main.call("quick_unlock.unlock", json!({}))),
        "not_found"
    );
    assert!(main.enrolled());
    main.start(&[]);
    main.drained();
    assert!(!main.enrolled());
    assert!(main.keychain.items.is_empty());
}

/// A malformed secrets file is never written over: nothing it names is
/// lost.
#[test]
fn a_malformed_file_is_left_alone() {
    let mut main = Main::new();
    main.start(&[]);
    main.import();
    main.stop();
    std::fs::write(main.secrets_path(), b"{\"version\":1").unwrap();
    main.start(&[]);
    let refused = main.enroll();
    assert_eq!(error_code(&refused), "storage", "{refused}");
    assert_eq!(refused["error"]["data"]["file"], "secrets");
    assert_eq!(
        std::fs::read(main.secrets_path()).unwrap(),
        b"{\"version\":1"
    );
    assert!(main.keychain.calls.is_empty());
}
