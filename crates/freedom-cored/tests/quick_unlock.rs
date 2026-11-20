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
//!   deadline or killing the helper after the OS acted (the item stored,
//!   or forgotten, and the answer lost). After a restart at each point the
//!   file names every item the keychain holds, the entry is the old one or
//!   the new, and after the next open the keychain holds only the key in
//!   use and the file no record. The start's own settling write, killed
//!   before and after it, is finished by the next start.
//! - **The vault delete** is one journaled operation with the secrets file:
//!   a crash leaves the vault, the entry and its key, or none of them and
//!   the key in `forget`; a secrets file that can't be read, or a write
//!   that fails before the commit, refuses the delete with the vault
//!   intact; an install that fails after it is finished before anything
//!   reads the vault again.
//! - **The rest of the row:** `forget_backlog` with `forget` made to fail;
//!   a record whose item was removed by hand, or whose backend this OS
//!   doesn't have, dropped without an error; an entry naming no vault
//!   removed at start.
//! - **The re-wrap** (PRF-1c-2): `quick_unlock: true` on `vault.create` and
//!   `vault.import`, and `vault.change_password` with quick unlock, each
//!   killed by a crash hook before and after each write, failed at each
//!   write, and with main failing the key store's `open` or `create`: after
//!   the restart the vault is the old one with its credential or the new
//!   one with its own, never a vault without its credential, and quick
//!   unlock opens it. An old entry never opens the new vault; unlock works
//!   locked and unlocked after a re-wrap; the credential under its second
//!   name, `quick-unlock.next`, kept at start and folded by the next write.

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
    /// The OS acts, then `unavailable` (`timeout`): a helper killed after
    /// the OS stored a `create`'s item, or forgot a `forget`'s, and before
    /// it answered.
    KilledAfterStore,
    /// `invalidated`: the item is there, but its key no longer opens.
    Invalidated,
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
            (_, Some(Fault::Invalidated)) => Some(json!({ "ok": false, "error": "invalidated" })),
            ("create", Some(Fault::KilledAfterStore)) => {
                let mut key = [0u8; 32];
                getrandom::fill(&mut key).unwrap();
                self.items.insert(item, key);
                Some(timeout)
            }
            // The OS forgot the item; the answer is lost.
            ("forget", Some(Fault::KilledAfterStore)) => {
                self.items.remove(&item);
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
    /// The hello names `vault_meta` in `store_moved` (PRF-5c-2).
    moved: bool,
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
            moved: false,
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
        if self.moved {
            core.store_moved = vec!["vault_meta"];
        }
        core.hello();
        self.core = Some(core);
    }

    /// Starts a core with the backend hook and `env`, which stops it before
    /// the hello is answered (the start's work runs without one): its exit
    /// code.
    fn start_killed(&mut self, env: &[(&str, &str)]) -> i32 {
        self.stop();
        let mut all = vec![BACKEND, DEADLINE];
        all.extend_from_slice(env);
        let mut core = common::spawn_env("serve", &self.data, &self.locks, &[], &all);
        core.exit_code(Duration::from_secs(10))
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
        self.try_call_in(json!({ "caller": caller }), method, params)
    }

    /// [`Main::try_call`] with a whole caller context.
    fn try_call_in(&mut self, context: Value, method: &str, params: Value) -> Option<Value> {
        let id = self.next_id;
        self.next_id += 1;
        self.core().send(&json!({
            "type": "request", "id": id, "method": method, "params": params,
            "context": context,
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

    fn vault_path(&self) -> PathBuf {
        self.data.join("identity-vault.json")
    }

    /// No vault delete's journal or its temp files, and no staged secrets
    /// file: nothing of a delete is left over.
    fn no_delete_left(&self) {
        for name in ["vault-delete-journal.json", "secrets.json.freedom-new"] {
            assert!(!self.data.join(name).exists(), "{name}");
        }
        let temps: Vec<String> = std::fs::read_dir(&self.data)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".vault-delete-journal.json."))
            .collect();
        assert!(temps.is_empty(), "{temps:?}");
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

/// Design 0013, API: enroll is main's own (`shell`); the rest are the
/// chrome's, behind main's Touch ID prompt; a page reaches none. Each
/// refused call is `forbidden` and asks the key store nothing.
#[test]
fn callers() {
    let mut main = enrolled();
    let page = json!({ "caller": "page", "page": {
        "origin": "https://app.example", "top_origin": "https://app.example",
        "frame": 1, "navigation": 1, "agent": false,
    } });
    let calls = main.keychain.calls.clone();
    for (method, params) in [
        (
            "quick_unlock.enroll",
            json!({ "password_b64": b64(PASSWORD) }),
        ),
        ("quick_unlock.unlock", json!({})),
        ("quick_unlock.export_mnemonic", json!({})),
        ("quick_unlock.export_private_key", json!({ "account": 0 })),
        ("quick_unlock.status", json!({})),
        ("quick_unlock.disable", json!({})),
    ] {
        let enroll = method == "quick_unlock.enroll";
        for (context, allowed) in [
            (json!({ "caller": "chrome" }), !enroll),
            (json!({ "caller": "shell" }), enroll),
            (page.clone(), false),
        ] {
            let response = main
                .try_call_in(context.clone(), method, params.clone())
                .unwrap();
            if allowed {
                assert!(
                    response["result"].is_object(),
                    "{method} {context}: {response}"
                );
                // Put back what the call changed.
                if method == "quick_unlock.disable" {
                    main.drained();
                    assert_eq!(main.enroll()["result"], json!({}));
                }
            } else {
                assert_eq!(
                    error_code(&response),
                    "forbidden",
                    "{method} {context}: {response}"
                );
                assert!(response["result"].is_null(), "{method} {context}");
            }
        }
    }
    // Only the allowed calls reached the keychain.
    assert!(calls.len() < main.keychain.calls.len());
    assert!(main.enrolled());
}

#[test]
fn no_key_store() {
    if cfg!(target_os = "macos") {
        return;
    }
    let mut main = Main::new();
    main.start(&[]);
    main.import();
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
    /// No entry; the vault stays.
    Off,
    /// The entry, and unlock works.
    Works,
    /// The entry, its key's item gone (a replace killed before it began).
    Dead,
    /// No vault, and no entry.
    Deleted,
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
    if hook == Some("before-delete-journal-rename") {
        // Killed with the journal's temp file written, before its rename:
        // the next start removes it.
        let temps = std::fs::read_dir(&main.data)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".vault-delete-journal.json.")
            })
            .count();
        assert_eq!(temps, 1);
        assert!(!main.data.join("vault-delete-journal.json").exists());
    }
    if fault == Some(("forget", Fault::KilledAfterStore)) {
        // The OS forgot the item and the answer was lost: the record stays,
        // naming an item the keychain no longer holds.
        let records: Vec<String> = main
            .file()
            .forget_list()
            .iter()
            .map(|sealed| sealed.item().hex())
            .collect();
        assert_eq!(records.len(), 1, "{:?}", main.file().items());
        assert!(!main.keychain.items.contains_key(&records[0]));
        assert!(main.keychain.calls.iter().any(|c| c == "forget"));
    }
    main.file_names_the_keychain();
    main.keychain.faults.clear();
    main.start(&[]);
    main.file_names_the_keychain();
    main.drained();
    main.only_the_key_in_use();
    main.no_delete_left();
    let entry = main.enrolled();
    let expect_entry = matches!(after, After::Works | After::Dead);
    assert_eq!(entry, expect_entry, "{hook:?} {fault:?}");
    assert_eq!(
        main.vault_path().exists(),
        after != After::Deleted,
        "{hook:?} {fault:?}"
    );
    let unlock = main.call("quick_unlock.unlock", json!({}));
    match after {
        After::Works => assert!(unlock["result"].is_object(), "{hook:?} {fault:?}: {unlock}"),
        After::Off => assert_eq!(
            error_code(&unlock),
            "not_found",
            "{hook:?} {fault:?}: {unlock}"
        ),
        After::Dead => assert_eq!(
            unlock["error"]["data"]["reason"], "not_found",
            "{hook:?} {fault:?}: {unlock}"
        ),
        After::Deleted => {
            assert_eq!(
                error_code(&unlock),
                "no_vault",
                "{hook:?} {fault:?}: {unlock}"
            )
        }
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

/// The committed key is dead: enroll replaces it. Its pending write takes
/// the dead entry off and moves the old key into `forget`; the commit writes
/// the entry under the new key. Dead two ways: its item gone (removed by
/// hand), or still there but `invalidated`, so that the old item's own
/// `forget` is what the faults and hooks act on.
#[test]
fn a_replace_killed_at_each_step() {
    let replace = || {
        let mut main = enrolled_stopped();
        main.keychain.items.clear();
        main
    };
    // The fault lasts until the restart, which clears it: the old key then
    // opens again if nothing forgot it.
    let invalidated = || {
        let mut main = enrolled_stopped();
        main.keychain.faults.insert("open", Fault::Invalidated);
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
        ("forget", Fault::KilledAfterStore, After::Works),
    ] {
        killed(replace(), enroll_op, None, Some((op, fault)), after);
    }
    for (hook, after) in [
        ("before-pending", After::Works),
        ("after-pending", After::Off),
        ("before-commit", After::Off),
        ("after-commit", After::Works),
        ("before-forgotten", After::Works),
        ("after-forgotten", After::Works),
    ] {
        killed(invalidated(), enroll_op, Some(hook), None, after);
    }
    for (op, fault, after) in [
        ("create", Fault::Hold, After::Off),
        ("create", Fault::KilledAfterStore, After::Off),
        ("forget", Fault::Hold, After::Works),
        ("forget", Fault::Timeout, After::Works),
        ("forget", Fault::KilledAfterStore, After::Works),
    ] {
        killed(invalidated(), enroll_op, None, Some((op, fault)), after);
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
    for fault in [Fault::Hold, Fault::Timeout, Fault::KilledAfterStore] {
        killed(
            enrolled_stopped(),
            disable_op,
            None,
            Some(("forget", fault)),
            After::Off,
        );
    }
}

/// The vault delete is one journaled operation with the secrets file
/// (design 0013, "Forgetting an item"). Killed before its journal, the
/// vault, the entry and its key stay, and the staged file goes at the next
/// start; killed after it, the next start finishes the delete: no vault, no
/// entry, and the key forgotten.
#[test]
fn a_vault_delete_killed_at_each_step() {
    for (hook, after) in [
        ("before-delete-stage", After::Works),
        ("before-delete-journal", After::Works),
        ("before-delete-journal-rename", After::Works),
        ("after-delete-journal", After::Deleted),
        ("after-delete-secrets", After::Deleted),
        ("after-delete-vault", After::Deleted),
        ("after-delete-done", After::Deleted),
        ("before-forgotten", After::Deleted),
        ("after-forgotten", After::Deleted),
    ] {
        killed(enrolled_stopped(), delete_op, Some(hook), None, after);
    }
    for fault in [Fault::Hold, Fault::Timeout, Fault::KilledAfterStore] {
        killed(
            enrolled_stopped(),
            delete_op,
            None,
            Some(("forget", fault)),
            After::Deleted,
        );
    }
}

/// A secrets file that can't be read, or a write of the delete's that fails
/// before its commit, refuses the delete: the vault, the entry and its key
/// stay as they were (review of #381).
#[test]
fn a_vault_delete_refused_while_the_secrets_file_cant_change() {
    let mut main = enrolled();
    let vault = std::fs::read(main.vault_path()).unwrap();
    let secrets = std::fs::read(main.secrets_path()).unwrap();
    let password = json!({ "password_b64": b64(PASSWORD) });
    std::fs::write(main.secrets_path(), b"{\"version\":1").unwrap();
    let refused = main.call("vault.delete", password.clone());
    assert_eq!(error_code(&refused), "storage", "{refused}");
    assert_eq!(
        refused["error"]["data"],
        json!({ "kind": "malformed", "file": "secrets" })
    );
    assert_eq!(std::fs::read(main.vault_path()).unwrap(), vault);
    assert_eq!(
        std::fs::read(main.secrets_path()).unwrap(),
        b"{\"version\":1"
    );
    main.no_delete_left();
    assert_eq!(main.keychain.calls, ["create"]);
    assert_eq!(main.keychain.items.len(), 1);
    // The staged write fails, or the journal's after the claim: refused
    // the same way, nothing changed.
    std::fs::write(main.secrets_path(), &secrets).unwrap();
    for step in ["delete-stage", "delete-journal"] {
        main.start(&[("FREEDOM_CORED_TEST_SECRETS_FAIL", step)]);
        let refused = main.call("vault.delete", password.clone());
        assert_eq!(error_code(&refused), "storage", "{step}: {refused}");
        assert_eq!(refused["error"]["data"]["file"], "secrets", "{step}");
        assert_eq!(std::fs::read(main.vault_path()).unwrap(), vault, "{step}");
        assert_eq!(
            std::fs::read(main.secrets_path()).unwrap(),
            secrets,
            "{step}"
        );
        main.no_delete_left();
        let unlock = main.call("quick_unlock.unlock", json!({}));
        assert!(unlock["result"].is_object(), "{step}: {unlock}");
    }
    assert!(!main.keychain.calls.iter().any(|c| c == "forget"));
    assert_eq!(main.keychain.items.len(), 1);
    // Once the file can change, the delete goes through.
    main.start(&[]);
    let deleted = main.call("vault.delete", password);
    assert_eq!(deleted["result"], json!({}), "{deleted}");
    main.drained();
    assert!(!main.vault_path().exists());
    assert!(!main.enrolled());
    assert!(main.keychain.items.is_empty());
    main.no_delete_left();
}

/// The install fails after the journal committed: the delete has happened,
/// and answers so, not durable yet. Nothing reads the vault it removes:
/// the journal is finished first, in the same start.
#[test]
fn a_vault_delete_whose_install_fails_after_its_commit() {
    let mut main = enrolled_stopped();
    main.start(&[("FREEDOM_CORED_TEST_SECRETS_FAIL", "delete-install")]);
    let deleted = delete_op(&mut main).unwrap();
    assert_eq!(deleted["result"], json!({ "durable": false }), "{deleted}");
    let unlock = main.call("vault.unlock", json!({ "password_b64": b64(PASSWORD) }));
    assert_eq!(error_code(&unlock), "no_vault", "{unlock}");
    main.drained();
    assert!(!main.vault_path().exists());
    assert!(!main.enrolled());
    assert!(main.keychain.items.is_empty());
    main.no_delete_left();
    main.only_the_key_in_use();
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

/// The start's settling write, killed before it and after it: the file
/// names every item the keychain holds at each point, nothing is forgotten
/// before the hello, and the next start settles what is left and drains
/// it. Two states need settling: a `pending` item a helper killed after the
/// OS stored it left, and an entry naming no vault.
#[test]
fn the_start_killed_before_and_after_its_settling_write() {
    let pending = || {
        let mut main = with_vault();
        main.start(&[]);
        main.keychain
            .faults
            .insert("create", Fault::KilledAfterStore);
        let refused = main.enroll();
        assert_eq!(error_code(&refused), "key_store_unavailable", "{refused}");
        main.stop();
        main.keychain.faults.clear();
        main
    };
    let no_vault = || {
        let main = enrolled_stopped();
        std::fs::remove_file(main.vault_path()).unwrap();
        main
    };
    let states: [(&str, &dyn Fn() -> Main); 2] = [("pending", &pending), ("no vault", &no_vault)];
    for (state, make) in states {
        for hook in ["before-startup", "after-startup"] {
            let mut main = make();
            assert_eq!(main.keychain.items.len(), 1, "{state}");
            let before = main.file();
            assert!(before.forget_list().is_empty(), "{state}");
            let code = main.start_killed(&[("FREEDOM_CORED_TEST_SECRETS_CRASH", hook)]);
            assert_eq!(code, 99, "{state} {hook}");
            main.file_names_the_keychain();
            assert_eq!(main.keychain.items.len(), 1, "{state} {hook}");
            assert!(main.keychain.calls.iter().all(|c| c != "forget"));
            let file = main.file();
            if hook == "before-startup" {
                assert_eq!(file, before, "{state}: the file as it was");
            } else {
                // Settled: the item moved into `forget`, the entry gone.
                assert_eq!(file.forget_list().len(), 1, "{state}: {:?}", file.items());
                assert!(!main.enrolled(), "{state}");
            }
            // The next start settles anything left, and drains.
            main.start(&[]);
            main.file_names_the_keychain();
            main.drained();
            main.only_the_key_in_use();
            assert!(main.file().items().is_empty(), "{state} {hook}");
            assert!(main.keychain.items.is_empty(), "{state} {hook}");
            assert!(!main.enrolled());
        }
    }
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

// ----- Create and import with the credential, and the re-wrap (PRF-1c-2)

/// BIP-39's own test phrase: a vault the import's tests tell apart from
/// `ABANDON`'s.
const LEGAL: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const NEW_PASSWORD: &str = "testpass2";

fn sha256_hex(bytes: &[u8]) -> String {
    <sha2::Sha256 as sha2::Digest>::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl Main {
    fn vault_digest(&self) -> Option<String> {
        std::fs::read(self.vault_path())
            .ok()
            .map(|v| sha256_hex(&v))
    }

    /// The file's entries, each with the vault digest it is bound to.
    fn entries(&self) -> BTreeMap<String, String> {
        let file = self.file();
        file.entry_names()
            .map(|name| {
                let bound = file.binding(name).unwrap().get("vault_fingerprint");
                (name.as_str().to_owned(), bound.unwrap_or("").to_owned())
            })
            .collect()
    }

    /// Sends the request `text` as it is, and serves the keychain until
    /// the response to `id`.
    fn raw_call(&mut self, id: u64, text: &str) -> Value {
        self.core().send_raw(&common::raw_frame(1, text.as_bytes()));
        let until = Instant::now() + Duration::from_secs(60);
        while Instant::now() < until {
            if let Ok(Some(message)) = self.serve_one(Duration::from_millis(200))
                && message["type"] == "response"
                && message["id"] == id
            {
                return message;
            }
        }
        panic!("no response to {id}");
    }

    fn create_quick(&mut self) -> Value {
        create_quick_op(self).expect("the core exited during vault.create")
    }

    fn change(&mut self, current: &str, new: &str) -> Value {
        self.call(
            "vault.change_password",
            json!({ "password_b64": b64(current), "new_password_b64": b64(new) }),
        )
    }

    fn verifies(&mut self, password: &str) -> bool {
        let verified = self.call(
            "vault.verify_password",
            json!({ "password_b64": b64(password) }),
        );
        verified["result"] == json!({})
    }

    /// What a re-wrap leaves holds, in this start or after a restart
    /// (`settled`): the vault is the old one (`old_vault`, `None` for no
    /// vault) or the new one, as `pair` says, and has exactly one
    /// credential (none for no vault, or for [`Pair::OldOff`]), which quick
    /// unlock opens. `tidy`: no other entry is left either.
    fn pair_holds(
        &mut self,
        old_vault: Option<&[u8]>,
        new_password: &str,
        pair: Pair,
        tidy: bool,
        label: &str,
    ) {
        let vault = std::fs::read(self.vault_path()).ok();
        match pair {
            Pair::Old | Pair::OldOff => {
                assert_eq!(vault.as_deref(), old_vault, "{label}: the old vault");
            }
            Pair::New => assert!(
                vault.is_some() && vault.as_deref() != old_vault,
                "{label}: the new vault"
            ),
        }
        let digest = vault.as_deref().map(sha256_hex);
        let entries = self.entries();
        let bound = entries
            .values()
            .filter(|d| Some(d.as_str()) == digest.as_deref())
            .count();
        let credential = vault.is_some() && pair != Pair::OldOff;
        assert_eq!(bound, usize::from(credential), "{label}: {entries:?}");
        if tidy {
            assert_eq!(entries.len(), bound, "{label}: {entries:?}");
        }
        assert_eq!(self.status()["enabled"], credential, "{label}");
        let unlock = self.call("quick_unlock.unlock", json!({}));
        if credential {
            assert!(unlock["result"].is_object(), "{label}: {unlock}");
        } else if vault.is_none() {
            assert_eq!(error_code(&unlock), "no_vault", "{label}: {unlock}");
        } else {
            assert_eq!(error_code(&unlock), "not_found", "{label}: {unlock}");
        }
        if vault.is_some() {
            let password = if pair == Pair::New {
                new_password
            } else {
                PASSWORD
            };
            assert!(self.verifies(password), "{label}: the pair's password");
        }
    }
}

/// What a re-wrap leaves, after the crash or the failure, a restart and
/// the drain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Pair {
    /// The vault as it was (none, for a create), with its credential.
    Old,
    /// The vault as it was, without its credential: its key was dead
    /// (`invalidated`), so the replace's `pending` write took the entry
    /// off, as enroll's does.
    OldOff,
    /// The new vault, with its own credential.
    New,
}

fn create_quick_op(main: &mut Main) -> Option<Value> {
    main.try_call(
        "chrome",
        "vault.create",
        json!({ "password_b64": b64(PASSWORD), "words": 12, "quick_unlock": true }),
    )
}

fn import_quick_op(main: &mut Main) -> Option<Value> {
    main.try_call(
        "chrome",
        "vault.import",
        json!({
            "password_b64": b64(NEW_PASSWORD), "mnemonic_b64": b64(LEGAL),
            "overwrite": true, "quick_unlock": true,
        }),
    )
}

fn change_op(main: &mut Main) -> Option<Value> {
    main.try_call(
        "chrome",
        "vault.change_password",
        json!({ "password_b64": b64(PASSWORD), "new_password_b64": b64(NEW_PASSWORD) }),
    )
}

/// Runs a re-wrap `op` on `main` with the crash hook `hook` (exit 99), the
/// writes `fails` failing, or main failing one key-store op with `fault`.
/// Checks the pair in that start (when it answered), and again after a
/// restart and the drain. Returns the answer, if there was one.
fn rewrapped(
    mut main: Main,
    op: fn(&mut Main) -> Option<Value>,
    new_password: &str,
    (hook, fails, fault): (Option<&str>, Option<&str>, Option<(&'static str, Fault)>),
    pair: Pair,
) -> Option<Value> {
    let label = format!("{hook:?} {fails:?} {fault:?}");
    let old_vault = std::fs::read(main.vault_path()).ok();
    let mut env = Vec::new();
    if let Some(step) = hook {
        env.push(("FREEDOM_CORED_TEST_SECRETS_CRASH", step));
    }
    if let Some(steps) = fails {
        env.push(("FREEDOM_CORED_TEST_SECRETS_FAIL", steps));
    }
    main.start(&env);
    if let Some((op, fault)) = fault {
        main.keychain.faults.insert(op, fault);
    }
    let response = op(&mut main);
    if hook.is_some() {
        assert!(response.is_none(), "{label}: answered {response:?}");
        assert_eq!(
            main.core().exit_code(Duration::from_secs(10)),
            99,
            "{label}"
        );
        main.core = None;
    } else {
        let answer = response.clone().expect("an answer");
        assert_eq!(
            answer["result"].is_object(),
            pair == Pair::New,
            "{label}: {answer}"
        );
        main.keychain.faults.clear();
        // A failed fold or rollback leaves an entry naming no vault, for
        // the next start.
        let tidy = !fails.is_some_and(|f| f.contains("fold") || f.contains("rollback"));
        main.pair_holds(old_vault.as_deref(), new_password, pair, tidy, &label);
        main.stop();
    }
    main.file_names_the_keychain();
    main.keychain.faults.clear();
    main.start(&[]);
    main.file_names_the_keychain();
    main.drained();
    main.only_the_key_in_use();
    main.no_delete_left();
    main.pair_holds(old_vault.as_deref(), new_password, pair, true, &label);
    response
}

fn hook(step: &str) -> (Option<&str>, Option<&str>, Option<(&'static str, Fault)>) {
    (Some(step), None, None)
}

fn fails(steps: &str) -> (Option<&str>, Option<&str>, Option<(&'static str, Fault)>) {
    (None, Some(steps), None)
}

fn fault(
    op: &'static str,
    fault: Fault,
) -> (
    Option<&'static str>,
    Option<&'static str>,
    Option<(&'static str, Fault)>,
) {
    (None, None, Some((op, fault)))
}

#[test]
fn create_and_import_with_quick_unlock() {
    let mut main = Main::new();
    main.start(&[]);
    let created = main.create_quick();
    assert!(created["result"]["mnemonic_b64"].is_string(), "{created}");
    assert_eq!(main.keychain.calls, ["create"]);
    // The entry is `quick-unlock`, bound to the new vault's digest.
    let digest = main.vault_digest().unwrap();
    assert_eq!(
        main.entries(),
        BTreeMap::from([("quick-unlock".to_owned(), digest.clone())])
    );
    assert_eq!(
        main.status(),
        json!({ "enabled": true, "policy": "unattended", "available": true })
    );
    // Unlocked (create unlocks), then locked.
    main.events();
    for _ in 0..2 {
        let unlocked = main.call("quick_unlock.unlock", json!({}));
        assert!(unlocked["result"]["addresses"].is_object(), "{unlocked}");
        assert_eq!(main.events(), ["vault.unlocked"]);
        main.call("vault.lock", json!({}));
        main.events();
    }
    // An import over it, with the credential: the old vault's entry is
    // replaced under the same key, bound to the new vault.
    let imported = import_quick_op(&mut main).unwrap();
    assert!(imported["result"]["addresses"].is_object(), "{imported}");
    assert_eq!(main.keychain.calls, ["create", "open", "open", "open"]);
    let digest = main.vault_digest().unwrap();
    assert_eq!(
        main.entries(),
        BTreeMap::from([("quick-unlock".to_owned(), digest)])
    );
    assert_eq!(main.keychain.items.len(), 1);
    let unlocked = main.call("quick_unlock.unlock", json!({}));
    assert!(unlocked["result"].is_object(), "{unlocked}");
    assert!(main.verifies(NEW_PASSWORD));
    // Without the credential, as before: the secrets file isn't touched,
    // and the new vault has no quick unlock.
    let secrets = std::fs::read(main.secrets_path()).unwrap();
    let imported = main.call(
        "vault.import",
        json!({ "password_b64": b64(PASSWORD), "mnemonic_b64": b64(ABANDON), "overwrite": true, "quick_unlock": false }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    assert_eq!(std::fs::read(main.secrets_path()).unwrap(), secrets);
    assert_eq!(main.status()["enabled"], false);
    // `quick_unlock` is a boolean or absent, and given once.
    for bad in [json!("yes"), json!(1), Value::Null] {
        let refused = main.call(
            "vault.import",
            json!({ "password_b64": b64(PASSWORD), "mnemonic_b64": b64(ABANDON), "overwrite": true, "quick_unlock": bad }),
        );
        assert_eq!(error_code(&refused), "invalid_argument", "{bad}: {refused}");
    }
    let twice = format!(
        r#"{{"type":"request","id":900,"method":"vault.import","params":{{"password_b64":"{}","mnemonic_b64":"{}","overwrite":true,"quick_unlock":false,"quick_unlock":true}},"context":{{"caller":"chrome"}}}}"#,
        b64(PASSWORD),
        b64(ABANDON),
    );
    let refused = main.raw_call(900, &twice);
    assert_eq!(error_code(&refused), "invalid_argument", "{refused}");
    assert_eq!(std::fs::read(main.secrets_path()).unwrap(), secrets);
    // A create with the credential into an empty profile, with no key made
    // yet: `pending`, `create`, then the entry.
    let mut main = Main::new();
    main.start(&[]);
    let imported = main.call(
        "vault.import",
        json!({ "password_b64": b64(PASSWORD), "mnemonic_b64": b64(ABANDON), "quick_unlock": true }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    assert_eq!(main.keychain.calls, ["create"]);
    assert_eq!(main.status()["enabled"], true);
}

#[test]
fn quick_unlock_on_create_needs_a_key_store() {
    if cfg!(target_os = "macos") {
        return;
    }
    let mut main = Main::new();
    main.start_with(&[]);
    for (method, params) in [
        (
            "vault.create",
            json!({ "password_b64": b64(PASSWORD), "words": 12, "quick_unlock": true }),
        ),
        (
            "vault.import",
            json!({ "password_b64": b64(PASSWORD), "mnemonic_b64": b64(ABANDON), "quick_unlock": true }),
        ),
    ] {
        let refused = main.call(method, params);
        assert_eq!(error_code(&refused), "key_store_unavailable", "{refused}");
        assert_eq!(refused["error"]["data"]["reason"], "unsupported");
        assert!(!main.vault_path().exists(), "{method}");
        assert!(!main.secrets_path().exists(), "{method}");
    }
    // The parity checks come first: a weak password is `weak_password`.
    let refused = main.call(
        "vault.create",
        json!({ "password_b64": b64("short"), "words": 12, "quick_unlock": true }),
    );
    assert_eq!(error_code(&refused), "weak_password", "{refused}");
    assert!(main.keychain.calls.is_empty());
}

/// Design 0013, "The re-wrap": a password change keeps quick unlock, under
/// the same key, bound to the new vault. Unlock works unlocked and locked,
/// the old entry never opens the new vault, and enroll takes the new
/// password, not the old.
#[test]
fn a_password_change_rewraps_quick_unlock() {
    let mut main = enrolled();
    let old_secrets = std::fs::read(main.secrets_path()).unwrap();
    let old_digest = main.vault_digest().unwrap();
    let calls = main.keychain.calls.len();
    // A wrong current password: refused before anything, and throttled as
    // `vault.unlock` is.
    let wrong = main.change("wrongpass", NEW_PASSWORD);
    assert_eq!(error_code(&wrong), "incorrect_password", "{wrong}");
    assert_eq!(main.keychain.calls.len(), calls);
    assert_eq!(std::fs::read(main.secrets_path()).unwrap(), old_secrets);
    let changed = main.change(PASSWORD, NEW_PASSWORD);
    assert_eq!(changed["result"], json!({}), "{changed}");
    // One open, no new key: the entry is `quick-unlock`, bound to the new
    // vault.
    assert_eq!(&main.keychain.calls[calls..], ["open"]);
    assert_eq!(main.keychain.items.len(), 1);
    let new_digest = main.vault_digest().unwrap();
    assert_ne!(new_digest, old_digest);
    assert_eq!(
        main.entries(),
        BTreeMap::from([("quick-unlock".to_owned(), new_digest.clone())])
    );
    assert_eq!(main.status()["enabled"], true);
    // Unlocked (the change kept the lock state), then locked.
    main.events();
    for _ in 0..2 {
        let unlocked = main.call("quick_unlock.unlock", json!({}));
        assert!(unlocked["result"]["addresses"].is_object(), "{unlocked}");
        assert_eq!(main.events(), ["vault.unlocked"]);
        main.call("vault.lock", json!({}));
        main.events();
    }
    let phrase = main.call("quick_unlock.export_mnemonic", json!({}));
    let phrase = STANDARD
        .decode(phrase["result"]["mnemonic_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(phrase, ABANDON.as_bytes());
    // The old entry never opens the new vault: as it was, it is bound to
    // the old vault, and quick unlock is off for this one; bound to this
    // one by hand, its associated data still names the old vault.
    let new_secrets = std::fs::read(main.secrets_path()).unwrap();
    std::fs::write(main.secrets_path(), &old_secrets).unwrap();
    let unlock = main.call("quick_unlock.unlock", json!({}));
    assert_eq!(error_code(&unlock), "not_found", "{unlock}");
    let moved = String::from_utf8(old_secrets.clone())
        .unwrap()
        .replace(&old_digest, &new_digest);
    assert!(SecretsFile::parse(moved.as_bytes()).is_ok());
    std::fs::write(main.secrets_path(), moved).unwrap();
    let unlock = main.call("quick_unlock.unlock", json!({}));
    assert_eq!(error_code(&unlock), "key_store_unavailable", "{unlock}");
    assert_eq!(
        unlock["error"]["data"]["reason"], "entry_refused",
        "{unlock}"
    );
    std::fs::write(main.secrets_path(), &new_secrets).unwrap();
    // Enroll checks against the new vault.
    let wrong = main.shell(
        "quick_unlock.enroll",
        json!({ "password_b64": b64(PASSWORD) }),
    );
    assert_eq!(error_code(&wrong), "incorrect_password", "{wrong}");
    let enrolled = main.shell(
        "quick_unlock.enroll",
        json!({ "password_b64": b64(NEW_PASSWORD) }),
    );
    assert_eq!(enrolled["result"], json!({}), "{enrolled}");
    // And it survives a restart.
    main.start(&[]);
    let unlocked = main.call("quick_unlock.unlock", json!({}));
    assert!(unlocked["result"].is_object(), "{unlocked}");
    // A change without quick unlock touches neither the secrets file nor
    // the key store.
    assert_eq!(
        main.call("quick_unlock.disable", json!({}))["result"],
        json!({})
    );
    main.drained();
    let secrets = std::fs::read(main.secrets_path()).unwrap();
    let calls = main.keychain.calls.len();
    let changed = main.change(NEW_PASSWORD, PASSWORD);
    assert_eq!(changed["result"], json!({}), "{changed}");
    assert_eq!(std::fs::read(main.secrets_path()).unwrap(), secrets);
    assert_eq!(main.keychain.calls.len(), calls);
}

#[test]
fn a_create_with_quick_unlock_killed_or_failed_at_each_step() {
    for (step, pair) in [
        ("before-stage-pending", Pair::Old),
        ("after-stage-pending", Pair::Old),
        ("before-stage", Pair::Old),
        ("after-stage", Pair::Old),
        ("before-vault-rename", Pair::Old),
        ("after-vault-rename", Pair::New),
    ] {
        rewrapped(Main::new(), create_quick_op, PASSWORD, hook(step), pair);
    }
    for (steps, code) in [
        ("stage-pending", "storage"),
        ("stage", "storage"),
        ("vault-claim", "deadline"),
        ("vault-rename", "storage"),
        ("vault-rename,rollback", "storage"),
    ] {
        let answer = rewrapped(
            Main::new(),
            create_quick_op,
            PASSWORD,
            fails(steps),
            Pair::Old,
        )
        .unwrap();
        assert_eq!(error_code(&answer), code, "{steps}: {answer}");
    }
    // The rollback's own write, killed before and after it.
    for step in ["before-rollback", "after-rollback"] {
        rewrapped(
            Main::new(),
            create_quick_op,
            PASSWORD,
            (Some(step), Some("vault-rename"), None),
            Pair::Old,
        );
    }
    for failure in [Fault::Hold, Fault::Timeout, Fault::KilledAfterStore] {
        let answer = rewrapped(
            Main::new(),
            create_quick_op,
            PASSWORD,
            fault("create", failure),
            Pair::Old,
        )
        .unwrap();
        assert_eq!(answer["error"]["data"]["reason"], "timeout", "{answer}");
    }
}

/// The two re-wraps over a vault with quick unlock: the new vault's
/// credential is `quick-unlock.next` until the fold.
fn rewrap_matrix(op: fn(&mut Main) -> Option<Value>) {
    for (step, pair) in [
        ("before-stage", Pair::Old),
        ("after-stage", Pair::Old),
        ("before-vault-rename", Pair::Old),
        ("after-vault-rename", Pair::New),
        ("before-fold", Pair::New),
        ("after-fold", Pair::New),
    ] {
        rewrapped(enrolled_stopped(), op, NEW_PASSWORD, hook(step), pair);
    }
    for (steps, pair) in [
        ("stage", Pair::Old),
        ("vault-claim", Pair::Old),
        ("vault-rename", Pair::Old),
        ("vault-rename,rollback", Pair::Old),
        ("fold", Pair::New),
    ] {
        rewrapped(enrolled_stopped(), op, NEW_PASSWORD, fails(steps), pair);
    }
    for step in ["before-rollback", "after-rollback"] {
        rewrapped(
            enrolled_stopped(),
            op,
            NEW_PASSWORD,
            (Some(step), Some("vault-rename"), None),
            Pair::Old,
        );
    }
    for failure in [Fault::Hold, Fault::Timeout] {
        let answer = rewrapped(
            enrolled_stopped(),
            op,
            NEW_PASSWORD,
            fault("open", failure),
            Pair::Old,
        )
        .unwrap();
        assert_eq!(answer["error"]["data"]["reason"], "timeout", "{answer}");
    }
}

#[test]
fn an_import_with_quick_unlock_killed_or_failed_at_each_step() {
    rewrap_matrix(import_quick_op);
}

#[test]
fn a_password_change_killed_or_failed_at_each_step() {
    rewrap_matrix(change_op);
}

/// The key under the old vault's credential is dead: the re-wrap replaces
/// it as enroll does. The `pending` write takes the dead entry off and
/// moves the key into `forget`; `create`; the commit writes the new
/// vault's entry under the new key; then the vault. Dead two ways: its item
/// gone (removed by hand), or still there but `invalidated` until the
/// restart, so that the old item's own `forget` runs.
#[test]
fn a_rewrap_over_a_dead_key_killed_at_each_step() {
    let gone = || {
        let mut main = enrolled_stopped();
        main.keychain.items.clear();
        main
    };
    let invalidated = || {
        let mut main = enrolled_stopped();
        main.keychain.faults.insert("open", Fault::Invalidated);
        main
    };
    for (step, gone_pair, invalidated_pair) in [
        // Before the `pending` write the old entry stands: dead, its item
        // gone; whole again once the fault clears.
        ("before-stage-pending", Pair::OldOff, Pair::Old),
        ("after-stage-pending", Pair::OldOff, Pair::OldOff),
        ("before-stage", Pair::OldOff, Pair::OldOff),
        ("after-stage", Pair::OldOff, Pair::OldOff),
        ("before-vault-rename", Pair::OldOff, Pair::OldOff),
        ("after-vault-rename", Pair::New, Pair::New),
    ] {
        if step != "before-stage-pending" {
            rewrapped(gone(), change_op, NEW_PASSWORD, hook(step), gone_pair);
        }
        rewrapped(
            invalidated(),
            change_op,
            NEW_PASSWORD,
            hook(step),
            invalidated_pair,
        );
    }
    for failure in [Fault::Hold, Fault::KilledAfterStore] {
        rewrapped(
            invalidated(),
            change_op,
            NEW_PASSWORD,
            fault("create", failure),
            Pair::OldOff,
        );
    }
    // Uninterrupted: a new key, and the old one forgotten.
    rewrapped(
        gone(),
        change_op,
        NEW_PASSWORD,
        (None, None, None),
        Pair::New,
    );
    rewrapped(
        invalidated(),
        import_quick_op,
        NEW_PASSWORD,
        (None, None, None),
        Pair::New,
    );
}

/// The credential under its second name: a re-wrap killed between its
/// vault's rename and its fold leaves the new vault's entry as
/// `quick-unlock.next`, and the start removes the old vault's. Quick unlock
/// works from it; enroll, a change, disable and the vault delete each take
/// it in their one write.
#[test]
fn the_credential_under_its_second_name() {
    let next = || {
        let mut main = enrolled_stopped();
        main.start(&[("FREEDOM_CORED_TEST_SECRETS_CRASH", "before-fold")]);
        assert!(change_op(&mut main).is_none());
        assert_eq!(main.core().exit_code(Duration::from_secs(10)), 99);
        main.core = None;
        main.start(&[]);
        let digest = main.vault_digest().unwrap();
        assert_eq!(
            main.entries(),
            BTreeMap::from([("quick-unlock.next".to_owned(), digest)])
        );
        assert_eq!(
            main.status(),
            json!({ "enabled": true, "policy": "unattended", "available": true })
        );
        let unlocked = main.call("quick_unlock.unlock", json!({}));
        assert!(unlocked["result"].is_object(), "{unlocked}");
        main
    };
    let only_main = |main: &Main| {
        let digest = main.vault_digest().unwrap();
        assert_eq!(
            main.entries(),
            BTreeMap::from([("quick-unlock".to_owned(), digest)])
        );
    };
    // Enroll: `quick-unlock`, and `quick-unlock.next` gone, in one write.
    let mut main = next();
    let enrolled = main.shell(
        "quick_unlock.enroll",
        json!({ "password_b64": b64(NEW_PASSWORD) }),
    );
    assert_eq!(enrolled["result"], json!({}), "{enrolled}");
    only_main(&main);
    assert_eq!(main.keychain.items.len(), 1);
    // A change from it: staged as `quick-unlock`, and the old vault's
    // `quick-unlock.next` gone after the commit.
    let mut main = next();
    let changed = main.change(NEW_PASSWORD, PASSWORD);
    assert_eq!(changed["result"], json!({}), "{changed}");
    only_main(&main);
    let unlocked = main.call("quick_unlock.unlock", json!({}));
    assert!(unlocked["result"].is_object(), "{unlocked}");
    assert!(main.verifies(PASSWORD));
    // Killed between that change's staged write and its rename: the old
    // vault keeps `quick-unlock.next`, its credential.
    let mut main = next();
    main.start(&[("FREEDOM_CORED_TEST_SECRETS_CRASH", "after-stage")]);
    assert!(
        main.try_call(
            "chrome",
            "vault.change_password",
            json!({ "password_b64": b64(NEW_PASSWORD), "new_password_b64": b64(PASSWORD) }),
        )
        .is_none()
    );
    assert_eq!(main.core().exit_code(Duration::from_secs(10)), 99);
    main.core = None;
    main.start(&[]);
    let digest = main.vault_digest().unwrap();
    assert_eq!(
        main.entries(),
        BTreeMap::from([("quick-unlock.next".to_owned(), digest)])
    );
    assert!(main.verifies(NEW_PASSWORD));
    let unlocked = main.call("quick_unlock.unlock", json!({}));
    assert!(unlocked["result"].is_object(), "{unlocked}");
    // Disable: gone, and its key forgotten.
    let mut main = next();
    assert_eq!(
        main.call("quick_unlock.disable", json!({}))["result"],
        json!({})
    );
    assert!(main.entries().is_empty());
    main.drained();
    assert!(main.keychain.items.is_empty());
    // The vault delete: in its journal, and its key forgotten.
    let mut main = next();
    let deleted = main.call("vault.delete", json!({ "password_b64": b64(NEW_PASSWORD) }));
    assert_eq!(deleted["result"], json!({}), "{deleted}");
    assert!(main.entries().is_empty());
    assert!(!main.vault_path().exists());
    main.drained();
    assert!(main.keychain.items.is_empty());
    main.no_delete_left();
}

/// A re-wrap that can't keep its promise is refused with nothing changed:
/// a secrets file that doesn't read, a full `forget` list, a password too
/// long for quick unlock. Without quick unlock, nothing of this applies.
#[test]
fn a_rewrap_refused_with_nothing_changed() {
    let mut main = enrolled();
    let vault = std::fs::read(main.vault_path()).unwrap();
    let secrets = std::fs::read(main.secrets_path()).unwrap();
    // A malformed secrets file: the change can't tell whether the vault
    // has a credential, and is refused.
    std::fs::write(main.secrets_path(), b"{\"version\":1").unwrap();
    let refused = main.change(PASSWORD, NEW_PASSWORD);
    assert_eq!(error_code(&refused), "storage", "{refused}");
    assert_eq!(
        refused["error"]["data"],
        json!({ "kind": "malformed", "file": "secrets" })
    );
    assert_eq!(std::fs::read(main.vault_path()).unwrap(), vault);
    let refused = main.call(
        "vault.import",
        json!({ "password_b64": b64(NEW_PASSWORD), "mnemonic_b64": b64(LEGAL), "overwrite": true, "quick_unlock": true }),
    );
    assert_eq!(error_code(&refused), "storage", "{refused}");
    assert_eq!(std::fs::read(main.vault_path()).unwrap(), vault);
    std::fs::write(main.secrets_path(), &secrets).unwrap();
    // A new password past the 1 KiB quick unlock holds: refused while
    // quick unlock is on.
    let long = "p".repeat(1025);
    let too_long = "The password is too long for quick unlock";
    let calls = main.keychain.calls.len();
    let refused = main.change(PASSWORD, &long);
    assert_eq!(error_code(&refused), "invalid_argument", "{refused}");
    assert_eq!(refused["error"]["message"], too_long, "{refused}");
    assert_eq!(std::fs::read(main.vault_path()).unwrap(), vault);
    assert_eq!(std::fs::read(main.secrets_path()).unwrap(), secrets);
    assert_eq!(main.keychain.calls.len(), calls);
    // And for a create, before any key is made for it.
    let mut fresh = Main::new();
    fresh.start(&[]);
    let refused = fresh.call(
        "vault.create",
        json!({ "password_b64": b64(&long), "words": 12, "quick_unlock": true }),
    );
    assert_eq!(refused["error"]["message"], too_long, "{refused}");
    assert!(fresh.keychain.calls.is_empty());
    assert!(!fresh.vault_path().exists());
    assert!(!fresh.secrets_path().exists());
    // A full `forget` list, its forgets failing: a create with quick unlock
    // is refused before its vault, as the `create` it needs.
    let mut main = Main::new();
    main.start(&[]);
    main.import();
    main.keychain.faults.insert("forget", Fault::Timeout);
    for _ in 0..4 {
        assert_eq!(main.enroll()["result"], json!({}));
        assert_eq!(
            main.call("quick_unlock.disable", json!({}))["result"],
            json!({})
        );
    }
    let deleted = main.call("vault.delete", json!({ "password_b64": b64(PASSWORD) }));
    assert_eq!(deleted["result"], json!({}), "{deleted}");
    let before = std::fs::read(main.secrets_path()).unwrap();
    let refused = main.create_quick();
    assert_eq!(error_code(&refused), "key_store_unavailable", "{refused}");
    assert_eq!(refused["error"]["data"]["reason"], "forget_backlog");
    assert!(!main.vault_path().exists());
    assert_eq!(std::fs::read(main.secrets_path()).unwrap(), before);
    // Once a forget works, so does the create.
    main.keychain.faults.clear();
    let created = main.create_quick();
    assert!(created["result"].is_object(), "{created}");
    main.drained();
    main.only_the_key_in_use();
    assert_eq!(main.status()["enabled"], true);
}

// ---- PRF-5c-2: the vault and its metadata, one write (design 0013) ----

const META: &str = "vault-meta.json";
const JOURNAL: &str = "vault-meta-journal.json";
const CORRUPT: &str = "vault-meta-journal.json.corrupt";
const STAGED: [&str; 2] = [
    "identity-vault.json.freedom-new",
    "vault-meta.json.freedom-new",
];
const WRITE_FAIL: &str = "FREEDOM_CORED_TEST_GRANT_WRITE_FAIL";
/// Metadata main wrote for the vault before (with `addresses`, so an
/// unlock leaves it).
const OLD_META: &str = "{\n  \"userKnowsPassword\": true,\n  \"createdAt\": \"2026-01-01T00:00:00.000Z\",\n  \"addresses\": {\n    \"userWallet\": \"0x01\",\n    \"beeWallet\": \"0x02\"\n  }\n}";
/// Metadata from before `afterUnlock`'s migration: no `addresses`.
const BARE_META: &str =
    "{\n  \"userKnowsPassword\": true,\n  \"createdAt\": \"2026-01-01T00:00:00.000Z\"\n}";

/// The journaled operations: create (with and without quick unlock, no
/// vault before) and import over a vault with metadata (with quick unlock
/// over an enrolled vault, and without).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MetaOp {
    Create,
    CreateQuick,
    Import,
    ImportQuick,
}

impl MetaOp {
    const ALL: [MetaOp; 4] = [
        MetaOp::Create,
        MetaOp::CreateQuick,
        MetaOp::Import,
        MetaOp::ImportQuick,
    ];

    fn quick(self) -> bool {
        matches!(self, MetaOp::CreateQuick | MetaOp::ImportQuick)
    }

    fn import(self) -> bool {
        matches!(self, MetaOp::Import | MetaOp::ImportQuick)
    }

    /// A stopped `main` with the op's state before: no vault for a create;
    /// the `abandon` vault with main's metadata for an import, enrolled for
    /// quick unlock's.
    fn before(self) -> Main {
        let mut main = if self == MetaOp::ImportQuick {
            enrolled_stopped()
        } else {
            Main::new()
        };
        if self == MetaOp::Import {
            main.start(&[]);
            main.import();
            main.stop();
        }
        if self.import() {
            std::fs::write(main.data.join(META), OLD_META).unwrap();
        }
        main.moved = true;
        main
    }

    fn params(self, knows: Option<bool>) -> Value {
        let mut params = if self.import() {
            json!({ "password_b64": b64(NEW_PASSWORD), "mnemonic_b64": b64(LEGAL), "overwrite": true })
        } else {
            json!({ "password_b64": b64(NEW_PASSWORD), "words": 12 })
        };
        if self.quick() {
            params["quick_unlock"] = json!(true);
        }
        if let Some(knows) = knows {
            params["user_knows_password"] = json!(knows);
        }
        params
    }

    fn method(self) -> &'static str {
        if self.import() {
            "vault.import"
        } else {
            "vault.create"
        }
    }

    fn run(self, main: &mut Main) -> Option<Value> {
        main.try_call("chrome", self.method(), self.params(Some(false)))
    }

    /// `vault.reconcile` for the op, `before` the vault's digest before it.
    fn reconcile(self, main: &mut Main, before: Option<&str>) -> Value {
        let mut params = json!({
            "op": if self.import() { "import" } else { "create" },
            "fingerprint_before": before,
            "password_b64": b64(NEW_PASSWORD),
        });
        if self.import() {
            params["mnemonic_b64"] = json!(b64(LEGAL));
        }
        main.shell("vault.reconcile", params)
    }
}

impl Main {
    fn read(&self, name: &str) -> Option<Vec<u8>> {
        std::fs::read(self.data.join(name)).ok()
    }

    /// No journal, no staged file.
    fn journal_gone(&self, label: &str) {
        for name in [JOURNAL].iter().chain(STAGED.iter()) {
            assert!(!self.data.join(name).exists(), "{label}: {name} is left");
        }
    }

    /// The pair after a crash or a failure: the old vault with its old
    /// metadata, or the new vault with its metadata (whose addresses are
    /// the new vault's, `userKnowsPassword` false). With quick unlock, the
    /// vault on disk has exactly its own credential, and quick unlock opens
    /// it.
    fn meta_pair_holds(
        &mut self,
        old: &(Option<Vec<u8>>, Option<Vec<u8>>),
        new: bool,
        quick: bool,
        label: &str,
    ) {
        let vault = self.read("identity-vault.json");
        let meta = self.read(META);
        if !new {
            assert_eq!(vault, old.0, "{label}: the old vault");
            assert_eq!(meta, old.1, "{label}: the old metadata");
        } else {
            assert!(vault.is_some() && vault != old.0, "{label}: the new vault");
            let meta: Value = serde_json::from_slice(&meta.expect("metadata")).unwrap();
            assert_eq!(meta["userKnowsPassword"], false, "{label}: {meta}");
            let unlocked = self.call("vault.unlock", json!({ "password_b64": b64(NEW_PASSWORD) }));
            let user = unlocked["result"]["addresses"]["user_wallet"].clone();
            assert!(user.is_string(), "{label}: {unlocked}");
            assert_eq!(meta["addresses"]["userWallet"], user, "{label}: {meta}");
            self.call("vault.lock", json!({}));
        }
        let digest = vault.as_deref().map(sha256_hex);
        let entries = self.entries();
        let bound = entries
            .values()
            .filter(|d| Some(d.as_str()) == digest.as_deref())
            .count();
        // The old vault keeps its own credential (an enrolled import's).
        let credential = if new { quick } else { !entries.is_empty() };
        assert_eq!(bound, usize::from(credential), "{label}: {entries:?}");
        assert_eq!(entries.len(), bound, "{label}: {entries:?}");
        if credential {
            let unlock = self.call("quick_unlock.unlock", json!({}));
            assert!(unlock["result"].is_object(), "{label}: {unlock}");
            self.call("vault.lock", json!({}));
        }
    }
}

/// The journal's own flush failing: nothing is renamed until the journal's
/// name is durable, in the write or in recovery. The old pair stays, and
/// both staged files are there for the journal.
fn nothing_renamed(main: &Main, old: &(Option<Vec<u8>>, Option<Vec<u8>>), label: &str) {
    assert_eq!(
        main.read("identity-vault.json"),
        old.0,
        "{label}: the vault"
    );
    assert_eq!(main.read(META), old.1, "{label}: the metadata");
    for name in STAGED {
        assert!(main.data.join(name).exists(), "{label}: {name}");
    }
}

fn hook_file(main: &Main, steps: &[&str]) -> PathBuf {
    let path = main.data.parent().unwrap().join("write-fail");
    let text: Vec<String> = steps
        .iter()
        .map(|s| format!("vault_meta_journal:{s}"))
        .collect();
    std::fs::write(&path, text.join("\n")).unwrap();
    path
}

#[test]
fn the_vault_and_its_metadata_killed_at_each_step() {
    for op in MetaOp::ALL {
        for (step, new) in [
            ("before-meta-stage", false),
            ("before-meta-journal", false),
            ("before-meta-journal-rename", false),
            ("after-meta-journal", true),
            ("after-meta-install-vault", true),
            ("after-meta-install-meta", true),
            ("after-meta-done", true),
        ] {
            let label = format!("{op:?} {step}");
            let mut main = op.before();
            let old = (main.read("identity-vault.json"), main.read(META));
            main.start(&[("FREEDOM_CORED_TEST_SECRETS_CRASH", step)]);
            assert!(op.run(&mut main).is_none(), "{label}: answered");
            assert_eq!(
                main.core().exit_code(Duration::from_secs(10)),
                99,
                "{label}"
            );
            main.core = None;
            if step == "after-meta-install-vault" {
                // The vault is installed first: an older build sees the new
                // vault with the old metadata, as today's flow can leave.
                assert_ne!(main.read("identity-vault.json"), old.0, "{label}");
                assert_eq!(
                    main.read(META),
                    old.1,
                    "{label}: the metadata after the vault"
                );
            }
            main.start(&[]);
            main.journal_gone(&label);
            assert!(!main.data.join(CORRUPT).exists(), "{label}");
            main.drained();
            main.meta_pair_holds(&old, new, op.quick(), &label);
        }
    }
}

#[test]
fn a_failure_before_the_commit_changes_nothing() {
    for op in [MetaOp::CreateQuick, MetaOp::ImportQuick, MetaOp::Import] {
        for (steps, code) in [
            ("meta-stage", "storage"),
            ("vault-claim", "deadline"),
            ("meta-journal", "storage"),
        ] {
            let label = format!("{op:?} {steps}");
            let mut main = op.before();
            let old = (main.read("identity-vault.json"), main.read(META));
            main.start(&[("FREEDOM_CORED_TEST_SECRETS_FAIL", steps)]);
            let answer = op.run(&mut main).unwrap();
            assert_eq!(error_code(&answer), code, "{label}: {answer}");
            main.journal_gone(&label);
            main.meta_pair_holds(&old, false, op.quick(), &label);
            main.start(&[]);
            main.drained();
            main.meta_pair_holds(&old, false, op.quick(), &label);
        }
    }
}

#[test]
fn a_returned_failure_after_the_commit_answers_the_committed_result() {
    for op in MetaOp::ALL {
        for step in [
            "journal-flush",
            "vault-rename",
            "vault-flush",
            "meta-rename",
            "meta-flush",
            "unlink",
        ] {
            let label = format!("{op:?} {step}");
            let mut main = op.before();
            let before = main.vault_digest();
            let old = (main.read("identity-vault.json"), main.read(META));
            let unflushed = step == "journal-flush";
            let hook = hook_file(&main, &[step]);
            let env = [(WRITE_FAIL, hook.to_str().unwrap())];
            main.start(&env);
            let answer = op.run(&mut main).unwrap();
            assert_eq!(answer["result"]["durable"], false, "{label}: {answer}");
            assert!(
                answer["result"]["addresses"].is_object(),
                "{label}: {answer}"
            );
            assert_eq!(
                answer["result"]["mnemonic_b64"].is_string(),
                !op.import(),
                "{label}"
            );
            assert!(
                main.data.join(JOURNAL).exists(),
                "{label}: the journal stays"
            );
            if unflushed {
                nothing_renamed(&main, &old, &label);
            }
            // While the hook holds: storage, and reconcile's `pending`.
            let listed = main.call("accounts.list", json!({}));
            assert_eq!(error_code(&listed), "storage", "{label}: {listed}");
            let verified = main.call(
                "vault.verify_password",
                json!({ "password_b64": b64(NEW_PASSWORD) }),
            );
            assert_eq!(error_code(&verified), "storage", "{label}: {verified}");
            let reconciled = op.reconcile(&mut main, before.as_deref());
            assert_eq!(
                reconciled["result"]["status"], "committed",
                "{label}: {reconciled}"
            );
            assert_eq!(
                reconciled["result"]["meta"], "pending",
                "{label}: {reconciled}"
            );
            if unflushed {
                nothing_renamed(&main, &old, &label);
            }
            // A restart keeps the journal and the staged credential.
            main.start(&env);
            assert!(main.data.join(JOURNAL).exists(), "{label}: after a restart");
            if unflushed {
                nothing_renamed(&main, &old, &label);
            }
            if op.quick() {
                let journal: Value = serde_json::from_slice(&main.read(JOURNAL).unwrap()).unwrap();
                let new = journal["files"][0]["sha256"].as_str().unwrap().to_owned();
                assert!(
                    main.entries().values().any(|d| *d == new),
                    "{label}: {:?}",
                    main.entries()
                );
            }
            // Cleared: the next read finishes the install.
            std::fs::write(&hook, "").unwrap();
            let listed = main.call("accounts.list", json!({}));
            assert!(listed["result"]["wallets"].is_array(), "{label}: {listed}");
            main.journal_gone(&label);
            let reconciled = op.reconcile(&mut main, before.as_deref());
            assert_eq!(
                reconciled["result"]["meta"], "written",
                "{label}: {reconciled}"
            );
            let entries = main.entries();
            let digest = main.vault_digest().unwrap();
            let expected: BTreeMap<String, String> = match op {
                MetaOp::CreateQuick => [("quick-unlock".to_owned(), digest)].into(),
                MetaOp::ImportQuick => [("quick-unlock.next".to_owned(), digest)].into(),
                _ => BTreeMap::new(),
            };
            assert_eq!(entries, expected, "{label}");
            // The snapshot taken while the journal was pending is the
            // start's: a fresh start reads the pair.
            main.start(&[]);
            main.meta_pair_holds(&(None, None), true, op.quick(), &label);
        }
    }
}

#[test]
fn the_journals_own_flush() {
    // Failing once: tried again, and the write finishes durable.
    for op in [MetaOp::CreateQuick, MetaOp::Import] {
        let label = format!("{op:?} once");
        let mut main = op.before();
        let old = (main.read("identity-vault.json"), main.read(META));
        main.start(&[("FREEDOM_CORED_TEST_SECRETS_FAIL", "meta-journal-flush")]);
        let answer = op.run(&mut main).unwrap();
        assert!(answer["result"].is_object(), "{label}: {answer}");
        assert!(
            answer["result"].get("durable").is_none(),
            "{label}: {answer}"
        );
        main.journal_gone(&label);
        main.meta_pair_holds(&old, true, op.quick(), &label);
    }
    // Held, with a crash hook past the vault's install: it never fires, as
    // nothing is renamed before the journal's name is durable. With that
    // name lost, as power loss could lose it, the old pair stays.
    for op in [MetaOp::CreateQuick, MetaOp::ImportQuick] {
        let label = format!("{op:?} held");
        let mut main = op.before();
        let old = (main.read("identity-vault.json"), main.read(META));
        let hook = hook_file(&main, &["journal-flush"]);
        main.start(&[
            (WRITE_FAIL, hook.to_str().unwrap()),
            (
                "FREEDOM_CORED_TEST_SECRETS_CRASH",
                "after-meta-install-vault",
            ),
        ]);
        let answer = op.run(&mut main).expect("answered, not killed");
        assert_eq!(answer["result"]["durable"], false, "{label}: {answer}");
        nothing_renamed(&main, &old, &label);
        main.stop();
        std::fs::remove_file(main.data.join(JOURNAL)).unwrap();
        main.start(&[]);
        main.journal_gone(&label);
        assert!(!main.data.join(CORRUPT).exists(), "{label}");
        main.drained();
        main.meta_pair_holds(&old, false, op.quick(), &label);
    }
}

/// Design 0013, "The delete's journal stays separate": an older core, which
/// doesn't read a metadata record, committed a delete of the vault it still
/// showed. The delete finishes first: while it can't, the record isn't
/// touched; then the record, whose vault is no longer its `before`, is set
/// aside, and the deleted vault stays deleted.
#[test]
fn a_vault_delete_journal_finishes_before_a_metadata_record() {
    let mut main = enrolled_stopped();
    std::fs::write(main.data.join(META), OLD_META).unwrap();
    main.moved = true;
    let old_vault = main.read("identity-vault.json").unwrap();
    // An import over the enrolled vault, killed after its commit.
    main.start(&[("FREEDOM_CORED_TEST_SECRETS_CRASH", "after-meta-journal")]);
    assert!(MetaOp::Import.run(&mut main).is_none());
    assert_eq!(main.core().exit_code(Duration::from_secs(10)), 99);
    main.core = None;
    // The older core's delete, committed and killed before its install.
    let staged = main
        .file()
        .remove(&fc_keystore::EntryName::new("quick-unlock").unwrap())
        .unwrap()
        .text();
    std::fs::write(main.data.join("secrets.json.freedom-new"), &staged).unwrap();
    let record = json!({ "op": "vault.delete", "files": [
        { "target": "secrets.json", "staged": "secrets.json.freedom-new",
          "sha256": sha256_hex(staged.as_bytes()) },
        { "target": "identity-vault.json", "sha256": sha256_hex(&old_vault), "remove": true },
    ]});
    std::fs::write(
        main.data.join("vault-delete-journal.json"),
        record.to_string(),
    )
    .unwrap();
    // The delete's install held failing.
    let hook = main.data.parent().unwrap().join("write-fail");
    std::fs::write(&hook, "delete_journal:install").unwrap();
    main.start(&[(WRITE_FAIL, hook.to_str().unwrap())]);
    let old = (Some(old_vault.clone()), Some(OLD_META.as_bytes().to_vec()));
    let held = |main: &Main, label: &str| {
        nothing_renamed(main, &old, label);
        assert!(main.data.join(JOURNAL).exists(), "{label}");
        assert!(
            main.data.join("vault-delete-journal.json").exists(),
            "{label}"
        );
    };
    held(&main, "at start");
    let listed = main.call("accounts.list", json!({}));
    assert_eq!(error_code(&listed), "storage", "{listed}");
    let verified = main.call(
        "vault.verify_password",
        json!({ "password_b64": b64(NEW_PASSWORD) }),
    );
    assert_eq!(error_code(&verified), "storage", "{verified}");
    // Nor does reconcile answer from the staged vault: once the delete
    // finishes, the record is set aside and that vault never installed.
    let before = sha256_hex(&old_vault);
    let reconciled = MetaOp::Import.reconcile(&mut main, Some(&before));
    assert_eq!(error_code(&reconciled), "storage", "{reconciled}");
    held(&main, "while the delete can't finish");
    // Cleared: the delete finishes, then the record is set aside (a vault
    // job's recovery; `accounts.*` would normalize the metadata).
    std::fs::write(&hook, "").unwrap();
    let verified = main.call(
        "vault.verify_password",
        json!({ "password_b64": b64(NEW_PASSWORD) }),
    );
    assert_ne!(error_code(&verified), "storage", "{verified}");
    main.no_delete_left();
    main.journal_gone("after the delete");
    assert!(main.data.join(CORRUPT).exists());
    assert!(
        main.read("identity-vault.json").is_none(),
        "the vault deleted"
    );
    assert_eq!(main.read(META).unwrap(), OLD_META.as_bytes());
    assert!(main.entries().is_empty(), "{:?}", main.entries());
    let reconciled = MetaOp::Import.reconcile(&mut main, Some(&before));
    assert_eq!(
        reconciled["result"]["status"], "not_committed",
        "{reconciled}"
    );
    main.start(&[]);
    assert!(
        main.read("identity-vault.json").is_none(),
        "after a restart"
    );
}

/// `meta` is a committed create's or import's: a password change and a
/// delete answer none, `vault_meta` moved.
/// An import with quick unlock over an enrolled vault, its vault's rename
/// failing after the commit (`vault-rename`, still held): the core serving,
/// the journal pending. The hook file, the vault's digest before, the old
/// pair, the journaled vault's digest, and the entries the write left (the
/// old vault's `quick-unlock` and the new one's `quick-unlock.next`).
struct PendingImport {
    main: Main,
    hook: PathBuf,
    before: Option<String>,
    old: (Option<Vec<u8>>, Option<Vec<u8>>),
    new: String,
    entries: BTreeMap<String, String>,
}

fn pending_import_quick() -> PendingImport {
    let op = MetaOp::ImportQuick;
    let mut main = op.before();
    let before = main.vault_digest();
    let old = (main.read("identity-vault.json"), main.read(META));
    let hook = hook_file(&main, &["vault-rename"]);
    main.start(&[(WRITE_FAIL, hook.to_str().unwrap())]);
    let answer = op.run(&mut main).unwrap();
    assert_eq!(answer["result"]["durable"], false, "{answer}");
    let journal: Value = serde_json::from_slice(&main.read(JOURNAL).unwrap()).unwrap();
    let new = journal["files"][0]["sha256"].as_str().unwrap().to_owned();
    let entries = main.entries();
    let expected: BTreeMap<String, String> = [
        ("quick-unlock".to_owned(), before.clone().unwrap()),
        ("quick-unlock.next".to_owned(), new.clone()),
    ]
    .into();
    assert_eq!(entries, expected);
    PendingImport {
        main,
        hook,
        before,
        old,
        new,
        entries,
    }
}

impl PendingImport {
    /// Nothing installed, and the secrets file as the write left it.
    fn untouched(&self, label: &str) {
        nothing_renamed(&self.main, &self.old, label);
        assert!(
            self.main.data.join(JOURNAL).exists(),
            "{label}: the journal"
        );
        assert_eq!(self.main.entries(), self.entries, "{label}: the entries");
    }

    /// Finished by recovery under the secrets file's lock: the new pair, and
    /// the journal-finish write left only the new vault's credential.
    fn finished(&self, label: &str) {
        self.main.journal_gone(label);
        assert_eq!(
            self.main.vault_digest().as_deref(),
            Some(self.new.as_str()),
            "{label}: the new vault"
        );
        let expected: BTreeMap<String, String> =
            [("quick-unlock.next".to_owned(), self.new.clone())].into();
        assert_eq!(self.main.entries(), expected, "{label}: the entries");
    }
}

/// Recovery under the secrets file's lock failing once (`settle-once`, a
/// transient failure): the request answers `storage`, or for reconcile the
/// journaled vault's `pending`, and nothing is installed, although a retry
/// outside the lock would now succeed. No read settles the journal itself.
/// The next request's recovery finishes it, under the lock, with the
/// journal-finish write: the replaced vault's `quick-unlock` leaves.
/// `quick_unlock.disable` doesn't run either, so its own load can't finish
/// it in the same request.
#[test]
fn a_failed_locked_recovery_answers_storage() {
    for first in [
        "vault.verify_password",
        "vault.reconcile",
        "quick_unlock.disable",
    ] {
        let label = first;
        let mut pending = pending_import_quick();
        std::fs::write(&pending.hook, "vault_meta_journal:settle-once").unwrap();
        let main = &mut pending.main;
        match first {
            "vault.verify_password" => {
                let verified = main.call(first, json!({ "password_b64": b64(NEW_PASSWORD) }));
                assert_eq!(error_code(&verified), "storage", "{label}: {verified}");
            }
            "vault.reconcile" => {
                let before = pending.before.clone();
                let reconciled = MetaOp::ImportQuick.reconcile(main, before.as_deref());
                assert_eq!(
                    reconciled["result"]["status"], "committed",
                    "{label}: {reconciled}"
                );
                assert_eq!(
                    reconciled["result"]["meta"], "pending",
                    "{label}: {reconciled}"
                );
            }
            _ => {
                let disabled = disable_op(main).unwrap();
                assert_eq!(error_code(&disabled), "storage", "{label}: {disabled}");
            }
        }
        pending.untouched(label);
        let main = &mut pending.main;
        let verified = main.call(
            "vault.verify_password",
            json!({ "password_b64": b64(NEW_PASSWORD) }),
        );
        assert_eq!(verified["result"], json!({}), "{label}: {verified}");
        pending.finished(label);
    }
}

/// A password check the throttle refused (#82) runs recovery first too,
/// under the secrets file's lock: failing once, it answers `storage` with
/// nothing installed; the next one's recovery finishes the journal, with
/// the journal-finish write, and the answer is `throttled`.
#[test]
fn a_throttled_check_recovers_first() {
    let mut pending = pending_import_quick();
    let label = "precheck";
    // Five wrong passwords through reconcile, which decides from the
    // journaled vault while recovery fails (`vault-rename` held): the
    // throttle is on for the next second.
    for _ in 0..5 {
        let params = json!({
            "op": "import",
            "fingerprint_before": pending.before,
            "password_b64": b64("wrongpass"),
            "mnemonic_b64": b64(LEGAL),
        });
        let wrong = pending.main.shell("vault.reconcile", params);
        assert_eq!(wrong["result"]["status"], "not_committed", "{wrong}");
    }
    std::fs::write(&pending.hook, "vault_meta_journal:settle-once").unwrap();
    let verify = json!({ "password_b64": b64(NEW_PASSWORD) });
    let refused = pending.main.call("vault.verify_password", verify.clone());
    assert_eq!(error_code(&refused), "storage", "{label}: {refused}");
    pending.untouched(label);
    let throttled = pending.main.call("vault.verify_password", verify);
    assert_eq!(error_code(&throttled), "throttled", "{label}: {throttled}");
    pending.finished(label);
}

#[test]
fn reconcile_answers_meta_only_for_create_and_import() {
    let mut main = MetaOp::Import.before();
    main.start(&[]);
    let before = main.vault_digest();
    let changed = main.change(PASSWORD, NEW_PASSWORD);
    assert!(changed["result"].is_object(), "{changed}");
    let reconciled = main.shell(
        "vault.reconcile",
        json!({ "op": "change_password", "fingerprint_before": before,
                "password_b64": b64(NEW_PASSWORD) }),
    );
    assert_eq!(reconciled["result"]["status"], "committed", "{reconciled}");
    assert!(reconciled["result"].get("meta").is_none(), "{reconciled}");
    let before = main.vault_digest();
    let deleted = main.call("vault.delete", json!({ "password_b64": b64(NEW_PASSWORD) }));
    assert!(deleted["result"].is_object(), "{deleted}");
    let reconciled = main.shell(
        "vault.reconcile",
        json!({ "op": "delete", "fingerprint_before": before,
                "password_b64": b64(NEW_PASSWORD) }),
    );
    assert_eq!(reconciled["result"]["status"], "committed", "{reconciled}");
    assert!(reconciled["result"].get("meta").is_none(), "{reconciled}");
}

/// A staged file swapped before its rename is never installed (the
/// install's identity check): the write is pending, and recovery, finding
/// a staged file without its digest, sets the record aside.
#[test]
fn a_staged_file_swapped_before_its_rename_is_never_installed() {
    let mut main = MetaOp::Import.before();
    let old = (main.read("identity-vault.json"), main.read(META));
    let foreign = main.data.parent().unwrap().join("foreign");
    std::fs::write(&foreign, b"{\"not\":\"the vault\"}").unwrap();
    let swap = format!("renaming={}", foreign.display());
    main.start(&[("FREEDOM_CORED_TEST_SWAP", swap.as_str())]);
    let answer = MetaOp::Import.run(&mut main).unwrap();
    assert_eq!(answer["result"]["durable"], false, "{answer}");
    assert_eq!(main.read("identity-vault.json"), old.0, "not installed");
    main.start(&[]);
    assert!(main.data.join(CORRUPT).exists(), "set aside");
    main.journal_gone("swapped");
    main.meta_pair_holds(&old, false, false, "swapped");
}

#[test]
fn the_finish_flush_failing_after_the_unlink() {
    let mut main = MetaOp::Create.before();
    let hook = hook_file(&main, &["finish-flush"]);
    main.start(&[(WRITE_FAIL, hook.to_str().unwrap())]);
    let answer = MetaOp::Create.run(&mut main).unwrap();
    assert_eq!(answer["result"]["durable"], false, "{answer}");
    main.journal_gone("finish-flush");
    let reconciled = MetaOp::Create.reconcile(&mut main, None);
    assert_eq!(reconciled["result"]["meta"], "written", "{reconciled}");
    main.stop();
    // The journal back, as a crash before a later flush would leave it.
    let vault = main.read("identity-vault.json").unwrap();
    let meta = main.read(META).unwrap();
    let record = json!({ "op": "vault.create", "quick_unlock": false, "files": [
        { "target": "identity-vault.json", "staged": STAGED[0], "before": null, "sha256": sha256_hex(&vault) },
        { "target": META, "staged": STAGED[1], "before": null, "sha256": sha256_hex(&meta) },
    ]});
    std::fs::write(main.data.join(JOURNAL), record.to_string()).unwrap();
    main.start(&[]);
    main.journal_gone("put back");
    assert_eq!(main.read("identity-vault.json").unwrap(), vault);
    assert_eq!(main.read(META).unwrap(), meta);
}

#[test]
fn a_record_recovery_cant_act_on_is_set_aside() {
    // No writer's record: set aside, nothing else changed.
    let mut main = MetaOp::Import.before();
    let old = (main.read("identity-vault.json"), main.read(META));
    std::fs::write(main.data.join(JOURNAL), b"{\"op\":\"vault.create\"}").unwrap();
    std::fs::write(main.data.join(STAGED[0]), b"x").unwrap();
    main.start(&[]);
    assert!(main.data.join(CORRUPT).exists());
    main.journal_gone("no writer's");
    main.meta_pair_holds(&old, false, false, "no writer's");
    // A Quick Setup vault whose credential an older core removed (killed
    // after the commit, before the install): never installed.
    let mut main = MetaOp::CreateQuick.before();
    main.start(&[("FREEDOM_CORED_TEST_SECRETS_CRASH", "after-meta-journal")]);
    assert!(MetaOp::CreateQuick.run(&mut main).is_none());
    assert_eq!(main.core().exit_code(Duration::from_secs(10)), 99);
    main.core = None;
    let file = main.file();
    let without = file
        .remove(&fc_keystore::EntryName::new("quick-unlock").unwrap())
        .unwrap();
    std::fs::write(main.secrets_path(), without.text()).unwrap();
    main.start(&[]);
    assert!(main.data.join(CORRUPT).exists(), "set aside");
    main.journal_gone("no credential");
    assert!(main.read("identity-vault.json").is_none() && main.read(META).is_none());
    // A target an older build changed after the vault's install: the
    // record set aside, its metadata stays.
    let mut main = MetaOp::Import.before();
    main.start(&[(
        "FREEDOM_CORED_TEST_SECRETS_CRASH",
        "after-meta-install-vault",
    )]);
    assert!(MetaOp::Import.run(&mut main).is_none());
    assert_eq!(main.core().exit_code(Duration::from_secs(10)), 99);
    main.core = None;
    let changed = OLD_META.replace("2026", "2025");
    std::fs::write(main.data.join(META), &changed).unwrap();
    let vault = main.read("identity-vault.json");
    main.start(&[]);
    assert!(main.data.join(CORRUPT).exists(), "set aside");
    main.journal_gone("changed metadata");
    assert_eq!(main.read(META).unwrap(), changed.as_bytes());
    assert_eq!(main.read("identity-vault.json"), vault);
}

#[test]
fn user_knows_password_is_required_once_moved_and_written() {
    for op in [MetaOp::Create, MetaOp::Import] {
        let mut main = op.before();
        main.start(&[]);
        let refused = main.call(op.method(), op.params(None));
        assert_eq!(
            error_code(&refused),
            "invalid_argument",
            "{op:?}: {refused}"
        );
        let wrote = main.call(op.method(), op.params(Some(true)));
        assert!(wrote["result"].is_object(), "{wrote}");
        assert!(wrote["result"].get("durable").is_none(), "{wrote}");
        let meta: Value = serde_json::from_slice(&main.read(META).unwrap()).unwrap();
        assert_eq!(meta["userKnowsPassword"], true, "{meta}");
        // Both installed from files staged with mode 0600.
        #[cfg(unix)]
        for name in ["identity-vault.json", META] {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(main.data.join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{op:?}: {name}");
        }
        // vault.delete leaves the metadata.
        let deleted = main.call("vault.delete", json!({ "password_b64": b64(NEW_PASSWORD) }));
        assert!(deleted["result"].is_object(), "{deleted}");
        assert!(
            main.read(META).is_some(),
            "{op:?}: vault.delete leaves vault-meta.json"
        );
    }
    // Before the move: ignored, and the core writes no metadata.
    let mut main = Main::new();
    main.start(&[]);
    let created = main.call("vault.create", MetaOp::Create.params(None));
    assert!(created["result"].is_object(), "{created}");
    assert!(main.read(META).is_none());
    let reconciled = MetaOp::Create.reconcile(&mut main, None);
    assert!(reconciled["result"].get("meta").is_none(), "{reconciled}");
}

#[test]
fn the_unlock_migrates_missing_addresses_once_moved() {
    let mut main = enrolled_stopped();
    std::fs::write(main.data.join(META), BARE_META).unwrap();
    // Not moved: nothing written.
    main.start(&[]);
    main.call("vault.unlock", json!({ "password_b64": b64(PASSWORD) }));
    assert_eq!(main.read(META).unwrap(), BARE_META.as_bytes());
    // Moved, the write failing: the unlock still answers; the next one
    // migrates.
    main.moved = true;
    let hook = main.data.parent().unwrap().join("meta-fail");
    std::fs::write(&hook, "vault_meta:rename").unwrap();
    main.start(&[(WRITE_FAIL, hook.to_str().unwrap())]);
    let unlocked = main.call("vault.unlock", json!({ "password_b64": b64(PASSWORD) }));
    assert!(unlocked["result"].is_object(), "{unlocked}");
    assert_eq!(main.read(META).unwrap(), BARE_META.as_bytes());
    std::fs::write(&hook, "").unwrap();
    main.call("vault.lock", json!({}));
    let unlocked = main.call("quick_unlock.unlock", json!({}));
    assert!(unlocked["result"].is_object(), "{unlocked}");
    let meta: Value = serde_json::from_slice(&main.read(META).unwrap()).unwrap();
    assert_eq!(
        meta["addresses"]["userWallet"], unlocked["result"]["addresses"]["user_wallet"],
        "{meta}"
    );
    // The exports migrate nothing.
    std::fs::write(main.data.join(META), BARE_META).unwrap();
    main.call("vault.lock", json!({}));
    let exported = main.shell("quick_unlock.export_mnemonic", json!({}));
    assert!(
        exported["result"].is_object() || exported["error"].is_object(),
        "{exported}"
    );
    assert_eq!(main.read(META).unwrap(), BARE_META.as_bytes());
}
