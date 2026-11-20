//! RPC API keys in the core (design 0013, "RPC API keys"; PRF-5h).
//!
//! The test plays main, as `quick_unlock.rs` does: it answers the core's
//! `shell.keystore` requests from a keychain of its own, with
//! `FREEDOM_CORED_TEST_KEYSTORE_BACKEND` offering the Keychain's
//! `Unattended` on every OS; with `none` the core has no key store on any
//! OS, as on Linux and Windows until PRF-7. The keychain outlives each core, so a
//! crash hook's exit and a restart show what each place holds.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use fc_keystore::SecretsFile;
use serde_json::{Value, json};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BACKEND: (&str, &str) = ("FREEDOM_CORED_TEST_KEYSTORE_BACKEND", "macos-keychain");
const DEADLINE: (&str, &str) = ("FREEDOM_CORED_TEST_KEYSTORE_DEADLINE_MS", "1500");
const METHODS: [&str; 4] = [
    "secrets.rpc_api_keys",
    "secrets.rpc_api_key_status",
    "secrets.set_rpc_api_key",
    "secrets.remove_rpc_api_key",
];

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

/// Main's keychain.
#[derive(Default)]
struct Keychain {
    items: BTreeMap<String, [u8; 32]>,
    /// Every op asked, in order.
    calls: Vec<String>,
}

impl Keychain {
    /// Main's answer to one `shell.keystore` request, or none.
    fn answer(&mut self, params: &Value) -> Option<Value> {
        let op = params["op"].as_str().unwrap().to_owned();
        let item = params["item"].as_str().unwrap().to_owned();
        assert_eq!(params["policy"], "unattended", "{params}");
        assert!(params.get("sealed").is_none(), "{params}");
        self.calls.push(op.clone());
        match op.as_str() {
            "create" => {
                assert!(!self.items.contains_key(&item), "a create of a named item");
                let mut key = [0u8; 32];
                getrandom::fill(&mut key).unwrap();
                self.items.insert(item.clone(), key);
                Some(sealed(params, "create", &item, &key))
            }
            "open" => match self.items.get(&item) {
                Some(key) => Some(sealed(params, "open", &item, key)),
                None => Some(json!({ "ok": false, "error": "not_found" })),
            },
            "forget" => Some(match self.items.remove(&item) {
                Some(_) => json!({ "ok": true }),
                None => json!({ "ok": false, "error": "not_found" }),
            }),
            other => panic!("op {other}"),
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
    grant_root: PathBuf,
    keychain: Keychain,
    core: Option<common::Core>,
    next_id: u64,
    /// The hello's `store_moved`.
    moved: Vec<&'static str>,
    /// Whether the core has the test's key store.
    key_store: bool,
}

impl Main {
    fn new(key_store: bool) -> Main {
        let (root, data, locks) = common::dirs();
        let grant_root = root.path().join("userData");
        std::fs::create_dir_all(&grant_root).unwrap();
        Main {
            _root: root,
            data,
            locks,
            grant_root,
            keychain: Keychain::default(),
            core: None,
            next_id: 10,
            moved: vec!["rpc_api_keys"],
            key_store,
        }
    }

    fn env(&self, env: &[(&str, &str)]) -> Vec<(&'static str, String)> {
        let mut all: Vec<(&'static str, String)> = Vec::new();
        if self.key_store {
            all.push((BACKEND.0, BACKEND.1.into()));
            all.push((DEADLINE.0, DEADLINE.1.into()));
        } else {
            // macOS's own Keychain off too.
            all.push((BACKEND.0, "none".into()));
        }
        for (k, v) in env {
            let k: &'static str = Box::leak(k.to_string().into_boxed_str());
            all.push((k, v.to_string()));
        }
        all
    }

    /// Starts a core with `env`, and says hello: its answer.
    fn start(&mut self, env: &[(&str, &str)]) -> Value {
        self.core = None;
        let all = self.env(env);
        let all: Vec<(&str, &str)> = all.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let mut core = common::spawn_env("serve", &self.data, &self.locks, &[], &all);
        assert_eq!(core.grant_root, self.grant_root);
        core.store_moved = self.moved.clone();
        let hello = core.hello();
        self.core = Some(core);
        hello
    }

    fn core(&mut self) -> &mut common::Core {
        self.core.as_mut().expect("a core runs")
    }

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

    /// `method` from `caller`, the keychain served until its response;
    /// `None` if the core exited first (its exit awaited).
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
                Err(()) => {
                    self.core().exit_code(Duration::from_secs(10));
                    self.core = None;
                    return None;
                }
                Ok(Some(message)) if message["type"] == "response" && message["id"] == id => {
                    return Some(message);
                }
                Ok(_) => {}
            }
        }
        panic!("no response to {method}");
    }

    /// `method` from `caller`, its key-store requests held unanswered (a
    /// slow key store) for `hold` after the first, or until its response,
    /// then answered.
    fn call_holding(
        &mut self,
        caller: &str,
        method: &str,
        params: Value,
        hold: Option<Duration>,
    ) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.core().send(&json!({
            "type": "request", "id": id, "method": method, "params": params,
            "context": { "caller": caller },
        }));
        let mut held: Vec<Value> = Vec::new();
        let mut first: Option<Instant> = None;
        let mut answered = false;
        let until = Instant::now() + Duration::from_secs(60);
        while Instant::now() < until {
            if let (Some(hold), Some(first)) = (hold, first)
                && first.elapsed() >= hold
            {
                answered = true;
                for request in std::mem::take(&mut held) {
                    let result = self.keychain.answer(&request["params"]).unwrap();
                    let id = request["id"].as_u64().unwrap();
                    self.core()
                        .send(&json!({ "type": "response", "id": id, "result": result }));
                }
            }
            let message = self
                .core()
                .recv_or_closed(Duration::from_millis(200))
                .expect("the core runs");
            let Some(message) = message else { continue };
            if message["type"] == "request" && message["method"] == "shell.keystore" {
                first.get_or_insert_with(Instant::now);
                held.push(message);
            } else if message["type"] == "response" && message["id"] == id {
                assert!(
                    answered || !held.is_empty(),
                    "nothing asked the key store: {message}"
                );
                for request in held {
                    let result = self.keychain.answer(&request["params"]).unwrap();
                    let id = request["id"].as_u64().unwrap();
                    self.core()
                        .send(&json!({ "type": "response", "id": id, "result": result }));
                }
                return message;
            }
        }
        panic!("no response to {method}");
    }

    fn call(&mut self, caller: &str, method: &str, params: Value) -> Value {
        self.try_call(caller, method, params)
            .unwrap_or_else(|| panic!("the core exited during {method}"))
    }

    fn set(&mut self, id: &str, key: &str) -> Value {
        self.call(
            "chrome",
            "secrets.set_rpc_api_key",
            json!({ "id": id, "api_key": key }),
        )
    }

    fn remove(&mut self, id: &str) -> Value {
        self.call("chrome", "secrets.remove_rpc_api_key", json!({ "id": id }))
    }

    /// The providers `rpc_api_key_status` answers present.
    fn status(&mut self) -> Vec<String> {
        let reply = self.call("chrome", "secrets.rpc_api_key_status", json!({}));
        let providers = reply["result"]["providers"]
            .as_array()
            .unwrap_or_else(|| panic!("{reply}"));
        assert!(!reply.to_string().contains("api_key"), "{reply}");
        providers
            .iter()
            .filter(|p| p["present"] == true)
            .map(|p| p["id"].as_str().unwrap().to_owned())
            .collect()
    }

    /// `secrets.rpc_api_keys`: each provider's key.
    fn keys(&mut self) -> BTreeMap<String, String> {
        let reply = self.call("shell", "secrets.rpc_api_keys", json!({}));
        reply["result"]["keys"]
            .as_array()
            .unwrap_or_else(|| panic!("{reply}"))
            .iter()
            .map(|k| {
                (
                    k["id"].as_str().unwrap().into(),
                    k["api_key"].as_str().unwrap().into(),
                )
            })
            .collect()
    }

    fn file_path(&self) -> PathBuf {
        self.grant_root.join("rpc-api-keys.json")
    }

    fn file(&self) -> Option<Value> {
        std::fs::read(self.file_path())
            .ok()
            .map(|b| serde_json::from_slice(&b).unwrap())
    }

    fn secrets(&self) -> SecretsFile {
        match std::fs::read(self.data.join("secrets.json")) {
            Ok(bytes) => SecretsFile::parse(&bytes).unwrap(),
            Err(_) => SecretsFile::new(),
        }
    }

    /// The RPC-key entries' providers.
    fn entries(&self) -> BTreeSet<String> {
        self.secrets()
            .entry_names()
            .filter_map(|n| n.as_str().strip_prefix("rpc-api-key.").map(str::to_owned))
            .collect()
    }
}

fn code(reply: &Value) -> &str {
    reply["error"]["code"].as_str().unwrap_or("")
}

/// `rpc-api-keys.json` in the reference's text: `JSON.stringify(keys, null,
/// 2)`, each key `{ apiKey, enabled: true, addedAt }`.
fn reference_text(keys: &[(&str, &str)]) -> String {
    let mut map = serde_json::Map::new();
    for (id, key) in keys {
        map.insert(
            (*id).into(),
            json!({ "apiKey": key, "enabled": true, "addedAt": 1_700_000_000_000u64 }),
        );
    }
    serde_json::to_string_pretty(&Value::Object(map)).unwrap()
}

/// The hello's `store_moved`: unknown names refused (and the core exits),
/// a name given twice echoed once, a known name this core doesn't serve
/// not echoed, absent meaning none.
#[test]
fn the_hello_names_the_stores() {
    let mut main = Main::new(false);
    main.moved = vec![
        "vault_meta",
        "intents",
        "payments",
        "safe_pending",
        "rpc_api_keys",
        "rpc_api_keys",
    ];
    let hello = main.start(&[]);
    assert_eq!(
        hello["result"]["store_moved"],
        json!(["vault_meta", "intents", "safe_pending", "rpc_api_keys"]),
        "{hello}"
    );
    main.moved = vec![];
    let hello = main.start(&[]);
    assert_eq!(hello["result"]["store_moved"], json!([]), "{hello}");
    main.moved = vec!["rpc_api_keys", "cookies"];
    let hello = main.start(&[]);
    assert_eq!(code(&hello), "invalid_argument", "{hello}");
    assert_eq!(main.core().exit_code(Duration::from_secs(5)), 76);
}

/// Before the store is named, all four answer `not_moved` (`data.store`)
/// and `rpc-api-keys.json` is never opened: an unreadable one stays where
/// it is. `secrets.rpc_api_keys` is the shell's alone; a page reaches none.
#[test]
fn callers_and_not_moved() {
    let mut main = Main::new(true);
    main.moved = vec!["vault_meta"];
    std::fs::write(main.file_path(), b"not json").unwrap();
    main.start(&[]);
    for method in METHODS {
        let params = json!({ "id": "alchemy", "api_key": "k" });
        for caller in ["chrome", "shell"] {
            let reply = main.call(caller, method, params.clone());
            if caller == "chrome" && method == "secrets.rpc_api_keys" {
                assert_eq!(code(&reply), "forbidden", "{reply}");
            } else {
                assert_eq!(code(&reply), "not_moved", "{method} {caller}: {reply}");
                assert_eq!(reply["error"]["data"]["store"], "rpc_api_keys");
            }
        }
        let reply = main.call("page", method, params);
        assert!(
            matches!(code(&reply), "forbidden" | "unknown_method"),
            "{reply}"
        );
    }
    assert_eq!(std::fs::read(main.file_path()).unwrap(), b"not json");
    assert!(
        !main
            .grant_root
            .join("rpc-api-keys.json.unreadable")
            .exists()
    );
    assert!(main.keychain.calls.is_empty(), "{:?}", main.keychain.calls);
    // Named: the chrome still can't read a key.
    main.moved = vec!["rpc_api_keys"];
    main.start(&[]);
    let reply = main.call("chrome", "secrets.rpc_api_keys", json!({}));
    assert_eq!(code(&reply), "forbidden", "{reply}");
}

/// Without a key store, set and remove write the file in the reference's
/// text, 0600, and nothing moves; the id form and the key's size hold.
#[test]
fn no_key_store_writes_the_file() {
    let mut main = Main::new(false);
    main.start(&[]);
    assert_eq!(main.status(), Vec::<String>::new());
    let reply = main.set("alchemy", "k-alchemy");
    assert_eq!(
        reply["result"]["providers"],
        json!([{ "id": "alchemy", "present": true }]),
        "{reply}"
    );
    let id52 = "a".repeat(52);
    assert!(main.set(&id52, "k52")["result"].is_object());
    for bad in [
        "a".repeat(53),
        "Alchemy".into(),
        String::new(),
        "a b".into(),
        "é".into(),
    ] {
        let reply = main.set(&bad, "k");
        assert_eq!(code(&reply), "invalid_argument", "{bad}: {reply}");
    }
    assert_eq!(
        code(&main.set("drpc", &"x".repeat(1025))),
        "invalid_argument"
    );
    assert!(main.set("drpc", &"x".repeat(1024))["result"].is_object());
    let text = std::fs::read_to_string(main.file_path()).unwrap();
    let file: Value = serde_json::from_str(&text).unwrap();
    let ids: Vec<&String> = file.as_object().unwrap().keys().collect();
    assert_eq!(ids, ["alchemy", id52.as_str(), "drpc"]);
    let added = file["alchemy"]["addedAt"].as_u64().unwrap();
    assert!(text.starts_with(&format!(
        "{{\n  \"alchemy\": {{\n    \"apiKey\": \"k-alchemy\",\n    \"enabled\": true,\n    \"addedAt\": {added}\n  }},"
    )), "{text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(main.file_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert_eq!(main.keys()["alchemy"], "k-alchemy");
    assert!(main.entries().is_empty());
    main.remove("alchemy");
    main.remove(&id52);
    main.remove("drpc");
    assert_eq!(std::fs::read_to_string(main.file_path()).unwrap(), "{}");
    assert!(main.status().is_empty());
}

/// An unreadable file is set aside once moved, and reads as none.
#[test]
fn an_unreadable_file_is_set_aside() {
    for text in ["not json", "[]", "null", "\u{feff}{}"] {
        let mut main = Main::new(false);
        std::fs::write(main.file_path(), text).unwrap();
        main.start(&[]);
        assert!(main.status().is_empty());
        assert!(!main.file_path().exists(), "{text}");
        assert_eq!(
            std::fs::read_to_string(main.grant_root.join("rpc-api-keys.json.unreadable")).unwrap(),
            text
        );
    }
}

/// With a key store: set and remove write entries, not the file; status
/// asks the key store nothing and answers no key; 16 entries beside quick
/// unlock's, a 17th refused and a replace taken.
#[test]
fn set_remove_and_the_bound() {
    let mut main = Main::new(true);
    main.start(&[]);
    let imported = main.call(
        "chrome",
        "vault.import",
        json!({ "password_b64": STANDARD.encode("testpass1"), "mnemonic_b64": STANDARD.encode(ABANDON), "overwrite": true }),
    );
    assert!(imported["result"].is_object(), "{imported}");
    let enrolled = main.call(
        "shell",
        "quick_unlock.enroll",
        json!({ "password_b64": STANDARD.encode("testpass1") }),
    );
    assert!(enrolled["result"].is_object(), "{enrolled}");
    for i in 0..16 {
        let reply = main.set(&format!("p{i:02}"), &format!("k{i}"));
        assert!(reply["result"].is_object(), "{reply}");
    }
    let reply = main.set("p16", "k16");
    assert_eq!(code(&reply), "invalid_argument", "{reply}");
    assert_eq!(reply["error"]["data"]["rule"], "rpc-keys-bound");
    assert!(main.set("p03", "k3-new")["result"].is_object());
    assert_eq!(main.entries().len(), 16);
    assert!(
        main.secrets()
            .entry_names()
            .any(|n| n.as_str() == "quick-unlock")
    );
    assert!(!main.file_path().exists());
    let calls = main.keychain.calls.len();
    assert_eq!(main.status().len(), 16);
    assert_eq!(
        main.keychain.calls.len(),
        calls,
        "status asked the key store"
    );
    let keys = main.keys();
    assert_eq!(keys["p03"], "k3-new");
    assert_eq!(keys["p15"], "k15");
    main.remove("p03");
    assert!(!main.entries().contains("p03"));
    assert!(main.set("p16", "k16")["result"].is_object());
    // A restart: the keys are where they were.
    main.start(&[]);
    assert_eq!(main.keys().len(), 16);
}

/// The migration: the file's keys the secrets file can hold move in one
/// write, then leave the file; an id outside the form and the keys past
/// the bound stay, answered, counted and removable; a set for that id
/// refused.
#[test]
fn the_migration_and_what_stays() {
    let mut main = Main::new(true);
    let mut keys: Vec<(String, String)> = vec![("Bad Id".into(), "k-bad".into())];
    keys.extend((0..20).map(|i| (format!("p{i:02}"), format!("k{i}"))));
    let refs: Vec<(&str, &str)> = keys.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    std::fs::write(main.file_path(), reference_text(&refs)).unwrap();
    main.start(&[]);
    assert_eq!(main.status().len(), 21);
    assert!(main.keychain.calls.is_empty(), "status asked the key store");
    assert!(main.entries().is_empty(), "status migrated");
    let answered = main.keys();
    assert_eq!(answered.len(), 21);
    for (id, key) in &keys {
        assert_eq!(&answered[id], key);
    }
    assert_eq!(main.entries().len(), 16);
    let left = main.file().unwrap();
    let left: Vec<&String> = left.as_object().unwrap().keys().collect();
    assert_eq!(left, ["Bad Id", "p16", "p17", "p18", "p19"]);
    assert_eq!(code(&main.set("Bad Id", "k")), "invalid_argument");
    main.remove("Bad Id");
    main.remove("p16");
    assert_eq!(main.status().len(), 19);
    let left = main.file().unwrap();
    assert_eq!(left.as_object().unwrap().len(), 3);
}

/// A crash at each write step of the migration: the next start resumes,
/// each provider's key answered once and equal to the file's.
#[test]
fn a_migration_killed_at_each_step() {
    let keys = [("alchemy", "k-a"), ("infura", "k-i"), ("drpc", "k-d")];
    for step in [
        "before-rpc-migrate-pending",
        "after-rpc-migrate-pending",
        "before-rpc-migrate",
        "after-rpc-migrate",
        "before-rpc-file",
        "after-rpc-file",
    ] {
        let mut main = Main::new(true);
        std::fs::write(main.file_path(), reference_text(&keys)).unwrap();
        main.start(&[("FREEDOM_CORED_TEST_SECRETS_CRASH", step)]);
        assert!(
            main.try_call("shell", "secrets.rpc_api_keys", json!({}))
                .is_none(),
            "{step}"
        );
        main.start(&[]);
        let answered = main.keys();
        assert_eq!(answered.len(), 3, "{step}");
        for (id, key) in keys {
            assert_eq!(answered[id], key, "{step}");
        }
        assert_eq!(main.entries().len(), 3, "{step}");
        assert!(!main.file_path().exists(), "{step}");
    }
}

/// A replacing set with the old key in the file (put there after this
/// start's migration, as an older build would): a failure before the
/// entry's write leaves the old key answered; a crash after it and before
/// the file's rewrite leaves the old key answered at the next start, and
/// after its migration only the old key, in an entry.
#[test]
fn a_replacing_set_over_the_file() {
    let old = [("alchemy", "k-old")];
    for step in ["rpc-set-pending", "rpc-set"] {
        let mut main = Main::new(true);
        main.start(&[("FREEDOM_CORED_TEST_SECRETS_FAIL", step)]);
        assert!(main.keys().is_empty());
        std::fs::write(main.file_path(), reference_text(&old)).unwrap();
        let reply = main.set("alchemy", "k-new");
        assert!(reply["error"].is_object(), "{step}: {reply}");
        assert_eq!(main.keys()["alchemy"], "k-old", "{step}");
        assert!(main.set("alchemy", "k-new")["result"].is_object(), "{step}");
        assert_eq!(main.keys()["alchemy"], "k-new", "{step}");
        assert!(!main.file_path().exists(), "{step}");
    }
    let mut main = Main::new(true);
    main.start(&[("FREEDOM_CORED_TEST_SECRETS_CRASH", "after-rpc-set")]);
    assert!(main.keys().is_empty());
    std::fs::write(main.file_path(), reference_text(&old)).unwrap();
    let set = json!({ "id": "alchemy", "api_key": "k-new" });
    assert!(
        main.try_call("chrome", "secrets.set_rpc_api_key", set)
            .is_none()
    );
    assert!(main.entries().contains("alchemy"));
    assert!(main.file().is_some());
    main.start(&[]);
    assert_eq!(main.status(), ["alchemy"]);
    assert_eq!(main.keys()["alchemy"], "k-old");
    assert!(!main.file_path().exists());
    assert_eq!(main.entries(), BTreeSet::from(["alchemy".to_owned()]));
    main.start(&[]);
    assert_eq!(main.keys()["alchemy"], "k-old");
}

/// A job abandoned before its commit writes nothing (design 0001's commit
/// claim): a set and the migration riding with it, the key store answering
/// after the request's deadline, answer `deadline`, and neither the secrets
/// file nor `rpc-api-keys.json` changes.
#[test]
fn an_abandoned_set_writes_nothing() {
    let env = [
        ("FREEDOM_CORED_TEST_KDF_DEADLINE_MS", "3000"),
        ("FREEDOM_CORED_TEST_KEYSTORE_DEADLINE_MS", "30000"),
    ];
    let mut main = Main::new(true);
    main.start(&env);
    assert!(main.set("alchemy", "k-a")["result"].is_object());
    // A new start, whose migration has yet to run.
    main.start(&env);
    std::fs::write(main.file_path(), reference_text(&[("drpc", "k-d")])).unwrap();
    let secrets = std::fs::read(main.data.join("secrets.json")).unwrap();
    let file = std::fs::read(main.file_path()).unwrap();
    let set = json!({ "id": "infura", "api_key": "k-i" });
    let reply = main.call_holding("chrome", "secrets.set_rpc_api_key", set.clone(), None);
    assert_eq!(code(&reply), "deadline", "{reply}");
    // Served after the abandoned job's end.
    assert_eq!(main.status(), ["alchemy", "drpc"]);
    assert_eq!(
        std::fs::read(main.data.join("secrets.json")).unwrap(),
        secrets
    );
    assert_eq!(std::fs::read(main.file_path()).unwrap(), file);
    // Answered past the claim time (two thirds into the deadline), before
    // the loop gives up: the claim itself refuses the write.
    let hold = Some(Duration::from_millis(2500));
    let reply = main.call_holding("chrome", "secrets.set_rpc_api_key", set, hold);
    assert_eq!(code(&reply), "deadline", "{reply}");
    assert_eq!(main.status(), ["alchemy", "drpc"]);
    assert_eq!(
        std::fs::read(main.data.join("secrets.json")).unwrap(),
        secrets
    );
    assert_eq!(std::fs::read(main.file_path()).unwrap(), file);
    assert_eq!(main.keys()["drpc"], "k-d");
    assert_eq!(main.entries().len(), 2);
}

/// Where the file's write or removal is the first that changes an answer,
/// it is the commit: a job that reaches it past its claim time answers
/// `deadline` and writes nothing. Without a key store, a set; with one, the
/// remove of the last key (outside the entry form) that empties the file.
#[test]
fn a_job_past_its_claim_time_writes_nothing() {
    let late = [
        ("FREEDOM_CORED_TEST_KDF_DEADLINE_MS", "1500"),
        ("FREEDOM_CORED_TEST_JOB_DELAY_MS", "1200"),
    ];
    let mut main = Main::new(false);
    main.start(&late);
    let reply = main.set("alchemy", "k");
    assert_eq!(code(&reply), "deadline", "{reply}");
    std::thread::sleep(Duration::from_millis(500));
    assert!(!main.file_path().exists());

    let mut main = Main::new(true);
    std::fs::write(main.file_path(), reference_text(&[("Bad Id", "k-bad")])).unwrap();
    main.start(&late);
    // Nothing to move: no write, so no claim.
    assert_eq!(main.keys()["Bad Id"], "k-bad");
    let reply = main.remove("Bad Id");
    assert_eq!(code(&reply), "deadline", "{reply}");
    std::thread::sleep(Duration::from_millis(500));
    assert!(main.file().unwrap().get("Bad Id").is_some());
}

/// The file keeps every key whose entry's write isn't durable (its
/// directory flush failing after the rename).
#[test]
fn a_write_that_isnt_durable_keeps_the_file() {
    // The migration: every key stays in the file too, and the next start
    // moves them again.
    let keys = [("alchemy", "k-a"), ("infura", "k-i")];
    let mut main = Main::new(true);
    std::fs::write(main.file_path(), reference_text(&keys)).unwrap();
    main.start(&[("FREEDOM_CORED_TEST_SECRETS_FAIL", "rpc-migrate-flush")]);
    assert_eq!(main.keys().len(), 2);
    assert_eq!(main.entries().len(), 2);
    assert_eq!(main.file().unwrap().as_object().unwrap().len(), 2);
    main.start(&[]);
    assert_eq!(main.keys()["infura"], "k-i");
    assert!(!main.file_path().exists());

    // A set over a key the file counts is refused, the file's key still
    // answered; then taken.
    let mut main = Main::new(true);
    main.start(&[("FREEDOM_CORED_TEST_SECRETS_FAIL", "rpc-set-flush")]);
    assert!(main.keys().is_empty());
    std::fs::write(main.file_path(), reference_text(&[("alchemy", "k-old")])).unwrap();
    let reply = main.set("alchemy", "k-new");
    assert_eq!(code(&reply), "storage", "{reply}");
    assert_eq!(reply["error"]["data"]["kind"], "not_durable");
    assert_eq!(main.keys()["alchemy"], "k-old");
    assert!(main.file().is_some());
    let reply = main.set("alchemy", "k-new");
    assert!(reply["result"].get("durable").is_none(), "{reply}");
    assert_eq!(main.keys()["alchemy"], "k-new");
    assert!(!main.file_path().exists());

    // Over no key in the file: the result, with `durable: false`.
    let mut main = Main::new(true);
    main.start(&[("FREEDOM_CORED_TEST_SECRETS_FAIL", "rpc-set-flush")]);
    let reply = main.set("infura", "k-i");
    assert_eq!(reply["result"]["durable"], false, "{reply}");
    assert_eq!(main.keys()["infura"], "k-i");

    // Without a key store, the file's own write.
    let mut main = Main::new(false);
    main.start(&[("FREEDOM_CORED_TEST_SECRETS_FAIL", "rpc-file-flush")]);
    let reply = main.set("infura", "k-i");
    assert_eq!(reply["result"]["durable"], false, "{reply}");
    assert_eq!(main.file().unwrap()["infura"]["apiKey"], "k-i");
    let reply = main.set("drpc", "k-d");
    assert!(reply["result"].get("durable").is_none(), "{reply}");
}
