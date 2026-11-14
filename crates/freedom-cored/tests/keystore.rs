//! The key-store helper, `freedom-cored keystore`, and the core's desktop
//! key store over `shell.keystore` (design 0013, PRF-1).
//!
//! - **The helper's contract, on every OS:** a request out of form, or any
//!   byte on stdin, is `bad_request` with no OS call; an OS without a
//!   backend answers `unsupported`; one line, within 4 KiB.
//! - **The core, on every OS:** where this OS offers no backend (or no
//!   policy), nothing is asked of main. On macOS the test plays main: it
//!   answers the core's `shell.keystore` with forged answers (no keychain
//!   touched) for the refusals and the deadline.
//! - **The macOS Keychain,** only where CI made a temporary keychain the
//!   default (`FREEDOM_TEST_KEYCHAIN` names it, and the test checks that
//!   `security default-keychain` is that file before touching anything):
//!   create, open, replace and forget through the helper, `NotFound` after
//!   forget, a helper killed after the store, children refused, and the
//!   core end to end through the real helper with no wrapping key in argv,
//!   stdin or what main relays. Elsewhere these tests return at once: they
//!   never reach the login keychain.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use common::BIN;

const ITEM: &str = "0123456789abcdef0123456789abcdef";

/// What main sees of one helper run.
struct Run {
    line: Option<String>,
    /// Everything on stdout, at most 4 KiB and one byte.
    stdout: Vec<u8>,
    status: Option<i32>,
}

/// Runs the helper as main does: argv, stdin the null device or `stdin`'s
/// bytes, at most 4 KiB and one byte read, killed past `deadline`.
fn helper(args: &[&str], stdin: Option<&[u8]>, env: &[(&str, &str)], deadline: Duration) -> Run {
    let mut command = Command::new(BIN);
    command
        .arg("keystore")
        .args(args)
        .envs(env.iter().copied())
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = {
        let _spawning = common::spawning();
        command.spawn().unwrap()
    };
    if let Some(bytes) = stdin {
        use std::io::Write;
        let mut pipe = child.stdin.take().unwrap();
        // The helper may answer before reading it all.
        let _ = pipe.write_all(bytes);
    }
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = (&mut stdout).take(4097).read_to_end(&mut bytes);
        bytes
    });
    let until = Instant::now() + deadline;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        if Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = reader.join().unwrap();
    let line = std::str::from_utf8(&stdout)
        .ok()
        .and_then(|text| text.strip_suffix('\n'))
        .filter(|line| !line.contains('\n'))
        .map(str::to_owned);
    Run {
        line,
        stdout,
        status,
    }
}

fn ask(args: &[&str]) -> Run {
    helper(args, None, &[], Duration::from_secs(60))
}

fn answer(run: &Run) -> Value {
    assert!(run.stdout.len() <= 4096, "answer over 4 KiB");
    assert_eq!(run.status, Some(0));
    serde_json::from_str(run.line.as_deref().expect("one line")).unwrap()
}

fn reply_key() -> (fc_seal::RecipientKey, String) {
    use base64::Engine as _;
    let pair = fc_seal::RecipientKey::generate(&mut OsRng).unwrap();
    let public = base64::engine::general_purpose::STANDARD.encode(pair.public_key());
    (pair, public)
}

/// The OS's RNG, for the test's own keys.
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

/// What the answer's seal binds, written out here apart from the core's:
/// `freedom-keystore/1`, 0, the op, 0, the item.
fn aad(op: &str, item: &str) -> Vec<u8> {
    [
        b"freedom-keystore/1".as_slice(),
        b"\0",
        op.as_bytes(),
        b"\0",
        item.as_bytes(),
    ]
    .concat()
}

/// The wrapping key a `create` or `open` answer carries.
fn opened(answer: &Value, pair: fc_seal::RecipientKey, op: &str, item: &str) -> [u8; 32] {
    use base64::Engine as _;
    assert_eq!(answer["ok"], true, "{answer}");
    let keys: Vec<&String> = answer.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["ok", "key"]);
    let sealed = base64::engine::general_purpose::STANDARD
        .decode(answer["key"].as_str().unwrap())
        .unwrap();
    assert_eq!(sealed.len(), 80);
    *pair
        .open_with(
            &sealed[..32],
            &sealed[32..],
            b"freedom-keystore/1",
            &aad(op, item),
        )
        .expect("the answer opens under the request's key, op and item")
}

fn spellings(key: &[u8]) -> Vec<String> {
    use base64::Engine as _;
    vec![
        key.iter().map(|b| format!("{b:02x}")).collect(),
        key.iter().map(|b| format!("{b:02X}")).collect(),
        base64::engine::general_purpose::STANDARD.encode(key),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key),
    ]
}

fn holds(haystack: &[u8], key: &[u8]) -> bool {
    let text = String::from_utf8_lossy(haystack);
    haystack.windows(key.len()).any(|w| w == key)
        || spellings(key).iter().any(|s| text.contains(s.as_str()))
}

#[test]
fn requests_out_of_form_are_bad_requests() {
    let (_, reply) = reply_key();
    let low_order = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let cases: Vec<Vec<&str>> = vec![
        vec![],
        vec!["--op", "create", "--policy", "unattended", "--item", ITEM],
        vec![
            "--op",
            "forget",
            "--policy",
            "unattended",
            "--item",
            ITEM,
            "--reply-key",
            &reply,
        ],
        vec![
            "--op",
            "open",
            "--policy",
            "unattended",
            "--item",
            "0123",
            "--reply-key",
            &reply,
        ],
        vec![
            "--op",
            "open",
            "--policy",
            "unattended",
            "--item",
            ITEM,
            "--reply-key",
            low_order,
        ],
        vec![
            "--op",
            "open",
            "--policy",
            "user_presence",
            "--item",
            ITEM,
            "--reply-key",
            &reply,
        ],
        vec![
            "--op",
            "create",
            "--policy",
            "unattended",
            "--item",
            ITEM,
            "--reply-key",
            &reply,
            "--reason",
            "export",
        ],
        vec![
            "--op",
            "open",
            "--policy",
            "unattended",
            "--item",
            ITEM,
            "--item",
            ITEM,
            "--reply-key",
            &reply,
        ],
        vec![
            "--op",
            "open",
            "--policy",
            "unattended",
            "--item",
            ITEM,
            "--reply-key",
            &reply,
            "--key",
            "00",
        ],
    ];
    for case in cases {
        let run = ask(&case);
        assert_eq!(
            answer(&run),
            json!({ "ok": false, "error": "backend", "reason": "bad_request" }),
            "{case:?}"
        );
    }
}

#[test]
fn bytes_on_stdin_are_refused_before_any_os_call() {
    let (_, reply) = reply_key();
    let create = [
        "--op",
        "create",
        "--policy",
        "unattended",
        "--item",
        ITEM,
        "--reply-key",
        &reply,
    ];
    for stdin in [&b"x"[..], &[7u8; 1025][..], &[7u8; 8192][..]] {
        let run = helper(&create, Some(stdin), &[], Duration::from_secs(60));
        assert_eq!(
            answer(&run),
            json!({ "ok": false, "error": "backend", "reason": "bad_request" })
        );
    }
    // An empty pipe is no bytes: on an OS without a backend that reaches
    // `unsupported`, so the refusal above came first.
    if !cfg!(target_os = "macos") {
        let run = helper(&create, Some(b""), &[], Duration::from_secs(60));
        assert_eq!(answer(&run)["reason"], "unsupported");
    }
}

#[test]
fn oses_and_policies_without_a_backend_answer_unsupported() {
    let (_, reply) = reply_key();
    let presence = [
        "--op",
        "open",
        "--policy",
        "user_presence",
        "--item",
        ITEM,
        "--reply-key",
        &reply,
        "--reason",
        "quick_unlock",
    ];
    let unsupported = json!({ "ok": false, "error": "unavailable", "reason": "unsupported" });
    assert_eq!(answer(&ask(&presence)), unsupported);
    if cfg!(target_os = "macos") {
        return;
    }
    for args in [
        vec![
            "--op",
            "create",
            "--policy",
            "unattended",
            "--item",
            ITEM,
            "--reply-key",
            &reply,
        ],
        vec![
            "--op",
            "open",
            "--policy",
            "unattended",
            "--item",
            ITEM,
            "--reply-key",
            &reply,
        ],
        vec!["--op", "forget", "--policy", "unattended", "--item", ITEM],
    ] {
        let run = ask(&args);
        assert_eq!(answer(&run), unsupported, "{args:?}");
        assert_eq!(
            run.line.as_deref(),
            Some(r#"{"ok":false,"error":"unavailable","reason":"unsupported"}"#)
        );
    }
}

// ----- The core over `shell.keystore`

fn serve(env: &[(&str, &str)]) -> (tempfile::TempDir, common::Core) {
    let (root, data, locks) = common::dirs();
    let mut all = vec![("FREEDOM_CORED_TEST_METHODS", "1")];
    all.extend_from_slice(env);
    let mut core = common::spawn_env("serve", &data, &locks, &[], &all);
    core.hello();
    (root, core)
}

/// Sends `test.keystore` with `params` as request `id`.
fn call(core: &mut common::Core, id: u64, params: Value) {
    core.send(&common::shell_request(id, "test.keystore", params));
}

/// The next frame: the core's `shell.keystore` request, or the response to
/// `id`.
enum Next {
    Asks(u64, Value),
    Answer(Value),
}

fn next(core: &mut common::Core, id: u64) -> Next {
    loop {
        let message = core.recv();
        if message["type"] == "request" && message["method"] == "shell.keystore" {
            return Next::Asks(message["id"].as_u64().unwrap(), message["params"].clone());
        }
        if message["type"] == "response" && message["id"] == id {
            return Next::Answer(message["result"].clone());
        }
        assert_eq!(message["type"], "event", "{message}");
    }
}

fn respond(core: &mut common::Core, id: u64, result: Value) {
    core.send(&json!({ "type": "response", "id": id, "result": result }));
}

/// Where this OS has no backend, the core asks main nothing: a create is
/// `unavailable`, and an open of a Keychain key `not_found`.
#[test]
fn without_a_backend_the_core_asks_nothing() {
    let (_root, mut core) = serve(&[]);
    if cfg!(target_os = "macos") {
        // UserPresence isn't offered yet.
        call(
            &mut core,
            2,
            json!({ "op": "create", "policy": "user_presence", "item": ITEM }),
        );
        let Next::Answer(result) = next(&mut core, 2) else {
            panic!("asked main");
        };
        assert_eq!(
            result,
            json!({ "ok": false, "error": "unavailable", "reason": "unsupported" })
        );
        return;
    }
    call(
        &mut core,
        2,
        json!({ "op": "create", "policy": "unattended", "item": ITEM }),
    );
    let Next::Answer(result) = next(&mut core, 2) else {
        panic!("asked main");
    };
    assert_eq!(
        result,
        json!({ "ok": false, "error": "unavailable", "reason": "unsupported" })
    );
    call(
        &mut core,
        3,
        json!({ "op": "open", "policy": "unattended", "item": ITEM }),
    );
    let Next::Answer(result) = next(&mut core, 3) else {
        panic!("asked main");
    };
    assert_eq!(result, json!({ "ok": false, "error": "not_found" }));
    call(
        &mut core,
        4,
        json!({ "op": "forget", "policy": "unattended", "item": ITEM }),
    );
    let Next::Answer(result) = next(&mut core, 4) else {
        panic!("asked main");
    };
    assert_eq!(result, json!({ "ok": true }));
}

/// On macOS the test plays main with forged answers: an answer sealed to
/// another key, a long one, an error, and none within the deadline.
#[cfg(target_os = "macos")]
#[test]
fn the_core_refuses_answers_not_its_own_and_gives_up_in_time() {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let (_root, mut core) = serve(&[("FREEDOM_CORED_TEST_KEYSTORE_DEADLINE_MS", "1500")]);
    let create = json!({ "op": "create", "policy": "unattended", "item": ITEM });
    let mut id = 1;
    let mut ask_core = |core: &mut common::Core, forge: &dyn Fn(&Value) -> Option<Value>| {
        id += 1;
        call(core, id, create.clone());
        let Next::Asks(request, params) = next(core, id) else {
            panic!("didn't ask main");
        };
        assert_eq!(params["op"], "create");
        assert_eq!(params["item"], ITEM);
        if let Some(result) = forge(&params) {
            respond(core, request, result);
        }
        let Next::Answer(result) = next(core, id) else {
            panic!("asked twice");
        };
        (request, result)
    };
    // Sealed to another key.
    let (_, result) = ask_core(&mut core, &|_| {
        let (_, other) = reply_key();
        let other: [u8; 32] = b64.decode(other).unwrap().try_into().unwrap();
        let sealed = fc_seal::seal_with(
            &other,
            &[1; 32],
            b"freedom-keystore/1",
            &aad("create", ITEM),
            &mut OsRng,
        )
        .unwrap();
        Some(
            json!({ "ok": true, "key": b64.encode([sealed.enc.as_slice(), &sealed.ciphertext].concat()) }),
        )
    });
    assert_eq!(
        result,
        json!({ "ok": false, "error": "backend", "reason": "answer_seal" })
    );
    // Sealed to the request's key, but for another op, or another item.
    for (op, item) in [
        ("open", ITEM),
        ("create", "ffffffffffffffffffffffffffffffff"),
    ] {
        let (_, result) = ask_core(&mut core, &|params| {
            let reply: [u8; 32] = b64
                .decode(params["reply_key"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let sealed = fc_seal::seal_with(
                &reply,
                &[1; 32],
                b"freedom-keystore/1",
                &aad(op, item),
                &mut OsRng,
            )
            .unwrap();
            Some(
                json!({ "ok": true, "key": b64.encode([sealed.enc.as_slice(), &sealed.ciphertext].concat()) }),
            )
        });
        assert_eq!(
            result,
            json!({ "ok": false, "error": "backend", "reason": "answer_seal" }),
            "{op} {item}"
        );
    }
    // Over 4 KiB.
    let (_, result) = ask_core(&mut core, &|_| {
        Some(json!({ "ok": true, "pad": "x".repeat(4096) }))
    });
    assert_eq!(
        result,
        json!({ "ok": false, "error": "backend", "reason": "answer_too_long" })
    );
    // Main's timeout answer, as its executor gives it.
    let (_, result) = ask_core(&mut core, &|_| {
        Some(json!({ "ok": false, "error": "unavailable", "reason": "timeout" }))
    });
    assert_eq!(
        result,
        json!({ "ok": false, "error": "unavailable", "reason": "timeout" })
    );
    // No answer within the deadline: unavailable. The late answer that
    // follows is dropped, and the core goes on.
    let started = Instant::now();
    let (late, result) = ask_core(&mut core, &|_| None);
    assert!(started.elapsed() >= Duration::from_millis(1500));
    assert_eq!(
        result,
        json!({ "ok": false, "error": "unavailable", "reason": "timeout" })
    );
    respond(&mut core, late, json!({ "ok": true }));
    let status = core.call(100, "vault.status", json!({}));
    assert!(status.get("result").is_some(), "{status}");
}

// ----- The macOS Keychain, in CI's temporary keychain only

/// Whether CI made a temporary keychain the default. Panics, before any
/// Keychain call, if it names one that isn't the default: then the login
/// keychain would be used.
fn temporary_keychain() -> bool {
    if !cfg!(target_os = "macos") {
        return false;
    }
    let Some(path) = std::env::var_os("FREEDOM_TEST_KEYCHAIN") else {
        return false;
    };
    let path = PathBuf::from(path);
    let shown = Command::new("security")
        .args(["default-keychain", "-d", "user"])
        .output()
        .unwrap();
    assert!(shown.status.success(), "security default-keychain failed");
    let shown = String::from_utf8(shown.stdout).unwrap();
    let shown = PathBuf::from(shown.trim().trim_matches('"'));
    assert!(
        is_the_keychain(&path, &shown),
        "the default keychain is {shown:?}, not the temporary {path:?}"
    );
    true
}

/// A keychain's path in canonical form: the file itself, symlinks and dot
/// segments resolved, when it exists; else its canonical directory joined
/// with its name, since `security` shows a keychain the Keychain stores as
/// `<name>-db` by `<name>`. `None` for a relative path, or one whose
/// directory doesn't exist.
fn canonical_keychain(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return Some(canonical);
    }
    let name = path.file_name()?;
    Some(std::fs::canonicalize(path.parent()?).ok()?.join(name))
}

/// Whether `shown`, the default keychain as `security` shows it, is the
/// keychain `expected` names: once both are canonical, the same complete
/// path, or the complete expected path with `-db` appended. Anything else
/// is refused: the same name in another directory, `-db` anywhere else, a
/// relative path, a path that can't be resolved.
fn is_the_keychain(expected: &Path, shown: &Path) -> bool {
    let (Some(expected), Some(shown)) = (canonical_keychain(expected), canonical_keychain(shown))
    else {
        return false;
    };
    let mut stored = expected.clone().into_os_string();
    stored.push("-db");
    shown == expected || shown == stored
}

/// The guard itself, on every OS: complete canonical paths, `-db` on the
/// expected path only.
#[test]
fn the_keychain_guard_compares_complete_canonical_paths() {
    let root = tempfile::tempdir().unwrap();
    let temp = root.path().join("temp");
    let other = root.path().join("other");
    std::fs::create_dir(&temp).unwrap();
    std::fs::create_dir(&other).unwrap();
    let name = "freedom-keystore-test.keychain";
    let expected = temp.join(name);
    // As the Keychain stores a new keychain: `<name>-db`.
    std::fs::write(temp.join(format!("{name}-db")), b"").unwrap();
    std::fs::write(other.join(format!("{name}-db")), b"").unwrap();

    // The exact path, and the exact path with `-db`.
    assert!(is_the_keychain(&expected, &expected));
    assert!(is_the_keychain(&expected, &temp.join(format!("{name}-db"))));
    // Dot segments resolve to the same path.
    assert!(is_the_keychain(
        &expected,
        &other.join("..").join("temp").join(name)
    ));

    // The same name in another directory, with or without `-db`, existing
    // or not: refused. The review's case: a temporary `login.keychain`
    // against the real `login.keychain-db`.
    assert!(!is_the_keychain(&expected, &other.join(name)));
    assert!(!is_the_keychain(
        &expected,
        &other.join(format!("{name}-db"))
    ));
    assert!(!is_the_keychain(
        &temp.join("login.keychain"),
        &other.join("login.keychain-db")
    ));
    // `-db` only on the complete expected path.
    assert!(!is_the_keychain(
        &temp.join(format!("{name}-db")),
        &expected
    ));
    assert!(!is_the_keychain(
        &expected,
        &temp.join("freedom-keystore-test-db.keychain")
    ));
    assert!(!is_the_keychain(
        &expected,
        &temp.join(format!("{name}-db-db"))
    ));
    assert!(!is_the_keychain(
        &expected,
        &temp.join("freedom-keystore-test.keychai")
    ));
    assert!(!is_the_keychain(&expected, &temp));
    // Relative paths, and a directory that doesn't exist: refused.
    assert!(!is_the_keychain(Path::new(name), Path::new(name)));
    let gone = root.path().join("gone").join(name);
    assert!(!is_the_keychain(&gone, &gone));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        // A symlinked directory and a symlinked file name the same keychain
        // once canonical.
        let alias = root.path().join("alias");
        symlink(&temp, &alias).unwrap();
        assert!(is_the_keychain(&alias.join(name), &expected));
        assert!(is_the_keychain(&expected, &alias.join(name)));
        assert!(is_the_keychain(
            &expected,
            &alias.join(format!("{name}-db"))
        ));
        let link = other.join("link.keychain-db");
        symlink(temp.join(format!("{name}-db")), &link).unwrap();
        assert!(is_the_keychain(&expected, &link));
        // The same name through a link to another directory: refused.
        let other_alias = root.path().join("other-alias");
        symlink(&other, &other_alias).unwrap();
        assert!(!is_the_keychain(&expected, &other_alias.join(name)));
        assert!(!is_the_keychain(
            &expected,
            &other_alias.join(format!("{name}-db"))
        ));
    }
}

/// Whether the temporary keychain itself holds Freedom's item `item`, read
/// with `security` (attributes only, which ask for nothing).
fn in_temporary_keychain(item: &str) -> bool {
    let keychain = std::env::var_os("FREEDOM_TEST_KEYCHAIN").unwrap();
    Command::new("security")
        .args([
            "find-generic-password",
            "-s",
            "baby.freedom.keystore",
            "-a",
            item,
        ])
        .arg(keychain)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

fn fresh_item() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).unwrap();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn create(item: &str) -> [u8; 32] {
    let (pair, reply) = reply_key();
    let run = ask(&[
        "--op",
        "create",
        "--policy",
        "unattended",
        "--item",
        item,
        "--reply-key",
        &reply,
    ]);
    let key = opened(&answer(&run), pair, "create", item);
    assert!(!holds(&run.stdout, &key));
    key
}

fn open(item: &str) -> Result<[u8; 32], Value> {
    let (pair, reply) = reply_key();
    let run = ask(&[
        "--op",
        "open",
        "--policy",
        "unattended",
        "--item",
        item,
        "--reply-key",
        &reply,
    ]);
    let answer = answer(&run);
    if answer["ok"] != true {
        return Err(answer);
    }
    let key = opened(&answer, pair, "open", item);
    assert!(!holds(&run.stdout, &key));
    Ok(key)
}

fn forget(item: &str) -> Value {
    answer(&ask(&[
        "--op",
        "forget",
        "--policy",
        "unattended",
        "--item",
        item,
    ]))
}

#[test]
fn the_keychain_creates_opens_replaces_and_forgets() {
    if !temporary_keychain() {
        return;
    }
    let first = fresh_item();
    assert!(!in_temporary_keychain(&first));
    let key = create(&first);
    assert!(
        in_temporary_keychain(&first),
        "the item is in the temporary keychain"
    );
    assert_eq!(open(&first).unwrap(), key, "a fresh helper opens it");
    // Each create makes a fresh key; a second create of the same id is
    // refused and leaves the first.
    let (_, reply) = reply_key();
    let again = answer(&ask(&[
        "--op",
        "create",
        "--policy",
        "unattended",
        "--item",
        &first,
        "--reply-key",
        &reply,
    ]));
    assert_eq!(
        again,
        json!({ "ok": false, "error": "backend", "reason": "duplicate" })
    );
    assert_eq!(open(&first).unwrap(), key);
    // A replace: a new key under a new id, then the old one forgotten.
    let second = fresh_item();
    let new_key = create(&second);
    assert_ne!(new_key, key);
    assert_eq!(forget(&first), json!({ "ok": true }));
    assert_eq!(
        open(&first),
        Err(json!({ "ok": false, "error": "not_found" }))
    );
    assert_eq!(open(&second).unwrap(), new_key);
    // Forgetting a missing item answers not_found, which counts as done.
    assert_eq!(forget(&first), json!({ "ok": false, "error": "not_found" }));
    assert_eq!(forget(&second), json!({ "ok": true }));
    assert_eq!(
        open(&second),
        Err(json!({ "ok": false, "error": "not_found" }))
    );
    assert!(!in_temporary_keychain(&first));
    assert!(!in_temporary_keychain(&second));
}

#[test]
fn stdin_bytes_leave_the_keychain_untouched() {
    if !temporary_keychain() {
        return;
    }
    let item = fresh_item();
    let (_, reply) = reply_key();
    let run = helper(
        &[
            "--op",
            "create",
            "--policy",
            "unattended",
            "--item",
            &item,
            "--reply-key",
            &reply,
        ],
        Some(b"blob"),
        &[],
        Duration::from_secs(60),
    );
    assert_eq!(answer(&run)["reason"], "bad_request");
    assert_eq!(
        open(&item),
        Err(json!({ "ok": false, "error": "not_found" }))
    );
}

/// A helper killed after the Keychain stored the item and before it
/// answered: the secrets file's committed state is as it was, its pending
/// item moves into `forget` at the next open, and its forget removes the
/// item.
#[test]
fn a_helper_killed_after_the_store_leaves_a_pending_item_to_forget() {
    use fc_keystore::{Backend, ItemId, Policy, SecretsFile};
    if !temporary_keychain() {
        return;
    }
    let item = fresh_item();
    let id = ItemId::parse(&item).unwrap();
    let before = SecretsFile::new();
    let pending = before
        .begin_create(Policy::Unattended, Backend::MacosKeychain, id)
        .unwrap();
    let (_, reply) = reply_key();
    let run = helper(
        &[
            "--op",
            "create",
            "--policy",
            "unattended",
            "--item",
            &item,
            "--reply-key",
            &reply,
        ],
        None,
        &[("FREEDOM_CORED_TEST_KEYSTORE_EXIT_AFTER_STORE", "1")],
        Duration::from_secs(60),
    );
    assert_eq!(run.line, None, "no answer");
    assert!(run.stdout.is_empty());
    assert_ne!(run.status, Some(0));
    // The item is in the keychain, and the file names it, uncommitted.
    assert!(open(&item).is_ok());
    assert_eq!(pending.key(Policy::Unattended), None);
    assert_eq!(
        pending.pending(Policy::Unattended),
        Some((Backend::MacosKeychain, id))
    );
    // The next open: pending into forget, then the forget.
    let settled = pending.settle();
    let records = settled.forget_list();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].item(), id);
    assert_eq!(forget(&item), json!({ "ok": true }));
    let done = settled.forgotten(id);
    assert!(done.items().is_empty());
    assert_eq!(done.text(), before.text());
    assert_eq!(
        open(&item),
        Err(json!({ "ok": false, "error": "not_found" }))
    );
}

#[test]
fn the_helper_cant_start_a_program() {
    if !temporary_keychain() {
        return;
    }
    let (_, reply) = reply_key();
    let run = helper(
        &[
            "--op",
            "create",
            "--policy",
            "unattended",
            "--item",
            &fresh_item(),
            "--reply-key",
            &reply,
        ],
        None,
        &[("FREEDOM_CORED_TEST_KEYSTORE_SPAWN_PROBE", "1")],
        Duration::from_secs(60),
    );
    assert_eq!(
        answer(&run),
        json!({ "ok": false, "error": "backend", "reason": "no_spawn" })
    );
}

/// The core end to end, the test as main running the real helper for
/// each `shell.keystore`: create, open, forget and `not_found`, and the
/// wrapping key nowhere in the request, argv, stdin or the relayed answer.
#[test]
fn the_core_uses_the_keychain_through_main_and_the_helper() {
    if !temporary_keychain() {
        return;
    }
    let (_root, mut core) = serve(&[]);
    let item = fresh_item();
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let mut run_one = |core: &mut common::Core, id: u64, params: Value| -> Value {
        call(core, id, params);
        loop {
            match next(core, id) {
                Next::Asks(request, params) => {
                    seen.push(params.to_string().into_bytes());
                    let mut args = vec![
                        "--op".to_owned(),
                        params["op"].as_str().unwrap().to_owned(),
                        "--policy".to_owned(),
                        params["policy"].as_str().unwrap().to_owned(),
                        "--item".to_owned(),
                        params["item"].as_str().unwrap().to_owned(),
                    ];
                    assert!(params.get("sealed").is_none());
                    for (field, flag) in [("reply_key", "--reply-key"), ("reason", "--reason")] {
                        if let Some(value) = params.get(field) {
                            args.push(flag.to_owned());
                            args.push(value.as_str().unwrap().to_owned());
                        }
                    }
                    seen.push(args.join(" ").into_bytes());
                    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
                    let run = helper(&refs, None, &[], Duration::from_secs(60));
                    seen.push(run.stdout.clone());
                    let line: Value = serde_json::from_str(run.line.as_deref().unwrap()).unwrap();
                    respond(core, request, line);
                }
                Next::Answer(result) => return result,
            }
        }
    };
    let created = run_one(
        &mut core,
        2,
        json!({ "op": "create", "policy": "unattended", "item": item }),
    );
    assert_eq!(created["ok"], true, "{created}");
    assert_eq!(created["item"], item.as_str());
    assert_eq!(created["backend"], "macos-keychain");
    let key_hex = created["key"].as_str().unwrap().to_owned();
    let opened = run_one(
        &mut core,
        3,
        json!({ "op": "open", "policy": "unattended", "item": item, "reason": "quick_unlock" }),
    );
    assert_eq!(opened["key"], key_hex.as_str());
    let forgot = run_one(
        &mut core,
        4,
        json!({ "op": "forget", "policy": "unattended", "item": item }),
    );
    assert_eq!(forgot, json!({ "ok": true }));
    let gone = run_one(
        &mut core,
        5,
        json!({ "op": "open", "policy": "unattended", "item": item }),
    );
    assert_eq!(gone, json!({ "ok": false, "error": "not_found" }));
    // A forget of the missing item is done, as the trait says.
    let again = run_one(
        &mut core,
        6,
        json!({ "op": "forget", "policy": "unattended", "item": item }),
    );
    assert_eq!(again, json!({ "ok": true }));
    let key: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&key_hex[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    assert_eq!(seen.len(), 15, "five calls: request, argv, answer each");
    for bytes in &seen {
        assert!(!holds(bytes, &key), "{}", String::from_utf8_lossy(bytes));
    }
}
