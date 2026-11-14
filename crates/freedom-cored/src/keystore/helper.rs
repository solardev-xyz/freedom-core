//! `freedom-cored keystore`, the one-shot helper (design 0013, "The helper,
//! `freedom-cored keystore`"):
//!
//! ```text
//! freedom-cored keystore --op <create|open|forget> --policy <unattended|user_presence>
//!                        --item <32 hex> [--reply-key <base64>] [--reason <quick_unlock|export>]
//! ```
//!
//! Main runs it for each `shell.keystore` request, one at a time per
//! profile, and relays its answer: one JSON line on stdout, at most
//! [`MAX_ANSWER_BYTES`](super::MAX_ANSWER_BYTES).
//!
//! - **The request** is argv alone, every field in a fixed form: each flag
//!   once, `--reply-key` (standard base64 of an X25519 public key) for
//!   `create` and `open` only, `--reason` for `open` only, and required for
//!   a `user_presence` one. Anything else is `{ ok: false, error: "backend",
//!   reason: "bad_request" }`, with no call to the OS.
//! - **Stdin** is read to its end before any OS call, at most 1 KiB and one
//!   byte more. Only a DPAPI `open` takes bytes there (0013, "DPAPI's
//!   blob"), and no backend here is DPAPI yet: any byte is `bad_request`,
//!   with no OS call.
//! - **The key** is made here, from the OS's RNG, where it is kept, and
//!   leaves only HPKE-sealed to `--reply-key` ([`super::associated_data`]
//!   binds the op and the item). No wrapping key crosses argv, stdin or
//!   what main relays. The helper's copy is wiped before it exits.
//! - **One call to the OS's key store,** then the answer, then exit. It
//!   runs no program and reads or writes no file. On macOS it first lowers
//!   its process limit to zero, so it can't start one either; how far it
//!   confines itself beyond that is the qualification gate's (0013).
//! - **No backend yet** (every OS but macOS until PRF-7, and `UserPresence`
//!   on macOS until PRF-1c's spike): `{ ok: false, error: "unavailable",
//!   reason: "unsupported" }`, after the form checks and with no OS call.
//!   No backend is ever faked.
//!
//! The exit status is 0 once an answer is written. Main reads the answer,
//! not the status: no line is `backend` (0013, "The answer").

use std::ffi::OsString;
use std::io::{Read, Write};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use fc_keystore::{BackendError, Capabilities, ItemId, KeyStoreError, Policy, Reason};
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use super::{Answer, LABEL, Op, SEALED_KEY_BYTES, associated_data};
use crate::exit::Exit;
use crate::rng::OsRng;

/// The most stdin bytes read: DPAPI's bound and one byte more, so an
/// oversized blob shows without reading all of it.
const MAX_STDIN_BYTES: usize = fc_keystore::MAX_BLOB_BYTES + 1;

/// One OS key store, as the helper calls it: the item is named by its id.
/// Each failure is the answer to give.
pub(super) trait OsStore {
    /// Keeps `key` as a new item; an item already there is refused.
    fn create(&self, policy: Policy, item: ItemId, key: &[u8; 32]) -> Result<(), Answer>;
    fn open(&self, policy: Policy, item: ItemId) -> Result<Zeroizing<[u8; 32]>, Answer>;
    /// Removes the item; a missing one is `not_found`.
    fn forget(&self, policy: Policy, item: ItemId) -> Result<(), Answer>;
}

/// A request in form.
#[derive(Debug, PartialEq, Eq)]
struct Request {
    op: Op,
    policy: Policy,
    item: ItemId,
    reply_key: Option<[u8; fc_seal::PUBLIC_KEY_LEN]>,
    reason: Option<Reason>,
}

/// The subcommand: `args` are those after `keystore`.
pub fn run(args: impl Iterator<Item = OsString>) -> Exit {
    let answer = if refuse_children() {
        let store = native_store();
        answer(args, &mut std::io::stdin().lock(), store, &mut OsRng)
    } else {
        Some(Answer::failed(backend("confine"), "confine"))
    };
    // A test hook stands for a helper killed after the OS stored the item
    // and before it answered: no line, as main would see it.
    let Some(answer) = answer else {
        return Exit::Internal;
    };
    let mut line = answer.text();
    line.push('\n');
    let mut stdout = std::io::stdout().lock();
    match stdout
        .write_all(line.as_bytes())
        .and_then(|()| stdout.flush())
    {
        Ok(()) => Exit::Ok,
        Err(_) => Exit::Internal,
    }
}

/// This OS's key store and what it offers; `None` where it has none yet.
fn native_store() -> Option<(&'static dyn OsStore, Capabilities)> {
    #[cfg(target_os = "macos")]
    {
        Some((&super::macos::Keychain, super::capabilities()))
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// On macOS, a process limit of zero: no fork or spawn succeeds from here
/// on (the limit binds every process of the user but root's). Linux counts
/// threads against the same limit, and Windows needs a job object: their
/// backends (PRF-7) choose their own means.
#[cfg(target_os = "macos")]
fn refuse_children() -> bool {
    use rustix::process::{Resource, Rlimit, setrlimit};
    setrlimit(
        Resource::Nproc,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .is_ok()
}

#[cfg(not(target_os = "macos"))]
fn refuse_children() -> bool {
    true
}

fn backend(reason: &'static str) -> KeyStoreError {
    KeyStoreError::Backend(BackendError::new(reason))
}

fn bad_request() -> Answer {
    Answer::failed(backend("bad_request"), "bad_request")
}

/// The answer to the request in `args`, with `stdin` read first; `None`
/// only for the test hook that leaves no answer.
pub(super) fn answer<R: TryCryptoRng + ?Sized>(
    args: impl Iterator<Item = OsString>,
    stdin: &mut dyn Read,
    store: Option<(&dyn OsStore, Capabilities)>,
    rng: &mut R,
) -> Option<Answer> {
    let request = parse(args);
    // Read before any OS call, whatever the request: bounded, so a stdin
    // that never ends is the deadline's.
    let mut bytes = Vec::new();
    let read = stdin.take(MAX_STDIN_BYTES as u64).read_to_end(&mut bytes);
    let (Some(request), Ok(0)) = (request, read) else {
        return Some(bad_request());
    };
    let Some((store, offered)) = store else {
        return Some(Answer::failed(
            super::unavailable("unsupported"),
            "unsupported",
        ));
    };
    if !offered.offers(request.policy) {
        return Some(Answer::failed(
            super::unavailable("unsupported"),
            "unsupported",
        ));
    }
    if let Some(spawned) = crate::testhooks::keystore_spawn_probe() {
        return Some(Answer::failed(
            backend("helper"),
            if spawned { "spawned" } else { "no_spawn" },
        ));
    }
    Some(match serve(&request, store, rng) {
        Ok(answer) => answer?,
        Err(answer) => answer,
    })
}

/// The one OS call, and the seal.
fn serve<R: TryCryptoRng + ?Sized>(
    request: &Request,
    store: &dyn OsStore,
    rng: &mut R,
) -> Result<Option<Answer>, Answer> {
    let key = match request.op {
        Op::Create => {
            let mut key = Zeroizing::new([0u8; 32]);
            rng.try_fill_bytes(&mut key[..])
                .map_err(|_| Answer::failed(backend("rng"), "rng"))?;
            store.create(request.policy, request.item, &key)?;
            if crate::testhooks::keystore_exit_after_store() {
                return Ok(None);
            }
            key
        }
        Op::Open => store.open(request.policy, request.item)?,
        Op::Forget => {
            store.forget(request.policy, request.item)?;
            return Ok(Some(Answer::Done));
        }
    };
    let reply_key = request.reply_key.ok_or_else(bad_request)?;
    let aad = associated_data(request.op, request.item, None);
    let sealed = fc_seal::seal_with(&reply_key, &key, LABEL, &aad, rng)
        .map_err(|_| Answer::failed(backend("seal"), "seal"))?;
    let mut sealed_key = [0u8; SEALED_KEY_BYTES];
    sealed_key[..fc_seal::ENC_LEN].copy_from_slice(&sealed.enc);
    sealed_key[fc_seal::ENC_LEN..].copy_from_slice(&sealed.ciphertext);
    Ok(Some(Answer::Key {
        sealed_key,
        blob: None,
    }))
}

/// The request argv spells, in form; `None` for anything else.
fn parse(mut args: impl Iterator<Item = OsString>) -> Option<Request> {
    let (mut op, mut policy, mut item, mut reply_key, mut reason) = (None, None, None, None, None);
    while let Some(flag) = args.next() {
        let value = args.next()?.into_string().ok()?;
        let slot_was_empty = match flag.to_str()? {
            "--op" => op.replace(Op::parse(&value)?).is_none(),
            "--policy" => policy.replace(Policy::parse(&value)?).is_none(),
            "--item" => item.replace(ItemId::parse(&value)?).is_none(),
            "--reply-key" => reply_key.replace(parse_reply_key(&value)?).is_none(),
            "--reason" => reason.replace(Reason::parse(&value)?).is_none(),
            _ => return None,
        };
        if !slot_was_empty {
            return None;
        }
    }
    let request = Request {
        op: op?,
        policy: policy?,
        item: item?,
        reply_key,
        reason,
    };
    let in_form = request.reply_key.is_some() == request.op.returns_key()
        && (request.reason.is_none() || request.op == Op::Open)
        && !(request.op == Op::Open
            && request.policy == Policy::UserPresence
            && request.reason.is_none());
    in_form.then_some(request)
}

/// Standard base64, padded, of a usable X25519 public key.
fn parse_reply_key(text: &str) -> Option<[u8; fc_seal::PUBLIC_KEY_LEN]> {
    if text.len() != fc_seal::PUBLIC_KEY_LEN.div_ceil(3) * 4 {
        return None;
    }
    let bytes = STANDARD.decode(text).ok()?;
    let key = <[u8; fc_seal::PUBLIC_KEY_LEN]>::try_from(bytes.as_slice()).ok()?;
    fc_seal::valid_recipient(&key).then_some(key)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use super::*;

    /// An in-memory store for the helper's own logic; never in the binary.
    #[derive(Default)]
    struct Memory {
        items: RefCell<BTreeMap<ItemId, [u8; 32]>>,
        calls: RefCell<usize>,
    }

    impl OsStore for Memory {
        fn create(&self, _: Policy, item: ItemId, key: &[u8; 32]) -> Result<(), Answer> {
            *self.calls.borrow_mut() += 1;
            let mut items = self.items.borrow_mut();
            if items.contains_key(&item) {
                return Err(Answer::failed(backend("duplicate"), "duplicate"));
            }
            items.insert(item, *key);
            Ok(())
        }

        fn open(&self, _: Policy, item: ItemId) -> Result<Zeroizing<[u8; 32]>, Answer> {
            *self.calls.borrow_mut() += 1;
            self.items
                .borrow()
                .get(&item)
                .map(|key| Zeroizing::new(*key))
                .ok_or(Answer::Failed {
                    error: KeyStoreError::NotFound,
                    reason: None,
                })
        }

        fn forget(&self, _: Policy, item: ItemId) -> Result<(), Answer> {
            *self.calls.borrow_mut() += 1;
            match self.items.borrow_mut().remove(&item) {
                Some(_) => Ok(()),
                None => Err(Answer::Failed {
                    error: KeyStoreError::NotFound,
                    reason: None,
                }),
            }
        }
    }

    const ITEM: &str = "00112233445566778899aabbccddeeff";

    fn recipient(_seed: u8) -> fc_seal::RecipientKey {
        fc_seal::RecipientKey::generate(&mut OsRng).unwrap()
    }

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    fn ask(store: &Memory, list: &[&str], stdin: &[u8]) -> Answer {
        let caps = Capabilities {
            backend: Some(fc_keystore::Backend::MacosKeychain),
            unattended: true,
            user_presence: false,
        };
        answer(
            args(list).into_iter(),
            &mut &stdin[..],
            Some((store, caps)),
            &mut OsRng,
        )
        .unwrap()
    }

    fn open_key(answer: &Answer, recipient: fc_seal::RecipientKey, op: Op) -> [u8; 32] {
        let Answer::Key { sealed_key, blob } = answer else {
            panic!("not a key: {answer:?}");
        };
        assert!(blob.is_none());
        let (enc, ciphertext) = sealed_key.split_at(fc_seal::ENC_LEN);
        let aad = associated_data(op, ItemId::parse(ITEM).unwrap(), None);
        *recipient.open_with(enc, ciphertext, LABEL, &aad).unwrap()
    }

    fn code(answer: &Answer) -> (&'static str, Option<&str>) {
        let Answer::Failed { error, reason } = answer else {
            panic!("not a failure: {answer:?}");
        };
        (error.code(), reason.as_deref())
    }

    #[test]
    fn create_open_and_forget_through_the_store() {
        let store = Memory::default();
        let r1 = recipient(1);
        let reply = STANDARD.encode(r1.public_key());
        let created = ask(
            &store,
            &[
                "--op",
                "create",
                "--policy",
                "unattended",
                "--item",
                ITEM,
                "--reply-key",
                &reply,
            ],
            b"",
        );
        let key = open_key(&created, r1, Op::Create);
        assert_eq!(store.items.borrow().values().next(), Some(&key));
        // The create answer opens only as a create's, for its item.
        let r2 = recipient(2);
        let reply = STANDARD.encode(r2.public_key());
        let opened = ask(
            &store,
            &[
                "--op",
                "open",
                "--policy",
                "unattended",
                "--item",
                ITEM,
                "--reply-key",
                &reply,
            ],
            b"",
        );
        assert_eq!(open_key(&opened, r2, Op::Open), key);
        let r3 = recipient(3);
        let reply = STANDARD.encode(r3.public_key());
        let opened = ask(
            &store,
            &[
                "--reply-key",
                &reply,
                "--item",
                ITEM,
                "--policy",
                "unattended",
                "--op",
                "open",
            ],
            b"",
        );
        let Answer::Key { sealed_key, .. } = &opened else {
            panic!("not a key");
        };
        let (enc, ct) = sealed_key.split_at(fc_seal::ENC_LEN);
        let other_op = associated_data(Op::Create, ItemId::parse(ITEM).unwrap(), None);
        assert!(r3.open_with(enc, ct, LABEL, &other_op).is_err());
        let forgot = ask(
            &store,
            &["--op", "forget", "--policy", "unattended", "--item", ITEM],
            b"",
        );
        assert_eq!(forgot, Answer::Done);
        let again = ask(
            &store,
            &["--op", "forget", "--policy", "unattended", "--item", ITEM],
            b"",
        );
        assert_eq!(code(&again), ("not_found", None));
        let r4 = recipient(4);
        let reply = STANDARD.encode(r4.public_key());
        let gone = ask(
            &store,
            &[
                "--op",
                "open",
                "--policy",
                "unattended",
                "--item",
                ITEM,
                "--reply-key",
                &reply,
            ],
            b"",
        );
        assert_eq!(code(&gone), ("not_found", None));
        // No answer line carries the key in any spelling.
        for answer in [&created, &opened] {
            let text = answer.text();
            assert!(!text.contains(&STANDARD.encode(key)));
            assert!(!text.contains(&ItemId::from_bytes([0; 16]).hex()));
        }
    }

    #[test]
    fn requests_out_of_form_make_no_os_call() {
        let store = Memory::default();
        let reply = STANDARD.encode(recipient(5).public_key());
        let low_order = STANDARD.encode([0u8; 32]);
        let short = STANDARD.encode([9u8; 31]);
        let cases: Vec<Vec<&str>> = vec![
            vec![],
            vec!["--op", "create"],
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
                "make",
                "--policy",
                "unattended",
                "--item",
                ITEM,
                "--reply-key",
                &reply,
            ],
            vec![
                "--op",
                "create",
                "--policy",
                "Unattended",
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
                "00112233445566778899AABBCCDDEEFF",
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
                &low_order,
            ],
            vec![
                "--op",
                "create",
                "--policy",
                "unattended",
                "--item",
                ITEM,
                "--reply-key",
                &short,
            ],
            vec![
                "--op",
                "create",
                "--policy",
                "unattended",
                "--item",
                ITEM,
                "--reply-key",
                "!!!",
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
                "forget",
                "--policy",
                "unattended",
                "--item",
                ITEM,
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
                "--reply-key",
                &reply,
                "--reason",
                "unlock",
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
                "open",
                "--op",
                "open",
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
                "--sealed",
                "AQ==",
            ],
            vec![
                "--op",
                "open",
                "--policy",
                "unattended",
                "--item",
                ITEM,
                "--reply-key",
            ],
        ];
        for case in cases {
            assert_eq!(
                code(&ask(&store, &case, b"")),
                ("backend", Some("bad_request")),
                "{case:?}"
            );
        }
        // Bytes on stdin, for any op: one byte, and DPAPI's bound and more.
        for stdin in [&b"x"[..], &[0u8; MAX_STDIN_BYTES + 10][..]] {
            for case in [
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
                assert_eq!(
                    code(&ask(&store, &case, stdin)),
                    ("backend", Some("bad_request"))
                );
            }
        }
        assert_eq!(*store.calls.borrow(), 0);
        assert!(store.items.borrow().is_empty());
    }

    #[test]
    fn policies_and_oses_without_a_backend_answer_unsupported() {
        let store = Memory::default();
        let reply = STANDARD.encode(recipient(6).public_key());
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
        assert_eq!(
            code(&ask(&store, &presence, b"")),
            ("unavailable", Some("unsupported"))
        );
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
        let none = answer(args(&create).into_iter(), &mut &b""[..], None, &mut OsRng);
        assert_eq!(
            none.map(|a| a.text()),
            Some(r#"{"ok":false,"error":"unavailable","reason":"unsupported"}"#.to_owned())
        );
        // Still form-checked first.
        let none = answer(args(&create).into_iter(), &mut &b"x"[..], None, &mut OsRng);
        assert_eq!(
            none.map(|a| a.text()),
            Some(r#"{"ok":false,"error":"backend","reason":"bad_request"}"#.to_owned())
        );
        assert_eq!(*store.calls.borrow(), 0);
    }

    #[test]
    fn a_duplicate_item_is_refused() {
        let store = Memory::default();
        let reply = STANDARD.encode(recipient(7).public_key());
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
        assert!(matches!(ask(&store, &create, b""), Answer::Key { .. }));
        let first = *store.items.borrow().values().next().unwrap();
        assert_eq!(
            code(&ask(&store, &create, b"")),
            ("backend", Some("duplicate"))
        );
        assert_eq!(store.items.borrow().values().next(), Some(&first));
    }
}
