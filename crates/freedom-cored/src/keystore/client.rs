//! The core's desktop [`KeyStore`] (design 0013, "The call"): each call is
//! a `shell.keystore` request to main, which runs the helper for it and
//! relays its answer. `serve` never calls a key store itself.
//!
//! - **The request:** `{ op, policy, item, sealed?, reply_key?, reason? }`.
//!   `reply_key` is the public half of an X25519 key pair made for that one
//!   request (standard base64), for `create` and `open`; `sealed` is DPAPI's
//!   blob, for a DPAPI `open` only; `reason` goes with an `open`.
//! - **The answer** is the helper's, relayed as the response's `result`:
//!   at most [`MAX_ANSWER_BYTES`], in form ([`Answer::parse`]), of the kind
//!   the op needs, and a `key` that opens under the request's private half,
//!   its op, its item and the answer's blob. Anything else is `Backend`.
//!   So main only ever relays ciphertext.
//! - **Deadlines:** main kills a helper past 60 s (`create`, `open`) or
//!   10 s (`forget`) and answers `unavailable`. The core waits that long
//!   and [`GRACE`] more for main's answer, then gives up with
//!   `Unavailable`; a late answer is dropped.
//! - **One call at a time:** main runs one helper at a time per profile,
//!   so a call queued behind another would spend its deadline waiting.
//! - **No call where none can work:** a policy this OS doesn't offer is
//!   `Unavailable`, and a key of a backend this OS doesn't have is
//!   `NotFound` for `open` and gone for `forget` (its item isn't here,
//!   0013 "An item already gone"), all without asking main. A DPAPI
//!   `forget` makes no call either: dropping the blob is the whole forget
//!   (0013, "Windows").
//! - **Calls block** their thread, never the event loop: the loop only
//!   routes main's responses here ([`DesktopKeyStore::deliver`]). The
//!   callers (quick unlock, PRF-1c) run on worker threads.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::mpsc::{self, RecvTimeoutError, Sender, SyncSender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use fc_keystore::{
    Backend, BackendError, Blob, Capabilities, ItemId, KeyStore, KeyStoreError, Label, Policy,
    Reason, Sealed, WrapKey,
};
use zeroize::Zeroizing;

use super::{Answer, LABEL, MAX_ANSWER_BYTES, Op, associated_data, unavailable};
use crate::requests::{self, Dispatch, Owner, Requests, Start};
use crate::rng::OsRng;
use crate::transport::{Allowance, Out};

/// How long past main's own deadline the core waits for its answer.
pub const GRACE: Duration = Duration::from_secs(5);

/// What main sent back for a request, as the event loop routed it.
enum Relayed {
    /// The response's `result`: the helper's answer, at most
    /// [`MAX_ANSWER_BYTES`].
    Answer(Zeroizing<Vec<u8>>),
    /// A `result` past [`MAX_ANSWER_BYTES`]: never parsed.
    TooLong,
    /// An error response, by its code.
    Error(String),
}

struct State {
    /// The writer's queue; `None` once the core exits.
    out: Option<Sender<Out>>,
    /// Calls waiting for main's answer, by request ID.
    waiting: BTreeMap<u64, SyncSender<Relayed>>,
}

/// See the module documentation.
pub struct DesktopKeyStore {
    capabilities: Capabilities,
    requests: Arc<Requests>,
    /// This producer's share of the writer: one small request at a time.
    allowance: Arc<Allowance>,
    state: Mutex<State>,
    /// Bumped whenever a request may go after `Full` or `NoRoom`.
    room: Arc<(Mutex<u64>, Condvar)>,
    /// Held across each call.
    one_at_a_time: Mutex<()>,
    /// Main's deadline for an op and [`GRACE`]; the test hook's instead.
    deadline: fn(Op) -> Duration,
}

impl DesktopKeyStore {
    /// This OS's key store, through main.
    pub fn new(requests: Arc<Requests>, out: Sender<Out>) -> Arc<Self> {
        let capabilities = crate::testhooks::keystore_capabilities(super::capabilities());
        Self::with(capabilities, requests, out, |op| {
            crate::testhooks::keystore_deadline(op.deadline() + GRACE)
        })
    }

    fn with(
        capabilities: Capabilities,
        requests: Arc<Requests>,
        out: Sender<Out>,
        deadline: fn(Op) -> Duration,
    ) -> Arc<Self> {
        let room = Arc::new((Mutex::new(0u64), Condvar::new()));
        let allowance = Allowance::new(4, 64 * 1024);
        let wake = {
            let room = Arc::clone(&room);
            move || {
                let (count, changed) = &*room;
                if let Ok(mut count) = count.lock() {
                    *count = count.wrapping_add(1);
                }
                changed.notify_all();
            }
        };
        allowance.on_room(wake.clone());
        requests.on_room(Owner::KeyStore, wake);
        Arc::new(Self {
            capabilities,
            requests,
            allowance,
            state: Mutex::new(State {
                out: Some(out),
                waiting: BTreeMap::new(),
            }),
            room,
            one_at_a_time: Mutex::new(()),
            deadline,
        })
    }

    /// Main's response to request `id`, from the event loop: the span of its
    /// `result` or its `error` in `message`. A call that gave up has gone,
    /// and its answer is dropped.
    pub fn deliver(&self, id: u64, outcome: Result<Range<usize>, Range<usize>>, message: &[u8]) {
        let relayed = match outcome {
            Ok(span) => match message.get(span) {
                Some(result) if result.len() <= MAX_ANSWER_BYTES => {
                    Relayed::Answer(Zeroizing::new(result.to_vec()))
                }
                _ => Relayed::TooLong,
            },
            Err(span) => Relayed::Error(
                message
                    .get(span)
                    .and_then(|error| serde_json::from_slice::<serde_json::Value>(error).ok())
                    .and_then(|error| error["code"].as_str().map(str::to_owned))
                    .unwrap_or_default(),
            ),
        };
        let waiter = self
            .state
            .lock()
            .ok()
            .and_then(|mut state| state.waiting.remove(&id));
        if let Some(waiter) = waiter {
            let _ = waiter.send(relayed);
        }
    }

    /// The core is exiting: no request goes from now on, and every call
    /// waiting for an answer is `Unavailable`. The writer's queue is let go,
    /// so the writer can end.
    pub fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.out = None;
            state.waiting.clear();
        }
        let (count, changed) = &*self.room;
        if let Ok(mut count) = count.lock() {
            *count = count.wrapping_add(1);
        }
        changed.notify_all();
    }

    /// Sends `params` as `shell.keystore` and waits for main's answer, until
    /// `op`'s deadline.
    fn ask(&self, op: Op, params: &[u8]) -> Result<Answer, KeyStoreError> {
        let _one = self.one_at_a_time.lock().map_err(|_| internal())?;
        let until = Instant::now() + (self.deadline)(op);
        let (tx, rx) = mpsc::sync_channel(1);
        let mut tx = Some(tx);
        let id = loop {
            let seen = self.room.0.lock().map(|count| *count).unwrap_or(0);
            {
                let mut state = self.state.lock().map_err(|_| internal())?;
                let Some(out) = state.out.clone() else {
                    return Err(unavailable("closed"));
                };
                // Under the state's lock, so the answer can't be routed
                // before its waiter is in place.
                let sent = self.requests.send(
                    Owner::KeyStore,
                    &self.allowance,
                    &out,
                    || requests::request_frame("shell.keystore", params, None),
                    || Start::Anytime,
                );
                match sent {
                    Dispatch::Sent(id) => {
                        if let Some(tx) = tx.take() {
                            state.waiting.insert(id, tx);
                        }
                        break id;
                    }
                    Dispatch::Full | Dispatch::NoRoom => {}
                    Dispatch::Closed | Dispatch::WriterGone => {
                        return Err(unavailable("closed"));
                    }
                    Dispatch::TooLarge | Dispatch::Late => return Err(backend("request")),
                }
            }
            // Wait for room, or the deadline.
            let (count, changed) = &*self.room;
            let mut count = count.lock().map_err(|_| internal())?;
            while *count == seen {
                let left = until.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(unavailable("timeout"));
                }
                count = changed.wait_timeout(count, left).map_err(|_| internal())?.0;
            }
        };
        let relayed = match rx.recv_timeout(until.saturating_duration_since(Instant::now())) {
            Ok(relayed) => relayed,
            Err(error) => {
                if let Ok(mut state) = self.state.lock() {
                    state.waiting.remove(&id);
                }
                return Err(unavailable(match error {
                    RecvTimeoutError::Timeout => "timeout",
                    // Closed while it waited: the core is exiting.
                    RecvTimeoutError::Disconnected => "closed",
                }));
            }
        };
        match relayed {
            Relayed::Answer(text) => relayed_answer(&text),
            Relayed::TooLong => Err(backend("answer_too_long")),
            // An older main with no executor, or one that ran out of time
            // or closed: no key store answered.
            Relayed::Error(code) if code == "unknown_method" => Err(unavailable("no_executor")),
            Relayed::Error(code) if code == "timeout" => Err(unavailable("timeout")),
            Relayed::Error(code) if code == "cancelled" => Err(unavailable("closed")),
            Relayed::Error(_) => Err(backend("shell_error")),
        }
    }

    /// The backend a key of this OS is made in, if it offers `policy`.
    fn backend_for(&self, policy: Policy) -> Option<Backend> {
        self.capabilities
            .backend
            .filter(|_| self.capabilities.offers(policy))
    }
}

fn backend(reason: &'static str) -> KeyStoreError {
    KeyStoreError::Backend(BackendError::new(reason))
}

fn internal() -> KeyStoreError {
    backend("internal")
}

/// The request's params, in the design's order. Every value is fixed-form,
/// so nothing needs escaping.
fn params(
    op: Op,
    policy: Policy,
    item: ItemId,
    blob: Option<&Blob>,
    reply_key: Option<&[u8; fc_seal::PUBLIC_KEY_LEN]>,
    reason: Option<Reason>,
) -> Vec<u8> {
    let mut json = format!(
        r#"{{"op":"{}","policy":"{}","item":"{}""#,
        op.name(),
        policy.name(),
        item.hex()
    );
    if let Some(blob) = blob {
        json.push_str(&format!(r#","sealed":"{}""#, blob.base64()));
    }
    if let Some(reply_key) = reply_key {
        json.push_str(&format!(r#","reply_key":"{}""#, STANDARD.encode(reply_key)));
    }
    if let Some(reason) = reason {
        json.push_str(&format!(r#","reason":"{}""#, reason.name()));
    }
    json.push('}');
    json.into_bytes()
}

/// The key a `create` or `open` answer carries, opened with the request's
/// private half under its op, its item and the answer's blob.
fn open_key(
    recipient: fc_seal::RecipientKey,
    op: Op,
    item: ItemId,
    sealed_key: &[u8],
    blob: Option<&Blob>,
) -> Result<WrapKey, KeyStoreError> {
    let (enc, ciphertext) = sealed_key.split_at(fc_seal::ENC_LEN.min(sealed_key.len()));
    let aad = associated_data(op, item, blob);
    let mut key = recipient
        .open_with(enc, ciphertext, LABEL, &aad)
        .map_err(|_| backend("answer_seal"))?;
    Ok(WrapKey::take(&mut key))
}

/// What an answer to a call yields, once [`take`] has checked it.
pub(super) enum Taken {
    /// `create` and `open`: the wrapping key, opened, and the blob a
    /// `create` of a backend that keeps one carries.
    Key(WrapKey, Option<Blob>),
    /// `forget`: done, or the item was already gone.
    Done,
}

/// The answer a relayed `result` holds ([`Answer::parse`]): anything out of
/// form, or over [`MAX_ANSWER_BYTES`], is `Backend`.
pub(super) fn relayed_answer(text: &[u8]) -> Result<Answer, KeyStoreError> {
    Answer::parse(text).map_err(backend)
}

/// What the core makes of the answer to `op` on `item` (0013, "The
/// answer"): the kind the op needs, with a blob on a `create` exactly when
/// the backend keeps one (`keeps_blob`) and never on an `open`, and a key
/// that opens under `recipient`, the op, the item and the answer's blob. A
/// failure answer is its error, and a `forget`'s `not_found` is done.
/// Anything else is `Backend`. `recipient` is the request's private half,
/// for `create` and `open`.
pub(super) fn take(
    op: Op,
    item: ItemId,
    keeps_blob: bool,
    recipient: Option<fc_seal::RecipientKey>,
    answer: Answer,
) -> Result<Taken, KeyStoreError> {
    match (op, answer) {
        (Op::Create, Answer::Key { sealed_key, blob }) if blob.is_some() == keeps_blob => {
            let recipient = recipient.ok_or_else(internal)?;
            let key = open_key(recipient, op, item, &sealed_key, blob.as_ref())?;
            Ok(Taken::Key(key, blob))
        }
        (
            Op::Open,
            Answer::Key {
                sealed_key,
                blob: None,
            },
        ) => {
            let recipient = recipient.ok_or_else(internal)?;
            let key = open_key(recipient, op, item, &sealed_key, None)?;
            Ok(Taken::Key(key, None))
        }
        (
            Op::Forget,
            Answer::Done
            | Answer::Failed {
                error: KeyStoreError::NotFound,
                ..
            },
        ) => Ok(Taken::Done),
        (_, Answer::Failed { error, .. }) => Err(error),
        _ => Err(backend("answer_form")),
    }
}

fn reply_pair() -> Result<fc_seal::RecipientKey, KeyStoreError> {
    fc_seal::RecipientKey::generate(&mut OsRng).map_err(|_| backend("rng"))
}

impl KeyStore for DesktopKeyStore {
    fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    fn create(&self, policy: Policy, label: &Label) -> Result<(WrapKey, Sealed), KeyStoreError> {
        let backend_kind = self
            .backend_for(policy)
            .ok_or_else(|| unavailable("unsupported"))?;
        let item = label.item();
        let recipient = reply_pair()?;
        let request = params(
            Op::Create,
            policy,
            item,
            None,
            Some(&recipient.public_key()),
            None,
        );
        let answer = self.ask(Op::Create, &request)?;
        match take(
            Op::Create,
            item,
            backend_kind.keeps_blob(),
            Some(recipient),
            answer,
        )? {
            Taken::Key(key, blob) => {
                let sealed = Sealed::new(backend_kind, policy, item, blob)
                    .map_err(|_| backend("answer_form"))?;
                Ok((key, sealed))
            }
            Taken::Done => Err(backend("answer_form")),
        }
    }

    fn open(&self, sealed: &Sealed, reason: Option<Reason>) -> Result<WrapKey, KeyStoreError> {
        let policy = sealed.policy();
        if policy == Policy::UserPresence && reason.is_none() {
            return Err(backend("no_reason"));
        }
        if self.capabilities.backend != Some(sealed.backend()) {
            return Err(KeyStoreError::NotFound);
        }
        if self.backend_for(policy).is_none() {
            return Err(unavailable("unsupported"));
        }
        let item = sealed.item();
        let recipient = reply_pair()?;
        let request = params(
            Op::Open,
            policy,
            item,
            sealed.blob(),
            Some(&recipient.public_key()),
            reason,
        );
        let answer = self.ask(Op::Open, &request)?;
        match take(Op::Open, item, false, Some(recipient), answer)? {
            Taken::Key(key, _) => Ok(key),
            Taken::Done => Err(backend("answer_form")),
        }
    }

    fn forget(&self, sealed: &Sealed) -> Result<(), KeyStoreError> {
        if !sealed.backend().holds_item() || self.capabilities.backend != Some(sealed.backend()) {
            return Ok(());
        }
        let request = params(Op::Forget, sealed.policy(), sealed.item(), None, None, None);
        let answer = self.ask(Op::Forget, &request)?;
        match take(Op::Forget, sealed.item(), false, None, answer)? {
            Taken::Done => Ok(()),
            Taken::Key(..) => Err(backend("answer_form")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Pending;

    const ITEM: &str = "00112233445566778899aabbccddeeff";

    fn item() -> ItemId {
        ItemId::parse(ITEM).unwrap()
    }

    /// A key store over a fake main: each request frame the core writes is
    /// handed to `answer`, whose reply (the `result`'s text, or an error
    /// code) goes back through [`DesktopKeyStore::deliver`].
    fn store(
        caps: Capabilities,
        deadline: fn(Op) -> Duration,
        answer: impl Fn(&serde_json::Value) -> Option<Result<Vec<u8>, String>> + Send + 'static,
    ) -> (
        Arc<DesktopKeyStore>,
        std::thread::JoinHandle<Vec<serde_json::Value>>,
    ) {
        let requests = Requests::new(requests::MAX_OUTSTANDING, Arc::new(Pending::default()));
        let (out, written) = mpsc::channel();
        let ks = DesktopKeyStore::with(caps, Arc::clone(&requests), out, deadline);
        let main = Arc::clone(&ks);
        let thread = std::thread::spawn(move || {
            let mut seen = Vec::new();
            while let Ok(Out::Frame { frame, .. }) = written.recv() {
                let request: serde_json::Value = serde_json::from_slice(&frame[5..]).unwrap();
                let id = request["id"].as_u64().unwrap();
                let reply = answer(&request["params"]);
                seen.push(request);
                let Some(reply) = reply else { continue };
                requests.answered(id);
                match reply {
                    Ok(result) => {
                        let message = [br#"{"result":"#.as_slice(), &result, b"}"].concat();
                        main.deliver(id, Ok(10..10 + result.len()), &message);
                    }
                    Err(code) => {
                        let error = format!(r#"{{"code":"{code}","message":"x"}}"#);
                        main.deliver(id, Err(0..error.len()), error.as_bytes());
                    }
                }
            }
            seen
        });
        (ks, thread)
    }

    fn keychain() -> Capabilities {
        Capabilities {
            backend: Some(Backend::MacosKeychain),
            unattended: true,
            user_presence: false,
        }
    }

    fn long(_: Op) -> Duration {
        Duration::from_secs(30)
    }

    fn short(_: Op) -> Duration {
        Duration::from_millis(200)
    }

    /// What a helper would answer to `params`, sealing `key` for its op and
    /// item, with `blob` for a create.
    fn seal_answer(params: &serde_json::Value, key: &[u8; 32], blob: Option<&Blob>) -> Vec<u8> {
        let reply: [u8; 32] = STANDARD
            .decode(params["reply_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let op = Op::parse(params["op"].as_str().unwrap()).unwrap();
        let item = ItemId::parse(params["item"].as_str().unwrap()).unwrap();
        let aad = associated_data(op, item, blob);
        let sealed = fc_seal::seal_with(&reply, key, LABEL, &aad, &mut OsRng).unwrap();
        let mut sealed_key = [0u8; super::super::SEALED_KEY_BYTES];
        sealed_key[..32].copy_from_slice(&sealed.enc);
        sealed_key[32..].copy_from_slice(&sealed.ciphertext);
        Answer::Key {
            sealed_key,
            blob: blob.cloned(),
        }
        .text()
        .into_bytes()
    }

    #[test]
    fn create_open_and_forget_through_main() {
        let (ks, main) = store(keychain(), long, |p| {
            Some(Ok(match p["op"].as_str().unwrap() {
                "forget" => br#"{"ok":true}"#.to_vec(),
                _ => seal_answer(p, &[7; 32], None),
            }))
        });
        let (key, sealed) = ks.create(Policy::Unattended, &Label::new(item())).unwrap();
        assert_eq!(key.expose(), &[7; 32]);
        assert_eq!(
            sealed,
            Sealed::new(Backend::MacosKeychain, Policy::Unattended, item(), None).unwrap()
        );
        assert_eq!(ks.open(&sealed, None).unwrap().expose(), &[7; 32]);
        assert_eq!(
            ks.open(&sealed, Some(Reason::QuickUnlock))
                .unwrap()
                .expose(),
            &[7; 32]
        );
        assert_eq!(ks.forget(&sealed), Ok(()));
        ks.close();
        let seen = main.join().unwrap();
        assert_eq!(seen.len(), 4);
        // The requests' form: the design's fields, and no key.
        let create = &seen[0];
        assert_eq!(create["method"], "shell.keystore");
        assert_eq!(create["context"]["caller"], "shell");
        let keys: Vec<&String> = create["params"].as_object().unwrap().keys().collect();
        assert_eq!(keys, ["op", "policy", "item", "reply_key"]);
        assert_eq!(seen[2]["params"]["reason"], "quick_unlock");
        let forget: Vec<&String> = seen[3]["params"].as_object().unwrap().keys().collect();
        assert_eq!(forget, ["op", "policy", "item"]);
        // Each request has its own reply key.
        assert_ne!(
            seen[0]["params"]["reply_key"],
            seen[1]["params"]["reply_key"]
        );
        for request in &seen {
            let text = request.to_string();
            assert!(!text.contains(&STANDARD.encode([7u8; 32])));
        }
    }

    #[test]
    fn answers_for_another_key_op_item_or_blob_are_refused() {
        type Forge = fn(&serde_json::Value) -> Vec<u8>;
        let cases: [(&str, Forge); 6] = [
            ("another reply key", |_| {
                let other = fc_seal::RecipientKey::generate(&mut OsRng).unwrap();
                let p = serde_json::json!({
                    "op": "create", "item": ITEM,
                    "reply_key": STANDARD.encode(other.public_key()),
                });
                seal_answer(&p, &[1; 32], None)
            }),
            ("another op", |p| {
                let mut p = p.clone();
                p["op"] = "open".into();
                seal_answer(&p, &[1; 32], None)
            }),
            ("another item", |p| {
                let mut p = p.clone();
                p["item"] = "ffeeddccbbaa99887766554433221100".into();
                seal_answer(&p, &[1; 32], None)
            }),
            ("a blob for a keychain key", |p| {
                seal_answer(p, &[1; 32], Some(&Blob::new(vec![1]).unwrap()))
            }),
            ("a forget's answer", |_| br#"{"ok":true}"#.to_vec()),
            ("not json", |_| b"ok".to_vec()),
        ];
        for (what, forge) in cases {
            let (ks, main) = store(keychain(), long, move |p| Some(Ok(forge(p))));
            let refused = ks.create(Policy::Unattended, &Label::new(item()));
            assert!(
                matches!(refused, Err(KeyStoreError::Backend(_))),
                "{what}: {:?}",
                refused.map(|(_, s)| s)
            );
            ks.close();
            main.join().unwrap();
        }
        // An open's answer sealed as a create's, and one with a blob.
        let (ks, main) = store(keychain(), long, |p| {
            let mut p = p.clone();
            p["op"] = "create".into();
            Some(Ok(seal_answer(&p, &[1; 32], None)))
        });
        let sealed = Sealed::new(Backend::MacosKeychain, Policy::Unattended, item(), None).unwrap();
        assert!(matches!(
            ks.open(&sealed, None),
            Err(KeyStoreError::Backend(_))
        ));
        ks.close();
        main.join().unwrap();
    }

    #[test]
    fn a_dpapi_blob_travels_and_is_bound() {
        let dpapi = Capabilities {
            backend: Some(Backend::Dpapi),
            unattended: true,
            user_presence: false,
        };
        let blob = Blob::new(vec![9; 200]).unwrap();
        let answer_blob = blob.clone();
        let (ks, main) = store(dpapi, long, move |p| {
            Some(Ok(match p["op"].as_str().unwrap() {
                "create" => seal_answer(p, &[5; 32], Some(&answer_blob)),
                _ => seal_answer(p, &[5; 32], None),
            }))
        });
        let (key, sealed) = ks.create(Policy::Unattended, &Label::new(item())).unwrap();
        assert_eq!(key.expose(), &[5; 32]);
        assert_eq!(sealed.blob(), Some(&blob));
        assert_eq!(ks.open(&sealed, None).unwrap().expose(), &[5; 32]);
        // A DPAPI forget makes no call.
        assert_eq!(ks.forget(&sealed), Ok(()));
        ks.close();
        let seen = main.join().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1]["params"]["sealed"], blob.base64());
        assert!(seen[0]["params"].get("sealed").is_none());

        // A create answer whose blob changed on the way doesn't open; nor
        // does one with no blob.
        for changed in [Some(Blob::new(vec![8; 200]).unwrap()), None] {
            let (ks, main) = store(dpapi, long, move |p| {
                let sealed_for = Blob::new(vec![9; 200]).unwrap();
                let mut text = seal_answer(p, &[5; 32], Some(&sealed_for));
                let value: serde_json::Value = serde_json::from_slice(&text).unwrap();
                text = match &changed {
                    Some(other) => Answer::Key {
                        sealed_key: STANDARD
                            .decode(value["key"].as_str().unwrap())
                            .unwrap()
                            .try_into()
                            .unwrap(),
                        blob: Some(other.clone()),
                    }
                    .text()
                    .into_bytes(),
                    None => format!(
                        r#"{{"ok":true,"key":"{}"}}"#,
                        value["key"].as_str().unwrap()
                    )
                    .into_bytes(),
                };
                Some(Ok(text))
            });
            assert!(matches!(
                ks.create(Policy::Unattended, &Label::new(item())),
                Err(KeyStoreError::Backend(_))
            ));
            ks.close();
            main.join().unwrap();
        }
    }

    #[test]
    fn failures_map_onto_the_trait() {
        for (answer, expected) in [
            (
                r#"{"ok":false,"error":"not_found"}"#,
                KeyStoreError::NotFound,
            ),
            (
                r#"{"ok":false,"error":"cancelled"}"#,
                KeyStoreError::Cancelled,
            ),
            (
                r#"{"ok":false,"error":"unavailable","reason":"timeout"}"#,
                unavailable("timeout"),
            ),
            (
                r#"{"ok":false,"error":"invalidated"}"#,
                KeyStoreError::Invalidated,
            ),
            (
                r#"{"ok":false,"error":"denied","reason":"interaction_not_allowed"}"#,
                KeyStoreError::Denied,
            ),
            (
                r#"{"ok":false,"error":"backend","reason":"bad_request"}"#,
                backend("bad_request"),
            ),
        ] {
            let (ks, main) = store(keychain(), long, move |_| {
                Some(Ok(answer.as_bytes().to_vec()))
            });
            let sealed =
                Sealed::new(Backend::MacosKeychain, Policy::Unattended, item(), None).unwrap();
            assert_eq!(ks.open(&sealed, None).err(), Some(expected), "{answer}");
            let forgot = ks.forget(&sealed);
            if expected == KeyStoreError::NotFound {
                assert_eq!(forgot, Ok(()), "a missing item is forgotten");
            } else {
                assert_eq!(forgot, Err(expected));
            }
            ks.close();
            main.join().unwrap();
        }
        // Main's own errors.
        for (code, expected) in [
            ("unknown_method", unavailable("no_executor")),
            ("timeout", unavailable("timeout")),
            ("cancelled", unavailable("closed")),
            ("invalid_argument", backend("shell_error")),
        ] {
            let (ks, main) = store(keychain(), long, move |_| Some(Err(code.to_owned())));
            assert_eq!(
                ks.create(Policy::Unattended, &Label::new(item())).err(),
                Some(expected)
            );
            ks.close();
            main.join().unwrap();
        }
    }

    #[test]
    fn a_long_answer_or_none_in_time_fails() {
        let (ks, main) = store(keychain(), long, |_| {
            let mut text = br#"{"ok":true}"#.to_vec();
            text.resize(MAX_ANSWER_BYTES + 1, b' ');
            Some(Ok(text))
        });
        let sealed = Sealed::new(Backend::MacosKeychain, Policy::Unattended, item(), None).unwrap();
        assert_eq!(ks.forget(&sealed), Err(backend("answer_too_long")));
        ks.close();
        main.join().unwrap();
        // At the cap exactly, an answer still counts.
        let (ks, main) = store(keychain(), long, |_| {
            let mut text = br#"{"ok":true}"#.to_vec();
            text.resize(MAX_ANSWER_BYTES, b' ');
            Some(Ok(text))
        });
        assert_eq!(ks.forget(&sealed), Ok(()));
        ks.close();
        main.join().unwrap();
        // No answer within the deadline: Unavailable, and the late answer
        // dropped.
        let (ks, main) = store(keychain(), short, |_| None);
        let started = Instant::now();
        assert_eq!(ks.forget(&sealed), Err(unavailable("timeout")));
        assert!(started.elapsed() >= Duration::from_millis(200));
        ks.deliver(1, Ok(0..11), br#"{"ok":true}"#);
        // Closing makes later calls Unavailable at once.
        ks.close();
        assert_eq!(ks.forget(&sealed), Err(unavailable("closed")));
        main.join().unwrap();
    }

    #[test]
    fn calls_that_cant_work_ask_nothing() {
        let (ks, main) = store(keychain(), long, |_| {
            panic!("no request expected");
        });
        // UserPresence isn't offered; without a reason it's refused first.
        assert_eq!(
            ks.create(Policy::UserPresence, &Label::new(item())).err(),
            Some(unavailable("unsupported"))
        );
        let presence =
            Sealed::new(Backend::MacosKeychain, Policy::UserPresence, item(), None).unwrap();
        assert_eq!(ks.open(&presence, None).err(), Some(backend("no_reason")));
        assert_eq!(
            ks.open(&presence, Some(Reason::Export)).err(),
            Some(unavailable("unsupported"))
        );
        // Another OS's key: its item isn't here.
        let foreign =
            Sealed::new(Backend::SecretService, Policy::Unattended, item(), None).unwrap();
        assert_eq!(ks.open(&foreign, None).err(), Some(KeyStoreError::NotFound));
        assert_eq!(ks.forget(&foreign), Ok(()));
        let dpapi = Sealed::new(
            Backend::Dpapi,
            Policy::Unattended,
            item(),
            Some(Blob::new(vec![1]).unwrap()),
        )
        .unwrap();
        assert_eq!(ks.forget(&dpapi), Ok(()));
        ks.close();
        assert!(main.join().unwrap().is_empty());
        // No backend at all.
        let (ks, main) = store(Capabilities::NONE, long, |_| {
            panic!("no request expected");
        });
        assert_eq!(
            ks.create(Policy::Unattended, &Label::new(item())).err(),
            Some(unavailable("unsupported"))
        );
        let keychain_key =
            Sealed::new(Backend::MacosKeychain, Policy::Unattended, item(), None).unwrap();
        assert_eq!(
            ks.open(&keychain_key, None).err(),
            Some(KeyStoreError::NotFound)
        );
        assert_eq!(ks.forget(&keychain_key), Ok(()));
        ks.close();
        assert!(main.join().unwrap().is_empty());
    }
}
