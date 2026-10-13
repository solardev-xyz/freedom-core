//! The core's own requests to main (`shell.*`, designs 0004 and 0005): one
//! gate for the naming and chain threads.
//!
//! - **One ID counter.** Main requires the core's request IDs to increase
//!   in the order it reads them (`reused_id` in `core-client.js`). Each ID
//!   is therefore taken, and its request handed to the writer, under one
//!   lock: the writer's queue sees requests in ID order, whichever thread
//!   sends them, and writes whole frames in the order they come.
//! - **One limit.** Main holds at most [`MAX_OUTSTANDING`] of the core's
//!   requests at a time, naming's and chain's together (0004, Bounds:
//!   Work). A thread that finds none free keeps its requests queued, and is
//!   woken once one is answered.
//! - **One registry.** Each request's owner, so the event loop routes main's
//!   response to the thread that asked, and a response that answers no
//!   request is unsolicited. The reader's [`Pending`] set is filled at the
//!   same time, before the writer has the request, so a fragmented answer
//!   always finds its request (design 0005, Frames).
//! - **Closing.** At shutdown the event loop closes the gate before it
//!   acknowledges, so no request follows the acknowledgement.
//! - **Frames made outside the lock.** A request's frame is made, up to
//!   one frame of copying and escaping, before the lock is taken, so
//!   neither thread nor main's answers wait for another's. Its ID and its
//!   `deadline_ms` are fixed-width slots, written under the lock in
//!   constant time ([`RequestFrame`]). The last step before a request is
//!   handed to the writer is its owner's check that it may still start, on
//!   the clock reading that also writes its `deadline_ms` (design 0005,
//!   Deadlines).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use fc_protocol::message::MAX_ID;
use zeroize::Zeroizing;

use crate::transport::{self, Allowance, Out, Pending};

/// The most of the core's requests main holds at a time (0004, Bounds:
/// Work; `MAX_INCOMING` in `core-client.js`).
pub const MAX_OUTSTANDING: usize = 256;

/// The thread a request belongs to: its response goes back there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Owner {
    Naming,
    Chain,
}

/// What became of a request offered to [`Requests::send`].
#[derive(Debug, PartialEq, Eq)]
pub enum Dispatch {
    /// Handed to the writer under this ID.
    Sent(u64),
    /// Over one frame: never sent (deviation `request-size`). Its producer
    /// completes it itself.
    TooLarge,
    /// The core is exiting: nothing more goes.
    Closed,
    /// Main holds as many of the core's requests as it takes. The owner is
    /// woken once one is answered.
    Full,
    /// The owner's share of the writer is full. Its allowance wakes it.
    NoRoom,
    /// Its latest start had passed when it would have taken its slot, its
    /// frame made: never sent, and nothing taken, no ID, slot or room.
    Late,
    /// The writer has gone.
    WriterGone,
}

/// Whether a request may still start, read as it takes its slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Start {
    /// It has no latest start.
    Anytime,
    /// It may start, with this many milliseconds left: its frame's
    /// `deadline_ms`, when it has one.
    Within(u64),
    /// Its latest start has passed.
    Late,
}

/// How wide a slot the gate writes is: a `u64`'s most digits.
pub const SLOT: usize = 20;

/// Appends a [`SLOT`]-wide slot for a number to `json`, reading `0` until
/// written ([`write_slot`]); where it starts.
pub fn slot_into(json: &mut Vec<u8>) -> usize {
    let at = json.len();
    json.resize(at + SLOT, b' ');
    if let Some(last) = json.last_mut() {
        *last = b'0';
    }
    at
}

/// Writes `value` into `slot`, right-aligned: spaces, then its digits.
/// JSON allows whitespace before a value, so a frame keeps its size,
/// whatever the value, and is written in place.
pub fn write_slot(slot: &mut [u8], value: u64) {
    slot.fill(b' ');
    let mut rest = value;
    for byte in slot.iter_mut().rev() {
        *byte = b'0' + u8::try_from(rest % 10).unwrap_or(0);
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
}

/// A request's frame, made before it takes its slot: outside the gate's
/// lock, however large it is. Its ID, and its `deadline_ms` when its
/// params have one, are [`SLOT`]-wide slots, written as it takes its slot,
/// under the lock: a constant amount of work.
pub struct RequestFrame {
    frame: Zeroizing<Vec<u8>>,
    /// Where its ID's slot starts.
    id: usize,
    /// Where its `deadline_ms`'s slot starts.
    deadline: Option<usize>,
}

impl RequestFrame {
    fn write(&mut self, id: u64, start: Start) {
        let at = self.id;
        if let Some(slot) = self.frame.get_mut(at..at.saturating_add(SLOT)) {
            write_slot(slot, id);
        }
        if let (Some(at), Start::Within(left)) = (self.deadline, start)
            && let Some(slot) = self.frame.get_mut(at..at.saturating_add(SLOT))
        {
            write_slot(slot, left);
        }
    }
}

type Wake = Box<dyn Fn() + Send>;

struct State {
    next_id: u64,
    closing: bool,
    /// The requests main hasn't answered yet, with their owners.
    owners: BTreeMap<u64, Owner>,
    /// Owners that found the limit reached: woken when a request is
    /// answered.
    waiting: BTreeSet<Owner>,
}

/// See the module documentation.
pub struct Requests {
    state: Mutex<State>,
    max_outstanding: usize,
    pending: Arc<Pending>,
    wakes: Mutex<BTreeMap<Owner, Wake>>,
}

impl Requests {
    pub fn new(max_outstanding: usize, pending: Arc<Pending>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                next_id: 1,
                closing: false,
                owners: BTreeMap::new(),
                waiting: BTreeSet::new(),
            }),
            max_outstanding,
            pending,
            wakes: Mutex::new(BTreeMap::new()),
        })
    }

    /// What to call when one of `owner`'s requests may go after a
    /// [`Dispatch::Full`].
    pub fn on_room(&self, owner: Owner, wake: impl Fn() + Send + 'static) {
        if let Ok(mut wakes) = self.wakes.lock() {
            wakes.insert(owner, Box::new(wake));
        }
    }

    /// The core is exiting: from now on no request is handed to the
    /// writer. A thread sending at this moment either finished before the
    /// lock was taken here, or sees it closed.
    pub fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closing = true;
        }
    }

    /// Hands a request of `owner`'s to the writer, if the gate is open, a
    /// slot is free and the owner's allowance has room.
    ///
    /// - `build` makes its frame, only once a slot is free, and outside the
    ///   lock; `None` when it is over one frame.
    /// - `start`, under the lock, is the last step before it is handed
    ///   over: whether it may still start, read then. Late, it takes
    ///   nothing. Otherwise its ID is taken, its slots written, the
    ///   request registered (for routing and for the reader) and the frame
    ///   queued, all under that lock, in constant time.
    pub fn send(
        &self,
        owner: Owner,
        allowance: &Arc<Allowance>,
        out: &Sender<Out>,
        build: impl FnOnce() -> Option<RequestFrame>,
        start: impl FnOnce() -> Start,
    ) -> Dispatch {
        {
            let Ok(mut state) = self.state.lock() else {
                return Dispatch::Closed;
            };
            if let Some(refused) = self.refusal(&mut state, owner) {
                return refused;
            }
        }
        let Some(mut request) = build() else {
            return Dispatch::TooLarge;
        };
        let Ok(mut state) = self.state.lock() else {
            return Dispatch::Closed;
        };
        // The gate may have closed, or the slot gone, while it was made.
        if let Some(refused) = self.refusal(&mut state, owner) {
            return refused;
        }
        let start = start();
        if start == Start::Late {
            return Dispatch::Late;
        }
        let Some(hold) = allowance.take(request.frame.len()) else {
            return Dispatch::NoRoom;
        };
        let id = state.next_id;
        request.write(id, start);
        state.next_id += 1;
        state.owners.insert(id, owner);
        // Before the writer has it, so main's answer can't come first.
        self.pending.insert(id);
        let frame = request.frame;
        if out.send(Out::Frame { frame, hold }).is_err() {
            return Dispatch::WriterGone;
        }
        Dispatch::Sent(id)
    }

    /// Why nothing of `owner`'s goes now, if so: the gate is closed, or
    /// main holds all it takes, and `owner` is woken once it holds fewer.
    fn refusal(&self, state: &mut State, owner: Owner) -> Option<Dispatch> {
        if state.closing || state.next_id > MAX_ID {
            return Some(Dispatch::Closed);
        }
        if state.owners.len() >= self.max_outstanding {
            state.waiting.insert(owner);
            return Some(Dispatch::Full);
        }
        None
    }

    /// Main answered request `id`: its owner, or `None` when it answers no
    /// request of the core's (an unsolicited or second response). Its slot
    /// is free from now on, and owners waiting for one are woken.
    pub fn answered(&self, id: u64) -> Option<Owner> {
        let (owner, woken) = {
            let mut state = self.state.lock().ok()?;
            let owner = state.owners.remove(&id)?;
            (owner, std::mem::take(&mut state.waiting))
        };
        self.pending.remove(id);
        if !woken.is_empty()
            && let Ok(wakes) = self.wakes.lock()
        {
            for waiting in woken {
                if let Some(wake) = wakes.get(&waiting) {
                    wake();
                }
            }
        }
        Some(owner)
    }

    /// Requests main hasn't answered.
    #[cfg(test)]
    pub fn outstanding(&self) -> usize {
        self.state.lock().map_or(0, |state| state.owners.len())
    }

    /// Whether the reader would take a fragmented answer for `id`.
    #[cfg(test)]
    pub fn is_pending(&self, id: u64) -> bool {
        self.pending.contains(id)
    }
}

/// A `shell.*` request's frame: the envelope around `params`, which is
/// already JSON, with a slot for its ID. `deadline` is where `params` has a
/// slot for `deadline_ms` ([`slot_into`]). `None` when it is over one
/// frame, or `deadline` names no slot. `method` is one of the core's own
/// names, which need no escaping.
pub fn request_frame(method: &str, params: &[u8], deadline: Option<usize>) -> Option<RequestFrame> {
    const CONTEXT: &[u8] = br#","context":{"caller":"shell"}}"#;
    let mut payload = Zeroizing::new(Vec::with_capacity(
        64 + SLOT + method.len() + params.len() + CONTEXT.len(),
    ));
    payload.extend_from_slice(br#"{"type":"request","id":"#);
    let id = slot_into(&mut payload);
    payload.extend_from_slice(br#","method":""#);
    payload.extend_from_slice(method.as_bytes());
    payload.extend_from_slice(br#"","params":"#);
    let start = payload.len();
    payload.extend_from_slice(params);
    payload.extend_from_slice(CONTEXT);
    let deadline = match deadline {
        Some(at) if at.checked_add(SLOT)? <= params.len() => Some(start + at),
        Some(_) => return None,
        None => None,
    };
    let frame = transport::frame(&payload)?;
    // The frame is its header, then the payload.
    let header = frame.len().checked_sub(payload.len())?;
    Some(RequestFrame {
        frame,
        id: header + id,
        deadline: deadline.map(|at| header + at),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn frame_of() -> Option<RequestFrame> {
        request_frame("shell.rpc", br#"{"endpoint":"e1"}"#, None)
    }

    /// A request with no latest start.
    fn send(
        requests: &Requests,
        owner: Owner,
        allowance: &Arc<Allowance>,
        out: &Sender<Out>,
    ) -> Dispatch {
        requests.send(owner, allowance, out, frame_of, || Start::Anytime)
    }

    /// The IDs of the requests the writer got, in order.
    fn written(rx: &mpsc::Receiver<Out>) -> Vec<u64> {
        let mut ids = Vec::new();
        while let Ok(Out::Frame { frame, .. }) = rx.try_recv() {
            let value: serde_json::Value = serde_json::from_slice(&frame[5..]).unwrap();
            ids.push(value["id"].as_u64().unwrap());
        }
        ids
    }

    #[test]
    fn one_counter_and_one_limit_for_every_owner() {
        let pending = Arc::new(Pending::default());
        let requests = Requests::new(3, Arc::clone(&pending));
        let (out, rx) = mpsc::channel();
        let naming = Allowance::new(usize::MAX, usize::MAX);
        let chain = Allowance::new(usize::MAX, usize::MAX);
        assert_eq!(
            send(&requests, Owner::Naming, &naming, &out),
            Dispatch::Sent(1)
        );
        assert_eq!(
            send(&requests, Owner::Chain, &chain, &out),
            Dispatch::Sent(2)
        );
        assert_eq!(
            send(&requests, Owner::Naming, &naming, &out),
            Dispatch::Sent(3)
        );
        // The limit counts both threads' requests.
        assert_eq!(send(&requests, Owner::Chain, &chain, &out), Dispatch::Full);
        assert_eq!(written(&rx), [1, 2, 3]);
        assert!(pending.contains(2));
        // A response goes back to its owner, frees its slot, and wakes the
        // owner that found none; a second one answers nothing.
        let woken = Arc::new(Mutex::new(Vec::new()));
        for owner in [Owner::Naming, Owner::Chain] {
            let woken = Arc::clone(&woken);
            requests.on_room(owner, move || woken.lock().unwrap().push(owner));
        }
        assert_eq!(requests.answered(1), Some(Owner::Naming));
        assert_eq!(*woken.lock().unwrap(), [Owner::Chain]);
        assert!(!pending.contains(1));
        assert_eq!(requests.answered(1), None);
        assert_eq!(requests.answered(99), None);
        assert_eq!(requests.outstanding(), 2);
        assert_eq!(
            send(&requests, Owner::Chain, &chain, &out),
            Dispatch::Sent(4)
        );
        assert_eq!(written(&rx), [4]);
        assert_eq!(requests.answered(4), Some(Owner::Chain));
        // Nobody was waiting: no wake.
        assert_eq!(woken.lock().unwrap().len(), 1);
    }

    #[test]
    fn ids_follow_write_order_across_threads() {
        let requests = Requests::new(usize::MAX, Arc::new(Pending::default()));
        let (out, rx) = mpsc::channel();
        let threads: Vec<_> = [Owner::Naming, Owner::Chain]
            .into_iter()
            .map(|owner| {
                let requests = Arc::clone(&requests);
                let out = out.clone();
                std::thread::spawn(move || {
                    let allowance = Allowance::new(usize::MAX, usize::MAX);
                    for _ in 0..500 {
                        assert!(matches!(
                            send(&requests, owner, &allowance, &out),
                            Dispatch::Sent(_)
                        ));
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let ids = written(&rx);
        assert_eq!(ids, (1..=1000).collect::<Vec<u64>>());
    }

    #[test]
    fn nothing_goes_once_closed_or_without_room() {
        let requests = Requests::new(usize::MAX, Arc::new(Pending::default()));
        let (out, rx) = mpsc::channel();
        // Room for one frame at a time.
        let allowance = Allowance::new(1, usize::MAX);
        assert_eq!(
            send(&requests, Owner::Chain, &allowance, &out),
            Dispatch::Sent(1)
        );
        assert_eq!(
            send(&requests, Owner::Chain, &allowance, &out),
            Dispatch::NoRoom
        );
        // An ID over one frame is not taken.
        assert_eq!(
            requests.send(Owner::Chain, &allowance, &out, || None, || Start::Anytime),
            Dispatch::TooLarge
        );
        // Nor one past its latest start.
        assert_eq!(
            requests.send(Owner::Chain, &allowance, &out, frame_of, || Start::Late),
            Dispatch::Late
        );
        drop(rx.try_recv());
        assert_eq!(
            send(&requests, Owner::Naming, &allowance, &out),
            Dispatch::Sent(2)
        );
        requests.close();
        drop(rx.try_recv());
        assert_eq!(
            send(&requests, Owner::Naming, &allowance, &out),
            Dispatch::Closed
        );
        drop(rx);
        let fresh = Requests::new(usize::MAX, Arc::new(Pending::default()));
        assert_eq!(
            send(&fresh, Owner::Naming, &allowance, &out),
            Dispatch::WriterGone
        );
    }

    #[test]
    fn a_request_frame_is_the_envelope_around_its_params() {
        let mut frame =
            request_frame("shell.verified", br#"{"myotis":"fee","chain_id":1}"#, None).unwrap();
        let size = frame.frame.len();
        frame.write(7, Start::Anytime);
        assert_eq!(frame.frame.len(), size);
        let value: serde_json::Value = serde_json::from_slice(&frame.frame[5..]).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "type": "request",
                "id": 7,
                "method": "shell.verified",
                "params": { "myotis": "fee", "chain_id": 1 },
                "context": { "caller": "shell" },
            })
        );
        let big = vec![b'1'; fc_protocol::frame::MAX_PAYLOAD];
        assert!(request_frame("shell.rpc", &big, None).is_none());
        // A deadline slot must lie within the params.
        assert!(request_frame("shell.rpc", br#"{"a":1}"#, Some(1)).is_none());
    }

    /// `{"generation":1,"deadline_ms":<slot>}`, and where its slot starts.
    fn params_with_deadline() -> (Vec<u8>, usize) {
        let mut params = br#"{"generation":1,"deadline_ms":"#.to_vec();
        let at = slot_into(&mut params);
        params.push(b'}');
        (params, at)
    }

    #[test]
    fn slots_are_space_padded_numbers_written_in_place() {
        let mut slot = [b'x'; SLOT];
        for (value, text) in [
            (0, "0"),
            (7, "7"),
            (1_234, "1234"),
            (MAX_ID, "9007199254740991"),
            (u64::MAX, "18446744073709551615"),
        ] {
            write_slot(&mut slot, value);
            assert_eq!(slot, *format!("{text:>20}").as_bytes());
        }
        // Unwritten, a slot reads 0: its params are JSON as made.
        let (params, at) = params_with_deadline();
        assert_eq!(&params[at..at + SLOT], format!("{:>20}", 0).as_bytes());
        let value: serde_json::Value = serde_json::from_slice(&params).unwrap();
        assert_eq!(value["deadline_ms"], 0);
    }

    #[test]
    fn a_frame_is_made_outside_the_lock_and_its_start_checked_last_under_it() {
        // Round 5 of PR #57's review: a frame takes time to make (up to one
        // frame of copying and escaping), so it is made first, outside the
        // lock, and the start checked once it is made, under the lock, on
        // the reading its `deadline_ms` is written from.
        let pending = Arc::new(Pending::default());
        let requests = Requests::new(usize::MAX, Arc::clone(&pending));
        let (out, rx) = mpsc::channel();
        let allowance = Allowance::new(usize::MAX, usize::MAX);
        let (params, at) = params_with_deadline();
        let steps = std::cell::RefCell::new(Vec::new());
        let sent = requests.send(
            Owner::Chain,
            &allowance,
            &out,
            || {
                assert!(requests.state.try_lock().is_ok(), "made under the lock");
                steps.borrow_mut().push("made");
                request_frame("shell.rpc", &params, Some(at))
            },
            || {
                assert!(
                    requests.state.try_lock().is_err(),
                    "checked outside the lock"
                );
                steps.borrow_mut().push("checked");
                Start::Within(4_850)
            },
        );
        assert_eq!(sent, Dispatch::Sent(1));
        assert_eq!(*steps.borrow(), ["made", "checked"]);
        let Ok(Out::Frame { frame, .. }) = rx.try_recv() else {
            panic!("no frame");
        };
        // The padded form, as main's JSON.parse reads it.
        let payload = std::str::from_utf8(&frame[5..]).unwrap();
        let id = format!("{:>20}", 1);
        let deadline = format!("{:>20}", 4_850);
        assert_eq!(
            payload,
            format!(
                r#"{{"type":"request","id":{id},"method":"shell.rpc","params":{{"generation":1,"deadline_ms":{deadline}}},"context":{{"caller":"shell"}}}}"#
            )
        );
        let value: serde_json::Value = serde_json::from_str(payload).unwrap();
        assert_eq!(value["id"], 1);
        assert_eq!(value["params"]["deadline_ms"], 4_850);
        assert!(pending.contains(1));
    }

    #[test]
    fn a_late_request_takes_nothing() {
        let pending = Arc::new(Pending::default());
        let requests = Requests::new(1, Arc::clone(&pending));
        let (out, rx) = mpsc::channel();
        let allowance = Allowance::new(usize::MAX, usize::MAX);
        assert_eq!(
            requests.send(Owner::Chain, &allowance, &out, frame_of, || Start::Late),
            Dispatch::Late
        );
        // No ID, no slot, no room, nothing written.
        assert_eq!(requests.outstanding(), 0);
        assert!(!pending.contains(1));
        assert_eq!(allowance.held_bytes(), 0);
        assert!(rx.try_recv().is_err());
        assert_eq!(
            send(&requests, Owner::Naming, &allowance, &out),
            Dispatch::Sent(1)
        );
    }

    #[test]
    fn no_frame_is_made_while_none_could_go() {
        let requests = Requests::new(1, Arc::new(Pending::default()));
        let (out, _rx) = mpsc::channel();
        let allowance = Allowance::new(usize::MAX, usize::MAX);
        assert_eq!(
            send(&requests, Owner::Naming, &allowance, &out),
            Dispatch::Sent(1)
        );
        let made = std::cell::Cell::new(0);
        let made_one = || {
            made.set(made.get() + 1);
            frame_of()
        };
        assert_eq!(
            requests.send(Owner::Chain, &allowance, &out, made_one, || Start::Anytime),
            Dispatch::Full
        );
        requests.close();
        assert_eq!(
            requests.send(Owner::Chain, &allowance, &out, made_one, || Start::Anytime),
            Dispatch::Closed
        );
        assert_eq!(made.get(), 0);
    }

    #[test]
    fn a_slot_gone_while_the_frame_was_made_is_waited_for() {
        let requests = Requests::new(1, Arc::new(Pending::default()));
        let (out, _rx) = mpsc::channel();
        let allowance = Allowance::new(usize::MAX, usize::MAX);
        let sent = requests.send(
            Owner::Chain,
            &allowance,
            &out,
            || {
                // Naming takes the last slot meanwhile.
                assert_eq!(
                    send(&requests, Owner::Naming, &allowance, &out),
                    Dispatch::Sent(1)
                );
                frame_of()
            },
            || panic!("checked without a slot"),
        );
        assert_eq!(sent, Dispatch::Full);
        let woken = Arc::new(Mutex::new(false));
        let wake = Arc::clone(&woken);
        requests.on_room(Owner::Chain, move || *wake.lock().unwrap() = true);
        assert_eq!(requests.answered(1), Some(Owner::Naming));
        assert!(*woken.lock().unwrap());
    }
}
