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
    /// Its latest start had passed when it would have taken its slot: never
    /// sent, nothing taken.
    Late,
    /// The writer has gone.
    WriterGone,
}

/// Why a request's frame wasn't made at the moment it would take its slot.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Over one frame.
    TooLarge,
    /// Past its latest start.
    Late,
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
    /// slot is free and the owner's allowance has room. `frame` makes its
    /// frame for the ID it would take, at the moment it would take its
    /// slot, or refuses: over one frame, or past its latest start. The ID
    /// is taken, the request registered (for routing and for the reader)
    /// and the frame queued under one lock.
    pub fn send(
        &self,
        owner: Owner,
        allowance: &Arc<Allowance>,
        out: &Sender<Out>,
        frame: impl FnOnce(u64) -> Result<Zeroizing<Vec<u8>>, Refusal>,
    ) -> Dispatch {
        let Ok(mut state) = self.state.lock() else {
            return Dispatch::Closed;
        };
        if state.closing || state.next_id > MAX_ID {
            return Dispatch::Closed;
        }
        if state.owners.len() >= self.max_outstanding {
            state.waiting.insert(owner);
            return Dispatch::Full;
        }
        let id = state.next_id;
        let frame = match frame(id) {
            Ok(frame) => frame,
            Err(Refusal::TooLarge) => return Dispatch::TooLarge,
            Err(Refusal::Late) => return Dispatch::Late,
        };
        let Some(hold) = allowance.take(frame.len()) else {
            return Dispatch::NoRoom;
        };
        state.next_id += 1;
        state.owners.insert(id, owner);
        // Before the writer has it, so main's answer can't come first.
        self.pending.insert(id);
        if out.send(Out::Frame { frame, hold }).is_err() {
            return Dispatch::WriterGone;
        }
        Dispatch::Sent(id)
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

/// A `shell.*` request's frame: the envelope with `id` around `params`,
/// which is already JSON. `None` when it is over one frame. `method` is
/// one of the core's own names, which need no escaping.
pub fn request_frame(id: u64, method: &str, params: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    const CONTEXT: &[u8] = br#","context":{"caller":"shell"}}"#;
    let id = id.to_string();
    let mut payload = Zeroizing::new(Vec::with_capacity(
        64 + id.len() + method.len() + params.len() + CONTEXT.len(),
    ));
    payload.extend_from_slice(br#"{"type":"request","id":"#);
    payload.extend_from_slice(id.as_bytes());
    payload.extend_from_slice(br#","method":""#);
    payload.extend_from_slice(method.as_bytes());
    payload.extend_from_slice(br#"","params":"#);
    payload.extend_from_slice(params);
    payload.extend_from_slice(CONTEXT);
    transport::frame(&payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn frame_of(id: u64) -> Result<Zeroizing<Vec<u8>>, Refusal> {
        request_frame(id, "shell.rpc", br#"{"endpoint":"e1"}"#).ok_or(Refusal::TooLarge)
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
            requests.send(Owner::Naming, &naming, &out, frame_of),
            Dispatch::Sent(1)
        );
        assert_eq!(
            requests.send(Owner::Chain, &chain, &out, frame_of),
            Dispatch::Sent(2)
        );
        assert_eq!(
            requests.send(Owner::Naming, &naming, &out, frame_of),
            Dispatch::Sent(3)
        );
        // The limit counts both threads' requests.
        assert_eq!(
            requests.send(Owner::Chain, &chain, &out, frame_of),
            Dispatch::Full
        );
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
            requests.send(Owner::Chain, &chain, &out, frame_of),
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
                            requests.send(owner, &allowance, &out, frame_of),
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
            requests.send(Owner::Chain, &allowance, &out, frame_of),
            Dispatch::Sent(1)
        );
        assert_eq!(
            requests.send(Owner::Chain, &allowance, &out, frame_of),
            Dispatch::NoRoom
        );
        // An ID over one frame is not taken.
        assert_eq!(
            requests.send(Owner::Chain, &allowance, &out, |_| Err(Refusal::TooLarge)),
            Dispatch::TooLarge
        );
        // Nor one past its latest start.
        assert_eq!(
            requests.send(Owner::Chain, &allowance, &out, |_| Err(Refusal::Late)),
            Dispatch::Late
        );
        drop(rx.try_recv());
        assert_eq!(
            requests.send(Owner::Naming, &allowance, &out, frame_of),
            Dispatch::Sent(2)
        );
        requests.close();
        drop(rx.try_recv());
        assert_eq!(
            requests.send(Owner::Naming, &allowance, &out, frame_of),
            Dispatch::Closed
        );
        drop(rx);
        let fresh = Requests::new(usize::MAX, Arc::new(Pending::default()));
        assert_eq!(
            fresh.send(Owner::Naming, &allowance, &out, frame_of),
            Dispatch::WriterGone
        );
    }

    #[test]
    fn a_request_frame_is_the_envelope_around_its_params() {
        let frame =
            request_frame(7, "shell.verified", br#"{"myotis":"fee","chain_id":1}"#).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&frame[5..]).unwrap();
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
        assert!(request_frame(1, "shell.rpc", &big).is_none());
    }
}
