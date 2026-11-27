//! The chain thread run by hand, for other modules' tests (design 0016,
//! SAFE-2's S1): the thread's own machine, wire forms and replies to the
//! core's reads ([`In::Internal`]), with the test's clock, and main played
//! by the test. Nothing runs on another thread: each call handles its mail
//! and flushes, as the thread's loop does.

use std::cell::Cell;
use std::rc::Rc;

use serde_json::{Value, json};

use super::*;
use crate::transport::Pending;

/// A reply to one of the core's own reads: its tag, its payload and
/// whether it failed at or after its deadline.
pub(crate) type Served = (u64, Vec<u8>, bool);

pub(crate) struct Scripted {
    chain: Chain,
    rx: Receiver<Out>,
    served: Receiver<Served>,
    clock: Rc<Cell<u64>>,
}

impl Scripted {
    /// A thread configured with `chains`, `chain.configure`'s.
    pub(crate) fn new(chains: Value) -> Self {
        let (out, rx) = mpsc::channel();
        let link = Link::new();
        link.offer();
        let clock = Rc::new(Cell::new(0));
        let now = Rc::clone(&clock);
        let mut chain = Chain::new(
            Machine::new(0, Bounds::default()),
            out,
            link,
            Shares {
                bulk: Allowance::new(usize::MAX, usize::MAX),
                control: Allowance::new(usize::MAX, usize::MAX),
            },
            Requests::new(256, Arc::new(Pending::default())),
            Box::new(move || now.get()),
        );
        let (tx, served) = mpsc::channel();
        chain.internal_served = Some(Box::new(move |tag, payload, past_due| {
            let _ = tx.send((tag, payload.to_vec(), past_due));
        }));
        let mut scripted = Scripted {
            chain,
            rx,
            served,
            clock,
        };
        let params = RawValue::from_string(json!({ "chains": chains }).to_string()).unwrap();
        scripted.handle(In::Request {
            id: 1,
            method: "chain.configure",
            params: Some(params),
        });
        let configured = scripted.written();
        assert!(
            configured
                .iter()
                .any(|f| f["id"] == 1 && f["result"].is_object()),
            "{configured:?}"
        );
        scripted
    }

    /// One of the core's own reads, as the event loop forwards it.
    pub(crate) fn internal(&mut self, read: crate::phone::ChainRead) {
        self.handle(In::Internal {
            tag: read.tag,
            chain_id: read.chain_id,
            method: read.method,
            params: read.params,
            deadline_ms: read.deadline_ms,
        });
    }

    /// The thread's requests to main and its cancels, written since the
    /// last look, as JSON.
    pub(crate) fn written(&mut self) -> Vec<Value> {
        let mut frames = Vec::new();
        while let Ok(item) = self.rx.try_recv() {
            match item {
                Out::Frame { frame, .. } => {
                    frames.push(serde_json::from_slice(&frame[5..]).unwrap());
                }
                Out::Fragmented { payload, .. } => {
                    frames.push(serde_json::from_slice(&payload).unwrap());
                }
                Out::Credit => {}
            }
        }
        frames
    }

    /// Main's terminal reply to request `id`: its `result`, or its
    /// `error`.
    pub(crate) fn answer(&mut self, id: u64, outcome: Result<Value, ErrorBody>) {
        assert_eq!(self.chain.requests.answered(id), Some(Owner::Chain));
        let (text, failed) = match outcome {
            Ok(result) => (result.to_string(), false),
            Err(error) => (serde_json::to_string(&error).unwrap(), true),
        };
        let member = if failed { "error" } else { "result" };
        let prefix = format!(r#"{{"type":"response","id":{id},"{member}":"#);
        let mut message = Zeroizing::new(prefix.clone().into_bytes());
        message.extend_from_slice(text.as_bytes());
        message.push(b'}');
        let span = prefix.len()..prefix.len() + text.len();
        let reply = if failed {
            Shell::Failed {
                message,
                error: span,
            }
        } else {
            Shell::Result {
                message,
                result: span,
            }
        };
        self.handle(In::Response { id, reply });
    }

    /// Moves the clock on by `ms`, and flushes.
    pub(crate) fn tick(&mut self, ms: u64) {
        self.clock.set(self.clock.get() + ms);
        assert!(self.chain.flush().is_ok());
    }

    /// The replies to the core's reads served since the last look.
    pub(crate) fn served(&mut self) -> Vec<Served> {
        self.served.try_iter().collect()
    }

    fn handle(&mut self, message: In) {
        assert!(self.chain.handle(message).is_ok());
        assert!(self.chain.flush().is_ok());
    }
}
