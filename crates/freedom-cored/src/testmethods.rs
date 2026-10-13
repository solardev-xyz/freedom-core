//! The `test.*` methods, for the integration tests: answered only when
//! `testhooks::test_methods()` says so (debug builds, with
//! `FREEDOM_CORED_TEST_METHODS` set); otherwise they are unknown methods.
//!
//! They stand in for the chain thread's side of the transport (design 0005,
//! Frames) until it exists, so the tests can drive responses of any size:
//! - **their own thread,** which takes every message as it arrives,
//!   whatever the writer's state;
//! - **their own share of the writer,** one message cap
//!   ([`transport::MAX_QUEUED_CHAIN_BYTES`]). Past it, replies wait in this
//!   thread's queue, and new requests are `busy` once what waits passes two
//!   caps;
//! - **responses over one frame** go fragmented to a peer that offered
//!   fragments. One over the message cap, or over one frame for a peer that
//!   didn't, fails with `too_large`.
//!
//! `test.large { bytes }` answers with a string of `bytes` letters, `a` to
//! `z` repeating, so a fragment out of order shows. Its reply is made at
//! once: a `cancel` always comes after it and changes nothing, as 0001's
//! races between cancels and responses allow.

use std::collections::VecDeque;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Weak};

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::message;
use serde::Deserialize;
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use crate::serve::Event;
use crate::transport::{self, Allowance, Credit, Link, Out, Reply};

/// The methods this thread answers.
pub const METHODS: &[&str] = &["test.large"];

/// The largest `bytes` asked for: past the cap, to see `too_large`.
const MAX_TEST_BYTES: usize = 2 * fc_protocol::frame::MAX_MESSAGE;

pub fn handles(method: &str) -> bool {
    METHODS.contains(&method)
}

/// What the event loop forwards.
pub enum In {
    Request {
        id: u64,
        params: Option<Box<RawValue>>,
    },
    /// The writer has room again for replies that wait here.
    Drained,
}

/// A message, with the reader's credit for the frame it came in.
type Mail = (In, Option<Credit>);

/// The event loop's side of the thread; dropping it ends the thread.
pub struct Handle {
    tx: Arc<Sender<Mail>>,
}

impl Handle {
    /// False once the thread has gone.
    pub fn send(&self, message: In, credit: Option<Credit>) -> bool {
        self.tx.send((message, credit)).is_ok()
    }
}

/// Starts the thread. It writes to `out`, and reports the writer's end to
/// the event loop.
pub fn spawn(out: Sender<Out>, link: Arc<Link>, events: Sender<Event>) -> std::io::Result<Handle> {
    let (tx, rx) = mpsc::channel();
    let tx = Arc::new(tx);
    let allowance = Allowance::new(usize::MAX, transport::MAX_QUEUED_CHAIN_BYTES);
    let wake: Weak<Sender<Mail>> = Arc::downgrade(&tx);
    allowance.on_room(move || {
        if let Some(tx) = wake.upgrade() {
            let _ = tx.send((In::Drained, None));
        }
    });
    std::thread::Builder::new()
        .name("test".into())
        .spawn(move || {
            let _notice = transport::DeathNotice::new(events.clone(), "test");
            let mut producer = Producer {
                out,
                link,
                allowance,
                outbox: VecDeque::new(),
                max_backlog: 2 * transport::MAX_QUEUED_CHAIN_BYTES,
            };
            if run(&rx, &mut producer).is_err() {
                let _ = events.send(Event::WriterFailed);
            }
        })?;
    Ok(Handle { tx })
}

/// The writer has gone.
struct Gone;

fn run(rx: &Receiver<Mail>, producer: &mut Producer) -> Result<(), Gone> {
    // The frame's credit goes once its message is handled.
    while let Ok((message, _credit)) = rx.recv() {
        match message {
            In::Request { id, params } => {
                let reply = producer.answer(id, params.as_deref());
                producer.outbox.push_back(reply);
                producer.pump()?;
            }
            In::Drained => producer.pump()?,
        }
    }
    // The event loop has gone: what waits goes to the writer, which the
    // loop gives its bounded drain.
    producer.drain();
    Ok(())
}

struct Producer {
    out: Sender<Out>,
    link: Arc<Link>,
    allowance: Arc<Allowance>,
    /// Replies waiting for room in the writer, in order.
    outbox: VecDeque<Reply>,
    /// What may wait, here and in the writer, before new requests are busy.
    max_backlog: usize,
}

impl Producer {
    fn answer(&self, id: u64, params: Option<&RawValue>) -> Reply {
        #[derive(Deserialize)]
        struct Params {
            bytes: usize,
        }
        let params = params.and_then(|p| serde_json::from_str::<Params>(p.get()).ok());
        let Some(Params { bytes }) = params.filter(|p| p.bytes <= MAX_TEST_BYTES) else {
            return error(id, ErrorCode::InvalidArgument, "Invalid parameters");
        };
        if self.backlog() > self.max_backlog {
            return error(id, ErrorCode::Busy, "Too many test replies waiting");
        }
        let mut text = "abcdefghijklmnopqrstuvwxyz".repeat(bytes.div_ceil(26));
        text.truncate(bytes);
        let mut payload = Zeroizing::new(Vec::with_capacity(bytes + 64));
        if message::write_result(&mut *payload, id, &text).is_err() {
            return error(id, ErrorCode::Internal, "Internal error");
        }
        Reply::new(&self.link, id, payload)
            .unwrap_or_else(|| error(id, ErrorCode::TooLarge, "Response too large"))
    }

    /// What waits to be written: in the writer, and here.
    fn backlog(&self) -> usize {
        self.allowance.held_bytes() + self.outbox.iter().map(Reply::len).sum::<usize>()
    }

    /// Hands waiting replies to the writer while the allowance has room; the
    /// rest wait for [`In::Drained`].
    fn pump(&mut self) -> Result<(), Gone> {
        while let Some(reply) = self.outbox.front() {
            let Some(hold) = self.allowance.take(reply.len()) else {
                return Ok(());
            };
            let Some(reply) = self.outbox.pop_front() else {
                return Ok(());
            };
            self.out.send(reply.into_out(hold)).map_err(|_| Gone)?;
        }
        Ok(())
    }

    /// Hands every waiting reply to the writer, past the allowance: at
    /// shutdown, where the writer's drain is bounded by time instead.
    fn drain(&mut self) {
        for reply in self.outbox.drain(..) {
            let hold = self.allowance.force(reply.len());
            let _ = self.out.send(reply.into_out(hold));
        }
    }
}

/// A small error reply: always one frame.
fn error(id: u64, code: ErrorCode, text: &str) -> Reply {
    let mut payload = Zeroizing::new(Vec::with_capacity(128));
    let _ = message::write_error(&mut *payload, id, &ErrorBody::new(code, text));
    Reply::Whole(transport::frame(&payload).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn producer(link: Arc<Link>, max_bytes: usize) -> (Producer, Receiver<Out>) {
        let (out, written) = mpsc::channel();
        let producer = Producer {
            out,
            link,
            allowance: Allowance::new(usize::MAX, max_bytes),
            outbox: VecDeque::new(),
            max_backlog: 2 * transport::MAX_QUEUED_CHAIN_BYTES,
        };
        (producer, written)
    }

    fn params(bytes: usize) -> Box<RawValue> {
        RawValue::from_string(format!(r#"{{"bytes":{bytes}}}"#)).unwrap()
    }

    fn error_code(reply: &Reply) -> Option<String> {
        let Reply::Whole(frame) = reply else {
            return None;
        };
        let value: serde_json::Value = serde_json::from_slice(&frame[5..]).ok()?;
        value["error"]["code"].as_str().map(str::to_owned)
    }

    #[test]
    fn large_replies_fragment_only_for_a_peer_that_offered() {
        let link = Link::new();
        let (producer, _) = producer(Arc::clone(&link), usize::MAX);
        let big = 2 << 20;
        // Not offered: over one frame fails as too large.
        let reply = producer.answer(3, Some(&params(big)));
        assert_eq!(error_code(&reply).as_deref(), Some("too_large"));
        assert!(matches!(
            producer.answer(3, Some(&params(100))),
            Reply::Whole(_)
        ));
        link.offer();
        let Reply::Fragmented { id: 3, payload } = producer.answer(3, Some(&params(big))) else {
            panic!("not fragmented");
        };
        let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        let text = value["result"].as_str().unwrap();
        assert_eq!(text.len(), big);
        assert!(text.starts_with("abcdefghijklmnopqrstuvwxyzabc"));
        // Over the cap, whatever was offered.
        let over = producer.answer(3, Some(&params(fc_protocol::frame::MAX_MESSAGE)));
        assert_eq!(error_code(&over).as_deref(), Some("too_large"));
        for bad in [r#"{}"#, r#"{"bytes":-1}"#, r#"{"bytes":"1"}"#] {
            let raw = RawValue::from_string(bad.to_owned()).unwrap();
            let reply = producer.answer(3, Some(&raw));
            assert_eq!(error_code(&reply).as_deref(), Some("invalid_argument"));
        }
        let reply = producer.answer(3, Some(&params(MAX_TEST_BYTES + 1)));
        assert_eq!(error_code(&reply).as_deref(), Some("invalid_argument"));
    }

    #[test]
    fn replies_past_the_allowance_wait_here_and_then_busy() {
        let link = Link::new();
        link.offer();
        // Room for 3 MiB: the first reply takes it.
        let (mut producer, written) = producer(link, 3 << 20);
        for id in 1..=3 {
            let reply = producer.answer(id, Some(&params(3 << 20)));
            producer.outbox.push_back(reply);
            assert!(producer.pump().is_ok());
        }
        let first = written.try_recv().unwrap();
        assert!(written.try_recv().is_err(), "the others wait here");
        assert_eq!(producer.outbox.len(), 2);
        // The writer frees the room: the next goes.
        drop(first);
        assert!(producer.pump().is_ok());
        assert!(matches!(
            written.try_recv(),
            Ok(Out::Fragmented { id: 2, .. })
        ));
        // Past the backlog bound (scaled down here), counting what the
        // writer holds and what waits here, new requests are busy.
        producer.max_backlog = 5 << 20;
        assert!(matches!(
            producer.answer(4, Some(&params(10))),
            Reply::Whole(_)
        ));
        producer
            .outbox
            .push_back(producer.answer(5, Some(&params(3 << 20))));
        let reply = producer.answer(6, Some(&params(10)));
        assert_eq!(error_code(&reply).as_deref(), Some("busy"));
    }
}
