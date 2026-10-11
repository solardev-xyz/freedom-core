//! Stdio transport (design 0001, "Transport"):
//!
//! - **Reader thread:** turns stdin into frames. At most
//!   [`MAX_QUEUED_FRAMES`] frames wait for the event loop at any time; beyond
//!   that the reader stops reading, which is backpressure on main.
//! - **Writer thread:** one serialized writer for stdout, behind a bounded
//!   queue. A full queue means main has stopped reading, and the core exits
//!   rather than buffer without limit.
//!
//! Lifecycle events (EOF, framing errors, writer failure, a thread dying) go
//! through an unbounded channel that frames can't fill.

use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Condvar, Mutex};

use fc_protocol::frame::Decoder;
use zeroize::Zeroizing;

use crate::serve::Event;

const READ_CHUNK: usize = 64 * 1024;
/// Frames waiting for the event loop.
pub const MAX_QUEUED_FRAMES: usize = 256;
/// Replies waiting for the writer.
pub const MAX_QUEUED_REPLIES: usize = 256;

/// Counts frames handed to the event loop and not yet handled.
#[derive(Default)]
pub struct Credits {
    in_flight: Mutex<usize>,
    freed: Condvar,
}

impl Credits {
    fn acquire(&self) {
        let Ok(mut in_flight) = self.in_flight.lock() else {
            return;
        };
        while *in_flight >= MAX_QUEUED_FRAMES {
            in_flight = match self.freed.wait(in_flight) {
                Ok(guard) => guard,
                Err(_) => return,
            };
        }
        *in_flight += 1;
    }

    /// Called by the event loop after handling a frame.
    pub fn release(&self) {
        if let Ok(mut in_flight) = self.in_flight.lock() {
            *in_flight = in_flight.saturating_sub(1);
            self.freed.notify_one();
        }
    }
}

/// Reports a thread that ends by panicking.
struct DeathNotice {
    events: Sender<Event>,
    name: &'static str,
}

impl Drop for DeathNotice {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let _ = self.events.send(Event::ThreadDied(self.name));
        }
    }
}

/// Reads stdin until EOF or a framing error.
pub fn spawn_reader(
    events: Sender<Event>,
    credits: Arc<Credits>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("stdin".into())
        .spawn(move || {
            let _notice = DeathNotice {
                events: events.clone(),
                name: "stdin",
            };
            let mut stdin = std::io::stdin().lock();
            let mut buffer = Zeroizing::new(vec![0u8; READ_CHUNK]);
            let mut decoder = Decoder::new();
            loop {
                let read = match stdin.read(&mut buffer[..]) {
                    Ok(0) => {
                        let _ = events.send(Event::Eof {
                            at_boundary: decoder.is_at_boundary(),
                        });
                        return;
                    }
                    Ok(read) => read,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        let _ = events.send(Event::Eof { at_boundary: false });
                        return;
                    }
                };
                // The decoder takes input up to its budget; hand its frames on,
                // then feed it the rest.
                let mut rest = &buffer[..read];
                while !rest.is_empty() {
                    let consumed = match decoder.push(rest) {
                        Ok(consumed) => consumed,
                        Err(e) => {
                            let _ = events.send(Event::ProtocolError(protocol_category(&e)));
                            return;
                        }
                    };
                    rest = &rest[consumed..];
                    while let Some(frame) = decoder.pop() {
                        credits.acquire();
                        if events.send(Event::Frame(frame)).is_err() {
                            return;
                        }
                    }
                }
            }
        })
}

fn protocol_category(error: &fc_protocol::frame::FrameError) -> &'static str {
    match error {
        fc_protocol::frame::FrameError::BadLength(_) => "bad_frame_length",
        fc_protocol::frame::FrameError::UnknownKind(_) => "unknown_frame_kind",
    }
}

/// The writer's handles: its bounded queue, and a signal when it finishes.
pub struct Writer {
    pub queue: SyncSender<Zeroizing<Vec<u8>>>,
    pub done: Receiver<()>,
}

/// Writes framed messages to stdout, in order, until the queue closes.
pub fn spawn_writer(events: Sender<Event>) -> std::io::Result<Writer> {
    let (queue, frames) = mpsc::sync_channel::<Zeroizing<Vec<u8>>>(MAX_QUEUED_REPLIES);
    let (done_tx, done) = mpsc::channel();
    std::thread::Builder::new()
        .name("stdout".into())
        .spawn(move || {
            let _notice = DeathNotice {
                events: events.clone(),
                name: "stdout",
            };
            let mut stdout = std::io::stdout().lock();
            for frame in frames {
                if stdout
                    .write_all(&frame)
                    .and_then(|()| stdout.flush())
                    .is_err()
                {
                    let _ = events.send(Event::WriterFailed);
                    return;
                }
            }
            let _ = done_tx.send(());
        })?;
    Ok(Writer { queue, done })
}

/// Frames one JSON message.
pub fn frame(payload: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(payload.len() + 5));
    fc_protocol::frame::encode_json(payload, &mut out).ok()?;
    Some(out)
}
