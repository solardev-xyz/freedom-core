//! Stdio transport (design 0001, "Transport"):
//!
//! - **Reader thread:** turns stdin into frames. At most
//!   [`MAX_QUEUED_FRAMES`] frames and [`MAX_QUEUED_FRAME_BYTES`] wait to be
//!   handled at any time, by the event loop or the naming thread a frame is
//!   forwarded to; beyond that the reader stops reading, which is
//!   backpressure on main.
//! - **Writer thread:** one serialized writer for stdout. Each producer has
//!   its own [`Allowance`] of queued frames, so naming traffic can't take
//!   the vault loop's room (0001's reserved control capacity). The vault
//!   loop's full allowance means main has stopped reading, and the core
//!   exits rather than buffer without limit; naming's frames wait in the
//!   naming thread instead.
//!
//! Lifecycle events (EOF, framing errors, writer failure, a thread dying) go
//! through an unbounded channel that frames can't fill.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};

use fc_protocol::frame::Decoder;
use zeroize::Zeroizing;

use crate::serve::Event;

const READ_CHUNK: usize = 64 * 1024;
/// Frames read and not yet handled...
pub const MAX_QUEUED_FRAMES: usize = 256;
/// ...and their bytes (a frame alone always passes).
pub const MAX_QUEUED_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// The vault loop's replies waiting for the writer.
pub const MAX_QUEUED_REPLIES: usize = 256;
/// Naming's frames waiting for the writer (design 0004, Bounds: the writer).
pub const MAX_QUEUED_NAMING_BYTES: usize = 8 * 1024 * 1024;

/// Counts frames read and not yet handled, and their bytes.
#[derive(Default)]
pub struct Credits {
    in_flight: Mutex<(usize, usize)>,
    freed: Condvar,
}

impl Credits {
    /// Waits for room for a frame of `len` bytes.
    fn acquire(self: &Arc<Self>, len: usize) -> Credit {
        if let Ok(mut held) = self.in_flight.lock() {
            while held.0 >= MAX_QUEUED_FRAMES
                || (held.0 > 0 && held.1 + len > MAX_QUEUED_FRAME_BYTES)
            {
                held = match self.freed.wait(held) {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
            }
            held.0 += 1;
            held.1 += len;
        }
        Credit {
            credits: Arc::clone(self),
            len,
        }
    }

    fn release(&self, len: usize) {
        if let Ok(mut held) = self.in_flight.lock() {
            held.0 = held.0.saturating_sub(1);
            held.1 = held.1.saturating_sub(len);
            self.freed.notify_one();
        }
    }
}

/// A read frame's place in [`Credits`], freed when dropped: once the event
/// loop has handled the frame, or the naming thread a message it forwarded.
pub struct Credit {
    credits: Arc<Credits>,
    len: usize,
}

impl Drop for Credit {
    fn drop(&mut self) {
        self.credits.release(self.len);
    }
}

/// One producer's share of the writer: the frames it has queued and the
/// writer hasn't written yet.
pub struct Allowance {
    held: Mutex<(usize, usize)>,
    max_frames: usize,
    max_bytes: usize,
    /// Set by a refusal; the next release then calls `wake`.
    refused: AtomicBool,
    wake: Mutex<Option<Box<dyn Fn() + Send>>>,
}

impl Allowance {
    pub fn new(max_frames: usize, max_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            held: Mutex::new((0, 0)),
            max_frames,
            max_bytes,
            refused: AtomicBool::new(false),
            wake: Mutex::new(None),
        })
    }

    /// What to call when room frees up after a refusal.
    pub fn on_room(&self, wake: impl Fn() + Send + 'static) {
        if let Ok(mut slot) = self.wake.lock() {
            *slot = Some(Box::new(wake));
        }
    }

    /// Room for a frame of `len` bytes, or `None` when the producer has
    /// used its share (a frame alone always fits).
    pub fn take(self: &Arc<Self>, len: usize) -> Option<Hold> {
        let mut held = self.held.lock().ok()?;
        if held.0 > 0 && (held.0 >= self.max_frames || held.1 + len > self.max_bytes) {
            self.refused.store(true, Ordering::SeqCst);
            return None;
        }
        held.0 += 1;
        held.1 += len;
        Some(Hold {
            allowance: Arc::clone(self),
            len,
        })
    }

    /// The bytes this producer has queued and the writer hasn't written.
    pub fn held_bytes(&self) -> usize {
        self.held.lock().map_or(0, |held| held.1)
    }

    /// Room for a frame however full the share is: for the shutdown drain,
    /// which time bounds instead.
    pub fn force(self: &Arc<Self>, len: usize) -> Hold {
        if let Ok(mut held) = self.held.lock() {
            held.0 += 1;
            held.1 += len;
        }
        Hold {
            allowance: Arc::clone(self),
            len,
        }
    }

    fn release(&self, len: usize) {
        if let Ok(mut held) = self.held.lock() {
            held.0 = held.0.saturating_sub(1);
            held.1 = held.1.saturating_sub(len);
        }
        if self.refused.swap(false, Ordering::SeqCst)
            && let Ok(wake) = self.wake.lock()
            && let Some(wake) = wake.as_ref()
        {
            wake();
        }
    }
}

/// A queued frame's place in its producer's [`Allowance`], freed once the
/// writer has written it.
pub struct Hold {
    allowance: Arc<Allowance>,
    len: usize,
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.allowance.release(self.len);
    }
}

/// A frame for the writer, with its place in its producer's allowance.
pub struct Out {
    pub frame: Zeroizing<Vec<u8>>,
    pub hold: Hold,
}

/// Reports a thread that ends by panicking.
pub struct DeathNotice {
    events: Sender<Event>,
    name: &'static str,
}

impl DeathNotice {
    pub fn new(events: Sender<Event>, name: &'static str) -> Self {
        DeathNotice { events, name }
    }
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
                        let credit = credits.acquire(frame.payload.len());
                        if events.send(Event::Frame(frame, credit)).is_err() {
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

/// The writer's handles: its queue, bounded by each producer's
/// [`Allowance`], and a signal when it finishes.
pub struct Writer {
    pub queue: Sender<Out>,
    pub done: Receiver<()>,
}

/// Writes framed messages to stdout, in order, until the queue closes.
pub fn spawn_writer(events: Sender<Event>) -> std::io::Result<Writer> {
    let (queue, frames) = mpsc::channel::<Out>();
    let (done_tx, done) = mpsc::channel();
    std::thread::Builder::new()
        .name("stdout".into())
        .spawn(move || {
            let _notice = DeathNotice {
                events: events.clone(),
                name: "stdout",
            };
            let mut stdout = std::io::stdout().lock();
            for Out { frame, hold } in frames {
                if stdout
                    .write_all(&frame)
                    .and_then(|()| stdout.flush())
                    .is_err()
                {
                    let _ = events.send(Event::WriterFailed);
                    return;
                }
                // Written: its place in the producer's allowance is free.
                drop(hold);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_allowance_refuses_past_its_share_and_wakes_once_freed() {
        let allowance = Allowance::new(usize::MAX, 10);
        let woken = Arc::new(Mutex::new(0));
        let count = Arc::clone(&woken);
        allowance.on_room(move || *count.lock().unwrap() += 1);
        let first = allowance.take(8).unwrap();
        assert!(allowance.take(3).is_none());
        // Freed after a refusal: one wake.
        drop(first);
        assert_eq!(*woken.lock().unwrap(), 1);
        // A frame alone always fits, whatever its size.
        let big = allowance.take(64).unwrap();
        let small = allowance.take(1);
        assert!(small.is_none());
        drop(big);
        assert_eq!(*woken.lock().unwrap(), 2);
        let frames = Allowance::new(1, usize::MAX);
        let _one = frames.take(1).unwrap();
        assert!(frames.take(1).is_none());
    }

    #[test]
    fn credits_bound_bytes_as_well_as_frames() {
        let credits = Arc::new(Credits::default());
        let big = credits.acquire(MAX_QUEUED_FRAME_BYTES);
        let waiter = {
            let credits = Arc::clone(&credits);
            std::thread::spawn(move || drop(credits.acquire(1)))
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!waiter.is_finished(), "the next frame waits for room");
        drop(big);
        waiter.join().unwrap();
    }
}
