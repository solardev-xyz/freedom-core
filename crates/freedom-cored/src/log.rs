//! JSON-lines logging to stderr, which main forwards to its own log.
//!
//! - **Never log request or response bodies,** or parser messages that may
//!   quote them: only fixed categories, method names, IDs, durations and
//!   error codes (design 0001).
//! - **Logging never blocks the caller.** Lines go through a bounded queue to
//!   a writer thread. If main stops draining stderr, lines are dropped and
//!   counted, not waited on.

use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::Duration;

const QUEUE: usize = 1024;

static SINK: Mutex<Option<SyncSender<Vec<u8>>>> = Mutex::new(None);
static DONE: Mutex<Option<Receiver<()>>> = Mutex::new(None);
static DROPPED: AtomicU64 = AtomicU64::new(0);
/// Set once `init` has run. After that, a missing writer thread means lines
/// are dropped, never written blocking.
static INITIALIZED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Starts the writer thread. Before this, lines are written directly.
pub fn init() {
    INITIALIZED.store(true, Ordering::Relaxed);
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(QUEUE);
    let (done_tx, done_rx) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("log".into())
        .spawn(move || {
            for line in rx {
                let dropped = DROPPED.swap(0, Ordering::Relaxed);
                let mut stderr = std::io::stderr().lock();
                if dropped > 0 {
                    let _ = writeln!(
                        stderr,
                        r#"{{"level":"warn","msg":"log lines dropped","count":{dropped}}}"#
                    );
                }
                let _ = stderr.write_all(&line);
            }
            let _ = done_tx.send(());
        });
    if spawned.is_ok() {
        if let Ok(mut sink) = SINK.lock() {
            *sink = Some(tx);
        }
        if let Ok(mut done) = DONE.lock() {
            *done = Some(done_rx);
        }
    }
}

/// Flushes queued lines, waiting at most `timeout`.
pub fn finish(timeout: Duration) {
    if let Ok(mut sink) = SINK.lock() {
        sink.take();
    }
    if let Some(done) = DONE.lock().ok().and_then(|mut d| d.take()) {
        let _ = done.recv_timeout(timeout);
    }
}

fn write(level: &str, message: &str, mut fields: serde_json::Value) {
    if !fields.is_object() {
        fields = serde_json::json!({});
    }
    if let Some(map) = fields.as_object_mut() {
        map.insert("level".into(), level.into());
        map.insert("msg".into(), message.into());
    }
    let Ok(mut line) = serde_json::to_vec(&fields) else {
        return;
    };
    line.push(b'\n');
    let sink = SINK.lock().ok().and_then(|sink| sink.clone());
    match sink {
        Some(sink) => {
            if sink.try_send(line).is_err() {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
        None if INITIALIZED.load(Ordering::Relaxed) => {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
        None => {
            let _ = std::io::stderr().lock().write_all(&line);
        }
    }
}

pub fn info(message: &str, fields: serde_json::Value) {
    write("info", message, fields);
}

pub fn warn(message: &str, fields: serde_json::Value) {
    write("warn", message, fields);
}

pub fn error(message: &str, fields: serde_json::Value) {
    write("error", message, fields);
}
