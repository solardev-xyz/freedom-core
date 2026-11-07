//! The output budget and bounded JSON (design 0008, "Pools and budgets",
//! "JSON results" and "Bounds").
//!
//! **The output budget** ([`Budget`]) is the process's: 256 MiB
//! ([`BUDGET`]), enforced by reservation. Every byte a read holds is
//! reserved before it is allocated, and released when it is freed:
//! - a [`Reservation`] holds its bytes until it drops, or gives part of
//!   them back first ([`Reservation::release`]): a blob's is twice its size
//!   while it loads, then once until its last byte is written
//!   ([`BLOB_LOADING`]);
//! - **a reservation that doesn't fit waits,** inside its read's deadline
//!   to the head ([`Until`]). It is granted once enough is released, and is
//!   `deadline` at the deadline, or `cancelled` once its token is: main's
//!   cancel, the deadline's (the pool's timer cancels it), the stop's. The
//!   deadline is looked at before each grant once it has waited, so bytes
//!   released at or after it grant nothing; a reservation that fits at its
//!   first look waits for nothing, and is granted even at its deadline (its
//!   token, looked at first, ends the read's work past it). One larger
//!   than the whole budget never fits, and is `too_large` at once.
//!   Waiters take what fits as it is released, in no order: none keeps a
//!   place for a larger one, which can wait to its deadline.
//!
//! **A JSON read** ([`json_read`]) holds at most 64 MiB ([`JSON_READ`]), of
//! which at most 32 MiB is JSON:
//! 1. **the built data:** libradicle's walk takes the read's token and a
//!    byte budget of 32 MiB ([`BUILT`]), as [`libradicle::Bounds`]: it
//!    charges each item as it is built, its estimate the item's JSON, and
//!    stops `TooLarge` when the next one doesn't fit. It loads at most as
//!    many bytes of objects (`Bounds::loads`). The walk charges a meter of
//!    its own, with no way into this budget, so the whole of its byte budget
//!    is reserved here before it starts: never less than its items take;
//! 2. **the JSON:** the result is serialized into a [`Json`] writer. It
//!    reserves from the budget in 64 KiB steps ([`STEP`]), each before it is
//!    allocated, and fails as soon as its output would pass 32 MiB
//!    ([`JSON`]). It counts the bytes the serializer gives it, after
//!    escaping, so lossy text (an invalid byte becomes 3) and escapes (a NUL
//!    becomes 6) can't pass it;
//! 3. **the built data is dropped,** and its reservation released, once the
//!    JSON is complete;
//! 4. **the JSON is a [`Body`]** of chunks of at most 64 KiB, one data frame
//!    each, and its length, for the head. Each chunk's reservation is
//!    released as the chunk drops, once it is written.
//!
//! **Past a cap** a read is `too_large`: its built data, its JSON, or a
//! reservation larger than the budget. A JSON read's JSON is complete
//! before its head, so `too_large` is always the read's reply, never its
//! stream's abort.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::stream::MAX_DATA;
use fc_service::log;
use libradicle::{Bounds, CancelToken};
use serde_json::json;

/// The output budget: every read's bytes, process-wide (0008, "Pools and
/// budgets").
pub const BUDGET: u64 = 256 << 20;

/// The step a [`Json`] writer reserves in: one data frame.
pub const STEP: usize = MAX_DATA;

/// The most JSON one read writes.
pub const JSON: u64 = 32 << 20;

/// The most data one JSON read builds before it is serialized: what a
/// JSON read may hold beside its JSON.
pub const BUILT: u64 = 32 << 20;

/// The most one JSON read holds: its built data and its JSON.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "0008's figure, which the tests hold the caps to")
)]
pub const JSON_READ: u64 = BUILT + JSON;

/// The largest blob a read serves (`rad.blob`).
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "rad.blob uses it, a later step")
)]
pub const BLOB: u64 = 64 << 20;

/// What a blob of [`BLOB`] reserves while it loads: libgit2's buffer and
/// the service's copy.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "rad.blob uses it, a later step")
)]
pub const BLOB_LOADING: u64 = 2 * BLOB;

/// How often a reservation that waits looks at its token, which nothing
/// signals: a cancel is seen within this.
const POLL: Duration = Duration::from_millis(10);

/// A JSON read's limits: what it builds and the JSON it writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Limits {
    built: u64,
    json: u64,
}

/// 0008's.
const READ: Limits = Limits {
    built: BUILT,
    json: JSON,
};

/// Why a reservation, or a bounded write, was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// Past a cap: `size` bytes, over `limit`.
    TooLarge { size: u64, limit: u64 },
    /// The read's deadline came first.
    Deadline,
    /// The read's token was cancelled.
    Cancelled,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // libradicle's own text for its `TooLarge`.
            Refused::TooLarge { size, limit } => {
                write!(f, "{size} bytes is over the limit of {limit}")
            }
            Refused::Deadline => f.write_str("past its deadline"),
            Refused::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl Refused {
    /// The read's reply (0008, "Errors"): `too_large`, `deadline` or
    /// `cancelled`.
    pub fn error(&self) -> ErrorBody {
        let code = match self {
            Refused::TooLarge { .. } => ErrorCode::TooLarge,
            Refused::Deadline => ErrorCode::Deadline,
            Refused::Cancelled => ErrorCode::Cancelled,
        };
        ErrorBody::new(code, self.to_string())
    }
}

/// How long a reservation may wait: its read's deadline to the head, and
/// its token.
#[derive(Debug, Clone)]
pub struct Until {
    pub deadline: Instant,
    pub cancel: CancelToken,
}

impl Until {
    pub fn new(deadline: Instant, cancel: CancelToken) -> Self {
        Self { deadline, cancel }
    }
}

/// The output budget: the bytes reserved, of its total.
#[derive(Debug)]
pub struct Budget {
    total: u64,
    used: Mutex<u64>,
    /// Notified as bytes are released.
    released: Condvar,
    /// The waits begun, each counted with the lock held: once a test sees
    /// one and takes the lock, its reservation is waiting.
    #[cfg(test)]
    waits: std::sync::atomic::AtomicU64,
}

impl Budget {
    /// A budget of `total` bytes, none reserved.
    pub fn new(total: u64) -> Arc<Self> {
        Arc::new(Self {
            total,
            used: Mutex::new(0),
            released: Condvar::new(),
            #[cfg(test)]
            waits: std::sync::atomic::AtomicU64::new(0),
        })
    }

    fn lock(&self) -> MutexGuard<'_, u64> {
        self.used.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Its total: `rad.stats`'s budget limit.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// The bytes reserved now: `rad.stats`'s budget use.
    pub fn used(&self) -> u64 {
        *self.lock()
    }

    /// Reserves `bytes`, waiting for them within `until` (see the module's
    /// doc): `too_large` at once if they are more than the whole budget,
    /// `cancelled` once the token is, `deadline` at the deadline. Once it
    /// has waited, it is never granted at or after its deadline; only bytes
    /// that fit at its first look are granted then.
    pub fn reserve(self: &Arc<Self>, bytes: u64, until: &Until) -> Result<Reservation, Refused> {
        if bytes > self.total {
            return Err(Refused::TooLarge {
                size: bytes,
                limit: self.total,
            });
        }
        let mut used = self.lock();
        let mut waited = false;
        loop {
            if until.cancel.is_cancelled() {
                return Err(Refused::Cancelled);
            }
            let fits = bytes <= self.total - *used;
            // Once it has waited, the deadline comes before a grant: what is
            // released at or after it grants nothing. Only a reservation
            // that fits at its first look is granted at its deadline: it
            // waits for nothing.
            let now = Instant::now();
            if now >= until.deadline && (waited || !fits) {
                return Err(Refused::Deadline);
            }
            if fits {
                *used += bytes;
                return Ok(Reservation {
                    budget: self.clone(),
                    bytes,
                });
            }
            waited = true;
            #[cfg(test)]
            self.waits
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let within = (until.deadline - now).min(POLL);
            used = match self.released.wait_timeout(used, within) {
                Ok((used, _)) => used,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }

    /// Gives `bytes` back, and wakes the reservations that wait.
    fn give_back(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        {
            let mut used = self.lock();
            *used = used.saturating_sub(bytes);
        }
        self.released.notify_all();
    }
}

/// Bytes reserved from a [`Budget`], until it drops.
#[must_use = "a reservation is released as it drops"]
pub struct Reservation {
    budget: Arc<Budget>,
    bytes: u64,
}

impl Reservation {
    /// The bytes it holds.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Gives back `bytes` of it, or all it holds if that is less: for what
    /// it covers that is freed before the rest.
    pub fn release(&mut self, bytes: u64) {
        let bytes = bytes.min(self.bytes);
        self.bytes -= bytes;
        self.budget.give_back(bytes);
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.release(self.bytes);
    }
}

impl fmt::Debug for Reservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reservation")
            .field("bytes", &self.bytes)
            .finish()
    }
}

/// At most [`STEP`] bytes of JSON, and their reservation, allocated after
/// it.
#[derive(Debug)]
pub struct Chunk {
    bytes: Vec<u8>,
    /// Its capacity's.
    reservation: Reservation,
}

impl Chunk {
    /// Its bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// What more it takes without allocating.
    fn room(&self) -> usize {
        usize::try_from(self.reservation.bytes())
            .unwrap_or(0)
            .saturating_sub(self.bytes.len())
    }
}

/// A writer of one read's JSON, bounded (see the module's doc): it reserves
/// before it allocates, in steps of [`STEP`], and refuses the write that
/// would pass its limit. Once refused, it takes nothing more.
pub struct Json {
    budget: Arc<Budget>,
    until: Until,
    limit: u64,
    len: u64,
    chunks: VecDeque<Chunk>,
    refused: Option<Refused>,
}

impl Json {
    /// A writer of at most `limit` bytes, reserving from `budget` within
    /// `until`.
    pub fn new(budget: Arc<Budget>, until: Until, limit: u64) -> Self {
        Self {
            budget,
            until,
            limit,
            len: 0,
            chunks: VecDeque::new(),
            refused: None,
        }
    }

    /// The bytes written.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the tests look at a writer's state")
    )]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Why it refused a write, if it did.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the tests look at a writer's state")
    )]
    pub fn refused(&self) -> Option<&Refused> {
        self.refused.as_ref()
    }

    /// The bytes its chunks have allocated.
    #[cfg(test)]
    fn allocated(&self) -> usize {
        self.chunks.iter().map(|chunk| chunk.bytes.capacity()).sum()
    }

    fn refuse(&mut self, refused: Refused) -> io::Error {
        let error = io::Error::other(refused.to_string());
        self.refused = Some(refused);
        error
    }

    /// Its JSON, once `written` says how its serialization ended: the
    /// writer's own refusal first, whatever the serializer made of it.
    pub fn finish(self, written: serde_json::Result<()>) -> Result<Body, Failure> {
        self.end(written.map_err(Failure::Json))
    }

    /// Its JSON, once `composed` says how its writing ended: the writer's
    /// own refusal first, whatever the writing made of it.
    pub fn end(self, composed: Result<(), Failure>) -> Result<Body, Failure> {
        if let Some(refused) = self.refused {
            return Err(Failure::Refused(refused));
        }
        composed?;
        Ok(Body {
            chunks: self.chunks,
            bytes: self.len,
        })
    }
}

impl io::Write for Json {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(refused) = &self.refused {
            return Err(io::Error::other(refused.to_string()));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let size = self.len.saturating_add(buf.len() as u64);
        if size > self.limit {
            return Err(self.refuse(Refused::TooLarge {
                size,
                limit: self.limit,
            }));
        }
        let mut rest = buf;
        while !rest.is_empty() {
            let room = self.chunks.back().map_or(0, Chunk::room);
            if room == 0 {
                // The next step, never past the limit, reserved before it
                // is allocated.
                let left = usize::try_from(self.limit - self.len).unwrap_or(STEP);
                let step = STEP.min(left);
                match self.budget.reserve(step as u64, &self.until) {
                    Ok(reservation) => self.chunks.push_back(Chunk {
                        bytes: Vec::with_capacity(step),
                        reservation,
                    }),
                    Err(refused) => return Err(self.refuse(refused)),
                }
                continue;
            }
            let (now, later) = rest.split_at(room.min(rest.len()));
            if let Some(chunk) = self.chunks.back_mut() {
                chunk.bytes.extend_from_slice(now);
            }
            self.len += now.len() as u64;
            rest = later;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A read's JSON, complete: its chunks in order, each holding its
/// reservation until it drops.
#[derive(Debug)]
pub struct Body {
    chunks: VecDeque<Chunk>,
    bytes: u64,
}

impl Body {
    /// Its length: the head's `bytes`.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Iterator for Body {
    type Item = Chunk;

    fn next(&mut self) -> Option<Chunk> {
        self.chunks.pop_front()
    }
}

/// Why a JSON read failed.
#[derive(Debug)]
pub enum Failure {
    /// Its budget's or its caps' refusal, libradicle's `TooLarge` and
    /// `Cancelled` among them.
    Refused(Refused),
    /// libradicle's other errors, for the operation to answer: `not_found`
    /// or `failed` (0008, "Errors").
    Radicle(libradicle::Error),
    /// The serializer's own error, not the writer's.
    Json(serde_json::Error),
    /// The op's own answer: a composed op's (`readme_at`'s "no readme").
    Answered(ErrorBody),
    /// A text that isn't what libradicle's serializer writes, as a
    /// composition reads it: never expected. By what it was.
    Internal(&'static str),
}

impl Failure {
    /// The read's reply: [`Refused::error`] for a refusal, `radicle`'s for
    /// libradicle's other errors, and `internal` for the serializer's.
    pub fn error(self, radicle: impl FnOnce(libradicle::Error) -> ErrorBody) -> ErrorBody {
        match self {
            Failure::Refused(refused) => refused.error(),
            Failure::Radicle(error) => radicle(error),
            Failure::Json(error) => {
                // Its category alone: never what was being written.
                log::error(
                    "a read's JSON could not be serialized",
                    json!({ "category": format!("{:?}", error.classify()) }),
                );
                ErrorBody::new(ErrorCode::Internal, "Internal error")
            }
            Failure::Answered(error) => error,
            Failure::Internal(what) => {
                log::error(
                    "a read's JSON could not be composed",
                    json!({ "category": what }),
                );
                ErrorBody::new(ErrorCode::Internal, "Internal error")
            }
        }
    }
}

impl From<libradicle::Error> for Failure {
    fn from(error: libradicle::Error) -> Self {
        match error {
            libradicle::Error::TooLarge { size, limit } => {
                Failure::Refused(Refused::TooLarge { size, limit })
            }
            libradicle::Error::Cancelled => Failure::Refused(Refused::Cancelled),
            error => Failure::Radicle(error),
        }
    }
}

impl From<Refused> for Failure {
    fn from(refused: Refused) -> Self {
        Failure::Refused(refused)
    }
}

/// A JSON read within 0008's limits (see the module's doc): `build` walks
/// within the [`Bounds`] it is given, and `write` serializes what it built.
pub fn json_read<T>(
    budget: &Arc<Budget>,
    until: &Until,
    build: impl FnOnce(&Bounds) -> Result<T, libradicle::Error>,
    write: impl FnOnce(&mut Json, &T) -> serde_json::Result<()>,
) -> Result<Body, Failure> {
    json_read_within(READ, budget, until, build, write)
}

fn json_read_within<T>(
    limits: Limits,
    budget: &Arc<Budget>,
    until: &Until,
    build: impl FnOnce(&Bounds) -> Result<T, libradicle::Error>,
    write: impl FnOnce(&mut Json, &T) -> serde_json::Result<()>,
) -> Result<Body, Failure> {
    // The walk's whole budget, before it starts.
    let built = budget.reserve(limits.built, until)?;
    let bounds = Bounds::new(until.cancel.clone(), limits.built).with_loads(limits.built);
    let value = build(&bounds)?;
    let mut json = Json::new(budget.clone(), until.clone(), limits.json);
    let written = write(&mut json, &value);
    drop(value);
    drop(built);
    json.finish(written)
}

/// A composed read within 0008's limits (`crate::reads`' composed ops):
/// everything it builds (its walks' data, the texts it composes from, and
/// its working set) within one reservation of the built budget,
/// [`BUILT`], taken before anything is built; its JSON in a [`Json`]
/// writer of at most [`JSON`]. `compose` writes it; what it built is freed
/// once it returns, and the reservation then released.
pub fn composed_read(
    budget: &Arc<Budget>,
    until: &Until,
    compose: impl FnOnce(&mut Json) -> Result<(), Failure>,
) -> Result<Body, Failure> {
    let built = budget.reserve(BUILT, until)?;
    let mut json = Json::new(budget.clone(), until.clone(), JSON);
    let composed = compose(&mut json);
    drop(built);
    json.end(composed)
}

#[cfg(test)]
mod tests;
