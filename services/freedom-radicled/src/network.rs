//! The network operations (design 0008, "Methods", "Deadlines", "Progress"
//! and "Errors"): `rad.connect_seeds` and `rad.clone`, on the network pool
//! (8 threads, 16 queued; [`crate::pools`]), each with its deadline from
//! admission: its own `timeout_ms` plus 30 s ([`SLACK`]).
//!
//! **`timeout_ms`** is the add-on's `u32`, as the add-on's exports take it:
//! a number that isn't an integer from 0 to 4,294,967,295 is
//! `invalid_argument`. So the deadline is at most about 49.7 days and 30 s
//! away, which no clock overflows.
//!
//! **`rad.connect_seeds { timeout_ms }`** answers today's report: the JSON
//! text libradicle's `json::seed_report` writes, byte for byte, as the
//! add-on's `connectSeeds` returns it (`attempted`, `connected`, `target`,
//! `targetReached`, `elapsedMs`, `failures`). libradicle takes no token for
//! it: main's cancel answers `cancelled` at once, and its work keeps its
//! slot until libradicle returns, within its own `timeout_ms`.
//!
//! **`rad.clone { rid, timeout_ms, progress }`** seeds `rid` and fetches it,
//! as the add-on's `cloneRepo` and `cloneRepoWithProgress` do
//! (libradicle's `clone_repo_with`, with `FetchPolicy::from_timeout`). It
//! answers `{ "ok": true }`, or `{ "cancelled": true }` for main's cancel.
//! With `progress: true` (absent or null is `false`) libradicle's progress
//! events go to main as `rad.progress` events, bounded per clone
//! ([`progress`]), and its terminal event comes before the answer.
//! - **Before its start,** each refusal is definitive: the pool's
//!   (`stopped`, `busy`); params that don't parse (`invalid_argument`, an
//!   unparsable RID with the add-on's own text); the node not running
//!   (`stopped`); a repository its gate doesn't hold open, `quarantined`
//!   with the record's `data.kind` and `data.step`, or `stopped` while it
//!   is repaired ([`crate::writes::closed`]); main's cancel, the deadline
//!   or the stop (`cancelled`, `deadline`, `stopped`).
//! - **Its start** ([`crate::pools::Ticket::claim`]) claims its request's
//!   commit point just before libradicle's call: from then on main's cancel
//!   reaches libradicle's token alone (0008: "flips its `CancelToken`,
//!   which replaces `cancelClone(rid)`"), and the answer comes as the
//!   clone actually stops: libradicle checks the token between candidates
//!   and in its handshake backoff, and a fetch in flight finishes first.
//!   The deadline answers `deadline` and the stop `stopped`, and the clone
//!   keeps its slot until libradicle returns.
//! - **Its outcome is marked:** a clone that libradicle reports cancelled
//!   (main's cancel, the deadline, the stop), one past the stop's drain and
//!   one that panicked leave the run uncertain, so the dirty marker stays
//!   (0008, "Reconciliation": "a clone or fetch that is cancelled or cut
//!   off"). One that returned `Ok`, or libradicle's error, is proven.
//! - **libradicle's errors:** `Gated` is refused as above; any other is
//!   `not_found` when today's message test matches it, else `failed`, with
//!   libradicle's text as the add-on gives it (`no seeds found for …`,
//!   `fetching … failed: …`, `fetching … timed out`).
//!
//! **No new socket:** both run through the node's own handle, whose dials
//! go through the service's dial gate ([`crate::dial`]); neither opens one
//! itself. Each takes the node's network view under the node's shared lock
//! and lets go of the lock at once, as the add-on's connects and clones
//! never held its mutex: a clone of minutes holds back no `rad.unseed`.

pub mod progress;

use std::path::Path;
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::conn::Connection;
use libradicle::{FetchPolicy, Progress};
use radicle::node::gate::RepoState;
use radicle::prelude::RepoId;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::value::RawValue;

use crate::node::Node;
use crate::pools::{Ticket, Work};
use crate::{reads, testhooks, writes};

/// What a network operation's deadline adds to its `timeout_ms` (0008,
/// "Deadlines").
pub const SLACK: Duration = Duration::from_secs(30);

/// `rad.connect_seeds`'s params.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectParams {
    timeout_ms: u32,
}

/// `rad.clone`'s params.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloneParams {
    rid: String,
    timeout_ms: u32,
    #[serde(default)]
    progress: Option<bool>,
}

/// A clone's params, checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cloning {
    rid: RepoId,
    timeout: Duration,
    progress: bool,
}

fn invalid(message: &str) -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidArgument, message)
}

/// Params as an object: serde takes a struct from an array too, which
/// none of these is.
fn parse<T: DeserializeOwned>(params: Option<&RawValue>) -> Option<T> {
    let value: serde_json::Value = serde_json::from_str(params?.get()).ok()?;
    if !value.is_object() {
        return None;
    }
    serde_json::from_value(value).ok()
}

fn refuse(conn: &Connection, id: u64, error: &ErrorBody) {
    let _ = conn.reply_error(id, error);
}

fn not_running() -> ErrorBody {
    ErrorBody::new(ErrorCode::Stopped, "the Radicle node is not running")
}

/// The deadline from admission of an operation given `timeout`: its own
/// time plus [`SLACK`]. Params that don't parse get the slack alone: their
/// work answers at once.
fn within(timeout: Option<Duration>) -> Duration {
    timeout.unwrap_or_default() + testhooks::network_slack(SLACK)
}

fn connect_params(params: Option<&RawValue>) -> Result<Duration, ErrorBody> {
    parse::<ConnectParams>(params)
        .map(|p| Duration::from_millis(p.timeout_ms.into()))
        .ok_or_else(|| invalid("rad.connect_seeds takes { timeout_ms }"))
}

/// The add-on's text for a RID that doesn't parse.
fn rid(rid: &str) -> Result<RepoId, ErrorBody> {
    RepoId::from_str(rid).map_err(|e| invalid(&format!("invalid RID {rid:?}: {e}")))
}

fn clone_params(params: Option<&RawValue>) -> Result<Cloning, ErrorBody> {
    let p = parse::<CloneParams>(params)
        .ok_or_else(|| invalid("rad.clone takes { rid, timeout_ms, progress }"))?;
    Ok(Cloning {
        rid: rid(&p.rid)?,
        timeout: Duration::from_millis(p.timeout_ms.into()),
        progress: p.progress.unwrap_or(false),
    })
}

/// The report's JSON, libradicle's own text.
fn report(report: &libradicle::SeedConnectReport) -> Option<Box<RawValue>> {
    let mut text = Vec::new();
    libradicle::json::seed_report(&mut text, report).ok()?;
    RawValue::from_string(String::from_utf8(text).ok()?).ok()
}

/// `rad.connect_seeds`'s work for its request's `params`, on `node`, and
/// its deadline from admission.
pub fn connect_seeds(
    conn: &Connection,
    node: &Arc<Node>,
    params: Option<&RawValue>,
) -> (Work, Duration) {
    let checked = connect_params(params);
    let deadline = within(checked.as_ref().ok().copied());
    let (conn, node) = (conn.clone(), node.clone());
    let work: Work = Box::new(move |ticket: &Ticket| {
        let timeout = match checked {
            Ok(timeout) => timeout,
            Err(error) => return refuse(&conn, ticket.id, &error),
        };
        let Some(handle) = node.handle() else {
            return refuse(&conn, ticket.id, &not_running());
        };
        let mut network = handle.node().network();
        drop(handle);
        testhooks::hold_work(&ticket.cancel);
        match network.connect_seed_book(timeout) {
            Ok(seeds) => match report(&seeds) {
                Some(raw) => {
                    let _ = conn.reply(ticket.id, &raw);
                }
                None => refuse(
                    &conn,
                    ticket.id,
                    &ErrorBody::new(ErrorCode::Internal, "Internal error"),
                ),
            },
            Err(e) => refuse(&conn, ticket.id, &reads::radicle_error(e)),
        }
    });
    (work, deadline)
}

/// `rad.clone`'s work for its request's `params`, on `node`, whose home is
/// `home`, its progress written through `hub`; and its deadline from
/// admission.
pub fn clone(
    conn: &Connection,
    node: &Arc<Node>,
    hub: &Arc<progress::Hub>,
    home: &Path,
    params: Option<&RawValue>,
) -> (Work, Duration) {
    let checked = clone_params(params);
    let deadline = within(checked.as_ref().ok().map(|c| c.timeout));
    let (conn, node, hub, home) = (conn.clone(), node.clone(), hub.clone(), home.to_path_buf());
    let work: Work = Box::new(move |ticket: &Ticket| {
        let clone = match checked {
            Ok(clone) => clone,
            Err(error) => return refuse(&conn, ticket.id, &error),
        };
        let Some(handle) = node.handle() else {
            return refuse(&conn, ticket.id, &not_running());
        };
        let state = handle.repositories.state(&clone.rid);
        if state != RepoState::Open {
            return refuse(&conn, ticket.id, &writes::closed(&home, clone.rid, state));
        }
        let mut network = handle.node().network();
        drop(handle);
        testhooks::hold_work(&ticket.cancel);
        if !ticket.claim() {
            // Answered, or being answered: nothing started.
            return;
        }
        let feed = clone.progress.then(|| hub.feed(ticket.id, conn.clone()));
        let mut emit = |event: Progress| {
            if let Some(feed) = &feed {
                feed.push(event);
            }
        };
        let policy = FetchPolicy::from_timeout(clone.timeout);
        let result = match testhooks::scripted_clone(clone.rid, &ticket.cancel, &mut emit) {
            Some(result) => result,
            None => network.clone_repo_with(clone.rid, &policy, &ticket.cancel, &mut emit),
        };
        // Its events, the terminal one last, before its answer.
        if let Some(feed) = &feed {
            feed.flush();
        }
        answer(&conn, ticket, &home, result);
        testhooks::at_clone_end();
    });
    (work, deadline)
}

/// What a clone answers once libradicle has returned.
#[derive(Debug, PartialEq)]
enum Outcome {
    /// Its result.
    Result(serde_json::Value),
    /// Its error.
    Error(ErrorBody),
    /// Nothing: the deadline or the stop answers it.
    Nothing,
}

/// A clone's answer for libradicle's `result` (see the module's doc), and
/// whether its outcome is proven. `main`: main cancelled it.
fn outcome(home: &Path, result: Result<(), libradicle::Error>, main: bool) -> (Outcome, bool) {
    match result {
        Ok(()) => (Outcome::Result(serde_json::json!({ "ok": true })), true),
        // Cut off: the run stays uncertain. Main's cancel is this work's to
        // answer; the deadline and the stop answer for themselves.
        Err(libradicle::Error::Cancelled) if main => (
            Outcome::Result(serde_json::json!({ "cancelled": true })),
            false,
        ),
        Err(libradicle::Error::Cancelled) => (Outcome::Nothing, false),
        Err(libradicle::Error::Gated { rid, state }) => {
            (Outcome::Error(writes::closed(home, rid, state)), true)
        }
        Err(e) => (Outcome::Error(reads::radicle_error(e)), true),
    }
}

/// A clone's answer, once libradicle has returned.
fn answer(conn: &Connection, ticket: &Ticket, home: &Path, result: Result<(), libradicle::Error>) {
    let (outcome, proven) = outcome(home, result, ticket.cancelled_by_main());
    if proven {
        ticket.proven();
    }
    match outcome {
        Outcome::Result(value) => {
            let _ = conn.reply(ticket.id, &value);
        }
        Outcome::Error(error) => refuse(conn, ticket.id, &error),
        Outcome::Nothing => {}
    }
}

#[cfg(test)]
mod tests;
