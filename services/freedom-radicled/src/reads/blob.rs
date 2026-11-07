//! `rad.blob` (design 0008, "The blob API", "Ranges", "Pools and budgets",
//! "Deadlines" and "Errors"), on the read pool with its 60 s deadline to
//! the head ([`crate::pools`]): a blob's raw bytes, or a byte range of
//! them, chunked over the stream.
//!
//! **`rad.blob { rid, revision, path, range?, head_only? }`** answers a
//! head, `{ oid, size, binary, range }`, then the bytes as a body stream.
//! `range` is the range served, `{ start, end }` inclusive, or null for the
//! whole blob; `binary` is libgit2's rule (`git_blob_is_binary`, the first
//! 8000 bytes), as the add-on's `blob_at` gives it. With `head_only` the
//! head has no `binary` and nothing is loaded: it serves `HEAD`. A head
//! whose body is empty (`head_only`, or an empty blob) opens no stream.
//! Main sets the content type, from the path's extension; the head has
//! none.
//!
//! **Its params:** a RID, a revision of 40 lowercase hex digits, as main
//! checks it, and a path, as `blob_at` takes it. `range` is absent or null,
//! or one of ([`Range`]):
//! - `{ start, end }`, both inclusive, `start` at most `end`;
//! - `{ start }`, to the blob's end;
//! - `{ suffix }`, the blob's last `suffix` bytes;
//!
//! each of non-negative integers. Main parses a single `bytes=` range into
//! it, and sends none for a header of several ranges or one that doesn't
//! parse. Anything else is `invalid_argument`, as is a `head_only` that
//! isn't a boolean or null.
//!
//! **Before anything is loaded, in this order:**
//! 1. the pool's refusals, then params that don't parse, as `rad.read`'s;
//! 2. the fence ([`super::fenced`]): `rad.blob` isn't a COB op, so only a
//!    `namespace` quarantine refuses it, `quarantined`, as `blob_at`;
//! 3. the blob's header ([`header`]): its path resolved at the commit as
//!    `blob_at` resolves it, each object on the way (the commit and the
//!    trees) at most the add-on's 16 MiB (`BINDING_READ_BUDGET`), within
//!    [`WALK`] reserved from the output budget, three such objects; the
//!    blob's ID and size from its object header. Anything that isn't a blob
//!    (a directory, a submodule) is `blob_at`'s `NotABlob`; libradicle's
//!    errors are `not_found` or `failed` by today's message test, with its
//!    message where that can't name a filesystem path, as `rad.read`'s
//!    ([`super::radicle_error`]): a repository the node doesn't have is
//!    `repository not found`;
//! 4. a blob over 64 MiB ([`BLOB`]) is `too_large`, `HEAD` too;
//! 5. the range normalized against the size ([`span`]):
//!    `range_not_satisfiable`, with `data.size`, when it is outside the
//!    blob.
//!
//! **Then the bytes:** the blob is loaded with libradicle's capped read at
//! its size, within twice its size reserved ([`BLOB_LOADING`] at most;
//! never less than [`WALK`], for the walk the load makes again), as
//! libgit2's buffer and libradicle's copy both exist while it loads. The
//! range is copied out of it in chunks of at most 64 KiB, each holding its
//! own share of that reservation, and the rest is released with the
//! loaded copy: from then on the read holds its range, each chunk released
//! once it is queued.
//!
//! **The head** is queued only before the deadline, with its bytes reserved
//! until it is written; from the deadline on the reply is `deadline`. Then
//! the body, one data frame per chunk, waiting for main's credit as long as
//! main takes: no service deadline after the head, as `rad.read`'s.
//! `too_large` and `range_not_satisfiable` are always the reply, never the
//! stream's abort: both are known before the head.

use std::path::Path;
use std::sync::Arc;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::conn::Connection;
use libradicle::{BINDING_READ_BUDGET, BlobHeader, Embedded};
use radicle::prelude::RepoId;
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{Value, json};

use super::{fenced, invalid, parse, radicle_error, refuse, revision, rid, stream};
use crate::node::{Handle, Node};
use crate::output::{BLOB, BLOB_LOADING, Body, Budget, Failure, Refused, Until};
use crate::pools::{Ticket, Work};
use crate::testhooks;

/// What a blob's walk may hold: the objects on the way to it, each at most
/// the add-on's 16 MiB by its header, three at once. libradicle's walk (its
/// `blob_header_in`, at the pinned commit) keeps the commit loaded until it
/// returns, and loads each tree on the path before it drops the one above
/// it: the commit, a tree and the next one.
pub const WALK: u64 = 3 * BINDING_READ_BUDGET;

/// `rad.blob`'s params.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobParams {
    rid: String,
    revision: String,
    path: String,
    #[serde(default)]
    range: Option<RangeParam>,
    #[serde(default)]
    head_only: Option<bool>,
}

/// `range`'s three shapes, each of exactly its members.
#[derive(Deserialize)]
#[serde(untagged)]
enum RangeParam {
    Closed(Closed),
    From(From),
    Suffix(Suffix),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Closed {
    start: u64,
    end: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct From {
    start: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Suffix {
    suffix: u64,
}

/// A range, as main parses it from a single `bytes=` range (0008,
/// "Ranges").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Range {
    /// `bytes=start-end`: both inclusive, `start` at most `end`.
    Closed { start: u64, end: u64 },
    /// `bytes=start-`: to the end.
    From { start: u64 },
    /// `bytes=-suffix`: the last `suffix` bytes.
    Suffix { suffix: u64 },
}

/// A range normalized against a blob: its first and last bytes, inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: u64,
    pub end: u64,
}

/// `rad.blob`'s params, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Request {
    rid: RepoId,
    revision: String,
    path: String,
    range: Option<Range>,
    head_only: bool,
}

const TAKES: &str = "rad.blob takes { rid, revision, path, range, head_only }";
const RANGES: &str = "range is { start, end }, { start } or { suffix }, of non-negative integers, \
                      with start at most end";

/// `rad.blob`'s params, checked (see the module's doc).
fn request(params: Option<&RawValue>) -> Result<Request, ErrorBody> {
    let raw = params.ok_or_else(|| invalid(TAKES))?;
    // An object (serde would take a struct from an array too), and its
    // `range` first on its own, for its own message.
    let value: Value = serde_json::from_str(raw.get()).map_err(|_| invalid(TAKES))?;
    if !value.is_object() {
        return Err(invalid(TAKES));
    }
    if let Some(range) = value.get("range")
        && !range.is_null()
        && (!range.is_object() || serde_json::from_value::<RangeParam>(range.clone()).is_err())
    {
        return Err(invalid(RANGES));
    }
    let p: BlobParams = parse(Some(raw)).ok_or_else(|| invalid(TAKES))?;
    let range = match p.range {
        None => None,
        Some(RangeParam::Closed(Closed { start, end })) if start <= end => {
            Some(Range::Closed { start, end })
        }
        Some(RangeParam::Closed(_)) => return Err(invalid(RANGES)),
        Some(RangeParam::From(From { start })) => Some(Range::From { start }),
        Some(RangeParam::Suffix(Suffix { suffix })) => Some(Range::Suffix { suffix }),
    };
    Ok(Request {
        rid: rid(&p.rid)?,
        revision: revision(p.revision, "revision")?,
        path: p.path,
        range,
        head_only: p.head_only.unwrap_or(false),
    })
}

/// `range` normalized against a blob of `size` bytes (0008, "Ranges"):
/// `None` for the whole blob; an `end` at or past the size clamped to its
/// last byte; a suffix from `max(0, size - suffix)` to the last byte. A
/// `start` at or past the size, a suffix of 0, and any range of an empty
/// blob are `range_not_satisfiable`, with `data.size`.
pub fn span(range: Option<Range>, size: u64) -> Result<Option<Span>, ErrorBody> {
    let Some(range) = range else {
        return Ok(None);
    };
    let unsatisfiable = || {
        ErrorBody::new(
            ErrorCode::RangeNotSatisfiable,
            format!("the range is outside the blob's {size} bytes"),
        )
        .with_data(json!({ "size": size }))
    };
    let last = size.checked_sub(1).ok_or_else(unsatisfiable)?;
    let (start, end) = match range {
        Range::Closed { start, end } => (start, end.min(last)),
        Range::From { start } => (start, last),
        // A suffix of 0 starts at the size, past the last byte.
        Range::Suffix { suffix } => (size.saturating_sub(suffix), last),
    };
    if start > last {
        return Err(unsatisfiable());
    }
    Ok(Some(Span { start, end }))
}

/// What a blob of `size` bytes reserves while it loads: twice its size, as
/// libgit2's buffer and libradicle's copy both exist; never less than
/// [`WALK`], for the walk its load makes again; at most [`BLOB_LOADING`],
/// since it is at most [`BLOB`].
fn loading(size: u64) -> u64 {
    size.saturating_mul(2).clamp(WALK, BLOB_LOADING)
}

/// The blob at `path` in `revision`: its ID and size, from its object
/// header, with none of it loaded (see the module's doc).
///
/// libradicle's `blob_header` bounds none of the objects on the way to the
/// blob, so the path is resolved first by its capped read at a cap of 0:
/// it walks to the blob as `blob_at` does, each object on the way at most
/// `BINDING_READ_BUDGET`, with `blob_at`'s errors, and refuses any blob
/// that isn't empty from its header (`TooLarge` with a limit of 0) before
/// loading it. The revision is a commit ID, so `blob_header` then walks the
/// same objects, every one known to fit.
fn header(node: &Embedded, rid: RepoId, revision: &str, path: &str) -> Result<BlobHeader, Failure> {
    match node.read_blob_at_capped(rid, revision, path, 0) {
        Ok(_) | Err(libradicle::Error::TooLarge { limit: 0, .. }) => {}
        Err(e) => return Err(e.into()),
    }
    Ok(node.blob_header(rid, revision, path)?)
}

/// What a read answers before its body: the head, and the body, if it has
/// one.
struct Served {
    head: Value,
    body: Option<Body>,
}

/// The blob's head and body, within the budget (see the module's doc).
fn serve(
    handle: &Handle,
    budget: &Arc<Budget>,
    until: &Until,
    r: &Request,
) -> Result<Served, Failure> {
    let walk = budget.reserve(WALK, until)?;
    let BlobHeader { oid, size } = header(&handle.node(), r.rid, &r.revision, &r.path)?;
    drop(walk);
    if size > BLOB {
        return Err(Refused::TooLarge { size, limit: BLOB }.into());
    }
    let span = span(r.range, size).map_err(Failure::Answered)?;
    let range = span.map_or(Value::Null, |s| json!({ "start": s.start, "end": s.end }));
    if r.head_only {
        return Ok(Served {
            head: json!({ "oid": oid, "size": size, "range": range }),
            body: None,
        });
    }
    let mut held = budget.reserve(loading(size), until)?;
    let blob = handle
        .node()
        .read_blob_at_capped(r.rid, &r.revision, &r.path, size)?;
    if blob.content.len() as u64 != size {
        return Err(Failure::Internal(
            "a blob's content isn't its header's size",
        ));
    }
    let (start, end) = span.map_or((0, size), |s| (s.start, s.end + 1));
    let bytes = usize::try_from(start)
        .ok()
        .zip(usize::try_from(end).ok())
        .and_then(|(start, end)| blob.content.get(start..end))
        .ok_or(Failure::Internal("a blob's range isn't within it"))?;
    let body = (!bytes.is_empty())
        .then(|| Body::copied(bytes, &mut held))
        .transpose()?;
    let head = json!({ "oid": oid, "size": size, "binary": blob.binary, "range": range });
    // The loaded copy, and what's left of its reservation.
    drop(blob);
    drop(held);
    Ok(Served { head, body })
}

/// `rad.blob`'s work, for its request's `params`, on `node`, whose home is
/// `home`, within `budget`.
pub fn blob(
    conn: &Connection,
    node: &Arc<Node>,
    budget: &Arc<Budget>,
    home: &Path,
    params: Option<&RawValue>,
) -> Work {
    let request = request(params);
    let (conn, node, budget, home) = (
        conn.clone(),
        node.clone(),
        budget.clone(),
        home.to_path_buf(),
    );
    Box::new(move |ticket: &Ticket| {
        let r = match request {
            Ok(r) => r,
            Err(error) => return refuse(&conn, ticket, &error),
        };
        let Some(handle) = node.handle() else {
            return refuse(
                &conn,
                ticket,
                &ErrorBody::new(ErrorCode::Stopped, "the Radicle node is not running"),
            );
        };
        if let Some(error) = fenced(&home, &handle.repositories, |_| false, r.rid, false) {
            return refuse(&conn, ticket, &error);
        }
        testhooks::hold_work(&ticket.cancel);
        let until = Until::new(ticket.deadline, ticket.cancel.clone());
        let served = serve(&handle, &budget, &until, &r);
        drop(handle);
        match served {
            Ok(Served { head, body }) => stream(&conn, ticket, &budget, &until, &head, body),
            // Whoever cancelled its token answers it, as `rad.read`'s.
            Err(Failure::Refused(Refused::Cancelled)) => {}
            Err(failure) => refuse(&conn, ticket, &failure.error(radicle_error)),
        }
    })
}

#[cfg(test)]
mod tests;
