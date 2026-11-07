//! The writes (design 0008, "Writes", "Methods" and "Profiles without a
//! vault"): `rad.write`, today's four COB writes, and `rad.unseed`, each on
//! the write queue with its 60 s deadline from admission
//! ([`crate::pools`]).
//!
//! **`rad.write { op, args }`** takes today's arguments, and answers
//! today's result:
//! - `create_issue`, `{ rid, title, description, labels }`: `{ id }`;
//! - `comment_issue`, `{ rid, issue_id, body, reply_to }`, `reply_to`
//!   optional or null: `{ id }`;
//! - `edit_issue_state`, `{ rid, issue_id, state }`, `state` one of `open`,
//!   `closed` and `solved`: `{ id, state }`;
//! - `comment_patch`, `{ rid, revision_id, body }`: `{ id }`.
//!
//! The COB writes take the node shared: libradicle's calls take `&self`.
//!
//! **`rad.unseed { rid }`** answers `{ unseeded }`, with the node held
//! exclusively, as libradicle's `unseed_repo` takes `&mut self`. It is
//! refused neither under a throwaway key, since seeding works on any
//! profile, nor for a quarantined repository: unseeding changes the
//! policy, not the record (0008, "The escape").
//!
//! **Before the mutation-start boundary, each refusal is definitive,** in
//! this order, and nothing ran:
//! 1. the pool's own: `stopped` before `RUNNING` and from the stop on, and
//!    `busy` past its bounds;
//! 2. params that don't parse, read at admission and answered by the work:
//!    `invalid_argument`. That is a RID, a COB ID (6 to 40 lowercase hex,
//!    as libradicle checks it), a title or a label Radicle doesn't take,
//!    or another state. So none of libradicle's own checks of them fails
//!    past the boundary;
//! 3. `rad.write` on a node with a throwaway key: `needs_vault` (main
//!    refuses it first, by the generation's identity);
//! 4. `rad.write` to a repository its gate doesn't hold open: `quarantined`,
//!    with `data.kind` and `data.step` from the record
//!    ([`crate::quarantine::refusal`]), or `stopped` for one whose online
//!    repair couldn't go on, which stays closed until the next start.
//!    Writes to a repository being repaired wait behind its repair in the
//!    write queue ([`crate::pools`]), so they reach this check once it is
//!    over. Otherwise the write holds a pass of the gate's
//!    (`Purpose::Mutate`) until its call returns, so a close of the
//!    repository waits for it;
//! 5. main's cancel, the deadline or the stop: `cancelled`, `deadline` or
//!    `stopped`, decided at the boundary ([`crate::pools::Ticket::begin`]).
//!
//! **Past it, only a success is proven.** A libradicle error is
//! `outcome_unknown`, its text logged with the code and never with the
//! write's content; and the pool answers a panic, main's cancel, the
//! deadline, the stop and the node's end so. A COB write commits a git
//! object, moves a ref, re-signs `rad/sigrefs`, updates the COB cache and
//! announces: an error at a later step doesn't prove that an earlier one
//! didn't commit. Such a COB write has its repository repaired online as
//! its call returns ([`crate::repair`]); the dirty marker stays until that
//! repair is over, and after a stop before it, for the next start's
//! reconciliation ([`crate::node`]). `rad.unseed` changes the seeding
//! policy, which no repair checks: one whose outcome is unknown keeps the
//! marker for the run.
//!
//! **Each write names its repository** as it is admitted
//! ([`crate::pools::Mutates`]), so that it waits behind that repository's
//! online repair.

use std::path::Path;
use std::str::FromStr as _;
use std::sync::Arc;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::conn::Connection;
use fc_service::log;
use radicle::node::gate::RepoState;
use radicle::prelude::RepoId;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::value::RawValue;
use serde_json::{Value, json};

use crate::node::Node;
use crate::pools::{self, Mutates, Ticket, Work};
use crate::{quarantine, testhooks};

/// `rad.write`'s params.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteParams {
    op: String,
    args: Value,
}

/// `create_issue`'s args.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateIssue {
    rid: String,
    title: String,
    description: String,
    labels: Vec<String>,
}

/// `comment_issue`'s args.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommentIssue {
    rid: String,
    issue_id: String,
    body: String,
    #[serde(default)]
    reply_to: Option<String>,
}

/// `edit_issue_state`'s args.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EditIssueState {
    rid: String,
    issue_id: String,
    state: String,
}

/// `comment_patch`'s args.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommentPatch {
    rid: String,
    revision_id: String,
    body: String,
}

/// `rad.unseed`'s params.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnseedParams {
    rid: String,
}

/// A COB write, checked.
enum Op {
    CreateIssue {
        title: String,
        description: String,
        labels: Vec<String>,
    },
    CommentIssue {
        issue_id: String,
        body: String,
        reply_to: Option<String>,
    },
    EditIssueState {
        issue_id: String,
        state: &'static str,
    },
    CommentPatch {
        revision_id: String,
        body: String,
    },
}

impl Op {
    fn name(&self) -> &'static str {
        match self {
            Op::CreateIssue { .. } => "create_issue",
            Op::CommentIssue { .. } => "comment_issue",
            Op::EditIssueState { .. } => "edit_issue_state",
            Op::CommentPatch { .. } => "comment_patch",
        }
    }
}

/// `rad.write`'s params, checked.
struct Write {
    rid: RepoId,
    op: Op,
}

fn invalid(message: &str) -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidArgument, message)
}

fn parse<T: DeserializeOwned>(params: Option<&RawValue>) -> Option<T> {
    params.and_then(|raw| serde_json::from_str(raw.get()).ok())
}

fn args<T: DeserializeOwned>(args: Value, takes: &str) -> Result<T, ErrorBody> {
    serde_json::from_value(args).map_err(|_| invalid(takes))
}

fn rid(rid: &str) -> Result<RepoId, ErrorBody> {
    RepoId::from_str(rid).map_err(|_| invalid("rid isn't a repository ID"))
}

/// A COB ID as libradicle checks it: 6 to 40 lowercase hex digits.
fn cob_id(id: &str, what: &str) -> Result<(), ErrorBody> {
    let hex = id
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if (6..=40).contains(&id.len()) && hex {
        Ok(())
    } else {
        Err(invalid(&format!("{what} isn't a COB ID")))
    }
}

/// `rad.write`'s params, checked as libradicle would check them past the
/// boundary.
fn write_params(params: Option<&RawValue>) -> Result<Write, ErrorBody> {
    let WriteParams { op, args: given } =
        parse(params).ok_or_else(|| invalid("rad.write takes { op, args }"))?;
    match op.as_str() {
        "create_issue" => {
            let a: CreateIssue = args(
                given,
                "create_issue takes { rid, title, description, labels }",
            )?;
            radicle::cob::Title::new(&a.title)
                .map_err(|_| invalid("the title isn't one Radicle takes"))?;
            for label in &a.labels {
                radicle::cob::Label::new(label)
                    .map_err(|_| invalid("a label isn't one Radicle takes"))?;
            }
            Ok(Write {
                rid: rid(&a.rid)?,
                op: Op::CreateIssue {
                    title: a.title,
                    description: a.description,
                    labels: a.labels,
                },
            })
        }
        "comment_issue" => {
            let a: CommentIssue = args(
                given,
                "comment_issue takes { rid, issue_id, body, reply_to }",
            )?;
            cob_id(&a.issue_id, "issue_id")?;
            if let Some(reply_to) = &a.reply_to {
                cob_id(reply_to, "reply_to")?;
            }
            Ok(Write {
                rid: rid(&a.rid)?,
                op: Op::CommentIssue {
                    issue_id: a.issue_id,
                    body: a.body,
                    reply_to: a.reply_to,
                },
            })
        }
        "edit_issue_state" => {
            let a: EditIssueState = args(given, "edit_issue_state takes { rid, issue_id, state }")?;
            cob_id(&a.issue_id, "issue_id")?;
            let state = match a.state.as_str() {
                "open" => "open",
                "closed" => "closed",
                "solved" => "solved",
                _ => return Err(invalid("state is one of open, closed and solved")),
            };
            Ok(Write {
                rid: rid(&a.rid)?,
                op: Op::EditIssueState {
                    issue_id: a.issue_id,
                    state,
                },
            })
        }
        "comment_patch" => {
            let a: CommentPatch = args(given, "comment_patch takes { rid, revision_id, body }")?;
            cob_id(&a.revision_id, "revision_id")?;
            Ok(Write {
                rid: rid(&a.rid)?,
                op: Op::CommentPatch {
                    revision_id: a.revision_id,
                    body: a.body,
                },
            })
        }
        _ => Err(invalid(
            "op is one of create_issue, comment_issue, edit_issue_state and comment_patch",
        )),
    }
}

fn refuse(conn: &Connection, id: u64, error: &ErrorBody) {
    let _ = conn.reply_error(id, error);
}

fn not_running() -> ErrorBody {
    ErrorBody::new(ErrorCode::Stopped, "the Radicle node is not running")
}

fn needs_vault() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::NeedsVault,
        "the node runs with a throwaway key: publishing needs a vault",
    )
}

/// The refusal of a write, or a clone ([`crate::network`]), to `rid`,
/// whose state at the gate isn't open.
pub(crate) fn closed(home: &Path, rid: RepoId, state: RepoState) -> ErrorBody {
    match state {
        RepoState::Quarantined(kind) => quarantine::refusal(home, rid, kind),
        // Writes wait behind a repair in progress: one still being
        // repaired here is one whose repair couldn't go on. And open, if it
        // opened since.
        RepoState::Repairing | RepoState::Open => {
            ErrorBody::new(ErrorCode::Stopped, "the repository is being repaired")
        }
    }
}

/// Past the boundary, libradicle's error: `outcome_unknown`, its text
/// logged with the code, never the write's content.
fn failed_past_start(conn: &Connection, id: u64, op: &str, rid: RepoId, e: &libradicle::Error) {
    let why = "libradicle's call failed";
    if conn.reply_error(id, &pools::outcome_unknown(why)).is_ok() {
        pools::unknown_logged(id, why);
    }
    log::error(
        "a write failed past its start",
        json!({
            "id": id,
            "code": "outcome_unknown",
            "op": op,
            "rid": rid.to_string(),
            "error": e.to_string(),
        }),
    );
}

/// The COB write itself, past the boundary.
fn call(node: &libradicle::Embedded, rid: RepoId, op: Op) -> Result<Value, libradicle::Error> {
    match op {
        Op::CreateIssue {
            title,
            description,
            labels,
        } => node
            .create_issue(rid, &title, &description, labels)
            .map(|id| json!({ "id": id })),
        Op::CommentIssue {
            issue_id,
            body,
            reply_to,
        } => node
            .comment_issue(rid, &issue_id, &body, reply_to.as_deref())
            .map(|id| json!({ "id": id })),
        Op::EditIssueState { issue_id, state } => node
            .edit_issue_state(rid, &issue_id, state)
            .map(|id| json!({ "id": id, "state": state })),
        Op::CommentPatch { revision_id, body } => node
            .comment_patch(rid, &revision_id, &body)
            .map(|id| json!({ "id": id })),
    }
}

/// `rad.write`'s work, for its request's `params`, on `node`, whose home is
/// `home`; `ephemeral`: the node runs with a throwaway key. And the
/// repository it writes to, if its params name one: an outcome it leaves
/// unknown is repaired online.
pub fn write(
    conn: &Connection,
    node: &Arc<Node>,
    home: &Path,
    params: Option<&RawValue>,
    ephemeral: bool,
) -> (Work, Option<Mutates>) {
    let write = write_params(params);
    let mutates = write.as_ref().ok().map(|write| Mutates {
        rid: write.rid,
        repaired: true,
    });
    let (conn, node, home) = (conn.clone(), node.clone(), home.to_path_buf());
    let work: Work = Box::new(move |ticket: &Ticket| {
        let Write { rid, op } = match write {
            Ok(write) => write,
            Err(error) => return refuse(&conn, ticket.id, &error),
        };
        if ephemeral {
            return refuse(&conn, ticket.id, &needs_vault());
        }
        let Some(handle) = node.handle() else {
            return refuse(&conn, ticket.id, &not_running());
        };
        // Held until the call returns: a close of the repository waits.
        let Some(_pass) = handle.repositories.enter(rid) else {
            let state = handle.repositories.state(&rid);
            return refuse(&conn, ticket.id, &closed(&home, rid, state));
        };
        let embedded = handle.node();
        testhooks::hold_work(&ticket.cancel);
        if !ticket.begin() {
            // Answered, or being answered: nothing started.
            return;
        }
        testhooks::at_write_start();
        let name = op.name();
        let called = call(&embedded, rid, op);
        testhooks::at_write_call_end();
        match called {
            Ok(result) => {
                ticket.proven();
                let _ = conn.reply(ticket.id, &result);
            }
            Err(e) => failed_past_start(&conn, ticket.id, name, rid, &e),
        }
        testhooks::at_write_end();
    });
    (work, mutates)
}

/// `rad.unseed`'s work, for its request's `params`, on `node`. And the
/// repository it unseeds, if its params name one: no repair checks a
/// policy, so an outcome it leaves unknown isn't repaired online.
pub fn unseed(
    conn: &Connection,
    node: &Arc<Node>,
    params: Option<&RawValue>,
) -> (Work, Option<Mutates>) {
    let unseeding = parse::<UnseedParams>(params)
        .ok_or_else(|| invalid("rad.unseed takes { rid }"))
        .and_then(|params| rid(&params.rid));
    let mutates = unseeding.as_ref().ok().map(|rid| Mutates {
        rid: *rid,
        repaired: false,
    });
    let (conn, node) = (conn.clone(), node.clone());
    let work: Work = Box::new(move |ticket: &Ticket| {
        let rid = match unseeding {
            Ok(rid) => rid,
            Err(error) => return refuse(&conn, ticket.id, &error),
        };
        let Some(handle) = node.handle() else {
            return refuse(&conn, ticket.id, &not_running());
        };
        let mut embedded = handle.node_mut();
        testhooks::hold_work(&ticket.cancel);
        if !ticket.begin() {
            return;
        }
        testhooks::at_write_start();
        let called = embedded.unseed_repo(rid);
        testhooks::at_write_call_end();
        match called {
            Ok(unseeded) => {
                ticket.proven();
                let _ = conn.reply(ticket.id, &json!({ "unseeded": unseeded }));
            }
            Err(e) => failed_past_start(&conn, ticket.id, "unseed", rid, &e),
        }
        testhooks::at_write_end();
    });
    (work, mutates)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const RID: &str = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5";

    fn checked(op: &str, args: Value) -> Result<Write, ErrorBody> {
        let raw = serde_json::value::to_raw_value(&json!({ "op": op, "args": args })).unwrap();
        write_params(Some(&raw))
    }

    fn code(checked: Result<Write, ErrorBody>) -> Option<ErrorCode> {
        checked.err().map(|e| e.code)
    }

    #[test]
    fn each_op_takes_todays_args() {
        let ok = [
            (
                "create_issue",
                json!({ "rid": RID, "title": "A title", "description": "", "labels": ["bug"] }),
            ),
            (
                "comment_issue",
                json!({ "rid": RID, "issue_id": "abcdef", "body": "", "reply_to": null }),
            ),
            (
                "comment_issue",
                json!({ "rid": RID, "issue_id": "abcdef", "body": "", "reply_to": "0123456789" }),
            ),
            (
                "comment_issue",
                json!({ "rid": RID, "issue_id": "abcdef", "body": "" }),
            ),
            (
                "edit_issue_state",
                json!({ "rid": RID, "issue_id": "abcdef", "state": "solved" }),
            ),
            (
                "comment_patch",
                json!({ "rid": RID, "revision_id": "abcdef", "body": "" }),
            ),
        ];
        for (op, args) in ok {
            let write = checked(op, args.clone());
            assert!(write.is_ok(), "{op} {args}");
            assert_eq!(write.ok().map(|w| w.op.name()), Some(op));
        }
    }

    /// Everything libradicle would refuse of the params is refused before
    /// the boundary: past it, a refusal would be `outcome_unknown`.
    #[test]
    fn what_libradicle_would_refuse_is_invalid_before_the_boundary() {
        let id40 = "a".repeat(40);
        let id41 = "a".repeat(41);
        let bad = [
            (
                "create_issue",
                json!({ "rid": "rad:nope", "title": "t", "description": "", "labels": [] }),
            ),
            (
                "create_issue",
                json!({ "rid": RID, "title": "", "description": "", "labels": [] }),
            ),
            (
                "create_issue",
                json!({ "rid": RID, "title": "two\nlines", "description": "", "labels": [] }),
            ),
            (
                "create_issue",
                json!({ "rid": RID, "title": "t", "description": "", "labels": [""] }),
            ),
            (
                "create_issue",
                json!({ "rid": RID, "title": "t", "description": "" }),
            ),
            (
                "create_issue",
                json!({ "rid": RID, "title": "t", "description": "", "labels": [], "x": 1 }),
            ),
            (
                "comment_issue",
                json!({ "rid": RID, "issue_id": "abcde", "body": "" }),
            ),
            (
                "comment_issue",
                json!({ "rid": RID, "issue_id": id41, "body": "" }),
            ),
            (
                "comment_issue",
                json!({ "rid": RID, "issue_id": "ABCDEF", "body": "" }),
            ),
            (
                "comment_issue",
                json!({ "rid": RID, "issue_id": "abcdef", "body": "", "reply_to": "xyz123" }),
            ),
            (
                "edit_issue_state",
                json!({ "rid": RID, "issue_id": "abcdef", "state": "Open" }),
            ),
            (
                "edit_issue_state",
                json!({ "rid": RID, "issue_id": "abcdef", "state": "merged" }),
            ),
            (
                "comment_patch",
                json!({ "rid": RID, "revision_id": "g00000", "body": "" }),
            ),
            (
                "comment_patch",
                json!({ "rid": RID, "revision_id": id40, "body": 1 }),
            ),
            ("delete_issue", json!({ "rid": RID })),
        ];
        for (op, args) in bad {
            assert_eq!(
                code(checked(op, args.clone())),
                Some(ErrorCode::InvalidArgument),
                "{op} {args}"
            );
        }
        for params in [json!({}), json!({ "op": "create_issue" }), json!([1])] {
            let raw = serde_json::value::to_raw_value(&params).unwrap();
            assert_eq!(
                code(write_params(Some(&raw))),
                Some(ErrorCode::InvalidArgument)
            );
        }
        assert_eq!(code(write_params(None)), Some(ErrorCode::InvalidArgument));
    }
}
