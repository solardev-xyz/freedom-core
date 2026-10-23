//! The service's side of the connection (design 0008, "The protocol").
//!
//! **This build:** `rad.hello` and `rad.identity` (0008, "Keys"). The node
//! never starts here, so the process never reaches `RUNNING`, and every
//! other method 0008 lists answers as a process before `RUNNING` does:
//! - `rad.reconcile` and `rad.start` before `rad.identity` has succeeded:
//!   `no_identity`, and the process ends;
//! - otherwise `stopped`.
//!
//! `rad.shutdown` is the connection's own ([`fc_service::conn`]). A method
//! 0008 doesn't list is `unknown_method`.

use std::sync::Mutex;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::conn::{Connection, End, Hello, Request, Service};
use fc_service::watchdog::Watchdog;
use fc_service::{Exit, log};
use serde_json::{Map, Value, json};

use crate::build_info;
use crate::confine::Grant;
use crate::identity::{self, Identity};

/// How the process ends after a start step it answered with an error
/// (0008: "the service answers with the error and then exits"). Main read
/// the error; this isn't a crash.
const FAILED_START: Exit = Exit::Ok;

/// The methods 0008 lists beside `rad.hello`, `rad.identity` and
/// `rad.shutdown`, which later steps implement.
const LATER: &[&str] = &[
    "rad.reconcile",
    "rad.quarantine_list",
    "rad.remove_repo",
    "rad.start",
    "rad.stats",
    "rad.read",
    "rad.blob",
    "rad.connect_seeds",
    "rad.clone",
    "rad.unseed",
    "rad.write",
    "rad.import_repo",
];

/// The methods that need the node's identity first.
const NEED_IDENTITY: &[&str] = &["rad.reconcile", "rad.start"];

pub struct RadicleService {
    identity: Identity,
    /// `rad.identity`'s deadline, armed by `rad.hello`'s reply.
    deadline: Mutex<Option<Watchdog>>,
}

impl RadicleService {
    /// The service for `grant`'s home, with the key for this start; `None`
    /// if the OS's randomness fails.
    pub fn new(grant: Grant) -> Option<Self> {
        let identity = Identity::new(&grant.home)?;
        Some(Self {
            identity,
            deadline: Mutex::new(None),
        })
    }

    fn disarm_deadline(&self) {
        if let Some(deadline) = self
            .deadline
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            deadline.disarm();
        }
    }

    /// Answers `error`, then ends the process (0008: a failed start step).
    fn fail_start(&self, conn: &Connection, id: u64, error: &ErrorBody) {
        log::error(
            "a start step failed",
            json!({ "code": serde_json::to_value(error.code).unwrap_or(Value::Null) }),
        );
        let _ = conn.reply_error(id, error);
        conn.fail(FAILED_START);
    }
}

impl Service for RadicleService {
    fn hello(&self, _hello: &Hello) -> Result<Map<String, Value>, ErrorBody> {
        let mut members = Map::new();
        members.insert("service_version".into(), env!("CARGO_PKG_VERSION").into());
        members.insert(
            "libradicle".into(),
            json!({
                "version": build_info::LIBRADICLE_VERSION,
                "git_commit": build_info::LIBRADICLE_COMMIT,
            }),
        );
        members.insert("recipient".into(), self.identity.recipient().into());
        // `rad.identity` within 30 s of this reply, or the process ends.
        let deadline = Watchdog::arm(
            "identity_deadline",
            crate::testhooks::identity_deadline(identity::DEADLINE),
            Exit::Protocol,
        );
        *self.deadline.lock().unwrap_or_else(|p| p.into_inner()) = Some(deadline);
        Ok(members)
    }

    fn request(&self, conn: &Connection, request: Request<'_>) {
        let method = request.method;
        if method == "rad.identity" {
            match self
                .identity
                .establish(request.params.map(serde_json::value::RawValue::get))
            {
                Ok(result) => {
                    self.disarm_deadline();
                    let _ = conn.reply(request.id, &result);
                }
                Err(identity::Failure(error)) => self.fail_start(conn, request.id, &error),
            }
        } else if NEED_IDENTITY.contains(&method) && !self.identity.known() {
            self.fail_start(
                conn,
                request.id,
                &ErrorBody::new(ErrorCode::NoIdentity, "rad.identity has not succeeded"),
            );
        } else if LATER.contains(&method) {
            let _ = conn.reply_error(
                request.id,
                &ErrorBody::new(ErrorCode::Stopped, "the Radicle node is not running"),
            );
        } else {
            let _ = conn.reply_error(
                request.id,
                &ErrorBody::new(ErrorCode::UnknownMethod, "unknown method"),
            );
        }
    }

    fn cancel(&self, _conn: &Connection, _id: u64) {
        // Every request is answered at once: nothing runs to cancel.
    }

    fn end(&self, _conn: &Connection, end: End) {
        self.disarm_deadline();
        log::info("connection ended", json!({ "end": end.name() }));
    }
}
