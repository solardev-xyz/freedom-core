//! The connection's side (design 0014, "Methods main calls"): what the
//! reader thread does with main's frames. It never blocks and never calls
//! into the C core: requests go to the verifier thread, which starts with
//! `colibri.hello`.

use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::conn::{Connection, End, Hello, Request, Service};
use fc_service::log;
use fc_service::panic::{TaskKind, with_kind};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::exec::Queue;
use crate::request::Params;
use crate::shared::{NotTaken, Shared};
use crate::verifier::{self, Job};
use crate::{CLIENT_VERSION, COLIBRI_VERSION};

pub struct ColibriService {
    shared: Arc<Shared>,
    queue: Arc<Queue<Job>>,
    verifier: Mutex<Option<JoinHandle<()>>>,
    /// Confinement's report, for `hello`.
    confinement: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Forget {
    client: String,
}

impl ColibriService {
    pub fn new(shared: Arc<Shared>, confinement: Value) -> ColibriService {
        ColibriService {
            shared,
            queue: Queue::new(),
            verifier: Mutex::new(None),
            confinement,
        }
    }

    /// Starts the verifier thread with the first request, which hands the
    /// service the connection (`hello` doesn't, and no thread may start
    /// before confinement). False if it can't start.
    fn start_verifier(&self, conn: &Connection) -> bool {
        let mut verifier = self.verifier.lock().unwrap_or_else(PoisonError::into_inner);
        if verifier.is_some() {
            return true;
        }
        let (conn, shared, queue) = (
            conn.clone(),
            Arc::clone(&self.shared),
            Arc::clone(&self.queue),
        );
        let spawned = std::thread::Builder::new()
            .name("verifier".into())
            .spawn(move || {
                with_kind(TaskKind::named("verifier"), || {
                    verifier::run(conn, shared, queue)
                })
            });
        match spawned {
            Ok(handle) => {
                *verifier = Some(handle);
                true
            }
            Err(e) => {
                log::error(
                    "the verifier thread didn't start",
                    json!({ "error": e.kind().to_string() }),
                );
                false
            }
        }
    }

    fn refuse(conn: &Connection, id: u64, code: ErrorCode, message: &str) {
        let _ = conn.reply_error(id, &ErrorBody::new(code, message));
    }
}

impl Service for ColibriService {
    fn hello(&self, _hello: &Hello) -> Result<Map<String, Value>, ErrorBody> {
        let mut result = Map::new();
        result.insert("colibri_version".into(), json!(COLIBRI_VERSION));
        // main.rs checked at start that the linked C core reports it.
        result.insert("client_version".into(), json!(CLIENT_VERSION));
        result.insert("chain_id".into(), json!(self.shared.chain_id));
        result.insert(
            "build".into(),
            json!({ "op": false, "zk": true, "prover": false, "verify_flags": crate::request::VERIFY_FLAGS }),
        );
        result.insert("network".into(), json!("offline"));
        result.insert("confinement".into(), self.confinement.clone());
        Ok(result)
    }

    fn request(&self, conn: &Connection, request: Request<'_>) {
        if !self.start_verifier(conn) {
            return Self::refuse(
                conn,
                request.id,
                ErrorCode::Internal,
                "the verifier thread didn't start",
            );
        }
        let params = request.params.map_or("null", |p| p.get());
        match request.method {
            "colibri.request" => {
                let params: Params = match serde_json::from_str(params) {
                    Ok(params) => params,
                    Err(_) => {
                        return Self::refuse(
                            conn,
                            request.id,
                            ErrorCode::InvalidArgument,
                            "colibri.request's params don't parse",
                        );
                    }
                };
                match self.shared.take_request() {
                    Ok(()) => self.queue.push(Job::Request {
                        id: request.id,
                        params,
                    }),
                    Err(NotTaken::Full) => Self::refuse(
                        conn,
                        request.id,
                        ErrorCode::Busy,
                        "the open requests are at their bound",
                    ),
                    Err(NotTaken::Recycling) => {
                        Self::refuse(conn, request.id, ErrorCode::Busy, "recycling")
                    }
                }
            }
            "colibri.forget" => match serde_json::from_str::<Forget>(params) {
                Ok(Forget { client }) => {
                    self.queue.push(Job::Forget { client });
                    let _ = conn.reply(request.id, &json!({}));
                }
                Err(_) => Self::refuse(
                    conn,
                    request.id,
                    ErrorCode::InvalidArgument,
                    "colibri.forget's params don't parse",
                ),
            },
            "colibri.stats" => {
                let _ = conn.reply(request.id, &self.shared.stats());
            }
            "colibri.checkpoint" => Self::refuse(
                conn,
                request.id,
                ErrorCode::InvalidArgument,
                "colibri.checkpoint is the checkpoint process's",
            ),
            _ => Self::refuse(conn, request.id, ErrorCode::UnknownMethod, "unknown method"),
        }
    }

    fn cancel(&self, _conn: &Connection, id: u64) {
        self.queue.push(Job::Cancel { id });
    }

    fn end(&self, _conn: &Connection, end: End) {
        self.queue.push(Job::End);
        let handle = self
            .verifier
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(handle) = handle
            && handle.join().is_err()
        {
            log::error("the verifier thread panicked", json!({}));
        }
        log::info("connection ended", json!({ "end": end.name() }));
    }
}
