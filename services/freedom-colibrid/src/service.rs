//! The connection's side (design 0014, "Methods main calls"): what the
//! reader thread does with main's frames. It never blocks and never calls
//! into the C core: requests go to the verifier thread.

use std::sync::atomic::{AtomicBool, Ordering};
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
use crate::shared::{Mode, NotTaken, Shared};
use crate::verifier::{self, Job};
use crate::{CLIENT_VERSION, COLIBRI_VERSION};

pub struct ColibriService {
    shared: Arc<Shared>,
    queue: Arc<Queue<Job>>,
    verifier: Mutex<Option<JoinHandle<()>>>,
    /// Whether the verifier thread has the connection.
    connected: AtomicBool,
    /// Confinement's report, for `hello`.
    confinement: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Forget {
    client: String,
}

impl ColibriService {
    /// Starts the verifier thread, which gives the C core its store and
    /// checks its version before anything else calls into it; returns once
    /// it has, or why it couldn't. Call it after confinement: it is the
    /// process's first thread but the main one.
    pub fn start(shared: Arc<Shared>, confinement: Value) -> Result<ColibriService, String> {
        let queue = Queue::new();
        let (ready, outcome) = std::sync::mpsc::sync_channel(1);
        let (thread_shared, thread_queue) = (Arc::clone(&shared), Arc::clone(&queue));
        let handle = std::thread::Builder::new()
            .name("verifier".into())
            .spawn(move || {
                with_kind(TaskKind::named("verifier"), || {
                    verifier::run(thread_shared, thread_queue, ready)
                })
            })
            .map_err(|e| format!("the verifier thread didn't start: {}", e.kind()))?;
        match outcome.recv() {
            Ok(Ok(())) => Ok(ColibriService {
                shared,
                queue,
                verifier: Mutex::new(Some(handle)),
                connected: AtomicBool::new(false),
                confinement,
            }),
            Ok(Err(e)) => {
                let _ = handle.join();
                Err(e)
            }
            Err(_) => {
                let _ = handle.join();
                Err("the verifier thread ended before its setup".to_owned())
            }
        }
    }

    /// Hands the verifier thread the connection, once, with the first
    /// request (the trait gives `hello` none).
    fn connect(&self, conn: &Connection) {
        if !self.connected.swap(true, Ordering::AcqRel) {
            self.queue.push(Job::Connect(conn.clone()));
        }
    }

    fn refuse(conn: &Connection, id: u64, code: ErrorCode, message: &str) {
        let _ = conn.reply_error(id, &ErrorBody::new(code, message));
    }
}

impl Service for ColibriService {
    fn hello(&self, _hello: &Hello) -> Result<Map<String, Value>, ErrorBody> {
        let mut result = Map::new();
        // The service's own release, which main pins (0014, "Methods main
        // calls"); the C core's is `colibri_version`.
        result.insert("service_version".into(), json!(env!("CARGO_PKG_VERSION")));
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
        self.connect(conn);
        let params = request.params.map_or("null", |p| p.get());
        match request.method {
            "colibri.request" if self.shared.mode == Mode::Checkpoint => Self::refuse(
                conn,
                request.id,
                ErrorCode::InvalidArgument,
                "the checkpoint process serves colibri.checkpoint alone",
            ),
            "colibri.checkpoint" if self.shared.mode == Mode::Checkpoint => {
                let params: crate::checkpoint::Params = match serde_json::from_str(params) {
                    Ok(params) => params,
                    Err(_) => {
                        return Self::refuse(
                            conn,
                            request.id,
                            ErrorCode::InvalidArgument,
                            "colibri.checkpoint's params don't parse",
                        );
                    }
                };
                if params.deadline().is_none() {
                    return Self::refuse(
                        conn,
                        request.id,
                        ErrorCode::InvalidArgument,
                        "deadline_ms is past what the clock holds",
                    );
                }
                match self.shared.take_request() {
                    Ok(()) => self.queue.push(Job::Checkpoint {
                        id: request.id,
                        params,
                    }),
                    Err(_) => Self::refuse(
                        conn,
                        request.id,
                        ErrorCode::Busy,
                        "the checkpoint process takes one check",
                    ),
                }
            }
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
                if params.deadline().is_none() {
                    return Self::refuse(
                        conn,
                        request.id,
                        ErrorCode::InvalidArgument,
                        "deadline_ms is past what the clock holds",
                    );
                }
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
                        // `data` says so for main, which sends the request
                        // to the process's successor (0014, "Crashes,
                        // overruns and restarts").
                        let _ = conn.reply_error(
                            request.id,
                            &ErrorBody::new(ErrorCode::Busy, "recycling")
                                .with_data(json!({ "recycling": true })),
                        );
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
