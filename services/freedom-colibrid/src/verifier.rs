//! The verifier thread (design 0014, "Inside the process"): the one thread
//! that calls into the C core. It starts right after confinement, gives the
//! C core its store and checks its version before anything else reaches the
//! C core, then runs each request as a task on [`crate::exec`]'s executor,
//! taking the connection's jobs first in every round.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::mpsc::SyncSender;

use fc_service::conn::Connection;

use crate::checkpoint;
use crate::exec::{Executor, Queue};
use crate::request::{self, Env, Params, TaskState};
use crate::shared::Shared;
use crate::store::StoreHandle;

/// What the reader thread hands the verifier thread.
pub enum Job {
    /// The connection, with the first request.
    Connect(Connection),
    /// A `colibri.request` the budget took.
    Request { id: u64, params: Params },
    /// The checkpoint process's one `colibri.checkpoint`.
    Checkpoint { id: u64, params: checkpoint::Params },
    /// Main cancelled request `id`.
    Cancel { id: u64 },
    /// `colibri.forget`: the client's ZK is back to what main sends.
    Forget { client: String },
    /// The connection ended: every context is freed, and the thread ends.
    End,
}

/// Runs until [`Job::End`]. `ready` gets the outcome of the C core's setup:
/// its store given, and its version the pinned one.
pub fn run(shared: Arc<Shared>, queue: Arc<Queue<Job>>, ready: SyncSender<Result<(), String>>) {
    crate::testhooks::probe("verifier");
    // The C core's store, before `hello` (0014): its own file store is off.
    colibri_stateless::register_storage(StoreHandle(Arc::clone(&shared.store)));
    let version = crate::client_version();
    if version != crate::CLIENT_VERSION {
        let _ = ready.send(Err(format!(
            "the linked C core reports {version}, not the pinned {}",
            crate::CLIENT_VERSION
        )));
        return;
    }
    if ready.send(Ok(())).is_err() {
        return;
    }
    let mut exec = Executor::new(queue);
    // Nothing reaches the C core before the connection: the first request
    // brings it, and the jobs behind it in the same round are kept for the
    // loop below.
    let mut carried = Vec::new();
    let conn = loop {
        let mut connected = None;
        for job in exec.wait() {
            match (job, &connected) {
                (Job::Connect(conn), None) => connected = Some(conn),
                (Job::End, None) => return,
                (job, Some(_)) => carried.push(job),
                (_, None) => {}
            }
        }
        if let Some(conn) = connected {
            break conn;
        }
    };
    let env = Rc::new(Env {
        conn,
        shared,
        timers: Rc::clone(&exec.timers),
        zk_off: RefCell::new(HashMap::new()),
        graveyard: RefCell::new(Vec::new()),
        fetches: Cell::new(0),
    });
    let mut states: HashMap<u64, Rc<TaskState>> = HashMap::new();
    loop {
        // The jobs first, each round: a cancel queued while a task's call
        // into the C core ran is seen before that task, or any other, runs
        // on.
        let jobs: Vec<Job> = if carried.is_empty() {
            exec.wait()
        } else {
            std::mem::take(&mut carried)
        };
        for job in jobs {
            match job {
                Job::Connect(_) => {}
                Job::Request { id, params } => {
                    let state = Rc::new(TaskState::default());
                    states.insert(id, Rc::clone(&state));
                    exec.spawn(
                        id,
                        Box::pin(request::run(Rc::clone(&env), id, params, state)),
                    );
                }
                Job::Checkpoint { id, params } => {
                    let state = Rc::new(TaskState::default());
                    states.insert(id, Rc::clone(&state));
                    exec.spawn(
                        id,
                        Box::pin(checkpoint::run(Rc::clone(&env), id, params, state)),
                    );
                }
                Job::Cancel { id } => {
                    if let Some(state) = states.get(&id) {
                        state.cancelled.set(true);
                        exec.wake(id);
                    }
                }
                Job::Forget { client } => {
                    env.zk_off.borrow_mut().remove(&client);
                }
                Job::End => {
                    // At exit: the open contexts, and those whose free
                    // couldn't be marked, are freed with no marker; the
                    // connection takes no events any more.
                    exec.clear();
                    env.graveyard.borrow_mut().clear();
                    return;
                }
            }
        }
        exec.run_one();
        states.retain(|id, _| exec.contains(*id));
    }
}
