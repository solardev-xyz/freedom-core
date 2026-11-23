//! The verifier thread (design 0014, "Inside the process"): the one thread
//! that calls into the C core. It runs each request as a task on
//! [`crate::exec`]'s executor, and takes the connection's jobs in order.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use fc_service::conn::Connection;

use crate::checkpoint;
use crate::exec::{Executor, Queue};
use crate::request::{self, Env, Params, TaskState};
use crate::shared::Shared;

/// What the reader thread hands the verifier thread.
pub enum Job {
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

/// Runs until [`Job::End`].
pub fn run(conn: Connection, shared: Arc<Shared>, queue: Arc<Queue<Job>>) {
    crate::testhooks::probe("verifier");
    let mut exec = Executor::new(queue);
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
        for job in exec.turn() {
            match job {
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
        states.retain(|id, _| exec.contains(*id));
    }
}
