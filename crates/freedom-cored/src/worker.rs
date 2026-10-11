//! The vault worker: one thread that runs the slow parts of vault operations
//! (900k-round PBKDF2, seed derivation, durable writes) off the event loop.
//! Operations are serialized, so at most one vault job runs at a time.

use std::sync::mpsc::{self, Sender, SyncSender};

use crate::serve::Event;
use crate::vault::Finished;

pub type Job = Box<dyn FnOnce() -> Finished + Send>;

/// Submits jobs to the worker thread.
pub struct Worker {
    jobs: SyncSender<(u64, Job)>,
}

impl Worker {
    pub fn spawn(events: Sender<Event>) -> std::io::Result<Worker> {
        // The vault serializes its jobs, so one slot is enough.
        let (jobs, queue) = mpsc::sync_channel::<(u64, Job)>(1);
        std::thread::Builder::new()
            .name("vault".into())
            .spawn(move || {
                let _notice = crate::transport::DeathNotice::new(events.clone(), "vault");
                for (id, job) in queue {
                    crate::testhooks::job_delay();
                    let output = job();
                    if events.send(Event::JobDone(id, output)).is_err() {
                        return;
                    }
                }
            })?;
        Ok(Worker { jobs })
    }

    /// Queues a job. False if the worker is gone.
    pub fn submit(&self, id: u64, job: Job) -> bool {
        self.jobs.send((id, job)).is_ok()
    }
}
