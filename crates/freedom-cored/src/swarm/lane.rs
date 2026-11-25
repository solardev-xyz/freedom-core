//! The mining lane (design 0015, "Messaging and GSOC mining" > "Mining, in
//! the core"; SWM-4 PR 8): GSOC signer searches on a thread of their own,
//! beside the swarm thread, under fc-swarm-provider's [`Lane`] rules.
//!
//! - **The rules** are the [`Lane`]'s: the cache, a join, the new-topic
//!   budget, the queue's bounds (16 waiting per site and 256 in all, then
//!   `busy`), fair turns, one job at a time, 15 s per job from its
//!   dispatch, and 256 candidates a batch.
//! - **[`Mining`]** is the swarm thread's side, which the engine holds: a
//!   request's mining ask is submitted once its charge
//!   ([`fc_swarm_provider::mining::JOB_CHARGE`]) is reserved, each
//!   [`Batch`] goes to the lane thread through the engine's `Io`, each
//!   [`Ran`] comes back through the swarm thread's mailbox, and the
//!   watchdog runs on [`Lane::deadline`], on the swarm thread's clock.
//! - **The lane thread** ([`spawn`]) runs each batch it is handed and sends
//!   its answer to the swarm thread. It starts with the first batch, as the
//!   reference's worker starts with the first job, and ends once its handle
//!   is dropped (or the swarm thread has gone) and it holds no batch.
//! - **A stuck batch:** one out for [`STUCK_MS`] ends its job
//!   `gsoc_mining_failed` (`mining lane stuck`), and the next batch goes to
//!   a fresh lane thread, the next generation. The stuck thread can't be
//!   stopped safely, so it is left: its handle is dropped, and whatever it
//!   answers is dropped, as is any answer from a thread that isn't the
//!   current one. A second stuck lane in one start turns mining off until
//!   the core restarts: every waiting job, and every later ask, ends
//!   `gsoc_mining_failed` (`mining is off until the core restarts`).
//! - **The clocks** (D14): a job's 15 s and the watchdog run on the swarm
//!   thread's monotonic clock; the new-topic budget, a budget, reads
//!   `Date.now()`, as the reference's `consumeNewTopicBudget` does. The
//!   test hooks' clock drives both (see the swarm thread's).
//!
//! [`STUCK_MS`]: fc_swarm_provider::mining::STUCK_MS

use std::sync::mpsc::{self, Sender};

use fc_json::JsString;
use fc_swarm_provider::machine::{AskId, MineJob, Mined};
use fc_swarm_provider::mining::{Batch, Lane, Ran, Submitted};

use super::engine::Ms;

/// Who waits for a search: a request and its ask.
pub type Waiter = (u64, AskId);

/// The lane's answers, each to its waiter.
pub type Answers = Vec<(Waiter, Mined)>;

/// What [`Mining::work`] gives: the answers for jobs whose time ran out
/// between batches, and the next batch, with the lane thread it goes to.
#[derive(Debug)]
pub struct Next {
    pub answers: Answers,
    pub batch: Option<(u64, Batch)>,
}

/// The swarm thread's side of the mining lane. See the module
/// documentation.
#[derive(Debug, Default)]
pub struct Mining {
    lane: Lane<Waiter>,
    /// The lane thread the batches go to: the next one after a stuck batch.
    generation: u64,
    /// A batch is out on the lane thread.
    out: bool,
    /// Batches handed out, for the test hooks.
    #[cfg(any(test, feature = "testhooks"))]
    batches: u64,
}

impl Mining {
    pub fn new() -> Self {
        Self::default()
    }

    /// A request's ask from `site`, its charge reserved: answered at once
    /// (a cache hit, the new-topic budget, `busy`, mining off), or `None`
    /// while it waits. `wall` is `Date.now()`, for the budget.
    pub fn submit(
        &mut self,
        wall: u64,
        site: &JsString,
        job: MineJob,
        waiter: Waiter,
    ) -> Option<Mined> {
        match self.lane.submit(wall, site, job, waiter) {
            Submitted::Done(mined) => Some(mined),
            Submitted::Waiting => None,
        }
    }

    /// The waiter has gone (its request's cancel or deadline): only its own
    /// wait ends; the job stops at its batch's answer when it was the last.
    pub fn cancel(&mut self, waiter: &Waiter) {
        self.lane.cancel(waiter);
    }

    /// While no batch is out: the jobs whose time ran out between batches,
    /// and the next batch.
    pub fn work(&mut self, now: Ms) -> Next {
        if self.out {
            return Next {
                answers: Vec::new(),
                batch: None,
            };
        }
        let work = self.lane.work(now);
        let batch = work.batch.map(|batch| {
            self.out = true;
            #[cfg(any(test, feature = "testhooks"))]
            {
                self.batches += 1;
            }
            (self.generation, batch)
        });
        Next {
            answers: work.answers,
            batch,
        }
    }

    /// Lane thread `generation`'s answer for a batch. An answer from a
    /// thread that isn't the current one, a stuck one's, is dropped.
    pub fn ran(&mut self, now: Ms, generation: u64, ran: Ran) -> Answers {
        if generation != self.generation || !self.out {
            return Vec::new();
        }
        self.out = false;
        self.lane.ran(now, ran)
    }

    /// When the watchdog falls due: a batch out for its second.
    pub fn due(&self) -> Option<Ms> {
        self.lane.deadline()
    }

    /// The watchdog at `now`: a batch out for its second ends its job, and
    /// the next batch goes to a fresh lane thread (none, once mining is
    /// off).
    pub fn watch(&mut self, now: Ms) -> Answers {
        if !self.due().is_some_and(|due| due <= now) {
            return Vec::new();
        }
        let watched = self.lane.watch(now);
        self.out = false;
        self.generation += 1;
        crate::log::warn(
            "swarm mining lane stuck",
            serde_json::json!({ "lanes": self.generation, "off": self.lane.off() }),
        );
        watched.answers
    }

    /// The lane's cache and budgets afresh, between the cases one core
    /// plays (D11): only while no job waits or runs, and never once mining
    /// is off, which lasts until the core restarts.
    #[cfg(any(test, feature = "testhooks"))]
    pub fn reset(&mut self) {
        if !self.out && self.lane.waiting() == 0 && !self.lane.off() {
            self.lane = Lane::new();
        }
    }

    /// The lane as it stands, for the test hooks: jobs waiting, whether a
    /// batch is out, mining off, the lane threads replaced, and the batches
    /// handed out.
    #[cfg(any(test, feature = "testhooks"))]
    pub fn state(&self) -> serde_json::Value {
        serde_json::json!({
            "waiting": self.lane.waiting(),
            "running": self.out,
            "off": self.lane.off(),
            "lane": self.generation,
            "batches": self.batches,
        })
    }
}

/// The handle of a lane thread: its batches go through it. Dropping it
/// lets the thread end once it holds no batch.
#[derive(Debug)]
pub struct Thread {
    generation: u64,
    batches: Sender<Batch>,
}

impl Thread {
    /// The generation the thread was started for.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Hands the thread a batch: false once it has gone (the watchdog then
    /// ends the job).
    pub fn run(&self, batch: Batch) -> bool {
        self.batches.send(batch).is_ok()
    }
}

/// Starts lane thread `generation`. It runs each batch it is handed (the
/// test hooks' delay or block first) and hands the answer, with its
/// generation, to `done`, until `done` refuses it (the swarm thread has
/// gone) or its handle is dropped.
pub fn spawn(
    generation: u64,
    done: impl Fn(u64, Ran) -> bool + Send + 'static,
) -> std::io::Result<Thread> {
    let (batches, rx) = mpsc::channel::<Batch>();
    std::thread::Builder::new()
        .name("swarm-mining".into())
        .spawn(move || {
            while let Ok(batch) = rx.recv() {
                crate::testhooks::swarm_mine_batch();
                if !done(generation, batch.run()) {
                    return;
                }
            }
        })?;
    Ok(Thread {
        generation,
        batches,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use std::time::Duration;

    use fc_swarm_provider::mining::{JOB_MS, STUCK_MS};

    use super::*;

    const A: &str = "https://a.example";
    const B: &str = "https://b.example";

    fn site(s: &str) -> JsString {
        JsString::from(s)
    }

    /// The GSOC search for `topic`.
    fn job(topic: &str) -> MineJob {
        fc_swarm_provider::methods::messaging::gsoc_job(topic)
    }

    fn waiter(n: u32) -> Waiter {
        (u64::from(n), AskId(u64::from(n)))
    }

    /// The lane thread's work, done here: each batch run at once at `now`
    /// until the lane idles, every answer in order.
    fn drain(mining: &mut Mining, now: Ms) -> Answers {
        let mut out = Vec::new();
        loop {
            let Next { answers, batch } = mining.work(now);
            out.extend(answers);
            let Some((lane, batch)) = batch else {
                return out;
            };
            out.extend(mining.ran(now, lane, batch.run()));
        }
    }

    /// One batch out at a time; its answer moves the job on; the topic
    /// `chat` gives bee-js's signer (the `gsoc` vectors' index 143).
    #[test]
    fn one_batch_at_a_time_finds_bee_js_signer() {
        let mut mining = Mining::new();
        assert_eq!(mining.submit(0, &site(A), job("chat"), waiter(1)), None);
        let Next { answers, batch } = mining.work(0);
        assert!(answers.is_empty());
        let (lane, batch) = batch.unwrap();
        assert_eq!(lane, 0);
        // While it is out, nothing else goes.
        assert!(mining.work(0).batch.is_none());
        assert_eq!(mining.due(), Some(STUCK_MS));
        assert_eq!(
            mining.ran(5, lane, batch.run()),
            [(waiter(1), Mined::Found(143))]
        );
        assert!(mining.work(5).batch.is_none());
        assert_eq!(mining.due(), None);
        // The cache answers it again at once.
        assert_eq!(
            mining.submit(5, &site(B), job("chat"), waiter(2)),
            Some(Mined::Found(143))
        );
    }

    /// The watchdog: a batch out for 1 s ends its job and moves the lane to
    /// the next generation, whose batches go to a fresh thread; the stuck
    /// thread's late answer is dropped. The second stuck lane turns mining
    /// off for the queue and every later ask.
    #[test]
    fn a_stuck_batch_moves_to_a_fresh_lane_then_mining_is_off() {
        let mut mining = Mining::new();
        mining.submit(0, &site(A), job("room"), waiter(1));
        mining.submit(0, &site(B), job("chat"), waiter(2));
        let (lane, stuck) = mining.work(0).batch.unwrap();
        assert!(mining.watch(STUCK_MS - 1).is_empty());
        assert_eq!(mining.watch(STUCK_MS), [(waiter(1), Mined::Stuck)]);
        // The next job goes to lane 1; lane 0's answer is dropped, though it
        // came first.
        let (fresh, next) = mining.work(STUCK_MS).batch.unwrap();
        assert_eq!((lane, fresh), (0, 1));
        assert!(mining.ran(STUCK_MS, lane, stuck.run()).is_empty());
        assert_eq!(
            mining.ran(STUCK_MS, fresh, next.run()),
            [(waiter(2), Mined::Found(143))]
        );
        // The second.
        mining.submit(2_000, &site(A), job("room"), waiter(3));
        mining.submit(2_000, &site(B), job("fast-29"), waiter(4));
        assert_eq!(mining.work(2_000).batch.unwrap().0, 1);
        assert_eq!(
            mining.watch(3_000),
            [(waiter(3), Mined::Stuck), (waiter(4), Mined::Off)]
        );
        assert!(mining.work(3_000).batch.is_none());
        assert_eq!(
            mining.submit(3_000, &site(A), job("chat"), waiter(5)),
            Some(Mined::Off)
        );
        // Off lasts: no reset turns it on.
        mining.reset();
        assert_eq!(
            mining.submit(3_000, &site(A), job("chat"), waiter(6)),
            Some(Mined::Off)
        );
    }

    /// A job's 15 s run on the clock the engine passes: it ends within one
    /// batch of them, and the next job's clock starts at its dispatch.
    #[test]
    fn a_job_ends_within_a_batch_of_its_time() {
        let mut mining = Mining::new();
        mining.submit(0, &site(A), job("long-608"), waiter(1));
        mining.submit(0, &site(B), job("chat"), waiter(2));
        let mut now = 0;
        let mut answers = Vec::new();
        while answers.is_empty() {
            let (lane, batch) = mining.work(now).batch.unwrap();
            now += 300;
            answers = mining.ran(now, lane, batch.run());
        }
        assert_eq!(answers, [(waiter(1), Mined::Timeout)]);
        assert!((JOB_MS..JOB_MS + 300).contains(&now), "{now}");
        assert_eq!(drain(&mut mining, now), [(waiter(2), Mined::Found(143))]);
    }

    /// The budget reads the clock `submit` is given (`Date.now()`), apart
    /// from the job's: a site's 17th new topic in a minute is refused.
    #[test]
    fn the_budget_reads_the_wall_clock() {
        let mut mining = Mining::new();
        let wall = 1_767_225_600_123;
        for n in 0..16 {
            let topic = format!("t{n}");
            assert_eq!(mining.submit(wall, &site(A), job(&topic), waiter(n)), None);
            mining.cancel(&waiter(n));
        }
        assert_eq!(
            mining.submit(wall + 1_000, &site(A), job("t16"), waiter(16)),
            Some(Mined::RateLimited {
                retry_after_ms: 59_000
            })
        );
        assert_eq!(
            mining.submit(wall + 60_000, &site(A), job("t16"), waiter(17)),
            None
        );
    }

    /// The test hooks' reset forgets the cache and budgets, only while
    /// nothing waits or runs.
    #[test]
    fn a_reset_waits_for_an_idle_lane() {
        let mut mining = Mining::new();
        mining.submit(0, &site(A), job("chat"), waiter(1));
        drain(&mut mining, 0);
        mining.submit(0, &site(A), job("room"), waiter(2));
        let out = mining.work(0).batch;
        mining.reset();
        assert_eq!(
            mining.submit(0, &site(B), job("chat"), waiter(3)),
            Some(Mined::Found(143)),
            "kept while a job runs"
        );
        let (lane, out) = out.unwrap();
        mining.cancel(&waiter(2));
        assert!(mining.ran(0, lane, out.run()).is_empty());
        mining.reset();
        assert_eq!(mining.submit(0, &site(B), job("chat"), waiter(4)), None);
        assert_eq!(mining.state()["waiting"], 1);
    }

    /// The lane thread runs each batch it is handed and answers with its
    /// generation; it ends once its handle goes.
    #[test]
    fn the_lane_thread_answers_with_its_generation() {
        let (tx, rx) = mpsc::channel();
        let thread = spawn(7, move |lane, ran| tx.send((lane, ran)).is_ok()).unwrap();
        assert_eq!(thread.generation(), 7);
        let mut mining = Mining::new();
        mining.generation = 7;
        mining.submit(0, &site(A), job("chat"), waiter(1));
        let (lane, batch) = mining.work(0).batch.unwrap();
        assert_eq!(lane, 7);
        assert!(thread.run(batch));
        let (lane, ran) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(mining.ran(1, lane, ran), [(waiter(1), Mined::Found(143))]);
        drop(thread);
        // The thread has gone: its receiver's sender with it.
        assert!(rx.recv_timeout(Duration::from_secs(10)).is_err());
    }
}
