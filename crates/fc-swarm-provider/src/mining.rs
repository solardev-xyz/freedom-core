//! The mining lane's rules (design 0015, "Messaging and GSOC mining" >
//! "Mining, in the core"; Budgets: "one lane; batches of 256 candidates;
//! 16 jobs waiting per site and 256 in all, then `busy`; a stuck batch's
//! watchdog at 1 s"), sans-I/O: the swarm thread owns one [`Lane`], hands
//! it each machine's [`Need::Mine`](crate::machine::Need::Mine) ask with
//! the request's site and a token of its own for the waiter, runs each
//! [`Batch`] the lane gives out on the lane thread, and hands the batch
//! back ([`Lane::ran`]). Every answer comes back as `(waiter, Mined)`.
//! Time is the core's clock, passed in.
//!
//! **Today's rules, kept** (messaging-service.js's `deriveGsoc`,
//! gsoc-miner.js):
//! - a cache of [`CACHE`] topics, the oldest dropped first; a hit is free;
//! - a second request for a topic in flight joins its job, and its site
//!   becomes an owner of the job while it waits (`joinJob`), so the job
//!   runs at whichever owner's turn comes first; a join is free;
//! - [`NEW_TOPICS`] new topics a minute per site; a job that fails counts;
//! - fair turns: one queue per site, served round-robin, one job a turn,
//!   the site served last going after every other site with work;
//! - one job at a time, and [`JOB_MS`] per job from its dispatch, then
//!   `gsoc_mining_timeout`.
//!
//! **The core's new limits:**
//! - at most [`WAITING_PER_SITE`] jobs waiting per site and [`WAITING`] in
//!   all; past either, [`Mined::Busy`] and nothing is mined for it
//!   (deviation `busy`). A join counts in the joiner's queue, as it waits
//!   there; it adds no job to the whole;
//! - the lane runs a job [`BATCH`] candidates at a time and checks the
//!   job's deadline and its waiters between batches. A waiter's cancel or
//!   deadline ends only its own wait; the job stops at the next batch when
//!   its last waiter has gone, and a job that hasn't started is dropped;
//! - a batch out for [`STUCK_MS`] marks the lane stuck: its job ends
//!   `gsoc_mining_failed`, and a new lane thread takes the queue
//!   ([`Watched::new_lane`]); the stuck thread's answer, if any, is
//!   dropped. A second stuck lane in one start turns mining off: every
//!   waiting job and every later request ends [`Mined::Off`].
//!
//! The search itself is `fc_swarm::gsoc::Miner`, bee-js's `gsocMine`.

use std::collections::{BTreeMap, VecDeque};

use fc_json::JsString;
use fc_swarm::gsoc::{Miner, Step};

use crate::machine::{MineJob, Mined};

/// Candidates a batch tries at most.
pub const BATCH: u32 = fc_swarm::gsoc::BATCH;
/// Jobs waiting for one site at most.
pub const WAITING_PER_SITE: usize = 16;
/// Jobs waiting in all at most.
pub const WAITING: usize = 256;
/// A job's time from its dispatch (`MINE_TIMEOUT_MS`).
pub const JOB_MS: u64 = 15_000;
/// How long one batch may run before the lane counts as stuck.
pub const STUCK_MS: u64 = 1_000;
/// Topics the cache holds (`GSOC_CACHE_MAX`).
pub const CACHE: usize = 128;
/// New topics a site may start within [`NEW_TOPIC_WINDOW_MS`]
/// (`NEW_TOPICS_PER_WINDOW`).
pub const NEW_TOPICS: usize = 16;
/// `NEW_TOPIC_WINDOW_MS`.
pub const NEW_TOPIC_WINDOW_MS: u64 = 60_000;
/// Stuck lanes in one start after which mining is off.
pub const STUCK_LANES: u8 = 2;
/// What a mining job holds in the swarm thread's memory (design 0015,
/// "The swarm thread's memory"): a request's ask for one.
pub const JOB_CHARGE: usize = 4 * 1024;

/// A job's identity: what it searches for.
type Key = ([u8; 32], [u8; 32], u32);

fn key_of(job: &MineJob) -> Key {
    (job.target, job.identifier, job.proximity)
}

/// What [`Lane::submit`] did with a request's ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Submitted {
    /// The waiter waits: its answer comes from [`Lane::work`],
    /// [`Lane::ran`] or [`Lane::watch`].
    Waiting,
    /// Answered at once: a cache hit, the new-topic budget, `busy`, or
    /// mining off.
    Done(Mined),
}

/// A batch for the lane thread: [`Batch::run`] there, and hand the
/// [`Ran`] back to [`Lane::ran`].
#[derive(Debug, Clone)]
pub struct Batch {
    id: u64,
    miner: Miner,
    n: u32,
}

impl Batch {
    /// The batch's number, to match its answer.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Tries at most [`BATCH`] candidates: the lane thread's work.
    pub fn run(mut self) -> Ran {
        let step = self.miner.step(self.n);
        Ran {
            id: self.id,
            miner: self.miner,
            step,
        }
    }
}

/// A batch's answer.
#[derive(Debug, Clone)]
pub struct Ran {
    id: u64,
    miner: Miner,
    step: Step,
}

impl Ran {
    /// The batch it answers.
    pub fn id(&self) -> u64 {
        self.id
    }
}

/// What [`Lane::work`] gives: answers for jobs that ended meanwhile, and
/// the batch the lane thread runs next, if any.
#[derive(Debug)]
pub struct Work<T> {
    pub answers: Vec<(T, Mined)>,
    pub batch: Option<Batch>,
}

/// What [`Lane::watch`] found.
#[derive(Debug)]
pub struct Watched<T> {
    pub answers: Vec<(T, Mined)>,
    /// The lane was stuck: start a new lane thread, which takes the queue.
    pub new_lane: bool,
}

#[derive(Debug)]
struct Job<T> {
    key: Key,
    owners: Vec<JsString>,
    waiters: Vec<T>,
    dispatched: bool,
}

/// The job the lane runs.
#[derive(Debug)]
struct Running {
    job: u64,
    dispatched_at: u64,
    /// The search, between batches; `None` while a batch is out.
    miner: Option<Miner>,
    /// The batch out and when it went.
    out: Option<(u64, u64)>,
}

/// The mining lane: its cache, budgets, queues and the job it runs.
#[derive(Debug)]
pub struct Lane<T> {
    cache: VecDeque<(Key, u32)>,
    /// Each site's new-topic starts within the window, oldest first.
    starts: Vec<(JsString, VecDeque<u64>)>,
    /// Jobs not yet settled, waiting or running.
    jobs: BTreeMap<u64, Job<T>>,
    /// Each owner's waiting jobs, the owners in their turn order.
    queues: Vec<(JsString, VecDeque<u64>)>,
    last_owner: Option<JsString>,
    running: Option<Running>,
    stuck: u8,
    next_job: u64,
    next_batch: u64,
}

impl<T> Default for Lane<T> {
    fn default() -> Self {
        Self {
            cache: VecDeque::new(),
            starts: Vec::new(),
            jobs: BTreeMap::new(),
            queues: Vec::new(),
            last_owner: None,
            running: None,
            stuck: 0,
            next_job: 0,
            next_batch: 0,
        }
    }
}

impl<T: Clone + PartialEq> Lane<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether two stuck lanes turned mining off.
    pub fn off(&self) -> bool {
        self.stuck >= STUCK_LANES
    }

    /// Jobs waiting in all.
    pub fn waiting(&self) -> usize {
        self.jobs.values().filter(|j| !j.dispatched).count()
    }

    /// Jobs waiting in `site`'s queue.
    pub fn waiting_for(&self, site: &JsString) -> usize {
        self.queues
            .iter()
            .find(|(owner, _)| owner == site)
            .map_or(0, |(_, q)| q.len())
    }

    /// When the swarm thread should next call [`Lane::watch`]: the out
    /// batch's watchdog.
    pub fn deadline(&self) -> Option<u64> {
        self.running
            .as_ref()
            .and_then(|r| r.out)
            .map(|(_, started)| started.saturating_add(STUCK_MS))
    }

    /// A request's ask for `job`, from `site`: `deriveGsoc`'s cache, the
    /// join of a job in flight, the new-topic budget, then the queue's
    /// bounds.
    pub fn submit(&mut self, now: u64, site: &JsString, job: MineJob, waiter: T) -> Submitted {
        if self.off() {
            return Submitted::Done(Mined::Off);
        }
        let key = key_of(&job);
        if let Some((_, index)) = self.cache.iter().find(|(k, _)| *k == key) {
            return Submitted::Done(Mined::Found(*index));
        }
        let joined = self
            .jobs
            .iter()
            .find(|(_, j)| j.key == key)
            .map(|(id, j)| (*id, j.dispatched, j.owners.contains(site)));
        if let Some((id, dispatched, owner)) = joined {
            if !dispatched && !owner {
                if self.waiting_for(site) >= WAITING_PER_SITE {
                    return Submitted::Done(Mined::Busy);
                }
                if let Some(j) = self.jobs.get_mut(&id) {
                    j.owners.push(site.clone());
                }
                self.enqueue(site, id);
            }
            if let Some(j) = self.jobs.get_mut(&id) {
                j.waiters.push(waiter);
            }
            return Submitted::Waiting;
        }
        if let Some(retry_after_ms) = self.consume_budget(now, site) {
            return Submitted::Done(Mined::RateLimited { retry_after_ms });
        }
        if self.waiting_for(site) >= WAITING_PER_SITE || self.waiting() >= WAITING {
            return Submitted::Done(Mined::Busy);
        }
        self.next_job += 1;
        let id = self.next_job;
        self.jobs.insert(
            id,
            Job {
                key,
                owners: vec![site.clone()],
                waiters: vec![waiter],
                dispatched: false,
            },
        );
        self.enqueue(site, id);
        Submitted::Waiting
    }

    /// `consumeNewTopicBudget(origin)`: every site's expired starts pruned,
    /// then `site`'s start recorded, or the time until its oldest leaves
    /// the window when it already has [`NEW_TOPICS`].
    fn consume_budget(&mut self, now: u64, site: &JsString) -> Option<u64> {
        let window = i128::from(NEW_TOPIC_WINDOW_MS);
        let elapsed = |start: u64| i128::from(now) - i128::from(start);
        for (_, starts) in &mut self.starts {
            while starts.front().is_some_and(|s| elapsed(*s) >= window) {
                starts.pop_front();
            }
        }
        self.starts.retain(|(_, starts)| !starts.is_empty());
        let at = match self.starts.iter().position(|(s, _)| s == site) {
            Some(at) => at,
            None => {
                self.starts.push((site.clone(), VecDeque::new()));
                self.starts.len() - 1
            }
        };
        let starts = &mut self.starts[at].1;
        if starts.len() >= NEW_TOPICS {
            let oldest = starts.front().copied().unwrap_or(now);
            let retry = window - elapsed(oldest);
            return Some(u64::try_from(retry).unwrap_or(u64::MAX));
        }
        starts.push_back(now);
        None
    }

    fn enqueue(&mut self, owner: &JsString, id: u64) {
        match self.queues.iter_mut().find(|(o, _)| o == owner) {
            Some((_, q)) => q.push_back(id),
            None => self.queues.push((owner.clone(), VecDeque::from([id]))),
        }
    }

    /// Takes `id` out of every owner's queue, dropping a queue left empty.
    fn unqueue(&mut self, id: u64) {
        for (_, q) in &mut self.queues {
            q.retain(|j| *j != id);
        }
        self.queues.retain(|(_, q)| !q.is_empty());
    }

    /// gsoc-miner.js's `nextJob`: the first owner with work other than the
    /// one served last (or that one, when it alone has work), its oldest
    /// job, which leaves every queue it sits in; the owner served goes to
    /// the back.
    fn next_job(&mut self) -> Option<u64> {
        let last = self.last_owner.as_ref();
        let at = self
            .queues
            .iter()
            .position(|(o, _)| Some(o) != last)
            .or_else(|| self.queues.iter().position(|(o, _)| Some(o) == last))?;
        let owner = self.queues[at].0.clone();
        let id = *self.queues[at].1.front()?;
        self.unqueue(id);
        if let Some(at) = self.queues.iter().position(|(o, _)| *o == owner) {
            let queue = self.queues.remove(at);
            self.queues.push(queue);
        }
        if let Some(job) = self.jobs.get_mut(&id) {
            job.dispatched = true;
        }
        self.last_owner = Some(owner);
        Some(id)
    }

    /// Ends job `id` with `mined` for each of its waiters.
    fn settle(&mut self, id: u64, mined: Mined, answers: &mut Vec<(T, Mined)>) {
        self.unqueue(id);
        if let Some(job) = self.jobs.remove(&id) {
            answers.extend(job.waiters.into_iter().map(|w| (w, mined)));
        }
    }

    /// The waiter went (its request's cancel or deadline): only its own
    /// wait ends. A job left with no waiter is dropped if it hasn't
    /// started, ends now between two batches, or at its batch's answer.
    pub fn cancel(&mut self, waiter: &T) {
        let Some((&id, job)) = self
            .jobs
            .iter_mut()
            .find(|(_, j)| j.waiters.contains(waiter))
        else {
            return;
        };
        job.waiters.retain(|w| w != waiter);
        if !job.waiters.is_empty() {
            return;
        }
        if !job.dispatched {
            self.unqueue(id);
            self.jobs.remove(&id);
            return;
        }
        if self
            .running
            .as_ref()
            .is_some_and(|r| r.job == id && r.out.is_none())
        {
            self.running = None;
            self.jobs.remove(&id);
        }
    }

    /// The lane thread is idle: the jobs whose time ran out between
    /// batches end, and the next batch goes, of the job running or of the
    /// next job in turn.
    pub fn work(&mut self, now: u64) -> Work<T> {
        let mut answers = Vec::new();
        loop {
            match self.running.as_mut() {
                Some(r) if r.out.is_some() => break,
                Some(r) => {
                    if now.saturating_sub(r.dispatched_at) >= JOB_MS {
                        let id = r.job;
                        self.running = None;
                        self.settle(id, Mined::Timeout, &mut answers);
                        continue;
                    }
                    let Some(miner) = r.miner.take() else {
                        // Every running job holds its search between
                        // batches; one that doesn't is dropped.
                        let id = r.job;
                        self.running = None;
                        self.settle(id, Mined::Exhausted, &mut answers);
                        continue;
                    };
                    self.next_batch += 1;
                    let id = self.next_batch;
                    r.out = Some((id, now));
                    return Work {
                        answers,
                        batch: Some(Batch {
                            id,
                            miner,
                            n: BATCH,
                        }),
                    };
                }
                None => {
                    if self.off() {
                        break;
                    }
                    let Some(id) = self.next_job() else {
                        break;
                    };
                    let Some(job) = self.jobs.get(&id) else {
                        continue;
                    };
                    let (target, identifier, proximity) = job.key;
                    self.running = Some(Running {
                        job: id,
                        dispatched_at: now,
                        miner: Some(Miner::new(&target, &identifier, proximity)),
                        out: None,
                    });
                }
            }
        }
        Work {
            answers,
            batch: None,
        }
    }

    /// A batch came back from the lane thread. A stuck lane's late answer,
    /// or one for a job no waiter waits for, is dropped.
    pub fn ran(&mut self, now: u64, ran: Ran) -> Vec<(T, Mined)> {
        let mut answers = Vec::new();
        let Some(r) = self.running.as_mut() else {
            return answers;
        };
        if r.out.map(|(id, _)| id) != Some(ran.id) {
            return answers;
        }
        r.out = None;
        let id = r.job;
        let waited = self.jobs.get(&id).is_some_and(|j| !j.waiters.is_empty());
        if !waited {
            self.running = None;
            self.jobs.remove(&id);
            return answers;
        }
        match ran.step {
            Step::Found(signer) => {
                self.running = None;
                if let Some(job) = self.jobs.get(&id) {
                    if self.cache.len() >= CACHE {
                        self.cache.pop_front();
                    }
                    self.cache.push_back((job.key, signer.index()));
                }
                self.settle(id, Mined::Found(signer.index()), &mut answers);
            }
            Step::Exhausted => {
                self.running = None;
                self.settle(id, Mined::Exhausted, &mut answers);
            }
            Step::More => {
                if now.saturating_sub(r.dispatched_at) >= JOB_MS {
                    self.running = None;
                    self.settle(id, Mined::Timeout, &mut answers);
                } else {
                    r.miner = Some(ran.miner);
                }
            }
        }
        answers
    }

    /// The watchdog, on the swarm thread's clock: a batch out for
    /// [`STUCK_MS`] ends its job `gsoc_mining_failed` and asks for a new
    /// lane thread; the second turns mining off, ending every waiting job.
    pub fn watch(&mut self, now: u64) -> Watched<T> {
        let mut answers = Vec::new();
        let stuck = self
            .running
            .as_ref()
            .and_then(|r| r.out.map(|(_, started)| (r.job, started)))
            .filter(|(_, started)| now.saturating_sub(*started) >= STUCK_MS);
        let Some((id, _)) = stuck else {
            return Watched {
                answers,
                new_lane: false,
            };
        };
        self.running = None;
        self.settle(id, Mined::Stuck, &mut answers);
        self.stuck = self.stuck.saturating_add(1);
        if self.off() {
            let waiting: Vec<u64> = self.jobs.keys().copied().collect();
            for id in waiting {
                self.settle(id, Mined::Off, &mut answers);
            }
            self.queues.clear();
            return Watched {
                answers,
                new_lane: false,
            };
        }
        Watched {
            answers,
            new_lane: true,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    const A: &str = "https://a.example";
    const B: &str = "https://b.example";

    fn site(s: &str) -> JsString {
        JsString::from(s)
    }

    /// A job that no candidate satisfies before the cap (proximity past
    /// 256), told apart by its target.
    fn endless(n: u8) -> MineJob {
        MineJob {
            target: [n; 32],
            identifier: [0; 32],
            proximity: 255,
        }
    }

    /// A job the first candidate satisfies (proximity 0).
    fn instant(n: u8) -> MineJob {
        MineJob {
            target: [n; 32],
            identifier: [1; 32],
            proximity: 0,
        }
    }

    /// Runs the lane's batches until it idles, at `now`, the lane thread
    /// answering each at once: every answer, in order.
    fn drain(lane: &mut Lane<u32>, now: u64) -> Vec<(u32, Mined)> {
        let mut out = Vec::new();
        loop {
            let work = lane.work(now);
            out.extend(work.answers);
            let Some(batch) = work.batch else {
                return out;
            };
            out.extend(lane.ran(now, batch.run()));
        }
    }

    /// gsoc-miner.test.js's "queued jobs are served round-robin across
    /// owners, not FIFO".
    #[test]
    fn turns_go_round_robin_across_sites() {
        let mut lane = Lane::new();
        let owners = [A, A, A, B, B, ""];
        for (i, owner) in owners.iter().enumerate() {
            let i = i as u8;
            assert_eq!(
                lane.submit(0, &site(owner), instant(i), u32::from(i)),
                Submitted::Waiting
            );
            if i == 0 {
                // The first is dispatched at once, as `pump` does.
                let work = lane.work(0);
                let ran = work.batch.unwrap().run();
                assert!(lane.ran(0, ran).len() == 1);
            }
        }
        let order: Vec<u32> = drain(&mut lane, 0).into_iter().map(|(w, _)| w).collect();
        // a1 ran first; then b1, a2, none1, b2, a3.
        assert_eq!(order, [3, 1, 5, 4, 2]);
    }

    /// gsoc-miner.test.js's "a joined job runs at the joiner's turn, once,
    /// and leaves both queues".
    #[test]
    fn a_join_runs_at_the_joiners_turn_once() {
        let mut lane = Lane::new();
        lane.submit(0, &site(A), endless(1), 1);
        // a1 runs; one batch out.
        let first = lane.work(0).batch.unwrap();
        lane.submit(0, &site(A), instant(2), 2);
        lane.submit(0, &site(A), instant(3), 3);
        lane.submit(0, &site(A), instant(9), 9);
        // B joins T (instant(9)); joining again, or as A, queues nothing.
        assert_eq!(lane.submit(0, &site(B), instant(9), 90), Submitted::Waiting);
        assert_eq!(lane.submit(0, &site(B), instant(9), 91), Submitted::Waiting);
        assert_eq!(lane.submit(0, &site(A), instant(9), 92), Submitted::Waiting);
        assert_eq!(lane.waiting_for(&site(B)), 1);
        assert_eq!(lane.waiting_for(&site(A)), 3);
        // a1 ends (its only waiter leaves); B's turn runs T.
        lane.cancel(&1);
        assert!(lane.ran(0, first.run()).is_empty());
        let answers = drain(&mut lane, 0);
        let order: Vec<u32> = answers.iter().map(|(w, _)| *w).collect();
        assert_eq!(order, [9, 90, 91, 92, 2, 3]);
        assert_eq!(lane.waiting(), 0);
    }

    /// Joining a running job queues nothing; a settled job is forgotten.
    #[test]
    fn a_join_of_a_running_job_queues_nothing() {
        let mut lane = Lane::new();
        lane.submit(0, &site(A), endless(1), 1);
        let batch = lane.work(0).batch.unwrap();
        assert_eq!(lane.submit(0, &site(B), endless(1), 2), Submitted::Waiting);
        assert_eq!(lane.waiting_for(&site(B)), 0);
        // Its time runs out at the batch's answer: both waiters end.
        let answers = lane.ran(JOB_MS, batch.run());
        assert_eq!(answers, [(1, Mined::Timeout), (2, Mined::Timeout)]);
        assert!(lane.work(JOB_MS).batch.is_none());
    }

    /// An instant job told apart by a number.
    fn numbered(i: u32) -> MineJob {
        let mut identifier = [7u8; 32];
        identifier[..4].copy_from_slice(&i.to_be_bytes());
        MineJob {
            target: [0; 32],
            identifier,
            proximity: 0,
        }
    }

    /// The cache answers a mined topic at once, and holds 128, the oldest
    /// going first.
    #[test]
    fn the_cache_holds_128_topics() {
        let mut lane = Lane::new();
        for i in 0..=CACHE as u32 {
            let job = numbered(i);
            // A new minute for every 16, so the budget doesn't refuse.
            let now = u64::from(i / 16) * NEW_TOPIC_WINDOW_MS;
            assert_eq!(lane.submit(now, &site(A), job, i), Submitted::Waiting);
            assert_eq!(drain(&mut lane, now), [(i, Mined::Found(0))]);
            assert_eq!(
                lane.submit(now, &site(B), job, 1000),
                Submitted::Done(Mined::Found(0))
            );
        }
        // The first topic went: it is mined again.
        let now = 9 * NEW_TOPIC_WINDOW_MS;
        assert_eq!(
            lane.submit(now, &site(B), numbered(0), 1),
            Submitted::Waiting
        );
    }

    /// 16 new topics a minute per site; cache hits and joins are free; a
    /// failed job counts; the window rolls per start.
    #[test]
    fn sixteen_new_topics_a_minute_per_site() {
        let mut lane = Lane::new();
        for i in 0..16u8 {
            assert_eq!(
                lane.submit(1000 + u64::from(i), &site(A), instant(i), u32::from(i)),
                Submitted::Waiting
            );
            drain(&mut lane, 1000);
        }
        // A cache hit is free.
        assert_eq!(
            lane.submit(2000, &site(A), instant(3), 99),
            Submitted::Done(Mined::Found(0))
        );
        assert_eq!(
            lane.submit(2000, &site(A), instant(16), 16),
            Submitted::Done(Mined::RateLimited {
                retry_after_ms: 59_000
            })
        );
        // Another site has its own.
        assert_eq!(
            lane.submit(2000, &site(B), instant(16), 17),
            Submitted::Waiting
        );
        // The oldest start leaves the window at 61,000.
        assert_eq!(
            lane.submit(60_999, &site(A), instant(20), 20),
            Submitted::Done(Mined::RateLimited { retry_after_ms: 1 })
        );
        assert_eq!(
            lane.submit(61_000, &site(A), instant(20), 20),
            Submitted::Waiting
        );
    }

    /// A site's 17th waiting job and the 257th in all are `busy`, and
    /// nothing is mined for them; another site is still admitted within
    /// its own 16 while there is room.
    #[test]
    fn a_full_queue_is_busy() {
        let mut lane = Lane::new();
        // One job runs, then 16 wait for A, each in a fresh minute, so the
        // new-topic budget doesn't refuse first.
        lane.submit(0, &site(A), endless(0), 0);
        let _out = lane.work(0).batch.unwrap();
        let minute = |i: u64| i * NEW_TOPIC_WINDOW_MS;
        for i in 1..=16u8 {
            let got = lane.submit(minute(u64::from(i)), &site(A), endless(i), u32::from(i));
            assert_eq!(got, Submitted::Waiting);
        }
        let now = minute(17);
        assert_eq!(
            lane.submit(now, &site(A), endless(17), 17),
            Submitted::Done(Mined::Busy)
        );
        assert_eq!(lane.waiting_for(&site(A)), 16);
        // A join from a site whose queue is full is busy too; B's own job
        // is admitted.
        assert_eq!(
            lane.submit(now, &site(B), endless(200), 200),
            Submitted::Waiting
        );
        assert_eq!(
            lane.submit(now, &site(A), endless(200), 201),
            Submitted::Done(Mined::Busy)
        );
        // 256 in all: 15 more sites of 16 each fill it, and the 257th is
        // busy.
        let mut n = 300u32;
        for s in 0..15 {
            let who = site(&format!("https://s{s}.example"));
            for _ in 0..16 {
                n += 1;
                let job = MineJob {
                    target: [(n % 256) as u8; 32],
                    identifier: [(n / 256) as u8; 32],
                    proximity: 255,
                };
                let before = lane.waiting();
                let got = lane.submit(now, &who, job, n);
                if before < WAITING {
                    assert_eq!(got, Submitted::Waiting, "{n}");
                } else {
                    assert_eq!(got, Submitted::Done(Mined::Busy), "{n}");
                }
            }
        }
        assert_eq!(lane.waiting(), WAITING);
        let late = site("https://late.example");
        assert_eq!(
            lane.submit(now, &late, endless(250), 9999),
            Submitted::Done(Mined::Busy)
        );
    }

    /// The only waiter's cancel stops the job at its batch's answer, and
    /// the next job starts; with two waiters, one cancel leaves it running.
    #[test]
    fn a_cancel_ends_only_its_own_wait() {
        let mut lane = Lane::new();
        lane.submit(0, &site(A), endless(1), 1);
        lane.submit(0, &site(A), endless(1), 2);
        lane.submit(0, &site(B), instant(2), 3);
        let batch = lane.work(0).batch.unwrap();
        lane.cancel(&1);
        let batch = {
            assert!(lane.ran(0, batch.run()).is_empty());
            lane.work(0).batch.unwrap()
        };
        lane.cancel(&2);
        assert!(lane.ran(0, batch.run()).is_empty());
        assert_eq!(drain(&mut lane, 0), [(3, Mined::Found(0))]);
        // A job that hasn't started is dropped at its last waiter's cancel.
        lane.submit(0, &site(A), endless(5), 5);
        let out = lane.work(0).batch.unwrap();
        lane.submit(0, &site(B), endless(6), 6);
        lane.cancel(&6);
        assert_eq!(lane.waiting(), 0);
        lane.cancel(&5);
        assert!(lane.ran(0, out.run()).is_empty());
        assert!(lane.work(0).batch.is_none());
    }

    /// A job past its 15 s ends `gsoc_mining_timeout` within one batch,
    /// its clock starting at its dispatch, and the next job then runs.
    #[test]
    fn a_slow_job_times_out_within_a_batch() {
        let mut lane = Lane::new();
        lane.submit(0, &site(A), endless(1), 1);
        lane.submit(0, &site(B), instant(2), 2);
        let mut now = 0;
        let mut answers = Vec::new();
        // Each batch takes 999 ms (a test hook's delay).
        while answers.is_empty() {
            let batch = lane.work(now).batch.unwrap();
            now += 999;
            answers = lane.ran(now, batch.run());
        }
        assert_eq!(answers, [(1, Mined::Timeout)]);
        assert!((JOB_MS..JOB_MS + 999).contains(&now));
        // B's job waited 15 s, but its own clock starts now.
        let batch = lane.work(now).batch.unwrap();
        assert_eq!(lane.ran(now, batch.run()), [(2, Mined::Found(0))]);
    }

    /// No signer within the cap: `gsoc_mining_failed`, not cached.
    #[test]
    fn an_exhausted_search_fails_and_isnt_cached() {
        let mut lane = Lane::new();
        let job = MineJob {
            target: [1; 32],
            identifier: [2; 32],
            proximity: 255,
        };
        lane.submit(0, &site(A), job, 1);
        let mut answers = Vec::new();
        let mut batches = 0;
        while answers.is_empty() {
            let batch = lane.work(0).batch.unwrap();
            batches += 1;
            answers = lane.ran(0, batch.run());
        }
        assert_eq!(answers, [(1, Mined::Exhausted)]);
        assert_eq!(batches, fc_swarm::gsoc::CANDIDATES.div_ceil(BATCH));
        assert_eq!(lane.submit(0, &site(A), job, 2), Submitted::Waiting);
    }

    /// A batch out for 1 s ends its job `gsoc_mining_failed` and asks for a
    /// new lane, which takes the queue; the stuck answer is dropped. A
    /// second stuck lane turns mining off.
    #[test]
    fn a_stuck_lane_is_replaced_once_then_mining_is_off() {
        let mut lane = Lane::new();
        lane.submit(0, &site(A), endless(1), 1);
        lane.submit(0, &site(B), instant(2), 2);
        let stuck = lane.work(0).batch.unwrap();
        assert_eq!(lane.deadline(), Some(STUCK_MS));
        let early = lane.watch(STUCK_MS - 1);
        assert!(early.answers.is_empty() && !early.new_lane);
        let watched = lane.watch(STUCK_MS);
        assert_eq!(watched.answers, [(1, Mined::Stuck)]);
        assert!(watched.new_lane);
        assert!(
            lane.ran(STUCK_MS, stuck.run()).is_empty(),
            "the late answer is dropped"
        );
        assert_eq!(drain(&mut lane, STUCK_MS), [(2, Mined::Found(0))]);
        // The second stuck lane.
        lane.submit(2000, &site(A), endless(3), 3);
        lane.submit(2000, &site(B), endless(4), 4);
        let _stuck = lane.work(2000).batch.unwrap();
        let watched = lane.watch(3000);
        assert_eq!(watched.answers, [(3, Mined::Stuck), (4, Mined::Off)]);
        assert!(!watched.new_lane);
        assert!(lane.off());
        assert_eq!(
            lane.submit(3000, &site(A), instant(9), 9),
            Submitted::Done(Mined::Off)
        );
        assert!(lane.work(3000).batch.is_none());
    }

    /// The lane's batches find bee-js's signer: the same as one `mine`.
    #[test]
    fn the_lane_finds_mines_signer() {
        let target = fc_evm::keccak256(b"freedom-gsoc-v1:chat");
        let identifier = fc_evm::keccak256(b"chat");
        let job = MineJob {
            target,
            identifier,
            proximity: 12,
        };
        let mut lane = Lane::new();
        lane.submit(0, &site(A), job, 1);
        let answers = drain(&mut lane, 0);
        let signer = fc_swarm::gsoc::mine(&target, &identifier, 12).unwrap();
        assert_eq!(answers, [(1, Mined::Found(signer.index()))]);
        assert_eq!(signer.index(), 143);
    }
}
