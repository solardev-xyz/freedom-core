//! NAT64 discovery (design 0007, "Network-specific NAT64 prefixes"): what
//! brings the address table to `direct` mode.
//!
//! An IPv6-only network can translate through a network-specific prefix of
//! its own (RFC 6052), whose addresses look like ordinary global unicast and
//! may reach private IPv4 addresses. So the service learns the prefixes as
//! RFC 7050 describes, and upstream's gate fails closed for IPv6 while it
//! doesn't know them. Upstream holds the state and the RFC 6052 arithmetic
//! (`Nat64State`, `Nat64Prefix`); discovery is the host's, here:
//!
//! - **Which resolvers:** the ones each interface learned, per OS
//!   ([`resolvers`]). The service's other resolvers (hickory's, the DoH
//!   endpoint) needn't see the access network's DNS64.
//! - **The query:** AAAA for `ipv4only.arpa` to each, over plain DNS, and
//!   nothing else ([`query`]). Its answers are parsed, never dialed.
//! - **The state** ([`Nat64State`]), published to every handle:
//!   - **pending** until the first round settles: every IPv6 target but an
//!     IPv4-mapped one waits for it;
//!   - **known** once every resolver answered: the union of the prefixes
//!     learned (none, when no resolver advertises one, or the OS lists
//!     none);
//!   - **unknown** while any resolver failed, or can't be asked;
//!   - **incomplete** past [`Nat64State::MAX_PREFIXES`] distinct prefixes,
//!     until the process restarts.
//!
//!   Learned prefixes are kept for the process's life: a refresh adds
//!   prefixes and never removes one, and a failed refresh keeps them all.
//! - **Refresh:** when the answers' TTL expires, and at least once a minute
//!   ([`Timing::ceiling`]), both counted from the round's start, so a
//!   network change leaves about a minute when a new network's prefix is
//!   unknown, and no answer is kept past its TTL; each round reads the
//!   resolvers again. After a failure, with backoff from 5 s to a minute.
//! - **At most [`MAX_RESOLVERS`] resolvers a round, the first the OS lists,**
//!   asked at once, so a round ends within one query's sends (two of 2 s):
//!   one listed past them isn't asked, and counts as a failure
//!   (`over_limit`), so the state can't be known.
//! - **A failure ends a known state at once:** the first one a round
//!   establishes publishes **pending**, before the others' answers, and the
//!   round's end publishes unknown, with every prefix it learned. Pending
//!   keeps every IPv6 target but an IPv4-mapped one waiting, the fixed forms
//!   included: an unknown published early would judge them by the prefixes
//!   learned so far, while an answer still out could teach one that covers
//!   a fixed form.
//! - **The result belongs to the process,** not to an instance. It runs
//!   only while a `direct` instance holds a [`Lease`]: a `socks5` instance
//!   learns nothing (the exit makes every connection), and a process with
//!   none sends no query: a round under way when the last lease goes sends
//!   nothing more, not even a resend, and isn't published. Resumed after a
//!   pause, the state is pending again, since the network may have changed
//!   meanwhile.

pub mod query;
pub mod resolvers;

use std::net::SocketAddr;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use fc_service::log;
use freedom_ipfs_gateway::net::Nat64Handle;
use freedom_ipfs_gateway::net::Nat64Publisher;
use freedom_ipfs_gateway::net::gate::{Nat64Prefix, Nat64State};
use serde_json::json;

use self::query::Failure;
use self::resolvers::Learned;

/// Where the resolvers come from: the OS ([`resolvers::learned`]), or a
/// test's.
pub type Source = Arc<dyn Fn() -> Vec<Learned> + Send + Sync>;

/// Discovery's timings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// How long one send of the query waits for its reply.
    pub attempt: Duration,
    /// Sends of the query to one resolver, per round.
    pub attempts: u32,
    /// The shortest wait before a refresh, whatever the answers' TTL.
    pub floor: Duration,
    /// The longest: a refresh at least this often.
    pub ceiling: Duration,
    /// The first wait after a failed round, doubled after each one that
    /// follows, up to [`Timing::ceiling`].
    pub backoff: Duration,
}

impl Timing {
    /// The design's: a refresh at least once a minute, backoff from 5 s to
    /// a minute. Each resolver gets two sends of 2 s each.
    pub const DESIGN: Timing = Timing {
        attempt: Duration::from_secs(2),
        attempts: 2,
        floor: Duration::from_secs(5),
        ceiling: Duration::from_secs(60),
        backoff: Duration::from_secs(5),
    };
}

/// The most resolvers asked in a round, all at once, each from a thread of
/// its own: a round lasts one query's sends, at most.
pub const MAX_RESOLVERS: usize = 8;

/// The process's discovery: the state every `direct` instance's gate reads.
#[derive(Clone)]
pub struct Discovery {
    shared: Arc<Shared>,
}

struct Shared {
    publisher: Nat64Publisher,
    /// The state as published.
    handle: Nat64Handle,
    /// Why the last round's resolvers failed, each a fixed name: none since
    /// a resume until a round publishes.
    failures: Mutex<Vec<&'static str>>,
    source: Source,
    timing: Timing,
    control: Mutex<Control>,
    wake: Condvar,
    /// Run between a send's check and the send, under the lock: tests.
    #[cfg(test)]
    before_send: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

#[derive(Default)]
struct Control {
    /// `direct` instances holding a [`Lease`].
    leases: usize,
    /// The rounds' thread has been started.
    started: bool,
    /// Bumped by each resume after a pause: a round begun before it
    /// doesn't publish.
    generation: u64,
}

/// A `direct` instance's hold on discovery: it runs while one is held.
pub struct Lease {
    shared: Arc<Shared>,
}

impl Discovery {
    /// Discovery over `source`'s resolvers, pending until a lease starts it.
    pub fn new(source: Source, timing: Timing) -> Discovery {
        let (publisher, handle) = Nat64Handle::channel(Nat64State::Pending);
        Discovery {
            shared: Arc::new(Shared {
                publisher,
                handle,
                failures: Mutex::new(Vec::new()),
                source,
                timing,
                control: Mutex::new(Control::default()),
                wake: Condvar::new(),
                #[cfg(test)]
                before_send: Mutex::new(None),
            }),
        }
    }

    /// Discovery over no resolver, for tests: known, with no prefix, once
    /// a lease starts it.
    #[cfg(test)]
    pub fn none() -> Discovery {
        Discovery::new(Arc::new(Vec::new), Timing::DESIGN)
    }

    /// The OS's resolvers ([`resolvers::learned`]).
    pub fn os_source() -> Source {
        Arc::new(resolvers::learned)
    }

    /// A handle on the state, for an instance's policy.
    pub fn handle(&self) -> Nat64Handle {
        self.shared.handle.clone()
    }

    /// The state now.
    pub fn state(&self) -> Nat64State {
        self.shared.handle.current()
    }

    /// What `ipfs.stats` reports of it: the state's name, the prefixes
    /// learned (`addr/len`), and why the last round's resolvers failed,
    /// each a fixed name (never an address).
    pub fn stats(&self) -> serde_json::Value {
        let state = self.state();
        let failures = self
            .shared
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        json!({
            "state": state_name(&state),
            "prefixes": state
                .prefixes()
                .iter()
                .map(|prefix| prefix.cidr().to_string())
                .collect::<Vec<_>>(),
            "failures": failures,
        })
    }

    /// Holds discovery running until the lease is dropped. The first lease
    /// starts it, and one after a pause resumes it, pending again.
    pub fn lease(&self) -> Lease {
        let mut control = self.shared.lock();
        control.leases += 1;
        if control.leases == 1 {
            if control.started {
                control.generation += 1;
                self.shared.publish(Nat64State::Pending, &[]);
            } else {
                control.started = true;
                let shared = self.shared.clone();
                let spawned = std::thread::Builder::new()
                    .name("ipfsd-nat64".into())
                    .spawn(move || shared.run());
                if spawned.is_err() {
                    // Pending stays: IPv6 targets wait, then are refused.
                    log::error("NAT64 discovery can't start its thread", json!({}));
                }
            }
            self.shared.wake.notify_all();
        }
        Lease {
            shared: self.shared.clone(),
        }
    }
}

impl Drop for Lease {
    /// The last one pauses discovery: the rounds' thread sends nothing
    /// more until a lease resumes it.
    fn drop(&mut self) {
        let mut control = self.shared.lock();
        control.leases = control.leases.saturating_sub(1);
    }
}

/// A resolver that failed, as logs name it, and why: a fixed name.
pub type Failed = (String, &'static str);

/// What a round learned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Round {
    pub state: Nat64State,
    /// The resolvers that failed, or couldn't be asked, and why.
    pub failures: Vec<Failed>,
    /// The smallest TTL the answers gave.
    pub ttl: Option<Duration>,
}

impl Shared {
    #[cfg(test)]
    fn before_send(&self) {
        let hook = self
            .before_send
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    fn lock(&self) -> MutexGuard<'_, Control> {
        self.control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Publishes `state` and its round's failures, and logs a change.
    fn publish(&self, state: Nat64State, failures: &[Failed]) {
        *self
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            failures.iter().map(|(_, why)| *why).collect();
        if self.handle.current() == state {
            return;
        }
        log::info(
            "NAT64 discovery",
            json!({
                "state": state_name(&state),
                "prefixes": state.prefixes().len(),
                "failures": failures
                    .iter()
                    .map(|(_, why)| *why)
                    .collect::<Vec<_>>(),
            }),
        );
        self.publisher.publish(state);
    }

    /// The rounds, for the process's life: each while a lease is held,
    /// then a wait for the next refresh, a resume or a pause.
    fn run(self: Arc<Self>) {
        let mut kept: Vec<Nat64Prefix> = Vec::new();
        let mut backoff = None;
        loop {
            let generation = {
                let mut control = self.lock();
                while control.leases == 0 {
                    control = self
                        .wake
                        .wait(control)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
                control.generation
            };
            // A round sends while its lease holds: once the last one goes,
            // or a resume begins another generation, it sends nothing more.
            let gate = LeaseGate {
                shared: &self,
                generation,
            };
            // The first failure ends a known state at once: pending until
            // the round's end (see the module's comment).
            let failed = |failures: &[Failed]| {
                let control = self.lock();
                if control.leases > 0 && control.generation == generation {
                    self.publish(Nat64State::Pending, failures);
                }
            };
            let started = Instant::now();
            let round = round(&(self.source)(), &mut kept, &self.timing, &gate, &failed);
            let mut control = self.lock();
            if control.leases == 0 || control.generation != generation {
                // Abandoned: paused, or resumed meanwhile. Nothing is
                // published, the backoff stays as it was, and the loop
                // waits for a lease, or starts the resumed round at once.
                continue;
            }
            self.publish(round.state.clone(), &round.failures);
            // From the round's start: the answers' TTLs began then, at the
            // latest, and the ceiling bounds start to start.
            let delay = next_delay(&round, &mut backoff, &self.timing);
            let deadline = started + delay;
            // Until the refresh, or a resume after a pause, which starts a
            // round at once. Paused, the next round waits for a lease above.
            loop {
                if control.generation != generation {
                    break;
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                control = self
                    .wake
                    .wait_timeout(control, left)
                    .map(|(control, _)| control)
                    .unwrap_or_else(|poisoned| poisoned.into_inner().0);
            }
        }
    }
}

/// One round: the first [`MAX_RESOLVERS`] resolvers `learned` lists, asked
/// at once, each from a thread of its own, their answers added to `kept`,
/// the prefixes learned so far. A resolver listed past them isn't asked, and
/// counts as a failure (`over_limit`), as one that can't be asked does.
///
/// - **Each send goes through `gate`:** once it says no, the round sends
///   nothing more, and its caller doesn't publish it.
/// - **The first failure is reported at once** (`failed`, with the failures
///   so far), not when the round ends, so a known state never outlasts an
///   established failure.
pub fn round(
    learned: &[Learned],
    kept: &mut Vec<Nat64Prefix>,
    timing: &Timing,
    gate: &dyn query::Gate,
    failed: &dyn Fn(&[Failed]),
) -> Round {
    let mut failures: Vec<Failed> = Vec::new();
    let mut asked: Vec<SocketAddr> = Vec::new();
    for (index, resolver) in learned.iter().enumerate() {
        match resolver {
            _ if index >= MAX_RESOLVERS => failures.push((describe(resolver), "over_limit")),
            Learned::Ask(addr) => asked.push(*addr),
            Learned::Unaskable(text) => failures.push((text.clone(), "unaskable")),
        }
    }
    let mut reported = false;
    let mut report = |failures: &[Failed]| {
        if !reported && !failures.is_empty() {
            reported = true;
            failed(failures);
        }
    };
    report(&failures);
    let mut ttl: Option<Duration> = None;
    std::thread::scope(|scope| {
        let (sent, answers) = std::sync::mpsc::channel();
        let asking: Vec<_> = asked
            .iter()
            .map(|addr| {
                let (addr, sent) = (*addr, sent.clone());
                scope.spawn(move || {
                    let answer =
                        query::ask(addr, query_id(), timing.attempt, timing.attempts, gate);
                    let _ = sent.send((addr, answer));
                })
            })
            .collect();
        drop(sent);
        // As each answers: until every thread has ended.
        let mut heard = 0;
        for (addr, answer) in answers {
            heard += 1;
            match answer {
                Ok(answer) => {
                    for prefix in answer.prefixes {
                        // Kept up to one past the bound: enough to stay
                        // incomplete.
                        if !kept.contains(&prefix) && kept.len() <= Nat64State::MAX_PREFIXES {
                            kept.push(prefix);
                        }
                    }
                    if let Some(answer_ttl) = answer.ttl {
                        ttl = Some(ttl.map_or(answer_ttl, |ttl| ttl.min(answer_ttl)));
                    }
                }
                Err(failure) => {
                    failures.push((addr.to_string(), failure.as_str()));
                    report(&failures);
                }
            }
        }
        // A thread that ended without an answer failed: it can only have
        // panicked, which its join contains.
        for asking in asking {
            let _ = asking.join();
        }
        if heard < asked.len() {
            failures.push(("a resolver's query".to_string(), Failure::Socket.as_str()));
        }
    });
    let state = if failures.is_empty() {
        Nat64State::known(kept.iter().copied())
    } else {
        Nat64State::unknown(kept.iter().copied())
    };
    Round {
        state,
        failures,
        ttl,
    }
}

/// A round's sends, allowed while a lease of its generation is held. The
/// check and the send are one step, under the lock [`Lease`]'s drop takes,
/// so once the last lease's drop has returned, no send it didn't cover can
/// follow; the send itself doesn't block ([`query::ask`]).
struct LeaseGate<'a> {
    shared: &'a Shared,
    generation: u64,
}

impl query::Gate for LeaseGate<'_> {
    fn run(&self, send: &dyn Fn() -> std::io::Result<usize>) -> Option<std::io::Result<usize>> {
        let control = self.shared.lock();
        if control.leases == 0 || control.generation != self.generation {
            return None;
        }
        #[cfg(test)]
        self.shared.before_send();
        let sent = send();
        drop(control);
        Some(sent)
    }
}

/// A resolver as logs name it.
fn describe(resolver: &Learned) -> String {
    match resolver {
        Learned::Ask(addr) => addr.to_string(),
        Learned::Unaskable(text) => text.clone(),
    }
}

/// How long to wait after `round`: its TTL within the floor and the
/// ceiling, or after a failure the backoff, which `backoff` carries from
/// one failed round to the next.
pub fn next_delay(round: &Round, backoff: &mut Option<Duration>, timing: &Timing) -> Duration {
    if round.failures.is_empty() {
        *backoff = None;
        round
            .ttl
            .unwrap_or(timing.ceiling)
            .clamp(timing.floor, timing.ceiling)
    } else {
        let delay = backoff.map_or(timing.backoff, |last| (last * 2).min(timing.ceiling));
        *backoff = Some(delay);
        delay
    }
}

/// A state's name, as logs and stats give it.
pub fn state_name(state: &Nat64State) -> &'static str {
    match state {
        Nat64State::Pending => "pending",
        Nat64State::Known(_) => "known",
        Nat64State::Unknown(_) => "unknown",
        Nat64State::Incomplete(_) => "incomplete",
    }
}

/// A query ID: unpredictable from outside the process (std's randomly
/// keyed hasher, over the time and a count).
fn query_id() -> u16 {
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(COUNT.fetch_add(1, Ordering::Relaxed));
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default(),
    );
    (hasher.finish() & 0xffff) as u16
}

#[cfg(test)]
mod tests {
    use super::query::tests::{reply_to, resolver};
    use super::*;
    use hickory_proto::op::ResponseCode;
    use std::net::Ipv6Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::Receiver;

    fn v6(text: &str) -> Ipv6Addr {
        text.parse().unwrap()
    }

    fn prefix(text: &str, len: u8) -> Nat64Prefix {
        Nat64Prefix::new(v6(text), len).unwrap()
    }

    /// An `ipv4only.arpa` answer under `prefix`, a /96: 192.0.0.170 last.
    fn under(prefix: &str) -> Ipv6Addr {
        let mut segments = v6(prefix).segments();
        segments[6] = 0xc000;
        segments[7] = 0x00aa;
        Ipv6Addr::from(segments)
    }

    const FAST: Timing = Timing {
        attempt: Duration::from_millis(150),
        attempts: 1,
        floor: Duration::from_millis(50),
        ceiling: Duration::from_millis(200),
        backoff: Duration::from_millis(50),
    };

    /// A resolver whose answer `answers` holds, changeable: the prefixes
    /// its AAAA records embed at /96, or `None` to answer SERVFAIL.
    fn dns64(answers: Arc<Mutex<Option<Vec<&'static str>>>>) -> (SocketAddr, Receiver<Vec<u8>>) {
        resolver(move |query| {
            let answer = answers.lock().unwrap().clone();
            vec![match answer {
                Some(prefixes) => {
                    let records: Vec<(Ipv6Addr, u32)> =
                        prefixes.iter().map(|prefix| (under(prefix), 30)).collect();
                    reply_to(query, ResponseCode::NoError, &records, None, |_| {})
                }
                None => reply_to(query, ResponseCode::ServFail, &[], None, |_| {}),
            }]
        })
    }

    fn ask(addr: SocketAddr) -> Learned {
        Learned::Ask(addr)
    }

    #[test]
    fn a_round_is_the_union_of_every_answer() {
        // Two interfaces: one's resolver advertises a prefix, the other's
        // answers NODATA, as a VPN beside the physical link.
        let (one, _) = dns64(Arc::new(Mutex::new(Some(vec!["2a00:1:2:3::"]))));
        let (other, _) = dns64(Arc::new(Mutex::new(Some(vec![]))));
        let mut kept = Vec::new();
        let union = round(
            &[ask(one), ask(other)],
            &mut kept,
            &FAST,
            &query::Open,
            &|_| {},
        );
        assert_eq!(
            union.state,
            Nat64State::Known(vec![prefix("2a00:1:2:3::", 96)])
        );
        assert!(union.failures.is_empty());
        assert_eq!(union.ttl, Some(Duration::from_secs(30)));
    }

    #[test]
    fn a_rounds_ttl_is_its_answers_smallest() {
        let records = |ttl: u32| {
            move |query: &[u8]| {
                vec![reply_to(
                    query,
                    ResponseCode::NoError,
                    &[(under("2a00:1:2:3::"), ttl)],
                    None,
                    |_| {},
                )]
            }
        };
        let (long, _) = resolver(records(300));
        let (short, _) = resolver(records(40));
        let mut kept = Vec::new();
        let both = round(
            &[ask(long), ask(short)],
            &mut kept,
            &FAST,
            &query::Open,
            &|_| {},
        );
        assert_eq!(both.ttl, Some(Duration::from_secs(40)));
    }

    #[test]
    fn one_resolver_failing_leaves_the_state_unknown() {
        let (answers, _) = dns64(Arc::new(Mutex::new(Some(vec!["2a00:1:2:3::"]))));
        let (failing, _) = dns64(Arc::new(Mutex::new(None)));
        let mut kept = Vec::new();
        let failed = round(
            &[ask(answers), ask(failing)],
            &mut kept,
            &FAST,
            &query::Open,
            &|_| {},
        );
        assert_eq!(
            failed.state,
            Nat64State::Unknown(vec![prefix("2a00:1:2:3::", 96)])
        );
        assert_eq!(failed.failures, vec![(failing.to_string(), "rcode")]);
        // So does one that can't be asked.
        let mut kept = Vec::new();
        let unaskable = round(
            &[ask(answers), Learned::Unaskable("fe80::1%wlan9".into())],
            &mut kept,
            &FAST,
            &query::Open,
            &|_| {},
        );
        assert_eq!(
            unaskable.state,
            Nat64State::Unknown(vec![prefix("2a00:1:2:3::", 96)])
        );
        assert_eq!(
            unaskable.failures,
            vec![("fe80::1%wlan9".to_string(), "unaskable")]
        );
    }

    #[test]
    fn no_resolver_listed_is_known_and_empty() {
        let mut kept = Vec::new();
        let none = round(&[], &mut kept, &FAST, &query::Open, &|_| {});
        assert_eq!(none.state, Nat64State::NONE);
        assert_eq!(none.ttl, None);
    }

    #[test]
    fn learned_prefixes_are_kept_and_past_sixteen_the_state_is_incomplete() {
        let answers = Arc::new(Mutex::new(Some(vec!["2a00:1:2:3::"])));
        let (addr, _) = dns64(answers.clone());
        let mut kept = Vec::new();
        round(&[ask(addr)], &mut kept, &FAST, &query::Open, &|_| {});
        // A refresh that drops the prefix doesn't forget it.
        *answers.lock().unwrap() = Some(vec![]);
        assert_eq!(
            round(&[ask(addr)], &mut kept, &FAST, &query::Open, &|_| {}).state,
            Nat64State::Known(vec![prefix("2a00:1:2:3::", 96)])
        );
        // A failed refresh keeps it too.
        *answers.lock().unwrap() = None;
        assert_eq!(
            round(&[ask(addr)], &mut kept, &FAST, &query::Open, &|_| {}).state,
            Nat64State::Unknown(vec![prefix("2a00:1:2:3::", 96)])
        );
        // Seventeen distinct prefixes: incomplete, for good.
        let seventeen: Vec<&'static str> = vec![
            "2a00:1:1::",
            "2a00:1:2::",
            "2a00:1:3::",
            "2a00:1:4::",
            "2a00:1:5::",
            "2a00:1:6::",
            "2a00:1:7::",
            "2a00:1:8::",
            "2a00:1:9::",
            "2a00:1:a::",
            "2a00:1:b::",
            "2a00:1:c::",
            "2a00:1:d::",
            "2a00:1:e::",
            "2a00:1:f::",
            "2a00:1:10::",
            "2a00:1:11::",
        ];
        *answers.lock().unwrap() = Some(seventeen);
        let state = round(&[ask(addr)], &mut kept, &FAST, &query::Open, &|_| {}).state;
        assert!(
            matches!(state, Nat64State::Incomplete(ref kept) if kept.len() == 16),
            "{state:?}"
        );
        *answers.lock().unwrap() = Some(vec![]);
        assert!(matches!(
            round(&[ask(addr)], &mut kept, &FAST, &query::Open, &|_| {}).state,
            Nat64State::Incomplete(_)
        ));
        assert_eq!(kept.len(), Nat64State::MAX_PREFIXES + 1);
    }

    #[test]
    fn refresh_follows_the_ttl_within_bounds_and_backs_off_after_failure() {
        let known = |ttl: Option<u64>| Round {
            state: Nat64State::NONE,
            failures: vec![],
            ttl: ttl.map(Duration::from_secs),
        };
        let failed = Round {
            state: Nat64State::unknown([]),
            failures: vec![("192.0.2.1:53".into(), "timeout")],
            ttl: None,
        };
        let mut backoff = None;
        let timing = Timing::DESIGN;
        assert_eq!(
            next_delay(&known(Some(30)), &mut backoff, &timing),
            Duration::from_secs(30)
        );
        assert_eq!(
            next_delay(&known(Some(3600)), &mut backoff, &timing),
            Duration::from_secs(60)
        );
        assert_eq!(
            next_delay(&known(Some(0)), &mut backoff, &timing),
            Duration::from_secs(5)
        );
        assert_eq!(
            next_delay(&known(None), &mut backoff, &timing),
            Duration::from_secs(60)
        );
        let backoffs: Vec<u64> = (0..6)
            .map(|_| next_delay(&failed, &mut backoff, &timing).as_secs())
            .collect();
        assert_eq!(backoffs, vec![5, 10, 20, 40, 60, 60]);
        // A success resets it.
        next_delay(&known(Some(30)), &mut backoff, &timing);
        assert_eq!(
            next_delay(&failed, &mut backoff, &timing),
            Duration::from_secs(5)
        );
    }

    fn wait_for(discovery: &Discovery, wanted: impl Fn(&Nat64State) -> bool) -> Nat64State {
        wait_within(discovery, Duration::from_secs(5), wanted)
    }

    /// The state once `wanted` holds, or as it is after `within`.
    fn wait_within(
        discovery: &Discovery,
        within: Duration,
        wanted: impl Fn(&Nat64State) -> bool,
    ) -> Nat64State {
        let deadline = Instant::now() + within;
        loop {
            let state = discovery.state();
            if wanted(&state) || Instant::now() > deadline {
                return state;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn pending_until_a_lease_then_published_and_refreshed() {
        let answers = Arc::new(Mutex::new(Some(vec!["2a00:1:2:3::"])));
        let (addr, queries) = dns64(answers.clone());
        let asked = Arc::new(AtomicUsize::new(0));
        let counted = asked.clone();
        let target = Arc::new(Mutex::new(addr));
        let listed = target.clone();
        let discovery = Discovery::new(
            Arc::new(move || {
                counted.fetch_add(1, Ordering::SeqCst);
                vec![Learned::Ask(*listed.lock().unwrap())]
            }),
            FAST,
        );
        // Nothing runs, and nothing is sent, without a lease.
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(discovery.state(), Nat64State::Pending);
        assert_eq!(asked.load(Ordering::SeqCst), 0);
        assert!(queries.try_recv().is_err());

        let lease = discovery.lease();
        let handle = discovery.handle();
        assert_eq!(
            wait_for(&discovery, |state| *state != Nat64State::Pending),
            Nat64State::Known(vec![prefix("2a00:1:2:3::", 96)])
        );
        assert_eq!(handle.current(), discovery.state());
        // Refreshed: a failing resolver turns it unknown, with the prefix.
        *answers.lock().unwrap() = None;
        assert_eq!(
            wait_for(&discovery, |state| matches!(state, Nat64State::Unknown(_))),
            Nat64State::Unknown(vec![prefix("2a00:1:2:3::", 96)])
        );
        // And back.
        *answers.lock().unwrap() = Some(vec!["2a00:5::"]);
        assert_eq!(
            wait_for(&discovery, |state| matches!(state, Nat64State::Known(_))),
            Nat64State::Known(vec![prefix("2a00:1:2:3::", 96), prefix("2a00:5::", 96)])
        );

        // Paused: no lease, no query, and no round: the list isn't read.
        drop(lease);
        std::thread::sleep(Duration::from_millis(300));
        while queries.try_recv().is_ok() {}
        let read = asked.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(500));
        assert!(queries.try_recv().is_err(), "a query while paused");
        assert_eq!(asked.load(Ordering::SeqCst), read, "a round while paused");

        // Resumed: pending at once. Its first round asks a resolver that
        // never answers, so it is still pending when read; then known again.
        let (silent, _) = resolver(|_| vec![]);
        *target.lock().unwrap() = silent;
        let _lease = discovery.lease();
        assert_eq!(discovery.state(), Nat64State::Pending);
        *target.lock().unwrap() = addr;
        assert!(matches!(
            wait_for(&discovery, |state| matches!(state, Nat64State::Known(_))),
            Nat64State::Known(_)
        ));
    }

    #[test]
    fn stats_give_the_state_its_prefixes_and_why_resolvers_failed() {
        let answers = Arc::new(Mutex::new(Some(vec!["2001:db8:64::"])));
        let (addr, _) = dns64(answers.clone());
        let listed = Arc::new(Mutex::new(vec![Learned::Ask(addr)]));
        let source = listed.clone();
        let discovery = Discovery::new(Arc::new(move || source.lock().unwrap().clone()), FAST);
        assert_eq!(
            discovery.stats(),
            json!({ "state": "pending", "prefixes": [], "failures": [] })
        );
        let lease = discovery.lease();
        wait_for(&discovery, |state| matches!(state, Nat64State::Known(_)));
        assert_eq!(
            discovery.stats(),
            json!({ "state": "known", "prefixes": ["2001:db8:64::/96"], "failures": [] })
        );
        // Unknown, then unknown for another reason: the reasons follow the
        // last round, though the state doesn't change.
        *answers.lock().unwrap() = None;
        wait_for(&discovery, |state| matches!(state, Nat64State::Unknown(_)));
        let failed = |discovery: &Discovery| discovery.stats()["failures"].clone();
        let deadline = Instant::now() + Duration::from_secs(5);
        while failed(&discovery) != json!(["rcode"]) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(failed(&discovery), json!(["rcode"]));
        *listed.lock().unwrap() = vec![Learned::Unaskable("fe80::1".into())];
        let deadline = Instant::now() + Duration::from_secs(5);
        while failed(&discovery) != json!(["unaskable"]) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            discovery.stats(),
            json!({ "state": "unknown", "prefixes": ["2001:db8:64::/96"], "failures": ["unaskable"] })
        );
        // Paused, then resumed: pending, with no failure of its own yet. The
        // resumed round asks a resolver that never answers, so it is still
        // pending when read.
        let (silent, _) = resolver(|_| vec![]);
        *listed.lock().unwrap() = vec![Learned::Ask(silent)];
        drop(lease);
        let _lease = discovery.lease();
        assert_eq!(
            discovery.stats(),
            json!({ "state": "pending", "prefixes": [], "failures": [] })
        );
    }

    #[test]
    fn every_query_is_ipv4only_arpa_aaaa_and_only_to_the_resolvers_learned() {
        let (one, one_queries) = dns64(Arc::new(Mutex::new(Some(vec![]))));
        let (two, two_queries) = dns64(Arc::new(Mutex::new(Some(vec![]))));
        let mut kept = Vec::new();
        round(
            &[ask(one), ask(two), ask(one)],
            &mut kept,
            &FAST,
            &query::Open,
            &|_| {},
        );
        for queries in [one_queries, two_queries] {
            let sent: Vec<Vec<u8>> = queries.try_iter().collect();
            assert!(!sent.is_empty());
            for query in sent {
                let message = hickory_proto::op::Message::from_vec(&query).unwrap();
                assert_eq!(message.queries().len(), 1);
                assert_eq!(message.queries()[0].name().to_ascii(), query::NAME);
                assert_eq!(
                    message.queries()[0].query_type(),
                    hickory_proto::rr::RecordType::AAAA
                );
            }
        }
    }

    /// A resolver that takes queries and never answers: each one it gets
    /// is reported.
    fn silent() -> (SocketAddr, Receiver<Vec<u8>>) {
        resolver(|_| vec![])
    }

    /// A one-round timing: a refresh only after `ceiling`.
    fn slow(attempt: Duration, attempts: u32) -> Timing {
        Timing {
            attempt,
            attempts,
            ceiling: Duration::from_secs(30),
            floor: Duration::from_secs(30),
            ..FAST
        }
    }

    #[test]
    fn a_pause_stops_the_round_under_way_and_it_is_not_published() {
        // A full round of resolvers that never answer, each sent to twice.
        let silent: Vec<(SocketAddr, Receiver<Vec<u8>>)> =
            (0..MAX_RESOLVERS).map(|_| silent()).collect();
        let learned: Vec<Learned> = silent.iter().map(|(addr, _)| ask(*addr)).collect();
        let discovery = Discovery::new(
            Arc::new(move || learned.clone()),
            slow(Duration::from_millis(300), 2),
        );
        let lease = discovery.lease();
        for (_, queries) in &silent {
            queries.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        drop(lease);
        // Past both sends: no resend, and nothing published.
        std::thread::sleep(Duration::from_millis(900));
        for (_, queries) in &silent {
            assert!(queries.try_recv().is_err(), "a resend after the pause");
        }
        assert_eq!(discovery.state(), Nat64State::Pending);
        assert_eq!(discovery.stats()["failures"], json!([]));
    }

    #[test]
    fn the_last_leases_drop_waits_for_the_send_it_allowed_and_nothing_follows() {
        // Both reviews' round 2 probes, for a gate that holds the lock
        // through the send: between a send's check and the send, under the
        // lock, the hook waits 200 ms, for the first send and for the
        // resend. The last lease's drop, called then, returns only once
        // that send is done, and nothing follows it.
        for (delayed, sent_before) in [(1, 1), (2, 2)] {
            let (addr, queries) = silent();
            let discovery = Discovery::new(
                Arc::new(move || vec![ask(addr)]),
                slow(Duration::from_millis(300), 3),
            );
            let checked = Arc::new(std::sync::Barrier::new(2));
            let hook_checked = checked.clone();
            let sends = Arc::new(AtomicUsize::new(0));
            *discovery.shared.before_send.lock().unwrap() = Some(Arc::new(move || {
                if sends.fetch_add(1, Ordering::SeqCst) + 1 == delayed {
                    hook_checked.wait();
                    std::thread::sleep(Duration::from_millis(200));
                }
            }));
            let lease = discovery.lease();
            // That send has passed its check, and hasn't sent.
            checked.wait();
            let dropping = Instant::now();
            drop(lease);
            let waited = dropping.elapsed();
            assert!(
                waited >= Duration::from_millis(150),
                "send {delayed}: {waited:?}"
            );
            // The sends it allowed, and nothing after.
            for _ in 0..sent_before {
                queries.recv_timeout(Duration::from_secs(1)).unwrap();
            }
            assert!(
                queries.recv_timeout(Duration::from_millis(700)).is_err(),
                "send {delayed}: a send after the last lease's drop"
            );
        }
    }

    #[test]
    fn a_pause_stops_resolvers_not_yet_asked() {
        // The adversarial review's probe: a ninth resolver, past the first
        // round's resolvers, is never asked after a pause (nor before it:
        // it is past the bound).
        let first: Vec<(SocketAddr, Receiver<Vec<u8>>)> =
            (0..MAX_RESOLVERS).map(|_| silent()).collect();
        let (ninth, ninth_queries) = silent();
        let mut learned: Vec<Learned> = first.iter().map(|(addr, _)| ask(*addr)).collect();
        learned.push(ask(ninth));
        let discovery = Discovery::new(
            Arc::new(move || learned.clone()),
            slow(Duration::from_millis(150), 1),
        );
        let lease = discovery.lease();
        for (_, queries) in &first {
            queries.recv_timeout(Duration::from_secs(1)).unwrap();
        }
        drop(lease);
        assert!(
            ninth_queries
                .recv_timeout(Duration::from_millis(400))
                .is_err(),
            "the paused discovery sent to a resolver it hadn't asked"
        );
    }

    #[test]
    fn the_refresh_counts_from_the_rounds_start() {
        // A full round, one resolver answering 400 ms late; every answer's
        // TTL is past the 500 ms ceiling. Counted from the round's start,
        // rounds start about 500 ms apart; from its end, about 900 ms.
        let answer = |query: &[u8]| {
            vec![reply_to(
                query,
                ResponseCode::NoError,
                &[(under("2001:db8:64::"), 300)],
                None,
                |_| {},
            )]
        };
        let starts = Arc::new(Mutex::new(Vec::<Instant>::new()));
        let seen = starts.clone();
        let (first, _) = resolver(move |query| {
            seen.lock().unwrap().push(Instant::now());
            answer(query)
        });
        let mut learned = vec![ask(first)];
        for _ in 2..MAX_RESOLVERS {
            learned.push(ask(resolver(answer).0));
        }
        learned.push(ask(resolver(move |query| {
            std::thread::sleep(Duration::from_millis(400));
            answer(query)
        })
        .0));
        let timing = Timing {
            attempt: Duration::from_secs(3),
            attempts: 1,
            floor: Duration::from_millis(50),
            ceiling: Duration::from_millis(500),
            backoff: Duration::from_millis(50),
        };
        let discovery = Discovery::new(Arc::new(move || learned.clone()), timing);
        let _lease = discovery.lease();
        let deadline = Instant::now() + Duration::from_secs(10);
        while starts.lock().unwrap().len() < 4 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let starts = starts.lock().unwrap().clone();
        assert!(starts.len() >= 4, "{}", starts.len());
        assert_eq!(
            discovery.state(),
            Nat64State::Known(vec![prefix("2001:db8:64::", 96)])
        );
        for pair in starts.windows(2) {
            let interval = pair[1] - pair[0];
            assert!(interval < Duration::from_millis(750), "{interval:?}");
        }
    }

    #[test]
    fn past_eight_resolvers_the_rest_are_not_asked_and_the_state_is_unknown() {
        // The bound decided for a round: the first eight the OS lists.
        assert_eq!(MAX_RESOLVERS, 8);
        let answering = Arc::new(Mutex::new(Some(vec!["2001:db8:64::"])));
        let resolvers: Vec<(SocketAddr, Receiver<Vec<u8>>)> = (0..=MAX_RESOLVERS)
            .map(|_| dns64(answering.clone()))
            .collect();
        let learned: Vec<Learned> = resolvers.iter().map(|(addr, _)| ask(*addr)).collect();
        let mut kept = Vec::new();
        let round = round(&learned, &mut kept, &FAST, &query::Open, &|_| {});
        assert_eq!(
            round.state,
            Nat64State::Unknown(vec![prefix("2001:db8:64::", 96)])
        );
        assert_eq!(
            round.failures,
            vec![(resolvers[MAX_RESOLVERS].0.to_string(), "over_limit")]
        );
        for (_, queries) in &resolvers[..MAX_RESOLVERS] {
            assert!(queries.try_recv().is_ok());
        }
        assert!(
            resolvers[MAX_RESOLVERS].1.try_recv().is_err(),
            "the ninth was asked"
        );
    }

    /// Discovery that knows no prefix from one answering resolver, then
    /// refreshes against `then`, every 30 ms, or `backoff` after a failed
    /// round's start.
    fn known_then(then: Vec<Learned>, attempt: Duration, backoff: Duration) -> Discovery {
        let (good, _) = dns64(Arc::new(Mutex::new(Some(vec![]))));
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        Discovery::new(
            Arc::new(move || {
                if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                    vec![Learned::Ask(good)]
                } else {
                    then.clone()
                }
            }),
            Timing {
                attempt,
                attempts: 1,
                floor: Duration::from_millis(30),
                ceiling: Duration::from_millis(30),
                backoff,
            },
        )
    }

    #[test]
    fn a_known_state_ends_at_the_first_failure_not_the_rounds_end() {
        // The adversarial review's probe, in one round: a resolver that
        // fails at once, beside one that never answers within its 2 s.
        let (failing, _) = dns64(Arc::new(Mutex::new(None)));
        let (quiet, quiet_queries) = silent();
        let discovery = known_then(
            vec![ask(failing), ask(quiet)],
            Duration::from_secs(2),
            Duration::from_secs(4),
        );
        let _lease = discovery.lease();
        assert_eq!(
            wait_for(&discovery, |state| *state != Nat64State::Pending),
            Nat64State::NONE
        );
        // The refresh is under way: the quiet one has its query, and won't
        // time out for 2 s. The failure is established already: pending,
        // well before the quiet one's 2 s are up.
        quiet_queries.recv_timeout(Duration::from_secs(2)).unwrap();
        let state = wait_within(&discovery, Duration::from_millis(800), |state| {
            *state == Nat64State::Pending
        });
        assert_eq!(state, Nat64State::Pending);
        let target: std::net::IpAddr = "2a00:1:2:3::7f00:1".parse().unwrap();
        assert!(freedom_ipfs_gateway::net::gate::check_address(target, &state).is_err());
        // Pending, with the failure it is pending for.
        assert_eq!(discovery.stats()["state"], "pending");
        assert_eq!(discovery.stats()["failures"], json!(["rcode"]));
        // The round's end: unknown.
        let state = wait_for(&discovery, |state| matches!(state, Nat64State::Unknown(_)));
        assert!(matches!(state, Nat64State::Unknown(_)), "{state:?}");
        assert!(freedom_ipfs_gateway::net::gate::check_address(target, &state).is_err());
    }

    #[test]
    fn an_early_failure_admits_no_fixed_form_before_the_rounds_other_answers() {
        // The adversarial review's round 2 probe. Known without a prefix;
        // on the refresh, one resolver fails at once while another is held
        // before it advertises a /96 under 6to4. Read as 6to4,
        // `2002:808:808::7f00:1` is 8.8.8.8; under that /96, 127.0.0.1.
        let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let released = release.clone();
        let (learning, learning_queries) = resolver(move |query| {
            let (lock, wake) = &*released;
            let ready = lock.lock().unwrap();
            let _ready = wake.wait_while(ready, |ready| !*ready).unwrap();
            vec![reply_to(
                query,
                ResponseCode::NoError,
                &[(v6("2002:808:808::c000:aa"), 30)],
                None,
                |_| {},
            )]
        });
        let (failing, _) = dns64(Arc::new(Mutex::new(None)));
        let discovery = known_then(
            vec![ask(learning), ask(failing)],
            Duration::from_secs(2),
            Duration::from_secs(4),
        );
        let _lease = discovery.lease();
        assert_eq!(
            wait_for(&discovery, |state| *state != Nat64State::Pending),
            Nat64State::NONE
        );
        learning_queries
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        let target: std::net::IpAddr = "2002:808:808::7f00:1".parse().unwrap();
        // While the learning answer is out: pending, which admits no IPv6
        // target but an IPv4-mapped one.
        let early = wait_within(&discovery, Duration::from_secs(1), |state| {
            *state == Nat64State::Pending
        });
        assert_eq!(early, Nat64State::Pending);
        assert!(freedom_ipfs_gateway::net::gate::check_address(target, &early).is_err());
        let mapped: std::net::IpAddr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(freedom_ipfs_gateway::net::gate::check_address(mapped, &early).is_ok());
        // Released: the round's end, unknown with the /96, refuses it.
        let (lock, wake) = &*release;
        *lock.lock().unwrap() = true;
        wake.notify_all();
        let end = wait_for(
            &discovery,
            |state| matches!(state, Nat64State::Unknown(prefixes) if !prefixes.is_empty()),
        );
        assert_eq!(end, Nat64State::unknown([prefix("2002:808:808::", 96)]));
        assert!(freedom_ipfs_gateway::net::gate::check_address(target, &end).is_err());
    }

    #[test]
    fn a_resolver_past_the_bound_ends_a_known_state_when_the_round_begins() {
        let first: Vec<(SocketAddr, Receiver<Vec<u8>>)> =
            (0..MAX_RESOLVERS).map(|_| silent()).collect();
        let mut then: Vec<Learned> = first.iter().map(|(addr, _)| ask(*addr)).collect();
        then.push(ask(silent().0));
        let discovery = known_then(then, Duration::from_secs(2), Duration::from_secs(4));
        let _lease = discovery.lease();
        assert_eq!(
            wait_for(&discovery, |state| *state != Nat64State::Pending),
            Nat64State::NONE
        );
        first[0].1.recv_timeout(Duration::from_secs(2)).unwrap();
        // Well before any of the round's 2 s timeouts: pending.
        let state = wait_within(&discovery, Duration::from_millis(800), |state| {
            *state == Nat64State::Pending
        });
        assert_eq!(state, Nat64State::Pending);
        assert_eq!(discovery.stats()["failures"], json!(["over_limit"]));
    }

    #[test]
    fn query_ids_vary() {
        let ids: std::collections::HashSet<u16> = (0..64).map(|_| query_id()).collect();
        assert!(ids.len() > 48, "{}", ids.len());
    }
}
