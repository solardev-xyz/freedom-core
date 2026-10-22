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
//!   ([`Timing::ceiling`]), so a network change leaves about a minute when
//!   a new network's prefix is unknown; each round reads the resolvers
//!   again. After a failure, with backoff from 5 s to a minute.
//! - **The result belongs to the process,** not to an instance. It runs
//!   only while a `direct` instance holds a [`Lease`]: a `socks5` instance
//!   learns nothing (the exit makes every connection), and a process with
//!   none sends no query. Resumed after a pause, the state is pending
//!   again, since the network may have changed meanwhile.

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

use self::query::{Answer, Failure};
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

/// The most resolvers asked at once, each from a thread of its own.
const CONCURRENT: usize = 8;

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

/// What a round learned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Round {
    pub state: Nat64State,
    /// The resolvers that failed, or couldn't be asked, and why.
    pub failures: Vec<(String, &'static str)>,
    /// The smallest TTL the answers gave.
    pub ttl: Option<Duration>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Control> {
        self.control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Publishes `state` and its round's failures, and logs a change.
    fn publish(&self, state: Nat64State, failures: &[(String, &'static str)]) {
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
            let round = round(&(self.source)(), &mut kept, &self.timing);
            let mut control = self.lock();
            if control.leases > 0 && control.generation == generation {
                self.publish(round.state.clone(), &round.failures);
            }
            let delay = next_delay(&round, &mut backoff, &self.timing);
            let deadline = Instant::now() + delay;
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

/// One round: every resolver `learned` lists, asked at once (a few at a
/// time), its answers added to `kept`, the prefixes learned so far.
pub fn round(learned: &[Learned], kept: &mut Vec<Nat64Prefix>, timing: &Timing) -> Round {
    let mut failures = Vec::new();
    let mut asked: Vec<SocketAddr> = Vec::new();
    for resolver in learned {
        match resolver {
            Learned::Ask(addr) => asked.push(*addr),
            Learned::Unaskable(text) => failures.push((text.clone(), "unaskable")),
        }
    }
    let mut ttl: Option<Duration> = None;
    for chunk in asked.chunks(CONCURRENT) {
        let answers: Vec<(SocketAddr, Result<Answer, Failure>)> = std::thread::scope(|scope| {
            let asking: Vec<_> = chunk
                .iter()
                .map(|addr| {
                    let addr = *addr;
                    scope.spawn(move || {
                        (
                            addr,
                            query::ask(addr, query_id(), timing.attempt, timing.attempts),
                        )
                    })
                })
                .collect();
            asking
                .into_iter()
                .zip(chunk)
                .map(|(asking, addr)| asking.join().unwrap_or((*addr, Err(Failure::Socket))))
                .collect()
        });
        for (addr, answer) in answers {
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
                Err(failure) => failures.push((addr.to_string(), failure.as_str())),
            }
        }
    }
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
        let union = round(&[ask(one), ask(other)], &mut kept, &FAST);
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
        let both = round(&[ask(long), ask(short)], &mut kept, &FAST);
        assert_eq!(both.ttl, Some(Duration::from_secs(40)));
    }

    #[test]
    fn one_resolver_failing_leaves_the_state_unknown() {
        let (answers, _) = dns64(Arc::new(Mutex::new(Some(vec!["2a00:1:2:3::"]))));
        let (failing, _) = dns64(Arc::new(Mutex::new(None)));
        let mut kept = Vec::new();
        let failed = round(&[ask(answers), ask(failing)], &mut kept, &FAST);
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
        let none = round(&[], &mut kept, &FAST);
        assert_eq!(none.state, Nat64State::NONE);
        assert_eq!(none.ttl, None);
    }

    #[test]
    fn learned_prefixes_are_kept_and_past_sixteen_the_state_is_incomplete() {
        let answers = Arc::new(Mutex::new(Some(vec!["2a00:1:2:3::"])));
        let (addr, _) = dns64(answers.clone());
        let mut kept = Vec::new();
        round(&[ask(addr)], &mut kept, &FAST);
        // A refresh that drops the prefix doesn't forget it.
        *answers.lock().unwrap() = Some(vec![]);
        assert_eq!(
            round(&[ask(addr)], &mut kept, &FAST).state,
            Nat64State::Known(vec![prefix("2a00:1:2:3::", 96)])
        );
        // A failed refresh keeps it too.
        *answers.lock().unwrap() = None;
        assert_eq!(
            round(&[ask(addr)], &mut kept, &FAST).state,
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
        let state = round(&[ask(addr)], &mut kept, &FAST).state;
        assert!(
            matches!(state, Nat64State::Incomplete(ref kept) if kept.len() == 16),
            "{state:?}"
        );
        *answers.lock().unwrap() = Some(vec![]);
        assert!(matches!(
            round(&[ask(addr)], &mut kept, &FAST).state,
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
        let deadline = Instant::now() + Duration::from_secs(5);
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
        let discovery = Discovery::new(
            Arc::new(move || {
                counted.fetch_add(1, Ordering::SeqCst);
                vec![Learned::Ask(addr)]
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

        // Paused: no lease, no query.
        drop(lease);
        std::thread::sleep(Duration::from_millis(300));
        while queries.try_recv().is_ok() {}
        std::thread::sleep(Duration::from_millis(500));
        assert!(queries.try_recv().is_err(), "a query while paused");

        // Resumed: pending at once, then known again.
        let _lease = discovery.lease();
        assert_eq!(discovery.state(), Nat64State::Pending);
        assert!(matches!(
            wait_for(&discovery, |state| *state != Nat64State::Pending),
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
        round(&[ask(one), ask(two), ask(one)], &mut kept, &FAST);
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

    #[test]
    fn query_ids_vary() {
        let ids: std::collections::HashSet<u16> = (0..64).map(|_| query_id()).collect();
        assert!(ids.len() > 48, "{}", ids.len());
    }
}
