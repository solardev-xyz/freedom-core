//! What the connection's reader thread and the verifier thread share: the
//! budgets' counts (design 0014, Budgets) and `colibri.stats`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::store::Store;

/// Open requests a persistent or private process takes (main sends at
/// most 8: 0004's bound per verifier).
pub const MAX_OPEN_REQUESTS: usize = 16;
/// Bodies in flight: the heads' exact `bytes`, reserved before credit.
pub const MAX_BODIES: u64 = 32 << 20;
/// Resident memory above which a persistent or private process recycles.
pub const MAX_RESIDENT: u64 = 256 << 20;

/// A checkpoint process's: one check, 8 MiB of bodies, and 128 MiB, past
/// which the check fails.
pub const CHECKPOINT_BODIES: u64 = 8 << 20;
pub const CHECKPOINT_RESIDENT: u64 = 128 << 20;

/// Which process this is (0014, "Spawn").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// A chain's persistent process, or a private session's.
    Serve,
    /// The one-shot checkpoint process: one `colibri.checkpoint`.
    Checkpoint,
}

/// The recycle flag in [`Shared`]'s count of open requests.
const RECYCLING: u64 = 1 << 63;

pub struct Shared {
    pub chain_id: u64,
    pub mode: Mode,
    max_open: u64,
    max_resident: u64,
    pub store: Arc<Store>,
    /// Requests accepted and not yet answered, with [`RECYCLING`] in the
    /// top bit: once above its memory budget, new requests are refused
    /// with `busy`, the open ones finish, then the process exits 0 (a
    /// recycle, no fault). One word, so admission and the recycle point
    /// fall in one order: no request is taken after the flag is set, and
    /// the last request out always sees it.
    open: AtomicU64,
    /// Steps run.
    steps: AtomicU64,
    /// Calls into the C core for requests, each behind its marker.
    calls: AtomicU64,
    /// Resident memory after the last step, in bytes (0 where it isn't
    /// read).
    resident: AtomicU64,
    /// Bodies reserved and not yet given back.
    pub bodies: Arc<AtomicU64>,
    pub bodies_limit: u64,
}

/// Why a request isn't taken.
#[derive(Debug, PartialEq, Eq)]
pub enum NotTaken {
    /// At [`MAX_OPEN_REQUESTS`].
    Full,
    /// Recycling.
    Recycling,
}

impl Shared {
    pub fn new(chain_id: u64, store: Arc<Store>, mode: Mode) -> Shared {
        let (max_open, bodies_limit, max_resident) = match mode {
            Mode::Serve => (MAX_OPEN_REQUESTS as u64, MAX_BODIES, MAX_RESIDENT),
            Mode::Checkpoint => (1, CHECKPOINT_BODIES, CHECKPOINT_RESIDENT),
        };
        Shared {
            chain_id,
            mode,
            max_open,
            max_resident: crate::testhooks::memory_budget().unwrap_or(max_resident),
            store,
            open: AtomicU64::new(0),
            steps: AtomicU64::new(0),
            calls: AtomicU64::new(0),
            resident: AtomicU64::new(0),
            bodies: Arc::new(AtomicU64::new(0)),
            bodies_limit,
        }
    }

    /// Takes a request, within the budget, unless recycling.
    pub fn take_request(&self) -> Result<(), NotTaken> {
        self.open
            .try_update(Ordering::AcqRel, Ordering::Acquire, |open| {
                (open & RECYCLING == 0 && open < self.max_open).then_some(open + 1)
            })
            .map(|_| ())
            .map_err(|open| {
                if open & RECYCLING == 0 {
                    NotTaken::Full
                } else {
                    NotTaken::Recycling
                }
            })
    }

    /// A request is answered. True when the process should now end: it is
    /// recycling and nothing is open.
    pub fn request_done(&self) -> bool {
        let before = self.open.fetch_sub(1, Ordering::AcqRel);
        before == RECYCLING | 1
    }

    /// A call into the C core for a request is made.
    pub fn call_done(&self) {
        self.calls.fetch_add(1, Ordering::Relaxed);
    }

    /// A step ran: counted, and resident memory read against the budget.
    pub fn step_done(&self) {
        self.steps.fetch_add(1, Ordering::Relaxed);
        if let Some(bytes) = resident_bytes() {
            self.resident.store(bytes, Ordering::Relaxed);
            // A checkpoint process doesn't recycle: its check fails
            // ([`Shared::over_resident`]).
            if bytes > self.max_resident && self.mode == Mode::Serve {
                self.recycle();
            }
        }
    }

    /// Whether resident memory, as read after the last step, is past the
    /// process's budget: a checkpoint check then fails.
    pub fn over_resident(&self) -> bool {
        self.resident.load(Ordering::Relaxed) > self.max_resident
    }

    /// Starts the recycle. Only a step does, so a request is open: the
    /// last one out ends the process.
    fn recycle(&self) {
        self.open.fetch_or(RECYCLING, Ordering::AcqRel);
    }

    pub fn recycling(&self) -> bool {
        self.open.load(Ordering::Acquire) & RECYCLING != 0
    }

    /// `colibri.stats`.
    pub fn stats(&self) -> serde_json::Value {
        serde_json::json!({
            "open_requests": self.open.load(Ordering::Acquire) & !RECYCLING,
            "steps": self.steps.load(Ordering::Relaxed),
            "calls": self.calls.load(Ordering::Relaxed),
            "resident_bytes": self.resident.load(Ordering::Relaxed),
            "store_bytes": self.store.total(),
            "store_keys": self.store.keys(),
            "recycling": self.recycling(),
        })
    }
}

/// The process's resident memory (0014, Budgets): `VmRSS` in
/// `/proc/self/status` on Linux, `proc_taskinfo`'s resident size on macOS,
/// and the working set on Windows (both through `fc-sys`).
#[cfg(target_os = "linux")]
pub fn resident_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    let kib: u64 = line
        .trim_start_matches("VmRSS:")
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    kib.checked_mul(1024)
}

#[cfg(target_os = "macos")]
pub fn resident_bytes() -> Option<u64> {
    fc_sys::macos::resident_bytes().ok()
}

#[cfg(windows)]
pub fn resident_bytes() -> Option<u64> {
    fc_sys::windows::resident_bytes().ok()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn resident_bytes() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_bounded() {
        let shared = Shared::new(1, Arc::new(Store::memory()), Mode::Serve);
        for _ in 0..MAX_OPEN_REQUESTS {
            assert_eq!(shared.take_request(), Ok(()));
        }
        assert_eq!(shared.take_request(), Err(NotTaken::Full));
        assert!(!shared.request_done());
        assert_eq!(shared.take_request(), Ok(()));
        shared.recycle();
        assert_eq!(shared.take_request(), Err(NotTaken::Recycling));
        for _ in 0..MAX_OPEN_REQUESTS - 1 {
            assert!(!shared.request_done());
        }
        // The last one out ends a recycling process.
        assert!(shared.request_done());
    }

    #[test]
    fn a_checkpoint_process_takes_one_check() {
        let shared = Shared::new(1, Arc::new(Store::memory()), Mode::Checkpoint);
        assert_eq!(shared.take_request(), Ok(()));
        assert_eq!(shared.take_request(), Err(NotTaken::Full));
        assert_eq!(shared.bodies_limit, CHECKPOINT_BODIES);
    }

    #[test]
    fn a_request_taken_as_the_recycle_starts_is_not_lost() {
        // Admitted just before the flag: open 1 -> 2, the flag, then the
        // first request's end (2 -> 1) doesn't end the process, the
        // second's does.
        let shared = Shared::new(1, Arc::new(Store::memory()), Mode::Serve);
        assert_eq!(shared.take_request(), Ok(()));
        assert_eq!(shared.take_request(), Ok(()));
        shared.recycle();
        assert_eq!(shared.take_request(), Err(NotTaken::Recycling));
        assert!(!shared.request_done());
        assert!(shared.request_done());
        assert_eq!(shared.stats()["open_requests"], 0);
    }

    #[test]
    fn admissions_racing_the_recycle_end_the_process_once() {
        for _ in 0..500 {
            let shared = Arc::new(Shared::new(1, Arc::new(Store::memory()), Mode::Serve));
            // The request whose step starts the recycle, then ends.
            assert_eq!(shared.take_request(), Ok(()));
            let ends = Arc::new(AtomicU64::new(0));
            let barrier = Arc::new(std::sync::Barrier::new(3));
            let readers: Vec<_> = (0..2)
                .map(|_| {
                    let (shared, ends) = (Arc::clone(&shared), Arc::clone(&ends));
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        barrier.wait();
                        loop {
                            match shared.take_request() {
                                Ok(()) => {
                                    if shared.request_done() {
                                        ends.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                Err(NotTaken::Full) => {}
                                Err(NotTaken::Recycling) => return,
                            }
                        }
                    })
                })
                .collect();
            barrier.wait();
            shared.recycle();
            if shared.request_done() {
                ends.fetch_add(1, Ordering::Relaxed);
            }
            for reader in readers {
                reader.join().unwrap();
            }
            // Whichever request was last out, the process ends, once.
            assert_eq!(ends.load(Ordering::Relaxed), 1);
            assert_eq!(shared.stats()["open_requests"], 0);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn resident_memory_is_read() {
        let bytes = resident_bytes().unwrap();
        assert!(bytes > 1 << 20 && bytes < 1 << 40, "{bytes}");
    }
}
