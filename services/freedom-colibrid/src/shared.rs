//! What the connection's reader thread and the verifier thread share: the
//! budgets' counts (design 0014, Budgets) and `colibri.stats`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

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

pub struct Shared {
    pub chain_id: u64,
    pub mode: Mode,
    max_open: usize,
    max_resident: u64,
    pub store: Arc<Store>,
    /// Requests accepted and not yet answered.
    open: AtomicUsize,
    /// Steps run.
    steps: AtomicU64,
    /// Resident memory after the last step, in bytes (0 where it isn't
    /// read).
    resident: AtomicU64,
    /// Above its memory budget: new requests are refused with `busy`, the
    /// open ones finish, then the process exits 0 (a recycle, no fault).
    recycling: AtomicBool,
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
            Mode::Serve => (MAX_OPEN_REQUESTS, MAX_BODIES, MAX_RESIDENT),
            Mode::Checkpoint => (1, CHECKPOINT_BODIES, CHECKPOINT_RESIDENT),
        };
        Shared {
            chain_id,
            mode,
            max_open,
            max_resident,
            store,
            open: AtomicUsize::new(0),
            steps: AtomicU64::new(0),
            resident: AtomicU64::new(0),
            recycling: AtomicBool::new(false),
            bodies: Arc::new(AtomicU64::new(0)),
            bodies_limit,
        }
    }

    /// Takes a request, within the budget.
    pub fn take_request(&self) -> Result<(), NotTaken> {
        if self.recycling.load(Ordering::Acquire) {
            return Err(NotTaken::Recycling);
        }
        self.open
            .try_update(Ordering::AcqRel, Ordering::Acquire, |open| {
                (open < self.max_open).then_some(open + 1)
            })
            .map(|_| ())
            .map_err(|_| NotTaken::Full)
    }

    /// A request is answered. True when the process should now end: it is
    /// recycling and nothing is open.
    pub fn request_done(&self) -> bool {
        let before = self.open.fetch_sub(1, Ordering::AcqRel);
        before == 1 && self.recycling.load(Ordering::Acquire)
    }

    /// A step ran: counted, and resident memory read against the budget.
    pub fn step_done(&self) {
        self.steps.fetch_add(1, Ordering::Relaxed);
        if let Some(bytes) = resident_bytes() {
            self.resident.store(bytes, Ordering::Relaxed);
            if bytes > self.max_resident && self.mode == Mode::Serve {
                self.recycling.store(true, Ordering::Release);
            }
        }
    }

    /// Whether resident memory, as read after the last step, is past the
    /// process's budget: a checkpoint check then fails.
    pub fn over_resident(&self) -> bool {
        self.resident.load(Ordering::Relaxed) > self.max_resident
    }

    pub fn recycling(&self) -> bool {
        self.recycling.load(Ordering::Acquire)
    }

    /// `colibri.stats`.
    pub fn stats(&self) -> serde_json::Value {
        serde_json::json!({
            "open_requests": self.open.load(Ordering::Acquire),
            "steps": self.steps.load(Ordering::Relaxed),
            "resident_bytes": self.resident.load(Ordering::Relaxed),
            "store_bytes": self.store.total(),
            "store_keys": self.store.keys(),
            "recycling": self.recycling(),
        })
    }
}

/// The process's resident memory: `VmRSS` in `/proc/self/status` on Linux
/// (0014, Budgets). Elsewhere it isn't read yet, and the budget isn't
/// applied: macOS's `task_info` needs an OS call of `fc-sys`'s kind.
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

#[cfg(not(target_os = "linux"))]
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
        shared.recycling.store(true, Ordering::Release);
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

    #[cfg(target_os = "linux")]
    #[test]
    fn resident_memory_is_read() {
        let bytes = resident_bytes().unwrap();
        assert!(bytes > 1 << 20 && bytes < 1 << 40, "{bytes}");
    }
}
