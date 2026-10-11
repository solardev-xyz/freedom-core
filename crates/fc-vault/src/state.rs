//! The vault's lock state: the one place that holds the mnemonic and seed,
//! so any lock (manual, auto, delete, shutdown) wipes them at once. Derived
//! keys aren't cached: each accessor derives on demand and returns an owned
//! key that wipes itself on drop. That keeps memory bounded, and no cache can
//! outlive a lock. This is the structural fix for K-1, where auto-lock
//! cleared the mnemonic but left derived keys cached elsewhere.
//!
//! **Unlocking is split in three,** so the expensive parts never run under
//! the state, and a lock always wins:
//!
//! 1. [`VaultState::ticket`] records the current generation (control path).
//! 2. [`Prepared::new`] decrypts and computes the seed (worker thread).
//! 3. [`VaultState::install`] installs it only if no lock or unlock happened
//!    since the ticket was taken (control path). Otherwise the prepared
//!    secrets are wiped and the result is [`Error::Revoked`].
//!
//! Every lock request bumps the generation, even while already locked, so
//! an unlock that is still deriving can never bring secrets back after a
//! lock.
//!
//! Time is a caller-supplied monotonic millisecond counter; this crate reads
//! no clock.

use fc_keys::freedom::{self, FreedomKeys};
use fc_keys::{Mnemonic, Secp256k1Key, Seed};

use crate::Error;

/// Default auto-lock delay: 15 minutes, as freedom-browser's `vault.js`.
pub const DEFAULT_AUTO_LOCK_MS: u64 = 15 * 60 * 1000;

/// Identifies one unlocked period. Work started under an epoch may install
/// results only while that epoch is still current.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(u64);

impl Epoch {
    pub fn get(self) -> u64 {
        self.0
    }
}

/// Permission to install an unlock, valid until the next lock or unlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "pass the ticket to VaultState::install"]
pub struct Ticket(u64);

/// A decrypted mnemonic with its seed, ready to install. Built on a worker
/// thread; wiped on drop if it's never installed.
pub struct Prepared {
    mnemonic: Mnemonic,
    seed: Seed,
}

impl Prepared {
    /// Computes the seed (PBKDF2, 2048 rounds): run it off the control path.
    pub fn new(mnemonic: Mnemonic) -> Self {
        let seed = mnemonic.to_seed();
        Prepared { mnemonic, seed }
    }
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Prepared(<redacted>)")
    }
}

/// Why the vault was locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    Manual,
    Auto,
    Delete,
    Shutdown,
}

/// Emitted when a lock revoked an unlocked epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Locked {
    pub epoch: Epoch,
    pub reason: LockReason,
}

struct Unlocked {
    epoch: Epoch,
    prepared: Prepared,
    /// Zero disables auto-lock.
    auto_lock_ms: u64,
    deadline_ms: Option<u64>,
}

/// The vault's lock state. Dropping it, or locking, wipes the secrets it
/// holds.
pub struct VaultState {
    /// Bumped by every lock and every install; tickets and epochs are taken
    /// from it, so none ever repeats.
    generation: u64,
    unlocked: Option<Unlocked>,
}

impl Default for VaultState {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultState {
    pub fn new() -> Self {
        VaultState {
            generation: 0,
            unlocked: None,
        }
    }

    /// Step 1 of an unlock: a ticket for the current generation.
    pub fn ticket(&self) -> Ticket {
        Ticket(self.generation)
    }

    /// Step 3 of an unlock: installs `prepared` if nothing locked or
    /// unlocked since `ticket` was taken, and starts the auto-lock timer
    /// (`auto_lock_ms == 0` disables it). On [`Error::Revoked`], `prepared`
    /// has been wiped.
    pub fn install(
        &mut self,
        ticket: Ticket,
        prepared: Prepared,
        auto_lock_ms: u64,
        now_ms: u64,
    ) -> Result<Epoch, Error> {
        if ticket.0 != self.generation {
            return Err(Error::Revoked);
        }
        let generation = self.generation.checked_add(1).ok_or(Error::Exhausted)?;
        self.generation = generation;
        let epoch = Epoch(generation);
        self.unlocked = Some(Unlocked {
            epoch,
            prepared,
            auto_lock_ms,
            deadline_ms: deadline(now_ms, auto_lock_ms),
        });
        Ok(epoch)
    }

    /// Locks and wipes the secrets. Always invalidates outstanding tickets,
    /// even when already locked. Returns the revoked epoch, if there was one.
    pub fn lock(&mut self, reason: LockReason) -> Option<Locked> {
        // At 2^64 locks the counter stops moving; install then refuses with
        // Exhausted instead of reusing a generation.
        self.generation = self.generation.saturating_add(1);
        self.unlocked.take().map(|unlocked| Locked {
            epoch: unlocked.epoch,
            reason,
        })
    }

    /// The current epoch, if unlocked.
    pub fn epoch(&self) -> Option<Epoch> {
        self.unlocked.as_ref().map(|u| u.epoch)
    }

    pub fn is_unlocked(&self) -> bool {
        self.unlocked.is_some()
    }

    /// Whether `epoch` is still the current unlocked epoch. Worker results
    /// from any other epoch must be wiped, not installed.
    pub fn is_current(&self, epoch: Epoch) -> bool {
        self.epoch() == Some(epoch)
    }

    /// Restarts the auto-lock timer after a successful operation
    /// (`resetAutoLockTimer`). No effect while locked.
    pub fn touch(&mut self, now_ms: u64) {
        if let Some(unlocked) = &mut self.unlocked {
            unlocked.deadline_ms = deadline(now_ms, unlocked.auto_lock_ms);
        }
    }

    /// When the auto-lock timer fires, if it runs.
    pub fn auto_lock_deadline(&self) -> Option<u64> {
        self.unlocked.as_ref().and_then(|u| u.deadline_ms)
    }

    /// Applies the auto-lock if its deadline has passed.
    pub fn tick(&mut self, now_ms: u64) -> Option<Locked> {
        match self.auto_lock_deadline() {
            Some(deadline) if now_ms >= deadline => self.lock(LockReason::Auto),
            _ => None,
        }
    }

    /// The unlocked mnemonic, for the user-requested export and for writing
    /// a vault under a new password.
    pub fn mnemonic(&self) -> Result<&Mnemonic, Error> {
        Ok(&self.unlocked()?.prepared.mnemonic)
    }

    /// The keys of `deriveAllKeys`, derived now; they wipe on drop.
    pub fn freedom_keys(&self) -> Result<FreedomKeys, Error> {
        freedom::derive_all(&self.unlocked()?.prepared.seed).map_err(Error::Keys)
    }

    /// User wallet `account` (`m/44'/60'/{account}'/0/0`), derived now.
    pub fn user_wallet(&self, account: u32) -> Result<Secp256k1Key, Error> {
        freedom::derive_user_wallet(&self.unlocked()?.prepared.seed, account).map_err(Error::Keys)
    }

    /// Swarm publisher key `origin` (`m/44'/73406'/{origin}'/0/0`), derived
    /// now.
    pub fn publisher(&self, origin: u32) -> Result<Secp256k1Key, Error> {
        freedom::derive_publisher(&self.unlocked()?.prepared.seed, origin).map_err(Error::Keys)
    }

    fn unlocked(&self) -> Result<&Unlocked, Error> {
        self.unlocked.as_ref().ok_or(Error::Locked)
    }
}

impl std::fmt::Debug for VaultState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultState")
            .field("epoch", &self.epoch())
            .field("auto_lock_deadline", &self.auto_lock_deadline())
            .finish_non_exhaustive()
    }
}

fn deadline(now_ms: u64, auto_lock_ms: u64) -> Option<u64> {
    (auto_lock_ms > 0).then(|| now_ms.saturating_add(auto_lock_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn prepared() -> Prepared {
        Prepared::new(Mnemonic::parse(PHRASE).unwrap())
    }

    fn unlock(state: &mut VaultState, auto_lock_ms: u64, now: u64) -> Epoch {
        let ticket = state.ticket();
        state
            .install(ticket, prepared(), auto_lock_ms, now)
            .unwrap()
    }

    #[test]
    fn starts_locked() {
        let mut state = VaultState::new();
        assert!(!state.is_unlocked());
        assert_eq!(state.mnemonic().unwrap_err(), Error::Locked);
        assert_eq!(state.user_wallet(0).unwrap_err(), Error::Locked);
        assert_eq!(state.lock(LockReason::Manual), None);
    }

    #[test]
    fn auto_lock_makes_every_key_unreachable() {
        let mut state = VaultState::new();
        let epoch = unlock(&mut state, 1000, 0);
        let address = state.user_wallet(0).unwrap().address().to_string();
        assert_eq!(address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
        state.publisher(3).unwrap();
        state.freedom_keys().unwrap();

        assert_eq!(state.tick(999), None);
        assert_eq!(
            state.tick(1000),
            Some(Locked {
                epoch,
                reason: LockReason::Auto
            })
        );
        // K-1: after auto-lock no derived key is reachable.
        assert_eq!(state.user_wallet(0).unwrap_err(), Error::Locked);
        assert_eq!(state.publisher(3).unwrap_err(), Error::Locked);
        assert_eq!(state.freedom_keys().map(|_| ()).unwrap_err(), Error::Locked);
        assert_eq!(state.mnemonic().map(|_| ()).unwrap_err(), Error::Locked);
        assert!(!state.is_current(epoch));
    }

    #[test]
    fn a_lock_revokes_an_unlock_in_progress() {
        // The lock happens while the vault is still locked, between the
        // ticket and the install (PR #6 review, M1).
        for reason in [LockReason::Manual, LockReason::Delete, LockReason::Shutdown] {
            let mut state = VaultState::new();
            let ticket = state.ticket();
            let work = prepared();
            assert_eq!(state.lock(reason), None);
            assert_eq!(
                state.install(ticket, work, 0, 0).unwrap_err(),
                Error::Revoked
            );
            assert!(!state.is_unlocked(), "{reason:?}");
        }
    }

    #[test]
    fn overlapping_unlocks_install_once() {
        let mut state = VaultState::new();
        let first = state.ticket();
        let second = state.ticket();
        let epoch = state.install(first, prepared(), 0, 0).unwrap();
        assert_eq!(
            state.install(second, prepared(), 0, 0).unwrap_err(),
            Error::Revoked
        );
        assert!(state.is_current(epoch));
    }

    #[test]
    fn touch_extends_and_zero_disables() {
        let mut state = VaultState::new();
        unlock(&mut state, 1000, 0);
        state.touch(900);
        assert_eq!(state.tick(1500), None);
        assert!(state.tick(1900).is_some());

        unlock(&mut state, 0, 0);
        assert_eq!(state.auto_lock_deadline(), None);
        assert_eq!(state.tick(u64::MAX), None);
    }

    #[test]
    fn epochs_never_repeat() {
        let mut state = VaultState::new();
        let first = unlock(&mut state, 0, 0);
        state.lock(LockReason::Manual);
        state.lock(LockReason::Manual);
        let second = unlock(&mut state, 0, 0);
        assert!(second > first);
        assert!(!state.is_current(first));
    }

    #[test]
    fn generation_exhaustion_fails_closed() {
        let mut state = VaultState {
            generation: u64::MAX,
            unlocked: None,
        };
        let ticket = state.ticket();
        assert_eq!(
            state.install(ticket, prepared(), 0, 0).unwrap_err(),
            Error::Exhausted
        );
        assert!(!state.is_unlocked());
        // Locking at the limit doesn't wrap around to an old generation.
        state.lock(LockReason::Manual);
        assert_eq!(state.ticket(), Ticket(u64::MAX));
    }

    #[test]
    fn debug_hides_secrets() {
        let mut state = VaultState::new();
        unlock(&mut state, 0, 0);
        assert!(!format!("{state:?}").contains("abandon"));
        assert_eq!(format!("{:?}", prepared()), "Prepared(<redacted>)");
    }
}
