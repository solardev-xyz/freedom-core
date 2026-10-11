//! The vault's lock state: one place that holds the mnemonic, the seed and
//! every derived key, so that any lock (manual, auto, delete, shutdown) wipes
//! all of them at once. This is the structural fix for K-1, where auto-lock
//! cleared the mnemonic but left derived keys cached elsewhere.
//!
//! Time is a caller-supplied monotonic millisecond counter; this crate reads
//! no clock.

use std::collections::BTreeMap;

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
    mnemonic: Mnemonic,
    seed: Seed,
    /// Zero disables auto-lock.
    auto_lock_ms: u64,
    deadline_ms: Option<u64>,
    freedom: Option<FreedomKeys>,
    user_wallets: BTreeMap<u32, Secp256k1Key>,
    publishers: BTreeMap<u32, Secp256k1Key>,
}

/// The vault's lock state. Dropping it, or locking, wipes every secret it
/// holds.
pub struct VaultState {
    last_epoch: u64,
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
            last_epoch: 0,
            unlocked: None,
        }
    }

    /// Installs `mnemonic` as the unlocked vault in a new epoch, and starts
    /// the auto-lock timer (`auto_lock_ms == 0` disables it). An existing
    /// unlocked epoch is revoked first.
    pub fn unlock(
        &mut self,
        mnemonic: Mnemonic,
        auto_lock_ms: u64,
        now_ms: u64,
    ) -> (Epoch, Option<Locked>) {
        let revoked = self.lock(LockReason::Manual);
        self.last_epoch += 1;
        let epoch = Epoch(self.last_epoch);
        let seed = mnemonic.to_seed();
        self.unlocked = Some(Unlocked {
            epoch,
            mnemonic,
            seed,
            auto_lock_ms,
            deadline_ms: deadline(now_ms, auto_lock_ms),
            freedom: None,
            user_wallets: BTreeMap::new(),
            publishers: BTreeMap::new(),
        });
        (epoch, revoked)
    }

    /// Locks and wipes everything. Returns the revoked epoch, or `None` if
    /// the vault was already locked.
    pub fn lock(&mut self, reason: LockReason) -> Option<Locked> {
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
        Ok(&self.unlocked()?.mnemonic)
    }

    /// The keys of `deriveAllKeys`, derived on first use and cached until
    /// the next lock.
    pub fn freedom_keys(&mut self) -> Result<&FreedomKeys, Error> {
        let unlocked = self.unlocked_mut()?;
        if unlocked.freedom.is_none() {
            unlocked.freedom = Some(freedom::derive_all(&unlocked.seed).map_err(Error::Keys)?);
        }
        unlocked
            .freedom
            .as_ref()
            .ok_or(Error::Internal("freedom keys"))
    }

    /// User wallet `account` (`m/44'/60'/{account}'/0/0`), cached until the
    /// next lock.
    pub fn user_wallet(&mut self, account: u32) -> Result<&Secp256k1Key, Error> {
        let unlocked = self.unlocked_mut()?;
        if !unlocked.user_wallets.contains_key(&account) {
            let key = freedom::derive_user_wallet(&unlocked.seed, account).map_err(Error::Keys)?;
            unlocked.user_wallets.insert(account, key);
        }
        unlocked
            .user_wallets
            .get(&account)
            .ok_or(Error::Internal("user wallet"))
    }

    /// Swarm publisher key `origin` (`m/44'/73406'/{origin}'/0/0`), cached
    /// until the next lock.
    pub fn publisher(&mut self, origin: u32) -> Result<&Secp256k1Key, Error> {
        let unlocked = self.unlocked_mut()?;
        if !unlocked.publishers.contains_key(&origin) {
            let key = freedom::derive_publisher(&unlocked.seed, origin).map_err(Error::Keys)?;
            unlocked.publishers.insert(origin, key);
        }
        unlocked
            .publishers
            .get(&origin)
            .ok_or(Error::Internal("publisher key"))
    }

    fn unlocked(&self) -> Result<&Unlocked, Error> {
        self.unlocked.as_ref().ok_or(Error::Locked)
    }

    fn unlocked_mut(&mut self) -> Result<&mut Unlocked, Error> {
        self.unlocked.as_mut().ok_or(Error::Locked)
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

    fn mnemonic() -> Mnemonic {
        Mnemonic::parse(PHRASE).unwrap()
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
    fn auto_lock_wipes_every_cache() {
        let mut state = VaultState::new();
        let (epoch, _) = state.unlock(mnemonic(), 1000, 0);
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
        // K-1: after auto-lock no derived key is reachable, whatever cached it.
        assert_eq!(state.user_wallet(0).unwrap_err(), Error::Locked);
        assert_eq!(state.publisher(3).unwrap_err(), Error::Locked);
        assert_eq!(state.freedom_keys().unwrap_err(), Error::Locked);
        assert_eq!(state.mnemonic().unwrap_err(), Error::Locked);
        assert!(!state.is_current(epoch));
    }

    #[test]
    fn touch_extends_and_zero_disables() {
        let mut state = VaultState::new();
        state.unlock(mnemonic(), 1000, 0);
        state.touch(900);
        assert_eq!(state.tick(1500), None);
        assert!(state.tick(1900).is_some());

        state.unlock(mnemonic(), 0, 0);
        assert_eq!(state.auto_lock_deadline(), None);
        assert_eq!(state.tick(u64::MAX), None);
        state.touch(5);
        assert!(state.is_unlocked());
    }

    #[test]
    fn epochs_never_repeat() {
        let mut state = VaultState::new();
        let (first, _) = state.unlock(mnemonic(), 0, 0);
        let (second, revoked) = state.unlock(mnemonic(), 0, 0);
        assert_eq!(
            revoked,
            Some(Locked {
                epoch: first,
                reason: LockReason::Manual
            })
        );
        assert!(second > first);
        assert!(!state.is_current(first));
        state.lock(LockReason::Shutdown);
        let (third, revoked) = state.unlock(mnemonic(), 0, 0);
        assert_eq!(revoked, None);
        assert!(third > second);
    }

    #[test]
    fn debug_hides_secrets() {
        let mut state = VaultState::new();
        state.unlock(mnemonic(), 0, 0);
        let debug = format!("{state:?}");
        assert!(!debug.contains("abandon"), "{debug}");
    }
}
