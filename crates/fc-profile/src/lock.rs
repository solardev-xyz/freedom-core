//! The lock format older builds share with the core: proper-lockfile 4.1.2's
//! staleness rule, and the profile lock's and the catalog write lock's
//! timings (`profile-lock.js`, `profile-catalog.js`). The locking itself, a
//! directory made with `mkdir` and kept by refreshing its mtime, is
//! `freedom-cored`'s.

/// The profile lock's stale time in a packaged build (`DEFAULT_STALE_MS`),
/// and the catalog write lock's in every build.
pub const STALE_MS: u64 = 30_000;
/// How often a holder refreshes a packaged profile lock, or the catalog
/// write lock (`DEFAULT_UPDATE_MS`).
pub const UPDATE_MS: u64 = 10_000;
/// A dev build's profile lock (`DEV_STALE_MS`, `DEV_UPDATE_MS`).
pub const DEV_STALE_MS: u64 = 5_000;
pub const DEV_UPDATE_MS: u64 = 1_000;

/// The catalog write lock's retries (`DEFAULT_CATALOG_LOCK_RETRIES`): five,
/// waiting `min(250, 50 × (n + 1))` ms before the n-th.
pub const CATALOG_LOCK_RETRIES: u32 = 5;

/// The wait before the catalog write lock's retry `n` (from 0).
pub fn catalog_retry_delay_ms(n: u32) -> u64 {
    (50 * (u64::from(n) + 1)).min(250)
}

/// proper-lockfile's `stale` option as it applies it: at least 2 s.
pub fn effective_stale_ms(stale_ms: u64) -> u64 {
    stale_ms.max(2_000)
}

/// proper-lockfile's `update` option as it applies it: half the stale time
/// when unset, then between 1 s and half the stale time.
pub fn effective_update_ms(stale_ms: u64, update_ms: Option<u64>) -> u64 {
    let stale = effective_stale_ms(stale_ms);
    let update = update_ms.unwrap_or(stale / 2);
    update.min(stale / 2).max(1_000)
}

/// proper-lockfile's `isLockStale`: a lock whose mtime is more than the
/// stale time before now (`mtime < now - stale`), both in whole
/// milliseconds. At exactly the stale time it is still fresh.
pub fn is_stale(mtime_ms: i64, now_ms: i64, stale_ms: u64) -> bool {
    let stale = i64::try_from(effective_stale_ms(stale_ms)).unwrap_or(i64::MAX);
    mtime_ms < now_ms.saturating_sub(stale)
}

/// `getProfileLockTiming`: (stale, update) for a profile's lock.
pub fn profile_lock_timing(dev: bool) -> (u64, u64) {
    if dev {
        (DEV_STALE_MS, DEV_UPDATE_MS)
    } else {
        (STALE_MS, UPDATE_MS)
    }
}

/// The mtime proper-lockfile's holder sets when it takes a lock (its
/// precision probe): now rounded up to the second, plus 5 ms, so it isn't
/// on a second.
pub fn probe_mtime_ms(now_ms: i64) -> i64 {
    now_ms.div_euclid(1000) * 1000
        + if now_ms.rem_euclid(1000) == 0 {
            0
        } else {
            1000
        }
        + 5
}

/// The mtime a refresh sets: now, or rounded up to the second where the
/// filesystem keeps only seconds (the probe read one back on a second).
pub fn refresh_mtime_ms(now_ms: i64, seconds_only: bool) -> i64 {
    if seconds_only {
        now_ms.div_euclid(1000) * 1000
            + if now_ms.rem_euclid(1000) == 0 {
                0
            } else {
                1000
            }
    } else {
        now_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staleness_is_proper_lockfiles() {
        let now = 1_000_000;
        assert!(!is_stale(now - 29_999, now, STALE_MS));
        assert!(!is_stale(now - 30_000, now, STALE_MS));
        assert!(is_stale(now - 30_001, now, STALE_MS));
        assert!(!is_stale(now - 2_000, now, 10));
        assert!(is_stale(now - 2_001, now, 10));
        assert_eq!(effective_update_ms(30_000, Some(10_000)), 10_000);
        assert_eq!(effective_update_ms(5_000, Some(1_000)), 1_000);
        assert_eq!(effective_update_ms(5_000, None), 2_500);
        assert_eq!(probe_mtime_ms(1_000), 1_005);
        assert_eq!(probe_mtime_ms(1_001), 2_005);
        assert_eq!(refresh_mtime_ms(1_001, true), 2_000);
        assert_eq!(catalog_retry_delay_ms(0), 50);
        assert_eq!(catalog_retry_delay_ms(9), 250);
    }
}
