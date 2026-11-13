//! proper-lockfile's lock, as the profile catalog's write lock and the
//! profile lock use it (design 0013, 5.1, "The catalog's write lock"; "The
//! lock"), so the core and every older build exclude each other:
//!
//! - **Taking it:** `mkdir` of the lock directory. If it exists, its mtime
//!   decides: more than the stale time old, it is removed and taken; fresh,
//!   the lock is held by another. On taking it, the holder sets its mtime
//!   to the next second plus 5 ms and reads it back, which tells whether
//!   the filesystem keeps milliseconds.
//! - **Keeping it:** a thread that does nothing else refreshes the mtime
//!   every update period. At each refresh it first checks the mtime is
//!   still the one it set: if not, or if the directory is gone, or if
//!   refreshes have failed past the stale time, the lock is compromised,
//!   another process may hold it, and nothing more may be written under it.
//! - **Letting go:** the directory is removed, unless the lock was
//!   compromised (it is then another's).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fc_profile::lock as rules;

/// Milliseconds since the epoch, now.
pub fn now_ms() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

/// A path's mtime in whole milliseconds, as a JavaScript `Date` holds it
/// (following a symlink, as `fs.stat`).
pub fn mtime_ms(path: &Path) -> std::io::Result<i64> {
    let modified = std::fs::metadata(path)?.modified()?;
    Ok(match modified.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        // Before the epoch: a Date truncates toward zero.
        Err(e) => -i64::try_from(e.duration().as_millis()).unwrap_or(i64::MAX),
    })
}

/// Sets a directory's access and modification times (`fs.utimes`).
fn set_mtime(dir: &Path, ms: i64) -> std::io::Result<()> {
    let time = if ms >= 0 {
        UNIX_EPOCH + Duration::from_millis(ms.unsigned_abs())
    } else {
        UNIX_EPOCH - Duration::from_millis(ms.unsigned_abs())
    };
    let times = std::fs::FileTimes::new()
        .set_accessed(time)
        .set_modified(time);
    open_dir_for_times(dir)?.set_times(times)
}

#[cfg(unix)]
fn open_dir_for_times(dir: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(dir)
}

#[cfg(windows)]
fn open_dir_for_times(dir: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_WRITE_ATTRIBUTES, and FILE_FLAG_BACKUP_SEMANTICS to open a
    // directory.
    std::fs::OpenOptions::new()
        .access_mode(0x0100)
        .custom_flags(0x0200_0000)
        .open(dir)
}

/// Whether the lock at `lock_dir` (with its `target`) is fresh: proper-
/// lockfile's `checkSync`, as `isProfileLocked` calls it. No target, or no
/// lock directory, is not locked; neither is one that can't be read.
pub fn is_fresh(target: &Path, lock_dir: &Path, stale_ms: u64) -> bool {
    if std::fs::metadata(target).is_err() {
        return false;
    }
    match mtime_ms(lock_dir) {
        Ok(mtime) => !rules::is_stale(mtime, now_ms(), stale_ms),
        Err(_) => false,
    }
}

#[derive(Debug)]
pub enum LockError {
    /// Another process holds it, through every retry (exit 75).
    Held,
    /// The lock directory couldn't be made, read or set (exit 74).
    Io(std::io::Error),
}

/// The timings a lock runs on.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub stale_ms: u64,
    pub update_ms: u64,
}

impl Timing {
    /// The catalog's write lock (`profile-catalog.js`).
    pub const CATALOG: Timing = Timing {
        stale_ms: rules::STALE_MS,
        update_ms: rules::UPDATE_MS,
    };
}

struct State {
    released: bool,
    compromised: bool,
    /// The mtime this holder set last.
    mtime_ms: i64,
    /// When it last set it.
    last_update_ms: i64,
    /// The filesystem keeps whole seconds only.
    seconds_only: bool,
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
}

/// A held lock. Dropping it lets go.
pub struct Lock {
    lock_dir: PathBuf,
    shared: Arc<Shared>,
    refresher: Option<std::thread::JoinHandle<()>>,
}

impl Lock {
    /// Takes the lock at `lock_dir`, with `retries` more tries after the
    /// first, waiting `delay(n)` before try `n + 1`, then keeps it from a
    /// thread of its own.
    pub fn acquire(
        lock_dir: &Path,
        timing: Timing,
        retries: u32,
        delay: impl Fn(u32) -> u64,
    ) -> Result<Lock, LockError> {
        let mut attempt = 0;
        let taken = loop {
            match take(lock_dir, timing.stale_ms) {
                Ok(taken) => break taken,
                Err(LockError::Held) if attempt < retries => {
                    std::thread::sleep(Duration::from_millis(delay(attempt)));
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        };
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                released: false,
                compromised: false,
                mtime_ms: taken.mtime_ms,
                last_update_ms: now_ms(),
                seconds_only: taken.seconds_only,
            }),
            wake: Condvar::new(),
        });
        let refresher = {
            let shared = Arc::clone(&shared);
            let lock_dir = lock_dir.to_owned();
            std::thread::Builder::new()
                .name("profile-lock".into())
                .spawn(move || refresh(&lock_dir, &shared, timing))
                .map_err(LockError::Io)?
        };
        Ok(Lock {
            lock_dir: lock_dir.to_owned(),
            shared,
            refresher: Some(refresher),
        })
    }

    /// The catalog's write lock at `app_root`: its target file made if
    /// missing, as the reference does, and five retries 50 to 250 ms apart.
    pub fn catalog(app_root: &Path, created_at: &str) -> Result<Lock, LockError> {
        let target = app_root.join(fc_profile::CATALOG_LOCK_TARGET);
        if std::fs::symlink_metadata(&target).is_err() {
            let text = format!("Freedom profile catalog write lock target\ncreatedAt={created_at}");
            // Nothing reads it: a failed write doesn't stop the lock.
            let _ = std::fs::write(&target, text);
        }
        Lock::acquire(
            &app_root.join(fc_profile::CATALOG_LOCK_DIR),
            Timing::CATALOG,
            rules::CATALOG_LOCK_RETRIES,
            rules::catalog_retry_delay_ms,
        )
    }

    /// Whether the lock is still this holder's: nothing may be committed
    /// under one that isn't.
    pub fn held(&self) -> bool {
        self.shared
            .state
            .lock()
            .map(|state| !state.compromised && !state.released)
            .unwrap_or(false)
    }

    /// Lets go: the directory is removed unless the lock was compromised.
    pub fn release(mut self) -> bool {
        self.let_go()
    }

    fn let_go(&mut self) -> bool {
        let compromised = match self.shared.state.lock() {
            Ok(mut state) => {
                if state.released {
                    return !state.compromised;
                }
                state.released = true;
                state.compromised
            }
            Err(_) => true,
        };
        self.shared.wake.notify_all();
        if let Some(refresher) = self.refresher.take() {
            let _ = refresher.join();
        }
        if compromised {
            return false;
        }
        match std::fs::remove_dir(&self.lock_dir) {
            Ok(()) => true,
            Err(e) => e.kind() == std::io::ErrorKind::NotFound,
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        self.let_go();
    }
}

struct Taken {
    mtime_ms: i64,
    seconds_only: bool,
}

/// One try: `mkdir`, or a stale lock removed and `mkdir` again (with no
/// second staleness check, as proper-lockfile).
fn take(lock_dir: &Path, stale_ms: u64) -> Result<Taken, LockError> {
    let mut check_stale = true;
    loop {
        match std::fs::create_dir(lock_dir) {
            Ok(()) => return probe(lock_dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(LockError::Io(e)),
        }
        if !check_stale {
            return Err(LockError::Held);
        }
        check_stale = false;
        match mtime_ms(lock_dir) {
            // Gone meanwhile: try again.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(LockError::Io(e)),
            Ok(mtime) if !rules::is_stale(mtime, now_ms(), stale_ms) => {
                return Err(LockError::Held);
            }
            Ok(_) => match std::fs::remove_dir(lock_dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(LockError::Io(e)),
            },
        }
    }
}

/// proper-lockfile's precision probe, on a lock just made.
fn probe(lock_dir: &Path) -> Result<Taken, LockError> {
    let set = rules::probe_mtime_ms(now_ms());
    let read = set_mtime(lock_dir, set).and_then(|()| mtime_ms(lock_dir));
    match read {
        Ok(mtime) => Ok(Taken {
            mtime_ms: mtime,
            seconds_only: mtime.rem_euclid(1000) == 0,
        }),
        Err(e) => {
            let _ = std::fs::remove_dir(lock_dir);
            Err(LockError::Io(e))
        }
    }
}

/// The refresher: every update period, the mtime checked, then set again.
fn refresh(lock_dir: &Path, shared: &Shared, timing: Timing) {
    let update = Duration::from_millis(rules::effective_update_ms(
        timing.stale_ms,
        Some(timing.update_ms),
    ));
    let stale = i64::try_from(rules::effective_stale_ms(timing.stale_ms)).unwrap_or(i64::MAX);
    let mut delay = update;
    let Ok(mut state) = shared.state.lock() else {
        return;
    };
    loop {
        let (next, _) = match shared
            .wake
            .wait_timeout_while(state, delay, |s| !s.released)
        {
            Ok(woken) => woken,
            Err(_) => return,
        };
        state = next;
        if state.released {
            return;
        }
        let over = |state: &State| state.last_update_ms.saturating_add(stale) < now_ms();
        match mtime_ms(lock_dir) {
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound || over(&state) {
                    state.compromised = true;
                    return;
                }
                delay = Duration::from_secs(1);
                continue;
            }
            Ok(mtime) if mtime != state.mtime_ms => {
                state.compromised = true;
                return;
            }
            Ok(_) => {}
        }
        let next = rules::refresh_mtime_ms(now_ms(), state.seconds_only);
        match set_mtime(lock_dir, next) {
            Ok(()) => {
                state.mtime_ms = next;
                state.last_update_ms = now_ms();
                delay = update;
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound || over(&state) {
                    state.compromised = true;
                    return;
                }
                delay = Duration::from_secs(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHORT: Timing = Timing {
        stale_ms: 2_000,
        update_ms: 1_000,
    };

    fn retries_none(_: u32) -> u64 {
        0
    }

    /// Taken by `mkdir`, refused while fresh, let go by removing it.
    #[test]
    fn taken_refused_and_let_go() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");
        let lock = Lock::acquire(&path, SHORT, 0, retries_none).unwrap();
        assert!(path.is_dir() && lock.held());
        // The probe's mtime: on a second, plus 5 ms (or a whole second
        // where the filesystem keeps no more).
        let mtime = mtime_ms(&path).unwrap();
        assert!(
            mtime.rem_euclid(1000) == 5 || mtime.rem_euclid(1000) == 0,
            "{mtime}"
        );
        assert!(matches!(
            Lock::acquire(&path, SHORT, 2, |_| 10),
            Err(LockError::Held)
        ));
        assert!(lock.release());
        assert!(!path.exists());
    }

    /// A refresher keeps it fresh past the stale time; a stale one is taken
    /// over.
    #[test]
    fn refreshed_while_held_and_taken_over_when_stale() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");
        let lock = Lock::acquire(&path, SHORT, 0, retries_none).unwrap();
        std::thread::sleep(Duration::from_millis(3_200));
        assert!(lock.held());
        assert!(!rules::is_stale(
            mtime_ms(&path).unwrap(),
            now_ms(),
            SHORT.stale_ms
        ));
        assert!(matches!(
            Lock::acquire(&path, SHORT, 0, retries_none),
            Err(LockError::Held)
        ));
        drop(lock);
        std::fs::create_dir(&path).unwrap();
        set_mtime(&path, now_ms() - 2_001).unwrap();
        let taken = Lock::acquire(&path, SHORT, 0, retries_none).unwrap();
        assert!(taken.held());
    }

    /// Another process taking the lock over (its mtime changed under the
    /// holder) compromises it: nothing more may commit, and letting go
    /// leaves the other's directory.
    #[test]
    fn a_takeover_compromises_the_holder() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");
        let lock = Lock::acquire(&path, SHORT, 0, retries_none).unwrap();
        set_mtime(&path, now_ms() - 60_000).unwrap();
        std::thread::sleep(Duration::from_millis(1_500));
        assert!(!lock.held());
        assert!(!lock.release());
        assert!(path.exists(), "the other holder's lock stays");

        // The directory removed under it, too.
        std::fs::remove_dir(&path).unwrap();
        let lock = Lock::acquire(&path, SHORT, 0, retries_none).unwrap();
        std::fs::remove_dir(&path).unwrap();
        std::thread::sleep(Duration::from_millis(1_500));
        assert!(!lock.held());
    }

    /// `is_fresh`, as `isProfileLocked`: no target or no lock directory is
    /// free; the lock's age decides otherwise.
    #[test]
    fn freshness_of_a_profile_lock() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("profile-open");
        let lock = dir.path().join("profile-open.lock");
        assert!(!is_fresh(&target, &lock, 30_000));
        std::fs::create_dir(&lock).unwrap();
        assert!(!is_fresh(&target, &lock, 30_000), "no target");
        std::fs::write(&target, "").unwrap();
        assert!(is_fresh(&target, &lock, 30_000));
        set_mtime(&lock, now_ms() - 29_000).unwrap();
        assert!(is_fresh(&target, &lock, 30_000));
        set_mtime(&lock, now_ms() - 31_000).unwrap();
        assert!(!is_fresh(&target, &lock, 30_000));
        assert!(is_fresh(&target, &lock, 60_000));
    }
}
