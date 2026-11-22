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
//!   every update period, bound to the directory this holder made, which
//!   it keeps open from the taking: it checks the handle's mtime is still
//!   the one it set, sets the times through the handle, then checks the
//!   path still names that directory. If not, if the directory is gone, or
//!   if any of it fails, the lock is compromised, another process may hold
//!   it, and nothing more may be written under it. A successor's lock is
//!   never refreshed: taken over mid-refresh, the times set are this
//!   holder's orphaned directory's.
//! - **Letting go:** the directory is removed, unless the lock was
//!   compromised or its path names another directory (it is then
//!   another's).

use std::fs::File;
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
    Ok(ms_of(std::fs::metadata(path)?.modified()?))
}

/// A time in whole milliseconds since the epoch, as a JavaScript `Date`
/// holds it.
fn ms_of(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        // Before the epoch: a Date truncates toward zero.
        Err(e) => -i64::try_from(e.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

/// The lock directory's mtime through its handle (`fstat`).
fn handle_mtime_ms(dir: &File) -> std::io::Result<i64> {
    Ok(ms_of(dir.metadata()?.modified()?))
}

/// Sets the lock directory's access and modification times through its
/// handle (`fs.utimes`'s effect), with `futimens`: the one form a confined
/// subcommand's seccomp filter lets through on Linux (fc-service's
/// `Policy::times`). Landlock has no right over times.
#[cfg(all(unix, not(target_os = "macos")))]
fn set_times(dir: &File, ms: i64) -> std::io::Result<()> {
    let time = rustix::fs::Timespec {
        tv_sec: ms.div_euclid(1000),
        tv_nsec: (ms.rem_euclid(1000) * 1_000_000) as _,
    };
    rustix::fs::futimens(
        dir,
        &rustix::fs::Timestamps {
            last_access: time,
            last_modification: time,
        },
    )?;
    Ok(())
}

/// Sets the lock directory's times through its handle, with `futimes`: the
/// call Seatbelt checks as `file-write-times`, which a confined
/// subcommand's profile allows in its read-write grants (fc-service's
/// `Policy::times`). libSystem's `futimens` and std's `set_times` go
/// through `setattrlist`, which that rule doesn't cover.
#[cfg(target_os = "macos")]
fn set_times(dir: &File, ms: i64) -> std::io::Result<()> {
    use std::os::fd::AsFd;
    let microseconds = i32::try_from(ms.rem_euclid(1000) * 1000)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    fc_sys::macos::set_times(dir.as_fd(), ms.div_euclid(1000), microseconds)
}

/// Sets the lock directory's times through its handle (`SetFileTime`).
#[cfg(windows)]
fn set_times(dir: &File, ms: i64) -> std::io::Result<()> {
    let time = if ms >= 0 {
        UNIX_EPOCH + Duration::from_millis(ms.unsigned_abs())
    } else {
        UNIX_EPOCH - Duration::from_millis(ms.unsigned_abs())
    };
    dir.set_times(
        std::fs::FileTimes::new()
            .set_accessed(time)
            .set_modified(time),
    )
}

/// The lock directory, opened once for the life of the lock: a directory,
/// not through a symlink at its name.
#[cfg(unix)]
fn open_dir(path: &Path) -> std::io::Result<File> {
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    Ok(File::from(rustix::fs::open(path, flags, Mode::empty())?))
}

/// The lock directory, opened once for the life of the lock, for its
/// attributes and its times (`FILE_FLAG_BACKUP_SEMANTICS`), not through a
/// reparse point at its name, sharing everything, so another process can
/// still remove it, as proper-lockfile removes a stale lock.
#[cfg(windows)]
fn open_dir(path: &Path) -> std::io::Result<File> {
    const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
    open_windows_dir(path, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
}

#[cfg(windows)]
const FILE_READ_ATTRIBUTES: u32 = 0x80;

#[cfg(windows)]
fn open_windows_dir(path: &Path, access: u32) -> std::io::Result<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let dir = std::fs::OpenOptions::new()
        .access_mode(access)
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let meta = dir.metadata()?;
    if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::other("the lock isn't a directory"));
    }
    Ok(dir)
}

/// Whether `path` still names the directory `dir` is open on: the same
/// device and inode (Unix), volume and file ID (Windows), not following a
/// symlink at it.
#[cfg(unix)]
fn names(path: &Path, dir: &File) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let (there, ours) = (std::fs::symlink_metadata(path)?, dir.metadata()?);
    Ok(there.dev() == ours.dev() && there.ino() == ours.ino())
}

#[cfg(windows)]
fn names(path: &Path, dir: &File) -> std::io::Result<bool> {
    use std::os::windows::io::AsHandle;
    let id = |file: &File| {
        fc_sys::windows::file_id(file.as_handle())
            .or_else(|_| fc_sys::windows::file_index(file.as_handle()))
    };
    let there = open_windows_dir(path, FILE_READ_ATTRIBUTES)?;
    Ok(id(&there)? == id(dir)?)
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
    /// [`Lock::keep`]'s refresh found the lock isn't this holder's any more
    /// (taken over since it was taken), or couldn't refresh it: nothing may
    /// be written under it (`lock_lost`, exit 74).
    Lost,
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

    /// A profile's lock (`profile-lock.js`): 30 s and 10 s, or a dev
    /// build's 5 s and 1 s.
    pub fn profile(dev: bool) -> Timing {
        let (stale_ms, update_ms) = rules::profile_lock_timing(dev);
        Timing {
            stale_ms,
            update_ms,
        }
    }
}

struct State {
    released: bool,
    compromised: bool,
    /// The mtime this holder set last.
    mtime_ms: i64,
    /// The filesystem keeps whole seconds only.
    seconds_only: bool,
    /// The lock directory this holder made, open from its taking to its
    /// letting go: every refresh checks and sets its times through this
    /// handle, then checks the path still names it, so a successor's lock
    /// is never refreshed or removed as this one's.
    dir: Option<File>,
}

/// Where a refresh is, for a test that takes the lock over between its
/// steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// The handle's mtime checked.
    Validated,
    /// The handle's times set.
    Refreshed,
    /// A release: the lock found fresh and its path naming the handle's
    /// directory, just before the removal.
    Identified,
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
}

/// A held lock. Dropping it lets go.
pub struct Lock {
    lock_dir: PathBuf,
    timing: Timing,
    shared: Arc<Shared>,
    /// Started by [`Lock::keep`], from a run's shared borrow of the lock.
    refresher: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Lock {
    /// Takes the lock at `lock_dir`, with `retries` more tries after the
    /// first, waiting `delay(n)` before try `n + 1`, then keeps it from a
    /// thread of its own. The subcommands take and keep in two steps, with
    /// their confinement between.
    #[cfg(test)]
    pub fn acquire(
        lock_dir: &Path,
        timing: Timing,
        retries: u32,
        delay: impl Fn(u32) -> u64,
    ) -> Result<Lock, LockError> {
        let lock = Lock::take(lock_dir, timing, retries, delay)?;
        lock.keep()?;
        Ok(lock)
    }

    /// [`Lock::acquire`] without the refresher: [`Lock::keep`] starts it. A
    /// subcommand confines itself between the two, while it is still the
    /// process's one thread (design 0010). A lock just taken stays fresh
    /// for its whole stale time, far longer than that moment.
    pub fn take(
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
                seconds_only: taken.seconds_only,
                dir: Some(taken.dir),
            }),
            wake: Condvar::new(),
        });
        Ok(Lock {
            lock_dir: lock_dir.to_owned(),
            timing,
            shared,
            refresher: Mutex::new(None),
        })
    }

    /// Starts keeping the lock from a thread of its own, once, after one
    /// refresh on the caller's thread ([`Lock::touch`]) that must find the
    /// lock still this holder's ([`LockError::Lost`] otherwise).
    pub fn keep(&self) -> Result<(), LockError> {
        let mut refresher = self
            .refresher
            .lock()
            .map_err(|_| LockError::Io(std::io::Error::other("the lock's state is poisoned")))?;
        if refresher.is_some() {
            return Ok(());
        }
        // One refresh now, before the caller writes anything: a lock taken
        // over since it was taken (the process stalled past the stale time
        // before it got here) is found here, not at the refresher's first
        // tick an update period later.
        if !self.touch() {
            return Err(LockError::Lost);
        }
        let shared = Arc::clone(&self.shared);
        let lock_dir = self.lock_dir.clone();
        let timing = self.timing;
        let thread = std::thread::Builder::new()
            .name("profile-lock".into())
            .spawn(move || refresh(&lock_dir, &shared, timing))
            .map_err(LockError::Io)?;
        *refresher = Some(thread);
        Ok(())
    }

    /// One refresh now, from the caller's thread, before [`Lock::keep`]
    /// starts the refresher (as each of the refresher's, [`refresh_once`]),
    /// so the refresher's first period starts from a fresh mtime whatever
    /// the run did before it (a starting move's preconditions). `false`,
    /// the lock compromised, when it isn't this holder's any more, or the
    /// refresh failed.
    pub fn touch(&self) -> bool {
        self.touch_with(&|_| {})
    }

    fn touch_with(&self, hook: &dyn Fn(Stage)) -> bool {
        let Ok(mut state) = self.shared.state.lock() else {
            return false;
        };
        if state.released || state.compromised {
            return false;
        }
        let ours = refresh_once(&self.lock_dir, &mut state, hook);
        if !ours {
            state.compromised = true;
        }
        ours
    }

    /// The lock directory's descriptor (Unix), held from the taking, for
    /// confinement's list of those that cross it; `None` elsewhere.
    pub fn descriptor(&self) -> Option<i32> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let state = self.shared.state.lock().ok()?;
            state.dir.as_ref().map(AsRawFd::as_raw_fd)
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    /// The catalog's write lock at `app_root`, taken but not yet kept
    /// ([`Lock::take`]): its target file made if missing, as the reference
    /// does, and five retries 50 to 250 ms apart.
    pub fn catalog(app_root: &Path, created_at: &str) -> Result<Lock, LockError> {
        let target = app_root.join(fc_profile::CATALOG_LOCK_TARGET);
        if std::fs::symlink_metadata(&target).is_err() {
            let text = format!("Freedom profile catalog write lock target\ncreatedAt={created_at}");
            // Nothing reads it: a failed write doesn't stop the lock.
            let _ = std::fs::write(&target, text);
        }
        Lock::take(
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
        self.let_go(&|_| {})
    }

    #[cfg(test)]
    fn release_with(mut self, hook: &dyn Fn(Stage)) -> bool {
        self.let_go(hook)
    }

    /// Lets go: the refresher stopped, then the directory removed only if
    /// the lock is still this holder's, fresh, and its path names the
    /// directory it made.
    /// - **Fresh:** the handle's mtime is the one this holder set, and
    ///   younger than the stale time less one update period. A lock older
    ///   than that may be a taker's to clean up (proper-lockfile takes one
    ///   past the stale time), so it is left in place.
    /// - **Its path names the handle's directory:** otherwise it is
    ///   another's.
    ///
    /// Between that check and the removal, a successor could replace the
    /// directory only once the lock is past its stale time: a freeze longer
    /// than the whole margin inside those few instructions, as in
    /// proper-lockfile's own release. Renaming the directory away first
    /// (and back if it weren't this holder's) would open a new window
    /// while the path is empty, so it isn't done.
    fn let_go(&mut self, hook: &dyn Fn(Stage)) -> bool {
        let (compromised, dir, mtime) = match self.shared.state.lock() {
            Ok(mut state) => {
                if state.released {
                    return !state.compromised;
                }
                state.released = true;
                (state.compromised, state.dir.take(), state.mtime_ms)
            }
            Err(_) => (true, None, 0),
        };
        self.shared.wake.notify_all();
        let refresher = match self.refresher.get_mut() {
            Ok(refresher) => refresher.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(refresher) = refresher {
            let _ = refresher.join();
        }
        let Some(dir) = dir else {
            return false;
        };
        let stale = i64::try_from(rules::effective_stale_ms(self.timing.stale_ms)).unwrap_or(0);
        let update = i64::try_from(rules::effective_update_ms(
            self.timing.stale_ms,
            Some(self.timing.update_ms),
        ))
        .unwrap_or(i64::MAX);
        let fresh = handle_mtime_ms(&dir)
            .is_ok_and(|seen| seen == mtime && now_ms().saturating_sub(seen) < stale - update);
        if compromised || !fresh || !names(&self.lock_dir, &dir).unwrap_or(false) {
            return false;
        }
        hook(Stage::Identified);
        // Closed first: on Windows a directory open elsewhere stays behind
        // as a pending delete.
        drop(dir);
        match std::fs::remove_dir(&self.lock_dir) {
            Ok(()) => true,
            Err(e) => e.kind() == std::io::ErrorKind::NotFound,
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        self.let_go(&|_| {});
    }
}

struct Taken {
    mtime_ms: i64,
    seconds_only: bool,
    dir: File,
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

/// proper-lockfile's precision probe, on a lock just made: through the
/// handle it is opened with and kept.
fn probe(lock_dir: &Path) -> Result<Taken, LockError> {
    let set = rules::probe_mtime_ms(now_ms());
    let read = open_dir(lock_dir).and_then(|dir| {
        set_times(&dir, set)
            .map_err(|e| std::io::Error::new(e.kind(), format!("setting the lock's mtime: {e}")))?;
        let mtime = handle_mtime_ms(&dir)?;
        Ok((dir, mtime))
    });
    match read {
        Ok((dir, mtime)) => Ok(Taken {
            mtime_ms: mtime,
            seconds_only: mtime.rem_euclid(1000) == 0,
            dir,
        }),
        Err(e) => {
            let _ = std::fs::remove_dir(lock_dir);
            Err(LockError::Io(e))
        }
    }
}

/// The refresher: every update period, one [`refresh_once`]. A refresh
/// that finds the lock isn't this holder's, or fails, compromises it.
fn refresh(lock_dir: &Path, shared: &Shared, timing: Timing) {
    let update = Duration::from_millis(rules::effective_update_ms(
        timing.stale_ms,
        Some(timing.update_ms),
    ));
    let Ok(mut state) = shared.state.lock() else {
        return;
    };
    loop {
        let (next, _) = match shared
            .wake
            .wait_timeout_while(state, update, |s| !s.released)
        {
            Ok(woken) => woken,
            Err(_) => return,
        };
        state = next;
        if state.released {
            return;
        }
        if !refresh_once(lock_dir, &mut state, &|_| {}) {
            state.compromised = true;
            return;
        }
    }
}

/// One refresh, bound to the directory this holder made, not its path:
/// (a) its handle's mtime must still be the one this holder set; (b) its
/// times are set through the handle; (c) the path must still name it.
/// Taken over between (a) and (b), the times set are this holder's
/// orphaned directory's, never a successor's, and (c) finds the path names
/// another (or nothing). Any failure is `false`: nothing proves the lock is
/// still this holder's.
fn refresh_once(lock_dir: &Path, state: &mut State, hook: &dyn Fn(Stage)) -> bool {
    let Some(dir) = state.dir.as_ref() else {
        return false;
    };
    if !handle_mtime_ms(dir).is_ok_and(|mtime| mtime == state.mtime_ms) {
        return false;
    }
    hook(Stage::Validated);
    let next = rules::refresh_mtime_ms(now_ms(), state.seconds_only);
    if set_times(dir, next).is_err() {
        return false;
    }
    hook(Stage::Refreshed);
    if !names(lock_dir, dir).unwrap_or(false) {
        return false;
    }
    state.mtime_ms = next;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A path's times set, as another process sets them.
    fn set_mtime(path: &Path, ms: i64) -> std::io::Result<()> {
        set_times(&open_dir(path)?, ms)
    }

    /// Another process's takeover: this holder's directory moved away (as
    /// if removed; it stays open here) and a new one made at the path, with
    /// its own mtime.
    fn take_over(path: &Path, mtime: i64) {
        let gone = path.with_extension("gone");
        std::fs::rename(path, &gone).unwrap();
        std::fs::create_dir(path).unwrap();
        set_mtime(path, mtime).unwrap();
    }

    const SHORT: Timing = Timing {
        stale_ms: 2_000,
        update_ms: 1_000,
    };

    /// For a test that holds a lock across refreshes and then lets it go:
    /// a release removes only a lock younger than the stale time less one
    /// update period, which `SHORT` leaves no room for (a healthy lock is
    /// up to one period old, more on a loaded runner). The real timings
    /// keep 20 s against 10 s, and 4 s against 1 s.
    const HELD: Timing = Timing {
        stale_ms: 4_000,
        update_ms: 1_000,
    };

    fn retries_none(_: u32) -> u64 {
        0
    }

    /// A touch before the refresher sets the mtime again while the lock is
    /// this holder's.
    #[test]
    fn a_touch_refreshes_the_lock_through_its_handle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");
        let lock = Lock::take(&path, SHORT, 0, retries_none).unwrap();
        let before = mtime_ms(&path).unwrap();
        std::thread::sleep(Duration::from_millis(1_100));
        assert!(lock.touch());
        assert_ne!(mtime_ms(&path).unwrap(), before);
        assert!(lock.held());
        assert!(lock.release());
        assert!(!path.exists());
    }

    /// Taken over between a refresh's steps, after its check of the
    /// handle's mtime or after its setting of the times: the successor's
    /// lock is never refreshed, the refresh finds the path names another
    /// directory, the lock is compromised, and its release leaves the
    /// successor's lock in place.
    #[test]
    fn a_takeover_between_a_refreshs_steps_is_found_and_the_successors_lock_untouched() {
        for stage in [Stage::Validated, Stage::Refreshed] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("x.lock");
            let lock = Lock::take(&path, SHORT, 0, retries_none).unwrap();
            let theirs = now_ms() - 60_000;
            let ours = lock.touch_with(&|at| {
                if at == stage {
                    take_over(&path, theirs);
                }
            });
            assert!(!ours, "{stage:?}");
            assert!(!lock.held(), "{stage:?}");
            assert_eq!(mtime_ms(&path).unwrap(), theirs, "{stage:?}: not refreshed");
            assert!(!lock.touch(), "{stage:?}: compromised");
            assert!(!lock.release(), "{stage:?}");
            assert!(path.is_dir(), "{stage:?}: the successor's lock stays");
            assert_eq!(mtime_ms(&path).unwrap(), theirs, "{stage:?}");
        }
    }

    /// The refresher, the same way: a takeover between two refreshes is
    /// found at the next, and nothing of the successor's is touched.
    #[test]
    fn the_refresher_finds_a_takeover_and_leaves_the_successors_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");
        let lock = Lock::acquire(&path, SHORT, 0, retries_none).unwrap();
        let theirs = now_ms() - 60_000;
        take_over(&path, theirs);
        std::thread::sleep(Duration::from_millis(1_500));
        assert!(!lock.held());
        assert_eq!(mtime_ms(&path).unwrap(), theirs);
        assert!(!lock.release());
        assert!(path.is_dir());
    }

    /// `keep` refreshes once on the caller's thread before the refresher
    /// starts: a lock taken over between its taking and `keep` is `Lost`
    /// there, before the caller writes anything, and the successor's lock
    /// is left as it is.
    #[test]
    fn keep_finds_a_takeover_since_the_lock_was_taken() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");
        let lock = Lock::take(&path, SHORT, 0, retries_none).unwrap();
        let theirs = now_ms() - 60_000;
        take_over(&path, theirs);
        assert!(matches!(lock.keep(), Err(LockError::Lost)));
        assert!(!lock.held());
        assert_eq!(mtime_ms(&path).unwrap(), theirs);
        assert!(!lock.release());
        assert!(path.is_dir());
        // Untouched, `keep` refreshes and starts the refresher.
        let other = dir.path().join("y.lock");
        let lock = Lock::take(&other, SHORT, 0, retries_none).unwrap();
        assert!(lock.keep().is_ok());
        assert!(lock.held());
        assert!(lock.release());
        assert!(!other.exists());
    }

    /// A release leaves a lock past the stale time less one update period
    /// in place, for a taker to clean up: it doesn't reach its identity
    /// check, so a successor replacing the directory there (staged by the
    /// hook) loses nothing. A fresh lock is removed as before.
    #[test]
    fn a_release_leaves_a_stale_lock_to_its_taker() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");
        let lock = Lock::take(&path, SHORT, 0, retries_none).unwrap();
        // SHORT: stale 2 s, update 1 s, so stale for a release past 1 s
        // (the probe's mtime may be up to a second ahead).
        std::thread::sleep(Duration::from_millis(2_300));
        let reached = std::cell::Cell::new(false);
        let theirs = now_ms();
        let released = lock.release_with(&|at| {
            if at == Stage::Identified {
                reached.set(true);
                take_over(&path, theirs);
            }
        });
        assert!(!released);
        assert!(!reached.get(), "a stale lock never reaches its removal");
        assert!(path.is_dir(), "left for its taker");

        let fresh = dir.path().join("y.lock");
        let lock = Lock::take(&fresh, SHORT, 0, retries_none).unwrap();
        let reached = std::cell::Cell::new(false);
        assert!(lock.release_with(&|at| reached.set(at == Stage::Identified)));
        assert!(reached.get());
        assert!(!fresh.exists());
    }

    /// A release whose path names another directory (replaced while the
    /// lock still read as held) removes nothing.
    #[test]
    fn a_release_removes_only_its_own_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");
        let lock = Lock::take(&path, SHORT, 0, retries_none).unwrap();
        take_over(&path, now_ms());
        assert!(lock.held(), "no refresh has looked yet");
        assert!(!lock.release());
        assert!(path.is_dir(), "the successor's lock stays");
    }

    /// Taken by `mkdir`, refused while fresh, let go by removing it.
    #[test]
    fn taken_refused_and_let_go() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");
        let lock = Lock::take(&path, SHORT, 0, retries_none).unwrap();
        assert!(path.is_dir() && lock.held());
        // The probe's mtime: on a second, plus 5 ms (or a whole second
        // where the filesystem keeps no more).
        let mtime = mtime_ms(&path).unwrap();
        assert!(
            mtime.rem_euclid(1000) == 5 || mtime.rem_euclid(1000) == 0,
            "{mtime}"
        );
        lock.keep().unwrap();
        assert!(matches!(
            Lock::acquire(&path, SHORT, 2, |_| 10),
            Err(LockError::Held)
        ));
        assert!(lock.release());
        assert!(!path.exists());
    }

    /// Taken without a refresher, it is held but not refreshed until kept.
    #[test]
    fn taken_then_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");
        let lock = Lock::take(&path, HELD, 0, retries_none).unwrap();
        assert!(lock.held());
        let taken = mtime_ms(&path).unwrap();
        std::thread::sleep(Duration::from_millis(1_300));
        assert_eq!(mtime_ms(&path).unwrap(), taken, "not refreshed before keep");
        lock.keep().unwrap();
        lock.keep().unwrap();
        std::thread::sleep(Duration::from_millis(1_300));
        assert_ne!(mtime_ms(&path).unwrap(), taken, "refreshed once kept");
        assert!(lock.held());
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
        // Another holder's stale lock, whether or not the release above
        // removed this one (it may not, at `SHORT`'s timing: see `HELD`).
        let _ = std::fs::remove_dir(&path);
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
