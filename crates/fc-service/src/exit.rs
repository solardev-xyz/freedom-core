//! Exit codes (sysexits.h values), which main reads to decide whether to
//! restart a service (designs 0001 and 0007, "Crashes, hangs and restarts").

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::gate::GateError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Normal exit: shutdown, stdin EOF, a failed write to stdout, or the
    /// parent gone.
    Ok,
    /// Bad command line: don't restart.
    Usage,
    /// A bug, a panic outside request work, or a teardown that couldn't
    /// prove quiescence: a crash, restarted.
    Internal,
    /// Storage failure or refused filesystem: don't restart.
    Storage,
    /// The lock is held by another process: don't restart.
    LockHeld,
    /// A protocol violation, the handshake's deadline, or the writer stall:
    /// a crash, restarted.
    Protocol,
    /// Confinement refused its own policy, found a second thread, or
    /// stopped halfway (design 0010): don't restart.
    Confinement,
}

impl Exit {
    pub fn code(self) -> u8 {
        match self {
            Exit::Ok => 0,
            Exit::Usage => 64,
            Exit::Internal => 70,
            Exit::Storage => 74,
            Exit::LockHeld => 75,
            Exit::Protocol => 76,
            Exit::Confinement => 77,
        }
    }
}

impl Exit {
    /// The exit with `code`, if it is one of these.
    pub(crate) fn from_code(code: u8) -> Option<Exit> {
        [
            Exit::Ok,
            Exit::Usage,
            Exit::Internal,
            Exit::Storage,
            Exit::LockHeld,
            Exit::Protocol,
            Exit::Confinement,
        ]
        .into_iter()
        .find(|exit| exit.code() == code)
    }
}

/// How long a fixed-time exit lets its report reach stderr.
pub(crate) const REPORT_BOUND: Duration = Duration::from_millis(150);

/// Set by the first exit to begin.
static EXITING: AtomicBool = AtomicBool::new(false);

/// The calling thread's part in the exit: none, or the owner of it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Held {
    No,
    /// It ends the process itself, with no timer behind it: `main` before it
    /// returns, or [`exit_reporting`] once it calls `std::process::exit`.
    Ending,
    /// Its report runs with a timer armed that ends the process.
    Timed,
}

thread_local! {
    // No destructor, so it stays readable while thread-locals are torn
    // down, which is when a re-entry most likely comes.
    static HELD: Cell<Held> = const { Cell::new(Held::No) };
}

/// Run by the timer as it ends the process, in tests: what an exit callback
/// on its thread would do.
#[cfg(test)]
static TIMER_EXITING: std::sync::OnceLock<fn()> = std::sync::OnceLock::new();

/// Claims begun, and claims won: tests wait on them to order two exits.
#[cfg(test)]
static ATTEMPTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static ACQUIRED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Claims the process's exit for the calling thread. It returns only to the
/// first caller. Any later caller waits, parked, for the first to end the
/// process, so no exit can cut off another's report (whose log drain it
/// would find already taken) or change its code. The first always ends the
/// process: [`exit_reporting`] within its bound, and `main` by returning.
/// So `main` calls this before it flushes the log and returns.
///
/// **The owner coming back** (a panic in its report, or in a thread-local
/// destructor that runs as it exits) must not park, because it is the one
/// ending the process. While its report's timer is armed it does park: the
/// timer ends the process with the first code. Otherwise it is already
/// ending the process and std can't exit twice on one thread, so it aborts.
pub fn claim() {
    #[cfg(test)]
    ATTEMPTS.fetch_add(1, Ordering::SeqCst);
    match HELD.try_with(Cell::get).unwrap_or(Held::No) {
        Held::Timed => park_forever(),
        Held::Ending => std::process::abort(),
        Held::No => {}
    }
    if EXITING.swap(true, Ordering::AcqRel) {
        park_forever();
    }
    let _ = HELD.try_with(|held| held.set(Held::Ending));
    #[cfg(test)]
    ACQUIRED.fetch_add(1, Ordering::SeqCst);
}

fn park_forever() -> ! {
    loop {
        std::thread::park();
    }
}

/// Ends the process with `exit`, after `report` and the log queue have had
/// at most `bound`.
///
/// The bound is armed first, on a thread of its own, so no exit waits on
/// stderr: if main stops draining it, a report blocked on the pipe (or on
/// stderr's lock, held by a log write blocked there) can't hold the process
/// up. If no thread can be started, the process exits at once, unreported.
/// Only the first exit gets this far ([`claim`]).
pub(crate) fn exit_reporting(exit: Exit, bound: Duration, report: impl FnOnce()) -> ! {
    claim();
    let code = i32::from(exit.code());
    let started = Instant::now();
    let armed = std::thread::Builder::new()
        .name("exit".into())
        .spawn(move || {
            std::thread::sleep(bound);
            // It ends the process on the owner's behalf, so it is an owner
            // too: coming back (a panic in an exit callback) must not park.
            let _ = HELD.try_with(|held| held.set(Held::Ending));
            #[cfg(test)]
            if let Some(exiting) = TIMER_EXITING.get() {
                exiting();
            }
            std::process::exit(code)
        });
    if armed.is_ok() {
        let _ = HELD.try_with(|held| held.set(Held::Timed));
        report();
        crate::log::finish(bound.saturating_sub(started.elapsed()));
    }
    let _ = HELD.try_with(|held| held.set(Held::Ending));
    std::process::exit(code)
}

impl From<&GateError> for Exit {
    fn from(error: &GateError) -> Self {
        match error {
            GateError::Held => Exit::LockHeld,
            GateError::Unqualified(_)
            | GateError::LockInsideData
            | GateError::Moved
            | GateError::NotPrivate(_)
            | GateError::Storage(_) => Exit::Storage,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::process::Command;

    const CHILD: &str = "FC_SERVICE_EXIT_CHILD";

    /// The child half: does nothing unless the parent test asked for a mode.
    #[test]
    fn child() {
        let Ok(mode) = std::env::var(CHILD) else {
            return;
        };
        crate::log::init();
        match mode.as_str() {
            // Two exits overlap: the first reports until the second has
            // claimed, whenever each thread runs.
            "concurrent" => {
                std::thread::spawn(|| {
                    exit_reporting(Exit::Internal, Duration::from_secs(10), || {
                        let pad = "a".repeat(256 * 1024);
                        crate::log::line(format!("{{\"first\":\"{pad}\"}}\n").into_bytes());
                        // Until the second exit has begun its claim.
                        reach(&ATTEMPTS, 2, 99);
                    })
                });
                // Until the first exit owns the process.
                reach(&ACQUIRED, 1, 98);
                exit_reporting(Exit::Protocol, Duration::from_secs(10), || {
                    crate::log::line(b"{\"second\":true}\n".to_vec());
                })
            }
            // The owner comes back from its own report: its timer ends the
            // process with the first code.
            "again_in_report" => exit_reporting(Exit::Internal, Duration::from_millis(300), || {
                exit_reporting(Exit::Protocol, Duration::from_secs(60), || {});
            }),
            // The owner comes back as `main` would after returning, or from
            // inside `std::process::exit`: it aborts rather than park.
            "again_after_claim" => {
                claim();
                exit_reporting(Exit::Protocol, Duration::from_secs(60), || {})
            }
            // The timer, ending the process for an owner still reporting,
            // comes back as an exit callback on its thread would.
            "again_in_timer" => {
                let _ = TIMER_EXITING.set(|| {
                    exit_reporting(Exit::Protocol, Duration::from_secs(60), || {});
                });
                exit_reporting(Exit::Internal, Duration::from_millis(300), || {
                    std::thread::sleep(Duration::from_secs(60));
                })
            }
            // A thread-local destructor that comes back while its thread
            // exits the process.
            "again_in_exit" => {
                struct Again;
                impl Drop for Again {
                    fn drop(&mut self) {
                        exit_reporting(Exit::Protocol, Duration::from_secs(60), || {});
                    }
                }
                thread_local! {
                    static AGAIN: Again = const { Again };
                }
                AGAIN.with(|_| {});
                exit_reporting(Exit::Internal, Duration::from_secs(60), || {})
            }
            other => panic!("unknown mode {other}"),
        }
    }

    /// Waits until `counter` reaches `n`; past 5 s the child exits with
    /// `fail`, a code no exit here uses, so a wait that never ends can't
    /// pass for the outcome under test.
    fn reach(counter: &std::sync::atomic::AtomicUsize, n: usize, fail: i32) {
        let until = Instant::now() + Duration::from_secs(5);
        while counter.load(Ordering::SeqCst) < n {
            if Instant::now() >= until {
                std::process::exit(fail);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Whether `code` is a `std::process::abort`: a signal on Unix, and
    /// `__fastfail`'s status (or the CRT's 3) on Windows.
    fn aborted(code: Option<i32>) -> bool {
        if cfg!(windows) {
            matches!(code, Some(c) if c as u32 == 0xC000_0409 || c == 3)
        } else {
            code.is_none()
        }
    }

    /// Runs the child in `mode`; its exit code (`None` for a signal) and
    /// stderr, or a panic past `within`, which a hang would hit.
    fn run_child(mode: &str, within: Duration) -> (Option<i32>, String) {
        use std::io::Read;
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "exit::tests::child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, mode)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut pipe = child.stderr.take().unwrap();
        let reader = std::thread::spawn(move || {
            let mut stderr = Vec::new();
            let _ = pipe.read_to_end(&mut stderr);
            stderr
        });
        let deadline = Instant::now() + within;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                panic!("the {mode} child did not exit within {within:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let stderr = String::from_utf8_lossy(&reader.join().unwrap()).into_owned();
        (status.code(), stderr)
    }

    /// Two exits at once: the first reports in full and decides the code;
    /// the second, begun during that report, neither writes nor ends the
    /// process.
    #[test]
    fn the_first_exit_reports_and_ends_the_process() {
        let (code, stderr) = run_child("concurrent", Duration::from_secs(30));
        let short: String = stderr.chars().take(200).collect();
        assert_eq!(code, Some(70), "{short}");
        assert!(!stderr.contains("second"), "{short}");
        let first = stderr
            .lines()
            .find(|line| line.starts_with("{\"first\""))
            .unwrap_or_else(|| panic!("no first line: {short}"));
        let parsed: serde_json::Value = serde_json::from_str(first).unwrap();
        assert_eq!(parsed["first"].as_str().map(str::len), Some(256 * 1024));
    }

    /// The owner coming back never parks the thread that ends the process.
    #[test]
    fn the_owner_coming_back_still_ends_the_process() {
        let (code, stderr) = run_child("again_in_report", Duration::from_secs(30));
        assert_eq!(code, Some(70), "{stderr}");
        let mut modes = vec!["again_after_claim", "again_in_timer"];
        // Thread-local destructors run inside `exit` on glibc only.
        if cfg!(all(target_os = "linux", target_env = "gnu")) {
            modes.push("again_in_exit");
        }
        for mode in modes {
            let (code, stderr) = run_child(mode, Duration::from_secs(30));
            assert!(aborted(code), "{mode}: {code:?} {stderr}");
        }
    }

    #[test]
    fn codes_are_0001s() {
        let codes: Vec<u8> = [
            Exit::Ok,
            Exit::Usage,
            Exit::Internal,
            Exit::Storage,
            Exit::LockHeld,
            Exit::Protocol,
        ]
        .map(Exit::code)
        .to_vec();
        assert_eq!(codes, [0, 64, 70, 74, 75, 76]);
        for code in codes {
            assert_eq!(Exit::from_code(code).map(Exit::code), Some(code));
        }
        assert_eq!(Exit::from_code(1), None);
    }
}
