//! Exit codes (sysexits.h values), which main reads to decide whether to
//! restart a service (designs 0001 and 0007, "Crashes, hangs and restarts").

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
        ]
        .into_iter()
        .find(|exit| exit.code() == code)
    }
}

/// How long a fixed-time exit lets its report reach stderr.
pub(crate) const REPORT_BOUND: Duration = Duration::from_millis(150);

/// Set by the first exit to begin.
static EXITING: AtomicBool = AtomicBool::new(false);

/// Claims the process's exit for the calling thread. It returns only to the
/// first caller. Any later caller waits, parked, for the first to end the
/// process, so no exit can cut off another's report (whose log drain it
/// would find already taken) or change its code. The first always ends the
/// process: [`exit_reporting`] within its bound, and `main` by returning.
/// So `main` calls this before it flushes the log and returns.
pub fn claim() {
    if EXITING.swap(true, Ordering::AcqRel) {
        loop {
            std::thread::park();
        }
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
            std::process::exit(code)
        });
    if armed.is_ok() {
        report();
        crate::log::finish(bound.saturating_sub(started.elapsed()));
    }
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
            "concurrent" => {
                let (reported, wait) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    exit_reporting(Exit::Internal, Duration::from_secs(10), || {
                        let pad = "a".repeat(256 * 1024);
                        crate::log::line(format!("{{\"first\":\"{pad}\"}}\n").into_bytes());
                        let _ = reported.send(());
                        // The second exit begins while this one reports.
                        std::thread::sleep(Duration::from_millis(300));
                    })
                });
                wait.recv().unwrap();
                exit_reporting(Exit::Protocol, Duration::from_secs(10), || {
                    crate::log::line(b"{\"second\":true}\n".to_vec());
                })
            }
            other => panic!("unknown mode {other}"),
        }
    }

    /// Two exits at once: the first reports in full and decides the code;
    /// the second, begun during that report, neither writes nor ends the
    /// process.
    #[test]
    fn the_first_exit_reports_and_ends_the_process() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "exit::tests::child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "concurrent")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        let short: String = stderr.chars().take(200).collect();
        assert_eq!(output.status.code(), Some(70), "{short}");
        assert!(!stderr.contains("second"), "{short}");
        let first = stderr
            .lines()
            .find(|line| line.starts_with("{\"first\""))
            .unwrap_or_else(|| panic!("no first line: {short}"));
        let parsed: serde_json::Value = serde_json::from_str(first).unwrap();
        assert_eq!(parsed["first"].as_str().map(str::len), Some(256 * 1024));
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
