//! The startup panic hook (design 0007, "Crashes, hangs and restarts").
//!
//! - **One fixed line.** The hook replaces Rust's default before any other
//!   work. It writes `{"panic":"<task kind>"}` to stderr, never the payload
//!   or a backtrace: payloads can carry paths, names and CIDs, and stderr
//!   goes to main's persistent log.
//! - **Request work unwinds.** Code polled under [`TaskKind::REQUEST`]
//!   (see [`Labeled`]) panics normally after the line: the panic is caught
//!   at its join handle and becomes that request's `internal` error, or its
//!   stream's `internal` abort. The service must be built with
//!   `panic = "unwind"`, Rust's default.
//! - **Everything else exits 70.** A panic in any other task (an instance's
//!   own, a library's), or on any other thread, exits the process with 70
//!   from the hook: a crash, which main restarts.
//! - **Reporting never holds the process up.** The line goes through the log
//!   queue, which never blocks once [`crate::log::init`] has run (before it,
//!   it is written directly). A fatal panic arms its exit first, on a thread
//!   of its own, and gives the line at most 150 ms: a stderr that main has
//!   stopped draining can't keep the process alive, nor stop a request's
//!   panic from unwinding.
//! - **Dropping request work is request work.** [`Labeled`] drops its future
//!   under its kind too, so a panic in a cancelled request's destructor
//!   unwinds like one in its poll.

use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::exit::{Exit, REPORT_BOUND, exit_reporting};

/// What a thread is doing, for the hook's line and for whether a panic may
/// unwind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskKind {
    name: &'static str,
    request: bool,
}

impl TaskKind {
    /// Request work: a panic unwinds to the request's join handle.
    pub const REQUEST: TaskKind = TaskKind {
        name: "request",
        request: true,
    };

    /// Any other task, named for the hook's line: a panic exits 70. The
    /// name is a fixed string, never data.
    pub const fn named(name: &'static str) -> TaskKind {
        TaskKind {
            name,
            request: false,
        }
    }

    pub fn name(self) -> &'static str {
        self.name
    }
}

thread_local! {
    static KIND: Cell<Option<TaskKind>> = const { Cell::new(None) };
}

/// Replaces the panic hook. Call it first, before any other work.
pub fn install() {
    std::panic::set_hook(Box::new(|_info| {
        let kind = KIND.with(Cell::get);
        let name = kind.map_or("thread", TaskKind::name);
        let line = format!("{{\"panic\":\"{name}\"}}\n").into_bytes();
        if kind.is_some_and(|kind| kind.request) {
            // It unwinds: queued, never waited on.
            crate::log::line(line);
        } else {
            exit_reporting(Exit::Internal, REPORT_BOUND, || crate::log::line(line));
        }
    }));
}

/// Runs `f` with this thread marked as `kind`.
pub fn with_kind<R>(kind: TaskKind, f: impl FnOnce() -> R) -> R {
    let previous = KIND.with(|current| current.replace(Some(kind)));
    let restore = Restore(previous);
    let result = f();
    drop(restore);
    result
}

struct Restore(Option<TaskKind>);

impl Drop for Restore {
    fn drop(&mut self) {
        KIND.with(|current| current.set(self.0));
    }
}

/// A future polled, and dropped, with its thread marked as `kind`, whatever
/// thread a runtime polls or drops it on: blocking regions inside the poll
/// are marked too.
pub struct Labeled<F> {
    kind: TaskKind,
    /// `None` only while it is being dropped.
    future: Option<Pin<Box<F>>>,
}

impl<F: Future> Labeled<F> {
    pub fn new(kind: TaskKind, future: F) -> Self {
        Labeled {
            kind,
            future: Some(Box::pin(future)),
        }
    }
}

impl<F: Future> Future for Labeled<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let kind = self.kind;
        match self.future.as_mut() {
            Some(future) => with_kind(kind, || future.as_mut().poll(cx)),
            None => Poll::Pending,
        }
    }
}

impl<F> Drop for Labeled<F> {
    fn drop(&mut self) {
        // A cancelled request's destructors are its work too.
        let future = self.future.take();
        with_kind(self.kind, move || drop(future));
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout
    )]

    use super::*;
    use std::process::Command;

    const CHILD: &str = "FC_SERVICE_PANIC_CHILD";

    /// The child half: does nothing unless the parent test asked for a mode.
    #[test]
    fn child() {
        let Ok(mode) = std::env::var(CHILD) else {
            return;
        };
        install();
        match mode.as_str() {
            "request" => {
                let caught = std::panic::catch_unwind(|| {
                    with_kind(TaskKind::REQUEST, || panic!("SECRET /path/bafy"))
                });
                assert!(caught.is_err());
                // The thread is unmarked again.
                assert_eq!(KIND.with(Cell::get), None);
            }
            "thread" => {
                let _ = std::thread::spawn(|| panic!("SECRET /path/bafy")).join();
            }
            "named" => {
                let mut future = Labeled::new(TaskKind::named("swarm"), async {
                    panic!("SECRET /path/bafy")
                });
                let waker = std::task::Waker::noop();
                let _ = Pin::new(&mut future).poll(&mut Context::from_waker(waker));
            }
            "request_drop" => {
                // A pending request dropped (cancelled) whose destructor
                // panics: request work, so it unwinds.
                struct PanicsOnDrop;
                impl Future for PanicsOnDrop {
                    type Output = ();
                    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
                        Poll::Pending
                    }
                }
                impl Drop for PanicsOnDrop {
                    fn drop(&mut self) {
                        panic!("SECRET /path/bafy");
                    }
                }
                let mut future = Labeled::new(TaskKind::REQUEST, PanicsOnDrop);
                let waker = std::task::Waker::noop();
                let _ = Pin::new(&mut future).poll(&mut Context::from_waker(waker));
                let caught = std::panic::catch_unwind(move || drop(future));
                assert!(caught.is_err());
                assert_eq!(KIND.with(Cell::get), None);
            }
            "blocked_stderr" => {
                // A log line main never drains: the log thread blocks on the
                // pipe, holding stderr's lock.
                crate::log::init();
                crate::log::info("filler", serde_json::json!({ "x": "x".repeat(1 << 20) }));
                std::thread::sleep(std::time::Duration::from_millis(100));
                let _ = std::thread::spawn(|| panic!("SECRET /path/bafy")).join();
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
            "blocked_stderr_request" => {
                crate::log::init();
                crate::log::info("filler", serde_json::json!({ "x": "x".repeat(1 << 20) }));
                std::thread::sleep(std::time::Duration::from_millis(100));
                let caught = std::panic::catch_unwind(|| {
                    with_kind(TaskKind::REQUEST, || panic!("SECRET /path/bafy"))
                });
                assert!(caught.is_err());
                // Unwound without waiting on stderr: say so on stdout.
                println!("UNWOUND");
                std::process::exit(0);
            }
            other => panic!("unknown mode {other}"),
        }
    }

    fn run_child(mode: &str) -> (Option<i32>, String) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "panic::tests::child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, mode)
            .output()
            .unwrap();
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    #[test]
    fn request_panics_unwind_after_one_fixed_line() {
        let (code, stderr) = run_child("request");
        assert_eq!(code, Some(0), "{stderr}");
        assert!(stderr.contains("{\"panic\":\"request\"}\n"), "{stderr}");
        assert!(!stderr.contains("SECRET"), "{stderr}");
    }

    #[test]
    fn a_request_dropped_with_a_panicking_destructor_unwinds() {
        let (code, stderr) = run_child("request_drop");
        assert_eq!(code, Some(0), "{stderr}");
        assert!(stderr.contains("{\"panic\":\"request\"}\n"), "{stderr}");
        assert!(!stderr.contains("SECRET"), "{stderr}");
    }

    /// Runs a child whose stderr is a pipe nobody reads, and returns its
    /// exit code and stdout once it exits, or `None` past `within`.
    fn run_child_unread_stderr(mode: &str, within: std::time::Duration) -> Option<(i32, String)> {
        use std::io::Read;
        use std::process::Stdio;
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "panic::tests::child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + within;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if std::time::Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let Some(status) = status else {
            child.kill().unwrap();
            child.wait().unwrap();
            return None;
        };
        let mut stdout = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut stdout)
            .unwrap();
        Some((status.code().unwrap_or(-1), stdout))
    }

    #[test]
    fn a_fatal_panic_exits_70_even_when_stderr_is_not_drained() {
        // The child panics 100 ms in; the exit's bound is 150 ms.
        let exited = run_child_unread_stderr("blocked_stderr", std::time::Duration::from_secs(3));
        assert_eq!(exited.map(|(code, _)| code), Some(70));
    }

    #[test]
    fn a_request_panic_unwinds_even_when_stderr_is_not_drained() {
        let exited =
            run_child_unread_stderr("blocked_stderr_request", std::time::Duration::from_secs(3));
        let (code, stdout) = exited.expect("the child hung in the hook");
        assert_eq!(code, 0);
        assert!(stdout.contains("UNWOUND"), "{stdout}");
    }

    #[test]
    fn other_panics_exit_70_with_their_kind() {
        for (mode, line) in [
            ("thread", "{\"panic\":\"thread\"}\n"),
            ("named", "{\"panic\":\"swarm\"}\n"),
        ] {
            let (code, stderr) = run_child(mode);
            assert_eq!(code, Some(70), "{mode}: {stderr}");
            assert!(stderr.contains(line), "{mode}: {stderr}");
            assert!(!stderr.contains("SECRET"), "{mode}: {stderr}");
            assert!(
                !stderr.contains("panicked at"),
                "{mode}: no default message"
            );
        }
    }
}
