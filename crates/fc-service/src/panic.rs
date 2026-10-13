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

use std::cell::Cell;
use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::exit::Exit;

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
        // Directly, not through the log queue: the process may exit now.
        let line = format!("{{\"panic\":\"{name}\"}}\n");
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
        if !kind.is_some_and(|kind| kind.request) {
            std::process::exit(i32::from(Exit::Internal.code()));
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

/// A future polled with its thread marked as `kind`, whatever thread a
/// runtime polls it on: blocking regions inside the poll are marked too.
pub struct Labeled<F> {
    kind: TaskKind,
    future: Pin<Box<F>>,
}

impl<F: Future> Labeled<F> {
    pub fn new(kind: TaskKind, future: F) -> Self {
        Labeled {
            kind,
            future: Box::pin(future),
        }
    }
}

impl<F: Future> Future for Labeled<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let kind = self.kind;
        with_kind(kind, || self.future.as_mut().poll(cx))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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
