//! The service processes' shared skeleton (design 0007, "Process model",
//! and 0008, implementation step 3): what `freedom-ipfsd` and
//! `freedom-radicled` share, on 0001's conventions.
//!
//! - [`gate`]: the lifetime lock, `<lock-dir>/<namespace>-<sha256(canonical
//!   data dir)>.lock`, under 0001's rules, and [`gate::hold_lock`] for the
//!   `hold-lock` subcommand.
//! - [`hardening`]: not dumpable on Linux, no core files on macOS, no error
//!   reporting dialog or dumps on Windows where the API allows it, and the
//!   parent checks (`--parent-pid`, `PR_SET_PDEATHSIG`).
//! - [`panic`]: the startup panic hook. It writes one fixed JSON line,
//!   `{"panic":"<task kind>"}`, never a payload or a backtrace. A panic in
//!   request work unwinds to its join handle; any other panic exits 70.
//! - [`conn`]: the frame I/O on stdin and stdout, with `fc-protocol`'s
//!   stream [`Sender`](fc_protocol::stream::Sender): one reader that never
//!   waits on the writer, one writer that serves control frames first, the
//!   handshake within its deadline, `<service>.shutdown`, parent death,
//!   the writer-stall exit, and the exit watchdog after EOF.
//! - [`watchdog`]: plain threads that end the process unless disarmed in
//!   time: the exit watchdog after EOF, and a teardown's 5 s bound
//!   (`teardown_unproven`, exit 70).
//! - [`log`], [`exit`] and [`storage`]: JSON-lines logging on stderr, the
//!   exit codes, and storage qualification, as `freedom-cored` has them.
//!
//! The reader, writer and lifecycle loops are plain threads, so the crate
//! needs no async runtime and adds none to the core's dependencies. A
//! service's async work waits for stream room through
//! [`conn::Connection::send`], a runtime-agnostic future.
//!
//! Desktop only: on iOS and Android the crate is empty.

#![cfg(not(any(target_os = "ios", target_os = "android")))]

pub mod conn;
pub mod exit;
pub mod gate;
pub mod hardening;
pub mod log;
pub mod panic;
pub mod storage;
pub mod watchdog;

pub use exit::Exit;
