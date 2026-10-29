//! `fc-sys`: the few OS calls the standard library lacks, each behind a safe
//! function. It is the workspace's only crate with `unsafe` code
//! (freedom-core#103). Every other crate inherits the workspace's
//! `forbid(unsafe_code)`, which no `#[allow]` can lift, so `unsafe` anywhere
//! else fails to compile.
//!
//! Each function makes one FFI call, in an unsafe block of one operation
//! with a `SAFETY` comment (both lints are denied here), under its own
//! `#[allow(unsafe_code)]`.
//!
//! The calls:
//! - [`windows::drive_type`]: storage qualification in `freedom-cored` and
//!   `fc-service` (design 0001, "Lifetime lock");
//! - [`windows::quiet_error_reporting`]: `fc-service`'s process hardening;
//! - [`linux::landlock_abi`], [`linux::cloexec_from`] and
//!   [`unix::set_cloexec`]: `fc-service`'s confinement on Linux (design
//!   0010);
//! - [`macos::executable_path`], [`macos::thread_count`],
//!   [`macos::apply_profile`], [`macos::sandboxed`] and [`macos::check`]:
//!   its confinement on macOS, through Seatbelt's private calls.
//!
//! On every other platform the crate is empty.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;
