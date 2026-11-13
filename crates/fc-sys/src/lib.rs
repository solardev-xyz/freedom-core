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
//! - [`windows::file_id`] and [`windows::file_index`]: a directory's
//!   identity, for `fc-service`'s `OpenDir` (design 0010, D5: the import's
//!   roots, checked again once confined);
//! - [`windows::owned_by_current_user`]: whether this process's user owns
//!   a permission file `freedom-cored` reads, from its handle (design 0012,
//!   "The files (Q10)", freedom-core#360);
//! - [`windows::open_dir_at`]: a directory opened or made relative to its
//!   parent's handle, never through a reparse point, for `fc-service`'s
//!   profile gate's lock directory (design 0013, "The lock");
//! - [`windows::Job`], [`windows::own_job_limits`] and
//!   [`windows::Mitigation`]: its confinement on Windows (design 0010), a job
//!   object of one process and the process mitigation policies, each read
//!   back;
//! - [`linux::landlock_abi`], [`linux::cloexec_from`] and
//!   [`unix::set_cloexec`]: `fc-service`'s confinement on Linux (design
//!   0010);
//! - [`macos::executable_path`], [`macos::thread_count`],
//!   [`macos::apply_profile`], [`macos::sandboxed`], [`macos::check`] and [`macos::exec_allowed`]:
//!   its confinement on macOS, through Seatbelt's private calls;
//! - [`macos::set_times`]: the profile lock's mtime in `freedom-cored`,
//!   through the one call a confined process's `file-write-times` covers
//!   (design 0013, "The lock").
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
