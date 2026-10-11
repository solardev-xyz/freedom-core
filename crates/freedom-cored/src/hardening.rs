//! Process hardening and parent tracking (design 0001, "Secrets in memory"
//! and "Shutdown, crashes and parent death").

/// Linux: not dumpable, which also stops same-user `ptrace` and reading
/// `/proc/<pid>/mem`. macOS: no core files; the hardened runtime from code
/// signing blocks `task_for_pid`. Failures are logged, not fatal.
pub fn harden() {
    #[cfg(target_os = "linux")]
    if let Err(e) =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
    {
        crate::log::warn(
            "could not mark the process non-dumpable",
            serde_json::json!({ "error": e.to_string() }),
        );
    }
    #[cfg(target_vendor = "apple")]
    if let Err(e) = rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    ) {
        crate::log::warn(
            "could not disable core files",
            serde_json::json!({ "error": e.to_string() }),
        );
    }
}

/// Whether the parent with PID `expected` is still our parent. Always true
/// where there's no `getppid` (Windows relies on stdin EOF).
pub fn parent_alive(expected: Option<u32>) -> bool {
    #[cfg(unix)]
    if let Some(expected) = expected {
        let current =
            rustix::process::getppid().map(|pid| pid.as_raw_nonzero().get().unsigned_abs());
        return current == Some(expected);
    }
    let _ = expected;
    true
}

/// Linux: ask for SIGTERM when the parent dies, then re-check, closing the
/// race where the parent died before the request.
pub fn request_parent_death_signal(expected: Option<u32>) -> bool {
    #[cfg(target_os = "linux")]
    if expected.is_some() {
        let _ =
            rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::TERM));
    }
    parent_alive(expected)
}
