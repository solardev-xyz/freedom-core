//! Process hardening and parent tracking (design 0001, "Secrets in memory"
//! and "Shutdown, crashes and parent death"; design 0007, "Spawn" and
//! "Startup and shutdown").

/// Hardens the process. Failures are logged, not fatal.
///
/// - **Linux:** not dumpable (`PR_SET_DUMPABLE=0`), which also suppresses
///   core dumps and stops same-user `ptrace` and reading `/proc/<pid>/mem`.
/// - **macOS:** no core files (`RLIMIT_CORE` 0); the hardened runtime from
///   code signing blocks `task_for_pid`.
/// - **Windows:** no Windows Error Reporting dialog and no dump collection
///   for the process, where the API allows it. Best-effort.
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
    #[cfg(windows)]
    windows::no_error_reporting();
}

#[cfg(windows)]
mod windows {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX, SetErrorMode,
    };
    use windows_sys::Win32::System::ErrorReporting::{
        WER_FAULT_REPORTING_FLAG_NOHEAP, WER_FAULT_REPORTING_NO_UI, WerSetFlags,
    };

    /// No fault dialog and no heap in WER's reports for this process.
    #[allow(unsafe_code)]
    pub fn no_error_reporting() {
        // SAFETY: SetErrorMode takes a flag set and only changes this
        // process's error mode; it reads no memory of ours.
        unsafe {
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
        }
        // SAFETY: WerSetFlags takes a flag set for this process; it reads no
        // memory of ours.
        let result =
            unsafe { WerSetFlags(WER_FAULT_REPORTING_NO_UI | WER_FAULT_REPORTING_FLAG_NOHEAP) };
        if result != 0 {
            crate::log::warn(
                "could not turn off error reporting",
                serde_json::json!({ "hresult": result }),
            );
        }
    }
}

/// Whether the parent with PID `expected` is still our parent. Always true
/// where there's no `getppid` (Windows relies on stdin EOF and its job
/// object).
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

/// Linux: asks for SIGTERM when the parent dies, then re-checks, closing
/// the race where the parent died before the request. Elsewhere: checks.
pub fn request_parent_death_signal(expected: Option<u32>) -> bool {
    #[cfg(target_os = "linux")]
    if expected.is_some() {
        let _ =
            rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::TERM));
    }
    parent_alive(expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn our_parent_is_alive_and_others_are_not() {
        assert!(parent_alive(None));
        #[cfg(unix)]
        {
            let parent = rustix::process::getppid()
                .map(|pid| pid.as_raw_nonzero().get().unsigned_abs())
                .unwrap_or(0);
            assert!(parent_alive(Some(parent)));
            assert!(!parent_alive(Some(parent.wrapping_add(1))));
        }
    }

    #[test]
    fn hardening_never_fails_the_process() {
        harden();
    }
}
