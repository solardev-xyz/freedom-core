//! Windows calls: storage qualification, error reporting, and
//! confinement's job object and process mitigation policies (design 0010,
//! "Windows").
//!
//! None of these calls closes a handle but [`Job`]'s own, which it owns.

use std::io;
#[cfg(feature = "test-windows")]
use std::os::windows::io::BorrowedHandle;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
use windows_sys::Win32::System::Diagnostics::Debug::{
    SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX, SetErrorMode,
};
use windows_sys::Win32::System::ErrorReporting::{
    WER_FAULT_REPORTING_FLAG_NOHEAP, WER_FAULT_REPORTING_NO_UI, WerSetFlags,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOBOBJECT_BASIC_LIMIT_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject,
};
use windows_sys::Win32::System::SystemServices::{
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessMitigationPolicy, PROCESS_MITIGATION_POLICY,
    ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy,
    SetProcessMitigationPolicy,
};

/// `GetDriveTypeW`'s `DRIVE_UNKNOWN`.
pub const DRIVE_UNKNOWN: u32 = 0;
/// `GetDriveTypeW`'s `DRIVE_NO_ROOT_DIR`.
pub const DRIVE_NO_ROOT_DIR: u32 = 1;
/// `GetDriveTypeW`'s `DRIVE_REMOTE`: a mapped network drive.
pub const DRIVE_REMOTE: u32 = 4;

/// `GetDriveTypeW` on a NUL-terminated UTF-16 root path, such as `C:\`.
/// [`DRIVE_UNKNOWN`] if `root` isn't NUL-terminated.
#[allow(unsafe_code)]
pub fn drive_type(root: &[u16]) -> u32 {
    if root.last() != Some(&0) {
        return DRIVE_UNKNOWN;
    }
    // SAFETY: `root` is a valid, NUL-terminated UTF-16 string that lives
    // for the whole call; GetDriveTypeW only reads it and keeps no
    // reference.
    unsafe { GetDriveTypeW(root.as_ptr()) }
}

/// No fault dialog, and no heap in Windows Error Reporting's reports, for
/// this process. `Err` carries `WerSetFlags`' HRESULT; `SetErrorMode` can't
/// fail.
#[allow(unsafe_code)]
pub fn quiet_error_reporting() -> Result<(), i32> {
    // SAFETY: SetErrorMode takes a flag set and only changes this process's
    // error mode; it reads no memory of ours.
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    }
    // SAFETY: WerSetFlags takes a flag set for this process; it reads no
    // memory of ours.
    let result =
        unsafe { WerSetFlags(WER_FAULT_REPORTING_NO_UI | WER_FAULT_REPORTING_FLAG_NOHEAP) };
    if result == 0 { Ok(()) } else { Err(result) }
}

/// This process's pseudo-handle (`GetCurrentProcess`): valid for the
/// process's life, and never closed.
#[allow(unsafe_code)]
fn current_process() -> HANDLE {
    // SAFETY: GetCurrentProcess takes nothing, reads no memory of ours, and
    // returns a constant pseudo-handle that needs no closing.
    unsafe { GetCurrentProcess() }
}

/// `Ok` for a Win32 call's nonzero `BOOL`, or the thread's last error.
fn win32(ok: windows_sys::core::BOOL) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// A job object's limit flags (`JOB_OBJECT_LIMIT_*`).
pub mod limit {
    use windows_sys::Win32::System::JobObjects as job;

    /// At most `active_processes` processes in the job: a process past it
    /// isn't created.
    pub const ACTIVE_PROCESS: u32 = job::JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    /// A child created with `CREATE_BREAKAWAY_FROM_JOB` leaves the job.
    pub const BREAKAWAY_OK: u32 = job::JOB_OBJECT_LIMIT_BREAKAWAY_OK;
    /// Every child leaves the job, unless an inner job forbids it.
    pub const SILENT_BREAKAWAY_OK: u32 = job::JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
    /// Closing the job's last handle ends every process in it.
    pub const KILL_ON_JOB_CLOSE: u32 = job::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    /// An unhandled exception ends the process, with no dialog.
    pub const DIE_ON_UNHANDLED_EXCEPTION: u32 = job::JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
}

/// A job's limits, as `JOBOBJECT_BASIC_LIMIT_INFORMATION` holds them: the
/// flags ([`limit`]), and the active-process limit, which counts only with
/// [`limit::ACTIVE_PROCESS`]. Nothing else is set: no UI restrictions,
/// which a job nested in another may not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub flags: u32,
    pub active_processes: u32,
}

/// An unnamed job object this process created (`CreateJobObjectW`), its
/// handle owned and closed on drop. With no name, no other process can open
/// it. A process assigned to it stays in it, under its limits, after its
/// last handle is closed; only [`limit::KILL_ON_JOB_CLOSE`] would end it
/// then.
#[derive(Debug)]
pub struct Job(OwnedHandle);

/// The size of `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`, as the job calls take
/// it.
const EXTENDED_LIMITS: u32 = size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32;
const _: () = assert!(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() <= u32::MAX as usize);

impl Job {
    /// A new job, with no limits, default security (no inheritable handle),
    /// and no name.
    #[allow(unsafe_code)]
    pub fn new() -> io::Result<Self> {
        // SAFETY: both pointers may be NULL: default security attributes,
        // and no name. The call reads nothing else of ours.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `handle` is the open job handle the call just returned,
        // which nothing else owns; the OwnedHandle closes it once, on drop.
        Ok(Self(unsafe { OwnedHandle::from_raw_handle(handle) }))
    }

    /// Sets the job's limits to `limits`, and clears every other basic and
    /// extended limit (`SetInformationJobObject`,
    /// `JobObjectExtendedLimitInformation`).
    #[allow(unsafe_code)]
    pub fn set_limits(&self, limits: Limits) -> io::Result<()> {
        let info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                LimitFlags: limits.flags,
                ActiveProcessLimit: limits.active_processes,
                ..Default::default()
            },
            ..Default::default()
        };
        // SAFETY: `info` is a whole JOBOBJECT_EXTENDED_LIMIT_INFORMATION of
        // EXTENDED_LIMITS bytes, borrowed for the call, which only reads it;
        // the handle is this job's, open while `self` lives.
        let ok = unsafe {
            SetInformationJobObject(
                self.0.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                EXTENDED_LIMITS,
            )
        };
        win32(ok)
    }

    /// The job's limits (`QueryInformationJobObject`).
    pub fn limits(&self) -> io::Result<Limits> {
        query_limits(self.0.as_raw_handle())
    }

    /// Assigns this process to the job (`AssignProcessToJobObject`): for
    /// good, since a process never leaves a job. A process already in a job
    /// gets this one nested inside it (Windows 8 and later), which needs
    /// that neither sets UI restrictions.
    #[allow(unsafe_code)]
    pub fn assign_current_process(&self) -> io::Result<()> {
        // SAFETY: the job handle is open while `self` lives, and the
        // process handle is this process's pseudo-handle; the call reads no
        // memory of ours.
        let ok = unsafe { AssignProcessToJobObject(self.0.as_raw_handle(), current_process()) };
        win32(ok)
    }

    /// Assigns the process `process` names to the job, as libuv assigns
    /// each child it spawns to its own job: the confinement tests' outer
    /// job.
    #[cfg(feature = "test-windows")]
    #[allow(unsafe_code)]
    pub fn assign(&self, process: BorrowedHandle<'_>) -> io::Result<()> {
        // SAFETY: both handles are open for the call: the job's while `self`
        // lives, and `process` for its borrow. A handle that isn't a
        // process's fails the call; it reads no memory of ours.
        let ok =
            unsafe { AssignProcessToJobObject(self.0.as_raw_handle(), process.as_raw_handle()) };
        win32(ok)
    }

    /// Whether this process is in the job, directly or through a job nested
    /// in it (`IsProcessInJob`).
    pub fn holds_current_process(&self) -> io::Result<bool> {
        in_job(current_process(), self.0.as_raw_handle())
    }

    /// Whether the process `process` names is in the job (`IsProcessInJob`).
    #[cfg(feature = "test-windows")]
    pub fn holds(&self, process: BorrowedHandle<'_>) -> io::Result<bool> {
        in_job(process.as_raw_handle(), self.0.as_raw_handle())
    }
}

/// `IsProcessInJob` on two handles open for the call.
#[allow(unsafe_code)]
fn in_job(process: HANDLE, job: HANDLE) -> io::Result<bool> {
    let mut result: windows_sys::core::BOOL = 0;
    // SAFETY: the callers pass an open process handle (or this process's
    // pseudo-handle) and an open job handle, both valid for the call, and
    // `result` is a BOOL of ours the call writes.
    let ok = unsafe { IsProcessInJob(process, job, &raw mut result) };
    win32(ok)?;
    Ok(result != 0)
}

/// `QueryInformationJobObject`'s limits, for an open job handle or NULL:
/// this process's immediate job.
#[allow(unsafe_code)]
fn query_limits(job: HANDLE) -> io::Result<Limits> {
    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    // SAFETY: `info` is a whole JOBOBJECT_EXTENDED_LIMIT_INFORMATION of
    // EXTENDED_LIMITS bytes, ours for the call, which writes at most that
    // many into it; the length pointer may be NULL. `job` is an open job
    // handle or NULL, which names this process's own job.
    let ok = unsafe {
        QueryInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&raw mut info).cast(),
            EXTENDED_LIMITS,
            std::ptr::null_mut(),
        )
    };
    win32(ok)?;
    Ok(Limits {
        flags: info.BasicLimitInformation.LimitFlags,
        active_processes: info.BasicLimitInformation.ActiveProcessLimit,
    })
}

/// The limits of this process's immediate job: the innermost, when jobs are
/// nested (`QueryInformationJobObject` with no handle). `Err` when the
/// process is in no job.
pub fn own_job_limits() -> io::Result<Limits> {
    query_limits(std::ptr::null_mut())
}

/// A process mitigation policy confinement sets on itself (design 0010,
/// "Windows"). Each policy's structure is one `DWORD` of flags, and none
/// can be unset once set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mitigation {
    /// `ProcessDynamicCodePolicy`: [`PROHIBIT_DYNAMIC_CODE`].
    DynamicCode,
    /// `ProcessImageLoadPolicy`: [`NO_REMOTE_IMAGES`],
    /// [`NO_LOW_LABEL_IMAGES`], [`PREFER_SYSTEM32_IMAGES`].
    ImageLoad,
    /// `ProcessExtensionPointDisablePolicy`: [`DISABLE_EXTENSION_POINTS`].
    ExtensionPoints,
}

/// `ProcessDynamicCodePolicy`'s `ProhibitDynamicCode`: no executable memory
/// made or changed, by this process or, with no `AllowRemoteDowngrade`,
/// another.
pub const PROHIBIT_DYNAMIC_CODE: u32 = 1 << 0;
/// `ProcessImageLoadPolicy`'s `NoRemoteImages`: no image from a remote
/// device, such as a share.
pub const NO_REMOTE_IMAGES: u32 = 1 << 0;
/// `ProcessImageLoadPolicy`'s `NoLowMandatoryLabelImages`: no image a low
/// integrity process could have written.
pub const NO_LOW_LABEL_IMAGES: u32 = 1 << 1;
/// `ProcessImageLoadPolicy`'s `PreferSystem32Images`: a DLL found in
/// System32 before the application's directory.
pub const PREFER_SYSTEM32_IMAGES: u32 = 1 << 2;
/// `ProcessExtensionPointDisablePolicy`'s `DisableExtensionPoints`: no
/// AppInit DLLs, legacy Winsock LSPs, global window hooks or legacy IMEs.
pub const DISABLE_EXTENSION_POINTS: u32 = 1 << 0;

// Each policy's structure is the one DWORD these calls pass.
const _: () = assert!(size_of::<PROCESS_MITIGATION_DYNAMIC_CODE_POLICY>() == size_of::<u32>());
const _: () = assert!(size_of::<PROCESS_MITIGATION_IMAGE_LOAD_POLICY>() == size_of::<u32>());
const _: () =
    assert!(size_of::<PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY>() == size_of::<u32>());

impl Mitigation {
    fn policy(self) -> PROCESS_MITIGATION_POLICY {
        match self {
            Mitigation::DynamicCode => ProcessDynamicCodePolicy,
            Mitigation::ImageLoad => ProcessImageLoadPolicy,
            Mitigation::ExtensionPoints => ProcessExtensionPointDisablePolicy,
        }
    }

    /// Sets the policy to `flags` for this process
    /// (`SetProcessMitigationPolicy`). An OS that doesn't know the policy
    /// fails it alone (`ERROR_INVALID_PARAMETER`).
    #[allow(unsafe_code)]
    pub fn set(self, flags: u32) -> io::Result<()> {
        // SAFETY: each policy's structure is one DWORD (the assertions
        // above), so `flags` is a whole one, borrowed for the call, which
        // only reads it.
        let ok = unsafe {
            SetProcessMitigationPolicy(self.policy(), (&raw const flags).cast(), size_of::<u32>())
        };
        win32(ok)
    }

    /// The policy's flags for this process, read back
    /// (`GetProcessMitigationPolicy`).
    #[allow(unsafe_code)]
    pub fn get(self) -> io::Result<u32> {
        let mut flags = 0u32;
        // SAFETY: each policy's structure is one DWORD (above), so `flags`
        // is a whole one, ours for the call, which writes at most that many
        // bytes into it; the process handle is this process's pseudo-handle.
        let ok = unsafe {
            GetProcessMitigationPolicy(
                current_process(),
                self.policy(),
                (&raw mut flags).cast(),
                size_of::<u32>(),
            )
        };
        win32(ok)?;
        Ok(flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_drive_is_local_and_bad_input_unknown() {
        let root: Vec<u16> = "C:\\\0".encode_utf16().collect();
        assert!(!matches!(
            drive_type(&root),
            DRIVE_UNKNOWN | DRIVE_NO_ROOT_DIR | DRIVE_REMOTE
        ));
        let unterminated: Vec<u16> = "C:\\".encode_utf16().collect();
        assert_eq!(drive_type(&unterminated), DRIVE_UNKNOWN);
    }

    #[test]
    fn a_job_keeps_the_limits_it_was_given() {
        let job = Job::new().unwrap();
        assert_eq!(
            job.limits().unwrap(),
            Limits {
                flags: 0,
                active_processes: 0
            }
        );
        let limits = Limits {
            flags: limit::ACTIVE_PROCESS,
            active_processes: 1,
        };
        job.set_limits(limits).unwrap();
        assert_eq!(job.limits().unwrap(), limits);
        // Not assigned: this test's process isn't in it.
        assert!(!job.holds_current_process().unwrap());
    }

    #[test]
    fn this_process_s_mitigations_read_back() {
        // Unset in a test process; this test sets none, since none can be
        // unset (the confinement tests set them, each in a child).
        for mitigation in [
            Mitigation::DynamicCode,
            Mitigation::ImageLoad,
            Mitigation::ExtensionPoints,
        ] {
            assert!(mitigation.get().is_ok(), "{mitigation:?}");
        }
    }
}
