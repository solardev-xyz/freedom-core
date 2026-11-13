//! Windows calls: storage qualification, error reporting, a file's
//! identity, a directory opened or made relative to its parent's handle,
//! and confinement's job object and process mitigation policies (design
//! 0010, "Windows").
//!
//! None of these calls closes a handle but [`Job`]'s own, which it owns.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_DIRECTORY_FILE, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    NtCreateFile,
};
use windows_sys::Win32::Foundation::{
    HANDLE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_NORMAL, FILE_ID_INFO, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo,
    GetDriveTypeW, GetFileInformationByHandle, GetFileInformationByHandleEx, SYNCHRONIZE,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX, SetErrorMode,
};
use windows_sys::Win32::System::ErrorReporting::{
    WER_FAULT_REPORTING_FLAG_NOHEAP, WER_FAULT_REPORTING_NO_UI, WerSetFlags,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
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

/// The size of `FILE_ID_INFO`, as `GetFileInformationByHandleEx` takes it.
const FILE_ID_INFO_SIZE: u32 = size_of::<FILE_ID_INFO>() as u32;
const _: () = assert!(size_of::<FILE_ID_INFO>() <= u32::MAX as usize);

/// The identity of the file `file` is open on, among every file of the
/// machine's volumes: its volume's serial number and its 128-bit file ID
/// (`GetFileInformationByHandleEx`, `FileIdInfo`), which ReFS needs whole. A
/// file system that doesn't give it fails the call, and [`file_index`]
/// serves there.
#[allow(unsafe_code)]
pub fn file_id(file: BorrowedHandle<'_>) -> io::Result<(u64, u128)> {
    let mut info = FILE_ID_INFO::default();
    // SAFETY: `info` is a whole FILE_ID_INFO of FILE_ID_INFO_SIZE bytes,
    // borrowed mutably for the call, which writes at most that many; the
    // handle is open for its borrow, and one that isn't a file's fails the
    // call.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&raw mut info).cast(),
            FILE_ID_INFO_SIZE,
        )
    };
    win32(ok)?;
    Ok((
        info.VolumeSerialNumber,
        u128::from_le_bytes(info.FileId.Identifier),
    ))
}

/// [`file_id`] as every file system gives it (`GetFileInformationByHandle`):
/// the volume's 32-bit serial number and the 64-bit file index, widened.
#[allow(unsafe_code)]
pub fn file_index(file: BorrowedHandle<'_>) -> io::Result<(u64, u128)> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `info` is a whole BY_HANDLE_FILE_INFORMATION, borrowed mutably
    // for the call, which writes only it; the handle is open for its
    // borrow, and one that isn't a file's fails the call.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut info) };
    win32(ok)?;
    Ok((
        u64::from(info.dwVolumeSerialNumber),
        (u128::from(info.nFileIndexHigh) << 32) | u128::from(info.nFileIndexLow),
    ))
}

/// The size of `OBJECT_ATTRIBUTES`, its `Length`.
const OBJECT_ATTRIBUTES_SIZE: u32 = size_of::<OBJECT_ATTRIBUTES>() as u32;
const _: () = assert!(size_of::<OBJECT_ATTRIBUTES>() <= u32::MAX as usize);

/// Opens the directory `name` in the directory `parent` is open on, making
/// it first if it is missing (`NtCreateFile`, `FILE_OPEN_IF`, relative to
/// `parent`): `name` is looked up in that directory itself, wherever it now
/// is, never by a path, so a parent renamed or replaced meanwhile can't
/// redirect it.
///
/// - **A reparse point** at `name` (a symlink or a junction) is opened
///   itself, never followed (`FILE_OPEN_REPARSE_POINT`), and nothing is made
///   through it: the caller refuses it by its attributes. A file there fails
///   (`NotADirectory`).
/// - **A directory made** inherits its parent's ACL, as `CreateDirectoryW`
///   without security attributes does.
/// - **The handle** lists the directory and reads its attributes, and shares
///   reading, writing and deletion, as std's opens do.
/// - **`name`** must be one plain component: not empty, not `.` or `..`, and
///   without a separator, a stream's `:` or a NUL (`InvalidInput`).
#[allow(unsafe_code)]
pub fn open_dir_at(parent: BorrowedHandle<'_>, name: &OsStr) -> io::Result<OwnedHandle> {
    let mut wide: Vec<u16> = name.encode_wide().collect();
    // NUL, `/`, `:` and `\`.
    let separator = |unit: &u16| matches!(*unit, 0x00 | 0x2f | 0x3a | 0x5c);
    let plain = !wide.is_empty() && name != "." && name != ".." && !wide.iter().any(separator);
    let bytes = wide
        .len()
        .checked_mul(2)
        .and_then(|n| u16::try_from(n).ok());
    let (true, Some(bytes)) = (plain, bytes) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not one plain path component",
        ));
    };
    let object_name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: OBJECT_ATTRIBUTES_SIZE,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &raw const object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle: HANDLE = std::ptr::null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `handle` and `status_block` are borrowed mutably for the call,
    // which writes only them; `attributes` and the UNICODE_STRING it points
    // to live for the whole call, and that string's buffer holds `bytes`
    // bytes of `wide`, which the call only reads; `parent` is open for its
    // borrow; no allocation size or extended attributes are passed (null,
    // 0).
    let status = unsafe {
        NtCreateFile(
            &raw mut handle,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &raw const attributes,
            &raw mut status_block,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN_IF,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: RtlNtStatusToDosError takes a status by value and reads no
        // memory of ours.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    // SAFETY: the call succeeded, so `handle` is a handle it opened for this
    // process, which nothing else owns or closes.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
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
    fn a_file_s_identity_is_its_own_and_survives_a_rename() {
        use std::os::windows::io::AsHandle;
        let dir = std::env::temp_dir().join(format!("fc-sys-file-id-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (one, two) = (dir.join("one"), dir.join("two"));
        std::fs::write(&one, b"one").unwrap();
        std::fs::write(&two, b"two").unwrap();
        let ids = |path: &std::path::Path| {
            let file = std::fs::File::open(path).unwrap();
            (
                file_id(file.as_handle()).unwrap(),
                file_index(file.as_handle()).unwrap(),
            )
        };
        let (id, index) = ids(&one);
        assert_ne!(ids(&two), (id, index));
        let renamed = dir.join("renamed");
        std::fs::rename(&one, &renamed).unwrap();
        assert_eq!(ids(&renamed), (id, index));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_directory_is_opened_or_made_at_its_parent_never_through_a_junction() {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use std::os::windows::io::AsHandle;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        let dir = std::env::temp_dir().join(format!("fc-sys-dir-at-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let parent = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&dir)
            .unwrap();
        let attributes = |handle: OwnedHandle| {
            std::fs::File::from(handle)
                .metadata()
                .unwrap()
                .file_attributes()
        };
        // Made, then opened as it is.
        let made = open_dir_at(parent.as_handle(), OsStr::new("made")).unwrap();
        assert!(dir.join("made").is_dir());
        assert_eq!(attributes(made) & FILE_ATTRIBUTE_REPARSE_POINT, 0);
        open_dir_at(parent.as_handle(), OsStr::new("made")).unwrap();
        // Relative to the handle: the parent renamed, it is still the one.
        let moved =
            std::env::temp_dir().join(format!("fc-sys-dir-at-{}-moved", std::process::id()));
        std::fs::rename(&dir, &moved).unwrap();
        open_dir_at(parent.as_handle(), OsStr::new("after")).unwrap();
        assert!(moved.join("after").is_dir());
        // A file fails; a junction is opened itself, nothing made through it.
        std::fs::write(moved.join("file"), b"x").unwrap();
        let file = open_dir_at(parent.as_handle(), OsStr::new("file")).unwrap_err();
        assert_eq!(file.kind(), io::ErrorKind::NotADirectory);
        let target = moved.join("target");
        std::fs::create_dir(&target).unwrap();
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(moved.join("junction"))
            .arg(&target)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J");
        let junction = open_dir_at(parent.as_handle(), OsStr::new("junction")).unwrap();
        assert_ne!(attributes(junction) & FILE_ATTRIBUTE_REPARSE_POINT, 0);
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
        for name in ["", ".", "..", "a\\b", "a/b", "a:b"] {
            let refused = open_dir_at(parent.as_handle(), OsStr::new(name)).unwrap_err();
            assert_eq!(refused.kind(), io::ErrorKind::InvalidInput, "{name:?}");
        }
        drop(parent);
        std::fs::remove_dir_all(&moved).unwrap();
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
