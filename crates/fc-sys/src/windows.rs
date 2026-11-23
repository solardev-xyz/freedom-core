//! Windows calls: storage qualification, error reporting, a file's
//! identity and whether this process's user owns it, files and directories
//! opened, made, renamed, deleted and listed relative to a directory's
//! handle (design 0013, "Windows handle I/O (#963)"), a volume's free space
//! from a handle (0013, "The move": PRF-9c's copy), and confinement's job
//! object and process mitigation policies (design 0010, "Windows").
//!
//! None of these calls closes a handle but its own: [`Job`]'s, and the
//! process token [`owned_by_current_user`] opens.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_INFORMATION_CLASS, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_RENAME_POSIX_SEMANTICS,
    FILE_RENAME_REPLACE_IF_EXISTS, FILE_SYNCHRONOUS_IO_NONALERT, FileFsFullSizeInformation,
    FileRenameInformation, FileRenameInformationEx, NtCreateFile, NtQueryVolumeInformationFile,
    NtSetInformationFile,
};
use windows_sys::Wdk::System::SystemServices::FILE_FS_FULL_SIZE_INFORMATION;
use windows_sys::Win32::Foundation::{
    ERROR_DIRECTORY_NOT_SUPPORTED, ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER,
    ERROR_NO_MORE_FILES, ERROR_NOT_SUPPORTED, HANDLE, LocalFree, NTSTATUS, OBJ_CASE_INSENSITIVE,
    RtlNtStatusToDosError, STATUS_FILE_IS_A_DIRECTORY, UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_MAX_SID_SIZE, TOKEN_INFORMATION_CLASS, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
    TokenOwner, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_DISPOSITION_FLAG_DELETE,
    FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX, FILE_ID_BOTH_DIR_INFO, FILE_ID_INFO,
    FILE_INFO_BY_HANDLE_CLASS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FileAttributeTagInfo, FileDispositionInfo, FileDispositionInfoEx,
    FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo, FileIdInfo, GetDriveTypeW,
    GetFileInformationByHandle, GetFileInformationByHandleEx, SYNCHRONIZE,
    SetFileInformationByHandle,
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
use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::SystemServices::{
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessMitigationPolicy, OpenProcessToken, PROCESS_MITIGATION_POLICY,
    ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy,
    SetProcessMitigationPolicy,
};

/// `GetDriveTypeW`'s `DRIVE_UNKNOWN`.
pub const DRIVE_UNKNOWN: u32 = 0;
/// `GetDriveTypeW`'s `DRIVE_NO_ROOT_DIR`.
pub const DRIVE_NO_ROOT_DIR: u32 = 1;
/// `GetDriveTypeW`'s `DRIVE_REMOTE`: a mapped network drive.
pub const DRIVE_REMOTE: u32 = 4;

/// This process's working set in bytes (`K32GetProcessMemoryInfo`'s
/// `WorkingSetSize`, kernel32's copy, so no psapi.dll): the Colibri
/// service's resident memory after each step (design 0014, Budgets).
#[allow(unsafe_code)]
pub fn resident_bytes() -> io::Result<u64> {
    let mut counters = PROCESS_MEMORY_COUNTERS::default();
    let size = u32::try_from(std::mem::size_of::<PROCESS_MEMORY_COUNTERS>()).unwrap_or(0);
    // SAFETY: GetCurrentProcess takes nothing and returns a pseudo-handle,
    // which needs no closing.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: with that handle, the call writes at most `size` bytes into
    // `counters`, which is exactly that large, and reads nothing of ours.
    let ok = unsafe { K32GetProcessMemoryInfo(process, &raw mut counters, size) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(counters.WorkingSetSize).map_err(|_| io::Error::other("working set past u64"))
}

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

/// A SID that stays valid while `'a` lasts: the owner in a security
/// descriptor [`file_owner`] read, a token's SID [`token_sid`] read, or
/// [`administrators`]. Nothing else makes one, so [`equal_sid`] only ever
/// reads a valid SID.
#[derive(Clone, Copy)]
struct Sid<'a>(PSID, std::marker::PhantomData<&'a ()>);

/// BUILTIN\Administrators (S-1-5-32-544), as a SID's memory: revision 1 and
/// two sub-authorities, the NT authority (`{0, 0, 0, 0, 0, 5}`), then the
/// sub-authorities 32 and 544. Words, so it is aligned as a SID's `DWORD`
/// sub-authorities need.
static ADMINISTRATORS_SID: [u32; 4] = [
    u32::from_ne_bytes([1, 2, 0, 0]),
    u32::from_ne_bytes([0, 0, 0, 5]),
    32,
    544,
];

/// [`ADMINISTRATORS_SID`] as a [`Sid`]. `EqualSid` only reads it, though
/// it takes a `PSID`.
fn administrators() -> Sid<'static> {
    Sid(
        ADMINISTRATORS_SID.as_ptr().cast_mut().cast(),
        std::marker::PhantomData,
    )
}

/// `EqualSid` on two valid SIDs. `false` when they differ (or, which a
/// [`Sid`] rules out, one isn't valid).
#[allow(unsafe_code)]
fn equal_sid(one: Sid<'_>, two: Sid<'_>) -> bool {
    // SAFETY: a `Sid` points to a valid SID for its lifetime, which spans
    // the call; EqualSid only reads both and keeps no reference.
    let equal = unsafe { EqualSid(one.0, two.0) };
    equal != 0
}

/// A security descriptor `GetSecurityInfo` allocated, with the owner SID
/// inside it, freed (`LocalFree`) once, on drop.
struct OwnerDescriptor {
    descriptor: PSECURITY_DESCRIPTOR,
    owner: PSID,
}

impl OwnerDescriptor {
    /// The owner, which lives inside the descriptor; `None` if it has none.
    fn owner(&self) -> Option<Sid<'_>> {
        (!self.owner.is_null()).then_some(Sid(self.owner, std::marker::PhantomData))
    }
}

impl Drop for OwnerDescriptor {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `descriptor` is the buffer GetSecurityInfo allocated for
        // this value alone (or NULL, which LocalFree ignores), freed once
        // here; no `Sid` borrowed from it outlives `self`.
        unsafe { LocalFree(self.descriptor) };
    }
}

/// The owner of the file `file` is open on (`GetSecurityInfo`,
/// `OWNER_SECURITY_INFORMATION`), read from the handle, which needs
/// `READ_CONTROL`: a handle without it fails (`PermissionDenied`).
#[allow(unsafe_code)]
fn file_owner(file: BorrowedHandle<'_>) -> io::Result<OwnerDescriptor> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `owner` and `descriptor` are ours, borrowed mutably for the
    // call, which writes only them: the owner's address inside the
    // descriptor, and the descriptor it allocates, which OwnerDescriptor
    // frees. The group, DACL and SACL pointers are NULL, since only the
    // owner is asked for. The handle is open for its borrow, and one that
    // isn't a file's fails the call.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    // Owned from here, so freed on every path.
    let read = OwnerDescriptor { descriptor, owner };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(read)
}

/// This process's token, open to query (`OpenProcessToken`, `TOKEN_QUERY`),
/// closed on drop.
#[allow(unsafe_code)]
fn process_token() -> io::Result<OwnedHandle> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the process handle is this process's pseudo-handle; `token` is
    // ours, borrowed mutably for the call, which writes only it.
    let ok = unsafe { OpenProcessToken(current_process(), TOKEN_QUERY, &raw mut token) };
    win32(ok)?;
    // SAFETY: the call succeeded, so `token` is a handle it opened for this
    // process, which nothing else owns or closes.
    Ok(unsafe { OwnedHandle::from_raw_handle(token) })
}

/// A token information class whose structure is a SID's address, which
/// `GetTokenInformation` writes followed by the SID itself.
trait SidClass: Copy + Default {
    const CLASS: TOKEN_INFORMATION_CLASS;
    fn sid(&self) -> PSID;
}

/// `TokenUser`: the token's user.
impl SidClass for TOKEN_USER {
    const CLASS: TOKEN_INFORMATION_CLASS = TokenUser;
    fn sid(&self) -> PSID {
        self.User.Sid
    }
}

/// `TokenOwner`: the owner the token gives the objects it creates.
impl SidClass for TOKEN_OWNER {
    const CLASS: TOKEN_INFORMATION_CLASS = TokenOwner;
    fn sid(&self) -> PSID {
        self.Owner
    }
}

/// A [`SidClass`] structure and room for the largest SID after it, as
/// `GetTokenInformation` lays them out.
#[repr(C)]
struct TokenSid<T> {
    head: T,
    sid: [u8; SECURITY_MAX_SID_SIZE as usize],
}

impl<T: SidClass> TokenSid<T> {
    /// The SID, which the call that filled `self` placed in it.
    fn sid(&self) -> Sid<'_> {
        Sid(self.head.sid(), std::marker::PhantomData)
    }
}

/// `token`'s SID of class `T` (`GetTokenInformation`), on the heap, so the
/// address the call writes stays the SID's while the box lives. A SID past
/// [`SECURITY_MAX_SID_SIZE`], which no SID is, fails the call.
#[allow(unsafe_code)]
fn token_sid<T: SidClass>(token: BorrowedHandle<'_>) -> io::Result<Box<TokenSid<T>>> {
    let mut info = Box::new(TokenSid {
        head: T::default(),
        sid: [0; SECURITY_MAX_SID_SIZE as usize],
    });
    let size = u32::try_from(size_of::<TokenSid<T>>()).map_err(io::Error::other)?;
    let mut written = 0u32;
    // SAFETY: `info` is a whole TokenSid<T> of `size` bytes on the heap,
    // aligned for T, borrowed mutably for the call, which writes at most
    // that many: the class's structure, which is T, and the SID it points
    // to, inside the same buffer; `written` is ours. The token is open for
    // its borrow, with TOKEN_QUERY.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            T::CLASS,
            (&raw mut *info).cast(),
            size,
            &raw mut written,
        )
    };
    win32(ok)?;
    Ok(info)
}

/// Whether this process's user owns the file `file` is open on, read from
/// the handle (`GetSecurityInfo`): its owner is the process token's user
/// (`TokenUser`), or BUILTIN\Administrators when that group is the token's
/// default owner (`TokenOwner`): an elevated administrator's token, whose
/// new files Windows gives to the group rather than the user under the
/// policy "Default owner for objects created by members of the
/// Administrators group". Only an administrator can give a file to that
/// group (short of the restore privilege, which could name the user just as
/// well). No other group counts, not even a token's default owner, since
/// another member could give a file to it.
///
/// `Err` when it can't tell: the handle lacks `READ_CONTROL`
/// (`PermissionDenied`), or a token call fails. A file with no owner isn't
/// the user's.
pub fn owned_by_current_user(file: BorrowedHandle<'_>) -> io::Result<bool> {
    use std::os::windows::io::AsHandle;
    let descriptor = file_owner(file)?;
    let token = process_token()?;
    let user = token_sid::<TOKEN_USER>(token.as_handle())?;
    let Some(owner) = descriptor.owner() else {
        return Ok(false);
    };
    if equal_sid(owner, user.sid()) {
        return Ok(true);
    }
    if !equal_sid(owner, administrators()) {
        return Ok(false);
    }
    let default_owner = token_sid::<TOKEN_OWNER>(token.as_handle())?;
    Ok(equal_sid(default_owner.sid(), administrators()))
}

/// Whether a path component, in UTF-16, is one Win32 paths read as
/// something other than the directory entry it spells, which `NtCreateFile`
/// would still make as spelled:
///
/// - **A DOS device:** `CON`, `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`,
///   `COM0`–`COM9` and `LPT0`–`LPT9`, and `COM`/`LPT` with a superscript
///   `¹`, `²` or `³`, in any case, alone or before an extension, and with
///   spaces before that extension (`NUL.txt`, `con .log`).
/// - **A name ending in a space or a period,** which Win32 strips.
fn win32_reserved(wide: &[u16]) -> bool {
    if matches!(wide.last(), Some(0x20 | 0x2e)) {
        return true;
    }
    let end = wide
        .iter()
        .position(|&unit| unit == 0x2e)
        .unwrap_or(wide.len());
    let mut base = &wide[..end];
    while let [rest @ .., 0x20] = base {
        base = rest;
    }
    let upper: Vec<u16> = base
        .iter()
        .map(|&unit| {
            if (0x61..=0x7a).contains(&unit) {
                unit - 0x20
            } else {
                unit
            }
        })
        .collect();
    let spells = |text: &str| text.encode_utf16().eq(upper.iter().copied());
    if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
        .into_iter()
        .any(spells)
    {
        return true;
    }
    if let &[a, b, c, digit] = upper.as_slice() {
        let prefix = [a, b, c];
        let port = "COM".encode_utf16().eq(prefix) || "LPT".encode_utf16().eq(prefix);
        // `0`–`9`, `¹`, `²` and `³`.
        let digit = (0x30..=0x39).contains(&digit) || matches!(digit, 0xb9 | 0xb2 | 0xb3);
        return port && digit;
    }
    false
}

/// The size of `OBJECT_ATTRIBUTES`, its `Length`.
const OBJECT_ATTRIBUTES_SIZE: u32 = size_of::<OBJECT_ATTRIBUTES>() as u32;
const _: () = assert!(size_of::<OBJECT_ATTRIBUTES>() <= u32::MAX as usize);

/// The access [`open_at`] asks for (`ACCESS_MASK` bits). Every open adds
/// reading the attributes ([`attribute_tag`]) and waiting on the handle
/// (its I/O is synchronous), which each handle here needs.
pub mod access {
    use windows_sys::Win32::Storage::FileSystem as fs;

    /// Reading the data, the attributes and the security descriptor (an
    /// owner check), as `GENERIC_READ` maps for a file.
    pub const READ: u32 = fs::FILE_GENERIC_READ;
    /// Reading a file's data alone (`FILE_READ_DATA`), without the extended
    /// attributes or the security descriptor `READ` adds: what a byte copy
    /// takes.
    pub const READ_DATA: u32 = fs::FILE_READ_DATA;
    /// Writing the data and the attributes, as `GENERIC_WRITE` maps: a
    /// flush needs it.
    pub const WRITE: u32 = fs::FILE_GENERIC_WRITE;
    /// Deleting or renaming what is opened ([`super::delete`],
    /// [`super::rename_at`]).
    pub const DELETE: u32 = fs::DELETE;
    /// Listing a directory.
    pub const LIST: u32 = fs::FILE_LIST_DIRECTORY;
    /// Every open's alone: the attributes and the identity.
    pub const ATTRIBUTES: u32 = fs::FILE_READ_ATTRIBUTES;
}

/// `CreateFileW` flags for a path std opens (`OpenOptionsExt::custom_flags`).
pub mod flags {
    use windows_sys::Win32::Storage::FileSystem as fs;

    /// A directory may be opened.
    pub const BACKUP_SEMANTICS: u32 = fs::FILE_FLAG_BACKUP_SEMANTICS;
    /// A reparse point (a symlink or a junction) is opened itself, never
    /// followed.
    pub const OPEN_REPARSE_POINT: u32 = fs::FILE_FLAG_OPEN_REPARSE_POINT;
}

/// Whether [`open_at`] makes what it opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Create {
    /// Only what is there (`FILE_OPEN`): nothing there is `NotFound`.
    No,
    /// Only something new (`FILE_CREATE`): anything there, a reparse point
    /// included, is `AlreadyExists`.
    New,
    /// What is there, made first if nothing is (`FILE_OPEN_IF`).
    IfMissing,
}

/// What [`open_at`] must find there, and makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// A file or a directory; made as a file.
    Any,
    /// A directory (`FILE_DIRECTORY_FILE`): anything else is
    /// `NotADirectory`. Made as one.
    Directory,
    /// Not a directory (`FILE_NON_DIRECTORY_FILE`): a directory (a junction
    /// included) is `IsADirectory`. Made as a file.
    File,
}

/// How [`open_at`] opens a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenAt {
    /// The access asked for ([`access`]).
    pub access: u32,
    pub create: Create,
    pub expect: Expect,
    /// Whether a reparse point at the name is followed. If not
    /// (`FILE_OPEN_REPARSE_POINT`), it is opened itself, nothing is made
    /// through it, and [`attribute_tag`] tells the caller what it is.
    pub follow: bool,
}

/// `name` as UTF-16 if it is one plain component: not empty, not `.` or
/// `..`, without a separator, a stream's `:` or a NUL, and not a name Win32
/// paths would read as something else ([`win32_reserved`]), so that a path
/// ending in it names what was opened (`InvalidInput`).
fn plain_component(name: &OsStr) -> io::Result<Vec<u16>> {
    let wide: Vec<u16> = name.encode_wide().collect();
    // NUL, `/`, `:` and `\`.
    let separator = |unit: &u16| matches!(*unit, 0x00 | 0x2f | 0x3a | 0x5c);
    let plain = !wide.is_empty()
        && name != "."
        && name != ".."
        && !wide.iter().any(separator)
        && !win32_reserved(&wide);
    if plain {
        Ok(wide)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not one plain path component",
        ))
    }
}

/// An NTSTATUS failure as the Win32 error std reads its kind from. A
/// directory where a file was asked for is `ERROR_DIRECTORY_NOT_SUPPORTED`
/// (`IsADirectory`), which `RtlNtStatusToDosError` would blur into "access
/// denied".
#[allow(unsafe_code)]
fn nt_error(status: NTSTATUS) -> io::Error {
    if status == STATUS_FILE_IS_A_DIRECTORY {
        return io::Error::from_raw_os_error(ERROR_DIRECTORY_NOT_SUPPORTED as i32);
    }
    // SAFETY: RtlNtStatusToDosError takes a status by value and reads no
    // memory of ours.
    let code = unsafe { RtlNtStatusToDosError(status) };
    io::Error::from_raw_os_error(code as i32)
}

/// `NtCreateFile` of `wide` relative to `parent`, as `how` says, sharing
/// reading, writing and deletion as std's opens do. A file or directory
/// made inherits its parent's ACL, as `CreateFileW` and `CreateDirectoryW`
/// without security attributes do. An empty `wide` opens `parent`'s file or
/// directory again, as a handle of its own (as `ReOpenFile` does).
#[allow(unsafe_code)]
fn nt_create(parent: BorrowedHandle<'_>, wide: &mut [u16], how: OpenAt) -> io::Result<OwnedHandle> {
    let Some(bytes) = wide
        .len()
        .checked_mul(2)
        .and_then(|n| u16::try_from(n).ok())
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a path component too long",
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
    let disposition = match how.create {
        Create::No => FILE_OPEN,
        Create::New => FILE_CREATE,
        Create::IfMissing => FILE_OPEN_IF,
    };
    let mut options = FILE_SYNCHRONOUS_IO_NONALERT
        | match how.expect {
            Expect::Any => 0,
            Expect::Directory => FILE_DIRECTORY_FILE,
            Expect::File => FILE_NON_DIRECTORY_FILE,
        };
    if !how.follow {
        options |= FILE_OPEN_REPARSE_POINT;
    }
    let mut handle: HANDLE = std::ptr::null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `handle` and `status_block` are borrowed mutably for the call,
    // which writes only them; `attributes` and the UNICODE_STRING it points
    // to live for the whole call, and that string's buffer holds `bytes`
    // bytes of `wide` (none when it is empty), which the call only reads;
    // `parent` is open for its borrow; no allocation size or extended
    // attributes are passed (null, 0).
    let status = unsafe {
        NtCreateFile(
            &raw mut handle,
            how.access | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &raw const attributes,
            &raw mut status_block,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            disposition,
            options,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(nt_error(status));
    }
    // SAFETY: the call succeeded, so `handle` is a handle it opened for this
    // process, which nothing else owns or closes.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// Opens `name` in the directory `parent` is open on, as `how` says
/// (`NtCreateFile` relative to `parent`): `name` is looked up in that
/// directory itself, wherever it now is, never by a path, so a parent
/// renamed, or replaced by a junction, meanwhile can't redirect it
/// (design 0013, "Windows handle I/O (#963)").
///
/// - **A reparse point** at `name` is opened itself unless `how.follow`,
///   and nothing is made through it; [`attribute_tag`] tells the caller.
/// - **`name`** must be one plain component ([`plain_component`]):
///   `InvalidInput` otherwise.
/// - **Errors** carry the Win32 code std reads a kind from: `NotFound`,
///   `AlreadyExists`, `NotADirectory`, `IsADirectory`, and so on.
pub fn open_at(parent: BorrowedHandle<'_>, name: &OsStr, how: OpenAt) -> io::Result<OwnedHandle> {
    let mut wide = plain_component(name)?;
    nt_create(parent, &mut wide, how)
}

/// Opens the directory `name` in the directory `parent` is open on, making
/// it first if it is missing ([`open_at`]: `FILE_OPEN_IF`, relative to
/// `parent`).
///
/// - **A reparse point** at `name` (a symlink or a junction) is opened
///   itself, never followed, and nothing is made through it: the caller
///   refuses it by its attributes. A file there fails (`NotADirectory`).
/// - **The handle** lists the directory and reads its attributes.
pub fn open_dir_at(parent: BorrowedHandle<'_>, name: &OsStr) -> io::Result<OwnedHandle> {
    let how = OpenAt {
        access: access::LIST,
        create: Create::IfMissing,
        expect: Expect::Directory,
        follow: false,
    };
    open_at(parent, name, how)
}

/// A file's attributes, as [`attribute_tag`] reads them from its handle or
/// [`list_dir`] from its directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attributes {
    /// The `FILE_ATTRIBUTE_*` bits.
    pub bits: u32,
    /// A reparse point's tag (`IO_REPARSE_TAG_*`); 0 for anything else.
    pub reparse_tag: u32,
}

impl Attributes {
    /// A directory, a junction or a directory symlink included.
    pub fn directory(self) -> bool {
        self.bits & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    /// A reparse point: a symlink, a junction, or another.
    pub fn reparse_point(self) -> bool {
        self.bits & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
}

/// The size of `FILE_ATTRIBUTE_TAG_INFO`, as `GetFileInformationByHandleEx`
/// takes it.
const ATTRIBUTE_TAG_INFO_SIZE: u32 = size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32;
const _: () = assert!(size_of::<FILE_ATTRIBUTE_TAG_INFO>() <= u32::MAX as usize);

/// The attributes of what `file` is open on, and its reparse tag
/// (`GetFileInformationByHandleEx`, `FileAttributeTagInfo`): a reparse
/// point opened itself says so here. The handle needs
/// `FILE_READ_ATTRIBUTES`, which every [`open_at`] handle has.
#[allow(unsafe_code)]
pub fn attribute_tag(file: BorrowedHandle<'_>) -> io::Result<Attributes> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: `info` is a whole FILE_ATTRIBUTE_TAG_INFO of
    // ATTRIBUTE_TAG_INFO_SIZE bytes, borrowed mutably for the call, which
    // writes at most that many; the handle is open for its borrow, and one
    // that isn't a file's fails the call.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            (&raw mut info).cast(),
            ATTRIBUTE_TAG_INFO_SIZE,
        )
    };
    win32(ok)?;
    Ok(Attributes {
        bits: info.FileAttributes,
        reparse_tag: info.ReparseTag,
    })
}

/// Whether a `FileDispositionInfoEx` or `FileRenameInformationEx` failure means
/// the call isn't served there: before Windows 10 1607 (1809 for the
/// read-only flag), or on a file system without POSIX semantics, such as
/// FAT. std's `remove_dir_all` reads these the same way.
fn ex_unserved(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code) if code == ERROR_INVALID_PARAMETER as i32
            || code == ERROR_NOT_SUPPORTED as i32
            || code == ERROR_INVALID_FUNCTION as i32
    )
}

/// The size of `FILE_DISPOSITION_INFO_EX`.
const DISPOSITION_INFO_EX_SIZE: u32 = size_of::<FILE_DISPOSITION_INFO_EX>() as u32;
const _: () = assert!(size_of::<FILE_DISPOSITION_INFO_EX>() <= u32::MAX as usize);
/// The size of `FILE_DISPOSITION_INFO`.
const DISPOSITION_INFO_SIZE: u32 = size_of::<FILE_DISPOSITION_INFO>() as u32;
const _: () = assert!(size_of::<FILE_DISPOSITION_INFO>() <= u32::MAX as usize);

#[allow(unsafe_code)]
fn set_disposition_ex(file: BorrowedHandle<'_>, flags: u32) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO_EX { Flags: flags };
    // SAFETY: `info` is a whole FILE_DISPOSITION_INFO_EX of
    // DISPOSITION_INFO_EX_SIZE bytes, borrowed for the call, which only
    // reads it; the handle is open for its borrow.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            (&raw const info).cast(),
            DISPOSITION_INFO_EX_SIZE,
        )
    };
    win32(ok)
}

#[allow(unsafe_code)]
fn set_disposition(file: BorrowedHandle<'_>) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: `info` is a whole FILE_DISPOSITION_INFO of
    // DISPOSITION_INFO_SIZE bytes, borrowed for the call, which only reads
    // it; the handle is open for its borrow.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&raw const info).cast(),
            DISPOSITION_INFO_SIZE,
        )
    };
    win32(ok)
}

/// Deletes what `file` is open on, by its handle, which must have
/// [`access::DELETE`]: the entry it was opened as, wherever that now is
/// (`SetFileInformationByHandle`). A directory must be empty
/// (`DirectoryNotEmpty`); a reparse point opened itself is deleted itself.
///
/// - **POSIX semantics** (`FileDispositionInfoEx`, Windows 10 1607 and
///   NTFS): the name goes when this handle closes, though other handles
///   stay open on the file, and the read-only attribute is ignored, as
///   `unlink` ignores a file's mode. Callers close the handle at once.
/// - **Where those aren't served** ([`ex_unserved`]), the fallback is
///   `FileDispositionInfo`: still by this handle, but the name stays,
///   delete-pending, until the last handle on the file closes, and a
///   read-only file is refused.
pub fn delete(file: BorrowedHandle<'_>) -> io::Result<()> {
    let flags = FILE_DISPOSITION_FLAG_DELETE
        | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
        | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
    match set_disposition_ex(file, flags) {
        Err(e) if ex_unserved(&e) => set_disposition(file),
        result => result,
    }
}

/// The longest name [`rename_at`] takes, in UTF-16 units: NTFS's limit on
/// one component.
const MAX_NAME: usize = 255;
/// Where `FILE_RENAME_INFORMATION`'s name starts.
const RENAME_NAME_OFFSET: usize = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
/// A `FILE_RENAME_INFORMATION` with the longest name and its NUL.
const RENAME_BUFFER_SIZE: usize = RENAME_NAME_OFFSET + 2 * (MAX_NAME + 1);
const _: () = assert!(align_of::<FILE_RENAME_INFORMATION>() <= 8);
const _: () = assert!(RENAME_BUFFER_SIZE >= size_of::<FILE_RENAME_INFORMATION>());
const _: () = assert!(RENAME_BUFFER_SIZE <= u32::MAX as usize);

/// A `FILE_RENAME_INFORMATION` as its bytes, aligned as the structure is, and the
/// size of the part the call reads. Built only by [`RenameInfo::new`], so
/// `size` never exceeds the buffer.
#[repr(C, align(8))]
struct RenameInfo {
    bytes: [u8; RENAME_BUFFER_SIZE],
    size: u32,
}

impl RenameInfo {
    /// `flags` in the union's place (for `FileRenameInformation`, 1 is
    /// `ReplaceIfExists = TRUE`: its BOOLEAN is the union's first byte),
    /// `dir`'s handle as `RootDirectory`, and `name` with its length and a
    /// NUL. The handle's value is copied in: the caller keeps it open for
    /// the call that reads it.
    fn new(flags: u32, dir: BorrowedHandle<'_>, name: &[u16]) -> io::Result<RenameInfo> {
        let too_long =
            || io::Error::new(io::ErrorKind::InvalidInput, "a name too long to rename to");
        if name.len() > MAX_NAME {
            return Err(too_long());
        }
        let mut info = RenameInfo {
            bytes: [0; RENAME_BUFFER_SIZE],
            size: 0,
        };
        let name_bytes = u32::try_from(2 * name.len()).map_err(|_| too_long())?;
        let root = dir.as_raw_handle().addr();
        let mut put = |offset: usize, bytes: &[u8]| -> io::Result<()> {
            info.bytes
                .get_mut(offset..offset + bytes.len())
                .ok_or_else(too_long)?
                .copy_from_slice(bytes);
            Ok(())
        };
        put(
            std::mem::offset_of!(FILE_RENAME_INFORMATION, Anonymous),
            &flags.to_ne_bytes(),
        )?;
        put(
            std::mem::offset_of!(FILE_RENAME_INFORMATION, RootDirectory),
            &root.to_ne_bytes(),
        )?;
        put(
            std::mem::offset_of!(FILE_RENAME_INFORMATION, FileNameLength),
            &name_bytes.to_ne_bytes(),
        )?;
        for (index, unit) in name.iter().enumerate() {
            put(RENAME_NAME_OFFSET + 2 * index, &unit.to_ne_bytes())?;
        }
        // The name and its NUL, as std's rename sizes it.
        info.size =
            u32::try_from(RENAME_NAME_OFFSET + 2 * name.len() + 2).map_err(|_| too_long())?;
        Ok(info)
    }
}

/// `NtSetInformationFile`, not `SetFileInformationByHandle`: kernelbase
/// turns a `FILE_RENAME_INFO`'s name into a full path from the current
/// directory, which a name relative to `RootDirectory` can't survive.
#[allow(unsafe_code)]
fn set_rename(
    file: BorrowedHandle<'_>,
    class: FILE_INFORMATION_CLASS,
    info: &RenameInfo,
) -> io::Result<()> {
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `status_block` is borrowed mutably for the call, which writes
    // only it; `info.bytes` holds a FILE_RENAME_INFORMATION image of at
    // least `info.size` bytes (RenameInfo::new keeps it within the buffer),
    // aligned to 8 as the structure needs, borrowed for the call, which only
    // reads it; the RootDirectory in it is a handle our caller borrows for
    // the whole call; `file` is open for its borrow.
    let status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &raw mut status_block,
            (&raw const info.bytes).cast(),
            info.size,
            class,
        )
    };
    if status < 0 {
        return Err(nt_error(status));
    }
    Ok(())
}

/// Renames what `file` is open on (with [`access::DELETE`]) to `name` in
/// the directory `dir` is open on, replacing whatever is there without
/// following it (`NtSetInformationFile` with `RootDirectory`): the
/// entry `file` was opened as, wherever it now is, into that directory
/// itself, wherever it now is, never by a path.
///
/// - **POSIX semantics** (`FileRenameInformationEx`, Windows 10 1607 and NTFS): a
///   file there is replaced even while other handles are open on it (with
///   `FILE_SHARE_DELETE`), as `renameat` replaces it.
/// - **Where those aren't served** ([`ex_unserved`]), the fallback is
///   `FileRenameInformation` with `ReplaceIfExists`: still relative to both
///   handles, but a file there that is open is refused (`PermissionDenied`).
/// - **A directory there** isn't replaced (`PermissionDenied`), a junction
///   or directory symlink included.
/// - **`name`** must be one plain component of at most 255 UTF-16 units
///   (`InvalidInput`).
pub fn rename_at(
    file: BorrowedHandle<'_>,
    dir: BorrowedHandle<'_>,
    name: &OsStr,
) -> io::Result<()> {
    let wide = plain_component(name)?;
    let posix = RenameInfo::new(
        FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
        dir,
        &wide,
    )?;
    match set_rename(file, FileRenameInformationEx, &posix) {
        Err(e) if ex_unserved(&e) => {
            let legacy = RenameInfo::new(1, dir, &wide)?;
            set_rename(file, FileRenameInformation, &legacy)
        }
        result => result,
    }
}

/// The size of `FILE_FS_FULL_SIZE_INFORMATION`.
const FS_FULL_SIZE_INFO_SIZE: u32 = size_of::<FILE_FS_FULL_SIZE_INFORMATION>() as u32;
const _: () = assert!(size_of::<FILE_FS_FULL_SIZE_INFORMATION>() <= u32::MAX as usize);

/// The bytes this process's user may still write on the volume `file` is
/// open on, and the volume's allocation unit in bytes
/// (`NtQueryVolumeInformationFile`, `FileFsFullSizeInformation`: the
/// caller's available allocation units, which a disk quota limits, as
/// `GetDiskFreeSpaceExW`'s first count). From the handle, never a path; it
/// needs no access of its own.
#[allow(unsafe_code)]
pub fn volume_space(file: BorrowedHandle<'_>) -> io::Result<(u64, u64)> {
    let mut info = FILE_FS_FULL_SIZE_INFORMATION::default();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `info` is a whole FILE_FS_FULL_SIZE_INFORMATION of
    // FS_FULL_SIZE_INFO_SIZE bytes and `status_block` an IO_STATUS_BLOCK,
    // both borrowed mutably for the call, which writes at most those; the
    // handle is open for its borrow.
    let status = unsafe {
        NtQueryVolumeInformationFile(
            file.as_raw_handle(),
            &raw mut status_block,
            (&raw mut info).cast(),
            FS_FULL_SIZE_INFO_SIZE,
            FileFsFullSizeInformation,
        )
    };
    if status < 0 {
        return Err(nt_error(status));
    }
    let unit = u64::from(info.SectorsPerAllocationUnit) * u64::from(info.BytesPerSector);
    let units = u64::try_from(info.CallerAvailableAllocationUnits).unwrap_or(0);
    Ok((units.saturating_mul(unit), unit))
}

/// The size of [`DirBuffer`]: a listing's entries are read this many bytes
/// at a time.
const DIR_BUFFER_SIZE: usize = 64 * 1024;
const _: () = assert!(DIR_BUFFER_SIZE <= u32::MAX as usize);

/// Bytes for `FILE_ID_BOTH_DIR_INFO` entries, aligned as they are.
#[repr(C, align(8))]
struct DirBuffer([u8; DIR_BUFFER_SIZE]);
const _: () = assert!(align_of::<FILE_ID_BOTH_DIR_INFO>() <= 8);

#[allow(unsafe_code)]
fn fill_dir(
    dir: BorrowedHandle<'_>,
    class: FILE_INFO_BY_HANDLE_CLASS,
    buffer: &mut DirBuffer,
) -> io::Result<()> {
    // SAFETY: `buffer` is DIR_BUFFER_SIZE bytes, aligned to 8 as the
    // entries need, borrowed mutably for the call, which writes at most that
    // many; the handle is open for its borrow, and one that isn't a
    // directory's fails the call.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            dir.as_raw_handle(),
            class,
            (&raw mut buffer.0).cast(),
            DIR_BUFFER_SIZE as u32,
        )
    };
    win32(ok)
}

/// The `u32` at `offset` in `bytes`, if it is all there.
fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let word = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_ne_bytes(word.try_into().ok()?))
}

/// The entries one fill wrote, from the buffer's start along each
/// `NextEntryOffset`, read field by field and bounded by the buffer: no
/// entry is trusted to fit.
fn entries_in(bytes: &[u8], names: &mut Vec<(OsString, Attributes)>) -> io::Result<()> {
    use std::mem::offset_of;
    use std::os::windows::ffi::OsStringExt;
    let malformed = || io::Error::other("a directory listing that doesn't parse");
    let mut start = 0usize;
    loop {
        let entry = bytes.get(start..).ok_or_else(malformed)?;
        let field = |offset| u32_at(entry, offset).ok_or_else(malformed);
        let next = field(offset_of!(FILE_ID_BOTH_DIR_INFO, NextEntryOffset))?;
        let bits = field(offset_of!(FILE_ID_BOTH_DIR_INFO, FileAttributes))?;
        // A reparse point's tag is in EaSize.
        let ea = field(offset_of!(FILE_ID_BOTH_DIR_INFO, EaSize))?;
        let length = field(offset_of!(FILE_ID_BOTH_DIR_INFO, FileNameLength))? as usize;
        let name_at = offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
        let name = entry
            .get(name_at..name_at.checked_add(length).ok_or_else(malformed)?)
            .ok_or_else(malformed)?;
        let units: Vec<u16> = name
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_ne_bytes(*pair))
            .collect();
        let name = OsString::from_wide(&units);
        if name != "." && name != ".." {
            let reparse_tag = if bits & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                ea
            } else {
                0
            };
            names.push((name, Attributes { bits, reparse_tag }));
        }
        if next == 0 {
            return Ok(());
        }
        start = start.checked_add(next as usize).ok_or_else(malformed)?;
    }
}

/// The names in the directory `dir` is open on, but `.` and `..`, each
/// with its attributes as the directory lists them
/// (`GetFileInformationByHandleEx`, `FileIdBothDirectoryInfo`). A reparse
/// point is listed as itself, never followed. They are read through a
/// handle of their own, the directory opened again from `dir` (no name,
/// relative to it), so that two listings of one directory never share a
/// position.
pub fn list_dir(dir: BorrowedHandle<'_>) -> io::Result<Vec<(OsString, Attributes)>> {
    let how = OpenAt {
        access: access::LIST,
        create: Create::No,
        expect: Expect::Directory,
        follow: false,
    };
    let own = nt_create(dir, &mut [], how)?;
    let mut buffer = Box::new(DirBuffer([0; DIR_BUFFER_SIZE]));
    let mut names = Vec::new();
    let mut class = FileIdBothDirectoryRestartInfo;
    loop {
        match fill_dir(own.as_handle(), class, &mut buffer) {
            Ok(()) => entries_in(&buffer.0, &mut names)?,
            Err(e) if e.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) => return Ok(names),
            Err(e) => return Err(e),
        }
        class = FileIdBothDirectoryInfo;
    }
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
    fn resident_memory_is_read() {
        let before = resident_bytes().unwrap();
        assert!(before > 1 << 20 && before < 1 << 40, "{before}");
        let held = vec![1u8; 64 << 20];
        let during = resident_bytes().unwrap();
        assert!(during >= before + (32 << 20), "{before} -> {during}");
        drop(held);
    }

    /// A rename across volumes fails with `STATUS_NOT_SAME_DEVICE`, which
    /// reads as Win32's `ERROR_NOT_SAME_DEVICE` (17) and std's
    /// `CrossesDevices`: the error a profile's move copies on (PRF-9c).
    #[test]
    fn a_rename_across_volumes_reads_as_crossing_devices() {
        use windows_sys::Win32::Foundation::{ERROR_NOT_SAME_DEVICE, STATUS_NOT_SAME_DEVICE};
        let error = nt_error(STATUS_NOT_SAME_DEVICE);
        assert_eq!(error.raw_os_error(), Some(ERROR_NOT_SAME_DEVICE as i32));
        assert_eq!(error.kind(), io::ErrorKind::CrossesDevices);
    }

    #[test]
    fn a_volume_s_space_is_read_from_a_handle() {
        use std::os::windows::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags::BACKUP_SEMANTICS)
            .open(std::env::temp_dir())
            .unwrap();
        let (available, unit) = volume_space(file.as_handle()).unwrap();
        assert!(unit >= 512 && unit.is_power_of_two(), "{unit}");
        assert!(available > 0);
    }

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

    /// Makes the SID `sid` (`S-1-...`) `path`'s owner (`icacls /setowner`),
    /// which takes an administrator's restore privilege, as CI's runner has.
    fn set_owner(path: &std::path::Path, sid: &str) {
        let output = std::process::Command::new("icacls")
            .arg(path)
            .arg("/setowner")
            .arg(format!("*{sid}"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "icacls /setowner {sid} (run as an administrator): {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    /// This process's user's SID, as `whoami /user` prints it.
    fn user_sid() -> String {
        let output = std::process::Command::new("whoami")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .unwrap();
        assert!(output.status.success(), "whoami /user");
        let line = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let sid = line
            .rsplit(',')
            .next()
            .unwrap()
            .trim_matches('"')
            .to_owned();
        assert!(sid.starts_with("S-1-"), "{line}");
        sid
    }

    #[test]
    fn a_file_is_the_user_s_only_if_its_owner_is() {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsHandle;
        let dir = std::env::temp_dir().join(format!("fc-sys-owner-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let owned = |path: &std::path::Path| {
            owned_by_current_user(std::fs::File::open(path).unwrap().as_handle())
        };
        let token = process_token().unwrap();
        // An elevated administrator's token gives its new files to the
        // Administrators group by default; any other, to its user.
        let to_administrators = equal_sid(
            token_sid::<TOKEN_OWNER>(token.as_handle()).unwrap().sid(),
            administrators(),
        );
        // A file this process makes is its user's, whichever owner it got.
        let made = dir.join("made");
        std::fs::write(&made, b"x").unwrap();
        assert!(
            owned(&made).unwrap(),
            "made by a token whose default owner is Administrators: {to_administrators}"
        );
        // The user named as the owner, elevated or not.
        let user = dir.join("user");
        std::fs::write(&user, b"x").unwrap();
        set_owner(&user, &user_sid());
        assert!(owned(&user).unwrap());
        // The Administrators group: read as the SID it is, and the user's
        // only when it is the token's default owner.
        let administrators_owned = dir.join("administrators");
        std::fs::write(&administrators_owned, b"x").unwrap();
        set_owner(&administrators_owned, "S-1-5-32-544");
        let file = std::fs::File::open(&administrators_owned).unwrap();
        let descriptor = file_owner(file.as_handle()).unwrap();
        assert!(equal_sid(descriptor.owner().unwrap(), administrators()));
        assert_eq!(owned(&administrators_owned).unwrap(), to_administrators);
        // BUILTIN\Users, a group the user is in: not the user's.
        let users = dir.join("users");
        std::fs::write(&users, b"x").unwrap();
        set_owner(&users, "S-1-5-32-545");
        assert!(!owned(&users).unwrap());
        // SYSTEM: another account, not the user's.
        let system = dir.join("system");
        std::fs::write(&system, b"x").unwrap();
        set_owner(&system, "S-1-5-18");
        assert!(!owned(&system).unwrap());
        // A handle without READ_CONTROL can't tell: an error, not "owned".
        let attributes_only = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .open(&made)
            .unwrap();
        let denied = owned_by_current_user(attributes_only.as_handle()).unwrap_err();
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
        drop((attributes_only, file, descriptor));
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
        for name in [
            "",
            ".",
            "..",
            "a\\b",
            "a/b",
            "a:b",
            "CON",
            "con",
            "Nul.txt",
            "aux .log",
            "PRN",
            "COM1",
            "lpt9.log",
            "COM\u{b9}",
            "lpt\u{b3}",
            "COM0",
            "CONIN$",
            "conout$.x",
            "name.",
            "name ",
            "NUL ",
        ] {
            let refused = open_dir_at(parent.as_handle(), OsStr::new(name)).unwrap_err();
            assert_eq!(refused.kind(), io::ErrorKind::InvalidInput, "{name:?}");
        }
        // Names that only look like a device are made, and a path ending in
        // one names the directory made.
        for name in ["COM10", "console", "nul-x", "LPT", "a.CON", ".nul"] {
            open_dir_at(parent.as_handle(), OsStr::new(name)).unwrap();
            assert!(moved.join(name).is_dir(), "{name:?}");
        }
        drop(parent);
        std::fs::remove_dir_all(&moved).unwrap();
    }

    #[test]
    fn files_are_opened_renamed_deleted_and_listed_by_handle() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = std::env::temp_dir().join(format!("fc-sys-at-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let parent: OwnedHandle = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags::BACKUP_SEMANTICS)
            .open(&dir)
            .unwrap()
            .into();
        let how = |access, create, expect| OpenAt {
            access,
            create,
            expect,
            follow: false,
        };
        let at = |name: &str, how| open_at(parent.as_handle(), OsStr::new(name), how);
        // Made new, then refused as there.
        let made = at("file", how(access::WRITE, Create::New, Expect::File)).unwrap();
        assert!(!attribute_tag(made.as_handle()).unwrap().directory());
        drop(made);
        let again = at("file", how(access::WRITE, Create::New, Expect::File)).unwrap_err();
        assert_eq!(again.kind(), io::ErrorKind::AlreadyExists);
        // A directory where a file is asked for, the reverse, and nothing.
        std::fs::create_dir(dir.join("sub")).unwrap();
        let directory = at("sub", how(access::READ, Create::No, Expect::File)).unwrap_err();
        assert_eq!(directory.kind(), io::ErrorKind::IsADirectory);
        let file = at("file", how(access::LIST, Create::No, Expect::Directory)).unwrap_err();
        assert_eq!(file.kind(), io::ErrorKind::NotADirectory);
        let missing = at("missing", how(access::ATTRIBUTES, Create::No, Expect::Any)).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        // Listed with attributes: a junction as a reparse point, its tag
        // IO_REPARSE_TAG_MOUNT_POINT.
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(dir.join("junction"))
            .arg(dir.join("sub"))
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J");
        let mut listed = list_dir(parent.as_handle()).unwrap();
        listed.sort_by(|one, two| one.0.cmp(&two.0));
        let names: Vec<_> = listed.iter().map(|(name, _)| name.clone()).collect();
        assert_eq!(names, ["file", "junction", "sub"]);
        let [(_, file), (_, junction), (_, sub)] = listed.as_slice() else {
            panic!("{listed:?}");
        };
        assert!(!file.directory() && !file.reparse_point());
        assert!(junction.directory() && junction.reparse_point());
        assert_eq!(junction.reparse_tag, 0xA000_0003);
        assert!(sub.directory() && !sub.reparse_point());
        let opened = at("junction", how(access::ATTRIBUTES, Create::No, Expect::Any)).unwrap();
        let tag = attribute_tag(opened.as_handle()).unwrap();
        assert!(tag.directory() && tag.reparse_point());
        assert_eq!(tag.reparse_tag, junction.reparse_tag);
        drop(opened);
        // Renamed into `sub` by both handles, then deleted by its handle
        // where it now is.
        let sub = at("sub", how(access::LIST, Create::No, Expect::Directory)).unwrap();
        let file = at("file", how(access::DELETE, Create::No, Expect::Any)).unwrap();
        rename_at(file.as_handle(), sub.as_handle(), OsStr::new("moved")).unwrap();
        assert!(dir.join("sub/moved").is_file());
        assert!(!dir.join("file").exists());
        // The name goes once this handle closes, other handles or not.
        delete(file.as_handle()).unwrap();
        drop(file);
        assert!(!dir.join("sub/moved").exists());
        // A non-empty directory isn't deleted.
        std::fs::write(dir.join("sub/inner"), b"x").unwrap();
        let full = at("sub", how(access::DELETE, Create::No, Expect::Directory)).unwrap();
        let error = delete(full.as_handle()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::DirectoryNotEmpty);
        // Names that aren't one plain component of at most 255 units.
        let other = at("other", how(access::DELETE, Create::New, Expect::File)).unwrap();
        for name in [
            "a\\b".to_owned(),
            "..".to_owned(),
            "NUL".to_owned(),
            "x".repeat(256),
        ] {
            let refused = rename_at(other.as_handle(), sub.as_handle(), OsStr::new(&name));
            assert_eq!(
                refused.unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{name:?}"
            );
        }
        rename_at(
            other.as_handle(),
            sub.as_handle(),
            OsStr::new(&"x".repeat(255)),
        )
        .unwrap();
        delete(other.as_handle()).unwrap();
        drop((other, full, sub, parent));
        std::fs::remove_dir_all(&dir).unwrap();
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
