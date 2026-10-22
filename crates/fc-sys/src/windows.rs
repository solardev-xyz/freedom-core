//! Windows calls.

use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
use windows_sys::Win32::System::Diagnostics::Debug::{
    SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX, SetErrorMode,
};
use windows_sys::Win32::System::ErrorReporting::{
    WER_FAULT_REPORTING_FLAG_NOHEAP, WER_FAULT_REPORTING_NO_UI, WerSetFlags,
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
}
