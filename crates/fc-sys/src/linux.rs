//! Linux calls: the raw syscall `fc-service`'s confinement needs (design
//! 0010) that neither std nor rustix offers, and the test-only calls
//! through the other syscall ABIs.

use std::io;

/// `LANDLOCK_CREATE_RULESET_VERSION`: `landlock_create_ruleset`'s flag that
/// asks for the ABI version instead of creating a ruleset.
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;

/// The running kernel's Landlock ABI version
/// (`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`).
///
/// `Err` carries the errno: `ENOSYS` when the kernel has no Landlock,
/// `EOPNOTSUPP` when it is disabled at boot, and anything else (`EPERM`
/// from a container's seccomp filter, say) when something outside refuses
/// the call.
#[allow(unsafe_code)]
pub fn landlock_abi() -> Result<u32, i32> {
    // SAFETY: with a NULL attribute pointer, a size of 0 and the version
    // flag, the call reads no memory and creates no descriptor: it only
    // returns the ABI version, or -1 with errno.
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0 as libc::size_t,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    match u32::try_from(result) {
        Ok(version) => Ok(version),
        Err(_) => Err(io::Error::last_os_error().raw_os_error().unwrap_or(0)),
    }
}

/// `getpid` through the x32 ABI: its number with `__X32_SYSCALL_BIT` set,
/// through the native `syscall` instruction. A test of seccomp's ABI guard.
#[cfg(all(feature = "test-abis", target_arch = "x86_64"))]
#[allow(unsafe_code)]
pub fn getpid_x32() -> i64 {
    /// `__X32_SYSCALL_BIT`.
    const X32_SYSCALL_BIT: libc::c_long = 0x4000_0000;
    // SAFETY: getpid takes no arguments and touches no memory; through the
    // x32 ABI it is the same call, or ENOSYS where x32 is off.
    unsafe { libc::syscall(libc::SYS_getpid | X32_SYSCALL_BIT) }
}

/// `getpid` through the i386 ABI (`int 0x80`, eax = 20). A test of
/// seccomp's ABI guard. A kernel without IA32 emulation answers with a
/// fault rather than a return.
#[cfg(all(feature = "test-abis", target_arch = "x86_64"))]
#[allow(unsafe_code)]
pub fn getpid_i386() -> i64 {
    /// i386's `__NR_getpid`.
    const NR_GETPID_I386: i64 = 20;
    let mut result: i64 = NR_GETPID_I386;
    // SAFETY: i386's getpid takes no arguments and touches no memory or
    // register beyond eax, which carries the number in and the result out.
    unsafe {
        std::arch::asm!("int 0x80", inlateout("rax") result, options(nostack));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn landlock_answers_a_version_or_why_not() {
        match landlock_abi() {
            Ok(version) => assert!(version >= 1),
            Err(errno) => assert!(errno > 0),
        }
    }
}
