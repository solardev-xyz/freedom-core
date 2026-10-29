//! macOS calls `fc-service`'s confinement needs (design 0010, "macOS"):
//! the process's own executable and thread count (libproc), and Seatbelt.
//!
//! **Seatbelt's calls are private and undocumented:** no public header
//! declares `sandbox_init_with_parameters` or `sandbox_check`, so they are
//! declared here, as Chromium and WebKit declare them. libSystem exports
//! them (`libsystem_sandbox`), and Apple can change them in any release.
//!
//! None of these calls closes a descriptor.

use std::ffi::{CStr, OsString, c_char, c_int};
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

// libsystem_sandbox, part of libSystem.
#[allow(unsafe_code)]
unsafe extern "C" {
    /// Compiles `profile` (SBPL text) with `parameters` (key, value, …,
    /// NULL) and applies it to the calling process. 0, or -1 with
    /// `*errorbuf` set to an allocated message.
    fn sandbox_init_with_parameters(
        profile: *const c_char,
        flags: u64,
        parameters: *const *const c_char,
        errorbuf: *mut *mut c_char,
    ) -> c_int;
    /// Frees a message `sandbox_init_with_parameters` allocated.
    fn sandbox_free_error(errorbuf: *mut c_char);
    /// Whether `pid`'s sandbox allows `operation` on the filter's value (0)
    /// or not (1); with a NULL operation, whether `pid` is sandboxed at all
    /// (1) or not (0). Variadic: one argument follows for a filter type
    /// that takes a value.
    fn sandbox_check(pid: libc::pid_t, operation: *const c_char, filter_type: c_int, ...) -> c_int;
    /// The flag a check ORs into its filter type so a denial isn't logged
    /// as a violation: an exported constant, not a macro.
    static SANDBOX_CHECK_NO_REPORT: c_int;
}

/// `sandbox_filter_type`'s values: no value, a path, a global (Mach) name.
const FILTER_NONE: c_int = 0;

/// What a [`check`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter<'a> {
    /// No value: the operation alone, such as `process-fork`.
    None,
    /// A file system path.
    Path(&'a CStr),
    /// A Mach service's global name.
    GlobalName(&'a CStr),
}

/// This process's id, as libproc and Seatbelt take it.
fn own_pid() -> libc::pid_t {
    libc::pid_t::try_from(std::process::id()).unwrap_or(libc::pid_t::MAX)
}

/// The absolute path of the file this process's image was executed from
/// (`proc_pidpath`): the entry's re-exec runs it (design 0010, step 1).
/// It names a path, not the running image: a file replaced there since is
/// what an exec of it runs.
#[allow(unsafe_code)]
pub fn executable_path() -> io::Result<PathBuf> {
    let size = libc::PROC_PIDPATHINFO_MAXSIZE;
    let mut buf = vec![0u8; usize::try_from(size).unwrap_or(4096)];
    let capacity = u32::try_from(buf.len()).unwrap_or(0);
    // SAFETY: proc_pidpath writes at most `capacity` bytes into `buf`,
    // which holds exactly that many and is ours for the call, and returns
    // how many it wrote, or 0 or less with errno.
    let written = unsafe { libc::proc_pidpath(own_pid(), buf.as_mut_ptr().cast(), capacity) };
    let Ok(written) = usize::try_from(written) else {
        return Err(io::Error::last_os_error());
    };
    if written == 0 || written > buf.len() {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(written);
    Ok(PathBuf::from(OsString::from_vec(buf)))
}

/// How many threads this process has (`proc_pidinfo`'s
/// `PROC_PIDTASKINFO`, `pti_threadnum`): `confine` refuses more than one
/// (design 0010, step 1).
#[allow(unsafe_code)]
pub fn thread_count() -> io::Result<usize> {
    let size = std::mem::size_of::<libc::proc_taskinfo>();
    let mut buf = vec![0u8; size];
    let capacity = c_int::try_from(size).unwrap_or(0);
    // SAFETY: with PROC_PIDTASKINFO and an argument of 0, proc_pidinfo
    // reads nothing of ours and writes at most `capacity` bytes into
    // `buf`, which holds exactly that many; it returns how many it wrote.
    let written = unsafe {
        libc::proc_pidinfo(
            own_pid(),
            libc::PROC_PIDTASKINFO,
            0,
            buf.as_mut_ptr().cast(),
            capacity,
        )
    };
    if written != capacity {
        return Err(io::Error::last_os_error());
    }
    // The field, read out of the bytes the call wrote: no unaligned or
    // uninitialized read.
    let offset = std::mem::offset_of!(libc::proc_taskinfo, pti_threadnum);
    let field: [u8; 4] = buf
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| io::Error::other("proc_taskinfo too short"))?;
    usize::try_from(i32::from_ne_bytes(field))
        .map_err(|_| io::Error::other("negative thread count"))
}

/// Applies the Seatbelt `profile` (SBPL text) to this process, with
/// `parameters` for its `(param "…")` (`sandbox_init_with_parameters`):
/// once applied, it can't be lifted. `Err` with the sandbox's message.
#[allow(unsafe_code)]
pub fn apply_profile(profile: &CStr, parameters: &[(&CStr, &CStr)]) -> Result<(), String> {
    let mut argv: Vec<*const c_char> = Vec::with_capacity(parameters.len() * 2 + 1);
    for (key, value) in parameters {
        argv.push(key.as_ptr());
        argv.push(value.as_ptr());
    }
    argv.push(std::ptr::null());
    let mut error: *mut c_char = std::ptr::null_mut();
    // SAFETY: `profile` and every pointer in `argv` refer to NUL-terminated
    // strings borrowed for the whole call, `argv` ends in NULL, and `error`
    // is a valid place for the call to store a message it allocates.
    let result =
        unsafe { sandbox_init_with_parameters(profile.as_ptr(), 0, argv.as_ptr(), &raw mut error) };
    if result == 0 {
        return Ok(());
    }
    if error.is_null() {
        return Err(format!("sandbox_init_with_parameters returned {result}"));
    }
    // SAFETY: on failure the call set `error` to a NUL-terminated message it
    // allocated, valid until it is freed below; it is copied out first.
    let message = unsafe { CStr::from_ptr(error) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: `error` came from sandbox_init_with_parameters, and is freed
    // once, after its last use above.
    unsafe { sandbox_free_error(error) };
    Err(message)
}

/// Whether this process is sandboxed already (`sandbox_check` with no
/// operation): an outer sandbox, which `confine` reports as `blocked`.
#[allow(unsafe_code)]
pub fn sandboxed() -> bool {
    // SAFETY: with a NULL operation and the filter type that takes no
    // value, sandbox_check reads no memory of ours and takes no variadic
    // argument: it only answers whether the process is sandboxed.
    let result = unsafe { sandbox_check(own_pid(), std::ptr::null(), FILTER_NONE) };
    result == 1
}

/// Whether the sandbox refuses this process an exec in place: an `execv`
/// of `program`, which must be a program that exits at once (`/usr/bin/true`).
/// `Ok(false)` when refused (`EPERM` or `EACCES`), `Err` with any other
/// errno. Allowed, it doesn't return: the process becomes `program`, which
/// exits, so a service that should have been confined ends instead (fails
/// closed). `sandbox_check` doesn't answer for `process-exec`, so this asks
/// the kernel itself; std's `CommandExt::exec` would reset the signal
/// handling first, whether or not the exec happens.
#[allow(unsafe_code)]
pub fn exec_allowed(program: &CStr) -> Result<bool, i32> {
    let argv = [program.as_ptr(), std::ptr::null()];
    // SAFETY: `program` and the NULL-terminated `argv` are borrowed for the
    // call. On success the image is replaced, and nothing of this process's
    // memory is used after; on failure it returns -1 with errno, changing
    // nothing.
    let _ = unsafe { libc::execv(program.as_ptr(), argv.as_ptr()) };
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => Ok(false),
        Some(code) => Err(code),
        None => Err(0),
    }
}

/// The flag that keeps a check's denial out of the violation log.
#[allow(unsafe_code)]
fn no_report() -> c_int {
    // SAFETY: SANDBOX_CHECK_NO_REPORT is a constant libsystem_sandbox
    // exports and never writes: reading it is a plain load.
    unsafe { SANDBOX_CHECK_NO_REPORT }
}

/// Whether this process's sandbox allows `operation` (an SBPL operation,
/// such as `file-read-data`) on what `filter` names (`sandbox_check`),
/// without logging a denial: `Ok(true)` or `Ok(false)`, or `Err` with what
/// the call returned when it answered neither. `confine` derives each
/// status from these, once the profile is applied.
#[allow(unsafe_code)]
pub fn check(operation: &CStr, filter: Filter<'_>) -> Result<bool, i32> {
    let result = match filter {
        Filter::None => {
            // SAFETY: `operation` is a NUL-terminated string borrowed for
            // the call, and the filter type that takes no value takes no
            // variadic argument.
            unsafe { sandbox_check(own_pid(), operation.as_ptr(), FILTER_NONE | no_report()) }
        }
        Filter::Path(value) | Filter::GlobalName(value) => {
            let filter_type = if matches!(filter, Filter::Path(_)) {
                1
            } else {
                2
            };
            // SAFETY: `operation` and `value` are NUL-terminated strings
            // borrowed for the call, and a filter type that takes a value
            // takes exactly one pointer to such a string as its variadic
            // argument.
            unsafe {
                sandbox_check(
                    own_pid(),
                    operation.as_ptr(),
                    filter_type | no_report(),
                    value.as_ptr(),
                )
            }
        }
    };
    match result {
        0 => Ok(true),
        1 => Ok(false),
        other => Err(other),
    }
}

/// Test-only Mach calls (design 0010, Tests): a lookup of a Mach service,
/// and how many port names the task holds.
#[cfg(feature = "test-macos")]
pub mod mach {
    use std::ffi::{CStr, c_char, c_int};

    /// Mach's port name, message count and address types, as
    /// `<mach/port.h>` and `<mach/vm_types.h>` declare them (libc's are
    /// deprecated in favour of a crate this one doesn't take).
    type Port = u32;
    type Count = u32;

    #[allow(unsafe_code)]
    unsafe extern "C" {
        static mach_task_self_: Port;
        static bootstrap_port: Port;
        fn bootstrap_look_up(bp: Port, service_name: *const c_char, sp: *mut Port) -> c_int;
        fn mach_host_self() -> Port;
        fn mach_thread_self() -> Port;
        fn mach_port_deallocate(task: Port, name: Port) -> c_int;
        fn mach_port_names(
            task: Port,
            names: *mut *mut Port,
            names_count: *mut Count,
            types: *mut *mut u32,
            types_count: *mut Count,
        ) -> c_int;
        fn vm_deallocate(task: Port, address: usize, size: usize) -> c_int;
    }

    #[allow(unsafe_code)]
    fn task() -> Port {
        // SAFETY: mach_task_self_ is the task's own port name, which the
        // runtime sets before main and never changes: a plain load.
        unsafe { mach_task_self_ }
    }

    /// Whether the bootstrap server gives this process a send right to
    /// `name`; a right it gives is released at once.
    pub fn look_up(name: &CStr) -> bool {
        look_up_name(name).is_some()
    }

    /// The name this task gives the send right the bootstrap server hands
    /// out for `name`, or None; the right is released at once. A task holds
    /// one name per port, so a name it already held is the same service.
    #[allow(unsafe_code)]
    pub fn look_up_name(name: &CStr) -> Option<u32> {
        // SAFETY: bootstrap_port is set before main and never written after.
        let bootstrap = unsafe { bootstrap_port };
        let mut port: Port = 0;
        // SAFETY: `name` is a NUL-terminated string borrowed for the call,
        // and `port` a valid place for the right's name.
        let result = unsafe { bootstrap_look_up(bootstrap, name.as_ptr(), &raw mut port) };
        if result != 0 {
            return None;
        }
        release(port);
        Some(port)
    }

    /// Releases one reference to the send right `port`.
    #[allow(unsafe_code)]
    fn release(port: Port) {
        // SAFETY: `port` names a send right this task was just given a
        // reference to, and that reference is released once.
        let _ = unsafe { mach_port_deallocate(task(), port) };
    }

    /// The task's own special ports, by name: its task, bootstrap, host and
    /// main-thread ports.
    #[allow(unsafe_code)]
    pub fn special_ports() -> Vec<(&'static str, u32)> {
        // SAFETY: bootstrap_port is set before main and never written after.
        let bootstrap = unsafe { bootstrap_port };
        // SAFETY: mach_host_self takes nothing and returns a send right to
        // the host port, one reference of which is released below.
        let host = unsafe { mach_host_self() };
        release(host);
        // SAFETY: as for mach_host_self, for the calling thread's port.
        let thread = unsafe { mach_thread_self() };
        release(thread);
        vec![
            ("task", task()),
            ("bootstrap", bootstrap),
            ("host", host),
            ("thread", thread),
        ]
    }

    /// The port names the task holds, each with its type bits
    /// (`mach_port_names`), or None.
    #[allow(unsafe_code)]
    pub fn port_names() -> Option<Vec<(u32, u32)>> {
        let mut names: *mut Port = std::ptr::null_mut();
        let mut names_count: Count = 0;
        let mut types: *mut u32 = std::ptr::null_mut();
        let mut types_count: Count = 0;
        // SAFETY: each out-pointer is a valid place the call fills with an
        // array it allocates in this task, and its length.
        let result = unsafe {
            mach_port_names(
                task(),
                &raw mut names,
                &raw mut names_count,
                &raw mut types,
                &raw mut types_count,
            )
        };
        if result != 0 {
            return None;
        }
        let count = usize::try_from(names_count.min(types_count)).unwrap_or(0);
        let ports: Vec<(u32, u32)> = if count == 0 || names.is_null() || types.is_null() {
            Vec::new()
        } else {
            // SAFETY: the call allocated `names` with `names_count`
            // initialized entries, at least `count`, which stay valid until
            // freed below.
            let names = unsafe { std::slice::from_raw_parts(names, count) };
            // SAFETY: as for `names`: `types_count` entries, at least `count`.
            let types = unsafe { std::slice::from_raw_parts(types, count) };
            names.iter().copied().zip(types.iter().copied()).collect()
        };
        for (array, count) in [
            (names.cast::<u8>(), names_count),
            (types.cast::<u8>(), types_count),
        ] {
            let bytes = usize::try_from(count).unwrap_or(0) * std::mem::size_of::<u32>();
            // SAFETY: the call allocated `array`, `count` four-byte entries
            // long, in this task's address space; it is freed once, unused
            // after.
            let _ = unsafe { vm_deallocate(task(), array as usize, bytes) };
        }
        Some(ports)
    }
}

/// Test-only probes of what the sandbox lets a process read about the
/// system and other processes (design 0010, Tests): `sysctl` by number and
/// by name, and the interface list.
#[cfg(feature = "test-macos")]
pub mod probe {
    use std::ffi::{CStr, c_int, c_uint};

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    /// The bytes `sysctl` returns for `mib`, read into a buffer of `len`,
    /// or the errno.
    #[allow(unsafe_code)]
    fn sysctl(mib: &[c_int], len: usize) -> Result<Vec<u8>, i32> {
        let mut mib = mib.to_vec();
        let count = c_uint::try_from(mib.len()).map_err(|_| 0)?;
        let mut buf = vec![0u8; len];
        let mut size = buf.len();
        // SAFETY: `mib` holds `count` integers, `buf` is ours for `size`
        // bytes, which the call writes at most and then updates `size` to,
        // and no new value is set (NULL, 0).
        let result = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                count,
                buf.as_mut_ptr().cast(),
                &raw mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if result != 0 {
            return Err(errno());
        }
        buf.truncate(size.min(len));
        Ok(buf)
    }

    /// Another process's arguments and environment
    /// (`{CTL_KERN, KERN_PROCARGS2, pid}`), or the errno.
    pub fn procargs(pid: i32) -> Result<Vec<u8>, i32> {
        sysctl(&[libc::CTL_KERN, libc::KERN_PROCARGS2, pid], 1 << 20)
    }

    /// Every process's `kinfo_proc` (`{CTL_KERN, KERN_PROC, KERN_PROC_ALL}`):
    /// how many bytes, or the errno.
    pub fn all_processes() -> Result<usize, i32> {
        sysctl(
            &[libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_ALL],
            8 << 20,
        )
        .map(|b| b.len())
    }

    /// The CPU count by number (`{CTL_HW, HW_NCPU}`), or the errno.
    pub fn ncpu() -> Result<u32, i32> {
        let bytes = sysctl(&[libc::CTL_HW, libc::HW_NCPU], 4)?;
        let bytes: [u8; 4] = bytes.as_slice().try_into().map_err(|_| 0)?;
        Ok(u32::from_ne_bytes(bytes))
    }

    /// How many bytes `sysctlbyname(name)` has, or the errno.
    #[allow(unsafe_code)]
    pub fn sysctl_name(name: &CStr) -> Result<usize, i32> {
        let mut size = 0usize;
        // SAFETY: `name` is a NUL-terminated string borrowed for the call;
        // with a NULL buffer the call only writes the size into `size`.
        let result = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                std::ptr::null_mut(),
                &raw mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if result == 0 { Ok(size) } else { Err(errno()) }
    }

    /// How many interface addresses `getifaddrs` lists, or the errno: NAT64
    /// discovery's interface indexes come from the same list.
    #[allow(unsafe_code)]
    pub fn interface_addresses() -> Result<usize, i32> {
        let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: `list` is a valid place for the call to store the head of
        // a list it allocates.
        let result = unsafe { libc::getifaddrs(&raw mut list) };
        if result != 0 {
            return Err(errno());
        }
        let mut count = 0;
        let mut entry = list;
        while !entry.is_null() {
            count += 1;
            // SAFETY: `entry` is a node of the list getifaddrs returned,
            // valid until it is freed below.
            entry = unsafe { (*entry).ifa_next };
        }
        // SAFETY: `list` came from getifaddrs and is freed once.
        unsafe { libc::freeifaddrs(list) };
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_executable_is_this_test_binary() {
        let path = executable_path().unwrap();
        assert!(path.is_absolute());
        assert_eq!(
            std::fs::canonicalize(&path).unwrap(),
            std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
        );
    }

    #[test]
    fn threads_are_counted() {
        assert!(thread_count().unwrap() >= 1);
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let _ = rx.recv();
        });
        // This test's thread and the one it holds, at least: other tests'
        // threads come and go meanwhile, so no exact count holds.
        assert!(thread_count().unwrap() >= 2);
        drop(tx);
        handle.join().unwrap();
    }

    #[test]
    fn an_unconfined_test_is_not_sandboxed() {
        assert!(!sandboxed());
        // Unconfined, a check allows everything.
        assert_eq!(
            check(c"file-read-data", Filter::Path(c"/usr/lib")),
            Ok(true)
        );
    }
}
