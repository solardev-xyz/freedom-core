//! The seccomp denylist (design 0010, "Linux"): syscalls a service never
//! makes, answered with an error rather than a kill, behind an ABI guard.
//!
//! Four programs, each installed as its own filter. seccomp runs every
//! filter installed, and the strictest answer wins; their sets don't
//! overlap:
//! 1. **`EPERM`:** process creation and exec, other processes, the file
//!    changes Landlock doesn't check, local sockets, and kernel surface the
//!    services never use.
//! 2. **`ENOSYS`** for `clone3`, whose flags a filter can't read, so the C
//!    library falls back to `clone`, which (1) checks.
//! 3. **`ENOTTY`** for every `ioctl` command but the allowlist, compared on
//!    the command's low 32 bits, as the kernel reads it.
//! 4. **On x86-64, the x32 guard:** any number with `__X32_SYSCALL_BIT`
//!    kills the process. x32 shares the native audit architecture, so the
//!    other filters' architecture check doesn't catch it.
//!
//! Every program built by `seccompiler` starts with its architecture check,
//! which kills a call through another ABI (i386 on x86-64, AArch32 on
//! AArch64).

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch, sock_filter,
};

use super::Network;

/// Syscalls newer than the `libc` crate's tables, with their numbers, the
/// same on x86-64 and AArch64 (Linux's unified table from 424 up).
const SYS_FCHMODAT2: i64 = 452;
const SYS_SETXATTRAT: i64 = 463;
const SYS_REMOVEXATTRAT: i64 = 466;
const SYS_FILE_SETATTR: i64 = 469;

/// `__X32_SYSCALL_BIT`.
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// The `ioctl` commands the services make (0010's allowlist): non-blocking
/// and close-on-exec flags, bytes readable, and `isatty`'s terminal queries.
// The request's type is the C library's: `c_ulong` with glibc, `c_int` with
// musl.
#[allow(clippy::unnecessary_cast)]
pub const IOCTL_ALLOWED: [u64; 6] = [
    libc::FIONBIO as u64,
    libc::FIOCLEX as u64,
    libc::FIONCLEX as u64,
    libc::FIONREAD as u64,
    libc::TCGETS as u64,
    libc::TIOCGWINSZ as u64,
];

/// `SIOCGIFINDEX`: an interface's index, by its name. Allowed only for a
/// policy that asks ([`super::Policy::interface_index`]): it reads one
/// index and changes nothing.
#[allow(clippy::unnecessary_cast)]
pub const SIOCGIFINDEX: u64 = libc::SIOCGIFINDEX as u64;

/// This build's architecture, or `None` where the services have no filter.
pub fn target() -> Option<TargetArch> {
    if cfg!(target_arch = "x86_64") {
        Some(TargetArch::x86_64)
    } else if cfg!(target_arch = "aarch64") {
        Some(TargetArch::aarch64)
    } else {
        None
    }
}

/// The syscalls refused unconditionally with `EPERM`.
fn denied() -> Vec<i64> {
    let mut calls = vec![
        // Exec, and other processes.
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
        // File changes Landlock doesn't check, by path or descriptor.
        libc::SYS_truncate,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        SYS_FCHMODAT2,
        libc::SYS_fchown,
        libc::SYS_fchownat,
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_fsetxattr,
        SYS_SETXATTRAT,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
        libc::SYS_fremovexattr,
        SYS_REMOVEXATTRAT,
        libc::SYS_utimensat,
        SYS_FILE_SETATTR,
        // Kernel surface the services never use.
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_personality,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_reboot,
    ];
    // x86-64 keeps the legacy calls AArch64's table never had.
    #[cfg(target_arch = "x86_64")]
    calls.extend([
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_chmod,
        libc::SYS_chown,
        libc::SYS_lchown,
        libc::SYS_utime,
        libc::SYS_utimes,
        libc::SYS_futimesat,
    ]);
    calls
}

fn condition(
    arg: u8,
    len: SeccompCmpArgLen,
    op: SeccompCmpOp,
    value: u64,
) -> Result<SeccompCondition, String> {
    SeccompCondition::new(arg, len, op, value).map_err(|e| e.to_string())
}

fn rule(conditions: Vec<SeccompCondition>) -> Result<SeccompRule, String> {
    SeccompRule::new(conditions).map_err(|e| e.to_string())
}

/// Program 1: `EPERM`.
fn eperm(network: Network, arch: TargetArch) -> Result<BpfProgram, String> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> =
        denied().into_iter().map(|nr| (nr, Vec::new())).collect();
    // `clone` without `CLONE_THREAD`: a new process. Its flags are the
    // first argument on both architectures.
    rules.insert(
        libc::SYS_clone,
        vec![rule(vec![condition(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(libc::CLONE_THREAD as u64),
            0,
        )?])?],
    );
    // `socket` for any family but IPv4 and IPv6; offline, for every family.
    let inet = [libc::AF_INET as u64, libc::AF_INET6 as u64];
    let socket = match network {
        Network::Offline => Vec::new(),
        Network::Direct | Network::Socks5 { .. } => vec![rule(
            inet.iter()
                .map(|family| condition(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, *family))
                .collect::<Result<_, _>>()?,
        )?],
    };
    rules.insert(libc::SYS_socket, socket);
    // `socketpair` for anything but a stream pair (tokio's signal driver):
    // the type's low four bits, its flags aside.
    let mut pair = Vec::new();
    for kind in 0..16u64 {
        if kind != libc::SOCK_STREAM as u64 {
            pair.push(rule(vec![condition(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(0xf),
                kind,
            )?])?);
        }
    }
    rules.insert(libc::SYS_socketpair, pair);
    compile(rules, SeccompAction::Errno(libc::EPERM as u32), arch)
}

/// Program 2: `ENOSYS` for `clone3`.
fn enosys(arch: TargetArch) -> Result<BpfProgram, String> {
    let rules = [(libc::SYS_clone3, Vec::new())].into_iter().collect();
    compile(rules, SeccompAction::Errno(libc::ENOSYS as u32), arch)
}

/// Program 3: `ENOTTY` for an `ioctl` command outside the allowlist, which
/// takes `SIOCGIFINDEX` too when `interface_index` is set.
fn enotty(arch: TargetArch, interface_index: bool) -> Result<BpfProgram, String> {
    let outside = rule(
        IOCTL_ALLOWED
            .iter()
            .chain(interface_index.then_some(&SIOCGIFINDEX))
            .map(|cmd| condition(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, *cmd))
            .collect::<Result<_, _>>()?,
    )?;
    let rules = [(libc::SYS_ioctl, vec![outside])].into_iter().collect();
    compile(rules, SeccompAction::Errno(libc::ENOTTY as u32), arch)
}

fn compile(
    rules: BTreeMap<i64, Vec<SeccompRule>>,
    on_match: SeccompAction,
    arch: TargetArch,
) -> Result<BpfProgram, String> {
    let filter = SeccompFilter::new(rules, SeccompAction::Allow, on_match, arch)
        .map_err(|e| e.to_string())?;
    BpfProgram::try_from(filter).map_err(|e| e.to_string())
}

/// Program 4, on x86-64: the x32 guard, a few hand-built instructions.
fn x32_guard() -> BpfProgram {
    const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const BPF_JSET_K: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K
    // `seccomp_data.nr` is at offset 0.
    vec![
        sock_filter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        },
        sock_filter {
            code: BPF_JSET_K,
            jt: 0,
            jf: 1,
            k: X32_SYSCALL_BIT,
        },
        sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_KILL_PROCESS,
        },
        sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ]
}

/// The programs for `network`, in the order they are installed, with
/// `SIOCGIFINDEX` allowed when `interface_index` is set.
pub fn programs(
    network: Network,
    arch: TargetArch,
    interface_index: bool,
) -> Result<Vec<BpfProgram>, String> {
    let mut programs = vec![
        eperm(network, arch)?,
        enosys(arch)?,
        enotty(arch, interface_index)?,
    ];
    if matches!(arch, TargetArch::x86_64) {
        programs.push(x32_guard());
    }
    Ok(programs)
}

/// How installing the filters ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Installed {
    All,
    /// None installed, for this reason: the kernel can't (`unavailable`), or
    /// something outside refused (`blocked`).
    Unavailable(String),
    Blocked(String),
}

/// Installs `programs`, each with `TSYNC`.
///
/// - **A failure at the first** is asked again, with a filter that allows
///   everything ([`probe`]). If the kernel takes that one, it takes filters,
///   so the service's own first program was refused: `Err`, an invalid
///   policy. If it refuses the probe too, the probe's errno says why:
///   [`classify`].
/// - **A failure at a later one** is an installation stopped halfway:
///   `Err`.
///
/// `forced_errno`, a test seam, fails the first program and the probe.
pub(super) fn install(
    programs: &[BpfProgram],
    forced_errno: Option<i32>,
) -> Result<Installed, String> {
    let apply = |program: &BpfProgram| match forced_errno {
        Some(errno) => Err(std::io::Error::from_raw_os_error(errno)),
        None => seccompiler::apply_filter_all_threads(program).map_err(|e| match e {
            seccompiler::Error::Seccomp(e) | seccompiler::Error::Prctl(e) => e,
            other => std::io::Error::other(other.to_string()),
        }),
    };
    for (i, program) in programs.iter().enumerate() {
        if let Err(e) = apply(program) {
            if i > 0 {
                return Err(format!(
                    "seccomp filter {} of {} failed: {e}",
                    i + 1,
                    programs.len()
                ));
            }
            return match apply(&probe()) {
                Ok(()) => Err(format!("the kernel refused the first seccomp filter: {e}")),
                Err(probe) => Ok(classify(&probe)),
            };
        }
    }
    Ok(Installed::All)
}

/// `BPF_RET | BPF_K`.
const BPF_RET_K: u16 = 0x06;

/// A filter that allows every call: whether the kernel takes a filter at
/// all.
fn probe() -> BpfProgram {
    vec![sock_filter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    }]
}

/// A program the kernel's checker rejects: an opcode classic BPF doesn't
/// have. A test seam ([`super::Options::seccomp_invalid`]).
pub(super) fn invalid_program() -> BpfProgram {
    vec![sock_filter {
        code: 0xffff,
        jt: 0,
        jf: 0,
        k: 0,
    }]
}

/// Why the kernel refused even the probe: `EINVAL` (no seccomp filters,
/// or no `TSYNC`) and `ENOSYS` (no `seccomp` call) are the kernel's lack;
/// anything else (`EPERM` or `EACCES` from an outer filter or policy,
/// `ENOMEM` from an outer sandbox's filters) is something outside refusing.
fn classify(error: &std::io::Error) -> Installed {
    match error.raw_os_error() {
        Some(libc::EINVAL | libc::ENOSYS) => {
            Installed::Unavailable(format!("the kernel takes no seccomp filter: {error}"))
        }
        _ => Installed::Blocked(format!("installing a seccomp filter failed: {error}")),
    }
}

#[cfg(test)]
mod tests {
    //! The generated programs, evaluated by a small classic-BPF interpreter
    //! on synthetic `seccomp_data` records, whatever CI's kernel enables.

    use super::*;

    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const AUDIT_ARCH_I386: u32 = 0x4000_0003;
    const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
    const AUDIT_ARCH_ARM: u32 = 0x4000_0028;

    /// A `seccomp_data`: nr, arch, instruction pointer, six arguments.
    struct Data {
        nr: u32,
        arch: u32,
        args: [u64; 6],
    }

    impl Data {
        fn word(&self, offset: u32) -> u32 {
            match offset {
                0 => self.nr,
                4 => self.arch,
                8 | 12 => 0,
                o if (16..64).contains(&o) => {
                    let arg = self.args[((o - 16) / 8) as usize];
                    if (o - 16) % 8 == 0 {
                        arg as u32
                    } else {
                        (arg >> 32) as u32
                    }
                }
                _ => panic!("load past seccomp_data at {offset}"),
            }
        }
    }

    /// Runs a classic BPF program: the subset seccompiler and the guard emit.
    fn run(program: &[sock_filter], data: &Data) -> u32 {
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        loop {
            let ins = &program[pc];
            pc += 1;
            let class = ins.code & 0x07;
            match class {
                0x00 => {
                    // ld: only W|ABS.
                    assert_eq!(ins.code, 0x20, "ld mode");
                    a = data.word(ins.k);
                }
                0x01 => x = data.word(ins.k), // ldx
                0x04 => {
                    // alu, K source.
                    let op = ins.code & 0xf0;
                    a = match op {
                        0x50 => a & ins.k,
                        0x40 => a | ins.k,
                        0x00 => a.wrapping_add(ins.k),
                        0x10 => a.wrapping_sub(ins.k),
                        0x70 => a >> ins.k,
                        0x60 => a << ins.k,
                        _ => panic!("alu op {op:#x}"),
                    };
                }
                0x05 => {
                    let op = ins.code & 0xf0;
                    let k = if ins.code & 0x08 != 0 { x } else { ins.k };
                    let taken = match op {
                        0x00 => {
                            pc += ins.k as usize;
                            continue;
                        }
                        0x10 => a == k,
                        0x20 => a > k,
                        0x30 => a >= k,
                        0x40 => a & k != 0,
                        _ => panic!("jmp op {op:#x}"),
                    };
                    pc += if taken { ins.jt } else { ins.jf } as usize;
                }
                0x06 => return ins.k, // ret K
                0x07 => {
                    if ins.code & 0xf8 == 0x00 {
                        x = a; // tax
                    } else {
                        a = x; // txa
                    }
                }
                _ => panic!("class {class:#x}"),
            }
        }
    }

    /// The strictest answer of all programs, as the kernel combines them.
    fn verdict(programs: &[BpfProgram], data: &Data) -> u32 {
        // The action is the high 16 bits, compared as a signed value: the
        // lowest wins (KILL_PROCESS, 0x8000_0000, is the most negative).
        programs
            .iter()
            .map(|program| run(program, data))
            .min_by_key(|ret| (ret & 0xffff_0000) as i32)
            .unwrap_or(libc::SECCOMP_RET_ALLOW)
    }

    fn errno(ret: u32) -> Option<i32> {
        (ret & 0xffff_0000 == libc::SECCOMP_RET_ERRNO).then_some((ret & 0xffff) as i32)
    }

    fn native() -> (TargetArch, u32, u32) {
        if cfg!(target_arch = "aarch64") {
            (TargetArch::aarch64, AUDIT_ARCH_AARCH64, AUDIT_ARCH_ARM)
        } else {
            (TargetArch::x86_64, AUDIT_ARCH_X86_64, AUDIT_ARCH_I386)
        }
    }

    fn call(nr: i64, args: [u64; 6]) -> Data {
        let (_, arch, _) = native();
        Data {
            nr: nr as u32,
            arch,
            args,
        }
    }

    #[test]
    fn every_denied_call_answers_eperm_and_common_ones_pass() {
        let (arch, _, _) = native();
        let programs = programs(Network::Direct, arch, false).unwrap();
        for nr in denied() {
            assert_eq!(
                errno(verdict(&programs, &call(nr, [0; 6]))),
                Some(libc::EPERM),
                "nr {nr}"
            );
        }
        for nr in [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_openat,
            libc::SYS_close,
            libc::SYS_mmap,
            libc::SYS_futex,
            libc::SYS_ftruncate,
            libc::SYS_getrandom,
            libc::SYS_connect,
            libc::SYS_landlock_restrict_self,
        ] {
            assert_eq!(
                verdict(&programs, &call(nr, [0; 6])),
                libc::SECCOMP_RET_ALLOW,
                "nr {nr}"
            );
        }
    }

    /// The calls 0010 denies with `EPERM`, by name and by number from the
    /// kernel's own tables (`arch/x86/entry/syscalls/syscall_64.tbl`,
    /// `include/uapi/asm-generic/unistd.h`), written out here and not taken
    /// from [`denied`] or libc: dropping a rule there fails this test.
    /// Process clones, `clone3`, sockets and `ioctl` have tests of their
    /// own.
    #[cfg(target_arch = "x86_64")]
    const REQUIRED: &[(&str, i64)] = &[
        ("fork", 57),
        ("vfork", 58),
        ("execve", 59),
        ("truncate", 76),
        ("chmod", 90),
        ("fchmod", 91),
        ("chown", 92),
        ("fchown", 93),
        ("lchown", 94),
        ("ptrace", 101),
        ("utime", 132),
        ("personality", 135),
        ("pivot_root", 155),
        ("mount", 165),
        ("umount2", 166),
        ("swapon", 167),
        ("swapoff", 168),
        ("reboot", 169),
        ("init_module", 175),
        ("delete_module", 176),
        ("setxattr", 188),
        ("lsetxattr", 189),
        ("fsetxattr", 190),
        ("removexattr", 197),
        ("lremovexattr", 198),
        ("fremovexattr", 199),
        ("utimes", 235),
        ("kexec_load", 246),
        ("add_key", 248),
        ("request_key", 249),
        ("keyctl", 250),
        ("fchownat", 260),
        ("futimesat", 261),
        ("fchmodat", 268),
        ("unshare", 272),
        ("utimensat", 280),
        ("perf_event_open", 298),
        ("setns", 308),
        ("process_vm_readv", 310),
        ("process_vm_writev", 311),
        ("finit_module", 313),
        ("kexec_file_load", 320),
        ("bpf", 321),
        ("execveat", 322),
        ("userfaultfd", 323),
        ("io_uring_setup", 425),
        ("io_uring_enter", 426),
        ("io_uring_register", 427),
        ("pidfd_getfd", 438),
        ("fchmodat2", 452),
        ("setxattrat", 463),
        ("removexattrat", 466),
        ("file_setattr", 469),
    ];

    /// [`REQUIRED`] on AArch64, whose table never had the legacy calls.
    #[cfg(target_arch = "aarch64")]
    const REQUIRED: &[(&str, i64)] = &[
        ("setxattr", 5),
        ("lsetxattr", 6),
        ("fsetxattr", 7),
        ("removexattr", 14),
        ("lremovexattr", 15),
        ("fremovexattr", 16),
        ("umount2", 39),
        ("mount", 40),
        ("pivot_root", 41),
        ("truncate", 45),
        ("fchmod", 52),
        ("fchmodat", 53),
        ("fchownat", 54),
        ("fchown", 55),
        ("utimensat", 88),
        ("personality", 92),
        ("unshare", 97),
        ("kexec_load", 104),
        ("init_module", 105),
        ("delete_module", 106),
        ("ptrace", 117),
        ("reboot", 142),
        ("add_key", 217),
        ("request_key", 218),
        ("keyctl", 219),
        ("execve", 221),
        ("swapon", 224),
        ("swapoff", 225),
        ("perf_event_open", 241),
        ("setns", 268),
        ("process_vm_readv", 270),
        ("process_vm_writev", 271),
        ("finit_module", 273),
        ("bpf", 280),
        ("execveat", 281),
        ("userfaultfd", 282),
        ("kexec_file_load", 294),
        ("io_uring_setup", 425),
        ("io_uring_enter", 426),
        ("io_uring_register", 427),
        ("pidfd_getfd", 438),
        ("fchmodat2", 452),
        ("setxattrat", 463),
        ("removexattrat", 466),
        ("file_setattr", 469),
    ];

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn the_required_calls_answer_eperm_and_nothing_else_is_denied() {
        let (arch, _, _) = native();
        for network in [Network::Direct, Network::Offline] {
            let programs = programs(network, arch, false).unwrap();
            for (name, nr) in REQUIRED {
                assert_eq!(
                    errno(verdict(&programs, &call(*nr, [0; 6]))),
                    Some(libc::EPERM),
                    "{name} ({nr})"
                );
            }
        }
        // And the other way: a rule outside the list is added to it on
        // purpose.
        for nr in denied() {
            assert!(
                REQUIRED.iter().any(|(_, required)| *required == nr),
                "nr {nr} is denied but not in REQUIRED"
            );
        }
    }

    /// The probe's errno: the kernel's lack, or something outside.
    #[test]
    fn a_refused_probe_is_unavailable_or_blocked() {
        let classified = |errno| classify(&std::io::Error::from_raw_os_error(errno));
        for errno in [libc::EINVAL, libc::ENOSYS] {
            assert!(
                matches!(classified(errno), Installed::Unavailable(_)),
                "{errno}"
            );
        }
        for errno in [libc::EPERM, libc::EACCES, libc::ENOMEM] {
            assert!(
                matches!(classified(errno), Installed::Blocked(_)),
                "{errno}"
            );
        }
    }

    #[test]
    fn threads_are_created_and_processes_are_not() {
        let (arch, _, _) = native();
        let programs = programs(Network::Direct, arch, false).unwrap();
        let thread = (libc::CLONE_VM | libc::CLONE_THREAD | libc::CLONE_SIGHAND) as u64;
        assert_eq!(
            verdict(&programs, &call(libc::SYS_clone, [thread, 0, 0, 0, 0, 0])),
            libc::SECCOMP_RET_ALLOW
        );
        for flags in [
            libc::SIGCHLD as u64,
            (libc::CLONE_VM | libc::CLONE_VFORK) as u64,
        ] {
            assert_eq!(
                errno(verdict(
                    &programs,
                    &call(libc::SYS_clone, [flags, 0, 0, 0, 0, 0])
                )),
                Some(libc::EPERM)
            );
        }
        assert_eq!(
            errno(verdict(&programs, &call(libc::SYS_clone3, [0; 6]))),
            Some(libc::ENOSYS)
        );
    }

    #[test]
    fn sockets_are_inet_only_and_pairs_stream_only() {
        let (arch, _, _) = native();
        let online = programs(Network::Socks5 { port: 9150 }, arch, false).unwrap();
        let socket = |programs: &[BpfProgram], family: i32| {
            verdict(
                programs,
                &call(
                    libc::SYS_socket,
                    [family as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0],
                ),
            )
        };
        assert_eq!(socket(&online, libc::AF_INET), libc::SECCOMP_RET_ALLOW);
        assert_eq!(socket(&online, libc::AF_INET6), libc::SECCOMP_RET_ALLOW);
        for family in [
            libc::AF_UNIX,
            libc::AF_NETLINK,
            libc::AF_PACKET,
            libc::AF_VSOCK,
        ] {
            assert_eq!(
                errno(socket(&online, family)),
                Some(libc::EPERM),
                "family {family}"
            );
        }
        let offline = programs(Network::Offline, arch, false).unwrap();
        assert_eq!(errno(socket(&offline, libc::AF_INET)), Some(libc::EPERM));
        let pair = |kind: i32| {
            verdict(
                &online,
                &call(
                    libc::SYS_socketpair,
                    [libc::AF_UNIX as u64, kind as u64, 0, 0, 0, 0],
                ),
            )
        };
        assert_eq!(
            pair(libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK),
            libc::SECCOMP_RET_ALLOW
        );
        for kind in [
            libc::SOCK_DGRAM,
            libc::SOCK_SEQPACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
        ] {
            assert_eq!(errno(pair(kind)), Some(libc::EPERM), "type {kind}");
        }
    }

    #[test]
    fn ioctl_answers_enotty_outside_the_allowlist_on_the_low_32_bits() {
        let (arch, _, _) = native();
        let programs = programs(Network::Direct, arch, false).unwrap();
        let ioctl = |cmd: u64| verdict(&programs, &call(libc::SYS_ioctl, [3, cmd, 0, 0, 0, 0]));
        for cmd in IOCTL_ALLOWED {
            assert_eq!(ioctl(cmd), libc::SECCOMP_RET_ALLOW, "cmd {cmd:#x}");
            // High bits the kernel ignores don't change the answer.
            assert_eq!(ioctl(cmd | 0xffff_ffff_0000_0000), libc::SECCOMP_RET_ALLOW);
        }
        // FS_IOC_SETFLAGS, FS_IOC_FSSETXATTR, FS_IOC_ENABLE_VERITY,
        // FS_IOC_SET_ENCRYPTION_POLICY, ext4's SETVERSION, and an unknown one.
        for cmd in [
            0x4008_6602u64,
            0x401c_581f,
            0x4080_6685,
            0x800c_6613,
            0x4008_6604,
            0x1234_5678,
        ] {
            assert_eq!(errno(ioctl(cmd)), Some(libc::ENOTTY), "cmd {cmd:#x}");
        }
    }

    /// `SIOCGIFINDEX` only for a policy that asks, and then nothing else
    /// new.
    #[test]
    fn the_interface_index_query_is_allowed_only_when_asked() {
        let (arch, _, _) = native();
        let ioctl = |programs: &[BpfProgram], cmd: u64| {
            verdict(programs, &call(libc::SYS_ioctl, [3, cmd, 0, 0, 0, 0]))
        };
        let without = programs(Network::Direct, arch, false).unwrap();
        assert_eq!(errno(ioctl(&without, SIOCGIFINDEX)), Some(libc::ENOTTY));
        let with = programs(Network::Direct, arch, true).unwrap();
        assert_eq!(ioctl(&with, SIOCGIFINDEX), libc::SECCOMP_RET_ALLOW);
        assert_eq!(
            ioctl(&with, SIOCGIFINDEX | 0xffff_ffff_0000_0000),
            libc::SECCOMP_RET_ALLOW
        );
        // Its neighbours stay refused: SIOCGIFNAME, SIOCSIFFLAGS, SIOCGIFADDR.
        for cmd in [0x8910u64, 0x8914, 0x8915] {
            assert_eq!(errno(ioctl(&with, cmd)), Some(libc::ENOTTY), "cmd {cmd:#x}");
        }
        assert_eq!(SIOCGIFINDEX, 0x8933);
    }

    #[test]
    fn other_abis_are_killed() {
        let (arch, _, compat) = native();
        let programs = programs(Network::Direct, arch, false).unwrap();
        let compat_call = Data {
            nr: 20,
            arch: compat,
            args: [0; 6],
        };
        assert_eq!(
            verdict(&programs, &compat_call),
            libc::SECCOMP_RET_KILL_PROCESS
        );
        if matches!(arch, TargetArch::x86_64) {
            let x32 = call(libc::SYS_getpid | i64::from(X32_SYSCALL_BIT), [0; 6]);
            assert_eq!(verdict(&programs, &x32), libc::SECCOMP_RET_KILL_PROCESS);
        }
    }
}
