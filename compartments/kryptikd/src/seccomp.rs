//! seccomp-bpf syscall filtering.
//!
//! Closes the largest hole left in the zone model: until now a zone had
//! namespaces and Landlock but the complete syscall surface, so every classic
//! kernel LPE and container-escape primitive was reachable from inside it.
//!
//! The filter is a hand-built classic-BPF program rather than libseccomp.
//! kryptikd runs privileged and mediates every boundary (ADR-010), and
//! libseccomp is a large C dependency in exactly the process that should have
//! the fewest. The program is small enough to read in full below.
//!
//! DEFAULT-DENY. docs/architecture.md specifies an allowlist, and that is what
//! this is: anything not named is killed. A denylist would be easier to tune
//! and worthless — it protects against the syscalls you thought of.

use std::io;

// x86-64 only for now. A filter that silently permitted a foreign
// architecture would be worse than no filter, so `install` refuses to run
// anywhere else rather than degrading.
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

const SYS_SECCOMP: libc::c_long = 317;
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_FILTER_FLAG_TSYNC: libc::c_ulong = 1;

// Classic BPF opcodes.
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// Filter return actions.
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

// Offsets into struct seccomp_data.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter { code, jt: 0, jf: 0, k }
}

const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

#[derive(Debug)]
pub enum SeccompError {
    UnsupportedArch,
    TooManyRules(usize),
    BadSyscallNumber(libc::c_long),
    Syscall { call: &'static str, errno: i32 },
}

impl std::fmt::Display for SeccompError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeccompError::UnsupportedArch => write!(
                f,
                "seccomp filtering is only implemented for x86-64; \
                 refusing to run a zone unfiltered"
            ),
            SeccompError::TooManyRules(n) => {
                write!(f, "filter would be {n} instructions; the kernel limit is 4096")
            }
            SeccompError::BadSyscallNumber(nr) => write!(
                f,
                "syscall number {nr} is out of range for a 32-bit comparison;                  refusing to build a filter that would compare a truncated value"
            ),
            SeccompError::Syscall { call, errno } => {
                write!(f, "{call}: {}", io::Error::from_raw_os_error(*errno))
            }
        }
    }
}

/// Syscalls a zoned process is permitted.
///
/// Derived from what a normal userspace program actually needs: file and
/// socket I/O, memory management, process and thread lifecycle, signals, time.
///
/// What is deliberately ABSENT is the point of the list — see `DENIED_RATIONALE`.
pub const BASE_ALLOWLIST: &[libc::c_long] = &[
    // --- file I/O ---
    libc::SYS_read, libc::SYS_write, libc::SYS_readv, libc::SYS_writev,
    libc::SYS_pread64, libc::SYS_pwrite64, libc::SYS_preadv, libc::SYS_pwritev,
    libc::SYS_open, libc::SYS_openat, libc::SYS_close, libc::SYS_lseek,
    libc::SYS_stat, libc::SYS_fstat, libc::SYS_lstat, libc::SYS_newfstatat,
    libc::SYS_statx, libc::SYS_access, libc::SYS_faccessat, libc::SYS_faccessat2,
    libc::SYS_getdents64, libc::SYS_readlink, libc::SYS_readlinkat,
    libc::SYS_fcntl, libc::SYS_ioctl, libc::SYS_dup, libc::SYS_dup2, libc::SYS_dup3,
    libc::SYS_pipe, libc::SYS_pipe2, libc::SYS_fsync, libc::SYS_fdatasync,
    libc::SYS_ftruncate, libc::SYS_truncate, libc::SYS_getcwd, libc::SYS_chdir,
    libc::SYS_fchdir, libc::SYS_rename, libc::SYS_renameat, libc::SYS_renameat2,
    libc::SYS_mkdir, libc::SYS_mkdirat, libc::SYS_rmdir, libc::SYS_unlink,
    libc::SYS_unlinkat, libc::SYS_symlink, libc::SYS_symlinkat, libc::SYS_link,
    libc::SYS_linkat, libc::SYS_chmod, libc::SYS_fchmod, libc::SYS_fchmodat,
    libc::SYS_umask, libc::SYS_flock, libc::SYS_fallocate,
    libc::SYS_copy_file_range, libc::SYS_sendfile, libc::SYS_splice,

    // --- memory ---
    libc::SYS_mmap, libc::SYS_munmap, libc::SYS_mremap, libc::SYS_brk,
    libc::SYS_madvise, libc::SYS_mlock, libc::SYS_munlock,
    // NOTE: mprotect is allowed because every dynamic linker needs it. It is
    // also how W^X is defeated. The kernel-side mitigation is that Kryptik
    // builds everything with RELRO+BIND_NOW so the GOT is read-only before
    // main() runs; see docs/hardening.md.
    libc::SYS_mprotect,

    // --- process / thread lifecycle ---
    libc::SYS_clone, libc::SYS_clone3, libc::SYS_fork, libc::SYS_vfork,
    libc::SYS_execve, libc::SYS_execveat, libc::SYS_exit, libc::SYS_exit_group,
    libc::SYS_wait4, libc::SYS_waitid,
    libc::SYS_getpid, libc::SYS_getppid, libc::SYS_gettid,
    libc::SYS_getuid, libc::SYS_geteuid, libc::SYS_getgid, libc::SYS_getegid,
    libc::SYS_getgroups, libc::SYS_getpgrp, libc::SYS_getpgid, libc::SYS_setpgid,
    libc::SYS_getsid, libc::SYS_setsid, libc::SYS_getrusage, libc::SYS_getrlimit,
    libc::SYS_prlimit64, libc::SYS_sched_yield, libc::SYS_sched_getaffinity,
    libc::SYS_set_tid_address, libc::SYS_set_robust_list, libc::SYS_get_robust_list,
    libc::SYS_futex, libc::SYS_arch_prctl, libc::SYS_membarrier,

    // --- signals ---
    libc::SYS_rt_sigaction, libc::SYS_rt_sigprocmask, libc::SYS_rt_sigreturn,
    libc::SYS_rt_sigpending, libc::SYS_rt_sigsuspend, libc::SYS_rt_sigtimedwait,
    libc::SYS_sigaltstack, libc::SYS_kill, libc::SYS_tgkill, libc::SYS_tkill,
    libc::SYS_restart_syscall,

    // --- time ---
    libc::SYS_clock_gettime, libc::SYS_clock_getres, libc::SYS_clock_nanosleep,
    libc::SYS_gettimeofday, libc::SYS_nanosleep, libc::SYS_times,

    // --- polling ---
    libc::SYS_poll, libc::SYS_ppoll, libc::SYS_select, libc::SYS_pselect6,
    libc::SYS_epoll_create1, libc::SYS_epoll_ctl, libc::SYS_epoll_wait,
    libc::SYS_epoll_pwait, libc::SYS_eventfd2, libc::SYS_signalfd4,
    libc::SYS_timerfd_create, libc::SYS_timerfd_settime, libc::SYS_timerfd_gettime,
    libc::SYS_inotify_init1, libc::SYS_inotify_add_watch, libc::SYS_inotify_rm_watch,

    // --- sockets ---
    // Present so zoned applications can talk to the network they are routed to
    // and to their own Wayland/broker sockets. A zone with network.mode="none"
    // has no interface to reach regardless (docs/architecture.md).
    libc::SYS_socket, libc::SYS_socketpair, libc::SYS_bind, libc::SYS_listen,
    libc::SYS_accept, libc::SYS_accept4, libc::SYS_connect, libc::SYS_shutdown,
    libc::SYS_getsockname, libc::SYS_getpeername, libc::SYS_setsockopt,
    libc::SYS_getsockopt, libc::SYS_sendto, libc::SYS_recvfrom,
    libc::SYS_sendmsg, libc::SYS_recvmsg, libc::SYS_sendmmsg, libc::SYS_recvmmsg,

    // --- misc ---
    libc::SYS_uname, libc::SYS_sysinfo, libc::SYS_getrandom, libc::SYS_prctl,
    libc::SYS_rseq, libc::SYS_statfs, libc::SYS_fstatfs,
];

/// Syscalls deliberately excluded, and why.
///
/// This is documentation with a test attached: `denied_list_is_actually_denied`
/// asserts none of these ever appears in the allowlist, so the reasoning below
/// cannot silently rot if someone extends the list.
pub const DENIED_RATIONALE: &[(libc::c_long, &str)] = &[
    (libc::SYS_ptrace, "read/write another process's memory; the classic escape"),
    (libc::SYS_process_vm_readv, "read another process's memory directly"),
    (libc::SYS_process_vm_writev, "write another process's memory directly"),
    (libc::SYS_mount, "re-mount the filesystem out from under Landlock"),
    (libc::SYS_umount2, "unmount the zone's own confinement"),
    (libc::SYS_pivot_root, "replace the zone's root"),
    (libc::SYS_chroot, "escape via the classic double-chroot trick"),
    (libc::SYS_unshare, "create nested namespaces; a known LPE surface"),
    (libc::SYS_setns, "ENTER ANOTHER ZONE'S NAMESPACE - defeats the whole model"),
    (libc::SYS_bpf, "load kernel programs; a well-worn privilege-escalation path"),
    (libc::SYS_perf_event_open, "long history of privilege escalation bugs"),
    (libc::SYS_userfaultfd, "reliable heap-grooming primitive for kernel exploits"),
    (libc::SYS_keyctl, "kernel keyring; repeated CVEs"),
    (libc::SYS_add_key, "kernel keyring"),
    (libc::SYS_request_key, "kernel keyring"),
    (libc::SYS_init_module, "load a kernel module"),
    (libc::SYS_finit_module, "load a kernel module"),
    (libc::SYS_delete_module, "unload a kernel module"),
    (libc::SYS_kexec_load, "boot a different kernel"),
    (libc::SYS_reboot, "reboot the host"),
    (libc::SYS_swapon, "attach swap"),
    (libc::SYS_swapoff, "detach swap"),
    (libc::SYS_setuid, "no zoned process should change uid"),
    (libc::SYS_setgid, "no zoned process should change gid"),
    (libc::SYS_ioperm, "raw I/O port access"),
    (libc::SYS_iopl, "raw I/O port access"),
    (libc::SYS_quotactl, "filesystem quota manipulation"),
    (libc::SYS_open_by_handle_at, "open a file by handle, bypassing path checks"),
    (libc::SYS_name_to_handle_at, "obtain the handle used by the above"),
];

/// Build the BPF program for a set of permitted syscalls.
///
/// Shape (all jumps are 0 or 1, so the program is safe at any list length —
/// a naive "jump to the ALLOW at the end" encoding breaks past 255 entries):
///
///   ld  [arch]
///   jeq X86_64 ? +1 : fallthrough
///   ret KILL                       ; wrong architecture
///   ld  [nr]
///   jeq >= X32_BIT ? fallthrough : +1
///   ret KILL                       ; x32 ABI aliases syscall numbers
///   for each allowed nr:
///       jeq nr ? fallthrough : +1
///       ret ALLOW
///   ret KILL                       ; default deny
fn build_program(allow: &[libc::c_long]) -> Result<Vec<SockFilter>, SeccompError> {
    let mut p = Vec::with_capacity(allow.len() * 2 + 8);

    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH));
    p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));

    // The x32 ABI reuses x86-64 syscall numbers with the high bit set, so an
    // x32 call arrives as 0x40000000 | nr. This must be a >= test, not ==:
    // an equality check against the bare bit matches only x32 syscall 0 and
    // silently lets every other x32 number through to the allowlist.
    //
    // Default-deny catches them anyway, since no x32 number can equal a plain
    // x86-64 one - so this is defense in depth rather than the primary control.
    // It is still worth being correct: a check that does nothing is worse than
    // no check, because it reads as though the case is handled.
    p.push(jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1));
    p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    for &nr in allow {
        // seccomp_data.nr is a 32-bit field, so the comparison is 32-bit. A
        // c_long that does not fit would be silently truncated and the filter
        // would compare against a DIFFERENT syscall than intended - permitting
        // one nobody reviewed. Refuse to build such a filter.
        //
        // No real syscall number comes close to this bound; the check exists so
        // that a future edit adding a bad constant fails loudly at build time
        // instead of producing a quietly wrong allowlist.
        if nr < 0 || nr > u32::MAX as libc::c_long {
            return Err(SeccompError::BadSyscallNumber(nr));
        }
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let nr_u32 = nr as u32; // bounds-checked immediately above
        p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr_u32, 0, 1));
        p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }

    p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    if p.len() > 4096 {
        return Err(SeccompError::TooManyRules(p.len()));
    }
    Ok(p)
}

/// Install a default-deny filter on this thread and all descendants.
///
/// Irreversible. TSYNC applies it to every thread in the process, so a
/// multi-threaded program cannot leave one thread unfiltered.
pub fn install(allow: &[libc::c_long]) -> Result<(), SeccompError> {
    if !cfg!(target_arch = "x86_64") {
        return Err(SeccompError::UnsupportedArch);
    }

    let prog = build_program(allow)?;

    // Required before seccomp for an unprivileged caller, and it is what stops
    // a setuid binary executed later from regaining what the filter removed.
    let nnp = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if nnp < 0 {
        return Err(SeccompError::Syscall {
            call: "prctl(PR_SET_NO_NEW_PRIVS)",
            errno: io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }

    let fprog = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };

    let ret = unsafe {
        libc::syscall(
            SYS_SECCOMP,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_TSYNC,
            &fprog as *const _ as *const libc::c_void,
        )
    };
    if ret < 0 {
        return Err(SeccompError::Syscall {
            call: "seccomp(SET_MODE_FILTER)",
            errno: io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }
    Ok(())
}

/// Install the standard zone filter.
pub fn confine_zone() -> Result<(), SeccompError> {
    install(BASE_ALLOWLIST)
}

/// Look up a syscall number by name, for the test harness.
pub fn syscall_by_name(name: &str) -> Option<libc::c_long> {
    Some(match name {
        "ptrace" => libc::SYS_ptrace,
        "setns" => libc::SYS_setns,
        "unshare" => libc::SYS_unshare,
        "mount" => libc::SYS_mount,
        "bpf" => libc::SYS_bpf,
        "perf_event_open" => libc::SYS_perf_event_open,
        "userfaultfd" => libc::SYS_userfaultfd,
        "keyctl" => libc::SYS_keyctl,
        "init_module" => libc::SYS_init_module,
        "kexec_load" => libc::SYS_kexec_load,
        "process_vm_readv" => libc::SYS_process_vm_readv,
        "pivot_root" => libc::SYS_pivot_root,
        "chroot" => libc::SYS_chroot,
        "getpid" => libc::SYS_getpid,
        "write" => libc::SYS_write,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn program_has_expected_shape() {
        let p = build_program(&[libc::SYS_read, libc::SYS_write]).unwrap();
        // 4 prologue + 2 x32 + 2 per syscall + 1 default deny
        assert_eq!(p.len(), 3 + 1 + 2 + 4 + 1);
        assert_eq!(p[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(p[0].k, OFF_ARCH);
        // Must END in a deny, never an allow.
        let last = p.last().unwrap();
        assert_eq!(last.code, BPF_RET | BPF_K);
        assert_eq!(last.k, SECCOMP_RET_KILL_PROCESS, "filter must default-deny");
    }

    #[test]
    fn every_jump_offset_fits_in_a_byte() {
        // The whole point of the two-instruction encoding: a "jump to the end"
        // encoding silently breaks once the allowlist passes 255 entries.
        let p = build_program(BASE_ALLOWLIST).unwrap();
        for (i, ins) in p.iter().enumerate() {
            assert!(ins.jt <= 1, "instruction {i} has jt={}", ins.jt);
            assert!(ins.jf <= 1, "instruction {i} has jf={}", ins.jf);
        }
    }

    #[test]
    fn program_fits_the_kernel_limit() {
        let p = build_program(BASE_ALLOWLIST).unwrap();
        assert!(p.len() <= 4096, "program is {} instructions", p.len());
    }

    #[test]
    fn arch_is_checked_before_the_syscall_number() {
        // Checking nr first would let a foreign architecture match a number
        // that means something else entirely.
        let p = build_program(&[libc::SYS_read]).unwrap();
        assert_eq!(p[0].k, OFF_ARCH, "arch must be loaded first");
        assert!(p.iter().take(3).any(|i| i.k == AUDIT_ARCH_X86_64));
    }

    /// A minimal interpreter for the BPF subset `build_program` emits.
    ///
    /// The previous x32 test asserted only that the constant 0x40000000
    /// appeared somewhere in the program. It passed while the comparison was
    /// BPF_JEQ instead of BPF_JGE - which matches only x32 syscall 0 and lets
    /// every other x32 number through. Checking that a constant is present
    /// says nothing about what the program DOES with it, so this evaluates the
    /// filter the way the kernel would.
    fn evaluate(prog: &[SockFilter], arch: u32, nr: u32) -> u32 {
        let mut pc = 0usize;
        let mut acc: u32 = 0;
        loop {
            let ins = prog[pc];
            match ins.code {
                c if c == BPF_LD | BPF_W | BPF_ABS => {
                    acc = match ins.k {
                        OFF_ARCH => arch,
                        OFF_NR => nr,
                        other => panic!("unexpected load offset {other}"),
                    };
                    pc += 1;
                }
                c if c == BPF_JMP | BPF_JEQ | BPF_K => {
                    pc += 1 + if acc == ins.k { ins.jt as usize } else { ins.jf as usize };
                }
                c if c == BPF_JMP | BPF_JGE | BPF_K => {
                    pc += 1 + if acc >= ins.k { ins.jt as usize } else { ins.jf as usize };
                }
                c if c == BPF_RET | BPF_K => return ins.k,
                other => panic!("unexpected opcode {other:#x}"),
            }
            assert!(pc < prog.len(), "program ran off the end without returning");
        }
    }

    #[test]
    fn interpreter_allows_permitted_syscalls() {
        let p = build_program(&[libc::SYS_read, libc::SYS_write]).unwrap();
        for nr in [libc::SYS_read, libc::SYS_write] {
            assert_eq!(
                evaluate(&p, AUDIT_ARCH_X86_64, nr as u32),
                SECCOMP_RET_ALLOW,
                "syscall {nr} should be allowed"
            );
        }
    }

    #[test]
    fn interpreter_kills_unlisted_syscalls() {
        let p = build_program(&[libc::SYS_read]).unwrap();
        assert_eq!(
            evaluate(&p, AUDIT_ARCH_X86_64, libc::SYS_ptrace as u32),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    #[test]
    fn interpreter_kills_a_foreign_architecture() {
        let p = build_program(&[libc::SYS_read]).unwrap();
        // i386 would otherwise match on a syscall number meaning something else.
        assert_eq!(evaluate(&p, 0x4000_0003, libc::SYS_read as u32), SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn every_x32_syscall_number_is_killed() {
        // The regression test for the JEQ/JGE bug. Checks a spread of x32
        // numbers, not just the bare bit: with BPF_JEQ only the first of these
        // was caught by the x32 check.
        let p = build_program(BASE_ALLOWLIST).unwrap();
        for offset in [0u32, 1, 2, 60, 101, 257, 1000] {
            let x32_nr = X32_SYSCALL_BIT | offset;
            assert_eq!(
                evaluate(&p, AUDIT_ARCH_X86_64, x32_nr),
                SECCOMP_RET_KILL_PROCESS,
                "x32 syscall {x32_nr:#x} (x86-64 nr {offset}) was not killed"
            );
        }
    }

    #[test]
    fn the_x32_guard_uses_a_range_comparison() {
        // Named explicitly so the reason survives: == matches one value, and
        // the guard needs to match a whole half of the number space.
        let p = build_program(&[libc::SYS_read]).unwrap();
        let guard = p
            .iter()
            .find(|i| i.k == X32_SYSCALL_BIT)
            .expect("no x32 guard in the program");
        assert_eq!(
            guard.code,
            BPF_JMP | BPF_JGE | BPF_K,
            "x32 guard must be a >= comparison, not =="
        );
    }

    #[test]
    fn the_whole_allowlist_evaluates_correctly() {
        let p = build_program(BASE_ALLOWLIST).unwrap();
        for &nr in BASE_ALLOWLIST {
            assert_eq!(
                evaluate(&p, AUDIT_ARCH_X86_64, nr as u32),
                SECCOMP_RET_ALLOW,
                "allowlisted syscall {nr} was not allowed"
            );
        }
        for (nr, why) in DENIED_RATIONALE {
            assert_eq!(
                evaluate(&p, AUDIT_ARCH_X86_64, *nr as u32),
                SECCOMP_RET_KILL_PROCESS,
                "denied syscall {nr} ({why}) was not killed"
            );
        }
    }

    /// The documentation-with-a-test: the denied list and the allowlist must
    /// never overlap, so the rationale above cannot rot as the allowlist grows.
    #[test]
    fn denied_list_is_actually_denied() {
        let allowed: HashSet<libc::c_long> = BASE_ALLOWLIST.iter().copied().collect();
        for (nr, why) in DENIED_RATIONALE {
            assert!(
                !allowed.contains(nr),
                "syscall {nr} is in BASE_ALLOWLIST but documented as denied: {why}"
            );
        }
    }

    #[test]
    fn out_of_range_syscall_numbers_are_refused() {
        // Would truncate to 1 (SYS_write) in a 32-bit comparison, silently
        // permitting a syscall nobody put on the list.
        let bogus: libc::c_long = 0x1_0000_0001;
        assert!(build_program(&[bogus]).is_err());
        assert!(build_program(&[-1]).is_err());
    }

    #[test]
    fn allowlist_has_no_duplicates() {
        let mut seen = HashSet::new();
        for nr in BASE_ALLOWLIST {
            assert!(seen.insert(*nr), "duplicate syscall {nr} in allowlist");
        }
    }

    #[test]
    fn essential_syscalls_are_permitted() {
        // A filter that blocks these produces a zone nothing can run in, and
        // the failure looks like a mysterious kill rather than a policy error.
        let allowed: HashSet<libc::c_long> = BASE_ALLOWLIST.iter().copied().collect();
        for nr in [
            libc::SYS_read, libc::SYS_write, libc::SYS_exit_group,
            libc::SYS_mmap, libc::SYS_munmap, libc::SYS_rt_sigreturn,
            libc::SYS_execve, libc::SYS_futex, libc::SYS_brk,
        ] {
            assert!(allowed.contains(&nr), "essential syscall {nr} is not allowed");
        }
    }
}
