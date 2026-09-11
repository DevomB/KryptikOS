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
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// Filter return actions.
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
// TRAP raises SIGSYS with si_syscall set to the offending number, instead of
// killing outright. Used only by `kryptikd seccomp-trace`, which is how a zone
// policy gets debugged: a KILL tells you a zone died, a TRAP tells you which
// syscall it died on.
const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
// ERRNO makes the syscall fail with the given errno instead of killing. Used
// where a program legitimately PROBES for a feature and must be told "no"
// rather than shot: clone3 (glibc falls back to clone on ENOSYS) and socket
// families a zone has no business opening.
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

// Offsets into struct seccomp_data.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
// args[6] are u64 at offset 16; on little-endian x86-64 the low 32 bits of
// args[i] sit at 16 + 8*i. Every argument inspected below is one the kernel
// itself reads as a 32-bit value (clone flags, ioctl cmd, socket family and
// protocol), so comparing the low word is exactly what the kernel sees.
const fn arg_lo(i: u32) -> u32 {
    16 + 8 * i
}

/// Namespace-creating clone(2) flags. clone() with any of these is the
/// unfiltered twin of unshare(2): it would hand a zone a fresh user namespace
/// with a full capability set inside it, which is the entry point of most
/// kernel privilege-escalation chains of the last decade. unshare was denied;
/// clone(CLONE_NEWUSER) sailed through the allowlist.
///
/// CLONE_NEWTIME (0x80) is deliberately absent: for legacy clone() the low
/// byte is the exit signal and the kernel strips it, so 0x80 there can never
/// request a namespace.
pub const CLONE_NS_MASK: u32 = 0x7e02_0000;

/// ioctl(2) requests that inject input into or read from the controlling
/// terminal. TIOCSTI is the classic sandbox escape: a zone that inherits the
/// operator's tty on stdin types commands into the operator's shell.
/// Kernels since 6.2 disable it by default (LEGACY_TIOCSTI=n); this filter
/// does not depend on that.
const TIOCSTI: u32 = 0x5412;
const TIOCLINUX: u32 = 0x541C;

/// Socket families a zone may open. Everything else - AF_VSOCK (not
/// namespaced: reaches the hypervisor/host), AF_ALG, AF_RDS, AF_TIPC,
/// AF_PACKET, AF_KEY, AF_XDP, AF_BLUETOOTH ... - is a kernel subsystem with a
/// CVE history that no zoned application needs. AF_NETLINK is limited to
/// NETLINK_ROUTE (protocol 0), which getifaddrs() and ip(8) need; the other
/// netlink families - NETLINK_NETFILTER in particular, the nf_tables LPE
/// surface - are refused. The `net` zone's DHCP client will need AF_PACKET;
/// that belongs in its per-zone policy, not the base.
const AF_UNIX: u32 = 1;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const AF_NETLINK: u32 = 16;
const NETLINK_ROUTE: u32 = 0;
const EAFNOSUPPORT: u32 = 97;
const ENOSYS: u32 = 38;

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
    libc::SYS_linkat,
    libc::SYS_umask, libc::SYS_flock, libc::SYS_fallocate, libc::SYS_creat,
    libc::SYS_openat2, libc::SYS_close_range,
    // FIFOs and unix sockets. Character and block nodes are refused by
    // Landlock (MAKE_CHAR / MAKE_BLOCK are handled and granted nowhere) and by
    // nodev on every zone mount, so the syscall itself is not the control.
    libc::SYS_mknod, libc::SYS_mknodat,
    // Mode changes on the zone's OWN files. These were removed after a review
    // changed the mode of a file outside the zone, but that escape depended
    // on the outside path being reachable - pivot_root removed it. Killing
    // chmod with SIGSYS instead broke tar, git checkout, cargo build, mv
    // across directories and install(1), all of which set modes on files they
    // create. The mounts a zone must not modify are read-only, which chmod
    // cannot cross (EROFS), and Landlock denies write there independently.
    libc::SYS_chmod, libc::SYS_fchmod, libc::SYS_fchmodat,
    libc::SYS_copy_file_range, libc::SYS_sendfile, libc::SYS_splice,
    // fadvise64 is not optional in practice: GNU cat and cp call
    // posix_fadvise() on every file they read. Leaving it out killed `cat`
    // with SIGSYS while `echo` and `ls` worked, which is a confusing enough
    // symptom to be worth naming here.
    libc::SYS_fadvise64, libc::SYS_readahead,
    // Timestamps and ownership: touch, cp -p, install.
    libc::SYS_utimensat, libc::SYS_futimesat,
    libc::SYS_sync, libc::SYS_syncfs,
    libc::SYS_getxattr, libc::SYS_lgetxattr, libc::SYS_fgetxattr,
    libc::SYS_listxattr, libc::SYS_llistxattr, libc::SYS_flistxattr,

    // --- memory ---
    libc::SYS_mmap, libc::SYS_munmap, libc::SYS_mremap, libc::SYS_brk,
    libc::SYS_madvise, libc::SYS_mlock, libc::SYS_munlock, libc::SYS_memfd_create,
    // NOTE: mprotect is allowed because every dynamic linker needs it. It is
    // also how W^X is defeated. The kernel-side mitigation is that Kryptik
    // builds everything with RELRO+BIND_NOW so the GOT is read-only before
    // main() runs; see docs/hardening.md.
    libc::SYS_mprotect,

    // --- process / thread lifecycle ---
    // clone is argument-filtered (no namespace flags) and clone3 returns
    // ENOSYS rather than being allowed: its arguments live in a struct the
    // filter cannot read, and glibc falls back to clone() on ENOSYS. See
    // `ARG_RULES`.
    libc::SYS_clone, libc::SYS_clone3, libc::SYS_fork, libc::SYS_vfork,
    libc::SYS_execve, libc::SYS_execveat, libc::SYS_exit, libc::SYS_exit_group,
    libc::SYS_wait4, libc::SYS_waitid,
    libc::SYS_getpid, libc::SYS_getppid, libc::SYS_gettid,
    libc::SYS_getuid, libc::SYS_geteuid, libc::SYS_getgid, libc::SYS_getegid,
    libc::SYS_getgroups, libc::SYS_getpgrp, libc::SYS_getpgid, libc::SYS_setpgid,
    libc::SYS_getsid, libc::SYS_setsid, libc::SYS_getrusage, libc::SYS_getrlimit,
    libc::SYS_prlimit64, libc::SYS_sched_yield, libc::SYS_sched_getaffinity,
    libc::SYS_sched_setaffinity, libc::SYS_getcpu, libc::SYS_capget,
    libc::SYS_set_tid_address, libc::SYS_set_robust_list, libc::SYS_get_robust_list,
    libc::SYS_futex, libc::SYS_arch_prctl, libc::SYS_membarrier,
    libc::SYS_getpriority, libc::SYS_setpriority,
    libc::SYS_sched_getparam, libc::SYS_sched_getscheduler,
    libc::SYS_sched_get_priority_max, libc::SYS_sched_get_priority_min,
    libc::SYS_getresuid, libc::SYS_getresgid,

    // --- signals ---
    libc::SYS_rt_sigaction, libc::SYS_rt_sigprocmask, libc::SYS_rt_sigreturn,
    libc::SYS_rt_sigpending, libc::SYS_rt_sigsuspend, libc::SYS_rt_sigtimedwait,
    libc::SYS_sigaltstack, libc::SYS_kill, libc::SYS_tgkill, libc::SYS_tkill,
    libc::SYS_restart_syscall,

    // --- time ---
    libc::SYS_clock_gettime, libc::SYS_clock_getres, libc::SYS_clock_nanosleep,
    libc::SYS_gettimeofday, libc::SYS_nanosleep, libc::SYS_times,
    libc::SYS_alarm, libc::SYS_setitimer, libc::SYS_getitimer, libc::SYS_pause,

    // --- polling ---
    libc::SYS_poll, libc::SYS_ppoll, libc::SYS_select, libc::SYS_pselect6,
    libc::SYS_epoll_create, libc::SYS_epoll_create1, libc::SYS_epoll_ctl,
    libc::SYS_epoll_wait, libc::SYS_epoll_pwait, libc::SYS_epoll_pwait2,
    libc::SYS_eventfd, libc::SYS_eventfd2, libc::SYS_signalfd, libc::SYS_signalfd4,
    libc::SYS_inotify_init,
    libc::SYS_timerfd_create, libc::SYS_timerfd_settime, libc::SYS_timerfd_gettime,
    libc::SYS_inotify_init1, libc::SYS_inotify_add_watch, libc::SYS_inotify_rm_watch,

    // --- sockets ---
    // Present so zoned applications can talk to the network they are routed to
    // and to their own Wayland/broker sockets. A zone with network.mode="none"
    // has no interface to reach regardless (docs/architecture.md).
    // socket(2) is additionally argument-filtered: see `ARG_RULES`.
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
    // Ownership changes are refused outright. A zone has exactly one mapped
    // uid, so chown to anything else is meaningless, and Landlock has no right
    // governing ownership. (chmod is allowed again - see BASE_ALLOWLIST.)
    (libc::SYS_chown, "change ownership; not covered by any Landlock right"),
    (libc::SYS_fchown, "change ownership via descriptor"),
    (libc::SYS_lchown, "change ownership of a symlink"),
    (libc::SYS_fchownat, "change ownership relative to a descriptor"),
    // The new mount API. mount(2) is denied above; these are the same power
    // through different entry points and were simply missing from the list.
    (libc::SYS_fsopen, "new mount API: open a filesystem context"),
    (libc::SYS_fsconfig, "new mount API: configure a filesystem context"),
    (libc::SYS_fsmount, "new mount API: create a mount from a context"),
    (libc::SYS_fspick, "new mount API: reconfigure an existing mount"),
    (libc::SYS_move_mount, "new mount API: attach a mount"),
    (libc::SYS_open_tree, "new mount API: detach a mount tree"),
    (libc::SYS_mount_setattr, "change mount flags, e.g. clear read-only"),
    // io_uring performs file and socket operations WITHOUT syscalls once set
    // up, which makes it a seccomp bypass by design, and it has its own CVE
    // history.
    (libc::SYS_io_uring_setup, "io_uring: bypasses the syscall filter by design"),
    (libc::SYS_io_uring_enter, "io_uring"),
    (libc::SYS_io_uring_register, "io_uring"),
    (libc::SYS_pidfd_getfd, "steal a descriptor from another process"),
    (libc::SYS_kcmp, "compare kernel objects across processes; ASLR/ptrace aid"),
    (libc::SYS_sethostname, "the zone's hostname is set by kryptikd, once"),
    (libc::SYS_setdomainname, "as sethostname"),
    (libc::SYS_setgroups, "no zoned process changes its groups"),
    (libc::SYS_setresuid, "no zoned process should change uid"),
    (libc::SYS_setresgid, "no zoned process should change gid"),
    (libc::SYS_setreuid, "no zoned process should change uid"),
    (libc::SYS_setregid, "no zoned process should change gid"),
    (libc::SYS_setfsuid, "no zoned process should change uid"),
    (libc::SYS_setfsgid, "no zoned process should change gid"),
    (libc::SYS_capset, "capabilities are fixed at zone entry"),
    (libc::SYS_personality, "change the execution domain; ASLR-disabling flag"),
];

/// Argument-inspected rules for syscalls that are on the allowlist but must
/// not be allowed with every argument. Applied BEFORE the plain allowlist, so
/// a syscall named here is decided here.
///
/// Each rule is a fixed BPF block; the shapes are written out in
/// `emit_arg_rule` with their jump offsets, and the interpreter-based tests
/// below evaluate them the way the kernel would.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgRule {
    /// clone(2): kill if any CLONE_NEW* flag is set in args[0].
    CloneNoNamespaces,
    /// clone3(2): fail with ENOSYS so libc falls back to clone(2), which the
    /// filter can inspect.
    Clone3Enosys,
    /// ioctl(2): kill on TIOCSTI / TIOCLINUX (terminal injection).
    IoctlNoTtyInject,
    /// socket(2): only AF_UNIX, AF_INET, AF_INET6 and AF_NETLINK/NETLINK_ROUTE;
    /// everything else fails with EAFNOSUPPORT.
    SocketFamilies,
}

pub const ARG_RULES: &[ArgRule] = &[
    ArgRule::CloneNoNamespaces,
    ArgRule::Clone3Enosys,
    ArgRule::IoctlNoTtyInject,
    ArgRule::SocketFamilies,
];

const fn errno_action(e: u32) -> u32 {
    SECCOMP_RET_ERRNO | (e & 0xffff)
}

/// Emit one argument rule as a self-contained block. The block is entered
/// with the syscall number in the accumulator; its first instruction skips
/// the whole block when the number does not match, so the accumulator still
/// holds the number for whatever follows. Every path inside a matched block
/// ends in a `ret`.
fn emit_arg_rule(p: &mut Vec<SockFilter>, rule: ArgRule, deny_action: u32) {
    let body: Vec<SockFilter> = match rule {
        ArgRule::CloneNoNamespaces => vec![
            stmt(BPF_LD | BPF_W | BPF_ABS, arg_lo(0)),
            jump(BPF_JMP | BPF_JSET | BPF_K, CLONE_NS_MASK, 0, 1),
            stmt(BPF_RET | BPF_K, deny_action),
            stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        ],
        ArgRule::Clone3Enosys => vec![stmt(BPF_RET | BPF_K, errno_action(ENOSYS))],
        ArgRule::IoctlNoTtyInject => vec![
            stmt(BPF_LD | BPF_W | BPF_ABS, arg_lo(1)),
            jump(BPF_JMP | BPF_JEQ | BPF_K, TIOCSTI, 2, 0),
            jump(BPF_JMP | BPF_JEQ | BPF_K, TIOCLINUX, 1, 0),
            stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            stmt(BPF_RET | BPF_K, deny_action),
        ],
        ArgRule::SocketFamilies => vec![
            stmt(BPF_LD | BPF_W | BPF_ABS, arg_lo(0)),
            jump(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 5, 0),
            jump(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 4, 0),
            jump(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 3, 0),
            jump(BPF_JMP | BPF_JEQ | BPF_K, AF_NETLINK, 0, 3),
            stmt(BPF_LD | BPF_W | BPF_ABS, arg_lo(2)),
            jump(BPF_JMP | BPF_JEQ | BPF_K, NETLINK_ROUTE, 0, 1),
            stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            stmt(BPF_RET | BPF_K, errno_action(EAFNOSUPPORT)),
        ],
    };
    let nr = match rule {
        ArgRule::CloneNoNamespaces => libc::SYS_clone,
        ArgRule::Clone3Enosys => libc::SYS_clone3,
        ArgRule::IoctlNoTtyInject => libc::SYS_ioctl,
        ArgRule::SocketFamilies => libc::SYS_socket,
    };
    // Skip offsets are relative to the next instruction, so skipping a body
    // of N instructions is jf = N. All bodies are far below 255.
    p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, body.len() as u8));
    p.extend(body);
}

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
    build_program_with(allow, SECCOMP_RET_KILL_PROCESS)
}

fn build_program_with(
    allow: &[libc::c_long],
    deny_action: u32,
) -> Result<Vec<SockFilter>, SeccompError> {
    let mut p = Vec::with_capacity(allow.len() * 2 + 8);

    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH));
    p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    p.push(stmt(BPF_RET | BPF_K, deny_action));

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
    p.push(stmt(BPF_RET | BPF_K, deny_action));

    // Argument-inspected syscalls are decided here, before the plain
    // allowlist can wave them through.
    for &rule in ARG_RULES {
        emit_arg_rule(&mut p, rule, deny_action);
    }

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

    p.push(stmt(BPF_RET | BPF_K, deny_action));

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
    install_with(allow, SECCOMP_RET_KILL_PROCESS)
}

/// Install the same filter but raise SIGSYS instead of killing, so a handler
/// can report which syscall was denied. Diagnostics only.
pub fn install_tracing(allow: &[libc::c_long]) -> Result<(), SeccompError> {
    install_with(allow, SECCOMP_RET_TRAP)
}

fn install_with(allow: &[libc::c_long], deny_action: u32) -> Result<(), SeccompError> {
    if !cfg!(target_arch = "x86_64") {
        return Err(SeccompError::UnsupportedArch);
    }

    let prog = build_program_with(allow, deny_action)?;

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

/// Best-effort name for a syscall number, for diagnostics.
pub fn name_of(nr: i32) -> String {
    let known: &[(libc::c_long, &str)] = &[
        (libc::SYS_read, "read"), (libc::SYS_write, "write"),
        (libc::SYS_openat, "openat"), (libc::SYS_close, "close"),
        (libc::SYS_fstat, "fstat"), (libc::SYS_newfstatat, "newfstatat"),
        (libc::SYS_statx, "statx"), (libc::SYS_mmap, "mmap"),
        (libc::SYS_mprotect, "mprotect"), (libc::SYS_munmap, "munmap"),
        (libc::SYS_brk, "brk"), (libc::SYS_ioctl, "ioctl"),
        (libc::SYS_lseek, "lseek"), (libc::SYS_execve, "execve"),
        (libc::SYS_exit_group, "exit_group"), (libc::SYS_getdents64, "getdents64"),
        (libc::SYS_fadvise64, "fadvise64"), (libc::SYS_pread64, "pread64"),
        (libc::SYS_prlimit64, "prlimit64"), (libc::SYS_getrandom, "getrandom"),
        (libc::SYS_rseq, "rseq"), (libc::SYS_set_robust_list, "set_robust_list"),
        (libc::SYS_futex, "futex"), (libc::SYS_sysinfo, "sysinfo"),
        (libc::SYS_uname, "uname"), (libc::SYS_readlink, "readlink"),
        (libc::SYS_access, "access"), (libc::SYS_arch_prctl, "arch_prctl"),
        (libc::SYS_set_tid_address, "set_tid_address"),
        (libc::SYS_rt_sigaction, "rt_sigaction"),
        (libc::SYS_rt_sigprocmask, "rt_sigprocmask"),
        (libc::SYS_getpid, "getpid"), (libc::SYS_dup2, "dup2"),
        (libc::SYS_dup3, "dup3"), (libc::SYS_pipe2, "pipe2"),
        (libc::SYS_wait4, "wait4"), (libc::SYS_clone, "clone"),
        (libc::SYS_fcntl, "fcntl"), (libc::SYS_umask, "umask"),
        (libc::SYS_getcwd, "getcwd"), (libc::SYS_chdir, "chdir"),
        (libc::SYS_setpgid, "setpgid"), (libc::SYS_getpgrp, "getpgrp"),
        (libc::SYS_geteuid, "geteuid"), (libc::SYS_getuid, "getuid"),
        (libc::SYS_getgid, "getgid"), (libc::SYS_getegid, "getegid"),
    ];
    for (n, name) in known {
        if *n as i32 == nr {
            return (*name).to_string();
        }
    }
    format!("syscall #{nr}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn program_has_expected_shape() {
        let p = build_program(&[libc::SYS_read, libc::SYS_write]).unwrap();
        // 4 prologue + 2 x32 + arg rules + 2 per syscall + 1 default deny
        let mut rules = Vec::new();
        for &r in ARG_RULES {
            emit_arg_rule(&mut rules, r, SECCOMP_RET_KILL_PROCESS);
        }
        assert_eq!(p.len(), 3 + 1 + 2 + rules.len() + 4 + 1);
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
        // The arg-rule blocks are small fixed shapes with offsets up to 9;
        // everything else is 0 or 1. Either way, every jump must land inside
        // the program.
        for (i, ins) in p.iter().enumerate() {
            assert!(ins.jt <= 9, "instruction {i} has jt={}", ins.jt);
            assert!(ins.jf <= 9, "instruction {i} has jf={}", ins.jf);
            if ins.code & 0x07 == BPF_JMP {
                assert!(i + 1 + ins.jt as usize < p.len(), "instruction {i} jt runs off the end");
                assert!(i + 1 + ins.jf as usize < p.len(), "instruction {i} jf runs off the end");
            }
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
        evaluate_args(prog, arch, nr, [0; 6])
    }

    fn evaluate_args(prog: &[SockFilter], arch: u32, nr: u32, args: [u64; 6]) -> u32 {
        let mut pc = 0usize;
        let mut acc: u32 = 0;
        loop {
            let ins = prog[pc];
            match ins.code {
                c if c == BPF_LD | BPF_W | BPF_ABS => {
                    acc = match ins.k {
                        OFF_ARCH => arch,
                        OFF_NR => nr,
                        k if (16..64).contains(&k) && (k - 16) % 8 == 0 => {
                            args[((k - 16) / 8) as usize] as u32
                        }
                        k if (16..64).contains(&k) && (k - 16) % 8 == 4 => {
                            (args[((k - 16) / 8) as usize] >> 32) as u32
                        }
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
                c if c == BPF_JMP | BPF_JSET | BPF_K => {
                    pc += 1 + if acc & ins.k != 0 { ins.jt as usize } else { ins.jf as usize };
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
            let r = evaluate(&p, AUDIT_ARCH_X86_64, nr as u32);
            // Argument-ruled syscalls decide on their arguments (all zero
            // here): clone3 is ENOSYS and socket family 0 is refused. They
            // must never be KILLED for being on the list, and everything
            // else must be allowed outright.
            assert_ne!(r, SECCOMP_RET_KILL_PROCESS, "allowlisted syscall {nr} was killed");
            if ![libc::SYS_clone3, libc::SYS_socket].contains(&nr) {
                assert_eq!(r, SECCOMP_RET_ALLOW, "allowlisted syscall {nr} was not allowed");
            }
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

    // --- argument rules -----------------------------------------------------

    const X86: u32 = AUDIT_ARCH_X86_64;

    fn with_arg(i: usize, v: u64) -> [u64; 6] {
        let mut a = [0u64; 6];
        a[i] = v;
        a
    }

    #[test]
    fn clone_without_namespace_flags_is_allowed() {
        let p = build_program(BASE_ALLOWLIST).unwrap();
        // What pthread_create and fork() actually pass.
        let thread = 0x3d0f00u64; // VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS|PARENT_SETTID|CHILD_CLEARTID
        let fork = 0x1200011u64; // CHILD_SETTID|CHILD_CLEARTID|SIGCHLD
        for f in [thread, fork, 17] {
            assert_eq!(
                evaluate_args(&p, X86, libc::SYS_clone as u32, with_arg(0, f)),
                SECCOMP_RET_ALLOW,
                "clone flags {f:#x} should be allowed"
            );
        }
    }

    #[test]
    fn clone_with_any_namespace_flag_is_killed() {
        // The regression test for the nested-userns escape: unshare(2) was
        // denied while clone(CLONE_NEWUSER) sailed through the allowlist.
        let p = build_program(BASE_ALLOWLIST).unwrap();
        for f in [
            libc::CLONE_NEWUSER, libc::CLONE_NEWNS, libc::CLONE_NEWPID,
            libc::CLONE_NEWNET, libc::CLONE_NEWIPC, libc::CLONE_NEWUTS,
            libc::CLONE_NEWCGROUP,
        ] {
            let flags = (f as u32 | libc::SIGCHLD as u32) as u64;
            assert_eq!(
                evaluate_args(&p, X86, libc::SYS_clone as u32, with_arg(0, flags)),
                SECCOMP_RET_KILL_PROCESS,
                "clone flags {flags:#x} must be killed"
            );
            // High bits are ignored by the kernel for legacy clone; the low
            // word is what matters and is what the filter reads.
            assert_eq!(
                evaluate_args(&p, X86, libc::SYS_clone as u32, with_arg(0, flags | (1 << 40))),
                SECCOMP_RET_KILL_PROCESS
            );
        }
    }

    #[test]
    fn clone3_fails_with_enosys_rather_than_killing() {
        let p = build_program(BASE_ALLOWLIST).unwrap();
        let r = evaluate_args(&p, X86, libc::SYS_clone3 as u32, [0; 6]);
        assert_eq!(r & 0xffff_0000, SECCOMP_RET_ERRNO);
        assert_eq!(r & 0xffff, ENOSYS);
    }

    #[test]
    fn tty_injection_ioctls_are_killed_and_others_allowed() {
        let p = build_program(BASE_ALLOWLIST).unwrap();
        for cmd in [TIOCSTI, TIOCLINUX] {
            assert_eq!(
                evaluate_args(&p, X86, libc::SYS_ioctl as u32, with_arg(1, cmd as u64)),
                SECCOMP_RET_KILL_PROCESS,
                "ioctl {cmd:#x} must be killed"
            );
        }
        // The kernel reads cmd as 32 bits: junk in the high word does not
        // hide TIOCSTI from the kernel and must not hide it from the filter.
        assert_eq!(
            evaluate_args(&p, X86, libc::SYS_ioctl as u32, with_arg(1, (1u64 << 40) | TIOCSTI as u64)),
            SECCOMP_RET_KILL_PROCESS
        );
        for cmd in [libc::TCGETS, libc::TIOCGWINSZ, libc::FIONREAD, libc::FIOCLEX] {
            assert_eq!(
                evaluate_args(&p, X86, libc::SYS_ioctl as u32, with_arg(1, cmd as u64)),
                SECCOMP_RET_ALLOW,
                "ioctl {cmd:#x} should be allowed"
            );
        }
    }

    #[test]
    fn socket_families_are_limited() {
        let p = build_program(BASE_ALLOWLIST).unwrap();
        for fam in [AF_UNIX, AF_INET, AF_INET6] {
            assert_eq!(
                evaluate_args(&p, X86, libc::SYS_socket as u32, with_arg(0, fam as u64)),
                SECCOMP_RET_ALLOW,
                "family {fam} should be allowed"
            );
        }
        // netlink: only NETLINK_ROUTE
        let mut a = [0u64; 6];
        a[0] = AF_NETLINK as u64;
        a[2] = NETLINK_ROUTE as u64;
        assert_eq!(evaluate_args(&p, X86, libc::SYS_socket as u32, a), SECCOMP_RET_ALLOW);
        a[2] = 12; // NETLINK_NETFILTER
        let r = evaluate_args(&p, X86, libc::SYS_socket as u32, a);
        assert_eq!(r, errno_action(EAFNOSUPPORT), "NETLINK_NETFILTER must be refused");
        for fam in [40u32 /* VSOCK */, 38 /* ALG */, 17 /* PACKET */, 15 /* KEY */, 21 /* RDS */, 30 /* TIPC */, 44 /* XDP */] {
            let r = evaluate_args(&p, X86, libc::SYS_socket as u32, with_arg(0, fam as u64));
            assert_eq!(r, errno_action(EAFNOSUPPORT), "family {fam} must be refused");
        }
    }

    #[test]
    fn arg_rules_do_not_disturb_the_plain_allowlist() {
        // Every arg-rule block must leave the accumulator holding the syscall
        // number when it does not match, or the allowlist after it compares
        // garbage. Checked by evaluating every allowed syscall with arguments
        // that would trip the rules if they were consulted.
        let p = build_program(BASE_ALLOWLIST).unwrap();
        let args = [CLONE_NS_MASK as u64, TIOCSTI as u64, 40, 7, 1 << 33, 9];
        for &nr in BASE_ALLOWLIST {
            if [libc::SYS_clone, libc::SYS_clone3, libc::SYS_ioctl, libc::SYS_socket].contains(&nr) {
                continue;
            }
            assert_eq!(
                evaluate_args(&p, X86, nr as u32, args),
                SECCOMP_RET_ALLOW,
                "syscall {nr} was affected by an argument rule"
            );
        }
    }

    #[test]
    fn chmod_is_allowed_and_chown_is_not() {
        // Documented decision, tested so it cannot drift silently either way.
        let allowed: HashSet<libc::c_long> = BASE_ALLOWLIST.iter().copied().collect();
        for nr in [libc::SYS_chmod, libc::SYS_fchmod, libc::SYS_fchmodat] {
            assert!(allowed.contains(&nr), "chmod family must be allowed (tar, git, cargo)");
        }
        for nr in [libc::SYS_chown, libc::SYS_fchown, libc::SYS_fchownat, libc::SYS_lchown] {
            assert!(!allowed.contains(&nr), "chown family must stay denied");
        }
    }
}
