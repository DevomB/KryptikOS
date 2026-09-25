//! seccomp-bpf syscall filtering: a default-deny allowlist
//! (docs/architecture.md), built as classic BPF by hand rather than with
//! libseccomp, a large C dependency (ADR-010).

use std::io;
use std::os::unix::io::RawFd;

// x86-64 only: `install` refuses to run anywhere else.
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
// Fail the call instead of killing: for probes such as clone3.
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

// Offsets into struct seccomp_data.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
/* Low 32 bits of args[i] (little-endian). The kernel reads every argument
 * checked here as 32 bits: clone flags, ioctl cmd, socket family, protocol. */
const fn arg_lo(i: u32) -> u32 {
    16 + 8 * i
}

/// Namespace-creating clone(2) flags: clone with any of them is unshare(2) by
/// another name. Not CLONE_NEWTIME (0x80): legacy clone's low byte is the exit
/// signal, which the kernel strips.
pub const CLONE_NS_MASK: u32 = 0x7e02_0000;

/// ioctls that inject into or read from the terminal: with TIOCSTI, a zone on
/// the user's tty types into the user's shell. Denied whatever LEGACY_TIOCSTI is.
const TIOCSTI: u32 = 0x5412;
const TIOCLINUX: u32 = 0x541C;

/// Socket families a zone may open. The rest (AF_VSOCK reaches the host;
/// AF_ALG, AF_PACKET, AF_XDP, ...) are CVE-prone and unneeded, though a policy
/// may add some. AF_NETLINK only as NETLINK_ROUTE, for getifaddrs() and ip(8).
pub const AF_UNIX: u32 = 1;
pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 10;
pub const AF_NETLINK: u32 = 16;
pub const NETLINK_ROUTE: u32 = 0;
const EAFNOSUPPORT: u32 = 97;
const ENOSYS: u32 = 38;

/// Families the base policy allows (AF_NETLINK only as NETLINK_ROUTE).
pub const BASE_SOCKET_FAMILIES: &[u32] = &[AF_UNIX, AF_INET, AF_INET6, AF_NETLINK];

/// The families a zone policy may name. Numbers from <linux/socket.h>.
pub const SOCKET_FAMILY_NAMES: &[(&str, u32)] = &[
    ("AF_UNIX", AF_UNIX), ("AF_INET", AF_INET), ("AF_INET6", AF_INET6), ("AF_NETLINK", AF_NETLINK),
    ("AF_PACKET", 17), ("AF_KEY", 15), ("AF_RDS", 21), ("AF_CAN", 29), ("AF_TIPC", 30),
    ("AF_BLUETOOTH", 31), ("AF_ALG", 38), ("AF_VSOCK", 40), ("AF_XDP", 44),
];

/// The netlink protocols a zone policy may name. Numbers from <linux/netlink.h>.
pub const NETLINK_PROTOCOL_NAMES: &[(&str, u32)] = &[
    ("NETLINK_ROUTE", NETLINK_ROUTE), ("NETLINK_XFRM", 6), ("NETLINK_AUDIT", 9),
    ("NETLINK_NETFILTER", 12), ("NETLINK_KOBJECT_UEVENT", 15), ("NETLINK_GENERIC", 16),
];

pub fn socket_family_by_name(name: &str) -> Option<u32> {
    SOCKET_FAMILY_NAMES.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

pub fn netlink_protocol_by_name(name: &str) -> Option<u32> {
    NETLINK_PROTOCOL_NAMES.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

/// What a zone policy adds to the socket(2) rule. Empty = the base rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocketPolicy {
    /// Extra families allowed outright (never AF_NETLINK: see `netlink_all`).
    pub families: Vec<u32>,
    /// Extra netlink protocols allowed besides NETLINK_ROUTE.
    pub netlink_protocols: Vec<u32>,
    /// AF_NETLINK allowed with any protocol.
    pub netlink_all: bool,
}

/// Is this syscall on the base denied list? A zone policy cannot re-allow it.
pub fn is_denied(nr: libc::c_long) -> bool {
    DENIED_RATIONALE.iter().any(|(n, _)| *n == nr)
}

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
                "syscall number {nr} is out of range for a 32-bit comparison; \
                 refusing to build a filter that would compare a truncated value"
            ),
            SeccompError::Syscall { call, errno } => {
                write!(f, "{call}: {}", io::Error::from_raw_os_error(*errno))
            }
        }
    }
}

/// Syscalls a zoned process may make. What is left out: `DENIED_RATIONALE`.
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
    // FIFOs and sockets; Landlock and nodev stop device nodes.
    libc::SYS_mknod, libc::SYS_mknodat,
    /* tar, git, cargo and install(1) set modes. Paths outside the zone are
     * unreachable after pivot_root, and read-only mounts refuse chmod (EROFS). */
    libc::SYS_chmod, libc::SYS_fchmod, libc::SYS_fchmodat,
    libc::SYS_copy_file_range, libc::SYS_sendfile, libc::SYS_splice,
    // GNU cat and cp call posix_fadvise() on every file they read.
    libc::SYS_fadvise64, libc::SYS_readahead,
    // Timestamps: touch, cp -p, install.
    libc::SYS_utimensat, libc::SYS_futimesat,
    libc::SYS_sync, libc::SYS_syncfs,
    libc::SYS_getxattr, libc::SYS_lgetxattr, libc::SYS_fgetxattr,
    libc::SYS_listxattr, libc::SYS_llistxattr, libc::SYS_flistxattr,

    // --- memory ---
    libc::SYS_mmap, libc::SYS_munmap, libc::SYS_mremap, libc::SYS_brk,
    libc::SYS_madvise, libc::SYS_mlock, libc::SYS_munlock, libc::SYS_memfd_create,
    /* Every dynamic linker needs mprotect, though it can defeat W^X; RELRO and
     * BIND_NOW make the GOT read-only before main() (docs/hardening.md). */
    libc::SYS_mprotect,

    // --- process / thread lifecycle ---
    /* clone is argument-filtered; clone3 gets ENOSYS, since the filter cannot
     * read its struct and glibc falls back to clone. See `ARG_RULES`. */
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
    libc::SYS_timerfd_create, libc::SYS_timerfd_settime, libc::SYS_timerfd_gettime,
    // inotify_init is refused softly: see `REFUSED_SOFTLY`.
    libc::SYS_inotify_add_watch, libc::SYS_inotify_rm_watch,

    // --- sockets ---
    // socket(2) is argument-filtered too: see `ARG_RULES`.
    libc::SYS_socket, libc::SYS_socketpair, libc::SYS_bind, libc::SYS_listen,
    libc::SYS_accept, libc::SYS_accept4, libc::SYS_connect, libc::SYS_shutdown,
    libc::SYS_getsockname, libc::SYS_getpeername, libc::SYS_setsockopt,
    libc::SYS_getsockopt, libc::SYS_sendto, libc::SYS_recvfrom,
    libc::SYS_sendmsg, libc::SYS_recvmsg, libc::SYS_sendmmsg, libc::SYS_recvmmsg,

    // --- misc ---
    libc::SYS_uname, libc::SYS_sysinfo, libc::SYS_getrandom, libc::SYS_prctl,
    libc::SYS_rseq, libc::SYS_statfs, libc::SYS_fstatfs,
];

/// Syscalls left out of the allowlist, and why; a zone policy cannot allow them.
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
    /* chown is in neither list: a zone policy may allow it (the nic zone's
     * DHCP client chowns its control socket). Without CAP_CHOWN a chown can
     * only be a no-op or a move between the caller's own groups. */
    // The new mount API: mount(2) through other entry points.
    (libc::SYS_fsopen, "new mount API: open a filesystem context"),
    (libc::SYS_fsconfig, "new mount API: configure a filesystem context"),
    (libc::SYS_fsmount, "new mount API: create a mount from a context"),
    (libc::SYS_fspick, "new mount API: reconfigure an existing mount"),
    (libc::SYS_move_mount, "new mount API: attach a mount"),
    (libc::SYS_open_tree, "new mount API: detach a mount tree"),
    (libc::SYS_mount_setattr, "change mount flags, e.g. clear read-only"),
    // io_uring does file and socket I/O without syscalls: a seccomp bypass.
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

/// Argument checks on allowlisted syscalls. They run before the plain
/// allowlist, so a syscall named here is decided here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgRule {
    /// clone(2): kill if any CLONE_NEW* flag is set in args[0].
    CloneNoNamespaces,
    /// clone3(2): ENOSYS, so libc falls back to clone(2), which the filter can read.
    Clone3Enosys,
    /// ioctl(2): kill on TIOCSTI / TIOCLINUX (terminal injection).
    IoctlNoTtyInject,
    /// socket(2): the base families plus the policy's; others get EAFNOSUPPORT.
    SocketFamilies,
}

pub const ARG_RULES: &[ArgRule] = &[
    ArgRule::CloneNoNamespaces,
    ArgRule::Clone3Enosys,
    ArgRule::IoctlNoTtyInject,
    ArgRule::SocketFamilies,
];

impl ArgRule {
    fn nr(self) -> libc::c_long {
        match self {
            ArgRule::CloneNoNamespaces => libc::SYS_clone,
            ArgRule::Clone3Enosys => libc::SYS_clone3,
            ArgRule::IoctlNoTtyInject => libc::SYS_ioctl,
            ArgRule::SocketFamilies => libc::SYS_socket,
        }
    }
}

/// Refused with an errno, not killed, since programs fall back when these
/// fail; a zone policy may allow them. inotify: a watch on the /usr the zones
/// share with zone 0 sees every program any of them starts.
pub const REFUSED_SOFTLY: &[(libc::c_long, u32)] = &[(libc::SYS_inotify_init, ENOSYS), (libc::SYS_inotify_init1, ENOSYS)];

const fn errno_action(e: u32) -> u32 {
    SECCOMP_RET_ERRNO | (e & 0xffff)
}

/// Emit one argument rule. Entered with the syscall number in the accumulator;
/// a non-matching number skips the block with the accumulator intact, and every
/// path through a matched block ends in `ret`.
fn emit_arg_rule(p: &mut Vec<SockFilter>, rule: ArgRule, deny_action: u32, sockets: &SocketPolicy) {
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
        /* Generated, since a zone policy can add families and protocols:
         *
         *   ld args[0]                       ; family
         *   jeq FAM_i  -> ALLOW              ; each allowed family
         *   [ jeq AF_NETLINK ? next : DENY   ; unless netlink_all
         *     ld args[2]                     ; protocol
         *     jeq PROTO_j -> ALLOW ]         ; each allowed protocol
         *   ret ALLOW
         *   ret ERRNO(EAFNOSUPPORT)
         *
         * A miss on the last comparison jumps to DENY; others fall through.
         */
        ArgRule::SocketFamilies => {
            let mut fams: Vec<u32> = vec![AF_UNIX, AF_INET, AF_INET6];
            for f in &sockets.families {
                if !fams.contains(f) && *f != AF_NETLINK {
                    fams.push(*f);
                }
            }
            if sockets.netlink_all {
                fams.push(AF_NETLINK);
            }
            let mut protos: Vec<u32> = vec![NETLINK_ROUTE];
            for pr in &sockets.netlink_protocols {
                if !protos.contains(pr) {
                    protos.push(*pr);
                }
            }
            let netlink_block = !sockets.netlink_all;
            let n = fams.len();
            let nl_len = if netlink_block { 2 + protos.len() } else { 0 };
            let allow_idx = 1 + n + nl_len;
            let deny_idx = allow_idx + 1;
            let off = |from: usize, to: usize| -> u8 {
                let d = to - (from + 1);
                assert!(d <= 255, "socket rule too long for a BPF jump");
                d as u8
            };
            let mut body = Vec::with_capacity(deny_idx + 1);
            body.push(stmt(BPF_LD | BPF_W | BPF_ABS, arg_lo(0)));
            for (i, f) in fams.iter().enumerate() {
                let idx = 1 + i;
                let jf = if idx + 1 == allow_idx { off(idx, deny_idx) } else { 0 };
                body.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *f, off(idx, allow_idx), jf));
            }
            if netlink_block {
                let idx = 1 + n;
                body.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AF_NETLINK, 0, off(idx, deny_idx)));
                body.push(stmt(BPF_LD | BPF_W | BPF_ABS, arg_lo(2)));
                for (j, pr) in protos.iter().enumerate() {
                    let idx = 1 + n + 2 + j;
                    let jf = if idx + 1 == allow_idx { off(idx, deny_idx) } else { 0 };
                    body.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *pr, off(idx, allow_idx), jf));
                }
            }
            body.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
            body.push(stmt(BPF_RET | BPF_K, errno_action(EAFNOSUPPORT)));
            body
        }
    };
    // Offsets count from the next instruction; every body is far below 255.
    p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, rule.nr() as u32, 0, body.len() as u8));
    p.extend(body);
}

#[cfg(test)]
fn build_program(allow: &[libc::c_long]) -> Result<Vec<SockFilter>, SeccompError> {
    build_program_with(allow, SECCOMP_RET_KILL_PROCESS)
}

#[cfg(test)]
fn build_program_with(
    allow: &[libc::c_long],
    deny_action: u32,
) -> Result<Vec<SockFilter>, SeccompError> {
    build_program_full(allow, deny_action, &SocketPolicy::default())
}

/// Build the BPF program: arch check, x32 check, argument rules, then a
/// `jeq nr; ret ALLOW` pair per syscall, so no jump offset (one byte) grows
/// with the list, then default deny.
fn build_program_full(
    allow: &[libc::c_long],
    deny_action: u32,
    sockets: &SocketPolicy,
) -> Result<Vec<SockFilter>, SeccompError> {
    let mut p = Vec::with_capacity(allow.len() * 2 + 8);

    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH));
    p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    p.push(stmt(BPF_RET | BPF_K, deny_action));

    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));

    /* x32 calls arrive as 0x40000000 | nr, so this is >=, not ==. Default deny
     * would catch them too; this is defence in depth. */
    p.push(jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1));
    p.push(stmt(BPF_RET | BPF_K, deny_action));

    /* Argument rules first, so the plain allowlist cannot allow their
     * syscalls, and only for a listed syscall: a rule's block can end in ALLOW. */
    for &rule in ARG_RULES {
        if allow.contains(&rule.nr()) {
            emit_arg_rule(&mut p, rule, deny_action, sockets);
        }
    }
    for &(nr, e) in REFUSED_SOFTLY {
        // Allowed by the list, it is allowed below like any other.
        if !allow.contains(&nr) {
            /* seccomp-trace answers these with the same errno, so the program
             * runs as it would in a zone and the call is still named. */
            let refuse = if deny_action == libc::SECCOMP_RET_USER_NOTIF { deny_action } else { errno_action(e) };
            p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, 1));
            p.push(stmt(BPF_RET | BPF_K, refuse));
        }
    }

    for &nr in allow {
        // seccomp_data.nr is 32 bits: a truncated number would allow another syscall.
        if nr < 0 || nr > u32::MAX as libc::c_long {
            return Err(SeccompError::BadSyscallNumber(nr));
        }
        if ARG_RULES.iter().any(|r| r.nr() == nr) {
            continue; // decided by its rule above
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

/// Install a default-deny filter on every thread of the process (TSYNC) and
/// all descendants. Irreversible.
pub fn install(allow: &[libc::c_long]) -> Result<(), SeccompError> {
    install_with(allow, SECCOMP_RET_KILL_PROCESS, &SocketPolicy::default(), SECCOMP_FILTER_FLAG_TSYNC).map(|_| ())
}

/// As `install` for a single-threaded caller, but a refused call waits for a
/// supervisor instead of killing: returns the listener descriptor, which is
/// close-on-exec (`kryptikd seccomp-trace`).
pub fn install_notifying(allow: &[libc::c_long]) -> Result<RawFd, SeccompError> {
    let fd = install_with(allow, libc::SECCOMP_RET_USER_NOTIF, &SocketPolicy::default(), libc::SECCOMP_FILTER_FLAG_NEW_LISTENER)?;
    Ok(fd as RawFd)
}

/// Returns what seccomp(2) returned: 0, or the listener with NEW_LISTENER.
fn install_with(
    allow: &[libc::c_long],
    deny_action: u32,
    sockets: &SocketPolicy,
    flags: libc::c_ulong,
) -> Result<libc::c_long, SeccompError> {
    if !cfg!(target_arch = "x86_64") {
        return Err(SeccompError::UnsupportedArch);
    }

    let prog = build_program_full(allow, deny_action, sockets)?;

    // Needed by an unprivileged caller; also keeps a later setuid exec unprivileged.
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
            flags,
            &fprog as *const _ as *const libc::c_void,
        )
    };
    if ret < 0 {
        return Err(SeccompError::Syscall {
            call: "seccomp(SET_MODE_FILTER)",
            errno: io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }
    Ok(ret)
}

/// Install the standard zone filter.
pub fn confine_zone() -> Result<(), SeccompError> {
    install(BASE_ALLOWLIST)
}

/// Install the zone filter widened by a policy: `extra` syscalls, checked again
/// against the denied list here, and the socket rule widened by `sockets`.
pub fn confine_zone_with(extra: &[libc::c_long], sockets: &SocketPolicy) -> Result<(), SeccompError> {
    let mut allow: Vec<libc::c_long> = BASE_ALLOWLIST.to_vec();
    for &nr in extra {
        if is_denied(nr) {
            return Err(SeccompError::BadSyscallNumber(nr));
        }
        if !allow.contains(&nr) {
            allow.push(nr);
        }
    }
    install_with(&allow, SECCOMP_RET_KILL_PROCESS, sockets, SECCOMP_FILTER_FLAG_TSYNC).map(|_| ())
}

/// `(name, number)` for each `libc::SYS_` constant given: a name is typed once.
macro_rules! by_name {
    ($($sys:ident),* $(,)?) => {
        &[$((unprefixed(stringify!($sys)), libc::$sys)),*]
    };
}

const fn unprefixed(sys: &'static str) -> &'static str {
    let (head, name) = sys.as_bytes().split_at(4);
    assert!(matches!(head, b"SYS_"));
    match std::str::from_utf8(name) {
        Ok(n) => n,
        Err(_) => unreachable!(),
    }
}

/// Syscall names a zone policy may use: denied ones (refused by name), base
/// ones (a redundant line warns) and plausible additions.
pub const SYSCALL_NAMES: &[(&str, libc::c_long)] = by_name![
    // denied, plus the chown family
    SYS_ptrace, SYS_process_vm_readv, SYS_process_vm_writev, SYS_mount, SYS_umount2, SYS_pivot_root,
    SYS_chroot, SYS_unshare, SYS_setns, SYS_bpf, SYS_perf_event_open, SYS_userfaultfd, SYS_keyctl,
    SYS_add_key, SYS_request_key, SYS_init_module, SYS_finit_module, SYS_delete_module, SYS_kexec_load,
    SYS_reboot, SYS_swapon, SYS_swapoff, SYS_setuid, SYS_setgid, SYS_ioperm, SYS_iopl, SYS_quotactl,
    SYS_open_by_handle_at, SYS_name_to_handle_at, SYS_chown, SYS_fchown, SYS_lchown, SYS_fchownat, SYS_fsopen,
    SYS_fsconfig, SYS_fsmount, SYS_fspick, SYS_move_mount, SYS_open_tree, SYS_mount_setattr,
    SYS_io_uring_setup, SYS_io_uring_enter, SYS_io_uring_register, SYS_pidfd_getfd, SYS_kcmp, SYS_sethostname,
    SYS_setdomainname, SYS_setgroups, SYS_setresuid, SYS_setresgid, SYS_setreuid, SYS_setregid, SYS_setfsuid,
    SYS_setfsgid, SYS_capset, SYS_personality,
    // in the base allowlist
    SYS_read, SYS_write, SYS_openat, SYS_close, SYS_getpid, SYS_clone, SYS_clone3, SYS_execve, SYS_socket,
    SYS_ioctl, SYS_prctl, SYS_mknod, SYS_chmod, SYS_memfd_create, SYS_capget,
    // plausible additions
    SYS_inotify_init, SYS_inotify_init1, SYS_adjtimex, SYS_clock_adjtime, SYS_clock_settime, SYS_settimeofday,
    SYS_sched_setscheduler, SYS_sched_setparam, SYS_ioprio_set, SYS_ioprio_get, SYS_mlockall, SYS_munlockall,
    SYS_mlock2, SYS_rt_sigqueueinfo, SYS_rt_tgsigqueueinfo, SYS_pidfd_open, SYS_pidfd_send_signal,
    SYS_process_madvise, SYS_msync, SYS_mincore, SYS_remap_file_pages, SYS_timer_create, SYS_timer_settime,
    SYS_timer_gettime, SYS_timer_delete, SYS_timer_getoverrun, SYS_semget, SYS_semop, SYS_semctl, SYS_shmget,
    SYS_shmat, SYS_shmdt, SYS_shmctl, SYS_msgget, SYS_msgsnd, SYS_msgrcv, SYS_msgctl, SYS_mq_open,
    SYS_mq_unlink, SYS_mq_timedsend, SYS_mq_timedreceive, SYS_mq_notify, SYS_mq_getsetattr, SYS_setxattr,
    SYS_lsetxattr, SYS_fsetxattr, SYS_removexattr, SYS_lremovexattr, SYS_fremovexattr, SYS_fanotify_init,
    SYS_fanotify_mark, SYS_sched_getattr, SYS_sched_setattr, SYS_vhangup, SYS_syslog, SYS_acct, SYS_getpgid,
    SYS_seccomp, SYS_landlock_create_ruleset, SYS_landlock_add_rule, SYS_landlock_restrict_self,
];

/// Look up a syscall number by name, for policy files and the test harness.
pub fn syscall_by_name(name: &str) -> Option<libc::c_long> {
    SYSCALL_NAMES.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn program_has_expected_shape() {
        let p = build_program(&[libc::SYS_read, libc::SYS_write]).unwrap();
        // 4 prologue + 2 x32 + 2 per soft refusal + 2 per syscall + 1 default
        // deny; neither syscall has an arg rule
        assert_eq!(p.len(), 3 + 1 + 2 + 2 * REFUSED_SOFTLY.len() + 4 + 1);
        assert_eq!(p[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(p[0].k, OFF_ARCH);
        let last = p.last().unwrap();
        assert_eq!(last.code, BPF_RET | BPF_K);
        assert_eq!(last.k, SECCOMP_RET_KILL_PROCESS, "filter must default-deny");
    }

    #[test]
    fn jump_offsets_stay_small() {
        let p = build_program(BASE_ALLOWLIST).unwrap();
        // Arg-rule offsets reach 9, the rest are 0 or 1; all must land inside.
        for (i, ins) in p.iter().enumerate() {
            assert!(ins.jt <= 9, "instruction {i} has jt={}", ins.jt);
            assert!(ins.jf <= 9, "instruction {i} has jf={}", ins.jf);
            if ins.code & 0x07 == BPF_JMP {
                assert!((i + 1 + ins.jt as usize) < p.len(), "instruction {i} jt runs off the end");
                assert!((i + 1 + ins.jf as usize) < p.len(), "instruction {i} jf runs off the end");
            }
        }
    }

    #[test]
    fn program_fits_kernel_limit() {
        let p = build_program(BASE_ALLOWLIST).unwrap();
        assert!(p.len() <= 4096, "program is {} instructions", p.len());
    }

    #[test]
    fn arch_checked_before_syscall_number() {
        // Else a foreign architecture's number could match a different syscall.
        let p = build_program(&[libc::SYS_read]).unwrap();
        assert_eq!(p[0].k, OFF_ARCH, "arch must be loaded first");
        assert!(p.iter().take(3).any(|i| i.k == AUDIT_ARCH_X86_64));
    }

    /// Interprets the BPF subset `build_program` emits, so tests check what the
    /// filter does rather than which constants it holds.
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
    fn arg_rules_follow_the_list() {
        // A rule allows on some path, so it exists only for a listed syscall.
        let p = build_program(&[libc::SYS_read]).unwrap();
        for nr in ARG_RULES.iter().map(|r| r.nr()) {
            assert_eq!(evaluate(&p, AUDIT_ARCH_X86_64, nr as u32), SECCOMP_RET_KILL_PROCESS, "syscall {nr} is not on the list");
        }
        let p = build_program(&[libc::SYS_read, libc::SYS_clone3]).unwrap();
        assert_eq!(evaluate(&p, AUDIT_ARCH_X86_64, libc::SYS_clone3 as u32), errno_action(ENOSYS));
    }

    #[test]
    fn inotify_refused_softly() {
        let p = build_program(BASE_ALLOWLIST).unwrap();
        for nr in [libc::SYS_inotify_init, libc::SYS_inotify_init1] {
            assert_eq!(evaluate(&p, AUDIT_ARCH_X86_64, nr as u32), errno_action(ENOSYS));
        }
        let mut allow = BASE_ALLOWLIST.to_vec();
        allow.push(libc::SYS_inotify_init1);
        let p = build_program(&allow).unwrap();
        assert_eq!(evaluate(&p, AUDIT_ARCH_X86_64, libc::SYS_inotify_init1 as u32), SECCOMP_RET_ALLOW, "a policy opens it");
    }

    #[test]
    fn trace_names_soft_refusals() {
        // clone3 keeps its errno: no policy opens it, so naming it would mislead.
        let p = build_program_with(BASE_ALLOWLIST, libc::SECCOMP_RET_USER_NOTIF).unwrap();
        assert_eq!(evaluate(&p, AUDIT_ARCH_X86_64, libc::SYS_inotify_init1 as u32), libc::SECCOMP_RET_USER_NOTIF);
        assert_eq!(evaluate(&p, AUDIT_ARCH_X86_64, libc::SYS_clone3 as u32), errno_action(ENOSYS));
    }

    #[test]
    fn interpreter_kills_foreign_arch() {
        let p = build_program(&[libc::SYS_read]).unwrap();
        // i386 would otherwise match on a syscall number meaning something else.
        assert_eq!(evaluate(&p, 0x4000_0003, libc::SYS_read as u32), SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn every_x32_syscall_is_killed() {
        // A spread of numbers: an == guard would catch only the first.
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
    fn x32_guard_is_range_comparison() {
        // == matches one value; the guard must cover every x32 number.
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
    fn whole_allowlist_evaluates_correctly() {
        let p = build_program(BASE_ALLOWLIST).unwrap();
        for &nr in BASE_ALLOWLIST {
            let r = evaluate(&p, AUDIT_ARCH_X86_64, nr as u32);
            /* With zero arguments clone3 gets ENOSYS and socket family 0 is
             * refused; nothing listed is killed, and the rest are allowed. */
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

    #[test]
    fn denied_list_not_in_allowlist() {
        let allowed: HashSet<libc::c_long> = BASE_ALLOWLIST.iter().copied().collect();
        for (nr, why) in DENIED_RATIONALE {
            assert!(
                !allowed.contains(nr),
                "syscall {nr} is in BASE_ALLOWLIST but documented as denied: {why}"
            );
        }
    }

    #[test]
    fn out_of_range_numbers_refused() {
        // Truncated to 32 bits this is 1, SYS_write.
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
            // Legacy clone ignores the high word, and so does the filter.
            assert_eq!(
                evaluate_args(&p, X86, libc::SYS_clone as u32, with_arg(0, flags | (1 << 40))),
                SECCOMP_RET_KILL_PROCESS
            );
        }
    }

    #[test]
    fn clone3_gets_enosys() {
        let p = build_program(BASE_ALLOWLIST).unwrap();
        let r = evaluate_args(&p, X86, libc::SYS_clone3 as u32, [0; 6]);
        assert_eq!(r & 0xffff_0000, SECCOMP_RET_ERRNO);
        assert_eq!(r & 0xffff, ENOSYS);
    }

    #[test]
    fn tty_injection_ioctls_are_killed() {
        let p = build_program(BASE_ALLOWLIST).unwrap();
        for cmd in [TIOCSTI, TIOCLINUX] {
            assert_eq!(
                evaluate_args(&p, X86, libc::SYS_ioctl as u32, with_arg(1, cmd as u64)),
                SECCOMP_RET_KILL_PROCESS,
                "ioctl {cmd:#x} must be killed"
            );
        }
        // The kernel reads cmd as 32 bits, so high-word junk must not hide TIOCSTI.
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
    fn arg_rules_leave_allowlist_alone() {
        /* A non-matching rule block must leave the syscall number in the
         * accumulator; these arguments would trip any rule consulted. */
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
        let allowed: HashSet<libc::c_long> = BASE_ALLOWLIST.iter().copied().collect();
        for nr in [libc::SYS_chmod, libc::SYS_fchmod, libc::SYS_fchmodat] {
            assert!(allowed.contains(&nr), "chmod family must be allowed (tar, git, cargo)");
        }
        for nr in [libc::SYS_chown, libc::SYS_fchown, libc::SYS_fchownat, libc::SYS_lchown] {
            assert!(!allowed.contains(&nr), "chown family must stay out of the base allowlist");
            // ...but a zone policy may allow it (the nic zone's DHCP client).
            assert!(!is_denied(nr), "chown family must be allowable by a zone policy");
        }
    }

    // --- zone policy widenings ---------------------------------------------

    #[test]
    fn widened_socket_rule_allows_named_extras() {
        let sp = SocketPolicy { families: vec![17], netlink_protocols: vec![12], netlink_all: false };
        let p = build_program_full(BASE_ALLOWLIST, SECCOMP_RET_KILL_PROCESS, &sp).unwrap();
        // The base families still pass...
        for fam in [AF_UNIX, AF_INET, AF_INET6] {
            assert_eq!(evaluate_args(&p, X86, libc::SYS_socket as u32, with_arg(0, fam as u64)), SECCOMP_RET_ALLOW, "{fam}");
        }
        // ...the extra family passes...
        assert_eq!(evaluate_args(&p, X86, libc::SYS_socket as u32, with_arg(0, 17)), SECCOMP_RET_ALLOW);
        // ...an unnamed family still does not...
        assert_eq!(evaluate_args(&p, X86, libc::SYS_socket as u32, with_arg(0, 40)), errno_action(EAFNOSUPPORT));
        // ...NETLINK_ROUTE and the extra protocol pass, another does not.
        let mut a = [0u64; 6];
        a[0] = AF_NETLINK as u64;
        for (proto, want) in [(0u64, SECCOMP_RET_ALLOW), (12, SECCOMP_RET_ALLOW), (9, errno_action(EAFNOSUPPORT))] {
            a[2] = proto;
            assert_eq!(evaluate_args(&p, X86, libc::SYS_socket as u32, a), want, "netlink proto {proto}");
        }
        // The rest of the program is unchanged.
        assert_eq!(evaluate_args(&p, X86, libc::SYS_ptrace as u32, [0; 6]), SECCOMP_RET_KILL_PROCESS);
        assert_eq!(evaluate_args(&p, X86, libc::SYS_read as u32, [0; 6]), SECCOMP_RET_ALLOW);
        for (i, ins) in p.iter().enumerate() {
            if ins.code & 0x07 == BPF_JMP {
                assert!((i + 1 + ins.jt as usize) < p.len() && (i + 1 + ins.jf as usize) < p.len(), "instruction {i} jumps off the end");
            }
        }
    }

    #[test]
    fn netlink_all_lifts_protocol_check() {
        let sp = SocketPolicy { families: vec![], netlink_protocols: vec![], netlink_all: true };
        let p = build_program_full(BASE_ALLOWLIST, SECCOMP_RET_KILL_PROCESS, &sp).unwrap();
        let mut a = [0u64; 6];
        a[0] = AF_NETLINK as u64;
        a[2] = 12;
        assert_eq!(evaluate_args(&p, X86, libc::SYS_socket as u32, a), SECCOMP_RET_ALLOW);
        assert_eq!(evaluate_args(&p, X86, libc::SYS_socket as u32, with_arg(0, 17)), errno_action(EAFNOSUPPORT));
    }

    #[test]
    fn base_socket_block_is_exact() {
        let mut generated = Vec::new();
        emit_arg_rule(&mut generated, ArgRule::SocketFamilies, SECCOMP_RET_KILL_PROCESS, &SocketPolicy::default());
        let expected = [
            (BPF_LD | BPF_W | BPF_ABS, 0, 0, arg_lo(0)),
            (BPF_JMP | BPF_JEQ | BPF_K, 5, 0, AF_UNIX),
            (BPF_JMP | BPF_JEQ | BPF_K, 4, 0, AF_INET),
            (BPF_JMP | BPF_JEQ | BPF_K, 3, 0, AF_INET6),
            (BPF_JMP | BPF_JEQ | BPF_K, 0, 3, AF_NETLINK),
            (BPF_LD | BPF_W | BPF_ABS, 0, 0, arg_lo(2)),
            (BPF_JMP | BPF_JEQ | BPF_K, 0, 1, NETLINK_ROUTE),
            (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW),
            (BPF_RET | BPF_K, 0, 0, errno_action(EAFNOSUPPORT)),
        ];
        assert_eq!(generated.len(), expected.len() + 1); // + the leading jeq SYS_socket
        for (ins, (code, jt, jf, k)) in generated[1..].iter().zip(expected.iter()) {
            assert_eq!((ins.code, ins.jt, ins.jf, ins.k), (*code, *jt, *jf, *k));
        }
    }

    #[test]
    fn syscall_name_table_is_consistent() {
        for (nr, why) in DENIED_RATIONALE {
            assert!(SYSCALL_NAMES.iter().any(|(_, n)| n == nr), "denied syscall {nr} ({why}) has no name in SYSCALL_NAMES");
            assert!(is_denied(*nr));
        }
        let mut seen = HashSet::new();
        for (name, nr) in SYSCALL_NAMES {
            assert!(seen.insert(*name), "duplicate name {name}");
            assert_eq!(syscall_by_name(name), Some(*nr));
        }
        assert!(!is_denied(libc::SYS_read));
    }
}
