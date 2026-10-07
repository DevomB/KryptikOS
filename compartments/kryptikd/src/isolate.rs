//! Zone isolation primitives as direct libc calls (ADR-010): namespaces, id maps, core
//! scheduling, and probes of what the kernel provides.

use std::io;

use crate::zone::{NetworkMode, Zone};

/// Namespaces every zone gets; the user namespace makes the zone's root weaker than the host's.
pub const ZONE_NAMESPACES: libc::c_int = libc::CLONE_NEWUSER
    | libc::CLONE_NEWNS
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWCGROUP;

pub const NS_NET: libc::c_int = libc::CLONE_NEWNET;

#[derive(Debug)]
pub enum IsolateError {
    Syscall { call: &'static str, errno: i32 },
    Refused(String),
}

impl std::fmt::Display for IsolateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IsolateError::Syscall { call, errno } => write!(
                f,
                "{call} failed: {}",
                io::Error::from_raw_os_error(*errno)
            ),
            IsolateError::Refused(m) => write!(f, "{m}"),
        }
    }
}

fn check(call: &'static str, ret: libc::c_int) -> Result<(), IsolateError> {
    if ret < 0 {
        Err(IsolateError::Syscall {
            call,
            errno: io::Error::last_os_error().raw_os_error().unwrap_or(0),
        })
    } else {
        Ok(())
    }
}

/// The namespaces a zone can be given, by name, in the order reports list them.
pub const NAMESPACES: [(libc::c_int, &str); 7] = [
    (libc::CLONE_NEWUSER, "user"),
    (libc::CLONE_NEWNS, "mount"),
    (libc::CLONE_NEWPID, "pid"),
    (libc::CLONE_NEWIPC, "ipc"),
    (libc::CLONE_NEWUTS, "uts"),
    (libc::CLONE_NEWCGROUP, "cgroup"),
    (libc::CLONE_NEWNET, "net"),
];

pub fn namespace_names(flags: libc::c_int) -> Vec<&'static str> {
    NAMESPACES.iter().filter(|(f, _)| flags & f != 0).map(|(_, n)| *n).collect()
}

/// Every zone gets its own network namespace; the nic zone's receives the physical NIC.
pub fn namespace_flags(zone: &Zone) -> libc::c_int {
    match zone.network {
        NetworkMode::None | NetworkMode::Routed | NetworkMode::Nic => ZONE_NAMESPACES | NS_NET,
    }
}

/// Enter new namespaces; CLONE_NEWPID applies to the caller's children, so fork afterwards.
pub fn unshare_namespaces(flags: libc::c_int) -> Result<(), IsolateError> {
    check("unshare", unsafe { libc::unshare(flags) })
}

/// Write a new user namespace's id maps, denying setgroups first as an unprivileged gid_map
/// needs. `with_nobody` maps 65534 too, which needs CAP_SETUID: a root launch only.
pub fn write_id_maps(
    pid: libc::pid_t,
    outer_uid: u32,
    outer_gid: u32,
    with_nobody: bool,
) -> Result<(), IsolateError> {
    use std::fs;

    let deny = format!("/proc/{pid}/setgroups");
    fs::write(&deny, "deny")
        .map_err(|e| IsolateError::Refused(format!("{deny}: {e}")))?;

    let map = |outer: u32| {
        let mut m = format!("0 {outer} 1\n");
        if with_nobody {
            m.push_str(&format!("65534 {} 1\n", outer + 65534));
        }
        m
    };

    let uid_map = format!("/proc/{pid}/uid_map");
    fs::write(&uid_map, map(outer_uid))
        .map_err(|e| IsolateError::Refused(format!("{uid_map}: {e}")))?;

    let gid_map = format!("/proc/{pid}/gid_map");
    fs::write(&gid_map, map(outer_gid))
        .map_err(|e| IsolateError::Refused(format!("{gid_map}: {e}")))?;

    Ok(())
}

/// Whether a sysctl restricts unprivileged user namespaces, and which: linux-hardened's
/// `unprivileged_userns_clone` (0) or Ubuntu's `apparmor_restrict_unprivileged_userns` (1).
pub fn userns_restriction_sysctl() -> Option<(bool, &'static str)> {
    let read = |p: &str| std::fs::read_to_string(p).ok().and_then(|s| s.trim().parse::<u32>().ok());
    if let Some(v) = read("/proc/sys/kernel/unprivileged_userns_clone") {
        return Some((v == 0, "kernel.unprivileged_userns_clone"));
    }
    if let Some(v) = read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") {
        return Some((v == 1, "kernel.apparmor_restrict_unprivileged_userns (emulation of the target)"));
    }
    None
}

/// Try `unshare(CLONE_NEWUSER)` in a child, as uid 65534 if we are root; `Ok(true)` is EPERM.
pub fn probe_userns_restriction() -> Result<bool, IsolateError> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(IsolateError::Syscall {
            call: "fork",
            errno: io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }
    if pid == 0 {
        unsafe {
            if libc::geteuid() == 0
                && (libc::setgroups(0, std::ptr::null()) < 0
                    || libc::setresgid(65534, 65534, 65534) < 0
                    || libc::setresuid(65534, 65534, 65534) < 0)
            {
                libc::_exit(3);
            }
            if libc::unshare(libc::CLONE_NEWUSER) == 0 {
                libc::_exit(0);
            }
            let e = *libc::__errno_location();
            libc::_exit(if e == libc::EPERM { 1 } else { 2 });
        }
    }
    let mut status: libc::c_int = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            break;
        }
        if r < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(IsolateError::Refused("probe: waitpid failed".into()));
    }
    if !libc::WIFEXITED(status) {
        return Err(IsolateError::Refused("probe child died by signal".into()));
    }
    match libc::WEXITSTATUS(status) {
        0 => Ok(false),
        1 => Ok(true),
        3 => Err(IsolateError::Refused("probe could not drop to uid 65534".into())),
        _ => Err(IsolateError::Refused(
            "unshare(CLONE_NEWUSER) failed with something other than EPERM".into(),
        )),
    }
}

/// SIGKILL when the parent exits; fork and any euid or egid change clear it, so re-arm after.
pub fn die_with_parent() -> Result<(), IsolateError> {
    check(
        "prctl(PR_SET_PDEATHSIG)",
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) },
    )
}

// From <linux/prctl.h>; the pinned libc crate lacks them.
const PR_SCHED_CORE: libc::c_int = 62;
const PR_SCHED_CORE_GET: libc::c_ulong = 0;
const PR_SCHED_CORE_CREATE: libc::c_ulong = 1;
const PIDTYPE_PID: libc::c_ulong = 0;

/// Give the calling task, and so its children, its own core-scheduling cookie: a core's
/// siblings then run it only beside the same cookie. ENODEV and EINVAL: see `CoreSched`.
pub fn take_core_cookie() -> io::Result<()> {
    if unsafe { libc::prctl(PR_SCHED_CORE, PR_SCHED_CORE_CREATE, 0, PIDTYPE_PID, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// What core scheduling can do for a zone on this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreSched {
    /// Sibling threads are online and scheduled by cookie.
    Cookies,
    /// ENODEV: no sibling thread online (`nosmt`, ADR-011), so nothing shares a core.
    NoSmt,
    /// EINVAL: a kernel built without CONFIG_SCHED_CORE.
    Unavailable,
}

/// Read our own cookie: with no sibling thread online, every PR_SCHED_CORE call gives ENODEV.
pub fn core_scheduling() -> CoreSched {
    match core_cookie_of(0) {
        Ok(_) => CoreSched::Cookies,
        Err(e) if e.raw_os_error() == Some(libc::ENODEV) => CoreSched::NoSmt,
        Err(_) => CoreSched::Unavailable,
    }
}

/// A task's core-scheduling cookie, 0 if none (pid 0: ours); another's needs ptrace-read access.
pub fn core_cookie_of(pid: libc::pid_t) -> io::Result<u64> {
    let mut cookie: libc::c_ulong = 0;
    let rc = unsafe {
        libc::prctl(PR_SCHED_CORE, PR_SCHED_CORE_GET, pid as libc::c_ulong, PIDTYPE_PID, &mut cookie as *mut libc::c_ulong as libc::c_ulong)
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cookie as u64)
}

/// One word for `kryptikd status`: does the zone's pid 1 have its own cookie.
pub fn core_cookie_word(pid: libc::pid_t) -> &'static str {
    match core_cookie_of(pid) {
        Ok(0) => "none",
        Ok(_) => "own",
        Err(e) if e.raw_os_error() == Some(libc::ENODEV) => "no-smt",
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => "unavailable",
        Err(_) => "unreadable",
    }
}

/// Set the hostname in the current UTS namespace (CAP_SYS_ADMIN there, once the id maps exist).
pub fn set_hostname(name: &str) -> Result<(), IsolateError> {
    check("sethostname", unsafe {
        libc::sethostname(name.as_ptr() as *const libc::c_char, name.len())
    })
}

/// Drop every supplementary group: needs CAP_SETGID (an unprivileged kryptikd gets EPERM), and
/// setgroups is denied inside the zone's namespace.
pub fn drop_supplementary_groups() -> Result<(), IsolateError> {
    check("setgroups", unsafe { libc::setgroups(0, std::ptr::null()) })
}

/// How many supplementary groups this process carries.
pub fn supplementary_group_count() -> usize {
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n < 0 { 0 } else { n as usize }
}

/// Bring up `lo`: even an air-gapped zone needs it, and it reaches nothing outside.
pub fn bring_up_loopback() -> Result<(), IsolateError> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(IsolateError::Syscall {
            call: "socket",
            errno: io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name = b"lo\0";
    for (i, &b) in name.iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;

    /* `as _`: the request is c_ulong in glibc and c_int in musl (the initramfs build); the
     * kernel reads 32 bits, and the assert checks the value fits them. */
    const _: () = assert!((libc::SIOCSIFFLAGS as u64) <= u32::MAX as u64);
    let ret = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) };
    unsafe { libc::close(sock) };
    check("ioctl(SIOCSIFFLAGS)", ret)
}

/// Which isolation mechanisms this kernel provides, for `kryptikd check`.
#[derive(Debug, Default)]
pub struct KernelSupport {
    pub user_ns: bool,
    pub pid_ns: bool,
    pub net_ns: bool,
    pub cgroup_v2: bool,
    pub seccomp: bool,
    pub landlock: Option<i32>,
}

impl KernelSupport {
    pub fn probe() -> Self {
        let ns = |n: &str| std::path::Path::new(&format!("/proc/self/ns/{n}")).exists();
        KernelSupport {
            user_ns: ns("user"),
            pid_ns: ns("pid"),
            net_ns: ns("net"),
            cgroup_v2: std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
            seccomp: std::fs::read_to_string("/proc/self/status")
                .map(|s| s.contains("Seccomp:"))
                .unwrap_or(false),
            landlock: crate::landlock::abi_version(),
        }
    }

    /// What the zone model needs and this kernel lacks.
    pub fn missing(&self) -> Vec<&'static str> {
        let mut m = Vec::new();
        if !self.user_ns { m.push("user namespaces"); }
        if !self.pid_ns { m.push("pid namespaces"); }
        if !self.net_ns { m.push("network namespaces"); }
        if !self.cgroup_v2 { m.push("cgroup v2"); }
        if !self.seccomp { m.push("seccomp"); }
        if self.landlock.is_none() { m.push("landlock"); }
        m
    }
}

#[cfg(test)]
mod tests;
