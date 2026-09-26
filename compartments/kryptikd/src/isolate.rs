//! Zone isolation primitives: namespaces and id maps, core scheduling, and
//! probes of what the kernel provides. Direct `libc` calls (ADR-010).

use std::io;

use crate::zone::{NetworkMode, Zone};

/// Namespaces every zone gets. The user namespace lets the others be created
/// and makes root inside the zone weaker than root outside it.
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

/// Namespace flags for a zone. Every zone gets its own network namespace; the
/// nic zone's is where the parent moves the physical NIC (netzone), leaving
/// zone 0 with loopback.
pub fn namespace_flags(zone: &Zone) -> libc::c_int {
    match zone.network {
        NetworkMode::None | NetworkMode::Routed | NetworkMode::Nic => ZONE_NAMESPACES | NS_NET,
    }
}

/// Enter new namespaces. CLONE_NEWPID puts the caller's children in the new pid
/// namespace, not the caller, so the caller must fork afterwards.
pub fn unshare_namespaces(flags: libc::c_int) -> Result<(), IsolateError> {
    check("unshare", unsafe { libc::unshare(flags) })
}

/// Write the uid/gid maps for a new user namespace. setgroups is denied first,
/// or the kernel refuses an unprivileged gid_map write. `with_nobody` also maps
/// nobody (65534) into the zone's range, which needs CAP_SETUID in the parent
/// namespace: privileged launch only.
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

/// Whether a sysctl restricts unprivileged user namespaces, and which:
/// linux-hardened's `unprivileged_userns_clone` (0 = restricted) or Ubuntu's
/// `apparmor_restrict_unprivileged_userns` (1 = restricted). `None`: neither.
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

/// Test the restriction rather than read it: in a child, as uid 65534 if we are
/// root, try `unshare(CLONE_NEWUSER)`. `Ok(true)` means EPERM (restricted).
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
            if libc::geteuid() == 0 {
                if libc::setgroups(0, std::ptr::null()) < 0
                    || libc::setresgid(65534, 65534, 65534) < 0
                    || libc::setresuid(65534, 65534, 65534) < 0
                {
                    libc::_exit(3);
                }
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

/// Die (SIGKILL) when the parent exits. The kernel clears this on fork and on
/// any euid or egid change (setresuid), so set it again after either.
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

/// Give the calling task its own core-scheduling cookie, which its children
/// inherit: a core's sibling threads then run it only alongside the same
/// cookie. Needs no privilege. ENODEV and EINVAL are not failures (`CoreSched`).
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
    /// ENODEV: no sibling thread online (`nosmt`, ADR-011, or no SMT at all).
    /// Nothing shares a core, which is what the cookie is for.
    NoSmt,
    /// EINVAL: a kernel built without CONFIG_SCHED_CORE.
    Unavailable,
}

/// Asks by reading our own cookie: while no sibling thread is online, every
/// PR_SCHED_CORE operation answers ENODEV first.
pub fn core_scheduling() -> CoreSched {
    match core_cookie_of(0) {
        Ok(_) => CoreSched::Cookies,
        Err(e) if e.raw_os_error() == Some(libc::ENODEV) => CoreSched::NoSmt,
        Err(_) => CoreSched::Unavailable,
    }
}

/// A task's core-scheduling cookie, 0 if none; pid 0 is the calling task.
/// /proc does not show it. Another task's needs ptrace-read access to it.
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

/// Set the hostname in the current UTS namespace. Needs CAP_SYS_ADMIN in the
/// owning user namespace, which the zone's root has once the id maps exist.
pub fn set_hostname(name: &str) -> Result<(), IsolateError> {
    check("sethostname", unsafe {
        libc::sethostname(name.as_ptr() as *const libc::c_char, name.len())
    })
}

/// Drop every supplementary group. Needs CAP_SETGID in the current user
/// namespace, so an unprivileged kryptikd gets EPERM, and setgroups is denied
/// inside the zone's namespace.
pub fn drop_supplementary_groups() -> Result<(), IsolateError> {
    check("setgroups", unsafe { libc::setgroups(0, std::ptr::null()) })
}

/// How many supplementary groups this process carries.
pub fn supplementary_group_count() -> usize {
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n < 0 { 0 } else { n as usize }
}

/// Bring up `lo` in the zone's network namespace. Even an air-gapped zone needs
/// it, and it reaches nothing outside the namespace.
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

    /* `as _`: the request is c_ulong in glibc and c_int in musl (the static
     * initramfs build). The kernel reads 32 bits and the assert checks the
     * value fits them, so narrowing to c_int loses nothing. */
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
mod tests {
    use super::*;
    use crate::zone::Zone;

    fn zone(mode: &str) -> Zone {
        let bridge = if mode == "nic" { "bridge = \"kryptik0\"\n" } else { "" };
        Zone::from_str(&format!(
            "[zone]\nname = \"t\"\n[network]\nmode = \"{mode}\"\n{bridge}\
             [storage]\nmode = \"ephemeral\"\nsize = \"256M\"\n[ui]\nborder_color = \"#123456\"\n"
        ))
        .unwrap()
    }

    /// Taken in a forked child and read from the parent, as `kryptikd status`
    /// reads a zone's; the test process itself keeps no cookie.
    #[test]
    fn task_takes_own_core_cookie() {
        let me = unsafe { libc::getpid() };
        match core_scheduling() {
            CoreSched::Cookies => {}
            CoreSched::NoSmt => {
                assert_eq!(core_cookie_word(me), "no-smt");
                assert_eq!(take_core_cookie().unwrap_err().raw_os_error(), Some(libc::ENODEV));
                eprintln!("no sibling threads online; no cookie to take; skipping the rest");
                return;
            }
            CoreSched::Unavailable => {
                assert_eq!(core_cookie_word(me), "unavailable");
                eprintln!("no core scheduling on this kernel; skipping the rest");
                return;
            }
        }
        let mut p = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0, "pipe failed");
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe {
                libc::close(p[0]);
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
                let b: u8 = if take_core_cookie().is_ok() { 1 } else { 0 };
                libc::write(p[1], &b as *const u8 as *const libc::c_void, 1);
                libc::close(p[1]);
                loop {
                    libc::pause();
                }
            }
        }
        unsafe { libc::close(p[1]) };
        let mut b = 0u8;
        let n = unsafe { libc::read(p[0], &mut b as *mut u8 as *mut libc::c_void, 1) };
        unsafe { libc::close(p[0]) };
        let child = core_cookie_of(pid);
        let mine = core_cookie_of(unsafe { libc::getpid() });
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            let mut st = 0;
            libc::waitpid(pid, &mut st, 0);
        }
        assert_eq!((n, b), (1, 1), "the child could not take a cookie");
        let child = child.expect("the parent may read its child's cookie");
        assert_ne!(child, 0, "the child's cookie reads as zero after PR_SCHED_CORE_CREATE");
        assert_eq!(mine.expect("a task may read its own cookie"), 0, "the parent took no cookie and must have none");
        assert_eq!(core_cookie_word(unsafe { libc::getpid() }), "none");
    }

    #[test]
    fn every_zone_gets_net_namespace() {
        assert_ne!(namespace_flags(&zone("none")) & libc::CLONE_NEWNET, 0);
        assert_ne!(namespace_flags(&zone("routed")) & libc::CLONE_NEWNET, 0);
        // The parent moves the physical NIC into this one.
        assert_ne!(namespace_flags(&zone("nic")) & libc::CLONE_NEWNET, 0);
    }

    #[test]
    fn every_zone_gets_core_namespaces() {
        for m in ["none", "routed", "nic"] {
            let f = namespace_flags(&zone(m));
            for (flag, name) in [
                (libc::CLONE_NEWUSER, "user"),
                (libc::CLONE_NEWNS, "mount"),
                (libc::CLONE_NEWPID, "pid"),
                (libc::CLONE_NEWIPC, "ipc"),
                (libc::CLONE_NEWUTS, "uts"),
            ] {
                assert_ne!(f & flag, 0, "zone mode {m} is missing the {name} namespace");
            }
        }
    }
}
