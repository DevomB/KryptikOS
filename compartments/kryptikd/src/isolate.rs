//! Zone isolation primitives: namespaces, seccomp, Landlock, cgroups.
//!
//! This is the code the isolation exit test attacks. Everything here is a direct
//! syscall via `libc` rather than a helper crate, because these calls are the
//! security boundary and their exact arguments matter (ADR-010).
//!
//! ORDERING IS LOAD-BEARING. Isolation is applied in a fixed order and the
//! reasons are written next to each step. Reordering these without
//! understanding why will produce a zone that looks isolated and is not.

use std::io;

use crate::zone::{NetworkMode, Zone};

/// Namespaces a zone always gets.
///
/// CLONE_NEWUSER is first in the constant but NOT optional: it is what allows
/// the remaining namespaces to be created and what makes "root inside the zone"
/// mean something weaker than root outside it. The isolation exit test runs as
/// root *inside* a zone precisely to prove that distinction holds.
pub const ZONE_NAMESPACES: libc::c_int = libc::CLONE_NEWUSER
    | libc::CLONE_NEWNS
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWCGROUP;

/// Added only for zones that do not hold the physical NIC.
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

/// Which namespace flags a given zone needs.
///
/// Every zone gets its own network namespace, the nic zone included: it
/// OWNS the physical interface, which the parent moves into its namespace
/// (netzone), so zone 0 is left with loopback. At first the nic zone stayed
/// in zone 0's namespace - a compartment-layer rule from before
/// the topology existed - which made "move the NIC into the nic zone" a
/// no-op and built the bridge in zone 0. Nothing measured it: the launcher
/// suite's routed-zone check only confirmed that the zone started, and the VM
/// topology probe that asks whether eth0 left zone 0 had not run yet.
pub fn namespace_flags(zone: &Zone) -> libc::c_int {
    match zone.network {
        NetworkMode::None | NetworkMode::Routed | NetworkMode::Nic => ZONE_NAMESPACES | NS_NET,
    }
}

/// Enter new namespaces.
///
/// unshare() rather than clone() so the caller keeps its pid; note that
/// CLONE_NEWPID does not move the calling process into the new pid namespace -
/// the first child does. Callers must fork after this for pid isolation to
/// take effect, which `spawn_in_zone` does.
pub fn unshare_namespaces(flags: libc::c_int) -> Result<(), IsolateError> {
    check("unshare", unsafe { libc::unshare(flags) })
}

/// Write the uid/gid maps for a new user namespace.
///
/// setgroups must be denied BEFORE writing gid_map, or the kernel refuses the
/// gid_map write. This ordering is a kernel requirement, not a preference.
///
/// `with_nobody` adds a second line mapping the zone's `nobody` (65534) to
/// `outer + 65534`, so files a zone creates as nobody are owned by a host uid
/// inside the zone's own range rather than by the kernel's overflow id. Only a
/// writer with CAP_SETUID in the parent namespace may map ids other than its
/// own, so this is the privileged launch only; an unprivileged launch writes
/// the single line the kernel permits.
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

/// The kernel's own answer to "may an unprivileged process create a user
/// namespace?", read from whichever knob this kernel has.
///
/// linux-hardened exposes `kernel.unprivileged_userns_clone` (0 = restricted);
/// Ubuntu's AppArmor exposes `kernel.apparmor_restrict_unprivileged_userns`
/// (1 = restricted). `None` when neither exists: a stock kernel with no
/// restriction knob, which is not the target and must not be mistaken for it.
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

/// Prove the restriction rather than read it: fork, drop to uid 65534 when
/// we are root, and try `unshare(CLONE_NEWUSER)`.
///
/// Returns `Ok(true)` when the kernel refused with EPERM (restricted),
/// `Ok(false)` when the namespace was created (not restricted), and an error
/// when the probe itself could not run. A sysctl says what is configured; this
/// says what the kernel does, which is what the privileged launch contract
/// (unprivileged user namespaces are off on the target) is about.
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
                // Become nobody with no supplementary groups: an ordinary
                // unprivileged process, which is what the rule constrains.
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

/// Die (SIGKILL) when the parent process exits.
///
/// Cleared by fork, so every process in the chain sets it for itself. Not
/// cleared by setresuid; cleared by execve of a set-id or file-capable
/// binary, which no_new_privs makes irrelevant for the zone's command.
pub fn die_with_parent() -> Result<(), IsolateError> {
    check(
        "prctl(PR_SET_PDEATHSIG)",
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) },
    )
}

// prctl(PR_SCHED_CORE) and its operations, from <linux/prctl.h>; the libc
// crate this tree pins does not name them.
const PR_SCHED_CORE: libc::c_int = 62;
const PR_SCHED_CORE_GET: libc::c_ulong = 0;
const PR_SCHED_CORE_CREATE: libc::c_ulong = 1;
const PIDTYPE_PID: libc::c_ulong = 0;

/// Give the calling task a core-scheduling cookie of its own. From then on
/// the kernel runs, on the sibling hardware threads of a core, only tasks
/// with the same cookie - every task this one forks inherits it - so a zone
/// that takes one shares a core with itself or with nothing, never with
/// another zone or the kernel's own threads. Needs no privilege: a task may
/// always cut itself off. EINVAL is a kernel built without
/// CONFIG_SCHED_CORE, which the caller treats as "nothing to isolate with".
pub fn take_core_cookie() -> io::Result<()> {
    if unsafe { libc::prctl(PR_SCHED_CORE, PR_SCHED_CORE_CREATE, 0, PIDTYPE_PID, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether this kernel has core scheduling at all: asking for the calling
/// task's cookie (zero when it has none) succeeds only where the feature is
/// built in. Harmless, so `explain` may ask.
pub fn core_scheduling_available() -> bool {
    let mut cookie: libc::c_ulong = 0;
    let rc = unsafe {
        libc::prctl(PR_SCHED_CORE, PR_SCHED_CORE_GET, 0, PIDTYPE_PID, &mut cookie as *mut libc::c_ulong as libc::c_ulong)
    };
    rc == 0
}

/// A task's core-scheduling cookie, asked of the kernel: 0 for a task that
/// has none. Nothing in /proc shows it (no kernel prints `core_cookie` in
/// /proc/<pid>/sched), so this prctl is the one readout. Another task's
/// cookie needs ptrace-read access to it, which root has everywhere and a
/// user has over the zones it launched (it owns their user namespace).
/// EINVAL is a kernel without CONFIG_SCHED_CORE.
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

/// One word for `kryptikd status`: whether a zone's pid 1 is cut off from
/// every other cookie on the machine.
pub fn core_cookie_word(pid: libc::pid_t) -> &'static str {
    match core_cookie_of(pid) {
        Ok(0) => "none",
        Ok(_) => "own",
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => "unavailable",
        Err(_) => "unreadable",
    }
}

/// Set the hostname in the current UTS namespace. Needs CAP_SYS_ADMIN in
/// the user namespace that owns it - which the zone's root has once the id
/// maps are written.
pub fn set_hostname(name: &str) -> Result<(), IsolateError> {
    check("sethostname", unsafe {
        libc::sethostname(name.as_ptr() as *const libc::c_char, name.len())
    })
}

/// Drop every supplementary group. Needs CAP_SETGID in the CURRENT user
/// namespace: works for a privileged kryptikd before it creates the zone's
/// namespace, fails with EPERM for an unprivileged one (which then cannot
/// drop them at all, since setgroups is denied inside the new namespace).
pub fn drop_supplementary_groups() -> Result<(), IsolateError> {
    check("setgroups", unsafe { libc::setgroups(0, std::ptr::null()) })
}

/// How many supplementary groups this process carries.
pub fn supplementary_group_count() -> usize {
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n < 0 { 0 } else { n as usize }
}

/// Bring up loopback inside the zone's network namespace.
///
/// Even an air-gapped zone needs `lo`: plenty of software fails in confusing
/// ways without it, and loopback inside a private netns reaches nothing.
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

    // `as _`, not a named type. ioctl(2)'s request argument is c_ulong in
    // glibc's binding and c_int in musl's, and SIOCSIFFLAGS is typed to match
    // each one - so naming either type here compiles on one libc and fails on
    // the other. Inferring it from the signature compiles on both, which is
    // what building a static kryptikd for the initramfs needs.
    // Every ioctl request is a 32-bit value (the kernel's sys_ioctl takes an
    // `unsigned int cmd`), so narrowing to musl's c_int cannot drop a bit for
    // any valid request number - including _IOR-encoded ones with bit 31 set,
    // which become negative c_ints with identical bits. The assert states that
    // invariant rather than leaving it to be re-derived, since `as _` is
    // silent about it. Recommended by the security review of 2026-09-11.
    const _: () = assert!((libc::SIOCSIFFLAGS as u64) <= u32::MAX as u64);
    let ret = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) };
    unsafe { libc::close(sock) };
    check("ioctl(SIOCSIFFLAGS)", ret)
}

/// Report which isolation mechanisms this kernel actually provides.
///
/// Used by `kryptikd check` and by the test suite so a missing mechanism is
/// visible rather than inferred from a zone that happens to start.
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

    /// Everything the zone model depends on.
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

    /// A task can cut itself off, and its parent can see that it did: after
    /// PR_SCHED_CORE_CREATE the child's cookie, read from the parent by
    /// PR_SCHED_CORE_GET, is non-zero and differs from the parent's own,
    /// which stays zero. Read from outside on purpose - that is how
    /// `kryptikd status` and the launcher suite look at a zone - in a forked
    /// child that pauses until it is read, so the test process keeps
    /// sharing cores with the rest of the suite. On a kernel without
    /// CONFIG_SCHED_CORE there is nothing to take and the test says so.
    #[test]
    fn a_task_can_take_a_core_cookie_of_its_own() {
        if !core_scheduling_available() {
            eprintln!("no core scheduling on this kernel; skipping");
            return;
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
    fn every_zone_gets_a_network_namespace_the_nic_zone_included() {
        assert_ne!(namespace_flags(&zone("none")) & libc::CLONE_NEWNET, 0);
        assert_ne!(namespace_flags(&zone("routed")) & libc::CLONE_NEWNET, 0);
        // The nic zone owns the real interface: the parent moves it INTO the
        // zone's namespace, which has to exist. Sharing zone 0's namespace
        // (the rule at first) made the move a no-op and left the
        // NIC, the bridge and the forwarding in zone 0.
        assert_ne!(namespace_flags(&zone("nic")) & libc::CLONE_NEWNET, 0);
    }

    #[test]
    fn every_zone_gets_the_core_namespaces() {
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
