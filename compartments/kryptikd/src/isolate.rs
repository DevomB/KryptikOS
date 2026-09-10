//! Zone isolation primitives: namespaces, seccomp, Landlock, cgroups.
//!
//! This is the code the Phase 5 exit test attacks. Everything here is a direct
//! syscall via `libc` rather than a helper crate, because these calls are the
//! security boundary and their exact arguments matter (ADR-010).
//!
//! ORDERING IS LOAD-BEARING. Isolation is applied in a fixed order and the
//! reasons are written next to each step. Reordering these without
//! understanding why will produce a zone that looks isolated and is not.

use std::ffi::CString;
use std::io;

use crate::zone::{NetworkMode, Zone};

/// Namespaces a zone always gets.
///
/// CLONE_NEWUSER is first in the constant but NOT optional: it is what allows
/// the remaining namespaces to be created and what makes "root inside the zone"
/// mean something weaker than root outside it. The Phase 5 exit test runs as
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
pub fn namespace_flags(zone: &Zone) -> libc::c_int {
    match zone.network {
        // The NIC-holding zone stays in the host network namespace: it is the
        // zone that owns the real interface. Everything else gets its own.
        NetworkMode::Nic => ZONE_NAMESPACES,
        NetworkMode::None | NetworkMode::Routed => ZONE_NAMESPACES | NS_NET,
    }
}

/// Drop the ability to gain privilege through execve.
///
/// MUST be called before seccomp: without no_new_privs, a seccomp filter can be
/// installed only by a privileged process, and a setuid binary executed later
/// could regain what the filter was meant to remove. This is also what makes
/// the filter survive execve.
pub fn set_no_new_privs() -> Result<(), IsolateError> {
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    check("prctl(PR_SET_NO_NEW_PRIVS)", ret)
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
pub fn write_id_maps(pid: libc::pid_t, outer_uid: u32, outer_gid: u32) -> Result<(), IsolateError> {
    use std::fs;

    let deny = format!("/proc/{pid}/setgroups");
    fs::write(&deny, "deny")
        .map_err(|e| IsolateError::Refused(format!("{deny}: {e}")))?;

    let uid_map = format!("/proc/{pid}/uid_map");
    fs::write(&uid_map, format!("0 {outer_uid} 1\n"))
        .map_err(|e| IsolateError::Refused(format!("{uid_map}: {e}")))?;

    let gid_map = format!("/proc/{pid}/gid_map");
    fs::write(&gid_map, format!("0 {outer_gid} 1\n"))
        .map_err(|e| IsolateError::Refused(format!("{gid_map}: {e}")))?;

    Ok(())
}

/// Make mount propagation private.
///
/// Without this, mounts performed inside the zone propagate back to the host
/// mount namespace and the filesystem isolation is decorative. This is the
/// single easiest thing to omit and the hardest to notice.
pub fn make_mounts_private() -> Result<(), IsolateError> {
    let root = CString::new("/").unwrap();
    let none = CString::new("none").unwrap();
    let ret = unsafe {
        libc::mount(
            none.as_ptr(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    check("mount(MS_REC|MS_PRIVATE)", ret)
}

/// Mount a fresh /proc so the zone sees only its own pid namespace.
///
/// Without this the zone inherits the host's /proc and can enumerate every
/// process on the system - defeating requirement (1) of the Phase 5 exit test
/// even though the pid namespace itself is correct.
pub fn mount_proc(root: &str) -> Result<(), IsolateError> {
    let target = CString::new(format!("{root}/proc"))
        .map_err(|e| IsolateError::Refused(e.to_string()))?;
    let proc_fs = CString::new("proc").unwrap();
    let ret = unsafe {
        libc::mount(
            proc_fs.as_ptr(),
            target.as_ptr(),
            proc_fs.as_ptr(),
            (libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    check("mount(proc)", ret)
}

/// Mount a fresh sysfs so the zone sees only its own network namespace.
///
/// Found by the Phase 5 adversarial test. A network namespace isolates the
/// interfaces a zone can USE, but sysfs is not re-instantiated by unshare, so
/// without this the zone reads the host's /sys/class/net and can enumerate
/// every interface on the machine — docker0, eth0, the lot.
///
/// It cannot send packets through them, so this is not a containment break.
/// It is reconnaissance: a compromised `untrusted` zone learns the host's
/// network topology for free. Requirement 3 of the exit test treats that as a
/// failure, and so should we.
///
/// Must be called AFTER unshare(CLONE_NEWNET), or the fresh sysfs is
/// instantiated against the old namespace and shows the same interfaces.
pub fn mount_sysfs(root: &str) -> Result<(), IsolateError> {
    let target = CString::new(format!("{root}/sys"))
        .map_err(|e| IsolateError::Refused(e.to_string()))?;
    let sysfs = CString::new("sysfs").unwrap();
    let ret = unsafe {
        libc::mount(
            sysfs.as_ptr(),
            target.as_ptr(),
            sysfs.as_ptr(),
            (libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV | libc::MS_RDONLY)
                as libc::c_ulong,
            std::ptr::null(),
        )
    };
    check("mount(sysfs)", ret)
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

    let ret = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS, &ifr) };
    unsafe { libc::close(sock) };
    check("ioctl(SIOCSIFFLAGS)", ret)
}

// --- Landlock ---------------------------------------------------------------
//
// Landlock is applied by the process itself and cannot be removed, which is why
// the architecture leans on it (ADR-007). These are raw syscall numbers because
// glibc does not wrap them.

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

/// Query the Landlock ABI version the running kernel supports.
///
/// Returns None when Landlock is unavailable. kryptikd must treat that as a
/// hard error at zone start rather than continuing without filesystem policy -
/// silently running a zone with one fewer control is exactly the failure this
/// project keeps finding elsewhere.
pub fn landlock_abi_version() -> Option<i32> {
    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<u8>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if ret < 0 {
        None
    } else {
        Some(ret as i32)
    }
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
            landlock: landlock_abi_version(),
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
             [storage]\nmode = \"ephemeral\"\n[ui]\nborder_color = \"#123456\"\n"
        ))
        .unwrap()
    }

    #[test]
    fn non_nic_zones_get_a_network_namespace() {
        assert_ne!(namespace_flags(&zone("none")) & libc::CLONE_NEWNET, 0);
        assert_ne!(namespace_flags(&zone("routed")) & libc::CLONE_NEWNET, 0);
    }

    #[test]
    fn the_nic_zone_does_not_get_its_own_netns() {
        // It owns the real interface; isolating it from itself is meaningless.
        assert_eq!(namespace_flags(&zone("nic")) & libc::CLONE_NEWNET, 0);
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
