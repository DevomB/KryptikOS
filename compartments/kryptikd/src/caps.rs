//! Zone capability bounding set: everything is dropped but `CAP_NET_BIND_SERVICE` and what
//! the zone's policy keeps from `KEEPABLE`.

use std::io;

/// Capability numbers from `linux/capability.h` (stable ABI; `libc` lacks them).
#[allow(dead_code)]
pub(crate) mod cap {
    use libc::c_int;
    pub const CHOWN: c_int = 0;
    pub const DAC_OVERRIDE: c_int = 1;
    pub const DAC_READ_SEARCH: c_int = 2;
    pub const FOWNER: c_int = 3;
    pub const FSETID: c_int = 4;
    pub const KILL: c_int = 5;
    pub const SETGID: c_int = 6;
    pub const SETUID: c_int = 7;
    pub const NET_BIND_SERVICE: c_int = 10;
    pub const NET_BROADCAST: c_int = 11;
    pub const NET_ADMIN: c_int = 12;
    pub const NET_RAW: c_int = 13;
    pub const IPC_LOCK: c_int = 14;
    pub const SYS_MODULE: c_int = 16;
    pub const SYS_CHROOT: c_int = 18;
    pub const SYS_PTRACE: c_int = 19;
    pub const SYS_ADMIN: c_int = 21;
    pub const SYS_NICE: c_int = 23;
    pub const MKNOD: c_int = 27;
}

/// Always kept: binding a low port inside the zone's own namespace is harmless.
pub const KEEP: libc::c_int = cap::NET_BIND_SERVICE;

/// What a zone policy may keep (`keep-capability CAP_X`): each is scoped to the zone's own
/// namespaces, processes or files.
pub const KEEPABLE: &[libc::c_int] = &[
    cap::NET_BIND_SERVICE, cap::NET_ADMIN, cap::NET_RAW, cap::NET_BROADCAST,
    cap::SYS_NICE, cap::IPC_LOCK, cap::KILL, cap::CHOWN, cap::FOWNER, cap::FSETID,
    cap::DAC_READ_SEARCH, cap::SETUID, cap::SETGID, cap::SYS_CHROOT,
];

/// What a daemon needs to drop to a user of its own (dhcpcd's privilege separation): kept
/// together or not at all, and each opens the calls `seccomp::CAP_CALLS` names.
pub const PRIVSEP: &[libc::c_int] = &[cap::SETUID, cap::SETGID, cap::SYS_CHROOT];

pub fn keeps_privsep(keep: &[libc::c_int]) -> bool {
    PRIVSEP.iter().all(|c| keep.contains(c))
}

/// Capability numbers by name, as linux/capability.h defines them.
pub const CAP_NAMES: &[(&str, libc::c_int)] = &[
    ("CAP_CHOWN", 0), ("CAP_DAC_OVERRIDE", 1), ("CAP_DAC_READ_SEARCH", 2), ("CAP_FOWNER", 3),
    ("CAP_FSETID", 4), ("CAP_KILL", 5), ("CAP_SETGID", 6), ("CAP_SETUID", 7), ("CAP_SETPCAP", 8),
    ("CAP_LINUX_IMMUTABLE", 9), ("CAP_NET_BIND_SERVICE", 10), ("CAP_NET_BROADCAST", 11),
    ("CAP_NET_ADMIN", 12), ("CAP_NET_RAW", 13), ("CAP_IPC_LOCK", 14), ("CAP_IPC_OWNER", 15),
    ("CAP_SYS_MODULE", 16), ("CAP_SYS_RAWIO", 17), ("CAP_SYS_CHROOT", 18), ("CAP_SYS_PTRACE", 19),
    ("CAP_SYS_PACCT", 20), ("CAP_SYS_ADMIN", 21), ("CAP_SYS_BOOT", 22), ("CAP_SYS_NICE", 23),
    ("CAP_SYS_RESOURCE", 24), ("CAP_SYS_TIME", 25), ("CAP_SYS_TTY_CONFIG", 26), ("CAP_MKNOD", 27),
    ("CAP_LEASE", 28), ("CAP_AUDIT_WRITE", 29), ("CAP_AUDIT_CONTROL", 30), ("CAP_SETFCAP", 31),
    ("CAP_MAC_OVERRIDE", 32), ("CAP_MAC_ADMIN", 33), ("CAP_SYSLOG", 34), ("CAP_WAKE_ALARM", 35),
    ("CAP_BLOCK_SUSPEND", 36), ("CAP_AUDIT_READ", 37), ("CAP_PERFMON", 38), ("CAP_BPF", 39),
    ("CAP_CHECKPOINT_RESTORE", 40),
];

/// Only the nic zone may keep these (`policy::check_for_zone`): another zone could use the
/// network ones to re-address its veth or forge frames, and only dhcpcd there needs `PRIVSEP`.
pub const NIC_ONLY: &[libc::c_int] = &[cap::NET_ADMIN, cap::NET_RAW, cap::SETUID, cap::SETGID, cap::SYS_CHROOT];

pub fn cap_by_name(name: &str) -> Option<libc::c_int> {
    CAP_NAMES.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

pub fn cap_name(cap: libc::c_int) -> &'static str {
    CAP_NAMES.iter().find(|(_, v)| *v == cap).map(|(n, _)| *n).unwrap_or("CAP_?")
}

/// Highest capability the running kernel defines, so ones newer than our table are dropped too.
fn last_cap() -> libc::c_int {
    match std::fs::read_to_string("/proc/sys/kernel/cap_last_cap") {
        Ok(s) => s.trim().parse().unwrap_or(40),
        // Sweeping to 63 costs a few failed prctls and cannot miss one.
        Err(_) => 63,
    }
}

#[derive(Debug)]
pub struct CapError {
    pub cap: libc::c_int,
    pub errno: i32,
}

impl std::fmt::Display for CapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "prctl(PR_CAPBSET_DROP, {}): {}",
            self.cap,
            io::Error::from_raw_os_error(self.errno)
        )
    }
}

/// Drop every bounding-set capability but `KEEP` and the `KEEPABLE` ones in `keep`.
pub fn drop_bounding_set_except(keep: &[libc::c_int]) -> Result<(), CapError> {
    let last = last_cap();
    for cap in 0..=last {
        if cap == KEEP || (keep.contains(&cap) && KEEPABLE.contains(&cap)) {
            continue;
        }
        // SAFETY: PR_CAPBSET_DROP takes an integer and touches no memory.
        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
        if rc < 0 {
            let e = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            // EINVAL: the kernel has no such capability.
            if e == libc::EINVAL {
                continue;
            }
            return Err(CapError { cap, errno: e });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
