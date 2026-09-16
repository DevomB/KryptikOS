//! The zone's capability bounding set.
//!
//! WHY THIS EXISTS
//!
//! A zone's root is root *in its own user namespace*. Every capability it
//! holds is scoped to objects that namespace owns, and every capability-gated
//! syscall that reaches outside it - the mount family, `setns`, `unshare`,
//! `clone` with a namespace flag, `bpf`, `keyctl`, module loading, `reboot`,
//! `ptrace` - is already denied by the seccomp filter. So the set has been
//! inert, and leaving it full was a defensible place to stop.
//!
//! That stops being true the moment a zone owns a real network interface.
//! `CAP_NET_ADMIN` and `CAP_NET_RAW` in a namespace holding one end of a veth
//! are not scoped to anything harmless: they let a compromised zone re-address
//! its own link, forge a source MAC, and open a raw socket on a segment it
//! shares with the bridge. The security review of 2026-09-11 calls dropping
//! the bounding set a **precondition** for the routed-network milestone rather
//! than a follow-up to it, and that is this file.
//!
//! WHAT IS KEPT, AND WHY ONLY THAT
//!
//! `CAP_NET_BIND_SERVICE` alone. A zoned application may legitimately listen
//! on a port below 1024 inside its own network namespace, and nothing outside
//! that namespace can reach the port except through the topology kryptikd
//! builds. Everything else is dropped.
//!
//! WHAT THIS DOES NOT DO
//!
//! Dropping the bounding set does not remove capabilities from the current
//! process's *effective* or *permitted* sets - it removes them from the set
//! that can ever be regained. A process that already holds a capability keeps
//! it until it drops it or execs. That is why this runs immediately before
//! `execvp`: after the exec the payload starts with nothing, and the bounding
//! set is what stops it acquiring anything, including through a file
//! capability on a binary it can reach.

use std::io;

/// Capability numbers from `linux/capability.h`.
///
/// The `libc` crate does not export these - they are kernel UAPI rather than
/// libc interface - and ADR-010 keeps this binary's dependencies to `libc`
/// alone. They are stable ABI: a capability number is never reused, because
/// doing so would silently change what every existing binary's file
/// capabilities grant.
#[allow(dead_code)]
mod cap {
    use libc::c_int;
    pub const CHOWN: c_int = 0;
    pub const DAC_READ_SEARCH: c_int = 2;
    pub const FOWNER: c_int = 3;
    pub const FSETID: c_int = 4;
    pub const KILL: c_int = 5;
    pub const NET_BROADCAST: c_int = 11;
    pub const IPC_LOCK: c_int = 14;
    pub const SYS_NICE: c_int = 23;
    pub const DAC_OVERRIDE: c_int = 1;
    pub const SETGID: c_int = 6;
    pub const SETUID: c_int = 7;
    pub const SETPCAP: c_int = 8;
    pub const NET_BIND_SERVICE: c_int = 10;
    pub const NET_ADMIN: c_int = 12;
    pub const NET_RAW: c_int = 13;
    pub const SYS_MODULE: c_int = 16;
    pub const SYS_ADMIN: c_int = 21;
    pub const SYS_PTRACE: c_int = 19;
    pub const MKNOD: c_int = 27;
}

/// The one capability a zone keeps.
///
/// A zoned service may bind a privileged port inside its own network
/// namespace. Nothing outside can reach it except through the topology
/// kryptikd builds, so the port number is not a boundary and pretending it is
/// would break ordinary software for no gain.
pub const KEEP: libc::c_int = cap::NET_BIND_SERVICE;

/// Capabilities a zone POLICY may keep, by name (`keep-capability CAP_X`).
///
/// A short list on purpose: each is scoped to something the zone already
/// owns (its network namespace, its own processes, its own files) and none
/// reaches the host. `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_DAC_OVERRIDE`,
/// `CAP_SETUID`/`SETGID`, `CAP_MKNOD`, `CAP_SYS_MODULE` and everything else
/// cannot be kept by writing a line in a file.
pub const KEEPABLE: &[libc::c_int] = &[
    cap::NET_BIND_SERVICE, cap::NET_ADMIN, cap::NET_RAW, cap::NET_BROADCAST,
    cap::SYS_NICE, cap::IPC_LOCK, cap::KILL, cap::CHOWN, cap::FOWNER, cap::FSETID,
    cap::DAC_READ_SEARCH,
];

/// Every capability number the kernel defines today, by name.
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

/// The capabilities only the zone that owns the NIC may keep: with either,
/// a zone could re-address its veth, route around the bridge, or forge
/// frames on the segment (policy.rs, `check_for_zone`).
pub const NIC_ONLY: &[libc::c_int] = &[cap::NET_ADMIN, cap::NET_RAW];

pub fn cap_by_name(name: &str) -> Option<libc::c_int> {
    CAP_NAMES.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

pub fn cap_name(cap: libc::c_int) -> &'static str {
    CAP_NAMES.iter().find(|(_, v)| *v == cap).map(|(n, _)| *n).unwrap_or("CAP_?")
}

/// The highest capability this kernel knows about.
///
/// Read rather than hardcoded: the constant grows with the kernel, and a build
/// compiled against an older header would silently leave the newest
/// capabilities in the bounding set - exactly the ones least likely to have
/// been considered.
fn last_cap() -> libc::c_int {
    match std::fs::read_to_string("/proc/sys/kernel/cap_last_cap") {
        Ok(s) => s.trim().parse().unwrap_or(40),
        // Unreadable /proc means we are already confined oddly; sweeping to 63
        // costs a handful of failed prctls and cannot leave one behind.
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

/// Drop every capability from the bounding set except [`KEEP`] and those in
/// `keep`. `KEEP` is always kept; a zone policy can add from `KEEPABLE` only,
/// and that is enforced here as well as in the policy parser.
///
/// Must run AFTER every privileged setup step - the mounts and `pivot_root`
/// need `CAP_SYS_ADMIN` - and BEFORE `execvp`, so the payload can never
/// acquire what this removes.
///
/// A drop that fails is fatal rather than logged. Reporting "could not drop
/// CAP_SYS_ADMIN" and continuing would start a zone weaker than the one the
/// operator asked for, which is the failure mode this project is built to
/// avoid.
///
/// This is the only entry point. An earlier `drop_bounding_set()` with no
/// `keep` and a `bounding_set()` reader were unused once policies could keep
/// capabilities; security-relevant functions nothing calls are removed
/// rather than left for someone to call by mistake.
pub fn drop_bounding_set_except(keep: &[libc::c_int]) -> Result<(), CapError> {
    let last = last_cap();
    for cap in 0..=last {
        if cap == KEEP || (keep.contains(&cap) && KEEPABLE.contains(&cap)) {
            continue;
        }
        // SAFETY: prctl with PR_CAPBSET_DROP takes an integer and touches no
        // memory of ours.
        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
        if rc < 0 {
            let e = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            // EINVAL means this kernel has no such capability - it is above
            // cap_last_cap or was never defined. Nothing to drop.
            if e == libc::EINVAL {
                continue;
            }
            return Err(CapError { cap, errno: e });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kept_capability_is_net_bind_service_and_nothing_else() {
        // If this ever changes, it must be a deliberate edit with a reason, not
        // a drift. CAP_NET_BIND_SERVICE is 10, so the surviving set is 1 << 10.
        assert_eq!(KEEP, 10);
        assert_eq!(1u64 << KEEP, 0x400);
    }

    #[test]
    fn the_dangerous_capabilities_are_not_the_one_we_keep() {
        // A guard against someone "fixing" KEEP to something convenient.
        for dangerous in [
            cap::SYS_ADMIN,
            cap::NET_ADMIN,
            cap::NET_RAW,
            cap::SYS_MODULE,
            cap::SYS_PTRACE,
            cap::DAC_OVERRIDE,
            cap::SETUID,
            cap::SETGID,
            cap::MKNOD,
        ] {
            assert_ne!(KEEP, dangerous, "capability {dangerous} must not be kept");
        }
    }

    #[test]
    fn last_cap_is_read_from_the_kernel_and_is_sane() {
        let n = last_cap();
        // 37 is CAP_CHECKPOINT_RESTORE, present since 5.9; anything lower than
        // the caps we name above would mean we are not sweeping far enough.
        assert!(n >= cap::SYS_ADMIN, "cap_last_cap {n} is implausibly low");
        assert!(n <= 63, "cap_last_cap {n} is out of range for a u64 mask");
    }
}
