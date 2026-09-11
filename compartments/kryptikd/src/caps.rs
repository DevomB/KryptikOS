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

/// Drop every capability from the bounding set except [`KEEP`].
///
/// Must run AFTER every privileged setup step - the mounts and `pivot_root`
/// need `CAP_SYS_ADMIN` - and BEFORE `execvp`, so the payload can never
/// acquire what this removes.
///
/// A drop that fails is fatal rather than logged. Reporting "could not drop
/// CAP_SYS_ADMIN" and continuing would start a zone weaker than the one the
/// operator asked for, which is the failure mode this project is built to
/// avoid.
pub fn drop_bounding_set() -> Result<(), CapError> {
    let last = last_cap();
    for cap in 0..=last {
        if cap == KEEP {
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

/// The bounding set as the kernel reports it, for diagnostics and for
/// `explain`. Returns None where /proc is unavailable.
pub fn bounding_set() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapBnd:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
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

    #[test]
    fn the_bounding_set_is_readable_here() {
        // The accessor must work, or the launcher check that reads CapBnd
        // would silently measure nothing.
        assert!(bounding_set().is_some(), "CapBnd not readable from /proc/self/status");
    }
}
