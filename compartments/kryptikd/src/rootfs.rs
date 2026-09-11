//! Building a real zone root with pivot_root.
//!
//! WHY THIS EXISTS
//!
//! Zones originally ran in the caller's mount namespace with Landlock as the
//! only filesystem control. That was not isolation, and an adversarial review
//! demonstrated two escapes against it without touching a kernel bug:
//!
//!   * an inherited file descriptor read a file outside the zone, because
//!     Landlock does not revoke descriptors that were already open when the
//!     ruleset was applied;
//!   * chmod changed the mode of a file outside the zone, because Landlock
//!     ABI 3 has no right governing metadata changes and the zone's uid maps
//!     to the launching user, who owns those files.
//!
//! Both have the same root cause: outside paths still EXISTED in the zone's
//! mount namespace. A path-based permission layer cannot fix that, because the
//! problem is not permission, it is reachability.
//!
//! pivot_root replaces the zone's root with a tree containing only what the
//! zone is meant to see. Landlock then becomes defense in depth over a much
//! smaller surface rather than the only thing standing between zones.

use std::ffi::CString;
use std::io;

#[derive(Debug)]
pub enum RootfsError {
    Syscall { call: &'static str, path: String, errno: i32 },
    Setup(String),
}

impl std::fmt::Display for RootfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RootfsError::Syscall { call, path, errno } => write!(
                f,
                "{call}({path}): {}",
                io::Error::from_raw_os_error(*errno)
            ),
            RootfsError::Setup(m) => write!(f, "{m}"),
        }
    }
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn cs(s: &str) -> Result<CString, RootfsError> {
    CString::new(s).map_err(|_| RootfsError::Setup(format!("path contains NUL: {s}")))
}

fn mount_raw(
    src: &str,
    target: &str,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
    call: &'static str,
) -> Result<(), RootfsError> {
    let c_src = cs(src)?;
    let c_tgt = cs(target)?;
    let c_fst = match fstype {
        Some(f) => Some(cs(f)?),
        None => None,
    };
    let c_data = match data {
        Some(d) => Some(cs(d)?),
        None => None,
    };

    let ret = unsafe {
        libc::mount(
            c_src.as_ptr(),
            c_tgt.as_ptr(),
            c_fst.as_ref().map_or(std::ptr::null(), |f| f.as_ptr()),
            flags,
            c_data
                .as_ref()
                .map_or(std::ptr::null(), |d| d.as_ptr() as *const libc::c_void),
        )
    };
    if ret < 0 {
        return Err(RootfsError::Syscall {
            call,
            path: target.to_string(),
            errno: errno(),
        });
    }
    Ok(())
}

/// Bind-mount `src` at `target`, read-only.
///
/// TWO calls, and the second is not redundant. A bind mount SILENTLY IGNORES
/// MS_RDONLY on the initial call - it inherits the source's flags - so a
/// one-call version produces a writable mount that reads as read-only in the
/// code. The flag only takes effect on a subsequent remount.
fn bind_ro(src: &str, target: &str) -> Result<(), RootfsError> {
    std::fs::create_dir_all(target)
        .map_err(|e| RootfsError::Setup(format!("{target}: {e}")))?;
    mount_raw(src, target, None, libc::MS_BIND | libc::MS_REC, None, "mount(bind)")?;
    mount_raw(
        "none",
        target,
        None,
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_REC
            | libc::MS_NOSUID | libc::MS_NODEV,
        None,
        "mount(remount,ro)",
    )
}

/// System directories a zone needs in order to run ordinary programs.
///
/// Read-only, nosuid, nodev. A zone gets the system's binaries and libraries
/// but cannot modify them, and cannot gain privilege through a setuid binary
/// it finds there.
const SYSTEM_PATHS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"];

/// Device nodes a zone is allowed. Anything not listed does not exist for it.
///
/// This replaces inheriting the caller's /dev wholesale, which was granting
/// far more than a zone should have - every disk, every tty, every input
/// device on the machine.
const DEVICES: &[(&str, &str)] = &[
    ("/dev/null", "null"),
    ("/dev/zero", "zero"),
    ("/dev/full", "full"),
    ("/dev/random", "random"),
    ("/dev/urandom", "urandom"),
    ("/dev/tty", "tty"),
];

/// Replace the zone's root with a tree containing only what it should see.
///
/// Must be called after unshare(CLONE_NEWNS) and after the uid map is written,
/// because pivot_root needs CAP_SYS_ADMIN in the new user namespace. Must be
/// called BEFORE the Landlock ruleset and the seccomp filter: both mount() and
/// pivot_root() are absent from the zone syscall allowlist, deliberately, so
/// doing this afterwards would kill the zone during its own construction.
pub fn pivot_into(rootfs: &str) -> Result<(), RootfsError> {
    // The whole tree must be private first, or every mount below propagates
    // back to the host namespace.
    mount_raw(
        "none",
        "/",
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
        "mount(private)",
    )?;

    // pivot_root requires new_root to be a mount point, and a plain directory
    // is not one. Bind it onto itself.
    mount_raw(
        rootfs,
        rootfs,
        None,
        libc::MS_BIND | libc::MS_REC,
        None,
        "mount(self-bind)",
    )?;

    // --- populate the new root ------------------------------------------
    for p in SYSTEM_PATHS {
        let target = format!("{rootfs}{p}");
        // A path missing on the host is skipped rather than fatal: /lib64 does
        // not exist everywhere.
        if std::path::Path::new(p).exists() {
            bind_ro(p, &target)?;
        }
    }

    // Fresh /proc, showing only this zone's pid namespace.
    let proc_dir = format!("{rootfs}/proc");
    std::fs::create_dir_all(&proc_dir).map_err(|e| RootfsError::Setup(e.to_string()))?;
    mount_raw(
        "proc",
        &proc_dir,
        Some("proc"),
        (libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV) as libc::c_ulong,
        None,
        "mount(proc)",
    )?;

    // Fresh sysfs, showing only this zone's network namespace. Read-only: a
    // zone has no business writing to /sys.
    let sys_dir = format!("{rootfs}/sys");
    std::fs::create_dir_all(&sys_dir).map_err(|e| RootfsError::Setup(e.to_string()))?;
    // Can legitimately fail in a nested namespace; sysfs is informational and
    // the network namespace is the actual control.
    let _ = mount_raw(
        "sysfs",
        &sys_dir,
        Some("sysfs"),
        (libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV | libc::MS_RDONLY)
            as libc::c_ulong,
        None,
        "mount(sysfs)",
    );

    // A minimal /dev on tmpfs, with exactly the nodes in DEVICES bind-mounted
    // in. Creating them with mknod would need real CAP_MKNOD on the host;
    // bind-mounting the host's nodes achieves the same visibility without it.
    let dev_dir = format!("{rootfs}/dev");
    std::fs::create_dir_all(&dev_dir).map_err(|e| RootfsError::Setup(e.to_string()))?;
    mount_raw(
        "tmpfs",
        &dev_dir,
        Some("tmpfs"),
        (libc::MS_NOSUID | libc::MS_NOEXEC) as libc::c_ulong,
        Some("mode=0755,size=1M"),
        "mount(dev tmpfs)",
    )?;
    for (host, name) in DEVICES {
        if !std::path::Path::new(host).exists() {
            continue;
        }
        let target = format!("{dev_dir}/{name}");
        std::fs::File::create(&target).map_err(|e| RootfsError::Setup(e.to_string()))?;
        // Device nodes are bound individually; a failure here is not fatal,
        // but a zone without /dev/null behaves very strangely, so say so.
        if mount_raw(host, &target, None, libc::MS_BIND, None, "mount(dev node)").is_err() {
            eprintln!("kryptikd: warning: could not provide {host} to the zone");
        }
    }

    // Private /tmp. Without this a zone shares the host's, which is a
    // cross-zone channel and a classic symlink-attack surface.
    let tmp_dir = format!("{rootfs}/tmp");
    std::fs::create_dir_all(&tmp_dir).map_err(|e| RootfsError::Setup(e.to_string()))?;
    mount_raw(
        "tmpfs",
        &tmp_dir,
        Some("tmpfs"),
        (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
        Some("mode=1777"),
        "mount(tmp)",
    )?;

    // --- pivot ------------------------------------------------------------
    let old_root = format!("{rootfs}/.oldroot");
    std::fs::create_dir_all(&old_root).map_err(|e| RootfsError::Setup(e.to_string()))?;

    let c_new = cs(rootfs)?;
    let c_old = cs(&old_root)?;
    let ret = unsafe {
        libc::syscall(libc::SYS_pivot_root, c_new.as_ptr(), c_old.as_ptr())
    };
    if ret < 0 {
        return Err(RootfsError::Syscall {
            call: "pivot_root",
            path: rootfs.to_string(),
            errno: errno(),
        });
    }

    let root = cs("/")?;
    if unsafe { libc::chdir(root.as_ptr()) } < 0 {
        return Err(RootfsError::Syscall {
            call: "chdir",
            path: "/".into(),
            errno: errno(),
        });
    }

    // Detach the old root. Until this runs the entire host filesystem is still
    // mounted at /.oldroot and the zone can simply walk into it - which would
    // make everything above pointless.
    let c_oldmount = cs("/.oldroot")?;
    if unsafe { libc::umount2(c_oldmount.as_ptr(), libc::MNT_DETACH) } < 0 {
        return Err(RootfsError::Syscall {
            call: "umount2",
            path: "/.oldroot".into(),
            errno: errno(),
        });
    }
    let _ = std::fs::remove_dir("/.oldroot");

    Ok(())
}

/// Close every descriptor above stderr before handing control to the zone.
///
/// The other half of the inherited-descriptor escape. Landlock governs paths,
/// not descriptors already open when the ruleset is applied, so a caller that
/// leaks an fd hands the zone a direct read into whatever it points at - which
/// is exactly how a file outside the zone was read during review.
///
/// pivot_root alone does not fix this: an open descriptor keeps working
/// regardless of what the mount namespace now looks like.
pub fn close_inherited_fds() {
    // /proc/self/fd is authoritative; fall back to a bounded sweep if reading
    // it fails, since guessing low is worse than closing a few spare numbers.
    let max = match std::fs::read_dir("/proc/self/fd") {
        Ok(entries) => {
            let mut fds: Vec<i32> = entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok()))
                .collect();
            fds.sort_unstable();
            for fd in fds {
                if fd > 2 {
                    unsafe { libc::close(fd) };
                }
            }
            return;
        }
        Err(_) => 4096,
    };
    for fd in 3..max {
        unsafe { libc::close(fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_paths_are_absolute() {
        for p in SYSTEM_PATHS {
            assert!(p.starts_with('/'), "{p} must be absolute");
        }
    }

    #[test]
    fn device_list_is_minimal_and_safe() {
        // A zone gets character devices that carry no data about the host.
        // Anything granting access to real hardware - disks, input devices,
        // the kernel's memory - must never appear here.
        for (host, _) in DEVICES {
            assert!(host.starts_with("/dev/"), "{host} is not under /dev");
            for banned in ["mem", "kmem", "port", "sda", "nvme", "input", "kvm"] {
                assert!(
                    !host.contains(banned),
                    "{host} exposes hardware a zone must not reach"
                );
            }
        }
    }

    #[test]
    fn close_inherited_fds_leaves_stdio_alone() {
        // Closing 0,1,2 would break the zone before it starts.
        close_inherited_fds();
        for fd in 0..=2 {
            let r = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(r >= 0, "fd {fd} was closed and must not have been");
        }
    }
}
