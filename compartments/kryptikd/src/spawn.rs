//! Zone spawning: create a zone and run something inside it.
//!
//! This is what turns kryptikd from a validator into a compartment manager.
//! Until now the Phase 5 exit test drove the isolation primitives with
//! `unshare(1)`, which proved the primitives were sound but said nothing about
//! whether kryptikd applies them correctly. This module is what the test can
//! attack instead.
//!
//! ORDER IS THE WHOLE THING. Each step below depends on the ones before it,
//! and several of the dependencies are not obvious. They are written down next
//! to the code rather than left to be rediscovered.

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;

use crate::isolate;
use crate::landlock;
use crate::seccomp;
use crate::zone::{StorageMode, Zone};

#[derive(Debug)]
pub enum SpawnError {
    Syscall { call: &'static str, errno: i32 },
    Setup(String),
    Confine(String),
}

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpawnError::Syscall { call, errno } => {
                write!(f, "{call}: {}", io::Error::from_raw_os_error(*errno))
            }
            SpawnError::Setup(m) => write!(f, "{m}"),
            SpawnError::Confine(m) => write!(f, "confinement failed: {m}"),
        }
    }
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// A one-byte pipe used to order the parent and child against each other.
///
/// The child cannot write its own uid_map — that requires privilege in the
/// PARENT user namespace — so it must stop and wait while the parent does it.
/// Getting this ordering wrong produces a zone running as nobody (65534)
/// instead of root, and every subsequent step then fails for reasons that
/// look unrelated.
struct SyncPipe {
    read: RawFd,
    write: RawFd,
}

impl SyncPipe {
    fn new() -> Result<Self, SpawnError> {
        let mut fds = [0 as RawFd; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
            return Err(SpawnError::Syscall { call: "pipe", errno: errno() });
        }
        Ok(SyncPipe { read: fds[0], write: fds[1] })
    }

    fn signal(&self) {
        let b = [1u8];
        unsafe { libc::write(self.write, b.as_ptr() as *const libc::c_void, 1) };
    }

    fn wait(&self) {
        let mut b = [0u8];
        unsafe { libc::read(self.read, b.as_mut_ptr() as *mut libc::c_void, 1) };
    }

    fn close_read(&self) { unsafe { libc::close(self.read) }; }
    fn close_write(&self) { unsafe { libc::close(self.write) }; }
}

/// Where a zone's filesystem lives on the host.
pub fn zone_rootfs(zone: &Zone, base: &str) -> String {
    format!("{base}/{}", zone.name)
}

/// Create the zone and execute `argv` inside it. Returns the child's exit code.
///
/// The caller must be able to create a user namespace. kryptikd proper runs
/// privileged in zone 0, but this path works unprivileged too, which is what
/// lets the adversarial test run it as an ordinary user.
pub fn run_in_zone(zone: &Zone, rootfs: &str, argv: &[String]) -> Result<i32, SpawnError> {
    if argv.is_empty() {
        return Err(SpawnError::Setup("no command given".into()));
    }

    // Landlock is not optional. A zone without filesystem confinement can read
    // every other zone, which is requirement 2 of the exit test - so refuse to
    // start rather than start something weaker than a zone.
    if landlock::abi_version().is_none() {
        return Err(SpawnError::Confine(
            "landlock unavailable on this kernel; refusing to start an unconfined zone".into(),
        ));
    }

    std::fs::create_dir_all(rootfs)
        .map_err(|e| SpawnError::Setup(format!("{rootfs}: {e}")))?;

    let outer_uid = unsafe { libc::getuid() };
    let outer_gid = unsafe { libc::getgid() };

    let sync = SyncPipe::new()?;
    let flags = isolate::namespace_flags(zone);

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(SpawnError::Syscall { call: "fork", errno: errno() });
    }

    if pid == 0 {
        // --- child -----------------------------------------------------------
        sync.close_write();
        let rc = child_main(zone, rootfs, argv, &sync);
        // Never return: this process must not run the parent's cleanup.
        unsafe { libc::_exit(rc) };
    }

    // --- parent --------------------------------------------------------------
    sync.close_read();

    // Map the child's root to our uid. This is what makes "root inside the
    // zone" mean root in a namespace that owns nothing outside it.
    if let Err(e) = isolate::write_id_maps(pid, outer_uid, outer_gid) {
        // Release the child so it dies rather than blocking forever on the pipe.
        sync.signal();
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        return Err(SpawnError::Setup(format!("id maps: {e}")));
    }

    sync.signal();
    sync.close_write();

    let mut status: libc::c_int = 0;
    if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        return Err(SpawnError::Syscall { call: "waitpid", errno: errno() });
    }

    Ok(decode_status(status))
}

fn decode_status(status: libc::c_int) -> i32 {
    if (status & 0x7f) == 0 {
        (status >> 8) & 0xff
    } else {
        // Killed by a signal; report it the way a shell does.
        128 + (status & 0x7f)
    }
}

/// Everything that happens inside the zone. Returns the exit code.
fn child_main(zone: &Zone, rootfs: &str, argv: &[String], sync: &SyncPipe) -> i32 {
    macro_rules! bail {
        ($($arg:tt)*) => {{
            eprintln!("kryptikd[zone {}]: {}", zone.name, format!($($arg)*));
            return 125;
        }};
    }

    let flags = isolate::namespace_flags(zone);

    // 1. Enter the new namespaces.
    if let Err(e) = isolate::unshare_namespaces(flags) {
        bail!("unshare: {e}");
    }

    // 2. Wait for the parent to write uid_map/gid_map. Until it does we are
    //    nobody (65534) and cannot mount anything.
    sync.wait();

    // 3. Become root in the new user namespace.
    if unsafe { libc::setresuid(0, 0, 0) } < 0 {
        bail!("setresuid: {}", io::Error::last_os_error());
    }
    if unsafe { libc::setresgid(0, 0, 0) } < 0 {
        bail!("setresgid: {}", io::Error::last_os_error());
    }

    // 4. CLONE_NEWPID does not move the CALLER into the new pid namespace -
    //    only its children. Fork so the grandchild becomes pid 1 there. Without
    //    this the zone shares the host pid namespace despite having asked for
    //    its own, and /proc shows every process on the machine.
    let inner = unsafe { libc::fork() };
    if inner < 0 {
        bail!("fork: {}", io::Error::last_os_error());
    }

    if inner > 0 {
        // Intermediate process: just reap pid 1 of the zone and mirror its code.
        let mut status: libc::c_int = 0;
        unsafe { libc::waitpid(inner, &mut status, 0) };
        return decode_status(status);
    }

    // --- we are now pid 1 inside the zone ---------------------------------

    // 5. Make mounts private BEFORE mounting anything, or every mount below
    //    propagates back to the host mount namespace and the isolation is
    //    decorative.
    if let Err(e) = isolate::make_mounts_private() {
        bail!("mount private: {e}");
    }

    // 6. A fresh /proc, so the pid namespace is actually visible. Skipping this
    //    leaves the host /proc mounted and the zone can enumerate every process
    //    even though its pid namespace is correct.
    if let Err(e) = isolate::mount_proc("") {
        bail!("mount /proc: {e}");
    }

    // 7. A fresh sysfs. The network namespace denies USE of host interfaces,
    //    but without this /sys/class/net still lists them - free reconnaissance.
    if let Err(e) = isolate::mount_sysfs("") {
        // Non-fatal: a read-only sysfs can fail in odd environments, and the
        // network namespace is the actual control. Say so rather than hide it.
        eprintln!("kryptikd[zone {}]: warning: sysfs remount failed: {e}", zone.name);
    }

    // 8. Loopback, for zones that have a network namespace at all.
    if flags & libc::CLONE_NEWNET != 0 {
        if let Err(e) = isolate::bring_up_loopback() {
            eprintln!("kryptikd[zone {}]: warning: lo did not come up: {e}", zone.name);
        }
    }

    // 9. Filesystem confinement. After the mounts, because Landlock is
    //    evaluated against the mount tree as it stands when the ruleset is
    //    applied.
    let extra: Vec<&str> = vec!["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"];
    if let Err(e) = landlock::confine_to_zone(rootfs, &extra) {
        bail!("landlock: {e}");
    }

    // 10. Syscall filtering, LAST. It must come after every privileged setup
    //     step above, because mount() and friends are not in the allowlist -
    //     installing the filter earlier would kill the zone during its own
    //     construction.
    if let Err(e) = seccomp::confine_zone() {
        bail!("seccomp: {e}");
    }

    // 11. Hand off.
    let prog = match CString::new(argv[0].as_str()) {
        Ok(c) => c,
        Err(_) => bail!("command contains a NUL byte"),
    };
    let args: Vec<CString> = argv
        .iter()
        .filter_map(|a| CString::new(a.as_str()).ok())
        .collect();
    let mut ptrs: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());

    unsafe { libc::execvp(prog.as_ptr(), ptrs.as_ptr()) };

    // execvp only returns on failure.
    eprintln!(
        "kryptikd[zone {}]: exec {:?}: {}",
        zone.name,
        argv[0],
        io::Error::last_os_error()
    );
    127
}

/// Describe what starting this zone would do, without doing it.
pub fn explain(zone: &Zone, rootfs: &str) -> String {
    let flags = isolate::namespace_flags(zone);
    let mut ns = Vec::new();
    for (f, n) in [
        (libc::CLONE_NEWUSER, "user"),
        (libc::CLONE_NEWNS, "mount"),
        (libc::CLONE_NEWPID, "pid"),
        (libc::CLONE_NEWIPC, "ipc"),
        (libc::CLONE_NEWUTS, "uts"),
        (libc::CLONE_NEWCGROUP, "cgroup"),
        (libc::CLONE_NEWNET, "net"),
    ] {
        if flags & f != 0 {
            ns.push(n);
        }
    }

    let storage = match zone.storage {
        StorageMode::Encrypted => format!(
            "encrypted volume {} (NOT YET IMPLEMENTED - using a plain directory)",
            zone.volume.as_deref().unwrap_or("?")
        ),
        StorageMode::Ephemeral => "ephemeral (NOT YET IMPLEMENTED - using a plain directory)".into(),
    };

    format!(
        "zone       {}\n\
         namespaces {}\n\
         rootfs     {}\n\
         storage    {}\n\
         landlock   confined to rootfs + read-only system paths\n\
         seccomp    default-deny, {} syscalls allowed",
        zone.name,
        ns.join(", "),
        rootfs,
        storage,
        seccomp::BASE_ALLOWLIST.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::Zone;

    fn z(mode: &str) -> Zone {
        let bridge = if mode == "nic" { "bridge = \"kryptik0\"\n" } else { "" };
        Zone::from_str(&format!(
            "[zone]\nname = \"t\"\n[network]\nmode = \"{mode}\"\n{bridge}\
             [storage]\nmode = \"ephemeral\"\n[ui]\nborder_color = \"#123456\"\n"
        ))
        .unwrap()
    }

    #[test]
    fn rootfs_path_is_under_the_base() {
        assert_eq!(zone_rootfs(&z("routed"), "/var/lib/kryptik/zones"),
                   "/var/lib/kryptik/zones/t");
    }

    #[test]
    fn explain_names_the_namespaces_and_is_honest_about_storage() {
        let e = explain(&z("none"), "/tmp/t");
        assert!(e.contains("user"), "{e}");
        assert!(e.contains("net"), "{e}");
        // Storage is not implemented, and explain must say so rather than
        // implying a zone gets an encrypted volume today.
        assert!(e.contains("NOT YET IMPLEMENTED"), "{e}");
    }

    #[test]
    fn exit_status_decoding_matches_shell_convention() {
        assert_eq!(decode_status(0), 0);
        assert_eq!(decode_status(3 << 8), 3);
        assert_eq!(decode_status(libc::SIGSYS), 128 + libc::SIGSYS);
    }
}
