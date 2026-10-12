//! wpa_supplicant off root in the nic zone (docs/design/net-zone.md): `kryptikd supplicant`
//! starts it as its own mapped user with CAP_NET_ADMIN and CAP_NET_RAW alone, under a socket
//! filter that keeps it off nf_tables and a Landlock ruleset that keeps it to what it reads and
//! its own directory. hostap's own privilege separation carries neither SAE nor PMF
//! (docs/design/net-zone-surface.md).

use std::io;
use std::os::unix::process::CommandExt;

use crate::caps::cap;
use crate::isolate::WIFI_ID;
use crate::landlock;

/// Its own directory, which rootfs.rs makes for `WIFI_ID`: the control socket and pid files.
pub const RUN_DIR: &str = "/run/wpa_supplicant";

/// nl80211 and interface flags take CAP_NET_ADMIN, EAPOL's packet socket CAP_NET_RAW.
pub const CAPS: [libc::c_int; 2] = [cap::NET_ADMIN, cap::NET_RAW];

/// Become the supplicant's user with `CAPS` alone, confined, and exec `argv`. Returns only on
/// failure, with what failed.
pub fn exec(argv: &[String]) -> String {
    match confine() {
        Err(e) => e,
        Ok(()) => format!("{}: {}", argv[0], std::process::Command::new(&argv[0]).args(&argv[1..]).exec()),
    }
}

fn confine() -> Result<(), String> {
    // Built while every path it names can still be opened.
    let rules = ruleset()?;
    let os = |call: &str| format!("{call}: {}", io::Error::last_os_error());
    // SAFETY: plain calls on this process's credentials; none touches memory.
    unsafe {
        // Permitted capabilities outlive the change of uid; ambient ones are raised after it.
        if libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0 {
            return Err(os("prctl(PR_SET_KEEPCAPS)"));
        }
        if libc::setgroups(0, std::ptr::null()) < 0 {
            return Err(os("setgroups"));
        }
        if libc::setgid(WIFI_ID) < 0 {
            return Err(os("setgid"));
        }
        if libc::setuid(WIFI_ID) < 0 {
            return Err(os("setuid"));
        }
    }
    set_caps(&CAPS)?;
    for c in CAPS {
        let raised = unsafe {
            libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong, c as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong)
        };
        if raised < 0 {
            return Err(os("prctl(PR_CAP_AMBIENT_RAISE)"));
        }
    }
    rules.restrict_self().map_err(|e| e.to_string())?;
    crate::seccomp::install_supplicant_filter().map_err(|e| e.to_string())
}

/// Read and run what the system paths hold, read its configuration and the kernel's views, use
/// the devices it opens, and write nowhere but `RUN_DIR`.
fn ruleset() -> Result<landlock::Ruleset, String> {
    let mut r = landlock::Ruleset::new().map_err(|e| e.to_string())?;
    /* A rule covers what is reached through its path, and each system path is a bind of its
     * own: the loader comes by /lib64 and libraries by /lib, which a rule on /usr does not
     * cover. One the zone lacks is skipped, as the zone skips it. */
    for path in crate::rootfs::SYSTEM_PATHS {
        if std::path::Path::new(path).is_dir() {
            r.allow(path, landlock::ACCESS_READ | landlock::ACCESS_EXEC).map_err(|e| format!("{path}: {e}"))?;
        }
    }
    for (path, access) in [
        ("/etc", landlock::ACCESS_READ),
        ("/proc", landlock::ACCESS_READ),
        ("/sys", landlock::ACCESS_READ),
        // /dev/null for daemon(3), /dev/random and /dev/urandom for its entropy.
        ("/dev", landlock::ACCESS_READ | landlock::ACCESS_WRITE_FILE),
        (RUN_DIR, landlock::ACCESS_READ | landlock::ACCESS_WRITE),
    ] {
        r.allow(path, access).map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(r)
}

/// Effective, permitted and inheritable sets all `caps`: capset narrows what the process holds.
fn set_caps(caps: &[libc::c_int]) -> Result<(), String> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    // _LINUX_CAPABILITY_VERSION_3: two words of each set.
    let header = Header { version: 0x2008_0522, pid: 0 };
    let mut data = [Data::default(); 2];
    for &c in caps {
        let (word, bit) = ((c / 32) as usize, 1u32 << (c % 32));
        data[word].effective |= bit;
        data[word].permitted |= bit;
        data[word].inheritable |= bit;
    }
    if unsafe { libc::syscall(libc::SYS_capset, &header as *const Header, data.as_ptr()) } < 0 {
        return Err(format!("capset: {}", io::Error::last_os_error()));
    }
    Ok(())
}
