//! A zone's Wayland proxy as a user of its own (docs/design/compositor-separation.md). The launch
//! daemon starts it for a session: as the uid at the top of the zone's block, which no zone maps,
//! in an empty network namespace and a cgroup of its own, under the zones' seccomp filter, and
//! with Landlock leaving it no file but its own program. A developer instance keeps its own uid
//! and makes neither the namespace nor the cgroup.

use std::ffi::CString;
use std::fs;
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileTypeExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::io::{AsRawFd as _, RawFd};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use crate::cgroup::Cgroup;
use crate::zone::Zone;

/// The most memory one proxy holds: its clients' queues both ways, their objects and descriptors.
const MEMORY_MAX: &str = "128M";
/// Clients one proxy serves at once.
const MAX_CLIENTS: &str = "32";

/// The proxy's uid and gid for a zone whose root maps to `uid_base`: the top of its block, which
/// no zone maps (a zone maps 0 and 65534 of its block, the nic zone 100 and 101 too).
pub fn uid_for(uid_base: u32) -> u32 {
    uid_base + 65535
}

/// Where `session`'s proxy for `zone` listens, under `run` (/run/kryptik, or a developer
/// instance's directory): in a directory of the zone's that only root enters, so the zone reaches
/// the socket through the bind into its tree, and nothing else reaches it at all.
pub fn socket_path(run: &Path, session: u32, zone: &str) -> PathBuf {
    run.join("proxy").join(session.to_string()).join(zone).join("wayland-0")
}

/// The proxy's log, which the session reads.
pub fn log_path(run: &Path, session: u32, zone: &str) -> PathBuf {
    run.join("proxy").join(session.to_string()).join(format!("{zone}.log"))
}

/// Where dwl serves `zone` for `session`: the proxy's upstream.
pub fn upstream_path(run: &Path, session: u32, zone: &str) -> PathBuf {
    run.join("compositor").join(session.to_string()).join(zone)
}

/// A running proxy. Its cgroup goes, with anything left in it, when this is dropped.
pub struct Proxy {
    pub session: u32,
    pub zone: String,
    pub pid: libc::pid_t,
    pub socket: PathBuf,
    _cgroup: Option<Cgroup>,
}

fn is_socket(p: &Path) -> bool {
    fs::symlink_metadata(p).map(|m| m.file_type().is_socket()).unwrap_or(false)
}

/// Start `zone`'s proxy, the program `exe`, for `session`'s compositor. As `root`, the child
/// becomes the zone's proxy uid in an empty network namespace and a cgroup of its own.
pub fn start(run: &Path, exe: &Path, session: u32, zone: &Zone, root: bool) -> Result<Proxy, String> {
    let upstream = upstream_path(run, session, &zone.name);
    if !is_socket(&upstream) {
        return Err(format!("no compositor serves zone {:?} for uid {session}: {} is no socket", zone.name, upstream.display()));
    }
    let uid = match (root, zone.uid_base) {
        (false, _) => None,
        (true, Some(base)) => Some(uid_for(base)),
        (true, None) => return Err(format!("zone {:?} declares no uid_base, so its proxy has no uid of its own", zone.name)),
    };
    let sock = socket_path(run, session, &zone.name);
    let zdir = sock.parent().ok_or("the proxy's socket has no directory")?;
    let sdir = zdir.parent().ok_or("the proxy's socket has no session directory")?;
    fs::create_dir_all(zdir).map_err(|e| format!("{}: {e}", zdir.display()))?;
    // The session's directory holds the logs; the zone's is root's alone.
    for (d, mode) in [(sdir.parent().unwrap_or(sdir), 0o755), (sdir, 0o755), (zdir, 0o700)] {
        fs::set_permissions(d, fs::Permissions::from_mode(mode)).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let _ = fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).map_err(|e| format!("{}: {e}", sock.display()))?;
    // Whichever of the zone's uids a program runs as connects through the bind.
    fs::set_permissions(&sock, fs::Permissions::from_mode(0o666)).map_err(|e| format!("{}: {e}", sock.display()))?;
    let log_path = log_path(run, session, &zone.name);
    let log = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o640)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&log_path)
        .map_err(|e| format!("{}: {e}", log_path.display()))?;
    if root {
        // The session reads its proxy's log; the proxy writes it through the descriptor.
        std::os::unix::fs::fchown(&log, Some(session), None).map_err(|e| format!("{}: {e}", log_path.display()))?;
    }
    let cgroup = if root {
        let base = crate::cgroup::available().map_err(|e| e.to_string())?;
        let name = format!("proxy-{}", zone.name);
        let cg = match Cgroup::create(&base, &name, session as i32) {
            Ok(cg) => cg,
            Err(_) => {
                // A proxy a daemon that died left behind holds the leaf (`<name>.<session>`): it goes.
                let _ = fs::write(base.join(format!("{name}.{session}")).join("cgroup.kill"), "1");
                std::thread::sleep(std::time::Duration::from_millis(200));
                Cgroup::create(&base, &name, session as i32).map_err(|e| e.to_string())?
            }
        };
        // One process, which starts none, in no more memory than its clients' queues need.
        cg.set_limits(Some(MEMORY_MAX), Some(1), None, None).map_err(|e| e.to_string())?;
        Some(cg)
    } else {
        None
    };
    let up = upstream.to_string_lossy().into_owned();
    let words = ["kryptik-wlproxy", "--zone", zone.name.as_str(), "--listen-fd", "3", "--upstream", up.as_str(), "--max-clients", MAX_CLIENTS];
    let argv = words.iter().map(|w| CString::new(*w).map_err(|_| format!("{w:?} holds a NUL"))).collect::<Result<Vec<_>, _>>()?;
    let cexe = CString::new(exe.as_os_str().as_bytes()).map_err(|_| "the proxy's path holds a NUL".to_string())?;
    let exe_s = exe.to_str().ok_or("the proxy's path is not UTF-8")?;
    let procs = cgroup.as_ref().map(|c| c.path().join("cgroup.procs"));

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        let why = become_proxy(listener.as_raw_fd(), log.as_raw_fd(), procs.as_deref(), uid, exe_s, &cexe, &argv);
        let _ = writeln!(std::io::stderr(), "kryptikd: zone {}'s proxy: {why}", zone.name);
        unsafe { libc::_exit(126) }
    }
    Ok(Proxy { session, zone: zone.name.clone(), pid, socket: sock, _cgroup: cgroup })
}

/// In the forked child: the proxy's descriptors, cgroup, namespace, ids and confinement, then the
/// exec. Returns only why it could not.
fn become_proxy(
    listener: RawFd,
    log: RawFd,
    procs: Option<&Path>,
    uid: Option<u32>,
    exe: &str,
    cexe: &CString,
    argv: &[CString],
) -> String {
    let os = |what: &str| format!("{what}: {}", std::io::Error::last_os_error());
    unsafe {
        libc::setsid();
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
        if null < 0 || libc::dup2(null, 0) < 0 || libc::dup2(log, 1) < 0 || libc::dup2(log, 2) < 0 {
            return os("stdio");
        }
        // The listener is descriptor 3; dup2 onto itself would leave close-on-exec set.
        if (listener != 3 && libc::dup2(listener, 3) < 0) || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
            return os("the listener");
        }
        if libc::syscall(libc::SYS_close_range, 4 as libc::c_uint, libc::c_uint::MAX, 0 as libc::c_uint) < 0 {
            return os("close_range");
        }
    }
    if let Some(p) = procs {
        // Moved in by itself while still root.
        if let Err(e) = fs::write(p, std::process::id().to_string()) {
            return format!("{}: {e}", p.display());
        }
    }
    if let Some(u) = uid {
        unsafe {
            if libc::unshare(libc::CLONE_NEWNET) < 0 {
                return os("unshare(CLONE_NEWNET)");
            }
            if libc::setgroups(0, std::ptr::null()) < 0 || libc::setresgid(u, u, u) < 0 || libc::setresuid(u, u, u) < 0 {
                return os("taking the proxy's ids");
            }
            if libc::getuid() != u || libc::geteuid() != u || libc::getgid() != u || libc::getegid() != u {
                return format!("still uid {} gid {} after taking {u}", libc::geteuid(), libc::getegid());
            }
        }
    }
    let ruled = crate::landlock::Ruleset::new().and_then(|mut r| {
        r.allow(exe, crate::landlock::ACCESS_EXEC)?;
        /* The installed proxy is static, so it needs nothing more. A developer's is built against
         * the host's libraries, which its loader reads: the system directories that are not links
         * (a link resolves into /usr, which is one). */
        if uid.is_none() {
            for p in crate::rootfs::SYSTEM_PATHS {
                if fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()) {
                    r.allow(p, crate::landlock::ACCESS_READ | crate::landlock::ACCESS_EXEC)?;
                }
            }
        }
        r.restrict_self()
    });
    if let Err(e) = ruled {
        return format!("Landlock: {e}");
    }
    if let Err(e) = crate::seccomp::confine_zone() {
        return format!("seccomp: {e}");
    }
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    unsafe { libc::execve(cexe.as_ptr(), ptrs.as_ptr(), envp.as_ptr()) };
    os(&format!("exec {exe}"))
}

#[cfg(test)]
mod tests;
