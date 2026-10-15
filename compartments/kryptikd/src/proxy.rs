//! A zone's Wayland proxy as a user of its own (docs/design/compositor-separation.md). The launch
//! daemon starts it for a session: as the uid at the top of the zone's block, which no zone maps,
//! in network and IPC namespaces and a cgroup of its own, under a seccomp filter of its own calls,
//! and with Landlock leaving it no file but its own program. A developer instance keeps its own
//! uid, makes neither the namespaces nor the cgroup, and takes the zones' filter, as a proxy built
//! on the host loads libraries the installed one does not.

use std::ffi::CString;
use std::fs;
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::io::{AsRawFd as _, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use crate::cgroup::Cgroup;
use crate::serve::InodeId;
use crate::zone::Zone;

/// The most memory one proxy holds: its clients' queues both ways, their objects and descriptors.
const MEMORY_MAX: &str = "128M";
/// Clients one proxy serves at once.
const MAX_CLIENTS: &str = "32";
/// Its descriptors: 32 clients' sockets and queued descriptors (wlproxy's FDS_PER_SESSION, 130
/// each) and its own few, so it cannot hold its zone's dwl socket open thousands of times.
const NOFILE: libc::rlim_t = 32 * 130 + 40;

/// The proxy's uid and gid for a zone whose root maps to `uid_base`: the top of its block, which
/// no zone maps (a zone maps 0 and 65534 of its block, the nic zone 100 and 101 too).
pub fn uid_for(uid_base: u32) -> u32 {
    uid_base + 65535
}

/// Where `session`'s proxy for `zone` listens, under `run` (/run, or a developer instance's
/// directory): in a directory of the zone's that only root enters, so the zone reaches the socket
/// through the bind into its tree, and nothing else reaches it at all. Not under /run/kryptik,
/// which the zone registry keeps root's alone.
pub fn socket_path(run: &Path, session: u32, zone: &str) -> PathBuf {
    run.join("kryptik-proxy").join(session.to_string()).join(zone).join("wayland-0")
}

/// The proxy's log, which the session reads.
pub fn log_path(run: &Path, session: u32, zone: &str) -> PathBuf {
    run.join("kryptik-proxy").join(session.to_string()).join(format!("{zone}.log"))
}

/// The move gesture's socket (kryptik-wlproxy's control.rs): the session's alone, beside the
/// zone's directory and so never bound into the zone.
pub fn control_path(run: &Path, session: u32, zone: &str) -> PathBuf {
    run.join("kryptik-proxy").join(session.to_string()).join(format!("{zone}.control"))
}

/// Where dwl serves `zone` for `session`: the proxy's upstream.
pub fn upstream_path(run: &Path, session: u32, zone: &str) -> PathBuf {
    run.join("kryptik-compositor").join(session.to_string()).join(zone)
}

/// A running proxy. Its cgroup goes, with anything left in it, when this is dropped.
pub struct Proxy {
    pub session: u32,
    pub zone: String,
    pub pid: libc::pid_t,
    pub socket: PathBuf,
    /// The dwl socket it was given; another there now means dwl has started again since.
    pub upstream: InodeId,
    _cgroup: Option<Cgroup>,
}

/// dwl's socket for `zone`, opened without following a link and taken only if it is a socket the
/// session owns: the session owns the directory, and could otherwise point the proxy at another
/// user's compositor.
pub fn upstream_of(run: &Path, session: u32, zone: &str) -> Result<(OwnedFd, InodeId), String> {
    let path = upstream_path(run, session, zone);
    let none = |e: String| format!("no compositor serves zone {zone:?} for uid {session}: {e}");
    let fd = crate::serve::open_nofollow(&path, true).map_err(none)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
        return Err(none(format!("fstat: {}", std::io::Error::last_os_error())));
    }
    if st.st_uid != session {
        return Err(none(format!("{} is not the session's socket", path.display())));
    }
    Ok((fd, InodeId::of(&st)))
}

/// Start `zone`'s proxy, the program `exe`, for `session`'s compositor. As `root`, the child
/// becomes the zone's proxy uid in namespaces and a cgroup of its own.
pub fn start(run: &Path, exe: &Path, session: u32, zone: &Zone, root: bool) -> Result<Proxy, String> {
    let (up, upstream) = upstream_of(run, session, &zone.name)?;
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
    // The session's launcher alone connects to the gesture's socket, and the proxy answers no
    // other uid there either.
    let control = control_path(run, session, &zone.name);
    let _ = fs::remove_file(&control);
    let ctl = UnixListener::bind(&control).map_err(|e| format!("{}: {e}", control.display()))?;
    fs::set_permissions(&control, fs::Permissions::from_mode(0o600)).map_err(|e| format!("{}: {e}", control.display()))?;
    if root {
        std::os::unix::fs::lchown(&control, Some(session), None).map_err(|e| format!("{}: {e}", control.display()))?;
    }
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
        // No zone's name holds a dot, so no zone's leaf (`<zone>.<pid>`) is ever a proxy's.
        let name = format!("proxy.{}", zone.name);
        let me = std::process::id() as i32;
        let cg = match Cgroup::create(&base, &name, me) {
            Ok(cg) => cg,
            Err(_) => {
                // A proxy an earlier daemon left behind holds a leaf of this zone's: it goes.
                for e in fs::read_dir(&base).into_iter().flatten().flatten() {
                    if e.file_name().to_string_lossy().starts_with(&format!("{name}.")) {
                        let _ = fs::write(e.path().join("cgroup.kill"), "1");
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
                Cgroup::create(&base, &name, me).map_err(|e| e.to_string())?
            }
        };
        // One process, which starts none, in no more memory than its clients' queues need.
        cg.set_limits(Some(MEMORY_MAX), Some(1), None, None).map_err(|e| e.to_string())?;
        Some(cg)
    } else {
        None
    };
    let uid_s = session.to_string();
    let words = proxy_words(zone, &uid_s);
    let argv = words.iter().map(|w| CString::new(*w).map_err(|_| format!("{w:?} holds a NUL"))).collect::<Result<Vec<_>, _>>()?;
    let cexe = CString::new(exe.as_os_str().as_bytes()).map_err(|_| "the proxy's path holds a NUL".to_string())?;
    let exe_s = exe.to_str().ok_or("the proxy's path is not UTF-8")?;
    let procs = cgroup.as_ref().map(|c| c.path().join("cgroup.procs"));

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        let why = become_proxy([listener.as_raw_fd(), up.as_raw_fd(), ctl.as_raw_fd()], log.as_raw_fd(), procs.as_deref(), uid, exe_s, &cexe, &argv);
        let _ = writeln!(std::io::stderr(), "kryptikd: zone {}'s proxy: {why}", zone.name);
        unsafe { libc::_exit(126) }
    }
    Ok(Proxy { session, zone: zone.name.clone(), pid, socket: sock, upstream, _cgroup: cgroup })
}

/// The proxy's command line, for the session uid `uid`. The upstream goes by descriptor: a connect
/// through the link reaches the socket checked here. The idle inhibitor is let through only for a
/// zone whose file lets it hold the screen awake.
fn proxy_words<'a>(zone: &'a Zone, uid: &'a str) -> Vec<&'a str> {
    let mut w = vec![
        "kryptik-wlproxy", "--zone", zone.name.as_str(), "--listen-fd", "3", "--upstream", "/proc/self/fd/4",
        "--control-fd", "5", "--control-uid", uid, "--max-clients", MAX_CLIENTS,
    ];
    if zone.hold_awake {
        w.push("--hold-awake");
    }
    w
}

/// Kill every proxy an earlier daemon left behind, as a daemon that starts has none of its own yet:
/// one it does not know of would serve on outside one desktop at a time.
pub fn kill_leftovers() {
    let Ok(base) = crate::cgroup::available() else { return };
    for e in fs::read_dir(&base).into_iter().flatten().flatten() {
        if e.file_name().to_string_lossy().starts_with("proxy.") {
            let _ = fs::write(e.path().join("cgroup.kill"), "1");
        }
    }
}

/// Whether two descriptors are the same file.
fn same_file(a: RawFd, b: RawFd) -> bool {
    let mut sa: libc::stat = unsafe { std::mem::zeroed() };
    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
    let read = unsafe { libc::fstat(a, &mut sa) == 0 && libc::fstat(b, &mut sb) == 0 };
    read && (sa.st_dev, sa.st_ino) == (sb.st_dev, sb.st_ino)
}

/// In the forked child: the proxy's descriptors (the listener as 3, dwl's socket as 4, the move
/// gesture's socket as 5), cgroup, namespaces, limits, ids and confinement, then the exec.
/// Returns only why it could not.
fn become_proxy(
    keep: [RawFd; 3],
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
        // Copies above 9 first, so placing one cannot overwrite another; dup2 clears close-on-exec.
        let high = keep.map(|fd| libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10));
        if high.iter().any(|&fd| fd < 0) || (0..3).any(|i| libc::dup2(high[i], 3 + i as RawFd) < 0) {
            return os("the proxy's descriptors");
        }
        // The argument line names 3, 4 and 5: each is the file it says, before the rest close.
        if (0..3).any(|i| !same_file(high[i], 3 + i as RawFd)) {
            return "3, 4 and 5 are not the listener, the upstream and the gesture's socket".into();
        }
        if libc::syscall(libc::SYS_close_range, 6 as libc::c_uint, libc::c_uint::MAX, 0 as libc::c_uint) < 0 {
            return os("close_range");
        }
        let nofile = libc::rlimit { rlim_cur: NOFILE, rlim_max: NOFILE };
        if libc::setrlimit(libc::RLIMIT_NOFILE, &nofile) < 0 {
            return os("RLIMIT_NOFILE");
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
            // No network, and no SysV or POSIX IPC shared with another proxy.
            if libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWIPC) < 0 {
                return os("unshare(CLONE_NEWNET | CLONE_NEWIPC)");
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
        r.allow(exe, crate::landlock::ACCESS_EXEC | crate::landlock::ACCESS_READ_FILE)?;
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
    let filtered = if uid.is_some() { crate::seccomp::confine_proxy() } else { crate::seccomp::confine_zone() };
    if let Err(e) = filtered {
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
