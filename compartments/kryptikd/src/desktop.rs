//! The desktop's compositor as the launch daemon starts it for a login (compositor separation,
//! docs/design/compositor-separation.md). dwl runs in the desktop's cgroup as the user, with the
//! login's groups less `kryptik` and no new privileges, so neither the daemon's socket nor the
//! mixer's control socket is within its reach. The session keeps what needs the group: the
//! spawner, which serves dwl's keys, and the chrome it starts. The session hands dwl three
//! descriptors: its socket to the spawner (3), the chrome's end of its status (stdout), and the
//! session's log (stderr).

use std::ffi::CString;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::path::Path;

/// What the session may set in dwl's environment: the keymap. The rest is the daemon's.
const KEYMAP: [&str; 6] = [
    "XKB_DEFAULT_RULES",
    "XKB_DEFAULT_MODEL",
    "XKB_DEFAULT_LAYOUT",
    "XKB_DEFAULT_VARIANT",
    "XKB_DEFAULT_OPTIONS",
    "KRYPTIK_LAYOUTS",
];
/// close_range's flag that marks the range close-on-exec instead of closing it.
const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;

/// A `desktop` request: `env NAME=VALUE` lines for the keymap, then `end`.
pub fn parse(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut lines = text.lines();
    if lines.next() != Some("desktop") {
        return Err("expected `desktop`".into());
    }
    let mut env: Vec<(String, String)> = Vec::new();
    for l in lines {
        if l == "end" {
            return Ok(env);
        }
        let (name, value) = l
            .strip_prefix("env ")
            .and_then(|kv| kv.split_once('='))
            .ok_or_else(|| format!("desktop: unexpected line {l:?}"))?;
        if !KEYMAP.contains(&name) {
            return Err(format!("desktop: {name} is not dwl's to be given"));
        }
        if env.iter().any(|(n, _)| n == name) {
            return Err(format!("desktop: {name} twice"));
        }
        // What xkbcommon reads: names, lists and options, nothing a shell or a path needs.
        if value.len() > 256 || !value.chars().all(|c| c.is_ascii_alphanumeric() || " ,:_-+().".contains(c)) {
            return Err(format!("desktop: {name} is not a keymap's"));
        }
        env.push((name.to_string(), value.to_string()));
    }
    Err("desktop: no `end`".into())
}

/// dwl's whole environment: the runtime directory the daemon made, pixman (the only renderer
/// built), the cursors of the verified root, and the session's keymap.
pub fn environment(runtime: &Path, keymap: &[(String, String)]) -> Vec<String> {
    let mut env = vec![
        format!("XDG_RUNTIME_DIR={}", runtime.display()),
        "WLR_RENDERER=pixman".to_string(),
        "XCURSOR_PATH=/usr/share/icons".to_string(),
    ];
    env.extend(keymap.iter().map(|(n, v)| format!("{n}={v}")));
    env
}

/// The real uid, the real gid and the groups in a process's status.
pub fn ids_of(status: &str) -> Option<(u32, u32, Vec<u32>)> {
    fn field<'a>(status: &'a str, name: &str) -> Option<&'a str> {
        status.lines().find_map(|l| l.strip_prefix(name)).map(str::trim)
    }
    let first = |v: &str| -> Option<u32> { v.split_whitespace().next()?.parse().ok() };
    let uid = first(field(status, "Uid:")?)?;
    let gid = first(field(status, "Gid:")?)?;
    let groups = field(status, "Groups:")?.split_whitespace().map(|g| g.parse().ok()).collect::<Option<Vec<u32>>>()?;
    Some((uid, gid, groups))
}

/// The login's groups less `kryptik`: dwl's.
pub fn groups_without(groups: &[u32], kryptik: u32) -> Vec<u32> {
    groups.iter().copied().filter(|&g| g != kryptik).collect()
}

/// The descriptors the session hands over, in its order.
pub struct Handed {
    spawner: OwnedFd,
    status: OwnedFd,
    log: OwnedFd,
}

/// A descriptor's file type and access mode.
fn kind_of(fd: RawFd) -> Option<(libc::mode_t, libc::c_int)> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat and fcntl on a descriptor the caller owns.
    let flags = unsafe {
        if libc::fstat(fd, &mut st) != 0 {
            return None;
        }
        libc::fcntl(fd, libc::F_GETFL)
    };
    (flags >= 0).then_some((st.st_mode & libc::S_IFMT, flags & libc::O_ACCMODE))
}

/// An int-sized socket option.
fn sock_int(fd: RawFd, opt: libc::c_int) -> Option<libc::c_int> {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: an int-sized option read into an int.
    let r = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, opt, &mut v as *mut libc::c_int as *mut libc::c_void, &mut len) };
    (r == 0).then_some(v)
}

/// The three descriptors, each the kind it should be: a Unix SOCK_SEQPACKET socket (the
/// spawner's), a pipe's write end (dwl's status), and a file, pipe or terminal open for writing
/// (the log).
pub fn handed(fds: Vec<OwnedFd>) -> Result<Handed, String> {
    let Ok([spawner, status, log]) = <[OwnedFd; 3]>::try_from(fds) else {
        return Err("desktop: three descriptors: the spawner's socket, dwl's status and the log".into());
    };
    let s = spawner.as_raw_fd();
    let socket = kind_of(s).is_some_and(|(m, _)| m == libc::S_IFSOCK);
    if !socket || sock_int(s, libc::SO_DOMAIN) != Some(libc::AF_UNIX) || sock_int(s, libc::SO_TYPE) != Some(libc::SOCK_SEQPACKET) {
        return Err("desktop: the first descriptor is not a Unix SOCK_SEQPACKET socket".into());
    }
    if !kind_of(status.as_raw_fd()).is_some_and(|(m, a)| m == libc::S_IFIFO && a == libc::O_WRONLY) {
        return Err("desktop: the second descriptor is not a pipe's write end".into());
    }
    let writes = |(m, a): (libc::mode_t, libc::c_int)| {
        [libc::S_IFREG, libc::S_IFIFO, libc::S_IFCHR].contains(&m) && (a == libc::O_WRONLY || a == libc::O_RDWR)
    };
    if !kind_of(log.as_raw_fd()).is_some_and(writes) {
        return Err("desktop: the third descriptor is not a file, pipe or terminal open for writing".into());
    }
    Ok(Handed { spawner, status, log })
}

/// Start dwl for `uid`'s login, as `gid` with `groups`, moved into the cgroup whose cgroup.procs
/// is `procs`, with the environment `env`: forked, and in the child the descriptors, the cgroup,
/// the ids and the exec. The child's pid; a child that cannot become dwl says why on `err` and
/// exits 126.
pub fn start(uid: u32, gid: u32, groups: &[u32], procs: &Path, env: &[String], h: Handed, err: RawFd) -> Result<libc::pid_t, String> {
    let env = env.iter().map(|e| CString::new(e.as_str())).collect::<Result<Vec<_>, _>>().map_err(|_| "dwl's environment holds a NUL".to_string())?;
    // SAFETY: getpid cannot fail.
    let daemon = unsafe { libc::getpid() };
    // SAFETY: the daemon runs one thread, so the child may do what the parent would.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        // SAFETY: a copy of `err` above 9, where placing dwl's descriptors cannot reach it.
        let err = unsafe { libc::fcntl(err, libc::F_DUPFD_CLOEXEC, 10) };
        let why = become_dwl(&h, uid, gid, groups, procs, daemon, &env);
        // SAFETY: the child ends here, running nothing more of the daemon's.
        unsafe {
            libc::write(err, why.as_ptr() as *const libc::c_void, why.len());
            libc::_exit(126)
        }
    }
    Ok(pid)
}

/// In the forked child: dwl's descriptors (stdin /dev/null, its status as stdout, the log as
/// stderr, the spawner's socket as 3), its cgroup, the login's ids less group kryptik, then the
/// exec. Returns only why it could not.
fn become_dwl(h: &Handed, uid: u32, gid: u32, groups: &[u32], procs: &Path, daemon: libc::pid_t, env: &[CString]) -> String {
    let os = |what: &str| format!("{what}: {}", std::io::Error::last_os_error());
    unsafe {
        libc::setsid();
        // Copies above 9 first, so placing one cannot overwrite another; dup2 clears close-on-exec.
        let high = [h.status.as_raw_fd(), h.log.as_raw_fd(), h.spawner.as_raw_fd()].map(|fd| libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10));
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
        if null < 0 || high.iter().any(|&fd| fd < 0) || libc::dup2(null, 0) < 0 || (0..3).any(|i| libc::dup2(high[i], 1 + i as RawFd) < 0) {
            return os("dwl's descriptors");
        }
        // The rest close at the exec, which the reason's descriptor stays open until.
        if libc::syscall(libc::SYS_close_range, 4 as libc::c_uint, libc::c_uint::MAX, CLOSE_RANGE_CLOEXEC) < 0 {
            return os("close_range");
        }
    }
    // Moved in by itself while still root.
    if let Err(e) = std::fs::write(procs, std::process::id().to_string()) {
        return format!("{}: {e}", procs.display());
    }
    unsafe {
        if libc::setgroups(groups.len() as _, groups.as_ptr()) < 0 || libc::setresgid(gid, gid, gid) < 0 || libc::setresuid(uid, uid, uid) < 0 {
            return os("taking the login's ids less group kryptik");
        }
        if libc::getuid() != uid || libc::geteuid() != uid || libc::getgid() != gid || libc::getegid() != gid {
            return format!("still uid {} gid {} after taking {uid}", libc::geteuid(), libc::getegid());
        }
        // Gone with the daemon, which answers for the login: set after the ids, which clear it.
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM as libc::c_ulong) < 0 || libc::getppid() != daemon {
            return "the daemon ended before dwl started".into();
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
            return os("prctl(PR_SET_NO_NEW_PRIVS)");
        }
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        if libc::chdir(c"/".as_ptr()) < 0 {
            return os("chdir /");
        }
    }
    let argv: [*const libc::c_char; 4] = [c"dwl".as_ptr(), c"-S".as_ptr(), c"3".as_ptr(), std::ptr::null()];
    let mut envp: Vec<*const libc::c_char> = env.iter().map(|e| e.as_ptr()).collect();
    envp.push(std::ptr::null());
    unsafe { libc::execve(c"/usr/bin/dwl".as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    os("exec /usr/bin/dwl")
}

#[cfg(test)]
mod tests;
