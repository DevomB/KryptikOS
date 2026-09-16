//! `kryptikd serve`: the launch daemon the desktop session talks to.
//!
//! Zones are created by root. The desktop session is an ordinary user. This
//! is the one door between them: a root-owned socket, reachable by the
//! `kryptik` group, that accepts a launch request naming a zone, the
//! per-zone proxy socket the session started, and the command - plus, over
//! SCM_RIGHTS, a descriptor carrying the passphrase the trusted prompt
//! collected. The daemon checks who is asking (SO_PEERCRED), checks what
//! they ask for, and runs `kryptikd run` for them. It grants nothing the
//! command line does not: every refusal kryptikd makes still applies.
//!
//!   socket   /run/kryptik-launch/launch.sock   (root:kryptik 0660)
//!   request  one connection per request, text lines, NUL-free:
//!              run <zone> [wayland=<path>] [pass=fd]\n
//!              arg <word>\n ...            the command, one word per line
//!              end\n
//!            with pass=fd, one descriptor rides with the first bytes
//!            stop <zone>\n
//!            clipboard-move <from> <to>\n   the zone 0 gesture: give <to> a copy
//!                                          of <from>'s clipboard payload
//!            status\n
//!            info <zone>\n                 encrypted yes|no, running yes|no
//!            runtime\n                     the session's runtime directory
//!   reply    ok <launcher pid>\n  |  error: <why>\n  |  lines ... end\n
//!
//! # What `ok` means
//!
//! `ok <pid>` is sent when the zone's pid 1 exists: namespaces, identity,
//! mounts, the volume (unlocked with the passphrase that came over the
//! socket), policy and cgroup all succeeded. The launcher reports that
//! through a pipe (`kryptikd run --ready-fd`); a launcher that exits first
//! is reported with its exit status and the last line it logged. A launch
//! that reaches neither within LAUNCH_DEADLINE is reported as such. A zone
//! whose command dies at once (exec failure: 127) is caught by a short
//! settling period after readiness, so "ok" is not sent for a window that
//! was never going to appear.
//!
//! # What holds the daemon
//!
//! One request is read at a time, and a request is read for at most
//! REQUEST_DEADLINE: a client that connects and stalls holds the daemon
//! that long and no longer. Launches in flight do not hold it at all -
//! their readiness pipes are polled beside the listener.
//!
//! # Descriptors
//!
//! Every descriptor this module receives or creates is an `Fd`, closed when
//! dropped, on every path. A request may carry at most one, with its first
//! bytes; truncated control data (MSG_CTRUNC) refuses the request.
//!
//! # Developer instances
//!
//! `--socket PATH` runs an instance for tests without root: it serves only
//! its own uid, launches zones the way an unprivileged `kryptikd run`
//! does, and logs beside its socket. Everything else is the same code.

use std::ffi::{CStr, CString};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

pub const SOCKET_DIR: &str = "/run/kryptik-launch";
pub const SOCKET_PATH: &str = "/run/kryptik-launch/launch.sock";
pub const GROUP: &str = "kryptik";
/// The only program a session's proxy socket may be served by.
pub const PROXY_EXE: &str = "/usr/bin/kryptik-wlproxy";
const MAX_REQUEST: usize = 16 * 1024;
/// A request must be complete within this after the connection is accepted.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(5);
/// A zone must reach its pid 1 within this after its launcher is started.
pub const LAUNCH_DEADLINE: Duration = Duration::from_secs(30);
/// After readiness, the launcher is watched this long for an immediate
/// failure before `ok` is sent.
const SETTLE: Duration = Duration::from_millis(300);

// --- descriptors -----------------------------------------------------------

/// A descriptor this module owns. Closed when dropped, which is the one rule
/// for every descriptor here: received with a request, opened for a check,
/// or created for a launch.
#[derive(Debug)]
pub struct Fd(RawFd);

impl Fd {
    pub fn raw(&self) -> RawFd {
        self.0
    }
    /// Give up ownership: the caller closes it.
    pub fn into_raw(self) -> RawFd {
        let fd = self.0;
        std::mem::forget(self);
        fd
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe { libc::close(self.0) };
        }
    }
}

fn pipe() -> Result<(Fd, Fd), String> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(format!("pipe: {}", std::io::Error::last_os_error()));
    }
    Ok((Fd(fds[0]), Fd(fds[1])))
}

fn clear_cloexec(fd: RawFd) {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFD);
        libc::fcntl(fd, libc::F_SETFD, fl & !libc::FD_CLOEXEC);
    }
}

// --- who is asking ----------------------------------------------------------

fn gid_of_group(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    let g = unsafe { libc::getgrnam(c.as_ptr()) };
    if g.is_null() {
        None
    } else {
        Some(unsafe { (*g).gr_gid })
    }
}

fn gid_of_uid(uid: u32) -> Option<u32> {
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        None
    } else {
        Some(unsafe { (*pw).pw_gid })
    }
}

/// Is `uid` root, or a member (primary or supplementary) of `group`?
fn in_group(uid: u32, group: &str) -> bool {
    if uid == 0 {
        return true;
    }
    let Some(gid) = gid_of_group(group) else { return false };
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return false;
    }
    if unsafe { (*pw).pw_gid } == gid {
        return true;
    }
    let name = unsafe { CStr::from_ptr((*pw).pw_name) }.to_string_lossy().to_string();
    let c = CString::new(group).unwrap();
    let g = unsafe { libc::getgrnam(c.as_ptr()) };
    if g.is_null() {
        return false;
    }
    let mut mem = unsafe { (*g).gr_mem };
    unsafe {
        while !mem.is_null() && !(*mem).is_null() {
            if CStr::from_ptr(*mem).to_string_lossy() == name {
                return true;
            }
            mem = mem.add(1);
        }
    }
    false
}

struct Peer {
    uid: u32,
    pid: i32,
}

fn peer_of(fd: RawFd) -> Option<Peer> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut libc::c_void, &mut len) };
    if r == 0 {
        Some(Peer { uid: cred.uid, pid: cred.pid })
    } else {
        None
    }
}

// --- the request -------------------------------------------------------------

/// Whether the bytes so far are a whole request. Single-line verbs end at
/// their newline; `run` ends at its `end` line.
fn request_complete(text: &[u8]) -> bool {
    if !text.ends_with(b"\n") {
        return false;
    }
    if text.starts_with(b"run ") {
        text.ends_with(b"\nend\n")
    } else {
        true
    }
}

/// Read the request text and any descriptor that came with it, within
/// `deadline`. At most one descriptor, and only with the first bytes.
fn recv_request(fd: RawFd, deadline: Instant) -> Result<(Vec<u8>, Option<Fd>), String> {
    let mut text = Vec::new();
    let mut carried: Option<Fd> = None;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(format!("request not completed within {} s", REQUEST_DEADLINE.as_secs()));
        }
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let r = unsafe { libc::poll(&mut pfd, 1, left.as_millis().min(i32::MAX as u128) as i32) };
        if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("poll: {e}"));
        }
        if r == 0 {
            continue; // the deadline check above reports it
        }
        let mut buf = [0u8; 4096];
        // Room for four descriptors: enough to see an excess and refuse it
        // by count rather than by truncation.
        let mut cmsg = [0u8; 64];
        let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg.len() as _;
        let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("recvmsg: {e}"));
        }
        // Take ownership of whatever arrived before deciding anything, so a
        // refusal below closes it.
        let mut got: Vec<Fd> = Vec::new();
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                    let data = libc::CMSG_DATA(c) as *const RawFd;
                    let count = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / std::mem::size_of::<RawFd>();
                    for i in 0..count {
                        got.push(Fd(*data.add(i)));
                    }
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
        }
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err("control data truncated: more descriptors than a request may carry".into());
        }
        if !got.is_empty() {
            if !text.is_empty() {
                return Err("a descriptor must accompany the first bytes of a request".into());
            }
            if got.len() > 1 || carried.is_some() {
                return Err(format!("at most one descriptor per request, got {}", got.len() + usize::from(carried.is_some())));
            }
            carried = got.pop();
        }
        if n == 0 {
            break;
        }
        text.extend_from_slice(&buf[..n as usize]);
        if text.len() > MAX_REQUEST {
            return Err("request too long".into());
        }
        if text.contains(&0) {
            return Err("request contains NUL".into());
        }
        if request_complete(&text) {
            break;
        }
    }
    Ok((text, carried))
}

fn ident_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

struct Request {
    zone: String,
    wayland: Option<PathBuf>,
    wants_fd: bool,
    argv: Vec<String>,
}

fn parse_run(text: &str) -> Result<Request, String> {
    let mut lines = text.lines();
    let first = lines.next().ok_or("empty request")?;
    let mut w = first.split_whitespace();
    if w.next() != Some("run") {
        return Err("expected `run`".into());
    }
    let zone = w.next().ok_or("run: zone name missing")?.to_string();
    if !ident_ok(&zone) {
        return Err(format!("run: zone name {zone:?} is not a plain identifier"));
    }
    let mut req = Request { zone, wayland: None, wants_fd: false, argv: Vec::new() };
    for opt in w {
        if let Some(p) = opt.strip_prefix("wayland=") {
            req.wayland = Some(PathBuf::from(p));
        } else if opt == "pass=fd" {
            req.wants_fd = true;
        } else {
            return Err(format!("run: unknown option {opt:?}"));
        }
    }
    let mut ended = false;
    for l in lines {
        if l == "end" {
            ended = true;
            break;
        }
        match l.strip_prefix("arg ") {
            Some(a) => req.argv.push(a.to_string()),
            None => return Err(format!("run: unexpected line {l:?}")),
        }
    }
    if !ended {
        return Err("run: request not terminated by `end`".into());
    }
    if req.argv.is_empty() {
        return Err("run: no command".into());
    }
    Ok(req)
}

// --- the proxy socket ----------------------------------------------------------

fn fstat(fd: RawFd) -> Result<libc::stat, String> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } < 0 {
        return Err(format!("fstat: {}", std::io::Error::last_os_error()));
    }
    Ok(st)
}

/// Open one path component under `dir` without following a symlink.
fn openat_component(dir: RawFd, name: &str, flags: libc::c_int) -> Result<Fd, String> {
    let c = CString::new(name).map_err(|_| "NUL in path".to_string())?;
    let fd = unsafe { libc::openat(dir, c.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(format!("{name}: {}", std::io::Error::last_os_error()));
    }
    Ok(Fd(fd))
}

/// The proxy socket a session may hand to a zone: exactly
/// `/run/user/<uid>/kryptik/<zone>/wayland-0`, reached one component at a
/// time without following a symlink; the `<uid>` directory owned by the
/// session, `kryptik/` and `<zone>/` owned by it and private; the socket a
/// socket owned by it; and the process listening on it a kryptik-wlproxy
/// started for that zone (its peer credentials and command line).
///
/// Returns an O_PATH descriptor to the socket's inode, which is what the
/// launcher gets: a path can be renamed under a check, an inode cannot.
/// A verified proxy socket: the descriptor pins the inode for as long as
/// the launch is being set up; the launcher is told the path and the inode
/// and opens the path itself, refusing a different inode, then stages it
/// where its child can reach it after `unshare` (spawn.rs, StagedSocket).
#[derive(Debug)]
pub struct ProxySocket {
    pub fd: Fd,
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
}

/// Open `path` one component at a time without following any symlink, as
/// O_PATH. Directories along the way must be directories; the last
/// component must be a socket when `want_socket`.
pub fn open_nofollow(path: &Path, want_socket: bool) -> Result<Fd, String> {
    if !path.is_absolute() {
        return Err(format!("{}: not an absolute path", path.display()));
    }
    let mut dir = openat_component(libc::AT_FDCWD, "/", libc::O_PATH | libc::O_DIRECTORY)?;
    let comps: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(n) => Some(n.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();
    let n = comps.len();
    for (i, comp) in comps.iter().enumerate() {
        let last = i + 1 == n;
        let flags = if last { libc::O_PATH } else { libc::O_PATH | libc::O_DIRECTORY };
        let next = openat_component(dir.raw(), comp, flags).map_err(|e| format!("{}: {e}", path.display()))?;
        if last && want_socket {
            let st = fstat(next.raw())?;
            if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
                return Err(format!("{}: not a socket", path.display()));
            }
        }
        dir = next;
    }
    Ok(dir)
}

fn verify_proxy_socket(p: &Path, uid: u32, zone: &str, proxy_exe: Option<&Path>) -> Result<ProxySocket, String> {
    let want = PathBuf::from(format!("/run/user/{uid}/kryptik/{zone}/wayland-0"));
    if p != want {
        return Err(format!("wayland socket must be {}", want.display()));
    }
    let root = openat_component(libc::AT_FDCWD, "/", libc::O_PATH | libc::O_DIRECTORY)?;
    let mut dir = root;
    let uid_s = uid.to_string();
    for (i, comp) in ["run", "user", uid_s.as_str(), "kryptik", zone].iter().enumerate() {
        let next = openat_component(dir.raw(), comp, libc::O_PATH | libc::O_DIRECTORY)
            .map_err(|e| format!("wayland socket path: {e}"))?;
        if i >= 2 {
            let st = fstat(next.raw())?;
            if st.st_uid != uid {
                return Err(format!("wayland socket path: {comp}/ is owned by uid {}, not the session", st.st_uid));
            }
            if i >= 3 && st.st_mode & 0o077 != 0 {
                return Err(format!("wayland socket path: {comp}/ is not private (mode {:o})", st.st_mode & 0o7777));
            }
        }
        dir = next;
    }
    let sock = openat_component(dir.raw(), "wayland-0", libc::O_PATH).map_err(|e| format!("wayland socket: {e}"))?;
    let st = fstat(sock.raw())?;
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err("wayland socket is not a socket".into());
    }
    if st.st_uid != uid {
        return Err(format!("wayland socket is owned by uid {}, not the session", st.st_uid));
    }
    verify_proxy_listener(&sock, uid, zone, proxy_exe)?;
    Ok(ProxySocket { fd: sock, path: want, dev: st.st_dev as u64, ino: st.st_ino as u64 })
}

/// Connect to the socket through its inode and ask the kernel who is
/// listening: the same uid as the session, running kryptik-wlproxy for
/// this zone. The connection is closed at once; the proxy logs it as a
/// client that disconnected.
fn verify_proxy_listener(sock: &Fd, uid: u32, zone: &str, proxy_exe: Option<&Path>) -> Result<(), String> {
    // This listener belongs to the session and may never accept. A full
    // Unix-socket backlog must refuse promptly, not block the root daemon.
    let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
    if s < 0 {
        return Err(format!("socket: {}", std::io::Error::last_os_error()));
    }
    let s = Fd(s);
    let path = format!("/proc/self/fd/{}", sock.raw());
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as _;
    for (i, b) in path.bytes().enumerate() {
        addr.sun_path[i] = b as _;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + path.len() + 1) as libc::socklen_t;
    if unsafe { libc::connect(s.raw(), &addr as *const _ as *const libc::sockaddr, len) } < 0 {
        return Err(format!("nothing usable is listening on the wayland socket: {}", std::io::Error::last_os_error()));
    }
    let peer = peer_of(s.raw()).ok_or("wayland socket: cannot identify the listener")?;
    if peer.uid != uid {
        return Err(format!("wayland socket is served by uid {}, not the session", peer.uid));
    }
    let cmdline = std::fs::read(format!("/proc/{}/cmdline", peer.pid))
        .map_err(|e| format!("wayland socket: cannot read the listener's command line: {e}"))?;
    let argv: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
    let is_proxy = argv.first().map(|a| a.ends_with(b"kryptik-wlproxy")).unwrap_or(false);
    if !is_proxy {
        return Err("wayland socket is not served by kryptik-wlproxy".into());
    }
    let zone_arg = argv.windows(2).any(|w| w[0] == b"--zone" && w[1] == zone.as_bytes());
    if !zone_arg {
        return Err(format!("wayland socket is served by a proxy for another zone, not {zone:?}"));
    }
    // A developer instance has no installed proxy to insist on; a root one
    // does, and a same-uid process merely named like the proxy is not it.
    if let Some(want) = proxy_exe {
        match std::fs::read_link(format!("/proc/{}/exe", peer.pid)) {
            Ok(exe) if exe == want => {}
            Ok(exe) => return Err(format!("wayland socket is served by {}, not {}", exe.display(), want.display())),
            Err(e) => return Err(format!("wayland socket: cannot identify the listener's program: {e}")),
        }
    }
    Ok(())
}

// --- launching -------------------------------------------------------------------

struct Launch {
    pid: i32,
    ready: Fd,
    log: PathBuf,
}

/// Start `kryptikd run` for the request. The passphrase and proxy
/// descriptors, if any, are handed to the child and closed here whatever
/// happens; the readiness pipe's read end is what comes back.
fn spawn_launcher(
    req: &Request,
    cfg: &ServeConfig,
    pass: Option<Fd>,
    wayland: Option<ProxySocket>,
    uid: u32,
) -> Result<Launch, String> {
    let exe = std::fs::read_link("/proc/self/exe").map_err(|e| format!("/proc/self/exe: {e}"))?;
    let (ready_r, ready_w) = pipe()?;
    let mut args: Vec<String> = vec![
        "run".into(),
        req.zone.clone(),
        "--zones".into(),
        cfg.zones_dir.display().to_string(),
        "--rootfs".into(),
        cfg.rootfs.clone(),
        "--ready-fd".into(),
        ready_w.raw().to_string(),
    ];
    // The path, not a descriptor: a descriptor opened here belongs to this
    // mount namespace and cannot be bind-mounted from the zone's (EINVAL).
    // The launcher re-opens the path itself without following symlinks,
    // refuses anything but this inode, and stages it in the zone's registry
    // entry for its child to bind after unshare (spawn.rs, StagedSocket).
    if let Some(w) = &wayland {
        args.push("--wayland-socket".into());
        args.push(w.path.display().to_string());
        args.push("--wayland-inode".into());
        args.push(format!("{}:{}", w.dev, w.ino));
    }
    if let Some(p) = &pass {
        args.push("--passphrase-fd".into());
        args.push(p.raw().to_string());
    }
    args.push("--".into());
    args.extend(req.argv.iter().cloned());

    let log = cfg.log_dir.join(format!("zone-{}.log", req.zone));
    let logf = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log)
        .map_err(|e| format!("{}: {e}", log.display()))?;
    let cexe = CString::new(exe.display().to_string()).map_err(|_| "NUL in exe path".to_string())?;
    let cargs: Vec<CString> = std::iter::once(CString::new("kryptikd").unwrap())
        .chain(args.iter().map(|a| CString::new(a.as_str()).unwrap_or_else(|_| CString::new("?").unwrap())))
        .collect();
    let env = CString::new(format!("KRYPTIK_LAUNCHED_BY_UID={uid}")).unwrap();
    let path = CString::new("PATH=/usr/bin:/usr/sbin").unwrap();

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        unsafe {
            libc::setsid();
            let null = libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDONLY);
            libc::dup2(null, 0);
            libc::dup2(logf.as_raw_fd(), 1);
            libc::dup2(logf.as_raw_fd(), 2);
            // These two cross the exec; everything else is CLOEXEC.
            clear_cloexec(ready_w.raw());
            if let Some(p) = &pass {
                clear_cloexec(p.raw());
            }
            let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
            ptrs.push(std::ptr::null());
            let envp: [*const libc::c_char; 3] = [env.as_ptr(), path.as_ptr(), std::ptr::null()];
            libc::execve(cexe.as_ptr(), ptrs.as_ptr(), envp.as_ptr());
            libc::_exit(127);
        }
    }
    // Parent: the child has its copies; ours close here. The proxy socket's
    // pin is released too: from here the inode check in the launcher is
    // what holds the identity.
    drop(ready_w);
    drop(pass);
    drop(wayland);
    Ok(Launch { pid, ready: ready_r, log })
}

/// The last thing a launcher wrote, for an error reply. One line, printable,
/// bounded.
fn last_log_line(log: &Path) -> String {
    // Zone output can make this file arbitrarily large or non-UTF-8. Read
    // only an 8 KiB tail for the diagnostic; full logs remain on disk.
    let Ok(mut file) = std::fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(log) else { return String::new() };
    let Ok(md) = file.metadata() else { return String::new() };
    if !md.is_file() || file.seek(SeekFrom::Start(md.len().saturating_sub(8192))).is_err() {
        return String::new();
    }
    let mut bytes = Vec::new();
    if file.take(8192).read_to_end(&mut bytes).is_err() { return String::new(); }
    let text = String::from_utf8_lossy(&bytes);
    let line = text.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("");
    let mut out: String = line.chars().filter(|c| !c.is_control()).take(200).collect();
    if line.chars().count() > 200 {
        out.push_str("...");
    }
    out
}

fn exit_text(status: i32) -> String {
    if libc::WIFEXITED(status) {
        format!("exited {}", libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        format!("killed by signal {}", libc::WTERMSIG(status))
    } else {
        format!("ended with status {status}")
    }
}

/// A launch whose reply is still owed.
struct Pending {
    conn: UnixStream,
    launch: Launch,
    zone: String,
    uid: u32,
    started: Instant,
    ready_at: Option<Instant>,
    exited: Option<i32>,
}

impl Pending {
    fn deadline(&self) -> Instant {
        match self.ready_at {
            Some(t) => t + SETTLE,
            None => self.started + LAUNCH_DEADLINE,
        }
    }
}

fn reply(mut c: &UnixStream, text: &str) {
    let _ = c.write_all(text.as_bytes());
    let _ = c.flush();
}

/// Reap children. A pending launcher's status is recorded for its reply;
/// any other launcher's is logged.
fn reap(pending: &mut [Pending]) {
    loop {
        let mut st = 0;
        let p = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
        if p <= 0 {
            break;
        }
        match pending.iter_mut().find(|x| x.launch.pid == p) {
            Some(x) => x.exited = Some(st),
            None => eprintln!("kryptikd serve: launcher {p} {}", exit_text(st)),
        }
    }
}

/// Wait briefly for a specific launcher's exit status after its pipe closed:
/// the close and the exit are the same instant from the launcher's side and
/// two events from ours.
fn wait_exit(p: &mut Pending) -> Option<i32> {
    if p.exited.is_some() {
        return p.exited;
    }
    let until = Instant::now() + Duration::from_millis(500);
    loop {
        let mut st = 0;
        let r = unsafe { libc::waitpid(p.launch.pid, &mut st, libc::WNOHANG) };
        if r == p.launch.pid {
            p.exited = Some(st);
            return p.exited;
        }
        if r < 0 || Instant::now() >= until {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn finish(p: &mut Pending, outcome: Result<(), String>) {
    match outcome {
        Ok(()) => {
            eprintln!("kryptikd serve: uid {} zone {:?}: ready (launcher {})", p.uid, p.zone, p.launch.pid);
            reply(&p.conn, &format!("ok {}\n", p.launch.pid));
        }
        Err(why) => {
            eprintln!("kryptikd serve: uid {} zone {:?}: {why}", p.uid, p.zone);
            reply(&p.conn, &format!("error: {why}\n"));
        }
    }
}

// --- the daemon --------------------------------------------------------------------

pub struct ServeConfig {
    pub socket: PathBuf,
    pub group: String,
    pub zones_dir: PathBuf,
    pub rootfs: String,
    pub log_dir: PathBuf,
    /// The program that must be listening on a session's proxy socket.
    pub proxy_exe: PathBuf,
    /// Unprivileged instance: serves its own uid only.
    pub developer: bool,
}

fn config_from(zones_dir: &Path, args: &[String]) -> Result<ServeConfig, String> {
    let opt = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned();
    let developer = unsafe { libc::geteuid() } != 0;
    let socket = match opt("--socket") {
        Some(s) => PathBuf::from(s),
        None if developer => {
            return Err("must run as root; `--socket PATH` runs a developer instance serving only your own uid".into())
        }
        None => PathBuf::from(SOCKET_PATH),
    };
    let log_dir = if developer {
        socket.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."))
    } else {
        PathBuf::from("/var/log/kryptik")
    };
    Ok(ServeConfig {
        socket,
        group: opt("--group").unwrap_or_else(|| GROUP.to_string()),
        zones_dir: zones_dir.to_path_buf(),
        rootfs: opt("--rootfs").unwrap_or_else(|| crate::DEFAULT_ROOTFS_BASE.to_string()),
        log_dir,
        proxy_exe: PathBuf::from(opt("--proxy-exe").unwrap_or_else(|| PROXY_EXE.to_string())),
        developer,
    })
}

fn authorised(cfg: &ServeConfig, uid: u32) -> bool {
    if cfg.developer {
        uid == unsafe { libc::geteuid() }
    } else {
        in_group(uid, &cfg.group)
    }
}

/// Bind the socket and set its ownership and mode.
fn bind(cfg: &ServeConfig) -> Result<UnixListener, String> {
    if cfg.developer {
        if let Some(d) = cfg.socket.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let _ = std::fs::remove_file(&cfg.socket);
        let l = UnixListener::bind(&cfg.socket).map_err(|e| format!("cannot bind {}: {e}", cfg.socket.display()))?;
        let _ = std::fs::set_permissions(&cfg.socket, std::fs::Permissions::from_mode(0o600));
        return Ok(l);
    }
    let gid = gid_of_group(&cfg.group).ok_or_else(|| format!("no group {:?}; nobody could connect", cfg.group))?;
    let dir = cfg.socket.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from(SOCKET_DIR));
    // The daemon owns its default directory: root:kryptik, 0750, so the
    // socket inside is reachable by the group and by nobody else. A
    // directory named through --socket belongs to whoever named it (a test's
    // workspace, say) and is left as found: taking it to 0750 root-owned
    // once made every zone launched from a test fail to traverse its own
    // data directory.
    if dir == Path::new(SOCKET_DIR) {
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750));
        let cdir = CString::new(dir.display().to_string()).unwrap();
        unsafe { libc::chown(cdir.as_ptr(), 0, gid) };
    }
    let _ = std::fs::remove_file(&cfg.socket);
    let l = UnixListener::bind(&cfg.socket).map_err(|e| format!("cannot bind {}: {e}", cfg.socket.display()))?;
    let csock = CString::new(cfg.socket.display().to_string()).unwrap();
    unsafe { libc::chown(csock.as_ptr(), 0, gid) };
    let _ = std::fs::set_permissions(&cfg.socket, std::fs::Permissions::from_mode(0o660));
    let _ = std::fs::create_dir_all(&cfg.log_dir);
    Ok(l)
}

/// The session's runtime directory, created for it: /run/user/<uid>, 0700,
/// owned by the user. There is no logind here to do it; the daemon is the
/// one root process the session can ask.
fn runtime_dir(cfg: &ServeConfig, uid: u32) -> Result<PathBuf, String> {
    let dir = if cfg.developer {
        cfg.log_dir.join(format!("run-user-{uid}"))
    } else {
        PathBuf::from(format!("/run/user/{uid}"))
    };
    match std::fs::symlink_metadata(&dir) {
        Ok(md) => {
            if !md.is_dir() {
                return Err(format!("{} exists and is not a directory", dir.display()));
            }
            if std::os::unix::fs::MetadataExt::uid(&md) != uid && !cfg.developer {
                return Err(format!("{} is owned by uid {}, not {uid}", dir.display(), std::os::unix::fs::MetadataExt::uid(&md)));
            }
        }
        Err(_) => {
            if let Some(p) = dir.parent() {
                let _ = std::fs::create_dir_all(p);
            }
            std::fs::create_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
            if !cfg.developer {
                let gid = gid_of_uid(uid).unwrap_or(uid);
                let c = CString::new(dir.display().to_string()).unwrap();
                if unsafe { libc::chown(c.as_ptr(), uid, gid) } < 0 {
                    return Err(format!("chown {}: {}", dir.display(), std::io::Error::last_os_error()));
                }
            }
        }
    }
    Ok(dir)
}

fn zone_named(cfg: &ServeConfig, name: &str) -> Result<crate::zone::Zone, String> {
    let zones = crate::zone::load_all(&cfg.zones_dir).map_err(|e| e.to_string())?;
    zones.into_iter().find(|z| z.name == name).ok_or_else(|| format!("no zone named {name:?}"))
}

fn zone_running(name: &str) -> bool {
    matches!(crate::registry::state(name), Ok(crate::registry::State::Running { .. }))
}

/// One accepted connection: read, check, act. A `run` that starts a
/// launcher returns it for the caller to watch; everything else is
/// answered here.
fn handle(cfg: &ServeConfig, conn: UnixStream) -> Option<Pending> {
    let fd = conn.as_raw_fd();
    let peer = match peer_of(fd) {
        Some(p) => p,
        None => {
            reply(&conn, "error: unidentified peer\n");
            return None;
        }
    };
    let uid = peer.uid;
    if !authorised(cfg, uid) {
        reply(&conn, &format!("error: uid {uid} is not in group {}\n", cfg.group));
        eprintln!("kryptikd serve: refused uid {uid} (pid {})", peer.pid);
        return None;
    }
    let (text, carried) = match recv_request(fd, Instant::now() + REQUEST_DEADLINE) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("kryptikd serve: uid {uid}: {e}");
            reply(&conn, &format!("error: {e}\n"));
            return None;
        }
    };
    let text = String::from_utf8_lossy(&text).to_string();
    let first = text.lines().next().unwrap_or("");
    let verb = first.split_whitespace().next().unwrap_or("");
    match verb {
        "status" => {
            let mut out = String::new();
            for z in crate::registry::names() {
                if zone_running(&z) {
                    out.push_str(&format!("running {z}\n"));
                }
            }
            out.push_str("end\n");
            reply(&conn, &out);
        }
        "info" => {
            let name = first.split_whitespace().nth(1).unwrap_or("");
            if !ident_ok(name) {
                reply(&conn, "error: info: bad zone name\n");
                return None;
            }
            match zone_named(cfg, name) {
                Ok(z) => {
                    let enc = z.storage == crate::zone::StorageMode::Encrypted;
                    reply(
                        &conn,
                        &format!(
                            "encrypted {}\nrunning {}\nlabel {}\nend\n",
                            if enc { "yes" } else { "no" },
                            if zone_running(name) { "yes" } else { "no" },
                            z.label.as_deref().unwrap_or(&z.name),
                        ),
                    );
                }
                Err(e) => reply(&conn, &format!("error: {e}\n")),
            }
        }
        "runtime" => match runtime_dir(cfg, uid) {
            Ok(d) => reply(&conn, &format!("ok {}\n", d.display())),
            Err(e) => reply(&conn, &format!("error: {e}\n")),
        },
        "clipboard-move" => {
            let mut w = first.split_whitespace().skip(1);
            let (from, to) = (w.next().unwrap_or(""), w.next().unwrap_or(""));
            if !ident_ok(from) || !ident_ok(to) || from == to {
                reply(&conn, "error: clipboard-move needs two different zone names\n");
                return None;
            }
            // The gesture is a trusted-UI act; the daemon performs it as
            // root through its own clipboard command, which requires both
            // zones to be running and copies one payload, once.
            let out = std::process::Command::new("/proc/self/exe").args(["clipboard", "move", from, to]).output();
            match out {
                Ok(o) if o.status.success() => {
                    eprintln!("kryptikd serve: uid {uid} moved the clipboard {from:?} -> {to:?}");
                    reply(&conn, &format!("ok {}", String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or("moved").to_string() + "\n"));
                }
                Ok(o) => reply(&conn, &format!("error: {}\n", String::from_utf8_lossy(&o.stderr).lines().last().unwrap_or("clipboard move failed"))),
                Err(e) => reply(&conn, &format!("error: {e}\n")),
            }
        }
        "stop" => {
            let zone = first.split_whitespace().nth(1).unwrap_or("");
            if !ident_ok(zone) {
                reply(&conn, "error: bad zone name\n");
                return None;
            }
            let r = std::process::Command::new("/proc/self/exe").args(["stop", zone]).status();
            match r {
                Ok(s) if s.success() => reply(&conn, "ok\n"),
                Ok(s) => reply(&conn, &format!("error: stop exited {}\n", s.code().unwrap_or(-1))),
                Err(e) => reply(&conn, &format!("error: {e}\n")),
            }
            eprintln!("kryptikd serve: uid {uid} stopped zone {zone:?}");
        }
        "run" => {
            let req = match parse_run(&text) {
                Ok(r) => r,
                Err(e) => {
                    reply(&conn, &format!("error: {e}\n"));
                    return None;
                }
            };
            // The zone must exist before anything is forked for it: a bad
            // name is an answer now, not a launcher's exit code later.
            if let Err(e) = zone_named(cfg, &req.zone) {
                reply(&conn, &format!("error: {e}\n"));
                return None;
            }
            let wayland = match &req.wayland {
                None => None,
                Some(w) => match verify_proxy_socket(w, uid, &req.zone, if cfg.developer { None } else { Some(&cfg.proxy_exe) }) {
                    Ok(sock) => Some(sock),
                    Err(e) => {
                        eprintln!("kryptikd serve: uid {uid} zone {:?}: {e}", req.zone);
                        reply(&conn, &format!("error: {e}\n"));
                        return None;
                    }
                },
            };
            let pass = if req.wants_fd {
                match carried {
                    Some(fd) => Some(fd),
                    None => {
                        reply(&conn, "error: pass=fd needs exactly one descriptor, got 0\n");
                        return None;
                    }
                }
            } else {
                if carried.is_some() {
                    reply(&conn, "error: a descriptor was sent without pass=fd\n");
                    return None;
                }
                None
            };
            match spawn_launcher(&req, cfg, pass, wayland, uid) {
                Ok(launch) => {
                    eprintln!(
                        "kryptikd serve: uid {uid} launching zone {:?} ({}) as launcher {}",
                        req.zone, req.argv[0], launch.pid
                    );
                    return Some(Pending {
                        conn,
                        launch,
                        zone: req.zone,
                        uid,
                        started: Instant::now(),
                        ready_at: None,
                        exited: None,
                    });
                }
                Err(e) => {
                    eprintln!("kryptikd serve: uid {uid} zone {:?}: {e}", req.zone);
                    reply(&conn, &format!("error: {e}\n"));
                }
            }
        }
        other => reply(&conn, &format!("error: unknown request {other:?}\n")),
    }
    None
}

pub fn cmd_serve(zones_dir: &Path, args: &[String]) -> ExitCode {
    let cfg = match config_from(zones_dir, args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("kryptikd serve: {e}");
            return ExitCode::from(2);
        }
    };
    let listener = match bind(&cfg) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("kryptikd serve: {e}");
            return ExitCode::FAILURE;
        }
    };
    let _ = listener.set_nonblocking(true);
    eprintln!(
        "kryptikd serve: listening on {} for {}; zones {}, data {}, logs {}",
        cfg.socket.display(),
        if cfg.developer { format!("uid {} (developer instance)", unsafe { libc::geteuid() }) } else { format!("group {}", cfg.group) },
        cfg.zones_dir.display(),
        cfg.rootfs,
        cfg.log_dir.display()
    );

    let mut pending: Vec<Pending> = Vec::new();
    loop {
        reap(&mut pending);

        // The listener, then one entry per launch still waiting for its
        // readiness pipe. Timeout: the nearest deadline among launches.
        let mut fds: Vec<libc::pollfd> = vec![libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 }];
        let mut watched: Vec<usize> = Vec::new();
        let now = Instant::now();
        let mut timeout: i32 = -1;
        for (i, p) in pending.iter().enumerate() {
            if p.ready_at.is_none() {
                fds.push(libc::pollfd { fd: p.launch.ready.raw(), events: libc::POLLIN, revents: 0 });
                watched.push(i);
            }
            let left = p.deadline().saturating_duration_since(now).as_millis() as i32;
            timeout = if timeout < 0 { left } else { timeout.min(left) };
        }
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, timeout) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                eprintln!("kryptikd serve: poll: {e}");
            }
            continue;
        }

        // Readiness pipes: a byte means the zone's pid 1 exists; EOF means
        // the launcher went away first.
        let mut done: Vec<usize> = Vec::new();
        for (k, &i) in watched.iter().enumerate() {
            let ev = fds[1 + k].revents;
            if ev & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
                continue;
            }
            let mut buf = [0u8; 16];
            let r = unsafe { libc::read(pending[i].launch.ready.raw(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if r > 0 {
                pending[i].ready_at = Some(Instant::now());
            } else {
                let p = &mut pending[i];
                let status = wait_exit(p);
                let why = match status {
                    Some(st) => format!("zone {:?} did not start: launcher {}: {}", p.zone, exit_text(st), last_log_line(&p.launch.log)),
                    None => format!("zone {:?} did not start: launcher {} closed its readiness pipe without starting the zone (see {})", p.zone, p.launch.pid, p.launch.log.display()),
                };
                finish(p, Err(why));
                done.push(i);
            }
        }
        // Deadlines: settled launches get their `ok`; stalled ones an error.
        let now = Instant::now();
        for (i, p) in pending.iter_mut().enumerate() {
            if done.contains(&i) || now < p.deadline() {
                continue;
            }
            if p.ready_at.is_some() {
                // One more look: a launcher that exited non-zero in the
                // settling window started a zone whose command failed.
                let mut st = 0;
                if p.exited.is_none() {
                    let r = unsafe { libc::waitpid(p.launch.pid, &mut st, libc::WNOHANG) };
                    if r == p.launch.pid {
                        p.exited = Some(st);
                    }
                }
                match p.exited {
                    Some(st) if !(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0) => {
                        let why = format!("zone {:?} started but its command ended at once: launcher {}: {}", p.zone, exit_text(st), last_log_line(&p.launch.log));
                        finish(p, Err(why));
                    }
                    _ => finish(p, Ok(())),
                }
            } else {
                let why = format!(
                    "zone {:?} not ready after {} s (launcher {} still running; see {})",
                    p.zone,
                    LAUNCH_DEADLINE.as_secs(),
                    p.launch.pid,
                    p.launch.log.display()
                );
                finish(p, Err(why));
            }
            done.push(i);
        }
        done.sort_unstable();
        for i in done.into_iter().rev() {
            pending.remove(i);
        }

        if fds[0].revents & libc::POLLIN != 0 {
            match listener.accept() {
                Ok((conn, _)) => {
                    let _ = conn.set_nonblocking(false);
                    if let Some(p) = handle(&cfg, conn) {
                        pending.push(p);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => eprintln!("kryptikd serve: accept: {e}"),
            }
        }
    }
}

/// Client side, for tests and for the kryptik command: send one request.
pub fn request(text: &str, fd: Option<RawFd>) -> Result<String, String> {
    request_at(Path::new(SOCKET_PATH), text, fd)
}

pub fn request_at(socket: &Path, text: &str, fd: Option<RawFd>) -> Result<String, String> {
    let mut s = UnixStream::connect(socket).map_err(|e| format!("{}: {e}", socket.display()))?;
    match fd {
        None => s.write_all(text.as_bytes()).map_err(|e| e.to_string())?,
        Some(fd) => {
            let bytes = text.as_bytes();
            let mut iov = libc::iovec { iov_base: bytes.as_ptr() as *mut libc::c_void, iov_len: bytes.len() };
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            let mut cbuf = [0u8; 64];
            let space = unsafe { libc::CMSG_SPACE(4) } as usize;
            msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = space as _;
            unsafe {
                let c = libc::CMSG_FIRSTHDR(&msg);
                (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS;
                (*c).cmsg_len = libc::CMSG_LEN(4) as _;
                *(libc::CMSG_DATA(c) as *mut RawFd) = fd;
                if libc::sendmsg(s.as_raw_fd(), &msg, 0) < 0 {
                    return Err(format!("sendmsg: {}", std::io::Error::last_os_error()));
                }
            }
        }
    }
    let _ = s.shutdown(std::net::Shutdown::Write);
    let mut out = String::new();
    s.read_to_string(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_parse_and_bad_ones_are_refused() {
        let r = parse_run("run work wayland=/run/user/1000/kryptik/work/wayland-0 pass=fd\narg havoc\narg -e\narg sh\nend\n").unwrap();
        assert_eq!(r.zone, "work");
        assert_eq!(r.argv, vec!["havoc", "-e", "sh"]);
        assert!(r.wants_fd);
        assert_eq!(r.wayland.as_deref(), Some(Path::new("/run/user/1000/kryptik/work/wayland-0")));
        for bad in [
            "",
            "run\n",
            "run ../x\narg a\nend\n",
            "run work\nend\n",
            "run work\narg a\n",
            "run work bogus=1\narg a\nend\n",
            "stop work\n",
        ] {
            assert!(parse_run(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn a_request_is_complete_at_its_terminator_and_not_before() {
        assert!(request_complete(b"status\n"));
        assert!(request_complete(b"info work\n"));
        assert!(request_complete(b"runtime\n"));
        assert!(request_complete(b"stop work\n"));
        assert!(!request_complete(b"stat"));
        assert!(!request_complete(b"run work\n"));
        assert!(!request_complete(b"run work\narg x\n"));
        assert!(request_complete(b"run work\narg x\nend\n"));
        assert!(!request_complete(b"run work\narg x\nend"));
    }

    /// The path rule, without a filesystem: only the session's own
    /// `<zone>/wayland-0` under its runtime directory is even considered.
    #[test]
    fn only_the_sessions_own_proxy_path_is_considered() {
        let bad = |p: &str, uid: u32, zone: &str| {
            let e = verify_proxy_socket(Path::new(p), uid, zone, None).unwrap_err();
            assert!(e.contains("must be") || e.contains("path"), "{p}: {e}");
        };
        bad("/run/user/1000/kryptik/work/wayland-0", 1001, "work");
        bad("/run/user/1000/kryptik/work/wayland-0", 1000, "vault");
        bad("/run/user/1000/wayland-0", 1000, "work");
        bad("/run/user/1000/kryptik/../wayland-0", 1000, "work");
        bad("/tmp/wayland-0", 1000, "work");
        bad("/run/user/1000/kryptik/work/wayland-0/", 1000, "work");
    }

    /// The remaining checks need a real directory tree and a listener:
    /// compartments/tests/serve.sh exercises them through the daemon.

    #[test]
    fn open_nofollow_refuses_links_and_non_sockets() {
        let dir = std::env::temp_dir().join(format!("kryptik-nofollow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("real")).unwrap();
        let sock = dir.join("real/s");
        let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();
        std::fs::write(dir.join("real/plain"), b"x").unwrap();
        assert!(open_nofollow(&sock, true).is_ok());
        assert!(open_nofollow(&dir.join("link/s"), true).is_err(), "a symlinked directory is refused");
        assert!(open_nofollow(&dir.join("real/plain"), true).is_err(), "a regular file is not a socket");
        assert!(open_nofollow(&dir.join("real/plain"), false).is_ok());
        assert!(open_nofollow(Path::new("relative/x"), false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_full_proxy_backlog_cannot_block_the_launch_daemon() {
        let dir = std::env::temp_dir().join(format!("kryptik-backlog-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
        let queued = UnixStream::connect(&path).unwrap();
        let sock = open_nofollow(&path, true).unwrap();
        let (done, completion) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = verify_proxy_listener(&sock, unsafe { libc::geteuid() }, "work", None);
            let _ = done.send(result);
        });
        let result = completion.recv_timeout(Duration::from_secs(2));
        // Closing the listener also releases the old blocking connect,
        // so the regression fails cleanly rather than hanging the suite.
        drop(listener);
        drop(queued);
        worker.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        assert!(result.is_ok(), "a session-owned listener held the root daemon at connect");
        assert!(result.unwrap().is_err(), "a full backlog must be refused");
    }

    #[test]
    fn identifiers() {
        assert!(ident_ok("work"));
        assert!(ident_ok("net-zone_2"));
        assert!(!ident_ok(""));
        assert!(!ident_ok("a/b"));
        assert!(!ident_ok(&"x".repeat(40)));
    }

    #[test]
    fn a_launcher_that_exits_reports_its_status_and_last_line() {
        let dir = std::env::temp_dir().join(format!("kryptik-serve-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("zone-x.log");
        std::fs::write(&log, "first\nkryptikd: could not start zone \"x\": no such policy\n\n").unwrap();
        assert_eq!(last_log_line(&log), "kryptikd: could not start zone \"x\": no such policy");
        assert_eq!(last_log_line(&dir.join("absent.log")), "");
        // Zone stdout shares this log and can contain arbitrary bytes. An
        // invalid byte earlier in the file must not hide the launch error.
        std::fs::write(&log, b"\xff\n").unwrap();
        let mut large = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        large.set_len(32 * 1024 * 1024).unwrap(); // sparse: no large allocation or disk write
        large.write_all(b"\nlast launch error\n\n").unwrap();
        assert_eq!(last_log_line(&log), "last launch error");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn descriptors_close_when_dropped() {
        let (r, w) = pipe().unwrap();
        let raw = r.raw();
        drop(r);
        drop(w);
        // A closed descriptor cannot be fstat'ed.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        assert!(unsafe { libc::fstat(raw, &mut st) } < 0);
    }

}
