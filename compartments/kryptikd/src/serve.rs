//! `kryptikd serve`: the launch daemon the desktop session talks to.
//!
//! Zones are created by root and the session is an ordinary user; this socket
//! is the one door between them. The daemon checks the peer (SO_PEERCRED) and
//! the request, then runs `kryptikd run`, whose every refusal still applies.
//!
//!   socket   /run/kryptik-launch/launch.sock   (root:kryptik 0660)
//!   request  one per connection, NUL-free text lines:
//!              run <zone> [wayland=<path>] [pass=fd], `arg <word>` lines, `end`
//!                (with pass=fd, one descriptor rides with the first bytes)
//!              wifi-add, `ssid <ssid>`, `psk <passphrase>`, `end`
//!              wifi-forget, `ssid <ssid>`, `end`
//!              stop <zone> | clipboard-move <from> <to> | info <zone> | status |
//!              runtime | wifi-list | update-status | update-fetch | update-apply
//!   reply    ok ...\n  |  error: <why>\n  |  lines ... end\n
//!
//! `run` replies `ok <launcher pid>` once the zone's pid 1 exists and the
//! launcher has not failed within SETTLE. One request is read at a time, for at
//! most REQUEST_DEADLINE; launches and jobs in flight do not hold the daemon.
//! `--socket PATH` runs a developer instance that serves only its own uid.

use std::ffi::{CStr, CString};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
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
/// How long after readiness a launcher is watched for an immediate failure.
const SETTLE: Duration = Duration::from_millis(300);

// --- descriptors -----------------------------------------------------------

fn pipe() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(format!("pipe: {}", std::io::Error::last_os_error()));
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn clear_cloexec(fd: RawFd) {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFD);
        libc::fcntl(fd, libc::F_SETFD, fl & !libc::FD_CLOEXEC);
    }
}

/// One recvmsg into `buf`, owning the descriptors that came with it. Control
/// data cut short is refused, and what did arrive is closed.
pub fn recv_with_fds(fd: RawFd, buf: &mut [u8], flags: libc::c_int) -> std::io::Result<(usize, Vec<OwnedFd>)> {
    // Aligned for cmsghdr, with room for twelve, so an excess is refused by count.
    #[repr(C, align(8))]
    struct Control([u8; 64]);
    let mut control = Control([0; 64]);
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.0.len() as _;
    let n = unsafe { libc::recvmsg(fd, &mut msg, flags | libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut got = Vec::new();
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(c) as *const RawFd;
                let count = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / std::mem::size_of::<RawFd>();
                for i in 0..count {
                    got.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(data.add(i))));
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "more descriptors than a request may carry"));
    }
    Ok((n as usize, got))
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

/// Is `uid` root, or a member (primary or supplementary) of `group`? Member
/// names are copied out first in case getpwuid(3) reuses getgrnam(3)'s buffer.
fn in_group(uid: u32, group: &str) -> bool {
    if uid == 0 {
        return true;
    }
    let Ok(c) = CString::new(group) else { return false };
    let g = unsafe { libc::getgrnam(c.as_ptr()) };
    if g.is_null() {
        return false;
    }
    let gid = unsafe { (*g).gr_gid };
    let mut members: Vec<String> = Vec::new();
    let mut mem = unsafe { (*g).gr_mem };
    unsafe {
        while !mem.is_null() && !(*mem).is_null() {
            members.push(CStr::from_ptr(*mem).to_string_lossy().into_owned());
            mem = mem.add(1);
        }
    }
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return false;
    }
    if unsafe { (*pw).pw_gid } == gid {
        return true;
    }
    let name = unsafe { CStr::from_ptr((*pw).pw_name) }.to_string_lossy();
    members.iter().any(|m| *m == name)
}

/// `SO_PEERCRED` of a connected AF_UNIX socket, which the kernel asserts.
pub fn peer_cred(fd: RawFd) -> std::io::Result<libc::ucred> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut libc::c_void, &mut len) };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred)
}

// --- the request -------------------------------------------------------------

/// Whether the bytes so far are a whole request. `run`, `wifi-add` and
/// `wifi-forget` end at an `end` line, other verbs at a newline.
fn request_complete(text: &[u8]) -> bool {
    if !text.ends_with(b"\n") {
        return false;
    }
    if text.starts_with(b"run ") || text.starts_with(b"wifi-add\n") || text.starts_with(b"wifi-forget\n") {
        text.ends_with(b"\nend\n")
    } else {
        true
    }
}

/// Read the request text and any descriptor that came with it, within
/// `deadline`. At most one descriptor, and only with the first bytes.
fn recv_request(fd: RawFd, deadline: Instant) -> Result<(Vec<u8>, Option<OwnedFd>), String> {
    let mut text = Vec::new();
    let mut carried: Option<OwnedFd> = None;
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
        // The descriptors are owned, so any refusal below closes them.
        let (n, mut got) = match recv_with_fds(fd, &mut buf, libc::MSG_DONTWAIT) {
            Ok(x) => x,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => return Err(e.to_string()),
            Err(e) => return Err(format!("recvmsg: {e}")),
        };
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
        text.extend_from_slice(&buf[..n]);
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

/// Debug prints the SSID only: the passphrase is never formatted.
struct WifiRequest {
    ssid: String,
    psk: Option<String>,
}

impl std::fmt::Debug for WifiRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WifiRequest {{ ssid: {:?}, psk: {} }}", self.ssid, if self.psk.is_some() { "<set>" } else { "None" })
    }
}

/// Parse `wifi-add` or `wifi-forget`. A value is all after the first space; a
/// refusal never repeats a line, which may hold the passphrase.
fn parse_wifi(text: &str) -> Result<WifiRequest, String> {
    let mut lines = text.lines();
    let verb = lines.next().unwrap_or("");
    if verb != "wifi-add" && verb != "wifi-forget" {
        let word = verb.split_whitespace().next().unwrap_or("wifi");
        return Err(format!("{word}: the verb stands alone on its line"));
    }
    let shape = if verb == "wifi-add" { "`ssid <SSID>`, `psk <PASSPHRASE>`, `end`" } else { "`ssid <SSID>`, `end`" };
    let (mut ssid, mut psk, mut ended) = (None, None, false);
    for l in lines {
        if l == "end" {
            ended = true;
            break;
        }
        if let Some(v) = l.strip_prefix("ssid ") {
            if ssid.replace(v.to_string()).is_some() {
                return Err(format!("{verb}: two ssid lines"));
            }
        } else if let Some(v) = l.strip_prefix("psk ").filter(|_| verb == "wifi-add") {
            if psk.replace(v.to_string()).is_some() {
                return Err(format!("{verb}: two psk lines"));
            }
        } else {
            return Err(format!(
                "{verb}: unexpected line; the request is {shape}, one per line, and neither value may hold a newline"
            ));
        }
    }
    if !ended {
        return Err(format!("{verb}: request not terminated by `end`"));
    }
    let ssid = ssid.ok_or_else(|| format!("{verb}: no ssid line"))?;
    if verb == "wifi-add" && psk.is_none() {
        return Err("wifi-add: no psk line".into());
    }
    Ok(WifiRequest { ssid, psk })
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
fn openat_component(dir: RawFd, name: &str, flags: libc::c_int) -> Result<OwnedFd, String> {
    let c = CString::new(name).map_err(|_| "NUL in path".to_string())?;
    let fd = unsafe { libc::openat(dir, c.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(format!("{name}: {}", std::io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A verified proxy socket. `_fd` pins the inode while the launch is set up;
/// the launcher gets the path and inode, reopens the path and refuses any
/// other inode (spawn.rs, StagedSocket).
#[derive(Debug)]
pub struct ProxySocket {
    pub _fd: OwnedFd,
    pub path: PathBuf,
    pub inode: InodeId,
}

/// (device, inode) of a verified object, passed to the launcher as `DEV:INO`
/// and checked again after each later open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeId {
    pub dev: u64,
    pub ino: u64,
}

impl InodeId {
    pub fn of(st: &libc::stat) -> Self {
        InodeId { dev: st.st_dev as u64, ino: st.st_ino as u64 }
    }

    /// Is `st` this object? Catches a rename or link between check and open.
    pub fn matches(&self, st: &libc::stat) -> bool {
        *self == Self::of(st)
    }
}

impl std::fmt::Display for InodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.dev, self.ino)
    }
}

impl std::str::FromStr for InodeId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let (d, n) = s.split_once(':').ok_or_else(|| "expected DEV:INO".to_string())?;
        Ok(InodeId {
            dev: d.parse().map_err(|_| "DEV is not a number".to_string())?,
            ino: n.parse().map_err(|_| "INO is not a number".to_string())?,
        })
    }
}

/// Open `path` as O_PATH a component at a time, following no symlink. With
/// `want_socket` the last component must be a socket.
pub fn open_nofollow(path: &Path, want_socket: bool) -> Result<OwnedFd, String> {
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
        let next = openat_component(dir.as_raw_fd(), comp, flags).map_err(|e| format!("{}: {e}", path.display()))?;
        if last && want_socket {
            let st = fstat(next.as_raw_fd())?;
            if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
                return Err(format!("{}: not a socket", path.display()));
            }
        }
        dir = next;
    }
    Ok(dir)
}

/// Accept only `/run/user/<uid>/kryptik/<zone>/wayland-0`, walked without
/// following symlinks. `<uid>/`, `kryptik/`, `<zone>/` and the socket must be
/// the session's, the last two directories private, and the listener its proxy.
fn verify_proxy_socket(p: &Path, uid: u32, zone: &str, proxy_exe: Option<&Path>) -> Result<ProxySocket, String> {
    let want = PathBuf::from(format!("/run/user/{uid}/kryptik/{zone}/wayland-0"));
    if p != want {
        return Err(format!("wayland socket must be {}", want.display()));
    }
    let root = openat_component(libc::AT_FDCWD, "/", libc::O_PATH | libc::O_DIRECTORY)?;
    let mut dir = root;
    let uid_s = uid.to_string();
    for (i, comp) in ["run", "user", uid_s.as_str(), "kryptik", zone].iter().enumerate() {
        let next = openat_component(dir.as_raw_fd(), comp, libc::O_PATH | libc::O_DIRECTORY)
            .map_err(|e| format!("wayland socket path: {e}"))?;
        if i >= 2 {
            let st = fstat(next.as_raw_fd())?;
            if st.st_uid != uid {
                return Err(format!("wayland socket path: {comp}/ is owned by uid {}, not the session", st.st_uid));
            }
            if i >= 3 && st.st_mode & 0o077 != 0 {
                return Err(format!("wayland socket path: {comp}/ is not private (mode {:o})", st.st_mode & 0o7777));
            }
        }
        dir = next;
    }
    let sock = openat_component(dir.as_raw_fd(), "wayland-0", libc::O_PATH).map_err(|e| format!("wayland socket: {e}"))?;
    let st = fstat(sock.as_raw_fd())?;
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err("wayland socket is not a socket".into());
    }
    if st.st_uid != uid {
        return Err(format!("wayland socket is owned by uid {}, not the session", st.st_uid));
    }
    verify_proxy_listener(&sock, uid, zone, proxy_exe)?;
    Ok(ProxySocket { _fd: sock, path: want, inode: InodeId::of(&st) })
}

/// Ask the kernel who listens on the socket's inode: it must be the session's
/// uid running kryptik-wlproxy for this zone (which logs a client disconnect).
fn verify_proxy_listener(sock: &OwnedFd, uid: u32, zone: &str, proxy_exe: Option<&Path>) -> Result<(), String> {
    /* Non-blocking: the listener is the session's and may never accept; a
     * full backlog must refuse at once, not block the root daemon. */
    let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
    if s < 0 {
        return Err(format!("socket: {}", std::io::Error::last_os_error()));
    }
    let s = unsafe { OwnedFd::from_raw_fd(s) };
    let path = format!("/proc/self/fd/{}", sock.as_raw_fd());
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as _;
    for (i, b) in path.bytes().enumerate() {
        addr.sun_path[i] = b as _;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + path.len() + 1) as libc::socklen_t;
    if unsafe { libc::connect(s.as_raw_fd(), &addr as *const _ as *const libc::sockaddr, len) } < 0 {
        return Err(format!("nothing usable is listening on the wayland socket: {}", std::io::Error::last_os_error()));
    }
    let peer = peer_cred(s.as_raw_fd()).map_err(|e| format!("wayland socket: cannot identify the listener: {e}"))?;
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
    // A same-uid process named like the proxy is not it (developer instances skip this).
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
    ready: OwnedFd,
    log: PathBuf,
}

/// Start `kryptikd run` for the request; returns the readiness pipe's read end.
/// The passphrase descriptor goes to the child; ours all close on every path.
fn spawn_launcher(
    req: &Request,
    cfg: &ServeConfig,
    pass: Option<OwnedFd>,
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
        "--wifi-dir".into(),
        cfg.wifi_dir.display().to_string(),
        "--ready-fd".into(),
        ready_w.as_raw_fd().to_string(),
    ];
    /* The path, not a descriptor: one opened in this mount namespace cannot be
     * bind-mounted from the zone's (EINVAL). The launcher reopens the path and
     * refuses any other inode (spawn.rs, StagedSocket). */
    if let Some(w) = &wayland {
        args.push("--wayland-socket".into());
        args.push(w.path.display().to_string());
        args.push("--wayland-inode".into());
        args.push(w.inode.to_string());
    }
    if let Some(p) = &pass {
        args.push("--passphrase-fd".into());
        args.push(p.as_raw_fd().to_string());
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
    /* A developer instance's registry is under XDG_RUNTIME_DIR (registry::base),
     * and its launcher must use the same one or `status` and `stop` would not
     * find the zone. Nothing else of the environment crosses. */
    let runtime_dir = if unsafe { libc::geteuid() } != 0 {
        std::env::var("XDG_RUNTIME_DIR").ok().and_then(|v| CString::new(format!("XDG_RUNTIME_DIR={v}")).ok())
    } else {
        None
    };

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
            clear_cloexec(ready_w.as_raw_fd());
            if let Some(p) = &pass {
                clear_cloexec(p.as_raw_fd());
            }
            let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
            ptrs.push(std::ptr::null());
            let mut envp: Vec<*const libc::c_char> = vec![env.as_ptr(), path.as_ptr()];
            if let Some(r) = &runtime_dir {
                envp.push(r.as_ptr());
            }
            envp.push(std::ptr::null());
            libc::execve(cexe.as_ptr(), ptrs.as_ptr(), envp.as_ptr());
            libc::_exit(127);
        }
    }
    // Ours close; from here the launcher's inode check holds the socket's identity.
    drop(ready_w);
    drop(pass);
    drop(wayland);
    Ok(Launch { pid, ready: ready_r, log })
}

/// The launcher's last log line, printable and bounded, for an error reply.
fn last_log_line(log: &Path) -> String {
    // Zone output can make the log any size and any bytes: read only the last 8 KiB.
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

/// A slow request (`stop`, `update-apply`), answered when `reap` sees its
/// command end so the daemon keeps serving meanwhile. Not a thread: `reap`
/// collects every child and would take the status a thread waited for.
struct Job {
    conn: UnixStream,
    pid: libc::pid_t,
    what: JobKind,
    /// stdout and stderr, in memfds: a pipe could fill while nobody reads it.
    out: std::fs::File,
    err: std::fs::File,
    exited: Option<i32>,
}

#[derive(Clone, PartialEq, Debug)]
enum JobKind {
    Stop { uid: u32, zone: String },
    UpdateApply,
}

fn memfile(name: &str) -> Result<std::fs::File, String> {
    let c = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
    let fd = unsafe { libc::memfd_create(c.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(format!("memfd_create: {}", std::io::Error::last_os_error()));
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Start a job's command. Its status is left for `reap`.
fn start_job(conn: UnixStream, what: JobKind, cmd: &mut std::process::Command) -> Result<Job, (UnixStream, String)> {
    let files = memfile("kryptikd-job-out").and_then(|o| memfile("kryptikd-job-err").map(|e| (o, e)));
    let (out, err) = match files {
        Ok(f) => f,
        Err(e) => return Err((conn, e)),
    };
    let (o2, e2) = match (out.try_clone(), err.try_clone()) {
        (Ok(o), Ok(e)) => (o, e),
        _ => return Err((conn, "could not hold the command's output".into())),
    };
    match cmd.stdin(std::process::Stdio::null()).stdout(o2).stderr(e2).spawn() {
        // The Child is dropped without a wait: `reap` collects it.
        Ok(child) => Ok(Job { conn, pid: child.id() as libc::pid_t, what, out, err, exited: None }),
        Err(e) => Err((conn, e.to_string())),
    }
}

fn read_back(f: &mut std::fs::File) -> String {
    use std::io::{Read, Seek};
    let mut s = String::new();
    let _ = f.seek(std::io::SeekFrom::Start(0));
    let _ = f.take(1 << 20).read_to_string(&mut s);
    s
}

/// Send a job's reply once its command has ended.
fn finish_job(j: &mut Job, st: i32) {
    let ok = libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0;
    // A failure's reason is the command's last line on stderr, which went to
    // this log before the command ran as a job.
    let why = |j: &mut Job, or: &str| {
        let err = read_back(&mut j.err);
        err.lines().rev().map(str::trim).find(|l| !l.is_empty()).unwrap_or(or).to_string()
    };
    match j.what.clone() {
        JobKind::Stop { uid, zone } if ok => {
            eprintln!("kryptikd serve: uid {uid} stopped zone {zone:?}");
            reply(&j.conn, "ok\n");
        }
        JobKind::Stop { uid, zone } => {
            let code = if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { -1 };
            let why = why(j, "no reason given");
            eprintln!("kryptikd serve: uid {uid} could not stop zone {zone:?}: exit {code}: {why}");
            reply(&j.conn, &format!("error: stop exited {code}: {why}\n"));
        }
        JobKind::UpdateApply if ok => {
            eprintln!("kryptikd serve: update-apply");
            reply(&j.conn, &format!("ok\n{}", read_back(&mut j.out)));
        }
        JobKind::UpdateApply => {
            let why = why(j, "kryptik-update apply failed");
            eprintln!("kryptikd serve: update-apply failed: {why}");
            reply(&j.conn, &format!("error: {why}\n"));
        }
    }
}

fn reply(mut c: &UnixStream, text: &str) {
    let _ = c.write_all(text.as_bytes());
    let _ = c.flush();
}

/// Reap children: record a pending launcher's or a job's status, log any other.
fn reap(pending: &mut [Pending], jobs: &mut [Job]) {
    loop {
        let mut st = 0;
        let p = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
        if p <= 0 {
            break;
        }
        if let Some(j) = jobs.iter_mut().find(|j| j.pid == p) {
            j.exited = Some(st);
            continue;
        }
        match pending.iter_mut().find(|x| x.launch.pid == p) {
            Some(x) => x.exited = Some(st),
            None => eprintln!("kryptikd serve: launcher {p} {}", exit_text(st)),
        }
    }
}

/// Wait up to 500 ms for a launcher's status once its pipe has closed: the
/// close can reach us before the exit does.
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
    /// The net zone's Wi-Fi credentials (wifi.rs), bound into the nic zone.
    pub wifi_dir: PathBuf,
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
        wifi_dir: PathBuf::from(opt("--wifi-dir").unwrap_or_else(|| crate::wifi::DEFAULT_DIR.to_string())),
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
    /* Only the default directory is made root:kryptik 0750, so the group alone
     * reaches the socket; a directory named with --socket is left as found. */
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

/// Create the session's /run/user/<uid> (0700, the user's). With no logind,
/// the daemon is the one root process the session can ask.
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

/// Serve one connection. A started launch is returned to be watched and a
/// slow command pushed to `jobs`; anything else is answered here.
fn handle(cfg: &ServeConfig, conn: UnixStream, jobs: &mut Vec<Job>) -> Option<Pending> {
    let fd = conn.as_raw_fd();
    let Ok(peer) = peer_cred(fd) else {
        reply(&conn, "error: unidentified peer\n");
        return None;
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
    let text = String::from_utf8_lossy(&text).into_owned();
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
            // A trusted-UI gesture, run as root through our own `clipboard move`.
            let out = std::process::Command::new("/proc/self/exe").args(["clipboard", "move", from, to]).output();
            match out {
                Ok(o) if o.status.success() => {
                    eprintln!("kryptikd serve: uid {uid} moved the clipboard {from:?} -> {to:?}");
                    reply(&conn, &format!("ok {}\n", String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or("moved")));
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
            let what = JobKind::Stop { uid, zone: zone.to_string() };
            match start_job(conn, what, std::process::Command::new("/proc/self/exe").args(["stop", zone])) {
                Ok(j) => jobs.push(j),
                Err((conn, e)) => reply(&conn, &format!("error: {e}\n")),
            }
        }
        /* The user's side of the update channel (update.rs). Until `fetch` the
         * net zone is told `idle`; `apply` hands the stage to kryptik-update,
         * which verifies it all again before writing a slot. */
        "update-status" | "update-fetch" | "update-apply" => {
            use crate::update as up;
            let dir = std::path::Path::new(up::STATE_DIR);
            let running = up::running_version();
            let done = match verb {
                "update-status" => {
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
                    Ok(up::status(dir, now, &running))
                }
                "update-fetch" => up::want(dir, &running).map(|v| format!("{v} will be fetched when the net zone next asks; `kryptik update status` shows it arriving\n")),
                _ => {
                    // Started, not waited for; one at a time.
                    if jobs.iter().any(|j| j.what == JobKind::UpdateApply) {
                        reply(&conn, "error: an update is already being applied\n");
                        return None;
                    }
                    match up::complete_stage(dir) {
                        Ok(stage) => {
                            let mut cmd = std::process::Command::new(up::TOOL);
                            cmd.arg("apply").arg(&stage).env_clear().env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
                            match start_job(conn, JobKind::UpdateApply, &mut cmd) {
                                Ok(j) => jobs.push(j),
                                Err((conn, e)) => reply(&conn, &format!("error: {}: {e}\n", up::TOOL)),
                            }
                        }
                        Err(e) => reply(&conn, &format!("error: {e}\n")),
                    }
                    return None;
                }
            };
            match done {
                Ok(text) => {
                    eprintln!("kryptikd serve: {verb}");
                    reply(&conn, &format!("ok\n{text}"));
                }
                Err(e) => reply(&conn, &format!("error: {e}\n")),
            }
        }
        "wifi-list" => match crate::wifi::list(&cfg.wifi_dir) {
            Ok(names) => {
                let mut out = String::new();
                for n in names {
                    out.push_str(&format!("network {n}\n"));
                }
                out.push_str("end\n");
                reply(&conn, &out);
            }
            Err(e) => reply(&conn, &format!("error: {e}\n")),
        },
        "wifi-add" | "wifi-forget" => {
            // The body holds the passphrase: nothing below prints the request or the psk.
            let req = match parse_wifi(&text) {
                Ok(r) => r,
                Err(e) => {
                    reply(&conn, &format!("error: {e}\n"));
                    return None;
                }
            };
            let owner = match crate::wifi::owner_for(&cfg.zones_dir) {
                Ok(o) => o,
                Err(e) => {
                    reply(&conn, &format!("error: {e}\n"));
                    return None;
                }
            };
            let done = if verb == "wifi-add" {
                crate::wifi::add(&cfg.wifi_dir, owner, &req.ssid, req.psk.as_deref().unwrap_or("")).map(|a| match a {
                    crate::wifi::Added::New => "added network",
                    crate::wifi::Added::Replaced => "replaced the passphrase of network",
                })
            } else {
                crate::wifi::forget(&cfg.wifi_dir, owner, &req.ssid).map(|()| "forgot network")
            };
            match done {
                Ok(what) => {
                    /* The file is bound in at zone start, so a restart applies it. A
                     * restart that cannot happen is reported, not a failure. */
                    let restart = crate::wifi::restart_net_zone(&cfg.wifi_dir);
                    eprintln!("kryptikd serve: uid {uid} {what} {:?}; {restart}", req.ssid);
                    reply(&conn, &format!("ok {what} {:?}; {restart}\n", req.ssid));
                }
                Err(e) => {
                    eprintln!("kryptikd serve: uid {uid} {verb} {:?} refused: {e}", req.ssid);
                    reply(&conn, &format!("error: {e}\n"));
                }
            }
        }
        "run" => {
            let req = match parse_run(&text) {
                Ok(r) => r,
                Err(e) => {
                    reply(&conn, &format!("error: {e}\n"));
                    return None;
                }
            };
            // Check the zone exists before forking, so a bad name is answered now.
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
        "kryptikd serve: listening on {} for {}; zones {}, data {}, wifi {}, logs {}",
        cfg.socket.display(),
        if cfg.developer { format!("uid {} (developer instance)", unsafe { libc::geteuid() }) } else { format!("group {}", cfg.group) },
        cfg.zones_dir.display(),
        cfg.rootfs,
        cfg.wifi_dir.display(),
        cfg.log_dir.display()
    );

    let mut pending: Vec<Pending> = Vec::new();
    let mut jobs: Vec<Job> = Vec::new();
    loop {
        reap(&mut pending, &mut jobs);
        jobs.retain_mut(|j| match j.exited {
            Some(st) => {
                finish_job(j, st);
                false
            }
            None => true,
        });

        // fds[0] is the listener, then one per launch awaiting readiness; timeout: nearest deadline.
        let mut fds: Vec<libc::pollfd> = vec![libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 }];
        let mut watched: Vec<usize> = Vec::new();
        let now = Instant::now();
        let mut timeout: i32 = -1;
        for (i, p) in pending.iter().enumerate() {
            if p.ready_at.is_none() {
                fds.push(libc::pollfd { fd: p.launch.ready.as_raw_fd(), events: libc::POLLIN, revents: 0 });
                watched.push(i);
            }
            let left = p.deadline().saturating_duration_since(now).as_millis() as i32;
            timeout = if timeout < 0 { left } else { timeout.min(left) };
        }
        // `reap` sees a job end only at the top of the loop: wake every 200 ms while jobs run.
        if !jobs.is_empty() {
            timeout = if timeout < 0 { 200 } else { timeout.min(200) };
        }
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, timeout) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                eprintln!("kryptikd serve: poll: {e}");
            }
            continue;
        }

        // A byte on a readiness pipe means the zone's pid 1 exists; EOF, that the launcher died first.
        let mut done: Vec<usize> = Vec::new();
        for (k, &i) in watched.iter().enumerate() {
            let ev = fds[1 + k].revents;
            if ev & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
                continue;
            }
            let mut buf = [0u8; 16];
            let r = unsafe { libc::read(pending[i].launch.ready.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
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
                // A launcher that exited non-zero while settling started a zone whose command failed.
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
                    if let Some(p) = handle(&cfg, conn, &mut jobs) {
                        pending.push(p);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => eprintln!("kryptikd serve: accept: {e}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_run_refuses_bad_requests() {
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
    fn request_complete_at_terminator() {
        assert!(request_complete(b"status\n"));
        assert!(request_complete(b"info work\n"));
        assert!(request_complete(b"runtime\n"));
        assert!(request_complete(b"stop work\n"));
        assert!(!request_complete(b"stat"));
        assert!(!request_complete(b"run work\n"));
        assert!(!request_complete(b"run work\narg x\n"));
        assert!(request_complete(b"run work\narg x\nend\n"));
        assert!(!request_complete(b"run work\narg x\nend"));
        assert!(request_complete(b"wifi-list\n"));
        assert!(!request_complete(b"wifi-add\n"));
        assert!(!request_complete(b"wifi-add\nssid x\npsk y\n"));
        assert!(request_complete(b"wifi-add\nssid x\npsk y\nend\n"));
        assert!(!request_complete(b"wifi-forget\nssid x\n"));
        assert!(request_complete(b"wifi-forget\nssid x\nend\n"));
    }

    #[test]
    fn parse_wifi_keeps_values_hides_psk() {
        let r = parse_wifi("wifi-add\nssid Cafe Wifi \npsk pass word\nend\n").unwrap();
        assert_eq!(r.ssid, "Cafe Wifi ");
        assert_eq!(r.psk.as_deref(), Some("pass word"));
        let r = parse_wifi("wifi-forget\nssid Home\nend\n").unwrap();
        assert_eq!((r.ssid.as_str(), r.psk), ("Home", None));
        for bad in [
            "wifi-add\nssid a\nend\n",                    // no psk
            "wifi-add\npsk secret\nend\n",                // no ssid
            "wifi-add\nssid a\npsk se\ncret\nend\n",      // a newline in the psk
            "wifi-add\nssid a\npsk secret\n",             // no end
            "wifi-add x\nssid a\npsk secret\nend\n",      // the verb stands alone
            "wifi-forget\nssid a\npsk secret\nend\n",     // forget takes no psk
            "wifi-add\nssid a\nssid b\npsk secret\nend\n", // one ssid
        ] {
            let e = parse_wifi(bad).unwrap_err();
            assert!(!e.contains("secret") && !e.contains("cret"), "{bad:?}: the refusal repeats a value: {e}");
        }
    }

    /// The path rule: only the session's own `<zone>/wayland-0` is considered.
    #[test]
    fn proxy_path_must_be_sessions_own() {
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

    // The ownership and listener checks run against the daemon in compartments/tests/serve.sh.

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
    fn full_proxy_backlog_does_not_block() {
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
        // Closing the listener releases a blocking connect, so a regression fails instead of hanging.
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
    fn last_log_line_reads_tail() {
        let dir = std::env::temp_dir().join(format!("kryptik-serve-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("zone-x.log");
        std::fs::write(&log, "first\nkryptikd: could not start zone \"x\": no such policy\n\n").unwrap();
        assert_eq!(last_log_line(&log), "kryptikd: could not start zone \"x\": no such policy");
        assert_eq!(last_log_line(&dir.join("absent.log")), "");
        // Zone output shares the log: an invalid byte or a huge file must not hide the error.
        std::fs::write(&log, b"\xff\n").unwrap();
        let mut large = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        large.set_len(32 * 1024 * 1024).unwrap(); // sparse: no large allocation or disk write
        large.write_all(b"\nlast launch error\n\n").unwrap();
        assert_eq!(last_log_line(&log), "last launch error");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn socketpair_peer_is_self() {
        let (a, _b) = UnixStream::pair().unwrap();
        let cred = peer_cred(a.as_raw_fd()).unwrap();
        assert_eq!((cred.uid, cred.gid), unsafe { (libc::geteuid(), libc::getegid()) });
        assert_eq!(cred.pid, std::process::id() as i32);
    }

    #[test]
    fn failed_job_says_why() {
        use std::io::Read;
        let (conn, mut client) = UnixStream::pair().unwrap();
        let mut err = memfile("t-err").unwrap();
        err.write_all(b"kryptikd: stopping\nzone \"alpha\" did not stop\n\n").unwrap();
        let what = JobKind::Stop { uid: 1000, zone: "alpha".into() };
        let mut j = Job { conn, pid: 0, what, out: memfile("t-out").unwrap(), err, exited: None };
        finish_job(&mut j, 3 << 8);
        drop(j);
        let mut got = String::new();
        client.read_to_string(&mut got).unwrap();
        assert_eq!(got, "error: stop exited 3: zone \"alpha\" did not stop\n");
    }
}
