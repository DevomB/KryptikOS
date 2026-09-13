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
//!            status\n
//!   reply    ok <launcher pid>\n  |  error: <why>\n  |  the status lines

use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub const SOCKET_DIR: &str = "/run/kryptik-launch";
pub const SOCKET_PATH: &str = "/run/kryptik-launch/launch.sock";
pub const GROUP: &str = "kryptik";
const MAX_REQUEST: usize = 16 * 1024;

fn gid_of_group(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    let g = unsafe { libc::getgrnam(c.as_ptr()) };
    if g.is_null() {
        None
    } else {
        Some(unsafe { (*g).gr_gid })
    }
}

/// Is `uid` root, or a member (primary or supplementary) of GROUP?
fn authorised(uid: u32) -> bool {
    if uid == 0 {
        return true;
    }
    let Some(gid) = gid_of_group(GROUP) else { return false };
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return false;
    }
    if unsafe { (*pw).pw_gid } == gid {
        return true;
    }
    let name = unsafe { CStr::from_ptr((*pw).pw_name) }.to_string_lossy().to_string();
    let c = CString::new(GROUP).unwrap();
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

fn peer_uid(fd: RawFd) -> Option<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut libc::c_void, &mut len) };
    if r == 0 {
        Some(cred.uid)
    } else {
        None
    }
}

/// Read the request text and any descriptor that came with it.
fn recv_request(fd: RawFd) -> Result<(Vec<u8>, Vec<RawFd>), String> {
    let mut text = Vec::new();
    let mut fds = Vec::new();
    loop {
        let mut buf = [0u8; 4096];
        let mut cmsg = [0u8; 64];
        let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg.len() as _;
        let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n < 0 {
            return Err(format!("recvmsg: {}", std::io::Error::last_os_error()));
        }
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                    let data = libc::CMSG_DATA(c) as *const RawFd;
                    let count = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / std::mem::size_of::<RawFd>();
                    for i in 0..count {
                        fds.push(*data.add(i));
                    }
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
        }
        if n == 0 {
            break;
        }
        text.extend_from_slice(&buf[..n as usize]);
        if text.len() > MAX_REQUEST {
            for f in fds {
                unsafe { libc::close(f) };
            }
            return Err("request too long".into());
        }
        if text.ends_with(b"end\n") || text.ends_with(b"status\n") || (text.starts_with(b"stop ") && text.ends_with(b"\n")) {
            break;
        }
    }
    Ok((text, fds))
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
            Some(a) if !a.contains('\0') => req.argv.push(a.to_string()),
            _ => return Err(format!("run: unexpected line {l:?}")),
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

/// The proxy socket a session may hand over: its own, under its runtime
/// directory, named as the proxy names it. Anything else is refused, so a
/// zone can only ever be given a proxy.
fn wayland_path_ok(p: &Path, uid: u32) -> bool {
    let want_prefix = format!("/run/user/{uid}/kryptik/");
    let s = p.display().to_string();
    s.starts_with(&want_prefix) && s.ends_with("/wayland-0") && !s.contains("/../")
}

fn reply(mut c: &UnixStream, text: &str) {
    let _ = c.write_all(text.as_bytes());
    let _ = c.flush();
}

fn spawn_launcher(req: &Request, zones_dir: &Path, rootfs: &str, pass_fd: Option<RawFd>, uid: u32) -> Result<i32, String> {
    let exe = std::fs::read_link("/proc/self/exe").map_err(|e| format!("/proc/self/exe: {e}"))?;
    let mut args: Vec<String> = vec![
        "run".into(), req.zone.clone(), "--zones".into(), zones_dir.display().to_string(), "--rootfs".into(), rootfs.into(),
    ];
    if let Some(w) = &req.wayland {
        args.push("--wayland-socket".into());
        args.push(w.display().to_string());
    }
    if let Some(fd) = pass_fd {
        args.push("--passphrase-fd".into());
        args.push(fd.to_string());
    }
    args.push("--".into());
    args.extend(req.argv.iter().cloned());
    let log = format!("/var/log/kryptik/zone-{}.log", req.zone);
    let logf = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(&log).map_err(|e| format!("{log}: {e}"))?;
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
            if let Some(fd) = pass_fd {
                // inherit through the exec
                let fl = libc::fcntl(fd, libc::F_GETFD);
                libc::fcntl(fd, libc::F_SETFD, fl & !libc::FD_CLOEXEC);
            }
            let cexe = CString::new(exe.display().to_string()).unwrap();
            let cargs: Vec<CString> = std::iter::once(CString::new("kryptikd").unwrap())
                .chain(args.iter().map(|a| CString::new(a.as_str()).unwrap()))
                .collect();
            let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
            ptrs.push(std::ptr::null());
            let env = CString::new(format!("KRYPTIK_LAUNCHED_BY_UID={uid}")).unwrap();
            let path = CString::new("PATH=/usr/bin:/usr/sbin").unwrap();
            let envp: [*const libc::c_char; 3] = [env.as_ptr(), path.as_ptr(), std::ptr::null()];
            libc::execve(cexe.as_ptr(), ptrs.as_ptr(), envp.as_ptr());
            libc::_exit(127);
        }
    }
    if let Some(fd) = pass_fd {
        unsafe { libc::close(fd) };
    }
    Ok(pid)
}

pub fn cmd_serve(zones_dir: &Path, args: &[String]) -> ExitCode {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("kryptikd serve: must run as root");
        return ExitCode::from(2);
    }
    let rootfs = args
        .iter()
        .position(|a| a == "--rootfs")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| crate::DEFAULT_ROOTFS_BASE.to_string());
    let Some(gid) = gid_of_group(GROUP) else {
        eprintln!("kryptikd serve: no group {GROUP:?}; nobody could connect");
        return ExitCode::FAILURE;
    };
    let _ = std::fs::create_dir_all(SOCKET_DIR);
    let _ = std::fs::set_permissions(SOCKET_DIR, std::fs::Permissions::from_mode(0o750));
    let cdir = CString::new(SOCKET_DIR).unwrap();
    unsafe { libc::chown(cdir.as_ptr(), 0, gid) };
    let _ = std::fs::remove_file(SOCKET_PATH);
    let listener = match UnixListener::bind(SOCKET_PATH) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("kryptikd serve: cannot bind {SOCKET_PATH}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let csock = CString::new(SOCKET_PATH).unwrap();
    unsafe { libc::chown(csock.as_ptr(), 0, gid) };
    let _ = std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o660));
    let _ = std::fs::create_dir_all("/var/log/kryptik");
    // Children are reaped as they exit; SA_NOCLDWAIT would lose their status,
    // and status is worth a log line.
    eprintln!("kryptikd serve: listening on {SOCKET_PATH} for group {GROUP} (gid {gid}); zones {}, data {rootfs}", zones_dir.display());
    loop {
        // reap
        loop {
            let mut st = 0;
            let p = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
            if p <= 0 {
                break;
            }
            eprintln!("kryptikd serve: launcher {p} exited ({})", if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 128 });
        }
        let (conn, _) = match listener.accept() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("kryptikd serve: accept: {e}");
                continue;
            }
        };
        let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let fd = conn.as_raw_fd();
        let uid = match peer_uid(fd) {
            Some(u) => u,
            None => {
                reply(&conn, "error: unidentified peer\n");
                continue;
            }
        };
        if !authorised(uid) {
            reply(&conn, &format!("error: uid {uid} is not in group {GROUP}\n"));
            eprintln!("kryptikd serve: refused uid {uid} (not in {GROUP})");
            continue;
        }
        let (text, fds) = match recv_request(fd) {
            Ok(x) => x,
            Err(e) => {
                reply(&conn, &format!("error: {e}\n"));
                continue;
            }
        };
        let text = String::from_utf8_lossy(&text).to_string();
        if text.starts_with("status") {
            let mut out = String::new();
            for z in crate::registry::names() {
                if let Ok(crate::registry::State::Running { .. }) = crate::registry::state(&z) {
                    out.push_str(&format!("running {z}\n"));
                }
            }
            out.push_str("end\n");
            reply(&conn, &out);
            for f in fds {
                unsafe { libc::close(f) };
            }
            continue;
        }
        if let Some(rest) = text.strip_prefix("stop ") {
            let zone = rest.trim();
            for f in fds {
                unsafe { libc::close(f) };
            }
            if !ident_ok(zone) {
                reply(&conn, "error: bad zone name\n");
                continue;
            }
            let r = std::process::Command::new("/proc/self/exe").args(["stop", zone]).status();
            match r {
                Ok(s) if s.success() => reply(&conn, "ok\n"),
                Ok(s) => reply(&conn, &format!("error: stop exited {}\n", s.code().unwrap_or(-1))),
                Err(e) => reply(&conn, &format!("error: {e}\n")),
            }
            eprintln!("kryptikd serve: uid {uid} stopped zone {zone:?}");
            continue;
        }
        let req = match parse_run(&text) {
            Ok(r) => r,
            Err(e) => {
                for f in fds {
                    unsafe { libc::close(f) };
                }
                reply(&conn, &format!("error: {e}\n"));
                continue;
            }
        };
        if let Some(w) = &req.wayland {
            if !wayland_path_ok(w, uid) {
                for f in fds {
                    unsafe { libc::close(f) };
                }
                reply(&conn, &format!("error: wayland socket must be /run/user/{uid}/kryptik/<zone>/wayland-0\n"));
                continue;
            }
        }
        let pass_fd = if req.wants_fd {
            match fds.len() {
                1 => Some(fds[0]),
                n => {
                    for f in fds {
                        unsafe { libc::close(f) };
                    }
                    reply(&conn, &format!("error: pass=fd needs exactly one descriptor, got {n}\n"));
                    continue;
                }
            }
        } else {
            for f in fds {
                unsafe { libc::close(f) };
            }
            None
        };
        match spawn_launcher(&req, zones_dir, &rootfs, pass_fd, uid) {
            Ok(pid) => {
                eprintln!("kryptikd serve: uid {uid} launched zone {:?} ({}) as launcher {pid}", req.zone, req.argv[0]);
                reply(&conn, &format!("ok {pid}\n"));
            }
            Err(e) => {
                eprintln!("kryptikd serve: uid {uid} zone {:?}: {e}", req.zone);
                reply(&conn, &format!("error: {e}\n"));
            }
        }
    }
}

/// Client side, for tests and for the kryptik command: send one request.
pub fn request(text: &str, fd: Option<RawFd>) -> Result<String, String> {
    let mut s = UnixStream::connect(SOCKET_PATH).map_err(|e| format!("{SOCKET_PATH}: {e}"))?;
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
    fn only_the_sessions_own_proxy_socket_is_accepted() {
        assert!(wayland_path_ok(Path::new("/run/user/1000/kryptik/work/wayland-0"), 1000));
        assert!(!wayland_path_ok(Path::new("/run/user/1000/kryptik/work/wayland-0"), 1001));
        assert!(!wayland_path_ok(Path::new("/run/user/1000/wayland-0"), 1000), "the compositor's own socket is never handed to a zone");
        assert!(!wayland_path_ok(Path::new("/run/user/1000/kryptik/../wayland-0"), 1000));
        assert!(!wayland_path_ok(Path::new("/tmp/wayland-0"), 1000));
    }

    #[test]
    fn identifiers() {
        assert!(ident_ok("work"));
        assert!(ident_ok("net-zone_2"));
        assert!(!ident_ok(""));
        assert!(!ident_ok("a/b"));
        assert!(!ident_ok(&"x".repeat(40)));
    }
}
