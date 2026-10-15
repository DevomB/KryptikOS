//! The proxy as a process, event loop included; the upstream is the test's own Unix listener.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(10);

// --- wire encoding ---------------------------------------------------------

fn u32ne(v: u32) -> [u8; 4] {
    v.to_ne_bytes()
}

fn msg(object: u32, opcode: u16, body: &[u8]) -> Vec<u8> {
    let size = (8 + body.len()) as u32;
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&u32ne(object));
    out.extend_from_slice(&u32ne((size << 16) | opcode as u32));
    out.extend_from_slice(body);
    out
}

fn wl_string(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let len = s.len() + 1;
    out.extend_from_slice(&u32ne(len as u32));
    out.extend_from_slice(s.as_bytes());
    out.push(0);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn get_registry(id: u32) -> Vec<u8> {
    msg(1, 1, &u32ne(id))
}

fn sync(callback: u32) -> Vec<u8> {
    msg(1, 0, &u32ne(callback))
}

fn global(registry: u32, name: u32, iface: &str, version: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&u32ne(name));
    body.extend_from_slice(&wl_string(iface));
    body.extend_from_slice(&u32ne(version));
    msg(registry, 0, &body)
}

fn bind(registry: u32, name: u32, iface: &str, version: u32, new_id: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&u32ne(name));
    body.extend_from_slice(&wl_string(iface));
    body.extend_from_slice(&u32ne(version));
    body.extend_from_slice(&u32ne(new_id));
    msg(registry, 0, &body)
}

/// Split a byte stream into (object, opcode, body) messages.
fn split_messages(mut bytes: &[u8]) -> Vec<(u32, u16, Vec<u8>)> {
    let mut out = Vec::new();
    while bytes.len() >= 8 {
        let object = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let word = u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let size = (word >> 16) as usize;
        let opcode = (word & 0xffff) as u16;
        assert!(size >= 8 && size <= bytes.len(), "malformed message in stream: size {size}, {} left", bytes.len());
        out.push((object, opcode, bytes[8..size].to_vec()));
        bytes = &bytes[size..];
    }
    assert!(bytes.is_empty(), "{} trailing bytes", bytes.len());
    out
}

fn decode_string(body: &[u8]) -> String {
    let len = u32::from_ne_bytes([body[0], body[1], body[2], body[3]]) as usize;
    assert!(len >= 1 && 4 + len <= body.len());
    assert_eq!(body[4 + len - 1], 0, "NUL-terminated");
    String::from_utf8(body[4..4 + len - 1].to_vec()).expect("the rewritten title is valid UTF-8")
}

// --- the proxy under test --------------------------------------------------

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// The proxy as a test starts it, or, for the proxy-calls check (KRYPTIK_PROXY_TRACE names a
/// directory), under a strace of its own writing one file for this start: the tests' own calls
/// are never traced, so none can be read as the proxy's.
fn proxy_command() -> Command {
    let bin = env!("CARGO_BIN_EXE_kryptik-wlproxy");
    let Some(dir) = std::env::var_os("KRYPTIK_PROXY_TRACE") else { return Command::new(bin) };
    let n = TRACED.fetch_add(1, Ordering::SeqCst);
    let mut cmd = Command::new("strace");
    cmd.args(["-f", "-q", "-s", "256", "-o"])
        .arg(Path::new(&dir).join(format!("proxy.{}.{n}", std::process::id())))
        .arg("--")
        .arg(bin);
    cmd
}
static TRACED: AtomicUsize = AtomicUsize::new(0);

struct Proxy {
    child: Child,
    dir: PathBuf,
    listen: PathBuf,
    upstream: UnixListener,
}

impl Proxy {
    fn start(zone: &str, extra: &[&str]) -> Proxy {
        Proxy::start_with(zone, extra, None)
    }

    /// Started with RLIMIT_NOFILE set to (soft, hard).
    fn start_with(zone: &str, extra: &[&str], nofile: Option<(u64, u64)>) -> Proxy {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        // Unix socket paths are limited to 108 bytes; the system temp dir is short.
        let dir = std::env::temp_dir().join(format!("kwlp-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let upstream_path = dir.join("upstream");
        let listen = dir.join("wayland-0");
        let upstream = UnixListener::bind(&upstream_path).unwrap();
        upstream.set_nonblocking(true).unwrap();
        let mut cmd = proxy_command();
        if let Some((soft, hard)) = nofile {
            let rl = libc::rlimit { rlim_cur: soft, rlim_max: hard };
            unsafe {
                cmd.pre_exec(move || match libc::setrlimit(libc::RLIMIT_NOFILE, &rl) {
                    0 => Ok(()),
                    _ => Err(std::io::Error::last_os_error()),
                });
            }
        }
        let child = cmd
            .arg("--zone")
            .arg(zone)
            .arg("--listen")
            .arg(&listen)
            .arg("--upstream")
            .arg(&upstream_path)
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn kryptik-wlproxy");
        let mut p = Proxy { child, dir, listen, upstream };
        let start = Instant::now();
        while !p.listen.exists() {
            if let Some(st) = p.child.try_wait().unwrap() {
                panic!("proxy exited before listening: {st}\n{}", p.stderr_so_far());
            }
            assert!(start.elapsed() < TIMEOUT, "proxy never created {}", p.listen.display());
            std::thread::sleep(Duration::from_millis(10));
        }
        p
    }

    /// As the launch daemon starts it: the listener made here and handed over as descriptor 3,
    /// the upstream as descriptor 4, which the proxy connects through by its /proc path, and the
    /// gesture's socket (`dir/control`) as descriptor 5, answering this test's uid.
    fn start_passed(zone: &str) -> Proxy {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("kwlp-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let upstream_path = dir.join("upstream");
        let listen = dir.join("wayland-0");
        let upstream = UnixListener::bind(&upstream_path).unwrap();
        upstream.set_nonblocking(true).unwrap();
        let listener = UnixListener::bind(&listen).unwrap();
        let path = std::ffi::CString::new(upstream_path.as_os_str().as_bytes()).unwrap();
        let up = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        assert!(up >= 0, "{}: {}", upstream_path.display(), std::io::Error::last_os_error());
        let control = UnixListener::bind(dir.join("control")).unwrap();
        let keep = [listener.as_raw_fd(), up, control.as_raw_fd()];
        let mut cmd = proxy_command();
        unsafe {
            cmd.pre_exec(move || {
                // All copied above 9 first, so placing one cannot overwrite another.
                let high = keep.map(|fd| libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10));
                if high.iter().any(|&fd| fd < 0) || (0..3).any(|i| libc::dup2(high[i], 3 + i as RawFd) < 0) {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let uid = unsafe { libc::geteuid() }.to_string();
        let child = cmd
            .args(["--zone", zone, "--listen-fd", "3", "--upstream", "/proc/self/fd/4"])
            .args(["--control-fd", "5", "--control-uid", uid.as_str()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn kryptik-wlproxy");
        unsafe { libc::close(up) };
        Proxy { child, dir, listen, upstream }
    }

    fn stderr_so_far(&mut self) -> String {
        // Only meaningful once the child has exited (the pipe is at EOF).
        let mut s = String::new();
        if let Some(e) = self.child.stderr.as_mut() {
            let _ = e.read_to_string(&mut s);
        }
        s
    }

    /// Connect a client; returns it with the upstream connection the proxy opened for it.
    fn connect(&mut self) -> (UnixStream, UnixStream) {
        let client = UnixStream::connect(&self.listen).expect("connect to the proxy");
        client.set_read_timeout(Some(TIMEOUT)).unwrap();
        client.set_write_timeout(Some(TIMEOUT)).unwrap();
        let start = Instant::now();
        let up = loop {
            match self.upstream.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    if let Some(st) = self.child.try_wait().unwrap() {
                        panic!("proxy exited while a client was connecting: {st}\n{}", self.stderr_so_far());
                    }
                    assert!(start.elapsed() < TIMEOUT, "the proxy never connected upstream for a client");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("upstream accept: {e}"),
            }
        };
        up.set_nonblocking(false).unwrap();
        up.set_read_timeout(Some(TIMEOUT)).unwrap();
        up.set_write_timeout(Some(TIMEOUT)).unwrap();
        (client, up)
    }

    /// The proxy's own pid: the child's, or under the check's strace that child's one child.
    fn proxy_pid(&self) -> u32 {
        let pid = self.child.id();
        if std::env::var_os("KRYPTIK_PROXY_TRACE").is_none() {
            return pid;
        }
        std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse().ok())
            .unwrap_or(pid)
    }

    fn alive(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }

    fn assert_alive(&mut self, when: &str) {
        if let Some(st) = self.child.try_wait().unwrap() {
            panic!("proxy exited {when}: {st}\n{}", self.stderr_so_far());
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        // Under the check's strace the proxy is killed first, and strace ends with it.
        let pid = self.proxy_pid();
        if pid != self.child.id() {
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn read_exact_or_panic(s: &mut UnixStream, n: usize, what: &str) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).unwrap_or_else(|e| panic!("reading {n} bytes ({what}): {e}"));
    buf
}

/// Read until `pred` is satisfied by what has arrived, or the deadline.
fn read_until(s: &mut UnixStream, pred: impl Fn(&[u8]) -> bool, what: &str) -> Vec<u8> {
    let mut acc = Vec::new();
    let mut buf = [0u8; 4096];
    s.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let start = Instant::now();
    while !pred(&acc) {
        match s.read(&mut buf) {
            Ok(0) => panic!("EOF while waiting for {what}; got {} bytes", acc.len()),
            Ok(n) => acc.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => panic!("{what}: {e}"),
        }
        assert!(start.elapsed() < TIMEOUT, "timed out waiting for {what}; got {} bytes", acc.len());
    }
    s.set_read_timeout(Some(TIMEOUT)).unwrap();
    acc
}

fn eof_within(s: &mut UnixStream, what: &str) {
    let mut buf = [0u8; 64];
    let start = Instant::now();
    loop {
        match s.read(&mut buf) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(_) => return,
        }
        assert!(start.elapsed() < TIMEOUT, "{what}: no EOF");
    }
}

fn assert_no_stale_socket(p: &Path) {
    assert!(!p.exists(), "{} still exists", p.display());
}

// --- tests -----------------------------------------------------------------

/// First client, more clients, disconnects and a reconnect: the proxy keeps serving.
#[test]
fn serves_clients_through_churn() {
    let mut p = Proxy::start("work", &[]);

    // Client 1's first request must reach the upstream.
    let (mut c1, mut u1) = p.connect();
    c1.write_all(&get_registry(2)).unwrap();
    assert_eq!(read_exact_or_panic(&mut u1, 12, "client 1's get_registry at the upstream"), get_registry(2));
    p.assert_alive("after its first client's first request");

    // The proxy's own data device comes first, named from the top of the range
    // (policy::OWN_GLOBAL_BASE); then the compositor's, filtered: the hidden global between two
    // allowed ones never arrives.
    let own = global(2, 0xFFFF_FF00, "wl_data_device_manager", 3);
    assert_eq!(read_exact_or_panic(&mut c1, own.len(), "the proxy's own data device at client 1"), own);
    u1.write_all(&global(2, 1, "wl_compositor", 6)).unwrap();
    let want = global(2, 1, "wl_compositor", 6);
    assert_eq!(read_exact_or_panic(&mut c1, want.len(), "wl_compositor global at client 1"), want);
    u1.write_all(&global(2, 2, "zwlr_screencopy_manager_v1", 3)).unwrap();
    u1.write_all(&global(2, 3, "wl_shm", 2)).unwrap();
    let want = global(2, 3, "wl_shm", 2);
    let got = read_exact_or_panic(&mut c1, want.len(), "wl_shm global at client 1");
    assert_eq!(got, want, "the hidden screencopy global must not be what arrives next");

    // Client 2 joins while client 1 is live; both are serviced.
    let (mut c2, mut u2) = p.connect();
    c2.write_all(&get_registry(2)).unwrap();
    assert_eq!(read_exact_or_panic(&mut u2, 12, "client 2's get_registry"), get_registry(2));
    c1.write_all(&sync(3)).unwrap();
    assert_eq!(read_exact_or_panic(&mut u1, 12, "client 1's sync after client 2 joined"), sync(3));
    p.assert_alive("with two clients");

    // Client 3 too: three sessions, each on its own pollfd pair.
    let (mut c3, mut u3) = p.connect();
    c3.write_all(&get_registry(2)).unwrap();
    assert_eq!(read_exact_or_panic(&mut u3, 12, "client 3's get_registry"), get_registry(2));
    c2.write_all(&sync(3)).unwrap();
    assert_eq!(read_exact_or_panic(&mut u2, 12, "client 2's sync with three clients"), sync(3));

    // Client 1 leaves: its upstream is closed, the others keep working.
    drop(c1);
    eof_within(&mut u1, "upstream of the departed client 1");
    p.assert_alive("after a client disconnected");
    c2.write_all(&sync(4)).unwrap();
    assert_eq!(read_exact_or_panic(&mut u2, 12, "client 2's sync after client 1 left"), sync(4));
    c3.write_all(&sync(3)).unwrap();
    assert_eq!(read_exact_or_panic(&mut u3, 12, "client 3's sync after client 1 left"), sync(3));

    // The middle session leaves: index bookkeeping after a removal.
    drop(c2);
    eof_within(&mut u2, "upstream of the departed client 2");
    c3.write_all(&sync(4)).unwrap();
    assert_eq!(read_exact_or_panic(&mut u3, 12, "client 3's sync after client 2 left"), sync(4));

    // Reconnect: a fresh client after churn is served like the first.
    let (mut c4, mut u4) = p.connect();
    c4.write_all(&get_registry(2)).unwrap();
    assert_eq!(read_exact_or_panic(&mut u4, 12, "client 4's get_registry"), get_registry(2));

    // The upstream closing on a client ends that session only.
    drop(u3);
    eof_within(&mut c3, "client 3 after its upstream closed");
    p.assert_alive("after an upstream closed");
    c4.write_all(&sync(3)).unwrap();
    assert_eq!(read_exact_or_panic(&mut u4, 12, "client 4's sync at the end"), sync(3));
    assert!(p.alive());
}

/// One sendmsg of `data` with `fds` attached.
fn send_fds(s: &UnixStream, data: &[u8], fds: &[RawFd]) {
    let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut libc::c_void, iov_len: data.len() };
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) } as usize;
    let mut cbuf = vec![0u64; space.div_ceil(8)];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(c) as *mut RawFd, fds.len());
        assert!(libc::sendmsg(s.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) >= 0, "sendmsg: {}", std::io::Error::last_os_error());
    }
}

/// Only clients whose queued fds fit the raised limit are served, so none starves the open ones.
#[test]
fn clients_fit_descriptor_limit() {
    // (300 - 8) / 130: two sessions.
    let mut p = Proxy::start_with("work", &["--max-clients", "32"], Some((100, 300)));
    let limits = std::fs::read_to_string(format!("/proc/{}/limits", p.proxy_pid())).unwrap();
    let files = limits.lines().find(|l| l.starts_with("Max open files")).unwrap();
    assert_eq!(files.split_whitespace().nth(3), Some("300"), "the soft limit was not raised: {files}");

    let (mut good, mut ugood) = p.connect();
    good.write_all(&get_registry(2)).unwrap();
    let _ = read_exact_or_panic(&mut ugood, 12, "good client's get_registry");
    // A second client parks as many descriptors as a session may hold.
    let (hostile, _uhostile) = p.connect();
    let null = std::fs::File::open("/dev/null").unwrap();
    for _ in 0..4 {
        send_fds(&hostile, b"x", &[null.as_raw_fd(); 16]);
    }
    // A third is left waiting: its descriptors would not fit.
    let _third = UnixStream::connect(&p.listen).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(matches!(p.upstream.accept(), Err(e) if e.kind() == ErrorKind::WouldBlock), "a client past the budget was served");
    p.assert_alive("with every session's descriptors queued");
    good.write_all(&sync(3)).unwrap();
    assert_eq!(read_exact_or_panic(&mut ugood, 12, "the good client's sync"), sync(3));
}

/// A client binding a hidden global is refused and cut off; its neighbour is unaffected.
#[test]
fn refused_client_leaves_others_running() {
    let mut p = Proxy::start("work", &[]);
    let (mut good, mut ugood) = p.connect();
    good.write_all(&get_registry(2)).unwrap();
    let _ = read_exact_or_panic(&mut ugood, 12, "good client's get_registry");

    let (mut bad, mut ubad) = p.connect();
    bad.write_all(&get_registry(2)).unwrap();
    let _ = read_exact_or_panic(&mut ubad, 12, "bad client's get_registry");
    ubad.write_all(&global(2, 7, "zwlr_screencopy_manager_v1", 3)).unwrap();
    // Guess the hidden global's name and bind it.
    bad.write_all(&bind(2, 7, "zwlr_screencopy_manager_v1", 3, 3)).unwrap();
    let reply = read_until(&mut bad, |b| b.windows(15).any(|w| w == b"kryptik-wlproxy"), "the refusal");
    let text = String::from_utf8_lossy(&reply);
    assert!(text.contains("not advertised"), "{text}");
    eof_within(&mut bad, "the refused client");
    eof_within(&mut ubad, "the refused client's upstream");

    p.assert_alive("after refusing a client");
    good.write_all(&sync(3)).unwrap();
    assert_eq!(read_exact_or_panic(&mut ugood, 12, "the good client's sync after the refusal"), sync(3));
}

/// Started as the launch daemon starts it, the proxy serves through the descriptors it was given.
#[test]
fn serves_through_the_daemons_descriptors() {
    let mut p = Proxy::start_passed("work");
    let (mut c, mut u) = p.connect();
    c.write_all(&get_registry(2)).unwrap();
    assert_eq!(read_exact_or_panic(&mut u, 12, "get_registry through the passed listener"), get_registry(2));
    let own = global(2, 0xFFFF_FF00, "wl_data_device_manager", 3);
    assert_eq!(read_exact_or_panic(&mut c, own.len(), "the proxy's own data device"), own);
    let want = global(2, 1, "wl_compositor", 6);
    u.write_all(&want).unwrap();
    assert_eq!(read_exact_or_panic(&mut c, want.len(), "wl_compositor back through it"), want);
    p.assert_alive("serving through the daemon's descriptors");
}

/// What a client has been sent and not yet looked at, the descriptors that rode along included.
#[derive(Default)]
struct Inbox {
    bytes: Vec<u8>,
    fds: Vec<RawFd>,
}

impl Inbox {
    /// Every message up to and including the first to `object` with `opcode`, as (object,
    /// opcode, body).
    fn until(&mut self, s: &UnixStream, object: u32, opcode: u16, what: &str) -> Vec<(u32, u16, Vec<u8>)> {
        let start = Instant::now();
        loop {
            let (mut at, mut msgs) = (0, Vec::new());
            while self.bytes.len() - at >= 8 {
                let word = u32::from_ne_bytes(self.bytes[at + 4..at + 8].try_into().unwrap());
                let size = (word >> 16) as usize;
                assert!(size >= 8, "a malformed message waiting for {what}");
                if self.bytes.len() - at < size {
                    break;
                }
                let id = u32::from_ne_bytes(self.bytes[at..at + 4].try_into().unwrap());
                let op = (word & 0xffff) as u16;
                msgs.push((id, op, self.bytes[at + 8..at + size].to_vec()));
                at += size;
                if (id, op) == (object, opcode) {
                    self.bytes.drain(..at);
                    return msgs;
                }
            }
            assert!(start.elapsed() < TIMEOUT, "timed out waiting for {what}; got {msgs:?}");
            self.recv(s, what);
        }
    }

    /// One recvmsg: its bytes, and its descriptors kept for the test to take.
    fn recv(&mut self, s: &UnixStream, what: &str) {
        let mut buf = [0u8; 4096];
        let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
        let mut cbuf = [0u64; 32];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&cbuf) as _;
        let n = unsafe { libc::recvmsg(s.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            assert!(matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted), "{what}: {e}");
            return;
        }
        assert!(n > 0, "end of file waiting for {what}");
        self.bytes.extend_from_slice(&buf[..n as usize]);
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                    let count = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / std::mem::size_of::<RawFd>();
                    let data = libc::CMSG_DATA(c) as *const RawFd;
                    for i in 0..count {
                        self.fds.push(std::ptr::read_unaligned(data.add(i)));
                    }
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
        }
    }
}

/// A client of the zone with wl_seat 3, its keyboard 4, the proxy's data device manager 5 and a
/// data device 6.
fn data_device(c: &mut UnixStream, u: &mut UnixStream) {
    c.write_all(&get_registry(2)).unwrap();
    let own = global(2, 0xFFFF_FF00, "wl_data_device_manager", 3);
    assert_eq!(read_exact_or_panic(c, own.len(), "the proxy's own data device"), own);
    assert_eq!(read_exact_or_panic(u, 12, "get_registry at the upstream"), get_registry(2));
    let seat = global(2, 1, "wl_seat", 9);
    u.write_all(&seat).unwrap();
    assert_eq!(read_exact_or_panic(c, seat.len(), "the seat"), seat);
    c.write_all(&bind(2, 1, "wl_seat", 9, 3)).unwrap();
    c.write_all(&msg(3, 1, &u32ne(4))).unwrap(); // wl_seat.get_keyboard
    c.write_all(&bind(2, 0xFFFF_FF00, "wl_data_device_manager", 3, 5)).unwrap();
    c.write_all(&msg(5, 1, &[u32ne(6), u32ne(3)].concat())).unwrap(); // get_data_device
    // The compositor speaks for the keyboard only once it has heard of it.
    Inbox::default().until(u, 3, 1, "get_keyboard at the upstream");
}

fn enter(u: &mut UnixStream) {
    u.write_all(&msg(4, 1, &[u32ne(10), u32ne(20), u32ne(0)].concat())).unwrap(); // enter(serial, surface, keys [])
}

fn leave(u: &mut UnixStream) {
    u.write_all(&msg(4, 2, &[u32ne(11), u32ne(20)].concat())).unwrap(); // leave(serial, surface)
}

/// The client copies: its data source `source`, offering `mime`, set as the selection.
fn copy(c: &mut UnixStream, source: u32, mime: &str) {
    c.write_all(&msg(5, 0, &u32ne(source))).unwrap(); // create_data_source
    c.write_all(&msg(source, 0, &wl_string(mime))).unwrap(); // offer
    c.write_all(&msg(6, 1, &[u32ne(source), u32ne(10)].concat())).unwrap(); // set_selection
}

/// The wl_data_offer that a data_offer event among `msgs` made.
fn offer_in(msgs: &[(u32, u16, Vec<u8>)]) -> u32 {
    let (_, _, body) = msgs.iter().find(|m| (m.0, m.1) == (6, 0)).expect("a data_offer event");
    u32::from_ne_bytes(body[..4].try_into().unwrap())
}

/// The client pastes `offer` as `mime`; the read end of the descriptor it gave.
fn paste(c: &UnixStream, offer: u32, mime: &str) -> UnixStream {
    let (r, w) = UnixStream::pair().unwrap();
    send_fds(c, &msg(offer, 1, &wl_string(mime)), &[w.as_raw_fd()]); // receive
    r.set_read_timeout(Some(TIMEOUT)).unwrap();
    r
}

/// One request on the gesture's socket, and the whole answer.
fn gesture(p: &Proxy, request: &[u8]) -> Vec<u8> {
    let mut s = UnixStream::connect(p.dir.join("control")).expect("connect to the gesture's socket");
    s.set_read_timeout(Some(TIMEOUT)).unwrap();
    s.write_all(request).unwrap();
    s.shutdown(std::net::Shutdown::Write).unwrap();
    let mut answer = Vec::new();
    s.read_to_end(&mut answer).expect("the proxy's answer");
    answer
}

/// Copy and paste inside the zone, and the gesture's take, give and clear on the socket the
/// daemon hands over: each of the proxy's paths for them, which CI traces.
#[test]
fn copy_paste_and_the_gesture_through_the_daemons_descriptors() {
    const TEXT: &str = "text/plain;charset=utf-8";
    let mut p = Proxy::start_passed("work");
    let (mut ca, mut ua) = p.connect();
    let (mut cb, mut ub) = p.connect();
    data_device(&mut ca, &mut ua);
    data_device(&mut cb, &mut ub);
    let (mut ia, mut ib) = (Inbox::default(), Inbox::default());
    assert_eq!(gesture(&p, b"take\n"), b"empty\n", "nothing copied yet");

    // A has the keyboard and copies; a take reads the copy through a pipe that A writes.
    enter(&mut ua);
    ia.until(&ca, 4, 1, "the keyboard's enter at A");
    copy(&mut ca, 7, TEXT);
    ia.until(&ca, 6, 5, "A's copy offered back to it");
    let mut ctl = UnixStream::connect(p.dir.join("control")).expect("connect to the gesture's socket");
    ctl.set_read_timeout(Some(TIMEOUT)).unwrap();
    ctl.write_all(b"take\n").unwrap();
    ctl.shutdown(std::net::Shutdown::Write).unwrap();
    let got = ia.until(&ca, 7, 1, "the take's send at A's source");
    assert!(String::from_utf8_lossy(&got[got.len() - 1].2).contains(TEXT), "{got:?}");
    let mut pipe = unsafe { std::fs::File::from_raw_fd(ia.fds.pop().expect("the take's pipe")) };
    pipe.write_all(b"hello").unwrap();
    drop(pipe);
    let mut answer = Vec::new();
    ctl.read_to_end(&mut answer).expect("the take's answer");
    let answer = String::from_utf8(answer).unwrap();
    assert!(answer.starts_with("ok ") && answer.ends_with(&format!(" {TEXT} 5\nhello")), "{answer:?}");

    // Given bytes are the proxy's own selection: A's copy is cancelled, A's paste of them is
    // written by the proxy, a take is answered from them, and a clear ends them.
    assert_eq!(gesture(&p, format!("give {TEXT} 5\nworld").as_bytes()), b"ok\n");
    let got = ia.until(&ca, 6, 5, "the given selection offered to A");
    assert!(got.iter().any(|m| (m.0, m.1) == (7, 2)), "A's copy hears it was replaced: {got:?}");
    let mut r = paste(&ca, offer_in(&got), TEXT);
    let mut pasted = String::new();
    r.read_to_string(&mut pasted).expect("the proxy's paste");
    assert_eq!(pasted, "world");
    let answer = String::from_utf8(gesture(&p, b"take\n")).unwrap();
    assert!(answer.ends_with(&format!(" {TEXT} 5\nworld")), "{answer:?}");
    let generation = answer.split(' ').nth(1).unwrap().to_string();
    assert_eq!(gesture(&p, format!("clear {generation}\n").as_bytes()), b"ok\n");
    ia.until(&ca, 6, 5, "the cleared selection said to A");

    // A copies again and B, given the keyboard, pastes it: B's descriptor reaches A's source.
    copy(&mut ca, 8, TEXT);
    ia.until(&ca, 6, 5, "A's second copy offered back to it");
    leave(&mut ua);
    enter(&mut ub);
    let got = ib.until(&cb, 4, 1, "the keyboard's enter at B");
    let mut r = paste(&cb, offer_in(&got), TEXT);
    ia.until(&ca, 8, 1, "B's paste at A's source");
    let mut writer = unsafe { std::fs::File::from_raw_fd(ia.fds.pop().expect("B's descriptor")) };
    writer.write_all(b"moved").unwrap();
    drop(writer);
    let mut pasted = String::new();
    r.read_to_string(&mut pasted).expect("B's paste");
    assert_eq!(pasted, "moved");
    p.assert_alive("after the zone's copies and the gesture");
}

/// `--once` serves one session and removes the listener on exit.
#[test]
fn once_serves_one_client() {
    let mut p = Proxy::start("work", &["--once"]);
    let listen = p.listen.clone();
    let (mut c, mut u) = p.connect();
    c.write_all(&get_registry(2)).unwrap();
    let _ = read_exact_or_panic(&mut u, 12, "the one client's get_registry");
    drop(c);
    let start = Instant::now();
    while p.alive() {
        assert!(start.elapsed() < TIMEOUT, "--once proxy did not exit after its client left");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_no_stale_socket(&listen);
}

/// Long multi-byte titles reach the upstream bounded, prefixed and valid.
#[test]
fn long_unicode_titles_are_rewritten() {
    let mut p = Proxy::start("work", &[]);
    let (mut c, mut u) = p.connect();
    c.write_all(&get_registry(2)).unwrap();
    let _ = read_exact_or_panic(&mut u, 12, "get_registry");
    u.write_all(&global(2, 1, "wl_compositor", 6)).unwrap();
    u.write_all(&global(2, 2, "xdg_wm_base", 6)).unwrap();
    let _ = read_until(&mut c, |b| holds_messages(b, 3), "the proxy's data device and both globals at the client");

    c.write_all(&bind(2, 1, "wl_compositor", 6, 3)).unwrap();
    c.write_all(&bind(2, 2, "xdg_wm_base", 6, 4)).unwrap();
    c.write_all(&msg(3, 0, &u32ne(5))).unwrap(); // wl_compositor.create_surface -> 5
    let mut body = Vec::new();
    body.extend_from_slice(&u32ne(6));
    body.extend_from_slice(&u32ne(5));
    c.write_all(&msg(4, 2, &body)).unwrap(); // xdg_wm_base.get_xdg_surface -> 6
    c.write_all(&msg(6, 1, &u32ne(7))).unwrap(); // xdg_surface.get_toplevel -> 7
    // Six: the proxy's app_id stamp follows get_toplevel.
    let _ = read_until(&mut u, |b| holds_messages(b, 6), "the five setup requests and the stamped app_id at the upstream");

    for (label, title) in [
        ("accented", "\u{00e9}".repeat(200)),
        ("emoji", "\u{1F600}".repeat(100)),
        ("mixed", format!("{}\u{00e9}\u{1F600}{}", "x".repeat(240), "y".repeat(50))),
        ("ascii", "Editor".to_string()),
    ] {
        c.write_all(&msg(7, 2, &wl_string(&title))).unwrap(); // xdg_toplevel.set_title
        let bytes = read_until(&mut u, |b| holds_messages(b, 1), &format!("the {label} title at the upstream"));
        let msgs = split_messages(&bytes);
        assert_eq!(msgs.len(), 1);
        assert_eq!((msgs[0].0, msgs[0].1), (7, 2));
        let got = decode_string(&msgs[0].2);
        assert!(got.starts_with("[work] "), "{label}: {got:?}");
        assert!(got.len() <= 256, "{label}: {} bytes", got.len());
        if title.len() + "[work] ".len() > 256 {
            assert!(got.ends_with("..."), "{label}: {got:?}");
        } else {
            assert_eq!(got, format!("[work] {title}"), "{label}");
        }
        p.assert_alive(&format!("after the {label} title"));
    }
}

/// Whether `bytes` holds exactly `n` complete messages and nothing else.
fn holds_messages(mut bytes: &[u8], n: usize) -> bool {
    let mut count = 0;
    while bytes.len() >= 8 {
        let word = u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let size = (word >> 16) as usize;
        if size < 8 || size > bytes.len() {
            return false;
        }
        bytes = &bytes[size..];
        count += 1;
    }
    bytes.is_empty() && count == n
}
