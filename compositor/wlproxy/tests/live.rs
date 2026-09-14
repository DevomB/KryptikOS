//! The proxy as a process: a real listening socket, a real upstream, real
//! clients. The unit tests in session.rs drive one `Session` over socket
//! pairs and cannot see `main`'s event loop, which is where the first
//! version crashed on its first accepted client (an index into a pollfd
//! snapshot taken before the session was appended). These tests can.
//!
//! No Wayland compositor is involved: the "upstream" is a Unix listener the
//! test owns, and the bytes exchanged are hand-encoded wire messages, so
//! the tests run anywhere the binary does.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(10);

// --- wire encoding ---------------------------------------------------------

fn u32le(v: u32) -> [u8; 4] {
    v.to_ne_bytes()
}

fn msg(object: u32, opcode: u16, body: &[u8]) -> Vec<u8> {
    let size = (8 + body.len()) as u32;
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&u32le(object));
    out.extend_from_slice(&u32le((size << 16) | opcode as u32));
    out.extend_from_slice(body);
    out
}

fn wl_string(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let len = s.len() + 1;
    out.extend_from_slice(&u32le(len as u32));
    out.extend_from_slice(s.as_bytes());
    out.push(0);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn get_registry(id: u32) -> Vec<u8> {
    msg(1, 1, &u32le(id))
}

fn sync(callback: u32) -> Vec<u8> {
    msg(1, 0, &u32le(callback))
}

fn global(registry: u32, name: u32, iface: &str, version: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&u32le(name));
    body.extend_from_slice(&wl_string(iface));
    body.extend_from_slice(&u32le(version));
    msg(registry, 0, &body)
}

fn bind(registry: u32, name: u32, iface: &str, version: u32, new_id: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&u32le(name));
    body.extend_from_slice(&wl_string(iface));
    body.extend_from_slice(&u32le(version));
    body.extend_from_slice(&u32le(new_id));
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

struct Proxy {
    child: Child,
    dir: PathBuf,
    listen: PathBuf,
    upstream: UnixListener,
}

impl Proxy {
    fn start(zone: &str, extra: &[&str]) -> Proxy {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        // Unix socket paths are short (108 bytes); the system temp dir is.
        let dir = std::env::temp_dir().join(format!("kwlp-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let upstream_path = dir.join("upstream");
        let listen = dir.join("wayland-0");
        let upstream = UnixListener::bind(&upstream_path).unwrap();
        upstream.set_nonblocking(true).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_kryptik-wlproxy"))
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

    fn stderr_so_far(&mut self) -> String {
        // Only meaningful once the child has exited (the pipe is at EOF).
        let mut s = String::new();
        if let Some(e) = self.child.stderr.as_mut() {
            let _ = e.read_to_string(&mut s);
        }
        s
    }

    /// Connect a client and take the upstream connection the proxy opens
    /// for it. The two are returned together so a test never confuses
    /// which upstream belongs to which client.
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

/// The reproduced crash: the first client, serviced. Then more clients,
/// a disconnect, a reconnect, and the proxy still serving after all of it.
#[test]
fn first_connection_then_many_then_disconnect_and_reconnect() {
    let mut p = Proxy::start("work", &[]);

    // Client 1: its first request must reach the upstream through the
    // proxy. This is the exact point the old loop panicked.
    let (mut c1, mut u1) = p.connect();
    c1.write_all(&get_registry(2)).unwrap();
    assert_eq!(read_exact_or_panic(&mut u1, 12, "client 1's get_registry at the upstream"), get_registry(2));
    p.assert_alive("after its first client's first request");

    // Events flow back, filtered: an allowed global arrives, a hidden one
    // does not, and the next allowed one arrives right after it.
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

/// The protocol checks survive the move of the accept: a client that binds
/// a hidden global is refused with a wl_display.error and disconnected,
/// and the next client is unaffected.
#[test]
fn a_refused_client_does_not_take_the_proxy_or_its_neighbours_down() {
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

/// `--once` still means one session, and the listener is removed on exit.
#[test]
fn once_serves_one_client_and_removes_its_socket() {
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

/// The whole title path, through the real binary: bind, create a toplevel,
/// set a long accented title, and see it arrive at the upstream bounded,
/// prefixed and valid - with the proxy still standing. This is the second
/// reproduced failure (a byte-index truncation inside a multi-byte
/// character; `panic = "abort"` made it a process exit).
#[test]
fn long_unicode_titles_are_rewritten_not_fatal() {
    let mut p = Proxy::start("work", &[]);
    let (mut c, mut u) = p.connect();
    c.write_all(&get_registry(2)).unwrap();
    let _ = read_exact_or_panic(&mut u, 12, "get_registry");
    u.write_all(&global(2, 1, "wl_compositor", 6)).unwrap();
    u.write_all(&global(2, 2, "xdg_wm_base", 6)).unwrap();
    let _ = read_until(&mut c, |b| split_messages_ok(b, 2), "both globals at the client");

    c.write_all(&bind(2, 1, "wl_compositor", 6, 3)).unwrap();
    c.write_all(&bind(2, 2, "xdg_wm_base", 6, 4)).unwrap();
    c.write_all(&msg(3, 0, &u32le(5))).unwrap(); // wl_compositor.create_surface -> 5
    let mut body = Vec::new();
    body.extend_from_slice(&u32le(6));
    body.extend_from_slice(&u32le(5));
    c.write_all(&msg(4, 2, &body)).unwrap(); // xdg_wm_base.get_xdg_surface -> 6
    c.write_all(&msg(6, 1, &u32le(7))).unwrap(); // xdg_surface.get_toplevel -> 7
    // Six, not five: the proxy stamps the new toplevel's app_id right behind
    // get_toplevel, so the compositor never sees a nameless toplevel.
    let _ = read_until(&mut u, |b| split_messages_ok(b, 6), "the five setup requests and the stamped app_id at the upstream");

    for (label, title) in [
        ("accented", "\u{00e9}".repeat(200)),
        ("emoji", "\u{1F600}".repeat(100)),
        ("mixed", format!("{}\u{00e9}\u{1F600}{}", "x".repeat(240), "y".repeat(50))),
        ("ascii", "Editor".to_string()),
    ] {
        c.write_all(&msg(7, 2, &wl_string(&title))).unwrap(); // xdg_toplevel.set_title
        let bytes = read_until(&mut u, |b| split_messages_ok(b, 1), &format!("the {label} title at the upstream"));
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
fn split_messages_ok(mut bytes: &[u8], n: usize) -> bool {
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
