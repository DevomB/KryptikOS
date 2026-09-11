//! Broker identity: who is on the other end of a Unix socket, and which zone
//! that is (docs/design/05-broker-and-desktop-boundary.md).
//!
//! THE ONE MECHANISM
//!
//! Every zone has a fixed host identity range (`[identity] uid_base`, Design
//! 01). A connection accepted in zone 0 carries `SO_PEERCRED`, whose uid is
//! kernel-asserted and cannot be chosen by the connecting process. If that
//! uid falls in exactly one zone's range, the peer IS that zone: no token, no
//! handshake, nothing a zone could forge. The peer pid is deliberately not
//! used - it is a pid in zone 0's namespace and may be reused - and the
//! peer gid is checked only for consistency.
//!
//! This module is the primitive. The verbs (file transfer, clipboard) and
//! the serving loop come later and are specified in Design 05; what they
//! all start with is `peer_identity` followed by `zone_for_uid`.
//!
//! Unprivileged developer launches map every zone to the launching user's
//! own uid, so identity cannot distinguish zones there; `zone_for_uid`
//! returns `None` for a uid outside every declared range, and the caller
//! refuses. That is the honest answer on a developer host and the correct
//! one on the target.

use std::io;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::zone::{Zone, IDENTITY_STRIDE};

/// Kernel-asserted credentials of a Unix-socket peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
}

/// `SO_PEERCRED` of a connected AF_UNIX socket (stream or seqpacket, or one
/// end of a socketpair).
pub fn peer_identity(fd: RawFd) -> io::Result<PeerCred> {
    let mut uc: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut uc as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCred { uid: uc.uid, gid: uc.gid })
}

/// The zone whose declared identity range contains `uid`, if exactly one
/// does. Ranges are disjoint by construction (`zone::check_invariants`), so
/// "exactly one" is a scan for the single match; a uid outside every range
/// - a host user, an unprivileged developer launch, root - matches nothing.
pub fn zone_for_uid<'a>(zones: &'a [Zone], uid: u32) -> Option<&'a Zone> {
    let mut found: Option<&Zone> = None;
    for z in zones {
        let Some(base) = z.uid_base else { continue };
        if uid >= base && uid - base < IDENTITY_STRIDE {
            if found.is_some() {
                return None; // overlapping ranges: refuse rather than guess
            }
            found = Some(z);
        }
    }
    found
}

/// Identify the zone behind a connection, or say why not. The gid must lie
/// in the same range as the uid: a process that somehow held a uid from one
/// zone and a gid from another is not any zone.
pub fn identify<'a>(zones: &'a [Zone], fd: RawFd) -> Result<&'a Zone, String> {
    let cred = peer_identity(fd).map_err(|e| format!("SO_PEERCRED: {e}"))?;
    let z = zone_for_uid(zones, cred.uid)
        .ok_or_else(|| format!("peer uid {} is not in any zone's identity range", cred.uid))?;
    match zone_for_uid(zones, cred.gid) {
        Some(g) if g.name == z.name => Ok(z),
        _ => Err(format!(
            "peer uid {} is zone {:?} but gid {} is not in that zone's range",
            cred.uid, z.name, cred.gid
        )),
    }
}

/// The socket file name inside a registry entry, and the path a zone sees.
pub const SOCKET_NAME: &str = "broker";
pub const ZONE_PATH: &str = "/run/kryptik/broker";

/// Bind a listening AF_UNIX socket at `path`, owned by the zone identity so
/// the zone (and nobody else) may connect to it. A stale file is removed
/// first: the path is inside a registry entry this launcher has just
/// claimed, so nothing else can own it.
pub fn listen_at(path: &std::path::Path, uid: u32, gid: u32) -> io::Result<RawFd> {
    let _ = std::fs::remove_file(path);
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in socket path"))?;
    if c.as_bytes().len() >= 108 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "socket path too long for sockaddr_un"));
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (i, b) in c.as_bytes().iter().enumerate() {
        sa.sun_path[i] = *b as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + c.as_bytes().len() + 1) as libc::socklen_t;
    let r = unsafe {
        // Nobody but the owner may connect: 0600 before the bind is visible.
        let old = libc::umask(0o177);
        let r = libc::bind(fd, &sa as *const _ as *const libc::sockaddr, len);
        libc::umask(old);
        r
    };
    if r < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    if unsafe { libc::geteuid() } == 0 && unsafe { libc::chown(c.as_ptr(), uid, gid) } < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    if unsafe { libc::listen(fd, 8) } < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

/// THE CLIPBOARD (Design 05)
///
/// One payload per zone, held by zone 0 in the zone's registry entry (0700,
/// root-owned on the target) as the file `clipboard`: first line the MIME
/// type, the bytes after it. A zone sets and gets its OWN payload through
/// its broker. Moving a payload between zones is a zone 0 act - the
/// operator's gesture, `kryptikd clipboard move FROM TO` - and never a zone
/// verb: no zone can ask for another zone's payload because the verb does
/// not exist on the zone-facing socket (B9, B10). After a move the source
/// keeps its payload (copy semantics for the user) and the destination's
/// previous one is replaced.
pub const CLIPBOARD_FILE: &str = "clipboard";
pub const CLIPBOARD_MAX: usize = 1 << 20;

/// The MIME types a zone may label a payload with. A fixed list: the label
/// crosses the boundary with the bytes, and a free-form label is a channel.
pub const MIME_TYPES: &[&str] = &[
    "text/plain",
    "text/plain;charset=utf-8",
    "text/html",
    "text/uri-list",
    "image/png",
    "image/jpeg",
    "application/octet-stream",
];

/// How long one request may take end to end. The launcher serves its broker
/// between waitpid polls, so a zone that dribbles bytes stalls its own
/// supervision and nothing else; the deadline bounds even that.
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

/// One request, parsed from its header line. The wire format is one header
/// line, and for `clipboard-set` exactly `len` payload bytes after it:
///
/// ```text
/// version\n                              -> kryptik-broker 1 zone=NAME\n
/// clipboard-set <mime> <len>\n<bytes>    -> ok\n
/// clipboard-get\n                        -> ok <mime> <len>\n<bytes>  |  empty\n
/// anything else                          -> error: <reason>\n
/// ```
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    Version,
    ClipboardSet { mime: String, len: usize },
    ClipboardGet,
    /// A verb that exists, but not on the zone-facing socket (B10).
    NotAZoneVerb(String),
    /// A designed verb that is not implemented yet (transfer).
    NotYet(String),
    Unknown(String),
}

pub fn parse_request(line: &str) -> Result<Request, String> {
    let mut words = line.trim().split_whitespace();
    let verb = words.next().unwrap_or("");
    let rest: Vec<&str> = words.collect();
    match (verb, rest.as_slice()) {
        ("version", []) => Ok(Request::Version),
        ("clipboard-get", []) => Ok(Request::ClipboardGet),
        ("clipboard-set", [mime, len]) => {
            if !MIME_TYPES.contains(mime) {
                return Err(format!("unsupported MIME type {mime:?}"));
            }
            let len: usize = len.parse().map_err(|_| format!("bad length {len:?}"))?;
            if len > CLIPBOARD_MAX {
                return Err(format!(
                    "payload of {len} bytes exceeds the {CLIPBOARD_MAX}-byte clipboard limit"
                ));
            }
            Ok(Request::ClipboardSet { mime: mime.to_string(), len })
        }
        ("clipboard-set", _) => Err("usage: clipboard-set <mime> <len>".into()),
        ("clipboard-move", _) => Ok(Request::NotAZoneVerb(verb.to_string())),
        ("transfer", _) => Ok(Request::NotYet(verb.to_string())),
        ("", _) => Err("empty request".into()),
        _ => Ok(Request::Unknown(verb.to_string())),
    }
}

/// Accept one connection and answer one request. Returns the verb handled,
/// for logging.
pub fn serve_one(listen_fd: RawFd, zone: &str, uid: u32, entry: &Path) -> io::Result<Option<String>> {
    let fd = unsafe { libc::accept4(listen_fd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
    if fd < 0 {
        let e = io::Error::last_os_error();
        return if e.raw_os_error() == Some(libc::EAGAIN) || e.raw_os_error() == Some(libc::EINTR) {
            Ok(None)
        } else {
            Err(e)
        };
    }
    let result = serve_connection(fd, zone, uid, entry);
    unsafe { libc::close(fd) };
    result
}

/// Answer one request on an accepted connection. The peer must be the zone
/// this launcher runs (`uid` is its mapped host uid); anything else gets a
/// refusal and no information. `entry` is the zone's registry entry, where
/// its clipboard lives. Every refusal happens before a payload is read.
pub fn serve_connection(fd: RawFd, zone: &str, uid: u32, entry: &Path) -> io::Result<Option<String>> {
    let cred = peer_identity(fd)?;
    if cred.uid != uid {
        reply(fd, "error: unidentified peer\n");
        return Ok(None);
    }
    let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as u32)
    };
    let started = Instant::now();
    let mut buf = read_until_newline(fd, 512, started)?;
    let Some(nl) = buf.iter().position(|b| *b == b'\n') else {
        reply(fd, "error: header line missing or too long\n");
        return Ok(None);
    };
    let header = String::from_utf8_lossy(&buf[..nl]).to_string();
    let mut rest: Vec<u8> = buf.split_off(nl + 1);
    let verb = header.split_whitespace().next().unwrap_or("").to_string();
    match parse_request(&header) {
        Err(why) => reply(fd, &format!("error: {why}\n")),
        Ok(Request::Version) => reply(fd, &format!("kryptik-broker 1 zone={zone}\n")),
        Ok(Request::ClipboardGet) => match clipboard_read(entry) {
            Ok(Some((mime, bytes))) => {
                reply(fd, &format!("ok {mime} {}\n", bytes.len()));
                send_all(fd, &bytes);
            }
            Ok(None) => reply(fd, "empty\n"),
            Err(e) => reply(fd, &format!("error: clipboard: {e}\n")),
        },
        Ok(Request::ClipboardSet { mime, len }) => {
            if let Err(e) = read_more(fd, &mut rest, len, started) {
                reply(fd, &format!("error: payload: {e}\n"));
                return Ok(Some(verb));
            }
            if rest.len() < len {
                reply(fd, &format!("error: payload short: {} of {len} bytes\n", rest.len()));
                return Ok(Some(verb));
            }
            match clipboard_write(entry, &mime, &rest[..len]) {
                Ok(()) => reply(fd, "ok\n"),
                Err(e) => reply(fd, &format!("error: clipboard: {e}\n")),
            }
        }
        Ok(Request::NotAZoneVerb(v)) => reply(fd, &format!("error: {v} is a zone 0 act, not a zone verb\n")),
        Ok(Request::NotYet(v)) => reply(fd, &format!("error: {v} is not implemented yet\n")),
        Ok(Request::Unknown(_)) => reply(fd, "error: unknown verb\n"),
    }
    Ok(Some(verb))
}

/// Read until the buffer holds a newline or `max` bytes, within the deadline.
fn read_until_newline(fd: RawFd, max: usize, started: Instant) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    while !buf.contains(&b'\n') && buf.len() < max {
        if !recv_some(fd, &mut buf, started)? {
            break;
        }
    }
    Ok(buf)
}

/// Read until the buffer holds at least `want` bytes, within the deadline.
/// EOF ends the read early; the caller sees the short count.
fn read_more(fd: RawFd, buf: &mut Vec<u8>, want: usize, started: Instant) -> io::Result<()> {
    while buf.len() < want {
        if !recv_some(fd, buf, started)? {
            break;
        }
    }
    Ok(())
}

/// One recv into `buf`. Ok(false) at EOF. SO_RCVTIMEO ticks (EAGAIN) are
/// retried until the request deadline, which is the bound that matters.
fn recv_some(fd: RawFd, buf: &mut Vec<u8>, started: Instant) -> io::Result<bool> {
    let mut chunk = [0u8; 4096];
    loop {
        if started.elapsed() > REQUEST_DEADLINE {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "request took longer than the deadline"));
        }
        let n = unsafe { libc::recv(fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len(), 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) | Some(libc::EAGAIN) => continue,
                _ => return Err(e),
            }
        }
        if n == 0 {
            return Ok(false);
        }
        buf.extend_from_slice(&chunk[..n as usize]);
        return Ok(true);
    }
}

fn reply(fd: RawFd, text: &str) {
    send_all(fd, text.as_bytes());
}

fn send_all(fd: RawFd, mut data: &[u8]) {
    while !data.is_empty() {
        let n = unsafe { libc::send(fd, data.as_ptr() as *const libc::c_void, data.len(), libc::MSG_NOSIGNAL) };
        if n <= 0 {
            return; // the peer is gone; nothing to do about it
        }
        data = &data[n as usize..];
    }
}

/// The zone's payload, if any: (mime, bytes). O_NOFOLLOW like every other
/// registry read (R-7b F1); a planted symlink is refused, not followed.
pub fn clipboard_read(entry: &Path) -> io::Result<Option<(String, Vec<u8>)>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let p = entry.join(CLIPBOARD_FILE);
    let mut f = match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&p) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut all = Vec::new();
    f.take(CLIPBOARD_MAX as u64 + 256).read_to_end(&mut all)?;
    let Some(nl) = all.iter().position(|b| *b == b'\n') else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "clipboard file has no MIME line"));
    };
    let mime = String::from_utf8_lossy(&all[..nl]).to_string();
    if !MIME_TYPES.contains(&mime.as_str()) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("clipboard file carries an unsupported MIME type {mime:?}")));
    }
    let bytes = all.split_off(nl + 1);
    if bytes.len() > CLIPBOARD_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "clipboard file is over the limit"));
    }
    Ok(Some((mime, bytes)))
}

/// Replace the zone's payload atomically: a new 0600 file created with
/// O_EXCL|O_NOFOLLOW, then renamed over `clipboard` (rename replaces a
/// planted symlink rather than following it). A failure leaves no partial
/// file and the previous payload untouched.
pub fn clipboard_write(entry: &Path, mime: &str, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if !MIME_TYPES.contains(&mime) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unsupported MIME type {mime:?}")));
    }
    if bytes.len() > CLIPBOARD_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "payload over the clipboard limit"));
    }
    let tmp = entry.join(format!(".{CLIPBOARD_FILE}.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let r = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(mime.as_bytes())?;
        f.write_all(b"\n")?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, entry.join(CLIPBOARD_FILE))
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

/// The zone 0 gesture: give `to` a copy of `from`'s payload. Both are
/// registry entry directories; the caller has checked both zones are
/// running. Returns what moved.
pub fn clipboard_move(from: &Path, to: &Path) -> io::Result<(String, usize)> {
    let Some((mime, bytes)) = clipboard_read(from)? else {
        return Err(io::Error::new(io::ErrorKind::NotFound, "nothing on the source zone's clipboard"));
    };
    clipboard_write(to, &mime, &bytes)?;
    Ok((mime, bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zones() -> Vec<Zone> {
        let mk = |name: &str, base: Option<u32>, colour: &str| {
            let ident = base.map(|b| format!("[identity]\nuid_base = {b}\n")).unwrap_or_default();
            Zone::from_str(&format!(
                "[zone]\nname = \"{name}\"\n[network]\nmode = \"routed\"\n\
                 [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n{ident}[ui]\nborder_color = \"{colour}\"\n"
            ))
            .unwrap()
        };
        vec![
            mk("work", Some(131072), "#111111"),
            mk("personal", Some(196608), "#222222"),
            mk("legacy", None, "#333333"),
        ]
    }

    #[test]
    fn a_uid_maps_to_exactly_the_zone_whose_range_holds_it() {
        let zs = zones();
        assert_eq!(zone_for_uid(&zs, 131072).map(|z| z.name.as_str()), Some("work"));
        assert_eq!(zone_for_uid(&zs, 131072 + 65534).map(|z| z.name.as_str()), Some("work"));
        assert_eq!(zone_for_uid(&zs, 131072 + 65535).map(|z| z.name.as_str()), Some("work"));
        assert_eq!(zone_for_uid(&zs, 196608).map(|z| z.name.as_str()), Some("personal"));
        // Host users, root, and the range just past the last zone match nothing.
        for uid in [0u32, 1000, 131071, 196608 + 65536, u32::MAX] {
            assert!(zone_for_uid(&zs, uid).is_none(), "uid {uid} must not identify a zone");
        }
    }

    #[test]
    fn a_socketpair_peer_is_this_process_and_identifies_by_uid() {
        let mut sv = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) }, 0);
        let cred = peer_identity(sv[0]).unwrap();
        assert_eq!(cred.uid, unsafe { libc::geteuid() });
        assert_eq!(cred.gid, unsafe { libc::getegid() });
        // Our own uid is a host user, not a zone: identify refuses, naming the uid.
        let err = identify(&zones(), sv[0]).unwrap_err();
        assert!(err.contains("not in any zone"), "{err}");
        unsafe {
            libc::close(sv[0]);
            libc::close(sv[1]);
        }
    }

    fn pair() -> (RawFd, RawFd) {
        let mut sv = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) }, 0);
        (sv[0], sv[1])
    }

    fn send_str(fd: RawFd, s: &str) {
        send_all(fd, s.as_bytes());
    }

    /// Everything the server sent, read after the server closed its end.
    fn recv_reply(fd: RawFd) -> Vec<u8> {
        let mut out = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = unsafe { libc::recv(fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len(), 0) };
            if n <= 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n as usize]);
        }
        out
    }

    fn entry(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kryptik-broker-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// One request against a fresh socketpair: the client side is written
    /// first (the socket buffers it), the server answers, and the client
    /// reads the whole reply. Returns (verb the server reported, reply).
    fn ask(dir: &Path, uid: u32, request: &str, half_close: bool) -> (Option<String>, Vec<u8>) {
        let (server, client) = pair();
        send_str(client, request);
        if half_close {
            unsafe { libc::shutdown(client, libc::SHUT_WR) };
        }
        let verb = serve_connection(server, "t", uid, dir).unwrap();
        unsafe { libc::close(server) };
        let reply = recv_reply(client);
        unsafe { libc::close(client) };
        (verb, reply)
    }

    #[test]
    fn a_zone_sets_and_gets_its_own_clipboard_through_its_broker() {
        use std::os::unix::fs::MetadataExt;
        let dir = entry("roundtrip");
        let me = unsafe { libc::geteuid() };
        assert_eq!(ask(&dir, me, "clipboard-get\n", false).1, b"empty\n");
        let (verb, r) = ask(&dir, me, "clipboard-set text/plain 5\nhello", false);
        assert_eq!(verb.as_deref(), Some("clipboard-set"));
        assert_eq!(r, b"ok\n");
        assert_eq!(std::fs::metadata(dir.join(CLIPBOARD_FILE)).unwrap().mode() & 0o777, 0o600);
        assert_eq!(ask(&dir, me, "clipboard-get\n", false).1, b"ok text/plain 5\nhello");
        // A second set replaces, and a payload that arrives in pieces still lands whole.
        let (server, client) = pair();
        send_str(client, "clipboard-set text/plain;charset=utf-8 11\nhello");
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            send_str(client, " world");
            client
        });
        serve_connection(server, "t", me, &dir).unwrap();
        unsafe { libc::close(server) };
        let client = t.join().unwrap();
        assert_eq!(recv_reply(client), b"ok\n");
        unsafe { libc::close(client) };
        assert_eq!(ask(&dir, me, "clipboard-get\n", false).1, b"ok text/plain;charset=utf-8 11\nhello world");
        assert_eq!(ask(&dir, me, "version\n", false).1, b"kryptik-broker 1 zone=t\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_refusal_happens_before_a_payload_is_read_and_leaves_the_clipboard_alone() {
        let dir = entry("refusals");
        let me = unsafe { libc::geteuid() };
        assert_eq!(ask(&dir, me, "clipboard-set text/plain 5\nhello", false).1, b"ok\n");
        let cases: &[(&str, &str)] = &[
            ("clipboard-set text/plain 1048577\n", "error: payload of 1048577 bytes exceeds the 1048576-byte clipboard limit\n"),
            ("clipboard-set text/evil 3\nabc", "error: unsupported MIME type \"text/evil\"\n"),
            ("clipboard-set text/plain\n", "error: usage: clipboard-set <mime> <len>\n"),
            ("clipboard-set text/plain -1\n", "error: bad length \"-1\"\n"),
            ("clipboard-move t other\n", "error: clipboard-move is a zone 0 act, not a zone verb\n"),
            ("transfer other x\n", "error: transfer is not implemented yet\n"),
            ("steal\n", "error: unknown verb\n"),
            ("\n", "error: empty request\n"),
        ];
        for (req, want) in cases {
            let (_, r) = ask(&dir, me, req, false);
            assert_eq!(String::from_utf8_lossy(&r), *want, "request {req:?}");
        }
        // A payload shorter than announced (the client half-closes): refused, nothing written.
        let (_, r) = ask(&dir, me, "clipboard-set text/plain 10\nabc", true);
        assert_eq!(r, b"error: payload short: 3 of 10 bytes\n");
        // A header with no newline within the limit.
        let (_, r) = ask(&dir, me, &"x".repeat(600), true);
        assert_eq!(r, b"error: header line missing or too long\n");
        // Through all of that the payload set first is still there, intact.
        assert_eq!(ask(&dir, me, "clipboard-get\n", false).1, b"ok text/plain 5\nhello");
        let left: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left, vec![std::ffi::OsString::from(CLIPBOARD_FILE)], "no temp files left behind");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_peer_that_is_not_the_zone_is_refused_without_information() {
        let dir = entry("peer");
        let me = unsafe { libc::geteuid() };
        let (verb, r) = ask(&dir, me.wrapping_add(1), "clipboard-get\n", false);
        assert_eq!(verb, None);
        assert_eq!(r, b"error: unidentified peer\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_zone_zero_move_copies_and_leaves_the_source() {
        let a = entry("move-a");
        let b = entry("move-b");
        let c = entry("move-c");
        clipboard_write(&a, "image/png", b"\x89PNG").unwrap();
        clipboard_write(&b, "text/plain", b"old").unwrap();
        assert_eq!(clipboard_move(&a, &b).unwrap(), ("image/png".to_string(), 4));
        assert_eq!(clipboard_read(&b).unwrap(), Some(("image/png".to_string(), b"\x89PNG".to_vec())));
        assert_eq!(clipboard_read(&a).unwrap(), Some(("image/png".to_string(), b"\x89PNG".to_vec())));
        // Nothing to move from an empty clipboard, and the destination is untouched.
        let e = clipboard_move(&c, &b).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert_eq!(clipboard_read(&b).unwrap().map(|(m, _)| m), Some("image/png".to_string()));
        // A planted symlink where the file should be is refused on read and replaced on write.
        std::os::unix::fs::symlink("/etc/hostname", c.join(CLIPBOARD_FILE)).unwrap();
        assert!(clipboard_read(&c).is_err());
        clipboard_write(&c, "text/plain", b"x").unwrap();
        assert!(!std::fs::symlink_metadata(c.join(CLIPBOARD_FILE)).unwrap().file_type().is_symlink());
        for d in [&a, &b, &c] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    #[test]
    fn parse_request_covers_the_wire_format() {
        assert_eq!(parse_request("version"), Ok(Request::Version));
        assert_eq!(parse_request("  clipboard-get  "), Ok(Request::ClipboardGet));
        assert_eq!(
            parse_request("clipboard-set image/jpeg 1048576"),
            Ok(Request::ClipboardSet { mime: "image/jpeg".into(), len: CLIPBOARD_MAX })
        );
        assert!(parse_request("clipboard-set image/jpeg 1048577").is_err());
        assert!(parse_request("clipboard-set image/gif 1").is_err());
        assert!(parse_request("clipboard-set text/plain 1 extra").is_err());
        assert!(parse_request("VERSION").is_ok_and(|r| matches!(r, Request::Unknown(_))));
        assert!(parse_request("version now").is_ok_and(|r| matches!(r, Request::Unknown(_))));
    }

    #[test]
    fn a_zone_with_no_identity_can_never_be_identified() {
        // "legacy" has no uid_base: nothing maps to it, so the broker can
        // never attribute a request to it - which is the point of P3.
        let zs = zones();
        for uid in 0..300_000u32 {
            if let Some(z) = zone_for_uid(&zs, uid) {
                assert_ne!(z.name, "legacy");
            }
        }
    }
}
