use super::*;

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

/// Send one request on a fresh socketpair, serve it, and return (verb, reply).
fn ask(s: &Served, request: &str, half_close: bool) -> (Option<&'static str>, Vec<u8>) {
    ask_with(s, request, &[], half_close)
}

/// The same, with descriptors attached to the first message.
fn ask_with(s: &Served, request: &str, fds: &[RawFd], half_close: bool) -> (Option<&'static str>, Vec<u8>) {
    let (server, client) = pair();
    send_with_fds(client, request.as_bytes(), fds);
    if half_close {
        unsafe { libc::shutdown(client, libc::SHUT_WR) };
    }
    let verb = serve_connection(server, s).unwrap();
    unsafe { libc::close(server) };
    let reply = recv_reply(client);
    unsafe { libc::close(client) };
    (verb, reply)
}

fn send_with_fds(sock: RawFd, data: &[u8], fds: &[RawFd]) {
    let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut libc::c_void, iov_len: data.len() };
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) } as usize;
    let mut cbuf = vec![0u8; space.max(1)];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if !fds.is_empty() {
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space as _;
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as _;
            std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(c) as *mut RawFd, fds.len());
        }
    }
    assert!(unsafe { libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) } >= 0, "sendmsg: {}", io::Error::last_os_error());
}

fn zone_t() -> Zone {
    Zone::from_str(
        "[zone]\nname = \"t\"\n[network]\nmode = \"none\"\n\
             [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n[ui]\nborder_color = \"#123456\"\n",
    )
    .unwrap()
}

fn no_dest(_: &str) -> Result<Target, String> {
    Err("no destinations in this test".into())
}

fn dev_unknown() -> Option<u64> {
    None
}

fn no_log(_: &str) {}

fn served<'a>(zone: &'a Zone, entry: &'a Path, uid: u32) -> Served<'a> {
    Served {
        zone,
        uid,
        entry,
        zones_dir: entry,
        home_dev: &dev_unknown,
        auto_approve: false,
        max_bytes: TRANSFER_MAX,
        resolve_dest: &no_dest,
        asking: &crate::consent::keep,
        log: &no_log,
        refused_until: Box::leak(Box::new(Cell::new(None))),
    }
}

#[test]
fn stalled_reader_cannot_block_supervision() {
    let dir = entry("stalled-reader");
    clipboard_write(&dir, "text/plain", &vec![b'x'; CLIPBOARD_MAX]).unwrap();
    let (server, client) = pair();
    let size: libc::c_int = 4096;
    assert_eq!(unsafe {
        libc::setsockopt(server, libc::SOL_SOCKET, libc::SO_SNDBUF,
            &size as *const _ as *const libc::c_void, std::mem::size_of_val(&size) as _)
    }, 0);
    send_str(client, "clipboard-get\n");
    let (done, completion) = std::sync::mpsc::channel();
    let worker_dir = dir.clone();
    let worker = std::thread::spawn(move || {
        let z = zone_t();
        let s = served(&z, &worker_dir, unsafe { libc::geteuid() });
        let result = serve_connection(server, &s);
        unsafe { libc::close(server) };
        let _ = done.send(result);
    });
    // Leave the reply unread; closing the peer afterwards frees a stuck worker.
    let result = completion.recv_timeout(REQUEST_DEADLINE + Duration::from_secs(2));
    unsafe { libc::close(client) };
    worker.join().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    assert!(result.is_ok(), "an unread clipboard response stalled the zone supervisor");
    assert_eq!(result.unwrap().unwrap(), Some("clipboard-get"));
}

#[test]
fn clipboard_round_trip() {
    use std::os::unix::fs::MetadataExt;
    let dir = entry("roundtrip");
    let me = unsafe { libc::geteuid() };
    let z = zone_t();
    let sv = served(&z, &dir, me);
    assert_eq!(ask(&sv, "clipboard-get\n", false).1, b"empty\n");
    let (verb, r) = ask(&sv, "clipboard-set text/plain 5\nhello", false);
    assert_eq!(verb, Some("clipboard-set"));
    assert_eq!(r, b"ok\n");
    assert_eq!(std::fs::metadata(dir.join(CLIPBOARD_FILE)).unwrap().mode() & 0o777, 0o600);
    assert_eq!(ask(&sv, "clipboard-get\n", false).1, b"ok text/plain 5\nhello");
    // A second set replaces, and a payload that arrives in pieces still lands whole.
    let (server, client) = pair();
    send_str(client, "clipboard-set text/plain;charset=utf-8 11\nhello");
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        send_str(client, " world");
        client
    });
    serve_connection(server, &sv).unwrap();
    unsafe { libc::close(server) };
    let client = t.join().unwrap();
    assert_eq!(recv_reply(client), b"ok\n");
    unsafe { libc::close(client) };
    assert_eq!(ask(&sv, "clipboard-get\n", false).1, b"ok text/plain;charset=utf-8 11\nhello world");
    assert_eq!(ask(&sv, "version\n", false).1, b"kryptik-broker 1 zone=t\n");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn requests_named_not_echoed() {
    let dir = entry("names");
    let z = zone_t();
    let sv = served(&z, &dir, unsafe { libc::geteuid() });
    let bogus = format!("\u{1b}[2J{}\n", "A".repeat(3990));
    assert_eq!(ask(&sv, &bogus, false), (Some("unknown verb"), b"error: unknown verb\n".to_vec()));
    assert_eq!(ask(&sv, "transfer x\n", false).0, Some("malformed request"));
    assert_eq!(ask(&sv, "clipboard-move a b\n", false).0, Some("zone 0 verb"));
    assert_eq!(ask(&sv, "version\n", false).0, Some("version"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn refusals_leave_clipboard_alone() {
    let dir = entry("refusals");
    let me = unsafe { libc::geteuid() };
    let z = zone_t();
    let sv = served(&z, &dir, me);
    assert_eq!(ask(&sv, "clipboard-set text/plain 5\nhello", false).1, b"ok\n");
    let cases: &[(&str, &str)] = &[
        ("clipboard-set text/plain 1048577\n", "error: payload of 1048577 bytes exceeds the 1048576-byte clipboard limit\n"),
        ("clipboard-set text/evil 3\nabc", "error: unsupported MIME type \"text/evil\"\n"),
        ("clipboard-set text/plain\n", "error: usage: clipboard-set <mime> <len>\n"),
        ("clipboard-set text/plain -1\n", "error: bad length \"-1\"\n"),
        ("clipboard-move t other\n", "error: clipboard-move is a zone 0 act, not a zone verb\n"),
        ("transfer other x extra\n", "error: usage: transfer <zone> <name>, with the file as one SCM_RIGHTS descriptor\n"),
        ("steal\n", "error: unknown verb\n"),
        ("\n", "error: empty request\n"),
    ];
    for (req, want) in cases {
        let (_, r) = ask(&sv, req, false);
        assert_eq!(String::from_utf8_lossy(&r), *want, "request {req:?}");
    }
    // A payload shorter than announced (the client half-closes): refused, nothing written.
    let (_, r) = ask(&sv, "clipboard-set text/plain 10\nabc", true);
    assert_eq!(r, b"error: payload short: 3 of 10 bytes\n");
    // A header with no newline within the limit.
    let (_, r) = ask(&sv, &"x".repeat(600), true);
    assert_eq!(r, b"error: header line missing or too long\n");
    // The first payload survives all of it.
    assert_eq!(ask(&sv, "clipboard-get\n", false).1, b"ok text/plain 5\nhello");
    let left: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name()).collect();
    assert_eq!(left, vec![std::ffi::OsString::from(CLIPBOARD_FILE)], "no temp files left behind");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn foreign_peer_learns_nothing() {
    let dir = entry("peer");
    let me = unsafe { libc::geteuid() };
    let z = zone_t();
    let sv = served(&z, &dir, me.wrapping_add(1));
    let (verb, r) = ask(&sv, "clipboard-get\n", false);
    assert_eq!(verb, None);
    assert_eq!(r, b"error: unidentified peer\n");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn clipboard_move_takes_the_payload() {
    let a = entry("move-a");
    let b = entry("move-b");
    let c = entry("move-c");
    clipboard_write(&a, "image/png", b"\x89PNG").unwrap();
    clipboard_write(&b, "text/plain", b"old").unwrap();
    assert_eq!(clipboard_move(&a, &b).unwrap(), ("image/png".to_string(), 4));
    assert_eq!(clipboard_read(&b).unwrap(), Some(("image/png".to_string(), b"\x89PNG".to_vec())));
    assert_eq!(clipboard_read(&a).unwrap(), None, "the payload left the source");
    // A second gesture has nothing to move, and the destination is untouched.
    let e = clipboard_move(&a, &b).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::NotFound);
    assert_eq!(clipboard_read(&b).unwrap().map(|(m, _)| m), Some("image/png".to_string()));
    // Nor from a zone that never set one.
    assert_eq!(clipboard_move(&c, &b).unwrap_err().kind(), io::ErrorKind::NotFound);
    // A planted symlink where the file should be is refused on read and replaced on write.
    std::os::unix::fs::symlink("/etc/hostname", c.join(CLIPBOARD_FILE)).unwrap();
    assert!(clipboard_read(&c).is_err());
    clipboard_write(&c, "text/plain", b"x").unwrap();
    assert!(!std::fs::symlink_metadata(c.join(CLIPBOARD_FILE)).unwrap().file_type().is_symlink());
    for d in [&a, &b, &c] {
        let _ = std::fs::remove_dir_all(d);
    }
}

struct Lab {
    dir: std::path::PathBuf,
    zones: std::path::PathBuf,
    root: std::path::PathBuf,
    sender: Zone,
    dev: u64,
}

/// Zones a (sender), b and c (plain) and n (nic); a destination root with
/// homes for b and c; the lab directory's filesystem as the data mount.
fn lab(tag: &str, to: &str) -> Lab {
    use std::os::unix::fs::MetadataExt;
    let dir = entry(&format!("transfer-{tag}"));
    let zones = dir.join("zones");
    std::fs::create_dir_all(&zones).unwrap();
    let plain = |name: &str, extra: &str| {
        format!(
            "[zone]\nname = \"{name}\"\n[network]\nmode = \"none\"\n\
                 [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n{extra}[ui]\nborder_color = \"#123456\"\n"
        )
    };
    std::fs::write(zones.join("a.toml"), plain("a", &format!("[transfer]\nto = \"{to}\"\n"))).unwrap();
    std::fs::write(zones.join("b.toml"), plain("b", "")).unwrap();
    std::fs::write(zones.join("c.toml"), plain("c", "")).unwrap();
    std::fs::write(
        zones.join("n.toml"),
        "[zone]\nname = \"n\"\n[network]\nmode = \"nic\"\n\
             [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n[ui]\nborder_color = \"#123456\"\n",
    )
    .unwrap();
    let root = dir.join("root");
    std::fs::create_dir_all(root.join("home/b")).unwrap();
    std::fs::create_dir_all(root.join("home/c")).unwrap();
    let sender = Zone::from_file(&zones.join("a.toml")).unwrap();
    let dev = std::fs::metadata(&dir).unwrap().dev();
    Lab { dir, zones, root, sender, dev }
}

/// The test stand-in for the registry: b and c "run" under the lab root.
fn resolver(root: std::path::PathBuf) -> impl Fn(&str) -> Result<Target, String> {
    move |dest: &str| {
        if dest != "b" && dest != "c" {
            return Err(format!("destination zone {dest:?} is not running"));
        }
        let c = CString::new(root.as_os_str().as_encoded_bytes()).unwrap();
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        assert!(fd >= 0);
        let root_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Target { root_fd, home_rel: format!("home/{dest}"), uid: unsafe { libc::geteuid() }, gid: unsafe { libc::getegid() } })
    }
}

/// How many of this process's descriptors point at `p`; tests run in
/// parallel, so a total count would be noise.
fn fds_pointing_at(p: &Path) -> usize {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .flatten()
        .filter(|e| std::fs::read_link(e.path()).map(|t| t == p).unwrap_or(false))
        .count()
}

fn open_flags(p: &Path, flags: libc::c_int) -> RawFd {
    let c = CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
    let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC, 0o600) };
    assert!(fd >= 0, "open {}: {}", p.display(), io::Error::last_os_error());
    fd
}

#[test]
fn transfer_lands_in_incoming() {
    use std::os::unix::fs::MetadataExt;
    let lab = lab("ok", "b c");
    let entry_dir = lab.dir.join("entry");
    std::fs::create_dir_all(&entry_dir).unwrap();
    let resolve = resolver(lab.root.clone());
    let dev = lab.dev;
    let home_dev = move || Some(dev);
    let sv = Served {
        zone: &lab.sender,
        uid: unsafe { libc::geteuid() },
        entry: &entry_dir,
        zones_dir: &lab.zones,
        home_dev: &home_dev,
        auto_approve: true,
        max_bytes: 64,
        resolve_dest: &resolve,
        asking: &crate::consent::keep,
        log: &no_log,
        refused_until: &Cell::new(None),
    };
    let file = lab.dir.join("report.pdf");
    std::fs::write(&file, b"hello transfer").unwrap();
    let src = open_flags(&file, libc::O_RDONLY);
    let (verb, r) = ask_with(&sv, "transfer b report.pdf\n", &[src], false);
    unsafe { libc::close(src) };
    assert_eq!(verb, Some("transfer"));
    assert_eq!(String::from_utf8_lossy(&r), "ok report.pdf\n");
    // The server must have closed its SCM_RIGHTS copy too.
    assert_eq!(fds_pointing_at(&file), 0, "the broker leaked a descriptor");
    let incoming = lab.root.join("home/b/incoming");
    assert_eq!(std::fs::read(incoming.join("report.pdf")).unwrap(), b"hello transfer");
    assert_eq!(std::fs::metadata(incoming.join("report.pdf")).unwrap().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(&incoming).unwrap().mode() & 0o777, 0o700);
    // The same name again gets -2.
    let src2 = open_flags(&file, libc::O_RDONLY);
    assert_eq!(ask_with(&sv, "transfer b report.pdf\n", &[src2], false).1, b"ok report.pdf-2\n");
    unsafe { libc::close(src2) };
    assert_eq!(std::fs::read(incoming.join("report.pdf-2")).unwrap(), b"hello transfer");
    // A symlink planted at -3 is skipped for -4, and its target is untouched.
    let victim = lab.dir.join("victim");
    std::fs::write(&victim, b"untouched").unwrap();
    std::os::unix::fs::symlink(&victim, incoming.join("report.pdf-3")).unwrap();
    let src3 = open_flags(&file, libc::O_RDONLY);
    assert_eq!(ask_with(&sv, "transfer b report.pdf\n", &[src3], false).1, b"ok report.pdf-4\n");
    unsafe { libc::close(src3) };
    assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
    // `incoming` itself a symlink to elsewhere: not followed, nothing lands.
    let elsewhere = lab.dir.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, lab.root.join("home/c/incoming")).unwrap();
    let src4 = open_flags(&file, libc::O_RDONLY);
    let (_, r) = ask_with(&sv, "transfer c report.pdf\n", &[src4], false);
    unsafe { libc::close(src4) };
    assert!(String::from_utf8_lossy(&r).contains("incoming/ is not a plain directory"), "{}", String::from_utf8_lossy(&r));
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    // Refusals close what they were handed, too.
    assert_eq!(fds_pointing_at(&file), 0, "the broker leaked a descriptor on a refusal");
    let _ = std::fs::remove_dir_all(&lab.dir);
}

/// One transfer of notes.txt ("hello transfer", 14 bytes) from a descriptor
/// the sender left at byte 6; returns the reply.
fn send_notes(sv: &Served, file: &Path) -> String {
    std::fs::write(file, b"hello transfer").unwrap();
    let src = open_flags(file, libc::O_RDONLY);
    unsafe { libc::lseek(src, 6, libc::SEEK_SET) };
    let r = ask_with(sv, "transfer b notes.txt\n", &[src], false).1;
    unsafe { libc::close(src) };
    String::from_utf8_lossy(&r).into_owned()
}

#[test]
fn transfer_carries_the_size_checked() {
    use std::io::Write;
    let lab = lab("size", "b");
    let entry_dir = lab.dir.join("entry");
    std::fs::create_dir_all(&entry_dir).unwrap();
    let file = lab.dir.join("notes.txt");
    let resolve = resolver(lab.root.clone());
    // Called after the checks (and the question), before the copy.
    let grow = |d: &str| {
        std::fs::OpenOptions::new().append(true).open(&file).unwrap().write_all(b" and more").unwrap();
        resolve(d)
    };
    let shrink = |d: &str| {
        std::fs::OpenOptions::new().write(true).open(&file).unwrap().set_len(5).unwrap();
        resolve(d)
    };
    let dev = lab.dev;
    let home_dev = move || Some(dev);
    let mut sv = Served {
        zone: &lab.sender,
        uid: unsafe { libc::geteuid() },
        entry: &entry_dir,
        zones_dir: &lab.zones,
        home_dev: &home_dev,
        auto_approve: true,
        max_bytes: 64,
        resolve_dest: &grow,
        asking: &crate::consent::keep,
        log: &no_log,
        refused_until: &Cell::new(None),
    };
    let incoming = lab.root.join("home/b/incoming");
    let r = send_notes(&sv, &file);
    assert!(r.contains("longer than the 14 bytes checked"), "{r}");
    sv.resolve_dest = &shrink;
    let r = send_notes(&sv, &file);
    assert!(r.contains("shrank to 5 of the 14 bytes checked"), "{r}");
    assert!(std::fs::read_dir(&incoming).map_or(true, |d| d.count() == 0), "a refused copy was left behind");
    // The whole file, whatever the descriptor's position.
    sv.resolve_dest = &resolve;
    assert_eq!(send_notes(&sv, &file), "ok notes.txt\n");
    assert_eq!(std::fs::read(incoming.join("notes.txt")).unwrap(), b"hello transfer");
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[test]
fn transfer_refusals_precede_copy() {
    use std::os::unix::fs::MetadataExt;
    let lab = lab("refuse", "b n");
    let entry_dir = lab.dir.join("entry");
    std::fs::create_dir_all(&entry_dir).unwrap();
    let resolve = resolver(lab.root.clone());
    let not_running = |d: &str| -> Result<Target, String> { Err(format!("destination zone {d:?} is not running")) };
    let dev = lab.dev;
    let home_dev = move || Some(dev);
    let mut sv = Served {
        zone: &lab.sender,
        uid: unsafe { libc::geteuid() },
        entry: &entry_dir,
        zones_dir: &lab.zones,
        home_dev: &home_dev,
        auto_approve: true,
        max_bytes: 64,
        resolve_dest: &resolve,
        asking: &crate::consent::keep,
        log: &no_log,
        refused_until: &Cell::new(None),
    };
    let file = lab.dir.join("f.txt");
    std::fs::write(&file, b"0123456789").unwrap();
    let ro = || open_flags(&file, libc::O_RDONLY);
    let big = lab.dir.join("big");
    std::fs::write(&big, vec![b'x'; 65]).unwrap();
    let long = "x".repeat(256);
    let cases: Vec<(String, Vec<RawFd>, &str)> = vec![
        ("transfer b f.txt\n".into(), vec![], "exactly one descriptor"),
        ("transfer b f.txt\n".into(), vec![ro(), ro()], "exactly one descriptor"),
        ("transfer b f.txt\n".into(), (0..20).map(|_| ro()).collect(), "more descriptors than a request may carry"),
        ("transfer a f.txt\n".into(), vec![ro()], "cannot transfer to itself"),
        ("transfer c f.txt\n".into(), vec![ro()], "does not name \"c\""),
        ("transfer zzz f.txt\n".into(), vec![ro()], "does not name \"zzz\""),
        ("transfer n f.txt\n".into(), vec![ro()], "receives nothing"),
        ("transfer b ../x\n".into(), vec![ro()], "single path component"),
        ("transfer b a/b\n".into(), vec![ro()], "single path component"),
        ("transfer b .hidden\n".into(), vec![ro()], "must not start with a dot"),
        ("transfer b ..\n".into(), vec![ro()], "not a file name"),
        (format!("transfer b {long}\n"), vec![ro()], "1 to 255 bytes"),
        ("transfer b f.txt extra\n".into(), vec![ro()], "usage: transfer"),
        ("transfer B f.txt\n".into(), vec![ro()], "not a zone name"),
        ("transfer b f.txt\n".into(), vec![open_flags(&lab.dir, libc::O_RDONLY | libc::O_DIRECTORY)], "not a regular file"),
        ("transfer b f.txt\n".into(), vec![open_flags(Path::new("/dev/null"), libc::O_RDONLY)], "not a regular file"),
        ("transfer b f.txt\n".into(), vec![open_flags(&file, libc::O_PATH)], "O_PATH"),
        ("transfer b f.txt\n".into(), vec![open_flags(&file, libc::O_RDWR)], "not opened read-only"),
        ("transfer b big\n".into(), vec![open_flags(&big, libc::O_RDONLY)], "transfer limit is 64"),
    ];
    for (req, fds, want) in cases {
        let (_, r) = ask_with(&sv, &req, &fds, false);
        for f in &fds {
            unsafe { libc::close(*f) };
        }
        let text = String::from_utf8_lossy(&r);
        assert!(text.starts_with("error: ") && text.contains(want), "request {req:?}: got {text:?}, wanted {want:?}");
    }
    /* Every refusal closed what it was handed. Checked after the loop,
     * since the cases open all their descriptors up front. */
    let left = fds_pointing_at(&file) + fds_pointing_at(&lab.dir) + fds_pointing_at(&big);
    assert_eq!(left, 0, "a refusal leaked a descriptor in the broker");
    // A file on another filesystem than the zone's data mount.
    let shm = Path::new("/dev/shm");
    if std::fs::metadata(shm).map(|m| m.dev() != lab.dev).unwrap_or(false) {
        let p = shm.join(format!("kryptik-transfer-{}", std::process::id()));
        std::fs::write(&p, b"elsewhere").unwrap();
        let (_, r) = ask_with(&sv, "transfer b f.txt\n", &[open_flags(&p, libc::O_RDONLY)], false);
        assert!(String::from_utf8_lossy(&r).contains("not on the zone's data mount"), "{}", String::from_utf8_lossy(&r));
        let _ = std::fs::remove_file(&p);
    } else {
        eprintln!("/dev/shm is on the same filesystem as the lab; the st_dev case is not exercised here");
    }
    /* Consent and an unknown data mount each refuse on their own. This sets
     * the variable consent's tests set, so it takes their lock. */
    sv.auto_approve = false;
    {
        let _env = crate::consent::ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("KRYPTIK_CONSENT_DIR", "/nonexistent/kryptik-consent");
        let (_, r) = ask_with(&sv, "transfer b f.txt\n", &[ro()], false);
        assert!(String::from_utf8_lossy(&r).contains("no consent channel"), "{}", String::from_utf8_lossy(&r));
        /* A destination that is not running is refused before any question:
         * even with no consent channel, the error is about the destination. */
        sv.resolve_dest = &not_running;
        let (_, r) = ask_with(&sv, "transfer b f.txt\n", &[ro()], false);
        let text = String::from_utf8_lossy(&r);
        assert!(text.contains("is not running") && !text.contains("consent"), "a transfer to a zone that is not running must be refused before any question: {text}");
        sv.resolve_dest = &resolve;
        std::env::remove_var("KRYPTIK_CONSENT_DIR");
    }
    sv.auto_approve = true;
    sv.home_dev = &dev_unknown;
    let (_, r) = ask_with(&sv, "transfer b f.txt\n", &[ro()], false);
    assert!(String::from_utf8_lossy(&r).contains("data mount is unknown"), "{}", String::from_utf8_lossy(&r));
    // Nothing was created on the destination side.
    assert!(!lab.root.join("home/b/incoming").exists());
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[test]
fn dest_resolved_after_consent() {
    /* The first lookup finds the zone under `before`; by the answer it runs
     * under the lab root, as a zone restarted during the wait would. */
    let lab = lab("again", "b");
    let entry_dir = lab.dir.join("entry");
    let before = lab.dir.join("before");
    std::fs::create_dir_all(&entry_dir).unwrap();
    std::fs::create_dir_all(before.join("home/b")).unwrap();
    let (first, after) = (resolver(before.clone()), resolver(lab.root.clone()));
    let calls = std::cell::Cell::new(0);
    let resolve = |d: &str| {
        calls.set(calls.get() + 1);
        if calls.get() == 1 { first(d) } else { after(d) }
    };
    let held = std::cell::Cell::new(0);
    let asking = || {
        held.set(held.get().max(fds_pointing_at(&before)));
        true
    };
    let dev = lab.dev;
    let home_dev = move || Some(dev);
    let sv = Served {
        zone: &lab.sender,
        uid: unsafe { libc::geteuid() },
        entry: &entry_dir,
        zones_dir: &lab.zones,
        home_dev: &home_dev,
        auto_approve: false,
        max_bytes: 64,
        resolve_dest: &resolve,
        asking: &asking,
        log: &no_log,
        refused_until: &Cell::new(None),
    };
    let file = lab.dir.join("f.txt");
    std::fs::write(&file, b"moved").unwrap();
    let src = open_flags(&file, libc::O_RDONLY);
    let consent = lab.dir.join("consent");
    std::fs::create_dir_all(&consent).unwrap();
    let watch = std::fs::File::create(consent.join(crate::consent::WATCHER_LOCK)).unwrap();
    assert_eq!(unsafe { libc::flock(watch.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
    let r = {
        let _env = crate::consent::ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("KRYPTIK_CONSENT_DIR", &consent);
        let d = consent.clone();
        let person = std::thread::spawn(move || {
            for _ in 0..250 {
                let q = std::fs::read_dir(&d).unwrap().flatten().map(|e| e.path()).find(|p| p.extension().is_some_and(|x| x == "ask"));
                if let Some(q) = q {
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    let id = q.file_stem().unwrap().to_string_lossy().into_owned();
                    std::fs::write(d.join(format!("{id}.answer")), "yes\n").unwrap();
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        });
        let (_, r) = ask_with(&sv, "transfer b f.txt\n", &[src], false);
        person.join().unwrap();
        std::env::remove_var("KRYPTIK_CONSENT_DIR");
        r
    };
    unsafe { libc::close(src) };
    assert_eq!(String::from_utf8_lossy(&r), "ok f.txt\n");
    assert_eq!(held.get(), 0, "the destination's root was held through the question");
    assert_eq!(std::fs::read(lab.root.join("home/b/incoming/f.txt")).unwrap(), b"moved");
    assert!(!before.join("home/b/incoming").exists(), "the transfer went into the tree the zone had left");
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[test]
fn refusal_pauses_questions() {
    /* Every question takes focus in zone 0: after a refusal the same launch
     * may raise no other for a minute, and is told so without one. */
    let lab = lab("pause", "b");
    let entry_dir = lab.dir.join("entry");
    std::fs::create_dir_all(&entry_dir).unwrap();
    let resolve = resolver(lab.root.clone());
    let dev = lab.dev;
    let home_dev = move || Some(dev);
    let refused = Cell::new(None);
    let sv = Served {
        zone: &lab.sender,
        uid: unsafe { libc::geteuid() },
        entry: &entry_dir,
        zones_dir: &lab.zones,
        home_dev: &home_dev,
        auto_approve: false,
        max_bytes: 64,
        resolve_dest: &resolve,
        asking: &crate::consent::keep,
        log: &no_log,
        refused_until: &refused,
    };
    let file = lab.dir.join("f.txt");
    std::fs::write(&file, b"no").unwrap();
    let consent = lab.dir.join("consent");
    std::fs::create_dir_all(&consent).unwrap();
    let watch = std::fs::File::create(consent.join(crate::consent::WATCHER_LOCK)).unwrap();
    assert_eq!(unsafe { libc::flock(watch.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
    let _env = crate::consent::ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("KRYPTIK_CONSENT_DIR", &consent);
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (d, stop) = (consent.clone(), done.clone());
    // The person says no to every question, and counts them.
    let person = std::thread::spawn(move || {
        let mut answered = std::collections::HashSet::new();
        for _ in 0..500 {
            for q in std::fs::read_dir(&d).unwrap().flatten().map(|e| e.path()) {
                if !q.extension().is_some_and(|x| x == "ask") {
                    continue;
                }
                let id = q.file_stem().unwrap().to_string_lossy().into_owned();
                if answered.insert(id.clone()) {
                    let tmp = d.join(format!("{id}.person"));
                    std::fs::write(&tmp, "no\n").unwrap();
                    std::fs::rename(&tmp, d.join(format!("{id}.answer"))).unwrap();
                }
            }
            if stop.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        answered.len()
    });
    let send = || {
        let src = open_flags(&file, libc::O_RDONLY);
        let r = ask_with(&sv, "transfer b f.txt\n", &[src], false).1;
        unsafe { libc::close(src) };
        String::from_utf8_lossy(&r).into_owned()
    };
    let first = send();
    let second = send();
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    let asked = person.join().unwrap();
    /* Once the pause is over the next request is asked again; with no
     * channel, it says so. That asked nobody, so the one right after it is
     * not paused: it reaches the channel check again. */
    refused.set(Some(Instant::now()));
    std::env::set_var("KRYPTIK_CONSENT_DIR", "/nonexistent/kryptik-consent");
    let third = send();
    let fourth = send();
    std::env::remove_var("KRYPTIK_CONSENT_DIR");
    assert!(fourth.contains("no consent channel"), "a refusal that asked nobody paused the next request: {fourth}");
    assert!(first.contains("refused by the user"), "{first}");
    assert!(second.contains("less than a minute ago"), "{second}");
    assert_eq!(asked, 1, "the request after a refusal raised a question");
    assert!(third.contains("no consent channel"), "{third}");
    assert!(!lab.root.join("home/b/incoming/f.txt").exists(), "a refused file landed");
    let _ = std::fs::remove_dir_all(&lab.dir);
}

#[test]
fn read_more_fills_then_stops_at_eof() {
    /* More than a socket buffer, in uneven pieces, after what the header
     * read already took; then a peer that stops short of what it announced. */
    let pair = || {
        let mut sv = [0; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) }, 0);
        (sv[0], sv[1])
    };
    let send = |w: RawFd, bytes: Vec<u8>| {
        std::thread::spawn(move || {
            for piece in bytes.chunks(6007) {
                assert_eq!(unsafe { libc::write(w, piece.as_ptr() as *const libc::c_void, piece.len()) }, piece.len() as isize);
            }
            unsafe { libc::close(w) };
        })
    };
    let data: Vec<u8> = (0..(1usize << 20) + 777).map(|i| (i % 251) as u8).collect();
    let (r, w) = pair();
    let t = send(w, data[10..].to_vec());
    let mut buf = data[..10].to_vec();
    read_more(r, &mut buf, data.len(), Instant::now()).unwrap();
    t.join().unwrap();
    unsafe { libc::close(r) };
    assert!(buf == data, "the payload came back different");
    let (r, w) = pair();
    let t = send(w, vec![7u8; 30]);
    let mut buf = Vec::new();
    read_more(r, &mut buf, 100, Instant::now()).unwrap();
    t.join().unwrap();
    unsafe { libc::close(r) };
    assert_eq!(buf, vec![7u8; 30], "EOF leaves what arrived, and no more");
}

#[test]
fn copy_stops_at_cap() {
    let dir = entry("cap");
    let src_p = dir.join("src");
    std::fs::write(&src_p, vec![b'y'; 20]).unwrap();
    let out_p = dir.join("out");
    let src = open_flags(&src_p, libc::O_RDONLY);
    let out = open_flags(&out_p, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC);
    let e = copy_capped(src, out, 10).unwrap_err();
    assert!(e.contains("longer than the 10 bytes checked"), "{e}");
    assert!(std::fs::metadata(&out_p).unwrap().len() <= 11);
    // And a file within the cap copies whole.
    let src2 = open_flags(&src_p, libc::O_RDONLY);
    let out2 = open_flags(&dir.join("out2"), libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC);
    assert_eq!(copy_capped(src2, out2, 20).unwrap(), 20);
    assert_eq!(std::fs::read(dir.join("out2")).unwrap(), vec![b'y'; 20]);
    for f in [src, out, src2, out2] {
        unsafe { libc::close(f) };
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parse_request_wire_format() {
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
    assert_eq!(
        parse_request("time-offset -0.25 4"),
        Ok(Request::TimeOffset(crate::time::Claim { offset: -0.25, sources: 4 }))
    );
    for bad in ["time-offset", "time-offset 1", "time-offset 1 2 3", "time-offset 1e9 4", "time-offset inf 4", "time-offset 1 0"] {
        assert!(parse_request(bad).is_err(), "{bad:?} was accepted");
    }
}

/// From the nic zone the claim reaches the decision, which refuses for want
/// of a floor; no clock is touched either way.
#[test]
fn only_nic_zone_reports_time() {
    let claim = crate::time::Claim { offset: 2.0, sources: 3 };
    let dir = std::env::temp_dir().join(format!("kryptik-broker-time-{}", std::process::id()));
    let zone_of = |mode: &str, extra: &str| {
        Zone::from_str(&format!(
            "[zone]\nname = \"t\"\n[network]\nmode = \"{mode}\"\n{extra}[storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n[ui]\nborder_color = \"#123456\"\n"
        ))
        .unwrap()
    };
    for mode in ["none", "routed"] {
        let out = time_offset_in(&zone_of(mode, ""), &claim, &mut crate::time::SystemClock, &dir, Some(0), &crate::consent::keep);
        assert!(matches!(&out, crate::time::Outcome::Refused(w) if w.contains("does not hold the network")), "{mode}: {out:?}");
    }
    let nic = zone_of("nic", "");
    let out = time_offset_in(&nic, &claim, &mut crate::time::SystemClock, &dir, None, &crate::consent::keep);
    assert!(matches!(&out, crate::time::Outcome::Refused(w) if w.contains("no floor is known")), "{out:?}");
    assert!(!dir.join("state").exists(), "a refused claim left state behind");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Lengths within their bounds and a one-component name, nothing else.
#[test]
fn update_verbs_parse_within_bounds() {
    use crate::update::{POINTER_MAX, PUT_MAX};
    assert_eq!(parse_request("update-latest 300 120"), Ok(Request::UpdateLatest { plen: 300, slen: 120 }));
    assert_eq!(parse_request("update-poll"), Ok(Request::UpdatePoll));
    assert_eq!(
        parse_request(&format!("update-put kryptik-root.img 1048576 {PUT_MAX}")),
        Ok(Request::UpdatePut { name: "kryptik-root.img".into(), offset: 1048576, len: PUT_MAX })
    );
    assert!(parse_request("update-put manifest.sig 0 120").is_ok());
    let over_pointer = format!("update-latest {} 120", POINTER_MAX + 1);
    let over_put = format!("update-put root.json 0 {}", PUT_MAX + 1);
    for bad in [
        "update-latest", "update-latest 300", "update-latest 0 120", "update-latest 300 0", "update-latest -1 120", over_pointer.as_str(),
        "update-poll now",
        "update-put", "update-put root.json 0", "update-put root.json 0 0", "update-put root.json -1 10", "update-put root.json x 10",
        "update-put ../root.json 0 10", "update-put a/b 0 10", "update-put .hidden 0 10", over_put.as_str(),
    ] {
        assert!(parse_request(bad).is_err(), "{bad:?} was accepted");
    }
}

#[test]
fn only_nic_zone_brings_update() {
    let zone_of = |mode: &str, extra: &str| {
        Zone::from_str(&format!(
            "[zone]\nname = \"t\"\n[network]\nmode = \"{mode}\"\n{extra}[storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n[ui]\nborder_color = \"#123456\"\n"
        ))
        .unwrap()
    };
    for mode in ["none", "routed"] {
        assert!(update_refusal(&zone_of(mode, "")).is_some_and(|w| w.contains("does not hold the network")), "{mode}");
    }
    assert_eq!(update_refusal(&zone_of("nic", "")), None);
}

/// Requests from fuzz-corpus/broker-requests (add any that ever breaks the
/// broker), damaged by a fixed-seed generator and sent down a real
/// connection, each with a fresh descriptor of `attach` when given. No
/// panic, no overrun of the deadline, one well-formed reply, and nothing
/// accepted outside the grammar. Returns (sent, accepted).
fn fuzz_pass(s: &Served, hello: &str, attach: Option<&Path>) -> (u32, u32) {
    const CORPUS: &str = include_str!("../fuzz-corpus/broker-requests");
    // xorshift64*: small, seeded, the same sequence everywhere.
    let mut state: u64 = 0x4252_4F4B_4552_3031;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    let (mut sent, mut accepted) = (0u32, 0u32);
    for seed in CORPUS.lines().filter(|l| !l.is_empty()) {
        // time-offset is refused here and logs every time, so it gets fewer rounds.
        let rounds = if seed.starts_with("time-offset") { 30 } else { 150 };
        for round in 0..rounds {
            let mut req = seed.as_bytes().to_vec();
            req.push(b'\n');
            let payload = (next() % 65) as usize;
            req.extend(std::iter::repeat_n(b'x', payload));
            if round > 0 {
                for _ in 0..1 + next() % 3 {
                    let at = (next() % req.len().max(1) as u64) as usize;
                    match next() % 6 {
                        0 if !req.is_empty() => req[at] ^= 1 << (next() % 8),
                        1 => req.truncate(at),
                        2 => req.insert(at, [b' ', b'\n', 0, 0xff, b'-', b'9'][(next() % 6) as usize]),
                        3 => req.splice(at..at, b"18446744073709551616".iter().copied()).for_each(drop),
                        4 => req.splice(at..at, std::iter::repeat_n(b'A', 600)).for_each(drop),
                        _ if !req.is_empty() => { req.remove(at); }
                        _ => {}
                    }
                }
            }
            let line_end = req.iter().position(|b| *b == b'\n').unwrap_or(req.len());
            let header = String::from_utf8_lossy(&req[..line_end]).into_owned();
            if let Ok(Request::ClipboardSet { len, .. }) = parse_request(&header) {
                assert!(len <= CLIPBOARD_MAX, "{header:?}: a length past the limit parsed");
            }

            let (server, client) = pair();
            match attach {
                Some(p) => {
                    let fd = open_flags(p, libc::O_RDONLY);
                    send_with_fds(client, &req, &[fd]);
                    unsafe { libc::close(fd) };
                }
                None => send_all(client, &req),
            }
            unsafe { libc::shutdown(client, libc::SHUT_WR) };
            let started = Instant::now();
            let served_it = serve_connection(server, s);
            unsafe { libc::close(server) };
            let reply = recv_reply(client);
            unsafe { libc::close(client) };
            sent += 1;
            assert!(served_it.is_ok(), "{header:?}: the connection failed: {served_it:?}");
            assert!(started.elapsed() < REQUEST_DEADLINE + Duration::from_secs(1), "{header:?}: held the launcher past the deadline");
            let text = String::from_utf8_lossy(&reply);
            let first = text.lines().next().unwrap_or("");
            assert!(
                ["ok", "error: ", "empty", hello].iter().any(|p| first.starts_with(p)) && text.contains('\n'),
                "{header:?}: replied {text:?}"
            );
            if first.starts_with("ok") || first.starts_with("empty") || first.starts_with("kryptik-broker") {
                accepted += 1;
            }
        }
    }
    (sent, accepted)
}

#[test]
fn broker_survives_any_request() {
    let dir = entry("fuzz");
    let z = zone_t();
    let s = served(&z, &dir, unsafe { libc::geteuid() });
    let (sent, accepted) = fuzz_pass(&s, "kryptik-broker 1 zone=t", None);
    std::fs::remove_dir_all(dir).unwrap();
    // The generator must reach both sides of the grammar.
    assert!(sent > 2000 && accepted > 50 && accepted < sent, "sent {sent}, accepted {accepted}");
}

/// The same damage past the transfer path's descriptor check: a sender
/// whose policy names b, its data mount the lab's, b running under the lab
/// root, and every request carrying a file of that mount.
#[test]
fn broker_survives_any_transfer() {
    let lab = lab("fuzz", "b");
    let entry_dir = lab.dir.join("entry");
    std::fs::create_dir_all(&entry_dir).unwrap();
    let resolve = resolver(lab.root.clone());
    let dev = lab.dev;
    let home_dev = move || Some(dev);
    let sv = Served {
        zone: &lab.sender,
        uid: unsafe { libc::geteuid() },
        entry: &entry_dir,
        zones_dir: &lab.zones,
        home_dev: &home_dev,
        auto_approve: true,
        max_bytes: 64,
        resolve_dest: &resolve,
        asking: &crate::consent::keep,
        log: &no_log,
        refused_until: &Cell::new(None),
    };
    let file = lab.dir.join("carried.txt");
    std::fs::write(&file, b"carried").unwrap();
    // Set up so a clean request lands: the damage below starts from there.
    let src = open_flags(&file, libc::O_RDONLY);
    assert_eq!(String::from_utf8_lossy(&ask_with(&sv, "transfer b first.txt\n", &[src], false).1), "ok first.txt\n");
    unsafe { libc::close(src) };
    let (sent, _) = fuzz_pass(&sv, "kryptik-broker 1 zone=a", Some(file.as_path()));
    assert_eq!(fds_pointing_at(&file), 0, "the broker kept a descriptor it was handed");
    let _ = std::fs::remove_dir_all(&lab.dir);
    assert!(sent > 2000, "sent {sent}");
}

/// The nic zone reaches time-offset's judgement and the update verbs'
/// payloads, and through them this host's clock and update state. As root
/// that would be the real thing, so it runs only unprivileged, where every
/// such write is refused, and with no consent channel for a question.
#[test]
fn broker_survives_any_request_from_the_nic_zone() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("as root the nic zone's pass would reach this host's clock and update state; skipped");
        return;
    }
    let dir = entry("fuzz-nic");
    let z = Zone::from_str(
        "[zone]\nname = \"t\"\n[network]\nmode = \"nic\"\n\
             [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n[ui]\nborder_color = \"#123456\"\n",
    )
    .unwrap();
    let s = served(&z, &dir, unsafe { libc::geteuid() });
    let _env = crate::consent::ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("KRYPTIK_CONSENT_DIR", "/nonexistent/kryptik-consent");
    let (sent, _) = fuzz_pass(&s, "kryptik-broker 1 zone=t", None);
    std::env::remove_var("KRYPTIK_CONSENT_DIR");
    std::fs::remove_dir_all(dir).unwrap();
    assert!(sent > 2000, "sent {sent}");
}
