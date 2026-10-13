use super::*;

#[test]
fn net_summary_passes_on_known_fields_only() {
    let line = "READY uplink=10.0.2.15/24 nat=yes dns=yes wifi=Cafe Wifi time=+0.5 bridge=kryptik0 uplinks=eth0 wlan0";
    assert_eq!(net_summary(line).as_deref(), Some("ready: Wi-Fi \"Cafe Wifi\", uplink 10.0.2.15/24, DNS"));
    let wired = "READY uplink=none nat=yes dns=no wifi=none time=no-uplink bridge=kryptik0 uplinks=eth0";
    assert_eq!(net_summary(wired).as_deref(), Some("ready: no uplink address, no DNS"));
    let joining = "READY uplink=10.0.2.15/24 nat=yes dns=yes wifi=connecting time=-2";
    assert_eq!(net_summary(joining).as_deref(), Some("ready: Wi-Fi connecting, uplink 10.0.2.15/24, DNS"));
    let off = "READY uplink=10.0.2.15/24 nat=yes dns=yes wifi=off time=-2";
    assert_eq!(net_summary(off).as_deref(), Some("ready: Wi-Fi switched off, uplink 10.0.2.15/24, DNS"));
    let down = "NOT READY firewall policy not loaded; forwarding off; uplink=none dns=no wifi=none time=x";
    assert_eq!(net_summary(down).as_deref(), Some("not ready: forwarding is off"));
    // An SSID is any access point's: what a terminal would act on comes out escaped, and words
    // in it that look like fields do not stand for the line's own.
    let hostile = "READY uplink=10.0.2.15/24 nat=yes dns=yes wifi=\\x1b[2J x time=0 dns=no time=+1 bridge=k";
    let s = net_summary(hostile).unwrap();
    assert!(!s.contains('\u{1b}') && s.contains("\\u{1b}[2J x time=0 dns=no"), "{s}");
    assert!(s.ends_with(", uplink 10.0.2.15/24, DNS"), "{s}");
    for bad in [
        "",
        "READY",
        "anything else",
        "READY uplink=10.0.2.300/24 nat=yes dns=yes wifi=none time=0",
        "READY uplink=10.0.2.15/33 nat=yes dns=yes wifi=none time=0",
        "READY uplink=10.0.2.15 nat=yes dns=yes wifi=none time=0",
        "READY uplink=none nat=yes dns=maybe wifi=none time=0",
        "READY uplink=none nat=yes dns=yes wifi= time=0",
        "READY uplink=none nat=yes dns=yes wifi=an SSID of thirty-three bytes!!!! time=0",
        "READY uplink=none nat=yes dns=yes time=0 wifi=late",
        // iw prints no control character as itself.
        "READY uplink=none nat=yes dns=yes wifi=\u{1b}[2J time=0",
    ] {
        assert_eq!(net_summary(bad), None, "{bad:?}");
    }
}

#[test]
fn net_summary_reads_an_ssid_back_from_iw() {
    let line = |printed: &str| format!("READY uplink=none nat=yes dns=yes wifi={printed} time=0");
    // iw prints each byte past ASCII as \xHH, four characters for one byte: a name of sixteen
    // bytes is sixty-four characters long, and comes back whole.
    let cyrillic = line("\\xd0\\xa0\\xd0\\xb5\\xd1\\x81\\xd1\\x82\\xd0\\xbe\\xd1\\x80\\xd0\\xb0\\xd0\\xbd");
    assert_eq!(net_summary(&cyrillic).as_deref(), Some("ready: Wi-Fi \"Ресторан\", no uplink address, DNS"));
    let full = line(&"\\xc3\\xa9".repeat(16));
    assert_eq!(net_summary(&full), Some(format!("ready: Wi-Fi \"{}\", no uplink address, DNS", "é".repeat(16))));
    assert_eq!(net_summary(&line(&format!("{}x", "\\xc3\\xa9".repeat(16)))), None, "33 bytes");
    // A name that is not UTF-8 keeps its escapes; one that turns text around is escaped.
    assert_eq!(net_summary(&line("Caf\\xe9")).as_deref(), Some("ready: Wi-Fi \"Caf\\xe9\", no uplink address, DNS"));
    let s = net_summary(&line("\\xe2\\x80\\xaegnp.exe")).unwrap();
    assert!(!s.contains('\u{202e}') && s.contains("\\u{202e}gnp.exe"), "{s}");
    for bad in ["\\x", "\\xd", "\\xzz", "\\q", "tail\\", "\\x00\\x00"] {
        assert_eq!(net_summary(&line(bad)), None, "{bad:?}");
    }
}

#[test]
fn net_summary_names_the_network_that_refused_the_passphrase() {
    let line = |wifi: &str| format!("READY uplink=none nat=yes dns=no wifi={wifi} time=no-uplink");
    let refused = line("refused:Home net");
    assert_eq!(net_summary(&refused).as_deref(), Some("ready: Wi-Fi \"Home net\" refused the passphrase, no uplink address, no DNS"));
    let cafe = line("refused:Caf\\xc3\\xa9");
    assert_eq!(net_summary(&cafe).as_deref(), Some("ready: Wi-Fi \"Café\" refused the passphrase, no uplink address, no DNS"));
    for bad in ["refused:", "refused:\\q", "refused:an SSID of thirty-three bytes!!!!"] {
        assert_eq!(net_summary(&line(bad)), None, "{bad:?}");
    }
}

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
fn parse_wifi_hides_psk() {
    let r = parse_wifi("wifi-add\nssid Cafe Wifi \npsk pass word\nend\n").unwrap();
    assert_eq!(r.ssid, "Cafe Wifi ");
    assert_eq!(r.psk.as_deref(), Some("pass word"));
    let r = parse_wifi("wifi-forget\nssid Home\nend\n").unwrap();
    assert_eq!((r.ssid.as_str(), r.psk), ("Home", None));
    let r = parse_wifi("wifi-add\nssid Cafe\nopen\nend\n").unwrap();
    assert_eq!((r.ssid.as_str(), r.psk, r.open), ("Cafe", None, true));
    for bad in [
        "wifi-add\nssid a\nend\n",                    // no psk
        "wifi-add\nssid a\npsk secret\nopen\nend\n",  // a psk and open
        "wifi-add\nssid a\nopen\nopen\nend\n",        // one open
        "wifi-forget\nssid a\nopen\nend\n",           // forget takes no open
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
fn proxy_path_rule() {
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
fn open_nofollow_refusals() {
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
fn full_backlog_never_blocks() {
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
fn spoiled_stage_is_known_by_the_updater_words() {
    // The two refusals kryptik-update gives a file that is not what its manifest signs.
    let tool = include_str!("../../../../tools/update/kryptik-update");
    for words in ["sha256 does not match the manifest", "truncated or altered"] {
        assert!(tool.contains(words), "kryptik-update no longer says {words:?}");
        assert!(spoiled(&format!("kryptik-update: FAILED: kryptik-root.img: {words}")));
    }
    assert!(!spoiled("kryptik-update: FAILED: another update is in progress (lock /run/kryptik/update.lock)"));
    assert!(!spoiled("kryptik-update: FAILED: slot b is 1 bytes; the root image needs 2"));
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
fn zone_log_starts_again_past_its_bound() {
    let dir = std::env::temp_dir().join(format!("kryptik-serve-log-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("zone-x.log");
    let old = dir.join("zone-x.log.old");
    // Under the bound a launch appends to what is there.
    std::fs::write(&log, "first launch\n").unwrap();
    open_zone_log(&log).unwrap().write_all(b"second launch\n").unwrap();
    assert_eq!(std::fs::read_to_string(&log).unwrap(), "first launch\nsecond launch\n");
    assert!(!old.exists(), "a log under the bound was moved aside");
    // Past it the file is kept as .old, in place of the one before, and a new one starts.
    std::fs::write(&old, "the generation before\n").unwrap();
    let grown = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
    grown.set_len(ZONE_LOG_KEEP + 1).unwrap(); // sparse: no large allocation or disk write
    drop(grown);
    open_zone_log(&log).unwrap().write_all(b"third launch\n").unwrap();
    assert_eq!(std::fs::read_to_string(&log).unwrap(), "third launch\n");
    assert_eq!(std::fs::metadata(&old).unwrap().len(), ZONE_LOG_KEEP + 1, "the grown log is not the one kept");
    // A link at the name is refused, and nothing is made through it.
    let target = dir.join("elsewhere");
    std::fs::remove_file(&log).unwrap();
    std::os::unix::fs::symlink(&target, &log).unwrap();
    assert!(open_zone_log(&log).is_err(), "a log was opened through a link");
    assert!(!target.exists(), "a file was made through a link at the log's name");
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
