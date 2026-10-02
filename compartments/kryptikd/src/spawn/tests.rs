use super::*;
use crate::zone::Zone;

/// A relay with no descriptor behind it: only `take` and `flush` are used.
fn relayed(chunks: &[&[u8]]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut o = std::mem::ManuallyDrop::new(ZoneOutput::new(-1, "work"));
    for c in chunks {
        o.take(c, &mut |l| lines.push(l.to_string()));
    }
    o.flush(&mut |l| lines.push(l.to_string()));
    lines
}

#[test]
fn zone_output_relay() {
    // Every line is marked, and a line split across reads stays one line.
    assert_eq!(
        relayed(&[b"kryptikd[zone work]: broker served \"steal\"\nhal", b"f\n"]),
        ["zone work| kryptikd[zone work]: broker served \"steal\"", "zone work| half"]
    );
    // Escapes and carriage returns are replaced.
    assert_eq!(relayed(&[b"\x1b[2Jgone\rtab\there\n"]), ["zone work| ?[2Jgone?tab\there"]);
    // A line with no end is cut at ZONE_LINE_MAX.
    let long = vec![b'a'; ZONE_LINE_MAX * 2 + 5];
    let got = relayed(&[&long]);
    assert_eq!(got.iter().map(|l| l.len() - "zone work| ".len()).collect::<Vec<_>>(), [ZONE_LINE_MAX, ZONE_LINE_MAX, 5]);
    // Past the bound nothing more is logged, and it says so once.
    let flood = vec![b'x'; ZONE_OUTPUT_MAX + 4096];
    let got = relayed(&[&flood, b"more\n"]);
    let logged: usize = got.iter().filter(|l| !l.contains("is not logged")).map(|l| l.len() - "zone work| ".len()).sum();
    assert_eq!(logged, ZONE_OUTPUT_MAX);
    assert_eq!(got.iter().filter(|l| l.contains("is not logged")).count(), 1);
    assert!(!got.iter().any(|l| l.contains("more")));
}

#[test]
fn broker_log_bounded() {
    // A zone reconnecting in a loop: every line is cut, and the total stops.
    let mut b = BrokerLog::new("work");
    let mut got: Vec<String> = Vec::new();
    let long = format!("kryptikd[zone work]: {}", "x".repeat(4000));
    for _ in 0..10_000 {
        b.line(&long, &mut |l: &str| got.push(l.to_string()));
    }
    assert!(got.iter().all(|l| l.len() <= ZONE_LINE_MAX));
    let total: usize = got.iter().map(|l| l.len() + 1).sum();
    assert!(total <= ZONE_OUTPUT_MAX + 100, "{total} bytes logged");
    assert_eq!(got.last().unwrap(), &format!("kryptikd[zone work]: broker lines past {ZONE_OUTPUT_MAX} bytes are not logged"));
    assert_eq!(got.iter().filter(|l| l.contains("not logged")).count(), 1);
    // A cut never splits a character.
    let mut b = BrokerLog::new("work");
    b.line(&"\u{e9}".repeat(ZONE_LINE_MAX), &mut |l: &str| assert!(l.len() <= ZONE_LINE_MAX));
}

#[test]
fn wayland_socket_verified() {
    let dir = std::env::temp_dir().join(format!("kryptik-wlsock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("wayland-0");
    let _first = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let c = CString::new(path.display().to_string()).unwrap();
    assert_eq!(unsafe { libc::stat(c.as_ptr(), &mut st) }, 0);
    let verified = crate::serve::InodeId::of(&st);
    assert!(open_wayland_socket(&path, Some(verified)).is_ok());
    // Another socket put in its place is refused; the first keeps its inode.
    std::fs::rename(&path, dir.join("wayland-0.old")).unwrap();
    let _second = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let e = open_wayland_socket(&path, Some(verified)).unwrap_err();
    assert!(e.contains("inode changed"), "{e}");
    assert!(open_wayland_socket(&path, None).is_ok(), "without a verified inode any socket there will do");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn peer_gone_after_close() {
    let p = SyncPipe::new().unwrap();
    assert!(!p.peer_gone(), "an open write end reads as a hang-up");
    p.close_write();
    assert!(p.peer_gone(), "a closed write end is not seen");
    p.close_read();
}

#[test]
fn pump_reads_bounded_amount() {
    // An endless writer must not keep a pump from returning: fill past one pass, check the rest.
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) }, 0);
    let (r, w) = (fds[0], fds[1]);
    let size = unsafe { libc::fcntl(w, libc::F_SETPIPE_SZ, 1 << 20) };
    let size = if size > 0 { size as usize } else { 65536 };
    let chunk = [b'y'; 4096];
    let mut written = 0usize;
    while written + chunk.len() <= size {
        let n = unsafe { libc::write(w, chunk.as_ptr() as *const libc::c_void, chunk.len()) };
        if n <= 0 { break; }
        written += n as usize;
    }
    let one_pass = ZONE_READS_PER_PUMP * 4096;
    assert!(written > one_pass, "the pipe took {written} bytes, not more than one pass ({one_pass})");
    let mut o = std::mem::ManuallyDrop::new(ZoneOutput::new(r, "work"));
    assert!(o.pump(&mut |_: &str| {}), "the writer is still there");
    let mut left: libc::c_int = 0;
    assert_eq!(unsafe { libc::ioctl(r, libc::FIONREAD, &mut left) }, 0);
    assert_eq!(left as usize, written - one_pass, "one pass read {} bytes, not {one_pass}", written - left as usize);
    unsafe { libc::close(w); libc::close(r) };
}

fn z(mode: &str) -> Zone {
    Zone::from_str(&format!(
        "[zone]\nname = \"t\"\n[network]\nmode = \"{mode}\"\n\
             [storage]\nmode = \"ephemeral\"\nsize = \"256M\"\n[ui]\nborder_color = \"#123456\"\n"
    ))
    .unwrap()
}

fn z_identity(base: u32) -> Zone {
    Zone::from_str(&format!(
        "[zone]\nname = \"t\"\n[network]\nmode = \"routed\"\n\
             [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n\
             [identity]\nuid_base = {base}\n[ui]\nborder_color = \"#123456\"\n"
    ))
    .unwrap()
}

/// The line matches what the launch will do on this kernel.
#[test]
fn explain_names_core_scheduling() {
    let e = explain(&z("none"), "/tmp/t", std::path::Path::new("/nonexistent"));
    let line = e.lines().find(|l| l.starts_with("core sched")).unwrap_or_else(|| panic!("no core sched line in:\n{e}"));
    let want = match isolate::core_scheduling() {
        isolate::CoreSched::Cookies => "own cookie",
        isolate::CoreSched::NoSmt => "no sibling threads online",
        isolate::CoreSched::Unavailable => "not available on this kernel",
    };
    assert!(line.contains(want), "{line}");
}

/// Two forked writers share a pipe, one through `log_line`; every line must come back whole.
#[test]
fn log_line_never_split() {
    use std::io::Read;
    use std::os::unix::io::FromRawFd;
    const N: usize = 1500;
    let a_line = format!("kryptikd[zone probe]: broker served {:?} {}", "steal", "x".repeat(160));
    let b_line = "error: unknown verb";
    let mut p = [0 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0, "pipe failed");
    let mut kids = Vec::new();
    for which in 0..2 {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe {
                libc::close(p[0]);
                if which == 0 {
                    libc::dup2(p[1], 2);
                    for _ in 0..N {
                        log_line(&a_line);
                    }
                } else {
                    let line = format!("{b_line}\n");
                    for _ in 0..N {
                        libc::write(p[1], line.as_ptr() as *const libc::c_void, line.len());
                    }
                }
                libc::_exit(0);
            }
        }
        kids.push(pid);
    }
    unsafe { libc::close(p[1]) };
    let mut all = String::new();
    unsafe { std::fs::File::from_raw_fd(p[0]) }.read_to_string(&mut all).expect("read the pipe");
    for k in kids {
        let mut st = 0;
        unsafe { libc::waitpid(k, &mut st, 0) };
    }
    let (mut a, mut b) = (0, 0);
    for line in all.lines() {
        if line == a_line {
            a += 1;
        } else if line == b_line {
            b += 1;
        } else {
            panic!("a line arrived that neither writer wrote whole: {line:?}");
        }
    }
    assert_eq!((a, b), (N, N), "lines were lost or merged");
}

#[test]
fn explain_policy_caps() {
    let dir = std::env::temp_dir().join(format!("kryptik-explain-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("policy")).unwrap();
    std::fs::write(dir.join("policy/n.seccomp"), "keep-capability CAP_NET_RAW\nkeep-capability CAP_NET_ADMIN\n").unwrap();
    let nic = Zone::from_str(
        "[zone]\nname = \"n\"\n[network]\nmode = \"nic\"\n\
             [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n[policy]\nseccomp = \"policy/n.seccomp\"\n\
             [ui]\nborder_color = \"#123456\"\n",
    )
    .unwrap();
    let e = explain(&nic, "/tmp/n", &dir);
    assert!(e.contains("caps       bounding set: CAP_NET_BIND_SERVICE + CAP_NET_RAW + CAP_NET_ADMIN (kept by policy)"), "{e}");
    // The same file on a routed zone is an error, and explain says so.
    let routed = Zone::from_str(
        "[zone]\nname = \"r\"\n[network]\nmode = \"routed\"\n\
             [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n[policy]\nseccomp = \"policy/n.seccomp\"\n\
             [ui]\nborder_color = \"#123457\"\n",
    )
    .unwrap();
    let e = explain(&routed, "/tmp/r", &dir);
    assert!(e.contains("ERROR") && e.contains("owns the NIC"), "{e}");
    assert!(e.contains("dropped to CAP_NET_BIND_SERVICE only"), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn explain_names_identity_range() {
    assert!(explain(&z_identity(196608), "/tmp/t", std::path::Path::new("/nonexistent")).contains("uid_base 196608"));
    assert!(explain(&z("routed"), "/tmp/t", std::path::Path::new("/nonexistent")).contains("none declared"));
}

#[test]
fn explain_warns_persistent_unencrypted() {
    let z = Zone::from_str(
        "[zone]\nname = \"t\"\n[network]\nmode = \"none\"\n\
             [storage]\nmode = \"persistent\"\n[ui]\nborder_color = \"#123456\"\n",
    )
    .unwrap();
    let e = explain(&z, "/var/lib/kryptik/zones/t", std::path::Path::new("/nonexistent"));
    assert!(e.contains("NOT encrypted at rest"), "say it in those words: {e}");
    assert!(
        e.contains("kept between launches"),
        "and say what it DOES do, or the line reads as a pure warning: {e}"
    );
    // Unlike an ephemeral zone's, this data directory is visible inside.
    assert!(
        e.contains("/var/lib/kryptik/zones/t (visible inside as"),
        "the data line must place it: {e}"
    );
}

fn z_encrypted() -> Zone {
    Zone::from_str(
        "[zone]\nname = \"t\"\n[network]\nmode = \"none\"\n\
             [storage]\nmode = \"encrypted\"\nvolume = \"/dev/kryptik/t\"\n\
             [ui]\nborder_color = \"#123456\"\n",
    )
    .unwrap()
}

#[test]
fn rootfs_under_base() {
    assert_eq!(zone_rootfs(&z("routed"), "/var/lib/kryptik/zones"),
               "/var/lib/kryptik/zones/t");
}

#[test]
fn explain_namespaces_storage() {
    let e = explain(&z("none"), "/tmp/t", std::path::Path::new("/nonexistent"));
    assert!(e.contains("user"), "{e}");
    assert!(e.contains("net"), "{e}");
    assert!(e.contains("tmpfs"), "explain must say what ephemeral storage is: {e}");
}

#[test]
fn explain_does_not_overclaim() {
    let e = explain(&z("routed"), "/tmp/t", std::path::Path::new("/tmp"));
    // A routed zone's way out is the nic zone's to open, never kryptikd's.
    let says_who = e.contains("no path out")
        || e.contains("loopback")
        || e.contains("nic zone")
        || e.contains("NAT")
        || e.contains("uid_base");
    assert!(says_who, "explain must say who opens a routed zone's way out: {e}");
    assert!(e.contains("swap"), "explain must name the swap caveat: {e}");
    assert!(
        e.contains("NOT secure erasure"),
        "explain must not let 'ephemeral' be read as secure erasure: {e}"
    );

    // Encrypted: the container and mapping are named, and unprivileged launches refused.
    let enc = explain(&z_encrypted(), "/tmp/t", std::path::Path::new("/nonexistent"));
    assert!(enc.contains("LUKS2") && enc.contains("/dev/mapper/kryptik-zone-t"), "{enc}");
    assert!(enc.contains("Unprivileged launches are refused"), "{enc}");
}

#[test]
fn decode_status_matches_shell() {
    assert_eq!(decode_status(0), 0);
    assert_eq!(decode_status(3 << 8), 3);
    assert_eq!(decode_status(libc::SIGSYS), 128 + libc::SIGSYS);
}

#[test]
fn environment_is_allowlist() {
    let caller: Vec<(String, String)> = [
        ("FOO_TOKEN", "leaked"),
        ("SSH_AUTH_SOCK", "/run/user/1000/keyring/ssh"),
        ("LD_PRELOAD", "/tmp/evil.so"),
        ("LD_LIBRARY_PATH", "/tmp"),
        ("KRYPTIK_EXPERIMENTAL", "1"),
        ("HOME", "/home/operator"),
        ("PATH", "/home/operator/bin:/usr/bin"),
        ("XDG_RUNTIME_DIR", "/run/user/1000"),
        ("TERM", "xterm-256color"),
        ("LANG", "en_US.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let env = zone_environment(&z("routed"), "/home/t", &caller, false);
    let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    for dropped in ["FOO_TOKEN", "SSH_AUTH_SOCK", "LD_PRELOAD", "LD_LIBRARY_PATH", "KRYPTIK_EXPERIMENTAL", "XDG_RUNTIME_DIR"] {
        assert!(get(dropped).is_none(), "{dropped} leaked into the zone");
    }
    assert_eq!(get("HOME"), Some("/home/t"), "caller HOME must be replaced");
    assert_eq!(get("PATH"), Some("/usr/bin:/usr/sbin:/bin:/sbin"));
    assert_eq!(get("TERM"), Some("xterm-256color"));
    assert_eq!(get("LANG"), Some("en_US.UTF-8"));
    assert_eq!(get("LC_ALL"), Some("C.UTF-8"));
    assert_eq!(get("KRYPTIK_ZONE"), Some("t"));
    assert_eq!(get("USER"), Some("root"));
}

#[test]
fn passthrough_well_formed() {
    assert!(env_value_is_sane("xterm-256color"));
    assert!(env_value_is_sane("en_US.UTF-8"));
    assert!(!env_value_is_sane(""));
    assert!(!env_value_is_sane("xterm\n"));
    assert!(!env_value_is_sane("$(id)"));
    assert!(!env_value_is_sane("/etc/passwd"));
    assert!(!env_value_is_sane("a b"));
    assert!(!env_value_is_sane(&"x".repeat(65)));
    let caller = vec![("TERM".to_string(), "xterm;rm -rf /".to_string())];
    let env = zone_environment(&z("routed"), "/home/t", &caller, false);
    let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    assert_eq!(get("TERM"), Some("dumb"), "a malformed TERM is replaced, not passed");
    assert_eq!(get("LANG"), Some("C.UTF-8"), "no caller LANG means a UTF-8 default");
}

#[test]
fn unprivileged_identity() {
    if unsafe { libc::geteuid() } == 0 {
        // As root the rule is the reverse; see the next test.
        return;
    }
    let err = launch_identity(&RunOptions { zone_uid: Some(1001), zone_gid: Some(1001), ..Default::default() }, &z("routed")).unwrap_err();
    assert!(err.to_string().contains("need root"), "{err}");
    let id = launch_identity(&RunOptions::default(), &z("routed")).unwrap();
    assert_eq!(id.uid, unsafe { libc::getuid() });
    assert!(!id.privileged);
}

#[test]
fn root_launch_identity() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    assert!(launch_identity(&RunOptions::default(), &z("routed")).is_err());
    assert!(launch_identity(&RunOptions { zone_uid: Some(0), zone_gid: Some(0), ..Default::default() }, &z("routed")).is_err());
    let id = launch_identity(&RunOptions { zone_uid: Some(100000), zone_gid: Some(100000), ..Default::default() }, &z("routed")).unwrap();
    assert!(id.privileged);
    // A declared identity wins, and an override of it is refused.
    let id = launch_identity(&RunOptions::default(), &z_identity(196608)).unwrap();
    assert_eq!((id.uid, id.gid), (196608, 196608));
    let err = launch_identity(&RunOptions { zone_uid: Some(100000), zone_gid: Some(100000), ..Default::default() }, &z_identity(196608)).unwrap_err();
    assert!(err.to_string().contains("not accepted"), "{err}");
}
