use super::*;

/// Run `body` in a forked child: these tests change descriptors and namespaces the harness shares.
fn in_child(body: impl FnOnce() -> i32) -> i32 {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        let rc = body();
        unsafe { libc::_exit(rc) };
    }
    let mut status = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            break;
        }
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EINTR));
    }
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        200 + libc::WTERMSIG(status)
    }
}

const SKIP: i32 = 77;

fn is_open(fd: i32) -> bool {
    (unsafe { libc::fcntl(fd, libc::F_GETFD) }) >= 0
}

/// Open /dev/null at a specific descriptor number.
fn open_at(fd: i32) {
    let c = CString::new("/dev/null").unwrap();
    let f = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
    assert!(f >= 0);
    assert!(unsafe { libc::dup2(f, fd) } == fd, "dup2 to {fd} failed");
    // dup2(f, f) is a no-op; closing f would then close `fd`.
    if f != fd {
        unsafe { libc::close(f) };
    }
}

#[test]
fn system_paths_exclude_etc() {
    for p in SYSTEM_PATHS {
        assert!(p.starts_with('/'), "{p} must be absolute");
        assert_ne!(*p, "/etc", "/etc is synthesized, never bound wholesale");
    }
}

#[test]
fn device_list_is_minimal() {
    // Nothing that reaches real hardware or kernel memory.
    for (host, _) in DEVICES {
        assert!(host.starts_with("/dev/"), "{host} is not under /dev");
        for banned in ["mem", "kmem", "port", "sda", "nvme", "input", "kvm"] {
            assert!(
                !host.contains(banned),
                "{host} exposes hardware a zone must not reach"
            );
        }
    }
}

#[test]
fn etc_view_excludes_secrets() {
    let all: Vec<&str> = ETC_RO_FILES.iter().chain(ETC_RO_DIRS).copied().collect();
    for banned in [
        "/etc/machine-id", "/etc/hostname", "/etc/hosts", "/etc/passwd", "/etc/group",
        "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/ssh", "/etc/ssl/private",
        "/etc/ld.so.preload", "/etc/fstab", "/etc/crypttab", "/etc/resolv.conf",
        "/etc/localtime", "/etc",
    ] {
        assert!(!all.contains(&banned), "{banned} must not be exposed to a zone");
    }
    for p in &all {
        assert!(p.starts_with("/etc/"), "{p}");
        assert!(!p.starts_with("/etc/ssl/private"), "{p}");
    }
}

#[test]
fn proc_hides_host_activity() {
    // What times keystrokes in other zones, and what shows which encrypted zones are open.
    for f in ["interrupts", "stat", "loadavg", "partitions", "diskstats"] {
        assert!(PROC_MASKED.contains(&f), "/proc/{f} must be masked");
    }
}

#[test]
fn bridge_resolver() {
    let r = resolv_conf_for_bridge();
    assert_eq!(r.lines().count(), 2);
    assert!(r.contains("nameserver 10.19.0.1") && r.contains("nameserver fd19::1"));
    assert!(!r.contains("10.0.2.3"), "must never name a host or slirp resolver");
}

#[test]
fn identity_names_zone() {
    let pw = passwd_for("work", "/home/work", false);
    assert!(pw.starts_with("root:x:0:0:work:/home/work:"), "{pw}");
    assert_eq!(pw.lines().count(), 2);
    assert_eq!(group_for(false).lines().count(), 2);
    // The nic zone's dhcpcd drops to the third mapped id, chrooted to an empty directory.
    let pw = passwd_for("net", "/home/net", true);
    assert_eq!(pw.lines().count(), 3);
    assert!(pw.contains("\ndhcpcd:x:100:100:dhcpcd:/var/empty:/bin/false\n"));
    assert!(group_for(true).contains("\ndhcpcd:x:100:\n"));
    assert_eq!(crate::isolate::SERVICE_ID, 100);
    assert!(hosts_for("work").contains("127.0.0.1 localhost work"));
    assert_eq!(zone_home("work"), "/home/work");
    assert!(nsswitch().contains("passwd: files"));
}

#[test]
fn data_dir_refusals() {
    let base = std::env::temp_dir().join(format!("kryptik-rootfs-test-{}", std::process::id()));
    let real = base.join("real");
    let link = base.join("link");
    fs::create_dir_all(&real).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let me = unsafe { libc::geteuid() };
    assert!(check_data_dir(real.to_str().unwrap(), me).is_ok());
    let err = check_data_dir(link.to_str().unwrap(), me).unwrap_err();
    assert!(err.to_string().contains("symlink"), "{err}");
    let err = check_data_dir(real.to_str().unwrap(), me + 1).unwrap_err();
    assert!(err.to_string().contains("owned by uid"), "{err}");
    let file = base.join("file");
    fs::write(&file, "x").unwrap();
    assert!(check_data_dir(file.to_str().unwrap(), me).is_err());
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn leftover_names_are_escaped() {
    use std::os::unix::ffi::OsStrExt;
    let base = std::env::temp_dir().join(format!("kryptik-leftovers-{}", std::process::id()));
    fs::create_dir_all(&base).unwrap();
    let dir = base.to_str().unwrap();
    assert!(check_data_dir_empty(dir, "z").is_ok());
    // A name that is not UTF-8 still counts as data.
    fs::write(base.join(std::ffi::OsStr::from_bytes(b"\xff")), "x").unwrap();
    let only_raw = check_data_dir_empty(dir, "z").map_err(|e| e.to_string());
    fs::write(base.join("a\x1b[2Jb"), "x").unwrap();
    let err = check_data_dir_empty(dir, "z").unwrap_err().to_string();
    let _ = fs::remove_dir_all(&base);
    assert!(only_raw.as_ref().is_err_and(|e| e.contains("\\xFF")), "{only_raw:?}");
    assert!(!err.contains('\x1b') && err.contains("\\u{1b}"), "{err}");
}

#[test]
fn close_fds_keeps_stdio() {
    let rc = in_child(|| {
        open_at(3);
        open_at(4095);
        open_at(5000);
        if !(is_open(3) && is_open(4095) && is_open(5000)) {
            return 10;
        }
        if close_inherited_fds().is_err() {
            return 11;
        }
        for fd in 0..=2 {
            if !is_open(fd) {
                return 20 + fd;
            }
        }
        for fd in [3, 4095, 5000] {
            if is_open(fd) {
                return 30;
            }
        }
        0
    });
    assert_eq!(rc, 0, "child reported failure code {rc}");
}

#[test]
fn ensure_stdio_reopens() {
    let rc = in_child(|| {
        unsafe { libc::close(0) };
        if is_open(0) {
            return 1;
        }
        ensure_stdio();
        if !is_open(0) {
            return 2;
        }
        0
    });
    assert_eq!(rc, 0);
}

/// A submount in the bound tree must be read-only too; skips without an unprivileged userns.
#[test]
fn ro_bind_recursive() {
    // Before the fork: temp_dir() takes std's env lock, which, held at fork time, hangs the child.
    let base = std::env::temp_dir().join(format!("kryptik-ro-test-{}", std::process::id()));
    let rc = in_child(|| {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } < 0 {
            return SKIP;
        }
        if fs::write("/proc/self/setgroups", "deny").is_err()
            || fs::write("/proc/self/uid_map", format!("0 {uid} 1\n")).is_err()
            || fs::write("/proc/self/gid_map", format!("0 {gid} 1\n")).is_err()
        {
            return SKIP;
        }
        if mount_raw("none", "/", None, libc::MS_REC | libc::MS_PRIVATE, None, "private").is_err() {
            return SKIP;
        }
        let src = base.join("src");
        let sub = src.join("sub");
        let dst = base.join("dst");
        if fs::create_dir_all(&sub).is_err() || fs::create_dir_all(&dst).is_err() {
            return 3;
        }
        // A writable tmpfs inside the source stands in for a submount under /usr.
        if mount_raw("tmpfs", sub.to_str().unwrap(), Some("tmpfs"), 0, Some("mode=0777"), "sub").is_err() {
            return SKIP;
        }
        if let Err(e) = bind_ro_dir(src.to_str().unwrap(), dst.to_str().unwrap()) {
            eprintln!("bind_ro_dir: {e}");
            return 4;
        }
        // Top level read-only...
        if fs::write(dst.join("top"), "x").is_ok() {
            return 5;
        }
        // ...and the submount too.
        if fs::write(dst.join("sub").join("inner"), "x").is_ok() {
            return 6;
        }
        // Control: the source itself is still writable.
        if fs::write(sub.join("control"), "x").is_err() {
            return 7;
        }
        0
    });
    match rc {
        0 => {}
        SKIP => eprintln!("no unprivileged user namespace here; skipping"),
        other => panic!("read-only bind check failed with code {other}"),
    }
}

#[test]
fn nic_sysfs_keeps_its_devices_and_no_others() {
    use std::os::unix::fs::symlink;
    let base = std::env::temp_dir().join(format!("kryptik-nic-sysfs-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    // A PCI NIC, a radio on a virtual device, the bridge, and a disk, linked as sysfs links them.
    for d in [
        "devices/pci0000:00/0000:00:03.0/net/eth0",
        "devices/virtual/mac80211_hwsim/hwsim0/net/wlan0",
        "devices/virtual/mac80211_hwsim/hwsim0/ieee80211/phy0",
        "devices/virtual/net/kryptik0",
        "devices/pci0000:00/0000:00:1f.2/ata1/host0/block/sda",
        "class/net",
        "class/ieee80211",
        "class/block",
    ] {
        fs::create_dir_all(base.join(d)).unwrap();
    }
    for (link, to) in [
        ("devices/pci0000:00/0000:00:03.0/net/eth0/device", "../../../0000:00:03.0"),
        ("devices/virtual/mac80211_hwsim/hwsim0/net/wlan0/device", "../../../hwsim0"),
        ("devices/virtual/mac80211_hwsim/hwsim0/ieee80211/phy0/device", "../../../hwsim0"),
        ("class/net/eth0", "../../devices/pci0000:00/0000:00:03.0/net/eth0"),
        ("class/net/wlan0", "../../devices/virtual/mac80211_hwsim/hwsim0/net/wlan0"),
        ("class/net/kryptik0", "../../devices/virtual/net/kryptik0"),
        ("class/ieee80211/phy0", "../../devices/virtual/mac80211_hwsim/hwsim0/ieee80211/phy0"),
        ("class/block/sda", "../../devices/pci0000:00/0000:00:1f.2/ata1/host0/block/sda"),
    ] {
        symlink(to, base.join(link)).unwrap();
    }
    let kept = nic_sysfs(base.to_str().unwrap());
    let _ = fs::remove_dir_all(&base);
    let want = [
        "class/net",
        "devices/virtual/net",
        "devices/system/cpu",
        "class/ieee80211",
        "devices/pci0000:00/0000:00:03.0",
        "devices/virtual/mac80211_hwsim/hwsim0",
    ];
    assert_eq!(kept, want, "the kept list, in order, once each");
}
