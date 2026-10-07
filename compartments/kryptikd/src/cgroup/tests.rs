use super::*;
use std::os::unix::fs::PermissionsExt;

/// A readable, delegated group this process cannot create leaves in is not available.
#[test]
fn availability_requires_creating_leaf() {
    let root = std::env::temp_dir().join(format!("kryptik-cg-{}", std::process::id()));
    let group = root.join(KRYPTIK_GROUP);
    fs::create_dir_all(&group).unwrap();
    for d in [&root, &group] {
        fs::write(d.join("cgroup.controllers"), "cpu io memory pids\n").unwrap();
        fs::write(d.join("cgroup.subtree_control"), "memory pids\n").unwrap();
    }
    // Readable and delegated, but not writable by us.
    fs::set_permissions(&group, fs::Permissions::from_mode(0o555)).unwrap();
    let r = available_under(&root);
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("running as root: a 0555 directory does not refuse root; skipping the negative half");
    } else {
        match r {
            Err(CgroupError::Unavailable(m)) => assert!(m.contains("cannot create a cgroup under"), "{m}"),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }
    // Writable again: available, and the trial leaf is gone.
    fs::set_permissions(&group, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(available_under(&root).unwrap(), group);
    let left: Vec<_> = fs::read_dir(&group).unwrap().flatten().filter(|e| e.path().is_dir()).collect();
    assert!(left.is_empty(), "trial directory left behind: {left:?}");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn memory_suffixes_convert() {
    assert_eq!(parse_memory_max("1024").unwrap(), 1024);
    assert_eq!(parse_memory_max("1K").unwrap(), 1024);
    assert_eq!(parse_memory_max("2M").unwrap(), 2 * 1024 * 1024);
    assert_eq!(parse_memory_max("4G").unwrap(), 4 * 1024 * 1024 * 1024);
    assert_eq!(parse_memory_max("1T").unwrap(), 1024u64 * 1024 * 1024 * 1024);
}

#[test]
fn cpu_and_io_limits_parse() {
    assert_eq!(parse_cpu_max("50%").unwrap(), 50);
    assert_eq!(parse_cpu_max("200%").unwrap(), 200);
    for bad in ["0%", "50", "%", "abc%", ""] {
        assert!(parse_cpu_max(bad).is_err(), "{bad:?}");
    }
    assert_eq!(parse_io_max("8M").unwrap(), 8 << 20);
    assert!(parse_io_max("fast").is_err());
    // A plain file is not a block device; a non-existent path is an error too.
    let f = std::env::temp_dir().join(format!("kryptik-notblock-{}", std::process::id()));
    fs::write(&f, "x").unwrap();
    assert!(block_devices(f.to_str().unwrap()).is_err());
    let _ = fs::remove_file(&f);
    assert!(block_devices("/nonexistent/device").is_err());
}

#[test]
fn partition_counts_as_disk() {
    // A disk's sysfs directory with a partition's inside it, as the kernel lays them out.
    let disk = std::env::temp_dir().join(format!("kryptik-disk-{}", std::process::id()));
    let part = disk.join("sda3");
    fs::create_dir_all(&part).unwrap();
    fs::write(disk.join("dev"), "8:0\n").unwrap();
    fs::write(part.join("dev"), "8:3\n").unwrap();
    fs::write(part.join("partition"), "3\n").unwrap();
    assert_eq!(whole_device(&part).as_deref(), Some("8:0"));
    assert_eq!(whole_device(&disk).as_deref(), Some("8:0"));
    assert_eq!(whole_device(&disk.join("absent")), None);
    let _ = fs::remove_dir_all(&disk);
}

#[test]
fn overflowing_limit_refused() {
    // Wrapping would impose a far tighter limit than asked for.
    assert!(parse_memory_max("18446744073709551615T").is_err());
    assert!(parse_memory_max("").is_err());
    assert!(parse_memory_max("G").is_err());
}

#[test]
fn sweep_spares_populated_cgroup() {
    // A plain directory stands in for the leaf; /sys/fs/cgroup may be out of reach.
    let leaf = std::env::temp_dir().join(format!("kryptik-procs-{}", std::process::id()));
    fs::create_dir_all(&leaf).unwrap();
    for (procs, live) in [("1234\n", true), ("1234\n5678\n", true), ("", false), ("\n", false), ("   \n", false)] {
        fs::write(leaf.join("cgroup.procs"), procs).unwrap();
        assert_eq!(populated(&leaf), live, "{procs:?}");
    }
    let _ = fs::remove_dir_all(&leaf);
    assert!(populated(&leaf), "an unreadable cgroup.procs counts as populated");
}

#[test]
fn sweep_goes_by_launcher_pid() {
    // Plain directories do: the sweep only reads cgroup.procs and /proc.
    let base = std::env::temp_dir().join(format!("kryptik-sweep-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let mut dead = 4_000_000;
    while Path::new(&format!("/proc/{dead}")).exists() {
        dead -= 1;
    }
    let alive = std::process::id();
    let leaf = |name: &str, procs: &str| {
        let p = base.join(name);
        fs::create_dir(&p).unwrap();
        fs::write(p.join("cgroup.procs"), procs).unwrap();
        p
    };
    let gone = leaf(&format!("untrusted.{dead}"), "");
    let live = leaf(&format!("work.{alive}"), "");
    let busy = leaf(&format!("dev.{dead}"), "4242\n");
    let unnamed = leaf("nopid", "");
    assert_eq!(launcher_of(&gone), Some(dead));
    assert_eq!(launcher_of(&live), Some(alive as i32));
    assert_eq!(launcher_of(&unnamed), None);
    // Only the dead launcher's empty leaf goes; live, busy and young pid-less leaves stay.
    assert_eq!(abandoned_leaves(&base), vec![gone.clone()]);
    assert!(live.exists() && busy.exists() && unnamed.exists());
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn available_leaves_no_probes() {
    // A probe left behind would be one more directory per launch.
    let Ok(group) = available() else {
        eprintln!("skipped: no usable cgroup v2 hierarchy here");
        return;
    };
    let _ = available();
    let left: Vec<_> = std::fs::read_dir(&group)
        .expect("the group we were just handed must be readable")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".probe."))
        .collect();
    assert!(left.is_empty(), "probe directories left behind: {left:?}");
}

#[test]
fn unwritable_limit_is_error() {
    // A read-only directory with only memory.max and pids.max, so memory.oom.group's write fails.
    let dir = std::env::temp_dir().join(format!("kryptik-cgtest-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    for f in ["memory.max", "pids.max"] {
        fs::write(dir.join(f), "max").unwrap();
    }
    let ro = fs::Permissions::from_mode(0o555);
    fs::set_permissions(&dir, ro).unwrap();
    // Root ignores the 0555 mode, so only an unprivileged run can test this.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("running as root: a read-only directory does not refuse root; skipped");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let _ = fs::remove_dir_all(&dir);
        return;
    }

    let cg = Cgroup { path: dir.clone() };
    let err = cg.set_limits(Some("1M"), Some(10), None, None).unwrap_err();
    let msg = err.to_string();

    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    let _ = fs::remove_dir_all(&dir);

    assert!(
        msg.contains("memory.oom.group"),
        "set_limits must fail naming the limit it could not apply, said: {msg}"
    );
}
