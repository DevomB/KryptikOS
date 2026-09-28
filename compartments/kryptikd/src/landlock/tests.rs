use super::*;

#[test]
fn parse_policy_accepts_and_refuses() {
    let p = parse_policy("# c\nread-exec /\nread-write /tmp\n\nread /usr/share # trailing\n", "t").unwrap();
    assert_eq!(p.len(), 3);
    assert_eq!(p[0].path, "/");
    assert_eq!(p[0].access, ACCESS_READ | ACCESS_EXEC);
    assert_eq!(p[1].access, ACCESS_READ | ACCESS_WRITE);
    assert_eq!(p[2].path, "/usr/share");
    assert!(p.iter().all(|r| r.required), "a policy rule is never optional");
    for bad in [
        "read\n",                    // no path
        "read /tmp extra\n",         // two paths
        "deny /tmp\n",               // there is no deny
        "write /tmp\n",              // not a directive
        "read tmp\n",                // relative
        "read /tmp/../etc\n",        // climbing
        "read /tmp\nread /tmp\n",    // named twice
        "# only a comment\n",        // grants nothing
        "",
    ] {
        assert!(parse_policy(bad, "t").is_err(), "{bad:?} must be refused");
    }
    assert!(parse_policy("# only a comment\n", "t").unwrap_err().contains("grants nothing"));
}

/// Against the kernel, in a forked child: restrict_self is irreversible.
#[test]
fn second_layer_narrows_never_widens() {
    let dir = std::env::temp_dir().join(format!("kryptik-ll-{}", std::process::id()));
    let keep = dir.join("keep");
    let lose = dir.join("lose");
    std::fs::create_dir_all(&keep).unwrap();
    std::fs::create_dir_all(&lose).unwrap();
    std::fs::write(keep.join("f"), b"in").unwrap();
    std::fs::write(lose.join("f"), b"out").unwrap();

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let rc = (|| -> i32 {
            if abi_version().is_none_or(|a| a < MIN_ABI) {
                return 77;
            }
            // Layer 1: read the whole tree, and write in `lose`.
            let mut base = match Ruleset::new() {
                Ok(r) => r,
                Err(_) => return 1,
            };
            if base.allow(dir.to_str().unwrap(), ACCESS_READ).is_err()
                || base.allow(lose.to_str().unwrap(), ACCESS_READ | ACCESS_WRITE).is_err()
                || base.restrict_self().is_err()
            {
                return 2;
            }
            if std::fs::read(keep.join("f")).is_err() || std::fs::read(lose.join("f")).is_err() {
                return 3; // both readable under layer 1 alone
            }
            // Layer 2: read-write on `keep` only; layer 1 never granted write.
            let rules = match parse_policy(&format!("read-write {}\n", keep.display()), "t") {
                Ok(r) => r,
                Err(_) => return 4,
            };
            if confine_further(&rules).is_err() {
                return 5;
            }
            // Narrowed: layer 1 allowed `lose`, layer 2 does not.
            if std::fs::read(lose.join("f")).is_ok() {
                return 6;
            }
            // Kept: both layers allow reading `keep`.
            if std::fs::read(keep.join("f")).is_err() {
                return 7;
            }
            // Not widened: write on `keep` is still denied.
            if std::fs::write(keep.join("g"), b"x").is_ok() {
                return 8;
            }
            0
        })();
        unsafe { libc::_exit(rc) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let code = libc::WEXITSTATUS(status);
    let _ = std::fs::remove_dir_all(&dir);
    match code {
        0 => {}
        77 => eprintln!("landlock unavailable or too old here; skipping"),
        other => panic!("stacked-layer test failed at step {other}"),
    }
}

#[test]
fn packed_attr_is_twelve_bytes() {
    // Same layout as the kernel's packed struct.
    assert_eq!(std::mem::size_of::<PathBeneathAttr>(), 12);
}

#[test]
fn ruleset_attrs_have_expected_sizes() {
    assert_eq!(std::mem::size_of::<RulesetAttrV1>(), 8);
    assert_eq!(std::mem::size_of::<RulesetAttrV4>(), 16);
}

#[test]
fn access_mask_grows_with_abi() {
    let v3 = access_mask_for(MIN_ABI);
    let v5 = access_mask_for(5);
    assert_eq!(v3 & (FS_REFER | FS_TRUNCATE), FS_REFER | FS_TRUNCATE, "REFER and TRUNCATE at the minimum ABI");
    assert_eq!(v3 & FS_IOCTL_DEV, 0, "IOCTL_DEV must not be set on ABI v3");
    assert_ne!(v5 & FS_IOCTL_DEV, 0, "IOCTL_DEV should appear at ABI v5");
}

#[test]
fn read_access_includes_dirs_and_files() {
    assert_ne!(ACCESS_READ & FS_READ_FILE, 0);
    assert_ne!(ACCESS_READ & FS_READ_DIR, 0);
}

#[test]
fn write_access_includes_truncate_and_refer() {
    assert_ne!(ACCESS_WRITE & FS_TRUNCATE, 0);
    assert_ne!(ACCESS_WRITE & FS_REFER, 0);
    assert_ne!(ACCESS_WRITE_FILE & FS_TRUNCATE, 0);
    assert_eq!(ACCESS_WRITE_FILE & FS_MAKE_REG, 0, "write-file must not create");
}

#[test]
fn device_node_creation_is_never_granted() {
    // MAKE_CHAR and MAKE_BLOCK are handled, so denied, and no rule grants them.
    for r in zone_rules("/home/t") {
        assert_eq!(r.access & (FS_MAKE_CHAR | FS_MAKE_BLOCK), 0, "{}", r.path);
    }
    assert_ne!(access_mask_for(MIN_ABI) & (FS_MAKE_CHAR | FS_MAKE_BLOCK), 0);
}

#[test]
fn root_rule_never_grants_write() {
    // Rules are additive: write on "/" would be write on every mount under it.
    let rules = zone_rules("/home/t");
    let root = rules.iter().find(|r| r.path == "/").expect("no rule for /");
    assert_eq!(root.access & ACCESS_WRITE, 0, "/ must not be writable");
    assert_eq!(root.access & FS_WRITE_FILE, 0);
    assert!(root.required);
    let writable: Vec<&str> = rules
        .iter()
        .filter(|r| r.access & (FS_WRITE_FILE | FS_MAKE_REG) != 0)
        .map(|r| r.path.as_str())
        .collect();
    assert_eq!(writable, vec!["/home/t", "/tmp", "/dev", "/dev/shm", "/proc"]);
    // Only the data dir, /tmp and /dev/shm may create files.
    for r in &rules {
        if r.access & FS_MAKE_REG != 0 {
            assert!(
                r.path == "/home/t" || r.path == "/tmp" || r.path == "/dev/shm",
                "{} must not allow creating files",
                r.path
            );
        }
    }
}

#[test]
fn nic_zone_adds_state_dirs_without_exec() {
    let extra = nic_zone_rules();
    let paths: Vec<&str> = extra.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(paths, vec!["/run", "/var/lib"]);
    for r in &extra {
        assert_eq!(r.access & ACCESS_EXEC, 0, "{} must not be executable", r.path);
        assert_ne!(r.access & FS_MAKE_REG, 0, "{} must allow creating files", r.path);
        assert!(r.required, "{} is a mount kryptikd made; its absence is a defect", r.path);
    }
    // No other zone gains them.
    assert!(zone_rules("/home/t").iter().all(|r| r.path != "/run" && r.path != "/var/lib"));
}

#[test]
fn ruleset_can_be_created_when_supported() {
    match abi_version() {
        Some(v) if v >= MIN_ABI => {
            let rs = Ruleset::new().expect("ruleset creation should succeed");
            assert_eq!(rs.abi, v);
        }
        Some(v) => {
            assert!(matches!(Ruleset::new(), Err(LandlockError::TooOld { .. })), "ABI {v}");
        }
        None => eprintln!("landlock unavailable on this kernel; skipping"),
    }
}

#[test]
fn allow_rejects_nonexistent_path() {
    if abi_version().is_none_or(|v| v < MIN_ABI) {
        return;
    }
    let mut rs = Ruleset::new().unwrap();
    assert!(rs.allow("/definitely/not/a/real/path", ACCESS_READ).is_err());
}

#[test]
fn symlinked_path_refused() {
    if abi_version().is_none_or(|a| a < MIN_ABI) {
        return;
    }
    // Canonical, so a linked TMPDIR does not refuse the exact path too.
    let dir = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("kryptik-ll-link-{}", std::process::id()));
    let real = dir.join("real");
    std::fs::create_dir_all(&real).unwrap();
    std::os::unix::fs::symlink(&dir, dir.join("link")).unwrap();
    let mut rs = Ruleset::new().unwrap();
    let name = |p: std::path::PathBuf| p.to_str().unwrap().to_string();
    let last = rs.allow(&name(dir.join("link")), ACCESS_READ);
    let through = rs.allow(&name(dir.join("link/real")), ACCESS_READ);
    let exact = rs.allow(&name(real), ACCESS_READ);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(matches!(last, Err(LandlockError::Symlink(_))), "{last:?}");
    assert!(matches!(through, Err(LandlockError::Symlink(_))), "{through:?}");
    assert!(exact.is_ok(), "{exact:?}");
}

#[test]
fn describe_access_is_readable() {
    assert_eq!(describe_access(ACCESS_READ | ACCESS_EXEC), "read+exec");
    assert_eq!(describe_access(ACCESS_READ | ACCESS_WRITE_FILE), "read+write-existing-files");
    assert_eq!(describe_access(ACCESS_READ | ACCESS_WRITE | ACCESS_EXEC), "read+write+exec");
}
