use super::*;

/// A /sys/block of the kernel's shape: device-mapper devices with a name and a suspended flag.
fn sys_block(dir: &Path, devices: &[(&str, &str, &str)]) {
    for (dev, name, suspended) in devices {
        let dm = dir.join(dev).join("dm");
        fs::create_dir_all(&dm).unwrap();
        fs::write(dm.join("name"), format!("{name}\n")).unwrap();
        fs::write(dm.join("suspended"), format!("{suspended}\n")).unwrap();
    }
}

#[test]
fn a_mapping_is_known_by_its_name() {
    let dir = std::env::temp_dir().join(format!("kryptikd-sys-block-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    sys_block(&dir, &[("dm-0", "kryptik-state", "1"), ("dm-1", "kryptik-zone-work", "0")]);
    // A disk, which has no dm directory.
    fs::create_dir_all(dir.join("vda")).unwrap();
    assert_eq!(suspended_in(&dir, "kryptik-state"), Some(true));
    assert_eq!(suspended_in(&dir, "kryptik-zone-work"), Some(false));
    assert_eq!(suspended_in(&dir, "kryptik-zone-dev"), None);
    assert_eq!(suspended_in(&dir, "kryptik"), None, "a name is matched whole");
    assert_eq!(suspended_in(&dir.join("absent"), "kryptik-state"), None);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_zone_waits_while_its_volume_is_suspended() {
    let dir = std::env::temp_dir().join(format!("kryptikd-waiting-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    sys_block(&dir, &[("dm-0", "kryptik-state", "0"), ("dm-1", "kryptik-zone-work", "1"), ("dm-2", "kryptik-zone-dev", "0")]);
    let mapped: Vec<String> = ["dev", "personal", "work"].map(String::from).to_vec();
    assert_eq!(waiting_in(&dir, &mapped), vec!["work".to_string()], "work alone: dev's volume has its key, and personal has no device");
    assert!(waiting_in(&dir, &[]).is_empty());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn an_update_holding_its_lock_keeps_the_machine_awake() {
    let p = std::env::temp_dir().join(format!("kryptikd-update-lock-{}", std::process::id()));
    let _ = fs::remove_file(&p);
    assert!(!locked_out(&p), "no lock file, no update");
    let f = fs::File::create(&p).unwrap();
    assert!(!locked_out(&p));
    // SAFETY: f is open.
    assert_eq!(unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
    assert!(locked_out(&p), "kryptik-update apply holds it");
    drop(f);
    assert!(!locked_out(&p), "released with its descriptor");
    let _ = fs::remove_file(&p);
}
