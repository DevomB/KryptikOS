use super::*;
use std::os::unix::fs::PermissionsExt;

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
fn a_display_on_virtio_gpu_keeps_the_machine_awake() {
    let sys = std::env::temp_dir().join(format!("kryptikd-sys-virtio-{}", std::process::id()));
    let _ = fs::remove_dir_all(&sys);
    assert_eq!(sleep_refused_in(&sys), None, "no virtio bus at all");
    let drv = sys.join("bus/virtio/drivers/virtio_gpu");
    fs::create_dir_all(&drv).unwrap();
    for f in ["bind", "unbind", "uevent", "module"] {
        fs::write(drv.join(f), "").unwrap();
    }
    assert_eq!(sleep_refused_in(&sys), None, "the module loaded, no device bound");
    std::os::unix::fs::symlink("../../../../devices/pci0000:00/0000:00:01.0/virtio0", drv.join("virtio0")).unwrap();
    assert!(sleep_refused_in(&sys).is_some_and(|why| why.contains("virtio-gpu")), "a device bound");
    let _ = fs::remove_dir_all(&sys);
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

#[test]
fn a_seal_that_left_a_zone_waiting_counts_itself() {
    let dir = std::env::temp_dir().join(format!("kryptikd-left-waiting-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let f = dir.join("left-waiting");
    count_left_waiting(&f);
    assert_eq!(fs::read_to_string(&f).unwrap(), "1\n");
    count_left_waiting(&f);
    assert_eq!(fs::read_to_string(&f).unwrap(), "2\n", "each such seal counts once more");
    fs::write(&f, "garbage").unwrap();
    count_left_waiting(&f);
    assert_eq!(fs::read_to_string(&f).unwrap(), "1\n", "a count it cannot read starts again");
    assert!(!dir.join(format!(".left-waiting.{}", std::process::id())).exists(), "the count is renamed into place");
    assert_eq!(fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o644, "the session's group reads it");
    // No directory to write in: nothing, and no panic.
    count_left_waiting(&dir.join("absent").join("left-waiting"));
    let _ = fs::remove_dir_all(&dir);
}

/// A power supply of the kernel's shape under `sys`: a directory with its type and attributes.
fn supply(sys: &Path, name: &str, kind: &str, attrs: &[(&str, &str)]) {
    let d = sys.join("class/power_supply").join(name);
    fs::create_dir_all(&d).unwrap();
    fs::write(d.join("type"), format!("{kind}\n")).unwrap();
    for (k, v) in attrs {
        fs::write(d.join(k), format!("{v}\n")).unwrap();
    }
}

fn fresh_sys(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kryptikd-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

// The cases of tools/tests/power.sh that decide power.sh's critical=: the two must agree.
#[test]
fn the_battery_is_critical_as_power_sh_has_it() {
    let s = fresh_sys("power-none");
    assert!(!critical_in(&s), "no supply at all, as in a VM");
    assert!(!critical_in(&s.join("absent")), "no power_supply class");

    let s = fresh_sys("power-low");
    supply(&s, "AC", "Mains", &[("online", "0")]);
    supply(&s, "BAT0", "Battery", &[("capacity", "3"), ("status", "Discharging")]);
    assert!(critical_in(&s), "3% on battery");
    supply(&s, "BAT1", "Battery", &[("capacity", "60"), ("status", "Discharging")]);
    assert!(!critical_in(&s), "but not while a second battery is full enough");

    let s = fresh_sys("power-four");
    supply(&s, "BAT0", "Battery", &[("capacity", "4"), ("status", "Discharging")]);
    assert!(!critical_in(&s), "4% is not yet");

    let s = fresh_sys("power-weak");
    supply(&s, "AC", "Mains", &[("online", "1")]);
    supply(&s, "BAT0", "Battery", &[("capacity", "2"), ("status", "Discharging")]);
    assert!(critical_in(&s), "plugged in to a charger that gives less than the machine uses, it runs down");
    supply(&s, "BAT0", "Battery", &[("status", "Charging")]);
    assert!(!critical_in(&s), "2% charging on mains");

    let s = fresh_sys("power-word");
    supply(&s, "BAT0", "Battery", &[("capacity", "2"), ("status", "Unknown")]);
    assert!(critical_in(&s), "no word from the battery and no adapter: it runs down");
    supply(&s, "ucsi", "USB", &[("online", "1")]);
    assert!(!critical_in(&s), "no word from the battery, a USB charger online");
    supply(&s, "BAT0", "Battery", &[("status", "Not charging")]);
    supply(&s, "ucsi", "USB", &[("online", "0")]);
    assert!(!critical_in(&s), "one that holds its charge");

    let s = fresh_sys("power-other");
    supply(&s, "hidpp_battery_0", "Battery", &[("capacity", "1"), ("scope", "Device"), ("status", "Discharging")]);
    assert!(!critical_in(&s), "a mouse's empty battery is not the machine's");
    supply(&s, "BAT0", "Battery", &[("capacity", "2"), ("present", "0"), ("status", "Discharging")]);
    supply(&s, "BAT1", "Battery", &[("capacity", "fail"), ("status", "Discharging")]);
    assert!(!critical_in(&s), "an absent battery and a bad reading count for nothing");

    let s = fresh_sys("power-energy");
    supply(&s, "BAT0", "Battery", &[("capacity", "fail"), ("energy_now", "5130000"), ("energy_full", "57000000"), ("status", "Discharging")]);
    assert!(!critical_in(&s), "with no capacity that reads, the energy against full: 9%");
    let s = fresh_sys("power-charge");
    supply(&s, "BAT0", "Battery", &[("charge_now", "120000"), ("charge_full", "4000000"), ("status", "Discharging")]);
    assert!(critical_in(&s), "or the charge against full: 3%");
    supply(&s, "BAT0", "Battery", &[("charge_full", "0")]);
    assert!(!critical_in(&s), "a battery full at nothing gives no charge");

    for tag in ["none", "low", "four", "weak", "word", "other", "energy", "charge"] {
        let _ = fs::remove_dir_all(std::env::temp_dir().join(format!("kryptikd-power-{tag}-{}", std::process::id())));
    }
}

#[test]
fn critical_twice_running_powers_off() {
    assert_eq!(sealed_look(0, true), (1, false), "one odd reading does not end the session");
    assert_eq!(sealed_look(1, true), (2, true), "the second, 30 s on, does");
    assert_eq!(sealed_look(1, false), (0, false), "a reading above starts the count again");
    assert_eq!(sealed_look(0, false), (0, false));
}
