use super::*;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

/// A /sys of the kernel's shape: devices under devices/, linked from class/block, each disk's
/// partitions in the disk's own directory, device-mapper devices under block/.
fn sys(tag: &str) -> PathBuf {
    let s = std::env::temp_dir().join(format!("kryptikd-stick-sys-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&s);
    fs::create_dir_all(s.join("class/block")).unwrap();
    fs::create_dir_all(s.join("block")).unwrap();
    s
}

/// A disk at devices/UNDER/block/NAME, with a size and what its device calls itself.
fn disk(s: &Path, under: &str, name: &str, sectors: u64, device: &[(&str, &str)]) -> PathBuf {
    let d = s.join("devices").join(under).join("block").join(name);
    fs::create_dir_all(d.join("device")).unwrap();
    fs::create_dir_all(d.join("holders")).unwrap();
    fs::write(d.join("size"), format!("{sectors}\n")).unwrap();
    for (k, v) in device {
        fs::write(d.join("device").join(k), format!("{v}\n")).unwrap();
    }
    symlink(&d, s.join("class/block").join(name)).unwrap();
    d
}

/// Partition N of a disk, with its GPT name if it has one.
fn part(s: &Path, disk: &Path, name: &str, n: u32, sectors: u64, label: Option<&str>) {
    let p = disk.join(name);
    fs::create_dir_all(p.join("holders")).unwrap();
    fs::write(p.join("partition"), format!("{n}\n")).unwrap();
    fs::write(p.join("size"), format!("{sectors}\n")).unwrap();
    let uevent = format!("DEVTYPE=partition\nPARTN={n}\n{}", label.map(|l| format!("PARTNAME={l}\n")).unwrap_or_default());
    fs::write(p.join("uevent"), uevent).unwrap();
    symlink(&p, s.join("class/block").join(name)).unwrap();
}

/// A device-mapper device NAME on SLAVES.
fn dm(s: &Path, dev: &str, name: &str, slaves: &[&str]) {
    let d = s.join("block").join(dev);
    fs::create_dir_all(d.join("dm")).unwrap();
    fs::create_dir_all(d.join("slaves")).unwrap();
    fs::write(d.join("dm/name"), format!("{name}\n")).unwrap();
    for sl in slaves {
        fs::create_dir_all(d.join("slaves").join(sl)).unwrap();
    }
}

const USB: &str = "pci0000:00/0000:00:14.0/usb3/3-1/3-1:1.0/host2/target2:0:0/2:0:0:0";

#[test]
fn a_partition_of_a_usb_stick_may_be_given() {
    let s = sys("usb");
    let d = disk(&s, USB, "sdb", 62_533_296, &[("vendor", "SanDisk "), ("model", "Cruzer Blade    ")]);
    part(&s, &d, "sdb1", 1, 62_531_248, Some("DATA"));
    let p = partition_in(&s, "", "sdb1").unwrap();
    assert_eq!(p.name, "sdb1");
    assert_eq!(p.sectors, 62_531_248);
    assert_eq!(p.what, "SanDisk Cruzer Blade, 32.0 GB, partition 1 (DATA)");
    let whole = partition_in(&s, "", "sdb").unwrap_err();
    assert!(whole.contains("has partitions"), "{whole}");
    let _ = fs::remove_dir_all(&s);
}

#[test]
fn a_stick_with_no_partition_table_is_given_whole() {
    let s = sys("floppy");
    disk(&s, USB, "sdc", 2_097_152, &[]);
    let p = partition_in(&s, "", "sdc").unwrap();
    assert_eq!(p.what, "a USB stick, 1.1 GB");
    let _ = fs::remove_dir_all(&s);
}

#[test]
fn an_sd_card_may_be_given_and_an_internal_disk_never() {
    let s = sys("sd");
    let card = disk(&s, "platform/rtsx_pci_sdmmc.0/mmc_host/mmc0/mmc0:aaaa", "mmcblk0", 61_067_264, &[("type", "SD"), ("name", "SD32G")]);
    part(&s, &card, "mmcblk0p1", 1, 61_065_216, None);
    assert_eq!(partition_in(&s, "", "mmcblk0p1").unwrap().what, "SD32G, 31.3 GB, partition 1");
    let nvme = disk(&s, "pci0000:00/0000:00:1d.0/0000:3d:00.0/nvme/nvme0", "nvme0n1", 1_000_215_216, &[("model", "Some SSD")]);
    part(&s, &nvme, "nvme0n1p1", 1, 2_097_152, None);
    let internal = partition_in(&s, "", "nvme0n1p1").unwrap_err();
    assert!(internal.contains("neither a USB disk nor an SD card"), "{internal}");
    let _ = fs::remove_dir_all(&s);
}

#[test]
fn a_partition_held_mounted_or_on_the_system_disk_is_refused() {
    let s = sys("held");
    let d = disk(&s, USB, "sdb", 4_194_304, &[]);
    part(&s, &d, "sdb1", 1, 1_048_576, None);
    part(&s, &d, "sdb2", 2, 1_048_576, None);
    fs::create_dir_all(d.join("sdb1/holders/dm-3")).unwrap();
    let held = partition_in(&s, "", "sdb1").unwrap_err();
    assert!(held.contains("held already"), "{held}");
    let mounted = partition_in(&s, "/dev/sdb2 /mnt vfat rw 0 0\n", "sdb2").unwrap_err();
    assert!(mounted.contains("mounted"), "{mounted}");
    // A stick's mapping is no system device; the verified root on sdb2 is.
    dm(&s, "dm-3", "kryptik-stick-work", &["sdb1"]);
    assert!(partition_in(&s, "", "sdb2").is_ok(), "a stick's own mapping made its disk the system's");
    dm(&s, "dm-0", "kroot", &["sdb2"]);
    fs::create_dir_all(d.join("sdb2/holders/dm-0")).unwrap();
    let e = disk(&s, USB, "sde", 4_194_304, &[]);
    part(&s, &e, "sde1", 1, 1_048_576, None);
    assert!(partition_in(&s, "", "sde1").is_ok());
    dm(&s, "dm-1", "kryptik-state", &["sde1"]);
    let system = partition_in(&s, "", "sde1").unwrap_err();
    assert!(system.contains("system's own disk"), "{system}");
    let _ = fs::remove_dir_all(&s);
}

#[test]
fn a_name_that_is_no_device_is_refused() {
    let s = sys("names");
    for bad in ["", "../sda", "sdb1/..", "SDB1", "sd b1"] {
        assert!(partition_in(&s, "", bad).is_err(), "{bad:?} was taken");
    }
    assert!(partition_in(&s, "", "sdz9").unwrap_err().contains("no block device"));
    let _ = fs::remove_dir_all(&s);
}

#[test]
fn a_grant_record_reads_back_as_written_and_nothing_else_does() {
    let g = Grant { writable: true, partition: "sdb1".into(), what: "SanDisk Cruzer, 32.0 GB, partition 1".into() };
    assert_eq!(Grant::parse(&g.render()), Some(g));
    for bad in ["", "mode rw\npartition sdb1\n", "mode xx\npartition sdb1\nwhat a\n", "mode ro\npartition ../sda\nwhat a\n",
                "mode ro\npartition sdb1\nwhat a\nextra 1\n"] {
        assert_eq!(Grant::parse(bad), None, "{bad:?} was read as a grant");
    }
}

#[test]
fn a_mapping_is_found_by_its_name() {
    let s = sys("dm");
    dm(&s, "dm-4", "kryptik-stick-work", &[]);
    assert_eq!(dm_device(&s.join("block"), "kryptik-stick-work"), Some("dm-4".to_string()));
    assert_eq!(dm_device(&s.join("block"), "kryptik-stick-personal"), None);
    let _ = fs::remove_dir_all(&s);
}

#[test]
fn an_opened_device_must_still_be_the_zones_mapping() {
    let s = sys("dm-opened");
    let d = s.join("dev/block/253:4/dm");
    fs::create_dir_all(&d).unwrap();
    fs::write(d.join("name"), "kryptik-stick-work\n").unwrap();
    assert!(mapping_at(&s, libc::makedev(253, 4), "kryptik-stick-work"));
    assert!(!mapping_at(&s, libc::makedev(253, 4), "kryptik-stick-personal"), "another zone's mapping");
    assert!(!mapping_at(&s, libc::makedev(253, 5), "kryptik-stick-work"), "another device, the number reused");
    let _ = fs::remove_dir_all(&s);
}
