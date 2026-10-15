use super::*;
use std::os::unix::fs::symlink;

/// A /sys of the kernel's shape: video4linux nodes under their devices, linked from the class,
/// each device's bus a link to /sys/bus/NAME.
fn sys(tag: &str) -> PathBuf {
    let s = std::env::temp_dir().join(format!("kryptikd-camera-sys-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&s);
    fs::create_dir_all(s.join("class/video4linux")).unwrap();
    s
}

/// Node NAME of the device at devices/UNDER on BUS, with its index, numbers and name.
fn node(s: &Path, under: &str, bus: &str, name: &str, index: u32, dev: &str, label: &str) {
    let d = s.join("devices").join(under);
    let n = d.join("video4linux").join(name);
    fs::create_dir_all(&n).unwrap();
    fs::create_dir_all(s.join("bus").join(bus)).unwrap();
    let _ = symlink(s.join("bus").join(bus), d.join("subsystem"));
    fs::write(n.join("index"), format!("{index}\n")).unwrap();
    fs::write(n.join("dev"), format!("{dev}\n")).unwrap();
    fs::write(n.join("name"), format!("{label}\n")).unwrap();
    symlink(&d, n.join("device")).unwrap();
    symlink(&n, s.join("class/video4linux").join(name)).unwrap();
}

const UVC: &str = "pci0000:00/0000:00:14.0/usb3/3-6/3-6:1.0";

#[test]
fn the_camera_is_the_first_capture_node() {
    let s = sys("uvc");
    assert_eq!(camera_in(&s), None, "no node, no camera");
    // A UVC camera: its capture node, then its metadata node.
    node(&s, UVC, "usb", "video1", 1, "81:1", "Integrated Camera: Integrated C");
    assert_eq!(camera_in(&s), None, "a metadata node is no camera");
    node(&s, UVC, "usb", "video0", 0, "81:0", "Integrated Camera: Integrated C");
    assert_eq!(camera_in(&s), Some(("video0".into(), 81, 0, "Integrated Camera: Integrated C".into())));
    // Numbered as numbers: video10 comes after video2.
    node(&s, "platform/vivid.0", "platform", "video10", 0, "81:10", "vivid");
    node(&s, "platform/vivid.1", "platform", "video2", 0, "81:2", "\u{1b}[2Jvivid");
    let _ = fs::remove_file(s.join("class/video4linux/video0"));
    assert_eq!(camera_in(&s), Some(("video2".into(), 81, 2, "[2Jvivid".into())), "a name shows no terminal escape");
    let _ = fs::remove_dir_all(&s);
}

#[test]
fn the_device_to_let_go_of_is_the_nodes_own() {
    let s = sys("dev");
    node(&s, UVC, "usb", "video0", 0, "81:0", "Integrated Camera");
    node(&s, "platform/vivid.0", "platform", "video3", 0, "81:3", "vivid");
    let (dev, bus, name) = device_of(&s, "video0").unwrap();
    assert_eq!((bus.as_str(), name.as_str()), ("usb", "3-6:1.0"));
    assert!(dev.ends_with("3-6:1.0"));
    let (_, bus, name) = device_of(&s, "video3").unwrap();
    assert_eq!((bus.as_str(), name.as_str()), ("platform", "vivid.0"));
    assert_eq!(device_of(&s, "video7"), None, "a node pulled out has no device");
    let _ = fs::remove_dir_all(&s);
}

#[test]
fn a_grant_record_reads_back_as_written_and_nothing_else_does() {
    let g = Grant { zone: "personal".into(), node: "video0".into(), name: "Integrated Camera".into() };
    assert_eq!(Grant::parse(&g.render()), Some(g));
    for bad in ["", "zone personal\nnode video0\n", "zone ../x\nnode video0\nname a\n", "zone work\nnode sda\nname a\n",
                "zone work\nnode video0\nname a\nextra 1\n", "zone Work\nnode video0\nname a\n"] {
        assert_eq!(Grant::parse(bad), None, "{bad:?} was read as a grant");
    }
}

#[test]
fn names_from_sysfs_are_one_component() {
    for good in ["usb", "platform", "3-6:1.0", "vivid.0"] {
        assert!(is_sys_name(good), "{good}");
    }
    for bad in ["", ".", "..", "a/b", "a b", "x\n"] {
        assert!(!is_sys_name(bad), "{bad:?}");
    }
}
