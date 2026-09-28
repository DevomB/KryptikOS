use super::*;

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

#[test]
fn seccomp_ioctls() {
    assert_eq!(NOTIF_RECV, 0xC050_2100);
    assert_eq!(NOTIF_SEND, 0xC018_2101);
}

#[test]
fn flags_stop_at_separator() {
    let a = args(&["run", "work", "--rootfs", "/r", "--", "tool", "--zones", "/x", "--rootfs", "/y", "--wifi-dir", "/w"]);
    assert_eq!(zone_dir_from(&a), PathBuf::from(DEFAULT_ZONE_DIR));
    assert_eq!(wifi_dir_from(&a), PathBuf::from(wifi::DEFAULT_DIR));
    assert_eq!(rootfs_base_from(&a), "/r");
    assert_eq!(value(&a, "--zones"), None);
}

#[test]
fn parsed_flag_needs_value() {
    assert_eq!(parsed::<u32>(&args(&["run", "w"]), "--zone-uid", "an id"), Ok(None));
    assert_eq!(parsed::<u32>(&args(&["--zone-uid", "7"]), "--zone-uid", "an id"), Ok(Some(7)));
    assert!(parsed::<u32>(&args(&["--zone-uid"]), "--zone-uid", "an id").is_err());
    assert!(parsed::<u32>(&args(&["--zone-uid", "x"]), "--zone-uid", "an id").is_err());
    assert!(parsed::<u32>(&args(&["--zone-uid", "--", "7"]), "--zone-uid", "an id").is_err());
}
