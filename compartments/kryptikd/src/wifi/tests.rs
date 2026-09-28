use super::*;
use std::os::unix::fs::MetadataExt;

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kryptik-wifi-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    d
}

#[test]
fn add_list_forget_round_trip() {
    let dir = tmpdir("roundtrip");
    assert_eq!(list(&dir).unwrap(), Vec::<String>::new(), "no file is no networks");
    assert_eq!(add(&dir, None, "Home", "correct horse battery").unwrap(), Added::New);
    assert_eq!(add(&dir, None, "Cafe Wifi", "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef").unwrap(), Added::New);
    assert_eq!(list(&dir).unwrap(), vec!["Home", "Cafe Wifi"]);
    let text = fs::read_to_string(conf_path(&dir)).unwrap();
    assert_eq!(
        text,
        "ctrl_interface=/run/wpa_supplicant\nupdate_config=0\n\
             \nnetwork={\n\tssid=\"Home\"\n\tpsk=\"correct horse battery\"\n}\n\
             \nnetwork={\n\tssid=\"Cafe Wifi\"\n\tpsk=0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef\n}\n"
    );
    let md = fs::metadata(conf_path(&dir)).unwrap();
    assert_eq!(md.mode() & 0o7777, 0o400);
    assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o7777, 0o711);
    forget(&dir, None, "Home").unwrap();
    assert_eq!(list(&dir).unwrap(), vec!["Cafe Wifi"]);
    let text = fs::read_to_string(conf_path(&dir)).unwrap();
    assert!(text.starts_with(HEADER), "the header stays: {text:?}");
    assert!(!text.contains("Home"));
    assert!(text.contains("\tssid=\"Cafe Wifi\"\n"));
    forget(&dir, None, "Cafe Wifi").unwrap();
    assert_eq!(fs::read_to_string(conf_path(&dir)).unwrap(), HEADER, "an emptied file keeps its header");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn passphrase_quoted_raw_psk_bare() {
    assert_eq!(check_passphrase("eight ch").unwrap(), Psk::Passphrase("eight ch".into()));
    let hex = "f".repeat(64);
    assert_eq!(check_passphrase(&hex).unwrap(), Psk::Hex(hex.clone()));
    let nets = vec![
        Network { ssid: "a".into(), psk: Psk::Passphrase("pass word".into()) },
        Network { ssid: "b".into(), psk: Psk::Hex(hex.clone()) },
    ];
    let text = render(&nets);
    assert!(text.contains("\tpsk=\"pass word\"\n"));
    assert!(text.contains(&format!("\tpsk={hex}\n")));
    assert_eq!(parse(&text).unwrap(), nets, "what was written reads back");
}

#[test]
fn ssid_and_passphrase_rules() {
    let long_ssid = "x".repeat(33);
    for (ssid, rule) in [
        ("", "1 to 32 bytes"),
        (long_ssid.as_str(), "1 to 32 bytes"),
        ("say \"hi\"", "'\"'"),
        ("back\\slash", "'\\'"),
        ("two\nlines", "printable"),
        ("tab\there", "printable"),
        ("caf\u{e9}", "printable"),
    ] {
        let e = check_ssid(ssid).unwrap_err();
        assert!(e.contains(rule), "{ssid:?}: {e}");
    }
    assert!(check_ssid("Home").is_ok());
    assert!(check_ssid(&"x".repeat(32)).is_ok());
    assert!(check_ssid(" spaces are fine ").is_ok());

    let (p64, p65, not_hex) = ("p".repeat(64), "p".repeat(65), format!("{}g", "f".repeat(63)));
    for (pass, rule) in [
        ("seven c", "8 to 63"),
        (p64.as_str(), "8 to 63"),
        (p65.as_str(), "8 to 63"),
        ("quote\"inside", "printable ASCII"),
        ("back\\slash", "printable ASCII"),
        ("new\nline", "printable ASCII"),
        (not_hex.as_str(), "8 to 63"),
    ] {
        let e = check_passphrase(pass).unwrap_err();
        assert!(e.contains(rule), "{pass:?}: {e}");
        assert!(!e.contains(pass), "the message must not repeat the passphrase: {e}");
    }
    assert!(check_passphrase("eight ch").is_ok());
    assert!(check_passphrase(&"p".repeat(63)).is_ok());
    assert!(check_passphrase(&"0a".repeat(32)).is_ok());

    // A refusal writes nothing and leaves an existing file as it was.
    let dir = tmpdir("refusals");
    assert!(add(&dir, None, "bad\"ssid", "long enough").is_err());
    assert!(!conf_path(&dir).exists(), "nothing written on refusal");
    add(&dir, None, "Home", "long enough").unwrap();
    let before = fs::read(conf_path(&dir)).unwrap();
    let ino = fs::metadata(conf_path(&dir)).unwrap().ino();
    assert!(add(&dir, None, "Home", "short").is_err());
    assert!(forget(&dir, None, "Nowhere").unwrap_err().contains("no network named"));
    assert_eq!(fs::read(conf_path(&dir)).unwrap(), before);
    assert_eq!(fs::metadata(conf_path(&dir)).unwrap().ino(), ino, "a refusal does not rewrite the file");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn readd_replaces_block_in_place() {
    let dir = tmpdir("replace");
    add(&dir, None, "First", "first pass").unwrap();
    add(&dir, None, "Second", "second pass").unwrap();
    assert_eq!(add(&dir, None, "First", "changed pass").unwrap(), Added::Replaced);
    let nets = load(&dir).unwrap();
    assert_eq!(nets.len(), 2, "replaced, not appended");
    assert_eq!(nets[0], Network { ssid: "First".into(), psk: Psk::Passphrase("changed pass".into()) });
    assert_eq!(nets[1].ssid, "Second", "order kept");
    assert_eq!(fs::read_to_string(conf_path(&dir)).unwrap().matches("network={").count(), 2);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn write_is_atomic_rename() {
    let dir = tmpdir("atomic");
    add(&dir, None, "Home", "long enough").unwrap();
    let ino = fs::metadata(conf_path(&dir)).unwrap().ino();
    // The temporary of a writer that died before its rename goes.
    fs::write(dir.join(format!(".{FILE_NAME}.4294967295")), "psk=\"secret\"").unwrap();
    add(&dir, None, "Other", "long enough").unwrap();
    assert_ne!(fs::metadata(conf_path(&dir)).unwrap().ino(), ino, "a new inode replaced the old file");
    let names: Vec<String> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(names, vec![FILE_NAME], "only the file itself is in the directory");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn foreign_file_refused() {
    for bad in [
        "network={\n\tssid=\"a\"\n\tpsk=\"long enough\"\n}\nap_scan=1\n",
        "network={\n\tssid=\"a\"\n\tkey_mgmt=NONE\n\tpsk=\"long enough\"\n}\n",
        "network={\n\tssid=\"a\"\n}\n",
        "network={\n\tssid=\"a\"\n\tpsk=\"long enough\"\n",
        "network={\n\tssid=\"a\"\n\tpsk=long enough\n}\n",
        "network={\n\tssid=\"a\"\n\tpsk=\"short\"\n}\n",
        "  ssid=\"a\"\n",
    ] {
        let e = parse(bad).unwrap_err();
        assert!(e.contains("line ") || e.contains("not closed"), "{bad:?}: {e}");
        assert!(!e.contains("long enough"), "{e}");
    }
    assert!(parse("\n\nctrl_interface=/run/wpa_supplicant\n\nupdate_config=0\n\n").unwrap().is_empty(), "blank lines are tolerated");
    let dir = tmpdir("foreign");
    fs::create_dir_all(&dir).unwrap();
    fs::write(conf_path(&dir), "ap_scan=1\n").unwrap();
    let e = add(&dir, None, "Home", "long enough").unwrap_err();
    assert!(e.contains("something else edited"), "{e}");
    assert_eq!(fs::read_to_string(conf_path(&dir)).unwrap(), "ap_scan=1\n");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn no_restart_for_other_directory() {
    let m = restart_net_zone(Path::new("/nonexistent/wifi"));
    assert!(m.contains("not restarted") && m.contains(DEFAULT_DIR), "{m}");
}
