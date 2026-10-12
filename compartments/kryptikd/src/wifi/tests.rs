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
    assert_eq!(add(&dir, None, "Home", Some("correct horse battery"), false).unwrap(), Added::New);
    assert_eq!(add(&dir, None, "Cafe Wifi", Some("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef"), false).unwrap(), Added::New);
    assert_eq!(list(&dir).unwrap(), vec!["Home", "Cafe Wifi"]);
    let text = fs::read_to_string(conf_path(&dir)).unwrap();
    // Each block also ends in its own address, which `each_network_has_an_address_of_its_own` reads.
    let without_addresses: String = text.lines().filter(|l| !l.starts_with("\tmac_")).map(|l| format!("{l}\n")).collect();
    assert_eq!(
        without_addresses,
        "ctrl_interface=/run/wpa_supplicant\nupdate_config=0\nscan_res_valid_for_connect=0\n\
             \nnetwork={\n\tssid=\"Home\"\n\tkey_mgmt=WPA-PSK WPA-PSK-SHA256 SAE\n\tieee80211w=1\n\tpsk=\"correct horse battery\"\n}\n\
             \nnetwork={\n\tssid=\"Cafe Wifi\"\n\tkey_mgmt=WPA-PSK WPA-PSK-SHA256\n\tieee80211w=1\n\tpsk=0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef\n}\n"
    );
    let md = fs::metadata(conf_path(&dir)).unwrap();
    assert_eq!(md.mode() & 0o7777, 0o440);
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
fn each_network_has_an_address_of_its_own() {
    let dir = tmpdir("addresses");
    let address = |ssid: &str| load(&dir).unwrap().into_iter().find(|n| n.ssid == ssid).and_then(|n| n.mac).unwrap();
    add(&dir, None, "Home", Some("correct horse battery"), false).unwrap();
    add(&dir, None, "Cafe", None, false).unwrap();
    let (home, cafe) = (address("Home"), address("Cafe"));
    assert!(check_mac(&home).is_ok() && check_mac(&cafe).is_ok(), "{home} {cafe}");
    assert_ne!(home, cafe, "two networks never see one address");
    // Kept through a new passphrase and another network's removal.
    add(&dir, None, "Home", Some("a different one"), false).unwrap();
    forget(&dir, None, "Cafe").unwrap();
    assert_eq!(address("Home"), home);
    let text = fs::read_to_string(conf_path(&dir)).unwrap();
    assert!(text.contains(&format!("\tpsk=\"a different one\"\n\tmac_addr=3\n\tmac_value={home}\n}}\n")), "{text}");
    // A file an older kryptikd wrote gets one per network once, then is current. Put in place
    // of the 0440 file, which takes no write.
    fs::remove_file(conf_path(&dir)).unwrap();
    fs::write(conf_path(&dir), "ctrl_interface=/run/wpa_supplicant\nupdate_config=0\n\nnetwork={\n\tssid=\"Old\"\n\tpsk=\"older pass\"\n}\n").unwrap();
    assert!(refresh(&dir, None).unwrap());
    let old = address("Old");
    assert!(check_mac(&old).is_ok(), "{old}");
    assert!(!refresh(&dir, None).unwrap(), "an address once given stays");
    assert_eq!(address("Old"), old);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn an_address_is_local_unicast_and_paired_with_its_policy() {
    for good in ["02:00:00:00:00:00", "fe:12:34:56:78:9a", "06:ab:cd:ef:01:23"] {
        assert!(check_mac(good).is_ok(), "{good}");
    }
    // Globally administered, a group address, upper case, five octets, not hex.
    for bad in ["00:11:22:33:44:55", "03:11:22:33:44:55", "02:AB:CD:EF:01:23", "02:11:22:33:44", "02:11:22:33:44:zz"] {
        assert!(check_mac(bad).is_err(), "{bad}");
    }
    for _ in 0..64 {
        let m = new_mac().unwrap();
        assert!(check_mac(&m).is_ok(), "{m}");
    }
    let head = "network={\n\tssid=\"a\"\n\tkey_mgmt=NONE\n";
    for (body, why) in [
        ("\tmac_addr=3\n}\n", "only one of mac_addr and mac_value"),
        ("\tmac_value=02:00:00:00:00:01\n}\n", "only one of mac_addr and mac_value"),
        ("\tmac_addr=3\n\tmac_value=00:11:22:33:44:55\n}\n", "locally administered"),
        ("\tmac_addr=3\n\tmac_addr=3\n\tmac_value=02:00:00:00:00:01\n}\n", "a second mac_addr"),
    ] {
        let e = parse(&format!("{head}{body}")).unwrap_err();
        assert!(e.contains(why), "{body:?}: {e}");
    }
}

#[test]
fn open_network_saved_without_key_or_protection() {
    let dir = tmpdir("open");
    assert_eq!(add(&dir, None, "Cafe", None, false).unwrap(), Added::New);
    add(&dir, None, "Home", Some("correct horse battery"), false).unwrap();
    let text = fs::read_to_string(conf_path(&dir)).unwrap();
    assert!(text.contains("\nnetwork={\n\tssid=\"Cafe\"\n\tkey_mgmt=NONE\n\tmac_addr=3\n\tmac_value="), "{text}");
    assert_eq!(list(&dir).unwrap(), vec!["Cafe", "Home"]);
    // A passphrase given later replaces the open block, and saving it open again drops it.
    assert_eq!(add(&dir, None, "Cafe", Some("now it has one"), false).unwrap(), Added::Replaced);
    assert!(fs::read_to_string(conf_path(&dir)).unwrap().contains("\tssid=\"Cafe\"\n\tkey_mgmt=WPA-PSK WPA-PSK-SHA256 SAE\n"));
    assert_eq!(add(&dir, None, "Home", None, false).unwrap(), Added::Replaced);
    let home = &load(&dir).unwrap()[1];
    assert_eq!((home.ssid.as_str(), &home.psk), ("Home", &Psk::Open));
    assert!(!fs::read_to_string(conf_path(&dir)).unwrap().contains("correct horse battery"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn hidden_network_asked_for_by_name() {
    let dir = tmpdir("hidden");
    assert_eq!(add(&dir, None, "Attic", Some("correct horse battery"), true).unwrap(), Added::New);
    add(&dir, None, "Cafe", None, true).unwrap();
    add(&dir, None, "Home", Some("long enough"), false).unwrap();
    let text = fs::read_to_string(conf_path(&dir)).unwrap();
    assert!(text.contains("\tssid=\"Attic\"\n\tscan_ssid=1\n\tkey_mgmt=WPA-PSK WPA-PSK-SHA256 SAE\n"), "{text}");
    assert!(text.contains("\tssid=\"Cafe\"\n\tscan_ssid=1\n\tkey_mgmt=NONE\n"), "{text}");
    assert_eq!(text.matches("scan_ssid").count(), 2, "{text}");
    let hidden: Vec<bool> = load(&dir).unwrap().iter().map(|n| n.hidden).collect();
    assert_eq!(hidden, vec![true, true, false]);
    // Each add says it anew: saved again without it, the network is no longer asked for.
    assert_eq!(add(&dir, None, "Attic", Some("a new passphrase"), false).unwrap(), Added::Replaced);
    assert!(!load(&dir).unwrap()[0].hidden);
    assert_eq!(said("Attic", Added::New, false, true), "added hidden network \"Attic\"");
    assert_eq!(said("Cafe", Added::Replaced, true, true), "hidden network \"Cafe\" is now open, joined without a passphrase");
    let twice = "network={\n\tssid=\"a\"\n\tscan_ssid=1\n\tscan_ssid=1\n\tkey_mgmt=NONE\n}\n";
    assert!(parse(twice).unwrap_err().contains("a second scan_ssid"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn open_block_refused_with_a_key_or_protection() {
    let head = "ctrl_interface=/run/wpa_supplicant\nupdate_config=0\n\nnetwork={\n\tssid=\"Cafe\"\n";
    for (body, why) in [
        ("\tkey_mgmt=NONE\n\tpsk=\"long enough\"\n}\n", "key management"),
        ("\tkey_mgmt=NONE\n\tieee80211w=1\n}\n", "key management"),
        ("}\n", "neither a psk nor key_mgmt=NONE"),
    ] {
        let e = parse(&format!("{head}{body}")).unwrap_err();
        assert!(e.contains(why), "{body:?}: {e}");
    }
}

#[test]
fn passphrase_quoted_raw_psk_bare() {
    assert_eq!(check_passphrase("eight ch").unwrap(), Psk::Passphrase("eight ch".into()));
    let hex = "f".repeat(64);
    assert_eq!(check_passphrase(&hex).unwrap(), Psk::Hex(hex.clone()));
    let nets = vec![
        Network { ssid: "a".into(), psk: Psk::Passphrase("pass word".into()), mac: None, hidden: false },
        Network { ssid: "b".into(), psk: Psk::Hex(hex.clone()), mac: None, hidden: false },
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
    assert!(add(&dir, None, "bad\"ssid", Some("long enough"), false).is_err());
    assert!(!conf_path(&dir).exists(), "nothing written on refusal");
    add(&dir, None, "Home", Some("long enough"), false).unwrap();
    let before = fs::read(conf_path(&dir)).unwrap();
    let ino = fs::metadata(conf_path(&dir)).unwrap().ino();
    assert!(add(&dir, None, "Home", Some("short"), false).is_err());
    assert!(forget(&dir, None, "Nowhere").unwrap_err().contains("no network named"));
    assert_eq!(fs::read(conf_path(&dir)).unwrap(), before);
    assert_eq!(fs::metadata(conf_path(&dir)).unwrap().ino(), ino, "a refusal does not rewrite the file");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn readd_replaces_block_in_place() {
    let dir = tmpdir("replace");
    add(&dir, None, "First", Some("first pass"), false).unwrap();
    add(&dir, None, "Second", Some("second pass"), false).unwrap();
    assert_eq!(add(&dir, None, "First", Some("changed pass"), false).unwrap(), Added::Replaced);
    let nets = load(&dir).unwrap();
    assert_eq!(nets.len(), 2, "replaced, not appended");
    assert_eq!((nets[0].ssid.as_str(), &nets[0].psk), ("First", &Psk::Passphrase("changed pass".into())));
    assert_eq!(nets[1].ssid, "Second", "order kept");
    assert_eq!(fs::read_to_string(conf_path(&dir)).unwrap().matches("network={").count(), 2);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn write_is_atomic_rename() {
    let dir = tmpdir("atomic");
    add(&dir, None, "Home", Some("long enough"), false).unwrap();
    let ino = fs::metadata(conf_path(&dir)).unwrap().ino();
    // A temporary left by a writer that died before its rename is removed.
    fs::write(dir.join(format!(".{FILE_NAME}.4294967295")), "psk=\"secret\"").unwrap();
    add(&dir, None, "Other", Some("long enough"), false).unwrap();
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
    let e = add(&dir, None, "Home", Some("long enough"), false).unwrap_err();
    assert!(e.contains("something else edited"), "{e}");
    assert_eq!(fs::read_to_string(conf_path(&dir)).unwrap(), "ap_scan=1\n");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn key_management_follows_what_was_saved() {
    let hex = "f".repeat(64);
    let text = render(&[
        Network { ssid: "a".into(), psk: Psk::Passphrase("pass word".into()), mac: None, hidden: false },
        Network { ssid: "b".into(), psk: Psk::Hex(hex.clone()), mac: None, hidden: false },
    ]);
    // A passphrase allows SAE, a raw key cannot; neither ever names 802.1X.
    assert!(text.contains("\tssid=\"a\"\n\tkey_mgmt=WPA-PSK WPA-PSK-SHA256 SAE\n\tieee80211w=1\n\tpsk=\"pass word\"\n"), "{text}");
    assert!(text.contains(&format!("\tssid=\"b\"\n\tkey_mgmt=WPA-PSK WPA-PSK-SHA256\n\tieee80211w=1\n\tpsk={hex}\n")), "{text}");
    assert!(!text.contains("EAP"), "{text}");
    for bad in [
        // The key management a raw key cannot have, and a passphrase's without its protection.
        format!("network={{\n\tssid=\"b\"\n\tkey_mgmt=WPA-PSK WPA-PSK-SHA256 SAE\n\tieee80211w=1\n\tpsk={hex}\n}}\n"),
        "network={\n\tssid=\"a\"\n\tkey_mgmt=WPA-PSK WPA-PSK-SHA256 SAE\n\tpsk=\"pass word\"\n}\n".to_string(),
        "network={\n\tssid=\"a\"\n\tieee80211w=1\n\tpsk=\"pass word\"\n}\n".to_string(),
        "network={\n\tssid=\"a\"\n\tkey_mgmt=WPA-EAP\n\tieee80211w=1\n\tpsk=\"pass word\"\n}\n".to_string(),
        "network={\n\tssid=\"a\"\n\tieee80211w=1\n\tieee80211w=1\n\tpsk=\"pass word\"\n}\n".to_string(),
    ] {
        let e = parse(&bad).unwrap_err();
        assert!(e.contains("line "), "{bad:?}: {e}");
        assert!(!e.contains("pass word"), "{e}");
    }
}

#[test]
fn older_file_rewritten_with_key_management() {
    let dir = tmpdir("refresh");
    assert!(!refresh(&dir, None).unwrap(), "no file: nothing to rewrite");
    fs::create_dir_all(&dir).unwrap();
    // As an older kryptikd wrote it: no key management, so wpa_supplicant's default with EAP and without SAE.
    let older = "ctrl_interface=/run/wpa_supplicant\nupdate_config=0\n\nnetwork={\n\tssid=\"Home\"\n\tpsk=\"correct horse battery\"\n}\n";
    fs::write(conf_path(&dir), older).unwrap();
    assert_eq!(list(&dir).unwrap(), vec!["Home"], "an older file still reads");
    assert!(refresh(&dir, None).unwrap());
    let now = fs::read_to_string(conf_path(&dir)).unwrap();
    assert!(now.contains("\tkey_mgmt=WPA-PSK WPA-PSK-SHA256 SAE\n\tieee80211w=1\n"), "{now}");
    // And the header's line that keeps the supplicant scanning after a failed join.
    assert!(now.starts_with(HEADER) && HEADER.contains("\nscan_res_valid_for_connect=0\n"), "{now}");
    assert_eq!(fs::metadata(conf_path(&dir)).unwrap().mode() & 0o7777, 0o440);
    assert!(!refresh(&dir, None).unwrap(), "a current file is left alone");
    // An older kryptikd's mode, which the supplicant's own user cannot read through its group.
    fs::set_permissions(conf_path(&dir), fs::Permissions::from_mode(0o400)).unwrap();
    assert!(refresh(&dir, None).unwrap(), "a current file at 0400 is rewritten");
    assert_eq!(fs::metadata(conf_path(&dir)).unwrap().mode() & 0o7777, 0o440);
    assert_eq!(fs::read_to_string(conf_path(&dir)).unwrap(), now, "and keeps its text");
    // Replaced, as the 0440 file takes no write.
    fs::remove_file(conf_path(&dir)).unwrap();
    fs::write(conf_path(&dir), "ap_scan=1\n").unwrap();
    assert!(refresh(&dir, None).unwrap_err().contains("something else edited"));
    assert_eq!(fs::read_to_string(conf_path(&dir)).unwrap(), "ap_scan=1\n", "a foreign file is not rewritten");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn no_restart_for_other_directory() {
    let m = restart_net_zone(Path::new("/nonexistent/wifi"));
    assert!(m.contains("not restarted") && m.contains(DEFAULT_DIR), "{m}");
}

#[test]
fn scan_answer_read_strongest_first_once_each() {
    let text = "radios nic0\n\
                -71\topen\tCafe\n\
                -40\twpa2/wpa3\tHome Net\n\
                -55\topen\tCafe\n\
                -80\twpa2\tCafe\n\
                -63\twpa3\tcaf\\xc3\\xa9\n";
    let s = parse_scan(text);
    assert_eq!(s.radios, vec!["nic0"]);
    assert!(s.off.is_empty());
    let got: Vec<(Vec<u8>, &str, i32)> = s.heard.iter().map(|h| (h.ssid.clone(), h.security, h.signal)).collect();
    assert_eq!(
        got,
        vec![
            (b"Home Net".to_vec(), "wpa2/wpa3", -40),
            (b"Cafe".to_vec(), "open", -55),
            ("café".as_bytes().to_vec(), "wpa3", -63),
            (b"Cafe".to_vec(), "wpa2", -80),
        ],
        "one entry per name and security, at its strongest, strongest first"
    );
}

#[test]
fn scan_answer_drops_what_is_not_its_form() {
    let text = "radios nic0 ../etc NIC1 nic2\n\
                off nic0\n\
                off nic0;rm\n\
                -30\topen\tfine\n\
                +5\topen\tpositive\n\
                -30\topen\tthree\textra\n\
                -30\twpa9\tunknown kind\n\
                -200\topen\ttoo weak\n\
                -30\topen\t\n\
                -30\topen\t\\x00\\x00\n\
                -30\topen\tlone \\ backslash\n\
                -30\topen\tbad \\xZZ hex\n\
                -30\topen\tshort \\x4\n\
                -30\topen\tabcdefghijklmnopqrstuvwxyz0123456\n\
                -30\topen\ttab\u{1b}[2Jescape\n\
                -30\topen\tdel\u{7f}\n";
    let s = parse_scan(text);
    assert_eq!(s.radios, vec!["nic0", "nic2"], "a radio's name is a plain one");
    assert_eq!(s.off, vec!["nic0"]);
    assert_eq!(s.heard.len(), 1, "{:?}", s.heard);
    assert_eq!(s.heard[0].ssid, b"fine".to_vec());
    assert_eq!(parse_scan("radios none\n").radios, Vec::<String>::new());
}

#[test]
fn scan_answer_is_bounded() {
    let mut text = String::from("radios nic0\n");
    for i in 0..200 {
        text.push_str(&format!("-{}\topen\tnet{i}\n", 20 + i % 80));
    }
    let s = parse_scan(&text);
    assert_eq!(s.heard.len(), MAX_HEARD);
    assert!(s.heard.windows(2).all(|w| w[0].signal >= w[1].signal));
}

#[test]
fn ssid_shown_with_nothing_unprintable() {
    assert_eq!(shown(b"Home"), "\"Home\"");
    assert_eq!(shown("café".as_bytes()), "\"café\"");
    assert_eq!(shown(b"a\"b\\c"), "\"a\\\"b\\\\c\"");
    assert_eq!(shown(b"x\x1b[2Jy"), "\"x\\u{1b}[2Jy\"");
    assert_eq!(shown(b"\xff\xfeok \"q\""), "\"\\xff\\xfeok \\x22q\\x22\"");
}

#[test]
fn scan_said_in_words() {
    let none = Scan::default();
    assert_eq!(scan_said(&none, &[]), "the net zone has no Wi-Fi radio\n");
    let quiet = Scan { radios: vec!["nic0".into()], off: vec!["nic0".into()], heard: vec![] };
    assert_eq!(
        scan_said(&quiet, &[]),
        "radio nic0 is switched off, by its switch or an airplane-mode key\nno network heard\n"
    );
    let s = parse_scan("radios nic0\n-40\twpa2\tHome\n-70\tenterprise\tWork\n-75\topen\tCafe\n");
    assert_eq!(
        scan_said(&s, &["Cafe".to_string()]),
        "\"Home\"  WPA2  -40 dBm\n\"Work\"  802.1X, which Kryptik does not join  -70 dBm\n\"Cafe\"  open  -75 dBm  saved\n"
    );
}
