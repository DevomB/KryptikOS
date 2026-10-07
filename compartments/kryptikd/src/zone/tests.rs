use super::*;

// r##: the colour's `"#` would end a single-hash raw string.
const VAULT: &str = r##"
[zone]
name = "vault"
description = "secrets"
[network]
mode = "none"
[storage]
mode = "encrypted"
volume = "/dev/kryptik/vault"
[limits]
pids_max = 128
[ui]
border_color = "#c9a227"
"##;

#[test]
fn parses_valid_zone() {
    let z = Zone::from_str(VAULT).expect("should parse");
    assert_eq!(z.name, "vault");
    assert_eq!(z.network, NetworkMode::None);
    assert_eq!(z.storage, StorageMode::Encrypted);
    assert_eq!(z.pids_max, Some(128));
}

#[test]
fn hash_in_colour_is_not_comment() {
    let z = Zone::from_str(VAULT).unwrap();
    assert_eq!(z.border_color, "#c9a227");
}

#[test]
fn tmpfs_larger_than_memory_max_refused() {
    let toml = r##"
[zone]
name = "z"
description = "d"
[network]
mode = "none"
[storage]
mode = "ephemeral"
size = "64M"
[limits]
memory_max = "48M"
[ui]
border_color = "#000000"
"##;
    let err = Zone::from_str(toml).expect_err("64M of tmpfs under a 48M cap must be refused");
    let msg = format!("{err}");
    assert!(msg.contains("storage.size"), "the message must name the key: {msg}");
    assert!(msg.contains("memory_max"), "and the limit it conflicts with: {msg}");

    // The other way round is fine.
    let ok = toml.replace("size = \"64M\"", "size = \"32M\"");
    Zone::from_str(&ok).expect("32M under a 48M cap is a sensible pair");
}

fn with_transfer(name: &str, mode: &str, to: Option<&str>) -> Result<Zone, ZoneError> {
    let t = to.map(|v| format!("[transfer]\nto = \"{v}\"\n")).unwrap_or_default();
    // Distinct colours, or check_invariants refuses the set.
    let colour = format!("#1234{:02x}", name.bytes().next().unwrap_or(0));
    Zone::from_str(&format!(
        "[zone]\nname = \"{name}\"\n[network]\nmode = \"{mode}\"\n\
             [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n{t}[ui]\nborder_color = \"{colour}\"\n"
    ))
}

#[test]
fn transfer_to_validates_names() {
    assert!(with_transfer("a", "none", None).unwrap().transfer_to.is_empty());
    assert_eq!(with_transfer("a", "none", Some("b c")).unwrap().transfer_to, vec!["b", "c"]);
    for bad in ["a", "b b", "", "B", "../x", "b/c"] {
        assert!(with_transfer("a", "none", Some(bad)).is_err(), "{bad:?} must be refused");
    }
}

#[test]
fn transfer_targets_exist_and_are_not_nic() {
    let set = |to: &str| {
        vec![
            with_transfer("n", "nic", None).unwrap(),
            with_transfer("b", "none", None).unwrap(),
            with_transfer("a", "none", Some(to)).unwrap(),
        ]
    };
    check_invariants(&set("b")).unwrap();
    let e = check_invariants(&set("zzz")).unwrap_err().to_string();
    assert!(e.contains("not a zone"), "{e}");
    let e = check_invariants(&set("n")).unwrap_err().to_string();
    assert!(e.contains("receives nothing"), "{e}");
}

fn persistent(extra: &str) -> Result<Zone, ZoneError> {
    Zone::from_str(&format!(
        "[zone]\nname = \"keeper\"\n[network]\nmode = \"none\"\n\
             [storage]\nmode = \"persistent\"\n{extra}[ui]\nborder_color = \"#123456\"\n"
    ))
}

#[test]
fn persistent_zone_needs_no_volume() {
    let z = persistent("").expect("persistent should be a valid mode");
    assert_eq!(z.storage, StorageMode::Persistent);
    assert_eq!(z.volume, None);
    assert_eq!(z.size, None);
    z.validate().expect("a bare persistent zone is complete as written");
}

#[test]
fn transfer_limit_within_cap() {
    let with = |v: &str| VAULT.replace("[ui]", &format!("[transfer]\nmax_bytes = {v}\n[ui]"));
    // A zone that sends nothing may still bound what it receives.
    for (v, want) in [("1", 1), ("4096", 4096), ("1073741824", 1 << 30), ("\"65536\"", 65536)] {
        assert_eq!(Zone::from_str(&with(v)).unwrap().transfer_max, Some(want), "{v}");
    }
    for v in ["0", "1073741825", "18446744073709551616", "\"-5\"", "\"+5\"", "\"1.5\"", "\"64M\"", "\"\"", "true"] {
        let err = Zone::from_str(&with(v)).unwrap_err();
        assert!(format!("{err}").contains("transfer.max_bytes"), "{v}: {err}");
    }
    // A bare sign or point is refused before the value is read.
    for v in ["-5", "1.5"] {
        assert!(Zone::from_str(&with(v)).is_err(), "{v}");
    }
    assert_eq!(Zone::from_str(VAULT).unwrap().transfer_max, None);
}

#[test]
fn persistent_zone_refuses_size() {
    let e = persistent("size = \"512M\"\n").expect_err("size must be refused");
    let m = e.to_string();
    assert!(m.contains("not in force"), "say why, not just no: {m}");
}

#[test]
fn persistent_zone_refuses_volume() {
    let e = persistent("volume = \"/dev/kryptik/keeper\"\n")
        .expect_err("a persistent zone opens no volume");
    let m = e.to_string();
    assert!(m.contains("/dev/kryptik/keeper"), "name the device: {m}");
    assert!(
        m.contains("refuse"),
        "point at the encrypted mode that WOULD be refused, so the reader learns \
             the difference rather than deleting the line: {m}"
    );
}

#[test]
fn unknown_storage_mode_lists_persistent() {
    let e = Zone::from_str(
        "[zone]\nname = \"t\"\n[network]\nmode = \"none\"\n\
             [storage]\nmode = \"durable\"\n[ui]\nborder_color = \"#123456\"\n",
    )
    .expect_err("durable is not a mode");
    assert!(e.to_string().contains("persistent"), "offer it: {e}");
}

#[test]
fn encrypted_storage_requires_volume() {
    let bad = VAULT.replace("volume = \"/dev/kryptik/vault\"\n", "");
    let err = Zone::from_str(&bad).unwrap_err();
    assert!(format!("{err}").contains("storage.volume"), "got: {err}");
}

#[test]
fn only_routed_zone_claims_local() {
    let routed = VAULT.replace("mode = \"none\"", "mode = \"routed\"");
    assert!(!Zone::from_str(&routed).unwrap().local);
    let yes = VAULT.replace("mode = \"none\"", "mode = \"routed\"\nlocal = true");
    assert!(Zone::from_str(&yes).unwrap().local);
    let no = VAULT.replace("mode = \"none\"", "mode = \"routed\"\nlocal = false");
    assert!(!Zone::from_str(&no).unwrap().local);
    let odd = VAULT.replace("mode = \"none\"", "mode = \"routed\"\nlocal = \"yes\"");
    let err = Zone::from_str(&odd).unwrap_err();
    assert!(format!("{err}").contains("true or false"), "got: {err}");
    let offline = VAULT.replace("mode = \"none\"", "mode = \"none\"\nlocal = true");
    let err = Zone::from_str(&offline).unwrap_err();
    assert!(format!("{err}").contains("only meaningful"), "got: {err}");
}

#[test]
fn only_nic_zone_names_interface() {
    let ok = VAULT.replace("mode = \"none\"", "mode = \"nic\"\nnic = \"eth0\"");
    assert_eq!(Zone::from_str(&ok).unwrap().nic.as_deref(), Some("eth0"));
    // "*": every physical interface of zone 0, decided at launch.
    let all = VAULT.replace("mode = \"none\"", "mode = \"nic\"\nnic = \"*\"");
    assert_eq!(Zone::from_str(&all).unwrap().nic.as_deref(), Some("*"));
    let bad = VAULT.replace("mode = \"none\"", "mode = \"none\"\nnic = \"eth0\"");
    let err = Zone::from_str(&bad).unwrap_err();
    assert!(format!("{err}").contains("only meaningful"), "got: {err}");
    let bad = VAULT.replace("mode = \"none\"", "mode = \"nic\"\nnic = \"averylongname123\"");
    assert!(Zone::from_str(&bad).is_err());
    for odd in ["eth\0x", "eth0:1", "..", "eth\u{1b}0", "eth 0", "eth\u{e9}"] {
        let bad = VAULT.replace("mode = \"none\"", &format!("mode = \"nic\"\nnic = \"{odd}\""));
        assert!(Zone::from_str(&bad).is_err(), "{odd:?} must be refused");
    }
}

#[test]
fn rejects_path_traversal_in_name() {
    let bad = VAULT.replace("\"vault\"", "\"../../etc\"");
    assert!(Zone::from_str(&bad).is_err());
}

#[test]
fn rejects_name_too_long_for_ifnamsiz() {
    let bad = VAULT.replace("\"vault\"", "\"averylongzonename\"");
    let err = Zone::from_str(&bad).unwrap_err();
    assert!(format!("{err}").contains("IFNAMSIZ"), "got: {err}");
}

#[test]
fn rejects_unknown_network_mode() {
    let bad = VAULT.replace("mode = \"none\"", "mode = \"host\"");
    let err = Zone::from_str(&bad).unwrap_err();
    assert!(format!("{err}").contains("network.mode"), "got: {err}");
}

#[test]
fn rejects_bad_colour() {
    let bad = VAULT.replace("\"#c9a227\"", "\"gold\"");
    assert!(Zone::from_str(&bad).is_err());
}

#[test]
fn rejects_duplicate_keys() {
    let bad = format!("{VAULT}\n[ui]\nborder_color = \"#111111\"\n");
    assert!(Zone::from_str(&bad).is_err());
}

#[test]
fn rejects_unparseable_limit() {
    let bad = VAULT.replace("pids_max = 128", "pids_max = 0");
    let err = Zone::from_str(&bad).unwrap_err();
    assert!(format!("{err}").contains("limits.pids_max"), "got: {err}");
    let bad = VAULT.replace("pids_max = 128", "pids_max = \"many\"");
    assert!(Zone::from_str(&bad).is_err());
    let bad = VAULT.replace("pids_max = 128", "memory_max = \"2 gigs\"");
    let err = Zone::from_str(&bad).unwrap_err();
    assert!(format!("{err}").contains("limits.memory_max"), "got: {err}");
    let ok = VAULT.replace("pids_max = 128", "memory_max = \"2G\"");
    assert_eq!(Zone::from_str(&ok).unwrap().memory_max.as_deref(), Some("2G"));
    for v in ["\"150\"", "\"0%\"", "\"abc%\"", "\"%\"", "2"] {
        let bad = VAULT.replace("pids_max = 128", &format!("cpu_max = {v}"));
        let err = Zone::from_str(&bad).unwrap_err();
        assert!(format!("{err}").contains("limits.cpu_max"), "{v}: {err}");
    }
    let ok = VAULT.replace("pids_max = 128", "cpu_max = \"150%\"");
    assert_eq!(Zone::from_str(&ok).unwrap().cpu_max.as_deref(), Some("150%"));
    assert_eq!(parse_cpu_max("50%"), Some(50));
    assert_eq!(parse_cpu_max("100%"), Some(100));
    for bad in ["0%", "50", "%", "", "1.5%", "-5%"] {
        assert_eq!(parse_cpu_max(bad), None, "{bad:?}");
    }
    // io_max is bytes per second on the volume: only an encrypted zone has one.
    let bad = VAULT.replace("pids_max = 128", "io_max = \"fast\"");
    assert!(format!("{}", Zone::from_str(&bad).unwrap_err()).contains("limits.io_max"));
    let ok = VAULT.replace("pids_max = 128", "io_max = \"20M\"");
    assert_eq!(Zone::from_str(&ok).unwrap().io_max.as_deref(), Some("20M"));
    let ephemeral = ok.replace("mode = \"encrypted\"\nvolume = \"/dev/kryptik/vault\"", "mode = \"ephemeral\"\nsize = \"64M\"");
    let err = Zone::from_str(&ephemeral).unwrap_err();
    assert!(format!("{err}").contains("io_max") && format!("{err}").contains("volume"), "got: {err}");
    assert_eq!(parse_size("32M"), Some(32 << 20));
    assert_eq!(parse_size("1g"), Some(1 << 30));
    assert_eq!(parse_size("2T"), Some(2 << 40));
    assert_eq!(parse_size("4096"), Some(4096));
    for bad in ["0", "0M", "", "M", "2GB", "max", "+5", "-5", "1.5G", "17179869184G", "18446744073709551615K"] {
        assert_eq!(parse_size(bad), None, "{bad:?}");
    }
}

#[test]
fn rejects_unknown_keys() {
    for extra in ["[limits]\nnice = 2", "[storage]\nunlock = \"on-start\"", "[network]\nbridge = \"kryptik0\""] {
        let err = Zone::from_str(&format!("{VAULT}\n{extra}\n")).unwrap_err();
        assert!(format!("{err}").contains("unknown key"), "{extra}: {err}");
    }
}

#[test]
fn file_named_for_zone() {
    let dir = std::env::temp_dir().join(format!("kryptik-stem-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    // A set needs one zone holding the NIC.
    let net = "[zone]\nname = \"net\"\n[network]\nmode = \"nic\"\n\
                   [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n[ui]\nborder_color = \"#123456\"\n";
    fs::write(dir.join("net.toml"), net).unwrap();
    fs::write(dir.join("10-vault.toml"), VAULT).unwrap();
    let err = load_all(&dir).unwrap_err();
    assert!(format!("{err}").contains("named vault.toml"), "got: {err}");
    fs::rename(dir.join("10-vault.toml"), dir.join("vault.toml")).unwrap();
    assert_eq!(load_all(&dir).unwrap().len(), 2);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn colour_case_ignored() {
    let a = zone_with("a", "none", "#AA3333");
    let b = zone_with("b", "none", "#aa3333");
    assert!(check_invariants(&[a, b]).is_err());
}

#[test]
fn identity_base_aligned_above_floor() {
    for bad in ["1000", "100000", "131073", "196607", "0", "\"x\""] {
        let t = VAULT.replace("[ui]", &format!("[identity]\nuid_base = {bad}\n[ui]"));
        let err = Zone::from_str(&t).unwrap_err();
        assert!(format!("{err}").contains("identity.uid_base"), "{bad}: {err}");
    }
    for ok in ["131072", "196608", "4294901760"] {
        let t = VAULT.replace("[ui]", &format!("[identity]\nuid_base = {ok}\n[ui]"));
        assert_eq!(Zone::from_str(&t).unwrap().uid_base, Some(ok.parse().unwrap()), "{ok}");
    }
    // 4294901760 is the last base with room for a full range.
    assert!(Zone::from_str(&VAULT.replace("[ui]", "[identity]\nuid_base = 4294967295\n[ui]")).is_err());
    assert_eq!(Zone::from_str(VAULT).unwrap().uid_base, None);
}

#[test]
fn identity_ranges_must_not_collide() {
    let with = |name: &str, colour: &str, base: u32| {
        let text = format!(
            "[zone]\nname = \"{name}\"\n[network]\nmode = \"routed\"\n\
                 [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n\
                 [identity]\nuid_base = {base}\n[ui]\nborder_color = \"{colour}\"\n"
        );
        Zone::from_str(&text).unwrap()
    };
    let nic = zone_with("net", "nic", "#111111");
    let err = check_invariants(&[nic.clone(), with("a", "#222222", 131072), with("b", "#333333", 131072)]).unwrap_err();
    assert!(format!("{err}").contains("identity ranges must not overlap"), "{err}");
    assert!(check_invariants(&[nic, with("a", "#222222", 131072), with("b", "#333333", 196608)]).is_ok());
}

#[test]
fn rejects_arrays() {
    let bad = VAULT.replace("pids_max = 128", "pids_max = [1, 2]");
    assert!(Zone::from_str(&bad).is_err());
}

fn zone_with(name: &str, mode: &str, colour: &str) -> Zone {
    let text = format!(
        "[zone]\nname = \"{name}\"\n[network]\nmode = \"{mode}\"\n\
             [storage]\nmode = \"ephemeral\"\nsize = \"256M\"\n[ui]\nborder_color = \"{colour}\"\n"
    );
    Zone::from_str(&text).unwrap()
}

#[test]
fn exactly_one_nic_zone() {
    let two = vec![
        zone_with("net", "nic", "#111111"),
        zone_with("net2", "nic", "#222222"),
    ];
    let err = check_invariants(&two).unwrap_err();
    assert!(format!("{err}").contains("claim the physical NIC"), "got: {err}");

    let none = vec![zone_with("work", "routed", "#111111")];
    assert!(check_invariants(&none).is_err());

    let one = vec![
        zone_with("net", "nic", "#111111"),
        zone_with("work", "routed", "#222222"),
    ];
    assert!(check_invariants(&one).is_ok());
}

#[test]
fn duplicate_colours_are_rejected() {
    let zones = vec![
        zone_with("net", "nic", "#111111"),
        zone_with("work", "routed", "#111111"),
    ];
    let err = check_invariants(&zones).unwrap_err();
    assert!(format!("{err}").contains("border_color"), "got: {err}");
}
