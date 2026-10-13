use super::*;

fn hex(c: char) -> String {
    std::iter::repeat(c).take(64).collect()
}

fn image(name: &str) -> String {
    format!(
        "image: {name} 140.4.0 bytes=12288 sha256={} data-blocks=2 root-hash={} salt={}",
        hex('a'),
        hex('b'),
        hex('c')
    )
}

/// A list over the root `1…1`, with these lines after its header.
fn list(lines: &[&str]) -> String {
    let mut s = format!("{MAGIC}\nrelease: 1.2.0\nbase: {}\n", hex('1'));
    for l in lines {
        s.push_str(l);
        s.push('\n');
    }
    s
}

#[test]
fn parses_a_list_as_stage_06_writes_it() {
    let m = parse(&list(&[&image("browser"), &image("viewer"), "needs: browser allow-syscall seccomp"])).unwrap();
    assert_eq!((m.release.as_str(), m.base.as_str()), ("1.2.0", hex('1').as_str()));
    assert_eq!(
        m.images[0],
        Image {
            name: "browser".into(),
            version: "140.4.0".into(),
            bytes: 12288,
            sha256: hex('a'),
            data_blocks: 2,
            root_hash: hex('b'),
            salt: hex('c'),
        }
    );
    assert_eq!(m.images[1].name, "viewer");
    assert_eq!(m.needs, vec![("browser".to_string(), "allow-syscall seccomp".to_string())]);
}

#[test]
fn refuses_what_stage_06_never_writes() {
    let good = image("browser");
    for (why, text) in [
        ("no header", list(&[&good]).replacen(MAGIC, "KRYPTIK-IMAGES-2", 1)),
        ("no final newline", list(&[&good]).trim_end().to_string()),
        ("a carriage return", list(&[&good]).replace('\n', "\r\n")),
        ("a blank line", list(&["", &good])),
        ("a comment", list(&["# browser", &good])),
        ("no image", list(&[])),
        ("a short base", list(&[&good]).replace(&hex('1'), &hex('1')[..63])),
        ("an upper-case root hash", list(&[&good.replace(&hex('b'), &hex('B'))])),
        ("a name with a slash", list(&[&image("a/b")])),
        ("a name of 33 bytes", list(&[&image(&"x".repeat(33))])),
        ("a field out of order", list(&[&good.replace("bytes=12288 ", "").replace(" salt=", " bytes=12288 salt=")])),
        ("a leading zero", list(&[&good.replace("bytes=12288", "bytes=012288")])),
        ("no room for the hash tree", list(&[&good.replace("bytes=12288", "bytes=8192")])),
        ("bytes not whole blocks", list(&[&good.replace("bytes=12288", "bytes=12289")])),
        ("no data", list(&[&good.replace("data-blocks=2", "data-blocks=0")])),
        ("past the cap", list(&[&good.replace("bytes=12288", &format!("bytes={}", (16u64 << 30) + 4096))])),
        ("two spaces", list(&[&good.replacen(' ', "  ", 1)])),
        ("out of order", list(&[&image("viewer"), &good])),
        ("listed twice", list(&[&good, &good])),
        ("needs for an image not listed", list(&[&good, "needs: viewer allow-syscall seccomp"])),
        ("needs no line", list(&[&good, "needs: browser"])),
        ("needs a line no policy file takes", list(&[&good, "needs: browser allow-syscall nosuchcall"])),
        ("needs a denied call", list(&[&good, "needs: browser allow-syscall ptrace"])),
        ("an image after the needs", list(&[&good, "needs: browser allow-syscall seccomp", &image("viewer")])),
        (
            "needs out of their image's order",
            list(&[&good, &image("viewer"), "needs: viewer allow-syscall seccomp", "needs: browser allow-syscall mlockall"]),
        ),
        ("an unknown line", list(&[&good, "signer: someone"])),
        ("requires for an image not listed", list(&[&good, &image("toolkit"), "requires: viewer toolkit"])),
        ("requires nothing", list(&[&good, &image("toolkit"), "requires: browser"])),
        ("requires itself", list(&[&good, &image("toolkit"), "requires: browser browser"])),
        ("requires an image not listed", list(&[&good, &image("toolkit"), "requires: browser fonts"])),
        ("requires one image twice", list(&[&good, &image("toolkit"), "requires: browser toolkit toolkit"])),
        ("two requires lines for one image", list(&[&good, &image("toolkit"), "requires: browser toolkit", "requires: browser toolkit"])),
        ("requires out of image order", list(&[&good, &image("fonts"), &image("toolkit"), "requires: toolkit fonts", "requires: browser toolkit"])),
        ("requires after needs", list(&[&good, &image("toolkit"), "needs: browser allow-syscall seccomp", "requires: browser toolkit"])),
        ("an image after requires", list(&[&good, "requires: browser toolkit", &image("toolkit")])),
    ] {
        assert!(parse(&text).is_err(), "{why}: {text:?}");
    }
}

#[test]
fn root_hash_from_the_signed_command_line() {
    let table = |dev: &str| {
        format!("0 2048000 verity 1 {dev} {dev} 4096 4096 256000 256001 sha256 {} {} 1 panic_on_corruption", hex('d'), hex('e'))
    };
    let installed = format!(
        "dm-mod.waitfor=PARTLABEL=kryptik-a dm-mod.create=\"kroot,,0,ro,{}\" root=/dev/dm-0 lockdown=confidentiality kryptik.slot=a",
        table("PARTLABEL=kryptik-a")
    );
    assert_eq!(root_hash_from(&installed), Some(hex('d')));
    let iso = format!(
        "dm-mod.create=\"kmedia,,0,ro,0 4000 linear /dev/sr0 128;kroot,,1,ro,{}\" root=/dev/dm-1 kryptik.media=iso",
        table("/dev/dm-0")
    );
    assert_eq!(root_hash_from(&iso), Some(hex('d')));
    assert_eq!(root_hash_from("root=/dev/vda2 ro"), None, "no verity root");
    assert_eq!(root_hash_from("dm-mod.create=\"kroot,,0,ro,0 8 linear /dev/vda2 0\""), None, "a root that is not verity");
    let short = installed.replace(&hex('d'), &hex('d')[..40]);
    assert_eq!(root_hash_from(&short), None, "a hash that is not 64 digits");
}

#[test]
fn needs_must_be_granted_by_the_zone_policy() {
    let m = parse(&list(&[&image("browser"), &image("viewer"), "needs: browser allow-syscall seccomp"])).unwrap();
    let grants = |text: &str| policy::parse(text, "zone").unwrap();
    assert!(needs_met(&m, "browser", Some(&grants("allow-syscall seccomp\nallow-syscall mlockall\n"))).is_ok());
    let refused = needs_met(&m, "browser", Some(&grants("allow-syscall mlockall\n"))).unwrap_err();
    assert!(refused.contains("allow-syscall seccomp"), "{refused}");
    assert!(needs_met(&m, "browser", None).is_err(), "a zone with no policy file grants nothing");
    assert!(needs_met(&m, "viewer", None).is_ok(), "an image that needs nothing");
    // What the base policy already allows needs no grant.
    let base = parse(&list(&[&image("browser"), "needs: browser allow-syscall read"])).unwrap();
    assert!(needs_met(&base, "browser", None).is_ok());
}

#[test]
fn an_image_built_over_others_needs_them_named() {
    let m = parse(&list(&[
        &image("browser"),
        &image("fonts"),
        &image("toolkit"),
        "requires: browser toolkit fonts",
        "requires: toolkit fonts",
        "needs: browser allow-syscall seccomp",
    ]))
    .unwrap();
    assert_eq!(
        m.requires,
        vec![
            ("browser".to_string(), vec!["toolkit".to_string(), "fonts".to_string()]),
            ("toolkit".to_string(), vec!["fonts".to_string()]),
        ]
    );
    let names = |n: &[&str]| n.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert!(requires_met(&m, &names(&["browser", "toolkit", "fonts"])).is_ok());
    assert!(requires_met(&m, &names(&["fonts"])).is_ok(), "an image built over nothing");
    let refused = requires_met(&m, &names(&["browser", "toolkit"])).unwrap_err();
    assert!(refused.contains("\"fonts\""), "{refused}");
    assert!(requires_met(&m, &names(&["toolkit"])).is_err());
}

#[test]
fn a_set_is_named_by_its_images_and_their_hashes() {
    let m = parse(&list(&[&image("browser"), &image("viewer")])).unwrap();
    let both: Vec<&Image> = m.images.iter().collect();
    assert_eq!(set_dir(&both), format!("/run/kryptik/usr/browser-{0}+viewer-{0}", &hex('b')[..16]));
    assert_eq!(set_dir(&both[..1]), format!("/run/kryptik/usr/browser-{}", &hex('b')[..16]));
}

#[test]
fn names_are_what_a_path_and_a_zone_file_take() {
    for ok in ["browser", "pdf-viewer", "a", "x1"] {
        assert!(valid_name(ok), "{ok}");
    }
    let long = "x".repeat(33);
    for bad in ["", "Browser", "a b", "a/b", "..", "a.b", "a_b", long.as_str()] {
        assert!(!valid_name(bad), "{bad:?}");
    }
}
