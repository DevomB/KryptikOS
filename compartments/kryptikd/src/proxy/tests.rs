use super::*;

#[test]
fn a_proxy_uid_is_the_top_of_its_zones_block_which_no_zone_maps() {
    assert_eq!(uid_for(131072), 196607);
    // A zone maps 0 and 65534 of its block, and the nic zone 100 and 101 too.
    for mapped in [0, 100, 101, 65534] {
        assert_ne!(uid_for(131072), 131072 + mapped);
    }
    assert!(uid_for(131072) < 196608, "inside its own block, below the next zone's");
}

#[test]
fn sockets_are_named_by_session_and_zone() {
    let run = Path::new("/run");
    assert_eq!(socket_path(run, 1000, "work"), Path::new("/run/kryptik-proxy/1000/work/wayland-0"));
    assert_eq!(log_path(run, 1000, "work"), Path::new("/run/kryptik-proxy/1000/work.log"));
    assert_eq!(upstream_path(run, 1000, "work"), Path::new("/run/kryptik-compositor/1000/work"));
}

#[test]
fn no_proxy_starts_without_a_compositor_socket() {
    let dir = std::env::temp_dir().join(format!("kryptik-proxy-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut z = crate::zone::Zone::from_file(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../zones/work.toml")).expect("work.toml");
    z.uid_base = Some(131072);
    let e = start(&dir, Path::new("/usr/bin/kryptik-wlproxy"), 1000, &z, false).err().expect("refused");
    assert!(e.contains("no compositor serves zone \"work\""), "{e}");
    assert!(!socket_path(&dir, 1000, "work").exists(), "nothing was made for it");
    let _ = fs::remove_dir_all(&dir);
}

/// The session owns the directory dwl's sockets are in: a link there, or a socket another uid
/// owns, is no upstream.
#[test]
fn the_upstream_is_a_socket_the_session_owns_and_no_link() {
    let me = unsafe { libc::geteuid() };
    let dir = std::env::temp_dir().join(format!("kryptik-proxy-upstream-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let up = upstream_path(&dir, me, "work");
    fs::create_dir_all(up.parent().unwrap()).unwrap();
    let real = up.with_file_name("elsewhere");
    let _keep = std::os::unix::net::UnixListener::bind(&real).unwrap();
    std::os::unix::fs::symlink(&real, &up).unwrap();
    let e = upstream_of(&dir, me, "work").err().expect("a link is refused");
    assert!(e.contains("no compositor serves zone \"work\""), "{e}");
    fs::remove_file(&up).unwrap();
    fs::rename(&real, &up).unwrap();
    let (_fd, id) = upstream_of(&dir, me, "work").expect("the session's own socket");
    assert_eq!(upstream_of(&dir, me, "work").unwrap().1, id, "the same socket, the same inode");
    let _ = fs::remove_dir_all(&dir);
}

/// dwl takes each zone's proxy uid from zone-colours.h, which must name the uid serve gives it.
#[test]
fn dwl_knows_each_shipped_zones_proxy_uid() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let header = fs::read_to_string(root.join("build/desktop/zone-colours.h")).expect("zone-colours.h");
    let mut seen = 0;
    for entry in fs::read_dir(root.join("compartments/zones")).expect("the shipped zones") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let z = Zone::from_file(&path).expect("a shipped zone parses");
        let head = format!("X(\"{}\",", z.name);
        let row = header.lines().map(str::trim_start).find(|l| l.starts_with(&head)).unwrap_or_else(|| panic!("no row for {}", z.name));
        let tail = &row[row.rfind(',').unwrap() + 1..];
        let uid: u32 = tail[..tail.find(')').unwrap()].trim().parse().unwrap();
        assert_eq!(uid, uid_for(z.uid_base.expect("a shipped zone declares uid_base")), "{}", z.name);
        seen += 1;
    }
    assert!(seen >= 6, "{seen} zones");
}
