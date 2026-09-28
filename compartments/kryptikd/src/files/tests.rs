use super::*;

fn scratch(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("kryptik-files-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    private_dir(&d).unwrap();
    d
}

fn names(d: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(d).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    v.sort();
    v
}

#[test]
fn replaces_whole() {
    let d = scratch("replace");
    let p = d.join("state");
    write_atomic(&p, &[b"old"], 0o600, None).unwrap();
    write_atomic(&p, &[b"new", b"\n", b"parts"], 0o400, None).unwrap();
    assert_eq!(fs::read(&p).unwrap(), b"new\nparts");
    assert_eq!(fs::metadata(&p).unwrap().mode() & 0o777, 0o400);
    assert_eq!(names(&d), ["state"], "no temporary left behind");
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn clears_dead_temps() {
    let d = scratch("dead");
    fs::write(d.join(".state.4294967295"), b"secret").unwrap(); // no such process
    fs::write(d.join(".state.1"), b"init's").unwrap(); // a live one
    write_atomic(&d.join("state"), &[b"new"], 0o600, None).unwrap();
    assert_eq!(names(&d), [".state.1", "state"]);
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn replaces_link_unfollowed() {
    let d = scratch("link");
    let victim = d.join("victim");
    fs::write(&victim, b"untouched").unwrap();
    std::os::unix::fs::symlink(&victim, d.join("state")).unwrap();
    write_atomic(&d.join("state"), &[b"mine"], 0o600, None).unwrap();
    assert!(fs::symlink_metadata(d.join("state")).unwrap().is_file());
    assert_eq!(fs::read(&victim).unwrap(), b"untouched");
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn failure_keeps_old_file() {
    if unsafe { libc::geteuid() } == 0 {
        return; // root may chown to anyone; the refusal below needs a user
    }
    let d = scratch("fail");
    let p = d.join("state");
    write_atomic(&p, &[b"old"], 0o600, None).unwrap();
    assert!(write_atomic(&p, &[b"new"], 0o600, Some((0, 0))).is_err());
    assert_eq!(fs::read(&p).unwrap(), b"old");
    assert_eq!(names(&d), ["state"], "the failed write's temporary is gone");
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn private_dir_refuses_shared() {
    let d = scratch("private");
    let open = d.join("open");
    fs::create_dir(&open).unwrap();
    fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(private_dir(&open).is_err(), "a directory others can read");
    std::os::unix::fs::symlink(&d, d.join("link")).unwrap();
    assert!(private_dir(&d.join("link")).is_err(), "a link to a private directory");
    assert!(private_dir(&d.join("made")).is_ok());
    let _ = fs::remove_dir_all(&d);
}
