use super::*;

#[test]
fn readable_passphrase_file_refused() {
    let dir = std::env::temp_dir().join(format!("kryptik-vol-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let f = dir.join("pass");
    fs::write(&f, "hunter2\n").unwrap();
    fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(Passphrase::from_file(&f), Err(VolumeError::Passphrase(_))));
    fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
    let p = Passphrase::from_file(&f).unwrap();
    assert_eq!(p.as_bytes(), b"hunter2");
    fs::write(&f, "").unwrap();
    assert!(Passphrase::from_file(&f).is_err(), "an empty passphrase file is refused");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn passphrase_link_and_size_refused() {
    let dir = std::env::temp_dir().join(format!("kryptik-pass-boundary-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("pass");
    fs::write(&path, b"secret").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&path, dir.join("link")).unwrap();
    let link_refused = Passphrase::from_file(&dir.join("link")).is_err();
    fs::write(&path, vec![b'x'; 4097]).unwrap();
    let oversized_refused = Passphrase::from_file(&path).is_err();
    fs::write(&path, b"\r\n").unwrap();
    let empty_refused = Passphrase::from_file(&path).is_err();
    fs::remove_dir_all(dir).unwrap();
    assert!(link_refused && oversized_refused && empty_refused,
        "link refused={link_refused}, oversized refused={oversized_refused}, empty refused={empty_refused}");
}

#[test]
fn passphrase_pipe_times_out() {
    let mut pipe = [0; 2];
    assert_eq!(unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    assert_eq!(unsafe { libc::write(pipe[1], b"partial".as_ptr() as *const libc::c_void, 7) }, 7);
    let (done, completion) = std::sync::mpsc::channel();
    let read_fd = pipe[0];
    let worker = std::thread::spawn(move || {
        let _ = done.send(Passphrase::from_fd(read_fd).is_err());
    });
    // Closing the writer afterwards frees the worker even if it still blocks.
    let result = completion.recv_timeout(std::time::Duration::from_secs(7));
    unsafe { libc::close(pipe[1]) };
    worker.join().unwrap();
    assert_eq!(result.ok(), Some(true), "a partial passphrase held the launcher indefinitely");
}

#[test]
fn passphrase_fd_isolated_from_sender() {
    use std::os::unix::io::IntoRawFd;
    let fd = unsafe { libc::memfd_create(c"kryptik-pass-test".as_ptr(), libc::MFD_CLOEXEC) };
    assert!(fd >= 0);
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    file.write_all(b"skipsecret\r\n").unwrap();
    file.seek(SeekFrom::Start(4)).unwrap();
    let pass = Passphrase::from_fd(file.try_clone().unwrap().into_raw_fd()).unwrap();
    assert_eq!(pass.as_bytes(), b"secret");
    assert_eq!(file.stream_position().unwrap(), 4, "the sender's offset must not be consumed");
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK, 0);
    for len in [0, 4096, 4097] {
        file.set_len(len).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let result = Passphrase::from_fd(file.try_clone().unwrap().into_raw_fd());
        assert_eq!(result.is_ok(), len == 4096, "descriptor length {len}");
    }
    let mut pipe = [0; 2];
    assert_eq!(unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    assert_eq!(unsafe { libc::write(pipe[1], b"secret\n".as_ptr() as *const libc::c_void, 7) }, 7);
    unsafe { libc::close(pipe[1]) };
    assert_eq!(Passphrase::from_fd(pipe[0]).unwrap().as_bytes(), b"secret");
    assert!(Passphrase::from_fd(-1).is_err());
}

#[test]
fn names_derive_from_zone() {
    assert_eq!(mapper_name("work"), "kryptik-zone-work");
    assert_eq!(mapper_path("work"), "/dev/mapper/kryptik-zone-work");
    assert_eq!(default_volume_path("vault"), "/var/lib/kryptik/volumes/vault.luks");
    assert_eq!(mountpoint_for(Path::new("/var/lib/kryptik/zones"), "work"), PathBuf::from("/var/lib/kryptik/zones/work"));
}

#[test]
fn gc_sees_only_zone_mappings() {
    // The state partition's mappings are not zones; a zone named state is.
    let names = ["kryptik-state", "kryptik-verify-state", "kroot", "control", "kryptik-zone-work", "kryptik-zone-state"];
    assert_eq!(zones_mapped(names.iter().map(|s| s.to_string()).collect()), ["state", "work"]);
}

#[test]
fn mount_paths_escaped() {
    assert_eq!(mount_escaped("/var/lib/kryptik/zones/work"), "/var/lib/kryptik/zones/work");
    assert_eq!(mount_escaped("/z/a b\tc\nd"), "/z/a\\040b\\011c\\012d");
    // A literal backslash is escaped too, so "\040" in a name is not a space.
    assert_eq!(mount_escaped("/z/a\\040b"), "/z/a\\134040b");
}

/// Needs root, cryptsetup and dm-crypt; returns early without them.
#[test]
fn luks2_lifecycle_when_root() {
    if unsafe { libc::geteuid() } != 0 || Command::new("cryptsetup").arg("--version").output().is_err() {
        eprintln!("not root or no cryptsetup: lifecycle test skipped");
        return;
    }
    let dir = std::env::temp_dir().join(format!("kryptik-luks-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let vol = dir.join("t.luks").display().to_string();
    let mnt = dir.join("mnt").display().to_string();
    let zone = format!("t{}", std::process::id());
    let good = Passphrase(b"correct horse".to_vec());
    let bad = Passphrase(b"wrong".to_vec());
    init(&zone, &vol, 64 * 1024 * 1024, &good, 0, 0).expect("init");
    assert_eq!(signature_of(&vol), "crypto_LUKS");
    assert!(init(&zone, &vol, 64 * 1024 * 1024, &good, 0, 0).is_err(), "double format refused");
    assert!(matches!(open_and_mount(&zone, &vol, &bad, &mnt), Err(VolumeError::WrongPassphrase { .. })));
    assert!(!mapping_exists(&zone), "a wrong passphrase leaves no mapping");
    let o = open_and_mount(&zone, &vol, &good, &mnt).expect("open");
    fs::write(format!("{mnt}/f"), b"persists").unwrap();
    o.close().expect("close");
    assert!(!mapping_exists(&zone));
    assert!(!is_mountpoint(&mnt));
    let o = open_and_mount(&zone, &vol, &good, &mnt).expect("reopen");
    assert_eq!(fs::read(format!("{mnt}/f")).unwrap(), b"persists");
    o.close().unwrap();
    let _ = fs::remove_dir_all(&dir);
}
