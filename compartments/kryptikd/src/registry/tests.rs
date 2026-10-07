use super::*;

#[test]
fn pid_stamp_round_trips() {
    let me = unsafe { libc::getpid() };
    let st = PidStamp::of(me).expect("our own start time must be readable");
    let enc = st.encode();
    let dec = PidStamp::decode(&enc, Path::new("/x")).unwrap();
    assert_eq!(st, dec);
    assert!(st.still_alive(), "we are alive");
}

#[test]
fn wrong_start_time_not_alive() {
    // Same pid, different process.
    let me = unsafe { libc::getpid() };
    let real = PidStamp::of(me).unwrap();
    let impostor = PidStamp { pid: me, start: real.start.wrapping_add(1) };
    assert!(real.still_alive());
    assert!(
        !impostor.still_alive(),
        "a stamp with the wrong start time must never be treated as live"
    );
}

#[test]
fn stat_parsed_after_last_paren() {
    // The comm (field 2) may contain spaces and parentheses.
    let fake = "123 (weird )( name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 rest";
    let rest = &fake[fake.rfind(')').unwrap() + 1..];
    let f22: u64 = rest.split_whitespace().nth(19).unwrap().parse().unwrap();
    assert_eq!(f22, 4242);
}

#[test]
fn registry_base_is_per_user() {
    let b = base();
    if unsafe { libc::geteuid() } == 0 {
        assert_eq!(b, Path::new("/run/kryptik/zones"));
    } else {
        // As text: Path::starts_with compares whole components, and "/tmp/kryptik-" is not one.
        let s = b.to_string_lossy();
        assert!(
            s.starts_with("/run/user/") || s.starts_with("/tmp/kryptik-"),
            "unprivileged registry must not be a shared path: {b:?}"
        );
    }
}

#[test]
fn bogus_runtime_dir_falls_back() {
    // The launcher suite sets XDG_RUNTIME_DIR=/run/user/9999.
    if unsafe { libc::geteuid() } == 0 {
        return; // root uses /run/kryptik regardless
    }
    let uid = unsafe { libc::getuid() };
    let fallback = PathBuf::from(format!("/tmp/kryptik-{uid}/zones"));
    assert_eq!(base_for(uid, uid, Some("/run/user/9999-does-not-exist")), fallback);
    assert_eq!(base_for(uid, uid, Some("")), fallback);
    assert_eq!(base_for(uid, uid, None), fallback);
    // An existing directory owned by someone else (/run is root's) is refused.
    assert_eq!(base_for(uid, uid, Some("/run")), fallback);
    // Root never consults the variable.
    assert_eq!(base_for(0, 0, Some("/run/user/0")), PathBuf::from("/run/kryptik/zones"));
}

#[test]
fn unsafe_registry_dir_is_refused() {
    // What an attacker could leave in /tmp before the user's first run.
    use std::os::unix::fs::MetadataExt;
    let root = std::env::temp_dir().join(format!("kryptik-regdir-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let mode_of = |p: &Path| fs::metadata(p).unwrap().mode() & 0o777;
    let refused = |p: &Path| matches!(check_or_create(p), Err(RegistryError::UnsafeBase { .. }));

    // A symlink, even to a directory we own: it can be re-aimed after the check.
    let target = root.join("real");
    fs::create_dir(&target).unwrap();
    let link = root.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(refused(&link), "a symlink must be refused");

    // Ours but world-writable: tightening would not undo what was put inside.
    let loose = root.join("loose");
    fs::create_dir(&loose).unwrap();
    set_mode(&loose, 0o777).unwrap();
    assert!(refused(&loose), "a world-writable directory must be refused");

    // Not a directory at all.
    let file = root.join("file");
    fs::write(&file, "").unwrap();
    assert!(refused(&file), "a plain file must be refused");

    // Ours and only too readable: repaired, not refused.
    let readable = root.join("readable");
    fs::create_dir(&readable).unwrap();
    set_mode(&readable, 0o755).unwrap();
    check_or_create(&readable).expect("a directory only this uid can write is repairable");
    assert_eq!(mode_of(&readable), 0o700, "it must be tightened to 0700");

    // Absent: created 0700, not 0755-by-umask.
    let fresh = root.join("fresh");
    check_or_create(&fresh).unwrap();
    assert_eq!(mode_of(&fresh), 0o700, "a new registry directory must be 0700");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn second_claim_refused_until_drop() {
    let zone = format!("regtest-{}", unsafe { libc::getpid() });
    let h = claim(&zone).expect("first claim");
    match state(&zone).unwrap() {
        // Locked but no launcher.pid yet: starting, which reads as Running.
        State::Running { launcher: None, .. } => {}
        other => panic!("expected Running with no pid yet, got {other:?}"),
    }
    // And once a pid is recorded it comes back.
    h.set_launcher(unsafe { libc::getpid() }).unwrap();
    match state(&zone).unwrap() {
        State::Running { launcher: Some(l), .. } => {
            assert_eq!(l.pid, unsafe { libc::getpid() });
            assert!(l.still_alive());
        }
        other => panic!("expected Running with our pid, got {other:?}"),
    }
    // flock is per open file description: a second claim from this process is refused too.
    match claim(&zone) {
        Err(RegistryError::AlreadyRunning { .. }) => {}
        other => panic!("a second claim must be refused, got {other:?}"),
    }
    drop(h);
    match state(&zone).unwrap() {
        State::Absent => {}
        other => panic!("dropping the handle must remove the entry, got {other:?}"),
    }
}

#[test]
fn sweep_removes_everything_in_entry() {
    // A broker killed before its rename strands a `.clipboard.<pid>` file.
    let zone = format!("regsweep-{}", unsafe { libc::getpid() });
    let h = claim(&zone).expect("claim");
    fs::write(h.dir().join(".clipboard.4242"), "stranded").unwrap();
    drop(h);
    match state(&zone).unwrap() {
        State::Absent => {}
        other => panic!("the launcher's own sweep must remove a file it did not write, got {other:?}"),
    }
    // The same entry, dead: a directory with a stray file and no lock.
    let dir = base().join(&zone);
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join(".clipboard.4242"), "stranded").unwrap();
    fs::write(dir.join("clipboard"), "text/plain\n").unwrap();
    reclaim(&zone).expect("reclaim must remove an entry whatever it holds");
    assert!(!dir.exists(), "the entry must be gone");
}

#[test]
fn sweep_keeps_lock_until_last() {
    // A claimer arriving mid-sweep must find the lock still held.
    let zone = format!("regorder-{}", unsafe { libc::getpid() });
    let h = claim(&zone).expect("claim");
    for f in ["a", "b", "c", "d"] {
        fs::write(h.dir().join(f), "x").unwrap();
    }
    let dir = h.dir().to_path_buf();
    sweep_with(&dir, &mut || {
        assert!(matches!(try_lock(&dir).unwrap(), Lock::Busy), "a claimer took the name mid-sweep");
    })
    .unwrap();
    assert!(!dir.exists(), "the entry must be gone");
    drop(h);
}

#[test]
fn reclaim_refuses_live_entry() {
    let zone = format!("reglive-{}", unsafe { libc::getpid() });
    let h = claim(&zone).expect("claim");
    match reclaim(&zone) {
        Err(RegistryError::AlreadyRunning { .. }) => {}
        other => panic!("reclaim must refuse an entry whose lock is held, got {other:?}"),
    }
    assert!(h.dir().join("started").exists(), "the live entry must be untouched");
    drop(h);
}

#[test]
fn reclaim_waits_out_probe() {
    // A probe holds the shared lock for an instant; reclaim must wait it out.
    let zone = format!("regwait-{}", unsafe { libc::getpid() });
    let dir = base().join(&zone);
    ensure_base(&base()).unwrap();
    fs::create_dir(&dir).unwrap();
    let fd = open_lock(&dir, true).unwrap().unwrap();
    assert_eq!(unsafe { libc::flock(fd, libc::LOCK_SH) }, 0);
    let probe = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(30));
        unsafe { libc::close(fd) };
    });
    reclaim(&zone).expect("a probe's instant must not make a stale entry live");
    probe.join().unwrap();
    assert!(!dir.exists());
}

#[test]
fn probe_creates_no_lock_file() {
    // An entry between its mkdir and its lock reads as not held.
    let zone = format!("regprobe-{}", unsafe { libc::getpid() });
    let dir = base().join(&zone);
    ensure_base(&base()).unwrap();
    fs::create_dir(&dir).unwrap();
    match state(&zone).unwrap() {
        State::Stale { .. } => {}
        other => panic!("an entry with no lock file is not held, got {other:?}"),
    }
    assert!(!dir.join("lock").exists(), "a probe must not create the lock file");
    reclaim(&zone).unwrap();
    assert!(!dir.exists());
}

#[test]
fn reclaim_stays_below_kryptik_root() {
    let root = Path::new("/sys/fs/cgroup/kryptik");
    assert!(under(Path::new("/sys/fs/cgroup/kryptik/zone-vault"), root));
    for p in [
        "/sys/fs/cgroup/kryptik/../user.slice",
        "/sys/fs/cgroup/kryptik/a/../../x",
        "/sys/fs/cgroup/kryptik",
        "/sys/fs/cgroup/kryptik/.",
        "/sys/fs/cgroup/kryptikx/a",
        "kryptik/a",
    ] {
        assert!(!under(Path::new(p), root), "{p} must not be reclaimed");
    }
}
