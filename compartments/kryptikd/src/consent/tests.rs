use super::*;

fn with_dir<T>(f: impl FnOnce(&std::path::Path) -> T) -> T {
    let d = std::env::temp_dir().join(format!("kryptik-consent-{}-{}", std::process::id(), COUNTER.load(Ordering::SeqCst)));
    std::fs::create_dir_all(&d).unwrap();
    let r = f(&d);
    let _ = std::fs::remove_dir_all(&d);
    r
}

/// The tests share the process environment, so they run one at a time.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Hold the watcher lock while the returned file lives. Children forked by
/// other tests inherit the flock, so no test may rely on its release.
fn hold_watch(d: &std::path::Path) -> std::fs::File {
    use std::os::unix::io::AsRawFd;
    let f = std::fs::File::create(d.join(WATCHER_LOCK)).unwrap();
    assert_eq!(unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
    f
}

/// The id of the first question to appear in `d`, as the chrome finds it.
fn wait_for_question(d: &std::path::Path) -> (String, String) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(ask) = std::fs::read_dir(d).unwrap().flatten().find(|e| e.path().extension().map(|x| x == "ask").unwrap_or(false)) {
            let text = std::fs::read_to_string(ask.path()).unwrap();
            let id = ask.path().file_stem().unwrap().to_string_lossy().to_string();
            return (id, text);
        }
        assert!(Instant::now() < deadline, "no question appeared");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn answer_when_asked(d: &std::path::Path, reply: &'static str) -> std::thread::JoinHandle<String> {
    let d = d.to_path_buf();
    std::thread::spawn(move || {
        let (id, text) = wait_for_question(&d);
        std::fs::write(d.join(format!("{id}.answer")), reply).unwrap();
        text
    })
}

#[test]
fn yes_approves_no_refuses() {
    let _g = env_lock();
    with_dir(|d| {
        std::env::set_var("KRYPTIK_CONSENT_DIR", d);
        std::env::set_var("KRYPTIK_CONSENT_TIMEOUT", "5");
        let _w = hold_watch(d);
        let h = answer_when_asked(d, "yes\n");
        assert!(ask("dev", "work", "report.pdf", 4096, &keep).is_ok());
        let q = h.join().unwrap();
        assert_eq!(q, "from=dev\nto=work\nname=report.pdf\nbytes=4096\n");
        let h = answer_when_asked(d, "no\n");
        let e = ask("dev", "work", "x", 1, &keep).unwrap_err();
        h.join().unwrap();
        assert!(e.contains("refused by the user") && e.shown, "{e}");
        let h = answer_when_asked(d, "maybe\n");
        let e = ask("dev", "work", "x", 1, &keep).unwrap_err();
        h.join().unwrap();
        assert!(e.contains("malformed"), "{e}");
        let left: Vec<_> = std::fs::read_dir(d).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left, vec![std::ffi::OsString::from(WATCHER_LOCK)], "question and answer are cleaned up");
    });
}

#[test]
fn silence_and_missing_channel_refuse() {
    let _g = env_lock();
    with_dir(|d| {
        std::env::set_var("KRYPTIK_CONSENT_DIR", d);
        std::env::set_var("KRYPTIK_CONSENT_TIMEOUT", "1");
        /* Nobody watching (no lock file, then one nobody holds): refused at
         * once, and no question is left behind. */
        for lock_file in [false, true] {
            if lock_file {
                std::fs::File::create(d.join(WATCHER_LOCK)).unwrap();
            }
            let t = Instant::now();
            let e = ask("dev", "work", "x", 1, &keep).unwrap_err();
            assert!(e.contains("no consent channel") && e.contains("watching") && !e.shown, "{e}");
            assert!(t.elapsed() < Duration::from_millis(500), "refused without waiting for the deadline");
            let placed = std::fs::read_dir(d).unwrap().flatten().filter(|e| e.file_name() != WATCHER_LOCK).count();
            assert_eq!(placed, 0, "no question was placed");
        }
        // Someone watching, nobody answering: the deadline, then a refusal.
        let _w = hold_watch(d);
        let e = ask("dev", "work", "x", 1, &keep).unwrap_err();
        assert!(e.contains("no answer") && e.shown, "{e}");
        let left: Vec<_> = std::fs::read_dir(d).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left, vec![std::ffi::OsString::from(WATCHER_LOCK)], "the unanswered question is withdrawn");
        std::env::set_var("KRYPTIK_CONSENT_DIR", d.join("absent"));
        let e = ask("dev", "work", "x", 1, &keep).unwrap_err();
        assert!(e.contains("no consent channel") && !e.shown, "{e}");
    });
}

#[test]
fn vanished_sender_withdraws_question() {
    let _g = env_lock();
    with_dir(|d| {
        std::env::set_var("KRYPTIK_CONSENT_DIR", d);
        std::env::set_var("KRYPTIK_CONSENT_TIMEOUT", "10");
        let _w = hold_watch(d);
        // There for the first two turns, then gone; no answer ever comes.
        let turns = std::cell::Cell::new(0u32);
        let gone_soon = || {
            turns.set(turns.get() + 1);
            turns.get() <= 2
        };
        let t = Instant::now();
        let e = ask("dev", "work", "x", 1, &gone_soon).unwrap_err();
        assert!(e.contains("went away") && e.contains("withdrawn"), "{e}");
        assert!(t.elapsed() < Duration::from_secs(5), "withdrawn on the asker's turn, not at the deadline");
        let left: Vec<_> = std::fs::read_dir(d).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left, vec![std::ffi::OsString::from(WATCHER_LOCK)], "the withdrawn question is gone from the chrome");
    });
}

/// A group member plants symlinks and a ready "yes" under the pid-counter
/// names: root must not write through them or believe the answer.
#[test]
fn planted_names_are_ignored() {
    use std::os::unix::fs::symlink;
    let _g = env_lock();
    with_dir(|d| {
        std::env::set_var("KRYPTIK_CONSENT_DIR", d);
        std::env::set_var("KRYPTIK_CONSENT_TIMEOUT", "1");
        let _w = hold_watch(d);
        let victim = std::env::temp_dir().join(format!("kryptik-consent-victim-{}", std::process::id()));
        std::fs::write(&victim, "precious\n").unwrap();
        let guess = format!("{}-{}", std::process::id(), COUNTER.load(Ordering::SeqCst));
        symlink(&victim, d.join(format!("{guess}.ask.tmp"))).unwrap();
        symlink(&victim, d.join(format!("{guess}.tmp"))).unwrap();
        symlink(&victim, d.join(format!("{guess}.ask"))).unwrap();
        std::fs::write(d.join(format!("{guess}.answer")), "yes\n").unwrap();
        let r = ask("dev", "work", "x", 1, &keep);
        let victim_now = std::fs::read_to_string(&victim).unwrap();
        let _ = std::fs::remove_file(&victim);
        assert_eq!(victim_now, "precious\n", "the question was written through a planted symlink");
        let e = r.unwrap_err();
        assert!(e.contains("no answer"), "a planted answer was believed, or the question was never asked: {e}");
    });
}

/// A FIFO at the answer's name must not hang the broker, and a symlink to
/// a "yes" must not be followed.
#[test]
fn non_file_answer_refused_promptly() {
    use std::os::unix::fs::symlink;
    let _g = env_lock();
    with_dir(|d| {
        std::env::set_var("KRYPTIK_CONSENT_DIR", d);
        std::env::set_var("KRYPTIK_CONSENT_TIMEOUT", "10");
        let _w = hold_watch(d);
        let yes = d.join("says-yes");
        std::fs::write(&yes, "yes\n").unwrap();
        for kind in ["fifo", "symlink"] {
            let (dd, yy) = (d.to_path_buf(), yes.clone());
            let planter = std::thread::spawn(move || {
                let (id, _) = wait_for_question(&dd);
                let answer = dd.join(format!("{id}.answer"));
                if kind == "fifo" {
                    let c = CString::new(answer.to_string_lossy().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
                } else {
                    symlink(&yy, &answer).unwrap();
                }
            });
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(ask("dev", "work", "x", 1, &keep));
            });
            let r = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_else(|_| panic!("{kind}: the broker never came back - a {kind} at the answer's name held it"));
            planter.join().unwrap();
            let e = r.unwrap_err();
            assert!(e.contains("not a plain file") && e.contains("refusal"), "{kind}: {e}");
        }
        let _ = std::fs::remove_file(&yes);
        let left: Vec<_> = std::fs::read_dir(d).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left, vec![std::ffi::OsString::from(WATCHER_LOCK)], "the questions and their bad answers are cleaned up");
    });
}
