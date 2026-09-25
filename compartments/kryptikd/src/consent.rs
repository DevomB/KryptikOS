//! Questions for the user in zone 0, drawn by the trusted chrome: may a file
//! cross between zones (docs/design/broker.md), may the clock be set.
//!
//!   /run/kryptik-consent/<id>.ask      from=ZONE to=ZONE name=NAME bytes=N
//!   /run/kryptik-consent/<id>.answer   yes | no        (written by the chrome)
//!
//! No zone can reach the directory (root:kryptik 2770, made by sysinit), but
//! the session's group can write to it, so nothing found there is trusted.
//! Anything but a plain-file `yes` before the deadline is a refusal.

use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub const DIR: &str = "/run/kryptik-consent";
pub const TIMEOUT_SECS: u64 = 60;
/// Held exclusively by the chrome's consent watcher while it runs.
pub const WATCHER_LOCK: &str = "watcher.lock";
/// Most bytes of an answer read; the chrome writes one word.
const ANSWER_MAX: u64 = 64;

static COUNTER: AtomicU64 = AtomicU64::new(1);

/// Serializes the tests, here and in broker.rs, that set this module's environment.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// Only tests set KRYPTIK_CONSENT_DIR and KRYPTIK_CONSENT_TIMEOUT.
fn dir() -> PathBuf {
    std::env::var("KRYPTIK_CONSENT_DIR").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(DIR))
}

fn timeout() -> Duration {
    std::env::var("KRYPTIK_CONSENT_TIMEOUT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(TIMEOUT_SECS))
}

/// Open the channel directory without following a link; every later access
/// is relative to it. It must be root's (or ours) and not world-writable.
fn open_channel(d: &Path) -> Result<OwnedFd, String> {
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(d.as_os_str().as_bytes())
        .map_err(|_| format!("no consent channel at {}: the path holds a NUL byte", d.display()))?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(format!(
            "no consent channel at {}: nothing in zone 0 can approve this transfer ({})",
            d.display(),
            io::Error::last_os_error()
        ));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let st = stat_of(fd.as_raw_fd()).map_err(|e| format!("no consent channel at {}: {e}", d.display()))?;
    let me = unsafe { libc::geteuid() };
    if st.st_uid != 0 && st.st_uid != me {
        return Err(format!("no consent channel: {} belongs to uid {}, not to root; refused", d.display(), st.st_uid));
    }
    if (st.st_mode & libc::S_IWOTH) != 0 {
        return Err(format!("no consent channel: {} is writable by everyone; refused", d.display()));
    }
    Ok(fd)
}

/// Open `name` relative to the channel, never through a symlink.
fn open_entry(dfd: RawFd, name: &str, flags: libc::c_int, mode: libc::c_uint) -> io::Result<OwnedFd> {
    let c = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let fd = unsafe { libc::openat(dfd, c.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn stat_of(fd: RawFd) -> io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

fn is_regular(st: &libc::stat) -> bool {
    (st.st_mode & libc::S_IFMT) == libc::S_IFREG
}

fn unlink(dfd: RawFd, name: &str) {
    if let Ok(c) = CString::new(name) {
        unsafe { libc::unlinkat(dfd, c.as_ptr(), 0) };
    }
}

fn nonce() -> Result<u64, String> {
    let mut b = [0u8; 8];
    let n = unsafe { libc::getrandom(b.as_mut_ptr() as *mut libc::c_void, b.len(), 0) };
    if n != b.len() as isize {
        return Err(format!("consent: no randomness for the question's name: {}", io::Error::last_os_error()));
    }
    Ok(u64::from_ne_bytes(b))
}

/// Whether the chrome is watching: its lock is a plain file that someone
/// holds exclusively. O_NONBLOCK keeps a FIFO at that name from hanging us.
fn watched(dfd: RawFd) -> bool {
    let Ok(f) = open_entry(dfd, WATCHER_LOCK, libc::O_RDONLY | libc::O_NONBLOCK, 0) else { return false };
    let Ok(st) = stat_of(f.as_raw_fd()) else { return false };
    if !is_regular(&st) {
        return false;
    }
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
        return false;
    }
    io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK)
}

/// Write the question to a fresh O_EXCL temporary, skipping taken names, make
/// it group-readable for the chrome, and rename it to `<id>.ask`. The id's
/// random nonce means no answer can be waiting under it in advance.
fn place_question(dfd: RawFd, text: &str) -> Result<String, String> {
    for _ in 0..8 {
        let id = format!("{}-{}-{:016x}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst), nonce()?);
        let tmp = format!("{id}.tmp");
        let f = match open_entry(dfd, &tmp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o640) {
            Ok(f) => f,
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => continue,
            Err(e) => return Err(format!("consent: cannot write the question: {e}")),
        };
        let written = (|| -> io::Result<()> {
            if unsafe { libc::fchmod(f.as_raw_fd(), 0o640) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut file = std::fs::File::from(f);
            file.write_all(text.as_bytes())
        })();
        if let Err(e) = written {
            unlink(dfd, &tmp);
            return Err(format!("consent: cannot write the question: {e}"));
        }
        let ask = format!("{id}.ask");
        let (ct, ca) = (CString::new(tmp.as_str()).unwrap(), CString::new(ask.as_str()).unwrap());
        if unsafe { libc::renameat(dfd, ct.as_ptr(), dfd, ca.as_ptr()) } < 0 {
            let e = io::Error::last_os_error();
            unlink(dfd, &tmp);
            return Err(format!("consent: cannot place the question: {e}"));
        }
        return Ok(id);
    }
    Err("consent: cannot place the question: every name tried was already taken".into())
}

/// The answer, if there is one yet; `Err` if its name holds anything but a plain file.
fn read_answer(dfd: RawFd, name: &str) -> Result<Option<String>, String> {
    let f = match open_entry(dfd, name, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err("a symlink".into()),
        Err(e) => return Err(e.to_string()),
    };
    let st = stat_of(f.as_raw_fd()).map_err(|e| e.to_string())?;
    if !is_regular(&st) {
        return Err("not a regular file".into());
    }
    let mut buf = Vec::new();
    std::fs::File::from(f).take(ANSWER_MAX).read_to_end(&mut buf).map_err(|e| e.to_string())?;
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

/// May this file cross? `Ok(())` only on an explicit `yes`. `asking` runs ten
/// times a second while the question is open; `false` withdraws it.
pub fn ask(from: &str, to: &str, name: &str, bytes: u64, asking: &dyn Fn() -> bool) -> Result<(), String> {
    ask_text(&format!("from={from}\nto={to}\nname={name}\nbytes={bytes}\n"), asking)
}

/// For a caller with nothing to do while its question is open.
pub fn keep() -> bool {
    true
}

/// May the clock be set? Asked past the unasked bound (docs/design/time.md).
/// `kind=clock` tells the chrome which question to draw; no kind is a transfer.
pub fn ask_clock(now: &str, proposed: &str, sources: u8, asking: &dyn Fn() -> bool) -> Result<(), String> {
    ask_text(&format!("kind=clock\nnow={now}\nproposed={proposed}\nsources={sources}\n"), asking)
}

/// Ask, and wait for the answer. `Ok(())` only on an explicit `yes`.
fn ask_text(text: &str, asking: &dyn Fn() -> bool) -> Result<(), String> {
    let d = dir();
    let channel = open_channel(&d)?;
    let dfd = channel.as_raw_fd();
    if !watched(dfd) {
        return Err(format!(
            "no consent channel: nothing in zone 0 is watching {} (no trusted window to ask); \
             refused for want of consent",
            d.display()
        ));
    }
    let id = place_question(dfd, text)?;
    let ask = format!("{id}.ask");
    let answer = format!("{id}.answer");
    let deadline = Instant::now() + timeout();
    let outcome = loop {
        match read_answer(dfd, &answer) {
            Ok(Some(a)) => {
                let first = a.lines().next().unwrap_or("").trim();
                break match first {
                    "yes" => Ok(()),
                    "no" => Err("refused by the user in zone 0".to_string()),
                    other => Err(format!("consent: malformed answer {other:?}; treated as a refusal")),
                };
            }
            Ok(None) => {}
            Err(e) => break Err(format!("consent: the answer is not a plain file ({e}); treated as a refusal")),
        }
        if Instant::now() >= deadline {
            break Err(format!("no answer from zone 0 within {} s; treated as a refusal", timeout().as_secs()));
        }
        /* The asker's turn: this wait holds up its launcher's loop, which
         * relays the zone's output and notices the zone ending. */
        if !asking() {
            break Err("the asking zone went away while the question was open; withdrawn".to_string());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    unlink(dfd, &ask);
    unlink(dfd, &answer);
    outcome
}

#[cfg(test)]
mod tests {
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
            assert!(e.contains("refused by the user"), "{e}");
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
                assert!(e.contains("no consent channel") && e.contains("watching"), "{e}");
                assert!(t.elapsed() < Duration::from_millis(500), "refused without waiting for the deadline");
                let placed = std::fs::read_dir(d).unwrap().flatten().filter(|e| e.file_name() != WATCHER_LOCK).count();
                assert_eq!(placed, 0, "no question was placed");
            }
            // Someone watching, nobody answering: the deadline, then a refusal.
            let _w = hold_watch(d);
            let e = ask("dev", "work", "x", 1, &keep).unwrap_err();
            assert!(e.contains("no answer"), "{e}");
            let left: Vec<_> = std::fs::read_dir(d).unwrap().flatten().map(|e| e.file_name()).collect();
            assert_eq!(left, vec![std::ffi::OsString::from(WATCHER_LOCK)], "the unanswered question is withdrawn");
            std::env::set_var("KRYPTIK_CONSENT_DIR", d.join("absent"));
            let e = ask("dev", "work", "x", 1, &keep).unwrap_err();
            assert!(e.contains("no consent channel"), "{e}");
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
}
