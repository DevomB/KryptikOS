//! Zone 0's answer to "may this file cross?": the person, asked by the
//! trusted chrome.
//!
//! The broker runs inside the launcher, as root, in zone 0. When a zone
//! offers a file to another zone and every policy and descriptor check has
//! passed, the last word is the user's, and the user is reached through the
//! desktop session - an ordinary user in group kryptik - which cannot be
//! called into from here. So the question is a file and the answer is a
//! file, in a directory only zone 0 and that group can see:
//!
//!   /run/kryptik-consent/<id>.ask      from=ZONE to=ZONE name=NAME bytes=N
//!   /run/kryptik-consent/<id>.answer   yes | no        (written by the chrome)
//!
//! sysinit creates the directory (root:kryptik, 2770; beside
//! /run/kryptik-launch rather than under /run/kryptik, which the registry
//! keeps 0700): no zone has a path to it (a zone's /run holds its broker
//! socket and nothing else), so nothing a zone controls can answer for the
//! user. The chrome watches for `.ask`
//! files, draws the question in its own window (unzoned border, the one
//! colour no zone can be given), and writes the answer; the broker waits a
//! bounded time and treats no answer, a malformed answer or a missing
//! directory as a refusal. `--auto-approve-transfers` (development) bypasses
//! this and says so at launch.
//!
//! The directory is shared with the session's group, and nothing found in
//! it is trusted. The broker is root: a root that wrote its question through
//! a symlink a group member had planted under the name it was about to use
//! would overwrite whatever the link points at, anywhere - the authority to
//! answer a question is not the authority to write root's files. So the
//! directory is opened once and every name is used relative to it, never
//! following a link; the question's temporary file is created O_EXCL under
//! a name that carries a random nonce, and the nonce is in the question's
//! id too, so no answer can be lying ready under a name nobody could have
//! known; and an answer that is not a plain file - a link, a FIFO that
//! would never end - is a refusal, not something to read.
//!
//! Whether anyone is there to ask is a lock, not a guess: the chrome's
//! watcher holds `watcher.lock` in that directory exclusively for as long
//! as it runs, and a broker that can take the lock shared knows nobody is
//! watching and refuses at once. Without that, a transfer offered while no
//! desktop session is up waited the whole minute for a window that could
//! never open - the boundary suite's no-consent transfer check measured
//! exactly that (it timed out, rc 124).
//!
//! Tests point the directory and the timeout elsewhere through the
//! environment; nothing else reads those variables.

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
/// An answer is one word on one line; more than this is not one the
/// chrome wrote, and is not read.
const ANSWER_MAX: u64 = 64;

static COUNTER: AtomicU64 = AtomicU64::new(1);

/// The tests here and the broker's set the environment this module reads,
/// and a process has one environment: they take turns on this. (The full
/// suite runs tests in parallel; without it a consent test could read the
/// broker test's "/nonexistent" channel and fail for a reason that is not
/// in the code under test.)
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

/// The channel directory, opened once; everything after goes through this
/// descriptor. Its name is not followed if it is a link, and it must be
/// root's (or, for a developer instance and the tests, this process's own)
/// and not writable by the world.
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

/// One name in the channel, opened relative to the directory and never
/// through a symlink. `mode` matters only with O_CREAT.
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

/// Is something in zone 0 watching the channel? True only when the watcher
/// lock is a plain file held exclusively by someone else; a lock that can
/// be taken shared, no lock file at all, or something at its name that is
/// not a file (a FIFO would hold this process at open) means nothing would
/// ever answer.
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

/// Write the question under a fresh id and place it as `<id>.ask`. The
/// temporary file is created exclusively - a name already taken, whatever
/// took it, is passed over for another - and made readable by the group,
/// which is how the chrome reads it, whatever this process's umask says.
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

/// The answer, if one is there yet. `Err` is an entry at the answer's name
/// that is not a plain file - a link, a FIFO, a directory - which nobody
/// honest wrote: it is a refusal, and it is not read.
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

/// May this file cross? `Ok(())` only on an explicit `yes`.
pub fn ask(from: &str, to: &str, name: &str, bytes: u64) -> Result<(), String> {
    ask_text(&format!("from={from}\nto={to}\nname={name}\nbytes={bytes}\n"))
}

/// May the clock be set? Asked when the network's claim is further from
/// this machine's clock than zone 0 believes without asking
/// (docs/design/time.md). The person is shown both times, because someone
/// with a watch can answer and nothing on this system can. `kind=clock`
/// tells the chrome which question to draw; a question with no kind is a
/// transfer, as every question was before this one existed.
pub fn ask_clock(now: &str, proposed: &str, sources: u8) -> Result<(), String> {
    ask_text(&format!("kind=clock\nnow={now}\nproposed={proposed}\nsources={sources}\n"))
}

/// Ask, and wait for the answer. `Ok(())` only on an explicit `yes`.
fn ask_text(text: &str) -> Result<(), String> {
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

    /// Stand in for the chrome's watcher: hold the lock for as long as the
    /// returned file lives. A flock travels with the open file into any
    /// child forked while it is held, and tests elsewhere in this binary
    /// fork helpers that outlive them - so no test here relies on the lock
    /// being RELEASED while this process runs: the "nobody watching" cases
    /// come before the lock is ever taken.
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
    fn yes_approves_no_refuses_and_the_question_names_everything() {
        let _g = env_lock();
        with_dir(|d| {
            std::env::set_var("KRYPTIK_CONSENT_DIR", d);
            std::env::set_var("KRYPTIK_CONSENT_TIMEOUT", "5");
            let _w = hold_watch(d);
            let h = answer_when_asked(d, "yes\n");
            assert!(ask("dev", "work", "report.pdf", 4096).is_ok());
            let q = h.join().unwrap();
            assert_eq!(q, "from=dev\nto=work\nname=report.pdf\nbytes=4096\n");
            let h = answer_when_asked(d, "no\n");
            let e = ask("dev", "work", "x", 1).unwrap_err();
            h.join().unwrap();
            assert!(e.contains("refused by the user"), "{e}");
            let h = answer_when_asked(d, "maybe\n");
            let e = ask("dev", "work", "x", 1).unwrap_err();
            h.join().unwrap();
            assert!(e.contains("malformed"), "{e}");
            let left: Vec<_> = std::fs::read_dir(d).unwrap().flatten().map(|e| e.file_name()).collect();
            assert_eq!(left, vec![std::ffi::OsString::from(WATCHER_LOCK)], "question and answer are cleaned up");
        });
    }

    #[test]
    fn silence_and_a_missing_channel_refuse() {
        let _g = env_lock();
        with_dir(|d| {
            std::env::set_var("KRYPTIK_CONSENT_DIR", d);
            std::env::set_var("KRYPTIK_CONSENT_TIMEOUT", "1");
            // Nobody watching: refused at once, with no question left behind
            // for a window that will never open - first with no lock file at
            // all, then with one nothing holds (a watcher that went away).
            for lock_file in [false, true] {
                if lock_file {
                    std::fs::File::create(d.join(WATCHER_LOCK)).unwrap();
                }
                let t = Instant::now();
                let e = ask("dev", "work", "x", 1).unwrap_err();
                assert!(e.contains("no consent channel") && e.contains("watching"), "{e}");
                assert!(t.elapsed() < Duration::from_millis(500), "refused without waiting for the deadline");
                let placed = std::fs::read_dir(d).unwrap().flatten().filter(|e| e.file_name() != WATCHER_LOCK).count();
                assert_eq!(placed, 0, "no question was placed");
            }
            // Someone watching, nobody answering: the deadline, then a refusal.
            let _w = hold_watch(d);
            let e = ask("dev", "work", "x", 1).unwrap_err();
            assert!(e.contains("no answer"), "{e}");
            let left: Vec<_> = std::fs::read_dir(d).unwrap().flatten().map(|e| e.file_name()).collect();
            assert_eq!(left, vec![std::ffi::OsString::from(WATCHER_LOCK)], "the unanswered question is withdrawn");
            std::env::set_var("KRYPTIK_CONSENT_DIR", d.join("absent"));
            let e = ask("dev", "work", "x", 1).unwrap_err();
            assert!(e.contains("no consent channel"), "{e}");
        });
    }

    /// The question's names used to be guessable - this process's pid and a
    /// counter - and the directory is writable by the session's group. A
    /// member of that group could plant a symlink where the question's
    /// temporary file would be written, and root wrote through it; or plant
    /// a ready "yes" where the answer would be read, and no window ever
    /// opened. Under the guessable names, both are planted here; neither
    /// may have any effect.
    #[test]
    fn what_a_group_member_plants_under_a_guessable_name_is_neither_written_through_nor_believed() {
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
            let r = ask("dev", "work", "x", 1);
            let victim_now = std::fs::read_to_string(&victim).unwrap();
            let _ = std::fs::remove_file(&victim);
            assert_eq!(victim_now, "precious\n", "the question was written through a planted symlink");
            let e = r.unwrap_err();
            assert!(e.contains("no answer"), "a planted answer was believed, or the question was never asked: {e}");
        });
    }

    /// What answers is not always the chrome. A FIFO nobody will ever write
    /// at the answer's name would hold the broker at open, past every
    /// deadline; a symlink to a file that says yes would be followed. Each
    /// is a refusal, and a prompt one.
    #[test]
    fn an_answer_that_is_not_a_plain_file_is_a_prompt_refusal() {
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
                    let _ = tx.send(ask("dev", "work", "x", 1));
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
