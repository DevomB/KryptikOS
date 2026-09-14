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
//! Whether anyone is there to ask is a lock, not a guess: the chrome's
//! watcher holds `watcher.lock` in that directory exclusively for as long
//! as it runs, and a broker that can take the lock shared knows nobody is
//! watching and refuses at once. Without that, a transfer offered while no
//! desktop session is up waited the whole minute for a window that could
//! never open - the boundary suite measured exactly that (G12, rc 124).
//!
//! Tests point the directory and the timeout elsewhere through the
//! environment; nothing else reads those variables.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub const DIR: &str = "/run/kryptik-consent";
pub const TIMEOUT_SECS: u64 = 60;
/// Held exclusively by the chrome's consent watcher while it runs.
pub const WATCHER_LOCK: &str = "watcher.lock";

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

/// Is something in zone 0 watching the channel? True only when the watcher
/// lock exists and is held exclusively by someone else; a lock that can be
/// taken shared, or no lock file at all, means nothing would ever answer.
fn watched(d: &Path) -> bool {
    use std::os::unix::io::AsRawFd;
    let Ok(f) = std::fs::File::open(d.join(WATCHER_LOCK)) else { return false };
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
        return false;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK)
}

/// Ask, and wait for the answer. `Ok(())` only on an explicit `yes`.
pub fn ask(from: &str, to: &str, name: &str, bytes: u64) -> Result<(), String> {
    let d = dir();
    if !d.is_dir() {
        return Err(format!(
            "no consent channel at {}: nothing in zone 0 can approve this transfer",
            d.display()
        ));
    }
    if !watched(&d) {
        return Err(format!(
            "no consent channel: nothing in zone 0 is watching {} (no trusted window to ask); \
             refused for want of consent",
            d.display()
        ));
    }
    let id = format!("{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst));
    let ask = d.join(format!("{id}.ask"));
    let tmp = d.join(format!("{id}.ask.tmp"));
    let answer = d.join(format!("{id}.answer"));
    let text = format!("from={from}\nto={to}\nname={name}\nbytes={bytes}\n");
    std::fs::write(&tmp, text).map_err(|e| format!("consent: cannot write the question: {e}"))?;
    std::fs::rename(&tmp, &ask).map_err(|e| format!("consent: cannot place the question: {e}"))?;
    let deadline = Instant::now() + timeout();
    let outcome = loop {
        if let Ok(a) = std::fs::read_to_string(&answer) {
            let first = a.lines().next().unwrap_or("").trim();
            break match first {
                "yes" => Ok(()),
                "no" => Err("refused by the user in zone 0".to_string()),
                other => Err(format!("consent: malformed answer {other:?}; treated as a refusal")),
            };
        }
        if Instant::now() >= deadline {
            break Err(format!("no answer from zone 0 within {} s; treated as a refusal", timeout().as_secs()));
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let _ = std::fs::remove_file(&ask);
    let _ = std::fs::remove_file(&answer);
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

    fn answer_when_asked(d: &std::path::Path, reply: &'static str) -> std::thread::JoinHandle<String> {
        let d = d.to_path_buf();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(ask) = std::fs::read_dir(&d).unwrap().flatten().find(|e| e.path().extension().map(|x| x == "ask").unwrap_or(false)) {
                    let text = std::fs::read_to_string(ask.path()).unwrap();
                    let id = ask.path().file_stem().unwrap().to_string_lossy().to_string();
                    std::fs::write(d.join(format!("{id}.answer")), reply).unwrap();
                    return text;
                }
                assert!(Instant::now() < deadline, "no question appeared");
                std::thread::sleep(Duration::from_millis(20));
            }
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
}
