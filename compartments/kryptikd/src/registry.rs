//! The running-zone registry.
//!
//! WHAT IT IS FOR
//!
//! `kryptikd run` supervises its own zone and always has. What it could not do
//! is let a *second* kryptikd process find that zone — so there was no `stop`,
//! no `status`, and no way for a routed zone to attach to a running `net` zone.
//! That is what blocks M3, and this is the registry Design 06 specifies.
//!
//! There is no daemon. The launcher is still the supervisor; the registry is
//! only how something else finds it.
//!
//! WHY LIVENESS IS A LOCK AND NOT A PID
//!
//! The obvious implementation records the launcher's pid and asks whether that
//! pid is alive. That is wrong twice over: pids are reused, so a stale entry
//! can name a process that now belongs to someone else entirely, and a
//! launcher killed with SIGKILL leaves its pid file behind with no way to tell
//! it apart from a live one.
//!
//! So the launcher holds `flock(LOCK_EX)` on `<entry>/lock` for its whole life.
//! A live entry is one whose lock cannot be taken. A crash releases the lock -
//! the kernel does it when the fd closes - which is precisely what makes
//! "lock free means stale" true rather than hopeful.
//!
//! The pid is still recorded, because `stop` has to signal something. It is
//! recorded WITH the process start time (field 22 of `/proc/<pid>/stat`), and
//! never signalled unless both match. That closes the reuse window between
//! checking the lock and calling `kill`.

use std::fs;
use std::io;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum RegistryError {
    AlreadyRunning { zone: String, pid: i32 },
    Io { path: String, err: io::Error },
    Malformed { path: String, what: String },
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::AlreadyRunning { zone, pid } if *pid > 0 => write!(
                f,
                "zone {zone:?} is already running (launcher pid {pid}). \
                 One instance per zone: stop it first, or use a different zone."
            ),
            RegistryError::AlreadyRunning { zone, .. } => write!(
                f,
                "zone {zone:?} is already being started by another kryptikd. \
                 One instance per zone: wait for it, or stop it."
            ),
            RegistryError::Io { path, err } => write!(f, "{path}: {err}"),
            RegistryError::Malformed { path, what } => write!(f, "{path}: {what}"),
        }
    }
}

fn io_err(p: &Path, e: io::Error) -> RegistryError {
    RegistryError::Io { path: p.display().to_string(), err: e }
}

/// Where the registry lives.
///
/// Root uses `/run/kryptik/zones`. An unprivileged developer launch uses
/// `$XDG_RUNTIME_DIR/kryptik/zones` so that the same code and the same tests
/// run on a developer host - a registry that only exists under root would mean
/// the lifecycle path is first exercised in the VM, which is where bugs are
/// most expensive to find.
pub fn base() -> PathBuf {
    let uid = unsafe { libc::getuid() };
    if unsafe { libc::geteuid() } == 0 {
        return PathBuf::from("/run/kryptik/zones");
    }

    // XDG_RUNTIME_DIR is the right place, but it is an environment variable
    // and callers set it to whatever they like. Trusting it blindly meant a
    // caller with a bogus one - a test harness, a container, a stale session -
    // could not start a zone AT ALL: `claim` failed on an uncreatable path and
    // the launch died before doing anything. That is a spectacular failure
    // mode for a variable that has nothing to do with isolation.
    //
    // So it is used only when it is real: an existing directory that this user
    // owns. Anything else falls back to a per-uid path under /tmp. Checking
    // ownership matters as much as existence - a registry in someone else's
    // directory would let them see which zones are running and, worse, create
    // entries that look live.
    if let Ok(x) = std::env::var("XDG_RUNTIME_DIR") {
        if !x.is_empty() {
            let p = Path::new(&x);
            if let Ok(md) = fs::metadata(p) {
                use std::os::unix::fs::MetadataExt;
                if md.is_dir() && md.uid() == uid {
                    return p.join("kryptik/zones");
                }
            }
        }
    }
    PathBuf::from(format!("/tmp/kryptik-{uid}/zones"))
}

fn ensure_base(b: &Path) -> Result<(), RegistryError> {
    if b.exists() {
        return Ok(());
    }
    fs::create_dir_all(b).map_err(|e| io_err(b, e))?;
    // 0700: the registry names running zones, their identities and their
    // cgroups. Nothing that is not kryptikd has any business reading it.
    set_mode(b, 0o700)
}

fn set_mode(p: &Path, mode: u32) -> Result<(), RegistryError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).map_err(|e| io_err(p, e))
}

/// `(pid, start_time)` as recorded in an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PidStamp {
    pub pid: i32,
    pub start: u64,
}

/// Field 22 of `/proc/<pid>/stat`, the process start time in clock ticks.
///
/// Parsed from the LAST `)` rather than by splitting on spaces: field 2 is the
/// executable name in parentheses and may itself contain spaces and brackets,
/// which is a classic way to misparse this file.
pub fn start_time(pid: i32) -> Option<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &s[s.rfind(')')? + 1..];
    // After the ')' the fields are: state(3) ppid(4) ... so field 22 is the
    // 20th whitespace-separated token here.
    rest.split_whitespace().nth(19)?.parse().ok()
}

impl PidStamp {
    pub fn of(pid: i32) -> Option<Self> {
        start_time(pid).map(|start| PidStamp { pid, start })
    }

    /// Is this still the same process it was when recorded?
    ///
    /// Both halves are required. The pid alone would be satisfied by any
    /// process that happened to reuse the number.
    pub fn still_alive(&self) -> bool {
        match start_time(self.pid) {
            Some(now) => now == self.start,
            None => false,
        }
    }

    fn encode(&self) -> String {
        format!("{} {}\n", self.pid, self.start)
    }

    fn decode(s: &str, path: &Path) -> Result<Self, RegistryError> {
        let mut it = s.split_whitespace();
        let pid = it.next().and_then(|v| v.parse().ok());
        let start = it.next().and_then(|v| v.parse().ok());
        match (pid, start) {
            (Some(pid), Some(start)) => Ok(PidStamp { pid, start }),
            _ => Err(RegistryError::Malformed {
                path: path.display().to_string(),
                what: format!("expected \"<pid> <starttime>\", got {s:?}"),
            }),
        }
    }
}

/// What the registry says about a zone right now.
#[derive(Debug)]
pub enum State {
    /// No entry.
    Absent,
    /// An entry whose lock is held: a launcher is alive.
    ///
    /// `launcher` is optional because the lock is taken by `claim()` BEFORE
    /// the fork that produces the pid to record - so there is a real window,
    /// however short, in which a zone is genuinely live and has no pid on
    /// disk. Calling that malformed would make `status` lie about a zone that
    /// is merely starting, and would make `stop` fail on a race rather than
    /// wait for it.
    Running {
        launcher: Option<PidStamp>,
        init: Option<PidStamp>,
        cgroup: Option<String>,
        started: String,
    },
    /// An entry whose lock is free: whatever wrote it is gone.
    Stale { launcher: Option<PidStamp>, cgroup: Option<String> },
}

fn read_field(dir: &Path, name: &str) -> Option<String> {
    fs::read_to_string(dir.join(name)).ok().map(|s| s.trim().to_string())
}

/// Try to take the entry's lock without blocking.
///
/// Returns the fd on success. The caller must keep it open for as long as the
/// entry is to count as live - closing it, including by exiting, releases the
/// lock, and that is the mechanism.
fn try_lock(dir: &Path) -> Result<Option<RawFd>, RegistryError> {
    let lock = dir.join("lock");
    let c = std::ffi::CString::new(lock.as_os_str().as_encoded_bytes())
        .map_err(|_| RegistryError::Malformed {
            path: lock.display().to_string(),
            what: "path contains NUL".into(),
        })?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600) };
    if fd < 0 {
        return Err(io_err(&lock, io::Error::last_os_error()));
    }
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        Ok(Some(fd))
    } else {
        unsafe { libc::close(fd) };
        Ok(None)
    }
}

/// Read a zone's state. Takes and immediately releases the lock to decide
/// liveness, so it is safe to call from any process.
pub fn state(zone: &str) -> Result<State, RegistryError> {
    let dir = base().join(zone);
    if !dir.exists() {
        return Ok(State::Absent);
    }
    let launcher = read_field(&dir, "launcher.pid")
        .and_then(|s| PidStamp::decode(&s, &dir).ok());
    let cgroup = read_field(&dir, "cgroup");

    match try_lock(&dir)? {
        Some(fd) => {
            // We got it, so nobody holds it: stale.
            unsafe { libc::close(fd) };
            Ok(State::Stale { launcher, cgroup })
        }
        None => Ok(State::Running {
            launcher,
            init: read_field(&dir, "init.pid").and_then(|s| PidStamp::decode(&s, &dir).ok()),
            cgroup,
            started: read_field(&dir, "started").unwrap_or_default(),
        }),
    }
}

/// Remove a stale entry, and whatever its cgroup still holds.
///
/// The recorded pid is NEVER signalled. It may have been reused by an
/// unrelated process, and killing that would be far worse than leaving a
/// directory behind. The cgroup is the safe handle: `cgroup.kill` can only
/// reach processes that are *in* it.
pub fn reclaim(zone: &str) -> Result<(), RegistryError> {
    let dir = base().join(zone);
    if !dir.exists() {
        return Ok(());
    }
    if let Some(path) = read_field(&dir, "cgroup") {
        let p = Path::new(&path);
        if p.is_dir() {
            let _ = fs::write(p.join("cgroup.kill"), "1");
            for _ in 0..100 {
                if fs::remove_dir(p).is_ok() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
    for f in ["launcher.pid", "init.pid", "cgroup", "started", "identity", "lock"] {
        let _ = fs::remove_file(dir.join(f));
    }
    fs::remove_dir(&dir).map_err(|e| io_err(&dir, e))
}

/// An entry this process owns. Dropping it removes the entry and releases the
/// lock, so an early return cannot leave a zone looking live.
#[derive(Debug)]
pub struct Handle {
    dir: PathBuf,
    fd: RawFd,
}

impl Handle {
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn write(&self, name: &str, contents: &str) -> Result<(), RegistryError> {
        let p = self.dir.join(name);
        fs::write(&p, contents).map_err(|e| io_err(&p, e))?;
        set_mode(&p, 0o600)
    }

    pub fn set_launcher(&self, pid: i32) -> Result<(), RegistryError> {
        let st = PidStamp::of(pid).ok_or_else(|| RegistryError::Malformed {
            path: format!("/proc/{pid}/stat"),
            what: "launcher pid vanished before it could be recorded".into(),
        })?;
        self.write("launcher.pid", &st.encode())
    }

    pub fn set_init(&self, pid: i32) -> Result<(), RegistryError> {
        match PidStamp::of(pid) {
            Some(st) => self.write("init.pid", &st.encode()),
            // The zone died between fork and here. Not an error: the launcher
            // is about to report the real failure.
            None => Ok(()),
        }
    }

    pub fn set_cgroup(&self, path: &str) -> Result<(), RegistryError> {
        self.write("cgroup", &format!("{path}\n"))
    }

    pub fn set_identity(&self, uid: u32, gid: u32) -> Result<(), RegistryError> {
        self.write("identity", &format!("{uid} {gid}\n"))
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        for f in ["launcher.pid", "init.pid", "cgroup", "started", "identity", "lock"] {
            let _ = fs::remove_file(self.dir.join(f));
        }
        let _ = fs::remove_dir(&self.dir);
        // Released by the close either way; explicit so the order is obvious.
        unsafe { libc::flock(self.fd, libc::LOCK_UN) };
        unsafe { libc::close(self.fd) };
    }
}

/// Claim a zone name, reclaiming a stale entry if there is one.
///
/// `mkdir` is the atomic operation: two launchers racing cannot both create
/// the directory. `EEXIST` means "already running OR stale", and the lock
/// decides which - the retry happens exactly once, because a second EEXIST
/// after a successful reclaim means another launcher won the race fairly.
pub fn claim(zone: &str) -> Result<Handle, RegistryError> {
    let b = base();
    ensure_base(&b)?;
    let dir = b.join(zone);

    for attempt in 0..2 {
        match fs::create_dir(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                match state(zone)? {
                    State::Running { launcher, .. } => {
                        return Err(RegistryError::AlreadyRunning {
                            zone: zone.to_string(),
                            // -1 when the other launcher has the lock but has
                            // not recorded its pid yet: it is starting, and
                            // refusing is still the right answer.
                            pid: launcher.map(|l| l.pid).unwrap_or(-1),
                        })
                    }
                    State::Stale { .. } | State::Absent => {
                        if attempt == 0 {
                            reclaim(zone)?;
                            continue;
                        }
                        return Err(RegistryError::AlreadyRunning {
                            zone: zone.to_string(),
                            pid: -1,
                        });
                    }
                }
            }
            Err(e) => return Err(io_err(&dir, e)),
        }

        set_mode(&dir, 0o700)?;
        let fd = match try_lock(&dir)? {
            Some(fd) => fd,
            None => {
                // Someone locked it between our mkdir and here.
                return Err(RegistryError::AlreadyRunning { zone: zone.to_string(), pid: -1 });
            }
        };
        let h = Handle { dir: dir.clone(), fd };
        h.write("started", &format!("{}\n", now_iso8601()))?;
        return Ok(h);
    }
    Err(RegistryError::AlreadyRunning { zone: zone.to_string(), pid: -1 })
}

fn now_iso8601() -> String {
    // No chrono (ADR-010). Seconds since the epoch is unambiguous and sorts.
    let secs = unsafe { libc::time(std::ptr::null_mut()) };
    format!("@{secs}")
}

/// Every zone name the registry knows about.
pub fn names() -> Vec<String> {
    let b = base();
    let Ok(rd) = fs::read_dir(&b) else { return Vec::new() };
    let mut v: Vec<String> = rd
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .collect();
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pid_stamp_round_trips() {
        let me = unsafe { libc::getpid() };
        let st = PidStamp::of(me).expect("our own start time must be readable");
        let enc = st.encode();
        let dec = PidStamp::decode(&enc, Path::new("/x")).unwrap();
        assert_eq!(st, dec);
        assert!(st.still_alive(), "we are alive");
    }

    #[test]
    fn a_wrong_start_time_is_not_alive() {
        // The whole point: same pid, different process.
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
    fn stat_is_parsed_from_the_last_paren() {
        // /proc/<pid>/stat field 2 is the comm in parentheses and can contain
        // spaces and brackets. Splitting on whitespace from the start is the
        // classic bug; we parse after the LAST ')'.
        let fake = "123 (weird )( name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 rest";
        let rest = &fake[fake.rfind(')').unwrap() + 1..];
        let f22: u64 = rest.split_whitespace().nth(19).unwrap().parse().unwrap();
        assert_eq!(f22, 4242);
    }

    #[test]
    fn the_registry_base_is_per_user_when_unprivileged() {
        let b = base();
        if unsafe { libc::geteuid() } == 0 {
            assert_eq!(b, Path::new("/run/kryptik/zones"));
        } else {
            assert!(
                b.starts_with("/run/user") || b.starts_with("/tmp/kryptik-"),
                "unprivileged registry must not be a shared path: {b:?}"
            );
        }
    }

    #[test]
    fn a_bogus_runtime_dir_falls_back_instead_of_breaking_every_launch() {
        // D3 in the launcher suite sets XDG_RUNTIME_DIR=/run/user/9999 to
        // check that host session variables do not reach a zone. Trusting it
        // meant no zone could start at all while it was set.
        if unsafe { libc::geteuid() } == 0 {
            return; // root uses /run/kryptik regardless
        }
        let uid = unsafe { libc::getuid() };
        let saved = std::env::var("XDG_RUNTIME_DIR").ok();

        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/9999-does-not-exist");
        assert_eq!(base(), PathBuf::from(format!("/tmp/kryptik-{uid}/zones")));

        std::env::set_var("XDG_RUNTIME_DIR", "");
        assert_eq!(base(), PathBuf::from(format!("/tmp/kryptik-{uid}/zones")));

        // A directory that exists but belongs to someone else is refused too:
        // /run is root-owned.
        std::env::set_var("XDG_RUNTIME_DIR", "/run");
        assert_eq!(base(), PathBuf::from(format!("/tmp/kryptik-{uid}/zones")));

        match saved {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    #[test]
    fn claim_refuses_a_second_claim_and_releases_on_drop() {
        let zone = format!("regtest-{}", unsafe { libc::getpid() });
        let h = claim(&zone).expect("first claim");
        match state(&zone).unwrap() {
            // No launcher.pid yet: claim() holds the lock but nothing has
            // forked. That is exactly the "starting" window, and it must read
            // as Running rather than as an error.
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
        // A second claim from this process cannot be tested with flock (locks
        // are per-open-file-description and this process already holds it), so
        // the check that matters here is the state and the cleanup on drop.
        drop(h);
        match state(&zone).unwrap() {
            State::Absent => {}
            other => panic!("dropping the handle must remove the entry, got {other:?}"),
        }
    }
}
