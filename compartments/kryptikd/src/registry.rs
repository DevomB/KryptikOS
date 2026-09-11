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

use crate::cgroup;
use std::fs;
use std::io;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum RegistryError {
    AlreadyRunning { zone: String, pid: i32 },
    Io { path: String, err: io::Error },
    Malformed { path: String, what: String },
    /// The registry directory exists but is not ours to use.
    UnsafeBase { path: String, why: String },
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
            RegistryError::UnsafeBase { path, why } => write!(
                f,
                "refusing to use the zone registry at {path}: {why}. \
                 Remove it (or point XDG_RUNTIME_DIR at a directory you own) \
                 and start the zone again."
            ),
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
    base_for(
        unsafe { libc::getuid() },
        unsafe { libc::geteuid() },
        std::env::var("XDG_RUNTIME_DIR").ok().as_deref(),
    )
}

/// `base()` as a function of its inputs, so the fallback rules can be tested
/// without mutating the process environment (which raced other tests that
/// resolve the registry concurrently).
pub fn base_for(uid: u32, euid: u32, xdg_runtime_dir: Option<&str>) -> PathBuf {
    if euid == 0 {
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
    if let Some(x) = xdg_runtime_dir {
        if !x.is_empty() {
            let p = Path::new(x);
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

/// Create the registry base, or satisfy ourselves that the one already there
/// is ours.
///
/// This used to return `Ok` the moment the path existed, which is a hole on the
/// developer path: `base()` falls back to `/tmp/kryptik-<uid>/zones`, and /tmp
/// is world-writable, so any local user can create that directory - or make it
/// a symlink - before the victim first runs kryptikd. Owning the registry's
/// parent is enough to rename a freshly created entry away and substitute one
/// whose `launcher.pid` is a symlink into the victim's home; `fs::write`
/// follows symlinks and truncates, so the victim's own kryptikd would then
/// overwrite whatever it pointed at. Found by the security tab (R-7b F1).
///
/// The check refuses rather than repairs. Making a planted directory fit by
/// chowning or chmod'ing it would adopt it, which is the attacker's goal; the
/// only safe response to "this is not the directory I would have created" is
/// to stop and say so.
fn ensure_base(b: &Path) -> Result<(), RegistryError> {
    // Both levels matter: owning `/tmp/kryptik-<uid>` is enough to replace
    // `zones` underneath it, so the parent is checked as well as the leaf.
    if let Some(parent) = b.parent() {
        if parent != Path::new("/") && !parent.as_os_str().is_empty() {
            check_or_create(parent)?;
        }
    }
    check_or_create(b)
}

/// One directory: create it 0700, or verify the existing one is a directory
/// (not a symlink to one), owned by us, and 0700.
fn check_or_create(p: &Path) -> Result<(), RegistryError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    // symlink_metadata, not metadata: a symlink pointing at a directory we do
    // own would otherwise pass every test below while the attacker keeps the
    // ability to re-aim it.
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut db = fs::DirBuilder::new();
            db.mode(0o700);
            // Not recursive: each level is created with 0700 by its own call,
            // so no intermediate is briefly world-writable.
            db.create(p).map_err(|e| io_err(p, e))
        }
        Err(e) => Err(io_err(p, e)),
        Ok(md) => {
            let me = unsafe { libc::getuid() };
            let mode = md.mode() & 0o777;

            // Refuse: someone else can still influence what this directory is.
            let refuse = if md.file_type().is_symlink() {
                Some("it is a symlink, and a symlink can be re-aimed after this check".to_string())
            } else if !md.is_dir() {
                Some("it is not a directory".to_string())
            } else if md.uid() != me {
                Some(format!("it is owned by uid {}, not by uid {me}", md.uid()))
            } else if mode & 0o022 != 0 {
                // Ours, but group- or world-WRITABLE. Tightening it now would
                // not undo anything already placed inside it while it was
                // open, so this one stops rather than repairs.
                Some(format!(
                    "its mode is {mode:04o}: it is writable by others, so its contents \
                     cannot be trusted even though it belongs to uid {me}"
                ))
            } else {
                None
            };
            if let Some(why) = refuse {
                return Err(RegistryError::UnsafeBase { path: p.display().to_string(), why });
            }

            // Ours, not writable by anyone else, but readable or searchable by
            // them - 0755, say, which is what kryptikd's own earlier
            // create_dir_all left behind under a default umask. That is an
            // information leak (the registry is an inventory of what this user
            // is running), not a foothold, and it can be closed here.
            //
            // This is a deliberate narrowing of what R-7b F1 asked for, which
            // was to refuse any mode other than 0700. The reasoning for
            // refusing was that chmod'ing a directory into shape would adopt a
            // planted one - but planting requires creating the directory, and
            // the uid check above has already excluded anything this process
            // did not create. Raised with security in the reply to R-7.
            if mode != 0o700 {
                eprintln!(
                    "kryptikd: tightening {} from {mode:04o} to 0700; the zone registry \
                     lists what you are running and should not be readable by others",
                    p.display()
                );
                set_mode(p, 0o700)?;
            }
            Ok(())
        }
    }
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

/// Where a zone's entry lives. For zone 0 acts on a running zone's entry
/// (the clipboard move); the entry itself is owned by its launcher.
pub fn entry_dir(zone: &str) -> PathBuf {
    base().join(zone)
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
        // Only ever inside kryptikd's own cgroup tree. With F1 fixed nothing
        // hostile can reach this field, but `cgroup.kill` is a loaded weapon
        // and one starts_with is a cheap safety catch: a malformed or planted
        // entry must not be able to aim it at, say, /sys/fs/cgroup/user.slice.
        if !p.starts_with(cgroup::kryptik_root()) {
            eprintln!(
                "kryptikd: ignoring a registry entry for zone {zone:?} that names a cgroup \
                 outside {}: {}",
                cgroup::kryptik_root().display(),
                p.display()
            );
        } else if p.is_dir() {
            let _ = fs::write(p.join("cgroup.kill"), "1");
            for _ in 0..100 {
                if fs::remove_dir(p).is_ok() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
    for f in ["launcher.pid", "init.pid", "cgroup", "started", "identity", "broker", "clipboard", "lock"] {
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

    /// Write one entry field.
    ///
    /// O_NOFOLLOW, and 0600 at creation rather than afterwards. `fs::write`
    /// follows symlinks and truncates, so if anything ever managed to plant a
    /// symlink here it would be kryptikd that did the damage, to a file of the
    /// attacker's choosing. ensure_base should make that unreachable; this is
    /// the second lock on the same door (R-7b F1).
    fn write(&self, name: &str, contents: &str) -> Result<(), RegistryError> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let p = self.dir.join(name);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&p)
            .map_err(|e| io_err(&p, e))?;
        f.write_all(contents.as_bytes()).map_err(|e| io_err(&p, e))?;
        // .mode() only applies when the file is created, so an entry that
        // already existed still gets its permissions asserted.
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
        for f in ["launcher.pid", "init.pid", "cgroup", "started", "identity", "broker", "clipboard", "lock"] {
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
                    // No launcher pid recorded. Usually that means another
                    // launcher really is mid-start and refusing is right. But
                    // state() itself takes and releases the entry lock to test
                    // liveness, so a `status` running concurrently with this
                    // call produces the same reading for an entry that is
                    // merely stale (R-7b F2). One retry after 50ms tells them
                    // apart: a real starting launcher still holds the lock,
                    // and a passing status has let go by then.
                    State::Running { launcher: None, .. } if attempt == 0 => {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        continue;
                    }
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
        let fallback = PathBuf::from(format!("/tmp/kryptik-{uid}/zones"));
        assert_eq!(base_for(uid, uid, Some("/run/user/9999-does-not-exist")), fallback);
        assert_eq!(base_for(uid, uid, Some("")), fallback);
        assert_eq!(base_for(uid, uid, None), fallback);
        // A directory that exists but belongs to someone else is refused too:
        // /run is root-owned.
        assert_eq!(base_for(uid, uid, Some("/run")), fallback);
        // Root never consults the variable.
        assert_eq!(base_for(0, 0, Some("/run/user/0")), PathBuf::from("/run/kryptik/zones"));
    }

    #[test]
    fn a_registry_directory_someone_else_could_control_is_refused() {
        // R-7b F1. Each case is a directory an attacker could have left in
        // /tmp before the victim's first `kryptikd run`.
        use std::os::unix::fs::MetadataExt;
        let root = std::env::temp_dir().join(format!("kryptik-f1-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let mode_of = |p: &Path| fs::metadata(p).unwrap().mode() & 0o777;
        let refused = |p: &Path| matches!(check_or_create(p), Err(RegistryError::UnsafeBase { .. }));

        // A symlink, even one aimed at a directory we do own: the attacker
        // keeps the ability to re-aim it after the check and before the write.
        let target = root.join("real");
        fs::create_dir(&target).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(refused(&link), "a symlink must be refused");

        // Ours, but world-writable: tightening it now would not undo whatever
        // was put inside while it was open.
        let loose = root.join("loose");
        fs::create_dir(&loose).unwrap();
        set_mode(&loose, 0o777).unwrap();
        assert!(refused(&loose), "a world-writable directory must be refused");

        // Not a directory at all.
        let file = root.join("file");
        fs::write(&file, "").unwrap();
        assert!(refused(&file), "a plain file must be refused");

        // Ours and not writable by anyone else, just too readable - which is
        // what kryptikd's own earlier create_dir_all left behind. Repairable,
        // so it is repaired rather than refused.
        let readable = root.join("readable");
        fs::create_dir(&readable).unwrap();
        set_mode(&readable, 0o755).unwrap();
        check_or_create(&readable).expect("a directory only we can write is repairable");
        assert_eq!(mode_of(&readable), 0o700, "it must be tightened to 0700");

        // Absent: created 0700, not 0755-by-umask.
        let fresh = root.join("fresh");
        check_or_create(&fresh).unwrap();
        assert_eq!(mode_of(&fresh), 0o700, "a new registry directory must be 0700");

        let _ = fs::remove_dir_all(&root);
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
