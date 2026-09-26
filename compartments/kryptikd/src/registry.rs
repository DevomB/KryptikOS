//! The running-zone registry (docs/design/zone-registry.md): how another
//! kryptikd finds a running zone. There is no daemon; the launcher supervises.
//!
//! Liveness is a lock, not a pid: a launcher holds `flock(LOCK_EX)` on
//! `<entry>/lock` for its whole life, and the kernel releases it when the
//! launcher dies. The recorded pid carries its start time (field 22 of
//! `/proc/<pid>/stat`) and is never signalled unless both match.

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

/// Where the registry lives: `/run/kryptik/zones` for root, otherwise under the
/// user's runtime directory (`base_for`), so the same code and tests run
/// unprivileged on a developer host.
pub fn base() -> PathBuf {
    base_for(
        unsafe { libc::getuid() },
        unsafe { libc::geteuid() },
        std::env::var("XDG_RUNTIME_DIR").ok().as_deref(),
    )
}

/// `base()` as a function of its inputs, testable without touching the environment.
pub fn base_for(uid: u32, euid: u32, xdg_runtime_dir: Option<&str>) -> PathBuf {
    if euid == 0 {
        return PathBuf::from("/run/kryptik/zones");
    }

    /* XDG_RUNTIME_DIR only if it is an existing directory this user owns: a
     * bogus one must not stop every launch, and one owned by someone else
     * would let them read and forge entries. Otherwise a per-uid /tmp path. */
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

/// Create the registry base, or check that the one already there is ours. Any
/// local user can plant the /tmp fallback first, so a directory we would not
/// have created is refused, never adopted by chown or chmod.
fn ensure_base(b: &Path) -> Result<(), RegistryError> {
    // The parent too: owning `/tmp/kryptik-<uid>` is enough to replace `zones`.
    if let Some(parent) = b.parent() {
        if parent != Path::new("/") && !parent.as_os_str().is_empty() {
            check_or_create(parent)?;
        }
    }
    check_or_create(b)
}

/// Create one directory 0700, or vet the one already there (`check_existing`).
fn check_or_create(p: &Path) -> Result<(), RegistryError> {
    use std::os::unix::fs::DirBuilderExt;

    /* symlink_metadata, not metadata: a symlink to a directory we own would
     * pass every check below and could still be re-aimed. */
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut db = fs::DirBuilder::new();
            db.mode(0o700);
            // Not recursive: each level gets 0700 from its own call.
            match db.create(p) {
                Ok(()) => Ok(()),
                // Another kryptikd created it since the lookup: vet it as existing.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => match fs::symlink_metadata(p) {
                    Ok(md) => check_existing(p, &md),
                    Err(e) => Err(io_err(p, e)),
                },
                Err(e) => Err(io_err(p, e)),
            }
        }
        Err(e) => Err(io_err(p, e)),
        Ok(md) => check_existing(p, &md),
    }
}

/// Refuse an existing path unless it is a real directory, ours, and writable by
/// no one else; tighten it to 0700 if it is only too readable.
fn check_existing(p: &Path, md: &fs::Metadata) -> Result<(), RegistryError> {
    use std::os::unix::fs::MetadataExt;
    let me = unsafe { libc::getuid() };
    let mode = md.mode() & 0o777;

    let refuse = if md.file_type().is_symlink() {
        Some("it is a symlink, and a symlink can be re-aimed after this check".to_string())
    } else if !md.is_dir() {
        Some("it is not a directory".to_string())
    } else if md.uid() != me {
        Some(format!("it is owned by uid {}, not by uid {me}", md.uid()))
    } else if mode & 0o022 != 0 {
        // Tightening it would not undo what was placed inside while it was open.
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

    /* Only too readable (0755, say): it leaks what this user runs but is no
     * foothold. Safe to repair, since the uid check has already excluded a
     * directory someone else planted. */
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

/// Field 22 of `/proc/<pid>/stat`, the start time in clock ticks. Parsed after
/// the last `)`, since field 2 (the name) may contain spaces and parentheses.
pub fn start_time(pid: i32) -> Option<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &s[s.rfind(')')? + 1..];
    // After the ')' come state (3), ppid (4), ...: field 22 is token 20.
    rest.split_whitespace().nth(19)?.parse().ok()
}

impl PidStamp {
    pub fn of(pid: i32) -> Option<Self> {
        start_time(pid).map(|start| PidStamp { pid, start })
    }

    /// Is this still the recorded process? The pid alone may have been reused.
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
    /// An entry whose lock is held: a launcher is alive. `launcher` is `None`
    /// while it starts, since `claim()` locks before the fork that makes the pid.
    Running {
        launcher: Option<PidStamp>,
        init: Option<PidStamp>,
        cgroup: Option<String>,
        started: String,
    },
    /// An entry whose lock is free: whatever wrote it is gone.
    Stale { launcher: Option<PidStamp>, cgroup: Option<String> },
}

/// Remove an entry and everything in it, found by listing the directory, so a
/// broker's stranded temporary file goes too. The caller holds the entry's lock.
fn sweep(dir: &Path) -> Result<(), RegistryError> {
    /* A privileged launch bind-mounts the Wayland proxy socket into the entry
     * (spawn.rs, StagedSocket), and a dead launcher can leave the mount. Detach
     * until the path is no mountpoint: each detach removes only the topmost. */
    let wl = dir.join(crate::rootfs::WAYLAND_SOCKET_NAME);
    if let Ok(c) = std::ffi::CString::new(wl.display().to_string()) {
        while unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) } == 0 {}
    }
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io_err(dir, e)),
    };
    for e in rd.flatten() {
        // The entry's own type, not what a symlink would point at.
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let p = e.path();
        let _ = if is_dir { fs::remove_dir(&p) } else { fs::remove_file(&p) };
    }
    match fs::remove_dir(dir) {
        Ok(()) => Ok(()),
        // Another reclaim finished first.
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err(dir, e)),
    }
}

fn read_field(dir: &Path, name: &str) -> Option<String> {
    // Trimmed in place, without a second String: `stop` polls `state` up to 160 times.
    fs::read_to_string(dir.join(name)).ok().map(|mut s| {
        let end = s.trim_end().len();
        s.truncate(end);
        let lead = s.len() - s.trim_start().len();
        if lead > 0 {
            s.drain(..lead);
        }
        s
    })
}

/// Open the entry's lock file, creating it only for an owner (`claim`,
/// `reclaim`), never for a probe. `None` if there is no file or no directory.
fn open_lock(dir: &Path, create: bool) -> Result<Option<RawFd>, RegistryError> {
    let lock = dir.join("lock");
    let c = std::ffi::CString::new(lock.as_os_str().as_encoded_bytes())
        .map_err(|_| RegistryError::Malformed {
            path: lock.display().to_string(),
            what: "path contains NUL".into(),
        })?;
    let flags = libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | if create { libc::O_CREAT } else { 0 };
    let fd = unsafe { libc::open(c.as_ptr(), flags, 0o600) };
    if fd < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(io_err(&lock, e));
    }
    Ok(Some(fd))
}

/// Whether `fd` is still the lock file `path` names. A reclaim unlinks the lock
/// it holds before releasing it, so a racing open can lock an orphaned inode.
fn same_inode(fd: RawFd, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(md) = fs::symlink_metadata(path) else { return false };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    rc == 0 && st.st_ino == md.ino() && st.st_dev == md.dev()
}

enum Lock {
    /// Held while the fd stays open; closing it, or exiting, releases the lock.
    Held(RawFd),
    /// A launcher holds it, or a probe is passing through.
    Busy,
    /// The entry went away under the open: a reclaim finished first.
    Gone,
}

/// Take the entry's lock without blocking, for an owner.
fn try_lock(dir: &Path) -> Result<Lock, RegistryError> {
    let Some(fd) = open_lock(dir, true)? else { return Ok(Lock::Gone) };
    if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        unsafe { libc::close(fd) };
        return Ok(Lock::Busy);
    }
    if !same_inode(fd, &dir.join("lock")) {
        unsafe { libc::close(fd) };
        return Ok(Lock::Gone);
    }
    Ok(Lock::Held(fd))
}

/// `try_lock`, waiting out a probe's instant on the shared lock (`held`). A
/// launcher holds its lock for its whole life, so Busy after 100 ms is one.
fn lock_owner(dir: &Path) -> Result<Lock, RegistryError> {
    let mut lock = try_lock(dir)?;
    for _ in 0..20 {
        if !matches!(lock, Lock::Busy) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
        lock = try_lock(dir)?;
    }
    Ok(lock)
}

/// Whether a launcher holds the entry's lock: a shared non-blocking lock is
/// refused exactly when one does. A probe creates nothing and takes nothing
/// exclusive. No lock file (mid-claim or mid-reclaim) means not held.
fn held(dir: &Path) -> Result<bool, RegistryError> {
    let Some(fd) = open_lock(dir, false)? else { return Ok(false) };
    let rc = unsafe { libc::flock(fd, libc::LOCK_SH | libc::LOCK_NB) };
    unsafe { libc::close(fd) };
    Ok(rc != 0)
}

/// A zone's entry directory, for zone 0 acting on a running zone (the
/// clipboard move). The entry belongs to its launcher.
pub fn entry_dir(zone: &str) -> PathBuf {
    base().join(zone)
}

/// Read a zone's state. The lock probe creates and holds nothing, so any
/// process may call this at any time.
pub fn state(zone: &str) -> Result<State, RegistryError> {
    let dir = base().join(zone);
    if !dir.exists() {
        return Ok(State::Absent);
    }
    let launcher = read_field(&dir, "launcher.pid")
        .and_then(|s| PidStamp::decode(&s, &dir).ok());
    let cgroup = read_field(&dir, "cgroup");

    if held(&dir)? {
        Ok(State::Running {
            launcher,
            init: read_field(&dir, "init.pid").and_then(|s| PidStamp::decode(&s, &dir).ok()),
            cgroup,
            started: read_field(&dir, "started").unwrap_or_default(),
        })
    } else {
        Ok(State::Stale { launcher, cgroup })
    }
}

/// Remove a stale entry, and kill whatever its cgroup still holds. The recorded
/// pid is never signalled, since it may have been reused; `cgroup.kill` reaches
/// only processes in the cgroup.
pub fn reclaim(zone: &str) -> Result<(), RegistryError> {
    let dir = base().join(zone);
    if !dir.exists() {
        return Ok(());
    }
    /* Hold the lock for the sweep (docs/design/zone-registry.md): a launcher
     * that claimed the name since the caller looked keeps its entry. */
    let fd = match lock_owner(&dir)? {
        Lock::Held(fd) => fd,
        Lock::Busy => return Err(RegistryError::AlreadyRunning { zone: zone.to_string(), pid: -1 }),
        Lock::Gone => return Ok(()),
    };
    let r = reclaim_locked(&dir, zone);
    unsafe { libc::close(fd) };
    r
}

fn reclaim_locked(dir: &Path, zone: &str) -> Result<(), RegistryError> {
    if let Some(path) = read_field(dir, "cgroup") {
        let p = Path::new(&path);
        /* Only inside kryptikd's own cgroup tree: a malformed or planted entry
         * must not aim cgroup.kill at, say, /sys/fs/cgroup/user.slice. */
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
    sweep(dir)
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

    /// Write one entry field: O_NOFOLLOW, so a planted symlink cannot aim the
    /// truncating write, and 0600 from creation. Backs up `ensure_base`.
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
        // .mode() applies only at creation; set it on an existing file too.
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
            // The zone already died; the launcher reports the real failure.
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
        let _ = sweep(&self.dir);
        // Released by the close either way; explicit so the order is obvious.
        unsafe { libc::flock(self.fd, libc::LOCK_UN) };
        unsafe { libc::close(self.fd) };
    }
}

/// Claim a zone name, reclaiming a stale entry if there is one. `mkdir` is the
/// atomic step; on EEXIST the lock tells running from stale, and a stale entry
/// is reclaimed once: EEXIST after that means another launcher won.
pub fn claim(zone: &str) -> Result<Handle, RegistryError> {
    let b = base();
    ensure_base(&b)?;
    let dir = b.join(zone);

    for attempt in 0..3 {
        match fs::create_dir(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                match state(zone)? {
                    /* Another launcher is between its lock and its fork: give
                     * it 50 ms once, then refuse. */
                    State::Running { launcher: None, .. } if attempt == 0 => {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        continue;
                    }
                    State::Running { launcher, .. } => {
                        return Err(RegistryError::AlreadyRunning {
                            zone: zone.to_string(),
                            // -1: locked, but no pid recorded yet.
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
        // A reclaim may have taken the fresh, unlocked directory: start over.
        match lock_owner(&dir)? {
            Lock::Held(fd) => {
                let h = Handle { dir: dir.clone(), fd };
                h.write("started", &format!("{}\n", epoch_stamp()))?;
                return Ok(h);
            }
            Lock::Busy => return Err(RegistryError::AlreadyRunning { zone: zone.to_string(), pid: -1 }),
            Lock::Gone => continue,
        }
    }
    Err(RegistryError::AlreadyRunning { zone: zone.to_string(), pid: -1 })
}

fn epoch_stamp() -> String {
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
    fn pid_stamp_round_trips() {
        let me = unsafe { libc::getpid() };
        let st = PidStamp::of(me).expect("our own start time must be readable");
        let enc = st.encode();
        let dec = PidStamp::decode(&enc, Path::new("/x")).unwrap();
        assert_eq!(st, dec);
        assert!(st.still_alive(), "we are alive");
    }

    #[test]
    fn wrong_start_time_is_not_alive() {
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
            /* As text: Path::starts_with compares whole components, and
             * "/tmp/kryptik-" is not one. */
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
        let root = std::env::temp_dir().join(format!("kryptik-f1-{}", std::process::id()));
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
        check_or_create(&readable).expect("a directory only we can write is repairable");
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
        /* flock is per open file description, so a second claim from this
         * process is refused like another launcher's. */
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
}
