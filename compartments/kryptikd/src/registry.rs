//! The running-zone registry (docs/design/zone-registry.md): how another kryptikd finds a
//! running zone. Liveness is the launcher's lifelong `flock(LOCK_EX)` on `<entry>/lock`, which
//! the kernel releases when it dies; a recorded pid counts only with its start time.

use crate::cgroup;
use std::fs;
use std::io;
use std::os::unix::io::RawFd;
use std::path::{Component, Path, PathBuf};

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
                "zone {zone:?} is already running (launcher pid {pid}); stop it first"
            ),
            RegistryError::AlreadyRunning { zone, .. } => write!(
                f,
                "zone {zone:?} is already being started by another kryptikd; wait for it, or stop it"
            ),
            RegistryError::Io { path, err } => write!(f, "{path}: {err}"),
            RegistryError::Malformed { path, what } => write!(f, "{path}: {what}"),
            RegistryError::UnsafeBase { path, why } => write!(
                f,
                "refusing to use the zone registry at {path}: {why}; remove it, \
                 or point XDG_RUNTIME_DIR at a directory you own"
            ),
        }
    }
}

fn io_err(p: &Path, e: io::Error) -> RegistryError {
    RegistryError::Io { path: p.display().to_string(), err: e }
}

/// `/run/kryptik/zones` for root; per user otherwise (`base_for`), so tests run unprivileged.
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

    /* XDG_RUNTIME_DIR only if it is a directory this user owns: a bogus one must not stop
     * every launch, and someone else's would let them read and forge entries. */
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

/// Create the registry base or vet the one there: any local user can plant the /tmp
/// fallback first, so a directory we would not have created is refused, never adopted.
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

    // symlink_metadata: a symlink to a directory we own would pass every check, then be re-aimed.
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

/// Accept only a directory of ours that no one else can write, tightening it to 0700 if needed.
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
        Some(format!("its mode is {mode:04o}: writable by others, so its contents cannot be trusted"))
    } else {
        None
    };
    if let Some(why) = refuse {
        return Err(RegistryError::UnsafeBase { path: p.display().to_string(), why });
    }

    // Only too readable (0755, say): no foothold, and ours per the uid check, so repair it.
    if mode != 0o700 {
        eprintln!(
            "kryptikd: tightening {} from {mode:04o} to 0700: the zone registry shows what you run",
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

/// Field 22 of `/proc/<pid>/stat`, the start time in clock ticks.
pub fn start_time(pid: i32) -> Option<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The name (field 2) may hold spaces and parentheses: start after the last `)`.
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
    /// The lock is held, so a launcher is alive (`launcher` is `None` while it starts).
    Running {
        launcher: Option<PidStamp>,
        init: Option<PidStamp>,
        cgroup: Option<String>,
        started: String,
    },
    /// An entry whose lock is free: whatever wrote it is gone.
    Stale { launcher: Option<PidStamp>, cgroup: Option<String> },
}

/// Remove an entry and all it holds, stranded temporaries too; the caller holds its lock.
fn sweep(dir: &Path) -> Result<(), RegistryError> {
    sweep_with(dir, &mut || {})
}

/// `sweep`, calling `between` after each removal, where a test arrives as a claimer would.
fn sweep_with(dir: &Path, between: &mut dyn FnMut()) -> Result<(), RegistryError> {
    /* A dead launcher can leave the Wayland socket's bind mount (spawn.rs, StagedSocket):
     * detach until none is left, as each detach removes only the topmost. */
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
        // The lock goes last: while it exists no claimer can take the name and remake the entry.
        if e.file_name() == "lock" {
            continue;
        }
        // The entry's own type, not what a symlink would point at.
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let p = e.path();
        let _ = if is_dir { fs::remove_dir(&p) } else { fs::remove_file(&p) };
        between();
    }
    let _ = fs::remove_file(dir.join("lock"));
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

/// Open the entry's lock file, created only for an owner, never a probe; `None` if absent.
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

/// Whether `fd` is still `path`'s inode: a racing open can lock one a reclaim has unlinked.
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

/// `try_lock`, waiting out a probe's instant on the shared lock; Busy after 100 ms is a launcher.
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

/// Whether a launcher holds the entry's lock: a shared non-blocking flock fails only then.
/// The probe creates nothing; no lock file (mid-claim or mid-reclaim) means not held.
fn held(dir: &Path) -> Result<bool, RegistryError> {
    let Some(fd) = open_lock(dir, false)? else { return Ok(false) };
    let rc = unsafe { libc::flock(fd, libc::LOCK_SH | libc::LOCK_NB) };
    unsafe { libc::close(fd) };
    Ok(rc != 0)
}

/// A zone's entry directory, for zone 0 acting on a running zone (the clipboard move).
pub fn entry_dir(zone: &str) -> PathBuf {
    base().join(zone)
}

/// Read a zone's state; any process may call this at any time.
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

/// Remove a stale entry and kill what its cgroup holds, never the recorded (maybe reused) pid.
pub fn reclaim(zone: &str) -> Result<(), RegistryError> {
    let dir = base().join(zone);
    if !dir.exists() {
        return Ok(());
    }
    // Locked for the sweep: a launcher that claimed the name since the caller looked keeps it.
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
        // Only in kryptikd's own tree: a planted entry must not aim cgroup.kill at user.slice.
        if !under(p, &cgroup::kryptik_root()) {
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

/// `p` names something below `root`. starts_with alone takes `root/../user.slice`.
fn under(p: &Path, root: &Path) -> bool {
    p.starts_with(root) && p != root && !p.components().any(|c| c == Component::ParentDir)
}

/// An entry we own; the drop removes it, so an early return cannot leave a zone looking live.
#[derive(Debug)]
pub struct Handle {
    dir: PathBuf,
    fd: RawFd,
}

impl Handle {
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Write one entry field, 0600 and O_NOFOLLOW: a planted symlink cannot aim the truncation.
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

/// Claim a zone name: `mkdir` is the atomic step, and on EEXIST the lock tells running from
/// stale. A stale entry is reclaimed once; EEXIST after that means another launcher won.
pub fn claim(zone: &str) -> Result<Handle, RegistryError> {
    let b = base();
    ensure_base(&b)?;
    let dir = b.join(zone);

    for attempt in 0..3 {
        match fs::create_dir(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                match state(zone)? {
                    // Another launcher is between its lock and its fork: give it 50 ms once.
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
mod tests;
