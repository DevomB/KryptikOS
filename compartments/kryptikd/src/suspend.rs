//! Suspend to RAM with the state partition's key dropped (docs/design/laptop.md): every zone
//! frozen, the state partition suspended with its key wiped (`cryptsetup luksSuspend`), then
//! the machine put to sleep. The partition comes back with its passphrase alone, which the
//! screen lock asks for, and the zones thaw. A zone volume keeps its key: its zone is frozen,
//! not stopped.
//!
//! While the state partition is suspended, whatever reaches /var, /home, /root or /etc's upper
//! layer waits for it. So what answers in that time reads only sysfs and cgroupfs, and the
//! resume runs cryptsetup where none of those mounts exist.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::registry::State;
use crate::volume::Passphrase;

/// The state partition's mapping, which sysinit opens at boot.
pub const STATE_MAPPER: &str = "kryptik-state";
/// `kryptik-update apply` holds it while it writes a slot.
const UPDATE_LOCK: &str = "/run/kryptik/update.lock";
/// Whether the kernel syncs every filesystem before it sleeps. With the state partition
/// suspended, that sync could wait on it for good, a flush to its device among others; the sync
/// that counts is the one made before the partition is suspended.
const SYNC_ON_SUSPEND: &str = "/sys/power/sync_on_suspend";
/// How long a zone may take to say it is frozen.
const FREEZE_WITHIN: Duration = Duration::from_secs(10);
/// How long the state partition's resume may take, its key derivation included.
const RESUME_WITHIN: Duration = Duration::from_secs(60);
const PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// Whether the device-mapper device `name` is suspended, as `sys_block` says, or None if no
/// device has that name.
pub fn suspended_in(sys_block: &Path, name: &str) -> Option<bool> {
    fs::read_dir(sys_block).ok()?.flatten().find_map(|e| {
        let dm = e.path().join("dm");
        let n = fs::read_to_string(dm.join("name")).ok()?;
        (n.trim_end() == name).then(|| fs::read_to_string(dm.join("suspended")).is_ok_and(|s| s.trim() == "1"))
    })
}

pub fn suspended(name: &str) -> bool {
    suspended_in(Path::new("/sys/block"), name) == Some(true)
}

/// Whether the state partition waits for its passphrase.
pub fn state_suspended() -> bool {
    suspended(STATE_MAPPER)
}

/// Why the machine may not sleep, if it may not, as `sys` says. 6.18's virtio-gpu has no
/// .freeze or .restore (drivers/gpu/drm/virtio/virtgpu_drv.c), so a sleep resets the device
/// under a driver that keeps its old queues, and the first commit that waits on it waits for
/// good, the compositor's with it. A machine that shows through it stays awake, until a kernel
/// whose driver has them.
pub fn sleep_refused_in(sys: &Path) -> Option<&'static str> {
    let bound = fs::read_dir(sys.join("bus/virtio/drivers/virtio_gpu"))
        .ok()?
        .flatten()
        .any(|e| e.file_name().to_string_lossy().starts_with("virtio"));
    bound.then_some("the display's driver, virtio-gpu, does not come back from a sleep")
}

pub fn sleep_refused() -> Option<&'static str> {
    sleep_refused_in(Path::new("/sys"))
}

/// A running zone's cgroup leaf, as the registry records it in kryptikd's own tree.
fn leaf(zone: &str) -> Option<PathBuf> {
    match crate::registry::state(zone) {
        Ok(State::Running { cgroup: Some(c), .. }) => {
            Some(PathBuf::from(c)).filter(|p| crate::registry::under(p, &crate::cgroup::kryptik_root()))
        }
        _ => None,
    }
}

fn set_freeze(leaf: &Path, on: bool) -> std::io::Result<()> {
    fs::write(leaf.join("cgroup.freeze"), if on { "1" } else { "0" })
}

/// Asked to freeze: the leaf's `cgroup.freeze`.
fn held(leaf: &Path) -> bool {
    fs::read_to_string(leaf.join("cgroup.freeze")).is_ok_and(|s| s.trim() == "1")
}

/// Frozen through: the leaf's `cgroup.events`.
fn frozen(leaf: &Path) -> bool {
    fs::read_to_string(leaf.join("cgroup.events")).is_ok_and(|s| s.lines().any(|l| l == "frozen 1"))
}

fn undo(done: &[(String, PathBuf)]) {
    for (_, l) in done {
        let _ = set_freeze(l, false);
    }
}

/// Freeze every running zone and wait until each is. One with no leaf to freeze, or that does
/// not freeze in time, thaws the rest and refuses; one that ended meanwhile is passed over.
fn freeze_all() -> Result<Vec<String>, String> {
    let mut done: Vec<(String, PathBuf)> = Vec::new();
    for zone in crate::registry::names() {
        if !matches!(crate::registry::state(&zone), Ok(State::Running { .. })) {
            continue;
        }
        let Some(l) = leaf(&zone) else {
            undo(&done);
            return Err(format!("zone {zone:?} runs without a cgroup to freeze"));
        };
        match set_freeze(&l, true) {
            Ok(()) => done.push((zone, l)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                undo(&done);
                return Err(format!("zone {zone:?}: {}: {e}", l.display()));
            }
        }
    }
    let until = Instant::now() + FREEZE_WITHIN;
    while let Some((zone, _)) = done.iter().find(|(_, l)| l.exists() && !frozen(l)) {
        if Instant::now() >= until {
            let why = format!("zone {zone:?} did not freeze within {} s", FREEZE_WITHIN.as_secs());
            undo(&done);
            return Err(why);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(done.into_iter().map(|(z, _)| z).collect())
}

/// Thaw every zone a suspend froze. The zones thawed.
pub fn thaw() -> Vec<String> {
    let mut thawed = Vec::new();
    for zone in crate::registry::names() {
        let Some(l) = leaf(&zone) else { continue };
        if held(&l) && set_freeze(&l, false).is_ok() {
            thawed.push(zone);
        }
    }
    thawed
}

/// Whether another holds `path` locked for writing, as `kryptik-update apply` holds its lock
/// while it writes a slot.
fn locked_out(path: &Path) -> bool {
    let Ok(f) = fs::File::open(path) else { return false };
    // SAFETY: f is open; a shared lock not had at once means an exclusive one is held.
    unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) != 0 }
}

/// Freeze every zone, flush, then suspend the state partition with its key wiped; the zones
/// it froze. Zone volumes are written out by the flush, through their files on the partition,
/// so nothing of theirs is left to reach it. A step that fails thaws the zones and refuses: the
/// machine must not sleep holding the key.
pub fn seal() -> Result<Vec<String>, String> {
    if locked_out(Path::new(UPDATE_LOCK)) {
        return Err("an update is being installed".into());
    }
    let zones = freeze_all()?;
    // SAFETY: sync takes no arguments and cannot fail.
    unsafe { libc::sync() };
    if let Err(e) = fs::write(SYNC_ON_SUSPEND, "0") {
        thaw();
        return Err(format!("{SYNC_ON_SUSPEND}: {e}: the kernel's own sync before it sleeps would wait on the suspended partition"));
    }
    if let Err(e) = crate::volume::suspend_mapping(STATE_MAPPER) {
        thaw();
        return Err(format!("the state partition did not suspend: {e}"));
    }
    Ok(zones)
}

/// Put the machine to sleep (suspend to RAM); returns once it has woken, or with why it did not
/// sleep. Nothing is read or started on the way, as the state partition is suspended by now.
pub fn sleep() -> Result<(), String> {
    fs::OpenOptions::new()
        .write(true)
        .open("/sys/power/state")
        .and_then(|mut f| f.write_all(b"mem"))
        .map_err(|e| format!("/sys/power/state: {e}"))
}

#[derive(Debug)]
pub enum ResumeError {
    /// cryptsetup exited 2: no keyslot took the passphrase.
    Wrong,
    Failed(String),
}

/// Between fork and exec for the state partition's resume: a mount namespace of the child's own,
/// private so nothing done in it reaches the system's, without the mounts the partition holds.
/// /etc is then the verified root's, which the overlay hides, so neither the loader nor
/// cryptsetup can wait on the partition being resumed. Each step is best effort: a resume
/// refused for want of one would leave the machine no way back.
fn leave_state_mounts() -> std::io::Result<()> {
    // SAFETY: system calls alone, on NUL-terminated literals, as is allowed after fork.
    unsafe {
        if libc::unshare(libc::CLONE_NEWNS) == 0
            && libc::mount(std::ptr::null(), c"/".as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) == 0
        {
            for m in [c"/home", c"/root", c"/etc", c"/var"] {
                libc::umount2(m.as_ptr(), libc::MNT_DETACH);
            }
        }
    }
    Ok(())
}

/// Give the state partition its key again (`cryptsetup luksResume`), then thaw the zones. The
/// zones thawed.
pub fn resume_state(pass: &Passphrase) -> Result<Vec<String>, ResumeError> {
    let mut cmd = Command::new("cryptsetup");
    cmd.args(["luksResume", "--key-file", "-", STATE_MAPPER])
        .env_clear()
        .env("PATH", PATH)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: leave_state_mounts makes system calls alone.
    unsafe { cmd.pre_exec(leave_state_mounts) };
    let mut child = cmd.spawn().map_err(|e| ResumeError::Failed(format!("cannot run cryptsetup: {e}")))?;
    if let Some(mut si) = child.stdin.take() {
        // Far less than a pipe holds: the write never waits on cryptsetup.
        let _ = si.write_all(pass.as_bytes());
    }
    let until = Instant::now() + RESUME_WITHIN;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                // The daemon reaps it whenever it ends.
                let _ = child.kill();
                return Err(ResumeError::Failed(format!("cryptsetup luksResume gave no answer within {} s", RESUME_WITHIN.as_secs())));
            }
            Err(e) => return Err(ResumeError::Failed(format!("cryptsetup luksResume: {e}"))),
        }
    };
    let mut err = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut err);
    }
    match status.code() {
        Some(0) => {
            // The partition takes writes again, so the kernel's sync before a sleep is safe again.
            let _ = fs::write(SYNC_ON_SUSPEND, "1");
            Ok(thaw())
        }
        Some(2) => Err(ResumeError::Wrong),
        code => Err(ResumeError::Failed(format!("cryptsetup luksResume exited {}: {}", code.unwrap_or(-1), err.trim()))),
    }
}

#[cfg(test)]
mod tests;
