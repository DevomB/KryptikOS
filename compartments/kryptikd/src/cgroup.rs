//! cgroup v2 resource limits for a zone.
//!
//! WHAT THIS IS FOR
//!
//! A zone file can say `memory_max = "4G"` and `pids_max = 512`. Until now
//! those parsed, validated, and then did nothing: `spawn.rs` refused to start
//! such a zone at all rather than let an operator believe a limit was in force.
//! That refusal was the honest behaviour and it is still the fallback here.
//! This module is what lets the limit actually hold.
//!
//! WHY A LIMIT THAT SILENTLY DOES NOTHING IS WORSE THAN NO LIMIT
//!
//! The whole point of `untrusted` is that it can be handed something hostile.
//! An operator who believes a zone is capped at 4G and 512 processes will run
//! things in it that they would not otherwise run. If the cap is absent, the
//! belief is what causes the damage, not the missing cgroup. So every path in
//! this file either establishes the limit or reports that it could not - there
//! is no branch that quietly proceeds without one.
//!
//! THE DELEGATION PROBLEM, WHICH IS THE REASON FOR `available()`
//!
//! Creating a cgroup means creating a directory under the cgroup2 mount, and
//! on an ordinary desktop an unprivileged user cannot: the hierarchy is owned
//! by root and managed by systemd. kryptikd proper runs privileged in zone 0
//! and has no difficulty, but the developer path - the one the test suite uses
//! - runs as an ordinary user and does. `available()` answers that question by
//! trying, rather than by guessing from uid: a delegated subtree (systemd
//! `Delegate=yes`, or a user slice) is writable by a normal user, and a root
//! process in a container may still find the hierarchy read-only.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Where the kernel mounts the unified hierarchy.
const CGROUP2_ROOT: &str = "/sys/fs/cgroup";

/// The directory kryptikd creates its per-zone cgroups under.
const KRYPTIK_GROUP: &str = "kryptik";

/// Controllers a zone limit needs. Both must be delegated to the parent of the
/// leaf, or `memory.max` and `pids.max` do not exist in it.
const NEEDED: &[&str] = &["memory", "pids"];

#[derive(Debug)]
pub enum CgroupError {
    Unavailable(String),
    Io { path: String, err: io::Error },
    BadLimit { field: &'static str, value: String },
}

impl std::fmt::Display for CgroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CgroupError::Unavailable(m) => write!(f, "{m}"),
            CgroupError::Io { path, err } => write!(f, "{path}: {err}"),
            CgroupError::BadLimit { field, value } => {
                write!(f, "{field}: cannot use {value:?} as a limit")
            }
        }
    }
}

fn io_err(path: &Path, err: io::Error) -> CgroupError {
    CgroupError::Io { path: path.display().to_string(), err }
}

/// Parse `memory_max` into bytes.
///
/// `zone.rs` has already checked the shape (`[0-9]+[KMGT]?`), so this is a
/// conversion rather than a validation - but it returns a Result anyway,
/// because a value that overflows a u64 would otherwise wrap to a small number
/// and silently impose a limit far tighter than the operator asked for. A
/// wrong limit in that direction is a zone that dies mysteriously.
pub fn parse_memory_max(v: &str) -> Result<u64, CgroupError> {
    let bad = || CgroupError::BadLimit { field: "memory_max", value: v.to_string() };
    let (digits, mult) = match v.as_bytes().last() {
        Some(b'K') | Some(b'k') => (&v[..v.len() - 1], 1024u64),
        Some(b'M') | Some(b'm') => (&v[..v.len() - 1], 1024 * 1024),
        Some(b'G') | Some(b'g') => (&v[..v.len() - 1], 1024 * 1024 * 1024),
        Some(b'T') | Some(b't') => (&v[..v.len() - 1], 1024u64 * 1024 * 1024 * 1024),
        _ => (v, 1),
    };
    let n: u64 = digits.parse().map_err(|_| bad())?;
    n.checked_mul(mult).ok_or_else(bad)
}

fn read_trim(p: &Path) -> Result<String, CgroupError> {
    Ok(fs::read_to_string(p).map_err(|e| io_err(p, e))?.trim().to_string())
}

/// Make sure `dir` delegates `NEEDED` to its children.
///
/// A controller is only usable in a child if the PARENT lists it in
/// `cgroup.subtree_control`. Missing this is the single most confusing cgroup2
/// failure: the directory is created successfully, and then `memory.max`
/// simply does not exist in it, with no error anywhere to say why.
fn ensure_subtree_control(dir: &Path) -> Result<(), CgroupError> {
    let avail_path = dir.join("cgroup.controllers");
    let avail = read_trim(&avail_path)?;
    let ctl_path = dir.join("cgroup.subtree_control");
    let enabled = read_trim(&ctl_path).unwrap_or_default();

    let mut add = String::new();
    for c in NEEDED {
        if !avail.split_whitespace().any(|a| a == *c) {
            return Err(CgroupError::Unavailable(format!(
                "the {c} controller is not available in {} (has: {avail})",
                dir.display()
            )));
        }
        if !enabled.split_whitespace().any(|e| e == *c) {
            add.push_str(&format!("+{c} "));
        }
    }
    if add.is_empty() {
        return Ok(());
    }
    fs::write(&ctl_path, add.trim()).map_err(|e| io_err(&ctl_path, e))
}

/// Can this process create per-zone cgroups, and where?
///
/// Answers by trying. Returns the directory per-zone cgroups go under.
pub fn available() -> Result<PathBuf, CgroupError> {
    available_under(Path::new(CGROUP2_ROOT))
}

/// `available` against a given hierarchy root, so the answer can be tested
/// against a directory tree shaped like one.
pub fn available_under(root: &Path) -> Result<PathBuf, CgroupError> {
    if !root.join("cgroup.controllers").exists() {
        return Err(CgroupError::Unavailable(format!(
            "{} is not a cgroup v2 hierarchy (no cgroup.controllers)",
            root.display()
        )));
    }

    // The root is exempt from the "no internal processes" rule, so enabling
    // controllers here is safe even with processes sitting directly in it.
    ensure_subtree_control(root)?;

    let group = root.join(KRYPTIK_GROUP);
    if !group.exists() {
        fs::create_dir(&group).map_err(|e| io_err(&group, e))?;
    }
    ensure_subtree_control(&group)?;

    // "Answers by trying" has to mean trying the thing that will actually be
    // done. Creating the GROUP proves nothing once it exists - the first
    // launcher to run creates it, and on a machine where that was a root one
    // it is a root-owned directory an unprivileged launcher cannot make leaves
    // in. available() then returned Ok, and the zone was refused far later by
    // a raw EACCES on a path the operator never typed, instead of by the
    // [limits] message that names the setting that could not be honoured.
    //
    // So create a leaf, which is what a launch does, and remove it.
    let probe = group.join(format!(".probe.{}", std::process::id()));
    let _ = fs::remove_dir(&probe);
    if let Err(e) = fs::create_dir(&probe) {
        return Err(CgroupError::Unavailable(format!(
            "cannot create a cgroup under {} ({e}), so this launcher could not put a \
             zone in one",
            group.display()
        )));
    }
    if let Err(e) = fs::remove_dir(&probe) {
        // Empty, so the sweep below reclaims it within STALE_AFTER; but a
        // directory this process made and could not unmake is worth a line.
        eprintln!(
            "kryptikd: note: could not remove the cgroup probe {}: {e}",
            probe.display()
        );
    }

    sweep_stale(&group);
    Ok(group)
}

/// How long a leaf must have existed before an empty one counts as abandoned.
///
/// A cgroup is created a few microseconds before the zone is moved into it, so
/// during that window a live launch has an empty cgroup too. Sweeping inside
/// it would delete a concurrent launcher's cgroup out from under it.
///
/// Five seconds is roughly a million times that window, and short enough that
/// the behaviour can be tested in a suite rather than asserted in a comment.
const STALE_AFTER: Duration = Duration::from_secs(5);

/// Remove cgroups left behind by launchers that died without cleaning up.
///
/// `Cgroup::drop` handles every ordinary exit, and `PR_SET_PDEATHSIG` kills the
/// zone's processes even when the launcher is SIGKILLed - but nothing runs Drop
/// in that case, so an EMPTY directory is left behind. One is harmless; one per
/// killed launch accumulates, and each still holds the limits it was given.
///
/// Only EMPTY leaves are removed, and only old ones. A leaf with any process
/// in it belongs to a live zone: `rmdir` on a populated cgroup fails with
/// EBUSY anyway, but relying on that would mean asking the kernel to protect
/// us from a mistake rather than not making it.
fn sweep_stale(base: &Path) {
    for p in abandoned_leaves(base) {
        // A leaf whose last task is still on its way out returns EBUSY for
        // a moment; a few tries cover that. What still cannot be removed is
        // named, with the reason, rather than left to be found by a count.
        let mut last = None;
        for _ in 0..5 {
            match fs::remove_dir(&p) {
                Ok(()) => {
                    last = None;
                    break;
                }
                Err(e) => {
                    last = Some(e);
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
        if let Some(e) = last {
            eprintln!("kryptikd: note: could not sweep the abandoned cgroup {}: {e}", p.display());
        }
    }
}

/// The leaves under `base` the sweep may remove: empty, and abandoned.
fn abandoned_leaves(base: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(base) else { return out };
    let now = SystemTime::now();
    for e in entries.flatten() {
        let p = e.path();
        if !p.is_dir() {
            continue;
        }
        // A leaf is named <zone>.<launcher pid>, and the launcher is what
        // decides whether an empty leaf is abandoned: one whose launcher is
        // gone will never be populated, however young the directory looks -
        // and on the target kernel it always looks young, because kernfs
        // gives a cgroup directory the time it was FIRST LOOKED AT, not the
        // time it was made (6.18: stat 7 s after mkdir reported the stat's
        // own second), so the age rule alone never swept a leaf nobody had
        // stat'ed, and the launcher suite's check for leftover cgroup leaves
        // found one surviving. A
        // launcher still alive - or a reused pid, treated the same - keeps
        // its leaf. The age rule remains for a leaf whose name carries no
        // pid.
        let abandoned = match launcher_of(&p) {
            Some(pid) => !Path::new(&format!("/proc/{pid}")).exists(),
            None => e
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|m| now.duration_since(m).ok())
                .is_some_and(|age| age > STALE_AFTER),
        };
        if !abandoned {
            continue;
        }
        let populated = fs::read_to_string(p.join("cgroup.procs"))
            .map(|s| s.lines().any(|l| !l.trim().is_empty()))
            .unwrap_or(true); // unreadable: assume live, leave it alone
        if !populated {
            out.push(p);
        }
    }
    out
}

/// The launcher pid a leaf is named after (`<zone>.<pid>`), if it is.
fn launcher_of(leaf: &Path) -> Option<i32> {
    leaf.file_name()?.to_str()?.rsplit_once('.')?.1.parse().ok()
}

/// Remove every empty per-zone cgroup, regardless of age. Returns how many.
///
/// `gc` is an explicit operator action, so it does not need the age heuristic
/// that `sweep_stale` uses to avoid racing a concurrent launch - but it is
/// still safe if one is racing, because `rmdir` on a cgroup with any process
/// in it fails with EBUSY. The kernel is the interlock, not the timestamp.
pub fn sweep_now() -> usize {
    let root = Path::new(CGROUP2_ROOT).join(KRYPTIK_GROUP);
    let Ok(entries) = fs::read_dir(&root) else { return 0 };
    let mut n = 0;
    for e in entries.flatten() {
        let p = e.path();
        if !p.is_dir() {
            continue;
        }
        let populated = fs::read_to_string(p.join("cgroup.procs"))
            .map(|s| s.lines().any(|l| !l.trim().is_empty()))
            .unwrap_or(true);
        if !populated && fs::remove_dir(&p).is_ok() {
            n += 1;
        }
    }
    n
}

/// The directory every zone's cgroup is created under.
///
/// Exposed because `registry::reclaim` checks a recorded cgroup path against it
/// before writing `cgroup.kill`: the registry entry is only as trustworthy as
/// the directory it was read from, and this is the one place that decides what
/// counts as ours.
pub fn kryptik_root() -> PathBuf {
    Path::new(CGROUP2_ROOT).join(KRYPTIK_GROUP)
}

/// One zone's cgroup. Removed when dropped, so an early return cannot leak it.
#[derive(Debug)]
pub struct Cgroup {
    path: PathBuf,
}

impl Cgroup {
    /// Create the leaf for one zone launch.
    ///
    /// The name carries the launcher's pid because `run` is one-shot and two
    /// launches of the same zone can overlap. Reusing a name would put both
    /// zones under one limit, which is a cross-zone channel: one zone could
    /// starve another by allocating.
    pub fn create(base: &Path, zone: &str, launcher_pid: i32) -> Result<Self, CgroupError> {
        let path = base.join(format!("{zone}.{launcher_pid}"));
        // A leftover from a previous run with the same pid would silently
        // inherit its limits; remove it rather than adopt it.
        let _ = fs::remove_dir(&path);
        fs::create_dir(&path).map_err(|e| io_err(&path, e))?;
        Ok(Cgroup { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write the limits. Both are optional; absent means "no limit", which is
    /// written as the literal `max` rather than left at whatever it inherited.
    pub fn set_limits(&self, memory_max: Option<&str>, pids_max: Option<u32>) -> Result<(), CgroupError> {
        let mem = self.path.join("memory.max");
        match memory_max {
            Some(v) => {
                let bytes = parse_memory_max(v)?;
                fs::write(&mem, bytes.to_string()).map_err(|e| io_err(&mem, e))?;
            }
            None => {
                let _ = fs::write(&mem, "max");
            }
        }

        let pids = self.path.join("pids.max");
        match pids_max {
            Some(n) => fs::write(&pids, n.to_string()).map_err(|e| io_err(&pids, e))?,
            None => {
                let _ = fs::write(&pids, "max");
            }
        }

        // memory.max alone lets the kernel reclaim forever instead of killing.
        // memory.oom.group makes the whole zone die together rather than
        // leaving a half-dead process tree when one allocation loses.
        //
        // Both of these were `let _ = fs::write(...)` until the security
        // review pointed out that this module's own
        // header - "every path in this file either establishes the limit or
        // reports that it could not" - was false in its last four lines. A
        // zone capped without oom.group dies one process at a time and the
        // survivors keep the zone's files and sockets open; an operator who
        // read `memory_max = "4G"` was promised something else.
        let og = self.path.join("memory.oom.group");
        fs::write(&og, "1").map_err(|e| io_err(&og, e))?;

        // Swap must be capped too, or a zone "limited" to 4G simply pages the
        // rest out and the limit measures nothing the operator cares about.
        //
        // Absent is not the same failure as unwritable. Without swap
        // accounting the file does not exist in any cgroup, so there is no
        // per-zone swap limit to lose - the operator's exposure is the same
        // for every process on the machine, and saying so once is more use
        // than refusing to start. cgroupfs does not create files on write, so
        // this really does arrive as ENOENT rather than as a new file. A file
        // that exists and refuses the write is a limit we failed to apply,
        // and that is fatal.
        let sw = self.path.join("memory.swap.max");
        match fs::write(&sw, "0") {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => eprintln!(
                "kryptikd: {} does not exist - this kernel has no swap accounting, \
                 so the zone's memory limit does not bound what it can page out",
                sw.display()
            ),
            Err(e) => return Err(io_err(&sw, e)),
        }
        Ok(())
    }

    /// Move a process into this cgroup.
    ///
    /// Must happen BEFORE the process unshares its cgroup namespace, so that
    /// the namespace roots here. Move it afterwards and the zone's own
    /// `/proc/self/cgroup` describes a path outside its namespace root.
    pub fn attach(&self, pid: i32) -> Result<(), CgroupError> {
        let p = self.path.join("cgroup.procs");
        fs::write(&p, pid.to_string()).map_err(|e| io_err(&p, e))
    }

    /// Kill everything still inside, then remove the directory.
    ///
    /// rmdir on a cgroup fails with EBUSY while any process remains, so a
    /// zone that outlived its launcher would leave the directory behind
    /// forever. `cgroup.kill` (Linux 5.14+) empties it atomically; where that
    /// is absent the removal is attempted anyway and its failure is reported
    /// by the caller rather than swallowed.
    pub fn destroy(&self) -> Result<(), CgroupError> {
        let _ = fs::write(self.path.join("cgroup.kill"), "1");
        for _ in 0..50 {
            match fs::remove_dir(&self.path) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
        fs::remove_dir(&self.path).map_err(|e| io_err(&self.path, e))
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        // Best effort: an error here has nowhere useful to go, and the caller
        // has already reported anything that matters.
        let _ = fs::write(self.path.join("cgroup.kill"), "1");
        let _ = fs::remove_dir(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// "Available" must mean this process can create a leaf, not that
    /// the directory exists with the right controllers. A root-owned kryptik/
    /// left by a privileged run read fine and then failed at mkdir, and the
    /// refusal stopped naming [limits].
    #[test]
    fn availability_is_proven_by_creating_a_leaf_not_by_reading() {
        let root = std::env::temp_dir().join(format!("kryptik-cg-{}", std::process::id()));
        let group = root.join(KRYPTIK_GROUP);
        fs::create_dir_all(&group).unwrap();
        for d in [&root, &group] {
            fs::write(d.join("cgroup.controllers"), "cpu memory pids\n").unwrap();
            fs::write(d.join("cgroup.subtree_control"), "memory pids\n").unwrap();
        }
        // Readable, delegated, and not writable by us: exactly the trap.
        fs::set_permissions(&group, fs::Permissions::from_mode(0o555)).unwrap();
        let r = available_under(&root);
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("running as root: a 0555 directory does not refuse root; skipping the negative half");
        } else {
            match r {
                Err(CgroupError::Unavailable(m)) => assert!(m.contains("cannot create a cgroup under"), "{m}"),
                other => panic!("expected Unavailable, got {other:?}"),
            }
        }
        // Writable again: available, and the trial leaf is gone.
        fs::set_permissions(&group, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(available_under(&root).unwrap(), group);
        let left: Vec<_> = fs::read_dir(&group).unwrap().flatten().filter(|e| e.path().is_dir()).collect();
        assert!(left.is_empty(), "trial directory left behind: {left:?}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn memory_suffixes_convert() {
        assert_eq!(parse_memory_max("1024").unwrap(), 1024);
        assert_eq!(parse_memory_max("1K").unwrap(), 1024);
        assert_eq!(parse_memory_max("2M").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_memory_max("4G").unwrap(), 4 * 1024 * 1024 * 1024);
        assert_eq!(parse_memory_max("1T").unwrap(), 1024u64 * 1024 * 1024 * 1024);
    }

    #[test]
    fn an_overflowing_limit_is_refused_not_wrapped() {
        // 16777216T overflows u64 when multiplied out. Wrapping would produce
        // a small number and impose a limit far tighter than asked for, which
        // shows up as a zone dying for no visible reason.
        assert!(parse_memory_max("18446744073709551615T").is_err());
        assert!(parse_memory_max("").is_err());
        assert!(parse_memory_max("G").is_err());
    }

    #[test]
    fn the_sweep_leaves_a_populated_cgroup_alone() {
        // The rule the sweep must never break: a leaf with a process in it
        // belongs to a live zone. Checked on the parsing of cgroup.procs
        // rather than against a real hierarchy, which the test process may
        // not be able to create.
        let populated = |s: &str| s.lines().any(|l| !l.trim().is_empty());
        assert!(populated("1234\n"));
        assert!(populated("1234\n5678\n"));
        assert!(!populated(""));
        assert!(!populated("\n"));
        assert!(!populated("   \n"));
    }

    #[test]
    fn the_sweep_goes_by_the_launcher_not_the_directory_time() {
        // Staged with plain directories: the sweep reads cgroup.procs as a
        // file and looks the launcher up in /proc, neither of which needs a
        // real hierarchy. A dead launcher's empty leaf goes at once; a live
        // launcher's empty leaf (a launch in progress) stays; a populated
        // leaf stays whoever its launcher was.
        let base = std::env::temp_dir().join(format!("kryptik-sweep-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let mut dead = 4_000_000;
        while Path::new(&format!("/proc/{dead}")).exists() {
            dead -= 1;
        }
        let alive = std::process::id();
        let leaf = |name: &str, procs: &str| {
            let p = base.join(name);
            fs::create_dir(&p).unwrap();
            fs::write(p.join("cgroup.procs"), procs).unwrap();
            p
        };
        let gone = leaf(&format!("untrusted.{dead}"), "");
        let live = leaf(&format!("work.{alive}"), "");
        let busy = leaf(&format!("dev.{dead}"), "4242\n");
        let unnamed = leaf("nopid", "");
        assert_eq!(launcher_of(&gone), Some(dead));
        assert_eq!(launcher_of(&live), Some(alive as i32));
        assert_eq!(launcher_of(&unnamed), None);
        // Only the dead launcher's empty leaf, and at once: a live launcher's
        // empty leaf is a launch in progress, a populated leaf is never
        // touched, and a leaf without a pid falls back to the age rule, under
        // which it is new.
        assert_eq!(abandoned_leaves(&base), vec![gone.clone()]);
        assert!(live.exists() && busy.exists() && unnamed.exists());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn available_leaves_no_probe_directories_behind() {
        // available() now proves it can create a leaf by creating one. A probe
        // that is not removed is one directory per launch, forever.
        let Ok(group) = available() else {
            eprintln!("skipped: no usable cgroup v2 hierarchy here");
            return;
        };
        let _ = available();
        let left: Vec<_> = std::fs::read_dir(&group)
            .expect("the group we were just handed must be readable")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".probe."))
            .collect();
        assert!(left.is_empty(), "probe directories left behind: {left:?}");
    }

    #[test]
    fn a_limit_that_cannot_be_written_is_an_error_not_a_shrug() {
        // Required by the security review. The regression this locks in: set_limits used
        // to discard the result of the memory.oom.group write, so a zone whose
        // limit was only half applied started anyway and reported success.
        //
        // Staged with a directory the process cannot create files in, holding
        // the attribute files that already exist in a real leaf. memory.max
        // and pids.max are writable, so the failure lands exactly where it is
        // being tested: on the file that is missing.
        let dir = std::env::temp_dir().join(format!("kryptik-cgtest-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for f in ["memory.max", "pids.max"] {
            fs::write(dir.join(f), "max").unwrap();
        }
        let ro = fs::Permissions::from_mode(0o555);
        fs::set_permissions(&dir, ro).unwrap();
        // Root writes through a 0555 directory; the refusal under test can
        // only be observed unprivileged. Skipped, not passed, as root.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("running as root: a read-only directory does not refuse root; skipped");
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
            let _ = fs::remove_dir_all(&dir);
            return;
        }

        let cg = Cgroup { path: dir.clone() };
        let err = cg.set_limits(Some("1M"), Some(10)).unwrap_err();
        let msg = err.to_string();

        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let _ = fs::remove_dir_all(&dir);

        assert!(
            msg.contains("memory.oom.group"),
            "set_limits must fail naming the limit it could not apply, said: {msg}"
        );
    }

    #[test]
    fn the_leaf_name_is_unique_per_launch() {
        // Two overlapping launches of one zone must not share a cgroup: a
        // shared limit is a channel between them.
        let base = Path::new("/sys/fs/cgroup/kryptik");
        let a = base.join(format!("{}.{}", "work", 111));
        let b = base.join(format!("{}.{}", "work", 222));
        assert_ne!(a, b);
    }
}
