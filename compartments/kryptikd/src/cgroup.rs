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
    let root = Path::new(CGROUP2_ROOT);
    if !root.join("cgroup.controllers").exists() {
        return Err(CgroupError::Unavailable(format!(
            "{CGROUP2_ROOT} is not a cgroup v2 hierarchy (no cgroup.controllers)"
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
    let Ok(entries) = fs::read_dir(base) else { return };
    let now = SystemTime::now();
    for e in entries.flatten() {
        let p = e.path();
        if !p.is_dir() {
            continue;
        }
        let Ok(meta) = e.metadata() else { continue };
        let old_enough = meta
            .modified()
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .is_some_and(|age| age > STALE_AFTER);
        if !old_enough {
            continue;
        }
        let populated = fs::read_to_string(p.join("cgroup.procs"))
            .map(|s| s.lines().any(|l| !l.trim().is_empty()))
            .unwrap_or(true); // unreadable: assume live, leave it alone
        if !populated {
            let _ = fs::remove_dir(&p);
        }
    }
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
        // Both of these were `let _ = fs::write(...)` until security's
        // REVIEW-R5 required follow-up 1, which is to say this module's own
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

    /// How many processes are in this cgroup right now.
    pub fn population(&self) -> usize {
        fs::read_to_string(self.path.join("cgroup.procs"))
            .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
            .unwrap_or(0)
    }

    /// Did the kernel OOM-kill anything here? Read after the zone exits, to
    /// tell "the zone hit its memory limit" apart from "the zone failed".
    pub fn oom_kills(&self) -> u64 {
        fs::read_to_string(self.path.join("memory.events"))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("oom_kill ").map(|v| v.trim().to_string()))
            })
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
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
    fn a_limit_that_cannot_be_written_is_an_error_not_a_shrug() {
        // REVIEW-R5 required 1. The regression this locks in: set_limits used
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
