//! cgroup v2 memory, pid, cpu and io limits for a zone (`[limits]`), never silently left unset.
//! `available()` finds out by trying: an unprivileged launcher often cannot create cgroups.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Where the kernel mounts the unified hierarchy.
const CGROUP2_ROOT: &str = "/sys/fs/cgroup";

/// The directory kryptikd creates its per-zone cgroups under.
const KRYPTIK_GROUP: &str = "kryptik";

/// Controllers the leaf's parent must delegate, or the leaf's limit files are missing.
const NEEDED: &[&str] = &["memory", "pids", "cpu", "io"];

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

/// Parse `memory_max` into bytes (`zone::parse_size`).
pub fn parse_memory_max(v: &str) -> Result<u64, CgroupError> {
    crate::zone::parse_size(v).ok_or_else(|| CgroupError::BadLimit { field: "memory_max", value: v.to_string() })
}

/// Parse `cpu_max` into a percentage of one CPU (`zone::parse_cpu_max`).
pub fn parse_cpu_max(v: &str) -> Result<u32, CgroupError> {
    crate::zone::parse_cpu_max(v).ok_or_else(|| CgroupError::BadLimit { field: "cpu_max", value: v.to_string() })
}

/// Parse `io_max` into bytes per second (`zone::parse_size`).
pub fn parse_io_max(v: &str) -> Result<u64, CgroupError> {
    crate::zone::parse_size(v).ok_or_else(|| CgroupError::BadLimit { field: "io_max", value: v.to_string() })
}

/// `MAJ:MIN` of the block device at `path` and of the disks under it (sysfs `slaves`), where an
/// encrypted volume's bytes land; a partition counts as its disk, the only thing io.max takes.
pub fn block_devices(path: &str) -> io::Result<Vec<String>> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let md = fs::metadata(path)?;
    if !md.file_type().is_block_device() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{path} is not a block device")));
    }
    let (major, minor) = (libc::major(md.rdev()), libc::minor(md.rdev()));
    let mut out = vec![format!("{major}:{minor}")];
    let slaves = Path::new("/sys/dev/block").join(format!("{major}:{minor}")).join("slaves");
    if let Ok(entries) = fs::read_dir(&slaves) {
        for e in entries.flatten() {
            if let Some(dev) = whole_device(&e.path()) {
                if !out.contains(&dev) {
                    out.push(dev);
                }
            }
        }
    }
    Ok(out)
}

/// A sysfs block entry's `MAJ:MIN`, or its disk's (the parent directory) for a partition.
fn whole_device(entry: &Path) -> Option<String> {
    let dir = if entry.join("partition").exists() { entry.join("..") } else { entry.to_path_buf() };
    let dev = fs::read_to_string(dir.join("dev")).ok()?;
    let dev = dev.trim();
    (!dev.is_empty()).then(|| dev.to_string())
}

fn read_trim(p: &Path) -> Result<String, CgroupError> {
    Ok(fs::read_to_string(p).map_err(|e| io_err(p, e))?.trim().to_string())
}

/// Make `dir` delegate `NEEDED`, or a child is created without error but has no `memory.max`.
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

/// The directory per-zone cgroups go under, if this process can create them there.
pub fn available() -> Result<PathBuf, CgroupError> {
    available_under(Path::new(CGROUP2_ROOT))
}

/// `available` against any hierarchy root, for tests.
pub fn available_under(root: &Path) -> Result<PathBuf, CgroupError> {
    if !root.join("cgroup.controllers").exists() {
        return Err(CgroupError::Unavailable(format!(
            "{} is not a cgroup v2 hierarchy (no cgroup.controllers)",
            root.display()
        )));
    }

    // The root is exempt from the "no internal processes" rule.
    ensure_subtree_control(root)?;

    let group = root.join(KRYPTIK_GROUP);
    if !group.exists() {
        fs::create_dir(&group).map_err(|e| io_err(&group, e))?;
    }
    ensure_subtree_control(&group)?;

    // The group may be root's, from a privileged launch: prove a leaf can be made, then remove it.
    let probe = group.join(format!(".probe.{}", std::process::id()));
    let _ = fs::remove_dir(&probe);
    if let Err(e) = fs::create_dir(&probe) {
        return Err(CgroupError::Unavailable(format!(
            "cannot create a cgroup under {} ({e})",
            group.display()
        )));
    }
    if let Err(e) = fs::remove_dir(&probe) {
        // The sweep reclaims it once this process has exited.
        eprintln!(
            "kryptikd: note: could not remove the cgroup probe {}: {e}",
            probe.display()
        );
    }

    sweep_stale(&group);
    Ok(group)
}

/// Age at which an empty pid-less leaf is abandoned; a live launch's is empty for microseconds.
const STALE_AFTER: Duration = Duration::from_secs(5);

/// Remove empty leaves whose launcher died before `Cgroup::drop`; populated ones are left alone.
fn sweep_stale(base: &Path) {
    for p in abandoned_leaves(base) {
        // EBUSY for a moment while the last task exits; retry, then report.
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
        /* A <zone>.<pid> leaf is abandoned once its launcher is gone. kernfs (6.18) dates a
         * cgroup directory from its first stat, not its mkdir, so only pid-less names go by age. */
        let abandoned = match launcher_of(&p) {
            Some(pid) => !Path::new(&format!("/proc/{pid}")).exists(),
            None => e
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|m| now.duration_since(m).ok())
                .is_some_and(|age| age > STALE_AFTER),
        };
        if abandoned && !populated(&p) {
            out.push(p);
        }
    }
    out
}

/// Whether a leaf holds a process; an unreadable `cgroup.procs` counts, so the leaf is left alone.
fn populated(leaf: &Path) -> bool {
    fs::read_to_string(leaf.join("cgroup.procs"))
        .map(|s| s.lines().any(|l| !l.trim().is_empty()))
        .unwrap_or(true)
}

/// The launcher pid a leaf is named after (`<zone>.<pid>`), if it is.
fn launcher_of(leaf: &Path) -> Option<i32> {
    leaf.file_name()?.to_str()?.rsplit_once('.')?.1.parse().ok()
}

/// Remove every empty zone cgroup for `gc` and count them; rmdir of a live one fails with EBUSY.
pub fn sweep_now() -> usize {
    let root = kryptik_root();
    let Ok(entries) = fs::read_dir(&root) else { return 0 };
    let mut n = 0;
    for e in entries.flatten() {
        let p = e.path();
        if !p.is_dir() {
            continue;
        }
        if !populated(&p) && fs::remove_dir(&p).is_ok() {
            n += 1;
        }
    }
    n
}

/// Where zone cgroups live; `registry::reclaim` checks a recorded path is under it before a kill.
pub fn kryptik_root() -> PathBuf {
    Path::new(CGROUP2_ROOT).join(KRYPTIK_GROUP)
}

/// One zone's cgroup. Removed when dropped, so an early return cannot leak it.
#[derive(Debug)]
pub struct Cgroup {
    path: PathBuf,
}

impl Cgroup {
    /// One launch's leaf, named with the launcher's pid so overlapping launches share no limit.
    pub fn create(base: &Path, zone: &str, launcher_pid: i32) -> Result<Self, CgroupError> {
        let path = base.join(format!("{zone}.{launcher_pid}"));
        // Never adopt a leftover leaf, and its limits, from a reused pid.
        let _ = fs::remove_dir(&path);
        fs::create_dir(&path).map_err(|e| io_err(&path, e))?;
        Ok(Cgroup { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// An absent limit is written as `max`, not inherited; `io_max` is (devices, bytes per second).
    pub fn set_limits(
        &self,
        memory_max: Option<&str>,
        pids_max: Option<u32>,
        cpu_max: Option<&str>,
        io_max: Option<(&[String], &str)>,
    ) -> Result<(), CgroupError> {
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

        // cpu.max is a quota per 100 ms period: N% of one CPU is N thousand microseconds.
        let cpu = self.path.join("cpu.max");
        match cpu_max {
            Some(v) => {
                let pct = parse_cpu_max(v)?;
                fs::write(&cpu, format!("{} 100000", u64::from(pct) * 1000)).map_err(|e| io_err(&cpu, e))?;
            }
            None => {
                let _ = fs::write(&cpu, "max 100000");
            }
        }

        // io.max is per device: one line for the mapping and for each device under it.
        if let Some((devices, v)) = io_max {
            let bps = parse_io_max(v)?;
            let io = self.path.join("io.max");
            for d in devices {
                fs::write(&io, format!("{d} rbps={bps} wbps={bps}")).map_err(|e| io_err(&io, e))?;
            }
        }

        // An OOM kills the whole zone, so no survivors keep its files and sockets open.
        let og = self.path.join("memory.oom.group");
        fs::write(&og, "1").map_err(|e| io_err(&og, e))?;

        /* Cap swap too, or the zone pages out past its memory limit. ENOENT means no swap
         * accounting (cgroupfs never creates files), so warn; any other failure is fatal. */
        let sw = self.path.join("memory.swap.max");
        match fs::write(&sw, "0") {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => eprintln!(
                "kryptikd: no swap accounting ({} is missing): the zone can page out past its memory limit",
                sw.display()
            ),
            Err(e) => return Err(io_err(&sw, e)),
        }
        Ok(())
    }

    /// Move a process in before it unshares its cgroup namespace, so the namespace is rooted here.
    pub fn attach(&self, pid: i32) -> Result<(), CgroupError> {
        let p = self.path.join("cgroup.procs");
        fs::write(&p, pid.to_string()).map_err(|e| io_err(&p, e))
    }

    /// Kill all inside (`cgroup.kill`, Linux 5.14+), then retry removing the directory for 1 s.
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
        // Best effort: an error here has nowhere to go.
        let _ = fs::write(self.path.join("cgroup.kill"), "1");
        let _ = fs::remove_dir(&self.path);
    }
}

#[cfg(test)]
mod tests;
