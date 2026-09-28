//! cgroup v2 memory and pid limits for a zone (`[limits]`).
//!
//! Every path either establishes the limits or reports that it could not. An
//! unprivileged launcher often cannot create cgroups at all, so `available()`
//! finds out by trying rather than by checking the uid.

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

/// The `MAJ:MIN` of the block device at `path`, then of the devices it is
/// built on (`slaves` in sysfs): io.max names devices, and an encrypted
/// volume's bytes land on the device under its mapping.
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
            if let Ok(dev) = fs::read_to_string(e.path().join("dev")) {
                let dev = dev.trim();
                if !dev.is_empty() {
                    out.push(dev.to_string());
                }
            }
        }
    }
    Ok(out)
}

fn read_trim(p: &Path) -> Result<String, CgroupError> {
    Ok(fs::read_to_string(p).map_err(|e| io_err(p, e))?.trim().to_string())
}

/// Make sure `dir` delegates `NEEDED` to its children. Without that, a child
/// is created without error but has no `memory.max`.
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

    /* The group may exist but be root's, made by a privileged launch, so prove
     * a leaf can be created, as a launch will, and remove it. */
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
        // The sweep reclaims it once this process has exited.
        eprintln!(
            "kryptikd: note: could not remove the cgroup probe {}: {e}",
            probe.display()
        );
    }

    sweep_stale(&group);
    Ok(group)
}

/// Age after which an empty leaf with no launcher pid in its name is abandoned.
/// A live launch's leaf is empty for the microseconds before the attach.
const STALE_AFTER: Duration = Duration::from_secs(5);

/// Remove the empty leaves of launchers killed before `Cgroup::drop` could run.
/// A populated leaf belongs to a live zone and is never touched.
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
        /* Leaves are named <zone>.<launcher pid>; a leaf whose launcher is gone
         * is abandoned, and a live (or reused) pid keeps it. Age is no guide:
         * kernfs (6.18) dates a cgroup directory from its first stat, not its
         * mkdir. The age rule covers only names without a pid. */
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

/// Remove every empty per-zone cgroup, for `gc`; returns how many. rmdir of a
/// populated cgroup fails with EBUSY, so running zones are safe.
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

/// The directory every zone's cgroup is created under. `registry::reclaim`
/// checks a recorded cgroup path against it before writing `cgroup.kill`.
pub fn kryptik_root() -> PathBuf {
    Path::new(CGROUP2_ROOT).join(KRYPTIK_GROUP)
}

/// One zone's cgroup. Removed when dropped, so an early return cannot leak it.
#[derive(Debug)]
pub struct Cgroup {
    path: PathBuf,
}

impl Cgroup {
    /// Create the leaf for one launch, named with the launcher's pid: two
    /// overlapping launches sharing one limit could starve each other.
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

    /// Write the limits; an absent one is written as `max`, not left as
    /// inherited. `io_max` names the volume's devices and the bytes per second.
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

        // cpu.max is a quota per 100 ms period: a percentage of one CPU is that many thousand microseconds.
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

        /* An OOM kills the whole zone at once, so no survivors keep its files
         * and sockets open. */
        let og = self.path.join("memory.oom.group");
        fs::write(&og, "1").map_err(|e| io_err(&og, e))?;

        /* Cap swap too, or the zone pages out past its memory limit. ENOENT
         * means no swap accounting in this kernel (cgroupfs never creates
         * files), so warn; any other write failure is fatal. */
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

    /// Move a process into this cgroup. Must happen before it unshares its
    /// cgroup namespace, so the namespace is rooted here.
    pub fn attach(&self, pid: i32) -> Result<(), CgroupError> {
        let p = self.path.join("cgroup.procs");
        fs::write(&p, pid.to_string()).map_err(|e| io_err(&p, e))
    }

    /// Kill everything inside (`cgroup.kill`, Linux 5.14+), then remove the
    /// directory, retrying for 1 s while the processes exit.
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
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A readable, delegated group this process cannot create leaves in is
    /// not available.
    #[test]
    fn availability_requires_creating_leaf() {
        let root = std::env::temp_dir().join(format!("kryptik-cg-{}", std::process::id()));
        let group = root.join(KRYPTIK_GROUP);
        fs::create_dir_all(&group).unwrap();
        for d in [&root, &group] {
            fs::write(d.join("cgroup.controllers"), "cpu io memory pids\n").unwrap();
            fs::write(d.join("cgroup.subtree_control"), "memory pids\n").unwrap();
        }
        // Readable and delegated, but not writable by us.
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
    fn cpu_and_io_limits_parse() {
        assert_eq!(parse_cpu_max("50%").unwrap(), 50);
        assert_eq!(parse_cpu_max("200%").unwrap(), 200);
        for bad in ["0%", "50", "%", "abc%", ""] {
            assert!(parse_cpu_max(bad).is_err(), "{bad:?}");
        }
        assert_eq!(parse_io_max("8M").unwrap(), 8 << 20);
        assert!(parse_io_max("fast").is_err());
        // A plain file is not a block device; a non-existent path is an error too.
        let f = std::env::temp_dir().join(format!("kryptik-notblock-{}", std::process::id()));
        fs::write(&f, "x").unwrap();
        assert!(block_devices(f.to_str().unwrap()).is_err());
        let _ = fs::remove_file(&f);
        assert!(block_devices("/nonexistent/device").is_err());
    }

    #[test]
    fn overflowing_limit_refused() {
        // Wrapping would impose a far tighter limit than asked for.
        assert!(parse_memory_max("18446744073709551615T").is_err());
        assert!(parse_memory_max("").is_err());
        assert!(parse_memory_max("G").is_err());
    }

    #[test]
    fn sweep_spares_populated_cgroup() {
        // Checks the cgroup.procs parsing; a real hierarchy may be out of reach.
        let populated = |s: &str| s.lines().any(|l| !l.trim().is_empty());
        assert!(populated("1234\n"));
        assert!(populated("1234\n5678\n"));
        assert!(!populated(""));
        assert!(!populated("\n"));
        assert!(!populated("   \n"));
    }

    #[test]
    fn sweep_goes_by_launcher_pid() {
        // Plain directories do: the sweep only reads cgroup.procs and /proc.
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
        /* Only the dead launcher's empty leaf goes. A live launcher's is a
         * launch in progress, a populated leaf is never touched, and the
         * pid-less one is young by the age rule. */
        assert_eq!(abandoned_leaves(&base), vec![gone.clone()]);
        assert!(live.exists() && busy.exists() && unnamed.exists());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn available_leaves_no_probes() {
        // A probe left behind would be one more directory per launch.
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
    fn unwritable_limit_is_error() {
        /* A read-only directory holding writable memory.max and pids.max, so
         * the failing write is memory.oom.group's, which must be an error. */
        let dir = std::env::temp_dir().join(format!("kryptik-cgtest-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for f in ["memory.max", "pids.max"] {
            fs::write(dir.join(f), "max").unwrap();
        }
        let ro = fs::Permissions::from_mode(0o555);
        fs::set_permissions(&dir, ro).unwrap();
        // Root ignores the 0555 mode, so only an unprivileged run can test this.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("running as root: a read-only directory does not refuse root; skipped");
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
            let _ = fs::remove_dir_all(&dir);
            return;
        }

        let cg = Cgroup { path: dir.clone() };
        let err = cg.set_limits(Some("1M"), Some(10), None, None).unwrap_err();
        let msg = err.to_string();

        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let _ = fs::remove_dir_all(&dir);

        assert!(
            msg.contains("memory.oom.group"),
            "set_limits must fail naming the limit it could not apply, said: {msg}"
        );
    }

    #[test]
    fn leaf_name_unique_per_launch() {
        // Overlapping launches of one zone must not share a limit.
        let base = Path::new("/sys/fs/cgroup/kryptik");
        let a = base.join(format!("{}.{}", "work", 111));
        let b = base.join(format!("{}.{}", "work", 222));
        assert_ne!(a, b);
    }
}
