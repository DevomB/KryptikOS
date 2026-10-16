//! A USB stick's partition given to one zone (ADR-025, docs/design/removable-storage.md). Zone 0
//! reads nothing on the stick: kryptikd makes a device-mapper linear mapping of the one partition
//! the user picked, read-only unless the user chose to write, and the zone's broker hands that
//! mapping to the zone as a descriptor, which the zone's own reader parses (tools/stick). Eject
//! writes out what the zone left unsynced, makes the mapping fail every read and write and drops
//! what was cached of the stick, so a descriptor the zone kept is worthless after; the mapping
//! goes once the last one closes.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::{Command, Stdio};

/// One record per zone given a stick, named after the zone, root's alone to write.
pub const RUN_DIR: &str = "/run/kryptik-stick";
pub const MAPPING_PREFIX: &str = "kryptik-stick-";
const PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
/// _IO(0x12, 97): write a block device's dirty cache out, then drop the clean pages.
const BLKFLSBUF: u32 = 0x1261;

pub fn mapping_name(zone: &str) -> String {
    format!("{MAPPING_PREFIX}{zone}")
}

/// What a zone was given: whether it may write, the partition, and how the chrome names it.
#[derive(Debug, PartialEq)]
pub struct Grant {
    pub writable: bool,
    pub partition: String,
    pub what: String,
}

impl Grant {
    fn render(&self) -> String {
        format!("mode {}\npartition {}\nwhat {}\n", self.mode(), self.partition, self.what)
    }

    pub fn mode(&self) -> &'static str {
        if self.writable { "rw" } else { "ro" }
    }

    /// A record as `render` wrote it; anything else is no grant.
    pub fn parse(text: &str) -> Option<Grant> {
        let (mut writable, mut partition, mut what) = (None, None, None);
        for line in text.lines() {
            match line.split_once(' ') {
                Some(("mode", "rw")) => writable = Some(true),
                Some(("mode", "ro")) => writable = Some(false),
                Some(("partition", p)) if is_name(p) => partition = Some(p.to_string()),
                Some(("what", w)) => what = Some(w.to_string()),
                _ => return None,
            }
        }
        Some(Grant { writable: writable?, partition: partition?, what: what? })
    }
}

/// A block device's name, as sysfs and /dev give it: lower-case letters and digits.
fn is_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// The grant `zone` holds, if any.
pub fn grant_of(zone: &str) -> Option<Grant> {
    fs::read_to_string(Path::new(RUN_DIR).join(zone)).ok().and_then(|t| Grant::parse(&t))
}

/// A partition, or a disk with no partition table, that a zone may be given.
#[derive(Debug, PartialEq)]
pub struct Partition {
    pub name: String,
    /// Its size in 512-byte sectors, as device-mapper counts.
    pub sectors: u64,
    /// For the chrome: the disk's vendor and model, the size, the partition's number and name.
    pub what: String,
}

fn read_trim(p: &Path) -> Option<String> {
    fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

/// What sysfs says of a device, for a terminal: printable ASCII alone, and short.
fn plain(s: &str) -> String {
    let kept: String = s.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(40).collect();
    kept.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The disk a partition is on: the device whose sysfs directory holds the partition's own.
fn disk_of(block: &Path, part: &str) -> Option<String> {
    if !block.join(part).join("partition").exists() {
        return Some(part.to_string());
    }
    fs::read_dir(block).ok()?.flatten().map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|d| d != part && block.join(d).join(part).join("partition").exists())
}

/// Disks the system's own device-mapper devices sit on (the verified root, the state partition):
/// none of their partitions is ever given, though one of them may be held by nothing.
fn system_disks(sys: &Path) -> Vec<String> {
    let block = sys.join("class/block");
    let mut disks = Vec::new();
    for dm in fs::read_dir(sys.join("block")).into_iter().flatten().flatten() {
        let name = read_trim(&dm.path().join("dm/name")).unwrap_or_default();
        if name.is_empty() || name.starts_with(MAPPING_PREFIX) {
            continue;
        }
        for s in fs::read_dir(dm.path().join("slaves")).into_iter().flatten().flatten() {
            if let Some(d) = disk_of(&block, &s.file_name().to_string_lossy()) {
                disks.push(d);
            }
        }
    }
    disks
}

/// Whether `name` may be given to a zone, `sys` standing for /sys and `mounts` for
/// /proc/self/mounts: a partition of a disk on USB or an SD card, or such a disk with no
/// partition table; held by nothing, mounted nowhere, and not on a disk the system's own
/// device-mapper devices use.
pub fn partition_in(sys: &Path, mounts: &str, name: &str) -> Result<Partition, String> {
    if !is_name(name) {
        return Err(format!("{name:?} is not a block device's name"));
    }
    let block = sys.join("class/block");
    let dev = block.join(name);
    if !dev.exists() {
        return Err(format!("no block device {name}"));
    }
    let disk = disk_of(&block, name).ok_or_else(|| format!("{name}: no disk holds it"))?;
    if disk == name && fs::read_dir(&dev).into_iter().flatten().flatten().any(|e| e.path().join("partition").exists()) {
        return Err(format!("{name} has partitions: give one of them"));
    }
    let on_usb = fs::canonicalize(block.join(&disk))
        .is_ok_and(|p| p.components().any(|c| c.as_os_str().to_str().is_some_and(|s| s.starts_with("usb"))));
    let sd_card = read_trim(&block.join(&disk).join("device/type")).as_deref() == Some("SD");
    if !on_usb && !sd_card {
        return Err(format!("{name} is on neither a USB disk nor an SD card"));
    }
    if fs::read_dir(dev.join("holders")).into_iter().flatten().flatten().next().is_some() {
        return Err(format!("{name} is held already: given to a zone, or the system's"));
    }
    let node = format!("/dev/{name}");
    if mounts.lines().any(|l| l.split(' ').next() == Some(node.as_str())) {
        return Err(format!("{name} is mounted in zone 0"));
    }
    if system_disks(sys).contains(&disk) {
        return Err(format!("{name} is on the system's own disk"));
    }
    let sectors = read_trim(&dev.join("size")).and_then(|s| s.parse::<u64>().ok()).filter(|n| *n > 0)
        .ok_or_else(|| format!("{name} has no size"))?;
    let device = block.join(&disk).join("device");
    let model = [read_trim(&device.join("vendor")), read_trim(&device.join("model")), read_trim(&device.join("name"))]
        .into_iter().flatten().map(|s| plain(&s)).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ");
    let mut what = if model.is_empty() { "a USB stick".to_string() } else { model };
    what.push_str(&format!(", {:.1} GB", sectors as f64 * 512.0 / 1e9));
    if let Some(n) = read_trim(&dev.join("partition")) {
        what.push_str(&format!(", partition {}", plain(&n)));
    }
    let label = read_trim(&dev.join("uevent")).and_then(|u| u.lines().find_map(|l| l.strip_prefix("PARTNAME=").map(plain)));
    if let Some(l) = label.filter(|l| !l.is_empty()) {
        what.push_str(&format!(" ({l})"));
    }
    Ok(Partition { name: name.to_string(), sectors, what })
}

/// Every block device a zone may be given now, as `partition_in` decides.
pub fn eligible() -> Vec<Partition> {
    let mounts = fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let mut names: Vec<String> = fs::read_dir("/sys/class/block").into_iter().flatten().flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    names.iter().filter_map(|n| partition_in(Path::new("/sys"), &mounts, n).ok()).collect()
}

/// The device-mapper device (dm-N) of the mapping called `name`, from sysfs.
fn dm_device(sys_block: &Path, name: &str) -> Option<String> {
    fs::read_dir(sys_block).ok()?.flatten().find_map(|e| {
        let n = read_trim(&e.path().join("dm/name"))?;
        (n == name).then(|| e.file_name().to_string_lossy().into_owned())
    })
}

fn dmsetup(args: &[&str]) -> Result<(), String> {
    let out = Command::new("dmsetup").args(args).env_clear().env("PATH", PATH)
        .stdin(Stdio::null()).output().map_err(|e| format!("cannot run dmsetup: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    Err(format!("dmsetup {}: {}", args[0], String::from_utf8_lossy(&out.stderr).trim()))
}

/// The partition `name` given to `zone`, read-only unless `writable`: its mapping made, holding
/// the partition so nothing else mounts it, and the zone's record written.
pub fn grant(zone: &crate::zone::Zone, name: &str, writable: bool) -> Result<Grant, String> {
    if !zone.removable {
        return Err(format!("zone {}'s file refuses USB sticks", zone.name));
    }
    reap_pulled();
    let map = mapping_name(&zone.name);
    if grant_of(&zone.name).is_some() {
        return Err(format!("zone {} holds a stick already: eject it first", zone.name));
    }
    if dm_device(Path::new("/sys/block"), &map).is_some() {
        return Err(format!("a program in zone {} still holds the stick taken back from it, until it ends", zone.name));
    }
    let mounts = fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let p = partition_in(Path::new("/sys"), &mounts, name)?;
    let table = format!("0 {} linear /dev/{} 0", p.sectors, p.name);
    let mut args = vec!["create", map.as_str(), "--table", table.as_str()];
    if !writable {
        args.push("--readonly");
    }
    dmsetup(&args)?;
    let g = Grant { writable, partition: p.name, what: p.what };
    let written = fs::create_dir_all(RUN_DIR).and_then(|()| {
        let tmp = Path::new(RUN_DIR).join(format!(".{}", zone.name));
        let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o644).open(&tmp)?;
        f.write_all(g.render().as_bytes())?;
        fs::rename(&tmp, Path::new(RUN_DIR).join(&zone.name))
    });
    if let Err(e) = written {
        let _ = dmsetup(&["remove", &map]);
        return Err(format!("{RUN_DIR}/{}: {e}", zone.name));
    }
    Ok(g)
}

/// BLKFLSBUF on /dev/DEV.
fn flush_and_drop(dev: &str) -> std::io::Result<()> {
    let f = fs::OpenOptions::new().read(true).custom_flags(libc::O_CLOEXEC).open(format!("/dev/{dev}"))?;
    // SAFETY: BLKFLSBUF takes no argument.
    if unsafe { libc::ioctl(f.as_raw_fd(), BLKFLSBUF as _, 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Take the stick back from `zone`: what it wrote and left unsynced written out first, then its
/// mapping made to fail every read and write and the stick's cached pages dropped, so a
/// descriptor the zone kept reads nothing more; the mapping removed once the last closes, and
/// the record gone. Whether a grant ended; a mapping left without one is cleared all the same.
pub fn eject(zone: &str) -> Result<bool, String> {
    let map = mapping_name(zone);
    let record = Path::new(RUN_DIR).join(zone);
    let held = record.exists();
    if let Some(dev) = dm_device(Path::new("/sys/block"), &map) {
        // A mapping ejected before goes by itself once its last descriptor closes, as when its
        // zone stops, which may be while this runs.
        let gone = || dm_device(Path::new("/sys/block"), &map).is_none();
        let or_gone = |r: Result<(), String>| r.or_else(|e| if gone() { Ok(()) } else { Err(e) });
        // A stick pulled out has nothing to flush to: the drop is what counts then.
        let _ = flush_and_drop(&dev);
        or_gone(dmsetup(&["wipe_table", &map]))?;
        or_gone(flush_and_drop(&dev).map_err(|e| format!("/dev/{dev}: {e}")))?;
        or_gone(dmsetup(&["remove", "--deferred", &map]))?;
    }
    if held {
        // The zone's own end takes the record too, and can while this runs: the wiped table fails
        // the reads of the program that held the stick, and the zone may stop when it exits.
        match fs::remove_file(&record) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(format!("{}: {e}", record.display())),
            _ => {}
        }
    }
    Ok(held)
}

/// Take back every grant whose stick was pulled out: its mapping fails every read already, but
/// holds the gone disk's name until it is removed. The chrome lists sticks whenever a block
/// device comes or goes, which comes here.
pub fn reap_pulled() {
    for e in fs::read_dir(RUN_DIR).into_iter().flatten().flatten() {
        let zone = e.file_name().to_string_lossy().into_owned();
        let Some(g) = grant_of(&zone) else { continue };
        if Path::new("/sys/class/block").join(&g.partition).exists() {
            continue;
        }
        match eject(&zone) {
            Ok(_) => eprintln!("kryptikd: zone {zone:?}: {} was pulled out, so its grant ended", g.what),
            Err(e) => eprintln!("kryptikd: zone {zone:?}: {} was pulled out: {e}", g.what),
        }
    }
}

/// The stick given to `zone`, opened for its broker to hand over: read-only unless granted to
/// write.
pub fn open_for(zone: &str) -> Result<(fs::File, Grant), String> {
    let g = grant_of(zone).ok_or("no USB stick is given to this zone")?;
    if !Path::new("/sys/class/block").join(&g.partition).exists() {
        return Err(format!("{} was pulled out", g.what));
    }
    let name = mapping_name(zone);
    let dev = dm_device(Path::new("/sys/block"), &name).ok_or("the stick was ejected")?;
    let f = fs::OpenOptions::new().read(true).write(g.writable).custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(format!("/dev/{dev}")).map_err(|e| format!("/dev/{dev}: {e}"))?;
    // The name became a number before the open: an eject and a new mapping in between would give
    // that number to another device, a zone's volume among them, so what opened must be this one.
    let rdev = f.metadata().map_err(|e| format!("/dev/{dev}: {e}"))?.rdev();
    if !mapping_at(Path::new("/sys"), rdev, &name) {
        return Err("the stick was ejected".into());
    }
    Ok((f, g))
}

/// Whether the block device numbered `rdev` is the device-mapper mapping called `name`, from `sys`.
fn mapping_at(sys: &Path, rdev: u64, name: &str) -> bool {
    let (major, minor) = (libc::major(rdev), libc::minor(rdev));
    read_trim(&sys.join(format!("dev/block/{major}:{minor}/dm/name"))).as_deref() == Some(name)
}

#[cfg(test)]
mod tests;
