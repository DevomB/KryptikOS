//! The camera, granted to one zone at a time (ADR-026, docs/design/camera.md). uvcvideo loads by
//! no alias (build/config/modprobe.d/camera.conf), so no camera's descriptors are parsed until
//! the user grants the camera in the chrome. kryptikd then loads the driver, finds the camera's
//! node in sysfs and makes it, the zone's root's alone, in the zone's directory here, which the
//! zone has had bound at `IN_ZONE` since it started, /dev/video0 a link into it. The grant ends
//! with the user's gesture, the screen lock or the zone's stop: the node goes, the driver lets
//! go of the device, so a descriptor the zone kept fails from then on, and the module is
//! unloaded unless something still holds it.

use std::ffi::CString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A tmpfs that allows device nodes, which /run does not: a directory per zone that may hold the
/// camera, and the grant's record.
pub const RUN_DIR: &str = "/run/kryptik-camera";
/// Where a zone sees its directory; /dev/video0 links to `NODE` in it.
pub const IN_ZONE: &str = "/run/kryptik/camera";
pub const NODE: &str = "video0";
const DRIVER: &str = "uvcvideo";
const PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
/// The grant's record, and the devices its end let go of, for the next grant to bind again.
const RECORD: &str = "grant";
const LET_GO: &str = "unbound";
/// Written when the driver could not be unloaded: something still holds it.
const STAYED: &str = "stayed";

/// Who holds the camera: the zone, the video4linux node, and the camera's name for the chrome.
#[derive(Debug, PartialEq)]
pub struct Grant {
    pub zone: String,
    pub node: String,
    pub name: String,
}

impl Grant {
    fn render(&self) -> String {
        format!("zone {}\nnode {}\nname {}\n", self.zone, self.node, self.name)
    }

    /// A record as `render` wrote it; anything else is no grant.
    pub fn parse(text: &str) -> Option<Grant> {
        let (mut zone, mut node, mut name) = (None, None, None);
        for line in text.lines() {
            match line.split_once(' ') {
                Some(("zone", z)) if is_zone_name(z) => zone = Some(z.to_string()),
                Some(("node", n)) if is_node(n) => node = Some(n.to_string()),
                Some(("name", n)) => name = Some(n.to_string()),
                _ => return None,
            }
        }
        Some(Grant { zone: zone?, node: node?, name: name? })
    }
}

/// A zone's name as zone.rs allows it: lower-case letters, digits and '-', up to 12.
fn is_zone_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 12 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A video4linux node's name: video and digits.
fn is_node(s: &str) -> bool {
    s.strip_prefix("video").is_some_and(|n| !n.is_empty() && n.len() <= 4 && n.bytes().all(|b| b.is_ascii_digit()))
}

/// The grant in force, if any.
pub fn holder() -> Option<Grant> {
    fs::read_to_string(Path::new(RUN_DIR).join(RECORD)).ok().and_then(|t| Grant::parse(&t))
}

/// Whether the last grant's end left the driver loaded.
pub fn stayed() -> bool {
    Path::new(RUN_DIR).join(STAYED).exists()
}

fn read_trim(p: &Path) -> Option<String> {
    fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

/// The camera's node in `sys`, standing for /sys: of the video4linux devices that are the first
/// node of their device (`index` 0, a UVC camera's capture node and not its metadata one), the
/// lowest numbered; its name, major and minor, and what the device calls itself.
pub fn camera_in(sys: &Path) -> Option<(String, u32, u32, String)> {
    let class = sys.join("class/video4linux");
    let mut found: Vec<(u32, String)> = fs::read_dir(&class).ok()?.flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            let num = n.strip_prefix("video")?.parse::<u32>().ok()?;
            (is_node(&n) && read_trim(&e.path().join("index")).as_deref() == Some("0")).then_some((num, n))
        })
        .collect();
    found.sort();
    let (_, node) = found.into_iter().next()?;
    let dev = read_trim(&class.join(&node).join("dev"))?;
    let (major, minor) = dev.split_once(':')?;
    let name: String = read_trim(&class.join(&node).join("name")).unwrap_or_default()
        .chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(48).collect();
    let name = if name.trim().is_empty() { "a camera".to_string() } else { name.trim().to_string() };
    Some((node, major.parse().ok()?, minor.parse().ok()?, name))
}

/// The device behind a video4linux node and the bus it is on, as /sys names them, from `sys`:
/// what the driver is told to let go of, and later to take again.
fn device_of(sys: &Path, node: &str) -> Option<(PathBuf, String, String)> {
    let dev = fs::canonicalize(sys.join("class/video4linux").join(node).join("device")).ok()?;
    let bus = fs::canonicalize(dev.join("subsystem")).ok()?.file_name()?.to_string_lossy().into_owned();
    let name = dev.file_name()?.to_string_lossy().into_owned();
    Some((dev, bus, name))
}

/// A bus's or a device's name from /sys, for a line of `LET_GO`: one path component.
fn is_sys_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s != "." && s != ".." && s.bytes().all(|b| b.is_ascii_graphic() && b != b'/')
}

fn write_to(path: &Path, text: &str) -> io::Result<()> {
    fs::OpenOptions::new().write(true).open(path)?.write_all(text.as_bytes())
}

fn modprobe(args: &[&str]) -> Result<(), String> {
    let out = Command::new("modprobe").args(args).env_clear().env("PATH", PATH)
        .stdin(Stdio::null()).output().map_err(|e| format!("cannot run modprobe: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    Err(format!("modprobe {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()))
}

/// RUN_DIR as a tmpfs of its own, mounted by the first to need it: /run is nodev.
fn mounted() -> io::Result<()> {
    let lock = fs::OpenOptions::new().write(true).create(true).mode(0o600).custom_flags(libc::O_CLOEXEC)
        .open("/run/kryptik-camera.lock")?;
    // SAFETY: flock on a descriptor we own; the lock goes with it.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    fs::create_dir_all(RUN_DIR)?;
    if fs::metadata(RUN_DIR)?.dev() != fs::metadata("/run")?.dev() {
        return Ok(());
    }
    let (src, dir, kind, opts) = (c("tmpfs"), c(RUN_DIR), c("tmpfs"), c("mode=0755,size=64k"));
    // SAFETY: every pointer is to a NUL-terminated string that outlives the call.
    let r = unsafe {
        libc::mount(src.as_ptr(), dir.as_ptr(), kind.as_ptr(), libc::MS_NOSUID | libc::MS_NOEXEC, opts.as_ptr().cast())
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn c(s: &str) -> CString {
    CString::new(s).expect("no NUL in a constant")
}

/// RUN_DIR mounted now: the compositor watches it for the grant's record, and a watch made
/// before the mount would be on the directory beneath.
pub fn mount_run_dir() -> io::Result<()> {
    mounted()
}

/// The directory `zone` sees at `IN_ZONE`, made when a zone that may hold the camera starts: a
/// node left in it by a grant that ended without kryptikd goes.
pub fn zone_dir(zone: &str) -> io::Result<PathBuf> {
    mounted()?;
    let dir = Path::new(RUN_DIR).join(zone);
    match fs::create_dir(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let md = fs::symlink_metadata(&dir)?;
    if !md.is_dir() || md.uid() != 0 {
        return Err(io::Error::other(format!("{} is not root's directory", dir.display())));
    }
    if holder().is_none_or(|g| g.zone != zone) {
        let _ = fs::remove_file(dir.join(NODE));
    }
    Ok(dir)
}

/// Give `zone` the camera: the driver loaded, devices an earlier grant's end let go of taken
/// again, and the camera's node made in the zone's directory. The camera moves to `zone` if
/// another zone held it.
pub fn grant(zone: &crate::zone::Zone) -> Result<Grant, String> {
    if !zone.camera {
        return Err(format!("zone {}'s file refuses the camera", zone.name));
    }
    let uid = zone.uid_base.ok_or_else(|| format!("zone {} has no fixed uid_base to own the camera's node", zone.name))?;
    if let Some(g) = holder() {
        if g.zone == zone.name {
            return Ok(g);
        }
        revoke()?;
    }
    let dir = zone_dir(&zone.name).map_err(|e| format!("{RUN_DIR}/{}: {e}", zone.name))?;
    modprobe(&[DRIVER])?;
    let _ = fs::remove_file(Path::new(RUN_DIR).join(STAYED));
    if let Ok(text) = fs::read_to_string(Path::new(RUN_DIR).join(LET_GO)) {
        for (bus, dev) in text.lines().filter_map(|l| l.split_once(' ')) {
            if is_sys_name(bus) && is_sys_name(dev) {
                let _ = write_to(&Path::new("/sys/bus").join(bus).join("drivers_probe"), dev);
            }
        }
        let _ = fs::remove_file(Path::new(RUN_DIR).join(LET_GO));
    }
    // A camera's node appears once its driver has probed it, which takes a moment.
    let deadline = Instant::now() + Duration::from_secs(3);
    let (node, major, minor, name) = loop {
        if let Some(found) = camera_in(Path::new("/sys")) {
            break found;
        }
        if Instant::now() > deadline {
            let _ = modprobe(&["-r", DRIVER]);
            return Err("no camera: none is plugged in, or its driver did not take it".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let path = dir.join(NODE);
    let _ = fs::remove_file(&path);
    let cpath = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|e| e.to_string())?;
    // SAFETY: a NUL-terminated path; mknod and chown touch nothing of ours.
    unsafe {
        if libc::mknod(cpath.as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(major, minor)) != 0
            || libc::chown(cpath.as_ptr(), uid, uid) != 0
        {
            let e = io::Error::last_os_error();
            let _ = fs::remove_file(&path);
            return Err(format!("{}: {e}", path.display()));
        }
    }
    let g = Grant { zone: zone.name.clone(), node, name };
    let tmp = Path::new(RUN_DIR).join(".grant");
    let written = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o644).open(&tmp)
        .and_then(|mut f| f.write_all(g.render().as_bytes()))
        .and_then(|()| fs::rename(&tmp, Path::new(RUN_DIR).join(RECORD)));
    if let Err(e) = written {
        let _ = fs::remove_file(&path);
        return Err(format!("{RUN_DIR}/{RECORD}: {e}"));
    }
    Ok(g)
}

/// What a grant's end did: the zone that held the camera, and whether the driver stayed loaded.
pub struct Ended {
    pub zone: String,
    pub stayed: bool,
}

/// Take the camera back from whoever holds it: the node gone, the driver made to let go of the
/// device, so a descriptor kept on it fails, and unloaded unless something still holds it.
pub fn revoke() -> Result<Option<Ended>, String> {
    let Some(g) = holder() else { return Ok(None) };
    match fs::remove_file(Path::new(RUN_DIR).join(&g.zone).join(NODE)) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{RUN_DIR}/{}/{NODE}: {e}", g.zone)),
    }
    // Gone already if the camera was pulled out.
    if let Some((dev, bus, name)) = device_of(Path::new("/sys"), &g.node) {
        write_to(&dev.join("driver/unbind"), &name).map_err(|e| format!("{}: letting go of {name}: {e}", g.name))?;
        if is_sys_name(&bus) && is_sys_name(&name) {
            let mut f = fs::OpenOptions::new().append(true).create(true).mode(0o644).open(Path::new(RUN_DIR).join(LET_GO))
                .map_err(|e| format!("{RUN_DIR}/{LET_GO}: {e}"))?;
            let _ = writeln!(f, "{bus} {name}");
        }
    }
    let stayed = modprobe(&["-r", DRIVER]).is_err();
    if stayed {
        let _ = fs::File::create(Path::new(RUN_DIR).join(STAYED));
    }
    fs::remove_file(Path::new(RUN_DIR).join(RECORD)).map_err(|e| format!("{RUN_DIR}/{RECORD}: {e}"))?;
    Ok(Some(Ended { zone: g.zone, stayed }))
}

#[cfg(test)]
mod tests;
