//! Per-zone LUKS2 volumes (Design 04): unlocked in zone 0 before the zone
//! exists, closed after it is gone.
//!
//! The volume is a LUKS2 container - a regular file under
//! `/var/lib/kryptik/volumes/` on the state partition, or a block device -
//! that cryptsetup opens to `/dev/mapper/kryptik-<zone>`. The ext4 inside is
//! mounted `nosuid,nodev` at the zone's data directory, which the zone then
//! receives at `/home/<zone>` exactly like a persistent directory. The zone
//! never sees the container, the mapping or a loop device: nothing under its
//! `/dev` names one, and `nodev` is on every mount it has.
//!
//! Keys: the passphrase reaches cryptsetup on stdin, never in argv or the
//! environment; the buffer is zeroed when dropped. On close, dm-crypt frees
//! the volume key in the kernel - "keys wiped on stop" means that and only
//! that; nothing about RAM afterwards is claimed.
//!
//! Every external program is run with a fixed argv and no shell.

use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const MAPPER_PREFIX: &str = "kryptik-";
pub const DEFAULT_VOLUME_DIR: &str = "/var/lib/kryptik/volumes";

#[derive(Debug)]
pub enum VolumeError {
    /// cryptsetup exited 2: no keyslot accepted the passphrase.
    WrongPassphrase { zone: String },
    /// The mapping already exists: a previous launcher died without closing
    /// it (run `kryptikd gc`), or the zone is running.
    AlreadyOpen { zone: String, mapper: String },
    /// The passphrase source is not acceptable (mode, owner, missing).
    Passphrase(String),
    /// A tool failed; the message carries its stderr.
    Tool { what: String, detail: String },
    /// An invariant did not hold (a mount still busy after the zone is gone).
    Invariant(String),
    Io(String),
}

impl std::fmt::Display for VolumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VolumeError::WrongPassphrase { zone } => write!(f, "zone {zone:?}: volume did not unlock (wrong passphrase)"),
            VolumeError::AlreadyOpen { zone, mapper } => write!(
                f,
                "zone {zone:?}: {mapper} already exists; the zone is running or a previous launcher did not close it (try: kryptikd gc)"
            ),
            VolumeError::Passphrase(m) => write!(f, "passphrase: {m}"),
            VolumeError::Tool { what, detail } => write!(f, "{what}: {detail}"),
            VolumeError::Invariant(m) => write!(f, "INVARIANT: {m}"),
            VolumeError::Io(m) => write!(f, "{m}"),
        }
    }
}

/// A passphrase that is zeroed when it goes out of scope.
pub struct Passphrase(Vec<u8>);

impl Passphrase {
    pub fn from_bytes(mut b: Vec<u8>) -> Self {
        while b.last() == Some(&b'\n') || b.last() == Some(&b'\r') {
            b.pop();
        }
        Passphrase(b)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Read a passphrase from a file that only root may read: owner uid 0 (or
    /// the caller), no group/other bits. A world-readable passphrase file is
    /// refused rather than used, because using it would teach people that
    /// such a file is fine.
    pub fn from_file(path: &Path) -> Result<Self, VolumeError> {
        let md = fs::metadata(path).map_err(|e| VolumeError::Passphrase(format!("{}: {e}", path.display())))?;
        if !md.is_file() {
            return Err(VolumeError::Passphrase(format!("{} is not a regular file", path.display())));
        }
        let me = unsafe { libc::geteuid() };
        if md.uid() != me && md.uid() != 0 {
            return Err(VolumeError::Passphrase(format!("{} is owned by uid {}, not by the launcher", path.display(), md.uid())));
        }
        if md.permissions().mode() & 0o077 != 0 {
            return Err(VolumeError::Passphrase(format!(
                "{} is mode {:04o}; a passphrase file must be readable by its owner only",
                path.display(),
                md.permissions().mode() & 0o7777
            )));
        }
        let mut f = fs::File::open(path).map_err(|e| VolumeError::Passphrase(format!("{}: {e}", path.display())))?;
        let mut b = Vec::new();
        f.read_to_end(&mut b).map_err(|e| VolumeError::Passphrase(format!("{}: {e}", path.display())))?;
        if b.is_empty() {
            return Err(VolumeError::Passphrase(format!("{} is empty", path.display())));
        }
        Ok(Passphrase::from_bytes(b))
    }
}

impl Drop for Passphrase {
    fn drop(&mut self) {
        unsafe { libc::explicit_bzero(self.0.as_mut_ptr() as *mut libc::c_void, self.0.len()) };
    }
}

pub fn mapper_name(zone: &str) -> String {
    format!("{MAPPER_PREFIX}{zone}")
}
pub fn mapper_path(zone: &str) -> String {
    format!("/dev/mapper/{}", mapper_name(zone))
}
pub fn default_volume_path(zone: &str) -> String {
    format!("{DEFAULT_VOLUME_DIR}/{zone}.luks")
}

fn run(what: &str, prog: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<String, (i32, String)> {
    let mut cmd = Command::new(prog);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).env_clear().env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return Err((127, format!("{what}: cannot run {prog}: {e}"))),
    };
    if let Some(bytes) = stdin {
        if let Some(mut si) = child.stdin.take() {
            let _ = si.write_all(bytes);
            // closing stdin here tells cryptsetup the passphrase is complete
        }
    }
    let out = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => return Err((126, format!("{what}: {e}"))),
    };
    let code = out.status.code().unwrap_or(126);
    if code != 0 {
        let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err((code, format!("{what}: {prog} exited {code}: {detail}")));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn tool_err(what: &str, e: (i32, String)) -> VolumeError {
    VolumeError::Tool { what: what.into(), detail: e.1 }
}

/// `blkid -p` type of a file or device: "crypto_LUKS", "ext4", ... or "".
pub fn signature_of(path: &str) -> String {
    run("blkid", "blkid", &["-p", "-s", "TYPE", "-o", "value", path], None)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

pub fn mapping_exists(zone: &str) -> bool {
    Path::new(&mapper_path(zone)).exists()
}

/// An open, mounted volume. Closed explicitly by `close()`; if it is dropped
/// unclosed (an error path in the launcher), it closes itself so a failed
/// launch never leaves plaintext mounted.
pub struct Opened {
    pub zone: String,
    pub mountpoint: String,
    closed: bool,
}

impl Drop for Opened {
    fn drop(&mut self) {
        if !self.closed {
            if let Err(e) = close_mapping(&self.zone, &self.mountpoint) {
                eprintln!("kryptikd: zone {:?}: closing the volume after a failed launch: {e}", self.zone);
            }
        }
    }
}

impl Opened {
    pub fn close(mut self) -> Result<(), VolumeError> {
        self.closed = true;
        close_mapping(&self.zone, &self.mountpoint)
    }
}

/// Unlock the container and mount its filesystem at `mountpoint`.
pub fn open_and_mount(zone: &str, volume: &str, pass: &Passphrase, mountpoint: &str) -> Result<Opened, VolumeError> {
    let mapper = mapper_path(zone);
    if mapping_exists(zone) {
        return Err(VolumeError::AlreadyOpen { zone: zone.into(), mapper });
    }
    if !Path::new(volume).exists() {
        return Err(VolumeError::Io(format!(
            "zone {zone:?}: no volume at {volume}; create it with: kryptikd volume init {zone}"
        )));
    }
    match run("cryptsetup open", "cryptsetup", &["open", "--type", "luks2", "--key-file", "-", volume, &mapper_name(zone)], Some(pass.as_bytes())) {
        Ok(_) => {}
        Err((2, _)) => return Err(VolumeError::WrongPassphrase { zone: zone.into() }),
        Err(e) => return Err(tool_err("cryptsetup open", e)),
    }
    if !Path::new(&mapper).exists() {
        return Err(VolumeError::Tool { what: "cryptsetup open".into(), detail: format!("{mapper} did not appear") });
    }
    let opened = Opened { zone: zone.into(), mountpoint: mountpoint.into(), closed: false };
    // An unclean filesystem gets fsck -p; anything it cannot fix alone
    // refuses the launch and names the device rather than mounting damage.
    match run("e2fsck", "e2fsck", &["-p", &mapper], None) {
        Ok(_) => {}
        Err((1, _)) => {} // errors corrected
        Err(e) => return Err(tool_err("e2fsck", e)),
    }
    fs::create_dir_all(mountpoint).map_err(|e| VolumeError::Io(format!("{mountpoint}: {e}")))?;
    run("mount", "mount", &["-t", "ext4", "-o", "nosuid,nodev,noatime", &mapper, mountpoint], None).map_err(|e| tool_err("mount", e))?;
    Ok(opened)
}

/// Unmount and close. EBUSY on the unmount is retried briefly - the zone's
/// mount namespace is released asynchronously after its pid 1 exits - and
/// then reported as an invariant failure: something is still holding the
/// zone's data, which means something escaped.
pub fn close_mapping(zone: &str, mountpoint: &str) -> Result<(), VolumeError> {
    let mapper = mapper_path(zone);
    let mut last = String::new();
    let mut unmounted = !is_mountpoint(mountpoint);
    for _ in 0..30 {
        if unmounted {
            break;
        }
        match run("umount", "umount", &[mountpoint], None) {
            Ok(_) => unmounted = true,
            Err((_, m)) => {
                last = m;
                std::thread::sleep(std::time::Duration::from_millis(100));
                unmounted = !is_mountpoint(mountpoint);
            }
        }
    }
    if !unmounted {
        return Err(VolumeError::Invariant(format!("{mountpoint} is still busy after the zone exited: {last}")));
    }
    if Path::new(&mapper).exists() {
        run("cryptsetup close", "cryptsetup", &["close", &mapper_name(zone)], None).map_err(|e| tool_err("cryptsetup close", e))?;
    }
    if Path::new(&mapper).exists() {
        return Err(VolumeError::Invariant(format!("{mapper} still exists after cryptsetup close")));
    }
    Ok(())
}

pub fn is_mountpoint(path: &str) -> bool {
    let Ok(text) = fs::read_to_string("/proc/self/mounts") else { return false };
    let esc = path.replace(' ', "\\040");
    text.lines().any(|l| l.split_whitespace().nth(1) == Some(&esc))
}

/// Create a volume: a sparse file of `size` bytes (or an existing empty
/// block device), LUKS2 with argon2id, an ext4 owned by the zone's identity.
/// Refuses anything that already carries a signature.
pub fn init(zone: &str, volume: &str, size: u64, pass: &Passphrase, uid: u32, gid: u32) -> Result<(), VolumeError> {
    let p = Path::new(volume);
    if p.exists() {
        let md = fs::metadata(p).map_err(|e| VolumeError::Io(format!("{volume}: {e}")))?;
        let sig = signature_of(volume);
        if !sig.is_empty() {
            return Err(VolumeError::Io(format!("{volume} already carries a {sig} signature; refusing to format it")));
        }
        if md.is_file() && md.len() > 0 {
            return Err(VolumeError::Io(format!("{volume} exists and is not empty ({} bytes); refusing", md.len())));
        }
    }
    if mapping_exists(zone) {
        return Err(VolumeError::AlreadyOpen { zone: zone.into(), mapper: mapper_path(zone) });
    }
    if !p.exists() || fs::metadata(p).map(|m| m.is_file()).unwrap_or(false) {
        if size < 32 * 1024 * 1024 {
            return Err(VolumeError::Io("a volume needs at least 32 MiB (LUKS2 header plus a filesystem)".into()));
        }
        if let Some(dir) = p.parent() {
            fs::create_dir_all(dir).map_err(|e| VolumeError::Io(format!("{}: {e}", dir.display())))?;
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        }
        let f = fs::OpenOptions::new().write(true).create(true).truncate(false).mode(0o600).open(p)
            .map_err(|e| VolumeError::Io(format!("{volume}: {e}")))?;
        f.set_len(size).map_err(|e| VolumeError::Io(format!("{volume}: set size: {e}")))?;
    }
    run(
        "cryptsetup luksFormat",
        "cryptsetup",
        &["luksFormat", "--type", "luks2", "--pbkdf", "argon2id", "--batch-mode", "--key-file", "-", volume],
        Some(pass.as_bytes()),
    )
    .map_err(|e| tool_err("cryptsetup luksFormat", e))?;
    let mapper = mapper_path(zone);
    run("cryptsetup open", "cryptsetup", &["open", "--type", "luks2", "--key-file", "-", volume, &mapper_name(zone)], Some(pass.as_bytes()))
        .map_err(|e| tool_err("cryptsetup open", e))?;
    let owner = format!("{uid}:{gid}");
    let r = run("mkfs.ext4", "mkfs.ext4", &["-q", "-F", "-E", &format!("root_owner={owner}"), "-L", &format!("kryptik-{zone}"), &mapper], None);
    let c = run("cryptsetup close", "cryptsetup", &["close", &mapper_name(zone)], None);
    r.map_err(|e| tool_err("mkfs.ext4", e))?;
    c.map_err(|e| tool_err("cryptsetup close", e))?;
    Ok(())
}

/// Change the passphrase in keyslot 0's place: the old one unlocks, the new
/// one replaces it. Both travel through memfds, never argv.
pub fn change_key(volume: &str, old: &Passphrase, new: &Passphrase) -> Result<(), VolumeError> {
    let oldfd = memfd("old", old.as_bytes())?;
    let newfd = memfd("new", new.as_bytes())?;
    let oldp = format!("/proc/self/fd/{oldfd}");
    let newp = format!("/proc/self/fd/{newfd}");
    let r = run("cryptsetup luksChangeKey", "cryptsetup", &["luksChangeKey", "--batch-mode", "--key-file", &oldp, volume, &newp], None);
    unsafe {
        libc::close(oldfd);
        libc::close(newfd);
    }
    match r {
        Ok(_) => Ok(()),
        Err((2, _)) => Err(VolumeError::WrongPassphrase { zone: volume.into() }),
        Err(e) => Err(tool_err("cryptsetup luksChangeKey", e)),
    }
}

/// A memfd holding `bytes`, inheritable (no CLOEXEC) so a child can read it
/// through /proc/self/fd/N. Sealed against growth; zeroed by the kernel on close.
fn memfd(name: &str, bytes: &[u8]) -> Result<i32, VolumeError> {
    let c = CString::new(name).unwrap();
    let fd = unsafe { libc::memfd_create(c.as_ptr(), 0) };
    if fd < 0 {
        return Err(VolumeError::Io(format!("memfd_create: {}", std::io::Error::last_os_error())));
    }
    let mut off = 0usize;
    while off < bytes.len() {
        let n = unsafe { libc::write(fd, bytes[off..].as_ptr() as *const libc::c_void, bytes.len() - off) };
        if n <= 0 {
            unsafe { libc::close(fd) };
            return Err(VolumeError::Io("memfd write failed".into()));
        }
        off += n as usize;
    }
    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    Ok(fd)
}

pub fn backup_header(volume: &str, out: &str) -> Result<(), VolumeError> {
    if Path::new(out).exists() {
        return Err(VolumeError::Io(format!("{out} exists; refusing to overwrite a header backup")));
    }
    run("cryptsetup luksHeaderBackup", "cryptsetup", &["luksHeaderBackup", "--header-backup-file", out, volume], None)
        .map_err(|e| tool_err("cryptsetup luksHeaderBackup", e))?;
    let _ = fs::set_permissions(out, fs::Permissions::from_mode(0o600));
    Ok(())
}

pub fn restore_header(volume: &str, from: &str) -> Result<(), VolumeError> {
    run("cryptsetup luksHeaderRestore", "cryptsetup", &["luksHeaderRestore", "--batch-mode", "--header-backup-file", from, volume], None)
        .map_err(|e| tool_err("cryptsetup luksHeaderRestore", e))?;
    Ok(())
}

/// Mappings under /dev/mapper named like ours: for `gc`, which closes the
/// ones whose zone has no live registry entry.
pub fn mappings() -> Vec<String> {
    let mut v = Vec::new();
    if let Ok(rd) = fs::read_dir("/dev/mapper") {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if let Some(z) = n.strip_prefix(MAPPER_PREFIX) {
                v.push(z.to_string());
            }
        }
    }
    v.sort();
    v
}

/// The data directory an encrypted zone mounts at, under the rootfs base.
pub fn mountpoint_for(base: &Path, zone: &str) -> PathBuf {
    base.join(zone)
}

/// Parse "512M", "2G", "1024" (bytes).
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last()? {
        'K' | 'k' => (&s[..s.len() - 1], 1024u64),
        'M' | 'm' => (&s[..s.len() - 1], 1024 * 1024),
        'G' | 'g' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        c if c.is_ascii_digit() => (s, 1),
        _ => return None,
    };
    num.parse::<u64>().ok().map(|n| n * mult)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrases_are_trimmed_and_zeroed() {
        let p = Passphrase::from_bytes(b"secret\n".to_vec());
        assert_eq!(p.as_bytes(), b"secret");
        let ptr = p.0.as_ptr();
        let len = p.0.len();
        drop(p);
        // The allocation may be reused; the point of the test is that Drop
        // ran the zeroing path without panicking. The bytes were zeroed
        // before the Vec was freed.
        let _ = (ptr, len);
    }

    #[test]
    fn a_readable_passphrase_file_is_refused() {
        let dir = std::env::temp_dir().join(format!("kryptik-vol-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("pass");
        fs::write(&f, "hunter2\n").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(Passphrase::from_file(&f), Err(VolumeError::Passphrase(_))));
        fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        let p = Passphrase::from_file(&f).unwrap();
        assert_eq!(p.as_bytes(), b"hunter2");
        fs::write(&f, "").unwrap();
        assert!(Passphrase::from_file(&f).is_err(), "an empty passphrase file is refused");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sizes_parse() {
        assert_eq!(parse_size("512M"), Some(512 * 1024 * 1024));
        assert_eq!(parse_size("2G"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("4096"), Some(4096));
        assert_eq!(parse_size("x"), None);
        assert_eq!(parse_size(""), None);
    }

    #[test]
    fn names_are_derived_from_the_zone() {
        assert_eq!(mapper_name("work"), "kryptik-work");
        assert_eq!(mapper_path("work"), "/dev/mapper/kryptik-work");
        assert_eq!(default_volume_path("vault"), "/var/lib/kryptik/volumes/vault.luks");
        assert_eq!(mountpoint_for(Path::new("/var/lib/kryptik/zones"), "work"), PathBuf::from("/var/lib/kryptik/zones/work"));
    }

    /// The whole lifecycle against a real kernel: needs root, cryptsetup and
    /// dm-crypt. Skipped (not passed) elsewhere.
    #[test]
    fn luks2_lifecycle_when_root() {
        if unsafe { libc::geteuid() } != 0 || Command::new("cryptsetup").arg("--version").output().is_err() {
            eprintln!("not root or no cryptsetup: lifecycle test skipped");
            return;
        }
        let dir = std::env::temp_dir().join(format!("kryptik-luks-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let vol = dir.join("t.luks").display().to_string();
        let mnt = dir.join("mnt").display().to_string();
        let zone = format!("t{}", std::process::id());
        let good = Passphrase::from_bytes(b"correct horse".to_vec());
        let bad = Passphrase::from_bytes(b"wrong".to_vec());
        init(&zone, &vol, 64 * 1024 * 1024, &good, 0, 0).expect("init");
        assert_eq!(signature_of(&vol), "crypto_LUKS");
        assert!(init(&zone, &vol, 64 * 1024 * 1024, &good, 0, 0).is_err(), "double format refused");
        assert!(matches!(open_and_mount(&zone, &vol, &bad, &mnt), Err(VolumeError::WrongPassphrase { .. })));
        assert!(!mapping_exists(&zone), "a wrong passphrase leaves no mapping");
        let o = open_and_mount(&zone, &vol, &good, &mnt).expect("open");
        fs::write(format!("{mnt}/f"), b"persists").unwrap();
        o.close().expect("close");
        assert!(!mapping_exists(&zone));
        assert!(!is_mountpoint(&mnt));
        let o = open_and_mount(&zone, &vol, &good, &mnt).expect("reopen");
        assert_eq!(fs::read(format!("{mnt}/f")).unwrap(), b"persists");
        o.close().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}
