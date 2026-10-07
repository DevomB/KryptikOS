//! Per-zone LUKS2 volumes (docs/design/encrypted-volumes.md), opened in zone 0 before the zone
//! exists and closed after it is gone; the zone sees only the ext4 inside, mounted `nosuid,nodev`.
//! Passphrases go on stdin or in a memfd, never argv, and no tool runs through a shell.

use std::ffi::CString;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Only zone volumes map under this prefix; `gc` closes whatever it finds there.
pub const MAPPER_PREFIX: &str = "kryptik-zone-";
pub const DEFAULT_VOLUME_DIR: &str = "/var/lib/kryptik/volumes";

#[derive(Debug)]
pub enum VolumeError {
    /// cryptsetup exited 2: no keyslot accepted the passphrase.
    WrongPassphrase { zone: String },
    /// The mapping exists: the zone is running, or a dead launcher left it (`kryptikd gc`).
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
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Read from a regular file owned by root or the caller, with no group or other access.
    pub fn from_file(path: &Path) -> Result<Self, VolumeError> {
        /* Check the opened inode, not the path, which could be swapped. NONBLOCK
         * keeps a planted FIFO from hanging open() before the type check. */
        let f = fs::OpenOptions::new().read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)
            .map_err(|e| VolumeError::Passphrase(format!("{}: {e}", path.display())))?;
        let md = f.metadata().map_err(|e| VolumeError::Passphrase(format!("{}: {e}", path.display())))?;
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
        Self::read_bounded(f)
    }

    /// Read from a memfd or pipe passed over SCM_RIGHTS, closing `fd`; a pipe must end within 5 s.
    pub fn from_fd(fd: i32) -> Result<Self, VolumeError> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(VolumeError::Passphrase(format!("fd {fd} is not open")));
        }
        let mut original = unsafe { fs::File::from_raw_fd(fd) };
        if flags & libc::O_PATH != 0 || flags & libc::O_ACCMODE == libc::O_WRONLY {
            return Err(VolumeError::Passphrase("descriptor is not readable".into()));
        }
        let md = original.metadata().map_err(|e| VolumeError::Passphrase(e.to_string()))?;
        if !md.is_file() && !md.file_type().is_fifo() {
            return Err(VolumeError::Passphrase("descriptor must be a regular file or pipe".into()));
        }
        /* A passed fd shares flags and offset with the sender. Reopening the
         * inode gives a private NONBLOCK description, which dup() would not. */
        let mut f = fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK)
            .open(format!("/proc/self/fd/{fd}"))
            .map_err(|e| VolumeError::Passphrase(format!("reopening fd {fd}: {e}")))?;
        if md.is_file() {
            let offset = original.stream_position().map_err(|e| VolumeError::Passphrase(e.to_string()))?;
            f.seek(SeekFrom::Start(offset)).map_err(|e| VolumeError::Passphrase(e.to_string()))?;
        }
        drop(original);
        Self::read_bounded(f)
    }

    fn read_bounded(mut f: fs::File) -> Result<Self, VolumeError> {
        use std::time::{Duration, Instant};
        /* One fixed allocation, so no realloc leaves a copy, owned by
         * Passphrase before the first read so every exit zeroes it. */
        let mut pass = Passphrase(vec![0; 4097]);
        let mut used = 0;
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(VolumeError::Passphrase("source did not reach EOF within 5 seconds".into()));
            }
            let mut pfd = libc::pollfd { fd: f.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            let ready = unsafe { libc::poll(&mut pfd, 1, left.as_millis() as i32) };
            if ready < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted { continue; }
                return Err(VolumeError::Passphrase(e.to_string()));
            }
            if ready == 0 { continue; }
            match f.read(&mut pass.0[used..]) {
                Ok(0) => break,
                Ok(n) => used += n,
                Err(e) if matches!(e.kind(), std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock) => continue,
                Err(e) => return Err(VolumeError::Passphrase(e.to_string())),
            }
            if used > 4096 {
                return Err(VolumeError::Passphrase("passphrase longer than 4096 bytes".into()));
            }
        }
        pass.0.truncate(used);
        while matches!(pass.0.last(), Some(b'\r' | b'\n')) { pass.0.pop(); }
        if pass.0.is_empty() {
            return Err(VolumeError::Passphrase("source carried no passphrase".into()));
        }
        Ok(pass)
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
            // Dropping stdin marks the end of the passphrase.
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
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
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

/// An open, mounted volume, closed on drop so a failed launch never leaves plaintext mounted.
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
    // Damage that fsck -p cannot fix refuses the launch instead of being mounted.
    match run("e2fsck", "e2fsck", &["-p", &mapper], None) {
        Ok(_) => {}
        Err((1, _)) => {} // errors corrected
        Err(e) => return Err(tool_err("e2fsck", e)),
    }
    fs::create_dir_all(mountpoint).map_err(|e| VolumeError::Io(format!("{mountpoint}: {e}")))?;
    run("mount", "mount", &["-t", "ext4", "-o", "nosuid,nodev,noatime", &mapper, mountpoint], None).map_err(|e| tool_err("mount", e))?;
    Ok(opened)
}

/// Unmount and close; dm-crypt then frees the volume key.
pub fn close_mapping(zone: &str, mountpoint: &str) -> Result<(), VolumeError> {
    let mapper = mapper_path(zone);
    let mut last = String::new();
    let mut unmounted = !is_mountpoint(mountpoint);
    // A dead zone's mount namespace goes asynchronously; still busy after 3 s, something escaped.
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

/// `path` as /proc/self/mounts writes it, with space, tab, newline and
/// backslash octal-escaped; backslash goes first, as the others add one.
fn mount_escaped(path: &str) -> String {
    path.replace('\\', "\\134").replace(' ', "\\040").replace('\t', "\\011").replace('\n', "\\012")
}

pub fn is_mountpoint(path: &str) -> bool {
    let Ok(text) = fs::read_to_string("/proc/self/mounts") else { return false };
    let esc = mount_escaped(path);
    text.lines().any(|l| l.split_whitespace().nth(1) == Some(&esc))
}

/// Create LUKS2 (argon2id) on a sparse file or blank device, holding an ext4 owned by the zone.
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

/// Replace passphrase `old` with `new`; both travel through memfds, never argv.
pub fn change_key(zone: &str, volume: &str, old: &Passphrase, new: &Passphrase) -> Result<(), VolumeError> {
    let oldfd = memfd("old", old.as_bytes())?;
    let newfd = memfd("new", new.as_bytes())?;
    let oldp = format!("/proc/self/fd/{}", oldfd.as_raw_fd());
    let newp = format!("/proc/self/fd/{}", newfd.as_raw_fd());
    match run("cryptsetup luksChangeKey", "cryptsetup", &["luksChangeKey", "--batch-mode", "--key-file", &oldp, volume, &newp], None) {
        Ok(_) => Ok(()),
        Err((2, _)) => Err(VolumeError::WrongPassphrase { zone: zone.into() }),
        Err(e) => Err(tool_err("cryptsetup luksChangeKey", e)),
    }
}

/// A memfd holding `bytes`, without CLOEXEC so a child can read /proc/self/fd/N.
fn memfd(name: &str, bytes: &[u8]) -> Result<OwnedFd, VolumeError> {
    let c = CString::new(name).unwrap();
    let fd = unsafe { libc::memfd_create(c.as_ptr(), 0) };
    if fd < 0 {
        return Err(VolumeError::Io(format!("memfd_create: {}", std::io::Error::last_os_error())));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut off = 0usize;
    while off < bytes.len() {
        let n = unsafe { libc::write(fd.as_raw_fd(), bytes[off..].as_ptr() as *const libc::c_void, bytes.len() - off) };
        if n <= 0 {
            return Err(VolumeError::Io("memfd write failed".into()));
        }
        off += n as usize;
    }
    unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) };
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

/// Erase a zone's key slots, then delete its container file: back to before `volume init`.
pub fn destroy(zone: &str, volume: &str) -> Result<(), VolumeError> {
    if mapping_exists(zone) {
        return Err(VolumeError::Io(format!(
            "zone {zone:?}: its volume is open at {}; stop the zone first (kryptikd stop {zone})",
            mapper_path(zone)
        )));
    }
    let p = Path::new(volume);
    let md = match fs::metadata(p) {
        Ok(md) => md,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(VolumeError::Io(format!("zone {zone:?}: no volume at {volume}")))
        }
        Err(e) => return Err(VolumeError::Io(format!("{volume}: {e}"))),
    };
    if !md.is_file() {
        return Err(VolumeError::Io(format!("{volume} is not a file; a block device is wiped by hand, not deleted")));
    }
    let sig = signature_of(volume);
    if !sig.contains("crypto_LUKS") {
        return Err(VolumeError::Io(format!(
            "{volume} carries {} rather than a LUKS signature; refusing to delete what volume init did not make",
            if sig.is_empty() { "no signature".to_string() } else { format!("a {sig} signature") }
        )));
    }
    // Slots first: an unlinked file's blocks linger, but without slots no key decrypts them.
    run("cryptsetup luksErase", "cryptsetup", &["luksErase", "--batch-mode", volume], None)
        .map_err(|e| tool_err("cryptsetup luksErase", e))?;
    fs::remove_file(p).map_err(|e| VolumeError::Io(format!("{volume}: {e}")))
}

/// Zones with a mapping under /dev/mapper, for `gc`.
pub fn mappings() -> Vec<String> {
    let names = fs::read_dir("/dev/mapper")
        .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    zones_mapped(names)
}

fn zones_mapped(names: Vec<String>) -> Vec<String> {
    let mut v: Vec<String> = names.iter().filter_map(|n| n.strip_prefix(MAPPER_PREFIX).map(str::to_string)).collect();
    v.sort();
    v
}

/// The data directory an encrypted zone mounts at, under the rootfs base.
pub fn mountpoint_for(base: &Path, zone: &str) -> PathBuf {
    base.join(zone)
}

#[cfg(test)]
mod tests;
