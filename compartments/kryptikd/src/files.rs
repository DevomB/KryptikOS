//! Zone 0's state files, written whole: the update channel's, the Wi-Fi
//! file, the clipboard and the clock's.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// Replace `path` with `parts`, whole: a temporary named for this process,
/// O_EXCL|O_NOFOLLOW with exactly `mode` and owned as asked, synced, renamed
/// over the file, then the directory synced where the filesystem allows. A
/// failure leaves the old file and no temporary.
pub fn write_atomic(path: &Path, parts: &[&[u8]], mode: u32, owner: Option<(u32, u32)>) -> io::Result<()> {
    let name = path.file_name().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let stem = format!(".{}.", name.to_string_lossy());
    /* A writer that died before its rename leaves its temporary, perhaps
     * with a secret in it (the Wi-Fi file). */
    for e in fs::read_dir(dir)?.flatten() {
        let n = e.file_name();
        let pid = n.to_str().and_then(|s| s.strip_prefix(stem.as_str())).and_then(|p| p.parse::<u32>().ok());
        if pid.is_some_and(|p| !Path::new(&format!("/proc/{p}")).exists()) {
            let _ = fs::remove_file(e.path());
        }
    }
    let tmp = dir.join(format!("{stem}{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let r = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        for p in parts {
            f.write_all(p)?;
        }
        f.set_permissions(fs::Permissions::from_mode(mode))?; // not what the umask left
        if let Some((uid, gid)) = owner {
            if unsafe { libc::fchown(f.as_raw_fd(), uid, gid) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if r.is_err() {
        let _ = fs::remove_file(&tmp);
        return r;
    }
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Make or find a directory of this user's alone. One that was there is
/// looked at: a link, another owner, or a mode that lets anyone else in is
/// refused.
pub fn private_dir(p: &Path) -> io::Result<()> {
    match fs::DirBuilder::new().recursive(true).mode(0o700).create(p) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let m = fs::symlink_metadata(p)?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "not a directory of this user's alone"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
