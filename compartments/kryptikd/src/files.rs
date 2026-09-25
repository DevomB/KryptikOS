//! Files zone 0 keeps state in, written whole. The update channel, the Wi-Fi
//! file, the clipboard and the clock each had a copy of write-then-rename,
//! and the copies had drifted: one followed symlinks, took its mode from the
//! umask and never synced its directory, and three shared one temporary name
//! between any two writers.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// Replace `path` with `parts`, whole. The new file is made beside it under a
/// name of this process's own, O_EXCL and O_NOFOLLOW, with exactly `mode`,
/// owned as asked, and synced before the rename; the directory is synced
/// after it, as far as the filesystem allows. A reader sees the old file or
/// the new one, and a failure leaves the old one and no temporary.
pub fn write_atomic(path: &Path, parts: &[&[u8]], mode: u32, owner: Option<(u32, u32)>) -> io::Result<()> {
    let name = path.file_name().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let stem = format!(".{}.", name.to_string_lossy());
    // A writer that died before its rename left its temporary, perhaps with
    // a secret in it (the Wi-Fi file); one whose process is gone goes now.
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
mod tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kryptik-files-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        private_dir(&d).unwrap();
        d
    }

    fn names(d: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(d).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    #[test]
    fn write_atomic_replaces_whole() {
        let d = scratch("replace");
        let p = d.join("state");
        write_atomic(&p, &[b"old"], 0o600, None).unwrap();
        write_atomic(&p, &[b"new", b"\n", b"parts"], 0o400, None).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"new\nparts");
        assert_eq!(fs::metadata(&p).unwrap().mode() & 0o777, 0o400);
        assert_eq!(names(&d), ["state"], "no temporary left behind");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn write_atomic_clears_dead_writers_temporaries() {
        let d = scratch("dead");
        fs::write(d.join(".state.4294967295"), b"secret").unwrap(); // no such process
        fs::write(d.join(".state.1"), b"init's").unwrap(); // a live one
        write_atomic(&d.join("state"), &[b"new"], 0o600, None).unwrap();
        assert_eq!(names(&d), [".state.1", "state"]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn write_atomic_replaces_a_link_without_following_it() {
        let d = scratch("link");
        let victim = d.join("victim");
        fs::write(&victim, b"untouched").unwrap();
        std::os::unix::fs::symlink(&victim, d.join("state")).unwrap();
        write_atomic(&d.join("state"), &[b"mine"], 0o600, None).unwrap();
        assert!(fs::symlink_metadata(d.join("state")).unwrap().is_file());
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn write_atomic_failure_keeps_old_file() {
        if unsafe { libc::geteuid() } == 0 {
            return; // root may chown to anyone; the refusal below needs a user
        }
        let d = scratch("fail");
        let p = d.join("state");
        write_atomic(&p, &[b"old"], 0o600, None).unwrap();
        assert!(write_atomic(&p, &[b"new"], 0o600, Some((0, 0))).is_err());
        assert_eq!(fs::read(&p).unwrap(), b"old");
        assert_eq!(names(&d), ["state"], "the failed write's temporary is gone");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn private_dir_refuses_what_others_can_reach() {
        let d = scratch("private");
        let open = d.join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(private_dir(&open).is_err(), "a directory others can read");
        std::os::unix::fs::symlink(&d, d.join("link")).unwrap();
        assert!(private_dir(&d.join("link")).is_err(), "a link to a private directory");
        assert!(private_dir(&d.join("made")).is_ok());
        let _ = fs::remove_dir_all(&d);
    }
}
