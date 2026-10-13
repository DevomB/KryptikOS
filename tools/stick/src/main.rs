//! kryptik-stick: the FAT filesystem on a USB stick the user gave this zone, read and written
//! here (ADR-025, docs/design/removable-storage.md). Nothing mounts the stick. Zone 0 hands the
//! zone a descriptor on the one partition granted, and this program parses the filesystem on it,
//! in an unprivileged process of this zone, so a hostile filesystem reaches nothing past it.
//!
//!   kryptik-stick                  what this zone was given
//!   kryptik-stick list [DIR]       a directory of the stick, / unless named
//!   kryptik-stick get PATH [DEST]  a file or a directory copied off the stick, into . unless named
//!   kryptik-stick put FILE [DIR]   a file copied onto the stick, into / unless named
//!
//! `--device FILE` reads FILE in place of the partition zone 0 hands over, for an image or a test.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fatfs::{FileSystem, FsOptions, ReadWriteSeek};

/// The zone's end of its broker, which kryptikd binds in (docs/design/broker.md).
const BROKER: &str = "/run/kryptik/broker";
/// Deeper than this, a directory tree is one built to loop.
const MAX_DEPTH: usize = 32;

const USAGE: &str = "usage: kryptik-stick [--device FILE] [list [DIR] | get PATH [DEST] | put FILE [DIR]]";

/// The partition, which refuses every write when the grant is read-only, whatever fatfs asks.
pub struct Disk {
    file: fs::File,
    writable: bool,
}

impl Read for Disk {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Seek for Disk {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}

impl Write for Disk {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.writable {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the stick was given to this zone read-only"));
        }
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// What zone 0's broker says of the grant, beside the descriptor.
struct Grant {
    disk: Disk,
    what: String,
}

/// FAT keeps local times, to two seconds, between 1980 and 2107; this zone's clock, as UTC, is
/// the nearest it has.
#[derive(Debug)]
struct Clock;

static CLOCK: Clock = Clock;

impl fatfs::TimeProvider for Clock {
    fn get_current_date(&self) -> fatfs::Date {
        self.get_current_date_time().date
    }

    fn get_current_date_time(&self) -> fatfs::DateTime {
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let (year, month, day, hour, min, sec) = civil(secs);
        fatfs::DateTime { date: fatfs::Date { year, month, day }, time: fatfs::Time { hour, min, sec, millis: 0 } }
    }
}

/// Seconds since 1970 as a UTC date and time, the year held to what FAT can say.
fn civil(secs: u64) -> (u16, u16, u16, u16, u16, u16) {
    // Days to a civil date (H. Hinnant's days_from_civil, inverted), from a March-based year.
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let (year, month, day, rem) = match year {
        y if y < 1980 => (1980, 1, 1, 0),
        y if y > 2107 => (2107, 12, 31, 86_399),
        y => (y, month, day, rem),
    };
    (year as u16, month as u16, day as u16, (rem / 3600) as u16, (rem / 60 % 60) as u16, (rem % 60) as u16)
}

/// A name the stick holds, for a terminal: control characters, which could act on it, as `?`.
fn shown(name: &str) -> String {
    name.chars().map(|c| if c.is_control() { '?' } else { c }).collect()
}

/// A name the stick holds, as one component of a path here, or why it cannot be one.
fn local_name(name: &str) -> Result<&str, String> {
    match name {
        "" | "." | ".." => Err(format!("the stick holds an entry named {:?}, which is no file name here", shown(name))),
        n if n.contains(['/', '\0']) => Err(format!("the stick holds an entry named {:?}, which is no file name here", shown(n))),
        n => Ok(n),
    }
}

/// A path on the stick without its leading and trailing slashes; / is "".
fn on_stick(path: &str) -> &str {
    path.trim_matches('/')
}

fn open_dir<'a, T: ReadWriteSeek>(fs: &'a FileSystem<T>, dir: &str) -> Result<fatfs::Dir<'a, T>, String> {
    match on_stick(dir) {
        "" => Ok(fs.root_dir()),
        d => fs.root_dir().open_dir(d).map_err(|e| format!("{}: {e}", shown(dir))),
    }
}

/// A directory's entries, `.` and `..` left out: name, whether a directory, length.
fn entries<T: ReadWriteSeek>(fs: &FileSystem<T>, dir: &str) -> Result<Vec<(String, bool, u64)>, String> {
    let mut out = Vec::new();
    for e in open_dir(fs, dir)?.iter() {
        let e = e.map_err(|e| format!("{}: {e}", shown(dir)))?;
        let name = e.file_name();
        if name != "." && name != ".." {
            out.push((name, e.is_dir(), e.len()));
        }
    }
    Ok(out)
}

/// A file of the stick copied to `to`, which must not exist yet.
fn copy_file_out<T: ReadWriteSeek>(mut from: fatfs::File<'_, T>, to: &Path) -> Result<u64, String> {
    let mut out = fs::OpenOptions::new().write(true).create_new(true).open(to).map_err(|e| format!("{}: {e}", to.display()))?;
    io::copy(&mut from, &mut out).map_err(|e| format!("{}: {e}", to.display()))
}

/// A directory of the stick copied to `to`, made new; the bytes copied.
fn copy_dir_out<T: ReadWriteSeek>(from: &fatfs::Dir<'_, T>, to: &Path, depth: usize) -> Result<u64, String> {
    if depth > MAX_DEPTH {
        return Err(format!("{}: directories nested more than {MAX_DEPTH} deep", to.display()));
    }
    fs::create_dir(to).map_err(|e| format!("{}: {e}", to.display()))?;
    let mut copied = 0;
    for e in from.iter() {
        let e = e.map_err(|e| format!("{}: {e}", to.display()))?;
        let name = e.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let target = to.join(local_name(&name)?);
        copied += if e.is_dir() { copy_dir_out(&e.to_dir(), &target, depth + 1)? } else { copy_file_out(e.to_file(), &target)? };
    }
    Ok(copied)
}

/// PATH copied off the stick: into DEST when it is a directory, else as DEST; the bytes copied.
fn get<T: ReadWriteSeek>(fs: &FileSystem<T>, path: &str, dest: &Path) -> Result<u64, String> {
    let p = on_stick(path);
    let name = p.rsplit('/').next().unwrap_or(p);
    let target = if dest.is_dir() && !p.is_empty() { dest.join(local_name(name)?) } else { dest.to_path_buf() };
    if p.is_empty() {
        return copy_dir_out(&fs.root_dir(), &target, 0);
    }
    match fs.root_dir().open_dir(p) {
        Ok(d) => copy_dir_out(&d, &target, 0),
        Err(_) => {
            let f = fs.root_dir().open_file(p).map_err(|e| format!("{}: {e}", shown(path)))?;
            copy_file_out(f, &target)
        }
    }
}

/// A regular file here copied onto the stick into DIR, under its own name, which must be free.
fn put<T: ReadWriteSeek>(fs: &FileSystem<T>, file: &Path, dir: &str) -> Result<u64, String> {
    let mut from = fs::File::open(file).map_err(|e| format!("{}: {e}", file.display()))?;
    if !from.metadata().map_err(|e| format!("{}: {e}", file.display()))?.is_file() {
        return Err(format!("{} is not a file", file.display()));
    }
    let name = file.file_name().and_then(|n| n.to_str()).ok_or_else(|| format!("{}: a name the stick cannot hold", file.display()))?;
    let d = open_dir(fs, dir)?;
    if d.open_file(name).is_ok() || d.open_dir(name).is_ok() {
        return Err(format!("{}/{name} is on the stick already", on_stick(dir)));
    }
    let mut to = d.create_file(name).map_err(|e| format!("{name}: {e}"))?;
    let n = io::copy(&mut from, &mut to).map_err(|e| format!("{name}: {e}"))?;
    to.flush().map_err(|e| format!("{name}: {e}"))?;
    Ok(n)
}

/// One descriptor and the line it came with, from the broker's reply.
fn recv_with_fd(s: &UnixStream) -> Result<(String, Option<fs::File>), String> {
    let mut buf = [0u8; 512];
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    let mut space = [0u64; 8];
    // SAFETY: an all-zero msghdr is valid; the pointers set below outlive the call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = space.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&space) as _;
    // SAFETY: msg describes live buffers of the lengths given.
    let n = unsafe { libc::recvmsg(s.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(format!("{BROKER}: {}", io::Error::last_os_error()));
    }
    let mut fds: Vec<RawFd> = Vec::new();
    // SAFETY: walks the control messages recvmsg filled in, within msg_controllen.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(c).cast::<RawFd>();
                let count = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / std::mem::size_of::<RawFd>();
                for i in 0..count {
                    fds.push(std::ptr::read_unaligned(data.add(i)));
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    // SAFETY: each descriptor arrived in this message, and nothing else owns it.
    let mut files = fds.into_iter().map(|fd| unsafe { fs::File::from_raw_fd(fd) });
    let file = files.next();
    // A second would be zone 0's mistake; closed.
    drop(files);
    let mut text = buf[..n as usize].to_vec();
    (&*s).take(4096).read_to_end(&mut text).map_err(|e| format!("{BROKER}: {e}"))?;
    Ok((String::from_utf8_lossy(&text).into_owned(), file))
}

/// The partition the user gave this zone, from zone 0's broker: `stick` asked, and `ok ro|rw WHAT`
/// answered with its descriptor, or `error: WHY`.
fn ask_broker() -> Result<Grant, String> {
    let s = UnixStream::connect(BROKER).map_err(|e| format!("{BROKER}: {e}: this zone has no broker to ask"))?;
    (&s).write_all(b"stick\n").map_err(|e| format!("{BROKER}: {e}"))?;
    s.shutdown(std::net::Shutdown::Write).map_err(|e| format!("{BROKER}: {e}"))?;
    let (reply, file) = recv_with_fd(&s)?;
    let line = reply.lines().next().unwrap_or("");
    let Some(rest) = line.strip_prefix("ok ") else {
        return Err(line.strip_prefix("error: ").unwrap_or("zone 0's broker gave no answer").to_string());
    };
    let (mode, what) = rest.split_once(' ').unwrap_or((rest, "a USB stick"));
    let writable = match mode {
        "rw" => true,
        "ro" => false,
        _ => return Err(format!("zone 0's broker answered {:?}", shown(line))),
    };
    let file = file.ok_or("zone 0's broker answered without the stick's descriptor")?;
    Ok(Grant { disk: Disk { file, writable }, what: shown(what) })
}

/// FILE itself, to read and write if this user may, else to read.
fn open_device(path: &str) -> Result<Grant, String> {
    let (file, writable) = match fs::OpenOptions::new().read(true).write(true).open(path) {
        Ok(f) => (f, true),
        Err(_) => (fs::File::open(path).map_err(|e| format!("{path}: {e}"))?, false),
    };
    Ok(Grant { disk: Disk { file, writable }, what: path.to_string() })
}

fn run(args: &[String]) -> Result<(), String> {
    let (device, args) = match args {
        [flag, path, rest @ ..] if flag == "--device" => (Some(path.as_str()), rest),
        _ => (None, args),
    };
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    if !matches!(words.as_slice(), [] | ["list"] | ["list", _] | ["get", _] | ["get", _, _] | ["put", _] | ["put", _, _]) {
        return Err(USAGE.to_string());
    }
    let grant = match device {
        Some(p) => open_device(p)?,
        None => ask_broker()?,
    };
    let writable = grant.disk.writable;
    // The partition's own descriptor, for the sync after fatfs has written its last.
    let syncer = grant.disk.file.try_clone().map_err(|e| e.to_string())?;
    let fs = FileSystem::new(grant.disk, FsOptions::new().time_provider(&CLOCK))
        .map_err(|e| format!("{}: no FAT filesystem this reader knows: {e}", grant.what))?;
    match words.as_slice() {
        [] => {
            let stats = fs.stats().map_err(|e| e.to_string())?;
            println!("{}: FAT{}, {}", grant.what, match fs.fat_type() {
                fatfs::FatType::Fat12 => 12,
                fatfs::FatType::Fat16 => 16,
                fatfs::FatType::Fat32 => 32,
            }, if writable { "to read and write" } else { "read-only" });
            println!("label {:?}, {} bytes free", shown(fs.volume_label().trim_end()),
                     u64::from(stats.free_clusters()) * u64::from(stats.cluster_size()));
        }
        ["list"] | ["list", _] => {
            for (name, dir, len) in entries(&fs, words.get(1).copied().unwrap_or("/"))? {
                if dir {
                    println!("{:>12}  {}/", "", shown(&name));
                } else {
                    println!("{len:>12}  {}", shown(&name));
                }
            }
        }
        ["get", path] | ["get", path, _] => {
            let dest = PathBuf::from(words.get(2).copied().unwrap_or("."));
            let n = get(&fs, path, &dest)?;
            println!("copied {n} bytes off the stick");
        }
        ["put", file] | ["put", file, _] => {
            let n = put(&fs, Path::new(file), words.get(2).copied().unwrap_or("/"))?;
            fs.unmount().map_err(|e| format!("{}: {e}", grant.what))?;
            // On the stick, not only in this machine's cache, before the user pulls it out.
            syncer.sync_all().map_err(|e| format!("{}: {e}", grant.what))?;
            println!("copied {n} bytes onto the stick");
        }
        _ => unreachable!("the words were matched above"),
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e == USAGE => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("kryptik-stick: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
