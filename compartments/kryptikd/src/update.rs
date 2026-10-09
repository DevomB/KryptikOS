//! Zone 0's side of the update channel (docs/design/update-channel.md): which pointers it accepts
//! and which bytes it stages; signatures are checked first, by `kryptik-update` (`Checks`).

use std::cmp::Ordering;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const POINTER_MAGIC: &str = "KRYPTIK-LATEST-1";
/// Byte limit for the pointer and for its signature.
pub const POINTER_MAX: usize = 8 * 1024;
/// Byte limit for the manifest and for its signature.
pub const MANIFEST_MAX: u64 = 64 * 1024;
/// Past this age a pointer is reported stale: it is re-issued on a schedule.
pub const STALE_AFTER_SECS: i64 = 30 * 86400;
/// Where a stale pointer is also reported: agetty prints its issue.d drop-ins above every login prompt.
pub const LOGIN_NOTICE: &str = "/run/issue.d/kryptik-update.issue";
/// Skew allowed in a statement's date; one dated later would make every genuine one a replay.
pub const MAX_AHEAD_SECS: i64 = 86400;
/// One pointer is considered per hour; the rest are refused unread.
pub const POINTER_INTERVAL_SECS: u64 = 3600;

/// A statement of what is current, after its signature has verified.
#[derive(Debug, Clone, PartialEq)]
pub struct Pointer {
    pub role: String,
    pub version: String,
    /// Seconds since the epoch.
    pub issued: i64,
    pub manifest_sha256: String,
    pub base: String,
}

fn is_version(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'~'))
}

/// The magic line, then each key once; an unknown key is refused, never half-understood.
pub fn parse_pointer(text: &str) -> Result<Pointer, String> {
    let mut lines = text.lines();
    if lines.next() != Some(POINTER_MAGIC) {
        return Err(format!("not a {POINTER_MAGIC}"));
    }
    let (mut role, mut version, mut issued, mut sha, mut base) = (None, None, None, None, None);
    for line in lines {
        let (k, v) = line.split_once(": ").ok_or_else(|| format!("not a `key: value` line: {line:?}"))?;
        let slot = match k {
            "role" => &mut role,
            "version" => &mut version,
            "issued" => &mut issued,
            "manifest-sha256" => &mut sha,
            "base" => &mut base,
            _ => return Err(format!("unknown key {k:?}")),
        };
        if slot.replace(v.to_string()).is_some() {
            return Err(format!("{k} is given twice"));
        }
    }
    let need = |o: Option<String>, k: &str| o.ok_or_else(|| format!("no {k}"));
    let (role, version, issued, sha, base) =
        (need(role, "role")?, need(version, "version")?, need(issued, "issued")?, need(sha, "manifest-sha256")?, need(base, "base")?);
    if !is_version(&version) {
        return Err(format!("{version:?} is not a version"));
    }
    let issued = crate::time::parse_iso8601(&issued).ok_or_else(|| format!("issued {issued:?} is not a date"))?;
    if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("manifest-sha256 is not 64 lowercase hex digits".into());
    }
    if base.is_empty() || base.len() > 512 || !base.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err("base must be 1 to 512 printable characters without spaces".into());
    }
    Ok(Pointer { role, version, issued, manifest_sha256: sha, base })
}

/// A release's URL: an absolute base as is, a relative one under the `CONF` channel, never under
/// what the net zone reports.
pub fn resolve_base(channel: &str, base: &str, role: &str) -> Result<String, String> {
    let mut url = if base.contains("://") {
        base.to_string()
    } else {
        if base.starts_with('/') || base.split('/').any(|c| c == "..") {
            return Err(format!("relative base {base:?} must stay under the channel address"));
        }
        format!("{}/{}", channel.trim_end_matches('/'), base)
    };
    if !url.ends_with('/') {
        url.push('/');
    }
    match url.split_once("://").map(|(scheme, _)| scheme) {
        Some("https") => Ok(url),
        // Plain http costs privacy, not integrity: the hash is signed.
        Some("http") if role == "development" => Ok(url),
        Some("http") => Err("a production image does not fetch over plain http".into()),
        _ => Err(format!("{url:?} is neither https nor http")),
    }
}

/// Orders versions like `sort -V`: digit runs as numbers, the rest byte by byte.
pub fn version_cmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i].is_ascii_digit() && b[j].is_ascii_digit() {
            let run = |s: &[u8], from: usize| (from..s.len()).find(|&k| !s[k].is_ascii_digit()).unwrap_or(s.len());
            let (ie, je) = (run(a, i), run(b, j));
            let strip = |s: &[u8]| s.iter().position(|&c| c != b'0').map_or(&s[s.len()..], |p| &s[p..]).to_vec();
            let (x, y) = (strip(&a[i..ie]), strip(&b[j..je]));
            match x.len().cmp(&y.len()).then_with(|| x.cmp(&y)) {
                Ordering::Equal => {}
                o => return o,
            }
            (i, j) = (ie, je);
        } else {
            match a[i].cmp(&b[j]) {
                Ordering::Equal => {}
                o => return o,
            }
            (i, j) = (i + 1, j + 1);
        }
    }
    (a.len() - i).cmp(&(b.len() - j))
}

/// Where this machine stands against an accepted pointer.
#[derive(Debug, PartialEq)]
pub enum Standing {
    /// The pointer's release is the running one, or older.
    Current,
    Available(String),
}

/// Accept a verified pointer for this image's role unless it is a replay or dated too far ahead.
pub fn accept_pointer(p: &Pointer, required_role: &str, running: &str, newest_issued: Option<i64>, now: i64) -> Result<Standing, String> {
    if p.role != required_role {
        return Err(format!("the pointer's role is '{}'; this image requires '{required_role}'", p.role));
    }
    if p.issued > now.saturating_add(MAX_AHEAD_SECS) {
        return Err("dated more than a day after this machine's clock: refused, or set the clock".into());
    }
    if let Some(seen) = newest_issued {
        if p.issued < seen {
            return Err("older than a statement this machine has already accepted: a replay".into());
        }
    }
    Ok(if version_cmp(&p.version, running) == Ordering::Greater { Standing::Available(p.version.clone()) } else { Standing::Current })
}

/// Whole days since `issued`, and whether that is stale; a clock behind it reads as zero.
pub fn staleness(now: i64, issued: i64) -> (i64, bool) {
    let age = (now - issued).max(0);
    (age / 86400, age > STALE_AFTER_SECS)
}

/// Whole days the clock reads before `then`, once that is more than the day a statement may lead it.
fn behind(now: i64, then: i64) -> Option<i64> {
    (then > now.saturating_add(MAX_AHEAD_SECS)).then(|| (then - now) / 86400)
}

/// One file of a release, from the verified manifest.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub name: String,
    pub size: u64,
}

/// Parse `check-manifest`'s `file <size> <name>` lines; names must pass the broker's check.
pub fn parse_file_list(text: &str) -> Result<Vec<Entry>, String> {
    let mut out: Vec<Entry> = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("file ") else { continue };
        let (size, name) = rest.split_once(' ').ok_or_else(|| format!("not `file <size> <name>`: {line:?}"))?;
        let size: u64 = size.parse().map_err(|_| format!("{size:?} is not a size"))?;
        crate::broker::check_transfer_name(name)?;
        if name == "manifest" || name == "manifest.sig" || out.iter().any(|e| e.name == name) {
            return Err(format!("the manifest lists {name:?}, which it cannot"));
        }
        out.push(Entry { name: name.to_string(), size });
    }
    if out.is_empty() {
        return Err("the manifest lists no files".into());
    }
    Ok(out)
}

pub fn total_bytes(files: &[Entry]) -> u64 {
    files.iter().fold(0, |sum, e| sum.saturating_add(e.size))
}

/// Whether `len` bytes of `name` may be written at `offset`, with `held` already there.
/// Until the manifest verifies, only it and its signature, whole and small; then listed files,
/// appended in order, never past the signed size.
pub fn may_put(files: Option<&[Entry]>, name: &str, offset: u64, len: u64, held: u64) -> Result<(), String> {
    if len == 0 {
        return Err("nothing to put".into());
    }
    let end = offset.checked_add(len).ok_or("offset and length overflow")?;
    if name == "manifest" || name == "manifest.sig" {
        if files.is_some() {
            return Err(format!("{name} has been verified; it is not replaced"));
        }
        if offset != 0 || end > MANIFEST_MAX {
            return Err(format!("{name} is put whole, from byte 0, in at most {MANIFEST_MAX} bytes"));
        }
        return Ok(());
    }
    let files = files.ok_or("nothing is accepted before the manifest and its signature have verified")?;
    let e = files.iter().find(|e| e.name == name).ok_or_else(|| format!("the signed manifest does not list {name:?}"))?;
    if offset != held {
        return Err(format!("{name}: {held} bytes are held; the next byte wanted is {held}, not {offset}"));
    }
    if end > e.size {
        return Err(format!("{name}: the signed manifest gives it {} bytes; {end} would be past that", e.size));
    }
    Ok(())
}

/// Each missing file and the byte it resumes at, for `update-poll`.
pub fn still_needed(files: &[Entry], held: impl Fn(&str) -> u64) -> Vec<(String, u64)> {
    files.iter().filter_map(|e| { let h = held(&e.name); (h < e.size).then(|| (e.name.clone(), h)) }).collect()
}

/* State under `STATE_DIR`, root's alone:
 *
 *   pointer             the newest statement accepted, as signed
 *   considered          when a statement was last looked at (rate limit)
 *   refused             when a manifest was last refused (rate limit)
 *   wanted              the version asked for (`kryptik update fetch`, or `auto`)
 *   auto                `on` while each newer release is asked for unprompted
 *   files               `check-manifest`'s output for it, once verified
 *   incoming/<version>/ the staged release, the directory `apply` is given
 *
 * Functions take the directory and the checks, so tests supply their own.
 */
pub const STATE_DIR: &str = "/var/lib/kryptik/update";
pub const TOOL: &str = "/usr/sbin/kryptik-update";
pub const ROLE_FILE: &str = "/usr/share/kryptik/trust/required-role";
pub const CONF: &str = "/etc/kryptik/update.conf";
/// What the installer wrote on the state partition, once: its age is how long a machine that has
/// never accepted a statement has gone without one.
pub const INSTALL_RECORD: &str = "/var/lib/kryptik/install.json";
/// The trial `kryptik-update apply` arms and boot-success settles.
pub const TRIAL: &str = "/var/lib/kryptik/boot/trial";
/// Largest `update-put`, so the launcher never goes long without checking its zone.
pub const PUT_MAX: usize = 1 << 20;

/// The signature checks, as functions so a test can stand in for `kryptik-update`.
pub struct Checks<'a> {
    pub pointer: &'a dyn Fn(&Path, &Path) -> Result<(), String>,
    /// Returns what `check-manifest` printed.
    pub manifest: &'a dyn Fn(&Path) -> Result<String, String>,
}

/// Who the checks run as. They read what the net zone sent, with ssh-keygen and the shell's text
/// tools, and need nothing of root's, so a flaw in those parsers is not root's either.
const CHECKER: u32 = 65534;
/// Where the checks' copies go: a tmpfs only root writes and every account may search, which
/// zone 0's /run/kryptik (0700) is not.
const CHECK_BASE: &str = "/run";
/// One check at a time, so what is left of one can be ended without touching another.
const CHECK_LOCK: &str = "/run/kryptik/check.lock";
/// How long a check may take, ample for 64 KiB: one that hangs holds the lock every check waits on.
const CHECK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// `tool VERB` on copies of `inputs`, each a file and the name its copy takes, in a directory of
/// their own under `base`, passed whole when `whole` and one by one otherwise. Under root it runs
/// as `CHECKER` with no new privileges, in a directory it owns and takes as its TMPDIR, one check
/// at a time, and nothing it started outlives it or `deadline`.
fn run_check(tool: &Path, base: &Path, verb: &str, inputs: &[(&Path, &str)], whole: bool, deadline: std::time::Duration) -> Result<String, String> {
    let root = unsafe { libc::geteuid() } == 0;
    let _one = if root { Some(check_lock()?) } else { None };
    let dir = make_scratch(base)?;
    let ran = check_in(tool, &dir, verb, inputs, whole, deadline);
    let _ = std::fs::remove_dir_all(&dir);
    ran
}

/// The lock that keeps checks one at a time; held while the returned file is open.
fn check_lock() -> Result<std::fs::File, String> {
    use std::os::unix::io::AsRawFd;
    let f = std::fs::OpenOptions::new().create(true).append(true).open(CHECK_LOCK).map_err(|e| format!("{CHECK_LOCK}: {e}"))?;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } < 0 {
        return Err(format!("{CHECK_LOCK}: {}", std::io::Error::last_os_error()));
    }
    Ok(f)
}

/// Kill whatever still runs as `CHECKER`: a checker taken over through a parser could leave a
/// process behind, which would sit beside the next check in the directory that check owns. No
/// other process on the host runs as that uid (a zone's nobody is its own base + 65534).
fn end_checker() {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new("/usr/bin/true");
    cmd.env_clear().uid(CHECKER).gid(CHECKER).stdin(std::process::Stdio::null());
    // SAFETY: only kill runs between fork and exec, as CHECKER, which spares the caller.
    unsafe {
        cmd.pre_exec(|| {
            libc::kill(-1, libc::SIGKILL);
            Ok(())
        });
    }
    let _ = cmd.status();
}

fn check_in(tool: &Path, dir: &Path, verb: &str, inputs: &[(&Path, &str)], whole: bool, deadline: std::time::Duration) -> Result<String, String> {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    let root = unsafe { libc::geteuid() } == 0;
    for (from, name) in inputs {
        let to = dir.join(name);
        std::fs::copy(from, &to).map_err(|e| format!("{}: {e}", from.display()))?;
        std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o644)).map_err(|e| format!("{}: {e}", to.display()))?;
    }
    if root {
        std::os::unix::fs::chown(dir, Some(CHECKER), Some(CHECKER)).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let mut cmd = std::process::Command::new(tool);
    cmd.arg(verb);
    if whole {
        cmd.arg(dir);
    } else {
        cmd.args(inputs.iter().map(|(_, name)| dir.join(name)));
    }
    cmd.env_clear().env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin").env("TMPDIR", dir).stdin(std::process::Stdio::null());
    if root {
        cmd.uid(CHECKER).gid(CHECKER);
        // SAFETY: only prctl runs between fork and exec, after the uid has changed.
        unsafe {
            cmd.pre_exec(|| match libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) {
                0 => Ok(()),
                _ => Err(std::io::Error::last_os_error()),
            });
        }
    }
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("{}: {e}", tool.display()))?;
    // Its answer is a few lines, which the pipes hold until it ends.
    let until = std::time::Instant::now() + deadline;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if std::time::Instant::now() < until => std::thread::sleep(std::time::Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Err(e) => return Err(format!("{}: {e}", tool.display())),
        }
    };
    // Nothing the checker started outlives it, or holds its pipes open.
    if root {
        end_checker();
    }
    let Some(status) = status else {
        return Err(format!("{verb} gave no answer within {} s", deadline.as_secs()));
    };
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_end(&mut stdout);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_end(&mut stderr);
    }
    if status.success() {
        return Ok(String::from_utf8_lossy(&stdout).into_owned());
    }
    let err = String::from_utf8_lossy(&stderr);
    Err(err.lines().last().unwrap_or("refused").trim_start_matches("kryptik-update: ").to_string())
}

/// A fresh directory that mkdtemp names under `base`, or under the system's temporary directory.
fn make_scratch(base: &Path) -> Result<PathBuf, String> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let parent = if base.is_dir() { base.to_path_buf() } else { std::env::temp_dir() };
    let mut template = parent.join("kryptik-check.XXXXXX").as_os_str().as_bytes().to_vec();
    template.push(0);
    if unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) }.is_null() {
        return Err(format!("{}: {}", parent.display(), std::io::Error::last_os_error()));
    }
    template.pop();
    Ok(PathBuf::from(std::ffi::OsString::from_vec(template)))
}

/// `kryptik-update VERB DIR` on the manifest and signature in `dir`, all it reads there.
fn check_signed_pair(verb: &str, dir: &Path) -> Result<String, String> {
    let (m, s) = (dir.join("manifest"), dir.join("manifest.sig"));
    run_check(Path::new(TOOL), Path::new(CHECK_BASE), verb, &[(&m, "manifest"), (&s, "manifest.sig")], true, CHECK_DEADLINE)
}

/// The installed system's checks: `kryptik-update`, on copies, as `CHECKER`.
pub fn tool_checks() -> Checks<'static> {
    Checks {
        pointer: &|p, s| {
            let pair = [(p, "latest"), (s, "latest.sig")];
            run_check(Path::new(TOOL), Path::new(CHECK_BASE), "check-pointer", &pair, false, CHECK_DEADLINE).map(|_| ())
        },
        manifest: &|d| check_signed_pair("check-manifest", d),
    }
}

/// `kryptik-update check-release` on the manifest and signature in `dir`:
/// its version and signed date once both verify, in any version order.
pub fn check_release(dir: &Path) -> Result<String, String> {
    check_signed_pair("check-release", dir)
}

/// The role this image requires. A missing file is refused, never read as
/// development: it must not be what decides which releases an image takes.
pub fn required_role() -> Result<String, String> {
    role_from(Path::new(ROLE_FILE))
}

fn role_from(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .map_err(|e| format!("{}: {e}; this image names no role, so it accepts no release", path.display()))
}

pub fn running_version() -> String {
    let text = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    text.lines().find_map(|l| l.strip_prefix("VERSION_ID=")).map(|v| v.trim_matches('"').to_string()).unwrap_or_default()
}

/// `channel = <address>` from `CONF`, the image's own: sysinit prunes a copy written under /etc.
/// The address is only where to ask; answers stand on their signatures.
pub fn channel_from(conf: &str) -> Option<String> {
    conf.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k.trim() == "channel" && !v.trim().is_empty()).then(|| v.trim().to_string())
    })
}

fn private_dir(p: &Path) -> Result<(), String> {
    crate::files::private_dir(p).map_err(|e| format!("{}: {e}", p.display()))
}

/// Written whole and renamed into place, readable by root alone.
fn put_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    crate::files::write_atomic(path, &[bytes], 0o600, None).map_err(|e| format!("{}: {e}", path.display()))
}

fn stored_pointer(dir: &Path) -> Option<Pointer> {
    parse_pointer(&std::fs::read_to_string(dir.join("pointer")).ok()?).ok()
}

fn wanted(dir: &Path) -> Option<String> {
    let v = std::fs::read_to_string(dir.join("wanted")).ok()?.trim().to_string();
    is_version(&v).then_some(v)
}

fn staging(dir: &Path, version: &str) -> PathBuf {
    dir.join("incoming").join(version)
}

fn held(stage: &Path, name: &str) -> u64 {
    std::fs::symlink_metadata(stage.join(name)).ok().filter(|m| m.is_file()).map_or(0, |m| m.len())
}

fn verified_files(dir: &Path, version: &str) -> Option<Vec<Entry>> {
    let text = std::fs::read_to_string(dir.join("files")).ok()?;
    (text.lines().next() == Some(&format!("version: {version}"))).then(|| parse_file_list(&text).ok()).flatten()
}

/// `update-latest`: one pointer per interval, so a hostile zone cannot keep zone 0 verifying.
pub fn latest(dir: &Path, checks: &Checks, now: i64, role: &str, running: &str, pointer: &[u8], sig: &[u8]) -> Result<Standing, String> {
    private_dir(dir)?;
    let last: Option<i64> = std::fs::read_to_string(dir.join("considered")).ok().and_then(|s| s.trim().parse().ok());
    if last.is_some_and(|t| (now - t).unsigned_abs() < POINTER_INTERVAL_SECS) {
        return Err(format!("one statement is considered every {} minutes", POINTER_INTERVAL_SECS / 60));
    }
    put_file(&dir.join("considered"), now.to_string().as_bytes())?;
    let text = std::str::from_utf8(pointer).map_err(|_| "the pointer is not text".to_string())?;
    // Verify before parsing, so a parse error tells an unsigned sender nothing.
    let scratch = dir.join("checking");
    let _ = std::fs::remove_dir_all(&scratch);
    private_dir(&scratch)?;
    let verdict = put_file(&scratch.join("latest"), pointer)
        .and_then(|_| put_file(&scratch.join("latest.sig"), sig))
        .and_then(|_| (checks.pointer)(&scratch.join("latest"), &scratch.join("latest.sig")));
    let _ = std::fs::remove_dir_all(&scratch);
    verdict?;
    let p = parse_pointer(text)?;
    let standing = accept_pointer(&p, role, running, stored_pointer(dir).map(|q| q.issued), now)?;
    put_file(&dir.join("pointer"), pointer)?;
    Ok(standing)
}

/// `kryptik update fetch`, or the poll with `auto` on: asks for the release the
/// newest accepted statement names. Nothing is fetched that was not asked for,
/// and nothing is asked for that this image would not fetch: the poll would
/// only say `idle`.
pub fn want(dir: &Path, channel: Option<&str>, role: &str, running: &str) -> Result<String, String> {
    let p = stored_pointer(dir).ok_or("no statement of what is current has been accepted yet")?;
    if version_cmp(&p.version, running) != Ordering::Greater {
        return Err(format!("{} is the newest release known, and this machine runs {running}", p.version));
    }
    let channel = channel.ok_or_else(|| format!("this image names no update channel ({CONF})"))?;
    // Refused here if this image would not fetch it: the poll would only say `idle`.
    resolve_base(channel, &p.base, role).map_err(|e| format!("{} cannot be fetched: {e}", p.version))?;
    if wanted(dir).as_deref() != Some(p.version.as_str()) {
        let _ = std::fs::remove_file(dir.join("files"));
        let _ = std::fs::remove_dir_all(dir.join("incoming"));
    }
    put_file(&dir.join("wanted"), p.version.as_bytes())?;
    Ok(p.version)
}

/// Anything but `on` is off, a damaged block among them.
fn auto(dir: &Path) -> bool {
    std::fs::read_to_string(dir.join("auto")).is_ok_and(|s| s.trim() == "on")
}

/// `kryptik update auto on|off`. Off asks for nothing more; what was asked
/// for keeps arriving, as after a `fetch`.
pub fn set_auto(dir: &Path, on: bool, channel: Option<&str>) -> Result<(), String> {
    private_dir(dir)?;
    let path = dir.join("auto");
    if !on {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("{}: {e}", path.display())),
            _ => Ok(()),
        };
    }
    if channel.is_none() {
        return Err(format!("this image names no update channel ({CONF}), so there is nothing to fetch"));
    }
    put_file(&path, b"on\n")
}

/// Whether a manifest was refused less than an interval before `now`.
fn refused_lately(dir: &Path, now: i64) -> bool {
    let t: Option<i64> = std::fs::read_to_string(dir.join("refused")).ok().and_then(|s| s.trim().parse().ok());
    t.is_some_and(|t| (now - t).unsigned_abs() < POINTER_INTERVAL_SECS)
}

/// A wanted release: its pointer, its base, and the files still missing with their sizes.
type Outstanding = (Pointer, String, Vec<(String, u64)>);

/// What is wanted, where from, and what of it is still missing: `None` when
/// nothing is, which the broker says as `idle`.
fn outstanding(dir: &Path, channel: &str, role: &str, running: &str, now: i64) -> Option<Outstanding> {
    let version = wanted(dir)?;
    let p = stored_pointer(dir).filter(|p| p.version == version)?;
    if version_cmp(&version, running) != Ordering::Greater {
        return None;
    }
    let base = resolve_base(channel, &p.base, role).ok()?;
    let stage = staging(dir, &version);
    let need = match verified_files(dir, &version) {
        Some(files) => still_needed(&files, |n| held(&stage, n)),
        // The next pair would be refused unread, so none is fetched.
        None if refused_lately(dir, now) => return None,
        None => ["manifest", "manifest.sig"].iter().filter(|n| held(&stage, n) == 0).map(|n| (n.to_string(), 0)).collect(),
    };
    Some((p, base, need))
}

/// `update-poll`: the net zone asks, because nothing can call it. With `auto`
/// on, the release the newest statement names is first asked for, as `fetch`
/// would ask for it.
pub fn poll(dir: &Path, channel: &str, role: &str, running: &str, now: i64) -> String {
    if auto(dir) && stored_pointer(dir).is_some_and(|p| wanted(dir) != Some(p.version)) {
        // Refused as `fetch` would be: nothing newer, or not fetchable here.
        let _ = want(dir, Some(channel), role, running);
    }
    match outstanding(dir, channel, role, running, now) {
        Some((p, base, need)) if !need.is_empty() => {
            let list: Vec<String> = need.iter().map(|(n, o)| format!("{n} {o}")).collect();
            format!("fetch {} {base} need {}", p.version, list.join(" "))
        }
        _ => "idle".into(),
    }
}

fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    (unsafe { libc::statvfs(c.as_ptr(), &mut st) } == 0).then(|| st.f_bavail as u64 * st.f_frsize as u64)
}

/// `update-put`: bytes for the wanted release, under `may_put`'s rule.
pub fn put(dir: &Path, checks: &Checks, now: i64, name: &str, offset: u64, bytes: &[u8]) -> Result<String, String> {
    let version = wanted(dir).ok_or("no release has been asked for")?;
    let p = stored_pointer(dir).filter(|p| p.version == version).ok_or("the release asked for is not the one the newest statement names")?;
    let stage = staging(dir, &version);
    let files = verified_files(dir, &version);
    may_put(files.as_deref(), name, offset, bytes.len() as u64, held(&stage, name))?;
    private_dir(&stage)?;
    let path = stage.join(name);
    if files.is_none() {
        let _ = std::fs::remove_file(&path);
    }
    let mut f = std::fs::OpenOptions::new().append(true).create(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&path)
        .map_err(|e| format!("{name}: {e}"))?;
    f.write_all(bytes).map_err(|e| format!("{name}: {e}"))?;
    drop(f);
    if let Some(files) = files {
        let size = files.iter().find(|e| e.name == name).map_or(0, |e| e.size);
        // may_put required `offset` bytes held, and the append wrote them all.
        let have = offset + bytes.len() as u64;
        return Ok(if have == size { format!("{name} complete") } else { format!("{name} {have}/{size}") });
    }
    if held(&stage, "manifest") == 0 || held(&stage, "manifest.sig") == 0 {
        return Ok(format!("{name} complete"));
    }
    // The pair is in: it must verify, match the pointer's hash and fit the free space.
    let refuse = |why: String| -> Result<String, String> {
        let _ = std::fs::remove_dir_all(&stage);
        Err(why)
    };
    /* One refused manifest per interval: a refusal clears the stage, so a
     * hostile zone could otherwise feed the verifier pairs as fast as it sends. */
    if refused_lately(dir, now) {
        return refuse(format!("a manifest was refused less than {} minutes ago", POINTER_INTERVAL_SECS / 60));
    }
    // Every refusal below starts the interval: each cost a download and a verification.
    let refuse_checked = |why: String| -> Result<String, String> {
        put_file(&dir.join("refused"), now.to_string().as_bytes())?;
        refuse(why)
    };
    let listing = match (checks.manifest)(&stage) {
        Ok(l) => l,
        Err(why) => return refuse_checked(why),
    };
    if listing.lines().next() != Some(&format!("version: {version}")) {
        return refuse_checked(format!("the manifest is not for {version}"));
    }
    if !listing.lines().any(|l| l.strip_prefix("sha256: ") == Some(p.manifest_sha256.as_str())) {
        return refuse_checked("the manifest is not the one the statement of what is current announced".into());
    }
    let files = match parse_file_list(&listing) {
        Ok(f) => f,
        Err(why) => return refuse_checked(why),
    };
    let (need, free) = (total_bytes(&files), free_bytes(&stage).unwrap_or(0));
    if need > free {
        return refuse_checked(format!("the release is {need} bytes and there is room for {free}"));
    }
    put_file(&dir.join("files"), listing.as_bytes())?;
    Ok(format!("{name} complete; the manifest verifies, {} file(s), {need} bytes", files.len()))
}

/// `kryptik update status`, as lines for the user; `since` as for `stale_line`.
pub fn status(dir: &Path, now: i64, running: &str, since: Option<i64>) -> String {
    let mut out = format!("running    {running}\n");
    match stored_pointer(dir) {
        None => out.push_str("newest     unknown: no statement of what is current has been accepted\n"),
        Some(p) => match behind(now, p.issued) {
            Some(days) => out.push_str(&format!("newest     {} (dated {days} day(s) after this machine's clock)\n", p.version)),
            None => out.push_str(&format!("newest     {} (stated {} day(s) ago)\n", p.version, staleness(now, p.issued).0)),
        },
    }
    if let Some(line) = stale_line(dir, now, since) {
        out.push_str(&format!("           {line}\n"));
    }
    out.push_str(if auto(dir) { "fetching   automatically, as each release is announced\n" } else { "fetching   only when asked\n" });
    match wanted(dir) {
        None => out.push_str("staged     nothing asked for\n"),
        Some(v) => {
            let stage = staging(dir, &v);
            match verified_files(dir, &v) {
                None => out.push_str(&format!("staged     {v}: waiting for its manifest\n")),
                Some(files) => {
                    let have: u64 = files.iter().map(|e| held(&stage, &e.name).min(e.size)).sum();
                    let total = total_bytes(&files);
                    let word = if have == total { "complete; `kryptik update apply` installs it" } else { "arriving" };
                    out.push_str(&format!("staged     {v}: {have} of {total} bytes, {word}\n"));
                }
            }
        }
    }
    out
}

/// What `status` and the login prompt say of a statement older than `STALE_AFTER_SECS`.
fn overdue(days: i64) -> String {
    format!("no statement from the release key for {days} days: either nothing has been published, or something is keeping it from this machine")
}

/// The same for a machine that has never accepted one, counted from its install.
fn never_heard(days: i64) -> String {
    format!("no statement from the release key since this machine was installed, {days} days ago: either nothing has been published, or something is keeping it from this machine")
}

/// A clock that reads more than a day before `what` refuses every newer statement as dated
/// ahead of it, so none would ever go stale.
fn clock_behind(days: i64, what: &str) -> String {
    let lag = if days == 1 { "1 day".to_string() } else { format!("{days} days") };
    format!("no statement from the release key can be accepted while this machine's clock reads {lag} before {what}: set the clock")
}

/// `overdue` for the newest accepted statement once it is stale. With none accepted, `never_heard`
/// once `since` is as old: the install, where the image names a channel. `clock_behind` while the
/// clock reads more than a day before either.
pub fn stale_line(dir: &Path, now: i64, since: Option<i64>) -> Option<String> {
    if let Some(p) = stored_pointer(dir) {
        if let Some(days) = behind(now, p.issued) {
            return Some(clock_behind(days, "the newest one it accepted"));
        }
        let (days, stale) = staleness(now, p.issued);
        return stale.then(|| overdue(days));
    }
    let since = since?;
    if let Some(days) = behind(now, since) {
        return Some(clock_behind(days, "its install"));
    }
    let (days, stale) = staleness(now, since);
    stale.then(|| never_heard(days))
}

/// When the record was written, which is when the machine was installed.
pub fn installed_at(record: &Path) -> Option<i64> {
    let t = std::fs::metadata(record).ok()?.modified().ok()?;
    t.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs() as i64)
}

/// The install, if this image names a channel: from then on, statements are expected.
pub fn expecting_since() -> Option<i64> {
    channel_from(&std::fs::read_to_string(CONF).unwrap_or_default())?;
    installed_at(Path::new(INSTALL_RECORD))
}

/// Write `stale_line` to `notice` for the login prompt, or remove it once there is none.
pub fn refresh_login_notice(dir: &Path, notice: &Path, now: i64, since: Option<i64>) -> Result<(), String> {
    let Some(line) = stale_line(dir, now, since) else {
        return match std::fs::remove_file(notice) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("{}: {e}", notice.display())),
            _ => Ok(()),
        };
    };
    if let Some(parent) = notice.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    let text = format!("kryptik update: {line}\n");
    crate::files::write_atomic(notice, &[text.as_bytes()], 0o644, None).map_err(|e| format!("{}: {e}", notice.display()))
}

/// Forget what has arrived of the wanted release: its files and the manifest
/// verified for it. The request stands, so the next poll names everything
/// again. False when the stage could not be removed.
pub fn discard_stage(dir: &Path) -> bool {
    let _ = std::fs::remove_file(dir.join("files"));
    match std::fs::remove_dir_all(dir.join("incoming")) {
        Ok(()) => true,
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
}

/// The staged release's directory once complete, for `kryptik-update apply`.
pub fn complete_stage(dir: &Path) -> Result<PathBuf, String> {
    let v = wanted(dir).ok_or("no release has been asked for")?;
    let files = verified_files(dir, &v).ok_or_else(|| format!("{v}: its manifest has not arrived"))?;
    let stage = staging(dir, &v);
    match still_needed(&files, |n| held(&stage, n)).first() {
        None => Ok(stage),
        Some((name, at)) => Err(format!("{v}: {name} has {at} bytes so far; the release is still arriving")),
    }
}

/// Clear the staged release once the machine runs it or a newer one.
pub fn forget_if_installed(dir: &Path, running: &str) {
    forget_unless_trial(dir, running, Path::new(TRIAL));
}

/// forget_if_installed while no trial is still to be judged and none has just failed: a failed
/// one has `kryptik-update` name this stage for `--retry`. boot-success renames the record to
/// `trial.failed` before it reboots, or instead of rebooting; arming a trial again removes that.
fn forget_unless_trial(dir: &Path, running: &str, trial: &Path) {
    if trial.exists() || trial.with_file_name("trial.failed").exists() {
        return;
    }
    if wanted(dir).is_some_and(|v| version_cmp(&v, running) != Ordering::Greater) {
        for f in ["wanted", "files"] {
            let _ = std::fs::remove_file(dir.join(f));
        }
        let _ = std::fs::remove_dir_all(dir.join("incoming"));
    }
}

#[cfg(test)]
mod tests;
