//! The update channel's rules (docs/design/update-channel.md): what zone 0
//! believes about a statement of what is current, and which bytes it will
//! take from the net zone for a release it has been asked to fetch.
//!
//! Nothing here verifies a signature. `kryptik-update check-pointer` and
//! `check-manifest` do that, with the code that verifies a release handed
//! over on a disk, and only text they have verified reaches these functions.
//! What is decided here is everything a signature cannot say: that a
//! statement is for this image's role, that it is not older than one already
//! accepted, how stale it is, and that a byte offered for staging is one the
//! signed manifest provides for, at the place it belongs.

use std::cmp::Ordering;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const POINTER_MAGIC: &str = "KRYPTIK-LATEST-1";
/// The pointer and its signature, each.
pub const POINTER_MAX: usize = 8 * 1024;
/// The manifest and its signature, each.
pub const MANIFEST_MAX: u64 = 64 * 1024;
/// A pointer older than this is reported as stale: the release process
/// re-issues it on a schedule, so its age is the only sign of a withheld one.
pub const STALE_AFTER_SECS: i64 = 30 * 86400;
/// How far ahead of this machine's clock a statement may be dated. One that
/// is dated further ahead is refused: accepted, it would make every honest
/// statement after it a replay until its date arrived, and would never read
/// as stale. A day covers a release host's clock and this one disagreeing.
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

/// The pointer's text: the magic line, then each key exactly once. A key it
/// does not know is refused rather than skipped, so a newer format cannot be
/// half-understood by an older system.
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

/// Where a release's files are fetched from. An absolute base is taken as it
/// is; a relative one is resolved against the channel address zone 0 was
/// given (`CONF`), never against anything the net zone reports. Only a
/// development image may be pointed at plain http. Where the bytes come from
/// decides nothing about what they must be - the pointer carries the
/// manifest's hash - so this is about not leaking the request, not trust.
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
        Some("http") if role == "development" => Ok(url),
        Some("http") => Err("a production image does not fetch over plain http".into()),
        _ => Err(format!("{url:?} is neither https nor http")),
    }
}

/// Versions compare the way `sort -V` orders them for the release tool: runs
/// of digits as numbers, everything else byte by byte.
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

/// What an accepted pointer says about this machine.
#[derive(Debug, PartialEq)]
pub enum Standing {
    /// It names the running release, or an older one.
    Current,
    Available(String),
}

/// Whether zone 0 accepts a verified pointer. The signature said who wrote
/// it; this says whether it is for this image and whether it is a replay:
/// an `issued` earlier than the newest one already accepted is refused
/// however valid its signature, and so is one dated more than
/// `MAX_AHEAD_SECS` after `now`.
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

/// How many whole days old the newest accepted pointer is, and whether that
/// is past the bound. A clock behind the pointer reads as zero days.
pub fn staleness(now: i64, issued: i64) -> (i64, bool) {
    let age = (now - issued).max(0);
    (age / 86400, age > STALE_AFTER_SECS)
}

/// One file of a release, from the verified manifest.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub name: String,
    pub size: u64,
}

/// The file list `kryptik-update check-manifest` prints for a manifest it
/// has verified: `file <size> <name>` per line, other lines ignored. Names
/// are held to the rule for anything that crosses the broker.
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

/// Whether `len` bytes offered for `name` at `offset` may be written, given
/// how many bytes of it are already held. `files` is `None` until the
/// manifest and its signature have verified, and until then only those two
/// are taken: whole, from byte zero, small. After that: a listed name, at
/// exactly the offset held (so a broken download resumes and nothing is
/// written twice or out of order), never past the signed size.
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

/// What is still missing and from which byte: the answer to `update-poll`.
pub fn still_needed(files: &[Entry], held: impl Fn(&str) -> u64) -> Vec<(String, u64)> {
    files.iter().filter_map(|e| { let h = held(&e.name); (h < e.size).then(|| (e.name.clone(), h)) }).collect()
}

// --- what zone 0 keeps, and what the broker's three verbs do with it -------
//
// Under `STATE_DIR`, root's and nobody else's:
//
//   pointer             the newest statement accepted, as it was signed
//   considered          when a statement was last looked at (the rate limit)
//   wanted              the version the person asked for (`kryptik update fetch`)
//   files               `check-manifest`'s output for it, once it has verified
//   incoming/<version>/ the staged release: the directory `apply` is given
//
// Every function takes the directory and the two checks, so the tests run
// them against a temporary directory with checks of their own.


pub const STATE_DIR: &str = "/var/lib/kryptik/update";
pub const TOOL: &str = "/usr/sbin/kryptik-update";
pub const ROLE_FILE: &str = "/usr/share/kryptik/trust/required-role";
pub const CONF: &str = "/etc/kryptik/update.conf";
/// The most one `update-put` carries. A release crosses in pieces this size,
/// each one request the launcher answers between two looks at its zone, so
/// the zone's supervision is never further away than one piece.
pub const PUT_MAX: usize = 1 << 20;

/// The two things only a signature can say, as functions so that a test can
/// stand in for `kryptik-update`. `pointer` verifies a statement and its
/// signature; `manifest` verifies the manifest and signature in a directory
/// and returns what `check-manifest` printed.
pub struct Checks<'a> {
    pub pointer: &'a dyn Fn(&Path, &Path) -> Result<(), String>,
    pub manifest: &'a dyn Fn(&Path) -> Result<String, String>,
}

fn run_tool(args: &[&std::ffi::OsStr]) -> Result<String, String> {
    let out = std::process::Command::new(TOOL)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("{TOOL}: {e}"))?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    Err(err.lines().last().unwrap_or("refused").trim_start_matches("kryptik-update: ").to_string())
}

/// The checks the installed system uses: `kryptik-update`, with the trust
/// anchor on the verified root and nothing from this process's environment.
pub fn tool_checks() -> Checks<'static> {
    Checks {
        pointer: &|p, s| run_tool(&["check-pointer".as_ref(), p.as_os_str(), s.as_os_str()]).map(|_| ()),
        manifest: &|d| run_tool(&["check-manifest".as_ref(), d.as_os_str()]),
    }
}

pub fn required_role() -> String {
    std::fs::read_to_string(ROLE_FILE).map(|s| s.trim().to_string()).unwrap_or_else(|_| "development".into())
}

pub fn running_version() -> String {
    let text = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    text.lines().find_map(|l| l.strip_prefix("VERSION_ID=")).map(|v| v.trim_matches('"').to_string()).unwrap_or_default()
}

/// `channel = <address>` from `CONF`. Only the verified root's copy lasts: one
/// root writes under /etc is moved out of the overlay at the next boot
/// (sysinit.sh, `prune_etc_upper`). The address says where to ask, nothing
/// more; what comes back is believed only on the trust anchor's signature.
pub fn channel_from(conf: &str) -> Option<String> {
    conf.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k.trim() == "channel" && !v.trim().is_empty()).then(|| v.trim().to_string())
    })
}

/// A directory that is this process's own and nobody else's, made or found.
/// One that was already there is looked at, not believed: a link, another
/// owner or a mode that lets anyone else in is refused.
fn private_dir(p: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::DirBuilder::new().recursive(true).mode(0o700).create(p) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("{}: {e}", p.display())),
    }
    let m = std::fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err(format!("{}: not a directory of this user's alone", p.display()));
    }
    Ok(())
}

/// Written whole and renamed into place, readable by root alone.
fn put_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(bytes).and_then(|_| f.sync_all()).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))?;
    // The name is the directory's to remember: without this the rename can be
    // lost to a power cut although the file's own bytes were synced.
    let parent = path.parent().unwrap_or(Path::new("."));
    std::fs::File::open(parent).and_then(|d| d.sync_all()).map_err(|e| format!("{}: {e}", parent.display()))
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

/// `update-latest`: a statement of what is current and its signature, from
/// the net zone. One is looked at per interval, whatever becomes of it, so a
/// hostile zone cannot make zone 0 verify signatures all day.
pub fn latest(dir: &Path, checks: &Checks, now: i64, role: &str, running: &str, pointer: &[u8], sig: &[u8]) -> Result<Standing, String> {
    private_dir(dir)?;
    let last: Option<i64> = std::fs::read_to_string(dir.join("considered")).ok().and_then(|s| s.trim().parse().ok());
    if last.is_some_and(|t| (now - t).unsigned_abs() < POINTER_INTERVAL_SECS) {
        return Err(format!("one statement is considered every {} minutes", POINTER_INTERVAL_SECS / 60));
    }
    put_file(&dir.join("considered"), now.to_string().as_bytes())?;
    let text = std::str::from_utf8(pointer).map_err(|_| "the pointer is not text".to_string())?;
    // What it says is judged only after who said it: a parse error must not
    // tell an unsigned sender anything a signed one would not also see.
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

/// `kryptik update fetch`: the person asks for the release the newest
/// accepted statement names. Nothing is fetched that was not asked for.
pub fn want(dir: &Path, running: &str) -> Result<String, String> {
    let p = stored_pointer(dir).ok_or("no statement of what is current has been accepted yet")?;
    if version_cmp(&p.version, running) != Ordering::Greater {
        return Err(format!("{} is the newest release known, and this machine runs {running}", p.version));
    }
    if wanted(dir).as_deref() != Some(p.version.as_str()) {
        let _ = std::fs::remove_file(dir.join("files"));
        let _ = std::fs::remove_dir_all(dir.join("incoming"));
    }
    put_file(&dir.join("wanted"), p.version.as_bytes())?;
    Ok(p.version)
}

/// What is wanted, where from, and what of it is still missing: `None` when
/// nothing is, which the broker says as `idle`.
fn outstanding(dir: &Path, channel: &str, role: &str, running: &str) -> Option<(Pointer, String, Vec<(String, u64)>)> {
    let version = wanted(dir)?;
    let p = stored_pointer(dir).filter(|p| p.version == version)?;
    if version_cmp(&version, running) != Ordering::Greater {
        return None;
    }
    let base = resolve_base(channel, &p.base, role).ok()?;
    let stage = staging(dir, &version);
    let need = match verified_files(dir, &version) {
        Some(files) => still_needed(&files, |n| held(&stage, n)),
        None => ["manifest", "manifest.sig"].iter().filter(|n| held(&stage, n) == 0).map(|n| (n.to_string(), 0)).collect(),
    };
    Some((p, base, need))
}

/// `update-poll`: the net zone asks, because nothing can call it.
pub fn poll(dir: &Path, channel: &str, role: &str, running: &str) -> String {
    match outstanding(dir, channel, role, running) {
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

/// `update-put`: bytes for the release that is wanted, under `may_put`'s
/// rule. When the manifest and its signature are both there they are
/// verified, held to the hash the accepted pointer announced, and measured
/// against the room there is; only then is anything they list accepted.
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
        let have = held(&stage, name);
        return Ok(if have == size { format!("{name} complete") } else { format!("{name} {have}/{size}") });
    }
    if held(&stage, "manifest") == 0 || held(&stage, "manifest.sig") == 0 {
        return Ok(format!("{name} complete"));
    }
    let refuse = |why: String| -> Result<String, String> {
        let _ = std::fs::remove_dir_all(&stage);
        Err(why)
    };
    // One refused manifest per interval, as one statement is looked at per
    // interval: a refusal clears the stage, so without this a hostile zone
    // could feed the verifier's parser a new pair as fast as it could send.
    let refused: Option<i64> = std::fs::read_to_string(dir.join("refused")).ok().and_then(|s| s.trim().parse().ok());
    if refused.is_some_and(|t| (now - t).unsigned_abs() < POINTER_INTERVAL_SECS) {
        return refuse(format!("a manifest was refused less than {} minutes ago", POINTER_INTERVAL_SECS / 60));
    }
    // Every refusal from here on starts the interval, whichever check made
    // it: a manifest that verifies but is for another version, or is not the
    // one announced, or does not fit, costs a download and a verification
    // as much as one that does not verify, and was retried every minute.
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

/// `kryptik update status`, as lines for a person.
pub fn status(dir: &Path, now: i64, running: &str) -> String {
    let mut out = format!("running    {running}\n");
    match stored_pointer(dir) {
        None => out.push_str("newest     unknown: no statement of what is current has been accepted\n"),
        Some(p) => {
            let (days, stale) = staleness(now, p.issued);
            out.push_str(&format!("newest     {} (stated {days} day(s) ago)\n", p.version));
            if stale {
                out.push_str(&format!(
                    "           no statement from the release key for {days} days: either nothing has been published,\n           or something is keeping it from this machine\n"
                ));
            }
        }
    }
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

/// The staged release's directory when every byte of it has arrived: what
/// `kryptik update apply` hands to `kryptik-update apply`.
pub fn complete_stage(dir: &Path) -> Result<PathBuf, String> {
    let v = wanted(dir).ok_or("no release has been asked for")?;
    let files = verified_files(dir, &v).ok_or_else(|| format!("{v}: its manifest has not arrived"))?;
    let stage = staging(dir, &v);
    match still_needed(&files, |n| held(&stage, n)).first() {
        None => Ok(stage),
        Some((name, at)) => Err(format!("{v}: {name} has {at} bytes so far; the release is still arriving")),
    }
}

/// Once the machine runs what was staged, the staging area has no job.
pub fn forget_if_installed(dir: &Path, running: &str) {
    if wanted(dir).is_some_and(|v| version_cmp(&v, running) != Ordering::Greater) {
        for f in ["wanted", "files"] {
            let _ = std::fs::remove_file(dir.join(f));
        }
        let _ = std::fs::remove_dir_all(dir.join("incoming"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn pointer_text(version: &str, issued: &str) -> String {
        format!("{POINTER_MAGIC}\nrole: production\nversion: {version}\nissued: {issued}\nmanifest-sha256: {SHA}\nbase: {version}/\n")
    }

    #[test]
    fn a_pointer_parses_and_anything_else_does_not() {
        let p = parse_pointer(&pointer_text("1.0.3", "2027-03-02T14:05:00+00:00")).unwrap();
        assert_eq!((p.role.as_str(), p.version.as_str(), p.base.as_str()), ("production", "1.0.3", "1.0.3/"));
        assert_eq!(p.issued, crate::time::parse_iso8601("2027-03-02T14:05:00Z").unwrap());
        let good = pointer_text("1.0.3", "2027-03-02T14:05:00Z");
        for (what, bad) in [
            ("a manifest's magic", good.replace(POINTER_MAGIC, "KRYPTIK-MANIFEST-1")),
            ("a key twice", format!("{good}role: development\n")),
            ("an unknown key", format!("{good}mirror: https://elsewhere/\n")),
            ("no issued", good.replace("issued: 2027-03-02T14:05:00Z\n", "")),
            ("a date that is not one", good.replace("2027-03-02T14:05:00Z", "yesterday")),
            ("a short hash", good.replace(SHA, &SHA[..63])),
            ("an uppercase hash", good.replace(SHA, &SHA.to_uppercase())),
            ("a version with a space", good.replace("version: 1.0.3", "version: 1.0 3")),
            ("a base with a space", good.replace("base: 1.0.3/", "base: 1.0.3/ x")),
        ] {
            assert!(parse_pointer(&bad).is_err(), "{what} was accepted");
        }
    }

    #[test]
    fn versions_order_as_the_release_tool_orders_them() {
        for (a, b) in [("1.0.3", "1.0.10"), ("1.9", "1.10"), ("1.0", "1.0.1"), ("0.9.9", "1.0"), ("1.0-rc1", "1.0-rc2"), ("1.02", "1.3")] {
            assert_eq!(version_cmp(a, b), Ordering::Less, "{a} < {b}");
            assert_eq!(version_cmp(b, a), Ordering::Greater, "{b} > {a}");
        }
        assert_eq!(version_cmp("1.0.3", "1.0.3"), Ordering::Equal);
        assert_eq!(version_cmp("1.01", "1.1"), Ordering::Equal);
    }

    #[test]
    fn a_pointer_is_accepted_for_this_role_and_never_backwards() {
        let p = parse_pointer(&pointer_text("1.0.3", "2027-03-02T14:05:00Z")).unwrap();
        assert_eq!(accept_pointer(&p, "production", "1.0.2", None, p.issued), Ok(Standing::Available("1.0.3".into())));
        assert_eq!(accept_pointer(&p, "production", "1.0.3", None, p.issued), Ok(Standing::Current));
        // An older release named by a newer statement is not an update.
        assert_eq!(accept_pointer(&p, "production", "1.1.0", None, p.issued), Ok(Standing::Current));
        assert!(accept_pointer(&p, "development", "1.0.2", None, p.issued).unwrap_err().contains("role"));
        // The same statement again is fine: that is what a re-issue looks
        // like to a machine that polls more often than the schedule.
        assert!(accept_pointer(&p, "production", "1.0.2", Some(p.issued), p.issued).is_ok());
        assert!(accept_pointer(&p, "production", "1.0.2", Some(p.issued + 1), p.issued).unwrap_err().contains("replay"));
        // Dated ahead of the clock: a day is tolerated, more is refused, so
        // one bad date cannot make every later statement a replay.
        assert!(accept_pointer(&p, "production", "1.0.2", None, p.issued - MAX_AHEAD_SECS).is_ok());
        assert!(accept_pointer(&p, "production", "1.0.2", None, p.issued - MAX_AHEAD_SECS - 1).unwrap_err().contains("clock"));
    }

    #[test]
    fn a_pointer_goes_stale_after_the_bound_and_not_before() {
        assert_eq!(staleness(1000 + STALE_AFTER_SECS, 1000), (30, false));
        assert_eq!(staleness(1001 + STALE_AFTER_SECS, 1000), (30, true));
        assert_eq!(staleness(500, 1000), (0, false));
    }

    #[test]
    fn a_base_resolves_against_the_verified_channel_only() {
        let ch = "https://updates.example/stable";
        assert_eq!(resolve_base(ch, "1.0.3/", "production").unwrap(), "https://updates.example/stable/1.0.3/");
        assert_eq!(resolve_base(&format!("{ch}/"), "1.0.3", "production").unwrap(), "https://updates.example/stable/1.0.3/");
        assert_eq!(resolve_base(ch, "https://mirror.example/k/1.0.3/", "production").unwrap(), "https://mirror.example/k/1.0.3/");
        assert!(resolve_base(ch, "../other/1.0.3/", "production").is_err());
        assert!(resolve_base(ch, "/etc/", "production").is_err());
        assert!(resolve_base(ch, "http://mirror.example/1.0.3/", "production").is_err());
        assert!(resolve_base(ch, "http://10.0.2.2:8080/1.0.3/", "development").is_ok());
        assert!(resolve_base(ch, "file:///var/lib/", "development").is_err());
    }

    fn files() -> Vec<Entry> {
        parse_file_list("version: 1.0.3\nfile 1000 kryptik-root.img\nfile 40 kryptik-a.efi\nfile 40 kryptik-b.efi\nfile 9 root.json\n").unwrap()
    }

    #[test]
    fn the_file_list_is_the_verified_manifests_and_nothing_odd() {
        assert_eq!(total_bytes(&files()), 1089);
        for bad in ["file 10 ../x\n", "file 10 .hidden\n", "file ten x\n", "file 10 manifest\n", "file 1 a\nfile 2 a\n", "version: 1\n", "file 10 a b\n"] {
            assert!(parse_file_list(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn nothing_large_is_taken_before_the_manifest_has_verified() {
        assert!(may_put(None, "manifest", 0, 4096, 0).is_ok());
        assert!(may_put(None, "manifest.sig", 0, MANIFEST_MAX, 0).is_ok());
        assert!(may_put(None, "manifest", 0, MANIFEST_MAX + 1, 0).is_err());
        assert!(may_put(None, "manifest", 1, 10, 0).is_err());
        assert!(may_put(None, "kryptik-root.img", 0, 10, 0).unwrap_err().contains("before the manifest"));
        // And once it has, the manifest is what was verified, for good.
        assert!(may_put(Some(&files()), "manifest", 0, 10, 0).is_err());
    }

    #[test]
    fn bytes_are_taken_only_where_the_signed_manifest_provides_for_them() {
        let f = files();
        assert!(may_put(Some(&f), "kryptik-root.img", 0, 1000, 0).is_ok());
        assert!(may_put(Some(&f), "kryptik-root.img", 600, 400, 600).is_ok());
        assert!(may_put(Some(&f), "kryptik-root.img", 600, 401, 600).unwrap_err().contains("past that"));
        assert!(may_put(Some(&f), "kryptik-root.img", 0, 10, 600).unwrap_err().contains("600 bytes are held"));
        assert!(may_put(Some(&f), "kryptik-root.img", 700, 10, 600).is_err());
        assert!(may_put(Some(&f), "kryptik-root.img", 1000, 1, 1000).is_err());
        assert!(may_put(Some(&f), "stowaway", 0, 1, 0).unwrap_err().contains("does not list"));
        assert!(may_put(Some(&f), "root.json", 0, 0, 0).is_err());
        assert!(may_put(Some(&f), "root.json", u64::MAX, 2, u64::MAX).is_err());
    }

    #[test]
    fn a_poll_names_what_is_missing_and_from_which_byte() {
        let held = |n: &str| match n { "kryptik-root.img" => 600, "kryptik-a.efi" => 40, _ => 0 };
        assert_eq!(
            still_needed(&files(), held),
            vec![("kryptik-root.img".to_string(), 600), ("kryptik-b.efi".to_string(), 0), ("root.json".to_string(), 0)]
        );
        assert!(still_needed(&files(), |_| u64::MAX).is_empty());
    }

    // --- the state, against a directory of the test's own ---

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kryptik-update-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    const LISTING: &str = "version: 1.0.3\nsha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\nfile 10 kryptik-root.img\nfile 4 root.json\n";

    fn yes() -> Checks<'static> {
        Checks { pointer: &|_, _| Ok(()), manifest: &|_| Ok(LISTING.to_string()) }
    }

    /// An hour after the statements these tests use were issued.
    const T0: i64 = 1_804_000_000;
    const CH: &str = "https://updates.example/stable";

    #[test]
    fn a_statement_is_stored_only_when_it_verifies_is_new_and_is_due() {
        let d = scratch("latest");
        let p = pointer_text("1.0.3", "2027-03-02T14:05:00Z");
        let no = Checks { pointer: &|_, _| Err("the pointer signature does NOT verify".into()), manifest: &|_| Err("unused".into()) };
        assert!(latest(&d, &no, T0, "production", "1.0.2", p.as_bytes(), b"sig").unwrap_err().contains("does NOT verify"));
        assert!(stored_pointer(&d).is_none(), "an unverified statement was stored");
        // Looking at that one used the interval up, whoever sent it.
        assert!(latest(&d, &yes(), T0 + 60, "production", "1.0.2", p.as_bytes(), b"sig").unwrap_err().contains("every 60 minutes"));
        let t1 = T0 + POINTER_INTERVAL_SECS as i64;
        assert_eq!(latest(&d, &yes(), t1, "production", "1.0.2", p.as_bytes(), b"sig"), Ok(Standing::Available("1.0.3".into())));
        assert_eq!(stored_pointer(&d).unwrap().version, "1.0.3");
        assert!(!d.join("checking").exists(), "the scratch copy outlived the check");
        // Last year's statement, validly signed, an interval later: a replay.
        let old = pointer_text("1.0.1", "2026-03-02T14:05:00Z");
        let t2 = t1 + POINTER_INTERVAL_SECS as i64;
        assert!(latest(&d, &yes(), t2, "production", "1.0.2", old.as_bytes(), b"sig").unwrap_err().contains("replay"));
        assert_eq!(stored_pointer(&d).unwrap().version, "1.0.3");
        // Next year's, validly signed: stored, it would make every honest
        // statement until then a replay. It is refused and nothing changes.
        let ahead = pointer_text("9.9.9", "2028-03-02T14:05:00Z");
        let t3 = t2 + POINTER_INTERVAL_SECS as i64;
        assert!(latest(&d, &yes(), t3, "production", "1.0.2", ahead.as_bytes(), b"sig").unwrap_err().contains("clock"));
        assert_eq!(stored_pointer(&d).unwrap().version, "1.0.3");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_release_is_staged_in_the_order_that_bounds_it() {
        let d = scratch("stage");
        let p = pointer_text("1.0.3", "2027-03-02T14:05:00Z");
        // Nothing asked for: nothing polled for, nothing taken.
        assert_eq!(poll(&d, CH, "production", "1.0.2"), "idle");
        assert!(want(&d, "1.0.2").unwrap_err().contains("no statement"));
        latest(&d, &yes(), T0, "production", "1.0.2", p.as_bytes(), b"sig").unwrap();
        assert_eq!(poll(&d, CH, "production", "1.0.2"), "idle", "fetching began before the person asked");
        assert!(put(&d, &yes(), T0, "manifest", 0, b"m").unwrap_err().contains("no release has been asked for"));
        assert_eq!(want(&d, "1.0.2").unwrap(), "1.0.3");
        assert!(want(&d, "1.0.3").unwrap_err().contains("newest release known"));

        assert_eq!(poll(&d, CH, "production", "1.0.2"), "fetch 1.0.3 https://updates.example/stable/1.0.3/ need manifest 0 manifest.sig 0");
        assert!(put(&d, &yes(), T0, "kryptik-root.img", 0, b"0123456789").unwrap_err().contains("before the manifest"));
        assert_eq!(put(&d, &yes(), T0, "manifest", 0, b"the manifest").unwrap(), "manifest complete");
        assert_eq!(poll(&d, CH, "production", "1.0.2"), "fetch 1.0.3 https://updates.example/stable/1.0.3/ need manifest.sig 0");
        assert!(put(&d, &yes(), T0, "manifest.sig", 0, b"its signature").unwrap().contains("the manifest verifies, 2 file(s), 14 bytes"));

        assert_eq!(poll(&d, CH, "production", "1.0.2"), "fetch 1.0.3 https://updates.example/stable/1.0.3/ need kryptik-root.img 0 root.json 0");
        assert!(put(&d, &yes(), T0, "manifest", 0, b"another").unwrap_err().contains("not replaced"));
        assert!(put(&d, &yes(), T0, "stowaway", 0, b"x").unwrap_err().contains("does not list"));
        assert_eq!(put(&d, &yes(), T0, "kryptik-root.img", 0, b"01234").unwrap(), "kryptik-root.img 5/10");
        // The connection dropped; the net zone is told where to resume, and
        // anything else is refused without a byte being written.
        assert_eq!(poll(&d, CH, "production", "1.0.2"), "fetch 1.0.3 https://updates.example/stable/1.0.3/ need kryptik-root.img 5 root.json 0");
        assert!(put(&d, &yes(), T0, "kryptik-root.img", 0, b"01234").unwrap_err().contains("5 bytes are held"));
        assert!(put(&d, &yes(), T0, "kryptik-root.img", 5, b"567890").unwrap_err().contains("past that"));
        assert!(complete_stage(&d).unwrap_err().contains("still arriving"));
        assert_eq!(put(&d, &yes(), T0, "kryptik-root.img", 5, b"56789").unwrap(), "kryptik-root.img complete");
        assert_eq!(put(&d, &yes(), T0, "root.json", 0, b"{  }").unwrap(), "root.json complete");
        assert_eq!(poll(&d, CH, "production", "1.0.2"), "idle");
        let stage = complete_stage(&d).unwrap();
        assert_eq!(std::fs::read(stage.join("kryptik-root.img")).unwrap(), b"0123456789");
        let mut names: Vec<String> = std::fs::read_dir(&stage).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        assert_eq!(names, ["kryptik-root.img", "manifest", "manifest.sig", "root.json"], "apply refuses a directory holding anything else");
        assert!(status(&d, T0, "1.0.2").contains("1.0.3: 14 of 14 bytes, complete"));

        // Once the machine runs it, the staging area is gone.
        forget_if_installed(&d, "1.0.2");
        assert!(stage.exists());
        forget_if_installed(&d, "1.0.3");
        assert!(!stage.exists() && wanted(&d).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_manifest_that_is_not_the_one_announced_is_thrown_away() {
        for (tag, listing, why) in [
            ("hash", LISTING.replace("sha256: 0", "sha256: f"), "announced"),
            ("version", LISTING.replace("version: 1.0.3", "version: 1.0.4"), "not for 1.0.3"),
            ("room", LISTING.replace("file 10 ", "file 18446744073709551000 "), "there is room for"),
        ] {
            let d = scratch(tag);
            let p = pointer_text("1.0.3", "2027-03-02T14:05:00Z");
            latest(&d, &yes(), T0, "production", "1.0.2", p.as_bytes(), b"sig").unwrap();
            want(&d, "1.0.2").unwrap();
            let listing_for = move |_: &Path| Ok::<String, String>(listing.clone());
            let checks = Checks { pointer: &|_, _| Ok(()), manifest: &listing_for };
            put(&d, &checks, T0, "manifest", 0, b"m").unwrap();
            assert!(put(&d, &checks, T0, "manifest.sig", 0, b"s").unwrap_err().contains(why), "{tag}");
            assert!(!staging(&d, "1.0.3").exists(), "{tag}: the refused manifest was kept");
            assert_eq!(poll(&d, CH, "production", "1.0.2"), "fetch 1.0.3 https://updates.example/stable/1.0.3/ need manifest 0 manifest.sig 0", "{tag}");
            // A manifest that verified and was refused anyway starts the
            // interval too: the next pair is not looked at a minute later.
            put(&d, &checks, T0 + 60, "manifest", 0, b"m").unwrap();
            assert!(put(&d, &checks, T0 + 60, "manifest.sig", 0, b"s").unwrap_err().contains("minutes ago"), "{tag}: retried within the interval");
            let _ = std::fs::remove_dir_all(&d);
        }
        let d = scratch("unsigned");
        let p = pointer_text("1.0.3", "2027-03-02T14:05:00Z");
        latest(&d, &yes(), T0, "production", "1.0.2", p.as_bytes(), b"sig").unwrap();
        want(&d, "1.0.2").unwrap();
        let no = Checks { pointer: &|_, _| Ok(()), manifest: &|_| Err("the manifest signature does NOT verify".into()) };
        put(&d, &no, T0, "manifest", 0, b"m").unwrap();
        assert!(put(&d, &no, T0, "manifest.sig", 0, b"s").unwrap_err().contains("does NOT verify"));
        // The next pair is not even looked at until the interval has passed,
        // whatever it is; after it, a manifest that verifies is taken.
        put(&d, &yes(), T0 + 60, "manifest", 0, b"m").unwrap();
        assert!(put(&d, &yes(), T0 + 60, "manifest.sig", 0, b"s").unwrap_err().contains("minutes ago"));
        let later = T0 + POINTER_INTERVAL_SECS as i64;
        put(&d, &no, later, "manifest", 0, b"m").unwrap();
        assert!(put(&d, &no, later, "manifest.sig", 0, b"s").unwrap_err().contains("does NOT verify"));
        assert!(put(&d, &no, T0, "kryptik-root.img", 0, b"x").unwrap_err().contains("before the manifest"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_channel_address_is_read_from_the_configuration() {
        assert_eq!(channel_from("# where releases are\nchannel = https://updates.example/stable\n").as_deref(), Some(CH));
        assert_eq!(channel_from("channel =\n"), None);
        assert_eq!(channel_from("interval = 1\n"), None);
    }
}
