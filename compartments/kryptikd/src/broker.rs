//! The zone broker (docs/design/broker.md): each zone's one socket into zone 0,
//! serving the clipboard, transfer, time and update verbs.
//!
//! A peer is known by its `SO_PEERCRED` uid, which the kernel asserts and the
//! zone cannot choose; each zone has its own `[identity]` uid range. The pid
//! is never used, since it may be reused.

use std::ffi::CString;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::registry;
use crate::serve::{peer_cred, recv_with_fds};
use crate::zone::{NetworkMode, Zone};

/// The socket's name in a registry entry, and in the zone's /run/kryptik.
pub const SOCKET_NAME: &str = "broker";

/// Listen on an AF_UNIX socket at `path` that only the zone identity can
/// connect to. A stale file is removed first: this launcher owns the entry.
pub fn listen_at(path: &std::path::Path, uid: u32, gid: u32) -> io::Result<RawFd> {
    let _ = std::fs::remove_file(path);
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in socket path"))?;
    if c.as_bytes().len() >= 108 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "socket path too long for sockaddr_un"));
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (i, b) in c.as_bytes().iter().enumerate() {
        sa.sun_path[i] = *b as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + c.as_bytes().len() + 1) as libc::socklen_t;
    let r = unsafe {
        // Nobody but the owner may connect: 0600 before the bind is visible.
        let old = libc::umask(0o177);
        let r = libc::bind(fd.as_raw_fd(), &sa as *const _ as *const libc::sockaddr, len);
        libc::umask(old);
        r
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::geteuid() } == 0 && unsafe { libc::chown(c.as_ptr(), uid, gid) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::listen(fd.as_raw_fd(), 8) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd.into_raw_fd())
}

/// A zone's clipboard, a file in its registry entry: the MIME type on the
/// first line, then the bytes. A zone reaches only its own; moving one to
/// another zone is the zone 0 command `kryptikd clipboard move`.
pub const CLIPBOARD_FILE: &str = "clipboard";
pub const CLIPBOARD_MAX: usize = 1 << 20;

/// MIME types a payload may carry: fixed, as a free-form label would be a channel.
pub const MIME_TYPES: &[&str] = &[
    "text/plain",
    "text/plain;charset=utf-8",
    "text/html",
    "text/uri-list",
    "image/png",
    "image/jpeg",
    "application/octet-stream",
];

/// How long one request may take end to end. The launcher serves its broker
/// between waitpid polls, so a slow zone stalls only its own supervision.
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

/// One request: a header line, then the payload its verb announces.
///
/// ```text
/// version\n                              -> kryptik-broker 1 zone=NAME\n
/// clipboard-set <mime> <len>\n<bytes>    -> ok\n
/// clipboard-get\n                        -> ok <mime> <len>\n<bytes>  |  empty\n
/// time-offset <seconds> <sources>\n        -> ok ignored | slewed | stepped | stepped after consent\n
///                                           (from the zone that holds the network, and no other)
/// update-latest <plen> <slen>\n<pointer><sig> -> ok current | ok available <version>\n
/// update-poll\n                          -> idle | fetch <version> <base> need <name> <offset> ...\n
/// update-put <name> <offset> <len>\n<bytes>   -> ok <name> <held>/<size> | ok <name> complete\n
///                                           (the same zone, and no other)
/// anything else                          -> error: <reason>\n
/// ```
#[derive(Debug, PartialEq)]
pub enum Request {
    Version,
    ClipboardSet { mime: String, len: usize },
    ClipboardGet,
    /// A verb that exists, but not on the zone-facing socket.
    NotAZoneVerb(String),
    /// `transfer <zone> <name>` with the file as one SCM_RIGHTS descriptor.
    Transfer { dest: String, name: String },
    /// The nic zone's claim of the clock's offset from network time (docs/design/time.md).
    TimeOffset(crate::time::Claim),
    /// The update channel (docs/design/update-channel.md), nic zone only.
    /// `update-latest` is followed by the pointer and its signature,
    /// `update-put` by `len` bytes of the named file.
    UpdateLatest { plen: usize, slen: usize },
    UpdatePoll,
    UpdatePut { name: String, offset: u64, len: usize },
    Unknown(String),
}

/// A destination as written in a request: the same alphabet as a zone name.
fn check_zone_name(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 12 || !s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err(format!("{s:?} is not a zone name"));
    }
    Ok(())
}

/// A transferred file's name: one path component of 1 to 255 printable ASCII
/// bytes, with no leading dot, so a zone cannot plant dotfiles.
pub fn check_transfer_name(n: &str) -> Result<(), String> {
    if n.is_empty() || n.len() > 255 {
        return Err("name must be 1 to 255 bytes".into());
    }
    if n.contains('/') {
        return Err(format!("name {n:?} must be a single path component"));
    }
    if n == "." || n == ".." {
        return Err(format!("name {n:?} is not a file name"));
    }
    if n.starts_with('.') {
        return Err(format!("name {n:?} must not start with a dot"));
    }
    if !n.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(format!("name {n:?} must be printable ASCII without spaces"));
    }
    Ok(())
}

pub fn parse_request(line: &str) -> Result<Request, String> {
    let mut words = line.trim().split_whitespace();
    let verb = words.next().unwrap_or("");
    let rest: Vec<&str> = words.collect();
    match (verb, rest.as_slice()) {
        ("version", []) => Ok(Request::Version),
        ("clipboard-get", []) => Ok(Request::ClipboardGet),
        ("clipboard-set", [mime, len]) => {
            if !MIME_TYPES.contains(mime) {
                return Err(format!("unsupported MIME type {mime:?}"));
            }
            let len: usize = len.parse().map_err(|_| format!("bad length {len:?}"))?;
            if len > CLIPBOARD_MAX {
                return Err(format!(
                    "payload of {len} bytes exceeds the {CLIPBOARD_MAX}-byte clipboard limit"
                ));
            }
            Ok(Request::ClipboardSet { mime: mime.to_string(), len })
        }
        ("clipboard-set", _) => Err("usage: clipboard-set <mime> <len>".into()),
        ("clipboard-move", _) => Ok(Request::NotAZoneVerb(verb.to_string())),
        ("transfer", [dest, name]) => {
            check_zone_name(dest)?;
            check_transfer_name(name)?;
            Ok(Request::Transfer { dest: dest.to_string(), name: name.to_string() })
        }
        ("transfer", _) => Err("usage: transfer <zone> <name>, with the file as one SCM_RIGHTS descriptor".into()),
        ("time-offset", [secs, sources]) => crate::time::parse_claim(&format!("{secs} {sources}")).map(Request::TimeOffset),
        ("time-offset", _) => Err("usage: time-offset <seconds> <sources>".into()),
        ("update-latest", [plen, slen]) => {
            let size = |w: &str, what: &str| match w.parse::<usize>() {
                Ok(n) if (1..=crate::update::POINTER_MAX).contains(&n) => Ok(n),
                _ => Err(format!("{what} length {w:?} is not 1 to {} bytes", crate::update::POINTER_MAX)),
            };
            Ok(Request::UpdateLatest { plen: size(plen, "pointer")?, slen: size(slen, "signature")? })
        }
        ("update-latest", _) => Err("usage: update-latest <pointer-len> <signature-len>, then the two".into()),
        ("update-poll", []) => Ok(Request::UpdatePoll),
        ("update-poll", _) => Err("usage: update-poll".into()),
        ("update-put", [name, offset, len]) => {
            check_transfer_name(name)?;
            let offset: u64 = offset.parse().map_err(|_| format!("bad offset {offset:?}"))?;
            match len.parse::<usize>() {
                Ok(len) if (1..=crate::update::PUT_MAX).contains(&len) => Ok(Request::UpdatePut { name: name.to_string(), offset, len }),
                _ => Err(format!("length {len:?} is not 1 to {} bytes", crate::update::PUT_MAX)),
            }
        }
        ("update-put", _) => Err("usage: update-put <name> <offset> <len>, then the bytes".into()),
        ("", _) => Err("empty request".into()),
        _ => Ok(Request::Unknown(verb.to_string())),
    }
}

/// `time-offset`, taken only from the nic zone: no other zone has a network of
/// its own to measure with. `time::consider` decides what to believe.
fn handle_time_offset(zone: &Zone, claim: &crate::time::Claim, asking: &dyn Fn() -> bool) -> crate::time::Outcome {
    time_offset_in(
        zone,
        claim,
        &mut crate::time::SystemClock,
        Path::new(crate::time::STATE_DIR),
        crate::time::floor_of_this_system(),
        asking,
    )
}

/// Why `zone` may not bring an update: only the nic zone can have fetched one.
/// What it sends is still untrusted; `update.rs` judges it.
fn update_refusal(zone: &Zone) -> Option<String> {
    (zone.network != NetworkMode::Nic)
        .then(|| format!("zone {:?} does not hold the network; only the zone that does may bring an update", zone.name))
}

/// For a zone `update_refusal` has passed, with the request's whole payload.
fn handle_update(req: &Request, payload: &[u8]) -> Result<String, String> {
    use crate::update as up;
    let dir = Path::new(up::STATE_DIR);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    match req {
        Request::UpdateLatest { plen, .. } => {
            // Not above the match: the thousands of update-put requests need neither.
            let (role, running) = (up::required_role(), up::running_version());
            let (pointer, sig) = payload.split_at(*plen);
            up::latest(dir, &up::tool_checks(), now, &role, &running, pointer, sig).map(|s| match s {
                up::Standing::Current => "ok current".to_string(),
                up::Standing::Available(v) => format!("ok available {v}"),
            })
        }
        Request::UpdatePoll => {
            let (role, running) = (up::required_role(), up::running_version());
            up::forget_if_installed(dir, &running);
            let conf = std::fs::read_to_string(up::CONF).unwrap_or_default();
            Ok(up::channel_from(&conf).map_or("idle".to_string(), |channel| up::poll(dir, &channel, &role, &running)))
        }
        Request::UpdatePut { name, offset, .. } => up::put(dir, &up::tool_checks(), now, name, *offset, payload).map(|r| format!("ok {r}")),
        _ => Err("not an update verb".into()),
    }
}

/// `handle_time_offset` with the clock, state directory and floor passed in, for tests.
fn time_offset_in(
    zone: &Zone,
    claim: &crate::time::Claim,
    clock: &mut dyn crate::time::Clock,
    dir: &Path,
    floor: Option<i64>,
    asking: &dyn Fn() -> bool,
) -> crate::time::Outcome {
    if zone.network != NetworkMode::Nic {
        return crate::time::Outcome::Refused(format!(
            "zone {:?} does not hold the network; only the zone that does may report the time",
            zone.name
        ));
    }
    crate::time::consider(clock, dir, floor, crate::time::DEFAULT_BOUND_SECS, claim, &mut |now, proposed, sources| {
        crate::consent::ask_clock(now, proposed, sources, asking)
    })
}

/// Largest file a transfer carries, in bytes.
pub const TRANSFER_MAX: u64 = 1 << 30;
pub const INCOMING: &str = "incoming";

/// Where a transfer lands.
pub struct Target {
    /// O_PATH directory descriptor: the destination's root.
    pub root_fd: OwnedFd,
    /// The destination's home, relative to that root (`home/<zone>`).
    pub home_rel: String,
    pub uid: u32,
    pub gid: u32,
}

/// What the broker knows about the zone it serves.
pub struct Served<'a> {
    pub zone: &'a Zone,
    /// The zone's mapped host uid: the one peer identity accepted.
    pub uid: u32,
    /// The zone's registry entry, where its clipboard lives.
    pub entry: &'a Path,
    /// The zone directory, to load a destination's zone file.
    pub zones_dir: &'a Path,
    /// st_dev of the zone's /home/<zone>, looked up per request because the
    /// zone's root is built after its pid 1 starts. None refuses every transfer.
    pub home_dev: &'a dyn Fn() -> Option<u64>,
    /// The development stand-in for the zone 0 prompt.
    pub auto_approve: bool,
    pub max_bytes: u64,
    /// Finds a running destination's root and identity: the registry, or a test directory.
    pub resolve_dest: &'a dyn Fn(&str) -> Result<Target, String>,
    /// Called ten times a second while the user is being asked; the launcher
    /// pumps zone output there, and `false` withdraws the question.
    pub asking: &'a dyn Fn() -> bool,
}

/// The launcher's `resolve_dest`: the registry says whether the zone runs and
/// as whom, and its pid 1's root leads into its mount namespace.
pub fn registry_target(dest: &str) -> Result<Target, String> {
    let st = match registry::state(dest) {
        Ok(registry::State::Running { init: Some(st), .. }) if st.still_alive() => st,
        Ok(registry::State::Running { .. }) => return Err(format!("destination zone {dest:?} is still starting")),
        Ok(_) => return Err(format!("destination zone {dest:?} is not running")),
        Err(e) => return Err(format!("destination zone {dest:?}: {e}")),
    };
    let ident = std::fs::read_to_string(registry::entry_dir(dest).join("identity"))
        .map_err(|e| format!("destination zone {dest:?}: identity unknown: {e}"))?;
    let mut w = ident.split_whitespace();
    let (uid, gid) = match (w.next().and_then(|v| v.parse().ok()), w.next().and_then(|v| v.parse().ok())) {
        (Some(u), Some(g)) => (u, g),
        _ => return Err(format!("destination zone {dest:?}: identity file is malformed")),
    };
    let p = CString::new(format!("/proc/{}/root", st.pid)).unwrap();
    let root_fd = unsafe { libc::open(p.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if root_fd < 0 {
        return Err(format!(
            "destination zone {dest:?}: cannot reach its root: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(Target { root_fd: unsafe { OwnedFd::from_raw_fd(root_fd) }, home_rel: format!("home/{dest}"), uid, gid })
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;

/// openat2(2): open with resolution restrictions the kernel enforces.
fn openat2(dirfd: RawFd, path: &str, flags: u64, mode: u64, resolve: u64) -> io::Result<OwnedFd> {
    let c = CString::new(path).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))?;
    let how = OpenHow { flags, mode, resolve };
    let r = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(r as RawFd) })
    }
}

/// Check a transfer, ask the user, then deliver it. The checks run in order,
/// refusing at the first failure: one descriptor; a destination other than the
/// sender, named in its `[transfer] to`, configured and not the nic zone; a
/// regular O_RDONLY file on the sender's data mount within the cap. The zone
/// learns only the name the file landed under.
fn handle_transfer(s: &Served, dest: &str, name: &str, fds: &[OwnedFd]) -> Result<(String, u64), String> {
    let sender = &s.zone.name;
    if fds.len() != 1 {
        return Err(format!("transfer needs exactly one descriptor attached (got {})", fds.len()));
    }
    if dest == sender {
        return Err("a zone cannot transfer to itself".into());
    }
    if !s.zone.transfer_to.iter().any(|d| d == dest) {
        return Err(format!(
            "[transfer] to in zone {sender:?} does not name {dest:?}; a zone sends only where its file says"
        ));
    }
    let dz = Zone::from_file(&s.zones_dir.join(format!("{dest}.toml")))
        .map_err(|e| format!("destination zone {dest:?}: {e}"))?;
    if dz.network == NetworkMode::Nic {
        return Err(format!("zone {dest:?} holds the NIC and receives nothing, ever"));
    }
    let src = fds[0].as_raw_fd();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(src, &mut st) } < 0 {
        return Err(format!("descriptor: {}", io::Error::last_os_error()));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err("descriptor is not a regular file".into());
    }
    let fl = unsafe { libc::fcntl(src, libc::F_GETFL) };
    if fl < 0 {
        return Err(format!("descriptor flags: {}", io::Error::last_os_error()));
    }
    if fl & libc::O_PATH != 0 {
        return Err("descriptor is O_PATH, not an open file".into());
    }
    if fl & libc::O_ACCMODE != libc::O_RDONLY {
        return Err("descriptor is not opened read-only".into());
    }
    match (s.home_dev)() {
        None => return Err("the sender's data mount is unknown; refusing".into()),
        Some(d) if d != st.st_dev as u64 => {
            return Err("file is not on the zone's data mount (/home/<zone>)".into())
        }
        _ => {}
    }
    if st.st_size as u64 > s.max_bytes {
        return Err(format!("file is {} bytes; the transfer limit is {}", st.st_size, s.max_bytes));
    }
    /* Ask last, once even the destination is known to be running: a question
     * whose answer changes nothing teaches people to say yes. Look it up again
     * afterwards; holding its root through the wait would pin its mounts, and
     * the zone may have restarted meanwhile. */
    if !s.auto_approve {
        drop((s.resolve_dest)(dest)?);
        crate::consent::ask(sender, dest, name, st.st_size as u64, s.asking)?;
    }
    let target = (s.resolve_dest)(dest)?;
    // The size checked, and shown if asked, is the size carried.
    deliver(&target, name, src, st.st_size as u64)
}

/// Copy into the destination's `incoming/`. Every path is resolved from its
/// root with openat2 and no symlinks, so nothing written leaves its tree.
fn deliver(target: &Target, name: &str, src: RawFd, size: u64) -> Result<(String, u64), String> {
    let home = openat2(
        target.root_fd.as_raw_fd(),
        &target.home_rel,
        (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        0,
        RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    )
    .map_err(|e| format!("destination home is not reachable: {e}"))?;
    /* Create as the destination identity: an ephemeral zone's home is a tmpfs
     * mounted in its user namespace, which refuses (EOVERFLOW) to create an
     * inode for an unmapped uid such as host root. Restored on every path;
     * the broker serves one request at a time. */
    let switched = unsafe { libc::geteuid() } == 0;
    if switched {
        unsafe {
            libc::setfsgid(target.gid);
            libc::setfsuid(target.uid);
        }
    }
    let r = deliver_into(home.as_raw_fd(), target, name, src, size);
    if switched {
        unsafe {
            libc::setfsuid(0);
            libc::setfsgid(0);
        }
    }
    r
}

fn deliver_into(home: RawFd, target: &Target, name: &str, src: RawFd, size: u64) -> Result<(String, u64), String> {
    let inc = CString::new(INCOMING).unwrap();
    let made = unsafe { libc::mkdirat(home, inc.as_ptr(), 0o700) } == 0;
    if !made {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EEXIST) {
            return Err(format!("incoming/: {e}"));
        }
    }
    if made && unsafe { libc::geteuid() } == 0 {
        if unsafe { libc::fchownat(home, inc.as_ptr(), target.uid, target.gid, libc::AT_SYMLINK_NOFOLLOW) } < 0 {
            return Err(format!("incoming/ ownership: {}", io::Error::last_os_error()));
        }
    }
    let inc_fd = openat2(
        home,
        INCOMING,
        (libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
        0,
        RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    )
    .map_err(|e| format!("incoming/ is not a plain directory: {e}"))?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(inc_fd.as_raw_fd(), &mut st) } < 0 {
        return Err(format!("incoming/: {}", io::Error::last_os_error()));
    }
    if st.st_uid != target.uid {
        return Err("incoming/ is not owned by the destination zone".into());
    }
    /* O_EXCL picks the name: a collision, or a planted symlink (also EEXIST),
     * moves on to the next number. */
    for i in 1..=100u32 {
        let cand = if i == 1 { name.to_string() } else { format!("{name}-{i}") };
        match openat2(
            inc_fd.as_raw_fd(),
            &cand,
            (libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
            0o600,
            RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
        ) {
            Ok(out) => {
                return match fill(out.as_raw_fd(), src, size, target) {
                    Ok(n) => Ok((cand, n)),
                    Err(e) => {
                        let c = CString::new(cand.as_str()).unwrap();
                        unsafe { libc::unlinkat(inc_fd.as_raw_fd(), c.as_ptr(), 0) };
                        Err(e)
                    }
                };
            }
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => continue,
            Err(e) => return Err(format!("incoming/{cand}: {e}")),
        }
    }
    Err(format!("incoming/ already holds {name} and 99 numbered variants of it"))
}

/// Copy the file as it was checked: `size` bytes, no more and no fewer.
fn fill(out: RawFd, src: RawFd, size: u64, target: &Target) -> Result<u64, String> {
    if unsafe { libc::geteuid() } == 0 && unsafe { libc::fchown(out, target.uid, target.gid) } < 0 {
        return Err(format!("ownership: {}", io::Error::last_os_error()));
    }
    let total = copy_capped(src, out, size)?;
    if total != size {
        return Err(format!("the file shrank to {total} of the {size} bytes checked; aborted"));
    }
    if unsafe { libc::fsync(out) } < 0 {
        return Err(format!("fsync: {}", io::Error::last_os_error()));
    }
    Ok(total)
}

/// Copy `src` from its first byte to `out`, enforcing `cap` on the bytes
/// actually copied: a file can grow after its st_size was checked. The read
/// offset is the copy's own, so a sender moving the shared descriptor's
/// position changes nothing.
pub fn copy_capped(src: RawFd, out: RawFd, cap: u64) -> Result<u64, String> {
    let mut total: u64 = 0;
    let mut fallback = false;
    // Allocated only if the read/write fallback is needed.
    let mut buf: Vec<u8> = Vec::new();
    loop {
        // One byte past the cap is enough to know the file is over it.
        let want = std::cmp::min(1u64 << 20, cap + 1 - total) as usize;
        let n = if !fallback {
            let mut at = total as libc::loff_t;
            let n = unsafe { libc::copy_file_range(src, &mut at, out, std::ptr::null_mut(), want, 0) };
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    // Older kernels refuse cross-filesystem copy_file_range.
                    Some(libc::EXDEV) | Some(libc::EINVAL) | Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP)
                        if total == 0 =>
                    {
                        fallback = true;
                        buf.resize(1 << 16, 0);
                        continue;
                    }
                    _ => return Err(format!("copy: {e}")),
                }
            }
            n as u64
        } else {
            let take = std::cmp::min(buf.len(), want);
            let n = unsafe { libc::pread(src, buf.as_mut_ptr() as *mut libc::c_void, take, total as libc::off_t) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(format!("read: {e}"));
            }
            if n > 0 {
                write_all(out, &buf[..n as usize]).map_err(|e| format!("write: {e}"))?;
            }
            n as u64
        };
        if n == 0 {
            return Ok(total);
        }
        total += n;
        if total > cap {
            return Err(format!("the file is longer than the {cap} bytes checked; aborted"));
        }
    }
}

fn write_all(fd: RawFd, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        data = &data[n as usize..];
    }
    Ok(())
}

/// Accept one connection and answer one request. Returns the verb handled,
/// for logging.
pub fn serve_one(listen_fd: RawFd, s: &Served) -> io::Result<Option<String>> {
    let fd = unsafe { libc::accept4(listen_fd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
    if fd < 0 {
        let e = io::Error::last_os_error();
        return if e.raw_os_error() == Some(libc::EAGAIN) || e.raw_os_error() == Some(libc::EINTR) {
            Ok(None)
        } else {
            Err(e)
        };
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    serve_connection(fd.as_raw_fd(), s)
}

/// Answer one request on an accepted connection. A peer other than the zone
/// (`s.uid`) learns nothing. Refusals come before any payload is read.
pub fn serve_connection(fd: RawFd, s: &Served) -> io::Result<Option<String>> {
    let zone = s.zone.name.as_str();
    let entry = s.entry;
    let cred = peer_cred(fd)?;
    if cred.uid != s.uid {
        reply(fd, "error: unidentified peer\n");
        return Ok(None);
    }
    let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as u32)
    };
    let started = Instant::now();
    let mut buf = Vec::new();
    let (mut more, fds) = match recv_first(fd, &mut buf, started) {
        Ok(v) => v,
        Err(e) => {
            reply(fd, &format!("error: {e}\n"));
            return Ok(None);
        }
    };
    while more && !buf.contains(&b'\n') && buf.len() < 512 {
        more = recv_some(fd, &mut buf, started)?;
    }
    let Some(nl) = buf.iter().position(|b| *b == b'\n') else {
        reply(fd, "error: header line missing or too long\n");
        return Ok(None);
    };
    let header = String::from_utf8_lossy(&buf[..nl]).into_owned();
    let mut rest: Vec<u8> = buf.split_off(nl + 1);
    let verb = header.split_whitespace().next().unwrap_or("").to_string();
    match parse_request(&header) {
        Err(why) => reply(fd, &format!("error: {why}\n")),
        Ok(Request::Version) => reply(fd, &format!("kryptik-broker 1 zone={zone}\n")),
        Ok(Request::Transfer { dest, name }) => match handle_transfer(s, &dest, &name, &fds) {
            Ok((final_name, bytes)) => {
                crate::spawn::log_line(&format!(
                    "kryptikd[zone {zone}]: transfer: {name} ({bytes} bytes) -> {dest} as incoming/{final_name}"
                ));
                reply(fd, &format!("ok {final_name}\n"));
            }
            Err(why) => reply(fd, &format!("error: {why}\n")),
        },
        Ok(Request::TimeOffset(claim)) => {
            let outcome = handle_time_offset(s.zone, &claim, s.asking);
            crate::spawn::log_line(&format!(
                "kryptikd[zone {zone}]: time-offset {:+.6} s from {} source(s): {}",
                claim.offset,
                claim.sources,
                outcome.reply()
            ));
            match outcome {
                crate::time::Outcome::Refused(why) => reply(fd, &format!("error: {why}\n")),
                done => reply(fd, &format!("{}\n", done.reply())),
            }
        }
        Ok(req @ (Request::UpdateLatest { .. } | Request::UpdatePoll | Request::UpdatePut { .. })) => {
            let len = match &req {
                Request::UpdateLatest { plen, slen } => plen + slen,
                Request::UpdatePut { len, .. } => *len,
                _ => 0,
            };
            // Who is asking is settled before a byte of payload is read.
            let outcome = match update_refusal(s.zone) {
                Some(why) => Err(why),
                None => match read_more(fd, &mut rest, len, started) {
                    Err(e) => Err(format!("payload: {e}")),
                    Ok(()) if rest.len() < len => Err(format!("payload short: {} of {len} bytes", rest.len())),
                    Ok(()) => handle_update(&req, &rest[..len]),
                },
            };
            // A release is thousands of pieces: log completions and refusals only.
            match &outcome {
                Ok(r) if verb == "update-poll" || (verb == "update-put" && !r.contains("complete")) => {}
                Ok(r) => crate::spawn::log_line(&format!("kryptikd[zone {zone}]: {verb}: {r}")),
                Err(why) => crate::spawn::log_line(&format!("kryptikd[zone {zone}]: {verb}: refused: {why}")),
            }
            match outcome {
                Ok(r) => reply(fd, &format!("{r}\n")),
                Err(why) => reply(fd, &format!("error: {why}\n")),
            }
        }
        Ok(Request::ClipboardGet) => match clipboard_read(entry) {
            Ok(Some((mime, bytes))) => {
                reply(fd, &format!("ok {mime} {}\n", bytes.len()));
                send_all(fd, &bytes);
            }
            Ok(None) => reply(fd, "empty\n"),
            Err(e) => reply(fd, &format!("error: clipboard: {e}\n")),
        },
        Ok(Request::ClipboardSet { mime, len }) => {
            if let Err(e) = read_more(fd, &mut rest, len, started) {
                reply(fd, &format!("error: payload: {e}\n"));
                return Ok(Some(verb));
            }
            if rest.len() < len {
                reply(fd, &format!("error: payload short: {} of {len} bytes\n", rest.len()));
                return Ok(Some(verb));
            }
            match clipboard_write(entry, &mime, &rest[..len]) {
                Ok(()) => reply(fd, "ok\n"),
                Err(e) => reply(fd, &format!("error: clipboard: {e}\n")),
            }
        }
        Ok(Request::NotAZoneVerb(v)) => reply(fd, &format!("error: {v} is a zone 0 act, not a zone verb\n")),
        Ok(Request::Unknown(_)) => reply(fd, "error: unknown verb\n"),
    }
    Ok(Some(verb))
}

/// The request's first recvmsg, where descriptors arrive. Ok(false, ..) at EOF.
fn recv_first(fd: RawFd, buf: &mut Vec<u8>, started: Instant) -> io::Result<(bool, Vec<OwnedFd>)> {
    let mut chunk = [0u8; 4096];
    loop {
        if started.elapsed() > REQUEST_DEADLINE {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "request took longer than the deadline"));
        }
        match recv_with_fds(fd, &mut chunk, 0) {
            Ok((n, fds)) => {
                buf.extend_from_slice(&chunk[..n]);
                return Ok((n > 0, fds));
            }
            Err(e) if matches!(e.raw_os_error(), Some(libc::EINTR) | Some(libc::EAGAIN)) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Receive straight into `buf` until it holds `want` bytes (a length the
/// header was checked against) or the peer reaches EOF, within the deadline.
fn read_more(fd: RawFd, buf: &mut Vec<u8>, want: usize, started: Instant) -> io::Result<()> {
    let mut filled = buf.len();
    if filled >= want {
        return Ok(());
    }
    buf.resize(want, 0);
    let r = loop {
        match recv_into(fd, &mut buf[filled..], started) {
            Ok(0) => break Ok(()),
            Ok(n) => filled += n,
            Err(e) => break Err(e),
        }
        if filled == want {
            break Ok(());
        }
    };
    buf.truncate(filled);
    r
}

/// One recv appended to `buf`. Ok(false) at EOF.
fn recv_some(fd: RawFd, buf: &mut Vec<u8>, started: Instant) -> io::Result<bool> {
    let mut chunk = [0u8; 4096];
    let n = recv_into(fd, &mut chunk, started)?;
    buf.extend_from_slice(&chunk[..n]);
    Ok(n > 0)
}

/// One recv into `out`, 0 at EOF. EAGAIN from SO_RCVTIMEO is retried until the deadline.
fn recv_into(fd: RawFd, out: &mut [u8], started: Instant) -> io::Result<usize> {
    loop {
        if started.elapsed() > REQUEST_DEADLINE {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "request took longer than the deadline"));
        }
        let n = unsafe { libc::recv(fd, out.as_mut_ptr() as *mut libc::c_void, out.len(), 0) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EINTR) | Some(libc::EAGAIN) => continue,
            _ => return Err(e),
        }
    }
}

fn reply(fd: RawFd, text: &str) {
    send_all(fd, text.as_bytes());
}

fn send_all(fd: RawFd, mut data: &[u8]) {
    // Bound the whole write, not each retry: a zone may stop reading midway.
    let started = Instant::now();
    while !data.is_empty() {
        let Some(left) = REQUEST_DEADLINE.checked_sub(started.elapsed()) else { return };
        let n = unsafe {
            libc::send(fd, data.as_ptr() as *const libc::c_void, data.len(), libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT)
        };
        if n < 0 {
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => {
                    let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
                    let ready = unsafe { libc::poll(&mut pfd, 1, left.as_millis() as i32) };
                    if ready > 0 || (ready < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)) {
                        continue;
                    }
                }
                _ => {}
            }
            return;
        }
        if n <= 0 {
            return; // the peer is gone
        }
        data = &data[n as usize..];
    }
}

/// The zone's payload, if any: (mime, bytes). O_NOFOLLOW refuses a planted symlink.
pub fn clipboard_read(entry: &Path) -> io::Result<Option<(String, Vec<u8>)>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let p = entry.join(CLIPBOARD_FILE);
    let f = match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&p) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut all = Vec::new();
    f.take(CLIPBOARD_MAX as u64 + 256).read_to_end(&mut all)?;
    let Some(nl) = all.iter().position(|b| *b == b'\n') else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "clipboard file has no MIME line"));
    };
    let mime = String::from_utf8_lossy(&all[..nl]).into_owned();
    if !MIME_TYPES.contains(&mime.as_str()) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("clipboard file carries an unsupported MIME type {mime:?}")));
    }
    let bytes = all.split_off(nl + 1);
    if bytes.len() > CLIPBOARD_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "clipboard file is over the limit"));
    }
    Ok(Some((mime, bytes)))
}

/// Replace the zone's payload whole, 0600; a planted symlink is replaced,
/// never followed.
pub fn clipboard_write(entry: &Path, mime: &str, bytes: &[u8]) -> io::Result<()> {
    if !MIME_TYPES.contains(&mime) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unsupported MIME type {mime:?}")));
    }
    if bytes.len() > CLIPBOARD_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "payload over the clipboard limit"));
    }
    crate::files::write_atomic(&entry.join(CLIPBOARD_FILE), &[mime.as_bytes(), b"\n", bytes], 0o600, None)
}

/// `kryptikd clipboard move`: give `to` a copy of `from`'s payload. Both are
/// registry entries of running zones. Returns what moved.
pub fn clipboard_move(from: &Path, to: &Path) -> io::Result<(String, usize)> {
    let Some((mime, bytes)) = clipboard_read(from)? else {
        return Err(io::Error::new(io::ErrorKind::NotFound, "nothing on the source zone's clipboard"));
    };
    clipboard_write(to, &mime, &bytes)?;
    Ok((mime, bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (RawFd, RawFd) {
        let mut sv = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) }, 0);
        (sv[0], sv[1])
    }

    fn send_str(fd: RawFd, s: &str) {
        send_all(fd, s.as_bytes());
    }

    /// Everything the server sent, read after the server closed its end.
    fn recv_reply(fd: RawFd) -> Vec<u8> {
        let mut out = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = unsafe { libc::recv(fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len(), 0) };
            if n <= 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n as usize]);
        }
        out
    }

    fn entry(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kryptik-broker-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Send one request on a fresh socketpair, serve it, and return (verb, reply).
    fn ask(s: &Served, request: &str, half_close: bool) -> (Option<String>, Vec<u8>) {
        ask_with(s, request, &[], half_close)
    }

    /// The same, with descriptors attached to the first message.
    fn ask_with(s: &Served, request: &str, fds: &[RawFd], half_close: bool) -> (Option<String>, Vec<u8>) {
        let (server, client) = pair();
        send_with_fds(client, request.as_bytes(), fds);
        if half_close {
            unsafe { libc::shutdown(client, libc::SHUT_WR) };
        }
        let verb = serve_connection(server, s).unwrap();
        unsafe { libc::close(server) };
        let reply = recv_reply(client);
        unsafe { libc::close(client) };
        (verb, reply)
    }

    fn send_with_fds(sock: RawFd, data: &[u8], fds: &[RawFd]) {
        let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut libc::c_void, iov_len: data.len() };
        let space = unsafe { libc::CMSG_SPACE((fds.len() * std::mem::size_of::<RawFd>()) as u32) } as usize;
        let mut cbuf = vec![0u8; space.max(1)];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if !fds.is_empty() {
            msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = space as _;
            unsafe {
                let c = libc::CMSG_FIRSTHDR(&msg);
                (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS;
                (*c).cmsg_len = libc::CMSG_LEN((fds.len() * std::mem::size_of::<RawFd>()) as u32) as _;
                std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(c) as *mut RawFd, fds.len());
            }
        }
        assert!(unsafe { libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) } >= 0, "sendmsg: {}", io::Error::last_os_error());
    }

    fn zone_t() -> Zone {
        Zone::from_str(
            "[zone]\nname = \"t\"\n[network]\nmode = \"none\"\n\
             [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n[ui]\nborder_color = \"#123456\"\n",
        )
        .unwrap()
    }

    fn no_dest(_: &str) -> Result<Target, String> {
        Err("no destinations in this test".into())
    }

    fn dev_unknown() -> Option<u64> {
        None
    }

    fn served<'a>(zone: &'a Zone, entry: &'a Path, uid: u32) -> Served<'a> {
        Served {
            zone,
            uid,
            entry,
            zones_dir: entry,
            home_dev: &dev_unknown,
            auto_approve: false,
            max_bytes: TRANSFER_MAX,
            resolve_dest: &no_dest,
            asking: &crate::consent::keep,
        }
    }

    #[test]
    fn stalled_reader_cannot_block_supervision() {
        let dir = entry("stalled-reader");
        clipboard_write(&dir, "text/plain", &vec![b'x'; CLIPBOARD_MAX]).unwrap();
        let (server, client) = pair();
        let size: libc::c_int = 4096;
        assert_eq!(unsafe {
            libc::setsockopt(server, libc::SOL_SOCKET, libc::SO_SNDBUF,
                &size as *const _ as *const libc::c_void, std::mem::size_of_val(&size) as _)
        }, 0);
        send_str(client, "clipboard-get\n");
        let (done, completion) = std::sync::mpsc::channel();
        let worker_dir = dir.clone();
        let worker = std::thread::spawn(move || {
            let z = zone_t();
            let s = served(&z, &worker_dir, unsafe { libc::geteuid() });
            let result = serve_connection(server, &s);
            unsafe { libc::close(server) };
            let _ = done.send(result);
        });
        // Leave the reply unread; closing the peer afterwards frees a stuck worker.
        let result = completion.recv_timeout(REQUEST_DEADLINE + Duration::from_secs(2));
        unsafe { libc::close(client) };
        worker.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        assert!(result.is_ok(), "an unread clipboard response stalled the zone supervisor");
        assert_eq!(result.unwrap().unwrap().as_deref(), Some("clipboard-get"));
    }

    #[test]
    fn clipboard_round_trip() {
        use std::os::unix::fs::MetadataExt;
        let dir = entry("roundtrip");
        let me = unsafe { libc::geteuid() };
        let z = zone_t();
        let sv = served(&z, &dir, me);
        assert_eq!(ask(&sv, "clipboard-get\n", false).1, b"empty\n");
        let (verb, r) = ask(&sv, "clipboard-set text/plain 5\nhello", false);
        assert_eq!(verb.as_deref(), Some("clipboard-set"));
        assert_eq!(r, b"ok\n");
        assert_eq!(std::fs::metadata(dir.join(CLIPBOARD_FILE)).unwrap().mode() & 0o777, 0o600);
        assert_eq!(ask(&sv, "clipboard-get\n", false).1, b"ok text/plain 5\nhello");
        // A second set replaces, and a payload that arrives in pieces still lands whole.
        let (server, client) = pair();
        send_str(client, "clipboard-set text/plain;charset=utf-8 11\nhello");
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            send_str(client, " world");
            client
        });
        serve_connection(server, &sv).unwrap();
        unsafe { libc::close(server) };
        let client = t.join().unwrap();
        assert_eq!(recv_reply(client), b"ok\n");
        unsafe { libc::close(client) };
        assert_eq!(ask(&sv, "clipboard-get\n", false).1, b"ok text/plain;charset=utf-8 11\nhello world");
        assert_eq!(ask(&sv, "version\n", false).1, b"kryptik-broker 1 zone=t\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refusals_leave_clipboard_alone() {
        let dir = entry("refusals");
        let me = unsafe { libc::geteuid() };
        let z = zone_t();
        let sv = served(&z, &dir, me);
        assert_eq!(ask(&sv, "clipboard-set text/plain 5\nhello", false).1, b"ok\n");
        let cases: &[(&str, &str)] = &[
            ("clipboard-set text/plain 1048577\n", "error: payload of 1048577 bytes exceeds the 1048576-byte clipboard limit\n"),
            ("clipboard-set text/evil 3\nabc", "error: unsupported MIME type \"text/evil\"\n"),
            ("clipboard-set text/plain\n", "error: usage: clipboard-set <mime> <len>\n"),
            ("clipboard-set text/plain -1\n", "error: bad length \"-1\"\n"),
            ("clipboard-move t other\n", "error: clipboard-move is a zone 0 act, not a zone verb\n"),
            ("transfer other x extra\n", "error: usage: transfer <zone> <name>, with the file as one SCM_RIGHTS descriptor\n"),
            ("steal\n", "error: unknown verb\n"),
            ("\n", "error: empty request\n"),
        ];
        for (req, want) in cases {
            let (_, r) = ask(&sv, req, false);
            assert_eq!(String::from_utf8_lossy(&r), *want, "request {req:?}");
        }
        // A payload shorter than announced (the client half-closes): refused, nothing written.
        let (_, r) = ask(&sv, "clipboard-set text/plain 10\nabc", true);
        assert_eq!(r, b"error: payload short: 3 of 10 bytes\n");
        // A header with no newline within the limit.
        let (_, r) = ask(&sv, &"x".repeat(600), true);
        assert_eq!(r, b"error: header line missing or too long\n");
        // The first payload survives all of it.
        assert_eq!(ask(&sv, "clipboard-get\n", false).1, b"ok text/plain 5\nhello");
        let left: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left, vec![std::ffi::OsString::from(CLIPBOARD_FILE)], "no temp files left behind");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn foreign_peer_learns_nothing() {
        let dir = entry("peer");
        let me = unsafe { libc::geteuid() };
        let z = zone_t();
        let sv = served(&z, &dir, me.wrapping_add(1));
        let (verb, r) = ask(&sv, "clipboard-get\n", false);
        assert_eq!(verb, None);
        assert_eq!(r, b"error: unidentified peer\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clipboard_move_copies() {
        let a = entry("move-a");
        let b = entry("move-b");
        let c = entry("move-c");
        clipboard_write(&a, "image/png", b"\x89PNG").unwrap();
        clipboard_write(&b, "text/plain", b"old").unwrap();
        assert_eq!(clipboard_move(&a, &b).unwrap(), ("image/png".to_string(), 4));
        assert_eq!(clipboard_read(&b).unwrap(), Some(("image/png".to_string(), b"\x89PNG".to_vec())));
        assert_eq!(clipboard_read(&a).unwrap(), Some(("image/png".to_string(), b"\x89PNG".to_vec())));
        // Nothing to move from an empty clipboard, and the destination is untouched.
        let e = clipboard_move(&c, &b).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert_eq!(clipboard_read(&b).unwrap().map(|(m, _)| m), Some("image/png".to_string()));
        // A planted symlink where the file should be is refused on read and replaced on write.
        std::os::unix::fs::symlink("/etc/hostname", c.join(CLIPBOARD_FILE)).unwrap();
        assert!(clipboard_read(&c).is_err());
        clipboard_write(&c, "text/plain", b"x").unwrap();
        assert!(!std::fs::symlink_metadata(c.join(CLIPBOARD_FILE)).unwrap().file_type().is_symlink());
        for d in [&a, &b, &c] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    struct Lab {
        dir: std::path::PathBuf,
        zones: std::path::PathBuf,
        root: std::path::PathBuf,
        sender: Zone,
        dev: u64,
    }

    /// Zones a (sender), b and c (plain) and n (nic); a destination root with
    /// homes for b and c; the lab directory's filesystem as the data mount.
    fn lab(tag: &str, to: &str) -> Lab {
        use std::os::unix::fs::MetadataExt;
        let dir = entry(&format!("transfer-{tag}"));
        let zones = dir.join("zones");
        std::fs::create_dir_all(&zones).unwrap();
        let plain = |name: &str, extra: &str| {
            format!(
                "[zone]\nname = \"{name}\"\n[network]\nmode = \"none\"\n\
                 [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n{extra}[ui]\nborder_color = \"#123456\"\n"
            )
        };
        std::fs::write(zones.join("a.toml"), plain("a", &format!("[transfer]\nto = \"{to}\"\n"))).unwrap();
        std::fs::write(zones.join("b.toml"), plain("b", "")).unwrap();
        std::fs::write(zones.join("c.toml"), plain("c", "")).unwrap();
        std::fs::write(
            zones.join("n.toml"),
            "[zone]\nname = \"n\"\n[network]\nmode = \"nic\"\n\
             [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n[ui]\nborder_color = \"#123456\"\n",
        )
        .unwrap();
        let root = dir.join("root");
        std::fs::create_dir_all(root.join("home/b")).unwrap();
        std::fs::create_dir_all(root.join("home/c")).unwrap();
        let sender = Zone::from_file(&zones.join("a.toml")).unwrap();
        let dev = std::fs::metadata(&dir).unwrap().dev();
        Lab { dir, zones, root, sender, dev }
    }

    /// The test stand-in for the registry: b and c "run" under the lab root.
    fn resolver(root: std::path::PathBuf) -> impl Fn(&str) -> Result<Target, String> {
        move |dest: &str| {
            if dest != "b" && dest != "c" {
                return Err(format!("destination zone {dest:?} is not running"));
            }
            let c = CString::new(root.as_os_str().as_encoded_bytes()).unwrap();
            let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
            assert!(fd >= 0);
            let root_fd = unsafe { OwnedFd::from_raw_fd(fd) };
            Ok(Target { root_fd, home_rel: format!("home/{dest}"), uid: unsafe { libc::geteuid() }, gid: unsafe { libc::getegid() } })
        }
    }

    /// How many of this process's descriptors point at `p`; tests run in
    /// parallel, so a total count would be noise.
    fn fds_pointing_at(p: &Path) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .flatten()
            .filter(|e| std::fs::read_link(e.path()).map(|t| t == p).unwrap_or(false))
            .count()
    }

    fn open_flags(p: &Path, flags: libc::c_int) -> RawFd {
        let c = CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
        let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC, 0o600) };
        assert!(fd >= 0, "open {}: {}", p.display(), io::Error::last_os_error());
        fd
    }

    #[test]
    fn transfer_lands_in_incoming() {
        use std::os::unix::fs::MetadataExt;
        let lab = lab("ok", "b c");
        let entry_dir = lab.dir.join("entry");
        std::fs::create_dir_all(&entry_dir).unwrap();
        let resolve = resolver(lab.root.clone());
        let dev = lab.dev;
        let home_dev = move || Some(dev);
        let sv = Served {
            zone: &lab.sender,
            uid: unsafe { libc::geteuid() },
            entry: &entry_dir,
            zones_dir: &lab.zones,
            home_dev: &home_dev,
            auto_approve: true,
            max_bytes: 64,
            resolve_dest: &resolve,
            asking: &crate::consent::keep,
        };
        let file = lab.dir.join("report.pdf");
        std::fs::write(&file, b"hello transfer").unwrap();
        let src = open_flags(&file, libc::O_RDONLY);
        let (verb, r) = ask_with(&sv, "transfer b report.pdf\n", &[src], false);
        unsafe { libc::close(src) };
        assert_eq!(verb.as_deref(), Some("transfer"));
        assert_eq!(String::from_utf8_lossy(&r), "ok report.pdf\n");
        // The server must have closed its SCM_RIGHTS copy too.
        assert_eq!(fds_pointing_at(&file), 0, "the broker leaked a descriptor");
        let incoming = lab.root.join("home/b/incoming");
        assert_eq!(std::fs::read(incoming.join("report.pdf")).unwrap(), b"hello transfer");
        assert_eq!(std::fs::metadata(incoming.join("report.pdf")).unwrap().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&incoming).unwrap().mode() & 0o777, 0o700);
        // The same name again gets -2.
        let src2 = open_flags(&file, libc::O_RDONLY);
        assert_eq!(ask_with(&sv, "transfer b report.pdf\n", &[src2], false).1, b"ok report.pdf-2\n");
        unsafe { libc::close(src2) };
        assert_eq!(std::fs::read(incoming.join("report.pdf-2")).unwrap(), b"hello transfer");
        // A symlink planted at -3 is skipped for -4, and its target is untouched.
        let victim = lab.dir.join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        std::os::unix::fs::symlink(&victim, incoming.join("report.pdf-3")).unwrap();
        let src3 = open_flags(&file, libc::O_RDONLY);
        assert_eq!(ask_with(&sv, "transfer b report.pdf\n", &[src3], false).1, b"ok report.pdf-4\n");
        unsafe { libc::close(src3) };
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        // `incoming` itself a symlink to elsewhere: not followed, nothing lands.
        let elsewhere = lab.dir.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, lab.root.join("home/c/incoming")).unwrap();
        let src4 = open_flags(&file, libc::O_RDONLY);
        let (_, r) = ask_with(&sv, "transfer c report.pdf\n", &[src4], false);
        unsafe { libc::close(src4) };
        assert!(String::from_utf8_lossy(&r).contains("incoming/ is not a plain directory"), "{}", String::from_utf8_lossy(&r));
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
        // Refusals close what they were handed, too.
        assert_eq!(fds_pointing_at(&file), 0, "the broker leaked a descriptor on a refusal");
        let _ = std::fs::remove_dir_all(&lab.dir);
    }

    /// One transfer of notes.txt ("hello transfer", 14 bytes) from a descriptor
    /// the sender left at byte 6; returns the reply.
    fn send_notes(sv: &Served, file: &Path) -> String {
        std::fs::write(file, b"hello transfer").unwrap();
        let src = open_flags(file, libc::O_RDONLY);
        unsafe { libc::lseek(src, 6, libc::SEEK_SET) };
        let r = ask_with(sv, "transfer b notes.txt\n", &[src], false).1;
        unsafe { libc::close(src) };
        String::from_utf8_lossy(&r).into_owned()
    }

    #[test]
    fn transfer_carries_the_size_checked() {
        use std::io::Write;
        let lab = lab("size", "b");
        let entry_dir = lab.dir.join("entry");
        std::fs::create_dir_all(&entry_dir).unwrap();
        let file = lab.dir.join("notes.txt");
        let resolve = resolver(lab.root.clone());
        // Called after the checks (and the question), before the copy.
        let grow = |d: &str| {
            std::fs::OpenOptions::new().append(true).open(&file).unwrap().write_all(b" and more").unwrap();
            resolve(d)
        };
        let shrink = |d: &str| {
            std::fs::OpenOptions::new().write(true).open(&file).unwrap().set_len(5).unwrap();
            resolve(d)
        };
        let dev = lab.dev;
        let home_dev = move || Some(dev);
        let mut sv = Served {
            zone: &lab.sender,
            uid: unsafe { libc::geteuid() },
            entry: &entry_dir,
            zones_dir: &lab.zones,
            home_dev: &home_dev,
            auto_approve: true,
            max_bytes: 64,
            resolve_dest: &grow,
            asking: &crate::consent::keep,
        };
        let incoming = lab.root.join("home/b/incoming");
        let r = send_notes(&sv, &file);
        assert!(r.contains("longer than the 14 bytes checked"), "{r}");
        sv.resolve_dest = &shrink;
        let r = send_notes(&sv, &file);
        assert!(r.contains("shrank to 5 of the 14 bytes checked"), "{r}");
        assert!(std::fs::read_dir(&incoming).map_or(true, |d| d.count() == 0), "a refused copy was left behind");
        // The whole file, whatever the descriptor's position.
        sv.resolve_dest = &resolve;
        assert_eq!(send_notes(&sv, &file), "ok notes.txt\n");
        assert_eq!(std::fs::read(incoming.join("notes.txt")).unwrap(), b"hello transfer");
        let _ = std::fs::remove_dir_all(&lab.dir);
    }

    #[test]
    fn transfer_refusals_precede_copy() {
        use std::os::unix::fs::MetadataExt;
        let lab = lab("refuse", "b n");
        let entry_dir = lab.dir.join("entry");
        std::fs::create_dir_all(&entry_dir).unwrap();
        let resolve = resolver(lab.root.clone());
        let not_running = |d: &str| -> Result<Target, String> { Err(format!("destination zone {d:?} is not running")) };
        let dev = lab.dev;
        let home_dev = move || Some(dev);
        let mut sv = Served {
            zone: &lab.sender,
            uid: unsafe { libc::geteuid() },
            entry: &entry_dir,
            zones_dir: &lab.zones,
            home_dev: &home_dev,
            auto_approve: true,
            max_bytes: 64,
            resolve_dest: &resolve,
            asking: &crate::consent::keep,
        };
        let file = lab.dir.join("f.txt");
        std::fs::write(&file, b"0123456789").unwrap();
        let ro = || open_flags(&file, libc::O_RDONLY);
        let big = lab.dir.join("big");
        std::fs::write(&big, vec![b'x'; 65]).unwrap();
        let long = "x".repeat(256);
        let cases: Vec<(String, Vec<RawFd>, &str)> = vec![
            ("transfer b f.txt\n".into(), vec![], "exactly one descriptor"),
            ("transfer b f.txt\n".into(), vec![ro(), ro()], "exactly one descriptor"),
            ("transfer b f.txt\n".into(), (0..20).map(|_| ro()).collect(), "more descriptors than a request may carry"),
            ("transfer a f.txt\n".into(), vec![ro()], "cannot transfer to itself"),
            ("transfer c f.txt\n".into(), vec![ro()], "does not name \"c\""),
            ("transfer zzz f.txt\n".into(), vec![ro()], "does not name \"zzz\""),
            ("transfer n f.txt\n".into(), vec![ro()], "receives nothing"),
            ("transfer b ../x\n".into(), vec![ro()], "single path component"),
            ("transfer b a/b\n".into(), vec![ro()], "single path component"),
            ("transfer b .hidden\n".into(), vec![ro()], "must not start with a dot"),
            ("transfer b ..\n".into(), vec![ro()], "not a file name"),
            (format!("transfer b {long}\n"), vec![ro()], "1 to 255 bytes"),
            ("transfer b f.txt extra\n".into(), vec![ro()], "usage: transfer"),
            ("transfer B f.txt\n".into(), vec![ro()], "not a zone name"),
            ("transfer b f.txt\n".into(), vec![open_flags(&lab.dir, libc::O_RDONLY | libc::O_DIRECTORY)], "not a regular file"),
            ("transfer b f.txt\n".into(), vec![open_flags(Path::new("/dev/null"), libc::O_RDONLY)], "not a regular file"),
            ("transfer b f.txt\n".into(), vec![open_flags(&file, libc::O_PATH)], "O_PATH"),
            ("transfer b f.txt\n".into(), vec![open_flags(&file, libc::O_RDWR)], "not opened read-only"),
            ("transfer b big\n".into(), vec![open_flags(&big, libc::O_RDONLY)], "transfer limit is 64"),
        ];
        for (req, fds, want) in cases {
            let (_, r) = ask_with(&sv, &req, &fds, false);
            for f in &fds {
                unsafe { libc::close(*f) };
            }
            let text = String::from_utf8_lossy(&r);
            assert!(text.starts_with("error: ") && text.contains(want), "request {req:?}: got {text:?}, wanted {want:?}");
        }
        /* Every refusal closed what it was handed. Checked after the loop,
         * since the cases open all their descriptors up front. */
        let left = fds_pointing_at(&file) + fds_pointing_at(&lab.dir) + fds_pointing_at(&big);
        assert_eq!(left, 0, "a refusal leaked a descriptor in the broker");
        // A file on another filesystem than the zone's data mount.
        let shm = Path::new("/dev/shm");
        if std::fs::metadata(shm).map(|m| m.dev() != lab.dev).unwrap_or(false) {
            let p = shm.join(format!("kryptik-transfer-{}", std::process::id()));
            std::fs::write(&p, b"elsewhere").unwrap();
            let (_, r) = ask_with(&sv, "transfer b f.txt\n", &[open_flags(&p, libc::O_RDONLY)], false);
            assert!(String::from_utf8_lossy(&r).contains("not on the zone's data mount"), "{}", String::from_utf8_lossy(&r));
            let _ = std::fs::remove_file(&p);
        } else {
            eprintln!("/dev/shm is on the same filesystem as the lab; the st_dev case is not exercised here");
        }
        /* Consent and an unknown data mount each refuse on their own. This sets
         * the variable consent's tests set, so it takes their lock. */
        sv.auto_approve = false;
        {
            let _env = crate::consent::ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            std::env::set_var("KRYPTIK_CONSENT_DIR", "/nonexistent/kryptik-consent");
            let (_, r) = ask_with(&sv, "transfer b f.txt\n", &[ro()], false);
            assert!(String::from_utf8_lossy(&r).contains("no consent channel"), "{}", String::from_utf8_lossy(&r));
            /* A destination that is not running is refused before any question:
             * even with no consent channel, the error is about the destination. */
            sv.resolve_dest = &not_running;
            let (_, r) = ask_with(&sv, "transfer b f.txt\n", &[ro()], false);
            let text = String::from_utf8_lossy(&r);
            assert!(text.contains("is not running") && !text.contains("consent"), "a transfer to a zone that is not running must be refused before any question: {text}");
            sv.resolve_dest = &resolve;
            std::env::remove_var("KRYPTIK_CONSENT_DIR");
        }
        sv.auto_approve = true;
        sv.home_dev = &dev_unknown;
        let (_, r) = ask_with(&sv, "transfer b f.txt\n", &[ro()], false);
        assert!(String::from_utf8_lossy(&r).contains("data mount is unknown"), "{}", String::from_utf8_lossy(&r));
        // Nothing was created on the destination side.
        assert!(!lab.root.join("home/b/incoming").exists());
        let _ = std::fs::remove_dir_all(&lab.dir);
    }

    #[test]
    fn dest_resolved_after_consent() {
        /* The first lookup finds the zone under `before`; by the answer it runs
         * under the lab root, as a zone restarted during the wait would. */
        let lab = lab("again", "b");
        let entry_dir = lab.dir.join("entry");
        let before = lab.dir.join("before");
        std::fs::create_dir_all(&entry_dir).unwrap();
        std::fs::create_dir_all(before.join("home/b")).unwrap();
        let (first, after) = (resolver(before.clone()), resolver(lab.root.clone()));
        let calls = std::cell::Cell::new(0);
        let resolve = |d: &str| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 { first(d) } else { after(d) }
        };
        let held = std::cell::Cell::new(0);
        let asking = || {
            held.set(held.get().max(fds_pointing_at(&before)));
            true
        };
        let dev = lab.dev;
        let home_dev = move || Some(dev);
        let sv = Served {
            zone: &lab.sender,
            uid: unsafe { libc::geteuid() },
            entry: &entry_dir,
            zones_dir: &lab.zones,
            home_dev: &home_dev,
            auto_approve: false,
            max_bytes: 64,
            resolve_dest: &resolve,
            asking: &asking,
        };
        let file = lab.dir.join("f.txt");
        std::fs::write(&file, b"moved").unwrap();
        let src = open_flags(&file, libc::O_RDONLY);
        let consent = lab.dir.join("consent");
        std::fs::create_dir_all(&consent).unwrap();
        let watch = std::fs::File::create(consent.join(crate::consent::WATCHER_LOCK)).unwrap();
        assert_eq!(unsafe { libc::flock(watch.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
        let r = {
            let _env = crate::consent::ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            std::env::set_var("KRYPTIK_CONSENT_DIR", &consent);
            let d = consent.clone();
            let person = std::thread::spawn(move || {
                for _ in 0..250 {
                    let q = std::fs::read_dir(&d).unwrap().flatten().map(|e| e.path()).find(|p| p.extension().is_some_and(|x| x == "ask"));
                    if let Some(q) = q {
                        std::thread::sleep(std::time::Duration::from_millis(300));
                        let id = q.file_stem().unwrap().to_string_lossy().into_owned();
                        std::fs::write(d.join(format!("{id}.answer")), "yes\n").unwrap();
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            });
            let (_, r) = ask_with(&sv, "transfer b f.txt\n", &[src], false);
            person.join().unwrap();
            std::env::remove_var("KRYPTIK_CONSENT_DIR");
            r
        };
        unsafe { libc::close(src) };
        assert_eq!(String::from_utf8_lossy(&r), "ok f.txt\n");
        assert_eq!(held.get(), 0, "the destination's root was held through the question");
        assert_eq!(std::fs::read(lab.root.join("home/b/incoming/f.txt")).unwrap(), b"moved");
        assert!(!before.join("home/b/incoming").exists(), "the transfer went into the tree the zone had left");
        let _ = std::fs::remove_dir_all(&lab.dir);
    }

    #[test]
    fn read_more_fills_then_stops_at_eof() {
        /* More than a socket buffer, in uneven pieces, after what the header
         * read already took; then a peer that stops short of what it announced. */
        let pair = || {
            let mut sv = [0; 2];
            assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) }, 0);
            (sv[0], sv[1])
        };
        let send = |w: RawFd, bytes: Vec<u8>| {
            std::thread::spawn(move || {
                for piece in bytes.chunks(6007) {
                    assert_eq!(unsafe { libc::write(w, piece.as_ptr() as *const libc::c_void, piece.len()) }, piece.len() as isize);
                }
                unsafe { libc::close(w) };
            })
        };
        let data: Vec<u8> = (0..(1usize << 20) + 777).map(|i| (i % 251) as u8).collect();
        let (r, w) = pair();
        let t = send(w, data[10..].to_vec());
        let mut buf = data[..10].to_vec();
        read_more(r, &mut buf, data.len(), Instant::now()).unwrap();
        t.join().unwrap();
        unsafe { libc::close(r) };
        assert!(buf == data, "the payload came back different");
        let (r, w) = pair();
        let t = send(w, vec![7u8; 30]);
        let mut buf = Vec::new();
        read_more(r, &mut buf, 100, Instant::now()).unwrap();
        t.join().unwrap();
        unsafe { libc::close(r) };
        assert_eq!(buf, vec![7u8; 30], "EOF leaves what arrived, and no more");
    }

    #[test]
    fn copy_stops_at_cap() {
        let dir = entry("cap");
        let src_p = dir.join("src");
        std::fs::write(&src_p, vec![b'y'; 20]).unwrap();
        let out_p = dir.join("out");
        let src = open_flags(&src_p, libc::O_RDONLY);
        let out = open_flags(&out_p, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC);
        let e = copy_capped(src, out, 10).unwrap_err();
        assert!(e.contains("longer than the 10 bytes checked"), "{e}");
        assert!(std::fs::metadata(&out_p).unwrap().len() <= 11);
        // And a file within the cap copies whole.
        let src2 = open_flags(&src_p, libc::O_RDONLY);
        let out2 = open_flags(&dir.join("out2"), libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC);
        assert_eq!(copy_capped(src2, out2, 20).unwrap(), 20);
        assert_eq!(std::fs::read(dir.join("out2")).unwrap(), vec![b'y'; 20]);
        for f in [src, out, src2, out2] {
            unsafe { libc::close(f) };
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_request_wire_format() {
        assert_eq!(parse_request("version"), Ok(Request::Version));
        assert_eq!(parse_request("  clipboard-get  "), Ok(Request::ClipboardGet));
        assert_eq!(
            parse_request("clipboard-set image/jpeg 1048576"),
            Ok(Request::ClipboardSet { mime: "image/jpeg".into(), len: CLIPBOARD_MAX })
        );
        assert!(parse_request("clipboard-set image/jpeg 1048577").is_err());
        assert!(parse_request("clipboard-set image/gif 1").is_err());
        assert!(parse_request("clipboard-set text/plain 1 extra").is_err());
        assert!(parse_request("VERSION").is_ok_and(|r| matches!(r, Request::Unknown(_))));
        assert!(parse_request("version now").is_ok_and(|r| matches!(r, Request::Unknown(_))));
        assert_eq!(
            parse_request("time-offset -0.25 4"),
            Ok(Request::TimeOffset(crate::time::Claim { offset: -0.25, sources: 4 }))
        );
        for bad in ["time-offset", "time-offset 1", "time-offset 1 2 3", "time-offset 1e9 4", "time-offset inf 4", "time-offset 1 0"] {
            assert!(parse_request(bad).is_err(), "{bad:?} was accepted");
        }
    }

    /// From the nic zone the claim reaches the decision, which refuses for want
    /// of a floor; no clock is touched either way.
    #[test]
    fn only_nic_zone_reports_time() {
        let claim = crate::time::Claim { offset: 2.0, sources: 3 };
        let dir = std::env::temp_dir().join(format!("kryptik-broker-time-{}", std::process::id()));
        let zone_of = |mode: &str, extra: &str| {
            Zone::from_str(&format!(
                "[zone]\nname = \"t\"\n[network]\nmode = \"{mode}\"\n{extra}[storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n[ui]\nborder_color = \"#123456\"\n"
            ))
            .unwrap()
        };
        for mode in ["none", "routed"] {
            let out = time_offset_in(&zone_of(mode, ""), &claim, &mut crate::time::SystemClock, &dir, Some(0), &crate::consent::keep);
            assert!(matches!(&out, crate::time::Outcome::Refused(w) if w.contains("does not hold the network")), "{mode}: {out:?}");
        }
        let nic = zone_of("nic", "");
        let out = time_offset_in(&nic, &claim, &mut crate::time::SystemClock, &dir, None, &crate::consent::keep);
        assert!(matches!(&out, crate::time::Outcome::Refused(w) if w.contains("no floor is known")), "{out:?}");
        assert!(!dir.join("state").exists(), "a refused claim left state behind");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Lengths within their bounds and a one-component name, nothing else.
    #[test]
    fn update_verbs_parse_within_bounds() {
        use crate::update::{POINTER_MAX, PUT_MAX};
        assert_eq!(parse_request("update-latest 300 120"), Ok(Request::UpdateLatest { plen: 300, slen: 120 }));
        assert_eq!(parse_request("update-poll"), Ok(Request::UpdatePoll));
        assert_eq!(
            parse_request(&format!("update-put kryptik-root.img 1048576 {PUT_MAX}")),
            Ok(Request::UpdatePut { name: "kryptik-root.img".into(), offset: 1048576, len: PUT_MAX })
        );
        assert!(parse_request("update-put manifest.sig 0 120").is_ok());
        let over_pointer = format!("update-latest {} 120", POINTER_MAX + 1);
        let over_put = format!("update-put root.json 0 {}", PUT_MAX + 1);
        for bad in [
            "update-latest", "update-latest 300", "update-latest 0 120", "update-latest 300 0", "update-latest -1 120", over_pointer.as_str(),
            "update-poll now",
            "update-put", "update-put root.json 0", "update-put root.json 0 0", "update-put root.json -1 10", "update-put root.json x 10",
            "update-put ../root.json 0 10", "update-put a/b 0 10", "update-put .hidden 0 10", over_put.as_str(),
        ] {
            assert!(parse_request(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn only_nic_zone_brings_update() {
        let zone_of = |mode: &str, extra: &str| {
            Zone::from_str(&format!(
                "[zone]\nname = \"t\"\n[network]\nmode = \"{mode}\"\n{extra}[storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n[ui]\nborder_color = \"#123456\"\n"
            ))
            .unwrap()
        };
        for mode in ["none", "routed"] {
            assert!(update_refusal(&zone_of(mode, "")).is_some_and(|w| w.contains("does not hold the network")), "{mode}");
        }
        assert_eq!(update_refusal(&zone_of("nic", "")), None);
    }

    /// Requests from fuzz-corpus/broker-requests (add any that ever breaks the
    /// broker), damaged by a fixed-seed generator and sent down a real
    /// connection. No panic, no overrun of the deadline, one well-formed reply,
    /// and nothing accepted outside the grammar.
    #[test]
    fn broker_survives_any_request() {
        const CORPUS: &str = include_str!("../fuzz-corpus/broker-requests");
        // xorshift64*: small, seeded, the same sequence everywhere.
        let mut state: u64 = 0x4252_4F4B_4552_3031;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let dir = entry("fuzz");
        let z = zone_t();
        let s = served(&z, &dir, unsafe { libc::geteuid() });
        let (mut sent, mut accepted) = (0u32, 0u32);
        for seed in CORPUS.lines().filter(|l| !l.is_empty()) {
            // time-offset is refused here and logs every time, so it gets fewer rounds.
            let rounds = if seed.starts_with("time-offset") { 30 } else { 150 };
            for round in 0..rounds {
                let mut req = seed.as_bytes().to_vec();
                req.push(b'\n');
                let payload = (next() % 65) as usize;
                req.extend(std::iter::repeat(b'x').take(payload));
                if round > 0 {
                    for _ in 0..1 + next() % 3 {
                        let at = (next() % req.len().max(1) as u64) as usize;
                        match next() % 6 {
                            0 if !req.is_empty() => req[at] ^= 1 << (next() % 8),
                            1 => req.truncate(at),
                            2 => req.insert(at, [b' ', b'\n', 0, 0xff, b'-', b'9'][(next() % 6) as usize]),
                            3 => req.splice(at..at, b"18446744073709551616".iter().copied()).for_each(drop),
                            4 => req.splice(at..at, std::iter::repeat(b'A').take(600)).for_each(drop),
                            _ if !req.is_empty() => { req.remove(at); }
                            _ => {}
                        }
                    }
                }
                let line_end = req.iter().position(|b| *b == b'\n').unwrap_or(req.len());
                let header = String::from_utf8_lossy(&req[..line_end]).into_owned();
                if let Ok(Request::ClipboardSet { len, .. }) = parse_request(&header) {
                    assert!(len <= CLIPBOARD_MAX, "{header:?}: a length past the limit parsed");
                }

                let (server, client) = pair();
                send_all(client, &req);
                unsafe { libc::shutdown(client, libc::SHUT_WR) };
                let started = Instant::now();
                let served_it = serve_connection(server, &s);
                unsafe { libc::close(server) };
                let reply = recv_reply(client);
                unsafe { libc::close(client) };
                sent += 1;
                assert!(served_it.is_ok(), "{header:?}: the connection failed: {served_it:?}");
                assert!(started.elapsed() < REQUEST_DEADLINE + Duration::from_secs(1), "{header:?}: held the launcher past the deadline");
                let text = String::from_utf8_lossy(&reply);
                let first = text.lines().next().unwrap_or("");
                assert!(
                    ["ok", "error: ", "empty", "kryptik-broker 1 zone=t"].iter().any(|p| first.starts_with(p)) && text.contains('\n'),
                    "{header:?}: replied {text:?}"
                );
                if first.starts_with("ok") || first.starts_with("empty") || first.starts_with("kryptik-broker") {
                    accepted += 1;
                }
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
        // The generator must reach both sides of the grammar.
        assert!(sent > 2000 && accepted > 50 && accepted < sent, "sent {sent}, accepted {accepted}");
    }
}
