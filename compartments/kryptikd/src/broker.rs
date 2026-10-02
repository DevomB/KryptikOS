//! The zone broker (docs/design/broker.md): each zone's socket into zone 0, for the clipboard,
//! transfer, time and update verbs. A peer is known by its `SO_PEERCRED` uid, as each zone
//! has its own uid range; never by its pid, which may be reused.

use std::cell::Cell;
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

/// Listen at `path` for the zone identity alone, replacing a stale file: the entry is ours.
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
    if unsafe { libc::geteuid() } == 0
        && unsafe { libc::fchownat(libc::AT_FDCWD, c.as_ptr(), uid, gid, libc::AT_SYMLINK_NOFOLLOW) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::listen(fd.as_raw_fd(), 8) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd.into_raw_fd())
}

/// A zone's clipboard, in its registry entry: a MIME type line, then the bytes.
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

/// One request's end-to-end deadline; a slow zone stalls only its own launcher meanwhile.
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

/// One request: a header line, then the payload its verb announces.
///
/// ```text
/// version\n                              -> kryptik-broker 1 zone=NAME\n
/// clipboard-set <mime> <len>\n<bytes>    -> ok\n
/// clipboard-get\n                        -> ok <mime> <len>\n<bytes>  |  empty\n
/// transfer <zone> <name>\n  (+1 fd)      -> ok <final name>\n
/// clipboard-move ...                     -> error: clipboard-move is a zone 0 act, not a zone verb\n
/// time-offset <seconds> <sources>\n      -> ok ignored | slewed | stepped | stepped after consent\n
/// update-latest <plen> <slen>\n<pointer><sig>
///                                        -> ok current | ok available <version>\n
/// update-poll\n                          -> idle | fetch <version> <base> need <name> <offset> ...\n
/// update-put <name> <offset> <len>\n<bytes>
///                                        -> ok <name> <held>/<size> | ok <name> complete\n
/// anything else                          -> error: <reason>\n
/// ```
///
/// The time and update verbs are taken from the nic zone alone.
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
    UpdateLatest { plen: usize, slen: usize },
    UpdatePoll,
    UpdatePut { name: String, offset: u64, len: usize },
    Unknown(String),
}

impl Request {
    /// What the launcher's log calls this request: never the zone's own words.
    pub fn name(&self) -> &'static str {
        match self {
            Request::Version => "version",
            Request::ClipboardSet { .. } => "clipboard-set",
            Request::ClipboardGet => "clipboard-get",
            Request::NotAZoneVerb(_) => "zone 0 verb",
            Request::Transfer { .. } => "transfer",
            Request::TimeOffset(_) => "time-offset",
            Request::UpdateLatest { .. } => "update-latest",
            Request::UpdatePoll => "update-poll",
            Request::UpdatePut { .. } => "update-put",
            Request::Unknown(_) => "unknown verb",
        }
    }
}

/// A destination as written in a request: the same alphabet as a zone name.
fn check_zone_name(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 12 || !s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err(format!("{s:?} is not a zone name"));
    }
    Ok(())
}

/// A transferred file's name: one component of 1 to 255 printable ASCII bytes, not a dotfile.
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
    let mut words = line.split_whitespace();
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

/// `time-offset`, nic zone only: no other zone has a network of its own to measure with.
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

/// Only the nic zone can have fetched an update; what it sends is still judged by update.rs.
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
            let (role, running) = (up::required_role()?, up::running_version());
            let (pointer, sig) = payload.split_at(*plen);
            up::latest(dir, &up::tool_checks(), now, &role, &running, pointer, sig).map(|s| match s {
                up::Standing::Current => "ok current".to_string(),
                up::Standing::Available(v) => format!("ok available {v}"),
            })
        }
        Request::UpdatePoll => {
            let (role, running) = (up::required_role()?, up::running_version());
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
    /// st_dev of the zone's /home/<zone>, per request: its root is built after pid 1 starts.
    pub home_dev: &'a dyn Fn() -> Option<u64>,
    /// The development stand-in for the zone 0 prompt.
    pub auto_approve: bool,
    pub max_bytes: u64,
    /// Finds a running destination's root and identity: the registry, or a test directory.
    pub resolve_dest: &'a dyn Fn(&str) -> Result<Target, String>,
    /// Called ten times a second while asking: the launcher pumps zone output; `false` withdraws.
    pub asking: &'a dyn Fn() -> bool,
    /// Where the broker's lines go; the launcher bounds them per launch.
    pub log: &'a dyn Fn(&str),
    /// After a refusal, no new question until then: each one takes focus in zone 0.
    pub refused_until: &'a Cell<Option<Instant>>,
}

/// How long a refused zone waits before it may ask again.
pub const REFUSAL_PAUSE: Duration = Duration::from_secs(60);

/// The launcher's `resolve_dest`, from the registry and the zone's pid 1 root.
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
    let root_fd = unsafe { OwnedFd::from_raw_fd(root_fd) };
    // The pid may have ended, and been reused, since the registry was read.
    if !st.still_alive() {
        return Err(format!("destination zone {dest:?} stopped while it was being reached"));
    }
    Ok(Target { root_fd, home_rel: format!("home/{dest}"), uid, gid })
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

/// Check a transfer in the order docs/design/broker.md gives, ask the user, then deliver it.
/// The zone learns only the name the file landed under.
fn handle_transfer(s: &Served, dest: &str, name: &str, fds: &[OwnedFd]) -> Result<(String, u64), String> {
    let sender = &s.zone.name;
    if fds.len() != 1 {
        return Err(format!("transfer needs exactly one descriptor attached (got {})", fds.len()));
    }
    if dest == sender {
        return Err("a zone cannot transfer to itself".into());
    }
    if !s.zone.transfer_to.iter().any(|d| d == dest) {
        return Err(format!("[transfer] to in zone {sender:?} does not name {dest:?}"));
    }
    let dz = Zone::from_file(&s.zones_dir.join(format!("{dest}.toml")))
        .map_err(|e| format!("destination zone {dest:?}: {e}"))?;
    if dz.network == NetworkMode::Nic {
        return Err(format!("zone {dest:?} holds the NIC and receives nothing"));
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
    /* Ask last, once the destination is known to run: a pointless question teaches people to say
     * yes. Then look it up again; holding its root through the wait would pin its mounts. */
    if !s.auto_approve {
        drop((s.resolve_dest)(dest)?);
        if s.refused_until.get().is_some_and(|t| Instant::now() < t) {
            return Err("a transfer from this zone was refused less than a minute ago; not asking again yet".into());
        }
        if let Err(r) = crate::consent::ask(sender, dest, name, st.st_size as u64, s.asking) {
            // Only a question placed took focus: with no channel or watcher nobody was asked.
            if r.shown {
                s.refused_until.set(Some(Instant::now() + REFUSAL_PAUSE));
            }
            return Err(r.why);
        }
    }
    let target = (s.resolve_dest)(dest)?;
    // The size checked, and shown if asked, is the size carried.
    deliver(&target, name, src, st.st_size as u64)
}

/// Copy into the destination's `incoming/`, every path resolved in its root without symlinks.
fn deliver(target: &Target, name: &str, src: RawFd, size: u64) -> Result<(String, u64), String> {
    let home = openat2(
        target.root_fd.as_raw_fd(),
        &target.home_rel,
        (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        0,
        RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    )
    .map_err(|e| format!("destination home is not reachable: {e}"))?;
    /* As the destination identity: an ephemeral home is a tmpfs in the zone's user namespace,
     * which refuses (EOVERFLOW) an inode for an unmapped uid such as host root. */
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
    if made
        && unsafe { libc::geteuid() } == 0
        && unsafe { libc::fchownat(home, inc.as_ptr(), target.uid, target.gid, libc::AT_SYMLINK_NOFOLLOW) } < 0
    {
        return Err(format!("incoming/ ownership: {}", io::Error::last_os_error()));
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
    // O_EXCL picks the name: a collision or a planted symlink (EEXIST) moves to the next number.
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

/// Copy `src` to `out` from byte 0, with `cap` on the bytes copied: the file may have grown.
/// The offset is the copy's own, so moving the shared descriptor's position changes nothing.
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

/// Accept one connection and answer its request; returns the request's name for the log.
pub fn serve_one(listen_fd: RawFd, s: &Served) -> io::Result<Option<&'static str>> {
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

/// Answer one request: a foreign peer learns nothing, and refusals come before the payload.
pub fn serve_connection(fd: RawFd, s: &Served) -> io::Result<Option<&'static str>> {
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
    let req = parse_request(&header);
    let verb = req.as_ref().map_or("malformed request", Request::name);
    match req {
        Err(why) => reply(fd, &format!("error: {why}\n")),
        Ok(Request::Version) => reply(fd, &format!("kryptik-broker 1 zone={zone}\n")),
        Ok(Request::Transfer { dest, name }) => match handle_transfer(s, &dest, &name, &fds) {
            Ok((final_name, bytes)) => {
                (s.log)(&format!(
                    "kryptikd[zone {zone}]: transfer: {name} ({bytes} bytes) -> {dest} as incoming/{final_name}"
                ));
                reply(fd, &format!("ok {final_name}\n"));
            }
            Err(why) => reply(fd, &format!("error: {why}\n")),
        },
        Ok(Request::TimeOffset(claim)) => {
            let outcome = handle_time_offset(s.zone, &claim, s.asking);
            (s.log)(&format!(
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
                Ok(r) => (s.log)(&format!("kryptikd[zone {zone}]: {verb}: {r}")),
                Err(why) => (s.log)(&format!("kryptikd[zone {zone}]: {verb}: refused: {why}")),
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

/// Receive into `buf` until it holds `want` bytes (a checked length) or EOF, by the deadline.
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

/// Replace the zone's payload whole, 0600; a planted symlink is replaced, never followed.
pub fn clipboard_write(entry: &Path, mime: &str, bytes: &[u8]) -> io::Result<()> {
    if !MIME_TYPES.contains(&mime) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unsupported MIME type {mime:?}")));
    }
    if bytes.len() > CLIPBOARD_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "payload over the clipboard limit"));
    }
    crate::files::write_atomic(&entry.join(CLIPBOARD_FILE), &[mime.as_bytes(), b"\n", bytes], 0o600, None)
}

/// Move `from`'s payload to `to` (registry entries of running zones); returns what moved.
pub fn clipboard_move(from: &Path, to: &Path) -> io::Result<(String, usize)> {
    let Some((mime, bytes)) = clipboard_read(from)? else {
        return Err(io::Error::new(io::ErrorKind::NotFound, "nothing on the source zone's clipboard"));
    };
    clipboard_write(to, &mime, &bytes)?;
    // The destination first: a failure here leaves the payload in both zones, never in none.
    match std::fs::remove_file(from.join(CLIPBOARD_FILE)) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(io::Error::new(e.kind(), format!("the payload reached the destination but is still on the source: {e}")));
        }
    }
    Ok((mime, bytes.len()))
}

/// The zone 0 gesture, for `kryptikd clipboard move` and serve: Ok is the line to show.
pub fn move_between(from: &str, to: &str) -> Result<String, String> {
    use crate::registry::{self, State};
    for z in [from, to] {
        match registry::state(z) {
            Ok(State::Running { .. }) => {}
            Ok(State::Stale { .. }) => return Err(format!("clipboard: zone {z:?} is not running (stale entry)")),
            Ok(State::Absent) => return Err(format!("clipboard: zone {z:?} is not running")),
            Err(e) => return Err(format!("clipboard: {e}")),
        }
    }
    match clipboard_move(&registry::entry_dir(from), &registry::entry_dir(to)) {
        Ok((mime, len)) => Ok(format!("clipboard: moved {len} bytes of {mime} from {from} to {to}")),
        Err(e) => Err(format!("clipboard: {e}")),
    }
}

#[cfg(test)]
mod tests;
