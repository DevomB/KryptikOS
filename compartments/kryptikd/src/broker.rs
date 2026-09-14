//! Broker identity: who is on the other end of a Unix socket, and which zone
//! that is (docs/design/05-broker-and-desktop-boundary.md).
//!
//! THE ONE MECHANISM
//!
//! Every zone has a fixed host identity range (`[identity] uid_base`, Design
//! 01). A connection accepted in zone 0 carries `SO_PEERCRED`, whose uid is
//! kernel-asserted and cannot be chosen by the connecting process. If that
//! uid falls in exactly one zone's range, the peer IS that zone: no token, no
//! handshake, nothing a zone could forge. The peer pid is deliberately not
//! used - it is a pid in zone 0's namespace and may be reused - and the
//! peer gid is checked only for consistency.
//!
//! This module is the primitive. The verbs (file transfer, clipboard) and
//! the serving loop come later and are specified in Design 05; what they
//! all start with is `peer_identity` followed by `zone_for_uid`.
//!
//! Unprivileged developer launches map every zone to the launching user's
//! own uid, so identity cannot distinguish zones there; `zone_for_uid`
//! returns `None` for a uid outside every declared range, and the caller
//! refuses. That is the honest answer on a developer host and the correct
//! one on the target.

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::registry;
use crate::zone::{NetworkMode, Zone, IDENTITY_STRIDE};

/// Kernel-asserted credentials of a Unix-socket peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
}

/// `SO_PEERCRED` of a connected AF_UNIX socket (stream or seqpacket, or one
/// end of a socketpair).
pub fn peer_identity(fd: RawFd) -> io::Result<PeerCred> {
    let mut uc: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut uc as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCred { uid: uc.uid, gid: uc.gid })
}

/// The zone whose declared identity range contains `uid`, if exactly one
/// does. Ranges are disjoint by construction (`zone::check_invariants`), so
/// "exactly one" is a scan for the single match; a uid outside every range
/// - a host user, an unprivileged developer launch, root - matches nothing.
pub fn zone_for_uid<'a>(zones: &'a [Zone], uid: u32) -> Option<&'a Zone> {
    let mut found: Option<&Zone> = None;
    for z in zones {
        let Some(base) = z.uid_base else { continue };
        if uid >= base && uid - base < IDENTITY_STRIDE {
            if found.is_some() {
                return None; // overlapping ranges: refuse rather than guess
            }
            found = Some(z);
        }
    }
    found
}

/// Identify the zone behind a connection, or say why not. The gid must lie
/// in the same range as the uid: a process that somehow held a uid from one
/// zone and a gid from another is not any zone.
pub fn identify<'a>(zones: &'a [Zone], fd: RawFd) -> Result<&'a Zone, String> {
    let cred = peer_identity(fd).map_err(|e| format!("SO_PEERCRED: {e}"))?;
    let z = zone_for_uid(zones, cred.uid)
        .ok_or_else(|| format!("peer uid {} is not in any zone's identity range", cred.uid))?;
    match zone_for_uid(zones, cred.gid) {
        Some(g) if g.name == z.name => Ok(z),
        _ => Err(format!(
            "peer uid {} is zone {:?} but gid {} is not in that zone's range",
            cred.uid, z.name, cred.gid
        )),
    }
}

/// The socket file name inside a registry entry, and the path a zone sees.
pub const SOCKET_NAME: &str = "broker";
pub const ZONE_PATH: &str = "/run/kryptik/broker";

/// Bind a listening AF_UNIX socket at `path`, owned by the zone identity so
/// the zone (and nobody else) may connect to it. A stale file is removed
/// first: the path is inside a registry entry this launcher has just
/// claimed, so nothing else can own it.
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
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (i, b) in c.as_bytes().iter().enumerate() {
        sa.sun_path[i] = *b as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + c.as_bytes().len() + 1) as libc::socklen_t;
    let r = unsafe {
        // Nobody but the owner may connect: 0600 before the bind is visible.
        let old = libc::umask(0o177);
        let r = libc::bind(fd, &sa as *const _ as *const libc::sockaddr, len);
        libc::umask(old);
        r
    };
    if r < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    if unsafe { libc::geteuid() } == 0 && unsafe { libc::chown(c.as_ptr(), uid, gid) } < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    if unsafe { libc::listen(fd, 8) } < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

/// THE CLIPBOARD (Design 05)
///
/// One payload per zone, held by zone 0 in the zone's registry entry (0700,
/// root-owned on the target) as the file `clipboard`: first line the MIME
/// type, the bytes after it. A zone sets and gets its OWN payload through
/// its broker. Moving a payload between zones is a zone 0 act - the
/// operator's gesture, `kryptikd clipboard move FROM TO` - and never a zone
/// verb: no zone can ask for another zone's payload because the verb does
/// not exist on the zone-facing socket (B9, B10). After a move the source
/// keeps its payload (copy semantics for the user) and the destination's
/// previous one is replaced.
pub const CLIPBOARD_FILE: &str = "clipboard";
pub const CLIPBOARD_MAX: usize = 1 << 20;

/// The MIME types a zone may label a payload with. A fixed list: the label
/// crosses the boundary with the bytes, and a free-form label is a channel.
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
/// between waitpid polls, so a zone that dribbles bytes stalls its own
/// supervision and nothing else; the deadline bounds even that.
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

/// One request, parsed from its header line. The wire format is one header
/// line, and for `clipboard-set` exactly `len` payload bytes after it:
///
/// ```text
/// version\n                              -> kryptik-broker 1 zone=NAME\n
/// clipboard-set <mime> <len>\n<bytes>    -> ok\n
/// clipboard-get\n                        -> ok <mime> <len>\n<bytes>  |  empty\n
/// anything else                          -> error: <reason>\n
/// ```
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    Version,
    ClipboardSet { mime: String, len: usize },
    ClipboardGet,
    /// A verb that exists, but not on the zone-facing socket (B10).
    NotAZoneVerb(String),
    /// `transfer <zone> <name>` with the file as one SCM_RIGHTS descriptor.
    Transfer { dest: String, name: String },
    Unknown(String),
}

/// A destination as written in a request: the same alphabet as a zone name.
fn check_zone_name(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 12 || !s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err(format!("{s:?} is not a zone name"));
    }
    Ok(())
}

/// The name a transferred file lands under (Design 05 B8): one path
/// component, printable ASCII, no leading dot so a zone cannot plant
/// dotfiles, at most 255 bytes.
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
        ("", _) => Err("empty request".into()),
        _ => Ok(Request::Unknown(verb.to_string())),
    }
}

/// TRANSFER (Design 05, B1-B8, B12)
///
/// A zone hands its broker an O_RDONLY descriptor to a regular file on its
/// own data mount and names a destination zone and a file name. Zone 0
/// checks, in order and refusing on the first failure: the descriptor count,
/// the destination (not itself; named in the sender's `[transfer] to`; a
/// configured zone; never the one holding the NIC), consent, then the
/// descriptor itself (regular file, O_RDONLY, not O_PATH, on the sender's
/// data mount, within the cap), then finds the running destination and
/// copies the bytes into its `incoming/`, owned by the destination identity,
/// under a name chosen by O_EXCL and never by stat-then-create. The zone
/// learns the final name and nothing else about the destination.
///
/// The path into the destination is resolved with openat2 from its root
/// (`/proc/<pid 1>/root`, an O_PATH descriptor into its mount namespace)
/// with RESOLVE_IN_ROOT and RESOLVE_NO_SYMLINKS: a symlink the destination
/// plants anywhere on the way - `incoming` itself, or the name - is refused
/// or skipped, never followed, so nothing zone 0 writes can leave the
/// destination's tree. That replaces the uid-switching helper Design 05
/// sketched: the resolution cannot escape, whoever runs it.
pub const TRANSFER_MAX: u64 = 1 << 30;
pub const INCOMING: &str = "incoming";

/// Where a transfer lands.
pub struct Target {
    /// O_PATH directory descriptor: the destination's root.
    pub root_fd: RawFd,
    /// The destination's home, relative to that root (`home/<zone>`).
    pub home_rel: String,
    pub uid: u32,
    pub gid: u32,
}

impl Drop for Target {
    fn drop(&mut self) {
        unsafe { libc::close(self.root_fd) };
    }
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
    /// st_dev of the zone's data mount as the zone sees it (/home/<zone>),
    /// asked for at request time: the zone's root is only built after its
    /// pid 1 exists, so it cannot be read once at launch. None when unknown,
    /// which refuses every transfer.
    pub home_dev: &'a dyn Fn() -> Option<u64>,
    /// The development stand-in for the zone 0 prompt.
    pub auto_approve: bool,
    pub max_bytes: u64,
    /// How a destination is found: running, its root, its identity. The
    /// launcher asks the registry; tests point at a directory.
    pub resolve_dest: &'a dyn Fn(&str) -> Result<Target, String>,
}

/// The launcher's destination lookup: the registry says whether the zone
/// runs and as whom; its pid 1's root is the way into its mount namespace.
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
fn openat2(dirfd: RawFd, path: &str, flags: u64, mode: u64, resolve: u64) -> io::Result<RawFd> {
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
        Ok(r as RawFd)
    }
}

fn handle_transfer(s: &Served, dest: &str, name: &str, fds: &[RawFd]) -> Result<(String, u64), String> {
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
    let src = fds[0];
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
    // Everything a machine can decide has been decided; the last word is
    // the user's, through the trusted chrome (consent.rs). Asked only now,
    // after the descriptor checks, so a request that would be refused
    // anyway never becomes a question.
    if !s.auto_approve {
        crate::consent::ask(sender, dest, name, st.st_size as u64)?;
    }
    let target = (s.resolve_dest)(dest)?;
    deliver(&target, name, src, s.max_bytes)
}

fn deliver(target: &Target, name: &str, src: RawFd, cap: u64) -> Result<(String, u64), String> {
    let home = openat2(
        target.root_fd,
        &target.home_rel,
        (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        0,
        RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    )
    .map_err(|e| format!("destination home is not reachable: {e}"))?;
    // As root, create AS the destination identity. An ephemeral zone's home
    // is a tmpfs mounted inside the zone's own user namespace, and the
    // kernel refuses to create an inode there for a uid that namespace does
    // not map - host root is exactly such a uid, and the first privileged
    // transfer into an ephemeral zone died on `incoming/` with EOVERFLOW.
    // The zone identity IS mapped (to 0 inside), so with the filesystem
    // uid/gid set to it everything lands owned by the destination without a
    // chown, and the chowns below become no-ops. Restored on every path out;
    // the broker serves one request at a time, so nothing else is affected.
    let switched = unsafe { libc::geteuid() } == 0;
    if switched {
        unsafe {
            libc::setfsgid(target.gid);
            libc::setfsuid(target.uid);
        }
    }
    let r = deliver_into(home, target, name, src, cap);
    if switched {
        unsafe {
            libc::setfsuid(0);
            libc::setfsgid(0);
        }
    }
    unsafe { libc::close(home) };
    r
}

fn deliver_into(home: RawFd, target: &Target, name: &str, src: RawFd, cap: u64) -> Result<(String, u64), String> {
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
    let r = (|| {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(inc_fd, &mut st) } < 0 {
            return Err(format!("incoming/: {}", io::Error::last_os_error()));
        }
        if st.st_uid != target.uid {
            return Err("incoming/ is not owned by the destination zone".into());
        }
        // O_EXCL chooses the name; a collision - or a planted symlink, which
        // O_CREAT|O_EXCL also reports as EEXIST - moves to the next number.
        for i in 1..=100u32 {
            let cand = if i == 1 { name.to_string() } else { format!("{name}-{i}") };
            match openat2(
                inc_fd,
                &cand,
                (libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
                0o600,
                RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
            ) {
                Ok(out) => {
                    let r = fill(out, src, cap, target);
                    unsafe { libc::close(out) };
                    return match r {
                        Ok(n) => Ok((cand, n)),
                        Err(e) => {
                            let c = CString::new(cand.as_str()).unwrap();
                            unsafe { libc::unlinkat(inc_fd, c.as_ptr(), 0) };
                            Err(e)
                        }
                    };
                }
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => continue,
                Err(e) => return Err(format!("incoming/{cand}: {e}")),
            }
        }
        Err(format!("incoming/ already holds {name} and 99 numbered variants of it"))
    })();
    unsafe { libc::close(inc_fd) };
    r
}

fn fill(out: RawFd, src: RawFd, cap: u64, target: &Target) -> Result<u64, String> {
    if unsafe { libc::geteuid() } == 0 && unsafe { libc::fchown(out, target.uid, target.gid) } < 0 {
        return Err(format!("ownership: {}", io::Error::last_os_error()));
    }
    let total = copy_capped(src, out, cap)?;
    if unsafe { libc::fsync(out) } < 0 {
        return Err(format!("fsync: {}", io::Error::last_os_error()));
    }
    Ok(total)
}

/// Copy `src` to `out` with a running byte cap. st_size was checked, but a
/// file can grow under a copy - a racing writer, or a sparse file that was
/// small on paper - and the cap is the bound the operator was promised, so
/// it is enforced on bytes actually copied (Design 05 B6).
pub fn copy_capped(src: RawFd, out: RawFd, cap: u64) -> Result<u64, String> {
    let mut total: u64 = 0;
    let mut fallback = false;
    let mut buf = vec![0u8; 1 << 16];
    loop {
        // One byte past the cap is enough to know the file is over it.
        let want = std::cmp::min(1u64 << 20, cap + 1 - total) as usize;
        let n = if !fallback {
            let n = unsafe {
                libc::copy_file_range(src, std::ptr::null_mut(), out, std::ptr::null_mut(), want, 0)
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    // Older kernels refuse cross-filesystem copies; read/write does the same job.
                    Some(libc::EXDEV) | Some(libc::EINVAL) | Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP)
                        if total == 0 =>
                    {
                        fallback = true;
                        continue;
                    }
                    _ => return Err(format!("copy: {e}")),
                }
            }
            n as u64
        } else {
            let take = std::cmp::min(buf.len(), want);
            let n = unsafe { libc::read(src, buf.as_mut_ptr() as *mut libc::c_void, take) };
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
            return Err(format!("file grew past the {cap}-byte limit during the copy; aborted"));
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
    let result = serve_connection(fd, s);
    unsafe { libc::close(fd) };
    result
}

/// Answer one request on an accepted connection. The peer must be the zone
/// this launcher runs (`s.uid` is its mapped host uid); anything else gets a
/// refusal and no information. Every refusal happens before a payload is
/// read; every descriptor a request attaches is closed here.
pub fn serve_connection(fd: RawFd, s: &Served) -> io::Result<Option<String>> {
    let zone = s.zone.name.as_str();
    let entry = s.entry;
    let cred = peer_identity(fd)?;
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
    let close_fds = |fds: &[RawFd]| {
        for f in fds {
            unsafe { libc::close(*f) };
        }
    };
    while more && !buf.contains(&b'\n') && buf.len() < 512 {
        more = match recv_some(fd, &mut buf, started) {
            Ok(m) => m,
            Err(e) => {
                close_fds(&fds);
                return Err(e);
            }
        };
    }
    let Some(nl) = buf.iter().position(|b| *b == b'\n') else {
        close_fds(&fds);
        reply(fd, "error: header line missing or too long\n");
        return Ok(None);
    };
    let header = String::from_utf8_lossy(&buf[..nl]).to_string();
    let mut rest: Vec<u8> = buf.split_off(nl + 1);
    let verb = header.split_whitespace().next().unwrap_or("").to_string();
    match parse_request(&header) {
        Err(why) => reply(fd, &format!("error: {why}\n")),
        Ok(Request::Version) => reply(fd, &format!("kryptik-broker 1 zone={zone}\n")),
        Ok(Request::Transfer { dest, name }) => match handle_transfer(s, &dest, &name, &fds) {
            Ok((final_name, bytes)) => {
                eprintln!("kryptikd[zone {zone}]: transfer: {name} ({bytes} bytes) -> {dest} as incoming/{final_name}");
                reply(fd, &format!("ok {final_name}\n"));
            }
            Err(why) => reply(fd, &format!("error: {why}\n")),
        },
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
                close_fds(&fds);
                reply(fd, &format!("error: payload: {e}\n"));
                return Ok(Some(verb));
            }
            if rest.len() < len {
                close_fds(&fds);
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
    close_fds(&fds);
    Ok(Some(verb))
}

/// The first recv of a request, which is where a descriptor arrives: one
/// recvmsg with room for a few SCM_RIGHTS entries. Every descriptor received
/// is CLOEXEC and handed back; the caller closes what it does not use.
/// Ok(false, ..) at EOF.
fn recv_first(fd: RawFd, buf: &mut Vec<u8>, started: Instant) -> io::Result<(bool, Vec<RawFd>)> {
    let mut chunk = [0u8; 4096];
    let mut cbuf = [0u8; 64];
    loop {
        if started.elapsed() > REQUEST_DEADLINE {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "request took longer than the deadline"));
        }
        let mut iov = libc::iovec { iov_base: chunk.as_mut_ptr() as *mut libc::c_void, iov_len: chunk.len() };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cbuf.len() as _;
        let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) | Some(libc::EAGAIN) => continue,
                _ => return Err(e),
            }
        }
        let mut fds = Vec::new();
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                    let data = libc::CMSG_DATA(c) as *const RawFd;
                    let bytes = (*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                    for i in 0..bytes / std::mem::size_of::<RawFd>() {
                        fds.push(std::ptr::read_unaligned(data.add(i)));
                    }
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
        }
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            for f in &fds {
                unsafe { libc::close(*f) };
            }
            return Err(io::Error::new(io::ErrorKind::InvalidData, "too many descriptors attached"));
        }
        if n == 0 {
            return Ok((false, fds));
        }
        buf.extend_from_slice(&chunk[..n as usize]);
        return Ok((true, fds));
    }
}

/// Read until the buffer holds at least `want` bytes, within the deadline.
/// EOF ends the read early; the caller sees the short count.
fn read_more(fd: RawFd, buf: &mut Vec<u8>, want: usize, started: Instant) -> io::Result<()> {
    while buf.len() < want {
        if !recv_some(fd, buf, started)? {
            break;
        }
    }
    Ok(())
}

/// One recv into `buf`. Ok(false) at EOF. SO_RCVTIMEO ticks (EAGAIN) are
/// retried until the request deadline, which is the bound that matters.
fn recv_some(fd: RawFd, buf: &mut Vec<u8>, started: Instant) -> io::Result<bool> {
    let mut chunk = [0u8; 4096];
    loop {
        if started.elapsed() > REQUEST_DEADLINE {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "request took longer than the deadline"));
        }
        let n = unsafe { libc::recv(fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len(), 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) | Some(libc::EAGAIN) => continue,
                _ => return Err(e),
            }
        }
        if n == 0 {
            return Ok(false);
        }
        buf.extend_from_slice(&chunk[..n as usize]);
        return Ok(true);
    }
}

fn reply(fd: RawFd, text: &str) {
    send_all(fd, text.as_bytes());
}

fn send_all(fd: RawFd, mut data: &[u8]) {
    while !data.is_empty() {
        let n = unsafe { libc::send(fd, data.as_ptr() as *const libc::c_void, data.len(), libc::MSG_NOSIGNAL) };
        if n <= 0 {
            return; // the peer is gone; nothing to do about it
        }
        data = &data[n as usize..];
    }
}

/// The zone's payload, if any: (mime, bytes). O_NOFOLLOW like every other
/// registry read (R-7b F1); a planted symlink is refused, not followed.
pub fn clipboard_read(entry: &Path) -> io::Result<Option<(String, Vec<u8>)>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let p = entry.join(CLIPBOARD_FILE);
    let mut f = match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&p) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut all = Vec::new();
    f.take(CLIPBOARD_MAX as u64 + 256).read_to_end(&mut all)?;
    let Some(nl) = all.iter().position(|b| *b == b'\n') else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "clipboard file has no MIME line"));
    };
    let mime = String::from_utf8_lossy(&all[..nl]).to_string();
    if !MIME_TYPES.contains(&mime.as_str()) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("clipboard file carries an unsupported MIME type {mime:?}")));
    }
    let bytes = all.split_off(nl + 1);
    if bytes.len() > CLIPBOARD_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "clipboard file is over the limit"));
    }
    Ok(Some((mime, bytes)))
}

/// Replace the zone's payload atomically: a new 0600 file created with
/// O_EXCL|O_NOFOLLOW, then renamed over `clipboard` (rename replaces a
/// planted symlink rather than following it). A failure leaves no partial
/// file and the previous payload untouched.
pub fn clipboard_write(entry: &Path, mime: &str, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if !MIME_TYPES.contains(&mime) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unsupported MIME type {mime:?}")));
    }
    if bytes.len() > CLIPBOARD_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "payload over the clipboard limit"));
    }
    let tmp = entry.join(format!(".{CLIPBOARD_FILE}.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let r = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(mime.as_bytes())?;
        f.write_all(b"\n")?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, entry.join(CLIPBOARD_FILE))
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

/// The zone 0 gesture: give `to` a copy of `from`'s payload. Both are
/// registry entry directories; the caller has checked both zones are
/// running. Returns what moved.
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

    fn zones() -> Vec<Zone> {
        let mk = |name: &str, base: Option<u32>, colour: &str| {
            let ident = base.map(|b| format!("[identity]\nuid_base = {b}\n")).unwrap_or_default();
            Zone::from_str(&format!(
                "[zone]\nname = \"{name}\"\n[network]\nmode = \"routed\"\n\
                 [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n{ident}[ui]\nborder_color = \"{colour}\"\n"
            ))
            .unwrap()
        };
        vec![
            mk("work", Some(131072), "#111111"),
            mk("personal", Some(196608), "#222222"),
            mk("legacy", None, "#333333"),
        ]
    }

    #[test]
    fn a_uid_maps_to_exactly_the_zone_whose_range_holds_it() {
        let zs = zones();
        assert_eq!(zone_for_uid(&zs, 131072).map(|z| z.name.as_str()), Some("work"));
        assert_eq!(zone_for_uid(&zs, 131072 + 65534).map(|z| z.name.as_str()), Some("work"));
        assert_eq!(zone_for_uid(&zs, 131072 + 65535).map(|z| z.name.as_str()), Some("work"));
        assert_eq!(zone_for_uid(&zs, 196608).map(|z| z.name.as_str()), Some("personal"));
        // Host users, root, and the range just past the last zone match nothing.
        for uid in [0u32, 1000, 131071, 196608 + 65536, u32::MAX] {
            assert!(zone_for_uid(&zs, uid).is_none(), "uid {uid} must not identify a zone");
        }
    }

    #[test]
    fn a_socketpair_peer_is_this_process_and_identifies_by_uid() {
        let mut sv = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) }, 0);
        let cred = peer_identity(sv[0]).unwrap();
        assert_eq!(cred.uid, unsafe { libc::geteuid() });
        assert_eq!(cred.gid, unsafe { libc::getegid() });
        // Our own uid is a host user, not a zone: identify refuses, naming the uid.
        let err = identify(&zones(), sv[0]).unwrap_err();
        assert!(err.contains("not in any zone"), "{err}");
        unsafe {
            libc::close(sv[0]);
            libc::close(sv[1]);
        }
    }

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

    /// One request against a fresh socketpair: the client side is written
    /// first (the socket buffers it), the server answers, and the client
    /// reads the whole reply. Returns (verb the server reported, reply).
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
        }
    }

    #[test]
    fn a_zone_sets_and_gets_its_own_clipboard_through_its_broker() {
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
    fn every_refusal_happens_before_a_payload_is_read_and_leaves_the_clipboard_alone() {
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
        // Through all of that the payload set first is still there, intact.
        assert_eq!(ask(&sv, "clipboard-get\n", false).1, b"ok text/plain 5\nhello");
        let left: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left, vec![std::ffi::OsString::from(CLIPBOARD_FILE)], "no temp files left behind");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_peer_that_is_not_the_zone_is_refused_without_information() {
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
    fn the_zone_zero_move_copies_and_leaves_the_source() {
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

    // ---- transfer -----------------------------------------------------------

    struct Lab {
        dir: std::path::PathBuf,
        zones: std::path::PathBuf,
        root: std::path::PathBuf,
        sender: Zone,
        dev: u64,
    }

    /// A zone directory (a = the sender, b and c = plain zones, n = the nic
    /// zone), a destination "root" with homes for b and c, and the sender's
    /// data mount = the lab directory's filesystem.
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
            "[zone]\nname = \"n\"\n[network]\nmode = \"nic\"\nbridge = \"kryptik0\"\n\
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
            Ok(Target { root_fd: fd, home_rel: format!("home/{dest}"), uid: unsafe { libc::geteuid() }, gid: unsafe { libc::getegid() } })
        }
    }

    /// How many of this process's descriptors point at `p`. Tests run in
    /// parallel threads, so a global descriptor count is noise; a count of
    /// links to one specific file is not.
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
    fn a_transfer_lands_in_the_destination_incoming_and_nowhere_else() {
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
        };
        let file = lab.dir.join("report.pdf");
        std::fs::write(&file, b"hello transfer").unwrap();
        let src = open_flags(&file, libc::O_RDONLY);
        let (verb, r) = ask_with(&sv, "transfer b report.pdf\n", &[src], false);
        unsafe { libc::close(src) };
        assert_eq!(verb.as_deref(), Some("transfer"));
        assert_eq!(String::from_utf8_lossy(&r), "ok report.pdf\n");
        // SCM_RIGHTS duplicated the descriptor into the server, which must
        // have closed its copy: with the sender's own copy closed, nothing
        // in this process points at the file any more.
        assert_eq!(fds_pointing_at(&file), 0, "the broker leaked a descriptor");
        let incoming = lab.root.join("home/b/incoming");
        assert_eq!(std::fs::read(incoming.join("report.pdf")).unwrap(), b"hello transfer");
        assert_eq!(std::fs::metadata(incoming.join("report.pdf")).unwrap().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&incoming).unwrap().mode() & 0o777, 0o700);
        // The same name again: O_EXCL picks -2. (A fresh descriptor: the
        // zone opens the file anew for every transfer, as the copy consumed
        // this one's offset.)
        let src2 = open_flags(&file, libc::O_RDONLY);
        assert_eq!(ask_with(&sv, "transfer b report.pdf\n", &[src2], false).1, b"ok report.pdf-2\n");
        unsafe { libc::close(src2) };
        assert_eq!(std::fs::read(incoming.join("report.pdf-2")).unwrap(), b"hello transfer");
        // B7: the destination planted a symlink where the next name would
        // land. O_EXCL reports it as existing, the copy moves on to -4, and
        // the symlink's target is untouched.
        let victim = lab.dir.join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        std::os::unix::fs::symlink(&victim, incoming.join("report.pdf-3")).unwrap();
        let src3 = open_flags(&file, libc::O_RDONLY);
        assert_eq!(ask_with(&sv, "transfer b report.pdf\n", &[src3], false).1, b"ok report.pdf-4\n");
        unsafe { libc::close(src3) };
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        // B7, the other way: `incoming` itself replaced by a symlink to a
        // directory elsewhere. Resolution refuses to follow it; nothing lands.
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

    #[test]
    fn every_transfer_refusal_is_specific_and_happens_before_any_copy() {
        use std::os::unix::fs::MetadataExt;
        let lab = lab("refuse", "b n");
        let entry_dir = lab.dir.join("entry");
        std::fs::create_dir_all(&entry_dir).unwrap();
        let resolve = resolver(lab.root.clone());
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
        // Every refusal closed what it was handed: with the senders' own
        // copies closed above, nothing in this process points at the lab's
        // files any more. (Checked after the loop: the cases open all their
        // descriptors up front.)
        let left = fds_pointing_at(&file) + fds_pointing_at(&lab.dir) + fds_pointing_at(&big);
        assert_eq!(left, 0, "a refusal leaked a descriptor in the broker");
        // B5: a file on another filesystem than the zone's data mount.
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
        // Consent, and an unknown data mount, each refuse on their own.
        // The environment is the process's: consent's own tests set the
        // same variable, so this section takes their lock.
        sv.auto_approve = false;
        {
            let _env = crate::consent::ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            std::env::set_var("KRYPTIK_CONSENT_DIR", "/nonexistent/kryptik-consent");
            let (_, r) = ask_with(&sv, "transfer b f.txt\n", &[ro()], false);
            assert!(String::from_utf8_lossy(&r).contains("no consent channel"), "{}", String::from_utf8_lossy(&r));
            std::env::remove_var("KRYPTIK_CONSENT_DIR");
        }
        sv.auto_approve = true;
        sv.home_dev = &dev_unknown;
        let (_, r) = ask_with(&sv, "transfer b f.txt\n", &[ro()], false);
        assert!(String::from_utf8_lossy(&r).contains("data mount is unknown"), "{}", String::from_utf8_lossy(&r));
        // Through all of that nothing was created on the destination side.
        assert!(!lab.root.join("home/b/incoming").exists());
        let _ = std::fs::remove_dir_all(&lab.dir);
    }

    #[test]
    fn the_copy_stops_at_the_cap_even_when_the_size_on_paper_was_fine() {
        let dir = entry("cap");
        let src_p = dir.join("src");
        std::fs::write(&src_p, vec![b'y'; 20]).unwrap();
        let out_p = dir.join("out");
        let src = open_flags(&src_p, libc::O_RDONLY);
        let out = open_flags(&out_p, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC);
        let e = copy_capped(src, out, 10).unwrap_err();
        assert!(e.contains("grew past the 10-byte limit"), "{e}");
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
    fn parse_request_covers_the_wire_format() {
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
    }

    #[test]
    fn a_zone_with_no_identity_can_never_be_identified() {
        // "legacy" has no uid_base: nothing maps to it, so the broker can
        // never attribute a request to it - which is the point of P3.
        let zs = zones();
        for uid in 0..300_000u32 {
            if let Some(z) = zone_for_uid(&zs, uid) {
                assert_ne!(z.name, "legacy");
            }
        }
    }
}
