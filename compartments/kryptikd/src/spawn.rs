//! Zone spawning: create a zone and run a command inside it.
//!
//!   kryptikd (parent)   waits; forwards SIGINT/TERM/HUP/QUIT down
//!    └─ intermediate    unshares the namespaces, becomes zone root, forks
//!       │               pid 1, forwards signals to it, and SIGKILLs it if
//!       │               it ignores them for GRACE_SECS
//!       └─ zone pid 1   pivots, confines itself, execs the command
//!
//! Every link carries PR_SET_PDEATHSIG(SIGKILL): if kryptikd dies, so does the
//! intermediate, then pid 1, and the kernel kills the rest of the pid namespace.

use std::ffi::CString;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use crate::broker;
use crate::caps;
use crate::cgroup;
use crate::isolate;
use crate::registry;
use crate::landlock;
use crate::netzone;
use crate::policy;
use crate::rootfs;
use crate::seccomp;
use crate::volume;
use crate::zone::{StorageMode, Zone};

#[derive(Debug)]
pub enum SpawnError {
    Syscall { call: &'static str, errno: i32 },
    Setup(String),
    Confine(String),
}

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpawnError::Syscall { call, errno } => {
                write!(f, "{call}: {}", io::Error::from_raw_os_error(*errno))
            }
            SpawnError::Setup(m) => write!(f, "{m}"),
            SpawnError::Confine(m) => write!(f, "confinement failed: {m}"),
        }
    }
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Options from the command line that change how the zone is launched.
#[derive(Debug, Default, Clone)]
pub struct RunOptions {
    /// Host uid/gid the zone's root maps to; accepted only when kryptikd runs as root.
    pub zone_uid: Option<u32>,
    pub zone_gid: Option<u32>,
    /// The zone directory, against which `[policy]` paths resolve.
    pub zones_dir: std::path::PathBuf,
    /// Wi-Fi credentials directory (wifi.rs); empty means the default. Only a
    /// nic zone gets its wpa_supplicant.conf, read-only at /etc/wpa_supplicant.conf.
    pub wifi_dir: std::path::PathBuf,
    /// Development only: approve every transfer this zone offers, unprompted.
    pub auto_approve_transfers: bool,
    /// An encrypted zone's passphrase, from a 0600 file (tests, root at a
    /// terminal). A passphrase is never read from argv or the environment.
    pub passphrase_file: Option<std::path::PathBuf>,
    /// Or from an inherited descriptor: what the trusted prompt collected.
    pub passphrase_fd: Option<i32>,
    /// The zone's Wayland proxy socket, bound at /run/kryptik/wayland-0; None: no display.
    pub wayland_socket: Option<std::path::PathBuf>,
    /// The inode the launch daemon verified; any other at that path is refused.
    pub wayland_inode: Option<crate::serve::InodeId>,
    /// The launch daemon's readiness pipe (serve.rs): gets `ready` and is closed
    /// once the zone's pid 1 exists; EOF before that means the launch failed.
    pub ready_fd: Option<i32>,
}

/// The Wayland proxy socket bind-mounted at `<entry>/wayland-0` in the host
/// mount namespace, for the child to open after unshare (see run_in_zone).
/// Drop detaches the bind and removes the mountpoint.
struct StagedSocket {
    path: std::path::PathBuf,
}

impl StagedSocket {
    fn stage(
        session_path: &std::path::Path,
        inode: Option<crate::serve::InodeId>,
        entry_dir: &std::path::Path,
        zone: &str,
    ) -> Result<Self, SpawnError> {
        use std::os::unix::fs::OpenOptionsExt;

        /* Host root can walk the session's private directories. Only the inode
         * the daemon verified is accepted, so a rename since its check fails. */
        let fd = crate::serve::open_nofollow(session_path, true)
            .map_err(|e| SpawnError::Setup(format!("wayland socket {e}")))?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
            return Err(SpawnError::Syscall { call: "fstat(wayland socket)", errno: errno() });
        }
        if let Some(want) = inode {
            if !want.matches(&st) {
                return Err(SpawnError::Setup(format!(
                    "wayland socket {} is not the socket the launch daemon verified (inode changed)",
                    session_path.display()
                )));
            }
        }

        let path = entry_dir.join(rootfs::WAYLAND_SOCKET_NAME);
        let cpath = CString::new(path.display().to_string())
            .map_err(|_| SpawnError::Setup("registry path contains a NUL".into()))?;
        /* Detach every bind a dead launcher left (each umount takes only the
         * topmost), then create the mountpoint new, so nothing planted is reused. */
        while unsafe { libc::umount2(cpath.as_ptr(), libc::MNT_DETACH) } == 0 {}
        let _ = std::fs::remove_file(&path);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| SpawnError::Setup(format!("{}: {e}", path.display())))?;
        let src = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
        if unsafe { libc::mount(src.as_ptr(), cpath.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) } < 0 {
            let e = errno();
            let _ = std::fs::remove_file(&path);
            return Err(SpawnError::Setup(format!(
                "staging the wayland socket of zone {zone:?} at {}: {}",
                path.display(),
                io::Error::from_raw_os_error(e)
            )));
        }
        // The mount holds its own reference to the inode.
        drop(fd);
        Ok(StagedSocket { path })
    }
}

impl Drop for StagedSocket {
    fn drop(&mut self) {
        if let Ok(c) = CString::new(self.path.display().to_string()) {
            while unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) } == 0 {}
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Seconds after a forwarded signal before pid 1 is SIGKILLed, and its pid namespace with it.
pub const GRACE_SECS: u32 = 5;

// --- signal forwarding ------------------------------------------------------
/* The parent and the intermediate each run this with their own statics:
 * FORWARD_TO is the target; ARM_KILL (the intermediate, for pid 1) also arms
 * the SIGKILL alarm. The handlers are async-signal-safe. */

static FORWARD_TO: AtomicI32 = AtomicI32::new(0);
static ARM_KILL: AtomicBool = AtomicBool::new(false);

extern "C" fn forward_signal(sig: libc::c_int) {
    let pid = FORWARD_TO.load(Ordering::SeqCst);
    if pid > 0 {
        unsafe {
            libc::kill(pid, sig);
            if ARM_KILL.load(Ordering::SeqCst) {
                libc::alarm(GRACE_SECS);
            }
        }
    }
}

extern "C" fn on_alarm(_sig: libc::c_int) {
    let pid = FORWARD_TO.load(Ordering::SeqCst);
    if pid > 0 {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

fn install_handler(sig: libc::c_int, handler: extern "C" fn(libc::c_int)) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as usize;
        // Interrupted waits restart (and retry on EINTR anyway).
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

fn install_forwarding(target: libc::pid_t, arm_kill: bool) {
    FORWARD_TO.store(target, Ordering::SeqCst);
    ARM_KILL.store(arm_kill, Ordering::SeqCst);
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        install_handler(sig, forward_signal);
    }
    if arm_kill {
        install_handler(libc::SIGALRM, on_alarm);
    }
}

/// One log line in a single write(2), which another writer on the descriptor
/// cannot split (a pipe write under PIPE_BUF is atomic; `eprintln!` writes in
/// pieces). Raw fd 2: `io::stderr()`'s lock can be inherited held across fork.
pub(crate) fn log_line(line: &str) {
    let mut bytes = Vec::with_capacity(line.len() + 1);
    bytes.extend_from_slice(line.as_bytes());
    bytes.push(b'\n');
    let mut off = 0;
    while off < bytes.len() {
        let n = unsafe { libc::write(2, bytes[off..].as_ptr() as *const libc::c_void, bytes.len() - off) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return;
        }
        off += n as usize;
    }
}

/// Most zone output one launch logs (the rest is read and dropped, so an endless
/// writer neither blocks nor fills the state partition), and the longest line.
const ZONE_OUTPUT_MAX: usize = 1 << 20;
const ZONE_LINE_MAX: usize = 1024;

/// Relays a daemon-launched zone's output into the launcher's log. The zone
/// gets a pipe, never the log: O_APPEND does not stop ftruncate or fallocate.
/// Lines are marked as the zone's, control bytes replaced, the total bounded.
struct ZoneOutput {
    fd: RawFd,
    mark: String,
    line: Vec<u8>,
    left: usize,
}

impl ZoneOutput {
    fn new(fd: RawFd, zone: &str) -> Self {
        ZoneOutput { fd, mark: format!("zone {zone}| "), line: Vec::new(), left: ZONE_OUTPUT_MAX }
    }

    fn flush(&mut self, emit: &mut dyn FnMut(&str)) {
        if !self.line.is_empty() {
            emit(&format!("{}{}", self.mark, String::from_utf8_lossy(&self.line)));
            self.line.clear();
        }
    }

    fn take(&mut self, data: &[u8], emit: &mut dyn FnMut(&str)) {
        for &b in data {
            if self.left == 0 {
                return;
            }
            self.left -= 1;
            match b {
                b'\n' => self.flush(emit),
                b'\t' | 0x20..=0x7e | 0x80..=0xff => self.line.push(b),
                _ => self.line.push(b'?'),
            }
            if self.line.len() >= ZONE_LINE_MAX {
                self.flush(emit);
            }
            if self.left == 0 {
                self.flush(emit);
                emit(&format!("{}(output past {ZONE_OUTPUT_MAX} bytes is not logged)", self.mark));
            }
        }
    }

    /// Read at most `reads` 4 KiB pieces; false once every writer has gone.
    /// Bounded, so a zone that never stops writing cannot hold the launcher here.
    fn pump_at_most(&mut self, reads: usize, emit: &mut dyn FnMut(&str)) -> bool {
        let mut buf = [0u8; 4096];
        let mut done = 0;
        while done < reads {
            let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n > 0 {
                self.take(&buf[..n as usize], emit);
                done += 1;
            } else if n == 0 {
                return false;
            } else if errno() != libc::EINTR {
                return true; // EAGAIN: nothing more for now
            }
        }
        true
    }

    fn pump(&mut self, emit: &mut dyn FnMut(&str)) -> bool {
        self.pump_at_most(ZONE_READS_PER_PUMP, emit)
    }
}

/// A pass of the relay reads at most this many pieces (64 KiB).
const ZONE_READS_PER_PUMP: usize = 16;

/// Relays what is left in the pipe, up to the log's bound.
impl Drop for ZoneOutput {
    fn drop(&mut self) {
        let mut emit = |line: &str| log_line(line);
        self.pump_at_most(ZONE_OUTPUT_MAX / 4096 + 1, &mut emit);
        self.flush(&mut emit);
        unsafe { libc::close(self.fd) };
    }
}

/// Whether the child has exited, without reaping it: WNOWAIT leaves it for
/// the waitpid that decides the launcher's status.
fn exited_unreaped(pid: libc::pid_t) -> bool {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) };
    r == 0 && unsafe { info.si_pid() } != 0
}

/// Serve the zone's broker socket and relay its output until the child exits.
/// Forwarded signals interrupt the poll, which just loops.
fn serve_until_exit(pid: libc::pid_t, listen_fd: RawFd, s: &broker::Served, out: Option<ZoneOutput>) -> Result<libc::c_int, SpawnError> {
    let zone = s.zone.name.as_str();
    let out = std::cell::RefCell::new(out);
    let pump = || {
        let mut o = out.borrow_mut();
        if o.as_mut().is_some_and(|o| !o.pump(&mut |line: &str| log_line(line))) {
            *o = None; // every writer has gone
        }
    };
    /* While a consent question is open the broker calls this ten times a
     * second: output keeps flowing, and a zone that has exited withdraws its
     * question. The child is only looked at; the loop below reaps it. */
    let asking = || {
        pump();
        !exited_unreaped(pid)
    };
    let s = &broker::Served { asking: &asking, ..*s };
    /* A pidfd is readable once the zone has ended, so the poll needs no
     * timeout. Without one it wakes every 200 ms: failing here would skip
     * the caller's closing of the zone's volume. */
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as RawFd;
    let _pidfd = (pidfd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(pidfd) });
    let timeout = if pidfd >= 0 { -1 } else { 200 };
    loop {
        let mut status: libc::c_int = 0;
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r == pid {
            return Ok(status); // dropping `out` relays what is left in the pipe
        }
        if r < 0 && errno() != libc::EINTR {
            return Err(SpawnError::Syscall { call: "waitpid", errno: errno() });
        }
        let mut pfds = [
            libc::pollfd { fd: listen_fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: out.borrow().as_ref().map_or(-1, |o| o.fd), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: pidfd, events: libc::POLLIN, revents: 0 },
        ];
        let n = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, timeout) };
        if n > 0 && pfds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            pump();
        }
        let pfd = pfds[0];
        if n > 0 && pfd.revents & libc::POLLIN != 0 {
            match broker::serve_one(listen_fd, s) {
                Ok(Some(verb)) => log_line(&format!("kryptikd[zone {zone}]: broker served {verb:?}")),
                Ok(None) => {}
                Err(e) => log_line(&format!("kryptikd[zone {zone}]: broker: {e}")),
            }
        }
    }
}

/// waitpid that survives EINTR.
fn wait_for(pid: libc::pid_t) -> Result<libc::c_int, SpawnError> {
    loop {
        let mut status: libc::c_int = 0;
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            return Ok(status);
        }
        if r < 0 && errno() == libc::EINTR {
            continue;
        }
        return Err(SpawnError::Syscall { call: "waitpid", errno: errno() });
    }
}

/// A pipe ordering the parent and the intermediate. The launch handshake:
///
///   parent --placed-->  child   in its cgroup, if any: may unshare
///   child  --ready-->   parent  unshared: the id maps may be written
///   parent --mapped-->  child   maps written: may become root
///   child  --initpid--> parent  the zone's pid 1, as the host sees it
///
/// `wait` tells a signal from the peer's death (EOF).
struct SyncPipe {
    read: RawFd,
    write: RawFd,
}

impl SyncPipe {
    fn new() -> Result<Self, SpawnError> {
        let mut fds = [0 as RawFd; 2];
        // CLOEXEC, in case the zone's descriptor sweep were ever skipped.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(SpawnError::Syscall { call: "pipe2", errno: errno() });
        }
        Ok(SyncPipe { read: fds[0], write: fds[1] })
    }

    fn signal(&self) {
        self.signal_byte(1)
    }

    /// Like `signal`, with a value (on `mapped`: whether a network path was built).
    fn signal_byte(&self, v: u8) {
        let b = [v];
        loop {
            let r = unsafe { libc::write(self.write, b.as_ptr() as *const libc::c_void, 1) };
            if r < 0 && errno() == libc::EINTR {
                continue;
            }
            // EPIPE means the peer is gone; nothing to do about it here.
            return;
        }
    }

    fn wait(&self) -> Result<(), SpawnError> {
        self.wait_byte().map(|_| ())
    }

    fn wait_byte(&self) -> Result<u8, SpawnError> {
        let mut b = [0u8];
        loop {
            let r = unsafe { libc::read(self.read, b.as_mut_ptr() as *mut libc::c_void, 1) };
            if r == 1 {
                return Ok(b[0]);
            }
            if r == 0 {
                return Err(SpawnError::Setup("peer exited before signalling".into()));
            }
            if errno() == libc::EINTR {
                continue;
            }
            return Err(SpawnError::Syscall { call: "read(sync pipe)", errno: errno() });
        }
    }

    /// Send a pid, 4 bytes in native order (both ends are the same binary).
    fn write_i32(&self, v: i32) {
        let b = v.to_ne_bytes();
        let mut off = 0usize;
        while off < 4 {
            let r = unsafe {
                libc::write(self.write, b[off..].as_ptr() as *const libc::c_void, 4 - off)
            };
            if r > 0 {
                off += r as usize;
            } else if r < 0 && errno() == libc::EINTR {
                continue;
            } else {
                return; // peer gone; the parent will see EOF and say so
            }
        }
    }

    /// Read a pid; None if the sender died first (the caller reports why).
    fn read_i32(&self) -> Option<i32> {
        let mut b = [0u8; 4];
        let mut off = 0usize;
        while off < 4 {
            let r = unsafe {
                libc::read(self.read, b[off..].as_mut_ptr() as *mut libc::c_void, 4 - off)
            };
            if r > 0 {
                off += r as usize;
            } else if r < 0 && errno() == libc::EINTR {
                continue;
            } else {
                return None;
            }
        }
        Some(i32::from_ne_bytes(b))
    }

    fn close_read(&self) { unsafe { libc::close(self.read) }; }
    fn close_write(&self) { unsafe { libc::close(self.write) }; }
}

/// Where a zone's persistent directory lives on the host.
pub fn zone_rootfs(zone: &Zone, base: &str) -> String {
    format!("{base}/{}", zone.name)
}

/// Which host identity the zone's root maps to.
#[derive(Debug)]
struct Identity {
    uid: u32,
    gid: u32,
    /// kryptikd runs as root; the id maps it writes put the zone at `uid`/`gid`.
    privileged: bool,
}

fn launch_identity(opts: &RunOptions, zone: &Zone) -> Result<Identity, SpawnError> {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        // A declared range owns the zone's data for life; an override would silently change that.
        if let Some(base) = zone.uid_base {
            if opts.zone_uid.is_some() || opts.zone_gid.is_some() {
                return Err(SpawnError::Setup(format!(
                    "zone {:?} declares [identity] uid_base = {base}; --zone-uid/--zone-gid \
                     are not accepted for a zone with a declared identity",
                    zone.name
                )));
            }
            return Ok(Identity { uid: base, gid: base, privileged: true });
        }
        match (opts.zone_uid, opts.zone_gid) {
            (Some(uid), Some(gid)) if uid != 0 && gid != 0 => Ok(Identity { uid, gid, privileged: true }),
            _ => Err(SpawnError::Setup(format!(
                "kryptikd is running as root and zone {:?} declares no [identity]. \
                 Mapping the zone's root to host uid 0 would make every permission \
                 check inside the zone succeed as the real superuser on everything the \
                 zone can reach. Add `[identity] uid_base = N` to the zone file (a \
                 multiple of 65536, at least 131072), or pass --zone-uid UID --zone-gid \
                 GID (both non-zero), or run kryptikd unprivileged.",
                zone.name
            ))),
        }
    } else {
        if opts.zone_uid.is_some() || opts.zone_gid.is_some() {
            return Err(SpawnError::Setup(
                "--zone-uid/--zone-gid need root: an unprivileged kryptikd can only \
                 map the zone to its own uid and gid"
                    .into(),
            ));
        }
        Ok(Identity {
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            privileged: false,
        })
    }
}

/// Create the zone and run `argv` inside it; returns the command's exit code.
/// Also runs unprivileged (as the tests do) where user namespaces are allowed.
pub fn run_in_zone(
    zone: &Zone,
    rootfs: &str,
    argv: &[String],
    opts: &RunOptions,
) -> Result<i32, SpawnError> {
    if argv.is_empty() {
        return Err(SpawnError::Setup("no command given".into()));
    }

    /* Landlock is required, at MIN_ABI or newer: without it a zone could read
     * every other zone, and an older ABI enforces less than the policy says. */
    match landlock::abi_version() {
        None => {
            return Err(SpawnError::Confine(
                "landlock unavailable on this kernel; refusing to start an unconfined zone".into(),
            ))
        }
        Some(abi) if abi < landlock::MIN_ABI => {
            return Err(SpawnError::Confine(
                landlock::LandlockError::TooOld { abi, need: landlock::MIN_ABI }.to_string(),
            ))
        }
        Some(_) => {}
    }

    if zone.storage == StorageMode::Ephemeral {
        eprintln!(
            "kryptikd: zone {:?}: ephemeral storage is a tmpfs freed on exit; its pages \
             can reach swap, so this is not secure erasure",
            zone.name
        );
    }

    if zone.storage == StorageMode::Persistent {
        eprintln!(
            "kryptikd: zone {:?}: persistent storage is a PLAIN DIRECTORY on the host \
             filesystem - kept between launches, and NOT encrypted at rest",
            zone.name
        );
    }

    if opts.auto_approve_transfers {
        eprintln!(
            "kryptikd: WARNING: --auto-approve-transfers: every file zone {:?} offers to another \
             zone is approved without a prompt (development flag; the prompt is desktop work)",
            zone.name
        );
    }

    /* KRYPTIK_EXPERIMENTAL=1 starts a zone without guarantees this build cannot
     * give. Environment only, never a config setting, so it is always a
     * conscious act. A root launch on a kernel that restricts unprivileged user
     * namespaces ignores it (docs/design/privileged-launch.md). */
    let mut experimental = std::env::var("KRYPTIK_EXPERIMENTAL").as_deref() == Ok("1");
    if experimental && unsafe { libc::geteuid() } == 0 {
        if let Some((true, knob)) = isolate::userns_restriction_sysctl() {
            eprintln!(
                "kryptikd: KRYPTIK_EXPERIMENTAL is ignored for a root launch on a kernel that \
                 restricts unprivileged user namespaces ({knob})"
            );
            experimental = false;
        }
    }
    let mut unsupported: Vec<String> = Vec::new();
    match zone.storage {
        /* Only a root launch can open the LUKS2 volume. Refused outright, not
         * waivable by KRYPTIK_EXPERIMENTAL, which would run the zone on a plain
         * directory. */
        StorageMode::Encrypted if unsafe { libc::geteuid() } != 0 => {
            return Err(SpawnError::Setup(format!(
                "zone {:?} is encrypted: its LUKS2 volume is opened by a root launch with the \
                 passphrase from the trusted prompt (kryptik-launch) or --passphrase-file; an \
                 unprivileged launch cannot open it (cryptsetup, dm-crypt, loop devices) and \
                 will not run the zone on a plain directory instead. KRYPTIK_EXPERIMENTAL does \
                 not change this.",
                zone.name
            )));
        }
        StorageMode::Encrypted => {}
        /* A per-launch tmpfs; the persistent directory is never bound
         * (docs/design/resource-limits-and-ephemeral-zones.md). */
        StorageMode::Ephemeral => {}
        // The zone's own directory, bound at $HOME and kept between launches.
        StorageMode::Persistent => {}
    }
    /* A Landlock policy file narrows the base rules (docs/design/zone-policy-files.md).
     * Parsed here: the zone cannot reach the zone directory once it has pivoted,
     * and a bad file must stop the launch before anything is built. */
    let fs_rules: Vec<landlock::ZoneRule> = match &zone.landlock {
        None => Vec::new(),
        Some(rel) => {
            let path = policy::resolve(&opts.zones_dir, rel);
            let text = std::fs::read_to_string(&path).map_err(|e| {
                SpawnError::Setup(format!("zone {:?} landlock policy {}: {e}", zone.name, path.display()))
            })?;
            landlock::parse_policy(&text, &path.display().to_string())
                .map_err(|e| SpawnError::Setup(format!("zone {:?} landlock policy: {e}", zone.name)))?
        }
    };
    /* A new network namespace must hold only loopback, but with tunnel drivers
     * built in (SIT is) the kernel adds fallback devices such as sit0 unless
     * net.core.fb_tunnels_only_for_init_net is set, which needs root. */
    if isolate::namespace_flags(zone) & libc::CLONE_NEWNET != 0 {
        match netzone::suppress_fallback_tunnels() {
            Ok(Some(note)) => eprintln!("kryptikd: {note}"),
            Ok(None) => {}
            Err(why) => unsupported.push(format!("[network]: {why}")),
        }
    }
    let zone_policy: Option<policy::Policy> = match &zone.seccomp {
        Some(rel) => {
            let path = policy::resolve(&opts.zones_dir, rel);
            let p = policy::load(&path)
                .map_err(|e| SpawnError::Setup(format!("zone {:?} policy: {e}", zone.name)))?;
            p.check_for_zone(zone)
                .map_err(|e| SpawnError::Setup(format!("zone {:?} policy: {e}", zone.name)))?;
            for w in &p.warnings {
                eprintln!("kryptikd: note: {w}");
            }
            Some(p)
        }
        None => None,
    };
    /* [limits] need a cgroup, and whether one can be made is found by trying,
     * not by uid: a delegated subtree is writable by a user, and root in a
     * container may find the hierarchy read-only. */
    let wants_limits = zone.memory_max.is_some() || zone.pids_max.is_some();
    let mut limits: Option<std::path::PathBuf> = None;
    if wants_limits {
        match cgroup::available() {
            Ok(base) => limits = Some(base),
            Err(e) => unsupported.push(format!(
                "[limits]: resource limits CANNOT be applied here ({e}); no cgroup \
                 would be created and the zone would run unlimited"
            )),
        }
    }
    if !unsupported.is_empty() {
        if !experimental {
            return Err(SpawnError::Setup(format!(
                "zone {:?} asks for guarantees this build does not provide:\n  - {}\n\
                 Refusing rather than implying a guarantee that does not hold.\n\
                 Set KRYPTIK_EXPERIMENTAL=1 to run it anyway, without them.",
                zone.name,
                unsupported.join("\n  - ")
            )));
        }
        for u in &unsupported {
            eprintln!("kryptikd: KRYPTIK_EXPERIMENTAL=1 - zone {:?}: {u}", zone.name);
        }
    }

    /* One instance per zone: two launchers would share a data directory, a
     * cgroup and a veth name. claim() is an atomic mkdir; a stale entry is reclaimed. */
    let entry = registry::claim(&zone.name).map_err(|e| SpawnError::Setup(e.to_string()))?;

    let id = launch_identity(opts, zone)?;
    entry
        .set_identity(id.uid, id.gid)
        .map_err(|e| SpawnError::Setup(e.to_string()))?;

    /* Mount the unlocked volume before the directory checks, so they see its
     * root (the zone identity's since `volume init`). Dropping `opened_volume`
     * closes it, so a failed launch never leaves plaintext mounted. */
    let mut opened_volume: Option<volume::Opened> = None;
    if zone.storage == StorageMode::Encrypted && id.privileged {
        let vol = zone.volume.clone().unwrap_or_else(|| volume::default_volume_path(&zone.name));
        let pass = match (&opts.passphrase_file, opts.passphrase_fd) {
            (Some(p), _) => volume::Passphrase::from_file(p).map_err(|e| SpawnError::Setup(e.to_string()))?,
            (None, Some(fd)) => volume::Passphrase::from_fd(fd).map_err(|e| SpawnError::Setup(e.to_string()))?,
            (None, None) => {
                return Err(SpawnError::Setup(format!(
                    "zone {:?} is encrypted: a passphrase is needed (--passphrase-fd N from the launch \
                     daemon, which asks in a trusted window; or --passphrase-file FILE, a 0600 \
                     root-owned file, for tests)",
                    zone.name
                )))
            }
        };
        std::fs::create_dir_all(rootfs).map_err(|e| SpawnError::Setup(format!("{rootfs}: {e}")))?;
        let o = volume::open_and_mount(&zone.name, &vol, &pass, rootfs).map_err(|e| SpawnError::Setup(e.to_string()))?;
        eprintln!("kryptikd: zone {:?}: volume {vol} unlocked and mounted at {rootfs} (nosuid,nodev)", zone.name);
        opened_volume = Some(o);
    }

    /* A new data directory is given to the zone identity. An existing one is
     * never re-owned: check_data_dir refuses one that belongs to someone else. */
    let existed = std::path::Path::new(rootfs).exists();
    std::fs::create_dir_all(rootfs)
        .map_err(|e| SpawnError::Setup(format!("{rootfs}: {e}")))?;
    if !existed && id.privileged {
        let c = CString::new(rootfs).map_err(|_| SpawnError::Setup("rootfs path contains NUL".into()))?;
        if unsafe { libc::chown(c.as_ptr(), id.uid, id.gid) } < 0 {
            return Err(SpawnError::Syscall { call: "chown(rootfs)", errno: errno() });
        }
    }
    rootfs::check_data_dir(rootfs, id.uid).map_err(|e| SpawnError::Setup(e.to_string()))?;

    // An ephemeral zone never writes here, so anything present is data the user believes gone.
    if zone.storage == StorageMode::Ephemeral {
        rootfs::check_data_dir_empty(rootfs, &zone.name)
            .map_err(|e| SpawnError::Setup(e.to_string()))?;
    }

    // The broker socket, in the registry entry; the zone sees it at /run/kryptik/broker.
    let broker_path = entry.dir().join(broker::SOCKET_NAME);
    let broker_fd = broker::listen_at(&broker_path, id.uid, id.gid)
        .map_err(|e| SpawnError::Setup(format!("broker socket {}: {e}", broker_path.display())))?;

    /* The child opens this path itself, after unshare(CLONE_NEWNS) and before it
     * takes the zone identity: the registry is root's and 0700
     * (docs/design/zone-registry.md), and a descriptor opened in another mount
     * namespace cannot be bind-mounted (EINVAL). */
    let broker_path_str = broker_path.display().to_string();

    /* After unshare(CLONE_NEWUSER) the child is host uid 0 with no capability
     * the host honours, so it cannot walk the session's 0700 runtime directory.
     * A privileged launch bind-mounts the verified socket into the registry
     * entry, which uid 0 walks by ownership. Declared after `entry`, so the bind
     * is undone before the entry is removed. A developer launch passes the path. */
    let staged: Option<StagedSocket> = match (&opts.wayland_socket, id.privileged) {
        (Some(p), true) => Some(StagedSocket::stage(p, opts.wayland_inode, entry.dir(), &zone.name)?),
        _ => None,
    };
    let wayland_path_str: Option<String> = match (&staged, &opts.wayland_socket) {
        (Some(s), _) => Some(s.path.display().to_string()),
        (None, None) => None,
        (None, Some(p)) => {
            let md = std::fs::metadata(p).map_err(|e| SpawnError::Setup(format!("wayland socket {}: {e}", p.display())))?;
            if !std::os::unix::fs::FileTypeExt::is_socket(&md.file_type()) {
                return Err(SpawnError::Setup(format!("wayland socket {} is not a socket", p.display())));
            }
            Some(p.display().to_string())
        }
    };

    // Nic zone only. Whether the file exists is decided at the bind: absent means unconfigured.
    let wifi_conf: Option<String> = if zone.network == crate::zone::NetworkMode::Nic {
        let dir = if opts.wifi_dir.as_os_str().is_empty() {
            std::path::PathBuf::from(crate::wifi::DEFAULT_DIR)
        } else {
            opts.wifi_dir.clone()
        };
        Some(crate::wifi::conf_path(&dir).display().to_string())
    } else {
        None
    };

    let placed = SyncPipe::new()?;
    let ready = SyncPipe::new()?;
    let mapped = SyncPipe::new()?;
    // Not carried on `ready`: pid 1 is forked only after the id maps exist.
    let initpid = SyncPipe::new()?;

    /* Daemon-launched, the zone's side gets a pipe relayed into our log
     * (ZoneOutput); at a terminal it keeps the terminal. */
    let mut zone_out: Option<(RawFd, RawFd)> = None;
    if opts.ready_fd.is_some() {
        let mut p = [0 as RawFd; 2];
        if unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(SpawnError::Syscall { call: "pipe2", errno: errno() });
        }
        // The read end only: a zone's stdout must block like anyone's.
        unsafe { libc::fcntl(p[0], libc::F_SETFL, libc::O_NONBLOCK) };
        zone_out = Some((p[0], p[1]));
    }

    let parent_pid = unsafe { libc::getpid() };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(SpawnError::Syscall { call: "fork", errno: errno() });
    }

    if pid == 0 {
        // --- intermediate ------------------------------------------------------
        /* Before anything on this side prints: nothing from here down holds
         * the log. dup2 clears close-on-exec on 1 and 2 only. */
        if let Some((r, w)) = zone_out {
            unsafe {
                libc::dup2(w, 1);
                libc::dup2(w, 2);
                libc::close(w);
                libc::close(r);
            }
        }
        placed.close_write();
        ready.close_read();
        mapped.close_write();
        initpid.close_read();
        // The parent answers the readiness pipe; a copy here would delay the EOF of a failed launch.
        if let Some(fd) = opts.ready_fd {
            unsafe { libc::close(fd) };
        }
        let rc = intermediate_main(
            zone, rootfs, argv, &id, parent_pid, &placed, &ready, &mapped, &initpid,
            zone_policy.as_ref(), &fs_rules, &broker_path_str, wayland_path_str.as_deref(), opts.wayland_inode,
            wifi_conf.as_deref(),
        );
        // Never return: this process must not run the parent's cleanup.
        unsafe { libc::_exit(rc) };
    }

    // --- parent --------------------------------------------------------------
    let zone_out = zone_out.map(|(r, w)| {
        unsafe { libc::close(w) };
        ZoneOutput::new(r, &zone.name)
    });
    placed.close_read();
    ready.close_write();
    mapped.close_read();
    initpid.close_write();
    install_forwarding(pid, false);

    /* Put the child in the zone's cgroup before it may unshare. Only the parent
     * writes to the cgroup filesystem; /sys/fs/cgroup is not bound into the zone.
     * The handle lives for the whole launch, so an early return cannot leak it. */
    let zone_cgroup = match &limits {
        Some(base) => {
            let cg = cgroup::Cgroup::create(base, &zone.name, parent_pid).map_err(|e| {
                SpawnError::Setup(format!(
                    "[limits]: the zone's cgroup could not be created, so \
                     limits.memory_max/limits.pids_max would not be in force: {e}"
                ))
            })?;
            cg.set_limits(zone.memory_max.as_deref(), zone.pids_max)
                .map_err(|e| SpawnError::Setup(format!("cgroup limits: {e}")))?;
            cg.attach(pid)
                .map_err(|e| SpawnError::Setup(format!("cgroup attach: {e}")))?;
            /* Lets reclaim kill a dead launcher's processes by cgroup.kill; unlike
             * a pid, a cgroup cannot be reused. A failure is logged, not fatal. */
            if let Err(e) = entry.set_cgroup(&cg.path().display().to_string()) {
                eprintln!("kryptikd: registry: could not record the cgroup of zone {}: {e}", zone.name);
            }
            Some(cg)
        }
        None => None,
    };

    // Recorded with its start time, so `stop` signals this process and no other.
    entry
        .set_launcher(parent_pid)
        .map_err(|e| SpawnError::Setup(format!("registry: {e}")))?;

    placed.signal();
    placed.close_write();

    // Maps written before the child has unshared fail (EPERM). On EOF the child has said why.
    if ready.wait().is_err() {
        let status = wait_for(pid)?;
        return Err(SpawnError::Setup(format!(
            "zone {:?} exited during setup (code {})",
            zone.name,
            decode_status(status)
        )));
    }

    /* A root launch plumbs the new, still idle network namespace from outside
     * (netzone.rs). A routed zone that fails to attach starts with loopback
     * only; a nic zone that fails is stopped, not left half-configured. */
    let mut plumbed = false;
    if id.privileged && zone.network != crate::zone::NetworkMode::None {
        match crate::netlink::open_netns_of(pid) {
            Ok(ns) => {
                let r = match zone.network {
                    crate::zone::NetworkMode::Nic => netzone::plumb_nic_zone(zone, ns, &opts.zones_dir),
                    crate::zone::NetworkMode::Routed => netzone::plumb_routed_zone(zone, ns, &opts.zones_dir, id.gid),
                    crate::zone::NetworkMode::None => Ok(()),
                };
                unsafe { libc::close(ns) };
                match (r, zone.network) {
                    (Ok(()), _) => plumbed = true,
                    (Err(e), crate::zone::NetworkMode::Nic) => {
                        mapped.close_write();
                        let _ = wait_for(pid);
                        return Err(SpawnError::Setup(format!("nic zone network: {e}")));
                    }
                    (Err(e), _) => eprintln!(
                        "kryptikd: zone {:?} has no network path: {e}",
                        zone.name
                    ),
                }
            }
            Err(e) => eprintln!("kryptikd: zone {:?}: cannot open its netns: {e}", zone.name),
        }
    }

    // Map the child's root to the zone identity: this is the privilege drop.
    if let Err(e) = isolate::write_id_maps(pid, id.uid, id.gid, id.privileged) {
        // Close our end so the child reads EOF and dies rather than blocking.
        mapped.close_write();
        let _ = wait_for(pid);
        return Err(SpawnError::Setup(format!("id maps: {e}")));
    }

    // 1 = mapped; 2 = mapped and a network path was built.
    mapped.signal_byte(if plumbed { 2 } else { 1 });
    mapped.close_write();

    // EOF means setup failed, which is reported below.
    let init_pid = initpid.read_i32();
    if let Some(zp) = init_pid {
        // Unrecorded, every transfer into the zone would say "still starting" with no reason.
        if let Err(e) = entry.set_init(zp) {
            eprintln!("kryptikd: registry: could not record pid 1 of zone {}: {e}", zone.name);
        }
        // Readiness for the launch daemon: every setup step before pid 1 succeeded.
        if let Some(fd) = opts.ready_fd {
            unsafe {
                libc::write(fd, "ready\n".as_ptr() as *const libc::c_void, 6);
                libc::close(fd);
            }
        }
    }

    /* Transfers accept only files on the zone's data mount, looked up through
     * pid 1's root at request time (the root is built after pid 1 exists).
     * Unknown means every transfer is refused. */
    let zone_name = zone.name.clone();
    let home_dev = move || -> Option<u64> {
        let zp = init_pid?;
        std::fs::metadata(format!("/proc/{zp}/root/home/{zone_name}"))
            .ok()
            .map(|m| std::os::unix::fs::MetadataExt::dev(&m))
    };
    let served = broker::Served {
        zone,
        uid: id.uid,
        entry: entry.dir(),
        zones_dir: &opts.zones_dir,
        home_dev: &home_dev,
        auto_approve: opts.auto_approve_transfers,
        max_bytes: broker::TRANSFER_MAX,
        resolve_dest: &broker::registry_target,
        // Replaced by serve_until_exit with the launcher's own turn.
        asking: &crate::consent::keep,
    };
    let status = serve_until_exit(pid, broker_fd, &served, zone_out)?;
    unsafe { libc::close(broker_fd) };
    let _ = std::fs::remove_file(&broker_path);
    // dm-crypt frees the volume key on close: that is all "keys wiped on stop" means.
    if let Some(o) = opened_volume.take() {
        match o.close() {
            Ok(()) => eprintln!("kryptikd: zone {:?}: volume closed; its key is gone from the kernel", zone.name),
            Err(e) => eprintln!("kryptikd[zone {}]: {e}", zone.name),
        }
    }

    /* Removed here rather than by Drop so a failure is reported: EBUSY means
     * something in the zone outlived the launcher. */
    if let Some(cg) = &zone_cgroup {
        if let Err(e) = cg.destroy() {
            eprintln!(
                "kryptikd[zone {}]: the zone's cgroup could not be removed ({e}); \
                 something in the zone may have outlived the launcher",
                zone.name
            );
        }
    }

    Ok(decode_status(status))
}

/// The exit code a wait status stands for, as a shell reports it.
pub(crate) fn decode_status(status: libc::c_int) -> i32 {
    if (status & 0x7f) == 0 {
        (status >> 8) & 0xff
    } else {
        128 + (status & 0x7f)
    }
}

/// The signal that terminated the child, if a signal did.
pub(crate) fn signalled_by(status: libc::c_int) -> Option<libc::c_int> {
    let sig = status & 0x7f;
    if sig != 0 && sig != 0x7f { Some(sig) } else { None }
}

/// The intermediate process: enters the namespaces, becomes root there, and
/// supervises pid 1 of the zone. Returns the exit code to mirror.
fn intermediate_main(
    zone: &Zone,
    rootfs: &str,
    argv: &[String],
    id: &Identity,
    parent_pid: libc::pid_t,
    placed: &SyncPipe,
    ready: &SyncPipe,
    mapped: &SyncPipe,
    initpid: &SyncPipe,
    zone_policy: Option<&policy::Policy>,
    fs_rules: &[landlock::ZoneRule],
    broker_path: &str,
    wayland_path: Option<&str>,
    wayland_inode: Option<crate::serve::InodeId>,
    wifi_conf: Option<&str>,
) -> i32 {
    macro_rules! bail {
        ($($arg:tt)*) => {{
            eprintln!("kryptikd[zone {}]: {}", zone.name, format!($($arg)*));
            return 125;
        }};
    }

    rootfs::ensure_stdio();

    /* The id map is the privilege drop (docs/design/privileged-launch.md), so
     * the namespace is created as root: the target kernel refuses
     * unshare(CLONE_NEWUSER) without CAP_SYS_ADMIN in the initial namespace.
     * Supplementary groups are outside the map and need CAP_SETGID, so they go
     * now: fatally when privileged; an unprivileged launch keeps them and says so. */
    if id.privileged {
        if let Err(e) = isolate::drop_supplementary_groups() {
            bail!("setgroups: {e}");
        }
    } else if isolate::drop_supplementary_groups().is_err() {
        let n = isolate::supplementary_group_count();
        if n > 0 {
            eprintln!(
                "kryptikd[zone {}]: note: {n} supplementary host group(s) inherited \
                 (unprivileged launch cannot drop them)",
                zone.name
            );
        }
    }

    /* Die with the parent. Armed again after the setresuid below: the kernel
     * clears PR_SET_PDEATHSIG when euid or egid changes (commit_creds). The
     * getppid check covers a parent that died before the prctl. */
    if let Err(e) = isolate::die_with_parent() {
        bail!("prctl(PR_SET_PDEATHSIG): {e}");
    }
    if unsafe { libc::getppid() } != parent_pid {
        return 125;
    }

    /* Be placed in the zone's cgroup before the unshare: CLONE_NEWCGROUP roots
     * the cgroup namespace at the current cgroup, and a zone rooted elsewhere
     * cannot name its own cgroup. */
    if let Err(e) = placed.wait() {
        bail!("parent did not place the zone in its cgroup: {e}");
    }
    placed.close_read();

    let flags = isolate::namespace_flags(zone);

    if let Err(e) = isolate::unshare_namespaces(flags) {
        // Name the likely cause of EPERM: the userns restriction if unprivileged, an LSM if root.
        if matches!(e, isolate::IsolateError::Syscall { errno, .. } if errno == libc::EPERM) {
            if unsafe { libc::geteuid() } != 0 {
                eprintln!(
                    "kryptikd[zone {}]: creating a user namespace was refused. This kernel \
                     restricts unprivileged user namespaces (CONFIG_USER_NS_UNPRIVILEGED=n, \
                     kernel.unprivileged_userns_clone=0, or an LSM policy); kryptikd must be \
                     started with CAP_SYS_ADMIN in the initial namespace.",
                    zone.name
                );
            } else {
                eprintln!(
                    "kryptikd[zone {}]: unshare refused for a root caller: is kryptikd \
                     confined by an LSM?",
                    zone.name
                );
            }
        }
        bail!("unshare: {e}");
    }

    /* The new network namespace must hold only loopback. A privileged launch
     * refuses anything else; a developer launch, which cannot set the
     * fallback-tunnel sysctl, says what it found. */
    if flags & libc::CLONE_NEWNET != 0 {
        match netzone::devices_besides_lo() {
            Ok(devs) if !devs.is_empty() => {
                if id.privileged {
                    bail!(
                        "the new network namespace is not empty: {} besides loopback (see {}); \
                         refusing to start a zone in a namespace that is not loopback-only",
                        devs.join(", "),
                        netzone::FB_TUNNELS_SYSCTL
                    );
                }
                eprintln!(
                    "kryptikd[zone {}]: note: the new network namespace has {} besides loopback; \
                     this kernel creates them in every namespace and {} = 1 would stop that",
                    zone.name,
                    devs.join(", "),
                    netzone::FB_TUNNELS_SYSCTL
                );
            }
            Ok(_) => {}
            Err(e) => eprintln!(
                "kryptikd[zone {}]: note: could not list the new namespace's interfaces: {e}",
                zone.name
            ),
        }
    }

    /* Open the broker socket while this process has its own mount namespace (so
     * a bind from /proc/self/fd works) and is still host root (so it can walk
     * the 0700 registry). O_PATH names the inode for the bind; pid 1 inherits it
     * and zone_init's descriptor sweep closes it before the exec. */
    let broker_fd_for_zone = {
        let c = match std::ffi::CString::new(broker_path) {
            Ok(c) => c,
            Err(_) => bail!("broker socket path contains a NUL"),
        };
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH) };
        if fd < 0 {
            bail!("broker socket {}: {}", broker_path, io::Error::last_os_error());
        }
        fd
    };
    let broker_in_zone = format!("/proc/self/fd/{broker_fd_for_zone}");
    /* The Wayland socket likewise, walked without following symlinks and
     * checked against the verified inode. On a privileged launch the path is
     * the StagedSocket bind in the registry entry, which host uid 0 walks by
     * ownership. */
    let wayland_in_zone: Option<String> = match wayland_path {
        None => None,
        Some(p) => {
            let fd = match crate::serve::open_nofollow(std::path::Path::new(p), true) {
                Ok(fd) => fd,
                Err(e) => bail!("wayland socket {e}"),
            };
            if let Some(want) = wayland_inode {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
                    bail!("wayland socket {}: fstat: {}", p, io::Error::last_os_error());
                }
                if !want.matches(&st) {
                    bail!("wayland socket {} is not the socket the launch daemon verified (inode changed)", p);
                }
            }
            // Like the broker's: pid 1 inherits it and the descriptor sweep closes it.
            let raw = fd.into_raw_fd();
            unsafe {
                let fl = libc::fcntl(raw, libc::F_GETFD);
                libc::fcntl(raw, libc::F_SETFD, fl & !libc::FD_CLOEXEC);
            }
            Some(format!("/proc/self/fd/{raw}"))
        }
    };

    // Until the parent writes our id maps we are nobody (65534) and cannot become root.
    ready.signal();
    ready.close_write();
    let plumbed = match mapped.wait_byte() {
        Ok(v) => v == 2,
        Err(e) => bail!("parent did not complete the id mapping: {e}"),
    };
    mapped.close_read();

    // Become root in the new user namespace.
    if unsafe { libc::setresuid(0, 0, 0) } < 0 {
        bail!("setresuid: {}", io::Error::last_os_error());
    }
    if unsafe { libc::setresgid(0, 0, 0) } < 0 {
        bail!("setresgid: {}", io::Error::last_os_error());
    }

    // Re-arm PR_SET_PDEATHSIG, which the credential change just cleared.
    if let Err(e) = isolate::die_with_parent() {
        bail!("prctl(PR_SET_PDEATHSIG) after the id switch: {e}");
    }
    // A parent that died since the first check will never send the signal.
    if unsafe { libc::getppid() } != parent_pid {
        return 125;
    }

    /* A core-scheduling cookie of the zone's own, inherited by everything it
     * runs, so a core's sibling threads never run another zone's tasks (ADR-011).
     * A refusal is judged by the machine, not the errno: with no SMT online it
     * is fine, without kernel support it is noted, with siblings online fatal. */
    if let Err(e) = isolate::take_core_cookie() {
        match isolate::core_scheduling() {
            isolate::CoreSched::NoSmt => {}
            isolate::CoreSched::Unavailable => eprintln!(
                "kryptikd[zone {}]: note: core scheduling: not available on this kernel ({e}); \
                 this zone shares a core's sibling threads with whatever else runs",
                zone.name
            ),
            isolate::CoreSched::Cookies => bail!("prctl(PR_SCHED_CORE_CREATE) on a machine with sibling threads online: {e}"),
        }
    }

    // A new UTS namespace starts with the host's hostname.
    if let Err(e) = isolate::set_hostname(&zone.name) {
        bail!("sethostname: {e}");
    }

    // CLONE_NEWPID moves only the caller's children, so fork to get pid 1.
    let inner = unsafe { libc::fork() };
    if inner < 0 {
        bail!("fork: {}", io::Error::last_os_error());
    }

    if inner == 0 {
        let rc = zone_init(zone, rootfs, argv, flags, zone_policy, fs_rules, plumbed, &broker_in_zone, wayland_in_zone.as_deref(), wifi_conf);
        unsafe { libc::_exit(rc) };
    }

    // The parent needs pid 1 for the registry; send it before blocking in wait_for.
    initpid.write_i32(inner);
    initpid.close_write();

    /* Forward signals to pid 1 and SIGKILL it after GRACE_SECS: pid 1 of a pid
     * namespace ignores signals it has no handler for, but not SIGKILL from here. */
    install_forwarding(inner, true);
    match wait_for(inner) {
        Ok(status) => decode_status(status),
        Err(e) => {
            eprintln!("kryptikd[zone {}]: {e}", zone.name);
            125
        }
    }
}

/// pid 1 of the zone. Returns only on failure; on success it has exec'd.
fn zone_init(
    zone: &Zone,
    rootfs: &str,
    argv: &[String],
    flags: libc::c_int,
    zone_policy: Option<&policy::Policy>,
    fs_rules: &[landlock::ZoneRule],
    plumbed: bool,
    broker_path: &str,
    wayland_path: Option<&str>,
    wifi_conf: Option<&str>,
) -> i32 {
    macro_rules! bail {
        ($($arg:tt)*) => {{
            eprintln!("kryptikd[zone {}]: {}", zone.name, format!($($arg)*));
            return 125;
        }};
    }

    // If the intermediate dies so does pid 1, and with it the whole pid namespace.
    if let Err(e) = isolate::die_with_parent() {
        bail!("prctl(PR_SET_PDEATHSIG): {e}");
    }

    /* A root holding only what this zone should see: the containment boundary.
     * Everything after it is defense in depth. */
    let ephemeral = match zone.storage {
        StorageMode::Ephemeral => zone.size.as_deref(),
        // None: the data directory is the home, encrypted or not.
        StorageMode::Encrypted | StorageMode::Persistent => None,
    };
    // resolv.conf follows the path the parent built, not the declared mode.
    let resolver = match (zone.network, plumbed) {
        (crate::zone::NetworkMode::Nic, true) => rootfs::Resolver::Writable,
        (crate::zone::NetworkMode::Routed, true) => rootfs::Resolver::Bridge,
        _ => rootfs::Resolver::None,
    };
    let home = match rootfs::pivot_into(rootfs, &zone.name, ephemeral, resolver, Some(broker_path), wayland_path, wifi_conf) {
        Ok(h) => h,
        Err(e) => bail!("could not build the zone root: {e}"),
    };

    if flags & libc::CLONE_NEWNET != 0 {
        if let Err(e) = isolate::bring_up_loopback() {
            eprintln!("kryptikd[zone {}]: warning: lo did not come up: {e}", zone.name);
        }
    }

    /* Landlock over the pivoted tree: writes only where landlock::zone_rules
     * allow, so read-only mounts are denied twice. A plumbed nic zone also
     * writes its /run and /var/lib (nic_zone_rules); the condition must match
     * pivot_into's, or a rule on a missing path would refuse the zone. */
    if let Err(e) = landlock::confine_pivoted_zone(&home, resolver == rootfs::Resolver::Writable) {
        bail!("landlock: {e}");
    }
    // The zone's policy file is a second layer; the kernel intersects layers, so it can only narrow.
    if !fs_rules.is_empty() {
        if let Err(e) = landlock::confine_further(fs_rules) {
            bail!("landlock policy: {e}");
        }
    }

    // Close every descriptor above stderr: an open descriptor still works after pivot_root.
    if let Err(e) = rootfs::close_inherited_fds() {
        bail!("close_range: {e}");
    }

    /* Rebuild the environment from the allowlist. Every variable is removed;
     * walked as OsStrings because std::env::vars() panics on non-UTF-8. */
    let all: Vec<(std::ffi::OsString, std::ffi::OsString)> = std::env::vars_os().collect();
    let caller: Vec<(String, String)> = all
        .iter()
        .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v.to_str()?.to_string())))
        .collect();
    let env = zone_environment_with(zone, &home, &caller, wayland_path.is_some());
    for (k, _) in &all {
        std::env::remove_var(k);
    }
    for (k, v) in &env {
        std::env::set_var(k, v);
    }

    /* Drop the bounding set after the privileged steps (the mounts and
     * pivot_root need CAP_SYS_ADMIN) and before exec, so the command cannot
     * regain a capability, even through a file capability. Fatal on failure. */
    let keep: &[libc::c_int] = zone_policy.map(|p| p.keep_caps.as_slice()).unwrap_or(&[]);
    if let Err(e) = caps::drop_bounding_set_except(keep) {
        bail!("could not drop the capability bounding set: {e}");
    }

    // seccomp last: mount() and the other setup calls are not in its allowlist.
    let installed = match zone_policy {
        Some(p) => seccomp::confine_zone_with(&p.extra_syscalls, &p.sockets),
        None => seccomp::confine_zone(),
    };
    if let Err(e) = installed {
        bail!("seccomp: {e}");
    }

    let prog = match CString::new(argv[0].as_str()) {
        Ok(c) => c,
        Err(_) => bail!("command contains a NUL byte"),
    };
    let args: Vec<CString> = argv
        .iter()
        .filter_map(|a| CString::new(a.as_str()).ok())
        .collect();
    let mut ptrs: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());

    unsafe { libc::execvp(prog.as_ptr(), ptrs.as_ptr()) };

    // execvp only returns on failure.
    eprintln!(
        "kryptikd[zone {}]: exec {:?}: {}",
        zone.name,
        argv[0],
        io::Error::last_os_error()
    );
    127
}

// --- environment ------------------------------------------------------------

/// Caller variables a zone may inherit, if well-formed; everything else is dropped.
pub const ENV_PASSTHROUGH: &[&str] = &[
    "TERM", "COLORTERM", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_COLLATE",
    "LC_MESSAGES", "LC_NUMERIC", "LC_TIME", "LC_MONETARY", "LC_PAPER", "LC_NAME",
    "LC_ADDRESS", "LC_TELEPHONE", "LC_MEASUREMENT", "LC_IDENTIFICATION",
];

/// A value fit for a locale or terminal name: short, with no shell or path
/// metacharacters. Anything else is dropped, not sanitized.
pub fn env_value_is_sane(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.chars().all(|c| c.is_ascii_alphanumeric() || "._+:@-".contains(c))
}

/// The complete environment the zone's command starts with. With a display,
/// WAYLAND_DISPLAY is the socket's absolute path (libwayland
/// needs no XDG_RUNTIME_DIR then) and XDG_RUNTIME_DIR is the zone's /tmp.
pub fn zone_environment_with(zone: &Zone, home: &str, caller: &[(String, String)], wayland: bool) -> Vec<(String, String)> {
    let mut env = zone_environment_base(zone, home, caller);
    if wayland {
        env.push(("WAYLAND_DISPLAY".into(), rootfs::WAYLAND_SOCKET_IN_ZONE.into()));
        env.push(("XDG_RUNTIME_DIR".into(), "/tmp".into()));
    }
    env
}

fn zone_environment_base(zone: &Zone, home: &str, caller: &[(String, String)]) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = vec![
        ("PATH".into(), "/usr/bin:/usr/sbin:/bin:/sbin".into()),
        ("HOME".into(), home.into()),
        ("TMPDIR".into(), "/tmp".into()),
        ("USER".into(), "root".into()),
        ("LOGNAME".into(), "root".into()),
        ("SHELL".into(), "/bin/sh".into()),
        ("KRYPTIK_ZONE".into(), zone.name.clone()),
    ];
    for (k, v) in caller {
        if ENV_PASSTHROUGH.contains(&k.as_str()) && env_value_is_sane(v) {
            env.push((k.clone(), v.clone()));
        }
    }
    // Without LANG, Python and others fall back to ASCII; C.UTF-8 names no country.
    if !env.iter().any(|(k, _)| k == "LANG") {
        env.push(("LANG".into(), "C.UTF-8".into()));
    }
    if !env.iter().any(|(k, _)| k == "TERM") {
        env.push(("TERM".into(), "dumb".into()));
    }
    env
}

/// Describe what starting this zone would do, without doing it.
pub fn explain(zone: &Zone, rootfs: &str, zones_dir: &std::path::Path) -> String {
    let network_line = netzone::plan(zone, unsafe { libc::geteuid() } == 0);
    let transfer_line = if zone.transfer_to.is_empty() {
        "transfer   none: no [transfer] to, this zone sends files nowhere".to_string()
    } else {
        format!(
            "transfer   to {} (through the broker, into their incoming/; each one needs zone 0 approval)",
            zone.transfer_to.join(", ")
        )
    };
    let core_line = match isolate::core_scheduling() {
        isolate::CoreSched::Cookies => "core sched own cookie: a core's sibling threads run this zone's tasks or nothing",
        isolate::CoreSched::NoSmt => "core sched no sibling threads online (nosmt): no core is shared with anything",
        isolate::CoreSched::Unavailable => "core sched not available on this kernel (no CONFIG_SCHED_CORE): siblings are shared",
    };
    let loaded = zone
        .seccomp
        .as_ref()
        .map(|rel| (rel.clone(), policy::load(&policy::resolve(zones_dir, rel)).and_then(|p| p.check_for_zone(zone).map(|_| p))));
    let policy_line = match &loaded {
        None => "policy     base only".to_string(),
        Some((rel, Ok(p))) => format!("policy     {rel}: {}", p.describe()),
        Some((rel, Err(e))) => format!("policy     {rel}: ERROR - {e} (the zone will not start)"),
    };
    // What the zone keeps depends on its policy (the nic zone keeps more).
    let caps_line = match &loaded {
        Some((_, Ok(p))) if !p.keep_cap_names.is_empty() => format!(
            "caps       bounding set: CAP_NET_BIND_SERVICE + {} (kept by policy)",
            p.keep_cap_names.join(" + ")
        ),
        _ => "caps       bounding set dropped to CAP_NET_BIND_SERVICE only".to_string(),
    };
    let ns = isolate::namespace_names(isolate::namespace_flags(zone));

    let storage = match zone.storage {
        StorageMode::Encrypted => format!(
            "encrypted: $HOME is the ext4 inside the LUKS2 container {},\n\
             \x20          opened to {} on a root launch (passphrase from\n\
             \x20          --passphrase-file), mounted nosuid,nodev at {}, unmounted\n\
             \x20          and closed when the zone exits (the key leaves the kernel).\n\
             \x20          Unprivileged launches are refused: they cannot open it.",
            zone.volume.as_deref().unwrap_or("?"),
            volume::mapper_path(&zone.name),
            rootfs
        ),
        StorageMode::Persistent => format!(
            "persistent: $HOME is {}, a plain directory kept between launches.\n\
             \x20           It is NOT encrypted at rest: anything that can read the\n\
             \x20           host filesystem can read this zone's files. On a privileged\n\
             \x20           launch they are owned by the zone identity below, which is\n\
             \x20           file ownership and not cryptography.",
            rootfs
        ),
        StorageMode::Ephemeral => format!(
            "ephemeral: $HOME is a per-launch tmpfs of {}, freed when the zone exits.\n\
             \x20          Nothing the zone writes reaches its persistent directory.\n\
             \x20          CAVEAT: tmpfs pages can be written to swap. Until Kryptik\n\
             \x20          ships with encrypted or no swap this is NOT secure erasure.",
            zone.size.as_deref().unwrap_or("?")
        ),
    };

    let home = rootfs::zone_home(&zone.name);
    let identity_line = match zone.uid_base {
        Some(b) => format!(
            "identity   uid_base {b}: a root launch maps zone root -> host {b}, nobody -> {} \
             (range {b}..{})",
            b + 65534,
            b + 65535
        ),
        None => "identity   none declared: a root launch needs --zone-uid/--zone-gid; \
                 check --target refuses this zone"
            .to_string(),
    };

    // An ephemeral zone cannot see its data directory, which must be empty for it to start.
    let data_line = match zone.storage {
        StorageMode::Ephemeral => format!(
            "data dir   {rootfs} (NOT visible inside; must be empty for the zone to start)"
        ),
        StorageMode::Encrypted | StorageMode::Persistent => {
            format!("data dir   {rootfs} (visible inside as {home})")
        }
    };

    let mut rules: Vec<String> = landlock::zone_rules(&home)
        .iter()
        .map(|r| format!("{:<12} {}", r.path, landlock::describe_access(r.access)))
        .collect();
    if zone.network == crate::zone::NetworkMode::Nic {
        rules.push("-- and, once it holds the NIC, its own tmpfs for the network stack's state:".to_string());
        rules.extend(
            landlock::nic_zone_rules()
                .iter()
                .map(|r| format!("{:<12} {}", r.path, landlock::describe_access(r.access))),
        );
    }
    if let Some(rel) = &zone.landlock {
        let path = policy::resolve(zones_dir, rel);
        match std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|t| landlock::parse_policy(&t, rel))
        {
            Ok(extra) => {
                rules.push(format!("-- and then narrowed by {rel}, which grants only:"));
                rules.extend(
                    extra
                        .iter()
                        .map(|r| format!("{:<12} {}", r.path, landlock::describe_access(r.access))),
                );
            }
            Err(e) => rules.push(format!("-- {rel}: ERROR - {e} (the zone will not start)")),
        }
    }

    format!(
        "zone       {}\n\
         namespaces {}\n\
         hostname   {}\n\
         {}\n\
         {}\n\
         storage    {}\n\
         root       tmpfs, read-only; {} bound read-only recursively\n\
         /etc       synthesized (passwd, group, hosts, nsswitch) + read-only {}\n\
         /dev       {} + shm, pts\n\
         landlock   ABI >= {}, rules:\n           {}\n\
         env        {} + passthrough of {}\n\
         {}\n\
         seccomp    default-deny, {} syscalls allowed, argument rules on {:?}\n\
         {}\n\
         {}\n\
         {}\n\
         {}",
        zone.name,
        ns.join(", "),
        zone.name,
        identity_line,
        data_line,
        storage,
        rootfs::SYSTEM_PATHS.join(" "),
        rootfs::ETC_RO_FILES
            .iter()
            .chain(rootfs::ETC_RO_DIRS)
            .map(|p| p.trim_start_matches("/etc/"))
            .collect::<Vec<_>>()
            .join(", "),
        rootfs::DEVICES.iter().map(|(_, n)| *n).collect::<Vec<_>>().join(", "),
        landlock::MIN_ABI,
        rules.join("\n           "),
        "PATH HOME TMPDIR USER LOGNAME SHELL KRYPTIK_ZONE",
        ENV_PASSTHROUGH.join(" "),
        caps_line,
        seccomp::BASE_ALLOWLIST.len(),
        seccomp::ARG_RULES,
        policy_line,
        network_line,
        transfer_line,
        core_line,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::Zone;

    /// A relay with no descriptor behind it: only `take` and `flush` are used.
    fn relayed(chunks: &[&[u8]]) -> Vec<String> {
        let mut lines = Vec::new();
        let mut o = std::mem::ManuallyDrop::new(ZoneOutput::new(-1, "work"));
        for c in chunks {
            o.take(c, &mut |l| lines.push(l.to_string()));
        }
        o.flush(&mut |l| lines.push(l.to_string()));
        lines
    }

    #[test]
    fn zone_output_is_prefixed_and_sanitized() {
        // Every line is marked, and a line split across reads stays one line.
        assert_eq!(
            relayed(&[b"kryptikd[zone work]: broker served \"steal\"\nhal", b"f\n"]),
            ["zone work| kryptikd[zone work]: broker served \"steal\"", "zone work| half"]
        );
        // Escapes and carriage returns are replaced.
        assert_eq!(relayed(&[b"\x1b[2Jgone\rtab\there\n"]), ["zone work| ?[2Jgone?tab\there"]);
        // A line with no end is cut at ZONE_LINE_MAX.
        let long = vec![b'a'; ZONE_LINE_MAX * 2 + 5];
        let got = relayed(&[&long]);
        assert_eq!(got.iter().map(|l| l.len() - "zone work| ".len()).collect::<Vec<_>>(), [ZONE_LINE_MAX, ZONE_LINE_MAX, 5]);
        // Past the bound nothing more is logged, and it says so once.
        let flood = vec![b'x'; ZONE_OUTPUT_MAX + 4096];
        let got = relayed(&[&flood, b"more\n"]);
        let logged: usize = got.iter().filter(|l| !l.contains("is not logged")).map(|l| l.len() - "zone work| ".len()).sum();
        assert_eq!(logged, ZONE_OUTPUT_MAX);
        assert_eq!(got.iter().filter(|l| l.contains("is not logged")).count(), 1);
        assert!(!got.iter().any(|l| l.contains("more")));
    }

    #[test]
    fn pump_reads_bounded_amount() {
        /* A zone that never stops writing must not keep one pump from
         * returning: fill the pipe past one pass and check the rest is left. */
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) }, 0);
        let (r, w) = (fds[0], fds[1]);
        let size = unsafe { libc::fcntl(w, libc::F_SETPIPE_SZ, 1 << 20) };
        let size = if size > 0 { size as usize } else { 65536 };
        let chunk = [b'y'; 4096];
        let mut written = 0usize;
        while written + chunk.len() <= size {
            let n = unsafe { libc::write(w, chunk.as_ptr() as *const libc::c_void, chunk.len()) };
            if n <= 0 { break; }
            written += n as usize;
        }
        let one_pass = ZONE_READS_PER_PUMP * 4096;
        assert!(written > one_pass, "the pipe took {written} bytes, not more than one pass ({one_pass})");
        let mut o = std::mem::ManuallyDrop::new(ZoneOutput::new(r, "work"));
        assert!(o.pump(&mut |_: &str| {}), "the writer is still there");
        let mut left: libc::c_int = 0;
        assert_eq!(unsafe { libc::ioctl(r, libc::FIONREAD, &mut left) }, 0);
        assert_eq!(left as usize, written - one_pass, "one pass read {} bytes, not {one_pass}", written - left as usize);
        unsafe { libc::close(w); libc::close(r) };
    }

    fn z(mode: &str) -> Zone {
        Zone::from_str(&format!(
            "[zone]\nname = \"t\"\n[network]\nmode = \"{mode}\"\n\
             [storage]\nmode = \"ephemeral\"\nsize = \"256M\"\n[ui]\nborder_color = \"#123456\"\n"
        ))
        .unwrap()
    }

    fn z_identity(base: u32) -> Zone {
        Zone::from_str(&format!(
            "[zone]\nname = \"t\"\n[network]\nmode = \"routed\"\n\
             [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n\
             [identity]\nuid_base = {base}\n[ui]\nborder_color = \"#123456\"\n"
        ))
        .unwrap()
    }

    /// The line matches what the launch will do on this kernel.
    #[test]
    fn explain_names_core_scheduling() {
        let e = explain(&z("none"), "/tmp/t", std::path::Path::new("/nonexistent"));
        let line = e.lines().find(|l| l.starts_with("core sched")).unwrap_or_else(|| panic!("no core sched line in:\n{e}"));
        let want = match isolate::core_scheduling() {
            isolate::CoreSched::Cookies => "own cookie",
            isolate::CoreSched::NoSmt => "no sibling threads online",
            isolate::CoreSched::Unavailable => "not available on this kernel",
        };
        assert!(line.contains(want), "{line}");
    }

    /// Two forked writers share one pipe, one of them through `log_line`;
    /// every line read back must be one writer's, whole.
    #[test]
    fn log_line_is_never_split() {
        use std::io::Read;
        use std::os::unix::io::FromRawFd;
        const N: usize = 1500;
        let a_line = format!("kryptikd[zone probe]: broker served {:?} {}", "steal", "x".repeat(160));
        let b_line = "error: unknown verb";
        let mut p = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0, "pipe failed");
        let mut kids = Vec::new();
        for which in 0..2 {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                unsafe {
                    libc::close(p[0]);
                    if which == 0 {
                        libc::dup2(p[1], 2);
                        for _ in 0..N {
                            log_line(&a_line);
                        }
                    } else {
                        let line = format!("{b_line}\n");
                        for _ in 0..N {
                            libc::write(p[1], line.as_ptr() as *const libc::c_void, line.len());
                        }
                    }
                    libc::_exit(0);
                }
            }
            kids.push(pid);
        }
        unsafe { libc::close(p[1]) };
        let mut all = String::new();
        unsafe { std::fs::File::from_raw_fd(p[0]) }.read_to_string(&mut all).expect("read the pipe");
        for k in kids {
            let mut st = 0;
            unsafe { libc::waitpid(k, &mut st, 0) };
        }
        let (mut a, mut b) = (0, 0);
        for line in all.lines() {
            if line == a_line {
                a += 1;
            } else if line == b_line {
                b += 1;
            } else {
                panic!("a line arrived that neither writer wrote whole: {line:?}");
            }
        }
        assert_eq!((a, b), (N, N), "lines were lost or merged");
    }

    #[test]
    fn explain_reports_capabilities_kept_by_policy() {
        let dir = std::env::temp_dir().join(format!("kryptik-explain-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("policy")).unwrap();
        std::fs::write(dir.join("policy/n.seccomp"), "keep-capability CAP_NET_RAW\nkeep-capability CAP_NET_ADMIN\n").unwrap();
        let nic = Zone::from_str(
            "[zone]\nname = \"n\"\n[network]\nmode = \"nic\"\n\
             [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n[policy]\nseccomp = \"policy/n.seccomp\"\n\
             [ui]\nborder_color = \"#123456\"\n",
        )
        .unwrap();
        let e = explain(&nic, "/tmp/n", &dir);
        assert!(e.contains("caps       bounding set: CAP_NET_BIND_SERVICE + CAP_NET_RAW + CAP_NET_ADMIN (kept by policy)"), "{e}");
        // The same file on a routed zone is an error, and explain says so.
        let routed = Zone::from_str(
            "[zone]\nname = \"r\"\n[network]\nmode = \"routed\"\n\
             [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n[policy]\nseccomp = \"policy/n.seccomp\"\n\
             [ui]\nborder_color = \"#123457\"\n",
        )
        .unwrap();
        let e = explain(&routed, "/tmp/r", &dir);
        assert!(e.contains("ERROR") && e.contains("owns the NIC"), "{e}");
        assert!(e.contains("dropped to CAP_NET_BIND_SERVICE only"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn explain_names_identity_range() {
        assert!(explain(&z_identity(196608), "/tmp/t", std::path::Path::new("/nonexistent")).contains("uid_base 196608"));
        assert!(explain(&z("routed"), "/tmp/t", std::path::Path::new("/nonexistent")).contains("none declared"));
    }

    #[test]
    fn explain_warns_persistent_unencrypted() {
        let z = Zone::from_str(
            "[zone]\nname = \"t\"\n[network]\nmode = \"none\"\n\
             [storage]\nmode = \"persistent\"\n[ui]\nborder_color = \"#123456\"\n",
        )
        .unwrap();
        let e = explain(&z, "/var/lib/kryptik/zones/t", std::path::Path::new("/nonexistent"));
        assert!(e.contains("NOT encrypted at rest"), "say it in those words: {e}");
        assert!(
            e.contains("kept between launches"),
            "and say what it DOES do, or the line reads as a pure warning: {e}"
        );
        // Unlike an ephemeral zone's, this data directory is visible inside.
        assert!(
            e.contains("/var/lib/kryptik/zones/t (visible inside as"),
            "the data line must place it: {e}"
        );
        assert!(!e.contains("NOT YET IMPLEMENTED"), "persistent IS implemented: {e}");
    }

    fn z_encrypted() -> Zone {
        Zone::from_str(
            "[zone]\nname = \"t\"\n[network]\nmode = \"none\"\n\
             [storage]\nmode = \"encrypted\"\nvolume = \"/dev/kryptik/t\"\n\
             [ui]\nborder_color = \"#123456\"\n",
        )
        .unwrap()
    }

    #[test]
    fn rootfs_path_is_under_base() {
        assert_eq!(zone_rootfs(&z("routed"), "/var/lib/kryptik/zones"),
                   "/var/lib/kryptik/zones/t");
    }

    #[test]
    fn explain_names_namespaces_and_storage() {
        let e = explain(&z("none"), "/tmp/t", std::path::Path::new("/nonexistent"));
        assert!(e.contains("user"), "{e}");
        assert!(e.contains("net"), "{e}");
        assert!(e.contains("tmpfs"), "explain must say what ephemeral storage IS: {e}");
    }

    #[test]
    fn explain_does_not_overclaim() {
        let e = explain(&z("routed"), "/tmp/t", std::path::Path::new("/tmp"));
        // The plan line must qualify routed networking (docs/design/net-zone.md: no NAT yet).
        let honest = e.contains("NOT IMPLEMENTED")
            || e.contains("not implemented")
            || e.contains("no path out")
            || e.contains("loopback")
            || e.contains("nic zone")
            || e.contains("NAT")
            || e.contains("uid_base");
        assert!(honest, "explain must not present routed networking as working: {e}");
        assert!(e.contains("swap"), "explain must name the swap caveat: {e}");
        assert!(
            e.contains("NOT secure erasure"),
            "explain must not let 'ephemeral' be read as secure erasure: {e}"
        );

        // Encrypted: the container and mapping are named, and unprivileged launches refused.
        let enc = explain(&z_encrypted(), "/tmp/t", std::path::Path::new("/nonexistent"));
        assert!(enc.contains("LUKS2") && enc.contains("/dev/mapper/kryptik-zone-t"), "{enc}");
        assert!(enc.contains("Unprivileged launches are refused"), "{enc}");
    }

    #[test]
    fn decode_status_matches_shell() {
        assert_eq!(decode_status(0), 0);
        assert_eq!(decode_status(3 << 8), 3);
        assert_eq!(decode_status(libc::SIGSYS), 128 + libc::SIGSYS);
    }

    #[test]
    fn environment_is_allowlist() {
        let caller: Vec<(String, String)> = [
            ("FOO_TOKEN", "leaked"),
            ("SSH_AUTH_SOCK", "/run/user/1000/keyring/ssh"),
            ("LD_PRELOAD", "/tmp/evil.so"),
            ("LD_LIBRARY_PATH", "/tmp"),
            ("KRYPTIK_EXPERIMENTAL", "1"),
            ("HOME", "/home/operator"),
            ("PATH", "/home/operator/bin:/usr/bin"),
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ("TERM", "xterm-256color"),
            ("LANG", "en_US.UTF-8"),
            ("LC_ALL", "C.UTF-8"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let env = zone_environment_with(&z("routed"), "/home/t", &caller, false);
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        for dropped in ["FOO_TOKEN", "SSH_AUTH_SOCK", "LD_PRELOAD", "LD_LIBRARY_PATH", "KRYPTIK_EXPERIMENTAL", "XDG_RUNTIME_DIR"] {
            assert!(get(dropped).is_none(), "{dropped} leaked into the zone");
        }
        assert_eq!(get("HOME"), Some("/home/t"), "caller HOME must be replaced");
        assert_eq!(get("PATH"), Some("/usr/bin:/usr/sbin:/bin:/sbin"));
        assert_eq!(get("TERM"), Some("xterm-256color"));
        assert_eq!(get("LANG"), Some("en_US.UTF-8"));
        assert_eq!(get("LC_ALL"), Some("C.UTF-8"));
        assert_eq!(get("KRYPTIK_ZONE"), Some("t"));
        assert_eq!(get("USER"), Some("root"));
    }

    #[test]
    fn passthrough_values_must_be_well_formed() {
        assert!(env_value_is_sane("xterm-256color"));
        assert!(env_value_is_sane("en_US.UTF-8"));
        assert!(!env_value_is_sane(""));
        assert!(!env_value_is_sane("xterm\n"));
        assert!(!env_value_is_sane("$(id)"));
        assert!(!env_value_is_sane("/etc/passwd"));
        assert!(!env_value_is_sane("a b"));
        assert!(!env_value_is_sane(&"x".repeat(65)));
        let caller = vec![("TERM".to_string(), "xterm;rm -rf /".to_string())];
        let env = zone_environment_with(&z("routed"), "/home/t", &caller, false);
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("TERM"), Some("dumb"), "a malformed TERM is replaced, not passed");
        assert_eq!(get("LANG"), Some("C.UTF-8"), "no caller LANG means a UTF-8 default");
    }

    #[test]
    fn unprivileged_launch_cannot_pick_identity() {
        if unsafe { libc::geteuid() } == 0 {
            // As root the rule is the reverse; see the next test.
            return;
        }
        let err = launch_identity(&RunOptions { zone_uid: Some(1001), zone_gid: Some(1001), ..Default::default() }, &z("routed")).unwrap_err();
        assert!(err.to_string().contains("need root"), "{err}");
        let id = launch_identity(&RunOptions::default(), &z("routed")).unwrap();
        assert_eq!(id.uid, unsafe { libc::getuid() });
        assert!(!id.privileged);
    }

    #[test]
    fn root_launch_needs_unprivileged_identity() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        assert!(launch_identity(&RunOptions::default(), &z("routed")).is_err());
        assert!(launch_identity(&RunOptions { zone_uid: Some(0), zone_gid: Some(0), ..Default::default() }, &z("routed")).is_err());
        let id = launch_identity(&RunOptions { zone_uid: Some(100000), zone_gid: Some(100000), ..Default::default() }, &z("routed")).unwrap();
        assert!(id.privileged);
        // A declared identity wins, and an override of it is refused.
        let id = launch_identity(&RunOptions::default(), &z_identity(196608)).unwrap();
        assert_eq!((id.uid, id.gid), (196608, 196608));
        let err = launch_identity(&RunOptions { zone_uid: Some(100000), zone_gid: Some(100000), ..Default::default() }, &z_identity(196608)).unwrap_err();
        assert!(err.to_string().contains("not accepted"), "{err}");
    }
}
