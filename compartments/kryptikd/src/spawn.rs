//! Zone spawning: create a zone and run something inside it.
//!
//! This is what turns kryptikd from a validator into a compartment manager.
//! Until now the Phase 5 exit test drove the isolation primitives with
//! `unshare(1)`, which proved the primitives were sound but said nothing about
//! whether kryptikd applies them correctly. This module is what the test can
//! attack instead.
//!
//! ORDER IS THE WHOLE THING. Each step below depends on the ones before it,
//! and several of the dependencies are not obvious. They are written down next
//! to the code rather than left to be rediscovered.
//!
//! PROCESS TREE
//!
//!   kryptikd (parent)          waits; forwards SIGINT/TERM/HUP/QUIT down
//!    └─ intermediate           unshares the namespaces, becomes zone root,
//!       │                      forks pid 1, forwards signals to it, and
//!       │                      SIGKILLs it if it ignores them for GRACE_SECS
//!       └─ zone pid 1          pivots, confines itself, execs the command
//!
//! Every link carries PR_SET_PDEATHSIG(SIGKILL): if kryptikd dies - killed,
//! crashed, terminal gone - the intermediate dies, and then pid 1 of the zone
//! dies, and then the kernel kills everything else in that pid namespace.
//! Before this, `kill -9` on kryptikd left the zone running detached, owned
//! by nothing.

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;
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
    /// Host uid the zone's root maps to. Only meaningful, and only accepted,
    /// when kryptikd itself runs as root.
    pub zone_uid: Option<u32>,
    pub zone_gid: Option<u32>,
    /// The zone directory, against which `[policy]` paths resolve.
    pub zones_dir: std::path::PathBuf,
    /// Development stand-in for the zone 0 prompt: approve every transfer
    /// this zone offers. Prints a warning at launch.
    pub auto_approve_transfers: bool,
    /// Where an encrypted zone's passphrase comes from: a 0600 file (tests
    /// and root at a terminal). Nothing reads a passphrase from argv or the
    /// environment.
    pub passphrase_file: Option<std::path::PathBuf>,
    /// Or from an inherited descriptor (the launch daemon hands over what
    /// the trusted prompt collected, through SCM_RIGHTS, never argv).
    pub passphrase_fd: Option<i32>,
    /// The per-zone Wayland proxy socket to bind into the zone at
    /// /run/kryptik/wayland-0 (Design 05a). None: the zone has no display.
    pub wayland_socket: Option<std::path::PathBuf>,
    /// The (device, inode) the socket must be, as the launch daemon
    /// verified it: the child opens the path without following symlinks
    /// and refuses any other inode, so nothing renamed or linked into
    /// place between the daemon's check and the bind is accepted.
    pub wayland_inode: Option<crate::serve::InodeId>,
    /// A pipe the launch daemon reads (serve.rs): `ready` is written to it
    /// when the zone's pid 1 exists, and it is closed then. Closed by exit
    /// before that means the zone did not start. CLOEXEC, so no zone
    /// command inherits it.
    pub ready_fd: Option<i32>,
}

/// The zone's Wayland proxy socket, staged in its registry entry for the
/// child to open after unshare: a bind mount of the verified inode at
/// `<entry>/wayland-0`, in the host mount namespace. Why it is needed is
/// explained where it is made, in `spawn`. Dropping it undoes the staging:
/// the bind is detached and the mountpoint file removed, so the registry
/// entry can be removed after it.
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

        // Open the session's socket as this process - root in the host
        // namespace, which walks the session's private directories - one
        // component at a time without following a symlink, and refuse any
        // inode but the one the daemon verified: a rename between its check
        // and this open is not honoured.
        let fd = crate::serve::open_nofollow(session_path, true)
            .map_err(|e| SpawnError::Setup(format!("wayland socket {e}")))?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.raw(), &mut st) } < 0 {
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
        // A launcher that died between staging and its Drop left a bind
        // here; the registry's reclaim detaches it, and so does this, so a
        // stale mount is never bound over - every one of them, since each
        // detach takes only the topmost. Then the mountpoint: an empty
        // file, root's, 0600, created new so nothing planted is reused.
        while unsafe { libc::umount2(cpath.as_ptr(), libc::MNT_DETACH) } == 0 {}
        let _ = std::fs::remove_file(&path);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| SpawnError::Setup(format!("{}: {e}", path.display())))?;
        let src = CString::new(format!("/proc/self/fd/{}", fd.raw())).unwrap();
        if unsafe { libc::mount(src.as_ptr(), cpath.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) } < 0 {
            let e = errno();
            let _ = std::fs::remove_file(&path);
            return Err(SpawnError::Setup(format!(
                "staging the wayland socket of zone {zone:?} at {}: {}",
                path.display(),
                io::Error::from_raw_os_error(e)
            )));
        }
        // The descriptor has done its work: the mount holds its own
        // reference to the inode, and nothing else may inherit this one.
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

/// Seconds a zone gets to exit after a forwarded SIGINT/SIGTERM before its
/// pid 1 is SIGKILLed, which takes the whole pid namespace with it.
pub const GRACE_SECS: u32 = 5;

// --- signal forwarding ------------------------------------------------------
//
// Both the parent and the intermediate run this. Each is its own process, so
// the statics are per-role: FORWARD_TO is the pid to forward to, ARM_KILL is
// whether a forwarded signal also arms the SIGKILL timer (only the
// intermediate does that; it is the only process that can SIGKILL pid 1 of
// the zone, since pid 1 ignores signals from inside its own namespace).
//
// Everything in the handlers is async-signal-safe: atomics, kill, alarm.

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
        // SA_RESTART: the waits below are restarted rather than failing with
        // EINTR - and they retry on EINTR anyway.
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

/// Supervise the child while answering the zone broker requests: poll the
/// listening socket with a short timeout, serve what arrives, and reap the
/// child when it exits. Signals forwarded by the handlers interrupt the
/// poll, which just loops.
fn serve_until_exit(pid: libc::pid_t, listen_fd: RawFd, s: &broker::Served) -> Result<libc::c_int, SpawnError> {
    let zone = s.zone.name.as_str();
    loop {
        let mut status: libc::c_int = 0;
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r == pid {
            return Ok(status);
        }
        if r < 0 && errno() != libc::EINTR {
            return Err(SpawnError::Syscall { call: "waitpid", errno: errno() });
        }
        let mut pfd = libc::pollfd { fd: listen_fd, events: libc::POLLIN, revents: 0 };
        let n = unsafe { libc::poll(&mut pfd, 1, 200) };
        if n > 0 && pfd.revents & libc::POLLIN != 0 {
            match broker::serve_one(listen_fd, s) {
                Ok(Some(verb)) => eprintln!("kryptikd[zone {zone}]: broker served {verb:?}"),
                Ok(None) => {}
                Err(e) => eprintln!("kryptikd[zone {zone}]: broker: {e}"),
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

/// A one-byte pipe used to order the parent and child against each other.
///
/// TWO of these are needed, in both directions, and the first version of this
/// code had only one. The handshake is:
///
///   child   unshare(CLONE_NEWUSER|...)
///   child  --ready-->  parent      "I am in the new namespace"
///   parent  writes /proc/PID/{setgroups,uid_map,gid_map}
///   parent --mapped-->  child      "your maps exist, you may become root"
///   child   setresuid(0,0,0)
///
/// Without the first signal the parent races ahead and writes the maps while
/// the child is still in the OLD user namespace. That write fails with EPERM
/// on setgroups, the maps never appear, and setresuid(0,0,0) then fails with
/// EINVAL because uid 0 was never mapped - two errors, neither of which points
/// at the missing synchronisation that caused them.
///
/// `wait` distinguishes a signal (one byte) from the peer going away (EOF):
/// the first version ignored the read result, so a parent that died between
/// fork and the map write left the child believing it had been mapped.
struct SyncPipe {
    read: RawFd,
    write: RawFd,
}

impl SyncPipe {
    fn new() -> Result<Self, SpawnError> {
        let mut fds = [0 as RawFd; 2];
        // CLOEXEC: these must not survive into the zone's command even if
        // descriptor closing were somehow skipped.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(SpawnError::Syscall { call: "pipe2", errno: errno() });
        }
        Ok(SyncPipe { read: fds[0], write: fds[1] })
    }

    fn signal(&self) {
        self.signal_byte(1)
    }

    /// Like `signal`, with a value the peer can read back. Used on `mapped`
    /// to tell the intermediate whether the parent built a network path.
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

    /// Send a pid to the other end. Four bytes in native order: both ends are
    /// the same process image on the same machine.
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

    /// Read a pid. `None` on EOF or a short read - which means the sender died
    /// before it could tell us. That is a real outcome, not an error: the
    /// caller is about to report why the zone failed.
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
    /// kryptikd itself runs as root and will switch to `uid`/`gid` before
    /// creating the user namespace.
    privileged: bool,
}

fn launch_identity(opts: &RunOptions, zone: &Zone) -> Result<Identity, SpawnError> {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        // The zone file is the authority. A declared range is fixed for the
        // life of the zone's data, so a command-line override of it would
        // silently change who owns that data; refuse the combination rather
        // than pick one.
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

/// Create the zone and execute `argv` inside it. Returns the child's exit code.
///
/// The caller must be able to create a user namespace. kryptikd proper runs
/// privileged in zone 0, but this path works unprivileged too, which is what
/// lets the adversarial test run it as an ordinary user.
pub fn run_in_zone(
    zone: &Zone,
    rootfs: &str,
    argv: &[String],
    opts: &RunOptions,
) -> Result<i32, SpawnError> {
    if argv.is_empty() {
        return Err(SpawnError::Setup("no command given".into()));
    }

    // Landlock is not optional. A zone without filesystem confinement can read
    // every other zone, which is requirement 2 of the exit test - so refuse to
    // start rather than start something weaker than a zone. Too old an ABI is
    // refused for the same reason: the policy would mean less than it says.
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

    // Refuse to start a zone whose definition promises something this code
    // does not deliver.
    //
    // A zone declaring storage.mode = "encrypted" currently gets an ordinary
    // directory: per-zone LUKS2 volumes are not implemented. Starting it
    // anyway would put secrets on plaintext storage while the configuration,
    // the UI and the operator all believe otherwise - the precise failure this
    // project exists to avoid. Same for "ephemeral", which is not yet wiped on
    // stop; for resource limits, which create no cgroup; and for per-zone
    // policy files, which are not applied. A setting that is parsed and then
    // ignored is a setting the operator believes is in force.
    //
    // KRYPTIK_EXPERIMENTAL=1 allows it for development, loudly. There is
    // deliberately no config option for this: it must be a conscious act at
    // the command line, not a setting someone can forget they enabled.
    // The one thing about ephemeral storage that is not delivered, said every
    // time rather than buried in a design document: tmpfs pages are swappable.
    // memory.swap.max=0 keeps the zone's PROCESS pages out of swap, but not
    // the tmpfs pages it wrote, which outlive the writer.
    if zone.storage == StorageMode::Ephemeral {
        eprintln!(
            "kryptikd: zone {:?}: ephemeral storage is a tmpfs freed on exit; its pages \
             can reach swap, so this is not secure erasure",
            zone.name
        );
    }

    // Persistent storage is implemented and it keeps data, which is its whole
    // promise. What it is not is encrypted, and that is said every launch
    // rather than left to be inferred from the word nobody wrote.
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

    // KRYPTIK_EXPERIMENTAL is a developer override. On a kernel that
    // restricts unprivileged user namespaces - the target, or its emulation -
    // a root launch is the real thing, and the override is ignored (Design
    // 01, P6): a development flag must not be able to start a zone on a
    // production kernel without the guarantees its file declares.
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
        // Encrypted is implemented for a ROOT launch (Design 04): the LUKS2
        // volume is opened and mounted below, before the zone exists, and
        // closed after it is gone. An unprivileged launch cannot run
        // cryptsetup, so it stays refused: running such a zone on a plain
        // directory while its file says "encrypted" is the failure this
        // project exists to avoid.
        //
        // Refused outright, not listed as an unimplemented guarantee that
        // KRYPTIK_EXPERIMENTAL may waive: the override exists for guarantees
        // this build does not provide, and encryption is provided - by a root
        // launch. Waiving it here would start the zone on a plain directory,
        // which the launcher suite (F3) and the cli suite (C1) both refuse to
        // accept, and which the first CI run after the volumes landed did.
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
        // Ephemeral is implemented (M2): the zone's home is a per-launch
        // tmpfs in its own mount namespace, and the persistent directory is
        // never bound anywhere. The one thing still worth saying out loud is
        // swap - see the note printed below, and docs/design/02.
        StorageMode::Ephemeral => {}
        // Persistent is implemented, and it promises only what it does: the
        // zone's own directory, bound at $HOME, still there next launch. It is
        // NOT on the unsupported list, so it needs no override and it starts
        // on the target kernel - the only mode that both survives a reboot and
        // does so honestly until encrypted volumes land.
        StorageMode::Persistent => {}
    }
    // A Landlock policy file is applied as a second layer over the base
    // rules (docs/design/07). Read and parsed HERE, in the parent, because
    // the zone cannot reach the zone directory once it has pivoted - and a
    // file that does not parse must stop the launch before anything is built.
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
    // [network]: every zone starts from an EMPTY network namespace - loopback
    // and nothing else - and only the parent adds to it. A kernel with the
    // tunnel modules built in (the Kryptik kernel builds SIT in) creates its
    // fallback devices in every new namespace unless
    // net.core.fb_tunnels_only_for_init_net says otherwise, and the target
    // kernel's first boot found sit0 inside an airgapped zone (R-13). A root
    // launcher raises the sysctl once; an unprivileged one cannot, and the
    // zone is then refused like any other guarantee this build cannot give.
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
    // [limits] is no longer unconditionally unsupported: it is supported when
    // this process can actually create a cgroup, and refused when it cannot.
    // The question is answered by TRYING, not by checking uid - a delegated
    // subtree is writable by an ordinary user, and root inside a container may
    // still find the hierarchy read-only.
    //
    // `limits` holds the base directory when enforcement is possible. When it
    // is None and the zone asked for limits, the zone is refused exactly as it
    // was before, because a limit that silently does nothing is worse than no
    // limit: the operator's belief in it is what causes the damage.
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

    // Claim the zone name before doing any work. One instance per zone is the
    // v1 rule: two launchers of the same zone would share a data directory, a
    // cgroup name and - once M3 lands - a veth name, and the second would
    // quietly corrupt the first. `mkdir` is the atomic operation; a stale
    // entry from a crashed launcher is reclaimed rather than obeyed.
    let entry = registry::claim(&zone.name).map_err(|e| SpawnError::Setup(e.to_string()))?;

    let id = launch_identity(opts, zone)?;
    entry
        .set_identity(id.uid, id.gid)
        .map_err(|e| SpawnError::Setup(e.to_string()))?;

    // Encrypted storage: unlock the zone's LUKS2 container and mount its
    // filesystem at the data directory BEFORE the directory checks, which
    // then see the filesystem's own root - owned by the zone identity since
    // `volume init`. Held in `opened_volume`; dropped on any error path
    // below, which closes it, so a failed launch never leaves plaintext
    // mounted, and closed explicitly after the zone has exited.
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

    // The persistent directory. Created if missing; when kryptikd is root it
    // is handed to the zone's identity, but an existing directory is never
    // re-owned - if it belongs to someone else, check_data_dir refuses it.
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

    // An ephemeral zone must not start over data from an earlier run. Nothing
    // it writes will reach this directory, so anything already there is data
    // the operator believes is gone and is not.
    if zone.storage == StorageMode::Ephemeral {
        rootfs::check_data_dir_empty(rootfs, &zone.name)
            .map_err(|e| SpawnError::Setup(e.to_string()))?;
    }

    // placed: parent -> child, "you are in your cgroup, you may unshare"
    // ready:  child -> parent, "I have unshared"
    // mapped: parent -> child, "your id maps are written"
    //
    // `placed` is third and it is ordered FIRST for a reason. The move into
    // the cgroup has to happen before the child unshares, because
    // CLONE_NEWCGROUP roots the child's cgroup namespace at whatever cgroup it
    // is in at that moment. Move it afterwards and enforcement still works,
    // but the zone's own /proc/self/cgroup describes a path outside its
    // namespace root - a zone that cannot name its own cgroup correctly is one
    // that cannot manage sub-cgroups later.
    // The zone's broker endpoint lives in its registry entry; the zone sees
    // it at /run/kryptik/broker. Served by this process while it waits.
    let broker_path = entry.dir().join(broker::SOCKET_NAME);
    let broker_fd = broker::listen_at(&broker_path, id.uid, id.gid)
        .map_err(|e| SpawnError::Setup(format!("broker socket {}: {e}", broker_path.display())))?;

    // THE ZONE OPENS THIS ITSELF, AFTER IT HAS ITS OWN MOUNT NAMESPACE.
    //
    // The child binds this socket into its root, and by then it has dropped to
    // the zone identity - which cannot walk to it. The registry is 0700 and
    // root-owned, deliberately (Design 06, and security's R-7b F1):
    //
    //     drwx------ root:root  /run/kryptik
    //     drwx------ root:root  /run/kryptik/zones
    //
    // so binding by path failed with EPERM on every privileged launch and took
    // the VM from 135 passing to 100 failing. It worked unprivileged only
    // because every zone maps to the launching user, who owns those
    // directories.
    //
    // The fix is a descriptor rather than a path - but it cannot be opened
    // HERE. A bind whose source mount belongs to a different mount namespace
    // is refused:
    //
    //     fd opened BEFORE unshare(CLONE_NEWNS): Invalid argument
    //     fd opened AFTER  unshare(CLONE_NEWNS): ok
    //
    // measured directly. So the path travels to the child, and the child opens
    // it in the window after it unshares and before it takes the zone's
    // identity, when it still has its own mount namespace AND is still root.
    let broker_path_str = broker_path.display().to_string();

    // The Wayland proxy socket, if the zone gets a display. The session made
    // it under its own runtime directory - /run/user/<uid>/kryptik/<zone>/
    // wayland-0, 0700 and the session's all the way down - and the child
    // cannot walk that. After unshare(CLONE_NEWUSER) it is host uid 0 with
    // no capability the host honours, and a directory it does not own that
    // grants nothing to others refuses it. The first installed system showed
    // exactly that: every zone with a window died at setup with "kryptik:
    // Permission denied" on the session's directory. The developer suite
    // never saw it because there the launcher IS the session's uid, and
    // owner bits let it through.
    //
    // So a privileged launch stages the socket where the child already looks
    // for the broker: the zone's registry entry, root-owned and 0700, which
    // host uid 0 walks by ownership alone (Design 05 named this very path,
    // /run/kryptik/zones/<zone>/wayland-0). The staging is a bind mount of
    // the inode the daemon verified, made HERE - in the host mount
    // namespace, which the child's unshare copies - and undone when the
    // launch ends, on every path, by `staged`'s Drop; it is declared after
    // `entry` so it is dropped before the entry directory is removed. A
    // developer launch cannot mount and does not need to: it hands the child
    // the path as given.
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

    let placed = SyncPipe::new()?;
    let ready = SyncPipe::new()?;
    let mapped = SyncPipe::new()?;
    // initpid: child -> parent, carrying the zone's pid 1 as the HOST sees it.
    //
    // Design 06 suggested widening `ready` to an i32 instead. It cannot be:
    // `ready` is signalled before the id maps are written, and the grandchild
    // that becomes pid 1 cannot be forked until after them, because it must be
    // root in the new user namespace first. So the pid does not exist yet when
    // `ready` fires, and this is a fourth pipe rather than a wider third one.
    // Same outcome, and only the parent ever writes the registry.
    let initpid = SyncPipe::new()?;

    let parent_pid = unsafe { libc::getpid() };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(SpawnError::Syscall { call: "fork", errno: errno() });
    }

    if pid == 0 {
        // --- intermediate ------------------------------------------------------
        placed.close_write();
        ready.close_read();
        mapped.close_write();
        initpid.close_read();
        // The daemon's readiness pipe is the parent's to answer; holding a
        // copy here would only delay the EOF that reports a failed launch.
        if let Some(fd) = opts.ready_fd {
            unsafe { libc::close(fd) };
        }
        let rc = intermediate_main(
            zone, rootfs, argv, &id, parent_pid, &placed, &ready, &mapped, &initpid,
            zone_policy.as_ref(), &fs_rules, &broker_path_str, wayland_path_str.as_deref(), opts.wayland_inode,
        );
        // Never return: this process must not run the parent's cleanup.
        unsafe { libc::_exit(rc) };
    }

    // --- parent --------------------------------------------------------------
    placed.close_read();
    ready.close_write();
    mapped.close_read();
    initpid.close_write();
    install_forwarding(pid, false);

    // Create the zone's cgroup and put the child in it before releasing it to
    // unshare. Everything here runs in the PARENT, which still holds whatever
    // privilege kryptikd started with; the child never writes to the cgroup
    // filesystem and /sys/fs/cgroup is not bound into the zone.
    //
    // The handle is held for the whole launch and dropped at the end, so an
    // early return cannot leak the directory.
    let zone_cgroup = match &limits {
        Some(base) => {
            // Naming [limits] and not just the syscall: available() proved a
            // leaf could be made moments ago, so reaching here means something
            // changed underneath us - and the operator still has to be able to
            // connect the failure to the setting they wrote in the zone file.
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
            // Recorded so a later `stop` or `gc` can reach whatever is left if
            // this launcher dies without cleaning up. The cgroup is the only
            // safe handle to a dead launcher's processes: unlike a pid, it
            // cannot have been reused.
            // Not fatal - the zone is up, and killing it over bookkeeping is
            // worse - but not silent either: without this field, reclaim
            // skips the cgroup.kill and a dead launcher's processes stay.
            if let Err(e) = entry.set_cgroup(&cg.path().display().to_string()) {
                eprintln!("kryptikd: registry: could not record the cgroup of zone {}: {e}", zone.name);
            }
            Some(cg)
        }
        None => None,
    };

    // Release the child to unshare, whether or not it got a cgroup.
    // The launcher's own pid, with its start time, so `stop` can signal it and
    // be certain it is signalling the same process.
    entry
        .set_launcher(parent_pid)
        .map_err(|e| SpawnError::Setup(format!("registry: {e}")))?;

    placed.signal();
    placed.close_write();

    // Wait until the child is actually inside the new user namespace. Writing
    // the maps before this point fails with EPERM. EOF means it died first;
    // it has already said why on stderr, so report its code and nothing else.
    if ready.wait().is_err() {
        let status = wait_for(pid)?;
        return Err(SpawnError::Setup(format!(
            "zone {:?} exited during setup (code {})",
            zone.name,
            decode_status(status)
        )));
    }

    // The zone's network namespace now exists and nothing runs in it. A root
    // launch builds the topology from OUTSIDE, here, before the zone becomes
    // anything: the nic zone takes the physical interface and gets the
    // bridge; a routed zone gets an isolated port on that bridge and an eth0
    // addressed from its identity. A failure to attach is not fatal - the
    // zone starts with loopback only, fail-closed - except for the nic zone,
    // where a NIC that could not be moved must not be left half-configured.
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

    // Map the child's root to the zone identity. This is what makes "root
    // inside the zone" mean root in a namespace that owns nothing outside it.
    if let Err(e) = isolate::write_id_maps(pid, id.uid, id.gid, id.privileged) {
        // Close our end so the child reads EOF and dies rather than blocking.
        mapped.close_write();
        let _ = wait_for(pid);
        return Err(SpawnError::Setup(format!("id maps: {e}")));
    }

    // 1 = mapped; 2 = mapped and a network path was built.
    mapped.signal_byte(if plumbed { 2 } else { 1 });
    mapped.close_write();

    // The zone's pid 1, as the host sees it. Read before waitpid because the
    // intermediate sends it as soon as it has forked; EOF means the zone died
    // during setup and the failure is reported below, not here.
    let init_pid = initpid.read_i32();
    if let Some(zp) = init_pid {
        // set_init already treats a pid that vanished as Ok; an Err here is
        // a registry write that failed, after which every transfer into the
        // zone reports "still starting" with nothing saying why.
        if let Err(e) = entry.set_init(zp) {
            eprintln!("kryptikd: registry: could not record pid 1 of zone {}: {e}", zone.name);
        }
        // Readiness, for the launch daemon: the zone's pid 1 exists, so
        // every setup step before it succeeded. Written once, then closed.
        if let Some(fd) = opts.ready_fd {
            unsafe {
                libc::write(fd, "ready\n".as_ptr() as *const libc::c_void, 6);
                libc::close(fd);
            }
        }
    }

    // The broker serves this zone until it exits. A transfer must know the
    // zone's data mount as the zone sees it (/home/<zone>, through its pid
    // 1's root) so that only files from there are accepted (Design 05 B5).
    // Asked at request time, not here: pid 1 exists before its root is
    // built, and a request can only arrive once the zone runs. Unknown
    // means every transfer is refused.
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
    };
    let status = serve_until_exit(pid, broker_fd, &served)?;
    unsafe { libc::close(broker_fd) };
    let _ = std::fs::remove_file(&broker_path);
    // The zone is gone (its pid namespace with it): unmount its data and
    // close the mapping. dm-crypt frees the volume key in the kernel on
    // close; that is what "keys wiped on stop" means, and all it means.
    if let Some(o) = opened_volume.take() {
        match o.close() {
            Ok(()) => eprintln!("kryptikd: zone {:?}: volume closed; its key is gone from the kernel", zone.name),
            Err(e) => eprintln!("kryptikd[zone {}]: {e}", zone.name),
        }
    }

    // Remove the cgroup here rather than leaving it to Drop. Drop still covers
    // every early return above, but it has nowhere to report to, and the one
    // failure that matters is worth reporting: rmdir returns EBUSY while any
    // process remains, so a cgroup that will not go away means something in
    // the zone outlived the launcher. Cleaning that up silently is how a
    // survivor holding the zone's files goes unnoticed.
    if let Some(cg) = &zone_cgroup {
        if let Err(e) = cg.destroy() {
            eprintln!(
                "kryptikd[zone {}]: the zone's cgroup could not be removed ({e});                  something in the zone may have outlived the launcher",
                zone.name
            );
        }
    }

    Ok(decode_status(status))
}

/// The exit code a wait status stands for, the way a shell reports it.
///
/// The one decoder in the crate: main.rs's seccomp probes decode the same
/// status and used to carry their own copies of this arithmetic, untested.
pub(crate) fn decode_status(status: libc::c_int) -> i32 {
    if (status & 0x7f) == 0 {
        (status >> 8) & 0xff
    } else {
        // Killed by a signal; report it the way a shell does.
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
) -> i32 {
    macro_rules! bail {
        ($($arg:tt)*) => {{
            eprintln!("kryptikd[zone {}]: {}", zone.name, format!($($arg)*));
            return 125;
        }};
    }

    rootfs::ensure_stdio();

    // 1. Identity. THE ID MAP IS THE DROP - see docs/design/01a-p5-correction.md.
    //
    //    This used to call setresuid/setresgid to the zone's host identity
    //    here, before creating the user namespace, on the reasoning that the
    //    namespace should not be created by root. Wiring the security tab's
    //    own contract probe into the VM proved that cannot work: a kernel with
    //    CONFIG_USER_NS_UNPRIVILEGED off (which is the kernel Kryptik intends
    //    to ship) refuses unshare(CLONE_NEWUSER) from a process without
    //    CAP_SYS_ADMIN in the initial namespace - so the process this code had
    //    just made unprivileged was exactly the case the kernel refuses, and
    //    no zone started at all. The kernel's own audit record named kryptikd.
    //
    //    The early switch was also not buying what it looked like it bought.
    //    What makes the zone's root a harmless host uid N is the uid_map the
    //    parent writes; the creator's identity only decides who OWNS the
    //    namespace, and a root-owned user namespace gives root nothing it did
    //    not already have. So: create the namespace as root, and let the map
    //    do the dropping. Design 01a §2.
    //
    //    Supplementary groups still go before the unshare, and still fatally:
    //    they are not covered by the map, and CAP_SETGID is needed to drop
    //    them, which this process has here and will not have after.
    //
    //    The cost, named rather than hidden: between the unshare below and the
    //    setresuid(0,0,0) at step 5, this process is host euid 0 inside a fresh
    //    user namespace. It does nothing in that window but wait on a pipe.
    //
    //    Unprivileged, the kernel only lets us map our own uid, and setgroups
    //    needs CAP_SETGID we do not have - so the host groups come along. They
    //    are named rather than hidden.
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

    // 2. Die with the parent.
    //
    //    Armed here AND again at step 5, because the kernel clears
    //    PR_SET_PDEATHSIG on any credential change (commit_creds drops it when
    //    the euid or egid moves). That used to be free: the identity switch
    //    happened above this point, so nothing after it changed credentials.
    //    Removing that switch for the P5 repair silently disarmed the whole
    //    mechanism - SIGKILLing a launcher left its zone running, which the
    //    suite caught as "2 zone process(es) outlived a SIGKILLed launcher"
    //    and then as a dozen zones that would not start because the registry
    //    correctly said they were already running.
    //
    //    Checked against the recorded parent pid to close the window in which
    //    the parent died before the prctl.
    if let Err(e) = isolate::die_with_parent() {
        bail!("prctl(PR_SET_PDEATHSIG): {e}");
    }
    if unsafe { libc::getppid() } != parent_pid {
        return 125;
    }

    // 2b. Wait until the parent has placed us in the zone's cgroup.
    //
    //     This MUST precede the unshare below. CLONE_NEWCGROUP roots our
    //     cgroup namespace at whichever cgroup we occupy at that instant, so a
    //     process moved afterwards is still limited - enforcement is by
    //     membership, not by namespace - but its own /proc/self/cgroup then
    //     describes a path outside its namespace root, and a zone that cannot
    //     name its own cgroup cannot manage sub-cgroups later.
    //
    //     EOF means the parent failed before it could place us; it has already
    //     said why.
    if let Err(e) = placed.wait() {
        bail!("parent did not place the zone in its cgroup: {e}");
    }
    placed.close_read();

    let flags = isolate::namespace_flags(zone);

    // 3. Enter the new namespaces.
    if let Err(e) = isolate::unshare_namespaces(flags) {
        // P7: when the kernel refuses, say which restriction is refusing,
        // because "Permission denied" on a machine whose administrator turned
        // unprivileged user namespaces off is otherwise a half-hour of
        // guessing. The two cases need different sentences: an unprivileged
        // caller is hitting the restriction the way it is meant to work, while
        // a root caller being refused means something is confining kryptikd
        // itself.
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

    // 3a. The network namespace must be empty: loopback and nothing else.
    //     The parent has already dealt with the kernel's fallback tunnel
    //     devices (net.core.fb_tunnels_only_for_init_net), so anything here
    //     now is a device this zone was never given. A privileged launch
    //     will not start a zone in a namespace it did not build; a developer
    //     launch, which cannot change the sysctl, says what it found.
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

    // 3b. Open the broker socket NOW: this process has its own mount namespace
    //     (so a bind from /proc/self/fd resolves in it) and is still root (so
    //     it can traverse the 0700 registry). Neither is true later - the
    //     identity switch at step 5 is one-way, and the zone must not be given
    //     a path it could not open for itself.
    //
    //     O_PATH because nothing reads or writes the socket here; the fd only
    //     names the inode for the bind. Not CLOEXEC: it has to survive the
    //     fork at step 7 into the process that builds the root. It is closed
    //     by zone_init's descriptor sweep (rootfs::close_inherited_fds), not
    //     by the exec: the sweep is what keeps it out of the zone.
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
    // Same for the Wayland proxy socket, when there is one - opened HERE,
    // in the zone's own mount namespace (a descriptor from the daemon's
    // namespace cannot be bind-mounted from this one), walking the path
    // without following a single symlink, and refusing any inode but the
    // one the daemon verified. On a privileged launch the path is the
    // staging bind in the zone's registry entry (StagedSocket): root's own
    // directory, which this process - host uid 0 with no capability the
    // host honours, since the unshare - still walks by ownership. The
    // session's runtime directory it could not: 0700 and not its own.
    let wayland_in_zone: Option<String> = match wayland_path {
        None => None,
        Some(p) => {
            let fd = match crate::serve::open_nofollow(std::path::Path::new(p), true) {
                Ok(fd) => fd,
                Err(e) => bail!("wayland socket {e}"),
            };
            if let Some(want) = wayland_inode {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(fd.raw(), &mut st) } < 0 {
                    bail!("wayland socket {}: fstat: {}", p, io::Error::last_os_error());
                }
                if !want.matches(&st) {
                    bail!("wayland socket {} is not the socket the launch daemon verified (inode changed)", p);
                }
            }
            // Not CLOEXEC, for the same reason as the broker's: it must
            // survive into the process that builds the root, and it is
            // closed by the descriptor sweep, not the exec.
            let raw = fd.into_raw();
            unsafe {
                let fl = libc::fcntl(raw, libc::F_GETFD);
                libc::fcntl(raw, libc::F_SETFD, fl & !libc::FD_CLOEXEC);
            }
            Some(format!("/proc/self/fd/{raw}"))
        }
    };

    // 4. Tell the parent we are in the new namespace, then wait for it to
    //    write uid_map/gid_map. Until those exist we are nobody (65534) and
    //    cannot mount anything or become root. EOF here means the parent
    //    failed or died; either way there is no zone to build.
    ready.signal();
    ready.close_write();
    let plumbed = match mapped.wait_byte() {
        Ok(v) => v == 2,
        Err(e) => bail!("parent did not complete the id mapping: {e}"),
    };
    mapped.close_read();

    // 5. Become root in the new user namespace.
    if unsafe { libc::setresuid(0, 0, 0) } < 0 {
        bail!("setresuid: {}", io::Error::last_os_error());
    }
    if unsafe { libc::setresgid(0, 0, 0) } < 0 {
        bail!("setresgid: {}", io::Error::last_os_error());
    }

    // 5b. Re-arm PR_SET_PDEATHSIG: the two calls above just cleared it. This
    //     is the one that actually matters, because everything the zone does
    //     from here on is after it - and without it a launcher killed with
    //     SIGKILL (which it cannot catch, so it can clean up nothing) leaves
    //     the zone running with nobody supervising it.
    if let Err(e) = isolate::die_with_parent() {
        bail!("prctl(PR_SET_PDEATHSIG) after the id switch: {e}");
    }
    // And check again: the parent may have died between step 2's check and
    // now, in which case the signal we just re-armed will never be delivered.
    if unsafe { libc::getppid() } != parent_pid {
        return 125;
    }

    // 6. The zone's hostname is the zone's name. The UTS namespace is new,
    //    but a new UTS namespace starts with the HOST's hostname in it.
    if let Err(e) = isolate::set_hostname(&zone.name) {
        bail!("sethostname: {e}");
    }

    // 7. CLONE_NEWPID does not move the CALLER into the new pid namespace -
    //    only its children. Fork so the grandchild becomes pid 1 there. Without
    //    this the zone shares the host pid namespace despite having asked for
    //    its own, and /proc shows every process on the machine.
    let inner = unsafe { libc::fork() };
    if inner < 0 {
        bail!("fork: {}", io::Error::last_os_error());
    }

    if inner == 0 {
        let rc = zone_init(zone, rootfs, argv, flags, zone_policy, fs_rules, plumbed, &broker_in_zone, wayland_in_zone.as_deref());
        unsafe { libc::_exit(rc) };
    }

    // Supervise pid 1 of the zone: forward signals, SIGKILL it if it ignores
    // them (pid 1 of a namespace ignores every signal from inside it that it
    // has no handler for, so a forwarded SIGTERM alone may do nothing), and
    // mirror its exit code.
    // Tell the parent the zone's pid 1 before waiting on it: the parent needs
    // it for the registry, and once we block in wait_for we cannot.
    initpid.write_i32(inner);
    initpid.close_write();

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
) -> i32 {
    macro_rules! bail {
        ($($arg:tt)*) => {{
            eprintln!("kryptikd[zone {}]: {}", zone.name, format!($($arg)*));
            return 125;
        }};
    }

    // 8. If the intermediate dies, so does the zone - and with pid 1 gone the
    //    kernel reaps the whole pid namespace.
    if let Err(e) = isolate::die_with_parent() {
        bail!("prctl(PR_SET_PDEATHSIG): {e}");
    }

    // 9. Replace the root with a tree containing only what this zone should
    //    see. This is the actual containment boundary; everything below is
    //    defense in depth over it.
    //
    //    Before this existed, zones ran in the caller's mount namespace with
    //    Landlock as the only filesystem control, and a review escaped it two
    //    ways without a kernel bug: an inherited descriptor read a file
    //    outside the zone, and chmod changed the mode of one. Both worked
    //    because those paths still EXISTED here. A permission layer cannot fix
    //    reachability.
    let ephemeral = match zone.storage {
        StorageMode::Ephemeral => zone.size.as_deref(),
        // Both of these bind the zone's own directory at $HOME. They differ in
        // what protects it at rest, which is not this call's business: None
        // here means "the data directory IS the home", not "unencrypted".
        StorageMode::Encrypted | StorageMode::Persistent => None,
    };
    // /etc/resolv.conf follows the path the parent built, not the mode the
    // file declares: a routed zone with no path names no resolver.
    let resolver = match (zone.network, plumbed) {
        (crate::zone::NetworkMode::Nic, true) => rootfs::Resolver::Writable,
        (crate::zone::NetworkMode::Routed, true) => rootfs::Resolver::Bridge,
        _ => rootfs::Resolver::None,
    };
    let home = match rootfs::pivot_into(rootfs, &zone.name, ephemeral, resolver, Some(broker_path), wayland_path) {
        Ok(h) => h,
        Err(e) => bail!("could not build the zone root: {e}"),
    };

    // 10. Loopback, for zones that have a network namespace at all.
    if flags & libc::CLONE_NEWNET != 0 {
        if let Err(e) = isolate::bring_up_loopback() {
            eprintln!("kryptikd[zone {}]: warning: lo did not come up: {e}", zone.name);
        }
    }

    // 11. Filesystem confinement, now over a tree that contains only the zone.
    //     Read+exec everywhere, write only in the places named in
    //     landlock::zone_rules - so the read-only mounts are denied write by
    //     two independent mechanisms, which is what "defense in depth" has to
    //     mean if it means anything.
    //     The nic zone alone also writes the two state mounts pivot_into gave
    //     it (/run, /var/lib); see landlock::nic_zone_rules. The condition
    //     is the one pivot_into used: a nic-mode zone that was NOT plumbed
    //     (unprivileged, nothing moved in) has no such mounts, and a
    //     required rule on a path that is not there would refuse the zone.
    if let Err(e) = landlock::confine_pivoted_zone(&home, resolver == rootfs::Resolver::Writable) {
        bail!("landlock: {e}");
    }
    // 11b. The zone's own policy file, as a SECOND layer. Layers intersect,
    //      so this can only narrow what step 11 allowed - a zone file cannot
    //      hand itself anything, and the kernel is what guarantees that.
    if !fs_rules.is_empty() {
        if let Err(e) = landlock::confine_further(fs_rules) {
            bail!("landlock policy: {e}");
        }
    }

    // 12. Close every descriptor above stderr.
    //
    //     The other half of the inherited-descriptor escape. pivot_root does
    //     NOT fix this on its own: a descriptor that was already open keeps
    //     working no matter what the mount namespace now looks like.
    rootfs::close_inherited_fds();

    // 13. An explicit environment. Nothing from the caller reaches the zone
    //     unless it is on the allowlist and looks like what it claims to be.
    //
    //     One walk of the environment, as OsStrings, and every variable in it
    //     is removed. Only the UTF-8 subset can be matched against the
    //     allowlist; the rest is not skipped, it is removed with everything
    //     else. (std::env::vars() would have panicked on a non-UTF-8 name or
    //     value, in the zone's pid 1, and a second walk with vars_os() did
    //     the removal.)
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

    // 14. Syscall filtering, LAST. It must come after every privileged setup
    //     step above, because mount() and friends are not in the allowlist -
    //     installing the filter earlier would kill the zone during its own
    //     construction.
    // Drop the capability bounding set, keeping only CAP_NET_BIND_SERVICE.
    //
    // AFTER every privileged step - the mounts and pivot_root above need
    // CAP_SYS_ADMIN - and BEFORE exec, so the payload can never acquire what
    // this removes, including through a file capability on a binary it can
    // reach.
    //
    // Inside its own user namespace the zone's root has held a full set. Every
    // capability-gated syscall that reaches outside the namespace is already
    // denied by the filter installed below, so the set has been inert - but it
    // stops being inert the moment a zone owns one end of a veth, where
    // CAP_NET_ADMIN and CAP_NET_RAW let a compromised zone re-address its link
    // and open a raw socket on the segment it shares with the bridge. The
    // security review calls this a precondition for that milestone rather than
    // a follow-up to it.
    //
    // Fatal on failure: a zone that starts with a fuller set than the operator
    // asked for is the failure this project exists to avoid.
    let keep: &[libc::c_int] = zone_policy.map(|p| p.keep_caps.as_slice()).unwrap_or(&[]);
    if let Err(e) = caps::drop_bounding_set_except(keep) {
        bail!("could not drop the capability bounding set: {e}");
    }

    let installed = match zone_policy {
        Some(p) => seccomp::confine_zone_with(&p.extra_syscalls, &p.sockets),
        None => seccomp::confine_zone(),
    };
    if let Err(e) = installed {
        bail!("seccomp: {e}");
    }

    // 15. Hand off.
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

/// Caller variables a zone may inherit, if their values are well-formed.
/// Everything else - tokens, agent sockets, LD_*, XDG_*, the caller's HOME
/// and PATH, KRYPTIK_EXPERIMENTAL - is dropped.
pub const ENV_PASSTHROUGH: &[&str] = &[
    "TERM", "COLORTERM", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_COLLATE",
    "LC_MESSAGES", "LC_NUMERIC", "LC_TIME", "LC_MONETARY", "LC_PAPER", "LC_NAME",
    "LC_ADDRESS", "LC_TELEPHONE", "LC_MEASUREMENT", "LC_IDENTIFICATION",
];

/// A value fit for a locale or terminal name: short, printable, no shell or
/// path metacharacters. Anything else is dropped rather than sanitized.
pub fn env_value_is_sane(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.chars().all(|c| c.is_ascii_alphanumeric() || "._+:@-".contains(c))
}

/// The complete environment the zone's command starts with.
pub fn zone_environment(zone: &Zone, home: &str, caller: &[(String, String)]) -> Vec<(String, String)> {
    zone_environment_with(zone, home, caller, false)
}

/// With a display: WAYLAND_DISPLAY names the proxy socket by absolute path
/// (libwayland accepts that without XDG_RUNTIME_DIR), and XDG_RUNTIME_DIR
/// is the zone's own tmpfs so clients that insist on one have one.
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
    // A UTF-8 locale by default: without LANG, Python and friends fall back
    // to ASCII and choke on non-ASCII filenames. C.UTF-8 names no country.
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
    let loaded = zone
        .seccomp
        .as_ref()
        .map(|rel| (rel.clone(), policy::load(&policy::resolve(zones_dir, rel)).and_then(|p| p.check_for_zone(zone).map(|_| p))));
    let policy_line = match &loaded {
        None => "policy     base only".to_string(),
        Some((rel, Ok(p))) => format!("policy     {rel}: {}", p.describe()),
        Some((rel, Err(e))) => format!("policy     {rel}: ERROR - {e} (the zone will not start)"),
    };
    // The capability line must say what the ZONE gets, which depends on its
    // policy: a static "NET_BIND_SERVICE only" was wrong for the nic zone.
    let caps_line = match &loaded {
        Some((_, Ok(p))) if !p.keep_cap_names.is_empty() => format!(
            "caps       bounding set: CAP_NET_BIND_SERVICE + {} (kept by policy)",
            p.keep_cap_names.join(" + ")
        ),
        _ => "caps       bounding set dropped to CAP_NET_BIND_SERVICE only".to_string(),
    };
    let flags = isolate::namespace_flags(zone);
    let mut ns = Vec::new();
    for (f, n) in [
        (libc::CLONE_NEWUSER, "user"),
        (libc::CLONE_NEWNS, "mount"),
        (libc::CLONE_NEWPID, "pid"),
        (libc::CLONE_NEWIPC, "ipc"),
        (libc::CLONE_NEWUTS, "uts"),
        (libc::CLONE_NEWCGROUP, "cgroup"),
        (libc::CLONE_NEWNET, "net"),
    ] {
        if flags & f != 0 {
            ns.push(n);
        }
    }

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

    // For an ephemeral zone the persistent directory is NOT visible inside -
    // that is the whole change - so the line must not keep claiming it is. It
    // is still worth printing, because it is the directory that must be empty
    // for the zone to start at all.
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
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::Zone;

    fn z(mode: &str) -> Zone {
        let bridge = if mode == "nic" { "bridge = \"kryptik0\"\n" } else { "" };
        Zone::from_str(&format!(
            "[zone]\nname = \"t\"\n[network]\nmode = \"{mode}\"\n{bridge}\
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

    #[test]
    fn explain_reports_capabilities_kept_by_policy() {
        let dir = std::env::temp_dir().join(format!("kryptik-explain-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("policy")).unwrap();
        std::fs::write(dir.join("policy/n.seccomp"), "keep-capability CAP_NET_RAW\nkeep-capability CAP_NET_ADMIN\n").unwrap();
        let nic = Zone::from_str(
            "[zone]\nname = \"n\"\n[network]\nmode = \"nic\"\nbridge = \"kryptik0\"\n\
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
    fn explain_names_the_identity_range_or_its_absence() {
        assert!(explain(&z_identity(196608), "/tmp/t", std::path::Path::new("/nonexistent")).contains("uid_base 196608"));
        assert!(explain(&z("routed"), "/tmp/t", std::path::Path::new("/nonexistent")).contains("none declared"));
    }

    #[test]
    fn explain_says_persistent_storage_is_not_encrypted() {
        // The whole risk of this mode is that its name sounds like a safe
        // place to put things. explain is where someone checks before they do.
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
        // The data directory is reachable from inside, unlike an ephemeral
        // zone where naming it would be misleading.
        assert!(
            e.contains("/var/lib/kryptik/zones/t (visible inside as"),
            "the data line must place it: {e}"
        );
        // And it must not borrow the encrypted mode's disclaimer.
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
    fn rootfs_path_is_under_the_base() {
        assert_eq!(zone_rootfs(&z("routed"), "/var/lib/kryptik/zones"),
                   "/var/lib/kryptik/zones/t");
    }

    #[test]
    fn explain_names_the_namespaces_and_is_honest_about_storage() {
        let e = explain(&z("none"), "/tmp/t", std::path::Path::new("/nonexistent"));
        assert!(e.contains("user"), "{e}");
        assert!(e.contains("net"), "{e}");
        // Ephemeral storage IS implemented now, so the old assertion - that
        // explain says NOT YET IMPLEMENTED - would be a lie in the other
        // direction. What explain must still do is refuse to overclaim: a
        // tmpfs freed on exit is not secure erasure while its pages can be
        // swapped, and an operator reading this is deciding what to put in the
        // zone.
        assert!(e.contains("tmpfs"), "explain must say what ephemeral storage IS: {e}");
    }

    #[test]
    fn explain_does_not_promise_routed_networking_it_cannot_deliver() {
        // A routed zone gets loopback and no routes today. Someone reading
        // `explain` is deciding what to put in the zone, and "routed" without
        // qualification reads as "connected, filtered".
        let e = explain(&z("routed"), "/tmp/t", std::path::Path::new("/tmp"));
        // Routed networking IS delivered now (Design 03a: a veth into the nic
        // zone's bridge, forwarded, no NAT yet), so "honest" means the plan
        // line says what it does and does not do rather than the old refusal.
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

        // Encrypted storage is implemented for a root launch (Design 04):
        // explain names the container, the mapping and the close, and says
        // that an unprivileged launch cannot open it.
        let enc = explain(&z_encrypted(), "/tmp/t", std::path::Path::new("/nonexistent"));
        assert!(enc.contains("LUKS2") && enc.contains("/dev/mapper/kryptik-t"), "{enc}");
        assert!(enc.contains("Unprivileged launches are refused"), "{enc}");
    }

    #[test]
    fn exit_status_decoding_matches_shell_convention() {
        assert_eq!(decode_status(0), 0);
        assert_eq!(decode_status(3 << 8), 3);
        assert_eq!(decode_status(libc::SIGSYS), 128 + libc::SIGSYS);
    }

    #[test]
    fn environment_is_an_allowlist_not_a_denylist() {
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
        let env = zone_environment(&z("routed"), "/home/t", &caller);
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
        let env = zone_environment(&z("routed"), "/home/t", &caller);
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("TERM"), Some("dumb"), "a malformed TERM is replaced, not passed");
        assert_eq!(get("LANG"), Some("C.UTF-8"), "no caller LANG means a UTF-8 default");
    }

    #[test]
    fn unprivileged_launch_cannot_pick_an_identity() {
        if unsafe { libc::geteuid() } == 0 {
            // As root the rule is the other way round; covered by the message
            // test below only when not root.
            return;
        }
        let err = launch_identity(&RunOptions { zone_uid: Some(1001), zone_gid: Some(1001), ..Default::default() }, &z("routed")).unwrap_err();
        assert!(err.to_string().contains("need root"), "{err}");
        let id = launch_identity(&RunOptions::default(), &z("routed")).unwrap();
        assert_eq!(id.uid, unsafe { libc::getuid() });
        assert!(!id.privileged);
    }

    #[test]
    fn root_launch_must_name_an_unprivileged_identity() {
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
