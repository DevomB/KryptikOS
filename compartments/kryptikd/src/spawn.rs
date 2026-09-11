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

use crate::isolate;
use crate::landlock;
use crate::rootfs;
use crate::seccomp;
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
#[derive(Debug, Default, Clone, Copy)]
pub struct RunOptions {
    /// Host uid the zone's root maps to. Only meaningful, and only accepted,
    /// when kryptikd itself runs as root.
    pub zone_uid: Option<u32>,
    pub zone_gid: Option<u32>,
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
        let b = [1u8];
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
        let mut b = [0u8];
        loop {
            let r = unsafe { libc::read(self.read, b.as_mut_ptr() as *mut libc::c_void, 1) };
            if r == 1 {
                return Ok(());
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

fn launch_identity(opts: &RunOptions) -> Result<Identity, SpawnError> {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        match (opts.zone_uid, opts.zone_gid) {
            (Some(uid), Some(gid)) if uid != 0 && gid != 0 => Ok(Identity { uid, gid, privileged: true }),
            _ => Err(SpawnError::Setup(
                "kryptikd is running as root. Mapping the zone's root to host uid 0 \
                 would make every permission check inside the zone succeed as the \
                 real superuser on everything the zone can reach. Pass \
                 --zone-uid UID --zone-gid GID (both non-zero) to map the zone to a \
                 dedicated unprivileged host identity, or run kryptikd unprivileged."
                    .into(),
            )),
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
    let experimental = std::env::var("KRYPTIK_EXPERIMENTAL").as_deref() == Ok("1");
    let mut unsupported: Vec<String> = Vec::new();
    match zone.storage {
        StorageMode::Encrypted => unsupported.push(
            "storage.mode = \"encrypted\": per-zone encrypted volumes are NOT IMPLEMENTED; \
             the zone would run on a plain directory while its configuration says otherwise"
                .into(),
        ),
        StorageMode::Ephemeral => unsupported.push(
            "storage.mode = \"ephemeral\": zone data is NOT yet wiped on stop".into(),
        ),
    }
    if zone.seccomp.is_some() || zone.landlock.is_some() {
        unsupported.push(
            "[policy]: per-zone seccomp/landlock files are NOT yet applied; the shared base \
             policy would be used"
                .into(),
        );
    }
    if zone.memory_max.is_some() || zone.pids_max.is_some() {
        unsupported.push(
            "[limits]: resource limits are NOT yet applied; no cgroup would be created".into(),
        );
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

    let id = launch_identity(opts)?;

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

    // ready: child -> parent, "I have unshared"
    // mapped: parent -> child, "your id maps are written"
    let ready = SyncPipe::new()?;
    let mapped = SyncPipe::new()?;

    let parent_pid = unsafe { libc::getpid() };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(SpawnError::Syscall { call: "fork", errno: errno() });
    }

    if pid == 0 {
        // --- intermediate ------------------------------------------------------
        ready.close_read();
        mapped.close_write();
        let rc = intermediate_main(zone, rootfs, argv, &id, parent_pid, &ready, &mapped);
        // Never return: this process must not run the parent's cleanup.
        unsafe { libc::_exit(rc) };
    }

    // --- parent --------------------------------------------------------------
    ready.close_write();
    mapped.close_read();
    install_forwarding(pid, false);

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

    // Map the child's root to the zone identity. This is what makes "root
    // inside the zone" mean root in a namespace that owns nothing outside it.
    if let Err(e) = isolate::write_id_maps(pid, id.uid, id.gid) {
        // Close our end so the child reads EOF and dies rather than blocking.
        mapped.close_write();
        let _ = wait_for(pid);
        return Err(SpawnError::Setup(format!("id maps: {e}")));
    }

    mapped.signal();
    mapped.close_write();

    let status = wait_for(pid)?;
    Ok(decode_status(status))
}

fn decode_status(status: libc::c_int) -> i32 {
    if (status & 0x7f) == 0 {
        (status >> 8) & 0xff
    } else {
        // Killed by a signal; report it the way a shell does.
        128 + (status & 0x7f)
    }
}

/// The intermediate process: enters the namespaces, becomes root there, and
/// supervises pid 1 of the zone. Returns the exit code to mirror.
fn intermediate_main(
    zone: &Zone,
    rootfs: &str,
    argv: &[String],
    id: &Identity,
    parent_pid: libc::pid_t,
    ready: &SyncPipe,
    mapped: &SyncPipe,
) -> i32 {
    macro_rules! bail {
        ($($arg:tt)*) => {{
            eprintln!("kryptikd[zone {}]: {}", zone.name, format!($($arg)*));
            return 125;
        }};
    }

    rootfs::ensure_stdio();

    // 1. Identity. A privileged kryptikd switches to the zone's host identity
    //    BEFORE creating the user namespace, dropping every supplementary
    //    group on the way; the parent, still root, may then map any uid.
    //    Unprivileged, the kernel only lets us map our own uid, and
    //    setgroups needs CAP_SETGID we do not have - so the host groups come
    //    along. They are named rather than hidden.
    if id.privileged {
        if let Err(e) = isolate::drop_supplementary_groups() {
            bail!("setgroups: {e}");
        }
        if unsafe { libc::setresgid(id.gid, id.gid, id.gid) } < 0 {
            bail!("setresgid({}): {}", id.gid, io::Error::last_os_error());
        }
        if unsafe { libc::setresuid(id.uid, id.uid, id.uid) } < 0 {
            bail!("setresuid({}): {}", id.uid, io::Error::last_os_error());
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

    // 2. Die with the parent. Set after the identity switch so no credential
    //    change can clear it, and checked against the recorded parent pid to
    //    close the window in which the parent died before the prctl.
    if let Err(e) = isolate::die_with_parent() {
        bail!("prctl(PR_SET_PDEATHSIG): {e}");
    }
    if unsafe { libc::getppid() } != parent_pid {
        return 125;
    }

    let flags = isolate::namespace_flags(zone);

    // 3. Enter the new namespaces.
    if let Err(e) = isolate::unshare_namespaces(flags) {
        bail!("unshare: {e}");
    }

    // 4. Tell the parent we are in the new namespace, then wait for it to
    //    write uid_map/gid_map. Until those exist we are nobody (65534) and
    //    cannot mount anything or become root. EOF here means the parent
    //    failed or died; either way there is no zone to build.
    ready.signal();
    ready.close_write();
    if let Err(e) = mapped.wait() {
        bail!("parent did not complete the id mapping: {e}");
    }
    mapped.close_read();

    // 5. Become root in the new user namespace.
    if unsafe { libc::setresuid(0, 0, 0) } < 0 {
        bail!("setresuid: {}", io::Error::last_os_error());
    }
    if unsafe { libc::setresgid(0, 0, 0) } < 0 {
        bail!("setresgid: {}", io::Error::last_os_error());
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
        let rc = zone_init(zone, rootfs, argv, flags);
        unsafe { libc::_exit(rc) };
    }

    // Supervise pid 1 of the zone: forward signals, SIGKILL it if it ignores
    // them (pid 1 of a namespace ignores every signal from inside it that it
    // has no handler for, so a forwarded SIGTERM alone may do nothing), and
    // mirror its exit code.
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
fn zone_init(zone: &Zone, rootfs: &str, argv: &[String], flags: libc::c_int) -> i32 {
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
    let home = match rootfs::pivot_into(rootfs, &zone.name) {
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
    if let Err(e) = landlock::confine_pivoted_zone(&home) {
        bail!("landlock: {e}");
    }

    // 12. Close every descriptor above stderr.
    //
    //     The other half of the inherited-descriptor escape. pivot_root does
    //     NOT fix this on its own: a descriptor that was already open keeps
    //     working no matter what the mount namespace now looks like.
    rootfs::close_inherited_fds();

    // 13. An explicit environment. Nothing from the caller reaches the zone
    //     unless it is on the allowlist and looks like what it claims to be.
    let caller: Vec<(String, String)> = std::env::vars().collect();
    let env = zone_environment(zone, &home, &caller);
    for (k, _) in std::env::vars_os().collect::<Vec<_>>() {
        std::env::remove_var(k);
    }
    for (k, v) in &env {
        std::env::set_var(k, v);
    }

    // 14. Syscall filtering, LAST. It must come after every privileged setup
    //     step above, because mount() and friends are not in the allowlist -
    //     installing the filter earlier would kill the zone during its own
    //     construction.
    if let Err(e) = seccomp::confine_zone() {
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
    env
}

/// Describe what starting this zone would do, without doing it.
pub fn explain(zone: &Zone, rootfs: &str) -> String {
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
            "encrypted volume {} (NOT YET IMPLEMENTED - using a plain directory)",
            zone.volume.as_deref().unwrap_or("?")
        ),
        StorageMode::Ephemeral => "ephemeral (NOT YET IMPLEMENTED - using a plain directory)".into(),
    };

    let home = rootfs::zone_home(&zone.name);
    let rules: Vec<String> = landlock::zone_rules(&home)
        .iter()
        .map(|r| format!("{:<12} {}", r.path, landlock::describe_access(r.access)))
        .collect();

    format!(
        "zone       {}\n\
         namespaces {}\n\
         hostname   {}\n\
         data dir   {} (visible inside as {})\n\
         storage    {}\n\
         root       tmpfs, read-only; {} bound read-only recursively\n\
         /etc       synthesized (passwd, group, hosts, nsswitch) + read-only {}\n\
         /dev       {} + shm, pts\n\
         landlock   ABI >= {}, rules:\n           {}\n\
         env        {} + passthrough of {}\n\
         seccomp    default-deny, {} syscalls allowed, argument rules on {:?}",
        zone.name,
        ns.join(", "),
        zone.name,
        rootfs,
        home,
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
        seccomp::BASE_ALLOWLIST.len(),
        seccomp::ARG_RULES,
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
             [storage]\nmode = \"ephemeral\"\n[ui]\nborder_color = \"#123456\"\n"
        ))
        .unwrap()
    }

    #[test]
    fn rootfs_path_is_under_the_base() {
        assert_eq!(zone_rootfs(&z("routed"), "/var/lib/kryptik/zones"),
                   "/var/lib/kryptik/zones/t");
    }

    #[test]
    fn explain_names_the_namespaces_and_is_honest_about_storage() {
        let e = explain(&z("none"), "/tmp/t");
        assert!(e.contains("user"), "{e}");
        assert!(e.contains("net"), "{e}");
        // Storage is not implemented, and explain must say so rather than
        // implying a zone gets an encrypted volume today.
        assert!(e.contains("NOT YET IMPLEMENTED"), "{e}");
        assert!(e.contains("/home/t"), "{e}");
        assert!(e.contains("read+exec"), "{e}");
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
        assert!(!env.iter().any(|(k, _)| k == "TERM"));
    }

    #[test]
    fn unprivileged_launch_cannot_pick_an_identity() {
        if unsafe { libc::geteuid() } == 0 {
            // As root the rule is the other way round; covered by the message
            // test below only when not root.
            return;
        }
        let err = launch_identity(&RunOptions { zone_uid: Some(1001), zone_gid: Some(1001) }).unwrap_err();
        assert!(err.to_string().contains("need root"), "{err}");
        let id = launch_identity(&RunOptions::default()).unwrap();
        assert_eq!(id.uid, unsafe { libc::getuid() });
        assert!(!id.privileged);
    }

    #[test]
    fn root_launch_must_name_an_unprivileged_identity() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        assert!(launch_identity(&RunOptions::default()).is_err());
        assert!(launch_identity(&RunOptions { zone_uid: Some(0), zone_gid: Some(0) }).is_err());
        let id = launch_identity(&RunOptions { zone_uid: Some(100000), zone_gid: Some(100000) }).unwrap();
        assert!(id.privileged);
    }
}
