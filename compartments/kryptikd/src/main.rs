//! kryptikd — Kryptik compartment manager.
//!
//! Owns zone lifecycle. Runs privileged in zone 0 (ADR-003) and is the only
//! process permitted to create zones or move data between them.
//!
//! STATUS: implemented here are zone definition parsing and validation, kernel
//! capability probing, the namespace, Landlock, seccomp and cgroup primitives
//! the isolation exit test attacks, the launch path (`run`, `stop`, the
//! registry, `gc`), the net zone's topology, per-zone LUKS2 volumes, the
//! brokered clipboard and file-transfer channels with their consent path, and
//! `serve`, the launch daemon. The per-zone Wayland proxy is the separate
//! compositor workspace. Anything not built is refused with an explicit error
//! rather than a silent no-op - a compartment manager that pretends to isolate
//! is worse than one that refuses to start.

mod broker;
mod caps;
mod cgroup;
mod consent;
mod isolate;
mod landlock;
mod netlink;
mod netzone;
mod policy;
mod registry;
mod rootfs;
mod seccomp;
mod serve;
mod spawn;
mod time;
mod volume;
mod wifi;
mod zone;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use isolate::KernelSupport;
use zone::Zone;

const DEFAULT_ZONE_DIR: &str = "/etc/kryptik/zones";

fn usage() -> &'static str {
    "kryptikd — Kryptik compartment manager

USAGE:
    kryptikd check [--zones DIR]      verify kernel support and validate zones
                   [--target]         and require what a Kryptik kernel must have:
                                      root, unprivileged userns restricted, cgroup2
                                      with memory+pids, every zone with [identity]
    kryptikd list  [--zones DIR]      list configured zones
    kryptikd show  NAME [--zones DIR]
    kryptikd explain NAME             what starting this zone would do
    kryptikd run NAME -- CMD [ARGS]   create the zone and run CMD inside it
    kryptikd stop NAME [--now]        stop a running zone (--now = SIGKILL)
    kryptikd status NAME              running, stale or absent
    kryptikd list --running           the zones the registry knows about
    kryptikd gc                       reclaim stale entries and empty cgroups
    kryptikd clipboard move FROM TO   the zone 0 gesture: give TO a copy of FROM's
                                      clipboard payload (both zones running)
    kryptikd serve [--rootfs DIR]     the launch daemon the desktop session talks
                   [--socket PATH]    to (root; --socket PATH runs a developer
                   [--group G]        instance that serves only your own uid)
                   [--proxy-exe P] [--wifi-dir DIR]
    kryptikd wifi list                the net zone's Wi-Fi networks, SSIDs only
    kryptikd wifi add SSID            add one, or replace its passphrase; the
                                      passphrase is read from stdin, never argv
    kryptikd wifi forget SSID         remove one
                   [--wifi-dir DIR]   (the session does this through `kryptik
                                      wifi` and the launch daemon; this is root's
                                      path and the tests')
    kryptikd time floor               at boot: a clock that reads earlier than this
                                      system was built is set to the build date
    kryptikd time status              the clock, the floor, and what was last done to it

    --rootfs DIR   base directory for zone data (default: /var/lib/kryptik/zones);
                   the zone sees its own directory as /home/NAME
    --wifi-dir DIR the directory holding the net zone's wpa_supplicant.conf
                   (default: /var/lib/kryptik/wifi); a nic zone gets the file
                   read-only at /etc/wpa_supplicant.conf when it exists
    --zone-uid N   host uid/gid the zone's root maps to. Required, and only
    --zone-gid N   accepted, when kryptikd itself runs as root.
    --auto-approve-transfers
                   development flag: approve every file this zone offers to
                   another zone without asking the person through the chrome
                   (/run/kryptik-consent); warns, for tests without a session
    --wayland-socket P   the zone's proxy socket, bound at /run/kryptik/wayland-0
    --wayland-inode D:I  ... and the (device, inode) it must be, or the launch fails
    --passphrase-fd N    an encrypted zone's passphrase, read from descriptor N
    --passphrase-file F  ... or from file F (root, tests); never on the command line
    --ready-fd N         written `ready` and closed once the zone's pid 1 exists
                         (the launch daemon passes all three; see `serve`)

Only descriptors 0, 1 and 2 reach the zone; the environment is rebuilt from
an allowlist (see `kryptikd explain NAME`).

    kryptikd volume init|passwd|backup-header|restore-header|status NAME
                                      an encrypted zone's LUKS2 volume (root;
                                      the passphrase comes on a descriptor or
                                      the terminal, never on a command line)

Transfers are a zone verb on the broker socket, sent by the zone that offers
the file (docs/design/broker.md), not a zone 0 command; the person answers through
the chrome."
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    }

    let zone_dir = zone_dir_from(&args);

    match args[0].as_str() {
        "check" => cmd_check(&zone_dir, args.iter().any(|a| a == "--target")),
        "list" if args.iter().any(|a| a == "--running") => cmd_list_running(),
        "list" => cmd_list(&zone_dir),
        "show" => match args.get(1) {
            Some(name) if !name.starts_with("--") => cmd_show(&zone_dir, name),
            _ => {
                eprintln!("show: expected a zone name");
                ExitCode::from(2)
            }
        },
        // kryptikd confine-test ROOTFS TARGET
        //
        // Confines this process to ROOTFS with Landlock, then attempts to read
        // TARGET. Used by the isolation exit test to prove requirements 2
        // and 4 rather than assert them.
        //
        //   exit 0  -> the read SUCCEEDED (confinement failed)
        //   exit 4  -> the read was BLOCKED (confinement worked)
        //   exit 1  -> could not confine at all
        "confine-test" => {
            let Some(root) = args.get(1) else {
                eprintln!("confine-test: expected ROOTFS TARGET");
                return ExitCode::from(2);
            };
            let Some(target) = args.get(2) else {
                eprintln!("confine-test: expected a TARGET path to try reading");
                return ExitCode::from(2);
            };

            // Sanity: the read must succeed BEFORE confinement, or a blocked
            // read afterwards proves nothing (the file might simply not exist).
            if std::fs::read(target).is_err() {
                eprintln!("confine-test: {target} is unreadable even before confinement");
                return ExitCode::from(2);
            }

            if let Err(e) = landlock::confine_to_zone(
                root,
                &["/usr", "/lib", "/lib64", "/bin", "/etc"],
            ) {
                eprintln!("confine-test: confinement failed: {e}");
                return ExitCode::FAILURE;
            }

            match std::fs::read(target) {
                Ok(_) => {
                    eprintln!("confine-test: READ SUCCEEDED after confinement");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("confine-test: read blocked ({})", e.kind());
                    ExitCode::from(4)
                }
            }
        }
        // kryptikd seccomp-test SYSCALL
        //
        // Forks; the child installs the zone seccomp filter and then makes the
        // named syscall. The parent reports how the child ended. Used by the
        // adversarial test to prove syscalls are actually killed rather than
        // assert that a filter was installed.
        //
        //   exit 0 -> syscall completed (NOT blocked)
        //   exit 5 -> child killed by SIGSYS (blocked, as intended)
        //   exit 1 -> could not install the filter
        // kryptikd seccomp-test PROBE
        //
        // PROBE may also name an argument-rule probe rather than a syscall:
        //   clone-newuser      clone(CLONE_NEWUSER)     -> expect SIGSYS   (exit 5)
        //   clone3             clone3()                 -> expect ENOSYS   (exit 7)
        //   socket-vsock       socket(AF_VSOCK)         -> expect EAFNOSUPPORT (exit 7)
        //   socket-netlink-nf  socket(NETLINK_NETFILTER)-> expect EAFNOSUPPORT (exit 7)
        //   socket-inet        socket(AF_INET)          -> expect success  (exit 0)
        //   ioctl-tiocsti      ioctl(0, TIOCSTI)        -> expect SIGSYS   (exit 5)
        "seccomp-test" => {
            let Some(name) = args.get(1) else {
                eprintln!("seccomp-test: expected a syscall name");
                return ExitCode::from(2);
            };
            if let Some(code) = cmd_seccomp_probe(name) {
                return code;
            }
            let Some(nr) = seccomp::syscall_by_name(name) else {
                eprintln!("seccomp-test: unknown syscall {name:?}");
                return ExitCode::from(2);
            };
            cmd_seccomp_test(name, nr)
        }
        "explain" => match args.get(1) {
            Some(name) if !name.starts_with("--") => cmd_explain(&zone_dir, name, &args),
            _ => {
                eprintln!("explain: expected a zone name");
                ExitCode::from(2)
            }
        },
        "run" => cmd_run(&zone_dir, &args),
        // kryptikd seccomp-trace -- CMD
        //
        // Runs CMD under the zone filter with the deny action set to TRAP
        // rather than KILL, and reports which syscall was refused. This is how
        // a zone policy gets debugged: a KILL tells you the zone died, a TRAP
        // tells you what it died on.
        "seccomp-trace" => {
            let Some(sep) = args.iter().position(|a| a == "--") else {
                eprintln!("seccomp-trace: expected `-- COMMAND`");
                return ExitCode::from(2);
            };
            let cmd: Vec<String> = args[sep + 1..].to_vec();
            if cmd.is_empty() {
                eprintln!("seccomp-trace: no command after `--`");
                return ExitCode::from(2);
            }
            cmd_seccomp_trace(&cmd)
        }
        "stop" => match args.get(1) {
            Some(name) if !name.starts_with("--") => {
                cmd_stop(name, args.iter().any(|a| a == "--now"))
            }
            _ => {
                eprintln!("stop: expected a zone name");
                ExitCode::from(2)
            }
        },
        "status" => match args.get(1) {
            Some(name) if !name.starts_with("--") => cmd_status(name),
            _ => {
                eprintln!("status: expected a zone name");
                ExitCode::from(2)
            }
        },
        "gc" => cmd_gc(),
        "volume" => cmd_volume(&zone_dir, &args),
        "serve" => serve::cmd_serve(&zone_dir, &args),
        "wifi" => cmd_wifi(&zone_dir, &args),
        "time" => cmd_time(&args),
        "clipboard" => cmd_clipboard(&args),
        "transfer" => {
            eprintln!(
                "kryptikd: 'transfer' is a zone verb on the broker socket, sent by the zone\n\
                 that offers the file (docs/design/broker.md); zone 0 has no transfer command."
            );
            ExitCode::from(2)
        }
        "-h" | "--help" | "help" => {
            println!("{}", usage());
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("kryptikd: unknown command {other:?}\n\n{}", usage());
            ExitCode::from(2)
        }
    }
}

/// Stop a running zone.
///
/// Signals the LAUNCHER, not the zone. The launcher forwards to the
/// intermediate, which forwards to pid 1 and escalates to SIGKILL after five
/// seconds - the supervision path that already exists and is already tested.
/// A second teardown path would be a second thing to get wrong.
///
/// The recorded pid is only signalled when both the pid AND its start time
/// still match. Pids are reused, and a stale entry's pid may belong to an
/// unrelated process by now; signalling it would be far worse than leaving a
/// directory behind.
fn cmd_stop(name: &str, now: bool) -> ExitCode {
    let mut st = match registry::state(name) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("kryptikd: {e}");
            return ExitCode::FAILURE;
        }
    };

    // "Still starting" is a window of a few milliseconds between claim() and
    // the fork that records the launcher pid. A script that does `run &` then
    // `stop` lands in it often enough to be annoying, and the answer is not to
    // report failure but to look again.
    if matches!(st, registry::State::Running { launcher: None, .. }) {
        std::thread::sleep(std::time::Duration::from_millis(100));
        st = match registry::state(name) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("kryptikd: {e}");
                return ExitCode::FAILURE;
            }
        };
    }

    match st {
        registry::State::Absent => {
            eprintln!("kryptikd: zone {name:?} is not running");
            ExitCode::FAILURE
        }
        registry::State::Stale { launcher, .. } => {
            let pid = launcher.map(|l| l.pid).unwrap_or(-1);
            if let Err(e) = registry::reclaim(name) {
                eprintln!("kryptikd: reclaiming {name:?}: {e}");
                return ExitCode::FAILURE;
            }
            println!("zone {name:?} was not running (stale entry from pid {pid} reclaimed)");
            ExitCode::SUCCESS
        }
        registry::State::Running { launcher: None, .. } => {
            eprintln!(
                "kryptikd: zone {name:?} is still starting (no launcher pid recorded yet); \
                 try again in a moment"
            );
            ExitCode::FAILURE
        }
        registry::State::Running { launcher: Some(l), .. } => {
            if !l.still_alive() {
                // The lock said live and the stamp says otherwise: the
                // launcher died between the two reads. Reclaim rather than
                // signal a pid that is no longer the process we meant.
                let _ = registry::reclaim(name);
                println!("zone {name:?} exited while stopping it");
                return ExitCode::SUCCESS;
            }
            let sig = if now { libc::SIGKILL } else { libc::SIGTERM };
            if unsafe { libc::kill(l.pid, sig) } < 0 {
                eprintln!(
                    "kryptikd: signalling launcher {}: {}",
                    l.pid,
                    std::io::Error::last_os_error()
                );
                return ExitCode::FAILURE;
            }

            // Wait for the entry to go. The launcher removes it on the way
            // out, so its disappearance is the zone actually being gone -
            // not a timer we hope is long enough. The bound is the 5 s
            // escalation plus teardown.
            for _ in 0..160 {
                match registry::state(name) {
                    Ok(registry::State::Absent) => {
                        println!("zone {name:?} stopped");
                        return ExitCode::SUCCESS;
                    }
                    Ok(registry::State::Stale { .. }) => {
                        let _ = registry::reclaim(name);
                        println!("zone {name:?} stopped");
                        return ExitCode::SUCCESS;
                    }
                    _ => {}
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            eprintln!(
                "kryptikd: zone {name:?} did not stop: launcher {} is still running. \
                 This should not happen; report it.",
                l.pid
            );
            ExitCode::from(2)
        }
    }
}

/// The cross-zone paste is a zone 0 gesture: no zone can ask for
/// another zone's payload - the verb does not exist on a zone's socket - so
/// the only way a payload moves is this command, run by the operator (or the
/// compositor on their behalf) in zone 0. Both zones must be running: the
/// payload lives in the running zone's registry entry and nowhere else.
fn cmd_clipboard(args: &[String]) -> ExitCode {
    let (from, to) = match (args.get(1).map(|s| s.as_str()), args.get(2), args.get(3)) {
        (Some("move"), Some(f), Some(t)) if !f.starts_with("--") && !t.starts_with("--") => (f.as_str(), t.as_str()),
        _ => {
            eprintln!("usage: kryptikd clipboard move FROM TO");
            return ExitCode::from(2);
        }
    };
    if from == to {
        eprintln!("clipboard: FROM and TO are the same zone");
        return ExitCode::from(2);
    }
    for z in [from, to] {
        match registry::state(z) {
            Ok(registry::State::Running { .. }) => {}
            Ok(registry::State::Stale { .. }) => {
                eprintln!("clipboard: zone {z:?} is not running (stale entry)");
                return ExitCode::from(1);
            }
            Ok(registry::State::Absent) => {
                eprintln!("clipboard: zone {z:?} is not running");
                return ExitCode::from(1);
            }
            Err(e) => {
                eprintln!("clipboard: {e}");
                return ExitCode::from(1);
            }
        }
    }
    match broker::clipboard_move(&registry::entry_dir(from), &registry::entry_dir(to)) {
        Ok((mime, len)) => {
            println!("clipboard: moved {len} bytes of {mime} from {from} to {to}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("clipboard: {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_status(name: &str) -> ExitCode {
    match registry::state(name) {
        Ok(registry::State::Absent) => {
            println!("{name}  absent");
            ExitCode::SUCCESS
        }
        Ok(registry::State::Stale { launcher, cgroup }) => {
            println!(
                "{name}  stale  (launcher {} is gone{})",
                launcher.map(|l| l.pid.to_string()).unwrap_or_else(|| "?".into()),
                cgroup.map(|c| format!(", cgroup {c}")).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Ok(registry::State::Running { launcher, init, cgroup, started }) => {
            // The last word is asked of the kernel, not recorded: whether the
            // zone's pid 1 runs under a core-scheduling cookie of its own
            // (own), under none (none), or on a kernel that has no such
            // thing (unavailable). Nothing in /proc shows it.
            println!(
                "{name}  running  launcher {}  init {}  since {}{}{}",
                launcher.map(|l| l.pid.to_string()).unwrap_or_else(|| "starting".into()),
                init.map(|i| i.pid.to_string()).unwrap_or_else(|| "-".into()),
                started,
                cgroup.map(|c| format!("  cgroup {c}")).unwrap_or_default(),
                init.map(|i| format!("  core-sched {}", isolate::core_cookie_word(i.pid))).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("kryptikd: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_list_running() -> ExitCode {
    let names = registry::names();
    if names.is_empty() {
        println!("no zones are running");
        return ExitCode::SUCCESS;
    }
    for n in names {
        let _ = cmd_status(&n);
    }
    ExitCode::SUCCESS
}

/// Reclaim every stale entry, and every empty per-zone cgroup.
///
/// Safe by construction rather than by bookkeeping: an entry is stale only if
/// its lock can be taken, and `rmdir` on a cgroup with live processes fails
/// with EBUSY - so the kernel itself refuses to let this remove a live zone's
/// cgroup, whatever the registry says.
fn cmd_gc() -> ExitCode {
    let mut reclaimed = 0usize;
    for n in registry::names() {
        if let Ok(registry::State::Stale { .. }) = registry::state(&n) {
            match registry::reclaim(&n) {
                Ok(()) => {
                    println!("reclaimed stale entry for zone {n:?}");
                    reclaimed += 1;
                }
                Err(e) => eprintln!("kryptikd: reclaiming {n:?}: {e}"),
            }
        }
    }
    let swept = cgroup::sweep_now();
    // Volumes whose launcher died without closing them: a
    // mapping with no running zone is plaintext nobody is using. Unmount
    // and close it; the ext4 gets fsck -p at the next open.
    let mut closed = 0usize;
    let base = DEFAULT_ROOTFS_BASE.to_string();
    for z in volume::mappings() {
        if let Ok(registry::State::Running { .. }) = registry::state(&z) {
            continue;
        }
        let mnt = volume::mountpoint_for(Path::new(&base), &z).display().to_string();
        match volume::close_mapping(&z, &mnt) {
            Ok(()) => {
                println!("closed the volume of zone {z:?}, which had no running launcher");
                closed += 1;
            }
            Err(e) => eprintln!("kryptikd: closing zone {z:?}'s volume: {e}"),
        }
    }
    if reclaimed == 0 && swept == 0 && closed == 0 {
        println!("nothing to reclaim");
    } else if swept > 0 {
        println!("removed {swept} empty zone cgroup(s)");
    }
    ExitCode::SUCCESS
}

fn zone_dir_from(args: &[String]) -> PathBuf {
    args.iter()
        .position(|a| a == "--zones")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ZONE_DIR))
}

fn cmd_check(dir: &Path, target: bool) -> ExitCode {
    let mut failed = false;
    let euid = unsafe { libc::geteuid() };
    if target {
        println!("target contract: required (--target)");
        if euid != 0 {
            eprintln!("  --target must run as root: zones on a Kryptik kernel are created by a root kryptikd");
            failed = true;
        }
    }

    println!("kernel support:");
    let s = KernelSupport::probe();
    let yn = |b: bool| if b { "yes" } else { "NO" };
    println!("  user namespaces  {}", yn(s.user_ns));
    println!("  pid namespaces   {}", yn(s.pid_ns));
    println!("  net namespaces   {}", yn(s.net_ns));
    println!("  cgroup v2        {}", yn(s.cgroup_v2));
    println!("  seccomp          {}", yn(s.seccomp));
    match s.landlock {
        Some(v) => {
            println!("  landlock         yes (ABI v{v})");
            // Prove a ruleset can actually be built, not just that the syscall
            // answers a version query. The struct layouts are size-sensitive
            // and a mismatch fails here rather than at zone start.
            match landlock::Ruleset::new() {
                Ok(_) => println!("  landlock ruleset creatable"),
                Err(e) => {
                    eprintln!("  landlock ruleset FAILED: {e}");
                    failed = true;
                }
            }
        }
        None => println!("  landlock         NO"),
    }

    // Prove the seccomp program actually builds and installs in a child, not
    // merely that the kernel reports seccomp support.
    //
    // A self-test that could not run is a failure, not a pass: this command
    // gates a kernel as fit to run zones, and "the filter was not verified"
    // reported as success is the exact outcome the paragraph below argues
    // against. (It used to fall through to success, and current_exe()
    // failing produced Command::new(""), which lands in that same arm.)
    let self_test = std::env::current_exe()
        .map_err(|e| format!("current_exe: {e}"))
        .and_then(|exe| {
            std::process::Command::new(exe)
                .args(["seccomp-test", "getpid"])
                .output()
                .map_err(|e| e.to_string())
        });
    match self_test {
        Ok(o) if o.status.code() == Some(0) => {
            println!("  seccomp filter   builds and permits allowed calls");
        }
        Ok(o) => {
            eprintln!("  seccomp filter   FAILED (exit {:?})", o.status.code());
            failed = true;
        }
        Err(e) => {
            eprintln!("  seccomp filter   FAILED: could not self-test: {e}");
            failed = true;
        }
    }

    // The privileged launch contract: on the target, only a process with CAP_SYS_ADMIN in the
    // initial namespace may create a user namespace. Read the knob, then
    // PROVE it by trying as uid 65534 (or as ourselves when unprivileged).
    let knob = isolate::userns_restriction_sysctl();
    match isolate::probe_userns_restriction() {
        Ok(true) => println!(
            "  unpriv userns    restricted (EPERM{})",
            knob.map(|(_, k)| format!("; {k}")).unwrap_or_default()
        ),
        Ok(false) => {
            println!(
                "  unpriv userns    ALLOWED{} - a developer kernel, not the target",
                knob.map(|(_, k)| format!(" ({k})")).unwrap_or_default()
            );
            if target {
                eprintln!("  --target: this kernel lets unprivileged processes create user namespaces");
                failed = true;
            }
        }
        Err(e) => {
            println!("  unpriv userns    could not probe: {e}");
            if target {
                failed = true;
            }
        }
    }
    if target {
        // The controllers cgroup supervision needs must be delegable from the root; the actual
        // creation is tried by every launch, this only names a missing one.
        let ctl = std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers").unwrap_or_default();
        for c in ["memory", "pids"] {
            if !ctl.split_whitespace().any(|x| x == c) {
                eprintln!("  --target: cgroup v2 root does not offer the {c} controller");
                failed = true;
            }
        }
        match s.landlock {
            Some(v) if v >= landlock::MIN_ABI => {}
            _ => {
                eprintln!("  --target: landlock ABI {} or newer is required", landlock::MIN_ABI);
                failed = true;
            }
        }
    }

    let missing = s.missing();
    if !missing.is_empty() {
        println!();
        eprintln!("MISSING: {}", missing.join(", "));
        eprintln!(
            "The zone model depends on all of the above. Kryptik will not start\n\
             zones on a kernel lacking any of them - a zone missing one control\n\
             is not a weaker zone, it is a zone that does not isolate."
        );
        failed = true;
    }

    println!();
    println!("zones in {}:", dir.display());
    match zone::load_all(dir) {
        Ok(zones) => {
            for z in &zones {
                let net = match z.network {
                    zone::NetworkMode::None => "no network stack",
                    zone::NetworkMode::Routed => "routed via nic zone",
                    zone::NetworkMode::Nic => "HOLDS PHYSICAL NIC",
                };
                let ident = match z.uid_base {
                    Some(b) => format!("uid_base {b}"),
                    None => "no [identity]".to_string(),
                };
                println!("  {:<10} {:<20} {:<16} {}", z.name, net, ident, z.border_color);
                if let Some(rel) = &z.seccomp {
                    match policy::load(&policy::resolve(dir, rel)).and_then(|p| p.check_for_zone(z).map(|_| p)) {
                        Ok(p) => {
                            println!("             policy {rel}: {}", p.describe());
                            for w in &p.warnings {
                                println!("             note: {w}");
                            }
                        }
                        Err(e) => {
                            eprintln!("             policy {rel}: {e}");
                            failed = true;
                        }
                    }
                }
                if z.landlock.is_some() {
                    println!("             landlock policy file: not applied (unimplemented; refused without the override)");
                }
                if target && z.uid_base.is_none() {
                    eprintln!(
                        "  --target: zone {:?} declares no [identity] uid_base; a root launch cannot start it",
                        z.name
                    );
                    failed = true;
                }
            }
            println!();
            println!("  {} zone(s), invariants hold", zones.len());
        }
        Err(e) => {
            eprintln!("  zone configuration error: {e}");
            failed = true;
        }
    }

    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn cmd_list(dir: &Path) -> ExitCode {
    match zone::load_all(dir) {
        Ok(zones) => {
            for z in zones {
                println!("{}", z.name);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("kryptikd: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_show(dir: &Path, name: &str) -> ExitCode {
    let zones = match zone::load_all(dir) {
        Ok(z) => z,
        Err(e) => {
            eprintln!("kryptikd: {e}");
            return ExitCode::FAILURE;
        }
    };

    let Some(z) = zones.into_iter().find(|z| z.name == name) else {
        eprintln!("kryptikd: no zone named {name:?}");
        return ExitCode::FAILURE;
    };

    println!("zone         {}", z.name);
    println!("description  {}", z.description);
    println!("network      {:?}", z.network);
    if let Some(b) = &z.bridge {
        println!("bridge       {b}");
    }
    println!("storage      {:?}", z.storage);
    if let Some(v) = &z.volume {
        println!("volume       {v}");
    }
    println!("border       {}", z.border_color);
    if let Some(m) = &z.memory_max {
        println!("memory_max   {m}");
    }
    if let Some(p) = z.pids_max {
        println!("pids_max     {p}");
    }

    let flags = isolate::namespace_flags(&z);
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
    println!("namespaces   {}", ns.join(", "));
    println!("seccomp      default-deny, {} syscalls allowed", seccomp::BASE_ALLOWLIST.len());

    if z.is_airgapped() {
        println!();
        println!("This zone has no network stack: its net namespace contains only");
        println!("loopback. That is not a firewall rule - there is no interface.");
    } else {
        // The counterpart, which was missing. A reader who sees a paragraph
        // for an airgapped zone and none for a routed one concludes the routed
        // one is unremarkable - that is, that it works.
        println!();
        println!("network.mode is {:?}, and routed networking is NOT IMPLEMENTED.", z.network);
        println!("This zone gets an empty net namespace: loopback only, no routes,");
        println!("no path out. It is isolated, and it is not connected.");
    }

    ExitCode::SUCCESS
}

const DEFAULT_ROOTFS_BASE: &str = "/var/lib/kryptik/zones";

fn rootfs_base_from(args: &[String]) -> String {
    args.iter()
        .position(|a| a == "--rootfs")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| DEFAULT_ROOTFS_BASE.to_string())
}

fn load_zone(dir: &Path, name: &str) -> Result<Zone, ExitCode> {
    let zones = zone::load_all(dir).map_err(|e| {
        eprintln!("kryptikd: {e}");
        ExitCode::FAILURE
    })?;
    zones.into_iter().find(|z| z.name == name).ok_or_else(|| {
        eprintln!("kryptikd: no zone named {name:?}");
        ExitCode::FAILURE
    })
}

fn cmd_explain(dir: &Path, name: &str, args: &[String]) -> ExitCode {
    let zone = match load_zone(dir, name) {
        Ok(z) => z,
        Err(c) => return c,
    };
    let base = rootfs_base_from(args);
    let rootfs = spawn::zone_rootfs(&zone, &base);
    println!("{}", spawn::explain(&zone, &rootfs, dir));
    ExitCode::SUCCESS
}

/// Argument-rule probes for `seccomp-test`. Returns None when `name` is not
/// a probe (so the plain syscall path runs instead).
fn cmd_seccomp_probe(name: &str) -> Option<ExitCode> {
    // The probe itself, run in the filtered child. Returns the child's exit
    // code: 7 = refused with the intended errno, 0 = completed.
    let probe: fn() -> i32 = match name {
        "clone-newuser" => || unsafe {
            let r = libc::syscall(
                libc::SYS_clone,
                (libc::CLONE_NEWUSER | libc::SIGCHLD) as libc::c_long,
                0usize, 0usize, 0usize, 0usize,
            );
            if r == 0 {
                libc::_exit(0); // we are the child in the nested namespace
            }
            if r > 0 {
                libc::waitpid(r as libc::pid_t, std::ptr::null_mut(), 0);
            }
            0
        },
        "clone3" => || unsafe {
            let r = libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0usize);
            if r < 0 && *libc::__errno_location() == libc::ENOSYS { 7 } else { 0 }
        },
        "socket-vsock" => || unsafe {
            let r = libc::socket(40, libc::SOCK_STREAM, 0);
            if r < 0 && *libc::__errno_location() == libc::EAFNOSUPPORT { 7 } else { 0 }
        },
        "socket-netlink-nf" => || unsafe {
            let r = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, 12);
            if r < 0 && *libc::__errno_location() == libc::EAFNOSUPPORT { 7 } else { 0 }
        },
        "socket-inet" => || unsafe {
            let r = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if r >= 0 { 0 } else { 7 }
        },
        "ioctl-tiocsti" => || unsafe {
            let c = b"x";
            libc::ioctl(0, libc::TIOCSTI as _, c.as_ptr());
            0
        },
        _ => return None,
    };

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        eprintln!("seccomp-test: fork failed");
        return Some(ExitCode::FAILURE);
    }
    if pid == 0 {
        if seccomp::confine_zone().is_err() {
            unsafe { libc::_exit(1) };
        }
        let rc = probe();
        unsafe { libc::_exit(rc) };
    }
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let termsig = spawn::signalled_by(status);
    let exitcode = (status >> 8) & 0xff;
    Some(if termsig == Some(libc::SIGSYS) {
        eprintln!("seccomp-test: {name} killed by SIGSYS (blocked)");
        ExitCode::from(5)
    } else if let Some(sig) = termsig {
        eprintln!("seccomp-test: {name} killed by signal {sig}");
        ExitCode::from(6)
    } else if exitcode == 7 {
        eprintln!("seccomp-test: {name} refused with the intended errno");
        ExitCode::from(7)
    } else if exitcode == 1 {
        eprintln!("seccomp-test: could not install filter");
        ExitCode::FAILURE
    } else {
        eprintln!("seccomp-test: {name} COMPLETED - not blocked");
        ExitCode::SUCCESS
    })
}

fn run_options_from(args: &[String]) -> Result<spawn::RunOptions, String> {
    let num = |flag: &str| -> Result<Option<u32>, String> {
        match args.iter().position(|a| a == flag) {
            None => Ok(None),
            Some(i) => args
                .get(i + 1)
                .and_then(|v| v.parse::<u32>().ok())
                .map(Some)
                .ok_or_else(|| format!("{flag}: expected a numeric id")),
        }
    };
    Ok(spawn::RunOptions {
        zone_uid: num("--zone-uid")?,
        zone_gid: num("--zone-gid")?,
        zones_dir: std::path::PathBuf::new(),
        wifi_dir: wifi_dir_from(args),
        auto_approve_transfers: args.iter().any(|a| a == "--auto-approve-transfers"),
        passphrase_file: args
            .iter()
            .position(|a| a == "--passphrase-file")
            .and_then(|i| args.get(i + 1))
            .map(PathBuf::from),
        passphrase_fd: match args.iter().position(|a| a == "--passphrase-fd") {
            None => None,
            Some(i) => Some(
                args.get(i + 1)
                    .and_then(|v| v.parse::<i32>().ok())
                    .ok_or_else(|| "--passphrase-fd: expected a descriptor number".to_string())?,
            ),
        },
        wayland_socket: args
            .iter()
            .position(|a| a == "--wayland-socket")
            .and_then(|i| args.get(i + 1))
            .map(PathBuf::from),
        wayland_inode: match args.iter().position(|a| a == "--wayland-inode") {
            None => None,
            Some(i) => Some(
                args.get(i + 1)
                    .ok_or_else(|| "--wayland-inode: expected DEV:INO".to_string())?
                    .parse::<serve::InodeId>()
                    .map_err(|e| format!("--wayland-inode: {e}"))?,
            ),
        },
        ready_fd: match args.iter().position(|a| a == "--ready-fd") {
            None => None,
            Some(i) => {
                let fd = args
                    .get(i + 1)
                    .and_then(|v| v.parse::<i32>().ok())
                    .ok_or_else(|| "--ready-fd: expected a descriptor number".to_string())?;
                // Ours alone from here: the zone's command must not inherit it.
                unsafe {
                    let fl = libc::fcntl(fd, libc::F_GETFD);
                    if fl < 0 {
                        return Err(format!("--ready-fd {fd}: not an open descriptor"));
                    }
                    libc::fcntl(fd, libc::F_SETFD, fl | libc::FD_CLOEXEC);
                }
                Some(fd)
            }
        },
    })
}

/// `kryptikd volume` - the encrypted zone's container, outside any launch
/// (docs/design/encrypted-volumes.md). Root only: cryptsetup, dm-crypt and
/// loop devices are.
///
///   volume init NAME [--size 512M] --passphrase-file F [--zone-uid N --zone-gid N]
///   volume passwd NAME --passphrase-file OLD --new-passphrase-file NEW
///   volume backup-header NAME FILE
///   volume restore-header NAME FILE
///   volume status NAME
fn cmd_volume(dir: &Path, args: &[String]) -> ExitCode {
    let sub = args.get(1).map(String::as_str).unwrap_or("");
    let Some(name) = args.get(2).filter(|a| !a.starts_with("--")) else {
        eprintln!("volume: usage: kryptikd volume init|passwd|backup-header|restore-header|status NAME ...");
        return ExitCode::from(2);
    };
    let zone = match load_zone(dir, name) {
        Ok(z) => z,
        Err(c) => return c,
    };
    if zone.storage != zone::StorageMode::Encrypted {
        eprintln!("volume: zone {name:?} has storage.mode {:?}, not \"encrypted\"", zone.storage);
        return ExitCode::from(2);
    }
    let vol = zone.volume.clone().unwrap_or_else(|| volume::default_volume_path(name));
    let opt = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned();
    let pass_from = |flag: &str| -> Result<volume::Passphrase, ExitCode> {
        let Some(p) = opt(flag) else {
            eprintln!("volume: {flag} FILE is required (a 0600 file holding the passphrase; it never travels in argv)");
            return Err(ExitCode::from(2));
        };
        volume::Passphrase::from_file(Path::new(&p)).map_err(|e| {
            eprintln!("volume: {e}");
            ExitCode::FAILURE
        })
    };
    let root = unsafe { libc::geteuid() } == 0;
    let done = |what: &str, r: Result<(), volume::VolumeError>| -> ExitCode {
        match r {
            Ok(()) => {
                println!("volume {name:?}: {what}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("volume: {e}");
                ExitCode::FAILURE
            }
        }
    };
    match sub {
        "status" => {
            let present = Path::new(&vol).exists();
            let mapper = volume::mapper_path(name);
            println!("zone      {name}");
            println!("container {vol} ({})", if present { "present" } else { "ABSENT" });
            println!("signature {}", if present { volume::signature_of(&vol) } else { "-".into() });
            println!("mapping   {} ({})", mapper, if Path::new(&mapper).exists() { "OPEN" } else { "closed" });
            ExitCode::SUCCESS
        }
        "init" => {
            if !root {
                eprintln!("volume init needs root (cryptsetup, dm-crypt, loop)");
                return ExitCode::from(2);
            }
            let size = match opt("--size").as_deref().map(volume::parse_size) {
                None => 512 * 1024 * 1024,
                Some(Some(n)) => n,
                Some(None) => {
                    eprintln!("volume: --size wants e.g. 512M or 2G");
                    return ExitCode::from(2);
                }
            };
            let pass = match pass_from("--passphrase-file") {
                Ok(p) => p,
                Err(c) => return c,
            };
            let uid = opt("--zone-uid").and_then(|v| v.parse::<u32>().ok());
            let gid = opt("--zone-gid").and_then(|v| v.parse::<u32>().ok());
            let (uid, gid) = match (uid, gid, zone.uid_base) {
                (Some(u), Some(g), _) => (u, g),
                (None, None, Some(b)) => (b, b),
                _ => {
                    eprintln!("volume init: give --zone-uid N --zone-gid N, or declare [identity] uid_base in the zone file");
                    return ExitCode::from(2);
                }
            };
            done(&format!("created {vol} ({} bytes, LUKS2/argon2id, ext4 owned by {uid}:{gid})", size), volume::init(name, &vol, size, &pass, uid, gid))
        }
        "passwd" => {
            if !root {
                eprintln!("volume passwd needs root");
                return ExitCode::from(2);
            }
            let old = match pass_from("--passphrase-file") { Ok(p) => p, Err(c) => return c };
            let new = match pass_from("--new-passphrase-file") { Ok(p) => p, Err(c) => return c };
            done("passphrase changed", volume::change_key(&vol, &old, &new))
        }
        "backup-header" => {
            let Some(file) = args.get(3) else { eprintln!("volume backup-header NAME FILE"); return ExitCode::from(2) };
            done(&format!("LUKS header written to {file} (holds the wrapped key: passphrase-protected, but sensitive)"), volume::backup_header(&vol, file))
        }
        "restore-header" => {
            let Some(file) = args.get(3) else { eprintln!("volume restore-header NAME FILE"); return ExitCode::from(2) };
            done(&format!("LUKS header restored from {file}"), volume::restore_header(&vol, file))
        }
        other => {
            eprintln!("volume: unknown subcommand {other:?}");
            ExitCode::from(2)
        }
    }
}

fn wifi_dir_from(args: &[String]) -> PathBuf {
    args.iter()
        .position(|a| a == "--wifi-dir")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(wifi::DEFAULT_DIR))
}


/// `kryptikd time floor | status` (docs/design/time.md). The clock is set in
/// two places only: here, from the floor and with no network involved, and
/// in the broker, from a claim the net zone made and zone 0 judged.
fn cmd_time(args: &[String]) -> ExitCode {
    let dir = Path::new(time::STATE_DIR);
    match args.get(1).map(String::as_str) {
        Some("floor") => match time::clamp(&mut time::SystemClock, dir, time::floor_of_this_system()) {
            Ok(said) => {
                println!("kryptikd: time: {said}");
                ExitCode::SUCCESS
            }
            Err(why) => {
                eprintln!("kryptikd: time: {why}");
                ExitCode::FAILURE
            }
        },
        Some("status") => {
            use time::Clock;
            println!("clock    {}", time::format_utc(time::SystemClock.now()));
            match time::floor_of_this_system() {
                Some(f) => println!("floor    {} (this system's build date; nothing earlier is believed)", time::format_utc(f as f64)),
                None => println!("floor    unknown: {} is missing or unreadable, so every claim is refused", time::IMAGE_JSON),
            }
            match std::fs::read_to_string(dir.join("history")) {
                Ok(h) => match h.lines().last() {
                    Some(l) => println!("last     {l}"),
                    None => println!("last     nothing has been done to the clock"),
                },
                Err(_) => println!("last     nothing has been done to the clock"),
            }
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: kryptikd time floor | status");
            ExitCode::from(2)
        }
    }
}

/// `kryptikd wifi`: the net zone's Wi-Fi credentials, from zone 0 (wifi.rs).
/// The session's path is `kryptik wifi` through the launch daemon; this is
/// the same file for root at a terminal and for the tests. The passphrase
/// is one line on stdin, never an argument.
///
///   wifi list                [--wifi-dir DIR]
///   wifi add SSID            [--wifi-dir DIR] [--zones DIR]
///   wifi forget SSID         [--wifi-dir DIR] [--zones DIR]
fn cmd_wifi(zones_dir: &Path, args: &[String]) -> ExitCode {
    let dir = wifi_dir_from(args);
    let sub = args.get(1).map(String::as_str).unwrap_or("");
    let ssid = args.get(2).filter(|a| !a.starts_with("--"));
    let usage = || {
        eprintln!("usage: kryptikd wifi list | add SSID | forget SSID   [--wifi-dir DIR]");
        ExitCode::from(2)
    };
    let refused = |e: String| {
        eprintln!("kryptikd: wifi: {e}");
        ExitCode::FAILURE
    };
    match (sub, ssid) {
        ("list", None) => match wifi::list(&dir) {
            Ok(names) => {
                for n in names {
                    println!("{n}");
                }
                ExitCode::SUCCESS
            }
            Err(e) => refused(e),
        },
        ("add", Some(ssid)) => {
            // The rules first, so a bad SSID is refused before anyone types
            // a passphrase for it.
            if let Err(e) = wifi::check_ssid(ssid) {
                return refused(e);
            }
            let pass = match wifi::read_passphrase(&format!("passphrase for {ssid}: ")) {
                Ok(p) => p,
                Err(e) => return refused(e),
            };
            let owner = match wifi::owner_for(zones_dir) {
                Ok(o) => o,
                Err(e) => return refused(e),
            };
            match wifi::add(&dir, owner, ssid, &pass) {
                Ok(wifi::Added::New) => println!("added network {ssid:?}; {}", wifi::restart_net_zone(&dir)),
                Ok(wifi::Added::Replaced) => {
                    println!("replaced the passphrase of network {ssid:?}; {}", wifi::restart_net_zone(&dir))
                }
                Err(e) => return refused(e),
            }
            ExitCode::SUCCESS
        }
        ("forget", Some(ssid)) => {
            let owner = match wifi::owner_for(zones_dir) {
                Ok(o) => o,
                Err(e) => return refused(e),
            };
            match wifi::forget(&dir, owner, ssid) {
                Ok(()) => {
                    println!("forgot network {ssid:?}; {}", wifi::restart_net_zone(&dir));
                    ExitCode::SUCCESS
                }
                Err(e) => refused(e),
            }
        }
        _ => usage(),
    }
}

fn cmd_run(dir: &Path, args: &[String]) -> ExitCode {
    let Some(name) = args.get(1).filter(|a| !a.starts_with("--")) else {
        eprintln!("run: expected a zone name");
        return ExitCode::from(2);
    };

    // Everything after `--` is the command. Requiring the separator keeps zone
    // options and the command unambiguous.
    let Some(sep) = args.iter().position(|a| a == "--") else {
        eprintln!("run: expected `-- COMMAND`, e.g. kryptikd run untrusted -- /bin/sh");
        return ExitCode::from(2);
    };
    let cmd: Vec<String> = args[sep + 1..].to_vec();
    if cmd.is_empty() {
        eprintln!("run: no command after `--`");
        return ExitCode::from(2);
    }

    let zone = match load_zone(dir, name) {
        Ok(z) => z,
        Err(c) => return c,
    };
    let base = rootfs_base_from(args);
    let rootfs = spawn::zone_rootfs(&zone, &base);
    // Options live before `--`; the command after it is never inspected.
    let mut opts = match run_options_from(&args[..sep]) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("run: {e}");
            return ExitCode::from(2);
        }
    };
    opts.zones_dir = dir.to_path_buf();

    match spawn::run_in_zone(&zone, &rootfs, &cmd, &opts) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(e) => {
            eprintln!("kryptikd: could not start zone {:?}: {e}", zone.name);
            ExitCode::FAILURE
        }
    }
}

/// SIGSYS handler: report the denied syscall number, then die.
///
/// Everything here must be async-signal-safe. An earlier version used
/// `format!` and `seccomp::name_of`, both of which allocate - the handler ran
/// (the process exited 159) but nothing was ever printed, which is exactly the
/// silent failure mode allocation in a signal handler produces. This version
/// formats the integer by hand into a stack buffer and uses a raw write(2).
///
/// The number is translated to a name by the PARENT, after the child dies,
/// where allocation is safe.
extern "C" fn sigsys_handler(
    _sig: libc::c_int,
    info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    // si_syscall sits at a fixed offset in the SIGSYS layout of siginfo_t:
    // si_signo, si_errno, si_code (3 x i32), si_call_addr (pointer), then
    // si_syscall. libc does not expose it as a field, so read it positionally.
    let nr: i32 = unsafe {
        let base = info as *const u8;
        let off = 3 * std::mem::size_of::<i32>() + std::mem::size_of::<usize>();
        *(base.add(off) as *const i32)
    };

    // Emit the line KRYPTIK_SECCOMP_DENIED <nr> without allocating.
    const PREFIX: &[u8] = b"KRYPTIK_SECCOMP_DENIED ";
    let mut buf = [0u8; 48];
    let mut len = 0;
    for &b in PREFIX {
        buf[len] = b;
        len += 1;
    }
    let mut n = if nr < 0 { 0u32 } else { nr as u32 };
    let mut digits = [0u8; 10];
    let mut d = 0;
    loop {
        digits[d] = b'0' + (n % 10) as u8;
        n /= 10;
        d += 1;
        if n == 0 {
            break;
        }
    }
    while d > 0 {
        d -= 1;
        buf[len] = digits[d];
        len += 1;
    }
    buf[len] = b'\n';
    len += 1;

    unsafe {
        libc::write(2, buf.as_ptr() as *const libc::c_void, len);
        libc::_exit(159);
    }
}

fn cmd_seccomp_trace(cmd: &[String]) -> ExitCode {
    use std::ffi::CString;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        eprintln!("seccomp-trace: fork failed");
        return ExitCode::FAILURE;
    }

    if pid == 0 {
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = sigsys_handler as usize;
            sa.sa_flags = libc::SA_SIGINFO;
            libc::sigaction(libc::SIGSYS, &sa, std::ptr::null_mut());
        }
        if seccomp::install_tracing(seccomp::BASE_ALLOWLIST).is_err() {
            unsafe { libc::_exit(1) };
        }
        let prog = CString::new(cmd[0].as_str()).unwrap_or_default();
        let args: Vec<CString> = cmd
            .iter()
            .filter_map(|a| CString::new(a.as_str()).ok())
            .collect();
        let mut ptrs: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        unsafe {
            libc::execvp(prog.as_ptr(), ptrs.as_ptr());
            libc::_exit(127)
        }
    }

    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let code = spawn::decode_status(status);
    if code == 159 {
        eprintln!(
            "seccomp-trace: the command was denied a syscall (see              KRYPTIK_SECCOMP_DENIED above for the number)"
        );
    }
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

fn cmd_seccomp_test(name: &str, nr: libc::c_long) -> ExitCode {
    // SAFETY: fork in a program that does no threading before this point.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        eprintln!("seccomp-test: fork failed");
        return ExitCode::FAILURE;
    }

    if pid == 0 {
        // Child. Anything past the filter install must itself be permitted, so
        // the syscall under test is made immediately and the result reported
        // through the exit code rather than by printing.
        if seccomp::confine_zone().is_err() {
            unsafe { libc::_exit(1) };
        }
        // Deliberately harmless arguments: the filter decides before the
        // kernel ever looks at them. A blocked call never returns.
        unsafe {
            libc::syscall(nr, 0, 0, 0, 0, 0, 0);
            libc::_exit(0)
        }
    }

    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };

    // libc::WIFSIGNALED / WTERMSIG are not const fns in all versions; the
    // status is decoded by spawn.rs, which owns the one tested decoder.
    let termsig = spawn::signalled_by(status);
    let exitcode = (status >> 8) & 0xff;

    if termsig == Some(libc::SIGSYS) {
        eprintln!("seccomp-test: {name} killed by SIGSYS (blocked)");
        ExitCode::from(5)
    } else if let Some(sig) = termsig {
        eprintln!("seccomp-test: {name} killed by signal {sig}");
        ExitCode::from(6)
    } else if exitcode == 1 {
        eprintln!("seccomp-test: could not install filter");
        ExitCode::FAILURE
    } else {
        eprintln!("seccomp-test: {name} COMPLETED - not blocked");
        ExitCode::SUCCESS
    }
}

/// Re-export for integration tests.
pub use zone::ZoneError;
