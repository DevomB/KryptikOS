//! kryptikd, the Kryptik compartment manager.
//!
//! Owns zone lifecycle. Runs privileged in zone 0 (ADR-003) and is the only
//! process that creates zones or moves data between them. Anything not built
//! is refused with an error, never a silent no-op.

mod broker;
mod caps;
mod cgroup;
mod consent;
mod files;
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
mod update;
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
    kryptikd seccomp-trace -- CMD     run CMD under the base seccomp filter; every
                   [--zone NAME]      call it refuses is named and fails with ENOSYS
                                      (--zone: NAME's filter, with its policy file)
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
        /* confine-test ROOTFS TARGET: Landlock-confine to ROOTFS, then read
         * TARGET. Exit 0: read succeeded (confinement failed); 4: blocked;
         * 1: could not confine. Used by the isolation exit test. */
        "confine-test" => {
            let Some(root) = args.get(1) else {
                eprintln!("confine-test: expected ROOTFS TARGET");
                return ExitCode::from(2);
            };
            let Some(target) = args.get(2) else {
                eprintln!("confine-test: expected a TARGET path to try reading");
                return ExitCode::from(2);
            };

            // Unless the read works before confinement, a blocked read proves nothing.
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
        /* seccomp-test SYSCALL|PROBE: a forked child installs the zone filter,
         * then makes the call (probes: cmd_seccomp_probe). Exit 0: completed;
         * 5: SIGSYS; 6: another signal; 7: refused with the intended errno;
         * 1: filter not installed. */
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
        /* seccomp-trace [--zone NAME] -- CMD: run CMD under the base filter, or
         * NAME's widened by its policy file, and name every call it refuses
         * (cmd_seccomp_trace). For writing a policy file. */
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
            let (allow, sockets) = match value(&args, "--zone") {
                None => (seccomp::BASE_ALLOWLIST.to_vec(), seccomp::SocketPolicy::default()),
                Some(name) => match trace_filter(&zone_dir, name) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("seccomp-trace: {e}");
                        return ExitCode::from(2);
                    }
                },
            };
            cmd_seccomp_trace(&cmd, &allow, &sockets)
        }
        "stop" => match args.get(1) {
            Some(name) if !name.starts_with("--") => {
                cmd_stop(name, args.iter().any(|a| a == "--now"), &rootfs_base_from(&args))
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

/// Stop a running zone by signalling its launcher, which forwards the signal
/// to pid 1 and escalates to SIGKILL after 5 s. The launcher is signalled only
/// while its pid and start time both still match: pids are reused.
fn cmd_stop(name: &str, now: bool, base: &str) -> ExitCode {
    let mut st = match registry::state(name) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("kryptikd: {e}");
            return ExitCode::FAILURE;
        }
    };

    /* "Still starting" lasts a few ms, between claim() and the fork that
     * records the launcher pid; `run &` then `stop` often lands in it. */
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
            close_left_volume(name, base);
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
        registry::State::Running { launcher: Some(l), init, .. } => {
            if !l.still_alive() {
                // The launcher died between the two reads; do not signal a reused pid.
                let _ = registry::reclaim(name);
                close_left_volume(name, base);
                println!("zone {name:?} exited while stopping it");
                return ExitCode::SUCCESS;
            }
            /* --now kills the zone's pid 1, which takes the pid namespace with
             * it, not the launcher: the launcher outlives its zone to unmount
             * and close the zone's volume. */
            let (pid, sig) = match init.filter(|i| now && i.still_alive()) {
                Some(i) => (i.pid, libc::SIGKILL),
                None => (l.pid, if now { libc::SIGKILL } else { libc::SIGTERM }),
            };
            if unsafe { libc::kill(pid, sig) } < 0 {
                eprintln!("kryptikd: signalling {pid}: {}", std::io::Error::last_os_error());
                return ExitCode::FAILURE;
            }

            // The launcher removes its entry on exit. 8 s covers the 5 s escalation plus teardown.
            for _ in 0..160 {
                match registry::state(name) {
                    Ok(registry::State::Absent) => {
                        println!("zone {name:?} stopped");
                        return ExitCode::SUCCESS;
                    }
                    Ok(registry::State::Stale { .. }) => {
                        let _ = registry::reclaim(name);
                        close_left_volume(name, base);
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

/// Close the volume of a zone whose launcher died without closing it, as
/// `gc` does for every zone: otherwise the plaintext stays mounted and its
/// key in the kernel after the zone is reported stopped.
fn close_left_volume(name: &str, base: &str) {
    if !volume::mappings().iter().any(|z| z == name) || matches!(registry::state(name), Ok(registry::State::Running { .. })) {
        return;
    }
    let mnt = volume::mountpoint_for(Path::new(base), name).display().to_string();
    match volume::close_mapping(name, &mnt) {
        Ok(()) => println!("closed the volume zone {name:?} left open"),
        Err(e) => eprintln!("kryptikd: closing zone {name:?}'s volume: {e}"),
    }
}

/// Cross-zone paste, a zone 0 gesture: no zone's socket has a verb to fetch
/// another zone's payload. Both zones must be running; the payload lives only
/// in the source zone's registry entry.
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
            /* core-sched is asked of the kernel (nothing in /proc shows it): own,
             * none, no-smt (no sibling thread online) or unavailable. */
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

/// Reclaim stale entries, empty zone cgroups and orphaned volume mappings.
/// A live zone is safe: an entry is stale only if its lock can be taken, and
/// the kernel refuses `rmdir` of a populated cgroup (EBUSY).
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
    // A mapping with no running zone is plaintext nobody uses; the next open runs fsck -p.
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

/// kryptikd's own arguments: those before `--`. The rest is the zone's command.
fn own(args: &[String]) -> &[String] {
    &args[..args.iter().position(|a| a == "--").unwrap_or(args.len())]
}

/// The value after `flag`, if the flag is given with one.
fn value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let own = own(args);
    own.iter().position(|a| a == flag).and_then(|i| own.get(i + 1)).map(String::as_str)
}

/// None when `flag` is absent; an error when its value is missing or does not parse.
fn parsed<T: std::str::FromStr>(args: &[String], flag: &str, what: &str) -> Result<Option<T>, String> {
    let own = own(args);
    match own.iter().position(|a| a == flag) {
        None => Ok(None),
        Some(i) => own.get(i + 1).and_then(|v| v.parse().ok()).map(Some).ok_or_else(|| format!("{flag}: expected {what}")),
    }
}

fn zone_dir_from(args: &[String]) -> PathBuf {
    PathBuf::from(value(args, "--zones").unwrap_or(DEFAULT_ZONE_DIR))
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
            // Build a ruleset, so a struct layout mismatch fails here and not at zone start.
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

    /* Install the filter in a child and make an allowed call. A self-test that
     * cannot run is a failure: this command gates a kernel as fit for zones. */
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

    /* On the target only CAP_SYS_ADMIN in the initial namespace may create a
     * user namespace. Read the knob, then prove it by trying. */
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
        // Only names a missing controller; every launch still tries the real creation.
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
                /* Parsed as the launcher parses it (spawn.rs), so a file that
                 * would stop a launch fails the check. */
                if let Some(rel) = &z.landlock {
                    let path = policy::resolve(dir, rel);
                    match std::fs::read_to_string(&path)
                        .map_err(|e| e.to_string())
                        .and_then(|t| landlock::parse_policy(&t, &path.display().to_string()))
                    {
                        Ok(rules) => println!("             landlock {rel}: {} rule(s) narrowing the base", rules.len()),
                        Err(e) => {
                            eprintln!("             landlock {rel}: {e}");
                            failed = true;
                        }
                    }
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
    if z.network != zone::NetworkMode::None {
        println!("bridge       {}", netzone::BRIDGE);
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

    println!("namespaces   {}", isolate::namespace_names(isolate::namespace_flags(&z)).join(", "));
    println!("seccomp      default-deny, {} syscalls allowed", seccomp::BASE_ALLOWLIST.len());

    println!();
    match z.network {
        zone::NetworkMode::None => {
            println!("This zone has no network stack: its net namespace contains only");
            println!("loopback. That is not a firewall rule - there is no interface.");
        }
        zone::NetworkMode::Routed => {
            println!("A root launch attaches this zone to the kryptik0 bridge, and it");
            println!("reaches the network through the nic zone. Launched without");
            println!("privilege it gets loopback only.");
        }
        zone::NetworkMode::Nic => {
            println!("This zone holds the physical network interface and routes the");
            println!("other zones' traffic (docs/design/net-zone.md).");
        }
    }

    ExitCode::SUCCESS
}

const DEFAULT_ROOTFS_BASE: &str = "/var/lib/kryptik/zones";

fn rootfs_base_from(args: &[String]) -> String {
    value(args, "--rootfs").unwrap_or(DEFAULT_ROOTFS_BASE).to_string()
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

/// Argument-rule and soft-refusal probes for `seccomp-test`; None when `name`
/// is not a probe.
fn cmd_seccomp_probe(name: &str) -> Option<ExitCode> {
    // Runs in the filtered child: 7 if refused with the intended errno, else 0.
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
        "inotify" => || unsafe {
            let r = libc::inotify_init1(0);
            if r < 0 && *libc::__errno_location() == libc::ENOSYS { 7 } else { 0 }
        },
        // As ncurses calls it around a terminfo open.
        "setfsuid" => || unsafe {
            let r = libc::syscall(libc::SYS_setfsuid, libc::getuid() as libc::c_long);
            if r < 0 && *libc::__errno_location() == libc::EPERM { 7 } else { 0 }
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

    Some(under_zone_filter(name, probe))
}

fn run_options_from(args: &[String]) -> Result<spawn::RunOptions, String> {
    Ok(spawn::RunOptions {
        zone_uid: parsed(args, "--zone-uid", "a numeric id")?,
        zone_gid: parsed(args, "--zone-gid", "a numeric id")?,
        zones_dir: std::path::PathBuf::new(),
        wifi_dir: wifi_dir_from(args),
        auto_approve_transfers: own(args).iter().any(|a| a == "--auto-approve-transfers"),
        passphrase_file: value(args, "--passphrase-file").map(PathBuf::from),
        passphrase_fd: parsed(args, "--passphrase-fd", "a descriptor number")?,
        wayland_socket: value(args, "--wayland-socket").map(PathBuf::from),
        wayland_inode: parsed::<serve::InodeId>(args, "--wayland-inode", "DEV:INO")?,
        ready_fd: match parsed::<i32>(args, "--ready-fd", "a descriptor number")? {
            None => None,
            Some(fd) => {
                // The zone's command must not inherit it.
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

/// An encrypted zone's LUKS2 container, outside any launch
/// (docs/design/encrypted-volumes.md). init and passwd need root.
///
///   volume init NAME [--size 512M] --passphrase-file F [--zone-uid N --zone-gid N]
///   volume passwd NAME --passphrase-file OLD --new-passphrase-file NEW
///   volume backup-header|restore-header NAME FILE
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
    let opt = |flag: &str| value(args, flag).map(str::to_string);
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
            let size = match opt("--size").as_deref().map(zone::parse_size) {
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


/// `kryptikd time floor | status` (docs/design/time.md). The clock is set only
/// here, from the floor, and in the broker, from a net zone claim zone 0 judged.
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

/// `kryptikd wifi list | add SSID | forget SSID`: the net zone's Wi-Fi networks,
/// for root and the tests (the session goes through the launch daemon). The
/// passphrase is one line on stdin, never an argument.
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
            // Refuse a bad SSID before asking for its passphrase.
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

/// `_IOWR('!', nr, size)`, the seccomp notification ioctls.
const fn seccomp_iowr(nr: u32, size: usize) -> libc::c_ulong {
    ((3 << 30) | ((size as u32) << 16) | ((b'!' as u32) << 8) | nr) as libc::c_ulong
}
const NOTIF_RECV: libc::c_ulong = seccomp_iowr(0, std::mem::size_of::<libc::seccomp_notif>());
const NOTIF_SEND: libc::c_ulong = seccomp_iowr(1, std::mem::size_of::<libc::seccomp_notif_resp>());

/// The filter zone `name` runs under: the base, widened by its policy file.
fn trace_filter(dir: &Path, name: &str) -> Result<(Vec<libc::c_long>, seccomp::SocketPolicy), String> {
    let zones = zone::load_all(dir).map_err(|e| e.to_string())?;
    let z = zones.iter().find(|z| z.name == name).ok_or_else(|| format!("no zone named {name:?}"))?;
    let Some(rel) = &z.seccomp else {
        return Ok((seccomp::BASE_ALLOWLIST.to_vec(), seccomp::SocketPolicy::default()));
    };
    let p = policy::load(&policy::resolve(dir, rel))
        .and_then(|p| p.check_for_zone(z).map(|_| p))
        .map_err(|e| format!("{rel}: {e}"))?;
    Ok((seccomp::widened(&p.extra_syscalls).map_err(|e| e.to_string())?, p.sockets))
}

/* Run CMD under a zone filter and name every call it refuses. Refused calls
 * come here by seccomp user notification (Kryptik forbids ptrace) and fail
 * with ENOSYS, so one run lists them all. The child shares our descriptor
 * table until exec: the zone filter has no sendmsg to pass its listener. */
fn cmd_seccomp_trace(cmd: &[String], allow: &[libc::c_long], sockets: &seccomp::SocketPolicy) -> ExitCode {
    use std::ffi::CString;

    let args: Vec<CString> = match cmd.iter().map(|a| CString::new(a.as_str())).collect() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("seccomp-trace: an argument contains NUL");
            return ExitCode::from(2);
        }
    };
    let mut ptrs: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    let mut pipe = [0 as libc::c_int; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        eprintln!("seccomp-trace: pipe: {}", std::io::Error::last_os_error());
        return ExitCode::FAILURE;
    }

    // A fork that shares the descriptor table; the child's exec unshares it.
    let pid = unsafe { libc::syscall(libc::SYS_clone, libc::CLONE_FILES | libc::SIGCHLD, 0, 0, 0, 0) } as libc::pid_t;
    if pid < 0 {
        eprintln!("seccomp-trace: clone: {}", std::io::Error::last_os_error());
        return ExitCode::FAILURE;
    }
    if pid == 0 {
        // Only calls the zone filter allows from here: write, execve, exit.
        let fd: libc::c_int = seccomp::install_notifying(allow, sockets).unwrap_or(-1);
        unsafe {
            libc::write(pipe[1], fd.to_ne_bytes().as_ptr() as *const libc::c_void, 4);
            if fd >= 0 {
                libc::execvp(ptrs[0], ptrs.as_ptr());
            }
            libc::_exit(127)
        }
    }

    let mut word = [0u8; 4];
    let got = unsafe { libc::read(pipe[0], word.as_mut_ptr() as *mut libc::c_void, 4) };
    unsafe {
        libc::close(pipe[0]);
        libc::close(pipe[1]);
    }
    let listener = i32::from_ne_bytes(word);
    /* The program's end is read from a pidfd: the listener hangs up only when
     * the last filtered task is reaped, and this loop is what would reap it. */
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as libc::c_int;
    let mut refused = 0u32;
    if got == 4 && listener >= 0 && pidfd >= 0 {
        loop {
            let mut pfds = [
                libc::pollfd { fd: listener, events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: pidfd, events: libc::POLLIN, revents: 0 },
            ];
            if unsafe { libc::poll(pfds.as_mut_ptr(), 2, -1) } < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if pfds[0].revents & libc::POLLIN == 0 {
                if pfds[1].revents != 0 || pfds[0].revents != 0 {
                    break;
                }
                continue;
            }
            let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
            if unsafe { libc::ioctl(listener, NOTIF_RECV as _, &mut req) } < 0 {
                continue; // the caller died before we read it
            }
            let nr = libc::c_long::from(req.data.nr);
            let name = seccomp::name_of(nr).unwrap_or("");
            // A soft refusal gets the errno a zone gets, and is marked.
            let soft = seccomp::REFUSED_SOFTLY.iter().find(|(n, _)| *n == nr).map(|&(_, e)| e as libc::c_int);
            eprintln!("KRYPTIK_SECCOMP_DENIED {nr} {name}{}", if soft.is_some() { " soft" } else { "" });
            refused += 1;
            let mut resp: libc::seccomp_notif_resp = unsafe { std::mem::zeroed() };
            resp.id = req.id;
            resp.error = -soft.unwrap_or(libc::ENOSYS);
            unsafe { libc::ioctl(listener, NOTIF_SEND as _, &mut resp) };
        }
    } else {
        eprintln!("seccomp-trace: the filter could not be installed, or the program watched");
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    for fd in [listener, pidfd] {
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }

    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    eprintln!("seccomp-trace: {refused} refused call(s)");
    ExitCode::from(u8::try_from(spawn::decode_status(status)).unwrap_or(1))
}

fn cmd_seccomp_test(name: &str, nr: libc::c_long) -> ExitCode {
    // The filter acts before the kernel reads the arguments; a blocked call never returns.
    under_zone_filter(name, || {
        unsafe { libc::syscall(nr, 0, 0, 0, 0, 0, 0) };
        0
    })
}

/// Run `probe` in a child under the zone filter and say how it ended. Exit 5:
/// killed by SIGSYS; 6: another signal; 7: refused with the intended errno;
/// 1: no filter; 0: completed.
fn under_zone_filter(name: &str, probe: impl FnOnce() -> i32) -> ExitCode {
    // SAFETY: fork in a program that does no threading before this point.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        eprintln!("seccomp-test: fork failed");
        return ExitCode::FAILURE;
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
    if termsig == Some(libc::SIGSYS) {
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
    }
}

pub use zone::ZoneError;

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn seccomp_ioctls() {
        assert_eq!(NOTIF_RECV, 0xC050_2100);
        assert_eq!(NOTIF_SEND, 0xC018_2101);
    }

    #[test]
    fn flags_stop_at_separator() {
        let a = args(&["run", "work", "--rootfs", "/r", "--", "tool", "--zones", "/x", "--rootfs", "/y"]);
        assert_eq!(zone_dir_from(&a), PathBuf::from(DEFAULT_ZONE_DIR));
        assert_eq!(rootfs_base_from(&a), "/r");
        assert_eq!(value(&a, "--zones"), None);
    }

    #[test]
    fn parsed_flag_needs_value() {
        assert_eq!(parsed::<u32>(&args(&["run", "w"]), "--zone-uid", "an id"), Ok(None));
        assert_eq!(parsed::<u32>(&args(&["--zone-uid", "7"]), "--zone-uid", "an id"), Ok(Some(7)));
        assert!(parsed::<u32>(&args(&["--zone-uid"]), "--zone-uid", "an id").is_err());
        assert!(parsed::<u32>(&args(&["--zone-uid", "x"]), "--zone-uid", "an id").is_err());
        assert!(parsed::<u32>(&args(&["--zone-uid", "--", "7"]), "--zone-uid", "an id").is_err());
    }
}
