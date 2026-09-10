//! kryptikd — Kryptik compartment manager.
//!
//! Owns zone lifecycle. Runs privileged in zone 0 (ADR-003) and is the only
//! process permitted to create zones or move data between them.
//!
//! STATUS: Phase 5 in progress. Implemented today are zone definition parsing
//! and validation, kernel capability probing, and the namespace/isolation
//! primitives the exit test exercises. NOT implemented: per-zone LUKS volumes,
//! the Wayland proxy, and the brokered file/clipboard channels. Those are
//! stubbed with explicit errors rather than silent no-ops - a compartment
//! manager that pretends to isolate is worse than one that refuses to start.

mod isolate;
mod landlock;
mod zone;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use isolate::KernelSupport;
use zone::Zone;

const DEFAULT_ZONE_DIR: &str = "/etc/kryptik/zones";

fn usage() -> &'static str {
    "kryptikd — Kryptik compartment manager

USAGE:
    kryptikd check [--zones DIR]     verify kernel support and validate zones
    kryptikd list  [--zones DIR]     list configured zones
    kryptikd show  NAME [--zones DIR]

Not yet implemented (Phase 5): start, stop, transfer, clipboard.
They exit with an error rather than pretending to work."
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    }

    let zone_dir = zone_dir_from(&args);

    match args[0].as_str() {
        "check" => cmd_check(&zone_dir),
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
        // TARGET. Used by the Phase 5 adversarial test to prove requirements 2
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
        "start" | "stop" | "transfer" | "clipboard" => {
            eprintln!(
                "kryptikd: '{}' is not implemented yet (Phase 5, docs/roadmap.md).\n\
                 Refusing rather than pretending. A compartment manager that\n\
                 silently does nothing is worse than one that will not start.",
                args[0]
            );
            ExitCode::from(3)
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

fn zone_dir_from(args: &[String]) -> PathBuf {
    args.iter()
        .position(|a| a == "--zones")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ZONE_DIR))
}

fn cmd_check(dir: &Path) -> ExitCode {
    let mut failed = false;

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
                println!("  {:<10} {:<20} {}", z.name, net, z.border_color);
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

    if z.is_airgapped() {
        println!();
        println!("This zone has no network stack: its net namespace contains only");
        println!("loopback. That is not a firewall rule - there is no interface.");
    }

    ExitCode::SUCCESS
}

/// Re-export for integration tests.
pub use zone::ZoneError;
