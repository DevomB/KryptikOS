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
mod rootfs;
mod seccomp;
mod spawn;
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
    kryptikd list  [--zones DIR]      list configured zones
    kryptikd show  NAME [--zones DIR]
    kryptikd explain NAME             what starting this zone would do
    kryptikd run NAME -- CMD [ARGS]   create the zone and run CMD inside it

    --rootfs DIR   base directory for zone filesystems
                   (default: /var/lib/kryptik/zones)

Not yet implemented (Phase 5): stop, transfer, clipboard, and per-zone
encrypted volumes. They exit with an error rather than pretending to work."
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
        "seccomp-test" => {
            let Some(name) = args.get(1) else {
                eprintln!("seccomp-test: expected a syscall name");
                return ExitCode::from(2);
            };
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
        "stop" | "transfer" | "clipboard" => {
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

    // Prove the seccomp program actually builds and installs in a child, not
    // merely that the kernel reports seccomp support.
    match std::process::Command::new(std::env::current_exe().unwrap_or_default())
        .args(["seccomp-test", "getpid"])
        .output()
    {
        Ok(o) if o.status.code() == Some(0) => {
            println!("  seccomp filter   builds and permits allowed calls");
        }
        Ok(o) => {
            eprintln!("  seccomp filter   FAILED (exit {:?})", o.status.code());
            failed = true;
        }
        Err(e) => eprintln!("  seccomp filter   could not self-test: {e}"),
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
    println!("seccomp      default-deny, {} syscalls allowed", seccomp::BASE_ALLOWLIST.len());

    if z.is_airgapped() {
        println!();
        println!("This zone has no network stack: its net namespace contains only");
        println!("loopback. That is not a firewall rule - there is no interface.");
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
    println!("{}", spawn::explain(&zone, &rootfs));
    ExitCode::SUCCESS
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

    match spawn::run_in_zone(&zone, &rootfs, &cmd) {
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
    let code = if (status & 0x7f) == 0 { (status >> 8) & 0xff } else { 128 + (status & 0x7f) };
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

    // libc::WIFSIGNALED / WTERMSIG are not const fns in all versions; decode
    // the wait status directly.
    let signalled = (status & 0x7f) != 0 && (status & 0x7f) != 0x7f;
    let termsig = status & 0x7f;
    let exited = (status & 0x7f) == 0;
    let exitcode = (status >> 8) & 0xff;

    if signalled && termsig == libc::SIGSYS {
        eprintln!("seccomp-test: {name} killed by SIGSYS (blocked)");
        ExitCode::from(5)
    } else if signalled {
        eprintln!("seccomp-test: {name} killed by signal {termsig}");
        ExitCode::from(6)
    } else if exited && exitcode == 1 {
        eprintln!("seccomp-test: could not install filter");
        ExitCode::FAILURE
    } else {
        eprintln!("seccomp-test: {name} COMPLETED - not blocked");
        ExitCode::SUCCESS
    }
}

/// Re-export for integration tests.
pub use zone::ZoneError;
