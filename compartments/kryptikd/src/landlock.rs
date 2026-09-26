//! Landlock filesystem confinement (ADR-007): self-applied, irreversible, and
//! needing no privilege. For a zone it backs up the pivoted root (`rootfs`).
//!
//! Rules are additive: a rule on a sub-path can only add rights, so `/` gets
//! the fewest and every writable place is named (`zone_rules`).

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;

// glibc has no wrappers for the landlock syscalls.
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;

const FS_EXECUTE: u64 = 1 << 0;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_REMOVE_DIR: u64 = 1 << 4;
const FS_REMOVE_FILE: u64 = 1 << 5;
const FS_MAKE_CHAR: u64 = 1 << 6;
const FS_MAKE_DIR: u64 = 1 << 7;
const FS_MAKE_REG: u64 = 1 << 8;
const FS_MAKE_SOCK: u64 = 1 << 9;
const FS_MAKE_FIFO: u64 = 1 << 10;
const FS_MAKE_BLOCK: u64 = 1 << 11;
const FS_MAKE_SYM: u64 = 1 << 12;
const FS_REFER: u64 = 1 << 13; // ABI v2
const FS_TRUNCATE: u64 = 1 << 14; // ABI v3
const FS_IOCTL_DEV: u64 = 1 << 15; // ABI v5

/// Oldest ABI a zone may run on (Linux 6.2). Below it the kernel cannot handle
/// REFER (v2) or TRUNCATE (v3), so the policy would not mean what it says.
pub const MIN_ABI: i32 = 3;

pub const ACCESS_READ: u64 = FS_READ_FILE | FS_READ_DIR;
/// Full write. Without REFER, `mv a dir/` fails with EXDEV; without TRUNCATE,
/// `>` on an existing file fails.
pub const ACCESS_WRITE: u64 = FS_WRITE_FILE
    | FS_REMOVE_DIR
    | FS_REMOVE_FILE
    | FS_MAKE_DIR
    | FS_MAKE_REG
    | FS_MAKE_SYM
    | FS_MAKE_SOCK
    | FS_MAKE_FIFO
    | FS_REFER
    | FS_TRUNCATE;
/// Write existing files; create or remove nothing (/dev, /proc).
pub const ACCESS_WRITE_FILE: u64 = FS_WRITE_FILE | FS_TRUNCATE;
pub const ACCESS_EXEC: u64 = FS_EXECUTE;
/// ioctl on device files (ABI 5+). Granted only on /dev, for terminals.
pub const ACCESS_IOCTL_DEV: u64 = FS_IOCTL_DEV;

#[repr(C)]
struct RulesetAttrV1 {
    handled_access_fs: u64,
}

#[repr(C)]
struct RulesetAttrV4 {
    handled_access_fs: u64,
    handled_access_net: u64,
}

// Matches the kernel's packed landlock_path_beneath_attr (12 bytes).
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[derive(Debug)]
pub enum LandlockError {
    Unsupported,
    TooOld { abi: i32, need: i32 },
    Syscall { call: &'static str, errno: i32 },
    BadPath(String),
}

impl std::fmt::Display for LandlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LandlockError::Unsupported => write!(
                f,
                "landlock is not available on this kernel; \
                 a zone cannot be confined without it"
            ),
            LandlockError::TooOld { abi, need } => write!(
                f,
                "landlock ABI v{abi} is too old (need v{need}, Linux 6.2+): the kernel \
                 cannot express truncate/rename restrictions, so the zone policy \
                 would silently mean less than it says"
            ),
            LandlockError::Syscall { call, errno } => {
                write!(f, "{call}: {}", io::Error::from_raw_os_error(*errno))
            }
            LandlockError::BadPath(p) => write!(f, "cannot open {p}"),
        }
    }
}

/// ABI version reported by the running kernel, or None if Landlock is absent.
pub fn abi_version() -> Option<i32> {
    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<u8>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if ret < 0 {
        None
    } else {
        Some(ret as i32)
    }
}

/// Access rights ABI `abi` knows. The kernel rejects any other bit (EINVAL).
fn access_mask_for(abi: i32) -> u64 {
    let mut mask = FS_EXECUTE
        | FS_WRITE_FILE
        | FS_READ_FILE
        | FS_READ_DIR
        | FS_REMOVE_DIR
        | FS_REMOVE_FILE
        | FS_MAKE_CHAR
        | FS_MAKE_DIR
        | FS_MAKE_REG
        | FS_MAKE_SOCK
        | FS_MAKE_FIFO
        | FS_MAKE_BLOCK
        | FS_MAKE_SYM;
    if abi >= 2 {
        mask |= FS_REFER;
    }
    if abi >= 3 {
        mask |= FS_TRUNCATE;
    }
    if abi >= 5 {
        mask |= FS_IOCTL_DEV;
    }
    mask
}

/// A ruleset under construction. Every handled access is denied unless a rule
/// allows it.
pub struct Ruleset {
    fd: RawFd,
    abi: i32,
}

impl Ruleset {
    pub fn new() -> Result<Self, LandlockError> {
        let abi = abi_version().ok_or(LandlockError::Unsupported)?;
        if abi < MIN_ABI {
            return Err(LandlockError::TooOld { abi, need: MIN_ABI });
        }
        let handled = access_mask_for(abi);

        /* The attr grew handled_access_net in ABI v4; later ABIs take the v4
         * size and zero the fields it lacks. */
        let v4 = RulesetAttrV4 {
            handled_access_fs: handled,
            handled_access_net: 0,
        };
        let v1 = RulesetAttrV1 {
            handled_access_fs: handled,
        };
        let (ptr, size): (*const libc::c_void, usize) = if abi >= 4 {
            (
                &v4 as *const _ as *const libc::c_void,
                std::mem::size_of::<RulesetAttrV4>(),
            )
        } else {
            (
                &v1 as *const _ as *const libc::c_void,
                std::mem::size_of::<RulesetAttrV1>(),
            )
        };

        let fd = unsafe { libc::syscall(SYS_LANDLOCK_CREATE_RULESET, ptr, size, 0u32) };
        if fd < 0 {
            return Err(LandlockError::Syscall {
                call: "landlock_create_ruleset",
                errno: io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        Ok(Ruleset { fd: fd as RawFd, abi })
    }

    pub fn abi(&self) -> i32 {
        self.abi
    }

    /// Allow `access` on everything beneath `path`. A missing path is an error,
    /// so a typo cannot silently change confinement.
    pub fn allow(&mut self, path: &str, access: u64) -> Result<(), LandlockError> {
        let c = CString::new(path).map_err(|_| LandlockError::BadPath(path.into()))?;
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(LandlockError::BadPath(path.into()));
        }

        // Trim to what this kernel handles, or add_rule returns EINVAL.
        let attr = PathBeneathAttr {
            allowed_access: access & access_mask_for(self.abi),
            parent_fd: fd,
        };

        let ret = unsafe {
            libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                self.fd,
                LANDLOCK_RULE_PATH_BENEATH,
                &attr as *const _ as *const libc::c_void,
                0u32,
            )
        };
        unsafe { libc::close(fd) };

        if ret < 0 {
            return Err(LandlockError::Syscall {
                call: "landlock_add_rule",
                errno: io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        Ok(())
    }

    /// Apply the ruleset to this process and every descendant. Irreversible.
    /// Sets `PR_SET_NO_NEW_PRIVS` first; without it restrict_self is EPERM.
    pub fn restrict_self(self) -> Result<(), LandlockError> {
        let nnp = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if nnp < 0 {
            return Err(LandlockError::Syscall {
                call: "prctl(PR_SET_NO_NEW_PRIVS)",
                errno: io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }

        let ret = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, self.fd, 0u32) };
        unsafe { libc::close(self.fd) };

        if ret < 0 {
            return Err(LandlockError::Syscall {
                call: "landlock_restrict_self",
                errno: io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        Ok(())
    }
}

/// Directives of a zone's Landlock policy file (`[policy] landlock`): one
/// `directive /path` per line, paths as the zone sees them. The file is a second
/// Landlock layer, and layers intersect, so it can only narrow the base rules.
/// There is no `deny`: Landlock has no subtraction.
pub const FS_DIRECTIVES: &[(&str, u64)] = &[
    ("read", ACCESS_READ),
    ("read-exec", ACCESS_READ | ACCESS_EXEC),
    ("read-write", ACCESS_READ | ACCESS_WRITE),
    ("read-write-exec", ACCESS_READ | ACCESS_WRITE | ACCESS_EXEC),
];

/// Parse a zone's Landlock policy file. Paths must be absolute and free of `..`:
/// they name places in the zone's pivoted root.
pub fn parse_policy(text: &str, source: &str) -> Result<Vec<ZoneRule>, String> {
    let mut out: Vec<ZoneRule> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let at = |m: &str| format!("{source}:{}: {m}", i + 1);
        let mut w = line.split_whitespace();
        let (Some(verb), Some(path)) = (w.next(), w.next()) else {
            return Err(at("expected a directive and one path"));
        };
        if w.next().is_some() {
            return Err(at("one path per line; a path containing a space cannot be named here"));
        }
        let Some((_, access)) = FS_DIRECTIVES.iter().find(|(n, _)| *n == verb) else {
            return Err(at(&format!(
                "unknown directive {verb:?} (expected {})",
                FS_DIRECTIVES.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
            )));
        };
        if !path.starts_with('/') {
            return Err(at(&format!("path {path:?} must be absolute, as the zone sees it")));
        }
        if path.split('/').any(|c| c == "..") {
            return Err(at(&format!("path {path:?} must not contain \"..\"")));
        }
        if out.iter().any(|r| r.path == path) {
            return Err(at(&format!("path {path:?} is named twice")));
        }
        out.push(ZoneRule { path: path.to_string(), access: *access, required: true });
    }
    if out.is_empty() {
        return Err(format!(
            "{source}: grants nothing, which would stop the zone reaching even its own \
             binaries. Omit [policy] landlock to use the base rules."
        ));
    }
    Ok(out)
}

/// Apply a zone's policy file as a layer over the base rules. Runs after
/// `confine_pivoted_zone`, inside the zone; a missing path is an error.
pub fn confine_further(rules: &[ZoneRule]) -> Result<(), LandlockError> {
    let mut rs = Ruleset::new()?;
    for r in rules {
        rs.allow(&r.path, r.access)?;
    }
    rs.restrict_self()
}

/// For `kryptikd confine-test`: confine this process, in the caller's mount
/// namespace, to `rootfs` (read, write, exec) and `extra_ro`.
pub fn confine_to_zone(rootfs: &str, extra_ro: &[&str]) -> Result<(), LandlockError> {
    let mut rs = Ruleset::new()?;
    rs.allow(rootfs, ACCESS_READ | ACCESS_WRITE | ACCESS_EXEC)?;
    for p in extra_ro {
        // Missing optional read-only paths are tolerated; the zone rootfs is not.
        let _ = rs.allow(p, ACCESS_READ | ACCESS_EXEC);
    }
    rs.restrict_self()
}

/// A Landlock rule for a pivoted zone; `required` makes a missing path fatal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneRule {
    pub path: String,
    pub access: u64,
    pub required: bool,
}

/// Rules for a zone already pivoted into its root (`rootfs::pivot_into`).
/// "/" gets read and exec only, so what a zone must not modify is denied write
/// by Landlock as well as by its mount flags. Writable places are named.
pub fn zone_rules(home: &str) -> Vec<ZoneRule> {
    let rule = |path: &str, access: u64, required: bool| ZoneRule {
        path: path.to_string(),
        access,
        required,
    };
    vec![
        rule("/", ACCESS_READ | ACCESS_EXEC, true),
        // Exec, so a zone can run what it builds or downloads.
        rule(home, ACCESS_READ | ACCESS_WRITE | ACCESS_EXEC, true),
        rule("/tmp", ACCESS_READ | ACCESS_WRITE | ACCESS_EXEC, true),
        // Write to the device nodes kryptikd provided; create nothing.
        rule("/dev", ACCESS_READ | ACCESS_WRITE_FILE | ACCESS_IOCTL_DEV, true),
        // POSIX shared memory needs create/unlink; the mount is noexec.
        rule("/dev/shm", ACCESS_READ | ACCESS_WRITE, false),
        // /proc/self/oom_score_adj, /proc/self/comm and friends.
        rule("/proc", ACCESS_READ | ACCESS_WRITE_FILE, true),
    ]
}

/// The nic zone's extra writable places: the private tmpfs mounts on /run and
/// /var/lib that `rootfs::pivot_into` gives it for network state. No exec.
pub fn nic_zone_rules() -> Vec<ZoneRule> {
    ["/run", "/var/lib"]
        .iter()
        .map(|p| ZoneRule {
            path: p.to_string(),
            access: ACCESS_READ | ACCESS_WRITE,
            required: true,
        })
        .collect()
}

/// Human-readable form of a rule's rights, for `kryptikd explain`.
pub fn describe_access(access: u64) -> String {
    let mut parts = Vec::new();
    if access & ACCESS_READ != 0 {
        parts.push("read");
    }
    if access & ACCESS_WRITE == ACCESS_WRITE {
        parts.push("write");
    } else if access & FS_WRITE_FILE != 0 {
        parts.push("write-existing-files");
    }
    if access & ACCESS_EXEC != 0 {
        parts.push("exec");
    }
    if access & ACCESS_IOCTL_DEV != 0 {
        parts.push("ioctl-dev");
    }
    parts.join("+")
}

/// Apply `zone_rules` to the current process. Must run after pivot_root and
/// before the seccomp filter (landlock_* are not in the allowlist).
pub fn confine_pivoted_zone(home: &str, nic: bool) -> Result<(), LandlockError> {
    let mut rs = Ruleset::new()?;
    let mut rules = zone_rules(home);
    if nic {
        rules.extend(nic_zone_rules());
    }
    for r in rules {
        match rs.allow(&r.path, r.access) {
            Ok(()) => {}
            Err(e) if !r.required => {
                eprintln!("kryptikd: note: landlock: {} absent, no rule added ({e})", r.path);
            }
            Err(e) => return Err(e),
        }
    }
    rs.restrict_self()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_policy_accepts_and_refuses() {
        let p = parse_policy("# c\nread-exec /\nread-write /tmp\n\nread /usr/share # trailing\n", "t").unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!(p[0].path, "/");
        assert_eq!(p[0].access, ACCESS_READ | ACCESS_EXEC);
        assert_eq!(p[1].access, ACCESS_READ | ACCESS_WRITE);
        assert_eq!(p[2].path, "/usr/share");
        assert!(p.iter().all(|r| r.required), "a policy rule is never optional");
        for bad in [
            "read\n",                    // no path
            "read /tmp extra\n",         // two paths
            "deny /tmp\n",               // there is no deny
            "write /tmp\n",              // not a directive
            "read tmp\n",                // relative
            "read /tmp/../etc\n",        // climbing
            "read /tmp\nread /tmp\n",    // named twice
            "# only a comment\n",        // grants nothing
            "",
        ] {
            assert!(parse_policy(bad, "t").is_err(), "{bad:?} must be refused");
        }
        assert!(parse_policy("# only a comment\n", "t").unwrap_err().contains("grants nothing"));
    }

    /// Against the kernel, in a forked child: restrict_self is irreversible.
    #[test]
    fn second_layer_narrows_never_widens() {
        let dir = std::env::temp_dir().join(format!("kryptik-ll-{}", std::process::id()));
        let keep = dir.join("keep");
        let lose = dir.join("lose");
        std::fs::create_dir_all(&keep).unwrap();
        std::fs::create_dir_all(&lose).unwrap();
        std::fs::write(keep.join("f"), b"in").unwrap();
        std::fs::write(lose.join("f"), b"out").unwrap();

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let rc = (|| -> i32 {
                if abi_version().is_none_or(|a| a < MIN_ABI) {
                    return 77;
                }
                // Layer 1: read the whole tree, and write in `lose`.
                let mut base = match Ruleset::new() {
                    Ok(r) => r,
                    Err(_) => return 1,
                };
                if base.allow(dir.to_str().unwrap(), ACCESS_READ).is_err()
                    || base.allow(lose.to_str().unwrap(), ACCESS_READ | ACCESS_WRITE).is_err()
                    || base.restrict_self().is_err()
                {
                    return 2;
                }
                if std::fs::read(keep.join("f")).is_err() || std::fs::read(lose.join("f")).is_err() {
                    return 3; // both readable under layer 1 alone
                }
                // Layer 2: read-write on `keep` only; layer 1 never granted write.
                let rules = match parse_policy(&format!("read-write {}\n", keep.display()), "t") {
                    Ok(r) => r,
                    Err(_) => return 4,
                };
                if confine_further(&rules).is_err() {
                    return 5;
                }
                // Narrowed: layer 1 allowed `lose`, layer 2 does not.
                if std::fs::read(lose.join("f")).is_ok() {
                    return 6;
                }
                // Kept: both layers allow reading `keep`.
                if std::fs::read(keep.join("f")).is_err() {
                    return 7;
                }
                // Not widened: write on `keep` is still denied.
                if std::fs::write(keep.join("g"), b"x").is_ok() {
                    return 8;
                }
                0
            })();
            unsafe { libc::_exit(rc) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        let code = libc::WEXITSTATUS(status);
        let _ = std::fs::remove_dir_all(&dir);
        match code {
            0 => {}
            77 => eprintln!("landlock unavailable or too old here; skipping"),
            other => panic!("stacked-layer test failed at step {other}"),
        }
    }

    #[test]
    fn packed_attr_is_twelve_bytes() {
        // Same layout as the kernel's packed struct.
        assert_eq!(std::mem::size_of::<PathBeneathAttr>(), 12);
    }

    #[test]
    fn ruleset_attrs_have_expected_sizes() {
        assert_eq!(std::mem::size_of::<RulesetAttrV1>(), 8);
        assert_eq!(std::mem::size_of::<RulesetAttrV4>(), 16);
    }

    #[test]
    fn access_mask_grows_with_abi() {
        let v1 = access_mask_for(1);
        let v2 = access_mask_for(2);
        let v3 = access_mask_for(3);
        let v5 = access_mask_for(5);
        assert_eq!(v1 & FS_REFER, 0, "REFER must not be set on ABI v1");
        assert_ne!(v2 & FS_REFER, 0, "REFER should appear at ABI v2");
        assert_eq!(v2 & FS_TRUNCATE, 0, "TRUNCATE must not be set on ABI v2");
        assert_ne!(v3 & FS_TRUNCATE, 0, "TRUNCATE should appear at ABI v3");
        assert_eq!(v3 & FS_IOCTL_DEV, 0, "IOCTL_DEV must not be set on ABI v3");
        assert_ne!(v5 & FS_IOCTL_DEV, 0, "IOCTL_DEV should appear at ABI v5");
    }

    #[test]
    fn read_access_includes_dirs_and_files() {
        assert_ne!(ACCESS_READ & FS_READ_FILE, 0);
        assert_ne!(ACCESS_READ & FS_READ_DIR, 0);
    }

    #[test]
    fn write_access_includes_truncate_and_refer() {
        assert_ne!(ACCESS_WRITE & FS_TRUNCATE, 0);
        assert_ne!(ACCESS_WRITE & FS_REFER, 0);
        assert_ne!(ACCESS_WRITE_FILE & FS_TRUNCATE, 0);
        assert_eq!(ACCESS_WRITE_FILE & FS_MAKE_REG, 0, "write-file must not create");
    }

    #[test]
    fn device_node_creation_is_never_granted() {
        // MAKE_CHAR and MAKE_BLOCK are handled, so denied, and no rule grants them.
        for r in zone_rules("/home/t") {
            assert_eq!(r.access & (FS_MAKE_CHAR | FS_MAKE_BLOCK), 0, "{}", r.path);
        }
        assert_ne!(access_mask_for(MIN_ABI) & (FS_MAKE_CHAR | FS_MAKE_BLOCK), 0);
    }

    #[test]
    fn root_rule_never_grants_write() {
        // Rules are additive: write on "/" would be write on every mount under it.
        let rules = zone_rules("/home/t");
        let root = rules.iter().find(|r| r.path == "/").expect("no rule for /");
        assert_eq!(root.access & ACCESS_WRITE, 0, "/ must not be writable");
        assert_eq!(root.access & FS_WRITE_FILE, 0);
        assert!(root.required);
        let writable: Vec<&str> = rules
            .iter()
            .filter(|r| r.access & (FS_WRITE_FILE | FS_MAKE_REG) != 0)
            .map(|r| r.path.as_str())
            .collect();
        assert_eq!(writable, vec!["/home/t", "/tmp", "/dev", "/dev/shm", "/proc"]);
        // Only the data dir, /tmp and /dev/shm may create files.
        for r in &rules {
            if r.access & FS_MAKE_REG != 0 {
                assert!(
                    r.path == "/home/t" || r.path == "/tmp" || r.path == "/dev/shm",
                    "{} must not allow creating files",
                    r.path
                );
            }
        }
    }

    #[test]
    fn nic_zone_adds_state_dirs_without_exec() {
        let extra = nic_zone_rules();
        let paths: Vec<&str> = extra.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, vec!["/run", "/var/lib"]);
        for r in &extra {
            assert_eq!(r.access & ACCESS_EXEC, 0, "{} must not be executable", r.path);
            assert_ne!(r.access & FS_MAKE_REG, 0, "{} must allow creating files", r.path);
            assert!(r.required, "{} is a mount kryptikd made; its absence is a defect", r.path);
        }
        // No other zone gains them.
        assert!(zone_rules("/home/t").iter().all(|r| r.path != "/run" && r.path != "/var/lib"));
    }

    #[test]
    fn ruleset_can_be_created_when_supported() {
        match abi_version() {
            Some(v) if v >= MIN_ABI => {
                let rs = Ruleset::new().expect("ruleset creation should succeed");
                assert_eq!(rs.abi(), v);
            }
            Some(v) => {
                assert!(matches!(Ruleset::new(), Err(LandlockError::TooOld { .. })), "ABI {v}");
            }
            None => eprintln!("landlock unavailable on this kernel; skipping"),
        }
    }

    #[test]
    fn allow_rejects_nonexistent_path() {
        if abi_version().map_or(true, |v| v < MIN_ABI) {
            return;
        }
        let mut rs = Ruleset::new().unwrap();
        assert!(rs.allow("/definitely/not/a/real/path", ACCESS_READ).is_err());
    }

    #[test]
    fn describe_access_is_readable() {
        assert_eq!(describe_access(ACCESS_READ | ACCESS_EXEC), "read+exec");
        assert_eq!(describe_access(ACCESS_READ | ACCESS_WRITE_FILE), "read+write-existing-files");
        assert_eq!(describe_access(ACCESS_READ | ACCESS_WRITE | ACCESS_EXEC), "read+write+exec");
    }
}
