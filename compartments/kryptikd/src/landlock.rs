//! Landlock filesystem confinement.
//!
//! This is what makes requirements 2 and 4 of the Phase 5 exit test hold. A
//! mount namespace gives a zone its own mount *table*, not its own view of the
//! files — the adversarial test proved a zone could still read another zone's
//! data through the shared filesystem. Landlock closes that.
//!
//! Landlock is applied by the process to itself, cannot be removed once set,
//! and needs no privilege. That is why ADR-007 leans on it instead of a
//! traditional MAC layer.
//!
//! RULES ARE ADDITIVE. A path_beneath rule grants rights on everything under
//! its path, and a second rule on a sub-path can only ADD rights, never take
//! them away. An earlier version granted read+write+exec on "/" and then
//! listed /usr, /etc and friends as "read-only": those rules did nothing, and
//! the zone had full Landlock rights everywhere, including /dev and /proc. The
//! rule set in `zone_rules` therefore grants the WIDEST scope the FEWEST
//! rights and names every writable location explicitly.
//!
//! glibc does not wrap these syscalls, so they are invoked directly.

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;

// Filesystem access rights, by the ABI version that introduced them.
// Passing a bit the running kernel does not know makes create_ruleset return
// EINVAL, so the mask is trimmed to the reported ABI in `access_mask_for`.
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

/// Oldest ABI a zone may run on.
///
/// Below v3 the kernel cannot express TRUNCATE (v3) or REFER (v2): a ruleset
/// that names them would have those rights silently dropped, so "write" would
/// mean less than the policy says. Refuse rather than run with a policy whose
/// words and effect disagree. ABI 3 is Linux 6.2; Kryptik targets 6.18.
pub const MIN_ABI: i32 = 3;

/// Everything a zone may be granted on a path it is allowed to use.
pub const ACCESS_READ: u64 = FS_READ_FILE | FS_READ_DIR;
/// Full write: create, remove, rename, truncate. REFER is what lets a file be
/// renamed or linked into a different directory - without it `mv a dir/`
/// fails with EXDEV on ABI >= 2, which killed tar, cargo and git inside
/// zones. TRUNCATE is what `>` needs on an existing file.
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
/// Write to files that already exist, but create and remove nothing. What
/// /dev and /proc need: programs write /dev/null and /proc/self/oom_score_adj,
/// none of them should be able to create entries there.
pub const ACCESS_WRITE_FILE: u64 = FS_WRITE_FILE | FS_TRUNCATE;
pub const ACCESS_EXEC: u64 = FS_EXECUTE;
/// ioctl on device files (ABI 5+). Needed on /dev for terminals; not granted
/// anywhere else, so on a kernel that handles it a zone cannot ioctl a device
/// it somehow reaches outside /dev.
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

// MUST be packed. The kernel defines landlock_path_beneath_attr with
// __attribute__((packed)); a naturally-aligned Rust struct is 16 bytes instead
// of 12 and the kernel rejects it with EINVAL.
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

/// The set of access rights this kernel understands.
///
/// Trimmed to the reported ABI: a bit the kernel does not know is not ignored,
/// it makes ruleset creation fail outright.
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

/// A ruleset under construction.
///
/// Default-deny: creating the ruleset declares which access types are
/// *handled*, and anything handled is denied unless a rule allows it. Adding no
/// rules therefore produces a zone that can read nothing.
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

        // The attr struct grew in ABI v4. Passing the wrong size is EINVAL.
        // Later ABIs (v6 adds `scoped`) accept the v4 size and treat the
        // missing fields as zero.
        //
        // Both variants live on the stack. An earlier version used Box::leak,
        // which leaked one allocation per ruleset - unbounded in a long-running
        // kryptikd that creates a ruleset per zone start. The kernel copies the
        // struct during the call and does not retain the pointer, so a stack
        // local is correct and the borrow ends with the syscall.
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

    /// Allow `access` on everything beneath `path`.
    ///
    /// A path that does not exist is an error rather than a silent skip: a
    /// typo in a zone policy must not quietly widen or narrow confinement.
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
    ///
    /// PR_SET_NO_NEW_PRIVS is required first, and is set here rather than left
    /// to the caller: without it restrict_self returns EPERM, and a caller who
    /// ignored that error would run a zone with no filesystem confinement at
    /// all while believing it was confined.
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

/// Confine the current process to a zone's permitted paths.
///
/// Used by `kryptikd confine-test`, which confines the test process ITSELF in
/// the caller's mount namespace. `rootfs` gets read, write and execute;
/// everything else on the system becomes unreadable, including other zones'
/// data and the vault — which is exactly requirements 2 and 4.
pub fn confine_to_zone(rootfs: &str, extra_ro: &[&str]) -> Result<(), LandlockError> {
    let mut rs = Ruleset::new()?;
    rs.allow(rootfs, ACCESS_READ | ACCESS_WRITE | ACCESS_EXEC)?;
    for p in extra_ro {
        // Missing optional read-only paths are tolerated; the zone rootfs is not.
        let _ = rs.allow(p, ACCESS_READ | ACCESS_EXEC);
    }
    rs.restrict_self()
}

/// One Landlock rule for a pivoted zone: the path, the rights, and whether a
/// missing path is fatal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneRule {
    pub path: String,
    pub access: u64,
    pub required: bool,
}

/// The rule set for a zone that has already pivoted into its own root
/// (`rootfs::pivot_into`). Paths are as the ZONE sees them.
///
/// The widest rule, "/", grants read and execute only. Every mount that a
/// zone must not modify - the read-only system paths, the sealed root tmpfs,
/// /sys - is therefore denied write by Landlock as well as by its mount flags:
/// two independent controls, which is what the previous version claimed and
/// did not have. Writable places are named one by one.
pub fn zone_rules(home: &str) -> Vec<ZoneRule> {
    let rule = |path: &str, access: u64, required: bool| ZoneRule {
        path: path.to_string(),
        access,
        required,
    };
    vec![
        rule("/", ACCESS_READ | ACCESS_EXEC, true),
        // The zone's own data. Exec is allowed so a zone can run what it
        // builds or downloads; that is what dev and untrusted are for.
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
pub fn confine_pivoted_zone(home: &str) -> Result<(), LandlockError> {
    let mut rs = Ruleset::new()?;
    for r in zone_rules(home) {
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
    fn packed_attr_is_twelve_bytes() {
        // The kernel struct is packed; 16 bytes here means EINVAL at runtime.
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
        // Regression: without TRUNCATE, `echo x > existing` was denied inside
        // a zone; without REFER, `mv a dir/` failed with EXDEV.
        assert_ne!(ACCESS_WRITE & FS_TRUNCATE, 0);
        assert_ne!(ACCESS_WRITE & FS_REFER, 0);
        assert_ne!(ACCESS_WRITE_FILE & FS_TRUNCATE, 0);
        assert_eq!(ACCESS_WRITE_FILE & FS_MAKE_REG, 0, "write-file must not create");
    }

    #[test]
    fn device_node_creation_is_never_granted() {
        // MAKE_CHAR and MAKE_BLOCK are handled (denied by default) and no rule
        // grants them, so a zone cannot create device nodes anywhere even
        // where it can create files.
        for r in zone_rules("/home/t") {
            assert_eq!(r.access & (FS_MAKE_CHAR | FS_MAKE_BLOCK), 0, "{}", r.path);
        }
        assert_ne!(access_mask_for(MIN_ABI) & (FS_MAKE_CHAR | FS_MAKE_BLOCK), 0);
    }

    #[test]
    fn root_rule_never_grants_write() {
        // The regression test for the additive-rules bug: any write right on
        // "/" is a write right on every mount beneath it, and the read-only
        // rules for /usr and friends would be decoration.
        let rules = zone_rules("/home/t");
        let root = rules.iter().find(|r| r.path == "/").expect("no rule for /");
        assert_eq!(root.access & ACCESS_WRITE, 0, "/ must not be writable");
        assert_eq!(root.access & FS_WRITE_FILE, 0);
        assert!(root.required);
        // And the writable places are exactly the ones a zone may change.
        let writable: Vec<&str> = rules
            .iter()
            .filter(|r| r.access & (FS_WRITE_FILE | FS_MAKE_REG) != 0)
            .map(|r| r.path.as_str())
            .collect();
        assert_eq!(writable, vec!["/home/t", "/tmp", "/dev", "/dev/shm", "/proc"]);
        // Only the data dir and /tmp may create files.
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
    fn allow_rejects_a_nonexistent_path() {
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
