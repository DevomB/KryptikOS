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

/// Everything a zone may be granted on a path it is allowed to use.
pub const ACCESS_READ: u64 = FS_READ_FILE | FS_READ_DIR;
pub const ACCESS_WRITE: u64 =
    FS_WRITE_FILE | FS_REMOVE_DIR | FS_REMOVE_FILE | FS_MAKE_DIR | FS_MAKE_REG
        | FS_MAKE_SYM | FS_MAKE_SOCK | FS_MAKE_FIFO;
pub const ACCESS_EXEC: u64 = FS_EXECUTE;

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
        let handled = access_mask_for(abi);

        // The attr struct grew in ABI v4. Passing the wrong size is EINVAL.
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
/// `rootfs` is the zone's own filesystem; it gets read, write and execute.
/// Everything else on the system becomes unreadable, including other zones'
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

/// Like `confine_to_zone`, but a few paths need write access as well as read.
///
/// /dev/null and /dev/tty are written by essentially every program, and /proc
/// takes writes for things like /proc/self/oom_score_adj. Granting read-only
/// there produces failures that look like the program is broken rather than
/// confined.
pub fn confine_to_zone_with_dev(
    rootfs: &str,
    read_only: &[&str],
    read_write: &[&str],
) -> Result<(), LandlockError> {
    let mut rs = Ruleset::new()?;
    rs.allow(rootfs, ACCESS_READ | ACCESS_WRITE | ACCESS_EXEC)?;
    for p in read_only {
        let _ = rs.allow(p, ACCESS_READ | ACCESS_EXEC);
    }
    for p in read_write {
        let _ = rs.allow(p, ACCESS_READ | ACCESS_WRITE | ACCESS_EXEC);
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
        assert_eq!(v1 & FS_REFER, 0, "REFER must not be set on ABI v1");
        assert_ne!(v2 & FS_REFER, 0, "REFER should appear at ABI v2");
        assert_eq!(v2 & FS_TRUNCATE, 0, "TRUNCATE must not be set on ABI v2");
        assert_ne!(v3 & FS_TRUNCATE, 0, "TRUNCATE should appear at ABI v3");
    }

    #[test]
    fn read_access_includes_dirs_and_files() {
        assert_ne!(ACCESS_READ & FS_READ_FILE, 0);
        assert_ne!(ACCESS_READ & FS_READ_DIR, 0);
    }

    #[test]
    fn ruleset_can_be_created_when_supported() {
        match abi_version() {
            Some(v) => {
                let rs = Ruleset::new().expect("ruleset creation should succeed");
                assert_eq!(rs.abi(), v);
            }
            None => eprintln!("landlock unavailable on this kernel; skipping"),
        }
    }

    #[test]
    fn allow_rejects_a_nonexistent_path() {
        if abi_version().is_none() {
            return;
        }
        let mut rs = Ruleset::new().unwrap();
        assert!(rs.allow("/definitely/not/a/real/path", ACCESS_READ).is_err());
    }
}
