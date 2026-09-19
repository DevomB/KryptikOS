//! Building a real zone root with pivot_root.
//!
//! WHY THIS EXISTS
//!
//! Zones originally ran in the caller's mount namespace with Landlock as the
//! only filesystem control. That was not isolation, and an adversarial review
//! demonstrated two escapes against it without touching a kernel bug:
//!
//!   * an inherited file descriptor read a file outside the zone, because
//!     Landlock does not revoke descriptors that were already open when the
//!     ruleset was applied;
//!   * chmod changed the mode of a file outside the zone, because Landlock
//!     ABI 3 has no right governing metadata changes and the zone's uid maps
//!     to the launching user, who owns those files.
//!
//! Both have the same root cause: outside paths still EXISTED in the zone's
//! mount namespace. A path-based permission layer cannot fix that, because the
//! problem is not permission, it is reachability.
//!
//! pivot_root replaces the zone's root with a tree containing only what the
//! zone is meant to see. Landlock then becomes defense in depth over a much
//! smaller surface rather than the only thing standing between zones.
//!
//! WHAT THE TREE IS MADE OF
//!
//! The root itself is a fresh tmpfs that lives only as long as the zone.
//! Every mount point in it is created by kryptikd on that tmpfs, so nothing
//! the zone wrote during a previous run can be a mount target. The first
//! version built the tree directly inside the persistent zone directory,
//! which the zone owns and can fill with symlinks: a planted `usr -> ...`
//! link would have redirected the next run's bind mounts. The persistent
//! directory is now bound in at ONE place, /home/<zone>, non-recursively,
//! and is never walked as a mount target.
//!
//! The system paths are bound read-only ALL THE WAY DOWN. A plain
//! `mount -o remount,bind,ro` changes one mount only: on a host where /usr
//! has submounts, the first version left those submounts read-write inside
//! the zone (observed: /usr/lib/modules rw on WSL). mount_setattr(2) with
//! AT_RECURSIVE fixes the whole tree, and on a kernel too old to have it
//! the zone refuses to start rather than start with a writable hole.
//!
//! /etc is not the host's. It is a synthesized minimum: passwd/group naming
//! the zone's single user, hosts and hostname naming the zone, nsswitch.conf,
//! plus a read-only view of a few non-secret host files (ld.so.cache, the CA
//! bundle, alternatives). The host's machine-id, ssh configuration, private
//! keys, shadow, fstab and every other file that describes the machine or
//! its owner do not exist inside a zone.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Debug)]
pub enum RootfsError {
    Syscall { call: &'static str, path: String, errno: i32 },
    Setup(String),
}

impl std::fmt::Display for RootfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RootfsError::Syscall { call, path, errno } => write!(
                f,
                "{call}({path}): {}",
                io::Error::from_raw_os_error(*errno)
            ),
            RootfsError::Setup(m) => write!(f, "{m}"),
        }
    }
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn cs(s: &str) -> Result<CString, RootfsError> {
    CString::new(s).map_err(|_| RootfsError::Setup(format!("path contains NUL: {s}")))
}

fn mount_raw(
    src: &str,
    target: &str,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
    call: &'static str,
) -> Result<(), RootfsError> {
    let c_src = cs(src)?;
    let c_tgt = cs(target)?;
    let c_fst = match fstype {
        Some(f) => Some(cs(f)?),
        None => None,
    };
    let c_data = match data {
        Some(d) => Some(cs(d)?),
        None => None,
    };

    let ret = unsafe {
        libc::mount(
            c_src.as_ptr(),
            c_tgt.as_ptr(),
            c_fst.as_ref().map_or(std::ptr::null(), |f| f.as_ptr()),
            flags,
            c_data
                .as_ref()
                .map_or(std::ptr::null(), |d| d.as_ptr() as *const libc::c_void),
        )
    };
    if ret < 0 {
        return Err(RootfsError::Syscall {
            call,
            path: target.to_string(),
            errno: errno(),
        });
    }
    Ok(())
}

// --- mount_setattr(2) --------------------------------------------------------
//
// Linux 5.12+. The only interface that can make a whole bind tree read-only
// in one atomic step. glibc does not wrap it.

const SYS_MOUNT_SETATTR: libc::c_long = 442;
const AT_RECURSIVE: libc::c_uint = 0x8000;
const MOUNT_ATTR_RDONLY: u64 = 0x1;
const MOUNT_ATTR_NOSUID: u64 = 0x2;
const MOUNT_ATTR_NODEV: u64 = 0x4;
const MOUNT_ATTR_NOEXEC: u64 = 0x8;

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// Add mount attributes to `target`, and to every mount beneath it when
/// `recursive`. Only ever ADDS restrictions.
fn set_mount_attr(target: &str, attrs: u64, recursive: bool) -> Result<(), RootfsError> {
    let c = cs(target)?;
    let attr = MountAttr {
        attr_set: attrs,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    let flags: libc::c_uint = if recursive { AT_RECURSIVE } else { 0 };
    let ret = unsafe {
        libc::syscall(
            SYS_MOUNT_SETATTR,
            libc::AT_FDCWD,
            c.as_ptr(),
            flags,
            &attr as *const _ as *const libc::c_void,
            std::mem::size_of::<MountAttr>(),
        )
    };
    if ret < 0 {
        return Err(RootfsError::Syscall {
            call: "mount_setattr",
            path: target.to_string(),
            errno: errno(),
        });
    }
    Ok(())
}

/// Mount points strictly beneath `target` in this mount namespace.
fn submounts_under(target: &str) -> Vec<String> {
    let prefix = format!("{}/", target.trim_end_matches('/'));
    fs::read_to_string("/proc/self/mountinfo")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split(' ').nth(4).map(str::to_string))
        .filter(|mp| mp.starts_with(&prefix))
        .collect()
}

/// Make a bind tree read-only, nosuid, nodev all the way down.
///
/// Prefers mount_setattr. Without it, the legacy remount fixes only the top
/// mount, so if anything is mounted beneath the target the zone would get it
/// read-write - and that is refused rather than allowed.
fn make_ro_recursive(target: &str) -> Result<(), RootfsError> {
    match set_mount_attr(
        target,
        MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
        true,
    ) {
        Ok(()) => Ok(()),
        Err(RootfsError::Syscall { errno, .. }) if errno == libc::ENOSYS => {
            // TWO calls, and the second is not redundant. A bind mount SILENTLY
            // IGNORES MS_RDONLY on the initial call - it inherits the source's
            // flags - so the flag only takes effect on a subsequent remount.
            mount_raw(
                "none",
                target,
                None,
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID
                    | libc::MS_NODEV,
                None,
                "mount(remount,ro)",
            )?;
            let subs = submounts_under(target);
            if !subs.is_empty() {
                return Err(RootfsError::Setup(format!(
                    "{target} has {} submount(s) ({}) that this kernel cannot make \
                     read-only recursively (mount_setattr needs Linux 5.12+); \
                     refusing to expose them read-write",
                    subs.len(),
                    subs.join(", ")
                )));
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Bind-mount the directory `src` at `target`, read-only nosuid nodev,
/// recursively so that nothing under `src` is hidden by the bind and nothing
/// under it is writable.
fn bind_ro_dir(src: &str, target: &str) -> Result<(), RootfsError> {
    fs::create_dir_all(target)
        .map_err(|e| RootfsError::Setup(format!("{target}: {e}")))?;
    mount_raw(src, target, None, libc::MS_BIND | libc::MS_REC, None, "mount(bind)")?;
    make_ro_recursive(target)
}

/// Bind-mount the regular file `src` at `target`, read-only.
fn bind_ro_file(src: &str, target: &str) -> Result<(), RootfsError> {
    if let Some(parent) = Path::new(target).parent() {
        fs::create_dir_all(parent)
            .map_err(|e| RootfsError::Setup(format!("{}: {e}", parent.display())))?;
    }
    fs::File::create(target).map_err(|e| RootfsError::Setup(format!("{target}: {e}")))?;
    mount_raw(src, target, None, libc::MS_BIND, None, "mount(bind file)")?;
    // A file has no submounts; the legacy remount is exact here.
    match set_mount_attr(target, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, false) {
        Ok(()) => Ok(()),
        Err(RootfsError::Syscall { errno, .. }) if errno == libc::ENOSYS => mount_raw(
            "none",
            target,
            None,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
            None,
            "mount(remount,ro)",
        ),
        Err(e) => Err(e),
    }
}

/// System directories a zone needs in order to run ordinary programs.
///
/// Read-only, nosuid, nodev. A zone gets the system's binaries and libraries
/// but cannot modify them, and cannot gain privilege through a setuid binary
/// it finds there. /etc is deliberately NOT here: see `populate_etc`.
pub const SYSTEM_PATHS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin"];

/// Host files under /etc that a zone gets a read-only view of. Each is
/// public, machine-independent data that programs need at runtime.
///
/// NOT here, on purpose: ld.so.preload (the LD_PRELOAD of files), machine-id
/// (links zones to each other and to the host), hostname, hosts, passwd and
/// group (name the host's users; the zone gets synthesized ones), resolv.conf
/// (the zone's resolver will come from kryptikd with its network path),
/// localtime (host fingerprint; zones run UTC), everything under ssh/, ssl/
/// private/, sudoers, shadow, fstab, crypttab.
pub const ETC_RO_FILES: &[&str] = &[
    "/etc/ld.so.cache",
    "/etc/services",
    "/etc/protocols",
    // The DHCP client's shipped defaults (require the server identifier,
    // which options to ask for): the nic zone's dhcpcd reads them; no secret.
    "/etc/dhcpcd.conf",
];
pub const ETC_RO_DIRS: &[&str] = &["/etc/alternatives", "/etc/ssl/certs", "/etc/pki/tls/certs"];

/// Device nodes a zone is allowed. Anything not listed does not exist for it.
///
/// This replaces inheriting the caller's /dev wholesale, which was granting
/// far more than a zone should have - every disk, every tty, every input
/// device on the machine.
pub const DEVICES: &[(&str, &str)] = &[
    ("/dev/null", "null"),
    ("/dev/zero", "zero"),
    ("/dev/full", "full"),
    ("/dev/random", "random"),
    ("/dev/urandom", "urandom"),
    ("/dev/tty", "tty"),
];

/// The zone's home: where its persistent directory appears inside the zone.
/// The proxy socket's name inside the zone; WAYLAND_DISPLAY names it by
/// absolute path.
pub const WAYLAND_SOCKET_NAME: &str = "wayland-0";
pub const WAYLAND_SOCKET_IN_ZONE: &str = "/run/kryptik/wayland-0";

pub fn zone_home(zone: &str) -> String {
    format!("/home/{zone}")
}

/// Synthesized /etc/passwd. One user - the zone's root - and nobody.
pub fn passwd_for(zone: &str, home: &str) -> String {
    format!(
        "root:x:0:0:{zone}:{home}:/bin/sh\n\
         nobody:x:65534:65534:nobody:/nonexistent:/bin/false\n"
    )
}

pub fn group_for() -> String {
    "root:x:0:\nnogroup:x:65534:\n".to_string()
}

pub fn nsswitch() -> String {
    "passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n\
     services: files\nprotocols: files\n"
        .to_string()
}

pub fn hosts_for(zone: &str) -> String {
    format!("127.0.0.1 localhost {zone}\n::1 localhost {zone}\n")
}

/// What a zone finds at /etc/resolv.conf (docs/design/net-zone.md, DNS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolver {
    /// No file at all: offline zones, and routed zones that got no path.
    None,
    /// A routed zone with a path: the nic zone's bridge address answers
    /// (once the stub resolver lands there); nothing else is ever named.
    Bridge,
    /// The nic zone: its DHCP client writes the file. The root tmpfs is
    /// sealed read-only, so /etc/resolv.conf is a symlink into the zone's
    /// private /tmp, where the client can write it.
    Writable,
}

pub fn resolv_conf_for_bridge() -> String {
    "nameserver 10.19.0.1\nnameserver fd19::1\n".to_string()
}

/// Refuse a zone data directory that is not a plain directory owned by the
/// identity the zone will run as.
///
/// A symlink here would redirect the bind mount to wherever it points; a
/// directory owned by someone else would expose their files under the zone's
/// mapped root.
/// Refuse an ephemeral zone whose persistent directory is not empty.
///
/// This is what turns "labelled ephemeral" into "cannot have been persistent".
/// An ephemeral zone's data lives in a tmpfs that exists only inside its mount
/// namespace, so nothing it writes reaches this directory - but a directory
/// left behind by an earlier build, or by the same zone before it was declared
/// ephemeral, would sit on disk unreferenced and unwiped while the operator
/// believed the zone kept nothing. Refusing is the only honest answer: kryptikd
/// must not delete data it did not create.
pub fn check_data_dir_empty(path: &str, zone: &str) -> Result<(), RootfsError> {
    let entries = fs::read_dir(path)
        .map_err(|e| RootfsError::Setup(format!("{path}: {e}")))?;
    let leftovers: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .take(6)
        .collect();
    if leftovers.is_empty() {
        return Ok(());
    }
    Err(RootfsError::Setup(format!(
        "ephemeral zone {zone:?} has persistent data in {path} from an earlier run \
         ({}); move or delete it. An ephemeral zone keeps nothing, so kryptikd will \
         not start one over data it did not write and must not silently destroy.",
        leftovers.join(", ")
    )))
}

pub fn check_data_dir(path: &str, expected_uid: u32) -> Result<(), RootfsError> {
    let md = fs::symlink_metadata(path)
        .map_err(|e| RootfsError::Setup(format!("{path}: {e}")))?;
    if md.file_type().is_symlink() {
        return Err(RootfsError::Setup(format!(
            "zone data directory {path} is a symlink; refusing to follow it"
        )));
    }
    if !md.is_dir() {
        return Err(RootfsError::Setup(format!(
            "zone data directory {path} is not a directory"
        )));
    }
    if md.uid() != expected_uid {
        return Err(RootfsError::Setup(format!(
            "zone data directory {path} is owned by uid {} but the zone maps to uid {}; \
             refusing to expose another identity's files",
            md.uid(),
            expected_uid
        )));
    }
    Ok(())
}

/// Replace the zone's root with a tree containing only what it should see.
/// Returns the zone's home path (where `data_dir` is visible from inside).
///
/// Must be called after unshare(CLONE_NEWNS) and after the uid map is written,
/// because pivot_root needs CAP_SYS_ADMIN in the new user namespace. Must be
/// called BEFORE the Landlock ruleset and the seccomp filter: both mount() and
/// pivot_root() are absent from the zone syscall allowlist, deliberately, so
/// doing this afterwards would kill the zone during its own construction.
/// `ephemeral` carries the tmpfs size for a `storage.mode = "ephemeral"` zone.
/// `None` means the persistent directory is bound at the zone's home, as
/// before. `wifi_conf` is the host path of the net zone's Wi-Fi credentials
/// file (wifi.rs), given for the nic zone only; it is bound read-only at
/// /etc/wpa_supplicant.conf when it exists and ignored when it does not.
pub fn pivot_into(
    data_dir: &str,
    zone: &str,
    ephemeral: Option<&str>,
    resolver: Resolver,
    broker: Option<&str>,
    wayland: Option<&str>,
    wifi_conf: Option<&str>,
) -> Result<String, RootfsError> {
    let home = zone_home(zone);

    // The whole tree must be private first, or every mount below propagates
    // back to the host namespace.
    mount_raw(
        "none",
        "/",
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
        "mount(private)",
    )?;

    // Take a handle on the data directory BEFORE hiding it under the root
    // tmpfs. O_NOFOLLOW: a symlink was already refused by check_data_dir, but
    // the check and the open are two steps, and the second must not follow
    // what the first rejected.
    //
    // An ephemeral zone takes no such handle: its home is a fresh tmpfs and the
    // persistent directory is never bound anywhere. -1 stands for "there is no
    // data directory to expose", which is the entire point of the mode.
    let data_fd = if ephemeral.is_some() {
        -1
    } else {
        let c_data = cs(data_dir)?;
        let fd = unsafe {
            libc::open(
                c_data.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(RootfsError::Syscall {
                call: "open(data dir)",
                path: data_dir.to_string(),
                errno: errno(),
            });
        }
        fd
    };

    // The root of the zone: a fresh tmpfs mounted over the data directory's
    // path. Every mount point below is created here, by us, on a filesystem
    // nothing else has ever written to.
    let root = data_dir;
    mount_raw(
        "tmpfs",
        root,
        Some("tmpfs"),
        (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
        Some("mode=0755,size=16m"),
        "mount(root tmpfs)",
    )?;
    let mkdir = |rel: &str| -> Result<String, RootfsError> {
        let p = format!("{root}/{rel}");
        fs::create_dir_all(&p).map_err(|e| RootfsError::Setup(format!("{p}: {e}")))?;
        Ok(p)
    };

    // --- system paths, read-only all the way down --------------------------
    for p in SYSTEM_PATHS {
        // A path missing on the host is skipped rather than fatal: /lib64 does
        // not exist everywhere. is_dir follows symlinks, so a merged-usr /bin
        // becomes a mount of /usr/bin, which is what programs expect.
        if Path::new(p).is_dir() {
            bind_ro_dir(p, &format!("{root}{p}"))?;
        }
    }

    populate_etc(root, zone, &home, resolver)?;

    // Fresh /proc, showing only this zone's pid namespace.
    let proc_dir = mkdir("proc")?;
    mount_raw(
        "proc",
        &proc_dir,
        Some("proc"),
        (libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV) as libc::c_ulong,
        None,
        "mount(proc)",
    )?;

    // Fresh sysfs, showing only this zone's network namespace. Read-only: a
    // zone has no business writing to /sys. Can legitimately fail in a nested
    // namespace; sysfs is informational and the network namespace is the
    // actual control.
    let sys_dir = mkdir("sys")?;
    let _ = mount_raw(
        "sysfs",
        &sys_dir,
        Some("sysfs"),
        (libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV | libc::MS_RDONLY)
            as libc::c_ulong,
        None,
        "mount(sysfs)",
    );

    populate_dev(root)?;

    // Private /tmp. Without this a zone shares the host's, which is a
    // cross-zone channel and a classic symlink-attack surface.
    let tmp_dir = mkdir("tmp")?;
    mount_raw(
        "tmpfs",
        &tmp_dir,
        Some("tmpfs"),
        (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
        Some("mode=1777"),
        "mount(tmp)",
    )?;

    // --- the nic zone's own /run and /var/lib -------------------------------
    // The network stack's daemons keep their state where they were built to:
    // pid files, control sockets and the resolver's upstream list under /run,
    // the DHCP lease database under /var/lib. In the nic zone both are
    // private tmpfs mounts, empty when the zone starts and gone with it;
    // nothing of the host's /run or /var is in them, and the socket binds
    // below land on top of the first. Every other zone sees no /var at all
    // and a /run on the sealed root that holds only what kryptikd binds
    // there. Without these the first net zone's dhcpcd died on its pid file
    // ("/run/dhcpcd: Read-only file system") and the routed zones had no
    // path out, which the guest check reported as "no READY line".
    if resolver == Resolver::Writable {
        for (rel, call) in [("run", "mount(nic /run tmpfs)"), ("var/lib", "mount(nic /var/lib tmpfs)")] {
            let d = mkdir(rel)?;
            mount_raw(
                "tmpfs",
                &d,
                Some("tmpfs"),
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
                Some("mode=0755,size=8m"),
                call,
            )?;
        }
    }

    // --- the net zone's Wi-Fi credentials, at /etc/wpa_supplicant.conf ------
    // Written in zone 0 by kryptikd (wifi.rs), 0400 and owned by this zone's
    // identity, which is what lets the supplicant the zone runs read it
    // while nothing else on the host can. Bound read-only, on a mount point
    // kryptikd creates on the root tmpfs like every other bound file. No
    // file means no networks are configured: nothing is mounted and nothing
    // is said here; the zone's own program reports that it is unconfigured.
    if let Some(conf) = wifi_conf {
        if fs::metadata(conf).map(|m| m.is_file()).unwrap_or(false) {
            bind_ro_file(conf, &format!("{root}{}", crate::wifi::IN_ZONE))?;
        }
    }

    // --- the broker socket, at /run/kryptik/broker --------------------------
    // The one thing under /run a zone sees: its own broker endpoint, a socket
    // file bound in from the registry entry. connect(2) on a Unix socket path
    // is not a Landlock filesystem access, and the file is owned by the zone
    // identity with mode 0600, so the zone can reach it and nothing else can.
    if let Some(sock) = broker {
        let rk = mkdir("run/kryptik")?;
        let target = format!("{rk}/{}", crate::broker::SOCKET_NAME);
        // Read-only like every other bound file: connect(2) needs no write
        // access to a socket inode (S_ISSOCK is exempt from the read-only
        // check), and nothing else the zone could do to the file is wanted.
        bind_ro_file(sock, &target)?;
    }
    // --- the Wayland proxy socket, at /run/kryptik/wayland-0 ---------------
    // The second and last thing under /run a zone sees: the
    // per-zone kryptik-wlproxy endpoint, bound in the same way. The
    // compositor's own socket is never reachable from a zone.
    if let Some(sock) = wayland {
        let rk = mkdir("run/kryptik")?;
        let target = format!("{rk}/{}", WAYLAND_SOCKET_NAME);
        bind_ro_file(sock, &target)?;
    }

    // --- the zone's own data, at /home/<zone> ------------------------------
    // Bound through the descriptor taken above, so it is the directory that
    // was checked, not whatever the path resolves to now. NON-recursive: a
    // mount the operator (or anything else) placed inside the data directory
    // is not carried into the zone. The kernel refuses a non-recursive bind
    // of a tree with locked submounts with EINVAL, which surfaces as a clear
    // error rather than a silently missing directory.
    let home_dir = mkdir(&home[1..])?;
    if let Some(size) = ephemeral {
        // A per-launch tmpfs, in the zone's OWN mount namespace. When pid 1
        // dies the namespace is released and the kernel frees these pages -
        // there is no unmount step to forget and no teardown path that can be
        // skipped by a crash, which is why the guarantee survives kill -9.
        //
        // mode=0700 and uid/gid 0: the zone's root inside its user namespace,
        // which is the unprivileged host uid it maps to.
        mount_raw(
            "tmpfs",
            &home_dir,
            Some("tmpfs"),
            (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
            Some(&format!("mode=0700,uid=0,gid=0,size={size}")),
            "mount(ephemeral home tmpfs)",
        )?;
    } else {
        let via_fd = format!("/proc/self/fd/{data_fd}");
        mount_raw(&via_fd, &home_dir, None, libc::MS_BIND, None, "mount(bind zone data)")
            .map_err(|e| match e {
                RootfsError::Syscall { errno, .. } if errno == libc::EINVAL => RootfsError::Setup(
                    format!("{data_dir} contains mounts of its own; a zone data directory must be plain"),
                ),
                other => other,
            })?;
        unsafe { libc::close(data_fd) };
    }
    if let Err(e) = set_mount_attr(&home_dir, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, false) {
        // nosuid is moot under no_new_privs and nodev under Landlock's
        // MAKE_CHAR/MAKE_BLOCK denial; say so rather than fail the zone.
        eprintln!("kryptikd: note: could not set nosuid,nodev on {home}: {e}");
    }

    // --- pivot ------------------------------------------------------------
    let old_root = mkdir(".oldroot")?;
    let c_new = cs(root)?;
    let c_old = cs(&old_root)?;
    let ret = unsafe { libc::syscall(libc::SYS_pivot_root, c_new.as_ptr(), c_old.as_ptr()) };
    if ret < 0 {
        return Err(RootfsError::Syscall {
            call: "pivot_root",
            path: root.to_string(),
            errno: errno(),
        });
    }

    let slash = cs("/")?;
    if unsafe { libc::chdir(slash.as_ptr()) } < 0 {
        return Err(RootfsError::Syscall {
            call: "chdir",
            path: "/".into(),
            errno: errno(),
        });
    }

    // Detach the old root. Until this runs the entire host filesystem is still
    // mounted at /.oldroot and the zone can simply walk into it - which would
    // make everything above pointless.
    let c_oldmount = cs("/.oldroot")?;
    if unsafe { libc::umount2(c_oldmount.as_ptr(), libc::MNT_DETACH) } < 0 {
        return Err(RootfsError::Syscall {
            call: "umount2",
            path: "/.oldroot".into(),
            errno: errno(),
        });
    }
    let _ = fs::remove_dir("/.oldroot");

    // Seal the root. The scaffold is complete; nothing may add to it now,
    // not even the zone's root user.
    match set_mount_attr(
        "/",
        MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC,
        false,
    ) {
        Ok(()) => {}
        Err(RootfsError::Syscall { errno, .. }) if errno == libc::ENOSYS => mount_raw(
            "none",
            "/",
            None,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID
                | libc::MS_NODEV | libc::MS_NOEXEC,
            None,
            "mount(seal root)",
        )?,
        Err(e) => return Err(e),
    }

    Ok(home)
}

/// The zone's /etc: synthesized identity files plus a read-only view of a
/// few non-secret host files. See the module comment for what is left out.
fn populate_etc(root: &str, zone: &str, home: &str, resolver: Resolver) -> Result<(), RootfsError> {
    let etc = format!("{root}/etc");
    fs::create_dir_all(&etc).map_err(|e| RootfsError::Setup(format!("{etc}: {e}")))?;
    let write = |name: &str, content: String| -> Result<(), RootfsError> {
        let p = format!("{etc}/{name}");
        fs::write(&p, content).map_err(|e| RootfsError::Setup(format!("{p}: {e}")))
    };
    write("passwd", passwd_for(zone, home))?;
    write("group", group_for())?;
    write("nsswitch.conf", nsswitch())?;
    write("hosts", hosts_for(zone))?;
    write("hostname", format!("{zone}\n"))?;
    match resolver {
        Resolver::None => {}
        Resolver::Bridge => write("resolv.conf", resolv_conf_for_bridge())?,
        Resolver::Writable => {
            std::os::unix::fs::symlink("/tmp/resolv.conf", format!("{etc}/resolv.conf"))
                .map_err(|e| RootfsError::Setup(format!("{etc}/resolv.conf: {e}")))?;
        }
    }

    for f in ETC_RO_FILES {
        // metadata() follows symlinks: only a real regular file is bound.
        if fs::metadata(f).map(|m| m.is_file()).unwrap_or(false) {
            bind_ro_file(f, &format!("{root}{f}"))?;
        }
    }
    for d in ETC_RO_DIRS {
        if Path::new(d).is_dir() {
            bind_ro_dir(d, &format!("{root}{d}"))?;
        }
    }
    Ok(())
}

/// A minimal /dev on tmpfs, with exactly the nodes in DEVICES bind-mounted
/// in, a private /dev/shm, a private devpts, and the usual convenience
/// symlinks. Creating nodes with mknod would need real CAP_MKNOD on the
/// host; bind-mounting the host's nodes achieves the same visibility without
/// it.
fn populate_dev(root: &str) -> Result<(), RootfsError> {
    let dev_dir = format!("{root}/dev");
    fs::create_dir_all(&dev_dir).map_err(|e| RootfsError::Setup(e.to_string()))?;
    mount_raw(
        "tmpfs",
        &dev_dir,
        Some("tmpfs"),
        (libc::MS_NOSUID | libc::MS_NOEXEC) as libc::c_ulong,
        Some("mode=0755,size=1M"),
        "mount(dev tmpfs)",
    )?;
    for (host, name) in DEVICES {
        if !Path::new(host).exists() {
            continue;
        }
        let target = format!("{dev_dir}/{name}");
        fs::File::create(&target).map_err(|e| RootfsError::Setup(e.to_string()))?;
        // Device nodes are bound individually; a failure here is not fatal,
        // but a zone without /dev/null behaves very strangely, so say so.
        if mount_raw(host, &target, None, libc::MS_BIND, None, "mount(dev node)").is_err() {
            eprintln!("kryptikd: warning: could not provide {host} to the zone");
        }
    }

    // POSIX shared memory. Private to the zone; noexec.
    let shm = format!("{dev_dir}/shm");
    fs::create_dir_all(&shm).map_err(|e| RootfsError::Setup(e.to_string()))?;
    mount_raw(
        "tmpfs",
        &shm,
        Some("tmpfs"),
        (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
        Some("mode=1777,size=256m"),
        "mount(dev/shm)",
    )?;

    // Pseudo-terminals, a private instance. Best effort: terminal programs
    // need it, nothing about isolation does.
    let pts = format!("{dev_dir}/pts");
    fs::create_dir_all(&pts).map_err(|e| RootfsError::Setup(e.to_string()))?;
    match mount_raw(
        "devpts",
        &pts,
        Some("devpts"),
        (libc::MS_NOSUID | libc::MS_NOEXEC) as libc::c_ulong,
        Some("newinstance,ptmxmode=0666,mode=0620"),
        "mount(devpts)",
    ) {
        Ok(()) => {
            let _ = std::os::unix::fs::symlink("pts/ptmx", format!("{dev_dir}/ptmx"));
        }
        Err(e) => eprintln!("kryptikd: note: no private devpts for the zone: {e}"),
    }

    for (link, target) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        let _ = std::os::unix::fs::symlink(target, format!("{dev_dir}/{link}"));
    }
    Ok(())
}

// --- descriptors --------------------------------------------------------------

/// Make sure descriptors 0, 1 and 2 are open before anything else happens.
///
/// If the caller closed one, the zone's first open() would land on it and a
/// program writing to "stdout" would write into whatever file that was.
pub fn ensure_stdio() {
    let devnull = cs("/dev/null").expect("static path");
    for fd in 0..=2 {
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 {
            continue;
        }
        let got = unsafe { libc::open(devnull.as_ptr(), libc::O_RDWR) };
        if got >= 0 && got != fd {
            // Lowest-free-descriptor semantics should have given us `fd`;
            // if not, do not leave a stray open.
            unsafe { libc::close(got) };
        }
    }
}

/// Close every descriptor above stderr before handing control to the zone.
///
/// The other half of the inherited-descriptor escape. Landlock governs paths,
/// not descriptors already open when the ruleset is applied, so a caller that
/// leaks an fd hands the zone a direct read into whatever it points at - which
/// is exactly how a file outside the zone was read during review.
///
/// pivot_root alone does not fix this: an open descriptor keeps working
/// regardless of what the mount namespace now looks like.
///
/// Descriptors 0, 1 and 2 are the ONLY inherited channels, by design: they
/// are how the operator talks to the zone. Anything else the caller had open
/// - including a descriptor deliberately passed with `3<file` - is closed.
pub fn close_inherited_fds() {
    if close_via_close_range() {
        return;
    }
    if close_via_proc() {
        return;
    }
    close_by_sweep(highest_possible_fd());
}

/// close_range(2), Linux 5.9+: closes every descriptor in one call whatever
/// its number, without consulting /proc.
fn close_via_close_range() -> bool {
    unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3 as libc::c_uint,
            libc::c_uint::MAX,
            0 as libc::c_uint,
        ) == 0
    }
}

/// Enumerate /proc/self/fd. Authoritative when readable.
fn close_via_proc() -> bool {
    let entries = match fs::read_dir("/proc/self/fd") {
        Ok(e) => e,
        Err(_) => return false,
    };
    let fds: Vec<i32> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok()))
        .collect();
    // The read_dir handle itself is in the list and is already closed by
    // now; closing it again is a harmless EBADF.
    for fd in fds {
        if fd > 2 {
            unsafe { libc::close(fd) };
        }
    }
    true
}

/// The highest descriptor number a process on this kernel could hold: the
/// system-wide nr_open, which no RLIMIT_NOFILE can exceed. An inherited fd
/// can sit above the current soft limit (the limit may have been lowered
/// after it was opened), so a sweep to the soft limit would miss it. Bounded
/// so a hostile value cannot turn this into a minutes-long loop.
pub(crate) fn highest_possible_fd() -> i32 {
    let nr_open: i32 = fs::read_to_string("/proc/sys/fs/nr_open")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    let hard: i32 = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0 {
        i32::try_from(rl.rlim_max).unwrap_or(i32::MAX)
    } else {
        0
    };
    nr_open.max(hard).max(1 << 20).min(1 << 22)
}

/// Last resort: close every number from 3 up to `max`.
pub(crate) fn close_by_sweep(max: i32) {
    for fd in 3..max {
        unsafe { libc::close(fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run `body` in a forked child and return its exit status. The tests
    /// below manipulate descriptors and mount namespaces, which must never
    /// happen in the shared test process: an earlier version of the fd test
    /// closed the test harness's own descriptors out from under the other
    /// test threads.
    fn in_child(body: impl FnOnce() -> i32) -> i32 {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let rc = body();
            unsafe { libc::_exit(rc) };
        }
        let mut status = 0;
        loop {
            let r = unsafe { libc::waitpid(pid, &mut status, 0) };
            if r == pid {
                break;
            }
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EINTR));
        }
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            200 + libc::WTERMSIG(status)
        }
    }

    const SKIP: i32 = 77;

    fn is_open(fd: i32) -> bool {
        (unsafe { libc::fcntl(fd, libc::F_GETFD) }) >= 0
    }

    /// Open /dev/null at a specific descriptor number.
    fn open_at(fd: i32) {
        let c = CString::new("/dev/null").unwrap();
        let f = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
        assert!(f >= 0);
        assert!(unsafe { libc::dup2(f, fd) } == fd, "dup2 to {fd} failed");
        // dup2(f, f) is a no-op, and closing f would then close the very
        // descriptor this helper was asked to open. That is exactly what
        // happened in a forked child whose lowest free descriptor was 3.
        if f != fd {
            unsafe { libc::close(f) };
        }
    }

    #[test]
    fn system_paths_are_absolute_and_exclude_etc() {
        for p in SYSTEM_PATHS {
            assert!(p.starts_with('/'), "{p} must be absolute");
            assert_ne!(*p, "/etc", "/etc is synthesized, never bound wholesale");
        }
    }

    #[test]
    fn device_list_is_minimal_and_safe() {
        // A zone gets character devices that carry no data about the host.
        // Anything granting access to real hardware - disks, input devices,
        // the kernel's memory - must never appear here.
        for (host, _) in DEVICES {
            assert!(host.starts_with("/dev/"), "{host} is not under /dev");
            for banned in ["mem", "kmem", "port", "sda", "nvme", "input", "kvm"] {
                assert!(
                    !host.contains(banned),
                    "{host} exposes hardware a zone must not reach"
                );
            }
        }
    }

    #[test]
    fn etc_view_contains_no_identity_or_secret_files() {
        let all: Vec<&str> = ETC_RO_FILES.iter().chain(ETC_RO_DIRS).copied().collect();
        for banned in [
            "/etc/machine-id", "/etc/hostname", "/etc/hosts", "/etc/passwd", "/etc/group",
            "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/ssh", "/etc/ssl/private",
            "/etc/ld.so.preload", "/etc/fstab", "/etc/crypttab", "/etc/resolv.conf",
            "/etc/localtime", "/etc",
        ] {
            assert!(!all.contains(&banned), "{banned} must not be exposed to a zone");
        }
        for p in &all {
            assert!(p.starts_with("/etc/"), "{p}");
            assert!(!p.starts_with("/etc/ssl/private"), "{p}");
        }
    }

    #[test]
    fn the_bridge_resolver_names_only_the_bridge() {
        let r = resolv_conf_for_bridge();
        assert_eq!(r.lines().count(), 2);
        assert!(r.contains("nameserver 10.19.0.1") && r.contains("nameserver fd19::1"));
        assert!(!r.contains("10.0.2.3"), "must never name a host or slirp resolver");
    }

    #[test]
    fn synthesized_identity_names_the_zone_not_the_host() {
        let pw = passwd_for("work", "/home/work");
        assert!(pw.starts_with("root:x:0:0:work:/home/work:"), "{pw}");
        assert_eq!(pw.lines().count(), 2);
        assert!(hosts_for("work").contains("127.0.0.1 localhost work"));
        assert_eq!(zone_home("work"), "/home/work");
        assert!(nsswitch().contains("passwd: files"));
    }

    #[test]
    fn data_dir_check_refuses_symlinks_and_other_owners() {
        let base = std::env::temp_dir().join(format!("kryptik-rootfs-test-{}", std::process::id()));
        let real = base.join("real");
        let link = base.join("link");
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let me = unsafe { libc::geteuid() };
        assert!(check_data_dir(real.to_str().unwrap(), me).is_ok());
        let err = check_data_dir(link.to_str().unwrap(), me).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
        let err = check_data_dir(real.to_str().unwrap(), me + 1).unwrap_err();
        assert!(err.to_string().contains("owned by uid"), "{err}");
        let file = base.join("file");
        fs::write(&file, "x").unwrap();
        assert!(check_data_dir(file.to_str().unwrap(), me).is_err());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn close_inherited_fds_closes_low_and_high_descriptors_in_a_child() {
        let rc = in_child(|| {
            open_at(3);
            open_at(4095);
            open_at(5000); // above the old fixed sweep bound of 4096
            if !(is_open(3) && is_open(4095) && is_open(5000)) {
                return 10;
            }
            close_inherited_fds();
            for fd in 0..=2 {
                if !is_open(fd) {
                    return 20 + fd;
                }
            }
            for fd in [3, 4095, 5000] {
                if is_open(fd) {
                    return 30;
                }
            }
            0
        });
        assert_eq!(rc, 0, "child reported failure code {rc}");
    }

    #[test]
    fn every_closing_strategy_reaches_high_descriptors() {
        // Each fallback is exercised on its own, in its own child, so a
        // regression in the strategy that is NOT taken on this kernel is
        // still caught here.
        for strategy in 0..3 {
            let rc = in_child(move || {
                open_at(5000);
                open_at(3);
                let done = match strategy {
                    0 => close_via_close_range(),
                    1 => close_via_proc(),
                    _ => {
                        close_by_sweep(highest_possible_fd());
                        true
                    }
                };
                if !done {
                    return SKIP;
                }
                if is_open(5000) || is_open(3) {
                    return 1;
                }
                if !(is_open(0) && is_open(1) && is_open(2)) {
                    return 2;
                }
                0
            });
            assert!(rc == 0 || rc == SKIP, "strategy {strategy} left descriptors open (rc {rc})");
        }
    }

    #[test]
    fn highest_possible_fd_covers_nr_open() {
        let h = highest_possible_fd();
        assert!(h >= 1 << 20, "sweep bound {h} is below the kernel default nr_open");
        assert!(h <= 1 << 22);
    }

    #[test]
    fn ensure_stdio_reopens_a_closed_descriptor_in_a_child() {
        let rc = in_child(|| {
            unsafe { libc::close(0) };
            if is_open(0) {
                return 1;
            }
            ensure_stdio();
            if !is_open(0) {
                return 2;
            }
            0
        });
        assert_eq!(rc, 0);
    }

    /// The regression test for read-only binds that were not read-only
    /// underneath: a submount inside the bound tree must be read-only inside
    /// the zone's view, not merely the top mount.
    ///
    /// Needs an unprivileged user namespace; skips (not passes) without one.
    #[test]
    fn read_only_bind_is_read_only_all_the_way_down() {
        let rc = in_child(|| {
            let uid = unsafe { libc::getuid() };
            let gid = unsafe { libc::getgid() };
            if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } < 0 {
                return SKIP;
            }
            if fs::write("/proc/self/setgroups", "deny").is_err()
                || fs::write("/proc/self/uid_map", format!("0 {uid} 1\n")).is_err()
                || fs::write("/proc/self/gid_map", format!("0 {gid} 1\n")).is_err()
            {
                return SKIP;
            }
            if mount_raw("none", "/", None, libc::MS_REC | libc::MS_PRIVATE, None, "private").is_err() {
                return SKIP;
            }
            let base = std::env::temp_dir().join(format!("kryptik-ro-test-{}", std::process::id()));
            let src = base.join("src");
            let sub = src.join("sub");
            let dst = base.join("dst");
            if fs::create_dir_all(&sub).is_err() || fs::create_dir_all(&dst).is_err() {
                return 3;
            }
            // A writable tmpfs INSIDE the source tree stands in for a host
            // submount under /usr.
            if mount_raw("tmpfs", sub.to_str().unwrap(), Some("tmpfs"), 0, Some("mode=0777"), "sub").is_err() {
                return SKIP;
            }
            if let Err(e) = bind_ro_dir(src.to_str().unwrap(), dst.to_str().unwrap()) {
                eprintln!("bind_ro_dir: {e}");
                return 4;
            }
            // Top level read-only...
            if fs::write(dst.join("top"), "x").is_ok() {
                return 5;
            }
            // ...and the submount too. This is the line that failed before.
            if fs::write(dst.join("sub").join("inner"), "x").is_ok() {
                return 6;
            }
            // Positive control: the source is still writable, so "read-only"
            // above was the bind's doing and not the tmpfs being broken.
            if fs::write(sub.join("control"), "x").is_err() {
                return 7;
            }
            0
        });
        match rc {
            0 => {}
            SKIP => eprintln!("no unprivileged user namespace here; skipping"),
            other => panic!("read-only bind check failed with code {other}"),
        }
    }
}
