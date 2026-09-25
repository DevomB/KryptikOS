//! Zone roots built with pivot_root, so host paths do not exist for a zone
//! rather than being denied: Landlock cannot revoke an inherited descriptor
//! or stop chmod on files the zone's uid owns.
//!
//! The root is a fresh tmpfs. System paths are bound read-only recursively,
//! /etc is synthesized, and the data directory is bound only at /home/<zone>.

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

/* mount_setattr(2), Linux 5.12+: the only way to make a whole bind tree
 * read-only in one step. glibc has no wrapper. */
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

/// Set mount attributes on `target`, and beneath it if `recursive`; clears none.
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

/// Make a bind tree read-only, nosuid, nodev all the way down. Without
/// mount_setattr only the top mount can be fixed, so submounts are refused.
fn make_ro_recursive(target: &str) -> Result<(), RootfsError> {
    match set_mount_attr(
        target,
        MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
        true,
    ) {
        Ok(()) => Ok(()),
        Err(RootfsError::Syscall { errno, .. }) if errno == libc::ENOSYS => {
            // The initial bind ignores MS_RDONLY; only a remount applies it.
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

/// Bind `src` at `target` recursively, read-only, nosuid, nodev all the way down.
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
    bind_over_ro(src, target)
}

/// Bind `src` over the existing file `target`, read-only.
fn bind_over_ro(src: &str, target: &str) -> Result<(), RootfsError> {
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

/// System directories a zone gets, read-only, nosuid, nodev. Not /etc: see
/// `populate_etc`.
pub const SYSTEM_PATHS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin"];

/// Host files under /etc a zone may read: public, machine-independent data.
/// Never ld.so.preload, machine-id (links zones to the host), the host's
/// identity files, resolv.conf, localtime (zones run UTC), or any secret.
pub const ETC_RO_FILES: &[&str] = &["/etc/ld.so.cache", "/etc/services", "/etc/protocols"];

/// The nic zone's own configuration, bound into that zone alone: its DHCP
/// client defaults, time sources (docs/design/time.md) and release source
/// (docs/design/update-channel.md).
pub const NIC_ETC_FILES: &[&str] = &["/etc/dhcpcd.conf", "/etc/kryptik/time.conf", "/etc/kryptik/update.conf"];

/// Files of a zone's /proc about the whole machine, hidden behind /dev/null:
/// the interrupt counts (interrupts, softirqs, the intr line of stat) time
/// every keystroke typed anywhere, and timer_list names other zones' tasks.
pub const PROC_MASKED: &[&str] = &["interrupts", "softirqs", "stat", "timer_list", "sched_debug"];

/// What a zone other than the nic zone sees of sysfs: its own interfaces and
/// the CPU layout (glibc counts CPUs there). The rest describes the machine:
/// disk, USB and monitor serials, and which encrypted zones are running.
pub const SYSFS_KEPT: &[&str] = &["class/net", "devices/virtual/net", "devices/system/cpu"];
pub const ETC_RO_DIRS: &[&str] = &["/etc/alternatives", "/etc/ssl/certs", "/etc/pki/tls/certs"];

/// Device nodes a zone gets; no other exists for it.
pub const DEVICES: &[(&str, &str)] = &[
    ("/dev/null", "null"),
    ("/dev/zero", "zero"),
    ("/dev/full", "full"),
    ("/dev/random", "random"),
    ("/dev/urandom", "urandom"),
    ("/dev/tty", "tty"),
];

/// The Wayland proxy socket's name, and its path in the zone (WAYLAND_DISPLAY).
pub const WAYLAND_SOCKET_NAME: &str = "wayland-0";
pub const WAYLAND_SOCKET_IN_ZONE: &str = "/run/kryptik/wayland-0";

/// Where the zone's data directory appears inside the zone.
pub fn zone_home(zone: &str) -> String {
    format!("/home/{zone}")
}

/// Synthesized /etc/passwd: the zone's root and nobody.
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
    /// A routed zone with a path: only the nic zone's bridge address is named.
    Bridge,
    /// The nic zone, whose DHCP client writes it: the root is sealed, so
    /// /etc/resolv.conf is a symlink into the zone's private /tmp.
    Writable,
}

pub fn resolv_conf_for_bridge() -> String {
    "nameserver 10.19.0.1\nnameserver fd19::1\n".to_string()
}

/// Refuse an ephemeral zone whose persistent directory is not empty: leftover
/// data would sit on disk unwiped, and kryptikd must not delete what it did not
/// create.
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

/// Refuse a data directory that is not a plain directory owned by the zone's
/// identity: a symlink would redirect the bind, and another owner's files would
/// be exposed to the zone.
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

/// Replace the zone's root with a tree holding only what it should see, and
/// return the zone's home path. Runs after unshare(CLONE_NEWNS) and the uid map
/// (pivot_root needs CAP_SYS_ADMIN in the new user namespace) and before
/// Landlock and seccomp, which forbid mount and pivot_root. `ephemeral` is the
/// home tmpfs size of an ephemeral zone.
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

    // Private first, or every mount below propagates back to the host.
    mount_raw(
        "none",
        "/",
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
        "mount(private)",
    )?;

    /* Open the data directory before the root tmpfs hides it; O_NOFOLLOW
     * closes the gap after check_data_dir. An ephemeral zone binds none: -1. */
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

    /* The zone's root: a fresh tmpfs over the data directory's path. Every
     * mount point below is created on it by kryptikd, so nothing the zone
     * wrote can redirect a mount. */
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

    for p in SYSTEM_PATHS {
        // Skip paths the host lacks; is_dir follows a merged-usr /bin symlink.
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
    mask_proc(root, &proc_dir)?;

    /* Read-only sysfs for this zone's network namespace: the nic zone gets
     * all of it, any other zone only `SYSFS_KEPT`, bound from a sysfs mounted
     * aside and then dropped. Best effort: it can fail in a nested namespace. */
    let sys_dir = mkdir("sys")?;
    let aside = if resolver == Resolver::Writable { sys_dir.clone() } else { mkdir(".sysfs")? };
    let mounted = mount_raw(
        "sysfs",
        &aside,
        Some("sysfs"),
        (libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV | libc::MS_RDONLY)
            as libc::c_ulong,
        None,
        "mount(sysfs)",
    );
    if aside != sys_dir {
        if mounted.is_ok() {
            if let Err(e) = keep_sysfs(&aside, &sys_dir) {
                eprintln!("kryptikd: note: the zone gets no /sys: {e}");
            }
            let c = cs(&aside)?;
            unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
        }
        let _ = fs::remove_dir(&aside);
    }

    populate_dev(root)?;

    // Private /tmp, sized: an unsized tmpfs may take half the host's memory.
    let tmp_dir = mkdir("tmp")?;
    mount_raw(
        "tmpfs",
        &tmp_dir,
        Some("tmpfs"),
        (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
        Some("mode=1777,size=256m"),
        "mount(tmp)",
    )?;

    /* The nic zone's private /run and /var/lib, for the network daemons' pid
     * files, sockets and DHCP leases. Other zones have no /var, and a /run on
     * the sealed root holding only what kryptikd binds there. */
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

    /* The nic zone's Wi-Fi credentials (wifi.rs): 0400, owned by the zone's
     * identity, bound read-only. No file means no networks are configured. */
    if let Some(conf) = wifi_conf {
        if fs::metadata(conf).map(|m| m.is_file()).unwrap_or(false) {
            bind_ro_file(conf, &format!("{root}{}", crate::wifi::IN_ZONE))?;
        }
    }

    /* The zone's broker socket, 0600 and owned by the zone identity.
     * connect(2) is not a Landlock filesystem access. */
    if let Some(sock) = broker {
        let rk = mkdir("run/kryptik")?;
        let target = format!("{rk}/{}", crate::broker::SOCKET_NAME);
        // Read-only is fine: the read-only check exempts sockets, so connect(2) works.
        bind_ro_file(sock, &target)?;
    }
    // The zone's kryptik-wlproxy socket; the compositor's own is never reachable.
    if let Some(sock) = wayland {
        let rk = mkdir("run/kryptik")?;
        let target = format!("{rk}/{}", WAYLAND_SOCKET_NAME);
        bind_ro_file(sock, &target)?;
    }

    /* The zone's data at /home/<zone>, bound through the descriptor so it is
     * the directory that was checked. Non-recursive, so mounts inside it are
     * not carried in; with locked submounts the kernel says EINVAL. */
    let home_dir = mkdir(&home[1..])?;
    if let Some(size) = ephemeral {
        /* A tmpfs in the zone's own mount namespace: the kernel frees it with
         * the namespace, even after kill -9. uid 0 is the zone's root. */
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
        // Not fatal: no_new_privs covers nosuid, and Landlock denies mknod.
        eprintln!("kryptikd: note: could not set nosuid,nodev on {home}: {e}");
    }

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

    // Until detached, the whole host filesystem is reachable at /.oldroot.
    let c_oldmount = cs("/.oldroot")?;
    if unsafe { libc::umount2(c_oldmount.as_ptr(), libc::MNT_DETACH) } < 0 {
        return Err(RootfsError::Syscall {
            call: "umount2",
            path: "/.oldroot".into(),
            errno: errno(),
        });
    }
    let _ = fs::remove_dir("/.oldroot");

    // Seal the root: nothing may add to it now, not even the zone's root.
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

/// The zone's /etc: synthesized identity files plus `ETC_RO_FILES` and `ETC_RO_DIRS`.
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

    let nic: &[&str] = if resolver == Resolver::Writable { NIC_ETC_FILES } else { &[] };
    for f in ETC_RO_FILES.iter().chain(nic) {
        // metadata() follows symlinks; the target must be a regular file.
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

/// Hide `PROC_MASKED` behind /dev/null, and give the zone a boot_id of its
/// own: the host's is the same in every zone, so it would link them.
fn mask_proc(root: &str, proc_dir: &str) -> Result<(), RootfsError> {
    for f in PROC_MASKED {
        let target = format!("{proc_dir}/{f}");
        if Path::new(&target).exists() {
            bind_over_ro("/dev/null", &target)?;
        }
    }
    let boot_id = format!("{proc_dir}/sys/kernel/random/boot_id");
    if Path::new(&boot_id).exists() {
        let own = format!("{root}/.boot_id");
        let setup = |e: io::Error| RootfsError::Setup(format!("{own}: {e}"));
        fs::write(&own, fs::read(format!("{proc_dir}/sys/kernel/random/uuid")).map_err(setup)?).map_err(setup)?;
        bind_over_ro(&own, &boot_id)?;
        let _ = fs::remove_file(&own);
    }
    Ok(())
}

/// Bind `SYSFS_KEPT` from the sysfs mounted at `aside` into a read-only
/// tmpfs at `sys_dir`.
fn keep_sysfs(aside: &str, sys_dir: &str) -> Result<(), RootfsError> {
    let flags = (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong;
    mount_raw("tmpfs", sys_dir, Some("tmpfs"), flags, Some("mode=0755,size=64k"), "mount(sys tmpfs)")?;
    for rel in SYSFS_KEPT {
        let src = format!("{aside}/{rel}");
        if Path::new(&src).is_dir() {
            bind_ro_dir(&src, &format!("{sys_dir}/{rel}"))?;
        }
    }
    mount_raw("none", sys_dir, None, flags | libc::MS_REMOUNT | libc::MS_RDONLY, None, "mount(sys tmpfs, ro)")
}

/// A minimal /dev on tmpfs: the `DEVICES` nodes bound from the host (mknod would
/// need CAP_MKNOD there), a private /dev/shm and devpts, and the usual links.
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
        // Not fatal, but a zone without /dev/null misbehaves: warn.
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

    // A private devpts instance; best effort, isolation does not depend on it.
    let pts = format!("{dev_dir}/pts");
    fs::create_dir_all(&pts).map_err(|e| RootfsError::Setup(e.to_string()))?;
    match mount_raw(
        "devpts",
        &pts,
        Some("devpts"),
        (libc::MS_NOSUID | libc::MS_NOEXEC) as libc::c_ulong,
        Some("newinstance,ptmxmode=0666,mode=0620,max=256"),
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

/// Open /dev/null on whichever of 0, 1, 2 is closed, so the zone's first open()
/// cannot become its stdout.
pub fn ensure_stdio() {
    let devnull = cs("/dev/null").expect("static path");
    for fd in 0..=2 {
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 {
            continue;
        }
        let got = unsafe { libc::open(devnull.as_ptr(), libc::O_RDWR) };
        if got >= 0 && got != fd {
            // open() should have returned `fd`, the lowest free number; close the stray.
            unsafe { libc::close(got) };
        }
    }
}

/// Close every descriptor above stderr before handing control to the zone.
/// Neither Landlock nor pivot_root affects a descriptor already open, so only
/// 0, 1 and 2 are inherited; even one passed with `3<file` is closed.
pub fn close_inherited_fds() {
    if close_via_close_range() {
        return;
    }
    if close_via_proc() {
        return;
    }
    close_by_sweep(highest_possible_fd());
}

/// close_range(2), Linux 5.9+: one call, any number, no /proc.
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
    // The read_dir handle is listed but already closed: a harmless EBADF.
    for fd in fds {
        if fd > 2 {
            unsafe { libc::close(fd) };
        }
    }
    true
}

/// Sweep bound: nr_open, which no RLIMIT_NOFILE exceeds (an inherited fd can
/// sit above a lowered soft limit). Capped so a hostile value cannot make the
/// sweep take minutes.
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

    /// Run `body` in a forked child and return its exit status: these tests
    /// change descriptors and mount namespaces the test harness shares.
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
        // dup2(f, f) is a no-op; closing f would then close `fd`.
        if f != fd {
            unsafe { libc::close(f) };
        }
    }

    #[test]
    fn system_paths_exclude_etc() {
        for p in SYSTEM_PATHS {
            assert!(p.starts_with('/'), "{p} must be absolute");
            assert_ne!(*p, "/etc", "/etc is synthesized, never bound wholesale");
        }
    }

    #[test]
    fn device_list_is_minimal() {
        // Nothing that reaches real hardware or kernel memory.
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
    fn etc_view_excludes_identity_and_secrets() {
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
    fn bridge_resolver_names_only_bridge() {
        let r = resolv_conf_for_bridge();
        assert_eq!(r.lines().count(), 2);
        assert!(r.contains("nameserver 10.19.0.1") && r.contains("nameserver fd19::1"));
        assert!(!r.contains("10.0.2.3"), "must never name a host or slirp resolver");
    }

    #[test]
    fn identity_names_zone_not_host() {
        let pw = passwd_for("work", "/home/work");
        assert!(pw.starts_with("root:x:0:0:work:/home/work:"), "{pw}");
        assert_eq!(pw.lines().count(), 2);
        assert!(hosts_for("work").contains("127.0.0.1 localhost work"));
        assert_eq!(zone_home("work"), "/home/work");
        assert!(nsswitch().contains("passwd: files"));
    }

    #[test]
    fn data_dir_refuses_symlinks_other_owners() {
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
    fn close_inherited_fds_keeps_only_stdio() {
        let rc = in_child(|| {
            open_at(3);
            open_at(4095);
            open_at(5000);
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
    fn every_close_strategy_reaches_high_fds() {
        // Each in its own child, so the fallbacks this kernel skips are tested too.
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
    fn ensure_stdio_reopens_closed_fd() {
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

    /// A submount inside the bound tree must be read-only too. Needs an
    /// unprivileged user namespace; skips without one.
    #[test]
    fn read_only_bind_is_recursive() {
        /* Before the fork: temp_dir() takes std's environment lock, which
         * another test thread may hold at fork time, hanging the child. */
        let base = std::env::temp_dir().join(format!("kryptik-ro-test-{}", std::process::id()));
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
            let src = base.join("src");
            let sub = src.join("sub");
            let dst = base.join("dst");
            if fs::create_dir_all(&sub).is_err() || fs::create_dir_all(&dst).is_err() {
                return 3;
            }
            // A writable tmpfs inside the source stands in for a submount under /usr.
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
            // ...and the submount too.
            if fs::write(dst.join("sub").join("inner"), "x").is_ok() {
                return 6;
            }
            // Control: the source itself is still writable.
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
