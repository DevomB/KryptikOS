//! Zone roots built with pivot_root, so host paths do not exist for a zone: Landlock cannot
//! revoke an inherited descriptor or stop chmod on files the zone's uid owns. The root is a
//! fresh tmpfs with system paths bound read-only, /etc synthesized and the data at /home/<zone>.

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

// mount_setattr(2), Linux 5.12+ with no glibc wrapper: makes a whole bind tree read-only at once.
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

/// Make a bind tree read-only, nosuid, nodev all the way down.
fn make_ro_recursive(target: &str) -> Result<(), RootfsError> {
    set_mount_attr(target, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, true)
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
    set_mount_attr(target, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, false)
}

/// System directories a zone gets, read-only, nosuid, nodev; /etc is `populate_etc`'s.
pub const SYSTEM_PATHS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin"];

/// Host files under /etc a zone may read: public, machine-independent data. man needs
/// man_db.conf; OpenSSL needs cert.pem, as ssl/certs has the bundle but no hash links.
pub const ETC_RO_FILES: &[&str] =
    &["/etc/ld.so.cache", "/etc/services", "/etc/protocols", "/etc/man_db.conf", "/etc/ssl/cert.pem"];

/// The nic zone's own configuration (DHCP client, time sources, release source), for it alone.
pub const NIC_ETC_FILES: &[&str] = &["/etc/dhcpcd.conf", "/etc/kryptik/time.conf", "/etc/kryptik/update.conf"];

/// /proc files hidden behind /dev/null: interrupt and context-switch counts time every keystroke,
/// and so do loadavg's count of running tasks, the fault and allocation counts in vmstat, zoneinfo
/// and buddyinfo, the stall times under pressure and the open-file and dentry counts under sys/fs;
/// partitions and diskstats show which encrypted zones are open, and timer_list names other
/// zones' tasks. Losing stat's CPU figures and the load (top, vmstat, uptime) is the price;
/// meminfo stays, coarse, and free and most runtimes read it.
pub const PROC_MASKED: &[&str] = &[
    "interrupts", "softirqs", "stat", "schedstat", "pressure/irq", "timer_list", "sched_debug",
    "loadavg", "partitions", "diskstats",
    "vmstat", "zoneinfo", "buddyinfo", "pressure/cpu", "pressure/memory", "pressure/io",
    "sys/fs/file-nr", "sys/fs/inode-nr", "sys/fs/dentry-state",
];

/// /proc directories hidden behind an empty tmpfs: irq/<n>/spurious counts keyboard interrupts too.
pub const PROC_EMPTIED: &[&str] = &["irq"];

/// What a zone sees of sysfs: its interfaces and the CPU layout (glibc counts CPUs there). The
/// rest holds disk and monitor serials and which encrypted zones run.
pub const SYSFS_KEPT: &[&str] = &["class/net", "devices/virtual/net", "devices/system/cpu"];

/// The nic zone's radios, kept beside `SYSFS_KEPT` with the devices under it (`nic_sysfs`).
pub const NIC_SYSFS_KEPT: &[&str] = &["class/ieee80211"];

/// Host directories under /etc a zone may read, as `ETC_RO_FILES`; lynx needs its lynx.cfg.
pub const ETC_RO_DIRS: &[&str] = &["/etc/alternatives", "/etc/ssl/certs", "/etc/pki/tls/certs", "/etc/lynx"];

/// The system allocator (ADR-005), preloaded in a zone from the /usr it shares with zone 0.
pub const ALLOCATOR: &str = "/usr/lib/libhardened_malloc.so";

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

/// The home and chroot of the user `service` adds: an empty directory on the sealed root.
pub const SERVICE_HOME: &str = "/var/empty";

/// Synthesized /etc/passwd: the zone's root and nobody, and with `service` dhcpcd at
/// `isolate::SERVICE_ID`, the user its privilege separation drops to.
pub fn passwd_for(zone: &str, home: &str, service: bool) -> String {
    let mut s = format!("root:x:0:0:{zone}:{home}:/bin/sh\n");
    if service {
        let id = crate::isolate::SERVICE_ID;
        s.push_str(&format!("dhcpcd:x:{id}:{id}:dhcpcd:{SERVICE_HOME}:/bin/false\n"));
    }
    s.push_str("nobody:x:65534:65534:nobody:/nonexistent:/bin/false\n");
    s
}

pub fn group_for(service: bool) -> String {
    let mut s = "root:x:0:\n".to_string();
    if service {
        s.push_str(&format!("dhcpcd:x:{}:\n", crate::isolate::SERVICE_ID));
    }
    s.push_str("nogroup:x:65534:\n");
    s
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
    /// No file at all: offline zones, and a nic zone that got no network.
    None,
    /// A routed zone, with a path or before it gets one: only the nic zone's bridge address is named.
    Bridge,
    /// The nic zone's DHCP client writes it, through a symlink into /tmp: the root is sealed.
    Writable,
}

pub fn resolv_conf_for_bridge() -> String {
    "nameserver 10.19.0.1\nnameserver fd19::1\n".to_string()
}

/// Refuse an ephemeral zone over leftover data: it would sit unwiped, and is not ours to delete.
pub fn check_data_dir_empty(path: &str, zone: &str) -> Result<(), RootfsError> {
    let entries = fs::read_dir(path)
        .map_err(|e| RootfsError::Setup(format!("{path}: {e}")))?;
    // The zone chose these names, and they reach a terminal: quoted and escaped.
    let leftovers: Vec<String> = entries
        .map(|e| e.map_or_else(|err| format!("<{err}>"), |e| format!("{:?}", e.file_name())))
        .take(6)
        .collect();
    if leftovers.is_empty() {
        return Ok(());
    }
    Err(RootfsError::Setup(format!(
        "ephemeral zone {zone:?} has persistent data in {path} from an earlier run \
         ({}); move or delete it",
        leftovers.join(", ")
    )))
}

/// Refuse a data directory that is a symlink, which would redirect the bind, or another owner's.
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

/// Pivot into a root holding only what the zone should see; returns the home. Runs as root in the
/// new user namespace, before Landlock and seccomp; `ephemeral` is a tmpfs home's size, and
/// `service` adds dhcpcd's user and `SERVICE_HOME`.
#[allow(clippy::too_many_arguments)]
pub fn pivot_into(
    data_dir: &str,
    zone: &str,
    ephemeral: Option<&str>,
    resolver: Resolver,
    broker: Option<&str>,
    wayland: Option<&str>,
    wifi_conf: Option<&str>,
    service: bool,
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

    /* A fresh tmpfs over the data directory's path: kryptikd makes every mount point on it, so
     * nothing the zone wrote can redirect a mount. */
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

    populate_etc(root, zone, &home, resolver, service)?;
    // Made on the root tmpfs, so the seal below leaves it empty and read-only.
    if service {
        mkdir(&SERVICE_HOME[1..])?;
    }

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

    /* Read-only sysfs, from one mounted aside: `SYSFS_KEPT`, and for the nic zone also its
     * radios and the devices under its interfaces (`nic_sysfs`). Best effort: it can fail in a
     * nested namespace. */
    let sys_dir = mkdir("sys")?;
    let aside = mkdir(".sysfs")?;
    let mounted = mount_raw(
        "sysfs",
        &aside,
        Some("sysfs"),
        (libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV | libc::MS_RDONLY)
            as libc::c_ulong,
        None,
        "mount(sysfs)",
    );
    if mounted.is_ok() {
        let kept = if resolver == Resolver::Writable {
            nic_sysfs(&aside)
        } else {
            SYSFS_KEPT.iter().map(|s| s.to_string()).collect()
        };
        if let Err(e) = keep_sysfs(&aside, &sys_dir, &kept) {
            eprintln!("kryptikd: note: the zone gets no /sys: {e}");
        }
        // Left mounted, the whole of sysfs would stay in the zone at the aside path.
        let c = cs(&aside)?;
        if unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) } < 0 {
            return Err(RootfsError::Syscall { call: "umount2", path: aside, errno: errno() });
        }
    }
    let _ = fs::remove_dir(&aside);

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

    /* The nic zone's private /run and /var/lib, for its daemons' pid files, sockets and leases.
     * Other zones have no /var, and in /run only what kryptikd binds there. */
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

    // The nic zone's Wi-Fi credentials, bound read-only; no file means no networks configured.
    if let Some(conf) = wifi_conf {
        if fs::metadata(conf).map(|m| m.is_file()).unwrap_or(false) {
            bind_ro_file(conf, &format!("{root}{}", crate::wifi::IN_ZONE))?;
        }
    }

    // The zone's broker socket; connect(2) is not a Landlock filesystem access.
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

    /* The zone's data at /home/<zone>, bound through the descriptor that was checked. Not
     * recursive, so mounts inside are not carried in (locked submounts give EINVAL). */
    let home_dir = mkdir(&home[1..])?;
    if let Some(size) = ephemeral {
        // Freed with the zone's mount namespace, even after kill -9; uid 0 is the zone's root.
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
    set_mount_attr("/", MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC, false)?;

    Ok(home)
}

/// The zone's /etc: synthesized identity files plus `ETC_RO_FILES` and `ETC_RO_DIRS`.
fn populate_etc(root: &str, zone: &str, home: &str, resolver: Resolver, service: bool) -> Result<(), RootfsError> {
    let etc = format!("{root}/etc");
    fs::create_dir_all(&etc).map_err(|e| RootfsError::Setup(format!("{etc}: {e}")))?;
    let write = |name: &str, content: String| -> Result<(), RootfsError> {
        let p = format!("{etc}/{name}");
        fs::write(&p, content).map_err(|e| RootfsError::Setup(format!("{p}: {e}")))
    };
    write("passwd", passwd_for(zone, home, service))?;
    write("group", group_for(service))?;
    write("nsswitch.conf", nsswitch())?;
    write("hosts", hosts_for(zone))?;
    write("hostname", format!("{zone}\n"))?;
    // Written here, not bound from the host's /etc: no host file picks a zone's preload.
    if Path::new(ALLOCATOR).is_file() {
        write("ld.so.preload", format!("{ALLOCATOR}\n"))?;
    }
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

/// Hide `PROC_MASKED` and `PROC_EMPTIED`, give the zone its own boot_id (the host's is the same
/// in every zone, so it would link them), and a copy of cpuinfo that holds still.
fn mask_proc(root: &str, proc_dir: &str) -> Result<(), RootfsError> {
    for f in PROC_MASKED {
        let target = format!("{proc_dir}/{f}");
        if Path::new(&target).exists() {
            bind_over_ro("/dev/null", &target)?;
        }
    }
    let flags = libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    for d in PROC_EMPTIED {
        let target = format!("{proc_dir}/{d}");
        if Path::new(&target).is_dir() {
            mount_raw("tmpfs", &target, Some("tmpfs"), flags as libc::c_ulong, Some("mode=0555,size=4k"), "mount(proc tmpfs)")?;
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
    // cpuinfo's "cpu MHz" is each CPU's speed over its last tick, so whether it just ran: a copy
    // taken as the zone starts holds still.
    let cpuinfo = format!("{proc_dir}/cpuinfo");
    if Path::new(&cpuinfo).exists() {
        let own = format!("{root}/.cpuinfo");
        let setup = |e: io::Error| RootfsError::Setup(format!("{own}: {e}"));
        fs::write(&own, fs::read(&cpuinfo).map_err(setup)?).map_err(setup)?;
        bind_over_ro(&own, &cpuinfo)?;
        let _ = fs::remove_file(&own);
    }
    Ok(())
}

/// The nic zone's sysfs: `SYSFS_KEPT`, `NIC_SYSFS_KEPT`, and the device each of its interfaces
/// and radios sits on, which their class entries link into; netzone-init.sh tells an uplink by
/// its `device`. Its NICs are moved in before its root is built, and none after.
fn nic_sysfs(aside: &str) -> Vec<String> {
    let mut kept: Vec<String> = SYSFS_KEPT.iter().chain(NIC_SYSFS_KEPT).map(|s| s.to_string()).collect();
    let Ok(base) = fs::canonicalize(aside) else { return kept };
    let mut devices = std::collections::BTreeSet::new();
    for class in ["class/net", "class/ieee80211"] {
        for e in fs::read_dir(format!("{aside}/{class}")).into_iter().flatten().flatten() {
            let Ok(dev) = fs::canonicalize(e.path().join("device")) else { continue };
            if let Ok(rel) = dev.strip_prefix(&base) {
                devices.insert(rel.to_string_lossy().into_owned());
            }
        }
    }
    for d in devices {
        if !d.is_empty() && !kept.contains(&d) {
            kept.push(d);
        }
    }
    kept
}

/// Bind `kept` from the sysfs at `aside` into a read-only tmpfs at `sys_dir`.
fn keep_sysfs(aside: &str, sys_dir: &str, kept: &[String]) -> Result<(), RootfsError> {
    let flags = (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong;
    mount_raw("tmpfs", sys_dir, Some("tmpfs"), flags, Some("mode=0755,size=64k"), "mount(sys tmpfs)")?;
    for rel in kept {
        let src = format!("{aside}/{rel}");
        if Path::new(&src).is_dir() {
            bind_ro_dir(&src, &format!("{sys_dir}/{rel}"))?;
        }
    }
    // Each CPU's idle-state counts are its wakeups, which a keystroke in any zone causes.
    let cpus = format!("{sys_dir}/devices/system/cpu");
    for e in fs::read_dir(&cpus).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let numbered = name.strip_prefix("cpu").is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        let idle = format!("{cpus}/{name}/cpuidle");
        if numbered && Path::new(&idle).is_dir() {
            mount_raw("tmpfs", &idle, Some("tmpfs"), flags | libc::MS_RDONLY, Some("mode=0555,size=4k"), "mount(cpuidle tmpfs)")?;
        }
    }
    // Their frequencies, where a driver scales them, fall and rise with every zone's load.
    let freq = format!("{cpus}/cpufreq");
    if Path::new(&freq).is_dir() {
        mount_raw("tmpfs", &freq, Some("tmpfs"), flags | libc::MS_RDONLY, Some("mode=0555,size=4k"), "mount(cpufreq tmpfs)")?;
    }
    mount_raw("none", sys_dir, None, flags | libc::MS_REMOUNT | libc::MS_RDONLY, None, "mount(sys tmpfs, ro)")
}

/// A minimal /dev: `DEVICES` bound from the host (mknod needs CAP_MKNOD there), shm and devpts.
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

/// Open /dev/null on any closed 0, 1 or 2, so the zone's first open() cannot become its stdout.
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

/// Close every descriptor above stderr: neither Landlock nor pivot_root affects an open one.
pub fn close_inherited_fds() -> std::io::Result<()> {
    let r = unsafe { libc::syscall(libc::SYS_close_range, 3 as libc::c_uint, libc::c_uint::MAX, 0 as libc::c_uint) };
    if r == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

#[cfg(test)]
mod tests;
