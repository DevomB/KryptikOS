//! Zone network topology (docs/design/net-zone.md): who owns the NIC, and how
//! a routed zone reaches it.
//!
//! ```text
//!  physical NIC  --moved into-->  net zone's netns   (mode = "nic")
//!                                   kryptik0 bridge 10.19.0.1/24, fd19::1/64
//!  routed zone k:  kv-<zone> in net's netns, on kryptik0, ISOLATED
//!                  eth0 in the zone's netns: 10.19.0.k/24, fd19::k/64,
//!                  default routes via the bridge
//!  zone 0:         keeps lo only once net has taken the NIC
//!  mode = "none":  nothing is ever created
//! ```
//!
//! Runs in the root parent while the new zone waits at its handshake. It needs
//! CAP_SYS_ADMIN over the initial namespace, so an unprivileged launch gets
//! loopback only. NAT, the forward policy and the resolver belong to the nic
//! zone's own program, tools/net/netzone-init.sh.

use std::ffi::CStr;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use crate::netlink;
use crate::registry;
use crate::zone::{NetworkMode, Zone};

pub const BRIDGE: &str = "kryptik0";

/// Where fallback tunnel devices (sit0, ...; our kernel builds SIT in) appear:
/// 0 = every new namespace, 1 = the initial one only, 2 = none.
pub const FB_TUNNELS_SYSCTL: &str = "/proc/sys/net/core/fb_tunnels_only_for_init_net";

/// Fallback devices the tunnel modules create per namespace.
pub const FALLBACK_DEVICES: &[&str] =
    &["sit0", "tunl0", "ip6tnl0", "gre0", "gretap0", "erspan0", "ip6gre0", "ip_vti0", "ip6_vti0"];

/// Every interface in this network namespace except loopback.
pub fn devices_besides_lo() -> io::Result<Vec<String>> {
    // SAFETY: the array ends at a zero index; each entry before it has a C-string name.
    let list = unsafe { libc::if_nameindex() };
    if list.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut p = list;
    unsafe {
        while (*p).if_index != 0 {
            let name = CStr::from_ptr((*p).if_name).to_string_lossy().into_owned();
            if name != "lo" {
                out.push(name);
            }
            p = p.add(1);
        }
        libc::if_freenameindex(list);
    }
    Ok(out)
}

/// The fallback devices a new network namespace would start with here, or
/// None if it would hold loopback only.
pub fn fallback_tunnels_expected() -> Option<Vec<String>> {
    let v = std::fs::read_to_string(FB_TUNNELS_SYSCTL).ok()?;
    if v.trim() != "0" {
        return None;
    }
    let here = devices_besides_lo().ok()?;
    let fb: Vec<String> = here.into_iter().filter(|d| FALLBACK_DEVICES.contains(&d.as_str())).collect();
    if fb.is_empty() {
        None
    } else {
        Some(fb)
    }
}

/// Make sure new network namespaces start empty: Ok(Some(note)) if the sysctl
/// had to be raised to 1, Err if it could not be and a zone would get devices.
pub fn suppress_fallback_tunnels() -> Result<Option<String>, String> {
    let Some(devs) = fallback_tunnels_expected() else { return Ok(None) };
    match std::fs::write(FB_TUNNELS_SYSCTL, "1") {
        Ok(()) => Ok(Some(format!(
            "set {FB_TUNNELS_SYSCTL} = 1 (was 0): this kernel would otherwise create {} in every \
             new network namespace, a zone's included",
            devs.join(", ")
        ))),
        Err(e) => Err(format!(
            "this kernel creates {} in every new network namespace ({FB_TUNNELS_SYSCTL} = 0) and \
             this process cannot change that ({e}); a zone would not start loopback-only",
            devs.join(", ")
        )),
    }
}

#[derive(Debug)]
pub enum NetError {
    Io(String),
    NoNetZone,
    Refused(String),
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::Io(m) => write!(f, "{m}"),
            NetError::NoNetZone => write!(
                f,
                "no running zone holds the NIC (start the nic zone first); the zone starts with \
                 loopback only"
            ),
            NetError::Refused(m) => write!(f, "{m}"),
        }
    }
}

fn io(what: &str, e: io::Error) -> NetError {
    NetError::Io(format!("{what}: {e}"))
}

/// A routed zone's host number on the bridge subnet, from its declared uid
/// base: 131072 -> 2, 196608 -> 3, ... Bases are unique, so numbers are too.
pub fn host_number(zone: &Zone) -> Option<u8> {
    let base = zone.uid_base?;
    let k = (base - crate::zone::IDENTITY_MIN) / crate::zone::IDENTITY_STRIDE + 2;
    if k >= 250 {
        return None;
    }
    Some(k as u8)
}

/// The veth end that sits on the bridge, named for the zone.
pub fn port_name(zone: &str) -> String {
    format!("kv-{zone}")
}

fn up_lo() -> io::Result<()> {
    netlink::set_up("lo")
}

/// An uplink's IPv4 configuration, read back so it can be re-applied after a
/// namespace move, which flushes addresses and routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uplink {
    pub addrs: Vec<([u8; 4], u8)>,
    pub gateway: Option<[u8; 4]>,
}

impl std::fmt::Display for Uplink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.addrs.is_empty() {
            write!(f, "no IPv4 address")?;
        }
        for (i, (a, p)) in self.addrs.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}.{}.{}.{}/{p}", a[0], a[1], a[2], a[3])?;
        }
        match self.gateway {
            Some(g) => write!(f, " via {}.{}.{}.{}", g[0], g[1], g[2], g[3]),
            None => write!(f, ", no default route"),
        }
    }
}

/// IPv4 addresses (getifaddrs) and default gateway (/proc/self/net/route) of `nic`.
pub fn uplink_config(nic: &str) -> io::Result<Uplink> {
    let mut addrs = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: null ifa_addr/ifa_netmask are checked; an AF_INET sockaddr is a sockaddr_in.
    if unsafe { libc::getifaddrs(&mut list) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut p = list;
    while !p.is_null() {
        unsafe {
            let e = &*p;
            let name = if e.ifa_name.is_null() { String::new() } else { CStr::from_ptr(e.ifa_name).to_string_lossy().into_owned() };
            if name == nic && !e.ifa_addr.is_null() && (*e.ifa_addr).sa_family as i32 == libc::AF_INET && !e.ifa_netmask.is_null() {
                let sa = &*(e.ifa_addr as *const libc::sockaddr_in);
                let mask = &*(e.ifa_netmask as *const libc::sockaddr_in);
                let prefix = u32::from_be(mask.sin_addr.s_addr).leading_ones() as u8;
                addrs.push((sa.sin_addr.s_addr.to_ne_bytes(), prefix));
            }
            p = e.ifa_next;
        }
    }
    unsafe { libc::freeifaddrs(list) };
    let gateway = std::fs::read_to_string("/proc/self/net/route")?
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            // A default route: Destination (field 1) and Mask (field 7) both zero.
            if f.len() > 7 && f[0] == nic && f[1] == "00000000" && f[7] == "00000000" {
                u32::from_str_radix(f[2], 16).ok().map(|g| g.to_ne_bytes())
            } else {
                None
            }
        })
        .next();
    Ok(Uplink { addrs, gateway })
}

/// Move `nic` into `zone_ns` and re-apply the IPv4 configuration the move
/// flushes (no DHCP here; a client in the nic zone can take over). Returns it.
fn carry_nic(nic: &str, zone_ns: i32) -> Result<Uplink, NetError> {
    let cfg = uplink_config(nic).map_err(|e| io(&format!("read the configuration of {nic}"), e))?;
    // A wireless netdev is namespace-local; move its wiphy instead.
    match netlink::wiphy_index_of(nic).map_err(|e| io(&format!("read the wiphy of {nic}"), e))? {
        Some(phy) => netlink::set_wiphy_netns(phy, zone_ns)
            .map_err(|e| io(&format!("move {nic} (wiphy {phy}) into the nic zone"), e))?,
        None => netlink::set_netns(nic, zone_ns).map_err(|e| io(&format!("move {nic} into the nic zone"), e))?,
    }
    netlink::with_netns(zone_ns, || {
        for (a, p) in &cfg.addrs {
            netlink::add_addr4(nic, *a, *p)?;
        }
        netlink::set_up(nic)?;
        if let Some(gw) = cfg.gateway {
            /* With a second uplink the first default route stands (the kernel
             * refuses a duplicate); the zone's DHCP client sorts them later. */
            match netlink::add_default_route4(gw, nic) {
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    eprintln!("kryptikd: {nic}: the nic zone already has a default route; keeping the first")
                }
                r => r?,
            }
        }
        Ok(())
    })
    .map_err(|e| io(&format!("configure {nic} inside the nic zone"), e))?;
    Ok(cfg)
}

/// Interfaces here that sit on a bus device (`/sys/class/net/<n>/device`
/// exists); software devices never do. `[network] nic = "*"` moves these.
pub fn physical_interfaces() -> io::Result<Vec<String>> {
    physical_interfaces_under(Path::new("/sys/class/net"))
}

/// `physical_interfaces` over any sysfs `class/net` directory, for tests.
fn physical_interfaces_under(class_net: &Path) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(class_net)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        if name == "lo" {
            continue;
        }
        if e.path().join("device").exists() {
            out.push(name);
        }
    }
    out.sort();
    Ok(out)
}

/// Plumb the nic zone (uplinks and bridge), then reattach running routed zones.
pub fn plumb_nic_zone(zone: &Zone, zone_ns: i32, zones_dir: &Path) -> Result<(), NetError> {
    plumb_nic_zone_bridge(zone, zone_ns)?;
    // One zone failing to reattach stops neither the others nor the nic zone.
    for (name, r) in replumb_routed_zones(zones_dir, zone_ns) {
        match r {
            Ok(()) => eprintln!("kryptikd: zone {name:?} reattached to the new nic zone"),
            Err(e) => eprintln!("kryptikd: zone {name:?} could not be reattached: {e}"),
        }
    }
    Ok(())
}

/// Attach every running routed zone to the nic zone in `nic_ns`; one result
/// per zone tried. A zone keeps the resolv.conf it started with, so one that
/// started before any gateway has no resolver until it restarts.
pub fn replumb_routed_zones(zones_dir: &Path, nic_ns: i32) -> Vec<(String, Result<(), NetError>)> {
    let mut out = Vec::new();
    for name in registry::names() {
        let Ok(z) = Zone::from_file(&zones_dir.join(format!("{name}.toml"))) else { continue };
        if z.network != NetworkMode::Routed {
            continue;
        }
        let Ok(registry::State::Running { init: Some(st), .. }) = registry::state(&name) else { continue };
        let ns = open_ns(&st);
        if !st.still_alive() {
            continue;
        }
        let r = (|| {
            let k = host_number(&z).ok_or_else(|| {
                NetError::Refused("no [identity] uid_base to derive an address".into())
            })?;
            let zone_ns = ns.map_err(|e| io("open the zone netns", e))?;
            // None: the ICMP group range set at first plumbing is still there.
            attach_routed(&z.name, k, nic_ns, zone_ns.as_raw_fd(), None)
        })();
        out.push((name, r));
    }
    out
}

/// Move the uplinks into the nic zone and create kryptik0 there.
fn plumb_nic_zone_bridge(zone: &Zone, zone_ns: i32) -> Result<(), NetError> {
    /* Without `[network] nic` the zone gets the bridge and no uplink: kryptikd
     * never picks a NIC to take out of zone 0 on its own. */
    let nics: Vec<String> = match zone.nic.as_deref() {
        None => Vec::new(),
        // Every physical interface, wired or wireless; finding none is not an error.
        Some("*") => physical_interfaces().map_err(|e| io("list the physical interfaces of zone 0", e))?,
        Some(n) => {
            // A named NIC missing from zone 0 is a configuration error.
            if unsafe { libc::if_nametoindex(std::ffi::CString::new(n).unwrap().as_ptr()) } == 0 {
                return Err(NetError::Refused(format!(
                    "[network] nic = {n:?} is not an interface in this namespace"
                )));
            }
            vec![n.to_string()]
        }
    };
    match (zone.nic.as_deref(), nics.is_empty()) {
        (None, _) => eprintln!(
            "kryptikd: zone {:?} declares no [network] nic: bridge only, no interface moved",
            zone.name
        ),
        (Some(_), true) => eprintln!(
            "kryptikd: zone {:?}: no physical interface in zone 0 to move: bridge only",
            zone.name
        ),
        _ => {}
    }
    for n in &nics {
        let carried = carry_nic(n, zone_ns)?;
        eprintln!("kryptikd: zone {:?}: {n} moved in with {carried}", zone.name);
    }
    netlink::with_netns(zone_ns, || {
        up_lo()?;
        netlink::create_bridge(BRIDGE)?;
        netlink::add_addr4(BRIDGE, netlink::BRIDGE_V4, 24)?;
        netlink::set_up(BRIDGE)?;
        // IPv6 is optional: without it the zone starts with IPv4 and says so.
        if let Err(e) = netlink::add_addr6(BRIDGE, netlink::BRIDGE_V6, 64) {
            eprintln!("kryptikd: zone {:?}: IPv6 on {BRIDGE} not configured ({e}); IPv4 is", zone.name);
        }
        /* Forwarding is set to 0 here, never inherited. tools/net/netzone-init.sh
         * turns it on once its nftables policy is loaded; before that, the
         * uplink could reach the routed zones this handshake reattaches.
         * Forwarding also joins routed zones via the bridge address, past port
         * isolation, but only with a host route, and so CAP_NET_ADMIN, which
         * no routed zone keeps (policy::check_for_zone).
         */
        sysctl("/proc/sys/net/ipv4/ip_forward", "0")?;
        if Path::new("/proc/sys/net/ipv6").exists() {
            sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "0")?;
        }
        for n in &nics {
            netlink::set_up(n)?;
        }
        Ok(())
    })
    .map_err(|e| io("configure the nic zone", e))
}

/// Write a sysctl; /proc/sys/net resolves to the opener's network namespace.
fn sysctl(path: &str, value: &str) -> io::Result<()> {
    std::fs::write(path, value).map_err(|e| io::Error::new(e.kind(), format!("{path} = {value}: {e}")))
}

/// Attach a new routed zone to the running nic zone's bridge.
pub fn plumb_routed_zone(zone: &Zone, zone_ns: i32, zones_dir: &Path, host_gid: u32) -> Result<(), NetError> {
    let k = host_number(zone).ok_or_else(|| {
        NetError::Refused("a routed zone needs [identity] uid_base to derive its address".into())
    })?;
    let net_ns = running_nic_zone_ns(zones_dir)?;
    attach_routed(&zone.name, k, net_ns.as_raw_fd(), zone_ns, Some(host_gid))
}

/// Create the veth from inside the nic zone with its peer born in the routed
/// zone as eth0, isolate the bridge port, then address and route eth0. On
/// failure the port is deleted, which takes the pair.
fn attach_routed(name: &str, k: u8, nic_ns: i32, zone_ns: i32, host_gid: Option<u32>) -> Result<(), NetError> {
    let port = port_name(name);
    let r = attach_v4(&port, k, nic_ns, zone_ns, host_gid);
    if r.is_err() {
        let _ = netlink::with_netns(nic_ns, || netlink::delete_link(&port));
    }
    r?;
    // With IPv6 disabled the address gets EACCES; IPv4 only is reported, not fatal.
    if let Err(e) = netlink::with_netns(zone_ns, || {
        netlink::add_addr6("eth0", netlink::zone_v6(k), 64)?;
        netlink::add_default_route6(netlink::BRIDGE_V6, "eth0")
    }) {
        eprintln!("kryptikd: zone {name:?}: IPv6 on eth0 not configured ({e}); IPv4 is");
    }
    Ok(())
}

fn attach_v4(port: &str, k: u8, nic_ns: i32, zone_ns: i32, host_gid: Option<u32>) -> Result<(), NetError> {
    netlink::with_netns(nic_ns, || {
        netlink::create_veth(port, "eth0", Some(zone_ns))?;
        netlink::set_master(port, BRIDGE)?;
        netlink::set_port_isolated(port, true)?;
        netlink::set_up(port)
    })
    .map_err(|e| io("attach the zone to the bridge", e))?;
    netlink::with_netns(zone_ns, || {
        up_lo()?;
        // Addresses come only from here: no router advertisements.
        let _ = sysctl("/proc/sys/net/ipv6/conf/eth0/accept_ra", "0");
        // IPv4 first and complete, so no IPv6 failure can cost the zone its route.
        netlink::add_addr4("eth0", netlink::zone_v4(k), 24)?;
        netlink::set_up("eth0")?;
        netlink::add_default_route4(netlink::BRIDGE_V4, "eth0")?;
        /* Unprivileged ICMP echo for the zone's group, since a routed zone
         * cannot keep CAP_NET_RAW. The range takes host gids: the parent
         * writes it from outside the zone's user namespace. */
        if let Some(g) = host_gid {
            let _ = sysctl("/proc/sys/net/ipv4/ping_group_range", &format!("{g} {g}"));
        }
        Ok(())
    })
    .map_err(|e| io("address the zone's eth0", e))
}

/// A zone's network namespace, opened before its pid is trusted: callers check
/// `still_alive` after, so a reused pid cannot hand over another namespace.
fn open_ns(st: &registry::PidStamp) -> io::Result<OwnedFd> {
    netlink::open_netns_of(st.pid).map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The running nic zone's network namespace. The root-owned zone files say
/// which zone that is, never what a namespace holds: a zone could create its
/// own kryptik0.
fn running_nic_zone_ns(zones_dir: &Path) -> Result<OwnedFd, NetError> {
    for name in registry::names() {
        let file = zones_dir.join(format!("{name}.toml"));
        let Ok(z) = Zone::from_file(&file) else { continue };
        if z.network != NetworkMode::Nic {
            continue;
        }
        if let Ok(registry::State::Running { init: Some(st), .. }) = registry::state(&name) {
            let ns = open_ns(&st);
            if st.still_alive() {
                return ns.map_err(|e| io("open the nic zone's netns", e));
            }
        }
    }
    Err(NetError::NoNetZone)
}

/// What the parent does for this zone, or why it does nothing.
pub fn plan(zone: &Zone, privileged: bool) -> String {
    let mut line = plan_line(zone, privileged);
    if let Some(devs) = fallback_tunnels_expected() {
        line.push_str(&format!(
            "\n           this kernel creates {} in every new network namespace ({FB_TUNNELS_SYSCTL} = 0): {}",
            devs.join(", "),
            if privileged {
                "the launcher sets it to 1 before the zone's namespace exists"
            } else {
                "an unprivileged launch cannot change that and is refused without KRYPTIK_EXPERIMENTAL=1"
            }
        ));
    }
    line
}

fn plan_line(zone: &Zone, privileged: bool) -> String {
    match (zone.network, privileged) {
        (NetworkMode::None, _) => "network    none: loopback only, nothing created".into(),
        (_, false) => "network    (unprivileged launch: no topology; loopback only)".into(),
        (NetworkMode::Nic, true) => format!(
            "network    nic: {} into this zone; bridge {} 10.19.0.1/24 fd19::1/64; \
             forwarding off until the zone's program enables it behind its firewall",
            match zone.nic.as_deref() {
                Some("*") => "every physical interface of zone 0 (wired by the netdev, wireless by its wiphy) moves".to_string(),
                Some(n) => format!("{n} moves"),
                None => "no interface moves (no [network] nic)".to_string(),
            },
            BRIDGE
        ),
        (NetworkMode::Routed, true) => match host_number(zone) {
            Some(k) => format!(
                "network    routed: eth0 = 10.19.0.{k}/24 fd19::{k:x}/64 via the nic zone's {BRIDGE}, \
                 isolated port {}; forwarding and NAT are the nic zone's program's to enable \
                 once its firewall is loaded (kryptikd leaves forwarding off)",
                port_name(&zone.name)
            ),
            None => "network    routed: needs [identity] uid_base to derive an address".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn z(mode: &str, base: Option<u32>, nic: Option<&str>) -> Zone {
        let ident = base.map(|b| format!("[identity]\nuid_base = {b}\n")).unwrap_or_default();
        let nicl = nic.map(|n| format!("nic = \"{n}\"\n")).unwrap_or_default();
        Zone::from_str(&format!(
            "[zone]\nname = \"t\"\n[network]\nmode = \"{mode}\"\n{nicl}\
             [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n{ident}[ui]\nborder_color = \"#123456\"\n"
        ))
        .unwrap()
    }

    /// This namespace plays a nic zone that inherited forwarding on; after the
    /// bridge half both forwarding knobs must read 0.
    #[test]
    fn bridge_half_turns_forwarding_off() {
        use crate::netlink::tests::in_userns_netns;
        let rc = in_userns_netns(|| {
            let ns = match netlink::open_netns_of(unsafe { libc::getpid() }) {
                Ok(fd) => fd,
                Err(_) => return 40,
            };
            if std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").is_err() {
                eprintln!("cannot write ip_forward in this namespace; skipping");
                unsafe { libc::close(ns) };
                return 77;
            }
            let _ = std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1");
            let r = plumb_nic_zone_bridge(&z("nic", Some(196608), None), ns);
            unsafe { libc::close(ns) };
            if let Err(e) = r {
                eprintln!("plumb_nic_zone_bridge: {e}");
                return 1;
            }
            let v4 = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap_or_default();
            if v4.trim() != "0" {
                eprintln!("ip_forward reads {v4:?} after the bridge half; expected 0");
                return 2;
            }
            if let Ok(v6) = std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding") {
                if v6.trim() != "0" {
                    eprintln!("IPv6 forwarding reads {v6:?} after the bridge half; expected 0");
                    return 3;
                }
            }
            0
        });
        match rc {
            0 => {}
            77 => eprintln!("no unprivileged user namespace; skipping"),
            other => panic!("forwarding-off test failed at step {other}"),
        }
    }

    /// A veth pair and a bridge must not count. Sysfs shows the network
    /// namespace of whoever mounted it, so the child mounts its own.
    #[test]
    fn only_bus_devices_count_as_physical() {
        use crate::netlink::tests::{in_userns_netns, step};
        use std::ffi::CString;
        /* Before the fork: temp_dir() takes std's environment lock, and a child
         * forked while another thread holds it waits forever. */
        let dir = std::env::temp_dir().join(format!("kryptik-sysfs-{}", std::process::id()));
        let rc = in_userns_netns(|| {
            if std::fs::create_dir_all(&dir).is_err() {
                return 70;
            }
            let root = CString::new("/").unwrap();
            let target = CString::new(dir.to_string_lossy().as_bytes()).unwrap();
            let sysfs = CString::new("sysfs").unwrap();
            unsafe {
                if libc::mount(std::ptr::null(), root.as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) < 0
                    || libc::mount(sysfs.as_ptr(), target.as_ptr(), sysfs.as_ptr(), 0, std::ptr::null()) < 0
                {
                    eprintln!("cannot mount a sysfs of this namespace: {}; skipping", io::Error::last_os_error());
                    let _ = std::fs::remove_dir(&dir);
                    return 77;
                }
            }
            let class_net = dir.join("class/net");
            let r: Result<(), i32> = (|| {
                let before = physical_interfaces_under(&class_net).map_err(|e| {
                    eprintln!("physical_interfaces: {e}");
                    1
                })?;
                if !before.is_empty() {
                    eprintln!("a fresh namespace already counts {before:?} as physical");
                    return Err(2);
                }
                step(3, netlink::create_veth("pa", "pb", None))?;
                step(4, netlink::create_bridge("br-t"))?;
                if !class_net.join("pa").exists() || !class_net.join("br-t").exists() {
                    eprintln!("the mounted sysfs does not show this namespace's devices; this proved nothing");
                    return Err(5);
                }
                let after = physical_interfaces_under(&class_net).map_err(|_| 6)?;
                if !after.is_empty() {
                    eprintln!("software devices counted as physical: {after:?}");
                    return Err(7);
                }
                Ok(())
            })();
            let _ = std::fs::remove_dir(&dir);
            match r {
                Ok(()) => 0,
                Err(c) => c,
            }
        });
        match rc {
            0 => {}
            77 => eprintln!("no unprivileged user namespace or sysfs mount; skipping"),
            other => panic!("physical-interface test failed at step {other}"),
        }
    }

    #[test]
    fn host_number_from_uid_base() {
        assert_eq!(host_number(&z("routed", Some(131072), None)), Some(2));
        assert_eq!(host_number(&z("routed", Some(196608), None)), Some(3));
        assert_eq!(host_number(&z("routed", Some(458752), None)), Some(7));
        assert_eq!(host_number(&z("routed", None, None)), None);
        // 248 zones fit: hosts 2 to 249.
        assert_eq!(host_number(&z("routed", Some(131072 + 247 * 65536), None)), Some(249));
        assert_eq!(host_number(&z("routed", Some(131072 + 248 * 65536), None)), None);
    }

    #[test]
    fn port_names_fit_ifnamsiz() {
        assert_eq!(port_name("untrusted"), "kv-untrusted");
        assert!(port_name("twelvecharsx").len() <= 15);
    }

    #[test]
    fn plan_describes_each_mode() {
        assert!(plan(&z("none", None, None), true).contains("nothing created"));
        assert!(plan(&z("routed", Some(131072), None), false).contains("unprivileged"));
        assert!(plan(&z("routed", Some(131072), None), true).contains("10.19.0.2/24"));
        assert!(plan(&z("routed", None, None), true).contains("needs [identity]"));
        assert!(plan(&z("nic", None, Some("eth0")), true).contains("eth0 moves"));
        assert!(plan(&z("nic", None, Some("*")), true).contains("every physical interface"));
        assert!(plan(&z("nic", None, None), true).contains("no interface moves"));
    }

    /// The launcher acts on `fallback_tunnels_expected` before a zone's namespace exists.
    #[test]
    fn fresh_namespace_matches_prediction() {
        use crate::netlink::tests::in_userns_netns;
        let mut predicted = fallback_tunnels_expected().unwrap_or_default();
        predicted.sort();
        let rc = in_userns_netns(move || {
            let mut got = match devices_besides_lo() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("if_nameindex: {e}");
                    return 1;
                }
            };
            got.sort();
            if got == predicted {
                0
            } else {
                eprintln!("fresh namespace has {got:?}, predicted {predicted:?}");
                2
            }
        });
        match rc {
            0 => {}
            77 => eprintln!("no unprivileged user namespace; skipping"),
            other => panic!("fresh-namespace contents test failed at step {other}"),
        }
    }

    /// This namespace plays the nic zone and a holder a zone with IPv6
    /// disabled; eth0 must still come out addressed, up and routed.
    #[test]
    fn ipv4_survives_disabled_ipv6() {
        use crate::netlink::tests::{in_userns_netns, spawn_netns_holder, step};
        let rc = in_userns_netns(|| {
            let (holder, zone_ns) = match spawn_netns_holder() {
                Ok(v) => v,
                Err(c) => return c,
            };
            let nic_ns = match netlink::open_netns_of(unsafe { libc::getpid() }) {
                Ok(fd) => fd,
                Err(_) => return 40,
            };
            let r: Result<(), i32> = (|| {
                step(1, netlink::create_bridge(BRIDGE))?;
                step(2, netlink::add_addr4(BRIDGE, netlink::BRIDGE_V4, 24))?;
                step(3, netlink::set_up(BRIDGE))?;
                step(
                    4,
                    netlink::with_netns(zone_ns, || {
                        std::fs::write("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1")?;
                        std::fs::write("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1")
                    }),
                )?;
                attach_routed("t", 7, nic_ns, zone_ns, None).map_err(|e| {
                    eprintln!("attach_routed: {e}");
                    5
                })?;
                let (routes, v6, up) = netlink::with_netns(zone_ns, || {
                    Ok((
                        std::fs::read_to_string("/proc/self/net/route")?,
                        std::fs::read_to_string("/proc/self/net/if_inet6").unwrap_or_default(),
                        netlink::is_up("eth0")?,
                    ))
                })
                .map_err(|_| 6)?;
                if !up {
                    return Err(7);
                }
                let rows: Vec<&str> = routes.lines().skip(1).collect();
                let default = rows.iter().any(|l| {
                    let mut f = l.split_whitespace();
                    f.next() == Some("eth0") && f.next() == Some("00000000")
                });
                if !default || rows.len() < 2 {
                    eprintln!("zone routes:\n{routes}");
                    return Err(8);
                }
                // Premise: IPv6 really was refused.
                if v6.lines().any(|l| l.contains("eth0")) {
                    eprintln!("IPv6 was not disabled in the zone namespace; this proved nothing:\n{v6}");
                    return Err(9);
                }
                Ok(())
            })();
            unsafe {
                libc::kill(holder, libc::SIGKILL);
                libc::close(nic_ns);
                libc::close(zone_ns);
            }
            match r {
                Ok(()) => 0,
                Err(c) => c,
            }
        });
        match rc {
            0 => {}
            77 => eprintln!("no unprivileged user namespace; skipping"),
            other => panic!("routed zone IPv4 path with IPv6 disabled: failed at step {other}"),
        }
    }

    /// A veth end with an address and default route plays the uplink; after
    /// `carry_nic` it must be up with the same configuration in the holder.
    #[test]
    fn uplink_config_travels_with_nic() {
        use crate::netlink::tests::{in_userns_netns, spawn_netns_holder, step};
        let rc = in_userns_netns(|| {
            let (holder, zone_ns) = match spawn_netns_holder() {
                Ok(v) => v,
                Err(c) => return c,
            };
            let r: Result<(), i32> = (|| {
                step(1, netlink::create_veth("up0", "up1", None))?;
                step(2, netlink::set_up("up1"))?;
                step(3, netlink::set_up("up0"))?;
                step(4, netlink::add_addr4("up0", [10, 77, 0, 5], 24))?;
                step(5, netlink::add_default_route4([10, 77, 0, 1], "up0"))?;
                let before = uplink_config("up0").map_err(|e| {
                    eprintln!("uplink_config: {e}");
                    6
                })?;
                if before.addrs != vec![([10, 77, 0, 5], 24)] || before.gateway != Some([10, 77, 0, 1]) {
                    eprintln!("read back {before}");
                    return Err(7);
                }
                let carried = carry_nic("up0", zone_ns).map_err(|e| {
                    eprintln!("carry_nic: {e}");
                    8
                })?;
                if carried != before {
                    return Err(9);
                }
                if netlink::is_up("up0").is_ok() {
                    return Err(10);
                }
                let (after, up) = netlink::with_netns(zone_ns, || Ok((uplink_config("up0")?, netlink::is_up("up0")?)))
                    .map_err(|e| {
                        eprintln!("inside the zone: {e}");
                        11
                    })?;
                if !up {
                    return Err(12);
                }
                if after != before {
                    eprintln!("inside the zone: {after}; expected {before}");
                    return Err(13);
                }
                Ok(())
            })();
            unsafe {
                libc::kill(holder, libc::SIGKILL);
                libc::close(zone_ns);
            }
            match r {
                Ok(()) => 0,
                Err(c) => c,
            }
        });
        match rc {
            0 => {}
            77 => eprintln!("no unprivileged user namespace; skipping"),
            other => panic!("uplink carry failed at step {other}"),
        }
    }

    #[test]
    fn gateway_comes_from_zone_directory() {
        // An empty zone directory names no nic zone, whatever else is running.
        let dir = std::env::temp_dir().join(format!("kryptik-nz-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let e = running_nic_zone_ns(&dir).unwrap_err();
        assert!(matches!(e, NetError::NoNetZone));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_nic_refused_before_move() {
        // Unprivileged: the check comes before any netlink call.
        let dir = std::env::temp_dir();
        let e = plumb_nic_zone(&z("nic", None, Some("nosuchnic99")), -1, &dir).unwrap_err();
        assert!(e.to_string().contains("not an interface"), "{e}");
    }

    #[test]
    fn replumb_empty_directory_attempts_nothing() {
        let dir = std::env::temp_dir().join(format!("kryptik-rp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(replumb_routed_zones(&dir, -1).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
