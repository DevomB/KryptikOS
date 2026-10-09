//! Zone network topology (docs/design/net-zone.md): who owns the NIC and how routed zones reach it.
//!
//! ```text
//!  physical NIC  --moved into-->  net zone's netns   (mode = "nic")
//!                                   kryptik0 bridge 10.19.0.1/24, fd19::1/64
//!  routed zone k:  kv-<zone> in net's netns, on kryptik0, isolated
//!                  eth0 in the zone's netns: 10.19.0.k/24, fd19::k/64,
//!                  MAC 02:19:00:00:00:k, default routes via the bridge
//!  zone 0:         keeps lo only once net has taken the NIC
//!  mode = "none":  nothing is ever created
//! ```
//!
//! Runs in the root parent while the zone waits at its handshake; an unprivileged launch gets
//! loopback only. NAT, forwarding policy and the resolver belong to tools/net/netzone-init.sh.

use std::ffi::{CStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use crate::netlink;
use crate::registry;
use crate::zone::{NetworkMode, Zone};

pub const BRIDGE: &str = "kryptik0";

/// Where fallback tunnel devices appear: 0 = every new namespace, 1 = the initial one, 2 = none.
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

/// The fallback devices a new network namespace would start with here, or None for loopback only.
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

/// Make new network namespaces start empty; Ok(Some(note)) if the sysctl had to be raised to 1.
pub fn suppress_fallback_tunnels() -> Result<Option<String>, String> {
    let Some(devs) = fallback_tunnels_expected() else { return Ok(None) };
    match std::fs::write(FB_TUNNELS_SYSCTL, "1") {
        Ok(()) => Ok(Some(format!(
            "set {FB_TUNNELS_SYSCTL} = 1 (was 0) so new network namespaces do not get {}",
            devs.join(", ")
        ))),
        Err(e) => Err(format!(
            "cannot set {FB_TUNNELS_SYSCTL} = 1 ({e}), so the zone's network namespace would get {}",
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

/// A routed zone's host number, from its unique uid base: 131072 -> 2, 196608 -> 3, ...
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

/// An uplink's IPv4 configuration, kept to re-apply after a namespace move flushes it.
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

/// Move `nic` into `zone_ns`, re-applying the IPv4 configuration it loses (DHCP is the zone's job).
fn carry_nic(nic: &str, zone_ns: i32) -> Result<Uplink, NetError> {
    let cfg = uplink_config(nic).map_err(|e| io(&format!("read the configuration of {nic:?}"), e))?;
    // A wireless netdev is namespace-local; move its wiphy instead.
    match netlink::wiphy_index_of(nic).map_err(|e| io(&format!("read the wiphy of {nic:?}"), e))? {
        Some(phy) => netlink::set_wiphy_netns(phy, zone_ns)
            .map_err(|e| io(&format!("move {nic:?} (wiphy {phy}) into the nic zone"), e))?,
        None => netlink::set_netns(nic, zone_ns).map_err(|e| io(&format!("move {nic:?} into the nic zone"), e))?,
    }
    netlink::with_netns(zone_ns, || {
        for (a, p) in &cfg.addrs {
            netlink::add_addr4(nic, *a, *p)?;
        }
        netlink::set_up(nic)?;
        if let Some(gw) = cfg.gateway {
            // The first uplink's default route stands; the zone's DHCP client sorts them out later.
            match netlink::add_default_route4(gw, nic) {
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    eprintln!("kryptikd: {nic:?}: the nic zone already has a default route; keeping the first")
                }
                r => r?,
            }
        }
        Ok(())
    })
    .map_err(|e| io(&format!("configure {nic:?} inside the nic zone"), e))?;
    Ok(cfg)
}

/// Interfaces on a bus device (`/sys/class/net/<n>/device`): what `[network] nic = "*"` moves.
///
/// A NIC comes back to zone 0 under whatever name the net zone that held it gave it, and the
/// next zone's script, nft set and dhcpcd would take that name as it is: one that is not plain
/// becomes `nic<N>` first. It came back down, as a rename needs.
///
/// A radio comes back with whatever netdevs that zone left on it, and leaves with one station,
/// as a boot gives it. One with several loses them all, since which to keep would be that
/// zone's choice, and moving the wiphy would take an AP, mesh or monitor netdev along; one with
/// none, then or before, gets a fresh station, which takes the radio's own address.
pub fn physical_interfaces() -> io::Result<Vec<String>> {
    let class_net = Path::new("/sys/class/net");
    let listed = physical_interfaces_under(class_net)?;
    let mut per_radio = std::collections::BTreeMap::new();
    for (_, _, phy) in &listed {
        if let Some(p) = phy {
            *per_radio.entry(*p).or_insert(0) += 1;
        }
    }
    for (name, idx, phy) in &listed {
        if phy.is_some_and(|p| per_radio[&p] > 1) {
            if let Err(e) = netlink::del_interface(*idx) {
                eprintln!("kryptikd: interface {name:?} on a radio with several could not be deleted: {e}");
            }
        }
    }
    for phy in bare_radios(Path::new("/sys/class")) {
        match netlink::new_station(phy, "nic%d") {
            Ok(()) => eprintln!("kryptikd: wiphy {phy} came back with no interface or several; it has one station now"),
            Err(e) => eprintln!("kryptikd: wiphy {phy} has no interface, and none could be added: {e}"),
        }
    }
    let mut out = Vec::new();
    let mut radios = std::collections::BTreeSet::new();
    for (name, idx, phy) in physical_interfaces_under(class_net)? {
        // A netdev that could not be deleted goes along with its radio's first.
        if phy.is_some_and(|p| !radios.insert(p)) {
            continue;
        }
        if plain_name(name.as_bytes()) {
            out.push(name.to_string_lossy().into_owned());
            continue;
        }
        match netlink::rename_index(idx, "nic%d") {
            Ok(now) => {
                eprintln!("kryptikd: interface {name:?} renamed {now:?} before it moves");
                out.push(now);
            }
            Err(e) => eprintln!("kryptikd: interface {name:?} left in zone 0: {e}"),
        }
    }
    out.sort();
    Ok(out)
}

/// A name as the kernel and eudev give one: a lower-case letter, then lower-case letters and
/// digits, so no option, quote, glob or control byte. Not `BRIDGE`, which the start makes in
/// the zone after the NICs move: a NIC by that name would fail it.
fn plain_name(name: &[u8]) -> bool {
    name.len() < 16
        && name != BRIDGE.as_bytes()
        && name.first().is_some_and(|b| b.is_ascii_lowercase())
        && name.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Each physical interface's name, as the kernel holds it, its index, and its wiphy's if it
/// is a radio's, under any sysfs `class/net` directory, for tests.
fn physical_interfaces_under(class_net: &Path) -> io::Result<Vec<(OsString, u32, Option<u32>)>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(class_net)? {
        let e = e?;
        let name = e.file_name();
        if name == "lo" || !e.path().join("device").exists() {
            continue;
        }
        let idx = sysfs_index(&e.path().join("ifindex"))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "a sysfs ifindex is not a number"))?;
        out.push((name, idx, sysfs_index(&e.path().join("phy80211/index"))));
    }
    out.sort();
    Ok(out)
}

/// The wiphys under a sysfs `class` directory that no netdev sits on, by index.
fn bare_radios(class: &Path) -> Vec<u32> {
    let entries = |d: &str| std::fs::read_dir(class.join(d)).into_iter().flatten().flatten();
    let held: std::collections::BTreeSet<u32> =
        entries("net").filter_map(|e| sysfs_index(&e.path().join("phy80211/index"))).collect();
    let mut bare: Vec<u32> =
        entries("ieee80211").filter_map(|e| sysfs_index(&e.path().join("index"))).filter(|p| !held.contains(p)).collect();
    bare.sort();
    bare
}

fn sysfs_index(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
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

/// Attach every running routed zone to the nic zone in `nic_ns`, one result per zone. Each names
/// the bridge's resolver from its start, so one started before any gateway resolves once attached.
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

/// Move the uplinks into the nic zone and create kryptik0 there. Only here, before its root is
/// built: its /sys keeps the devices of the NICs it holds then (`rootfs::nic_sysfs`).
fn plumb_nic_zone_bridge(zone: &Zone, zone_ns: i32) -> Result<(), NetError> {
    // Without `[network] nic`, bridge only: kryptikd never picks a NIC to take from zone 0 itself.
    let nics: Vec<String> = match zone.nic.as_deref() {
        None => Vec::new(),
        // Every physical interface, wired or wireless; finding none is not an error.
        Some("*") => physical_interfaces().map_err(|e| io("list the physical interfaces of zone 0", e))?,
        Some(n) => {
            // A named NIC missing from zone 0 is a configuration error.
            let c = std::ffi::CString::new(n).map_err(|_| NetError::Refused(format!("[network] nic = {n:?}")))?;
            if unsafe { libc::if_nametoindex(c.as_ptr()) } == 0 {
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
        eprintln!("kryptikd: zone {:?}: {n:?} moved in with {carried}", zone.name);
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
        /* Forwarding stays off until netzone-init.sh loads its nftables policy, or the uplink could
         * reach routed zones; forwarding past port isolation also needs CAP_NET_ADMIN, which none keeps. */
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

/// An isolated bridge port, its veth peer born in the zone as eth0, then addresses and routes.
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

/// How long a port a zone left behind may take to go: the kernel tears a dead zone's namespace
/// down, and its end of the pair with it, after the zone has exited.
const STALE_PORT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

fn attach_v4(port: &str, k: u8, nic_ns: i32, zone_ns: i32, host_gid: Option<u32>) -> Result<(), NetError> {
    netlink::with_netns(nic_ns, || {
        /* One instance of a zone runs at a time (registry::claim), so a port by this name is the
         * last instance's, still waiting on its namespace's teardown: delete it, or wait. */
        let since = std::time::Instant::now();
        loop {
            match netlink::create_veth(port, "eth0", Some(zone_ns), Some(netlink::zone_mac(k))) {
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && since.elapsed() < STALE_PORT_WAIT => {
                    let _ = netlink::delete_link(port);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                r => break r?,
            }
        }
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
        /* Unprivileged ping for the zone's group, as no routed zone keeps CAP_NET_RAW; host gids,
         * since the parent writes the range from outside the zone's user namespace. */
        if let Some(g) = host_gid {
            let _ = sysctl("/proc/sys/net/ipv4/ping_group_range", &format!("{g} {g}"));
        }
        Ok(())
    })
    .map_err(|e| io("address the zone's eth0", e))
}

/// A zone's netns, opened before callers check `still_alive`, so a reused pid cannot swap it.
fn open_ns(st: &registry::PidStamp) -> io::Result<OwnedFd> {
    netlink::open_netns_of(st.pid).map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The running nic zone's netns, picked by the root-owned zone files: any zone can make a kryptik0.
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
                 once its firewall is loaded (kryptikd leaves forwarding off); {}",
                port_name(&zone.name),
                if zone.local {
                    "may reach the networks the uplinks sit on ([network] local)"
                } else {
                    "refused the networks the uplinks sit on"
                }
            ),
            None => "network    routed: needs [identity] uid_base to derive an address".into(),
        },
    }
}

#[cfg(test)]
mod tests;
