//! The zone network topology (docs/design/03): who owns the NIC, and how a
//! routed zone reaches it.
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
//! Everything here runs in the PARENT `kryptikd run` process, as root, while
//! the new zone is paused at its handshake: its network namespace exists,
//! nothing runs in it yet, and it has no capabilities over anything. The
//! parent needs CAP_SYS_ADMIN over the initial namespace (to move the NIC and
//! to setns), which is why this is the privileged path only: an unprivileged
//! developer launch gets a note and a zone with loopback, as before.
//!
//! What is deliberately not here yet: NAT and a resolver in the net zone
//! (they need nftables and a stub resolver in the image), so a routed zone
//! today reaches the bridge and the net zone, not the world. Design 03 lists
//! the rest; this is the ownership and isolation half, which is the security
//! boundary.

use std::ffi::CStr;
use std::io;
use std::path::Path;

use crate::netlink;
use crate::registry;
use crate::zone::{NetworkMode, Zone};

pub const BRIDGE: &str = "kryptik0";

/// The kernel creates its fallback tunnel devices (sit0, tunl0, ...) in EVERY
/// new network namespace when the tunnel modules are built in or loaded,
/// unless this sysctl says otherwise: 0 = every namespace, 1 = only the
/// initial one, 2 = none (since 4.16). The Kryptik kernel builds SIT in, and
/// its first boot found sit0 inside an airgapped zone (R-13).
pub const FB_TUNNELS_SYSCTL: &str = "/proc/sys/net/core/fb_tunnels_only_for_init_net";

/// The fallback devices the kernel's tunnel modules register per namespace.
pub const FALLBACK_DEVICES: &[&str] =
    &["sit0", "tunl0", "ip6tnl0", "gre0", "gretap0", "erspan0", "ip6gre0", "ip_vti0", "ip6_vti0"];

/// Every interface in the calling process's network namespace except
/// loopback, as the kernel lists them.
pub fn devices_besides_lo() -> io::Result<Vec<String>> {
    // SAFETY: if_nameindex returns an array terminated by a zero index that
    // we free with if_freenameindex; every entry before the terminator has a
    // NUL-terminated if_name.
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

/// What a new network namespace would start with on this host, if not
/// nothing: the fallback devices present here, when the sysctl says every
/// namespace gets them. None when a new namespace would be loopback-only.
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

/// Make sure a zone's new network namespace will be empty. Ok(None): it will
/// be, nothing to do. Ok(Some(note)): the sysctl was raised to 1 - the
/// initial namespace keeps its devices, new ones get none - and the note
/// says so. Err(why): a zone would get devices and this process cannot
/// prevent it (an unprivileged launcher, or a read-only /proc/sys).
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

/// The routed zone's host number on the bridge subnet, from its declared
/// identity: base 131072 -> 2, 196608 -> 3, ... Stable across zone additions
/// (it is declared, not positional) and disjoint by construction, because
/// bases are unique multiples of 65536.
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

/// Bring up loopback and, for a routed zone, nothing else here: the parent
/// plumbs eth0 from outside.
fn up_lo() -> io::Result<()> {
    netlink::set_up("lo")
}

/// The IPv4 configuration an uplink carries: what DHCP or an installer left
/// on it, read back from the kernel so it can be re-applied where the
/// interface is going. Moving an interface between namespaces flushes its
/// addresses and routes.
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

/// The IPv4 addresses (getifaddrs) and default gateway (/proc/self/net/route)
/// of `nic` in the calling process's network namespace.
pub fn uplink_config(nic: &str) -> io::Result<Uplink> {
    let mut addrs = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills a list we walk and free with freeifaddrs;
    // ifa_addr/ifa_netmask may be null and are checked; an AF_INET entry's
    // sockaddr is a sockaddr_in.
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
            // Iface Destination Gateway Flags ... Mask: a default route is
            // destination and mask both zero on this interface.
            if f.len() > 7 && f[0] == nic && f[1] == "00000000" && f[7] == "00000000" {
                u32::from_str_radix(f[2], 16).ok().map(|g| g.to_ne_bytes())
            } else {
                None
            }
        })
        .next();
    Ok(Uplink { addrs, gateway })
}

/// Move `nic` into `zone_ns` and give it back the IPv4 configuration it had
/// here: the kernel flushes addresses and routes on a namespace move, and a
/// nic zone with a bare interface would route every zone to nothing. What
/// travels is what was there - no DHCP is spoken here; a client in the nic
/// zone can take over the lease later. Returns what was carried.
fn carry_nic(nic: &str, zone_ns: i32) -> Result<Uplink, NetError> {
    let cfg = uplink_config(nic).map_err(|e| io(&format!("read the configuration of {nic}"), e))?;
    netlink::set_netns(nic, zone_ns).map_err(|e| io(&format!("move {nic} into the nic zone"), e))?;
    netlink::with_netns(zone_ns, || {
        for (a, p) in &cfg.addrs {
            netlink::add_addr4(nic, *a, *p)?;
        }
        netlink::set_up(nic)?;
        if let Some(gw) = cfg.gateway {
            netlink::add_default_route4(gw, nic)?;
        }
        Ok(())
    })
    .map_err(|e| io(&format!("configure {nic} inside the nic zone"), e))?;
    Ok(cfg)
}

/// The nic zone: create the bridge in its namespace and move the physical
/// interface into it. Called by the root parent with the zone's netns fd.
pub fn plumb_nic_zone(zone: &Zone, zone_ns: i32, zones_dir: &Path) -> Result<(), NetError> {
    plumb_nic_zone_bridge(zone, zone_ns)?;
    // Routed zones that are already running - started before this gateway,
    // or stranded when a previous gateway died and took their peers with it
    // - are attached now (Design 03 N8, reconnection). Each failure is
    // reported and does not stop the others or the nic zone.
    for (name, r) in replumb_routed_zones(zones_dir, zone_ns) {
        match r {
            Ok(()) => eprintln!("kryptikd: zone {name:?} reattached to the new nic zone"),
            Err(e) => eprintln!("kryptikd: zone {name:?} could not be reattached: {e}"),
        }
    }
    Ok(())
}

/// Attach every running routed zone (per the zone directory and the
/// registry) to the nic zone whose namespace is `nic_ns`. Returns one result
/// per zone attempted; an empty registry attempts nothing.
///
/// A routed zone keeps the resolv.conf it was started with: a zone that
/// started before any gateway has none, and gets a path here but no
/// resolver until it is restarted. Its root is sealed; kryptikd does not
/// reach into a running zone to change its files.
pub fn replumb_routed_zones(zones_dir: &Path, nic_ns: i32) -> Vec<(String, Result<(), NetError>)> {
    let mut out = Vec::new();
    for name in registry::names() {
        let Ok(z) = Zone::from_file(&zones_dir.join(format!("{name}.toml"))) else { continue };
        if z.network != NetworkMode::Routed {
            continue;
        }
        let Ok(registry::State::Running { init: Some(st), .. }) = registry::state(&name) else { continue };
        if !st.still_alive() {
            continue;
        }
        let r = (|| {
            let k = host_number(&z).ok_or_else(|| {
                NetError::Refused("no [identity] uid_base to derive an address".into())
            })?;
            let zone_ns = netlink::open_netns_of(st.pid).map_err(|e| io("open the zone netns", e))?;
            let r = attach_routed(&z.name, k, nic_ns, zone_ns);
            unsafe { libc::close(zone_ns) };
            r
        })();
        out.push((name, r));
    }
    out
}

/// The bridge half of the nic zone: create kryptik0 in its namespace and
/// move the physical interface into it.
fn plumb_nic_zone_bridge(zone: &Zone, zone_ns: i32) -> Result<(), NetError> {
    // A nic zone without `[network] nic` gets the bridge and no interface:
    // routed zones can attach and reach it, nothing reaches the world. Said
    // out loud rather than guessed - kryptikd never picks a NIC to move out
    // of zone 0 on its own.
    let nic = zone.nic.as_deref();
    if let Some(n) = nic {
        // The NIC must exist here (zone 0) before we hand it over; a name
        // that is not an interface is a configuration error, not a retry.
        if unsafe { libc::if_nametoindex(std::ffi::CString::new(n).unwrap().as_ptr()) } == 0 {
            return Err(NetError::Refused(format!(
                "[network] nic = {n:?} is not an interface in this namespace"
            )));
        }
        let carried = carry_nic(n, zone_ns)?;
        eprintln!("kryptikd: zone {:?}: {n} moved in with {carried}", zone.name);
    } else {
        eprintln!(
            "kryptikd: zone {:?} declares no [network] nic: bridge only, no interface moved",
            zone.name
        );
    }
    netlink::with_netns(zone_ns, || {
        up_lo()?;
        netlink::create_bridge(BRIDGE)?;
        netlink::add_addr4(BRIDGE, netlink::BRIDGE_V4, 24)?;
        netlink::set_up(BRIDGE)?;
        // IPv6 is additive here as on the routed side: a nic zone that
        // cannot have it still starts, with IPv4, and says so.
        if let Err(e) = netlink::add_addr6(BRIDGE, netlink::BRIDGE_V6, 64) {
            eprintln!("kryptikd: zone {:?}: IPv6 on {BRIDGE} not configured ({e}); IPv4 is", zone.name);
        }
        // Forward between the bridge and the uplink. Without NAT this only
        // reaches the world behind something that accepts any source address
        // (QEMU user networking does); behind a real NIC the routed zones'
        // addresses are not routable and NAT (nftables) is still required.
        // Said in `plan` so nobody reads a VM result as more than it is.
        //
        // Forwarding also opens an L3 path between two routed zones through
        // the bridge address itself, which the port isolation does not cover
        // - but only for a zone that can install a host route, and a routed
        // zone can never keep CAP_NET_ADMIN (policy::check_for_zone).
        sysctl("/proc/sys/net/ipv4/ip_forward", "1")?;
        sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1")?;
        match nic {
            Some(n) => netlink::set_up(n),
            None => Ok(()),
        }
    })
    .map_err(|e| io("configure the nic zone", e))
}

/// Write a network sysctl of the CURRENT network namespace (procfs resolves
/// /proc/sys/net against the namespace of the process that opens it).
fn sysctl(path: &str, value: &str) -> io::Result<()> {
    std::fs::write(path, value).map_err(|e| io::Error::new(e.kind(), format!("{path} = {value}: {e}")))
}

/// A routed zone: a veth pair whose bridge end lives in the running net
/// zone's namespace (isolated port on kryptik0) and whose other end is
/// created directly in the new zone as eth0, addressed from its identity.
pub fn plumb_routed_zone(zone: &Zone, zone_ns: i32, zones_dir: &Path) -> Result<(), NetError> {
    let k = host_number(zone).ok_or_else(|| {
        NetError::Refused("a routed zone needs [identity] uid_base to derive its address".into())
    })?;
    let net_pid = running_nic_zone_init(zones_dir)?;
    let net_ns = netlink::open_netns_of(net_pid).map_err(|e| io("open the nic zone's netns", e))?;
    let r = attach_routed(&zone.name, k, net_ns, zone_ns);
    unsafe { libc::close(net_ns) };
    r
}

/// One routed zone onto the bridge: the pair is created from inside the nic
/// zone's namespace with the peer landing directly in the routed zone as
/// eth0; the port is enslaved, isolated and brought up; then the routed end
/// is addressed from its host number with default routes to the bridge.
fn attach_routed(name: &str, k: u8, nic_ns: i32, zone_ns: i32) -> Result<(), NetError> {
    let port = port_name(name);
    netlink::with_netns(nic_ns, || {
        netlink::create_veth(&port, "eth0", Some(zone_ns))?;
        netlink::set_master(&port, BRIDGE)?;
        netlink::set_port_isolated(&port, true)?;
        netlink::set_up(&port)
    })
    .map_err(|e| io("attach the zone to the bridge", e))?;
    netlink::with_netns(zone_ns, || {
        up_lo()?;
        // No router advertisements are ever accepted in a routed zone: its
        // addresses come from here and nowhere else (Design 03, IPv6).
        let _ = sysctl("/proc/sys/net/ipv6/conf/eth0/accept_ra", "0");
        // IPv4 first and completely - address, link up, default route - so
        // that nothing on the IPv6 side can cost the zone its path. The
        // target kernel's first boot delivered a routed zone with an
        // interface and no routes (R-13): one failure in this sequence lost
        // every step after it, the IPv4 route included, and left the zone a
        // device it could not use.
        netlink::add_addr4("eth0", netlink::zone_v4(k), 24)?;
        netlink::set_up("eth0")?;
        netlink::add_default_route4(netlink::BRIDGE_V4, "eth0")?;
        // ping without CAP_NET_RAW: unprivileged ICMP echo sockets for every
        // group. A routed zone cannot keep CAP_NET_RAW, so this is the only
        // way it gets to ping, and it cannot forge anything with it.
        let _ = sysctl("/proc/sys/net/ipv4/ping_group_range", "0 65534");
        Ok(())
    })
    .map_err(|e| io("address the zone's eth0", e))?;
    // IPv6 is additive. A kernel or sysctl profile that disables it (a
    // hardened image may well set disable_ipv6) refuses the address with
    // EACCES; the zone then has IPv4 only - less connectivity, not less
    // isolation - and that is reported rather than fatal.
    if let Err(e) = netlink::with_netns(zone_ns, || {
        netlink::add_addr6("eth0", netlink::zone_v6(k), 64)?;
        netlink::add_default_route6(netlink::BRIDGE_V6, "eth0")
    }) {
        eprintln!("kryptikd: zone {name:?}: IPv6 on eth0 not configured ({e}); IPv4 is");
    }
    Ok(())
}

/// pid 1 of the running nic zone.
///
/// WHICH zone is the nic zone comes from the zone directory - the operator's
/// files, root-owned, the same source `run` itself trusts - never from what
/// a namespace happens to contain. An earlier draft recognised the nic zone
/// by finding a bridge called kryptik0 in its namespace; a routed zone whose
/// policy keeps CAP_NET_ADMIN could have created one and been chosen as the
/// gateway for every zone started after it. The registry says who is
/// running; the zone file says who is allowed to be the gateway.
fn running_nic_zone_init(zones_dir: &Path) -> Result<libc::pid_t, NetError> {
    for name in registry::names() {
        let file = zones_dir.join(format!("{name}.toml"));
        let Ok(z) = Zone::from_file(&file) else { continue };
        if z.network != NetworkMode::Nic {
            continue;
        }
        if let Ok(registry::State::Running { init: Some(st), .. }) = registry::state(&name) {
            if st.still_alive() {
                return Ok(st.pid);
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
            "network    nic: {} moves into this zone; bridge {} 10.19.0.1/24 fd19::1/64",
            zone.nic.as_deref().unwrap_or("?"),
            BRIDGE
        ),
        (NetworkMode::Routed, true) => match host_number(zone) {
            Some(k) => format!(
                "network    routed: eth0 = 10.19.0.{k}/24 fd19::{k:x}/64 via the nic zone's {BRIDGE}, \
                 isolated port {}; forwarded without NAT (reaches the world only behind a \
                 gateway that accepts any source, e.g. QEMU user networking)",
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
        let bridge = if mode == "nic" { "bridge = \"kryptik0\"\n" } else { "" };
        let nicl = nic.map(|n| format!("nic = \"{n}\"\n")).unwrap_or_default();
        Zone::from_str(&format!(
            "[zone]\nname = \"t\"\n[network]\nmode = \"{mode}\"\n{bridge}{nicl}\
             [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n{ident}[ui]\nborder_color = \"#123456\"\n"
        ))
        .unwrap()
    }

    #[test]
    fn host_numbers_follow_the_declared_identity() {
        assert_eq!(host_number(&z("routed", Some(131072), None)), Some(2));
        assert_eq!(host_number(&z("routed", Some(196608), None)), Some(3));
        assert_eq!(host_number(&z("routed", Some(458752), None)), Some(7));
        assert_eq!(host_number(&z("routed", None, None)), None);
        // 248 zones fit; the 249th would collide with the bridge's reserved end.
        assert_eq!(host_number(&z("routed", Some(131072 + 247 * 65536), None)), Some(249));
        assert_eq!(host_number(&z("routed", Some(131072 + 248 * 65536), None)), None);
    }

    #[test]
    fn port_names_fit_ifnamsiz() {
        assert_eq!(port_name("untrusted"), "kv-untrusted");
        assert!(port_name("twelvecharsx").len() <= 15);
    }

    #[test]
    fn the_plan_is_honest_about_what_happens() {
        assert!(plan(&z("none", None, None), true).contains("nothing created"));
        assert!(plan(&z("routed", Some(131072), None), false).contains("unprivileged"));
        assert!(plan(&z("routed", Some(131072), None), true).contains("10.19.0.2/24"));
        assert!(plan(&z("routed", None, None), true).contains("needs [identity]"));
        assert!(plan(&z("nic", None, Some("eth0")), true).contains("eth0 moves"));
    }

    /// A fresh namespace holds exactly what `fallback_tunnels_expected`
    /// predicts from the sysctl and the initial namespace: nothing on a host
    /// without the tunnel modules, the fallback devices on one with them and
    /// the sysctl at 0. Kernel-backed; the predictor is what the launcher
    /// acts on before the zone's namespace exists.
    #[test]
    fn a_fresh_namespace_holds_exactly_what_the_predictor_says() {
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

    /// R-13: the target kernel's first boot delivered a routed zone with an
    /// interface and no routes. Whatever fails on the IPv6 side must not cost
    /// the zone its IPv4 path. Kernel-backed: this namespace plays the nic
    /// zone (bridge and all), a holder plays the zone with IPv6 disabled the
    /// way a hardened sysctl profile would, and the zone end must still come
    /// out addressed, up and routed - counted the way the suite counts it.
    #[test]
    fn ipv4_survives_a_zone_whose_ipv6_is_disabled() {
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
                attach_routed("t", 7, nic_ns, zone_ns).map_err(|e| {
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
                // The premise: IPv6 really was refused, so the IPv4 path
                // above was built in spite of a failure, not beside a success.
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

    /// Moving an interface between namespaces flushes what was configured on
    /// it. Kernel-backed: a veth end plays the uplink with the configuration
    /// DHCP leaves (address, prefix, default gateway); after `carry_nic` it
    /// is gone from here and up, addressed and routed inside the holder's
    /// namespace, read back through the same code the launcher uses.
    #[test]
    fn the_uplink_configuration_travels_with_the_nic() {
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
                // Gone from here...
                if netlink::is_up("up0").is_ok() {
                    return Err(10);
                }
                // ...and present, up and configured there.
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
    fn the_gateway_is_chosen_from_the_zone_directory_not_from_a_namespace() {
        // No running nic zone in this (empty) zone directory: the lookup must
        // say so rather than pick any running zone.
        let dir = std::env::temp_dir().join(format!("kryptik-nz-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let e = running_nic_zone_init(&dir).unwrap_err();
        assert!(matches!(e, NetError::NoNetZone));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unknown_nic_is_refused_before_anything_moves() {
        // Needs no privilege: the check happens before any netlink call.
        let dir = std::env::temp_dir();
        let e = plumb_nic_zone(&z("nic", None, Some("nosuchnic99")), -1, &dir).unwrap_err();
        assert!(e.to_string().contains("not an interface"), "{e}");
    }

    #[test]
    fn replumb_with_no_routed_zones_in_the_directory_attempts_nothing() {
        let dir = std::env::temp_dir().join(format!("kryptik-rp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(replumb_routed_zones(&dir, -1).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
