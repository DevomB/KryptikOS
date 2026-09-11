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

use std::io;
use std::path::Path;

use crate::netlink;
use crate::registry;
use crate::zone::{NetworkMode, Zone};

pub const BRIDGE: &str = "kryptik0";

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
        netlink::set_netns(n, zone_ns).map_err(|e| io(&format!("move {n} into the nic zone"), e))?;
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
        netlink::add_addr6(BRIDGE, netlink::BRIDGE_V6, 64)?;
        netlink::set_up(BRIDGE)?;
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
        netlink::add_addr4("eth0", netlink::zone_v4(k), 24)?;
        netlink::add_addr6("eth0", netlink::zone_v6(k), 64)?;
        netlink::set_up("eth0")?;
        netlink::add_default_route4(netlink::BRIDGE_V4, "eth0")?;
        netlink::add_default_route6(netlink::BRIDGE_V6, "eth0")?;
        // ping without CAP_NET_RAW: unprivileged ICMP echo sockets for every
        // group. A routed zone cannot keep CAP_NET_RAW, so this is the only
        // way it gets to ping, and it cannot forge anything with it.
        let _ = sysctl("/proc/sys/net/ipv4/ping_group_range", "0 65534");
        Ok(())
    })
    .map_err(|e| io("address the zone's eth0", e))
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
