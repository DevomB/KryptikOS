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
