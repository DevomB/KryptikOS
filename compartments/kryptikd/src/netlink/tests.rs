use super::*;
use std::fs;

/// Run `body` in a forked child in a fresh user and network namespace.
/// Returns its exit code, or 77 when no user namespace could be created.
pub(crate) fn in_userns_netns(body: impl FnOnce() -> i32) -> i32 {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWNS) } < 0 {
            unsafe { libc::_exit(77) };
        }
        if fs::write("/proc/self/setgroups", "deny").is_err()
            || fs::write("/proc/self/uid_map", format!("0 {uid} 1\n")).is_err()
            || fs::write("/proc/self/gid_map", format!("0 {gid} 1\n")).is_err()
        {
            unsafe { libc::_exit(77) };
        }
        // A fresh sysfs shows this namespace's interfaces, not the host's.
        unsafe {
            let none = CString::new("none").unwrap();
            let root = CString::new("/").unwrap();
            let sysfs = CString::new("sysfs").unwrap();
            let sys = CString::new("/sys").unwrap();
            if libc::mount(none.as_ptr(), root.as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) < 0
                || libc::mount(sysfs.as_ptr(), sys.as_ptr(), sysfs.as_ptr(), 0, std::ptr::null()) < 0
            {
                libc::_exit(77);
            }
        }
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
    if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { 200 + libc::WTERMSIG(status) }
}

pub(crate) fn step(n: i32, r: io::Result<()>) -> Result<(), i32> {
    r.map_err(|e| {
        eprintln!("step {n}: {e}");
        n
    })
}

/// First wireless netdev whose device belongs to mac80211_hwsim, if any.
fn hwsim_netdev() -> Option<String> {
    let mut found = Vec::new();
    for e in fs::read_dir("/sys/class/net").ok()?.flatten() {
        let p = e.path();
        if !p.join("phy80211").exists() {
            continue;
        }
        let dev = fs::read_link(p.join("device")).unwrap_or_default();
        if dev.to_string_lossy().contains("mac80211_hwsim") {
            found.push(e.file_name().to_string_lossy().into_owned());
        }
    }
    found.sort();
    found.into_iter().next()
}

/// Root and mac80211_hwsim only. The netdev alone gets EINVAL; the wiphy
/// move carries it, same name, into the holder, and cfg80211 returns it
/// to the initial namespace when the holder dies.
#[test]
fn wireless_moves_by_wiphy() {
    use std::process::Command;
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("not root; skipping (the wiphy move needs CAP_NET_ADMIN in the initial namespace)");
        return;
    }
    let loaded_before = std::path::Path::new("/sys/module/mac80211_hwsim").exists();
    let modprobe = Command::new("modprobe").args(["mac80211_hwsim", "radios=1"]).status();
    if !modprobe.map(|s| s.success()).unwrap_or(false) {
        eprintln!("mac80211_hwsim not available on this kernel; skipping");
        return;
    }
    let unload = || {
        if !loaded_before {
            let _ = Command::new("modprobe").args(["-r", "mac80211_hwsim"]).status();
        }
    };
    let Some(dev) = hwsim_netdev() else {
        unload();
        panic!("mac80211_hwsim loaded but no wireless netdev of its own appeared");
    };
    let phy = match wiphy_index_of(&dev) {
        Ok(Some(p)) => p,
        other => {
            unload();
            panic!("{dev}: no wiphy index ({other:?})");
        }
    };
    // The netdev alone must refuse: that refusal is why the wiphy path exists.
    let (holder, zone_ns) = match spawn_netns_holder() {
        Ok(v) => v,
        Err(c) => {
            unload();
            panic!("no namespace holder ({c})");
        }
    };
    let r: Result<(), String> = (|| {
        match set_netns(&dev, zone_ns) {
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {}
            Err(e) => return Err(format!("RTM_SETLINK on {dev}: expected EINVAL, got {e}")),
            Ok(()) => return Err(format!("RTM_SETLINK moved wireless {dev} on its own; the premise is gone")),
        }
        set_wiphy_netns(phy, zone_ns).map_err(|e| format!("set_wiphy_netns: {e}"))?;
        if index_of(&dev).is_ok() {
            return Err(format!("{dev} is still in this namespace after the wiphy move"));
        }
        let there = with_netns(zone_ns, || index_of(&dev)).map_err(|e| format!("inside the holder: {e}"))?;
        if there == 0 {
            return Err(format!("{dev} has no index inside the holder"));
        }
        Ok(())
    })();
    unsafe {
        libc::kill(holder, libc::SIGKILL);
        let mut st = 0;
        libc::waitpid(holder, &mut st, 0);
        libc::close(zone_ns);
    }
    // Namespace teardown runs on a workqueue; give the wiphy 5 s to return.
    let mut back = false;
    for _ in 0..50 {
        if index_of(&dev).is_ok() {
            back = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    unload();
    if let Err(e) = r {
        panic!("{e}");
    }
    assert!(back, "{dev} did not return to the initial namespace after its holder died");
}

#[test]
fn message_layout_matches_kernel() {
    /* ifinfomsg is 16 bytes, attributes are 4-aligned, a nested length
     * covers its payload, and the header length is the total. */
    let mut m = Msg::new(RTM_NEWLINK, NLM_F_CREATE, 7);
    m.ifinfomsg(0, 0, 0, 0);
    m.attr_str(IFLA_IFNAME, "ab"); // 4 + 3 = 7 -> padded to 8
    let li = m.begin_nested(IFLA_LINKINFO);
    m.attr_str(IFLA_INFO_KIND, "veth"); // 4 + 5 = 9 -> 12
    m.end_nested(li);
    let b = m.finish();
    assert_eq!(b.len(), 16 + 16 + 8 + (4 + 12));
    assert_eq!(u32::from_ne_bytes(b[0..4].try_into().unwrap()) as usize, b.len());
    assert_eq!(u16::from_ne_bytes(b[4..6].try_into().unwrap()), RTM_NEWLINK);
    assert_eq!(u16::from_ne_bytes(b[6..8].try_into().unwrap()), NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE);
    // IFLA_IFNAME attr: len 7, type 3
    assert_eq!(u16::from_ne_bytes(b[32..34].try_into().unwrap()), 7);
    assert_eq!(u16::from_ne_bytes(b[34..36].try_into().unwrap()), IFLA_IFNAME);
    // nested LINKINFO: len 16, type 18 | NESTED
    assert_eq!(u16::from_ne_bytes(b[40..42].try_into().unwrap()), 16);
    assert_eq!(u16::from_ne_bytes(b[42..44].try_into().unwrap()), IFLA_LINKINFO | NLA_F_NESTED);
    assert_eq!(&b[48..53], b"veth\0");
}

#[test]
fn address_plan_is_fixed() {
    assert_eq!(zone_v4(2), [10, 19, 0, 2]);
    assert_eq!(zone_v6(2)[15], 2);
    assert_eq!(&zone_v6(2)[..2], &[0xfd, 0x19]);
    assert!(check_name("kv-untrusted").is_ok());
    assert!(check_name("kv-averylongzonename").is_err());
    assert!(check_name("a/b").is_err());
}

/// Fork a child that unshares a network namespace and waits to be killed.
/// Returns (pid, netns fd); the caller's user namespace owns the namespace.
pub(crate) fn spawn_netns_holder() -> Result<(libc::pid_t, RawFd), i32> {
    let mut p = [0 as RawFd; 2];
    if unsafe { libc::pipe(p.as_mut_ptr()) } < 0 {
        return Err(60);
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(61);
    }
    if pid == 0 {
        unsafe {
            libc::close(p[0]);
            // Die with the parent: an orphaned holder keeps cargo's output pipe open.
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            if libc::getppid() == 1 {
                libc::_exit(1);
            }
            if libc::unshare(libc::CLONE_NEWNET) < 0 {
                libc::_exit(1);
            }
            let b = [1u8];
            libc::write(p[1], b.as_ptr() as *const libc::c_void, 1);
            libc::close(p[1]);
            loop {
                libc::pause();
            }
        }
    }
    unsafe { libc::close(p[1]) };
    let mut b = [0u8];
    let n = unsafe { libc::read(p[0], b.as_mut_ptr() as *mut libc::c_void, 1) };
    unsafe { libc::close(p[0]) };
    if n != 1 {
        return Err(62);
    }
    let fd = open_netns_of(pid).map_err(|_| 63)?;
    Ok((pid, fd))
}

fn sockaddr(addr: [u8; 4], port: u16) -> libc::sockaddr_in {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_port = port.to_be();
    sa.sin_addr = libc::in_addr { s_addr: u32::from_ne_bytes(addr) };
    sa
}

/// A UDP socket in `ns`, bound to `bind` if given, with a 300 ms receive timeout.
fn udp_in(ns: RawFd, bind: Option<([u8; 4], u16)>) -> Result<RawFd, i32> {
    with_netns(ns, || {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        if let Some((a, port)) = bind {
            let sa = sockaddr(a, port);
            if unsafe { libc::bind(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as u32) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let tv = libc::timeval { tv_sec: 0, tv_usec: 300_000 };
        unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as u32)
        };
        Ok(fd)
    })
    .map_err(|e| {
        eprintln!("udp_in: {e}");
        64
    })
}

fn udp_send(fd: RawFd, to: [u8; 4], port: u16) {
    let sa = sockaddr(to, port);
    let msg = b"kryptik";
    unsafe {
        libc::sendto(fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as u32)
    };
}

fn udp_received(fd: RawFd) -> bool {
    let mut b = [0u8; 16];
    unsafe { libc::recv(fd, b.as_mut_ptr() as *mut libc::c_void, b.len(), 0) > 0 }
}

/// Veth, addresses, bridge, port and routes in a private namespace, plus
/// two refusals (duplicate address and name) that show requests are acked.
#[test]
fn veth_bridge_addresses_routes() {
    let rc = in_userns_netns(|| {
        let r: Result<(), i32> = (|| {
            step(1, create_veth("va", "vb", None))?;
            if index_of("va").is_err() || index_of("vb").is_err() {
                return Err(2);
            }
            step(3, set_up("va"))?;
            step(4, set_up("vb"))?;
            if !is_up("va").unwrap_or(false) {
                return Err(5);
            }
            step(6, add_addr4("va", [10, 99, 0, 1], 24))?;
            step(7, add_addr6("va", zone_v6(1), 64))?;
            if add_addr4("va", [10, 99, 0, 1], 24).is_ok() {
                return Err(9); // EXCL: a duplicate address is refused
            }
            step(10, create_bridge("br0"))?;
            step(11, set_up("br0"))?;
            step(12, set_master("vb", "br0"))?;
            step(13, set_port_isolated("vb", true))?;
            step(14, add_addr4("br0", [10, 99, 0, 2], 24))?;
            step(18, add_default_route4([10, 99, 0, 2], "va"))?;
            step(19, add_default_route6(zone_v6(2), "va"))?;
            if create_veth("va", "vx", None).is_ok() {
                return Err(20); // EXCL: a duplicate name is refused
            }
            Ok(())
        })();
        match r {
            Ok(()) => 0,
            Err(code) => code,
        }
    });
    match rc {
        0 => {}
        77 => eprintln!("no unprivileged user namespace; skipping"),
        other => panic!("kernel-backed netlink test failed at step {other}"),
    }
}

#[test]
fn veth_peer_in_other_namespace() {
    let rc = in_userns_netns(|| {
        let (gc, ns) = match spawn_netns_holder() {
            Ok(v) => v,
            Err(c) => return c,
        };
        let r = create_veth("kv-t", "eth0", Some(ns));
        if let Err(e) = r {
            eprintln!("create_veth into peer ns: {e}");
            unsafe { libc::kill(gc, libc::SIGKILL) };
            return 34;
        }
        if index_of("kv-t").is_err() {
            return 35;
        }
        if index_of("eth0").is_ok() {
            return 36;
        }
        let there = with_netns(ns, || index_of("eth0").map(|_| ())).is_ok();
        unsafe { libc::kill(gc, libc::SIGKILL) };
        if there { 0 } else { 38 }
    });
    match rc {
        0 => {}
        77 => eprintln!("no unprivileged user namespace; skipping"),
        other => panic!("peer-namespace veth test failed with code {other}"),
    }
}

/// Isolated ports drop zone-to-zone traffic but pass traffic to the bridge
/// address; clearing the flag restores zone-to-zone delivery.
#[test]
fn isolated_ports_block_zone_to_zone() {
    let rc = in_userns_netns(|| {
        let r: Result<(), i32> = (|| {
            let (gc1, ns1) = spawn_netns_holder()?;
            let (gc2, ns2) = spawn_netns_holder()?;
            let _kill = (gc1, gc2);
            step(40, create_bridge("kryptik0"))?;
            step(41, set_up("kryptik0"))?;
            step(42, add_addr4("kryptik0", [10, 99, 0, 254], 24))?;
            for (k, ns) in [(1u8, ns1), (2u8, ns2)] {
                let port = format!("kv-z{k}");
                step(43, create_veth(&port, "eth0", Some(ns)))?;
                step(44, set_master(&port, "kryptik0"))?;
                step(45, set_port_isolated(&port, true))?;
                let flag = fs::read_to_string(format!("/sys/class/net/{port}/brport/isolated")).map_err(|_| 49)?;
                eprintln!("{port}: brport/isolated = {}", flag.trim());
                if flag.trim() != "1" {
                    return Err(49);
                }
                step(46, set_up(&port))?;
                step(47, with_netns(ns, || {
                    set_up("lo")?;
                    set_up("eth0")?;
                    add_addr4("eth0", [10, 99, 0, k], 24)
                }))?;
            }
            // Receiver in zone 2, sender in zone 1, control receiver on the bridge.
            let rx2 = udp_in(ns2, Some(([0, 0, 0, 0], 9999)))?;
            let rx_br = udp_in(open_netns_of(unsafe { libc::getpid() }).map_err(|_| 48)?, Some(([10, 99, 0, 254], 9999)))?;
            let tx1 = udp_in(ns1, None)?;

            // Isolated: the bridge drops zone 1 -> zone 2.
            udp_send(tx1, [10, 99, 0, 2], 9999);
            let got = udp_received(rx2);
            eprintln!("isolated: zone1 -> zone2 delivered = {got}");
            if got {
                return Err(50);
            }
            // Control: zone 1 -> the bridge address is delivered.
            udp_send(tx1, [10, 99, 0, 254], 9999);
            if !udp_received(rx_br) {
                return Err(51);
            }
            step(52, set_port_isolated("kv-z1", false))?;
            step(53, set_port_isolated("kv-z2", false))?;
            /* The unanswered ARP request left the neighbour entry in
             * retransmit backoff (about 1 s); keep sending for up to 3 s. */
            let mut delivered = false;
            for _ in 0..10 {
                udp_send(tx1, [10, 99, 0, 2], 9999);
                if udp_received(rx2) {
                    delivered = true;
                    break;
                }
            }
            eprintln!("not isolated: zone1 -> zone2 delivered = {delivered}");
            if !delivered {
                return Err(54);
            }
            unsafe {
                libc::kill(gc1, libc::SIGKILL);
                libc::kill(gc2, libc::SIGKILL);
            }
            Ok(())
        })();
        match r {
            Ok(()) => 0,
            Err(code) => code,
        }
    });
    match rc {
        0 => {}
        77 => eprintln!("no unprivileged user namespace; skipping"),
        other => panic!("bridge isolation test failed at step {other}"),
    }
}
