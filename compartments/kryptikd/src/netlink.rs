//! Minimal rtnetlink client for the zone topology (docs/design/net-zone.md).
//!
//! Built here because kryptikd depends on `libc` alone (ADR-010) and busybox
//! `ip` cannot create a veth peer in another namespace or set bridge port
//! flags. A netlink socket belongs to the namespace it was opened in, so each
//! request opens its own, and none succeeds until the kernel acks it.

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;

const NETLINK_ROUTE: libc::c_int = 0;
const NETLINK_GENERIC: libc::c_int = 16;

// From <linux/genetlink.h> and <linux/nl80211.h>.
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const NL80211_CMD_SET_WIPHY_NETNS: u8 = 49;
const NL80211_ATTR_WIPHY: u16 = 1;
const NL80211_ATTR_NETNS_FD: u16 = 219;
const NLA_TYPE_MASK: u16 = 0x3fff;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_SETLINK: u16 = 19;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLA_F_NESTED: u16 = 0x8000;

const IFLA_IFNAME: u16 = 3;
const IFLA_MASTER: u16 = 10;
/* A bridge setlink acks an unknown attribute and ignores it, so a wrong
 * number here fails silently: the isolation test checks sysfs and the wire. */
const IFLA_PROTINFO: u16 = 12;
const IFLA_LINKINFO: u16 = 18;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;
const IFLA_BRPORT_ISOLATED: u16 = 33;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;

const AF_BRIDGE: u8 = 7;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// A netlink message under construction: header, fixed struct, attributes.
struct Msg {
    buf: Vec<u8>,
}

impl Msg {
    fn new(msg_type: u16, flags: u16, seq: u32) -> Msg {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&0u32.to_ne_bytes()); // len, patched in finish()
        buf.extend_from_slice(&msg_type.to_ne_bytes());
        buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK | flags).to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // pid: kernel fills
        Msg { buf }
    }

    fn raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        while self.buf.len() % 4 != 0 {
            self.buf.push(0);
        }
    }

    /// struct ifinfomsg { u8 family; u8 pad; u16 type; i32 index; u32 flags; u32 change }
    fn ifinfomsg(&mut self, family: u8, index: i32, flags: u32, change: u32) {
        let mut b = Vec::with_capacity(16);
        b.push(family);
        b.push(0);
        b.extend_from_slice(&0u16.to_ne_bytes());
        b.extend_from_slice(&index.to_ne_bytes());
        b.extend_from_slice(&flags.to_ne_bytes());
        b.extend_from_slice(&change.to_ne_bytes());
        self.raw(&b);
    }

    /// struct ifaddrmsg { u8 family; u8 prefixlen; u8 flags; u8 scope; u32 index }
    fn ifaddrmsg(&mut self, family: u8, prefixlen: u8, index: u32) {
        let mut b = vec![family, prefixlen, 0, 0];
        b.extend_from_slice(&index.to_ne_bytes());
        self.raw(&b);
    }

    /// struct genlmsghdr { u8 cmd; u8 version; u16 reserved }
    fn genlmsghdr(&mut self, cmd: u8, version: u8) {
        self.raw(&[cmd, version, 0, 0]);
    }

    /// struct rtmsg { u8 family, dst_len, src_len, tos, table, protocol, scope, type; u32 flags }
    fn rtmsg(&mut self, family: u8) {
        let b = [family, 0, 0, 0, RT_TABLE_MAIN, RTPROT_BOOT, RT_SCOPE_UNIVERSE, RTN_UNICAST, 0, 0, 0, 0];
        self.raw(&b);
    }

    fn attr(&mut self, kind: u16, data: &[u8]) {
        let len = (4 + data.len()) as u16;
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.raw(data);
    }

    fn attr_str(&mut self, kind: u16, s: &str) {
        let mut d = s.as_bytes().to_vec();
        d.push(0);
        self.attr(kind, &d);
    }

    fn attr_u32(&mut self, kind: u16, v: u32) {
        self.attr(kind, &v.to_ne_bytes());
    }

    /// Begin a nested attribute; returns the offset to pass to `end_nested`.
    fn begin_nested(&mut self, kind: u16) -> usize {
        let start = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_ne_bytes());
        self.buf.extend_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
        start
    }

    fn end_nested(&mut self, start: usize) {
        let len = (self.buf.len() - start) as u16;
        self.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
    }

    fn finish(mut self) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

/// Most reply payload one request may gather; real replies are a few hundred bytes.
const MAX_REPLY: usize = 64 * 1024;

/// One request/ack exchange on a fresh NETLINK_ROUTE socket.
fn transact(msg: Vec<u8>, what: &str) -> io::Result<()> {
    transact_on(NETLINK_ROUTE, msg, what).map(|_| ())
}

/// One request on a fresh socket of protocol `proto`, read until the ack or
/// DONE. Returns the payloads of the replies before it, without their headers.
fn transact_on(proto: libc::c_int, msg: Vec<u8>, what: &str) -> io::Result<Vec<u8>> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, proto) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        /* Connect to port 0 so only the kernel can reply. Unconnected, anything
         * with CAP_NET_ADMIN in this namespace could, and the nic zone has it. */
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let rc = unsafe {
            libc::connect(
                fd,
                &kernel as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let sent = unsafe { libc::send(fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = [0u8; 8192];
        let mut replies = Vec::new();
        loop {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(e);
            }
            let n = n as usize;
            let mut off = 0;
            while off + 16 <= n {
                let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
                let ty = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
                if len < 16 || off + len > n {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated netlink reply"));
                }
                match ty {
                    NLMSG_ERROR => {
                        if len < 20 {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, "netlink error without a code"));
                        }
                        let code = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap());
                        return if code == 0 {
                            Ok(replies)
                        } else {
                            Err(io::Error::new(
                                io::Error::from_raw_os_error(-code).kind(),
                                format!("{what}: {}", io::Error::from_raw_os_error(-code)),
                            ))
                        };
                    }
                    NLMSG_DONE => return Ok(replies),
                    _ if replies.len() + len > MAX_REPLY => {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "netlink reply too large"));
                    }
                    _ => replies.extend_from_slice(&buf[off + 16..off + len]),
                }
                off += align4(len);
            }
        }
    })();
    unsafe { libc::close(fd) };
    result
}

fn index_of(dev: &str) -> io::Result<u32> {
    let c = CString::new(dev).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in name"))?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("no such interface: {dev}")));
    }
    Ok(idx)
}

fn check_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name.len() > 15 || name.contains('/') || name.contains(char::is_whitespace) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("bad interface name {name:?}")));
    }
    Ok(())
}

/// Create a veth pair `a` <-> `b`. When `peer_ns` is given, `b` is created in
/// that network namespace and never appears in this one.
pub fn create_veth(a: &str, b: &str, peer_ns: Option<RawFd>) -> io::Result<()> {
    check_name(a)?;
    check_name(b)?;
    let mut m = Msg::new(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, 1);
    m.ifinfomsg(libc::AF_UNSPEC as u8, 0, 0, 0);
    m.attr_str(IFLA_IFNAME, a);
    let li = m.begin_nested(IFLA_LINKINFO);
    m.attr_str(IFLA_INFO_KIND, "veth");
    let data = m.begin_nested(IFLA_INFO_DATA);
    let peer = m.begin_nested(VETH_INFO_PEER);
    m.ifinfomsg(libc::AF_UNSPEC as u8, 0, 0, 0);
    m.attr_str(IFLA_IFNAME, b);
    if let Some(fd) = peer_ns {
        m.attr_u32(IFLA_NET_NS_FD, fd as u32);
    }
    m.end_nested(peer);
    m.end_nested(data);
    m.end_nested(li);
    transact(m.finish(), &format!("create veth {a}/{b}"))
}

pub fn create_bridge(name: &str) -> io::Result<()> {
    check_name(name)?;
    let mut m = Msg::new(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, 1);
    m.ifinfomsg(libc::AF_UNSPEC as u8, 0, 0, 0);
    m.attr_str(IFLA_IFNAME, name);
    let li = m.begin_nested(IFLA_LINKINFO);
    m.attr_str(IFLA_INFO_KIND, "bridge");
    m.end_nested(li);
    transact(m.finish(), &format!("create bridge {name}"))
}

/// Enslave `dev` to bridge `master`.
pub fn set_master(dev: &str, master: &str) -> io::Result<()> {
    let idx = index_of(dev)?;
    let midx = index_of(master)?;
    let mut m = Msg::new(RTM_NEWLINK, 0, 1);
    m.ifinfomsg(libc::AF_UNSPEC as u8, idx as i32, 0, 0);
    m.attr_u32(IFLA_MASTER, midx);
    transact(m.finish(), &format!("enslave {dev} to {master}"))
}

/// Set a bridge port's isolation flag. Isolated ports never exchange frames
/// with each other, and a zone cannot clear the flag from its end of the veth.
pub fn set_port_isolated(dev: &str, on: bool) -> io::Result<()> {
    let idx = index_of(dev)?;
    let mut m = Msg::new(RTM_SETLINK, 0, 1);
    m.ifinfomsg(AF_BRIDGE, idx as i32, 0, 0);
    let pi = m.begin_nested(IFLA_PROTINFO);
    m.attr(IFLA_BRPORT_ISOLATED, &[u8::from(on)]);
    m.end_nested(pi);
    transact(m.finish(), &format!("set isolation of bridge port {dev} to {on}"))
}

/// Delete `dev`. Deleting either end of a veth pair deletes both.
pub fn delete_link(dev: &str) -> io::Result<()> {
    let idx = index_of(dev)?;
    let mut m = Msg::new(RTM_DELLINK, 0, 1);
    m.ifinfomsg(libc::AF_UNSPEC as u8, idx as i32, 0, 0);
    transact(m.finish(), &format!("delete {dev}"))
}

pub fn set_up(dev: &str) -> io::Result<()> {
    let idx = index_of(dev)?;
    let mut m = Msg::new(RTM_NEWLINK, 0, 1);
    m.ifinfomsg(libc::AF_UNSPEC as u8, idx as i32, libc::IFF_UP as u32, libc::IFF_UP as u32);
    transact(m.finish(), &format!("bring up {dev}"))
}

/// Move `dev` into the namespace behind `ns_fd`. A wireless netdev is
/// namespace-local and gets EINVAL; move its wiphy with `set_wiphy_netns`.
pub fn set_netns(dev: &str, ns_fd: RawFd) -> io::Result<()> {
    let idx = index_of(dev)?;
    let mut m = Msg::new(RTM_NEWLINK, 0, 1);
    m.ifinfomsg(libc::AF_UNSPEC as u8, idx as i32, 0, 0);
    m.attr_u32(IFLA_NET_NS_FD, ns_fd as u32);
    transact(m.finish(), &format!("move {dev} into namespace"))
}

/// Wiphy index of a wireless interface (sysfs `phy80211/index`); None if wired.
pub fn wiphy_index_of(dev: &str) -> io::Result<Option<u32>> {
    check_name(dev)?;
    match std::fs::read_to_string(format!("/sys/class/net/{dev}/phy80211/index")) {
        Ok(s) => s
            .trim()
            .parse::<u32>()
            .map(Some)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("{dev}: phy80211/index is not a number: {s:?}"))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Id of a generic-netlink family, asked of the controller: only names are fixed.
fn genl_family_id(name: &str) -> io::Result<u16> {
    let mut m = Msg::new(GENL_ID_CTRL, 0, 1);
    m.genlmsghdr(CTRL_CMD_GETFAMILY, 1);
    m.attr_str(CTRL_ATTR_FAMILY_NAME, name);
    let reply = transact_on(NETLINK_GENERIC, m.finish(), &format!("look up the {name} family"))?;
    // Skip the genlmsghdr; the family id is a u16 attribute.
    let mut off = 4;
    while off + 4 <= reply.len() {
        let len = u16::from_ne_bytes(reply[off..off + 2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(reply[off + 2..off + 4].try_into().unwrap()) & NLA_TYPE_MASK;
        if len < 4 || off + len > reply.len() {
            break;
        }
        if kind == CTRL_ATTR_FAMILY_ID && len >= 6 {
            return Ok(u16::from_ne_bytes(reply[off + 4..off + 6].try_into().unwrap()));
        }
        off += align4(len);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("the kernel has no {name} generic-netlink family (no wireless stack?)"),
    ))
}

/// Move a wiphy and its interfaces, names intact, into the namespace behind
/// `ns_fd` (`iw phy <phy> set netns`). Needs CAP_NET_ADMIN where it is now.
pub fn set_wiphy_netns(phy: u32, ns_fd: RawFd) -> io::Result<()> {
    let family = genl_family_id("nl80211")?;
    let mut m = Msg::new(family, 0, 1);
    m.genlmsghdr(NL80211_CMD_SET_WIPHY_NETNS, 0);
    m.attr_u32(NL80211_ATTR_WIPHY, phy);
    m.attr_u32(NL80211_ATTR_NETNS_FD, ns_fd as u32);
    transact_on(NETLINK_GENERIC, m.finish(), &format!("move wiphy {phy} into namespace")).map(|_| ())
}

pub fn add_addr4(dev: &str, addr: [u8; 4], prefix: u8) -> io::Result<()> {
    let idx = index_of(dev)?;
    let mut m = Msg::new(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, 1);
    m.ifaddrmsg(libc::AF_INET as u8, prefix, idx);
    m.attr(IFA_LOCAL, &addr);
    m.attr(IFA_ADDRESS, &addr);
    transact(m.finish(), &format!("add {} /{prefix} to {dev}", fmt4(addr)))
}

pub fn add_addr6(dev: &str, addr: [u8; 16], prefix: u8) -> io::Result<()> {
    let idx = index_of(dev)?;
    let mut m = Msg::new(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, 1);
    m.ifaddrmsg(libc::AF_INET6 as u8, prefix, idx);
    m.attr(IFA_ADDRESS, &addr);
    transact(m.finish(), &format!("add v6 /{prefix} to {dev}"))
}

pub fn add_default_route4(gw: [u8; 4], dev: &str) -> io::Result<()> {
    let idx = index_of(dev)?;
    let mut m = Msg::new(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, 1);
    m.rtmsg(libc::AF_INET as u8);
    m.attr(RTA_GATEWAY, &gw);
    m.attr_u32(RTA_OIF, idx);
    transact(m.finish(), &format!("default route via {} dev {dev}", fmt4(gw)))
}

pub fn add_default_route6(gw: [u8; 16], dev: &str) -> io::Result<()> {
    let idx = index_of(dev)?;
    let mut m = Msg::new(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, 1);
    m.rtmsg(libc::AF_INET6 as u8);
    m.attr(RTA_GATEWAY, &gw);
    m.attr_u32(RTA_OIF, idx);
    transact(m.finish(), &format!("default v6 route dev {dev}"))
}

fn fmt4(a: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

/// Is `dev` administratively up?
#[cfg(test)]
pub fn is_up(dev: &str) -> io::Result<bool> {
    let c = CString::new(dev).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL"))?;
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in c.as_bytes_with_nul().iter().take(libc::IFNAMSIZ).enumerate() {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    let r = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) };
    let e = io::Error::last_os_error();
    unsafe { libc::close(sock) };
    if r < 0 {
        return Err(e);
    }
    let flags = unsafe { ifr.ifr_ifru.ifru_flags } as i32;
    Ok(flags & libc::IFF_UP != 0)
}

/// Open a handle on a process's network namespace.
pub fn open_netns_of(pid: libc::pid_t) -> io::Result<RawFd> {
    let p = CString::new(format!("/proc/{pid}/ns/net")).unwrap();
    let fd = unsafe { libc::open(p.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Run `f` inside the network namespace behind `ns_fd`, then switch back.
/// Needs CAP_SYS_ADMIN over both namespaces; setns moves only this thread.
pub fn with_netns<T>(ns_fd: RawFd, f: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    let mine = open_netns_of(unsafe { libc::getpid() })?;
    if unsafe { libc::setns(ns_fd, libc::CLONE_NEWNET) } < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(mine) };
        return Err(io::Error::new(e.kind(), format!("setns(net): {e}")));
    }
    let result = f();
    let back = unsafe { libc::setns(mine, libc::CLONE_NEWNET) };
    let back_err = io::Error::last_os_error();
    unsafe { libc::close(mine) };
    if back < 0 {
        // Being stranded in another namespace outranks any error from `f`.
        return Err(io::Error::new(back_err.kind(), format!("setns back to own netns: {back_err}")));
    }
    result
}

/// Routed-zone address plan (docs/design/net-zone.md): the bridge is
/// 10.19.0.1/24 and fd19::1/64; host number `k` is 10.19.0.k and fd19::k.
pub const BRIDGE_V4: [u8; 4] = [10, 19, 0, 1];
pub const BRIDGE_V6: [u8; 16] = [0xfd, 0x19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

pub fn zone_v4(k: u8) -> [u8; 4] {
    [10, 19, 0, k]
}

pub fn zone_v6(k: u8) -> [u8; 16] {
    let mut a = BRIDGE_V6;
    a[15] = k;
    a
}

#[cfg(test)]
pub(crate) mod tests {
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
}
