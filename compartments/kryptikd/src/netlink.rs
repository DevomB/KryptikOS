//! Minimal netlink client for the zone topology (docs/design/net-zone.md): kryptikd uses only
//! `libc` (ADR-010), and busybox `ip` cannot put a veth peer in another namespace or set bridge
//! port flags. A socket belongs to the namespace it was opened in, so each request opens its own.

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
const NL80211_CMD_NEW_INTERFACE: u8 = 7;
const NL80211_CMD_DEL_INTERFACE: u8 = 8;
const NL80211_CMD_SET_WIPHY_NETNS: u8 = 49;
const NL80211_ATTR_WIPHY: u16 = 1;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFNAME: u16 = 4;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_IFTYPE_STATION: u32 = 2;
const NL80211_ATTR_NETNS_FD: u16 = 219;
const NLA_TYPE_MASK: u16 = 0x3fff;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const RTM_SETLINK: u16 = 19;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELLINKPROP: u16 = 109;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLA_F_NESTED: u16 = 0x8000;

const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_MASTER: u16 = 10;
// A bridge acks and ignores an unknown attribute, so the isolation test checks sysfs and the wire.
const IFLA_PROTINFO: u16 = 12;
const IFLA_LINKINFO: u16 = 18;
const IFLA_IFALIAS: u16 = 20;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_PROP_LIST: u16 = 52;
const IFLA_ALT_IFNAME: u16 = 53;
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
        while !self.buf.len().is_multiple_of(4) {
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

/// Cap on the reply payload one request gathers: most are a few hundred bytes, and a link's
/// altnames, up to 64 KiB, are the most any reply here carries.
const MAX_REPLY: usize = 128 * 1024;

/// One request/ack exchange on a fresh NETLINK_ROUTE socket.
fn transact(msg: Vec<u8>, what: &str) -> io::Result<()> {
    transact_on(NETLINK_ROUTE, msg, what).map(|_| ())
}

/// One request on a fresh `proto` socket; returns the reply payloads that precede the ack or DONE.
fn transact_on(proto: libc::c_int, msg: Vec<u8>, what: &str) -> io::Result<Vec<u8>> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, proto) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        // Connect to port 0 so only the kernel can reply, not the nic zone with its CAP_NET_ADMIN.
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
        let mut buf = Vec::new();
        let mut replies = Vec::new();
        loop {
            // Each read sized to its message: a link's altnames alone can reach 64 KiB.
            let need = unsafe { libc::recv(fd, std::ptr::null_mut(), 0, libc::MSG_PEEK | libc::MSG_TRUNC) };
            if need < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(e);
            }
            if need as usize > MAX_REPLY {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "netlink reply too large"));
            }
            buf.resize((need as usize).max(16), 0);
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

/// Rename the interface at `idx`, which must be down, and return its new name: a `%d` in `name`
/// takes the first number free in this namespace.
pub fn rename_index(idx: u32, name: &str) -> io::Result<String> {
    check_name(name)?;
    let mut m = Msg::new(RTM_NEWLINK, 0, 1);
    m.ifinfomsg(libc::AF_UNSPEC as u8, idx as i32, 0, 0);
    m.attr_str(IFLA_IFNAME, name);
    transact(m.finish(), &format!("rename interface {idx} to {name:?}"))?;
    name_of(idx)
}

/// The name of the interface at `idx` in this namespace.
pub fn name_of(idx: u32) -> io::Result<String> {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: if_indextoname writes at most IF_NAMESIZE bytes, its NUL included.
    if unsafe { libc::if_indextoname(idx, buf.as_mut_ptr()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned())
}

/// Create a veth pair `a` <-> `b`, `b` born in namespace `peer_ns` and with MAC `peer_mac` when given.
pub fn create_veth(a: &str, b: &str, peer_ns: Option<RawFd>, peer_mac: Option<[u8; 6]>) -> io::Result<()> {
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
    if let Some(mac) = peer_mac {
        m.attr(IFLA_ADDRESS, &mac);
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

/// Isolated bridge ports never exchange frames, and a zone cannot clear the flag from its end.
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

/// Move `dev` into `ns_fd`'s namespace; a wireless netdev refuses (EINVAL): see `set_wiphy_netns`.
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

/// `iw phy <phy> set netns`: move a wiphy and its interfaces into `ns_fd`'s netns (CAP_NET_ADMIN).
pub fn set_wiphy_netns(phy: u32, ns_fd: RawFd) -> io::Result<()> {
    let family = genl_family_id("nl80211")?;
    let mut m = Msg::new(family, 0, 1);
    m.genlmsghdr(NL80211_CMD_SET_WIPHY_NETNS, 0);
    m.attr_u32(NL80211_ATTR_WIPHY, phy);
    m.attr_u32(NL80211_ATTR_NETNS_FD, ns_fd as u32);
    transact_on(NETLINK_GENERIC, m.finish(), &format!("move wiphy {phy} into namespace")).map(|_| ())
}

/// `iw phy <phy> interface add <name> type managed`: a station netdev on a wiphy, `%d` in
/// `name` taking the first free number.
pub fn new_station(phy: u32, name: &str) -> io::Result<()> {
    check_name(name)?;
    let family = genl_family_id("nl80211")?;
    let mut m = Msg::new(family, 0, 1);
    m.genlmsghdr(NL80211_CMD_NEW_INTERFACE, 0);
    m.attr_u32(NL80211_ATTR_WIPHY, phy);
    m.attr_str(NL80211_ATTR_IFNAME, name);
    m.attr_u32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_STATION);
    transact_on(NETLINK_GENERIC, m.finish(), &format!("add a station to wiphy {phy}")).map(|_| ())
}

/// `iw dev <dev> del`: remove a radio's netdev, by index.
pub fn del_interface(idx: u32) -> io::Result<()> {
    let family = genl_family_id("nl80211")?;
    let mut m = Msg::new(family, 0, 1);
    m.genlmsghdr(NL80211_CMD_DEL_INTERFACE, 0);
    m.attr_u32(NL80211_ATTR_IFINDEX, idx);
    transact_on(NETLINK_GENERIC, m.finish(), &format!("delete wireless interface {idx}")).map(|_| ())
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

/// `dev`'s MAC.
pub fn mac_of(dev: &str) -> io::Result<[u8; 6]> {
    let c = CString::new(dev).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL"))?;
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in c.as_bytes_with_nul().iter().take(libc::IFNAMSIZ).enumerate() {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    let r = unsafe { libc::ioctl(sock, libc::SIOCGIFHWADDR as _, &mut ifr) };
    let e = io::Error::last_os_error();
    unsafe { libc::close(sock) };
    if r < 0 {
        return Err(e);
    }
    let sa = unsafe { ifr.ifr_ifru.ifru_hwaddr };
    let mut mac = [0u8; 6];
    for (m, b) in mac.iter_mut().zip(sa.sa_data.iter()) {
        *m = *b as u8;
    }
    Ok(mac)
}

/// Set `dev`'s address and MTU, which needs it down, and drop its alias.
pub fn set_link(dev: &str, mac: Option<[u8; 6]>, mtu: Option<u32>, drop_alias: bool) -> io::Result<()> {
    let idx = index_of(dev)?;
    let mut m = Msg::new(RTM_NEWLINK, 0, 1);
    m.ifinfomsg(libc::AF_UNSPEC as u8, idx as i32, 0, 0);
    if let Some(a) = mac {
        m.attr(IFLA_ADDRESS, &a);
    }
    if let Some(n) = mtu {
        m.attr_u32(IFLA_MTU, n);
    }
    if drop_alias {
        m.attr(IFLA_IFALIAS, &[]);
    }
    transact(m.finish(), &format!("set the address and MTU of {dev:?}"))
}

/// The (type, data) attributes in `buf` from `off`.
fn attrs(buf: &[u8], mut off: usize) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while off + 4 <= buf.len() {
        let len = u16::from_ne_bytes(buf[off..off + 2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(buf[off + 2..off + 4].try_into().unwrap()) & NLA_TYPE_MASK;
        if len < 4 || off + len > buf.len() {
            break;
        }
        out.push((kind, &buf[off + 4..off + len]));
        off += align4(len);
    }
    out
}

/// `dev`'s altnames, which answer to a lookup as its name does, and whether it has an alias.
pub fn names_left(dev: &str) -> io::Result<(Vec<Vec<u8>>, bool)> {
    let idx = index_of(dev)?;
    let mut m = Msg::new(RTM_GETLINK, 0, 1);
    m.ifinfomsg(libc::AF_UNSPEC as u8, idx as i32, 0, 0);
    let reply = transact_on(NETLINK_ROUTE, m.finish(), &format!("read {dev:?}"))?;
    let (mut alt, mut alias) = (Vec::new(), false);
    // An ifinfomsg, 16 bytes, then the link's attributes.
    for (kind, data) in attrs(&reply, 16) {
        if kind == IFLA_PROP_LIST {
            for (k, name) in attrs(data, 0) {
                if k == IFLA_ALT_IFNAME {
                    alt.push(name.split(|b| *b == 0).next().unwrap_or(name).to_vec());
                }
            }
        } else if kind == IFLA_IFALIAS {
            alias = data.first().is_some_and(|b| *b != 0);
        }
    }
    Ok((alt, alias))
}

/// Remove altnames from `dev`, 64 to a request: a property list's length is 16 bits, and one
/// altname can take 132 bytes of it.
pub fn del_altnames(dev: &str, names: &[Vec<u8>]) -> io::Result<()> {
    let idx = index_of(dev)?;
    for some in names.chunks(64) {
        let mut m = Msg::new(RTM_DELLINKPROP, 0, 1);
        m.ifinfomsg(libc::AF_UNSPEC as u8, idx as i32, 0, 0);
        let list = m.begin_nested(IFLA_PROP_LIST);
        for n in some {
            m.attr(IFLA_ALT_IFNAME, &[n.as_slice(), b"\0"].concat());
        }
        m.end_nested(list);
        transact(m.finish(), &format!("remove the altnames of {dev:?}"))?;
    }
    Ok(())
}

const SIOCETHTOOL: libc::c_ulong = 0x8946;
const ETHTOOL_GWOL: u32 = 5;
const ETHTOOL_SWOL: u32 = 6;
const ETHTOOL_GPERMADDR: u32 = 0x20;

// As linux/ethtool.h lays them out: the kernel reads fields this code never does.
#[allow(dead_code)]
#[repr(C)]
struct WolInfo {
    cmd: u32,
    supported: u32,
    wolopts: u32,
    sopass: [u8; 6],
}

#[allow(dead_code)]
#[repr(C)]
struct PermAddr {
    cmd: u32,
    size: u32,
    data: [u8; 32],
}

/// One `SIOCETHTOOL` request on `dev`, whose answer the kernel writes back into `req`.
fn ethtool<T>(dev: &str, req: &mut T) -> io::Result<()> {
    let c = CString::new(dev).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL"))?;
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in c.as_bytes_with_nul().iter().take(libc::IFNAMSIZ).enumerate() {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    ifr.ifr_ifru.ifru_data = req as *mut T as *mut libc::c_char;
    // SAFETY: the kernel reads and writes `req`, which outlives the call, as the command says.
    let r = unsafe { libc::ioctl(sock, SIOCETHTOOL as _, &mut ifr) };
    let e = io::Error::last_os_error();
    unsafe { libc::close(sock) };
    if r < 0 {
        return Err(e);
    }
    Ok(())
}

/// The address the hardware came with, if its driver gives one.
pub fn perm_mac_of(dev: &str) -> io::Result<Option<[u8; 6]>> {
    let mut p = PermAddr { cmd: ETHTOOL_GPERMADDR, size: 32, data: [0; 32] };
    ethtool(dev, &mut p)?;
    let mac: [u8; 6] = p.data[..6].try_into().unwrap();
    Ok((p.size == 6 && mac != [0; 6]).then_some(mac))
}

/// Turn Wake-on-LAN off; false when it was off already or the driver has none.
pub fn wol_off(dev: &str) -> io::Result<bool> {
    let mut w = WolInfo { cmd: ETHTOOL_GWOL, supported: 0, wolopts: 0, sopass: [0; 6] };
    match ethtool(dev, &mut w) {
        Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => return Ok(false),
        r => r?,
    }
    if w.wolopts == 0 {
        return Ok(false);
    }
    let mut off = WolInfo { cmd: ETHTOOL_SWOL, supported: 0, wolopts: 0, sopass: [0; 6] };
    ethtool(dev, &mut off)?;
    Ok(true)
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

/// Run `f` in `ns_fd`'s netns and switch back (CAP_SYS_ADMIN over both); moves only this thread.
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

/// The bridge is 10.19.0.1/24 and fd19::1/64; zone host `k` is 10.19.0.k and fd19::k.
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

/// Host `k`'s eth0 MAC, 02:19:00:00:00:k; the net zone takes 10.19.0.k and fd19::k only with it.
pub fn zone_mac(k: u8) -> [u8; 6] {
    [0x02, 0x19, 0, 0, 0, k]
}

#[cfg(test)]
pub(crate) mod tests;
