//! A minimal rtnetlink client: the handful of link, address and route
//! operations the zone topology needs (docs/design/03-net-zone-boundary.md).
//!
//! WHY NOT ip(8)
//!
//! kryptikd keeps its dependencies to `libc` (ADR-010), and the images it
//! runs in carry busybox's `ip`, which cannot create veth pairs with a peer
//! in another namespace or set bridge port flags. Shelling out would also put
//! a path lookup and an argv parser between kryptikd and the kernel on the
//! one operation - moving a physical interface - that defines the network
//! boundary. So the messages are built here, in full, and the encoding is
//! checked by tests against the kernel rather than against a mock.
//!
//! WHAT IS HERE
//!
//! - `create_veth(a, b, peer_ns)`: a veth pair, with `b` created DIRECTLY in
//!   another network namespace (IFLA_NET_NS_FD inside VETH_INFO_PEER), so the
//!   zone end never exists, even briefly, where the zone is not.
//! - `create_bridge`, `set_master` (enslave), `set_port_isolated`: the bridge
//!   in the net zone and the per-port isolation flag that stops two routed
//!   zones from talking to each other over it without any firewall rule.
//! - `set_up`, `set_netns`: bring a link up; move a link (the physical NIC)
//!   into a namespace by fd.
//! - `add_addr4/6`, `add_default_route4/6`: static addressing for zone ends.
//! - `with_netns(fd, f)`: run `f` inside another network namespace and come
//!   back. Only a process with CAP_SYS_ADMIN in its own user namespace can do
//!   this (a root kryptikd in zone 0); netlink sockets belong to the namespace
//!   they were opened in, so every operation opens its own.
//!
//! Every request carries NLM_F_ACK and is not considered done until the
//! kernel's acknowledgement arrives; a negative errno in the ack becomes an
//! `io::Error`, so a refused operation is never mistaken for a completed one.

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;

const NETLINK_ROUTE: libc::c_int = 0;

const RTM_NEWLINK: u16 = 16;
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
// 12, not 7: 7 is IFLA_STATS. The kernel ignores unknown attributes in a
// bridge setlink and acknowledges the request anyway, so a wrong number here
// produced an ACK and an unchanged port - which is why the isolation test
// checks the flag through sysfs and the behaviour on the wire, not the ACK.
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

/// One request/ack exchange on a fresh NETLINK_ROUTE socket.
fn transact(msg: Vec<u8>, what: &str) -> io::Result<()> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_ROUTE) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let sent = unsafe { libc::send(fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = [0u8; 8192];
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
                        let code = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap());
                        return if code == 0 {
                            Ok(())
                        } else {
                            Err(io::Error::new(
                                io::Error::from_raw_os_error(-code).kind(),
                                format!("{what}: {}", io::Error::from_raw_os_error(-code)),
                            ))
                        };
                    }
                    NLMSG_DONE => return Ok(()),
                    _ => {}
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

/// Mark a bridge port isolated (or not): an isolated port may exchange
/// frames only with non-isolated ports, never with another isolated one. Two
/// routed zones on isolated ports cannot reach each other through the bridge
/// at all - no firewall rule involved, and nothing a zone can undo from its
/// own side of the veth.
pub fn set_port_isolated(dev: &str, on: bool) -> io::Result<()> {
    let idx = index_of(dev)?;
    let mut m = Msg::new(RTM_SETLINK, 0, 1);
    m.ifinfomsg(AF_BRIDGE, idx as i32, 0, 0);
    let pi = m.begin_nested(IFLA_PROTINFO);
    m.attr(IFLA_BRPORT_ISOLATED, &[u8::from(on)]);
    m.end_nested(pi);
    transact(m.finish(), &format!("set isolation of bridge port {dev} to {on}"))
}

pub fn set_up(dev: &str) -> io::Result<()> {
    let idx = index_of(dev)?;
    let mut m = Msg::new(RTM_NEWLINK, 0, 1);
    m.ifinfomsg(libc::AF_UNSPEC as u8, idx as i32, libc::IFF_UP as u32, libc::IFF_UP as u32);
    transact(m.finish(), &format!("bring up {dev}"))
}

/// Move `dev` into the network namespace behind `ns_fd`.
pub fn set_netns(dev: &str, ns_fd: RawFd) -> io::Result<()> {
    let idx = index_of(dev)?;
    let mut m = Msg::new(RTM_NEWLINK, 0, 1);
    m.ifinfomsg(libc::AF_UNSPEC as u8, idx as i32, 0, 0);
    m.attr_u32(IFLA_NET_NS_FD, ns_fd as u32);
    transact(m.finish(), &format!("move {dev} into namespace"))
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

/// Is `dev` administratively up, as the kernel reports it?
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

/// Run `f` inside the network namespace behind `ns_fd`, then return to the
/// caller's own. Needs CAP_SYS_ADMIN in the caller's user namespace and over
/// the target's: the root kryptikd in zone 0 has both. Single-threaded by
/// construction (setns changes only the calling thread).
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
        // Being stranded in another namespace is worse than any failure of
        // `f`; report it first.
        return Err(io::Error::new(back_err.kind(), format!("setns back to own netns: {back_err}")));
    }
    result
}

/// The routed-zone address plan (docs/design/03): the bridge is
/// 10.19.0.1/24 and fd19::1/64; routed zone `k` is 10.19.0.(k+1) / fd19::(k+1).
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

    /// Run `body` in a forked child inside a fresh user + network namespace
    /// (unprivileged where the kernel allows it). Returns the exit code, or
    /// 77 when no user namespace could be created.
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
            // A fresh sysfs shows THIS namespace's interfaces; the inherited
            // one shows the host's, which is useless for checking port flags.
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

    #[test]
    fn message_encoding_has_the_kernel_layout() {
        // ifinfomsg is 16 bytes, attributes are 4-aligned, nested lengths
        // cover their payload, and the header length is the total.
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

    /// A grandchild that unshares its own network namespace and then waits
    /// to be killed. Returns (pid, fd of its netns). The namespace is owned
    /// by the caller's user namespace, so the caller may create interfaces
    /// in it and enter it with setns.
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
                // Die with the test child: a holder left pausing forever
                // keeps cargo's output pipe open and hangs the whole run.
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

    /// A UDP socket created (and therefore living) inside `ns`, bound to
    /// `bind` when given, with a 300 ms receive timeout.
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

    /// The kernel is the oracle: a veth pair, addresses, a bridge, an
    /// enslaved port and default routes, all in a private namespace, plus the
    /// two refusals (duplicate address, duplicate name) that prove a request
    /// is acked rather than assumed.
    #[test]
    fn veth_bridge_addresses_and_routes_against_the_kernel() {
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
                    return Err(9); // EXCL: an existing address is refused, not ignored
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

    /// The peer of a veth pair is created directly in another namespace.
    #[test]
    fn veth_peer_lands_in_the_other_namespace() {
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
            // The near end is here; the far end is not...
            if index_of("kv-t").is_err() {
                return 35;
            }
            if index_of("eth0").is_ok() {
                return 36;
            }
            // ...and it IS there.
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

    /// Design 03 N5, against the kernel: two "zones" (namespaces) bridged
    /// through isolated ports cannot reach each other, the same sender does
    /// reach the bridge's own address (the uplink side), and clearing the
    /// flag restores zone-to-zone delivery - so the denial is the flag's
    /// doing and nothing else's.
    #[test]
    fn isolated_bridge_ports_block_zone_to_zone_but_not_the_uplink() {
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

                // Isolated: zone 1 -> zone 2 is dropped by the bridge.
                udp_send(tx1, [10, 99, 0, 2], 9999);
                let got = udp_received(rx2);
                eprintln!("isolated: zone1 -> zone2 delivered = {got}");
                if got {
                    return Err(50);
                }
                // Positive control: zone 1 -> the bridge address is delivered.
                udp_send(tx1, [10, 99, 0, 254], 9999);
                if !udp_received(rx_br) {
                    return Err(51);
                }
                // Clear isolation on both ports: zone 1 -> zone 2 now arrives.
                step(52, set_port_isolated("kv-z1", false))?;
                step(53, set_port_isolated("kv-z2", false))?;
                // The ARP request sent while isolated got no reply, so the
                // neighbour entry is in its retransmit backoff (about a
                // second). Keep sending until the kernel retries and the
                // datagram arrives; 3 s is far beyond the backoff.
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
