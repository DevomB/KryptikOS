//! One proxied connection: a zone client on one side, the compositor on the
//! other, and this in between reading, checking, rewriting and forwarding.
//!
//! Both directions are framed here (wire.rs) against the protocol tables
//! (protocol.rs). The object map is the state: every object id the client
//! or the compositor creates is recorded with its interface, so an opcode
//! can be looked up, its signature walked, its descriptors counted and its
//! new objects registered. A message on an unknown object, an unknown
//! opcode, a malformed body, a bind of a hidden global or a resource bound
//! exceeded ends the session: the client gets one wl_display.error and both
//! sockets close.
//!
//! Descriptors travel in the same sendmsg as the bytes that need them. Each
//! side keeps a queue of received descriptors in arrival order; a message
//! whose signature carries `h` arguments takes that many from the front and
//! sends them along with its own bytes. A message that needs descriptors
//! that have not arrived yet waits, as libwayland does.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::os::unix::io::RawFd;

use crate::policy;
use crate::protocol::{self, Message};
use crate::wire::{ArgReader, Header, MessageWriter, WireError, HEADER_LEN, MAX_MESSAGE_LEN, SERVER_ID_BASE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug)]
pub enum SessionError {
    Wire(WireError),
    UnknownObject(u32),
    UnknownOpcode { interface: &'static str, opcode: u16 },
    HiddenInterface(String),
    VersionTooHigh { interface: String, asked: u32, max: u32 },
    IdOutOfRange { id: u32, dir: Dir },
    TooManyObjects,
    TooMuchPending(Dir),
    TooManyFds,
    Io(io::Error),
    PeerClosed(Dir),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Wire(e) => write!(f, "malformed message: {e}"),
            SessionError::UnknownObject(id) => write!(f, "message for unknown object {id}"),
            SessionError::UnknownOpcode { interface, opcode } => write!(f, "{interface} has no opcode {opcode}"),
            SessionError::HiddenInterface(i) => write!(f, "bind of an interface not advertised to this zone: {i}"),
            SessionError::VersionTooHigh { interface, asked, max } => write!(f, "{interface} version {asked} asked, {max} allowed"),
            SessionError::IdOutOfRange { id, dir } => write!(f, "object id {id} is not in the {dir:?} range"),
            SessionError::TooManyObjects => write!(f, "too many live objects"),
            SessionError::TooMuchPending(d) => write!(f, "too much unsent data ({d:?})"),
            SessionError::TooManyFds => write!(f, "too many queued descriptors"),
            SessionError::Io(e) => write!(f, "{e}"),
            SessionError::PeerClosed(d) => write!(f, "peer closed ({d:?})"),
        }
    }
}

impl From<WireError> for SessionError {
    fn from(e: WireError) -> Self {
        SessionError::Wire(e)
    }
}
impl From<io::Error> for SessionError {
    fn from(e: io::Error) -> Self {
        SessionError::Io(e)
    }
}

/// A socket endpoint with its inbound bytes and descriptors, and outbound
/// bytes with the descriptors that must go with the first message in them.
pub struct Endpoint {
    pub fd: RawFd,
    inbuf: Vec<u8>,
    in_fds: VecDeque<RawFd>,
    /// (bytes, fds to send with them) in order; sent from the front.
    outq: VecDeque<(Vec<u8>, Vec<RawFd>)>,
    pub pending_out: usize,
    pub closed: bool,
}

impl Endpoint {
    pub fn new(fd: RawFd) -> Endpoint {
        Endpoint { fd, inbuf: Vec::new(), in_fds: VecDeque::new(), outq: VecDeque::new(), pending_out: 0, closed: false }
    }

    /// One recvmsg with room for descriptors. Returns bytes read (0 = EOF).
    pub fn read(&mut self) -> io::Result<usize> {
        let mut buf = [0u8; 4096];
        let mut cmsg = [0u8; 256];
        let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg.len() as _;
        let n = unsafe { libc::recvmsg(self.fd, &mut msg, libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::WouldBlock {
                return Ok(usize::MAX);
            }
            return Err(e);
        }
        // Collect descriptors before the bytes, in order.
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                    let data = libc::CMSG_DATA(c) as *const RawFd;
                    let bytes = (*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                    let count = bytes / std::mem::size_of::<RawFd>();
                    for i in 0..count {
                        self.in_fds.push_back(*data.add(i));
                    }
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
        }
        if n == 0 {
            return Ok(0);
        }
        self.inbuf.extend_from_slice(&buf[..n as usize]);
        Ok(n as usize)
    }

    /// Send as much of the queue as the socket takes. Returns whether
    /// anything remains (the caller polls for POLLOUT then).
    pub fn flush(&mut self) -> io::Result<bool> {
        while let Some((bytes, fds)) = self.outq.front_mut() {
            let mut iov = libc::iovec { iov_base: bytes.as_ptr() as *mut libc::c_void, iov_len: bytes.len() };
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            let mut cbuf = [0u8; 256];
            if !fds.is_empty() {
                let space = unsafe { libc::CMSG_SPACE((fds.len() * std::mem::size_of::<RawFd>()) as u32) } as usize;
                assert!(space <= cbuf.len());
                msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
                msg.msg_controllen = space as _;
                unsafe {
                    let c = libc::CMSG_FIRSTHDR(&msg);
                    (*c).cmsg_level = libc::SOL_SOCKET;
                    (*c).cmsg_type = libc::SCM_RIGHTS;
                    (*c).cmsg_len = libc::CMSG_LEN((fds.len() * std::mem::size_of::<RawFd>()) as u32) as _;
                    let data = libc::CMSG_DATA(c) as *mut RawFd;
                    for (i, fd) in fds.iter().enumerate() {
                        *data.add(i) = *fd;
                    }
                }
            }
            let n = unsafe { libc::sendmsg(self.fd, &msg, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::WouldBlock {
                    return Ok(true);
                }
                return Err(e);
            }
            let n = n as usize;
            // The descriptors went with the first byte; they must not be
            // sent again with the remainder. Close our copies.
            for fd in fds.drain(..) {
                unsafe { libc::close(fd) };
            }
            self.pending_out -= n;
            if n == bytes.len() {
                self.outq.pop_front();
            } else {
                bytes.drain(..n);
            }
        }
        Ok(false)
    }

    fn queue(&mut self, bytes: Vec<u8>, fds: Vec<RawFd>) -> Result<(), SessionError> {
        self.pending_out += bytes.len();
        self.outq.push_back((bytes, fds));
        Ok(())
    }

    pub fn close_all(&mut self) {
        if !self.closed {
            unsafe { libc::close(self.fd) };
            self.closed = true;
        }
        for fd in self.in_fds.drain(..) {
            unsafe { libc::close(fd) };
        }
        for (_, fds) in self.outq.drain(..) {
            for fd in fds {
                unsafe { libc::close(fd) };
            }
        }
    }
}

/// The proxied connection.
pub struct Session {
    pub zone: String,
    pub client: Endpoint,
    pub server: Endpoint,
    /// object id -> interface (static from the tables)
    objects: HashMap<u32, &'static protocol::Interface>,
    /// Globals the server advertised and we let through: name -> (interface, version)
    globals: HashMap<u32, (&'static str, u32)>,
    /// Hidden globals: their names are never forwarded; a bind of them is refused.
    pub hidden_count: usize,
    pub forwarded_c2s: u64,
    pub forwarded_s2c: u64,
    pub rewritten: u64,
}

const WL_DISPLAY: u32 = 1;
const WL_DISPLAY_ERROR: u16 = 0; // event
const WL_DISPLAY_DELETE_ID: u16 = 1; // event
const WL_DISPLAY_GET_REGISTRY: u16 = 1; // request
const WL_REGISTRY_BIND: u16 = 0; // request
const WL_REGISTRY_GLOBAL: u16 = 0; // event
const WL_REGISTRY_GLOBAL_REMOVE: u16 = 1; // event

impl Session {
    pub fn new(zone: &str, client_fd: RawFd, server_fd: RawFd) -> Session {
        let mut objects = HashMap::new();
        objects.insert(WL_DISPLAY, protocol::find("wl_display").expect("wl_display in tables"));
        Session {
            zone: zone.to_string(),
            client: Endpoint::new(client_fd),
            server: Endpoint::new(server_fd),
            objects,
            globals: HashMap::new(),
            hidden_count: 0,
            forwarded_c2s: 0,
            forwarded_s2c: 0,
            rewritten: 0,
        }
    }

    fn lookup(&self, id: u32, dir: Dir, opcode: u16) -> Result<(&'static protocol::Interface, &'static Message), SessionError> {
        let iface = *self.objects.get(&id).ok_or(SessionError::UnknownObject(id))?;
        let table = match dir {
            Dir::ClientToServer => iface.requests,
            Dir::ServerToClient => iface.events,
        };
        let m = table.get(opcode as usize).ok_or(SessionError::UnknownOpcode { interface: iface.name, opcode })?;
        Ok((iface, m))
    }

    fn register(&mut self, id: u32, iface_name: &str, dir: Dir) -> Result<(), SessionError> {
        let in_client_range = id < SERVER_ID_BASE;
        let ok = match dir {
            Dir::ClientToServer => in_client_range,
            Dir::ServerToClient => !in_client_range,
        };
        if !ok || id == 0 {
            return Err(SessionError::IdOutOfRange { id, dir });
        }
        if self.objects.len() >= policy::MAX_OBJECTS {
            return Err(SessionError::TooManyObjects);
        }
        // Unknown interfaces cannot be tracked; a client cannot create one
        // (bind is checked against the allowlist) and a server creating one
        // means the tables are behind the compositor: refuse rather than guess.
        let iface = protocol::find(iface_name).ok_or_else(|| SessionError::HiddenInterface(iface_name.to_string()))?;
        self.objects.insert(id, iface);
        Ok(())
    }

    /// Process everything complete in one direction's inbound buffer.
    /// Returns Ok(()) when more input is needed.
    pub fn pump(&mut self, dir: Dir) -> Result<(), SessionError> {
        loop {
            let src = match dir {
                Dir::ClientToServer => &mut self.client,
                Dir::ServerToClient => &mut self.server,
            };
            if src.inbuf.len() < HEADER_LEN {
                return Ok(());
            }
            let h = Header::parse(&src.inbuf)?;
            let size = h.size as usize;
            if src.inbuf.len() < size {
                if src.inbuf.len() > MAX_MESSAGE_LEN {
                    return Err(SessionError::Wire(WireError::BadSize(h.size)));
                }
                return Ok(());
            }
            let (iface, m) = self.lookup(h.object, dir, h.opcode)?;
            let needed = m.fd_count();
            let src = match dir {
                Dir::ClientToServer => &mut self.client,
                Dir::ServerToClient => &mut self.server,
            };
            if src.in_fds.len() < needed {
                if src.in_fds.len() > policy::MAX_PENDING_FDS {
                    return Err(SessionError::TooManyFds);
                }
                return Ok(()); // descriptors still in flight
            }
            let mut msg: Vec<u8> = src.inbuf.drain(..size).collect();
            let fds: Vec<RawFd> = src.in_fds.drain(..needed).collect();
            let body = msg[HEADER_LEN..].to_vec();
            let decoded = protocol::decode(m, &body)?;

            // --- policy, per message ---------------------------------------
            let mut forward = true;
            match dir {
                Dir::ClientToServer => {
                    if h.object == WL_DISPLAY && h.opcode == WL_DISPLAY_GET_REGISTRY {
                        // registry is created by the client; track it
                    }
                    if iface.name == "wl_registry" && h.opcode == WL_REGISTRY_BIND {
                        let (name, version) = match (&decoded.new_objects[..], decoded.bind_version) {
                            ([(_, n)], Some(v)) => (n.clone(), v),
                            _ => return Err(SessionError::Wire(WireError::ArgOverrun)),
                        };
                        let max = policy::allowed_version(&name).ok_or_else(|| SessionError::HiddenInterface(name.clone()))?;
                        if version > max {
                            return Err(SessionError::VersionTooHigh { interface: name, asked: version, max });
                        }
                        // and the global name must be one we advertised
                        let mut r = ArgReader::new(&body);
                        let gname = r.u32()?;
                        if !self.globals.contains_key(&gname) {
                            return Err(SessionError::HiddenInterface(format!("{name} (global {gname} not advertised)")));
                        }
                    }
                    if iface.name == "xdg_toplevel" && (m.name == "set_title" || m.name == "set_app_id") {
                        if let Some((_, s)) = decoded.strings.first() {
                            let new = if m.name == "set_title" { policy::title_for(&self.zone, s) } else { policy::app_id_for(&self.zone, s) };
                            match MessageWriter::new(h.object, h.opcode).string(&new).finish() {
                                Some(rebuilt) => {
                                    msg = rebuilt;
                                    self.rewritten += 1;
                                }
                                None => return Err(SessionError::Wire(WireError::BadSize(h.size))),
                            }
                        }
                    }
                }
                Dir::ServerToClient => {
                    if iface.name == "wl_registry" && h.opcode == WL_REGISTRY_GLOBAL {
                        let mut r = ArgReader::new(&body);
                        let gname = r.u32()?;
                        let iname = r.string()?.unwrap_or("").to_string();
                        let version = r.u32()?;
                        if policy::advertise(&iname) {
                            let cap = policy::allowed_version(&iname).unwrap_or(1).min(version);
                            // advertise at most the version we can parse
                            if cap != version {
                                msg = MessageWriter::new(h.object, h.opcode).u32(gname).string(&iname).u32(cap).finish().unwrap_or(msg);
                            }
                            let iface_static: &'static str = protocol::find(&iname).map(|i| i.name).unwrap_or("?");
                            self.globals.insert(gname, (iface_static, cap));
                        } else {
                            self.hidden_count += 1;
                            forward = false;
                        }
                    }
                    if iface.name == "wl_registry" && h.opcode == WL_REGISTRY_GLOBAL_REMOVE {
                        let mut r = ArgReader::new(&body);
                        let gname = r.u32()?;
                        if self.globals.remove(&gname).is_none() {
                            forward = false; // was hidden; the client never saw it
                        }
                    }
                    if h.object == WL_DISPLAY && h.opcode == WL_DISPLAY_DELETE_ID {
                        let mut r = ArgReader::new(&body);
                        let id = r.u32()?;
                        self.objects.remove(&id);
                    }
                }
            }
            // New objects, whichever side created them.
            for (id, name) in &decoded.new_objects {
                self.register(*id, name, dir)?;
            }
            let dst = match dir {
                Dir::ClientToServer => &mut self.server,
                Dir::ServerToClient => &mut self.client,
            };
            if forward {
                if dst.pending_out + msg.len() > policy::MAX_PENDING_BYTES {
                    return Err(SessionError::TooMuchPending(dir));
                }
                dst.queue(msg, fds)?;
                match dir {
                    Dir::ClientToServer => self.forwarded_c2s += 1,
                    Dir::ServerToClient => self.forwarded_s2c += 1,
                }
            } else {
                for fd in fds {
                    unsafe { libc::close(fd) };
                }
            }
        }
    }

    /// Tell the client why, then close both sides. The error goes on the
    /// wl_display object with code 3 (implementation), which every client
    /// understands as fatal.
    pub fn refuse(&mut self, why: &str) {
        let text = format!("kryptik-wlproxy: {why}");
        if let Some(m) = MessageWriter::new(WL_DISPLAY, WL_DISPLAY_ERROR).u32(WL_DISPLAY).u32(3).string(&text).finish() {
            let _ = self.client.queue(m, Vec::new());
            let _ = self.client.flush();
        }
        self.client.close_all();
        self.server.close_all();
    }

    pub fn object_count(&self) -> usize {
        self.objects.len()
    }
    pub fn has_object(&self, id: u32) -> bool {
        self.objects.contains_key(&id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::os::unix::io::{AsRawFd, IntoRawFd};
    use std::io::{Read, Write};

    /// A session over two socketpairs: (client side, server side) handles
    /// the test drives, and the session holds the other ends.
    fn make() -> (Session, UnixStream, UnixStream) {
        let (c_test, c_prox) = UnixStream::pair().unwrap();
        let (s_test, s_prox) = UnixStream::pair().unwrap();
        c_test.set_nonblocking(true).unwrap();
        s_test.set_nonblocking(true).unwrap();
        let s = Session::new("work", c_prox.into_raw_fd(), s_prox.into_raw_fd());
        (s, c_test, s_test)
    }
    fn pump_all(s: &mut Session) -> Result<(), SessionError> {
        loop {
            let a = s.client.read()?;
            let b = s.server.read()?;
            s.pump(Dir::ClientToServer)?;
            s.pump(Dir::ServerToClient)?;
            s.server.flush()?;
            s.client.flush()?;
            if (a == usize::MAX || a == 0) && (b == usize::MAX || b == 0) {
                return Ok(());
            }
        }
    }
    fn read_all(st: &mut UnixStream) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match st.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        out
    }
    fn get_registry(id: u32) -> Vec<u8> {
        MessageWriter::new(1, WL_DISPLAY_GET_REGISTRY).u32(id).finish().unwrap()
    }
    fn global(reg: u32, name: u32, iface: &str, version: u32) -> Vec<u8> {
        MessageWriter::new(reg, WL_REGISTRY_GLOBAL).u32(name).string(iface).u32(version).finish().unwrap()
    }

    #[test]
    fn hidden_globals_never_reach_the_client_and_cannot_be_bound() {
        let (mut s, mut c, mut sv) = make();
        c.write_all(&get_registry(2)).unwrap();
        pump_all(&mut s).unwrap();
        assert!(s.has_object(2));
        sv.write_all(&global(2, 1, "wl_compositor", 6)).unwrap();
        sv.write_all(&global(2, 2, "zwlr_screencopy_manager_v1", 3)).unwrap();
        sv.write_all(&global(2, 3, "wl_data_device_manager", 3)).unwrap();
        sv.write_all(&global(2, 4, "wl_shm", 2)).unwrap();
        pump_all(&mut s).unwrap();
        let seen = read_all(&mut c);
        let text = String::from_utf8_lossy(&seen).to_string();
        assert!(text.contains("wl_compositor") && text.contains("wl_shm"));
        assert!(!text.contains("screencopy") && !text.contains("data_device"), "{text}");
        assert_eq!(s.hidden_count, 2);
        // binding the hidden global by guessing its name is refused
        let bind = MessageWriter::new(2, WL_REGISTRY_BIND).u32(2).string("zwlr_screencopy_manager_v1").u32(3).u32(5).finish().unwrap();
        c.write_all(&bind).unwrap();
        let r = pump_all(&mut s);
        assert!(matches!(r, Err(SessionError::HiddenInterface(_))), "{r:?}");
        // and an allowed one at an allowed version is forwarded and tracked
        let (mut s, mut c, mut sv) = make();
        c.write_all(&get_registry(2)).unwrap();
        sv.write_all(&global(2, 1, "wl_compositor", 6)).unwrap();
        pump_all(&mut s).unwrap();
        let bind = MessageWriter::new(2, WL_REGISTRY_BIND).u32(1).string("wl_compositor").u32(6).u32(3).finish().unwrap();
        c.write_all(&bind).unwrap();
        pump_all(&mut s).unwrap();
        assert!(s.has_object(3));
        let got = read_all(&mut sv);
        assert!(got.len() >= bind.len(), "bind forwarded to the compositor");
        // too high a version is refused
        let bind = MessageWriter::new(2, WL_REGISTRY_BIND).u32(1).string("wl_compositor").u32(99).u32(4).finish().unwrap();
        c.write_all(&bind).unwrap();
        assert!(matches!(pump_all(&mut s), Err(SessionError::VersionTooHigh { .. })));
    }

    #[test]
    fn titles_and_app_ids_are_rewritten_with_the_zone() {
        let (mut s, mut c, mut sv) = make();
        c.write_all(&get_registry(2)).unwrap();
        sv.write_all(&global(2, 1, "wl_compositor", 6)).unwrap();
        sv.write_all(&global(2, 2, "xdg_wm_base", 6)).unwrap();
        pump_all(&mut s).unwrap();
        c.write_all(&MessageWriter::new(2, WL_REGISTRY_BIND).u32(1).string("wl_compositor").u32(6).u32(3).finish().unwrap()).unwrap();
        c.write_all(&MessageWriter::new(2, WL_REGISTRY_BIND).u32(2).string("xdg_wm_base").u32(6).u32(4).finish().unwrap()).unwrap();
        c.write_all(&MessageWriter::new(3, 0).u32(5).finish().unwrap()).unwrap(); // create_surface -> 5
        c.write_all(&MessageWriter::new(4, 2).u32(6).u32(5).finish().unwrap()).unwrap(); // get_xdg_surface -> 6
        c.write_all(&MessageWriter::new(6, 1).u32(7).finish().unwrap()).unwrap(); // get_toplevel -> 7
        pump_all(&mut s).unwrap();
        let _ = read_all(&mut sv);
        c.write_all(&MessageWriter::new(7, 2).string("Notes").finish().unwrap()).unwrap(); // set_title
        c.write_all(&MessageWriter::new(7, 3).string("editor").finish().unwrap()).unwrap(); // set_app_id
        pump_all(&mut s).unwrap();
        let got = String::from_utf8_lossy(&read_all(&mut sv)).to_string();
        assert!(got.contains("[work] Notes"), "{got}");
        assert!(got.contains("kryptik.work.editor"), "{got}");
        assert!(!got.contains("\0Notes\0"), "the bare title must not pass");
        assert_eq!(s.rewritten, 2);
    }

    /// A long multi-byte title goes through the same rewrite as an ASCII
    /// one: bounded, prefixed, still valid, and the session survives it.
    #[test]
    fn long_multibyte_titles_are_rewritten_and_forwarded() {
        let (mut s, mut c, mut sv) = make();
        c.write_all(&get_registry(2)).unwrap();
        sv.write_all(&global(2, 1, "wl_compositor", 6)).unwrap();
        sv.write_all(&global(2, 2, "xdg_wm_base", 6)).unwrap();
        pump_all(&mut s).unwrap();
        c.write_all(&MessageWriter::new(2, WL_REGISTRY_BIND).u32(1).string("wl_compositor").u32(6).u32(3).finish().unwrap()).unwrap();
        c.write_all(&MessageWriter::new(2, WL_REGISTRY_BIND).u32(2).string("xdg_wm_base").u32(6).u32(4).finish().unwrap()).unwrap();
        c.write_all(&MessageWriter::new(3, 0).u32(5).finish().unwrap()).unwrap();
        c.write_all(&MessageWriter::new(4, 2).u32(6).u32(5).finish().unwrap()).unwrap();
        c.write_all(&MessageWriter::new(6, 1).u32(7).finish().unwrap()).unwrap();
        pump_all(&mut s).unwrap();
        let _ = read_all(&mut sv);
        let title = "\u{00e9}".repeat(200); // 400 bytes; byte 253 is mid-character
        c.write_all(&MessageWriter::new(7, 2).string(&title).finish().unwrap()).unwrap();
        pump_all(&mut s).unwrap();
        let got = read_all(&mut sv);
        let h = Header::parse(&got).unwrap();
        assert_eq!((h.object, h.opcode), (7, 2));
        let mut r = ArgReader::new(&got[HEADER_LEN..h.size as usize]);
        let t = r.string().unwrap().unwrap();
        assert!(t.starts_with("[work] \u{00e9}"), "{t:?}");
        assert!(t.len() <= policy::MAX_TITLE_BYTES);
        assert!(t.ends_with("..."));
        assert_eq!(s.rewritten, 1);
        assert!(!s.client.closed && !s.server.closed, "the session is still up");
    }

    #[test]
    fn fragmented_and_malformed_input() {
        let (mut s, mut c, mut sv) = make();
        let m = get_registry(2);
        c.write_all(&m[..3]).unwrap();
        pump_all(&mut s).unwrap();
        assert!(!s.has_object(2), "half a header creates nothing");
        c.write_all(&m[3..]).unwrap();
        pump_all(&mut s).unwrap();
        assert!(s.has_object(2));
        assert_eq!(read_all(&mut sv), m, "the reassembled message is forwarded whole");
        // a message with size below the header
        let bad = Header { object: 2, opcode: 0, size: 4 }.encode();
        c.write_all(&bad).unwrap();
        assert!(matches!(pump_all(&mut s), Err(SessionError::Wire(WireError::BadSize(4)))));
        // unknown object
        let (mut s, mut c, _sv) = make();
        c.write_all(&MessageWriter::new(77, 0).finish().unwrap()).unwrap();
        assert!(matches!(pump_all(&mut s), Err(SessionError::UnknownObject(77))));
        // unknown opcode on a known object
        let (mut s, mut c, _sv) = make();
        c.write_all(&MessageWriter::new(1, 9).finish().unwrap()).unwrap();
        assert!(matches!(pump_all(&mut s), Err(SessionError::UnknownOpcode { .. })));
        // a client creating an id in the server's range
        let (mut s, mut c, _sv) = make();
        c.write_all(&get_registry(0xFF00_0001)).unwrap();
        assert!(matches!(pump_all(&mut s), Err(SessionError::IdOutOfRange { .. })));
    }

    #[test]
    fn descriptors_ride_with_their_message_and_no_other() {
        let (mut s, mut c, mut sv) = make();
        c.write_all(&get_registry(2)).unwrap();
        sv.write_all(&global(2, 1, "wl_shm", 2)).unwrap();
        pump_all(&mut s).unwrap();
        c.write_all(&MessageWriter::new(2, WL_REGISTRY_BIND).u32(1).string("wl_shm").u32(2).u32(3).finish().unwrap()).unwrap();
        pump_all(&mut s).unwrap();
        let _ = read_all(&mut sv);
        // wl_shm.create_pool(new_id pool, fd, size): send bytes and one fd together
        let (probe_a, probe_b) = UnixStream::pair().unwrap();
        let msg = MessageWriter::new(3, 0).u32(4).i32(4096).finish().unwrap();
        send_with_fd(c.as_raw_fd(), &msg, probe_a.as_raw_fd());
        pump_all(&mut s).unwrap();
        assert!(s.has_object(4), "the pool object is tracked");
        let (bytes, fds) = recv_with_fds(sv.as_raw_fd());
        assert_eq!(bytes, msg);
        assert_eq!(fds.len(), 1, "exactly one descriptor arrived with create_pool");
        // the descriptor is the same open file: write on it, read on probe_b
        let mut f = unsafe { <UnixStream as std::os::unix::io::FromRawFd>::from_raw_fd(fds[0]) };
        f.write_all(b"same file").unwrap();
        let mut probe_b = probe_b;
        probe_b.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 16];
        let n = probe_b.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"same file");
        // a message that carries no fd must not take one: send an fd with a
        // request whose signature has none, then a create_pool without one -
        // the queued descriptor goes with the create_pool, in order.
        let (extra_a, _extra_b) = UnixStream::pair().unwrap();
        send_with_fd(c.as_raw_fd(), &MessageWriter::new(3, 1).finish().unwrap(), extra_a.as_raw_fd()); // wl_shm.release (v2), carries no fd
        c.write_all(&MessageWriter::new(3, 0).u32(5).i32(8192).finish().unwrap()).unwrap();
        pump_all(&mut s).unwrap();
        let (bytes, fds) = recv_with_fds(sv.as_raw_fd());
        assert_eq!(bytes.len(), 8 + 16, "release (8) then create_pool (16)");
        assert_eq!(fds.len(), 1);
        for fd in fds { unsafe { libc::close(fd) }; }
    }

    #[test]
    fn a_message_waits_for_its_descriptor() {
        let (mut s, mut c, mut sv) = make();
        c.write_all(&get_registry(2)).unwrap();
        sv.write_all(&global(2, 1, "wl_shm", 2)).unwrap();
        pump_all(&mut s).unwrap();
        c.write_all(&MessageWriter::new(2, WL_REGISTRY_BIND).u32(1).string("wl_shm").u32(2).u32(3).finish().unwrap()).unwrap();
        pump_all(&mut s).unwrap();
        let _ = read_all(&mut sv);
        // most of the bytes first, no fd: nothing is forwarded yet
        let msg = MessageWriter::new(3, 0).u32(4).i32(4096).finish().unwrap();
        c.write_all(&msg[..12]).unwrap();
        pump_all(&mut s).unwrap();
        assert!(!s.has_object(4));
        assert!(read_all(&mut sv).is_empty());
        // the last bytes arrive with the fd (Linux carries SCM_RIGHTS only with
        // data, as libwayland does): now it goes
        let (a, _b) = UnixStream::pair().unwrap();
        send_with_fd(c.as_raw_fd(), &msg[12..], a.as_raw_fd());
        pump_all(&mut s).unwrap();
        assert!(s.has_object(4));
        let (bytes, fds) = recv_with_fds(sv.as_raw_fd());
        assert_eq!(bytes, msg);
        assert_eq!(fds.len(), 1);
        for fd in fds { unsafe { libc::close(fd) }; }
    }

    #[test]
    fn disconnect_and_refusal_close_both_sides() {
        let (mut s, mut c, sv) = make();
        c.write_all(&get_registry(2)).unwrap();
        pump_all(&mut s).unwrap();
        s.refuse("test refusal");
        let got = read_all(&mut c);
        let text = String::from_utf8_lossy(&got).to_string();
        assert!(text.contains("test refusal"), "the client is told why");
        assert!(s.client.closed && s.server.closed);
        drop(sv);
        // peer EOF is reported as such
        let (mut s, c, _sv) = make();
        drop(c);
        assert_eq!(s.client.read().unwrap(), 0);
    }

    #[test]
    fn object_bound_is_enforced() {
        let (mut s, mut c, mut sv) = make();
        c.write_all(&get_registry(2)).unwrap();
        sv.write_all(&global(2, 1, "wl_compositor", 6)).unwrap();
        pump_all(&mut s).unwrap();
        c.write_all(&MessageWriter::new(2, WL_REGISTRY_BIND).u32(1).string("wl_compositor").u32(6).u32(3).finish().unwrap()).unwrap();
        pump_all(&mut s).unwrap();
        let mut err = None;
        for i in 0..(policy::MAX_OBJECTS as u32 + 5) {
            c.write_all(&MessageWriter::new(3, 0).u32(10 + i).finish().unwrap()).unwrap();
            if let Err(e) = pump_all(&mut s) {
                err = Some(e);
                break;
            }
            let _ = read_all(&mut sv);
        }
        assert!(matches!(err, Some(SessionError::TooManyObjects)), "{err:?}");
    }

    // --- helpers --------------------------------------------------------------
    fn send_with_fd(sock: RawFd, bytes: &[u8], fd: RawFd) {
        assert!(!bytes.is_empty(), "SCM_RIGHTS needs at least one byte of data");
        let mut iov = libc::iovec { iov_base: bytes.as_ptr() as *mut libc::c_void, iov_len: bytes.len() };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        let mut cbuf = [0u8; 64];
        let space = unsafe { libc::CMSG_SPACE(4) } as usize;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space as _;
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(4) as _;
            *(libc::CMSG_DATA(c) as *mut RawFd) = fd;
            let n = libc::sendmsg(sock, &msg, 0);
            assert!(n >= 0, "sendmsg: {}", io::Error::last_os_error());
        }
    }
    fn recv_with_fds(sock: RawFd) -> (Vec<u8>, Vec<RawFd>) {
        let mut ep = Endpoint::new(sock);
        loop {
            match ep.read() {
                Ok(usize::MAX) | Ok(0) => break,
                Ok(_) => continue,
                Err(e) => panic!("{e}"),
            }
        }
        let fds: Vec<RawFd> = ep.in_fds.drain(..).collect();
        let bytes = std::mem::take(&mut ep.inbuf);
        std::mem::forget(ep); // the test owns `sock`; do not close it here
        (bytes, fds)
    }
}
