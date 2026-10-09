//! One proxied connection, zone client to compositor. A message the object map or the tables
//! cannot account for, a hidden bind or an exceeded bound ends it with one wl_display.error.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::os::unix::io::{FromRawFd, IntoRawFd, OwnedFd, RawFd};

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
    DuplicateObject(u32),
    UnknownOpcode { interface: &'static str, opcode: u16 },
    HiddenInterface(String),
    VersionTooHigh { interface: String, asked: u32, max: u32 },
    IdOutOfRange { id: u32, dir: Dir },
    SparseId(u32),
    TooManyObjects,
    TooMuchPending(Dir),
    TooManyFds,
    Forbidden(&'static str),
    ResourceLimit(&'static str),
    Io(io::Error),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Wire(e) => write!(f, "malformed message: {e}"),
            SessionError::UnknownObject(id) => write!(f, "message for unknown object {id}"),
            SessionError::DuplicateObject(id) => write!(f, "object id {id} is already live"),
            SessionError::UnknownOpcode { interface, opcode } => write!(f, "{interface} has no opcode {opcode}"),
            SessionError::HiddenInterface(i) => {
                // The client's own words, which may be 4 KiB: a prefix and the length.
                let shown: String = i.chars().take(80).collect();
                if shown.len() == i.len() {
                    write!(f, "bind of an interface not advertised to this zone: {i:?}")
                } else {
                    write!(f, "bind of an interface not advertised to this zone: {shown:?}... ({} bytes)", i.len())
                }
            }
            SessionError::VersionTooHigh { interface, asked, max } => write!(f, "{interface} version {asked} asked, {max} allowed"),
            SessionError::IdOutOfRange { id, dir } => write!(f, "object id {id} is not in the {dir:?} range"),
            SessionError::SparseId(id) => write!(f, "object id {id} skips past the ids in use"),
            SessionError::TooManyObjects => write!(f, "too many live objects"),
            SessionError::TooMuchPending(d) => write!(f, "too much unsent data ({d:?})"),
            SessionError::TooManyFds => write!(f, "too many queued descriptors"),
            SessionError::Forbidden(why) => write!(f, "forbidden request: {why}"),
            SessionError::ResourceLimit(why) => write!(f, "resource limit: {why}"),
            SessionError::Io(e) => write!(f, "{e}"),
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

/// Bytes gathered into one outbound batch: the largest message.
const BATCH_BYTES: usize = MAX_MESSAGE_LEN;
/// Descriptors per sendmsg: libwayland reads at most 28 (MAX_FDS_OUT) and hangs up on more.
pub(crate) const BATCH_FDS: usize = 28;

/// One socket: inbound bytes and descriptors, outbound batches with theirs.
pub struct Endpoint {
    pub fd: RawFd,
    /// Inbound bytes; those before `in_pos` are consumed.
    inbuf: Vec<u8>,
    in_pos: usize,
    in_fds: VecDeque<RawFd>,
    /// Batches of whole messages and their descriptors, one sendmsg each (`queue`).
    outq: VecDeque<(Vec<u8>, Vec<RawFd>)>,
    pub pending_out: usize,
    pending_fds: usize,
    pub closed: bool,
}

impl Endpoint {
    pub fn new(fd: RawFd) -> Endpoint {
        Endpoint { fd, inbuf: Vec::new(), in_pos: 0, in_fds: VecDeque::new(), outq: VecDeque::new(), pending_out: 0, pending_fds: 0, closed: false }
    }

    /// The inbound bytes not yet consumed.
    fn pending_in(&self) -> &[u8] {
        &self.inbuf[self.in_pos..]
    }

    /// Move the next `n` pending bytes into `out`; the caller has checked they are there.
    fn take(&mut self, n: usize, out: &mut Vec<u8>) {
        out.clear();
        out.extend_from_slice(&self.inbuf[self.in_pos..self.in_pos + n]);
        self.in_pos += n;
        if self.in_pos == self.inbuf.len() {
            self.inbuf.clear();
            self.in_pos = 0;
        }
    }

    /// Everything pending, leaving the buffer empty (tests).
    #[cfg(test)]
    fn take_inbuf(&mut self) -> Vec<u8> {
        let bytes = self.inbuf.split_off(self.in_pos);
        self.inbuf.clear();
        self.in_pos = 0;
        bytes
    }

    /// One recvmsg with room for descriptors: bytes read, 0 at EOF, usize::MAX if it would block.
    pub fn read(&mut self) -> io::Result<usize> {
        let mut buf = [0u8; 4096];
        let mut cmsg = [0usize; 32]; // cmsghdr needs native alignment
        let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = std::mem::size_of_val(&cmsg) as _;
        let n = unsafe { libc::recvmsg(self.fd, &mut msg, libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::WouldBlock {
                return Ok(usize::MAX);
            }
            return Err(e);
        }
        // Queue the descriptors in order before any check, so a refused read cannot leak them.
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
        // Bounds hold at ingress too, so nothing piles up while pump waits for a descriptor.
        if msg.msg_flags & libc::MSG_CTRUNC != 0
            || self.in_fds.len() > policy::MAX_PENDING_FDS
            || self.pending_in().len() + n as usize > policy::MAX_PENDING_BYTES
        {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated control data or inbound resource limit exceeded"));
        }
        if n == 0 {
            return Ok(0);
        }
        // Compact once per read, not once per message.
        if self.in_pos > 0 {
            self.inbuf.drain(..self.in_pos);
            self.in_pos = 0;
        }
        self.inbuf.extend_from_slice(&buf[..n as usize]);
        Ok(n as usize)
    }

    /// Send what the socket takes; returns whether anything remains (poll for POLLOUT).
    pub fn flush(&mut self) -> io::Result<bool> {
        while let Some((bytes, fds)) = self.outq.front_mut() {
            let mut iov = libc::iovec { iov_base: bytes.as_ptr() as *mut libc::c_void, iov_len: bytes.len() };
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            let mut cbuf = [0usize; 32];
            if !fds.is_empty() {
                let space = unsafe { libc::CMSG_SPACE((fds.len() * std::mem::size_of::<RawFd>()) as u32) } as usize;
                assert!(space <= std::mem::size_of_val(&cbuf));
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
            // The descriptors went with the first byte: close ours, so the rest goes without them.
            self.pending_fds -= fds.len();
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

    /// Add to the last batch if it fits; fds ride with it, in order and never after their message.
    fn queue(&mut self, bytes: &[u8], fds: Vec<RawFd>) {
        self.pending_out += bytes.len();
        self.pending_fds += fds.len();
        if let Some((b, f)) = self.outq.back_mut() {
            if b.len() + bytes.len() <= BATCH_BYTES && f.len() + fds.len() <= BATCH_FDS {
                b.extend_from_slice(bytes);
                f.extend(fds);
                return;
            }
        }
        self.outq.push_back((bytes.to_vec(), fds));
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
        self.pending_out = 0;
        self.pending_fds = 0;
    }
}

/// A live object: its interface from the tables and its negotiated version.
type Obj = (&'static protocol::Interface, u32);

/// Live objects, a vector per id range: libwayland ids are dense, and one that skips is refused.
struct Objects {
    client: Vec<Option<Obj>>,
    server: Vec<Option<Obj>>,
    live: usize,
}

impl Objects {
    fn new(display: Obj) -> Objects {
        // Slot 0 is never an object.
        Objects { client: vec![None, Some(display)], server: Vec::new(), live: 1 }
    }

    fn slots(&mut self, id: u32) -> (&mut Vec<Option<Obj>>, usize) {
        if id < SERVER_ID_BASE {
            (&mut self.client, id as usize)
        } else {
            (&mut self.server, (id - SERVER_ID_BASE) as usize)
        }
    }

    fn get(&self, id: u32) -> Option<Obj> {
        let (v, i) = if id < SERVER_ID_BASE { (&self.client, id as usize) } else { (&self.server, (id - SERVER_ID_BASE) as usize) };
        v.get(i).copied().flatten()
    }

    /// A new object, in a free slot or the next one.
    fn insert(&mut self, id: u32, o: Obj) -> Result<(), SessionError> {
        let full = self.live >= policy::MAX_OBJECTS;
        let (v, i) = self.slots(id);
        match v.get(i) {
            Some(Some(_)) => return Err(SessionError::DuplicateObject(id)),
            _ if full => return Err(SessionError::TooManyObjects),
            Some(None) => v[i] = Some(o),
            None if i == v.len() && v.len() < policy::MAX_ID_SLOTS => v.push(Some(o)),
            None => return Err(SessionError::SparseId(id)),
        }
        self.live += 1;
        Ok(())
    }

    fn remove(&mut self, id: u32) {
        let (v, i) = self.slots(id);
        if let Some(slot @ Some(_)) = v.get_mut(i) {
            *slot = None;
            self.live -= 1;
        }
    }

    /// A client-range object where a test wants it, gaps and all.
    #[cfg(test)]
    fn place(&mut self, id: u32, o: Obj) {
        let i = id as usize;
        if self.client.len() <= i {
            self.client.resize(i + 1, None);
        }
        if self.client[i].replace(o).is_none() {
            self.live += 1;
        }
    }
}

/// A wl_shm pool's charge on the budgets, kept until the pool and its buffers are all deleted
/// and no surface may still show one: the compositor holds a committed buffer past both.
struct Pool {
    size: usize,
    buffers: usize,
    deleted: bool,
    held: usize,
}

/// The pools a wl_surface may hold in the compositor: the last one it committed, and each one a
/// subsurface committed while synchronized, which wlroots 0.19 caches until the cache is applied
/// (types/wlr_subcompositor.c, mirrored below).
#[derive(Default)]
struct Surface {
    /// While it is a subsurface: the wl_subsurface that made it one, its parent, and that
    /// subsurface's own sync flag.
    role: Option<u32>,
    parent: Option<u32>,
    sync: bool,
    /// What it committed is cached, not yet applied.
    cached: bool,
    children: Vec<u32>,
    /// What the last attach named since the last commit: a pool, or no shm buffer.
    pending: Option<Option<u64>>,
    held: Vec<Option<u64>>,
}

/// The proxied connection.
pub struct Session {
    pub zone: String,
    pub client: Endpoint,
    pub server: Endpoint,
    objects: Objects,
    pools: HashMap<u64, Pool>,
    pool_ids: HashMap<u32, u64>,
    buffer_pools: HashMap<u32, u64>,
    surfaces: HashMap<u32, Surface>,
    /// wl_subsurface object -> its wl_surface.
    subsurfaces: HashMap<u32, u32>,
    next_pool: u64,
    pub shm_pool_bytes: usize,
    pub shm_pool_count: usize,
    pub toplevels: usize,
    /// Globals let through to the client: name -> (interface, version cap).
    globals: HashMap<u32, (&'static str, u32)>,
    /// wl_output object -> the global it was bound from, which names the output to the zone.
    outputs: HashMap<u32, u32>,
    pub hidden_count: usize,
    pub forwarded_c2s: u64,
    pub forwarded_s2c: u64,
    pub rewritten: u64,
}

const WL_DISPLAY: u32 = 1;
const WL_DISPLAY_ERROR: u16 = 0; // event
const WL_DISPLAY_DELETE_ID: u16 = 1; // event
const WL_REGISTRY_BIND: u16 = 0; // request
const WL_REGISTRY_GLOBAL: u16 = 0; // event
const WL_REGISTRY_GLOBAL_REMOVE: u16 = 1; // event

impl Session {
    pub fn new(zone: &str, client_fd: RawFd, server_fd: RawFd) -> Session {
        Session {
            zone: zone.to_string(),
            client: Endpoint::new(client_fd),
            server: Endpoint::new(server_fd),
            objects: Objects::new((protocol::find("wl_display").expect("wl_display in tables"), 1)),
            pools: HashMap::new(),
            pool_ids: HashMap::new(),
            buffer_pools: HashMap::new(),
            surfaces: HashMap::new(),
            subsurfaces: HashMap::new(),
            next_pool: 0,
            shm_pool_bytes: 0,
            shm_pool_count: 0,
            toplevels: 0,
            globals: HashMap::new(),
            outputs: HashMap::new(),
            hidden_count: 0,
            forwarded_c2s: 0,
            forwarded_s2c: 0,
            rewritten: 0,
        }
    }

    fn lookup(&self, id: u32, dir: Dir, opcode: u16) -> Result<(&'static protocol::Interface, &'static Message, u32), SessionError> {
        let (iface, version) = self.objects.get(id).ok_or(SessionError::UnknownObject(id))?;
        let table = match dir {
            Dir::ClientToServer => iface.requests,
            Dir::ServerToClient => iface.events,
        };
        let m = table.get(opcode as usize).ok_or(SessionError::UnknownOpcode { interface: iface.name, opcode })?;
        if m.since > version {
            return Err(SessionError::VersionTooHigh {
                interface: format!("{}.{}", iface.name, m.name), asked: m.since, max: version,
            });
        }
        Ok((iface, m, version))
    }

    fn register(&mut self, id: u32, iface_name: &str, version: u32, dir: Dir) -> Result<(), SessionError> {
        let in_client_range = id < SERVER_ID_BASE;
        let ok = match dir {
            Dir::ClientToServer => in_client_range,
            Dir::ServerToClient => !in_client_range,
        };
        if !ok || id == 0 {
            return Err(SessionError::IdOutOfRange { id, dir });
        }
        /* Refuse an interface the tables lack: binds are allowlisted, so only a
         * compositor newer than the tables can name one. */
        let iface = protocol::find(iface_name).ok_or_else(|| SessionError::HiddenInterface(iface_name.to_string()))?;
        if iface.name == "xdg_toplevel" && self.toplevels >= policy::MAX_TOPLEVELS_PER_SESSION {
            return Err(SessionError::ResourceLimit("too many toplevels in one session"));
        }
        self.objects.insert(id, (iface, version))?;
        if iface.name == "xdg_toplevel" {
            self.toplevels += 1;
        }
        Ok(())
    }

    fn release_pool_if_unused(&mut self, generation: u64) {
        if self.pools.get(&generation).is_some_and(|p| p.deleted && p.buffers == 0 && p.held == 0) {
            let pool = self.pools.remove(&generation).unwrap();
            self.shm_pool_bytes -= pool.size;
            self.shm_pool_count -= 1;
        }
    }

    fn unhold(&mut self, generation: u64) {
        if let Some(p) = self.pools.get_mut(&generation) {
            p.held -= 1;
        }
        self.release_pool_if_unused(generation);
    }

    /// `id` and the surfaces above it, nearest first; bounded, as the client names the parents.
    fn up(&self, id: u32) -> impl Iterator<Item = u32> + '_ {
        std::iter::successors(Some(id), |s| self.surfaces.get(s).and_then(|sf| sf.parent)).take(self.subsurfaces.len() + 1)
    }

    /// wlroots' subsurface_is_synchronized: its own flag or an ancestor subsurface's.
    fn synced(&self, id: u32) -> bool {
        self.up(id).any(|s| self.surfaces.get(&s).is_some_and(|sf| sf.sync))
    }

    /// A surface's state applied: it keeps only its last commit, and each subsurface under it with
    /// its own flag set and a cache is applied in turn, as wlroots' parent commit does.
    fn apply(&mut self, id: u32) {
        let (mut todo, mut freed) = (vec![id], Vec::new());
        while let Some(s) = todo.pop() {
            let Some(sf) = self.surfaces.get_mut(&s) else { continue };
            let keep = sf.held.pop();
            freed.extend(sf.held.drain(..).flatten());
            sf.held.extend(keep);
            sf.cached = false;
            let kids = &self.surfaces[&s].children;
            todo.extend(kids.iter().copied().filter(|k| self.surfaces.get(k).is_some_and(|c| c.sync && c.cached)));
        }
        for g in freed {
            self.unhold(g);
        }
    }

    /// A subsurface's role ends; wlroots applies what it cached first.
    fn detach(&mut self, id: u32) {
        if self.surfaces.get(&id).is_some_and(|sf| sf.cached) {
            self.apply(id);
        }
        let Some(sf) = self.surfaces.get_mut(&id) else { return };
        let parent = sf.parent.take();
        sf.role = None;
        sf.sync = false;
        if let Some(p) = parent.and_then(|p| self.surfaces.get_mut(&p)) {
            p.children.retain(|&c| c != id);
        }
    }

    /// A commit holds the attached buffer's pool; a synchronized subsurface's is cached, any
    /// other surface's applied.
    fn commit(&mut self, id: u32) -> Result<(), SessionError> {
        if let Some(sf) = self.surfaces.get_mut(&id) {
            if let Some(p) = sf.pending.take() {
                if sf.held.last() != Some(&p) {
                    if sf.held.len() >= policy::MAX_HELD_PER_SURFACE {
                        return Err(SessionError::ResourceLimit("commits cached on one surface"));
                    }
                    sf.held.push(p);
                    if let Some(g) = p {
                        if let Some(pool) = self.pools.get_mut(&g) {
                            pool.held += 1;
                        }
                    }
                }
            }
        }
        if self.synced(id) {
            if let Some(sf) = self.surfaces.get_mut(&id) {
                sf.cached = true;
            }
        } else {
            self.apply(id);
        }
        Ok(())
    }

    /// Process every complete message in one direction; Ok(()) when more input is needed.
    pub fn pump(&mut self, dir: Dir) -> Result<(), SessionError> {
        // Reused for every message of this pass.
        let mut msg: Vec<u8> = Vec::new();
        loop {
            let src = match dir {
                Dir::ClientToServer => &mut self.client,
                Dir::ServerToClient => &mut self.server,
            };
            if src.pending_in().len() < HEADER_LEN {
                return Ok(());
            }
            let h = Header::parse(src.pending_in())?;
            let size = h.size as usize;
            // read() caps what may wait here, bytes and descriptors alike.
            if src.pending_in().len() < size {
                return Ok(());
            }
            let (iface, m, version) = self.lookup(h.object, dir, h.opcode)?;
            let needed = m.fd_count();
            let src = match dir {
                Dir::ClientToServer => &mut self.client,
                Dir::ServerToClient => &mut self.server,
            };
            if src.in_fds.len() < needed {
                return Ok(()); // descriptors still in flight
            }
            src.take(size, &mut msg);
            // Owned, so a rejection before queueing closes them.
            let fds: Vec<OwnedFd> = src.in_fds.drain(..needed).map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }).collect();
            let decoded = protocol::decode(m, &msg[HEADER_LEN..])?;

            // --- policy, per message ---------------------------------------
            let mut forward = true;
            // What goes out in the message's place, when policy rewrites it.
            let mut rewritten: Option<Vec<u8>> = None;
            // A message of the proxy's own, sent right behind this one.
            let mut stamp: Option<Vec<u8>> = None;
            match dir {
                Dir::ClientToServer => {
                    // get_registry needs no check here; its new registry is registered below.
                    if iface.name == "wl_registry" && h.opcode == WL_REGISTRY_BIND {
                        let (name, version) = match (decoded.new_object, decoded.bind_version) {
                            (Some((_, n)), Some(v)) => (n, v),
                            _ => return Err(SessionError::Wire(WireError::ArgOverrun)),
                        };
                        let max = policy::allowed_version(name).ok_or_else(|| SessionError::HiddenInterface(name.to_string()))?;
                        // The global's number pins one advertised interface and version cap.
                        let mut r = ArgReader::new(&msg[HEADER_LEN..]);
                        let gname = r.u32()?;
                        let (advertised, cap) = self.globals.get(&gname).ok_or_else(||
                            SessionError::HiddenInterface(format!("{name} (global {gname} not advertised)")))?;
                        if *advertised != name || version == 0 {
                            return Err(SessionError::HiddenInterface(format!("{name} v{version} (global {gname} advertises {advertised} v{cap})")));
                        }
                        let max = max.min(*cap);
                        if version > max {
                            return Err(SessionError::VersionTooHigh { interface: name.to_string(), asked: version, max });
                        }
                        if name == "wl_output" {
                            if let Some((id, _)) = decoded.new_object {
                                self.outputs.insert(id, gname);
                            }
                        }
                    }
                    if iface.name == "xdg_toplevel" && (m.name == "set_title" || m.name == "set_app_id") {
                        if let Some((_, s)) = decoded.strings.first() {
                            let new = if m.name == "set_title" { policy::title_for(&self.zone, s) } else { policy::app_id_for(&self.zone, s) };
                            match MessageWriter::new(h.object, h.opcode).string(&new).finish() {
                                Some(rebuilt) => {
                                    rewritten = Some(rebuilt);
                                    self.rewritten += 1;
                                }
                                None => return Err(SessionError::Wire(WireError::BadSize(h.size))),
                            }
                        }
                    }
                    if iface.name == "xdg_surface" && m.name == "get_popup" {
                        return Err(SessionError::Forbidden("xdg_surface.get_popup"));
                    }
                    if iface.name == "wl_shm" && m.name == "create_pool" {
                        let mut r = ArgReader::new(&msg[HEADER_LEN..]);
                        let id = r.u32()?;
                        let size = r.u32()? as i32;
                        if size <= 0 || size as usize > policy::MAX_SHM_POOL_BYTES {
                            return Err(SessionError::ResourceLimit("wl_shm pool size"));
                        }
                        if self.shm_pool_count >= policy::MAX_SHM_POOLS_PER_SESSION
                            || self.shm_pool_bytes + size as usize > policy::MAX_SHM_BYTES_PER_SESSION {
                            return Err(SessionError::ResourceLimit("wl_shm pool budget in one session"));
                        }
                        /* A destroyed pool may still back buffers; the generation keeps
                         * them apart from a new pool on the same object id. */
                        self.next_pool += 1;
                        self.shm_pool_count += 1;
                        self.shm_pool_bytes += size as usize;
                        self.pool_ids.insert(id, self.next_pool);
                        self.pools.insert(self.next_pool, Pool { size: size as usize, buffers: 0, deleted: false, held: 0 });
                    }
                    if iface.name == "wl_shm_pool" && m.name == "resize" {
                        let mut r = ArgReader::new(&msg[HEADER_LEN..]);
                        let size = r.u32()? as i32;
                        let generation = *self.pool_ids.get(&h.object).ok_or(SessionError::ResourceLimit("unknown wl_shm pool"))?;
                        let old = self.pools[&generation].size;
                        if size <= 0 || size as usize > policy::MAX_SHM_POOL_BYTES || (size as usize) < old {
                            return Err(SessionError::ResourceLimit("wl_shm pool resize size"));
                        }
                        let growth = size as usize - old;
                        if self.shm_pool_bytes + growth > policy::MAX_SHM_BYTES_PER_SESSION {
                            return Err(SessionError::ResourceLimit("wl_shm pool budget in one session"));
                        }
                        self.shm_pool_bytes += growth;
                        self.pools.get_mut(&generation).unwrap().size = size as usize;
                    }
                    if iface.name == "wl_shm_pool" && m.name == "create_buffer" {
                        let id = decoded.new_object.ok_or(SessionError::Wire(WireError::ArgOverrun))?.0;
                        let generation = *self.pool_ids.get(&h.object).ok_or(SessionError::ResourceLimit("unknown wl_shm pool"))?;
                        self.buffer_pools.insert(id, generation);
                        self.pools.get_mut(&generation).unwrap().buffers += 1;
                    }
                    if iface.name == "wl_surface" && m.name == "attach" {
                        let buffer = ArgReader::new(&msg[HEADER_LEN..]).u32()?;
                        let pool = self.buffer_pools.get(&buffer).copied();
                        self.surfaces.entry(h.object).or_default().pending = Some(pool);
                    }
                    if iface.name == "wl_surface" && m.name == "commit" {
                        self.commit(h.object)?;
                    }
                    if iface.name == "wl_subcompositor" && m.name == "get_subsurface" {
                        if self.subsurfaces.len() >= policy::MAX_SUBSURFACES_PER_SESSION {
                            return Err(SessionError::ResourceLimit("too many subsurfaces in one session"));
                        }
                        let mut r = ArgReader::new(&msg[HEADER_LEN..]);
                        let (id, surface, parent) = (r.u32()?, r.u32()?, r.u32()?);
                        // The compositor refuses these as well; refused here, the parents never loop.
                        if self.surfaces.get(&surface).is_some_and(|sf| sf.role.is_some()) || self.up(parent).any(|s| s == surface) {
                            return Err(SessionError::Forbidden("get_subsurface on a subsurface or above its parent"));
                        }
                        let sf = self.surfaces.entry(surface).or_default();
                        sf.role = Some(id);
                        sf.parent = Some(parent);
                        sf.sync = true;
                        self.surfaces.entry(parent).or_default().children.push(surface);
                        self.subsurfaces.insert(id, surface);
                    }
                    if iface.name == "wl_subsurface" {
                        // One whose surface or parent is gone is inert, in wlroots as here.
                        let live = self.subsurfaces.get(&h.object).copied()
                            .filter(|s| self.surfaces.get(s).is_some_and(|sf| sf.role == Some(h.object)));
                        match (m.name, live) {
                            ("set_sync", Some(s)) => self.surfaces.get_mut(&s).unwrap().sync = true,
                            ("set_desync", Some(s)) => {
                                let sf = self.surfaces.get_mut(&s).unwrap();
                                if std::mem::take(&mut sf.sync) && sf.cached && !self.synced(s) {
                                    self.apply(s);
                                }
                            }
                            ("destroy", _) => {
                                self.subsurfaces.remove(&h.object);
                                if let Some(s) = live {
                                    self.detach(s);
                                }
                            }
                            _ => {}
                        }
                    }
                    /* Stamp the zone's app_id right behind get_toplevel: the compositor draws
                     * a toplevel with no app_id as zone 0's own, with the trusted border. */
                    if iface.name == "xdg_surface" && m.name == "get_toplevel" {
                        if let Some((id, _)) = decoded.new_object {
                            // Looked up once, not hardcoded; tables without set_app_id refuse.
                            static SET_APP_ID: std::sync::OnceLock<Option<u16>> = std::sync::OnceLock::new();
                            let opcode = SET_APP_ID
                                .get_or_init(|| {
                                    protocol::find("xdg_toplevel")
                                        .and_then(|i| i.requests.iter().position(|r| r.name == "set_app_id"))
                                        .map(|p| p as u16)
                                })
                                .ok_or(SessionError::Forbidden("no xdg_toplevel.set_app_id in the tables"))?;
                            // Unstamped it would be drawn as zone 0's: refused, should the name not fit.
                            let app_id = MessageWriter::new(id, opcode).string(&policy::app_id_for(&self.zone, "")).finish();
                            stamp = Some(app_id.ok_or(SessionError::Forbidden("the zone's app_id does not fit a message"))?);
                        }
                    }
                }
                Dir::ServerToClient => {
                    if iface.name == "wl_registry" && h.opcode == WL_REGISTRY_GLOBAL {
                        let mut r = ArgReader::new(&msg[HEADER_LEN..]);
                        let gname = r.u32()?;
                        let iname = r.string()?.unwrap_or("");
                        let version = r.u32()?;
                        if let Some(allowed) = policy::allowed_version(iname) {
                            let cap = allowed.min(version);
                            // advertise at most the version the proxy parses
                            if cap != version {
                                rewritten = MessageWriter::new(h.object, h.opcode).u32(gname).string(iname).u32(cap).finish();
                            }
                            let iface_static: &'static str = protocol::find(iname).map(|i| i.name).unwrap_or("?");
                            self.globals.insert(gname, (iface_static, cap));
                        } else {
                            self.hidden_count += 1;
                            forward = false;
                        }
                    }
                    if iface.name == "wl_registry" && h.opcode == WL_REGISTRY_GLOBAL_REMOVE {
                        let mut r = ArgReader::new(&msg[HEADER_LEN..]);
                        let gname = r.u32()?;
                        /* Sent once per registry the client holds, so the entry stays;
                         * a bind racing the removal is the compositor's to answer. */
                        forward = self.globals.contains_key(&gname); // hidden: never seen
                    }
                    /* A monitor's make and model, and its serial, which wlroots puts in the
                     * description, would follow the machine from zone to zone: blank, and the
                     * output named by its global's number, the same in every client. */
                    if iface.name == "wl_output" && matches!(m.name, "geometry" | "name" | "description") {
                        let mut r = ArgReader::new(&msg[HEADER_LEN..]);
                        let w = MessageWriter::new(h.object, h.opcode);
                        let w = if m.name == "geometry" {
                            let (x, y, mm_w, mm_h, subpixel) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?, r.u32()?);
                            let _ = (r.string()?, r.string()?);
                            let transform = r.u32()?;
                            w.u32(x).u32(y).u32(mm_w).u32(mm_h).u32(subpixel).string("").string("").u32(transform)
                        } else {
                            w.string(&format!("output-{}", self.outputs.get(&h.object).copied().unwrap_or(0)))
                        };
                        rewritten = Some(w.finish().ok_or(SessionError::Wire(WireError::BadSize(h.size)))?);
                    }
                    if h.object == WL_DISPLAY && h.opcode == WL_DISPLAY_DELETE_ID {
                        let mut r = ArgReader::new(&msg[HEADER_LEN..]);
                        let id = r.u32()?;
                        if self.objects.get(id).is_some_and(|(i, _)| i.name == "xdg_toplevel") {
                            self.toplevels -= 1;
                        }
                        self.outputs.remove(&id);
                        if let Some(generation) = self.pool_ids.remove(&id) {
                            self.pools.get_mut(&generation).unwrap().deleted = true;
                            self.release_pool_if_unused(generation);
                        }
                        if let Some(generation) = self.buffer_pools.remove(&id) {
                            self.pools.get_mut(&generation).unwrap().buffers -= 1;
                            self.release_pool_if_unused(generation);
                        }
                        // A surface's end ends its subsurfaces' roles too, applying their caches.
                        if let Some(sf) = self.surfaces.remove(&id) {
                            for c in sf.children {
                                self.detach(c);
                            }
                            if let Some(p) = sf.parent.and_then(|p| self.surfaces.get_mut(&p)) {
                                p.children.retain(|&c| c != id);
                            }
                            for g in sf.held.into_iter().flatten() {
                                self.unhold(g);
                            }
                        }
                        self.objects.remove(id);
                    }
                }
            }
            // A bind picks the new object's version; any other new object inherits its parent's.
            if let Some((id, name)) = decoded.new_object {
                self.register(id, name, decoded.bind_version.unwrap_or(version), dir)?;
            }
            let msg: &[u8] = rewritten.as_deref().unwrap_or(&msg);
            let dst = match dir {
                Dir::ClientToServer => &mut self.server,
                Dir::ServerToClient => &mut self.client,
            };
            if forward {
                let extra = stamp.as_ref().map(Vec::len).unwrap_or(0);
                if dst.pending_out + msg.len() + extra > policy::MAX_PENDING_BYTES {
                    return Err(SessionError::TooMuchPending(dir));
                }
                if dst.pending_fds + fds.len() > policy::MAX_PENDING_FDS {
                    return Err(SessionError::TooManyFds);
                }
                dst.queue(msg, fds.into_iter().map(IntoRawFd::into_raw_fd).collect());
                if let Some(s) = stamp {
                    dst.queue(&s, Vec::new());
                    self.rewritten += 1;
                }
                match dir {
                    Dir::ClientToServer => self.forwarded_c2s += 1,
                    Dir::ServerToClient => self.forwarded_s2c += 1,
                }
            }
        }
    }

    /// Tell the client why in a fatal wl_display.error (code 3, implementation); close both sides.
    pub fn refuse(&mut self, why: &str) {
        let text = format!("kryptik-wlproxy: {why}");
        if let Some(m) = MessageWriter::new(WL_DISPLAY, WL_DISPLAY_ERROR).u32(WL_DISPLAY).u32(3).string(&text).finish() {
            self.client.queue(&m, Vec::new());
            let _ = self.client.flush();
        }
        self.client.close_all();
        self.server.close_all();
    }

    #[cfg(test)]
    pub fn has_object(&self, id: u32) -> bool {
        self.objects.get(id).is_some()
    }
}

#[cfg(test)]
mod tests;
