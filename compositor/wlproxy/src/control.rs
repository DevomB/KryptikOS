//! The zone 0 move gesture's door into this zone's proxy (`kryptik-launch --clipboard-move`): a
//! socket beside the zone's own, never bound into the zone, that answers the session's user
//! alone, one move at a time. `take` reads the zone's selection in one type from the broker's
//! list, 1 MiB and 2 s at most; `give` makes bytes another zone's proxy took the selection here,
//! held and served by the proxy itself; `clear` ends the selection once it has moved, if it is
//! still the one taken. The bytes reach no log.

use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::clipboard::{Action, Clipboard, Selection, OWN};
use crate::policy;

/// How long a request may take to arrive, and the copying client to answer a take.
pub const DEADLINE: Duration = Duration::from_secs(2);
/// How long a paste of the proxy's own selection may take to drain, and how many at once.
const WRITE_DEADLINE: Duration = Duration::from_secs(10);
pub const MAX_WRITERS: usize = 8;
/// The longest request line: `give`, a type from the list and a length.
const LINE_MAX: usize = 128;

#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    Take,
    Clear(u64),
    Give(String, Vec<u8>),
}

/// One request, once it has all come: Ok(None) while more is to come.
pub fn parse(buf: &[u8]) -> Result<Option<Request>, String> {
    let Some(nl) = buf.iter().position(|&b| b == b'\n') else {
        return if buf.len() > LINE_MAX { Err(format!("a request line over {LINE_MAX} bytes")) } else { Ok(None) };
    };
    let line = std::str::from_utf8(&buf[..nl]).map_err(|_| "a request line that is not UTF-8".to_string())?;
    let rest = &buf[nl + 1..];
    let mut w = line.split(' ');
    match (w.next(), w.next(), w.next(), w.next()) {
        (Some("take"), None, ..) if rest.is_empty() => Ok(Some(Request::Take)),
        (Some("clear"), Some(g), None, _) if rest.is_empty() => {
            g.parse().map(|g| Some(Request::Clear(g))).map_err(|_| format!("{g:?} is not a generation"))
        }
        (Some("give"), Some(mime), Some(len), None) => {
            if !policy::MOVE_TYPES.contains(&mime) {
                return Err(format!("{mime:?} is not a type the gesture carries"));
            }
            let len: usize = len.parse().map_err(|_| format!("{len:?} is not a length"))?;
            if len > policy::MAX_MOVE_BYTES {
                Err(format!("{len} bytes, over the {} a move carries", policy::MAX_MOVE_BYTES))
            } else if rest.len() > len {
                Err("bytes past the length given".into())
            } else if rest.len() < len {
                Ok(None)
            } else {
                Ok(Some(Request::Give(mime.to_string(), rest.to_vec())))
            }
        }
        _ => Err("the requests are take, clear GENERATION and give TYPE LENGTH".into()),
    }
}

pub enum State {
    /// Reading the request; `give` brings its bytes after its line.
    Request(Vec<u8>),
    /// The copying client writes the selection into `pipe`.
    Taking { pipe: OwnedFd, mime: String, generation: u64, data: Vec<u8> },
    /// The answer, as it is written.
    Replying(Vec<u8>, usize),
}

/// The move in progress on the control socket.
pub struct Control {
    pub conn: UnixStream,
    deadline: Instant,
    pub state: State,
    /// What the move did, for the log: zones, types and lengths, never bytes.
    pub said: String,
}

fn nonblocking(fd: RawFd) {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
}

impl Control {
    pub fn new(conn: UnixStream, now: Instant) -> Control {
        let _ = conn.set_nonblocking(true);
        Control { conn, deadline: now + DEADLINE, state: State::Request(Vec::new()), said: String::new() }
    }

    /// What to poll for: the connection, and the copying client's pipe while it is read.
    pub fn wants(&self) -> (i16, Option<RawFd>) {
        match &self.state {
            State::Request(_) => (libc::POLLIN, None),
            State::Taking { pipe, .. } => (0, Some(pipe.as_raw_fd())),
            State::Replying(..) => (libc::POLLOUT, None),
        }
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    fn reply(&mut self, out: Vec<u8>, now: Instant) {
        self.deadline = now + DEADLINE;
        self.state = State::Replying(out, 0);
    }

    fn refuse(&mut self, why: &str, now: Instant) {
        self.said = format!("move refused: {why}");
        self.reply(format!("error: {why}\n").into_bytes(), now);
    }

    /// As far as the connection and the pipe allow; true once it is over and may be dropped.
    pub fn step(&mut self, clip: &mut Clipboard, now: Instant) -> bool {
        loop {
            match &mut self.state {
                State::Request(buf) => {
                    let mut chunk = [0u8; 16384];
                    let eof = match self.conn.read(&mut chunk) {
                        Ok(0) => true,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            false
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
                        Err(_) => return true,
                    };
                    match parse(buf) {
                        Ok(Some(r)) => self.answer(r, clip, now),
                        Ok(None) if eof => return true,
                        Ok(None) if now >= self.deadline => self.refuse("the request did not come in time", now),
                        Ok(None) if buf.len() > LINE_MAX + policy::MAX_MOVE_BYTES => self.refuse("a request over its bound", now),
                        Ok(None) => return false,
                        Err(why) => self.refuse(&why, now),
                    }
                }
                State::Taking { pipe, mime, generation, data } => {
                    let mut chunk = [0u8; 65536];
                    let n = unsafe { libc::read(pipe.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
                    if n > 0 {
                        data.extend_from_slice(&chunk[..n as usize]);
                        if data.len() > policy::MAX_MOVE_BYTES {
                            self.refuse("the selection is over 1 MiB, so nothing moved", now);
                        }
                        continue;
                    }
                    if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
                        if now < self.deadline {
                            return false;
                        }
                        self.refuse("the copying window did not answer within 2 s, so nothing moved", now);
                        continue;
                    }
                    // The copying client closed its end, or the pipe failed.
                    if n < 0 || clip.generation != *generation {
                        self.refuse("the selection changed while it was read, so nothing moved", now);
                        continue;
                    }
                    let mut out = format!("ok {generation} {mime} {}\n", data.len()).into_bytes();
                    self.said = format!("move: took {} bytes of {mime}", data.len());
                    out.append(data);
                    self.reply(out, now);
                }
                State::Replying(out, pos) => {
                    match self.conn.write(&out[*pos..]) {
                        Ok(n) => *pos += n,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => return now >= self.deadline,
                        Err(_) => return true,
                    }
                    if *pos == out.len() {
                        return true;
                    }
                }
            }
        }
    }

    fn answer(&mut self, r: Request, clip: &mut Clipboard, now: Instant) {
        match r {
            Request::Take => {
                let Some(sel) = &clip.selection else {
                    self.said = "move: nothing to take".into();
                    return self.reply(b"empty\n".to_vec(), now);
                };
                let Some(mime) = policy::MOVE_TYPES.iter().find(|t| sel.mimes.iter().any(|m| m == *t)) else {
                    return self.refuse("the selection offers no type the gesture carries", now);
                };
                // A selection the proxy holds itself is answered from memory.
                if let Some(data) = &sel.data {
                    let mut out = format!("ok {} {mime} {}\n", clip.generation, data.len()).into_bytes();
                    self.said = format!("move: took {} bytes of {mime}", data.len());
                    out.extend_from_slice(data);
                    return self.reply(out, now);
                }
                let mut p = [0 as libc::c_int; 2];
                if unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
                    return self.refuse("no pipe for the copy", now);
                }
                let (r, w) = unsafe { (OwnedFd::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1])) };
                nonblocking(r.as_raw_fd());
                clip.actions.push(Action::Send(sel.owner, sel.source, mime.to_string(), w));
                self.deadline = now + DEADLINE;
                self.state = State::Taking { pipe: r, mime: mime.to_string(), generation: clip.generation, data: Vec::new() };
            }
            Request::Give(mime, data) => {
                self.said = format!("move: given {} bytes of {mime}", data.len());
                clip.set(Some(Selection { owner: OWN, source: 0, mimes: vec![mime], data: Some(Rc::new(data)) }));
                self.reply(b"ok\n".to_vec(), now);
            }
            Request::Clear(g) if g == clip.generation => {
                self.said = "move: the selection taken was cleared".into();
                clip.set(None);
                self.reply(b"ok\n".to_vec(), now);
            }
            Request::Clear(_) => self.refuse("the selection changed since it was taken, and was left as it is", now),
        }
    }
}

/// A paste of the selection the proxy holds, written as the reader's descriptor drains.
pub struct Writer {
    pub fd: OwnedFd,
    data: Rc<Vec<u8>>,
    pos: usize,
    deadline: Instant,
}

impl Writer {
    pub fn new(fd: OwnedFd, data: Rc<Vec<u8>>, now: Instant) -> Writer {
        nonblocking(fd.as_raw_fd());
        Writer { fd, data, pos: 0, deadline: now + WRITE_DEADLINE }
    }

    /// True once it is all written, the reader went away, or the time is up.
    pub fn step(&mut self, now: Instant) -> bool {
        while self.pos < self.data.len() {
            let rest = &self.data[self.pos..];
            let n = unsafe { libc::write(self.fd.as_raw_fd(), rest.as_ptr().cast(), rest.len()) };
            if n > 0 {
                self.pos += n as usize;
            } else if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
                return now >= self.deadline;
            } else {
                return true;
            }
        }
        true
    }
}

/// The uid at the other end of a Unix socket.
pub fn peer_uid(fd: RawFd) -> Option<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len) };
    (r == 0).then_some(cred.uid)
}

#[cfg(test)]
mod tests;
