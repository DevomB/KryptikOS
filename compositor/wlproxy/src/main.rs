//! kryptik-wlproxy: the per-zone Wayland filtering proxy, single-threaded and unprivileged.
//!
//!   kryptik-wlproxy --zone NAME (--listen PATH | --listen-fd N) --upstream PATH
//!                   [--max-clients N] [--once]
//!                   [--control PATH | --control-fd N] [--control-uid UID]
//!
//! Each client of the listening socket (the zone's /run/kryptik/wayland-0) gets its own Session
//! to --upstream, and the zone's clients share one selection (clipboard.rs). With --listen-fd the
//! launch daemon made the socket and passed it listening. --control is the zone 0 move gesture's
//! socket (control.rs), which no zone holds, made here or handed over listening as descriptor N;
//! --control-uid is the one peer it answers, the session's user (by default the uid the proxy
//! runs as).

mod clipboard;
mod control;
mod policy;
mod protocol;
mod protocol_tables;
mod session;
mod wire;

use std::io::Write;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use session::{Dir, Session};

/// Bounded log: the file is in /run, which is RAM, and a client can make lines at will.
struct Log { zone: String, since: Instant, lines: u32, dropped: u32, left: usize }
impl Log {
    const PER_SECOND: u32 = 20;
    const LINE_MAX: usize = 1024;
    const MAX_BYTES: usize = 1 << 20;

    fn new(zone: &str) -> Self {
        Log { zone: zone.to_string(), since: Instant::now(), lines: 0, dropped: 0, left: Self::MAX_BYTES }
    }

    fn line(&mut self, text: std::fmt::Arguments) {
        if self.since.elapsed() >= Duration::from_secs(1) {
            if self.dropped > 0 {
                let n = self.dropped;
                self.put(&format!("{n} lines not logged"), &mut std::io::stderr());
            }
            (self.since, self.lines, self.dropped) = (Instant::now(), 0, 0);
        }
        if self.lines < Self::PER_SECOND {
            self.lines += 1;
            self.put(&text.to_string(), &mut std::io::stderr());
        } else {
            self.dropped += 1;
        }
    }

    fn put(&mut self, text: &str, out: &mut dyn std::io::Write) {
        if self.left == 0 {
            return;
        }
        let mut end = text.len().min(Self::LINE_MAX);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let mut line = format!("kryptik-wlproxy[{}]: {}\n", self.zone, &text[..end]);
        if line.len() < self.left {
            self.left -= line.len();
        } else {
            self.left = 0;
            line = format!("kryptik-wlproxy[{}]: the log is full; nothing more is logged\n", self.zone);
        }
        let _ = out.write_all(line.as_bytes());
    }
}

/// Stop reading a side when the other side's unsent queue is this full.
const HIGH_WATER: usize = policy::MAX_PENDING_BYTES / 2;

fn usage() -> ! {
    eprintln!("usage: kryptik-wlproxy --zone NAME (--listen PATH | --listen-fd N) --upstream PATH [--max-clients N] [--once] [--control PATH | --control-fd N] [--control-uid UID]");
    std::process::exit(2)
}

struct Opts {
    zone: String,
    listen: PathBuf,
    listen_fd: Option<RawFd>,
    upstream: PathBuf,
    max_clients: usize,
    once: bool,
    control: Option<PathBuf>,
    control_fd: Option<RawFd>,
    control_uid: Option<u32>,
}

fn parse(args: &[String]) -> Opts {
    let mut o = Opts { zone: String::new(), listen: PathBuf::new(), listen_fd: None, upstream: PathBuf::new(), max_clients: 16, once: false, control: None, control_fd: None, control_uid: None };
    let mut i = 0;
    while i < args.len() {
        let take = |i: &mut usize| -> String {
            *i += 1;
            args.get(*i).cloned().unwrap_or_else(|| usage())
        };
        match args[i].as_str() {
            "--zone" => o.zone = take(&mut i),
            "--listen" => o.listen = PathBuf::from(take(&mut i)),
            "--listen-fd" => o.listen_fd = Some(take(&mut i).parse().ok().filter(|&fd: &RawFd| fd > 2).unwrap_or_else(|| usage())),
            "--upstream" => o.upstream = PathBuf::from(take(&mut i)),
            "--max-clients" => o.max_clients = take(&mut i).parse().unwrap_or_else(|_| usage()),
            "--once" => o.once = true,
            "--control" => o.control = Some(PathBuf::from(take(&mut i))),
            "--control-fd" => o.control_fd = Some(take(&mut i).parse().ok().filter(|&fd: &RawFd| fd > 2).unwrap_or_else(|| usage())),
            "--control-uid" => o.control_uid = Some(take(&mut i).parse().unwrap_or_else(|_| usage())),
            _ => usage(),
        }
        i += 1;
    }
    // One listening socket, a path or a descriptor, and one control socket at most, never the same.
    if o.zone.is_empty() || o.listen.as_os_str().is_empty() == o.listen_fd.is_none() || o.upstream.as_os_str().is_empty()
        || (o.control.is_some() && o.control_fd.is_some()) || (o.listen_fd.is_some() && o.listen_fd == o.control_fd) {
        usage();
    }
    if !zone_ok(&o.zone) {
        eprintln!("kryptik-wlproxy: zone name {:?} is not a plain identifier of at most 32 bytes", o.zone);
        std::process::exit(2);
    }
    o
}

/// A zone name as kryptik-launch passes one (its ident_ok), so the app_id and title prefix the
/// proxy stamps with it always fit a message.
fn zone_ok(zone: &str) -> bool {
    !zone.is_empty() && zone.len() <= 32 && zone.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Descriptors one session can hold: its two sockets and a full queue each way.
const FDS_PER_SESSION: usize = 2 + 2 * policy::MAX_PENDING_FDS;
/// stdio, the listener and room to spare, and the copy of each pool the zone may hold.
const FDS_RESERVED: usize = 8 + policy::MAX_SHM_POOLS_PER_ZONE;
/// How long the pools of a connection that ended wait to be punched: dwl drops them once it reads
/// the hang-up, and a frame it was drawing would read a punched page in again.
const POOL_GRACE: Duration = Duration::from_secs(1);

/// How many clients' descriptors fit under `limit`; at least one.
fn clients_within(limit: u64, wanted: usize) -> usize {
    let room = usize::try_from(limit).unwrap_or(usize::MAX).saturating_sub(FDS_RESERVED) / FDS_PER_SESSION;
    wanted.min(room).max(1)
}

/// Raise the fd limit to the hard one and fit max_clients under it; past it, accept and recvmsg fail.
fn fit_descriptors(o: &mut Opts) {
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } != 0 {
        return;
    }
    if rl.rlim_cur < rl.rlim_max {
        let raised = libc::rlimit { rlim_cur: rl.rlim_max, rlim_max: rl.rlim_max };
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
            rl = raised;
        }
    }
    let fit = clients_within(rl.rlim_cur, o.max_clients);
    if fit < o.max_clients {
        eprintln!("kryptik-wlproxy[{}]: {} descriptors fit {fit} clients, not {}", o.zone, rl.rlim_cur, o.max_clients);
        o.max_clients = fit;
    }
}

/// Whether `fd` is a socket that listen() was called on.
fn listening(fd: RawFd) -> bool {
    let mut on: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let r = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ACCEPTCONN, (&mut on as *mut libc::c_int).cast(), &mut len) };
    r == 0 && on == 1
}

/// A descriptor handed over listening, or the end of the proxy: one that is not would be polled
/// for ever.
fn handed_over(zone: &str, fd: RawFd) -> UnixListener {
    if !listening(fd) {
        eprintln!("kryptik-wlproxy[{zone}]: descriptor {fd} is no listening socket");
        std::process::exit(1);
    }
    // SAFETY: the descriptor is the caller's to give, and this is its one owner from here.
    unsafe { UnixListener::from_raw_fd(fd) }
}

fn set_nonblocking(fd: RawFd) {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
}

struct Live {
    s: Session,
    id: u64,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut o = parse(&args);
    fit_descriptors(&mut o);
    let (listener, at) = match o.listen_fd {
        Some(fd) => (handed_over(&o.zone, fd), format!("descriptor {fd}")),
        None => {
            let _ = std::fs::remove_file(&o.listen);
            let l = match UnixListener::bind(&o.listen) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("kryptik-wlproxy[{}]: cannot listen on {}: {e}", o.zone, o.listen.display());
                    std::process::exit(1);
                }
            };
            // 0666 so the zone's uid can connect through the bind mount; the directory keeps others out.
            let _ = std::fs::set_permissions(&o.listen, std::os::unix::fs::PermissionsExt::from_mode(0o666));
            (l, o.listen.display().to_string())
        }
    };
    listener.set_nonblocking(true).expect("nonblocking listener");
    eprintln!("kryptik-wlproxy[{}]: listening on {at} -> {}", o.zone, o.upstream.display());
    // The move gesture's socket: 0600, in the directory whose wayland-0 alone is bound into the
    // zone, or handed over already listening; a connection from any uid but the session user's
    // is refused.
    let control = match (&o.control, o.control_fd) {
        (Some(p), _) => {
            let _ = std::fs::remove_file(p);
            UnixListener::bind(p)
                .map_err(|e| eprintln!("kryptik-wlproxy[{}]: no control socket at {}: {e}", o.zone, p.display()))
                .ok()
                .inspect(|_| {
                    let _ = std::fs::set_permissions(p, std::os::unix::fs::PermissionsExt::from_mode(0o600));
                })
        }
        (None, Some(fd)) => Some(handed_over(&o.zone, fd)),
        (None, None) => None,
    }
    .filter(|l| l.set_nonblocking(true).is_ok());
    let me = o.control_uid.unwrap_or_else(|| unsafe { libc::geteuid() });
    let mut moving: Option<control::Control> = None;
    let mut writers: Vec<control::Writer> = Vec::new();

    let mut sessions: Vec<Live> = Vec::new();
    let mut clip = clipboard::Clipboard::default();
    let mut next_id = 1u64;
    let mut served = 0u64;
    let mut log = Log::new(&o.zone);
    // A failed accept leaves the connection pending, so the listener rests or poll would spin.
    let mut accept_after = Instant::now();
    let mut fds: Vec<libc::pollfd> = Vec::new();
    // The pools of connections that ended, each with the time it is punched.
    let mut gone: Vec<(OwnedFd, usize, Instant)> = Vec::new();
    loop {
        // fds: the listener, then session i at 1+2i and 2+2i; valid until `sessions` changes.
        let polled = sessions.len();
        fds.clear();
        let pause = accept_after.saturating_duration_since(Instant::now());
        let accepting = polled < o.max_clients && pause.is_zero();
        fds.push(libc::pollfd { fd: listener.as_raw_fd(), events: if accepting { libc::POLLIN } else { 0 }, revents: 0 });
        for l in &sessions {
            let mut ce = 0i16;
            let mut se = 0i16;
            if l.s.server.pending_out < HIGH_WATER { ce |= libc::POLLIN; }
            if l.s.client.pending_out < HIGH_WATER { se |= libc::POLLIN; }
            if l.s.client.pending_out > 0 { ce |= libc::POLLOUT; }
            if l.s.server.pending_out > 0 { se |= libc::POLLOUT; }
            fds.push(libc::pollfd { fd: l.s.client.fd, events: ce, revents: 0 });
            fds.push(libc::pollfd { fd: l.s.server.fd, events: se, revents: 0 });
        }
        debug_assert_eq!(fds.len(), 1 + 2 * polled);
        // Then the control socket, the move in progress and the copy's pipe, and the pastes the
        // proxy writes itself.
        let ctl_at = fds.len();
        if let Some(c) = &control {
            fds.push(libc::pollfd { fd: c.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        if let Some(m) = &moving {
            let (events, pipe) = m.wants();
            // Not while the copy is read: a hang-up there would wake poll at once, again and again.
            if events != 0 {
                fds.push(libc::pollfd { fd: m.conn.as_raw_fd(), events, revents: 0 });
            }
            if let Some(p) = pipe {
                fds.push(libc::pollfd { fd: p, events: libc::POLLIN, revents: 0 });
            }
        }
        for w in &writers {
            fds.push(libc::pollfd { fd: w.fd.as_raw_fd(), events: libc::POLLOUT, revents: 0 });
        }
        let mut timeout = if pause.is_zero() { -1 } else { pause.as_millis() as libc::c_int + 1 };
        // A move or a paste has a deadline to keep.
        if moving.is_some() || !writers.is_empty() {
            timeout = if timeout < 0 { 250 } else { timeout.min(250) };
        }
        if let Some(at) = gone.iter().map(|g| g.2).min() {
            let ms = at.saturating_duration_since(Instant::now()).as_millis() as libc::c_int + 1;
            timeout = if timeout < 0 { ms } else { timeout.min(ms) };
        }
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, timeout) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted { continue; }
            eprintln!("kryptik-wlproxy[{}]: poll: {e}", o.zone);
            std::process::exit(1);
        }
        let mut closed: Vec<usize> = Vec::new();
        // Pools waiting for their punch still count: dwl may hold them yet.
        let mut zone_pool_bytes: usize = sessions.iter().map(|l| l.s.shm_pool_bytes).sum::<usize>() + gone.iter().map(|g| g.1).sum::<usize>();
        let mut zone_pool_count: usize = sessions.iter().map(|l| l.s.shm_pool_count).sum::<usize>() + gone.len();
        let mut zone_toplevels: usize = sessions.iter().map(|l| l.s.toplevels).sum();
        for (idx, l) in sessions.iter_mut().enumerate().take(polled) {
            let ce = fds[1 + idx * 2].revents;
            let se = fds[2 + idx * 2].revents;
            let old_pool_bytes = l.s.shm_pool_bytes;
            let old_pool_count = l.s.shm_pool_count;
            let old_toplevels = l.s.toplevels;
            let mut step = |s: &mut Session, ce: i16, se: i16| -> Result<(), String> {
                if (ce | se) & libc::POLLNVAL != 0 {
                    return Err("a socket vanished under the proxy".into());
                }
                if ce & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                    match s.client.read() {
                        Ok(0) => return Err("client disconnected".into()),
                        Ok(_) => {}
                        Err(e) => return Err(format!("client read: {e}")),
                    }
                }
                if se & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                    match s.server.read() {
                        Ok(0) => return Err("compositor closed the connection".into()),
                        Ok(_) => {}
                        Err(e) => return Err(format!("compositor read: {e}")),
                    }
                }
                s.pump(Dir::ClientToServer, &mut clip).map_err(|e| e.to_string())?;
                s.pump(Dir::ServerToClient, &mut clip).map_err(|e| e.to_string())?;
                if zone_pool_bytes + s.shm_pool_bytes - old_pool_bytes > policy::MAX_SHM_BYTES_PER_ZONE
                    || zone_pool_count + s.shm_pool_count - old_pool_count > policy::MAX_SHM_POOLS_PER_ZONE
                    || zone_toplevels + s.toplevels - old_toplevels > policy::MAX_TOPLEVELS_PER_ZONE {
                    return Err("zone Wayland resource budget exceeded".into());
                }
                s.server.flush().map_err(|e| format!("compositor write: {e}"))?;
                s.client.flush().map_err(|e| format!("client write: {e}"))?;
                Ok(())
            };
            let stepped = step(&mut l.s, ce, se);
            if let Some(e) = l.s.unpunched.take() {
                log.line(format_args!("client #{}: a gone pool's pages were not freed: {e}", l.id));
            }
            if let Err(why) = stepped {
                log.line(format_args!(
                    "client #{} ended: {why} (forwarded {} requests, {} events; hid {} globals; rewrote {} identities)",
                    l.id, l.s.forwarded_c2s, l.s.forwarded_s2c, l.s.hidden_count, l.s.rewritten
                ));
                l.s.refuse(&why);
                closed.push(idx);
            } else {
                zone_pool_bytes = zone_pool_bytes - old_pool_bytes + l.s.shm_pool_bytes;
                zone_pool_count = zone_pool_count - old_pool_count + l.s.shm_pool_count;
                zone_toplevels = zone_toplevels - old_toplevels + l.s.toplevels;
            }
        }
        // A move, one at a time, from this user alone.
        let now = Instant::now();
        if let Some(c) = &control {
            if fds[ctl_at].revents & libc::POLLIN != 0 {
                if let Ok((conn, _)) = c.accept() {
                    let why = if control::peer_uid(conn.as_raw_fd()) != Some(me) {
                        Some("not the session's user")
                    } else if moving.is_some() {
                        Some("a move is already in progress")
                    } else {
                        None
                    };
                    match why {
                        Some(why) => {
                            log.line(format_args!("move refused: {why}"));
                            let _ = conn.set_nonblocking(true);
                            let _ = (&conn).write(format!("error: {why}\n").as_bytes());
                        }
                        None => moving = Some(control::Control::new(conn, now)),
                    }
                }
            }
        }
        if moving.as_mut().is_some_and(|m| m.step(&mut clip, now)) {
            if let Some(m) = moving.take() {
                if !m.said.is_empty() {
                    log.line(format_args!("{}", m.said));
                }
            }
        }
        // What one client's copy or paste asked of another session, now every turn is over;
        // a session that ends hands back its selection, which may be news to the keyboard's.
        loop {
            for a in std::mem::take(&mut clip.actions) {
                // A paste of the selection the proxy holds is written by the proxy itself.
                if a.session() == clipboard::OWN {
                    let data = clip.selection.as_ref().and_then(|s| s.data.clone());
                    if let (clipboard::Action::Send(_, _, _, fd), Some(data)) = (a, data) {
                        if writers.len() < control::MAX_WRITERS {
                            writers.push(control::Writer::new(fd, data, Instant::now()));
                        }
                    }
                    continue;
                }
                let Some(idx) = sessions.iter().position(|l| l.id == a.session()) else { continue };
                if closed.contains(&idx) {
                    continue;
                }
                let l = &mut sessions[idx];
                if let Err(e) = l.s.act(a, &clip) {
                    log.line(format_args!("client #{} ended: {e}", l.id));
                    l.s.refuse(&e.to_string());
                    closed.push(idx);
                }
            }
            if closed.is_empty() {
                break;
            }
            closed.sort_unstable();
            closed.dedup();
            for idx in closed.drain(..).rev() {
                let mut l = sessions.remove(idx);
                let at = Instant::now() + POOL_GRACE;
                gone.extend(l.s.take_pools().into_iter().map(|(fd, size)| (fd, size, at)));
                clip.session_gone(l.id);
                served += 1;
                if o.once {
                    // No later turn punches them.
                    for (fd, size, _) in gone.drain(..) {
                        if let Err(e) = session::punch(&fd, size) {
                            log.line(format_args!("a gone pool's pages were not freed: {e}"));
                        }
                    }
                    eprintln!("kryptik-wlproxy[{}]: --once: served {served}, exiting", o.zone);
                    if o.listen_fd.is_none() {
                        let _ = std::fs::remove_file(&o.listen);
                    }
                    return;
                }
            }
        }
        let now = Instant::now();
        writers.retain_mut(|w| !w.step(now));
        gone.retain(|(fd, size, at)| {
            let due = *at <= now;
            if due {
                if let Err(e) = session::punch(fd, *size) {
                    log.line(format_args!("a gone pool's pages were not freed: {e}"));
                }
            }
            !due
        });
        // Accept last, once nothing indexes `fds` by session.
        if fds[0].revents & libc::POLLIN != 0 {
            match listener.accept() {
                Ok((client, _)) => match UnixStream::connect(&o.upstream) {
                    Ok(up) => {
                        let cfd = client.into_raw_fd();
                        let sfd = up.into_raw_fd();
                        set_nonblocking(cfd);
                        set_nonblocking(sfd);
                        log.line(format_args!("client #{next_id} connected"));
                        let mut s = Session::new(&o.zone, cfd, sfd);
                        s.id = next_id;
                        sessions.push(Live { s, id: next_id });
                        next_id += 1;
                    }
                    Err(e) => {
                        log.line(format_args!("compositor at {} refused: {e}", o.upstream.display()));
                        drop(client);
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    log.line(format_args!("accept: {e}"));
                    accept_after = Instant::now() + Duration::from_secs(1);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
