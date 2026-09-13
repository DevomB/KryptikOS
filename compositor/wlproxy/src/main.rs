//! kryptik-wlproxy: the per-zone Wayland filtering proxy.
//!
//!   kryptik-wlproxy --zone NAME --listen PATH --upstream PATH [--max-clients N] [--once]
//!
//! Listens on PATH (a socket the launcher binds into the zone as
//! /run/kryptik/wayland-0), connects each accepted client to the
//! compositor at --upstream, and runs one Session per client: framing,
//! object tracking, descriptor accounting, the global allowlist, identity
//! rewriting and bounds (session.rs, policy.rs). A client that breaks the
//! protocol or reaches for something hidden gets a wl_display.error and is
//! disconnected; nothing it sent after that is forwarded.
//!
//! Single-threaded, poll(2)-driven, no allocations the client controls
//! beyond the bounded buffers. Runs unprivileged, as the desktop user.

mod policy;
mod protocol;
mod protocol_tables;
mod session;
mod wire;

use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

use session::{Dir, Session};

/// Stop reading a side when the other side's unsent queue is this full.
const HIGH_WATER: usize = policy::MAX_PENDING_BYTES / 2;

fn usage() -> ! {
    eprintln!("usage: kryptik-wlproxy --zone NAME --listen PATH --upstream PATH [--max-clients N] [--once]");
    std::process::exit(2)
}

struct Opts {
    zone: String,
    listen: PathBuf,
    upstream: PathBuf,
    max_clients: usize,
    once: bool,
}

fn parse(args: &[String]) -> Opts {
    let mut o = Opts { zone: String::new(), listen: PathBuf::new(), upstream: PathBuf::new(), max_clients: 16, once: false };
    let mut i = 0;
    while i < args.len() {
        let take = |i: &mut usize| -> String {
            *i += 1;
            args.get(*i).cloned().unwrap_or_else(|| usage())
        };
        match args[i].as_str() {
            "--zone" => o.zone = take(&mut i),
            "--listen" => o.listen = PathBuf::from(take(&mut i)),
            "--upstream" => o.upstream = PathBuf::from(take(&mut i)),
            "--max-clients" => o.max_clients = take(&mut i).parse().unwrap_or_else(|_| usage()),
            "--once" => o.once = true,
            _ => usage(),
        }
        i += 1;
    }
    if o.zone.is_empty() || o.listen.as_os_str().is_empty() || o.upstream.as_os_str().is_empty() {
        usage();
    }
    if !o.zone.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        eprintln!("kryptik-wlproxy: zone name {:?} is not a plain identifier", o.zone);
        std::process::exit(2);
    }
    o
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
    let o = parse(&args);
    let _ = std::fs::remove_file(&o.listen);
    let listener = match UnixListener::bind(&o.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("kryptik-wlproxy[{}]: cannot listen on {}: {e}", o.zone, o.listen.display());
            std::process::exit(1);
        }
    };
    // The zone's uid must be able to connect through the bind mount; the
    // directory on this side is what keeps everyone else out.
    let _ = std::fs::set_permissions(&o.listen, std::os::unix::fs::PermissionsExt::from_mode(0o666));
    listener.set_nonblocking(true).expect("nonblocking listener");
    eprintln!("kryptik-wlproxy[{}]: listening on {} -> {}", o.zone, o.listen.display(), o.upstream.display());

    let mut sessions: Vec<Live> = Vec::new();
    let mut next_id = 1u64;
    let mut served = 0u64;
    loop {
        // Build the poll set: the listener, then each session's two sockets.
        let mut fds: Vec<libc::pollfd> = vec![libc::pollfd { fd: listener.as_raw_fd(), events: if sessions.len() < o.max_clients { libc::POLLIN } else { 0 }, revents: 0 }];
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
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, -1) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted { continue; }
            eprintln!("kryptik-wlproxy[{}]: poll: {e}", o.zone);
            std::process::exit(1);
        }
        // Accept.
        if fds[0].revents & libc::POLLIN != 0 {
            match listener.accept() {
                Ok((client, _)) => match UnixStream::connect(&o.upstream) {
                    Ok(up) => {
                        let cfd = client.into_raw_fd();
                        let sfd = up.into_raw_fd();
                        set_nonblocking(cfd);
                        set_nonblocking(sfd);
                        eprintln!("kryptik-wlproxy[{}]: client #{next_id} connected", o.zone);
                        sessions.push(Live { s: Session::new(&o.zone, cfd, sfd), id: next_id });
                        next_id += 1;
                    }
                    Err(e) => {
                        eprintln!("kryptik-wlproxy[{}]: compositor at {} refused: {e}", o.zone, o.upstream.display());
                        drop(client);
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => eprintln!("kryptik-wlproxy[{}]: accept: {e}", o.zone),
            }
        }
        // Service sessions.
        let mut closed: Vec<usize> = Vec::new();
        for (idx, l) in sessions.iter_mut().enumerate() {
            let ce = fds[1 + idx * 2].revents;
            let se = fds[2 + idx * 2].revents;
            let mut end: Option<String> = None;
            let step = |s: &mut Session, ce: i16, se: i16| -> Result<(), String> {
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
                s.pump(Dir::ClientToServer).map_err(|e| e.to_string())?;
                s.pump(Dir::ServerToClient).map_err(|e| e.to_string())?;
                s.server.flush().map_err(|e| format!("compositor write: {e}"))?;
                s.client.flush().map_err(|e| format!("client write: {e}"))?;
                Ok(())
            };
            if let Err(why) = step(&mut l.s, ce, se) {
                end = Some(why);
            }
            if let Some(why) = end {
                eprintln!(
                    "kryptik-wlproxy[{}]: client #{} ended: {why} (forwarded {} requests, {} events; hid {} globals; rewrote {} identities)",
                    o.zone, l.id, l.s.forwarded_c2s, l.s.forwarded_s2c, l.s.hidden_count, l.s.rewritten
                );
                l.s.refuse(&why);
                closed.push(idx);
            }
        }
        for idx in closed.into_iter().rev() {
            sessions.remove(idx);
            served += 1;
            if o.once {
                eprintln!("kryptik-wlproxy[{}]: --once: served {served}, exiting", o.zone);
                let _ = std::fs::remove_file(&o.listen);
                return;
            }
        }
    }
}
