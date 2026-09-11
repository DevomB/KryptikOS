//! Broker identity: who is on the other end of a Unix socket, and which zone
//! that is (docs/design/05-broker-and-desktop-boundary.md).
//!
//! THE ONE MECHANISM
//!
//! Every zone has a fixed host identity range (`[identity] uid_base`, Design
//! 01). A connection accepted in zone 0 carries `SO_PEERCRED`, whose uid is
//! kernel-asserted and cannot be chosen by the connecting process. If that
//! uid falls in exactly one zone's range, the peer IS that zone: no token, no
//! handshake, nothing a zone could forge. The peer pid is deliberately not
//! used - it is a pid in zone 0's namespace and may be reused - and the
//! peer gid is checked only for consistency.
//!
//! This module is the primitive. The verbs (file transfer, clipboard) and
//! the serving loop come later and are specified in Design 05; what they
//! all start with is `peer_identity` followed by `zone_for_uid`.
//!
//! Unprivileged developer launches map every zone to the launching user's
//! own uid, so identity cannot distinguish zones there; `zone_for_uid`
//! returns `None` for a uid outside every declared range, and the caller
//! refuses. That is the honest answer on a developer host and the correct
//! one on the target.

use std::io;
use std::os::unix::io::RawFd;

use crate::zone::{Zone, IDENTITY_STRIDE};

/// Kernel-asserted credentials of a Unix-socket peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
}

/// `SO_PEERCRED` of a connected AF_UNIX socket (stream or seqpacket, or one
/// end of a socketpair).
pub fn peer_identity(fd: RawFd) -> io::Result<PeerCred> {
    let mut uc: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut uc as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCred { uid: uc.uid, gid: uc.gid })
}

/// The zone whose declared identity range contains `uid`, if exactly one
/// does. Ranges are disjoint by construction (`zone::check_invariants`), so
/// "exactly one" is a scan for the single match; a uid outside every range
/// - a host user, an unprivileged developer launch, root - matches nothing.
pub fn zone_for_uid<'a>(zones: &'a [Zone], uid: u32) -> Option<&'a Zone> {
    let mut found: Option<&Zone> = None;
    for z in zones {
        let Some(base) = z.uid_base else { continue };
        if uid >= base && uid - base < IDENTITY_STRIDE {
            if found.is_some() {
                return None; // overlapping ranges: refuse rather than guess
            }
            found = Some(z);
        }
    }
    found
}

/// Identify the zone behind a connection, or say why not. The gid must lie
/// in the same range as the uid: a process that somehow held a uid from one
/// zone and a gid from another is not any zone.
pub fn identify<'a>(zones: &'a [Zone], fd: RawFd) -> Result<&'a Zone, String> {
    let cred = peer_identity(fd).map_err(|e| format!("SO_PEERCRED: {e}"))?;
    let z = zone_for_uid(zones, cred.uid)
        .ok_or_else(|| format!("peer uid {} is not in any zone's identity range", cred.uid))?;
    match zone_for_uid(zones, cred.gid) {
        Some(g) if g.name == z.name => Ok(z),
        _ => Err(format!(
            "peer uid {} is zone {:?} but gid {} is not in that zone's range",
            cred.uid, z.name, cred.gid
        )),
    }
}

/// The socket file name inside a registry entry, and the path a zone sees.
pub const SOCKET_NAME: &str = "broker";
pub const ZONE_PATH: &str = "/run/kryptik/broker";

/// Bind a listening AF_UNIX socket at `path`, owned by the zone identity so
/// the zone (and nobody else) may connect to it. A stale file is removed
/// first: the path is inside a registry entry this launcher has just
/// claimed, so nothing else can own it.
pub fn listen_at(path: &std::path::Path, uid: u32, gid: u32) -> io::Result<RawFd> {
    let _ = std::fs::remove_file(path);
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in socket path"))?;
    if c.as_bytes().len() >= 108 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "socket path too long for sockaddr_un"));
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (i, b) in c.as_bytes().iter().enumerate() {
        sa.sun_path[i] = *b as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + c.as_bytes().len() + 1) as libc::socklen_t;
    let r = unsafe {
        // Nobody but the owner may connect: 0600 before the bind is visible.
        let old = libc::umask(0o177);
        let r = libc::bind(fd, &sa as *const _ as *const libc::sockaddr, len);
        libc::umask(old);
        r
    };
    if r < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    if unsafe { libc::geteuid() } == 0 && unsafe { libc::chown(c.as_ptr(), uid, gid) } < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    if unsafe { libc::listen(fd, 8) } < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

/// Accept one connection and answer one request. The peer must be the zone
/// this launcher runs (`uid` is its mapped host uid); anything else gets a
/// refusal and no information. Verbs: `version`. Everything else is an
/// error reply. Returns the verb handled, for logging.
pub fn serve_one(listen_fd: RawFd, zone: &str, uid: u32) -> io::Result<Option<String>> {
    let fd = unsafe { libc::accept4(listen_fd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
    if fd < 0 {
        let e = io::Error::last_os_error();
        return if e.raw_os_error() == Some(libc::EAGAIN) || e.raw_os_error() == Some(libc::EINTR) {
            Ok(None)
        } else {
            Err(e)
        };
    }
    let result = (|| {
        let cred = peer_identity(fd)?;
        if cred.uid != uid {
            reply(fd, "error: unidentified peer\n");
            return Ok(None);
        }
        let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
        unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as u32)
        };
        let mut buf = [0u8; 256];
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n <= 0 {
            return Ok(None);
        }
        let line = String::from_utf8_lossy(&buf[..n as usize]);
        let verb = line.lines().next().unwrap_or("").trim().to_string();
        match verb.as_str() {
            "version" => reply(fd, &format!("kryptik-broker 1 zone={zone}\n")),
            _ => reply(fd, "error: unknown verb\n"),
        }
        Ok(Some(verb))
    })();
    unsafe { libc::close(fd) };
    result
}

fn reply(fd: RawFd, text: &str) {
    unsafe { libc::send(fd, text.as_ptr() as *const libc::c_void, text.len(), libc::MSG_NOSIGNAL) };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zones() -> Vec<Zone> {
        let mk = |name: &str, base: Option<u32>, colour: &str| {
            let ident = base.map(|b| format!("[identity]\nuid_base = {b}\n")).unwrap_or_default();
            Zone::from_str(&format!(
                "[zone]\nname = \"{name}\"\n[network]\nmode = \"routed\"\n\
                 [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n{ident}[ui]\nborder_color = \"{colour}\"\n"
            ))
            .unwrap()
        };
        vec![
            mk("work", Some(131072), "#111111"),
            mk("personal", Some(196608), "#222222"),
            mk("legacy", None, "#333333"),
        ]
    }

    #[test]
    fn a_uid_maps_to_exactly_the_zone_whose_range_holds_it() {
        let zs = zones();
        assert_eq!(zone_for_uid(&zs, 131072).map(|z| z.name.as_str()), Some("work"));
        assert_eq!(zone_for_uid(&zs, 131072 + 65534).map(|z| z.name.as_str()), Some("work"));
        assert_eq!(zone_for_uid(&zs, 131072 + 65535).map(|z| z.name.as_str()), Some("work"));
        assert_eq!(zone_for_uid(&zs, 196608).map(|z| z.name.as_str()), Some("personal"));
        // Host users, root, and the range just past the last zone match nothing.
        for uid in [0u32, 1000, 131071, 196608 + 65536, u32::MAX] {
            assert!(zone_for_uid(&zs, uid).is_none(), "uid {uid} must not identify a zone");
        }
    }

    #[test]
    fn a_socketpair_peer_is_this_process_and_identifies_by_uid() {
        let mut sv = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) }, 0);
        let cred = peer_identity(sv[0]).unwrap();
        assert_eq!(cred.uid, unsafe { libc::geteuid() });
        assert_eq!(cred.gid, unsafe { libc::getegid() });
        // Our own uid is a host user, not a zone: identify refuses, naming the uid.
        let err = identify(&zones(), sv[0]).unwrap_err();
        assert!(err.contains("not in any zone"), "{err}");
        unsafe {
            libc::close(sv[0]);
            libc::close(sv[1]);
        }
    }

    #[test]
    fn a_zone_with_no_identity_can_never_be_identified() {
        // "legacy" has no uid_base: nothing maps to it, so the broker can
        // never attribute a request to it - which is the point of P3.
        let zs = zones();
        for uid in 0..300_000u32 {
            if let Some(z) = zone_for_uid(&zs, uid) {
                assert_ne!(z.name, "legacy");
            }
        }
    }
}
