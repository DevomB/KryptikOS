//! wpa_supplicant off root in the nic zone (docs/design/net-zone.md): `kryptikd supplicant`
//! starts it as its own mapped user with CAP_NET_ADMIN and CAP_NET_RAW alone, under a socket
//! filter that keeps it off nf_tables and a Landlock ruleset that keeps it to what it reads and
//! its own directory. hostap's own privilege separation carries neither SAE nor PMF
//! (docs/design/net-zone-surface.md). `kryptikd supplicant --watch`, so confined, listens to it
//! for a network that refused the passphrase.

use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::time::Duration;

use crate::caps::cap;
use crate::isolate::WIFI_ID;
use crate::landlock;

/// Its own directory, which rootfs.rs makes for `WIFI_ID`: the control socket and pid files.
pub const RUN_DIR: &str = "/run/wpa_supplicant";

/// nl80211 and interface flags take CAP_NET_ADMIN, EAPOL's packet socket CAP_NET_RAW.
pub const CAPS: [libc::c_int; 2] = [cap::NET_ADMIN, cap::NET_RAW];

/// Become the supplicant's user with `CAPS` alone, confined, and exec `argv`. Returns only on
/// failure, with what failed.
pub fn exec(argv: &[String]) -> String {
    match confine() {
        Err(e) => e,
        Ok(()) => format!("{}: {}", argv[0], std::process::Command::new(&argv[0]).args(&argv[1..]).exec()),
    }
}

/// Become the supplicant's user as `exec` does, and listen to the supplicant on `radio`
/// (`listen`). Returns when that supplicant is gone.
pub fn watch(radio: &str) -> Result<(), String> {
    // It becomes a path here: an interface's name as the kernel takes one, and nothing else.
    let bad = |c: char| c == '/' || c == ':' || c.is_whitespace();
    if radio.is_empty() || radio.len() > 15 || radio == "." || radio == ".." || radio.contains(bad) {
        return Err(format!("{radio:?} is not an interface's name"));
    }
    confine()?;
    listen(Path::new(RUN_DIR), radio).map_err(|e| format!("{radio}: {e}"))
}

/// How long the socket may stay quiet before the listener asks whether the supplicant is there.
const QUIET: Duration = Duration::from_secs(30);

/* Why a join failed is said only to a listener on the supplicant's control socket: wpa_cli's
 * action mode passes on neither event that means a refused passphrase. `RADIO.refused` names
 * the network that last refused it, as iw prints an SSID, for the status line, and goes once a
 * network is joined. The nic zone's root, which may not list this directory, reads it by name. */
fn listen(dir: &Path, radio: &str) -> io::Result<()> {
    // A path of this listener's own: one that outlives its supplicant must not, as it ends, take
    // the next one's away.
    let ours = dir.join(format!("{radio}.listen-{}", std::process::id()));
    let _ = std::fs::remove_file(&ours);
    let sock = UnixDatagram::bind(&ours)?;
    let done = attach(&sock, &dir.join(radio)).and_then(|()| hear(&sock, dir, radio));
    let _ = std::fs::remove_file(&ours);
    done
}

fn attach(sock: &UnixDatagram, supplicant: &Path) -> io::Result<()> {
    sock.connect(supplicant)?;
    sock.set_read_timeout(Some(QUIET))?;
    sock.send(b"ATTACH").map(drop)
}

/// Keep `RADIO.refused` by what the supplicant says, until it ends or is gone.
fn hear(sock: &UnixDatagram, dir: &Path, radio: &str) -> io::Result<()> {
    let mut buf = [0u8; 4096];
    // The access point being joined and its network's SSID: SAE's refusal names only the former.
    let mut trying: Option<(String, Vec<u8>)> = None;
    loop {
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            // A supplicant that is gone takes no ping.
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                if sock.send(b"PING").is_err() {
                    return Ok(());
                }
                continue;
            }
            Err(e) => return Err(e),
        };
        // Replies, OK and PONG, are not events.
        let Some(event) = std::str::from_utf8(&buf[..n]).ok().and_then(heard) else {
            continue;
        };
        let kept = match event {
            Heard::Trying { bssid, ssid } => {
                trying = Some((bssid, ssid));
                Ok(())
            }
            Heard::WrongKey { ssid } => keep(dir, radio, Some(&ssid[..])),
            Heard::SaeRefused { bssid } => match &trying {
                Some((b, ssid)) if *b == bssid => keep(dir, radio, Some(&ssid[..])),
                _ => Ok(()),
            },
            Heard::Joined => keep(dir, radio, None),
            Heard::Ending => return Ok(()),
        };
        // Not kept, the status line says "connecting", as it did before there was a file.
        if let Err(e) = kept {
            eprintln!("kryptikd supplicant --watch {radio}: {e}");
        }
    }
}

/// What one of the supplicant's events says to the listener.
#[derive(Debug, PartialEq)]
enum Heard {
    /// It is authenticating with the access point `bssid`, of the network `ssid`.
    Trying { bssid: String, ssid: Vec<u8> },
    /// WPA2's 4-way handshake with the network failed: the passphrase is not its.
    WrongKey { ssid: Vec<u8> },
    /// The access point refused the station's SAE confirm: the passphrase is not its.
    SaeRefused { bssid: String },
    Joined,
    Ending,
}

/// An event as the control socket sends one, `<LEVEL>TEXT`, in wpa_supplicant 2.12's words.
fn heard(event: &str) -> Option<Heard> {
    let text = event.strip_prefix('<')?.split_once('>')?.1;
    if let Some(r) = text.strip_prefix("SME: Trying to authenticate with ") {
        let (bssid, r) = r.split_once(" (SSID='")?;
        let (ssid, _) = r.rsplit_once("' freq=")?;
        return Some(Heard::Trying { bssid: bssid.to_string(), ssid: unescape_wpa(ssid)? });
    }
    if let Some(r) = text.strip_prefix("CTRL-EVENT-SSID-TEMP-DISABLED ") {
        // id=N ssid="SSID" auth_failures=N duration=N reason=WHY
        let (_, r) = r.split_once(" ssid=\"")?;
        let (ssid, r) = r.rsplit_once("\" auth_failures=")?;
        if !r.ends_with(" reason=WRONG_KEY") {
            return None;
        }
        return Some(Heard::WrongKey { ssid: unescape_wpa(ssid)? });
    }
    if let Some(r) = text.strip_prefix("CTRL-EVENT-AUTH-REJECT ") {
        let mut w = r.split(' ');
        let bssid = w.next()?.to_string();
        // SAE (3) refused at its confirm (2) as a failed challenge (15), which wpa_supplicant
        // itself takes for a passphrase that is not the network's.
        let confirm_refused = w.take(3).eq(["auth_type=3", "auth_transaction=2", "status_code=15"]);
        return confirm_refused.then_some(Heard::SaeRefused { bssid });
    }
    if text.starts_with("CTRL-EVENT-CONNECTED ") {
        return Some(Heard::Joined);
    }
    text.starts_with("CTRL-EVENT-TERMINATING").then_some(Heard::Ending)
}

/// An SSID as wpa_supplicant prints one (printf_encode): printable ASCII, `\\`, `\"`, `\e`,
/// `\n`, `\r`, `\t`, and `\xHH` for any other byte; none if it is not 1 to 32 bytes.
fn unescape_wpa(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut b = s.bytes();
    while let Some(c) = b.next() {
        out.push(match c {
            b'\\' => match b.next()? {
                b'\\' => b'\\',
                b'"' => b'"',
                b'e' => 0x1b,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'x' => {
                    let h = [b.next()?, b.next()?];
                    if !h.iter().all(u8::is_ascii_hexdigit) {
                        return None;
                    }
                    u8::from_str_radix(std::str::from_utf8(&h).ok()?, 16).ok()?
                }
                _ => return None,
            },
            b' '..=b'~' => c,
            _ => return None,
        });
    }
    (1..=32).contains(&out.len()).then_some(out)
}

/// Keep `RADIO.refused` naming `ssid`, as iw prints one, or with none remove it.
fn keep(dir: &Path, radio: &str, ssid: Option<&[u8]>) -> io::Result<()> {
    let path = dir.join(format!("{radio}.refused"));
    let Some(ssid) = ssid else {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    };
    // Whole or not at all for a reader, and readable by the zone's root whatever the umask.
    let new = dir.join(format!("{radio}.refused.new"));
    let mut f = std::fs::File::create(&new)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    f.write_all(format!("{}\n", crate::wifi::as_iw_prints(ssid)).as_bytes())?;
    std::fs::rename(&new, &path)
}

fn confine() -> Result<(), String> {
    // Built while every path it names can still be opened.
    let rules = ruleset()?;
    let os = |call: &str| format!("{call}: {}", io::Error::last_os_error());
    // SAFETY: plain calls on this process's credentials; none touches memory.
    unsafe {
        // Permitted capabilities outlive the change of uid; ambient ones are raised after it.
        if libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0 {
            return Err(os("prctl(PR_SET_KEEPCAPS)"));
        }
        if libc::setgroups(0, std::ptr::null()) < 0 {
            return Err(os("setgroups"));
        }
        if libc::setgid(WIFI_ID) < 0 {
            return Err(os("setgid"));
        }
        if libc::setuid(WIFI_ID) < 0 {
            return Err(os("setuid"));
        }
    }
    set_caps(&CAPS)?;
    for c in CAPS {
        let raised = unsafe {
            libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong, c as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong)
        };
        if raised < 0 {
            return Err(os("prctl(PR_CAP_AMBIENT_RAISE)"));
        }
    }
    rules.restrict_self().map_err(|e| e.to_string())?;
    crate::seccomp::install_supplicant_filter().map_err(|e| e.to_string())
}

/// Read and run what the system paths hold, read its configuration and the kernel's views, use
/// the devices it opens, and write nowhere but `RUN_DIR`.
fn ruleset() -> Result<landlock::Ruleset, String> {
    let mut r = landlock::Ruleset::new().map_err(|e| e.to_string())?;
    /* A rule covers what is reached through its path, and each system path is a bind of its
     * own: the loader comes by /lib64 and libraries by /lib, which a rule on /usr does not
     * cover. One the zone lacks is skipped, as the zone skips it. */
    for path in crate::rootfs::SYSTEM_PATHS {
        if std::path::Path::new(path).is_dir() {
            r.allow(path, landlock::ACCESS_READ | landlock::ACCESS_EXEC).map_err(|e| format!("{path}: {e}"))?;
        }
    }
    for (path, access) in [
        ("/etc", landlock::ACCESS_READ),
        ("/proc", landlock::ACCESS_READ),
        ("/sys", landlock::ACCESS_READ),
        // /dev/null for daemon(3), /dev/random and /dev/urandom for its entropy.
        ("/dev", landlock::ACCESS_READ | landlock::ACCESS_WRITE_FILE),
        (RUN_DIR, landlock::ACCESS_READ | landlock::ACCESS_WRITE),
    ] {
        r.allow(path, access).map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(r)
}

/// Effective, permitted and inheritable sets all `caps`: capset narrows what the process holds.
fn set_caps(caps: &[libc::c_int]) -> Result<(), String> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    // _LINUX_CAPABILITY_VERSION_3: two words of each set.
    let header = Header { version: 0x2008_0522, pid: 0 };
    let mut data = [Data::default(); 2];
    for &c in caps {
        let (word, bit) = ((c / 32) as usize, 1u32 << (c % 32));
        data[word].effective |= bit;
        data[word].permitted |= bit;
        data[word].inheritable |= bit;
    }
    if unsafe { libc::syscall(libc::SYS_capset, &header as *const Header, data.as_ptr()) } < 0 {
        return Err(format!("capset: {}", io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
