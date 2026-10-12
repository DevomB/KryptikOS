//! Wi-Fi credentials for the net zone (docs/design/net-zone.md). kryptikd alone writes the file,
//! 0440, owned by the nic zone's wpa_supplicant user and grouped with its root, which checks it is
//! there; the zone gets it read-only on next start.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};

use crate::zone::NetworkMode;

pub const DEFAULT_DIR: &str = "/var/lib/kryptik/wifi";
pub const FILE_NAME: &str = "wpa_supplicant.conf";
/// Where the nic zone finds the file.
pub const IN_ZONE: &str = "/etc/wpa_supplicant.conf";
/// The net zone's service directory on an installed system.
pub const SERVICE_DIR: &str = "/run/service/net-zone";

/* No scan is recent enough to join from without a new one. With two networks saved, a first
 * failed join makes wpa_supplicant 2.12 pick again from its last scan; picking the access point
 * that just failed (one gone, which the kernel's scan cache keeps for 30 s), it counts itself
 * still joining it and asks for no scan, and waits until something else scans. */
const HEADER: &str = "ctrl_interface=/run/wpa_supplicant\nupdate_config=0\nscan_res_valid_for_connect=0\n";

/* How a saved network may be joined, from what was saved: a passphrase by WPA2's pre-shared
 * key or WPA3's SAE, a raw key by the former alone (SAE needs the passphrase), and neither by
 * 802.1X, so no access point's beacon chooses EAP for a saved SSID. Unnamed, wpa_supplicant
 * takes WPA-PSK and WPA-EAP and never SAE. Management frames are protected where offered.
 * A network saved as open is joined only without a key, so a beacon offering one changes
 * nothing; it has no management frames to protect. */
const KEY_MGMT_PASSPHRASE: &str = "\tkey_mgmt=WPA-PSK WPA-PSK-SHA256 SAE";
const KEY_MGMT_KEY: &str = "\tkey_mgmt=WPA-PSK WPA-PSK-SHA256";
const KEY_MGMT_OPEN: &str = "\tkey_mgmt=NONE";
const PMF: &str = "\tieee80211w=1";

fn key_mgmt(psk: &Psk) -> &'static str {
    match psk {
        Psk::Passphrase(_) => KEY_MGMT_PASSPHRASE,
        Psk::Hex(_) => KEY_MGMT_KEY,
        Psk::Open => KEY_MGMT_OPEN,
    }
}

pub fn conf_path(dir: &Path) -> PathBuf {
    dir.join(FILE_NAME)
}

/// A `psk=` value: a passphrase (written quoted) or the raw 64-hex-digit key; or none, for a
/// network saved as open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Psk {
    Passphrase(String),
    Hex(String),
    Open,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    pub ssid: String,
    pub psk: Psk,
    /// The station's address on this network alone (`mac_value`); none in a file an older
    /// kryptikd wrote, until it is rewritten.
    pub mac: Option<String>,
}

/* Each saved network is joined from an address of its own, made when it is first saved and
 * kept with it: the network sees the same station each time, and no other network, nor the
 * radio's own address, is seen there (wpa_supplicant's dedicated address per ESS). */
const MAC_POLICY: &str = "\tmac_addr=3";

/// A locally administered unicast address, as `mac_value` holds one.
fn check_mac(v: &str) -> Result<(), String> {
    let octets: Vec<&str> = v.split(':').collect();
    let hex = octets.len() == 6 && octets.iter().all(|o| o.len() == 2 && o.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    match hex.then(|| u8::from_str_radix(octets[0], 16)) {
        Some(Ok(first)) if first & 0x03 == 0x02 => Ok(()),
        _ => Err("an address is six lowercase hex octets, locally administered and unicast".into()),
    }
}

/// A random address with the locally administered bit set and the group bit clear.
pub fn random_mac() -> io::Result<[u8; 6]> {
    let mut b = [0u8; 6];
    let n = unsafe { libc::getrandom(b.as_mut_ptr() as *mut libc::c_void, b.len(), 0) };
    if n != b.len() as isize {
        return Err(io::Error::last_os_error());
    }
    b[0] = (b[0] & 0xfc) | 0x02;
    Ok(b)
}

/// A new address for a network, as `mac_value` takes it.
fn new_mac() -> Result<String, String> {
    let b = random_mac().map_err(|e| format!("no randomness for a network's address: {e}"))?;
    Ok(b.iter().map(|o| format!("{o:02x}")).collect::<Vec<_>>().join(":"))
}

/// Give each network without an address one of its own.
fn give_addresses(nets: &mut [Network]) -> Result<(), String> {
    for n in nets.iter_mut().filter(|n| n.mac.is_none()) {
        n.mac = Some(new_mac()?);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Added {
    New,
    /// The SSID was already configured; its block was replaced.
    Replaced,
}

fn is_printable(c: char) -> bool {
    c.is_ascii_graphic() || c == ' '
}

/// An SSID this file can hold: 1 to 32 printable ASCII bytes, no quote or backslash.
pub fn check_ssid(ssid: &str) -> Result<(), String> {
    if ssid.is_empty() || ssid.len() > 32 {
        return Err(format!("an SSID is 1 to 32 bytes; this one is {}", ssid.len()));
    }
    if let Some(c) = ssid.chars().find(|&c| !is_printable(c) || c == '"' || c == '\\') {
        return Err(format!(
            "an SSID is printable ASCII without '\"' or '\\'; {c:?} is not allowed"
        ));
    }
    Ok(())
}

/// 8 to 63 printable ASCII without quote or backslash, or 64 hex digits; errors never echo it.
pub fn check_passphrase(pass: &str) -> Result<Psk, String> {
    if pass.len() == 64 && pass.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(Psk::Hex(pass.to_string()));
    }
    if pass.chars().any(|c| !is_printable(c) || c == '"' || c == '\\') {
        return Err(
            "a passphrase is printable ASCII without '\"', '\\' or a newline (or exactly 64 hex \
             digits for a raw PSK)"
                .into(),
        );
    }
    if pass.len() < 8 || pass.len() > 63 {
        return Err(format!(
            "a passphrase is 8 to 63 characters, or exactly 64 hex digits for a raw PSK; this \
             one is {} characters",
            pass.len()
        ));
    }
    Ok(Psk::Passphrase(pass.to_string()))
}

/// The file's text: the header, then one tab-indented block per network.
pub fn render(nets: &[Network]) -> String {
    let mut out = String::from(HEADER);
    for n in nets {
        out.push_str("\nnetwork={\n");
        out.push_str(&format!("\tssid=\"{}\"\n{}\n", n.ssid, key_mgmt(&n.psk)));
        match &n.psk {
            Psk::Passphrase(p) => out.push_str(&format!("{PMF}\n\tpsk=\"{p}\"\n")),
            Psk::Hex(h) => out.push_str(&format!("{PMF}\n\tpsk={h}\n")),
            Psk::Open => {}
        }
        if let Some(m) = &n.mac {
            out.push_str(&format!("{MAC_POLICY}\n\tmac_value={m}\n"));
        }
        out.push_str("}\n");
    }
    out
}

/// What one `network={` block has said so far.
#[derive(Default)]
struct Block {
    ssid: Option<String>,
    psk: Option<Psk>,
    key_mgmt: Option<&'static str>,
    pmf: bool,
    mac_policy: bool,
    mac: Option<String>,
}

impl Block {
    /// The network the closed block names; `n` is its closing line.
    fn close(self, n: usize) -> Result<Network, String> {
        let Some(ssid) = self.ssid else {
            return Err(format!("line {n}: a network block without an ssid"));
        };
        // A file an older kryptikd wrote names neither key management nor protection, and no address.
        let psk = match (self.psk, self.key_mgmt, self.pmf) {
            (Some(p), None, false) => p,
            (Some(p), Some(k), true) if k == key_mgmt(&p) => p,
            (None, Some(KEY_MGMT_OPEN), false) => Psk::Open,
            (None, None, _) => return Err(format!("line {n}: a network block with neither a psk nor key_mgmt=NONE")),
            _ => return Err(format!("line {n}: a block whose key management is not what kryptikd writes for its psk")),
        };
        if self.mac_policy != self.mac.is_some() {
            return Err(format!("line {n}: a block with only one of mac_addr and mac_value"));
        }
        Ok(Network { ssid, psk, mac: self.mac })
    }
}

/// Read back what `render` writes and refuse anything else, which a rewrite would lose or keep
/// unchecked. Errors name the line, never its content.
pub fn parse(text: &str) -> Result<Vec<Network>, String> {
    let mut nets = Vec::new();
    let mut block: Option<Block> = None;
    let foreign = |n: usize| format!("line {n} is not one kryptikd writes; refusing to read a file something else edited");
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        let Some(b) = &mut block else {
            if line.trim().is_empty() || HEADER.lines().any(|h| h == line) {
                continue;
            }
            if line != "network={" {
                return Err(foreign(n));
            }
            block = Some(Block::default());
            continue;
        };
        if line == "}" {
            nets.push(block.take().expect("a block is open").close(n)?);
        } else if let Some(v) = line.strip_prefix("\tssid=\"").and_then(|r| r.strip_suffix('"')) {
            check_ssid(v).map_err(|e| format!("line {n}: {e}"))?;
            if b.ssid.replace(v.to_string()).is_some() {
                return Err(format!("line {n}: a second ssid in one block"));
            }
        } else if let Some(k) = [KEY_MGMT_PASSPHRASE, KEY_MGMT_KEY, KEY_MGMT_OPEN].into_iter().find(|k| *k == line) {
            if b.key_mgmt.replace(k).is_some() {
                return Err(format!("line {n}: a second key_mgmt in one block"));
            }
        } else if line == PMF {
            if std::mem::replace(&mut b.pmf, true) {
                return Err(format!("line {n}: a second ieee80211w in one block"));
            }
        } else if line == MAC_POLICY {
            if std::mem::replace(&mut b.mac_policy, true) {
                return Err(format!("line {n}: a second mac_addr in one block"));
            }
        } else if let Some(v) = line.strip_prefix("\tmac_value=") {
            check_mac(v).map_err(|e| format!("line {n}: {e}"))?;
            if b.mac.replace(v.to_string()).is_some() {
                return Err(format!("line {n}: a second mac_value in one block"));
            }
        } else if let Some(v) = line.strip_prefix("\tpsk=") {
            let quoted = v.strip_prefix('"').and_then(|r| r.strip_suffix('"'));
            let value = match (quoted, check_passphrase(quoted.unwrap_or(v))) {
                (Some(_), Ok(p @ Psk::Passphrase(_))) => p,
                (None, Ok(p @ Psk::Hex(_))) => p,
                (_, Ok(_)) => return Err(format!("line {n}: the psk is quoted the wrong way for its form")),
                (_, Err(e)) => return Err(format!("line {n}: {e}")),
            };
            if b.psk.replace(value).is_some() {
                return Err(format!("line {n}: a second psk in one block"));
            }
        } else {
            return Err(foreign(n));
        }
    }
    if block.is_some() {
        return Err("the last network block is not closed".into());
    }
    Ok(nets)
}

/// The file's text, or none when there is no file yet.
fn read_text(dir: &Path) -> Result<Option<String>, String> {
    let path = conf_path(dir);
    let mut f = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    String::from_utf8(bytes).map(Some).map_err(|_| format!("{}: not UTF-8; refusing to read it", path.display()))
}

/// The configured networks, or none when there is no file yet.
pub fn load(dir: &Path) -> Result<Vec<Network>, String> {
    let Some(text) = read_text(dir)? else { return Ok(Vec::new()) };
    parse(&text).map_err(|e| format!("{}: {e}", conf_path(dir).display()))
}

/// Rewrite in today's form, owner and mode a file an older kryptikd wrote, so the net zone's
/// supplicant reads it, each network's key management and an address of its own; true when it
/// was rewritten. A current, absent or foreign file is left alone.
pub fn refresh(dir: &Path, owner: Option<(u32, u32)>) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;
    let Some(text) = read_text(dir)? else { return Ok(false) };
    let mut nets = parse(&text).map_err(|e| format!("{}: {e}", conf_path(dir).display()))?;
    give_addresses(&mut nets)?;
    let current = render(&nets);
    let md = fs::symlink_metadata(conf_path(dir)).map_err(|e| format!("{}: {e}", conf_path(dir).display()))?;
    let owned = owner.map_or(true, |(u, g)| md.uid() == u && md.gid() == g);
    if current == text && owned && md.mode() & 0o7777 == MODE {
        return Ok(false);
    }
    write_atomic(dir, &current, owner)?;
    Ok(true)
}

/// The SSIDs, in file order. Never a passphrase.
pub fn list(dir: &Path) -> Result<Vec<String>, String> {
    Ok(load(dir)?.into_iter().map(|n| n.ssid).collect())
}

/// Who owns the file on a root run, from the nic zone's identity; `None` keeps the writer's.
pub fn owner_for(zones_dir: &Path) -> Result<Option<(u32, u32)>, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(None);
    }
    let zones = crate::zone::load_all(zones_dir)
        .map_err(|e| format!("cannot tell which identity must own the file: {e}"))?;
    Ok(zones
        .iter()
        .find(|z| z.network == NetworkMode::Nic)
        .and_then(|z| z.uid_base)
        .map(|b| owner_in(b, b)))
}

/// The host ids that own the file for a nic zone whose root is host `uid`/`gid`: its
/// supplicant's user, which reads it, and its root's group, as `MODE` lets both read.
pub fn owner_in(uid: u32, gid: u32) -> (u32, u32) {
    (uid + crate::isolate::WIFI_ID, gid)
}

/// Add a network or replace its block, open when there is no passphrase; nothing is written
/// unless both values pass.
pub fn add(dir: &Path, owner: Option<(u32, u32)>, ssid: &str, passphrase: Option<&str>) -> Result<Added, String> {
    check_ssid(ssid)?;
    let psk = passphrase.map_or(Ok(Psk::Open), check_passphrase)?;
    let mut nets = load(dir)?;
    let outcome = match nets.iter_mut().find(|n| n.ssid == ssid) {
        Some(n) => {
            n.psk = psk;
            Added::Replaced
        }
        None => {
            nets.push(Network { ssid: ssid.to_string(), psk, mac: None });
            Added::New
        }
    };
    // A replaced network keeps its address; a new one, and any an older kryptikd wrote, get one.
    give_addresses(&mut nets)?;
    write_atomic(dir, &render(&nets), owner)?;
    Ok(outcome)
}

/// What `add` did, in the words the command and the daemon both print.
pub fn said(ssid: &str, added: Added, open: bool) -> String {
    match (added, open) {
        (Added::New, false) => format!("added network {ssid:?}"),
        (Added::Replaced, false) => format!("replaced the passphrase of network {ssid:?}"),
        (Added::New, true) => format!("added open network {ssid:?}"),
        (Added::Replaced, true) => format!("network {ssid:?} is now open, joined without a passphrase"),
    }
}

/// Remove one network's block; an unknown SSID is an error and writes nothing.
pub fn forget(dir: &Path, owner: Option<(u32, u32)>, ssid: &str) -> Result<(), String> {
    check_ssid(ssid)?;
    let mut nets = load(dir)?;
    let before = nets.len();
    nets.retain(|n| n.ssid != ssid);
    if nets.len() == before {
        return Err(format!("no network named {ssid:?} is configured"));
    }
    give_addresses(&mut nets)?;
    write_atomic(dir, &render(&nets), owner)
}

/// Create the directory 0711 if missing: the zone's identity reaches the file, nobody lists it.
fn ensure_dir(dir: &Path) -> Result<(), String> {
    match fs::symlink_metadata(dir) {
        Ok(md) if md.is_dir() => Ok(()),
        Ok(_) => Err(format!("{} exists and is not a directory", dir.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = dir.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
            }
            fs::DirBuilder::new()
                .mode(0o711)
                .create(dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
            // Undo the umask.
            fs::set_permissions(dir, fs::Permissions::from_mode(0o711))
                .map_err(|e| format!("{}: {e}", dir.display()))?;
            Ok(())
        }
        Err(e) => Err(format!("{}: {e}", dir.display())),
    }
}

/// Read by its owner, the supplicant's user, and its group, the zone's root; dhcpcd and nobody
/// in the zone cannot.
const MODE: u32 = 0o440;

/// The file, `MODE` and owned as asked, replaced whole.
fn write_atomic(dir: &Path, contents: &str, owner: Option<(u32, u32)>) -> Result<(), String> {
    ensure_dir(dir)?;
    let path = conf_path(dir);
    crate::files::write_atomic(&path, &[contents.as_bytes()], MODE, owner).map_err(|e| format!("{}: {e}", path.display()))
}

/// Restart the net zone on the new file and say how it went; other directories (tests) skip this.
pub fn restart_net_zone(dir: &Path) -> String {
    if dir != Path::new(DEFAULT_DIR) {
        return format!(
            "the net zone was not restarted: its service reads {DEFAULT_DIR}, not {}",
            dir.display()
        );
    }
    if !Path::new(SERVICE_DIR).is_dir() {
        return format!(
            "the net zone was not restarted: no service directory at {SERVICE_DIR} (not an installed system)"
        );
    }
    match std::process::Command::new("s6-svc").args(["-r", SERVICE_DIR]).output() {
        Ok(o) if o.status.success() => "the net zone is restarting with the new file".into(),
        Ok(o) => format!(
            "the net zone was not restarted: s6-svc {}: {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("the net zone was not restarted: s6-svc: {e}"),
    }
}

/// Read the passphrase from stdin, echo off on a terminal; never from argv or the environment.
pub fn read_passphrase(prompt: &str) -> Result<String, String> {
    let mut line = String::new();
    if unsafe { libc::isatty(0) } == 1 {
        line = read_silent(prompt)?;
    } else {
        io::stdin().read_line(&mut line).map_err(|e| format!("reading the passphrase: {e}"))?;
    }
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    if line.is_empty() {
        return Err("no passphrase given".into());
    }
    Ok(line)
}

static CAUGHT: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(sig: libc::c_int) {
    CAUGHT.store(sig, Ordering::SeqCst);
}

/// One line from the terminal on stdin with echo off from before the prompt. Ctrl-C and the
/// like end the read, and take effect once the terminal is as it was.
fn read_silent(prompt: &str) -> Result<String, String> {
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(0, &mut saved) } < 0 {
        return Err(format!("tcgetattr: {}", io::Error::last_os_error()));
    }
    let sigs = [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP];
    let mut old: [libc::sigaction; 4] = unsafe { std::mem::zeroed() };
    unsafe {
        // No SA_RESTART: the signal must interrupt the read.
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_signal as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        for (s, o) in sigs.iter().zip(old.iter_mut()) {
            libc::sigaction(*s, &sa, o);
        }
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        libc::tcsetattr(0, libc::TCSANOW, &quiet);
    }
    let _ = io::stderr().write_all(prompt.as_bytes());
    let mut got = Vec::new();
    let mut buf = [0u8; 256];
    while CAUGHT.load(Ordering::SeqCst) == 0 && !got.ends_with(b"\n") {
        let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
        if n == 0 || (n < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted) {
            break;
        }
        if n > 0 {
            got.extend_from_slice(&buf[..n as usize]);
        }
    }
    unsafe {
        libc::tcsetattr(0, libc::TCSANOW, &saved);
        for (s, o) in sigs.iter().zip(old.iter()) {
            libc::sigaction(*s, o, std::ptr::null_mut());
        }
    }
    let _ = io::stderr().write_all(b"\n");
    let sig = CAUGHT.swap(0, Ordering::SeqCst);
    if sig != 0 {
        unsafe { libc::raise(sig) };
        return Err("interrupted".into());
    }
    String::from_utf8(got).map_err(|_| "the passphrase is not UTF-8".into())
}

#[cfg(test)]
mod tests;
