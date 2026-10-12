//! Wi-Fi credentials for the net zone (docs/design/net-zone.md). kryptikd alone writes the file,
//! 0440, owned by the nic zone's wpa_supplicant user and grouped with its root, which checks it is
//! there; the zone gets it read-only on next start. A scan of what is in range is asked of the
//! zone, which holds the radios, and its answer read as an untrusted zone's.

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
    /// A network that does not name itself in its beacons, asked for by name in each scan.
    pub hidden: bool,
}

/* Each saved network is joined from an address of its own, made when it is first saved and
 * kept with it: the network sees the same station each time, and no other network, nor the
 * radio's own address, is seen there (wpa_supplicant's dedicated address per ESS). */
const MAC_POLICY: &str = "\tmac_addr=3";

/* A network that hides its name answers only a scan that asks for it by name, so the station
 * names it in its probe requests wherever it is, to anyone listening, until it joins. */
const HIDDEN: &str = "\tscan_ssid=1";

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
        out.push_str(&format!("\tssid=\"{}\"\n", n.ssid));
        if n.hidden {
            out.push_str(&format!("{HIDDEN}\n"));
        }
        out.push_str(&format!("{}\n", key_mgmt(&n.psk)));
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
    hidden: bool,
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
        Ok(Network { ssid, psk, mac: self.mac, hidden: self.hidden })
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
        } else if line == HIDDEN {
            if std::mem::replace(&mut b.hidden, true) {
                return Err(format!("line {n}: a second scan_ssid in one block"));
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

/// Add a network or replace its block, open when there is no passphrase and asked for by name
/// when `hidden`, which a new passphrase keeps, as it would not be found again without it;
/// nothing is written unless both values pass. Says what it did, and whether the network is
/// asked for by name now.
pub fn add(dir: &Path, owner: Option<(u32, u32)>, ssid: &str, passphrase: Option<&str>, hidden: bool) -> Result<(Added, bool), String> {
    check_ssid(ssid)?;
    let psk = passphrase.map_or(Ok(Psk::Open), check_passphrase)?;
    let mut nets = load(dir)?;
    let outcome = match nets.iter_mut().find(|n| n.ssid == ssid) {
        Some(n) => {
            n.psk = psk;
            n.hidden |= hidden;
            (Added::Replaced, n.hidden)
        }
        None => {
            nets.push(Network { ssid: ssid.to_string(), psk, mac: None, hidden });
            (Added::New, hidden)
        }
    };
    // A replaced network keeps its address; a new one, and any an older kryptikd wrote, get one.
    give_addresses(&mut nets)?;
    write_atomic(dir, &render(&nets), owner)?;
    Ok(outcome)
}

/// What `add` did, in the words the command and the daemon both print.
pub fn said(ssid: &str, added: Added, open: bool, hidden: bool) -> String {
    let h = if hidden { "hidden " } else { "" };
    match (added, open) {
        (Added::New, false) => format!("added {h}network {ssid:?}"),
        (Added::Replaced, false) => format!("replaced the passphrase of {h}network {ssid:?}"),
        (Added::New, true) => format!("added {h}open network {ssid:?}"),
        (Added::Replaced, true) => format!("{h}network {ssid:?} is now open, joined without a passphrase"),
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

/// Where the nic zone answers a scan, in its own root (tools/net/netzone-init.sh, `scan_radios`).
const SCAN_FILE: &str = "run/netzone-scan";
/// From the ask to the answer: the zone may first finish a time query (8 s at most), then
/// scans every channel of each radio, a listening scan taking some seconds a radio.
const SCAN_WAIT: std::time::Duration = std::time::Duration::from_secs(40);
const SCAN_CAP: u64 = 64 * 1024;
const MAX_HEARD: usize = 40;
const SECURITIES: [&str; 9] = ["open", "wep", "wpa", "wpa2", "wpa3", "wpa2/wpa3", "owe", "enterprise", "other"];

/// A network the nic zone heard, as its scan put it.
#[derive(Debug, PartialEq)]
pub struct Heard {
    pub ssid: Vec<u8>,
    pub security: &'static str,
    pub signal: i32,
}

/// The nic zone's answer to a scan: its radios, those the kernel holds switched off, and each
/// network heard once, at its strongest, strongest first.
#[derive(Debug, Default, PartialEq)]
pub struct Scan {
    pub radios: Vec<String>,
    pub off: Vec<String>,
    pub heard: Vec<Heard>,
}

/// Ask the nic zone to scan, and read its answer. The ask is a signal, which carries nothing;
/// the answer is a file of the zone's, read as `parse_scan` reads what an untrusted zone wrote.
pub fn scan(zones_dir: &Path) -> Result<Scan, String> {
    use std::os::unix::fs::MetadataExt;
    let zones = crate::zone::load_all(zones_dir).map_err(|e| format!("the zone definitions: {e}"))?;
    let name = zones
        .iter()
        .find(|z| z.network == NetworkMode::Nic)
        .map(|z| z.name.clone())
        .ok_or("no zone holds the network (mode = \"nic\")")?;
    let Ok(crate::registry::State::Running { init: Some(init), .. }) = crate::registry::state(&name) else {
        return Err(format!("the {name} zone is not running"));
    };
    // A new answer is a new file: the zone renames each one into place.
    let stamp = |f: &fs::File| f.metadata().ok().map(|m| (m.ino(), m.mtime(), m.mtime_nsec()));
    let before = init.file_in_root(SCAN_FILE).as_ref().and_then(stamp);
    if let Err(e) = init.signal(libc::SIGUSR1) {
        // Ended since the registry said it runs, as a zone restarting after a save does.
        return Err(if init.still_alive() {
            format!("the {name} zone could not be asked: {e}")
        } else {
            format!("the {name} zone is not running")
        });
    }
    let until = std::time::Instant::now() + SCAN_WAIT;
    while std::time::Instant::now() < until {
        std::thread::sleep(std::time::Duration::from_millis(250));
        if let Some(f) = init.file_in_root(SCAN_FILE).filter(|f| stamp(f) != before) {
            let mut raw = Vec::new();
            f.take(SCAN_CAP).read_to_end(&mut raw).map_err(|e| format!("the {name} zone's answer: {e}"))?;
            return Ok(parse_scan(&String::from_utf8_lossy(&raw)));
        }
        if !init.still_alive() {
            return Err(format!("the {name} zone stopped before it answered"));
        }
    }
    Err(format!("the {name} zone did not answer within {} s", SCAN_WAIT.as_secs()))
}

/// Read an answer the nic zone wrote: `radios NAME...` (or `none`), `off NAME` for a radio
/// switched off, and a line per network heard: its signal in dBm, its security and its SSID as
/// iw escapes one, tab-separated. The zone is untrusted, so a line of any other form is left
/// out, and so is a network with no name, which cannot be added by it.
pub fn parse_scan(text: &str) -> Scan {
    let plain = |n: &str| (1..16).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let mut s = Scan::default();
    for line in text.lines().take(1000) {
        if let Some(names) = line.strip_prefix("radios ") {
            s.radios = names.split(' ').filter(|&n| n != "none" && plain(n)).map(String::from).collect();
        } else if let Some(n) = line.strip_prefix("off ").filter(|&n| plain(n)) {
            s.off.push(n.to_string());
        } else if let Some(h) = heard_line(line) {
            match s.heard.iter_mut().find(|o| o.ssid == h.ssid && o.security == h.security) {
                Some(o) => o.signal = o.signal.max(h.signal),
                None => s.heard.push(h),
            }
        }
    }
    s.heard.sort_by(|a, b| b.signal.cmp(&a.signal).then_with(|| a.ssid.cmp(&b.ssid)));
    s.heard.truncate(MAX_HEARD);
    s
}

fn heard_line(line: &str) -> Option<Heard> {
    let mut f = line.split('\t');
    let (signal, security, ssid) = (f.next()?, f.next()?, f.next()?);
    if f.next().is_some() {
        return None;
    }
    let signal = signal.parse::<i32>().ok().filter(|s| (-150..=0).contains(s))?;
    let security = SECURITIES.into_iter().find(|s| *s == security)?;
    let ssid = unescape_iw(ssid).filter(|b| (1..=32).contains(&b.len()) && b.iter().any(|c| *c != 0))?;
    Some(Heard { ssid, security, signal })
}

/// An SSID as iw prints one: printable ASCII but a backslash, and \xHH for every other byte.
fn unescape_iw(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            let hex = b.get(i + 1..i + 4).filter(|h| h[0] == b'x' && h[1..].iter().all(u8::is_ascii_hexdigit))?;
            out.push(u8::from_str_radix(std::str::from_utf8(&hex[1..]).ok()?, 16).ok()?);
            i += 4;
        } else if b[i] == b' ' || b[i].is_ascii_graphic() {
            out.push(b[i]);
            i += 1;
        } else {
            return None;
        }
    }
    Some(out)
}

/// An SSID for a terminal: quoted as Rust quotes a string where it is UTF-8, so nothing
/// unprintable reaches the screen, else with \xHH for each byte that is not printable ASCII.
pub fn shown(ssid: &[u8]) -> String {
    match std::str::from_utf8(ssid) {
        Ok(s) => format!("{s:?}"),
        Err(_) => {
            let mut out = String::from("\"");
            for &c in ssid {
                if c == b' ' || (c.is_ascii_graphic() && c != b'"' && c != b'\\') {
                    out.push(c as char);
                } else {
                    out.push_str(&format!("\\x{c:02x}"));
                }
            }
            out.push('"');
            out
        }
    }
}

/// A scan in words, a line each: a radio switched off, then every network heard with its
/// security and signal, and whether it is saved.
pub fn scan_said(s: &Scan, saved: &[String]) -> String {
    if s.radios.is_empty() {
        return "the net zone has no Wi-Fi radio\n".into();
    }
    let mut out = String::new();
    for r in &s.off {
        out.push_str(&format!("radio {r} is switched off, by its switch or an airplane-mode key\n"));
    }
    if s.heard.is_empty() {
        out.push_str("no network heard\n");
    }
    for h in &s.heard {
        let security = match h.security {
            "open" => "open",
            "wep" => "WEP, which Kryptik does not join",
            "wpa" => "WPA",
            "wpa2" => "WPA2",
            "wpa3" => "WPA3",
            "wpa2/wpa3" => "WPA2/WPA3",
            "owe" => "OWE, which Kryptik does not join yet",
            "enterprise" => "802.1X, which Kryptik does not join",
            _ => "another kind",
        };
        let is_saved = std::str::from_utf8(&h.ssid).is_ok_and(|n| saved.iter().any(|s| s == n));
        out.push_str(&format!("{}  {security}  {} dBm{}\n", shown(&h.ssid), h.signal, if is_saved { "  saved" } else { "" }));
    }
    out
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
