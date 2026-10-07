//! Wi-Fi credentials for the net zone (docs/design/net-zone.md). kryptikd alone writes the file,
//! 0400 and owned by the host uid of the nic zone's root; the zone gets it read-only on next start.

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

const HEADER: &str = "ctrl_interface=/run/wpa_supplicant\nupdate_config=0\n";

pub fn conf_path(dir: &Path) -> PathBuf {
    dir.join(FILE_NAME)
}

/// A `psk=` value: a passphrase (written quoted) or the raw 64-hex-digit key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Psk {
    Passphrase(String),
    Hex(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    pub ssid: String,
    pub psk: Psk,
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
        match &n.psk {
            Psk::Passphrase(p) => out.push_str(&format!("\tpsk=\"{p}\"\n")),
            Psk::Hex(h) => out.push_str(&format!("\tpsk={h}\n")),
        }
        out.push_str("}\n");
    }
    out
}

/// Read back what `render` writes and refuse anything else, which a rewrite would lose or keep
/// unchecked. Errors name the line, never its content.
pub fn parse(text: &str) -> Result<Vec<Network>, String> {
    let mut nets = Vec::new();
    let mut block: Option<(Option<String>, Option<Psk>)> = None;
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        match &mut block {
            None => {
                if line.trim().is_empty() || HEADER.lines().any(|h| h == line) {
                    continue;
                }
                if line == "network={" {
                    block = Some((None, None));
                    continue;
                }
                return Err(format!(
                    "line {n} is not one kryptikd writes; refusing to read a file something else edited"
                ));
            }
            Some((ssid, psk)) => {
                if line == "}" {
                    match (ssid.take(), psk.take()) {
                        (Some(s), Some(p)) => nets.push(Network { ssid: s, psk: p }),
                        _ => return Err(format!("line {n}: a network block without both an ssid and a psk")),
                    }
                    block = None;
                } else if let Some(v) = line.strip_prefix("\tssid=\"").and_then(|r| r.strip_suffix('"')) {
                    check_ssid(v).map_err(|e| format!("line {n}: {e}"))?;
                    if ssid.replace(v.to_string()).is_some() {
                        return Err(format!("line {n}: a second ssid in one block"));
                    }
                } else if let Some(v) = line.strip_prefix("\tpsk=") {
                    let quoted = v.strip_prefix('"').and_then(|r| r.strip_suffix('"'));
                    let value = match (quoted, check_passphrase(quoted.unwrap_or(v))) {
                        (Some(_), Ok(p @ Psk::Passphrase(_))) => p,
                        (None, Ok(p @ Psk::Hex(_))) => p,
                        (_, Ok(_)) => return Err(format!("line {n}: the psk is quoted the wrong way for its form")),
                        (_, Err(e)) => return Err(format!("line {n}: {e}")),
                    };
                    if psk.replace(value).is_some() {
                        return Err(format!("line {n}: a second psk in one block"));
                    }
                } else {
                    return Err(format!(
                        "line {n} is not one kryptikd writes; refusing to read a file something else edited"
                    ));
                }
            }
        }
    }
    if block.is_some() {
        return Err("the last network block is not closed".into());
    }
    Ok(nets)
}

/// The configured networks, or none when there is no file yet.
pub fn load(dir: &Path) -> Result<Vec<Network>, String> {
    let path = conf_path(dir);
    let mut f = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let text = String::from_utf8(bytes).map_err(|_| format!("{}: not UTF-8; refusing to read it", path.display()))?;
    parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// The SSIDs, in file order. Never a passphrase.
pub fn list(dir: &Path) -> Result<Vec<String>, String> {
    Ok(load(dir)?.into_iter().map(|n| n.ssid).collect())
}

/// The nic zone's identity, to own the file on a root run; `None` keeps the writer's.
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
        .map(|b| (b, b)))
}

/// Add a network or replace its block; nothing is written unless both values pass.
pub fn add(dir: &Path, owner: Option<(u32, u32)>, ssid: &str, passphrase: &str) -> Result<Added, String> {
    check_ssid(ssid)?;
    let psk = check_passphrase(passphrase)?;
    let mut nets = load(dir)?;
    let outcome = match nets.iter_mut().find(|n| n.ssid == ssid) {
        Some(n) => {
            n.psk = psk;
            Added::Replaced
        }
        None => {
            nets.push(Network { ssid: ssid.to_string(), psk });
            Added::New
        }
    };
    write_atomic(dir, &render(&nets), owner)?;
    Ok(outcome)
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

/// The file, 0400 and owned as asked, replaced whole.
fn write_atomic(dir: &Path, contents: &str, owner: Option<(u32, u32)>) -> Result<(), String> {
    ensure_dir(dir)?;
    let path = conf_path(dir);
    crate::files::write_atomic(&path, &[contents.as_bytes()], 0o400, owner).map_err(|e| format!("{}: {e}", path.display()))
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
