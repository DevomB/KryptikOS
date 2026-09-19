//! Wi-Fi credentials for the net zone (docs/design/net-zone.md).
//!
//! The net zone owns the wireless interface and runs wpa_supplicant inside
//! itself. The passphrases the supplicant needs are kept in zone 0, in one
//! file that kryptikd writes and nothing else touches:
//!
//!   /var/lib/kryptik/wifi/wpa_supplicant.conf    0400, owned by the nic zone's identity
//!
//! The zone sees it read-only at /etc/wpa_supplicant.conf (rootfs.rs) from
//! its next start; the zone is ephemeral and the file is bound in at
//! launch, so a change reaches it through a restart of the net-zone
//! service. The session changes the file through the launch daemon
//! (`wifi-add`, `wifi-forget`, `wifi-list` in serve.rs); root at a terminal
//! and the tests use `kryptikd wifi`. Both come here.
//!
//! Ownership, and why it is not root's: inside the zone, root is host uid N
//! (`[identity] uid_base`), so a root:root 0600 file bound in would be
//! EACCES to the one party that must read it. Nobody else on the host runs
//! as N. The directory is root:root 0711: the zone's identity traverses it,
//! nobody else lists it. On an unprivileged run (a developer instance) the
//! writer keeps the file, which is the only identity such a zone has.
//!
//! kryptikd never derives keys. A passphrase is written quoted and the
//! supplicant derives the PSK from it; exactly 64 hex digits are written
//! unquoted, which the supplicant reads as the raw PSK. The file holds the
//! two header lines below and the blocks kryptikd wrote, nothing else, and
//! a file with anything else in it is refused rather than rewritten.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

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

/// What the `psk=` line holds: a passphrase the supplicant derives the key
/// from, or the 64-hex-digit key itself.
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

// --- validation ----------------------------------------------------------------

fn is_printable(c: char) -> bool {
    c.is_ascii_graphic() || c == ' '
}

/// An SSID as this file can hold it: 1 to 32 bytes of printable ASCII,
/// without the quote and backslash the supplicant would read as syntax and
/// without a newline or any other control character.
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

/// A passphrase as the supplicant accepts it: 8 to 63 printable ASCII
/// characters without '"', '\\' or a newline, or exactly 64 hex digits for
/// a raw PSK. The message never repeats any of the passphrase.
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

// --- the file's text -------------------------------------------------------------

/// The file, exactly as kryptikd writes it: the header, then one block per
/// network in order, tab-indented like the supplicant's own examples.
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

/// Read back what `render` wrote, and only that: the two header lines,
/// blank lines, and blocks of exactly an ssid and a psk. Anything else
/// means someone edited the file, and rewriting it would lose their change
/// or carry something kryptikd did not check; both are refused. A value
/// that fails its own rule is reported by line, never by content.
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

// --- the file on disk ------------------------------------------------------------

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

/// Who owns the file: the nic zone's identity from the zone directory, on a
/// root run. `None` keeps the writer's ownership: an unprivileged run, or a
/// zone set whose nic zone declares no identity (a developer host either
/// way; on the target every zone declares one).
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

/// Add a network, or replace the block of one already configured. Nothing
/// is written unless both values pass their rules.
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

/// Remove one network's block. A network that is not there is an error and
/// the file is not touched.
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

/// The directory, root:root 0711 when it has to be made: search-only for
/// others, so the zone's identity can reach the file and nobody else can
/// list what is there.
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
            // The umask applied to the create; the mode is meant literally.
            fs::set_permissions(dir, fs::Permissions::from_mode(0o711))
                .map_err(|e| format!("{}: {e}", dir.display()))?;
            Ok(())
        }
        Err(e) => Err(format!("{}: {e}", dir.display())),
    }
}

/// Write the whole file at once: a new `.tmp` beside it, 0400 and owned as
/// asked before it has a name anyone reads, fsync, then rename over the
/// old file. A reader sees the old file or the new one, never a partial
/// one, and a crash leaves at most a `.tmp` that the next write replaces.
fn write_atomic(dir: &Path, contents: &str, owner: Option<(u32, u32)>) -> Result<(), String> {
    ensure_dir(dir)?;
    let path = conf_path(dir);
    let tmp = dir.join(format!("{FILE_NAME}.tmp"));
    // A leftover from an interrupted write is root's and 0400; an
    // unprivileged writer could not open it for writing, so it goes first.
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", tmp.display())),
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    let finish = |r: Result<(), String>| -> Result<(), String> {
        if r.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        r
    };
    finish(f.write_all(contents.as_bytes()).map_err(|e| format!("{}: {e}", tmp.display())))?;
    finish(f.sync_all().map_err(|e| format!("{}: fsync: {e}", tmp.display())))?;
    // Literal 0400 whatever the umask did (it can only have removed bits,
    // and there are none to remove, but the intent is stated once).
    finish(
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o400))
            .map_err(|e| format!("{}: chmod: {e}", tmp.display())),
    )?;
    if let Some((uid, gid)) = owner {
        if unsafe { libc::fchown(f.as_raw_fd(), uid, gid) } < 0 {
            return finish(Err(format!(
                "{}: chown to {uid}:{gid}: {}",
                tmp.display(),
                io::Error::last_os_error()
            )));
        }
    }
    drop(f);
    finish(fs::rename(&tmp, &path).map_err(|e| format!("rename {} over {}: {e}", tmp.display(), path.display())))?;
    // The rename is durable once the directory is. Best effort: a
    // filesystem that refuses to fsync a directory still renamed atomically.
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Restart the net zone so it comes back with the current file. Reported,
/// never fatal: the file is written either way, and the reply says whether
/// the zone will see it now or at its next start. Nothing is restarted for
/// a directory other than the one the service reads, so a test daemon
/// working under its own directory leaves an installed net zone alone.
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

/// One line from standard input, for `kryptikd wifi add`: with echo off
/// and a prompt when that is a terminal, silently when it is a pipe (the
/// `kryptik` command reads the terminal itself and pipes the line). The
/// passphrase never comes from argv or the environment.
pub fn read_passphrase(prompt: &str) -> Result<String, String> {
    let tty = unsafe { libc::isatty(0) } == 1;
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    if tty {
        if unsafe { libc::tcgetattr(0, &mut saved) } < 0 {
            return Err(format!("tcgetattr: {}", io::Error::last_os_error()));
        }
        let mut raw = saved;
        raw.c_lflag &= !libc::ECHO;
        let _ = io::stderr().write_all(prompt.as_bytes());
        let _ = io::stderr().flush();
        if unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &raw) } < 0 {
            return Err(format!("tcsetattr: {}", io::Error::last_os_error()));
        }
    }
    let mut line = String::new();
    let read = io::stdin().read_line(&mut line);
    if tty {
        unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &saved) };
        let _ = io::stderr().write_all(b"\n");
    }
    read.map_err(|e| format!("reading the passphrase: {e}"))?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    if line.is_empty() {
        return Err("no passphrase given".into());
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kryptik-wifi-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn add_list_forget_round_trip() {
        let dir = tmpdir("roundtrip");
        assert_eq!(list(&dir).unwrap(), Vec::<String>::new(), "no file is no networks");
        assert_eq!(add(&dir, None, "Home", "correct horse battery").unwrap(), Added::New);
        assert_eq!(add(&dir, None, "Cafe Wifi", "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef").unwrap(), Added::New);
        assert_eq!(list(&dir).unwrap(), vec!["Home", "Cafe Wifi"]);
        let text = fs::read_to_string(conf_path(&dir)).unwrap();
        assert_eq!(
            text,
            "ctrl_interface=/run/wpa_supplicant\nupdate_config=0\n\
             \nnetwork={\n\tssid=\"Home\"\n\tpsk=\"correct horse battery\"\n}\n\
             \nnetwork={\n\tssid=\"Cafe Wifi\"\n\tpsk=0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef\n}\n"
        );
        let md = fs::metadata(conf_path(&dir)).unwrap();
        assert_eq!(md.mode() & 0o7777, 0o400);
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o7777, 0o711);
        forget(&dir, None, "Home").unwrap();
        assert_eq!(list(&dir).unwrap(), vec!["Cafe Wifi"]);
        let text = fs::read_to_string(conf_path(&dir)).unwrap();
        assert!(text.starts_with(HEADER), "the header stays: {text:?}");
        assert!(!text.contains("Home"));
        assert!(text.contains("\tssid=\"Cafe Wifi\"\n"));
        forget(&dir, None, "Cafe Wifi").unwrap();
        assert_eq!(fs::read_to_string(conf_path(&dir)).unwrap(), HEADER, "an emptied file keeps its header");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_passphrase_is_quoted_and_a_raw_psk_is_not() {
        assert_eq!(check_passphrase("eight ch").unwrap(), Psk::Passphrase("eight ch".into()));
        let hex = "f".repeat(64);
        assert_eq!(check_passphrase(&hex).unwrap(), Psk::Hex(hex.clone()));
        let nets = vec![
            Network { ssid: "a".into(), psk: Psk::Passphrase("pass word".into()) },
            Network { ssid: "b".into(), psk: Psk::Hex(hex.clone()) },
        ];
        let text = render(&nets);
        assert!(text.contains("\tpsk=\"pass word\"\n"));
        assert!(text.contains(&format!("\tpsk={hex}\n")));
        assert_eq!(parse(&text).unwrap(), nets, "what was written reads back");
    }

    #[test]
    fn every_rule_refuses_what_it_names() {
        let long_ssid = "x".repeat(33);
        for (ssid, rule) in [
            ("", "1 to 32 bytes"),
            (long_ssid.as_str(), "1 to 32 bytes"),
            ("say \"hi\"", "'\"'"),
            ("back\\slash", "'\\'"),
            ("two\nlines", "printable"),
            ("tab\there", "printable"),
            ("caf\u{e9}", "printable"),
        ] {
            let e = check_ssid(ssid).unwrap_err();
            assert!(e.contains(rule), "{ssid:?}: {e}");
        }
        assert!(check_ssid("Home").is_ok());
        assert!(check_ssid(&"x".repeat(32)).is_ok());
        assert!(check_ssid(" spaces are fine ").is_ok());

        let (p64, p65, not_hex) = ("p".repeat(64), "p".repeat(65), format!("{}g", "f".repeat(63)));
        for (pass, rule) in [
            ("seven c", "8 to 63"),
            (p64.as_str(), "8 to 63"),
            (p65.as_str(), "8 to 63"),
            ("quote\"inside", "printable ASCII"),
            ("back\\slash", "printable ASCII"),
            ("new\nline", "printable ASCII"),
            (not_hex.as_str(), "8 to 63"),
        ] {
            let e = check_passphrase(pass).unwrap_err();
            assert!(e.contains(rule), "{pass:?}: {e}");
            assert!(!e.contains(pass), "the message must not repeat the passphrase: {e}");
        }
        assert!(check_passphrase("eight ch").is_ok());
        assert!(check_passphrase(&"p".repeat(63)).is_ok());
        assert!(check_passphrase(&"0a".repeat(32)).is_ok());

        // A refusal writes nothing, and a refused add on an existing file
        // leaves it as it was.
        let dir = tmpdir("refusals");
        assert!(add(&dir, None, "bad\"ssid", "long enough").is_err());
        assert!(!conf_path(&dir).exists(), "nothing written on refusal");
        add(&dir, None, "Home", "long enough").unwrap();
        let before = fs::read(conf_path(&dir)).unwrap();
        let ino = fs::metadata(conf_path(&dir)).unwrap().ino();
        assert!(add(&dir, None, "Home", "short").is_err());
        assert!(forget(&dir, None, "Nowhere").unwrap_err().contains("no network named"));
        assert_eq!(fs::read(conf_path(&dir)).unwrap(), before);
        assert_eq!(fs::metadata(conf_path(&dir)).unwrap().ino(), ino, "a refusal does not rewrite the file");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn adding_an_ssid_again_replaces_its_block_in_place() {
        let dir = tmpdir("replace");
        add(&dir, None, "First", "first pass").unwrap();
        add(&dir, None, "Second", "second pass").unwrap();
        assert_eq!(add(&dir, None, "First", "changed pass").unwrap(), Added::Replaced);
        let nets = load(&dir).unwrap();
        assert_eq!(nets.len(), 2, "replaced, not appended");
        assert_eq!(nets[0], Network { ssid: "First".into(), psk: Psk::Passphrase("changed pass".into()) });
        assert_eq!(nets[1].ssid, "Second", "order kept");
        assert_eq!(fs::read_to_string(conf_path(&dir)).unwrap().matches("network={").count(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_write_is_a_rename_with_nothing_left_behind() {
        let dir = tmpdir("atomic");
        add(&dir, None, "Home", "long enough").unwrap();
        let ino = fs::metadata(conf_path(&dir)).unwrap().ino();
        // A stale temporary from an interrupted earlier write is replaced.
        fs::write(dir.join(format!("{FILE_NAME}.tmp")), "junk").unwrap();
        add(&dir, None, "Other", "long enough").unwrap();
        assert_ne!(fs::metadata(conf_path(&dir)).unwrap().ino(), ino, "a new inode replaced the old file");
        let names: Vec<String> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(names, vec![FILE_NAME], "only the file itself is in the directory");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_kryptikd_did_not_write_is_refused_not_rewritten() {
        for bad in [
            "network={\n\tssid=\"a\"\n\tpsk=\"long enough\"\n}\nap_scan=1\n",
            "network={\n\tssid=\"a\"\n\tkey_mgmt=NONE\n\tpsk=\"long enough\"\n}\n",
            "network={\n\tssid=\"a\"\n}\n",
            "network={\n\tssid=\"a\"\n\tpsk=\"long enough\"\n",
            "network={\n\tssid=\"a\"\n\tpsk=long enough\n}\n",
            "network={\n\tssid=\"a\"\n\tpsk=\"short\"\n}\n",
            "  ssid=\"a\"\n",
        ] {
            let e = parse(bad).unwrap_err();
            assert!(e.contains("line ") || e.contains("not closed"), "{bad:?}: {e}");
            assert!(!e.contains("long enough"), "{e}");
        }
        assert!(parse("\n\nctrl_interface=/run/wpa_supplicant\n\nupdate_config=0\n\n").unwrap().is_empty(), "blank lines are tolerated");
        let dir = tmpdir("foreign");
        fs::create_dir_all(&dir).unwrap();
        fs::write(conf_path(&dir), "ap_scan=1\n").unwrap();
        let e = add(&dir, None, "Home", "long enough").unwrap_err();
        assert!(e.contains("something else edited"), "{e}");
        assert_eq!(fs::read_to_string(conf_path(&dir)).unwrap(), "ap_scan=1\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_restart_is_reported_not_attempted_for_another_directory() {
        let m = restart_net_zone(Path::new("/nonexistent/wifi"));
        assert!(m.contains("not restarted") && m.contains(DEFAULT_DIR), "{m}");
    }
}
