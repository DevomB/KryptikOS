//! Zone 0's mixer, kryptik-sound (docs/design/laptop.md): the zones it serves, the directory a
//! zone's socket is in, and the word that takes a stopped zone's microphone back.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use crate::zone::Zone;

/// The mixer's directory, which its service makes as root.
pub const RUN_DIR: &str = "/run/kryptik-sound";
/// Where a zone finds its socket's directory.
pub const IN_ZONE: &str = "/run/kryptik/sound";

/// The mixer's list, "NAME UID" a line: every zone with an identity whose file lets it play,
/// never the nic zone (`Zone::sound`). The uid is the one the zone's root maps to, the only
/// peer its socket takes.
pub fn zones_list(zones: &[Zone]) -> String {
    zones
        .iter()
        .filter(|z| z.sound)
        .filter_map(|z| z.uid_base.map(|uid| format!("{} {uid}\n", z.name)))
        .collect()
}

/// A zone's socket directory, if the mixer's service made it: one root owns, under directories
/// root owns, so the mixer, which writes in it, cannot have it name another place.
pub fn zone_dir(name: &str) -> Option<PathBuf> {
    let p = PathBuf::from(RUN_DIR).join("zones").join(name);
    let md = std::fs::symlink_metadata(&p).ok()?;
    (md.is_dir() && std::os::unix::fs::MetadataExt::uid(&md) == 0).then_some(p)
}

/// Take a stopped zone's grant of the microphone back, if it held it; nothing if no mixer runs.
pub fn revoke(name: &str) {
    let Ok(mut s) = UnixStream::connect(format!("{RUN_DIR}/control/socket")) else {
        return;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(1)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(1)));
    if s.write_all(format!("revoke {name}\n").as_bytes()).is_ok() {
        let mut answer = [0u8; 64];
        let _ = s.read(&mut answer);
    }
}

#[cfg(test)]
mod tests;
