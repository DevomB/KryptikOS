//! Zone identities from a directory of zone files.
//!
//! The same files kryptikd installs under /etc/kryptik/zones: `[zone] name`
//! and the four `[ui]` channels are all this crate reads from them.

use std::path::{Path, PathBuf};

use crate::identity::ZoneIdentity;
use crate::toml;

/// Read every `*.toml` in `dir` as a zone definition.
///
/// A file without a `[ui] border_color` is skipped rather than failing the
/// run: the directory is a zone directory, not a palette file, and a zone that
/// does not configure a colour is a separate problem from zones whose colours
/// collide.
pub fn load_zones(dir: &Path) -> Result<Vec<ZoneIdentity>, String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?;

    let mut paths: Vec<PathBuf> = Vec::new();
    for e in entries {
        let e = e.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) == Some("toml") {
            paths.push(p);
        }
    }
    // Sorted so the report is stable across filesystems.
    paths.sort();

    let mut out = Vec::new();
    for p in paths {
        let text = std::fs::read_to_string(&p)
            .map_err(|e| format!("cannot read {}: {e}", p.display()))?;
        let doc = toml::parse(&text).map_err(|e| format!("{}: {e}", p.display()))?;

        let Some(color) = doc.get("ui", "border_color") else {
            continue;
        };
        // Fall back to the filename only if the file does not name itself;
        // the [zone] name is authoritative because that is what kryptikd uses.
        let name = doc
            .get("zone", "name")
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                p.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("?")
                    .to_string()
            });

        let id = ZoneIdentity::new(
            &name,
            color,
            doc.get("ui", "border_pattern"),
            doc.get("ui", "glyph"),
            doc.get("ui", "label"),
        )
        .map_err(|e| format!("{}: [ui] {e}", p.display()))?;
        out.push(id);
    }
    Ok(out)
}

/// The zone directory this crate ships beside, for its own tests.
pub fn shipped_zone_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compartments/zones")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distinct::{analyze, Thresholds, COMPOSITOR_COLOURS, MIN_DELTA_E};
    use crate::identity::Channel;

    /// The header dwl is built with holds exactly the colours zoneid audits:
    /// it cannot draw one (a focus shade, say) that no check has seen.
    #[test]
    fn header_colours_are_audited() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/desktop/zone-colours.h");
        let header = std::fs::read_to_string(&path).expect("zone-colours.h");
        let mut drawn: Vec<String> = header
            .match_indices("0x")
            .filter_map(|(i, _)| header.get(i + 2..i + 10))
            .filter(|h| h.ends_with("ff") && h.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(|h| format!("#{}", h[..6].to_ascii_lowercase()))
            .collect();
        let mut audited: Vec<String> = load_zones(&shipped_zone_dir())
            .expect("the shipped zone files parse")
            .iter()
            .map(|z| z.color.to_hex())
            .chain(COMPOSITOR_COLOURS.iter().map(|(_, hex)| hex.to_string()))
            .collect();
        drawn.sort();
        audited.sort();
        assert_eq!(drawn, audited);
    }

    /// The claim the whole crate exists to make good on: the zone files
    /// that ship are distinguishable. Every pair differs in colour under
    /// every vision model by at least the floor, and every zone carries all
    /// four channels with a distinct value in each.
    #[test]
    fn the_shipped_zone_files_pass_the_invariant() {
        let zones = load_zones(&shipped_zone_dir()).expect("the shipped zone files parse");
        assert!(zones.len() >= 6, "expected the six shipped zones, found {}", zones.len());
        let r = analyze(&zones, Thresholds::default());
        assert!(!r.is_fatal(), "critical: {:?}", r.critical().map(|c| &c.detail).collect::<Vec<_>>());
        assert!(r.collisions.is_empty(), "no collision of any severity: {:?}", r.collisions);
        assert!(r.contrast.is_empty(), "every border clears 3:1 on both backgrounds: {:?}", r.contrast);
        assert!(r.missing.is_empty(), "every zone has a non-colour channel: {:?}", r.missing);
        for z in &zones {
            let ch = z.present_channels();
            for want in [Channel::Color, Channel::Pattern, Channel::Glyph, Channel::Label] {
                assert!(ch.contains(&want), "{}: no {}", z.zone, want.name());
            }
        }
        for (_, d, a, b) in &r.worst_per_vision {
            assert!(*d >= MIN_DELTA_E, "{a}/{b}: {d:.2} below the floor");
        }
    }
}
