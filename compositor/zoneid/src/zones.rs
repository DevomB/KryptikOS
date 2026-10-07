//! Zone identities from a zone directory; only `[zone] name` and the `[ui]` channels are read.

use std::path::{Path, PathBuf};

use crate::identity::ZoneIdentity;
use crate::toml;

/// Load every `*.toml` in `dir`, skipping zones with no `[ui] border_color` to collide.
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
        // kryptikd goes by [zone] name; the file stem is only a fallback.
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

/// The zone directory beside this crate in the source tree.
pub fn shipped_zone_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compartments/zones")
}

#[cfg(test)]
mod tests;
