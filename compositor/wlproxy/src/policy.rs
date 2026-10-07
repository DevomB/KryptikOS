//! What a zone's client may bind, and how its titles and app_ids carry the zone's name.
//! Nothing else is advertised: no capture, global input, layer shell (nothing may draw over the
//! chrome), clipboard (the broker is the only cross-zone channel), virtual keyboard, output
//! management or activation.

/// Bindable interfaces, capped at the tables' versions: a newer request could not be parsed.
pub const ALLOWED: &[(&str, u32)] = &[
    ("wl_compositor", 6),
    ("wl_subcompositor", 1),
    ("wl_shm", 2),
    ("wl_seat", 9),
    ("wl_output", 4),
    ("xdg_wm_base", 6),
    ("zxdg_decoration_manager_v1", 1),
    ("wp_viewporter", 1),
];

pub fn allowed_version(interface: &str) -> Option<u32> {
    ALLOWED.iter().find(|(n, _)| *n == interface).map(|(_, v)| *v)
}

/// The most bytes a rewritten title may carry; only one line is ever shown.
pub const MAX_TITLE_BYTES: usize = 256;

/// Prefix a title with `[zone] `; a claimed `[vault] ` follows the real one: `[work] [vault] ...`.
pub fn title_for(zone: &str, title: &str) -> String {
    // Titles reach dwl's status lines and terminal chrome: controls and bidi marks become spaces.
    let title: String = title.chars().map(|c| {
        if c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}') { ' ' } else { c }
    }).collect();
    let mut out = format!("[{zone}] {title}");
    bound_utf8(&mut out, MAX_TITLE_BYTES);
    out
}

/// Cut `s` to `max` bytes with a `...`, on a char boundary: `String::truncate` panics inside one.
fn bound_utf8(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    let mut cut = max.saturating_sub(3);
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
    s.push_str("...");
}

/// `kryptik.<zone>.<claimed>`, the claim cut to `[A-Za-z0-9_-]` so it cannot pass for another zone.
pub fn app_id_for(zone: &str, claimed: &str) -> String {
    let cleaned: String = claimed
        .chars()
        .take(64)
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    format!("kryptik.{zone}.{}", if cleaned.is_empty() { "app".to_string() } else { cleaned })
}

// Resource bounds per client connection and across a zone's connections.
pub const MAX_OBJECTS: usize = 4096;
/// Id slots per range: libwayland reuses freed ids, so only a client that never does reaches this.
pub const MAX_ID_SLOTS: usize = 2 * MAX_OBJECTS;
pub const MAX_PENDING_BYTES: usize = 1 << 20; // per direction
pub const MAX_PENDING_FDS: usize = 64;
pub const MAX_TOPLEVELS_PER_SESSION: usize = 8;
pub const MAX_TOPLEVELS_PER_ZONE: usize = 64;
pub const MAX_SHM_POOLS_PER_SESSION: usize = 32;
pub const MAX_SHM_POOLS_PER_ZONE: usize = 128;
pub const MAX_SHM_POOL_BYTES: usize = 64 << 20; // room for a 4K RGBA frame and stride padding
pub const MAX_SHM_BYTES_PER_SESSION: usize = 128 << 20;
pub const MAX_SHM_BYTES_PER_ZONE: usize = 256 << 20;

#[cfg(test)]
mod tests;
