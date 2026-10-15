//! What a zone's client may bind, and how its titles and app_ids carry the zone's name.
//! Nothing else is advertised: no capture, global input, layer shell (nothing may draw over the
//! chrome), primary selection or data control, virtual keyboard, output management or
//! activation. The data device a zone's clients bind is the proxy's own (clipboard.rs), never
//! the compositor's: copy and paste stays inside the zone, and the broker is the only channel
//! between zones.

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
    // A cursor by name from the compositor's own theme; an image a zone draws is never taken.
    ("wp_cursor_shape_manager_v1", 1),
];

pub fn allowed_version(interface: &str) -> Option<u32> {
    ALLOWED.iter().find(|(n, _)| *n == interface).map(|(_, v)| *v)
}

/// What the proxy serves itself: a bind of one, and every request on the objects they make, is
/// answered here and never reaches the compositor.
pub const SERVED: &[&str] = &["wl_data_device_manager", "wl_data_source", "wl_data_device", "wl_data_offer"];

pub fn served(interface: &str) -> bool {
    SERVED.contains(&interface)
}

/// The globals the proxy advertises as its own, on every registry, while the compositor's of the
/// same interface stays hidden: a zone never needs the compositor to offer them. Version 3 is
/// the last a selection needs.
pub const OWN_GLOBALS: &[(&str, u32)] = &[("wl_data_device_manager", 3)];
/// Their registry names, from the top of the range, which a compositor numbering its globals
/// from 1 does not reach.
pub const OWN_GLOBAL_BASE: u32 = 0xFFFF_FF00;

pub fn own_version(interface: &str) -> Option<u32> {
    OWN_GLOBALS.iter().find(|(n, _)| *n == interface).map(|(_, v)| *v)
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

/* Resource bounds per client connection and across a zone's connections. Passing one ends the
 * connection, as Wayland answers a pool or a window it will not make only with a protocol error,
 * and a browser draws all its windows over one connection: the bounds sit above what Firefox
 * needs on two 4K heads (docs/design/resource-limits-and-ephemeral-zones.md). */
pub const MAX_OBJECTS: usize = 4096;
/// Id slots per range: libwayland reuses freed ids, so only a client that never does reaches this.
pub const MAX_ID_SLOTS: usize = 2 * MAX_OBJECTS;
pub const MAX_PENDING_BYTES: usize = 1 << 20; // per direction
pub const MAX_PENDING_FDS: usize = 64;
/// A browser's windows, dialogs and picture-in-picture all count.
pub const MAX_TOPLEVELS_PER_SESSION: usize = 32;
pub const MAX_TOPLEVELS_PER_ZONE: usize = 64;
/// Menus and their submenus, tooltips: the compositor keeps each inside its window.
pub const MAX_POPUPS_PER_SESSION: usize = 16;
/// Each pool is a mapping in dwl: far below vm.max_map_count, where dwl's own mappings would fail.
pub const MAX_SHM_POOLS_PER_SESSION: usize = 128;
pub const MAX_SHM_POOLS_PER_ZONE: usize = 256;
pub const MAX_SHM_POOL_BYTES: usize = 128 << 20; // room for a 6K RGBA frame and stride padding
/// What dwl maps for a zone at one time. A page dwl reads before the zone wrote it is charged to
/// dwl, not to the zone's memory_max; these bound that while the pools live, not after.
pub const MAX_SHM_BYTES_PER_SESSION: usize = 1 << 30;
pub const MAX_SHM_BYTES_PER_ZONE: usize = 1 << 30;
/// A pool a surface may still show stays charged, so these bound what one session can hold.
pub const MAX_SUBSURFACES_PER_SESSION: usize = 256;
pub const MAX_HELD_PER_SURFACE: usize = 64;
/// The types the zone 0 move gesture carries, the broker's list (kryptikd's broker.rs
/// MIME_TYPES): fixed, as a free-form label would be a channel. The first one offered is taken.
pub const MOVE_TYPES: &[&str] = &[
    "text/plain;charset=utf-8",
    "text/plain",
    "text/html",
    "text/uri-list",
    "image/png",
    "image/jpeg",
    "application/octet-stream",
];
/// What one move carries at most, as much as the broker's clipboard holds.
pub const MAX_MOVE_BYTES: usize = 1 << 20;
/// Copies one session may hold at once: a cancelled one is its client's to destroy.
pub const MAX_DATA_SOURCES_PER_SESSION: usize = 64;
/// The types one copy offers, each a short MIME name that other clients of the zone are shown.
pub const MAX_MIME_TYPES: usize = 32;
pub const MAX_MIME_BYTES: usize = 256;

#[cfg(test)]
mod tests;
