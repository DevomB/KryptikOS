//! What a zone's client may reach through the proxy, and what the proxy
//! changes on the way.
//!
//! The allowlist is the boundary. Globals not on it are never advertised
//! to the client, so they cannot be bound: no screen capture, no global
//! input, no layer shell (nothing from a zone may draw over the trusted
//! chrome), no data-device or primary-selection clipboard (the broker is
//! the only cross-zone channel), no virtual keyboard, no output management,
//! no activation. A client that binds something it was not told about is
//! either broken or probing, and is disconnected.
//!
//! Identity is text the client cannot control: every xdg_toplevel title and
//! app_id passes through here and comes out prefixed with the zone name, so
//! the compositor and the trusted chrome know whose window it is whatever
//! the application claims.

/// Interfaces a zone client may bind, with the highest version the proxy
/// will forward. The version cap is what the generated tables know; a
/// newer compositor's extra requests would otherwise be unparseable here.
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

/// Is this global advertised to the client at all?
pub fn advertise(interface: &str) -> bool {
    allowed_version(interface).is_some()
}

/// The identity prefix for titles: `[zone] `.
pub fn title_for(zone: &str, title: &str) -> String {
    let t = if title.starts_with('[') && title.contains("] ") {
        // A client pretending to carry a prefix: it becomes part of its own
        // title, visibly, after the real one.
        title
    } else {
        title
    };
    let mut out = format!("[{zone}] {t}");
    // Bounded: a title is not a channel for megabytes.
    if out.len() > 256 {
        out.truncate(253);
        out.push_str("...");
    }
    out
}

/// The app_id the compositor sees: `kryptik.<zone>.<claimed>`, with the
/// claimed part restricted to a safe alphabet so a zone name inside it
/// cannot be confused with the real one.
pub fn app_id_for(zone: &str, claimed: &str) -> String {
    let cleaned: String = claimed
        .chars()
        .take(64)
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    format!("kryptik.{zone}.{}", if cleaned.is_empty() { "app".to_string() } else { cleaned })
}

/// The zone a compositor-side app_id belongs to, if it went through a proxy.
pub fn zone_of_app_id(app_id: &str) -> Option<&str> {
    let rest = app_id.strip_prefix("kryptik.")?;
    let (zone, _) = rest.split_once('.')?;
    if zone.is_empty() {
        None
    } else {
        Some(zone)
    }
}

/// Resource bounds per client connection.
pub const MAX_OBJECTS: usize = 4096;
pub const MAX_PENDING_BYTES: usize = 1 << 20; // per direction
pub const MAX_PENDING_FDS: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_capture_and_clipboard_interfaces_are_not_advertised() {
        for hidden in [
            "zwlr_screencopy_manager_v1",
            "wl_data_device_manager",
            "zwp_primary_selection_device_manager_v1",
            "zwlr_layer_shell_v1",
            "zwp_virtual_keyboard_manager_v1",
            "zwlr_data_control_manager_v1",
            "zwlr_output_manager_v1",
            "xdg_activation_v1",
            "zwlr_foreign_toplevel_manager_v1",
            "zwp_input_inhibit_manager_v1",
            "ext_image_copy_capture_manager_v1",
        ] {
            assert!(!advertise(hidden), "{hidden} must not reach a zone");
        }
        for shown in ["wl_compositor", "wl_shm", "wl_seat", "xdg_wm_base"] {
            assert!(advertise(shown), "{shown} is what a window needs");
        }
    }

    #[test]
    fn every_allowed_interface_is_in_the_tables() {
        for (n, v) in ALLOWED {
            let i = crate::protocol::find(n).unwrap_or_else(|| panic!("{n} missing from the generated tables"));
            assert!(i.version >= *v, "{n}: tables know v{}, policy allows v{v}", i.version);
        }
    }

    #[test]
    fn titles_and_app_ids_carry_the_zone_and_only_the_zone() {
        assert_eq!(title_for("work", "Editor"), "[work] Editor");
        assert_eq!(title_for("work", "[vault] Editor"), "[work] [vault] Editor");
        assert_eq!(app_id_for("work", "foot"), "kryptik.work.foot");
        assert_eq!(app_id_for("work", "kryptik.vault.x"), "kryptik.work.kryptik_vault_x");
        assert_eq!(app_id_for("work", ""), "kryptik.work.app");
        assert_eq!(zone_of_app_id("kryptik.work.foot"), Some("work"));
        assert_eq!(zone_of_app_id("foot"), None);
        assert_eq!(zone_of_app_id("kryptik..x"), None);
        let long = title_for("w", &"x".repeat(1000));
        assert!(long.len() <= 256);
    }
}
