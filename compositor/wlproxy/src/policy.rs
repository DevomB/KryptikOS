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

/// The most bytes a rewritten title may carry. A title is not a channel
/// for megabytes; the compositor and the chrome only ever show one line.
pub const MAX_TITLE_BYTES: usize = 256;

/// The identity prefix for titles: `[zone] `.
///
/// The claimed title follows the prefix whatever it contains: a client that
/// writes its own `[vault] ` merely becomes `[work] [vault] ...`, visibly,
/// after the real one.
pub fn title_for(zone: &str, title: &str) -> String {
    // Titles enter dwl's line-based status stream and terminal chrome.
    // Controls must not inject records, terminal escapes, or bidi overrides.
    let title: String = title.chars().map(|c| {
        if c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}') { ' ' } else { c }
    }).collect();
    let mut out = format!("[{zone}] {title}");
    bound_utf8(&mut out, MAX_TITLE_BYTES);
    out
}

/// Cut `s` down to at most `max` bytes, ending in `...` when anything was
/// cut. The cut lands on a character boundary: a byte count is not a
/// character count, and `String::truncate` panics inside a multi-byte
/// sequence - which, with `panic = "abort"` in release, took the whole
/// proxy down for a title of accented text.
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
            assert!(allowed_version(hidden).is_none(), "{hidden} must not reach a zone");
        }
        for shown in ["wl_compositor", "wl_shm", "wl_seat", "xdg_wm_base"] {
            assert!(allowed_version(shown).is_some(), "{shown} is what a window needs");
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
        let long = title_for("w", &"x".repeat(1000));
        assert!(long.len() <= 256);
    }

    #[test]
    fn title_controls_cannot_inject_status_lines_or_reorder_identity() {
        let title = title_for("untrusted", "notes\nmonitor appid trusted\r\u{1b}[2J\u{202e}VAULT\u{2069}\u{2028}é");
        assert_eq!(title, "[untrusted] notes monitor appid trusted  [2J VAULT  é");
        assert_eq!(title.lines().count(), 1);
    }

    /// The bound is in bytes; the cut must still be a character boundary.
    /// Each case is one the byte-index truncation got wrong or would have.
    #[test]
    fn long_multibyte_titles_are_bounded_on_a_character_boundary() {
        // 200 x U+00E9 is 400 bytes; byte 253 is inside a character.
        let t = title_for("vault", &"\u{00e9}".repeat(200));
        assert!(t.len() <= MAX_TITLE_BYTES, "{}", t.len());
        assert!(t.starts_with("[vault] "), "the identity prefix survives: {t}");
        assert!(t.ends_with("..."), "a cut title says so: {t}");
        let body = &t["[vault] ".len()..t.len() - 3];
        assert!(body.chars().all(|c| c == '\u{00e9}'), "every kept character is intact: {body:?}");
        assert!(!body.is_empty());

        // Four-byte characters, with the prefix chosen so that byte 253 is
        // the second byte of an emoji.
        let t = title_for("w", &"\u{1F600}".repeat(120));
        assert!(t.len() <= MAX_TITLE_BYTES);
        assert!(t.ends_with("..."));
        assert!(t.trim_end_matches("...").chars().skip(4).all(|c| c == '\u{1F600}'), "{t:?}");

        // Mixed widths: an accented character exactly straddling the cut.
        let mut title = "x".repeat(MAX_TITLE_BYTES - 3 - "[work] ".len() - 1);
        title.push('\u{00e9}');
        title.push_str("tail");
        let t = title_for("work", &title);
        assert!(t.len() <= MAX_TITLE_BYTES);
        assert!(t.ends_with("..."));
        assert!(std::str::from_utf8(t.as_bytes()).is_ok());

        // Exactly at the bound: untouched. One byte over: cut.
        let fits = "y".repeat(MAX_TITLE_BYTES - "[work] ".len());
        assert_eq!(title_for("work", &fits).len(), MAX_TITLE_BYTES);
        assert!(!title_for("work", &fits).ends_with("..."));
        let over = format!("{fits}z");
        let t = title_for("work", &over);
        assert_eq!(t.len(), MAX_TITLE_BYTES);
        assert!(t.ends_with("..."));

        // A long zone name is bounded like everything else, and the
        // multi-byte rule still holds when the prefix itself is what gets cut.
        let t = title_for(&"\u{00e9}".repeat(300), "Editor");
        assert!(t.len() <= MAX_TITLE_BYTES);
        assert!(t.starts_with("[\u{00e9}"));
        assert!(t.ends_with("..."));

        // Nothing multi-byte in the input, nothing changes from before.
        assert_eq!(title_for("work", "Editor"), "[work] Editor");
    }
}
