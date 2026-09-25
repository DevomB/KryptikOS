//! What a zone's client may reach through the proxy, and what it rewrites.
//!
//! Globals off the allowlist are never advertised, so they cannot be bound: no
//! capture, global input, layer shell (nothing may draw over the chrome),
//! clipboard (the broker is the only cross-zone channel), virtual keyboard,
//! output management or activation; binding one anyway disconnects the client.
//! Every toplevel title and app_id comes out carrying the zone's name.

/// Interfaces a zone client may bind, capped at the version the generated
/// tables know: requests of a newer version could not be parsed here.
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

/// Prefix a title with `[zone] `. A claimed `[vault] ` just follows the real
/// prefix: `[work] [vault] ...`.
pub fn title_for(zone: &str, title: &str) -> String {
    /* Titles reach dwl's line-based status stream and terminal chrome: no
     * control may inject records, terminal escapes or bidi overrides. */
    let title: String = title.chars().map(|c| {
        if c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}') { ' ' } else { c }
    }).collect();
    let mut out = format!("[{zone}] {title}");
    bound_utf8(&mut out, MAX_TITLE_BYTES);
    out
}

/// Cut `s` to at most `max` bytes, ending in `...` if anything was cut. The
/// cut lands on a character boundary: `String::truncate` panics inside one.
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

/// `kryptik.<zone>.<claimed>`, the claimed part cut to a safe alphabet so a
/// zone name inside it cannot pass for the real one.
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
    fn capture_and_clipboard_are_hidden() {
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

    /// Objects are forgotten only on delete_id, which names client-created ids,
    /// so no event a zone can reach may create one.
    #[test]
    fn no_compositor_created_objects() {
        use crate::protocol::{find, Arg};
        let mut reach: Vec<&str> = ALLOWED.iter().map(|(n, _)| *n).chain(["wl_display", "wl_registry"]).collect();
        let mut i = 0;
        while i < reach.len() {
            let iface = find(reach[i]).unwrap();
            for m in iface.requests {
                for a in m.args() {
                    if let Arg::NewId { iface: Some(n) } = a {
                        if !reach.contains(&n) {
                            reach.push(n);
                        }
                    }
                }
            }
            for m in iface.events {
                assert!(m.args().all(|a| !matches!(a, Arg::NewId { .. })), "{}.{} creates an object", iface.name, m.name);
            }
            i += 1;
        }
        assert!(reach.len() > ALLOWED.len() + 2, "the walk reached the objects the globals create");
    }

    #[test]
    fn allowed_interfaces_are_in_tables() {
        for (n, v) in ALLOWED {
            let i = crate::protocol::find(n).unwrap_or_else(|| panic!("{n} missing from the generated tables"));
            assert!(i.version >= *v, "{n}: tables know v{}, policy allows v{v}", i.version);
        }
    }

    #[test]
    fn titles_and_app_ids_carry_zone() {
        assert_eq!(title_for("work", "Editor"), "[work] Editor");
        assert_eq!(title_for("work", "[vault] Editor"), "[work] [vault] Editor");
        assert_eq!(app_id_for("work", "foot"), "kryptik.work.foot");
        assert_eq!(app_id_for("work", "kryptik.vault.x"), "kryptik.work.kryptik_vault_x");
        assert_eq!(app_id_for("work", ""), "kryptik.work.app");
        let long = title_for("w", &"x".repeat(1000));
        assert!(long.len() <= 256);
    }

    #[test]
    fn title_controls_are_replaced() {
        let title = title_for("untrusted", "notes\nmonitor appid trusted\r\u{1b}[2J\u{202e}VAULT\u{2069}\u{2028}é");
        assert_eq!(title, "[untrusted] notes monitor appid trusted  [2J VAULT  é");
        assert_eq!(title.lines().count(), 1);
    }

    /// The bound is in bytes; the cut must still land on a character boundary.
    #[test]
    fn multibyte_title_cut_on_char_boundary() {
        // 200 x U+00E9 is 400 bytes; byte 253 is inside a character.
        let t = title_for("vault", &"\u{00e9}".repeat(200));
        assert!(t.len() <= MAX_TITLE_BYTES, "{}", t.len());
        assert!(t.starts_with("[vault] "), "the identity prefix survives: {t}");
        assert!(t.ends_with("..."), "a cut title says so: {t}");
        let body = &t["[vault] ".len()..t.len() - 3];
        assert!(body.chars().all(|c| c == '\u{00e9}'), "every kept character is intact: {body:?}");
        assert!(!body.is_empty());

        // Four-byte characters, with byte 253 the second byte of an emoji.
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

        // A long zone name: the prefix itself is cut, still on a boundary.
        let t = title_for(&"\u{00e9}".repeat(300), "Editor");
        assert!(t.len() <= MAX_TITLE_BYTES);
        assert!(t.starts_with("[\u{00e9}"));
        assert!(t.ends_with("..."));

        // Plain ASCII is untouched.
        assert_eq!(title_for("work", "Editor"), "[work] Editor");
    }
}
