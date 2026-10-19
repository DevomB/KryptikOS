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
        assert!(allowed_version(hidden, false).is_none(), "{hidden} must not reach a zone");
        assert!(allowed_version(hidden, true).is_none(), "{hidden} must not reach a zone that holds the screen awake");
    }
    for shown in ["wl_compositor", "wl_shm", "wl_seat", "xdg_wm_base"] {
        assert!(allowed_version(shown, false).is_some(), "{shown} is what a window needs");
    }
    // The data device a zone binds is the proxy's own, never the compositor's.
    assert!(own_version("wl_data_device_manager").is_some() && served("wl_data_device_manager"));
}

/// The gesture carries the types the broker's clipboard takes, no more: a type only one of them
/// knew would leave a payload one path can carry and the other cannot.
#[test]
fn move_types_are_the_brokers() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compartments/kryptikd/src/broker.rs");
    let broker = std::fs::read_to_string(&path).expect("broker.rs");
    let start = broker.find("pub const MIME_TYPES: &[&str] = &[").expect("the broker's MIME list");
    let end = start + broker[start..].find("];").expect("the end of that list");
    let mut theirs: Vec<&str> = broker[start..end].split('"').skip(1).step_by(2).collect();
    let mut ours = MOVE_TYPES.to_vec();
    theirs.sort_unstable();
    ours.sort_unstable();
    assert_eq!(ours, theirs);
    assert_eq!(MOVE_TYPES[0], "text/plain;charset=utf-8", "text with its charset is taken first");
}

/// dwl's zone sockets offer this list too (tools/desktop/dwl-zone-borders.py): the two never drift.
#[test]
fn dwl_zone_sockets_offer_the_same_list() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/desktop/dwl-zone-borders.py");
    let patch = std::fs::read_to_string(&path).expect("dwl-zone-borders.py");
    let start = patch.find("zoneglobals[] = {").expect("the zones' list in the dwl patch");
    let end = start + patch[start..].find("};").expect("the end of that list");
    let mut dwl: Vec<&str> = patch[start..end].split('"').skip(1).step_by(2).collect();
    let mut proxy: Vec<&str> = ALLOWED.iter().map(|(n, _)| *n).collect();
    dwl.sort_unstable();
    proxy.sort_unstable();
    assert_eq!(dwl, proxy);
    // The idle inhibitor is on neither list: each gives it only to a zone allowed to hold.
    let (hold, _) = HOLD_AWAKE;
    let filter = patch.find("zoneglobal(const struct wl_client").expect("dwl's global filter");
    let filter = &patch[filter..filter + patch[filter..].find("\n}\n").expect("its end")];
    let at = filter.find(&format!("strcmp(name, \"{hold}\") == 0)")).expect("dwl's filter names the idle inhibitor");
    let then = filter[at..].lines().nth(1).unwrap_or("").trim().trim_start_matches("\\t");
    assert_eq!(then, "return z->hold;", "{filter}");
}

/// The idle inhibitor reaches only a proxy started with --hold-awake.
#[test]
fn the_idle_inhibitor_is_the_hold_awake_zones_alone() {
    let (hold, v) = HOLD_AWAKE;
    assert_eq!(allowed_version(hold, false), None);
    assert_eq!(allowed_version(hold, true), Some(v));
    assert!(!ALLOWED.iter().any(|(n, _)| *n == hold));
}

/// Only delete_id frees objects, and only client-created ones: no event the compositor can send
/// creates one. The server range is then the proxy's own, for the offers it makes (clipboard.rs);
/// a global let through whose events create objects fails here before its ids could collide.
#[test]
fn no_compositor_created_objects() {
    use crate::protocol::{find, Arg};
    let mut reach: Vec<&str> = ALLOWED.iter().chain([&HOLD_AWAKE]).map(|(n, _)| *n).chain(["wl_display", "wl_registry"]).collect();
    let mut i = 0;
    while i < reach.len() {
        let iface = find(reach[i]).unwrap();
        for m in iface.requests {
            for &a in m.args {
                if let Arg::NewId { iface: Some(n) } = a {
                    if !reach.contains(&n) {
                        reach.push(n);
                    }
                }
            }
        }
        for m in iface.events {
            assert!(m.args.iter().all(|a| !matches!(a, Arg::NewId { .. })), "{}.{} creates an object", iface.name, m.name);
        }
        i += 1;
    }
    assert!(reach.len() > ALLOWED.len() + 3, "the walk reached the objects the globals create");
}

#[test]
fn allowed_interfaces_are_in_tables() {
    for (n, v) in ALLOWED.iter().chain([&HOLD_AWAKE]) {
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
fn title_cut_on_char_boundary() {
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

    // Mixed widths: an accented character straddling the cut.
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
