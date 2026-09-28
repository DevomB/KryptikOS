use super::*;
use crate::distinct::{analyze, Thresholds, COMPOSITOR_COLOURS, MIN_DELTA_E};
use crate::identity::Channel;

/// dwl's colour header holds exactly the audited colours, so dwl draws none unchecked.
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

/// Every shipped pair clears the floor under every vision model, with no
/// other finding, and every zone carries all four channels.
#[test]
fn shipped_zones_pass_invariant() {
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
