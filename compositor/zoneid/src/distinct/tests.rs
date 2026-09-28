use super::*;
use crate::identity::Pattern;

fn id(zone: &str, color: &str) -> ZoneIdentity {
    ZoneIdentity::new(zone, color, None, None, None).unwrap()
}

fn id_p(zone: &str, color: &str, p: Pattern) -> ZoneIdentity {
    ZoneIdentity::new(zone, color, Some(p.name()), None, None).unwrap()
}

#[test]
fn constants_parse() {
    for (_, hex) in BACKGROUNDS.iter().chain(COMPOSITOR_COLOURS.iter()) {
        assert!(Srgb::from_hex(hex).is_ok(), "{hex}");
    }
    assert_eq!(backgrounds().len(), BACKGROUNDS.len());
}

#[test]
fn identical_colours() {
    let z = [id("a", "#2d60d1"), id("b", "#2d60d1")];
    let r = analyze(&z, Thresholds::default());
    assert!(r.is_fatal());
    // Same colour fails under every vision model, including normal.
    assert_eq!(r.critical().count(), Vision::ALL.len());
}

#[test]
fn pattern_rescues_nothing() {
    // Nothing draws a pattern, so different ones cannot tell two zones apart.
    let z = [
        id_p("a", "#2d60d1", Pattern::Solid),
        id_p("b", "#2d60d1", Pattern::Dotted),
    ];
    assert!(analyze(&z, Thresholds::default()).is_fatal());
}

#[test]
fn zone_in_a_compositor_colour() {
    for (name, hex) in COMPOSITOR_COLOURS {
        let r = analyze(&[id("x", hex)], Thresholds::default());
        assert!(r.critical().any(|c| c.a == "x" && c.b == name), "{name}");
    }
}

#[test]
fn compositor_colours_alone() {
    let r = analyze(&[], Thresholds::default());
    assert!(!r.is_fatal(), "{:?}", r.collisions);
    assert_eq!(r.worst_per_vision.len(), Vision::ALL.len());
}

#[test]
fn missing_channels() {
    // A pattern alone is not a channel anyone sees.
    let z = [id("a", "#2d60d1"), id_p("b", "#009b79", Pattern::Dotted)];
    let r = analyze(&z, Thresholds::default());
    assert_eq!(r.missing.len(), 2);
}

#[test]
fn low_contrast_reported_per_background() {
    // Near-black: invisible on the dark desktop, fine on the light one.
    let z = [id("ink", "#101010")];
    let r = analyze(&z, Thresholds::default());
    assert_eq!(r.contrast.len(), 1);
    assert_eq!(r.contrast[0].background, "dark");
}

#[test]
fn duplicate_glyphs_and_labels_reported() {
    let a = ZoneIdentity::new("a", "#aa3333", None, Some("!"), Some("WORK")).unwrap();
    let b = ZoneIdentity::new("b", "#2f6f9f", None, Some("!"), Some("w-o-r-k")).unwrap();
    let r = analyze(&[a, b], Thresholds::default());
    assert!(r.collisions.iter().any(|c| c.channel == Channel::Glyph));
    assert!(r.collisions.iter().any(|c| c.channel == Channel::Label));
}

#[test]
fn worst_pair_when_clean() {
    let z = [id("a", "#2d60d1"), id("b", "#009b79")];
    let r = analyze(&z, Thresholds::default());
    assert!(!r.is_fatal());
    assert_eq!(r.worst_per_vision.len(), Vision::ALL.len());
    for (_, d, _, _) in &r.worst_per_vision {
        assert!(*d > MIN_DELTA_E);
    }
}

#[test]
fn single_zone() {
    let r = analyze(&[id("solo", "#2d60d1")], Thresholds::default());
    assert!(r.collisions.is_empty());
}

/// A known-bad palette must keep failing, worst under deuteranopia.
#[test]
fn known_bad_palette_fails() {
    let shipped = [
        id("dev", "#b5651d"),
        id("net", "#2f6f9f"),
        id("personal", "#7a4fa3"),
        id("untrusted", "#aa3333"),
        id("vault", "#c9a227"),
        id("work", "#3a7d44"),
    ];
    let r = analyze(&shipped, Thresholds::default());
    assert!(
        r.is_fatal(),
        "the original palette is expected to fail; if this now passes, the \
             metric has changed and needs looking at"
    );

    let pair = |a: &str, b: &str, v: Vision| {
        r.critical().any(|c| {
            c.vision == Some(v)
                && ((c.a == a && c.b == b) || (c.a == b && c.b == a))
        })
    };
    assert!(
        pair("net", "personal", Vision::Deuteranopia),
        "net/personal under deuteranopia is the worst pair in the palette"
    );
    assert!(
        pair("untrusted", "work", Vision::Deuteranopia),
        "untrusted/work under deuteranopia is the pair that matters to the \
             threat model: sketchy links and your job, same window edge"
    );
}
