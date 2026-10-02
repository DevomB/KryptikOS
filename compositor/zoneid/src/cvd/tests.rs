use super::*;
use crate::color::delta_e;

#[test]
fn normal_vision_is_identity() {
    for hex in ["#000000", "#ffffff", "#b5651d", "#2f6f9f", "#aa3333"] {
        let c = Srgb::from_hex(hex).unwrap();
        assert_eq!(simulate(c, Vision::Normal), c);
    }
}

#[test]
fn greys_unchanged() {
    // Each matrix's rows sum to about 1, so greys pass; a transcription error makes them drift.
    for hex in ["#000000", "#404040", "#808080", "#c0c0c0", "#ffffff"] {
        let c = Srgb::from_hex(hex).unwrap();
        for v in Vision::ALL {
            let s = simulate(c, v);
            assert!(
                delta_e(c, s) < 1.5,
                "{} shifted under {}: {} -> {}",
                hex,
                v.name(),
                hex,
                s.to_hex()
            );
        }
    }
}

#[test]
fn red_green_collapse_under_deuteranopia() {
    // Fails if the matrix is wrong or applied to gamma-encoded values.
    let red = Srgb::from_hex("#ff0000").unwrap();
    let green = Srgb::from_hex("#00ff00").unwrap();
    let normal = delta_e(red, green);
    let deutan = delta_e(
        simulate(red, Vision::Deuteranopia),
        simulate(green, Vision::Deuteranopia),
    );
    assert!(
        deutan < normal / 2.0,
        "red/green separation barely changed: {normal} -> {deutan}"
    );
}

#[test]
fn blue_yellow_survive_deuteranopia() {
    // A matrix that flattened everything would pass the red/green test.
    let blue = Srgb::from_hex("#0000ff").unwrap();
    let yellow = Srgb::from_hex("#ffff00").unwrap();
    let deutan = delta_e(
        simulate(blue, Vision::Deuteranopia),
        simulate(yellow, Vision::Deuteranopia),
    );
    let tritan = delta_e(
        simulate(blue, Vision::Tritanopia),
        simulate(yellow, Vision::Tritanopia),
    );
    assert!(deutan > 50.0, "blue/yellow lost under deuteranopia: {deutan}");
    assert!(tritan < deutan, "tritanopia did not reduce blue/yellow: {tritan}");
}

#[test]
fn simulation_is_deterministic() {
    let c = Srgb::from_hex("#7a4fa3").unwrap();
    for v in Vision::ALL {
        assert_eq!(simulate(c, v), simulate(c, v));
    }
}
