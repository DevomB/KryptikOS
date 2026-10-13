use super::*;

fn close(a: f64, b: f64, tol: f64) -> bool {
    (a - b).abs() <= tol
}

#[test]
fn hex_roundtrip() {
    for h in ["#000000", "#ffffff", "#b5651d", "#2f6f9f", "#7a4fa3"] {
        assert_eq!(Srgb::from_hex(h).unwrap().to_hex(), h);
    }
}

#[test]
fn hex_is_strict() {
    assert_eq!(Srgb::from_hex("b5651d"), Err(ParseHexError::MissingHash));
    assert_eq!(Srgb::from_hex("#b56"), Err(ParseHexError::BadLength(4)));
    assert_eq!(Srgb::from_hex("#b5651dff"), Err(ParseHexError::BadLength(9)));
    assert_eq!(Srgb::from_hex("#gg0000"), Err(ParseHexError::BadDigit('g')));
}

#[test]
fn transfer_function_continuous_at_knee() {
    // The two branches must meet, or everything near black is off.
    let knee = 0.040_45;
    let below = srgb_to_linear(knee - 1e-12);
    let above = srgb_to_linear(knee + 1e-12);
    assert!(close(below, above, 1e-6), "{below} vs {above}");
}

#[test]
fn transfer_function_roundtrips() {
    for i in 0..=255 {
        let v = i as f64 / 255.0;
        assert!(close(linear_to_srgb(srgb_to_linear(v)), v, 1e-9));
    }
}

#[test]
fn white_is_d65_white() {
    let w = Srgb::from_hex("#ffffff").unwrap().to_lab();
    assert!(close(w.l, 100.0, 1e-6), "L* = {}", w.l);
    assert!(close(w.a, 0.0, 0.01), "a* = {}", w.a);
    assert!(close(w.b, 0.0, 0.01), "b* = {}", w.b);
}

#[test]
fn black_is_zero() {
    let k = Srgb::from_hex("#000000").unwrap().to_lab();
    assert!(close(k.l, 0.0, 1e-9));
}

#[test]
fn wcag_contrast_endpoints() {
    // The specification's own two anchor values.
    let w = Srgb::from_hex("#ffffff").unwrap();
    let k = Srgb::from_hex("#000000").unwrap();
    assert!(close(contrast_ratio(w, k), 21.0, 1e-6));
    assert!(close(contrast_ratio(w, w), 1.0, 1e-12));
    assert!(close(contrast_ratio(w, k), contrast_ratio(k, w), 1e-12));
}

#[test]
fn delta_e_zero_when_identical() {
    let c = Srgb::from_hex("#aa3333").unwrap();
    assert!(close(delta_e(c, c), 0.0, 1e-9));
}

#[test]
fn delta_e_is_symmetric() {
    let a = Srgb::from_hex("#aa3333").unwrap();
    let b = Srgb::from_hex("#3a7d44").unwrap();
    assert!(close(delta_e(a, b), delta_e(b, a), 1e-9));
}

/// Sharma, Wu & Dalal (2005), "The CIEDE2000 Color-Difference Formula", Table 1: pairs that
/// catch the hue wraparounds and the RT term near blue.
#[test]
fn ciede2000_reference_data() {
    let cases: &[(f64, f64, f64, f64, f64, f64, f64)] = &[
        // L1,      a1,       b1,       L2,      a2,       b2,       expect
        (50.0000, 2.6772, -79.7751, 50.0000, 0.0000, -82.7485, 2.0425),
        (50.0000, 3.1571, -77.2803, 50.0000, 0.0000, -82.7485, 2.8615),
        (50.0000, 2.8361, -74.0200, 50.0000, 0.0000, -82.7485, 3.4412),
        (50.0000, -1.3802, -84.2814, 50.0000, 0.0000, -82.7485, 1.0000),
        (50.0000, -1.1848, -84.8006, 50.0000, 0.0000, -82.7485, 1.0000),
        (50.0000, -0.9009, -85.5211, 50.0000, 0.0000, -82.7485, 1.0000),
        (50.0000, 0.0000, 0.0000, 50.0000, -1.0000, 2.0000, 2.3669),
        (50.0000, -1.0000, 2.0000, 50.0000, 0.0000, 0.0000, 2.3669),
        (50.0000, 2.5000, 0.0000, 50.0000, 0.0000, -2.5000, 4.3065),
        (50.0000, 2.5000, 0.0000, 73.0000, 25.0000, -18.0000, 27.1492),
        (50.0000, 2.5000, 0.0000, 61.0000, -5.0000, 29.0000, 22.8977),
        (50.0000, 2.5000, 0.0000, 56.0000, -27.0000, -3.0000, 31.9030),
        (50.0000, 2.5000, 0.0000, 58.0000, 24.0000, 15.0000, 19.4535),
        (60.2574, -34.0099, 36.2677, 60.4626, -34.1751, 39.4387, 1.2644),
        (63.0109, -31.0961, -5.8663, 62.8187, -29.7946, -4.0864, 1.2630),
        (61.2901, 3.7196, -5.3901, 61.4292, 2.2480, -4.9620, 1.8731),
        (35.0831, -44.1164, 3.7933, 35.0232, -40.0716, 1.5901, 1.8645),
        (22.7233, 20.0904, -46.6940, 23.0331, 14.9730, -42.5619, 2.0373),
        (36.4612, 47.8580, 18.3852, 36.2715, 50.5065, 21.2231, 1.4146),
        (90.8027, -2.0831, 1.4410, 91.1528, -1.6435, 0.0447, 1.4441),
        (90.9257, -0.5406, -0.9208, 88.6381, -0.8985, -0.7239, 1.5381),
        (6.7747, -0.2908, -2.4247, 5.8714, -0.0985, -2.2286, 0.6377),
        (2.0776, 0.0795, -1.1350, 0.9033, -0.0636, -0.5514, 0.9082),
    ];
    for &(l1, a1, b1, l2, a2, b2, expect) in cases {
        let got = ciede2000(Lab { l: l1, a: a1, b: b1 }, Lab { l: l2, a: a2, b: b2 });
        assert!(
            close(got, expect, 1e-4),
            "CIEDE2000(({l1},{a1},{b1}), ({l2},{a2},{b2})) = {got}, expected {expect}"
        );
    }
}
