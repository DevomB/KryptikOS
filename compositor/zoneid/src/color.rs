//! Colour science from published formulae, each tested against reference
//! values (CIEDE2000 against the Sharma, Wu & Dalal 2005 data).
//!
//! `Srgb` is gamma-encoded and `LinearRgb` light-linear, both in 0..=1 (not
//! 0..=255). Vision simulation and luminance work on linear values only.

use std::fmt;

/// A gamma-encoded sRGB colour, components in 0..=1.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Srgb {
    pub r: f64,
    pub g: f64,
    pub b: f64,
}

/// A light-linear RGB colour, nominally in 0..=1. Vision simulation can leave
/// that range; values are clamped only on conversion back to `Srgb`.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct LinearRgb {
    pub r: f64,
    pub g: f64,
    pub b: f64,
}

/// CIE 1931 XYZ, D65 white point.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Xyz {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

/// CIE L*a*b*, D65 white point.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Lab {
    pub l: f64,
    pub a: f64,
    pub b: f64,
}

#[derive(Debug, PartialEq)]
pub enum ParseHexError {
    MissingHash,
    BadLength(usize),
    BadDigit(char),
}

impl fmt::Display for ParseHexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseHexError::MissingHash => write!(f, "colour must begin with '#'"),
            ParseHexError::BadLength(n) => {
                write!(f, "colour must be #RRGGBB (7 characters), got {n}")
            }
            ParseHexError::BadDigit(c) => write!(f, "'{c}' is not a hex digit"),
        }
    }
}

impl Srgb {
    /// Parse `#RRGGBB` only: no short form, alpha or names. Coercing a bad zone
    /// colour could give a zone another zone's identity.
    pub fn from_hex(s: &str) -> Result<Srgb, ParseHexError> {
        let bytes = s.as_bytes();
        if bytes.first() != Some(&b'#') {
            return Err(ParseHexError::MissingHash);
        }
        if bytes.len() != 7 {
            return Err(ParseHexError::BadLength(bytes.len()));
        }
        let mut v = [0u8; 3];
        for (i, chunk) in bytes[1..].chunks(2).enumerate() {
            let hi = hex_digit(chunk[0])?;
            let lo = hex_digit(chunk[1])?;
            v[i] = hi * 16 + lo;
        }
        Ok(Srgb {
            r: v[0] as f64 / 255.0,
            g: v[1] as f64 / 255.0,
            b: v[2] as f64 / 255.0,
        })
    }

    pub fn to_hex(self) -> String {
        let q = |v: f64| -> u8 { (v.clamp(0.0, 1.0) * 255.0).round() as u8 };
        format!("#{:02x}{:02x}{:02x}", q(self.r), q(self.g), q(self.b))
    }

    pub fn to_linear(self) -> LinearRgb {
        LinearRgb {
            r: srgb_to_linear(self.r),
            g: srgb_to_linear(self.g),
            b: srgb_to_linear(self.b),
        }
    }

    pub fn to_lab(self) -> Lab {
        self.to_linear().to_xyz().to_lab()
    }

    /// WCAG 2.x relative luminance.
    pub fn relative_luminance(self) -> f64 {
        let l = self.to_linear();
        0.2126 * l.r + 0.7152 * l.g + 0.0722 * l.b
    }
}

impl LinearRgb {
    pub fn to_srgb(self) -> Srgb {
        Srgb {
            r: linear_to_srgb(self.r),
            g: linear_to_srgb(self.g),
            b: linear_to_srgb(self.b),
        }
    }


    pub fn to_xyz(self) -> Xyz {
        Xyz {
            x: RGB_TO_XYZ[0][0] * self.r + RGB_TO_XYZ[0][1] * self.g + RGB_TO_XYZ[0][2] * self.b,
            y: RGB_TO_XYZ[1][0] * self.r + RGB_TO_XYZ[1][1] * self.g + RGB_TO_XYZ[1][2] * self.b,
            z: RGB_TO_XYZ[2][0] * self.r + RGB_TO_XYZ[2][1] * self.g + RGB_TO_XYZ[2][2] * self.b,
        }
    }
}

/// Linear sRGB to CIE XYZ, D65 (IEC 61966-2-1).
const RGB_TO_XYZ: [[f64; 3]; 3] = [
    [0.412_456_4, 0.357_576_1, 0.180_437_5],
    [0.212_672_9, 0.715_152_2, 0.072_175_0],
    [0.019_333_9, 0.119_192_0, 0.950_304_1],
];

/// The reference white, derived from `RGB_TO_XYZ`: the rounded matrix misses
/// canonical D65 slightly (Y sums to 1.0000001), and deriving keeps L* = 100.
const WHITE: (f64, f64, f64) = (
    RGB_TO_XYZ[0][0] + RGB_TO_XYZ[0][1] + RGB_TO_XYZ[0][2],
    RGB_TO_XYZ[1][0] + RGB_TO_XYZ[1][1] + RGB_TO_XYZ[1][2],
    RGB_TO_XYZ[2][0] + RGB_TO_XYZ[2][1] + RGB_TO_XYZ[2][2],
);

impl Xyz {
    pub fn to_lab(self) -> Lab {
        // D65, 2-degree observer; see WHITE.
        let (xn, yn, zn) = WHITE;
        let f = |t: f64| -> f64 {
            const DELTA: f64 = 6.0 / 29.0;
            if t > DELTA * DELTA * DELTA {
                t.cbrt()
            } else {
                t / (3.0 * DELTA * DELTA) + 4.0 / 29.0
            }
        };
        let (fx, fy, fz) = (f(self.x / xn), f(self.y / yn), f(self.z / zn));
        Lab {
            l: 116.0 * fy - 16.0,
            a: 500.0 * (fx - fy),
            b: 200.0 * (fy - fz),
        }
    }
}

fn hex_digit(c: u8) -> Result<u8, ParseHexError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ParseHexError::BadDigit(c as char)),
    }
}

fn srgb_to_linear(c: f64) -> f64 {
    if c <= 0.040_45 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

fn linear_to_srgb(c: f64) -> f64 {
    let c = c.clamp(0.0, 1.0);
    if c <= 0.003_130_8 {
        12.92 * c
    } else {
        1.055 * c.powf(1.0 / 2.4) - 0.055
    }
}

/// WCAG 2.x contrast ratio, in 1.0..=21.0; used for a border against its background.
pub fn contrast_ratio(a: Srgb, b: Srgb) -> f64 {
    let (la, lb) = (a.relative_luminance(), b.relative_luminance());
    let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

/// CIEDE2000 colour difference: CIE 142-2001 as corrected by Sharma, Wu &
/// Dalal (2005), with kL = kC = kH = 1. The corrections matter near blue.
pub fn ciede2000(p: Lab, q: Lab) -> f64 {
    const POW25_7: f64 = 6_103_515_625.0; // 25^7

    let (l1, a1, b1) = (p.l, p.a, p.b);
    let (l2, a2, b2) = (q.l, q.a, q.b);

    let c1 = (a1 * a1 + b1 * b1).sqrt();
    let c2 = (a2 * a2 + b2 * b2).sqrt();
    let c_bar = (c1 + c2) / 2.0;

    let c_bar7 = c_bar.powi(7);
    let g = 0.5 * (1.0 - (c_bar7 / (c_bar7 + POW25_7)).sqrt());

    let a1p = (1.0 + g) * a1;
    let a2p = (1.0 + g) * a2;
    let c1p = (a1p * a1p + b1 * b1).sqrt();
    let c2p = (a2p * a2p + b2 * b2).sqrt();

    // atan2(0, 0) == 0, as the standard requires for a neutral colour.
    let h1p = deg(b1.atan2(a1p));
    let h2p = deg(b2.atan2(a2p));

    let dlp = l2 - l1;
    let dcp = c2p - c1p;

    let dhp = if c1p * c2p == 0.0 {
        0.0
    } else {
        let d = h2p - h1p;
        if d > 180.0 {
            d - 360.0
        } else if d < -180.0 {
            d + 360.0
        } else {
            d
        }
    };
    let big_dhp = 2.0 * (c1p * c2p).sqrt() * (dhp.to_radians() / 2.0).sin();

    let lbp = (l1 + l2) / 2.0;
    let cbp = (c1p + c2p) / 2.0;

    let hbp = if c1p * c2p == 0.0 {
        h1p + h2p
    } else {
        let s = h1p + h2p;
        if (h1p - h2p).abs() <= 180.0 {
            s / 2.0
        } else if s < 360.0 {
            (s + 360.0) / 2.0
        } else {
            (s - 360.0) / 2.0
        }
    };

    let t = 1.0 - 0.17 * (hbp - 30.0).to_radians().cos()
        + 0.24 * (2.0 * hbp).to_radians().cos()
        + 0.32 * (3.0 * hbp + 6.0).to_radians().cos()
        - 0.20 * (4.0 * hbp - 63.0).to_radians().cos();

    let d_theta = 30.0 * (-(((hbp - 275.0) / 25.0).powi(2))).exp();
    let cbp7 = cbp.powi(7);
    let rc = 2.0 * (cbp7 / (cbp7 + POW25_7)).sqrt();

    let sl = 1.0 + (0.015 * (lbp - 50.0).powi(2)) / (20.0 + (lbp - 50.0).powi(2)).sqrt();
    let sc = 1.0 + 0.045 * cbp;
    let sh = 1.0 + 0.015 * cbp * t;
    let rt = -(2.0 * d_theta).to_radians().sin() * rc;

    let term_l = dlp / sl;
    let term_c = dcp / sc;
    let term_h = big_dhp / sh;

    (term_l * term_l + term_c * term_c + term_h * term_h + rt * term_c * term_h).sqrt()
}

/// Radians to degrees, normalised to 0..360.
fn deg(rad: f64) -> f64 {
    let d = rad.to_degrees();
    if d < 0.0 {
        d + 360.0
    } else {
        d
    }
}

/// Shorthand: CIEDE2000 between two sRGB colours.
pub fn delta_e(a: Srgb, b: Srgb) -> f64 {
    ciede2000(a.to_lab(), b.to_lab())
}

#[cfg(test)]
mod tests {
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

    /// Sharma, Wu & Dalal (2005), "The CIEDE2000 Color-Difference Formula:
    /// Implementation Notes, Supplementary Test Data, and Mathematical
    /// Observations", Table 1: pairs that catch the hue wraparounds and the RT
    /// term near blue.
    #[test]
    fn ciede2000_against_sharma_reference_data() {
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
}
