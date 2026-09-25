//! Colour-vision deficiency simulation.
//!
//! Kryptik identifies zones by colour, and that has to hold for the people
//! actually using the system: roughly 8% of men of Northern European descent
//! have some form of red-green colour-vision deficiency. If two zones are the
//! same colour to them, the identification fails for one user in twelve.
//!
//! # Why only severity 1.0
//!
//! This module simulates DICHROMACY only - the complete absence of one cone
//! class - and deliberately offers no severity parameter.
//!
//! That is not a simplification, it is the conservative bound. Anomalous
//! trichromacy (deuteranomaly, protanomaly - the common mild forms) is
//! strictly less severe than the corresponding dichromacy: the shifted cone
//! still discriminates, just worse. A palette whose zones remain distinct
//! under full dichromacy is therefore distinct under every milder form, so
//! checking the endpoint checks the whole range. Checking at severity 0.6
//! would pass palettes that fail for people at 0.9, which is precisely the
//! kind of "mostly works" a security boundary cannot be built on.
//!
//! The alternative - interpolating the transform toward identity - is what
//! most implementations do and it is not the same thing as Machado's
//! per-severity matrices. Rather than ship an approximation under a name that
//! implies precision, this module does not offer the parameter at all.
//!
//! # Method
//!
//! Machado, Oliveira & Fernandes (2009), "A Physiologically-based Model for
//! Simulation of Color Vision Deficiency", IEEE TVCG 15(6). The published
//! matrices operate on LINEAR RGB, not gamma-encoded sRGB. Applying them to
//! gamma-encoded values is the single most common error in implementations of
//! this paper and produces plausible-looking, wrong colours - so `simulate`
//! takes and returns `Srgb` and does the conversion itself, leaving no way to
//! get it wrong from outside.

use crate::color::{LinearRgb, Srgb};

/// A vision model to evaluate the palette under.
///
/// `Normal` is included so callers can iterate one list rather than special-
/// casing the trichromatic check, and so a report always states the baseline.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Vision {
    Normal,
    /// No long-wavelength (red) cone. ~1% of men.
    Protanopia,
    /// No medium-wavelength (green) cone. ~1% of men.
    Deuteranopia,
    /// No short-wavelength (blue) cone. ~0.01% of people, both sexes.
    Tritanopia,
}

impl Vision {
    /// Every model the distinctness invariant is evaluated under.
    pub const ALL: [Vision; 4] = [
        Vision::Normal,
        Vision::Protanopia,
        Vision::Deuteranopia,
        Vision::Tritanopia,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Vision::Normal => "normal",
            Vision::Protanopia => "protanopia",
            Vision::Deuteranopia => "deuteranopia",
            Vision::Tritanopia => "tritanopia",
        }
    }

    /// Approximate share of the population affected, for reports.
    ///
    /// Deliberately coarse. These are population statistics with wide
    /// geographic variation, quoted here so a report can say "one user in
    /// twelve" rather than leaving the reader to guess whether the finding
    /// matters. They are not used in any computation.
    pub fn prevalence_note(self) -> &'static str {
        match self {
            Vision::Normal => "baseline",
            Vision::Protanopia => "~1% of men",
            Vision::Deuteranopia => "~1% of men; deuteranomaly, the milder form, ~6%",
            Vision::Tritanopia => "~0.01%, affects both sexes equally",
        }
    }

    /// The Machado et al. (2009) severity-1.0 transform, row-major, linear
    /// RGB; None for normal vision, which sees the colour as it is.
    fn matrix(self) -> Option<[[f64; 3]; 3]> {
        Some(match self {
            Vision::Normal => return None,
            Vision::Protanopia => [
                [0.152_286, 1.052_583, -0.204_868],
                [0.114_503, 0.786_281, 0.099_216],
                [-0.003_882, -0.048_116, 1.051_998],
            ],
            Vision::Deuteranopia => [
                [0.367_322, 0.860_646, -0.227_968],
                [0.280_085, 0.672_501, 0.047_413],
                [-0.011_820, 0.042_940, 0.968_881],
            ],
            Vision::Tritanopia => [
                [1.255_528, -0.076_749, -0.178_779],
                [-0.078_411, 0.930_809, 0.147_602],
                [0.004_733, 0.691_367, 0.303_900],
            ],
        })
    }
}

/// How `c` appears to someone with the given vision.
///
/// Takes and returns gamma-encoded sRGB; the linearisation the model requires
/// happens inside, so a caller cannot apply the matrix to the wrong values.
pub fn simulate(c: Srgb, v: Vision) -> Srgb {
    let Some(m) = v.matrix() else {
        return c;
    };
    let l = c.to_linear();
    LinearRgb {
        r: m[0][0] * l.r + m[0][1] * l.g + m[0][2] * l.b,
        g: m[1][0] * l.r + m[1][1] * l.g + m[1][2] * l.b,
        b: m[2][0] * l.r + m[2][1] * l.g + m[2][2] * l.b,
    }
    .to_srgb()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::delta_e;

    #[test]
    fn normal_vision_is_the_identity() {
        for hex in ["#000000", "#ffffff", "#b5651d", "#2f6f9f", "#aa3333"] {
            let c = Srgb::from_hex(hex).unwrap();
            assert_eq!(simulate(c, Vision::Normal), c);
        }
    }

    #[test]
    fn achromatic_colours_are_unchanged_by_any_model() {
        // Every one of these matrices has rows summing to approximately 1, so
        // greys must pass through. If a transcription error crept into the
        // table, greys drift and this catches it without needing reference
        // colours for the chromatic cases.
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
    fn red_and_green_collapse_under_deuteranopia() {
        // The defining property of the deficiency. If this does not hold, the
        // matrix is wrong or is being applied to gamma-encoded values.
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
    fn blue_and_yellow_survive_deuteranopia_but_not_tritanopia() {
        // The complementary check: deuteranopia must NOT flatten the
        // blue-yellow axis. A matrix that flattens everything would pass the
        // red/green test above while being useless.
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
}
