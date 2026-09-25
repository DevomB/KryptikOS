//! Colour-vision deficiency simulation, after Machado, Oliveira & Fernandes
//! (2009), "A Physiologically-based Model for Simulation of Color Vision
//! Deficiency", IEEE TVCG 15(6).
//!
//! Only dichromacy (severity 1.0) is modelled: the milder anomalous forms are
//! strictly less severe, so a palette that passes here passes for them too.
//! The matrices apply to linear RGB, and `simulate` does the conversion.

use crate::color::{LinearRgb, Srgb};

/// A vision model. `Normal` is included so one list covers the baseline too.
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

    /// Rough share of the population affected, for reports only.
    pub fn prevalence_note(self) -> &'static str {
        match self {
            Vision::Normal => "baseline",
            Vision::Protanopia => "~1% of men",
            Vision::Deuteranopia => "~1% of men; deuteranomaly, the milder form, ~6%",
            Vision::Tritanopia => "~0.01%, affects both sexes equally",
        }
    }

    /// The Machado et al. severity-1.0 transform (row-major, linear RGB); None for normal vision.
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

/// How `c` appears under vision `v`. Linearises internally, as the model requires.
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
    fn normal_vision_is_identity() {
        for hex in ["#000000", "#ffffff", "#b5651d", "#2f6f9f", "#aa3333"] {
            let c = Srgb::from_hex(hex).unwrap();
            assert_eq!(simulate(c, Vision::Normal), c);
        }
    }

    #[test]
    fn greys_unchanged_by_any_model() {
        /* Each matrix's rows sum to about 1, so greys pass through; a
         * transcription error in a matrix makes them drift. */
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
}
