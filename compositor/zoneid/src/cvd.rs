//! Colour-vision deficiency simulation (Machado, Oliveira & Fernandes 2009, IEEE TVCG 15(6)).
//! Only dichromacy (severity 1.0) is modelled: a palette that passes it passes the milder forms.

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
mod tests;
