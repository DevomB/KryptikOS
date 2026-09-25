//! The distinctness invariant: can a human tell these two zones apart?
//!
//! # The rule
//!
//! Every pair of border colours the compositor draws - each zone's, and its
//! own for a window from no zone, from an unknown zone, or asking for
//! attention - must differ by the floor under every vision model. Zones must
//! also have distinct glyphs and distinct labels, which the chrome shows for
//! the focused window. The border pattern is validated but nothing draws it,
//! so it separates nothing.
//!
//! # What a "collision" is and is not
//!
//! A collision is a statement about two configured identities under a stated
//! vision model and a stated metric. It is not a claim about whether a
//! particular person, in a particular room, in a hurry, would be confused.
//! Real confusion also involves habit, screen calibration, ambient light and
//! haste, none of which are modelled here. This is a floor, and treating it as
//! a guarantee would be the same overreach as treating a passing test suite as
//! proof of correctness.

use crate::color::{ciede2000, contrast_ratio, Lab, Srgb};
use crate::cvd::{simulate, Vision};
use crate::identity::{Channel, ZoneIdentity};

/// The colour-difference floor, in CIEDE2000 units.
///
/// For scale: ~1.0 is the classic just-noticeable difference under laboratory
/// conditions and ~2.3 is a difference a person reliably notices when the two
/// samples are adjacent and they are looking for it. Neither is the situation
/// here. A zone border is seen peripherally, on an uncalibrated screen, at
/// arbitrary ambient brightness, by someone whose attention is on their work -
/// and the consequence of a mistake is typing a password into the wrong zone.
///
/// 15.0 is chosen as a floor that keeps a pair separable under those
/// conditions while remaining achievable: `zoneid propose` searches the sRGB
/// gamut for six-colour palettes under the 3:1 contrast constraint, clear of
/// the compositor's own colours, and reaches 15.70 (measured 2026-09-25), so
/// the floor is achievable but not by much: it is the binding constraint.
/// The shipped colours reach 15.88.
/// The original six colours reached 1.48.
pub const MIN_DELTA_E: f64 = 15.0;

/// Minimum contrast between a zone border and the background behind it.
///
/// WCAG 2.1 SC 1.4.11 (Non-text Contrast) requires 3:1 for user interface
/// components whose perception is necessary. A zone border is the canonical
/// example of one: if it vanishes into the desktop the window is unattributed,
/// which is the same failure as two zones sharing a colour and is easy to miss
/// because it only happens on one of the two backgrounds.
pub const MIN_BORDER_CONTRAST: f64 = 3.0;

/// The two backgrounds a border is checked against.
///
/// Checking one is the trap. A colour tuned for a dark desktop can disappear
/// on a light one, and Kryptik does not currently forbid either.
pub const BACKGROUNDS: [(&str, &str); 2] = [("dark", "#1c1c1c"), ("light", "#f0f0f0")];

/// The border colours the compositor draws besides the zones': a window from
/// no zone (the chrome), from a zone it has no colour for, and one asking for
/// attention. gen-zone-colours.py writes the same values into the header dwl
/// is built with, and a test in zones.rs holds the two together. They are
/// held to the floor against every zone, not to the contrast rule: the
/// unzoned grey is light by design and the desktop is dark.
pub const COMPOSITOR_COLOURS: [(&str, &str); 3] =
    [("unzoned", "#d8d8d8"), ("unknown", "#a2c9ff"), ("urgent", "#ffd000")];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Thresholds {
    pub min_delta_e_millis: u32,
    pub min_contrast_millis: u32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            min_delta_e_millis: (MIN_DELTA_E * 1000.0) as u32,
            min_contrast_millis: (MIN_BORDER_CONTRAST * 1000.0) as u32,
        }
    }
}

impl Thresholds {
    pub fn min_delta_e(&self) -> f64 {
        self.min_delta_e_millis as f64 / 1000.0
    }
    pub fn min_contrast(&self) -> f64 {
        self.min_contrast_millis as f64 / 1000.0
    }
}

/// How badly a finding breaks the model.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Severity {
    /// Two border colours below the floor under some vision model: for a
    /// user with that vision, the two are the same window edge.
    Critical,
    /// A glyph or label shared by two zones.
    Warning,
}

impl Severity {
    pub fn name(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::Warning => "warning",
        }
    }
}

/// Two zones that are not distinguishable in some channel.
#[derive(Clone, Debug)]
pub struct Collision {
    pub a: String,
    pub b: String,
    pub channel: Channel,
    /// The vision model under which the collision occurs. `None` for channels
    /// that do not depend on vision, such as glyph and label.
    pub vision: Option<Vision>,
    /// The measured difference, for colour collisions.
    pub delta_e: Option<f64>,
    pub severity: Severity,
    pub detail: String,
}

/// A border that is hard to see against one of the backgrounds.
#[derive(Clone, Debug)]
pub struct ContrastFinding {
    pub zone: String,
    pub background: &'static str,
    pub ratio: f64,
}

/// A zone with no channel that survives colour-vision deficiency.
#[derive(Clone, Debug)]
pub struct MissingChannel {
    pub zone: String,
}

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub collisions: Vec<Collision>,
    pub contrast: Vec<ContrastFinding>,
    pub missing: Vec<MissingChannel>,
    /// Worst (smallest) colour difference seen, per vision model, with the
    /// pair responsible. Reported even when nothing failed, because "it
    /// passed" is much less useful than "it passed with 3.2 to spare".
    pub worst_per_vision: Vec<(Vision, f64, String, String)>,
}

impl Report {
    pub fn critical(&self) -> impl Iterator<Item = &Collision> {
        self.collisions
            .iter()
            .filter(|c| c.severity == Severity::Critical)
    }

    /// Whether a zone set carrying these findings should be refused.
    ///
    /// Only critical collisions block. A missing channel or a low-contrast
    /// border is a genuine finding and is reported loudly, but refusing to
    /// boot a machine over it would make the invariant unshippable, and an
    /// invariant nobody can enable protects nobody.
    pub fn is_fatal(&self) -> bool {
        self.critical().next().is_some()
    }
}

/// Evaluate a zone set.
pub fn analyze(zones: &[ZoneIdentity], t: Thresholds) -> Report {
    let mut r = Report::default();

    for z in zones {
        if !z.has_non_color_channel() {
            r.missing.push(MissingChannel {
                zone: z.zone.clone(),
            });
        }
        for (bg_name, bg_hex) in BACKGROUNDS {
            // The backgrounds are compile-time constants checked by a test
            // below, so a parse failure here is a programming error, not
            // configuration, and there is nothing useful to report about it.
            let Ok(bg) = Srgb::from_hex(bg_hex) else {
                continue;
            };
            let ratio = contrast_ratio(z.color, bg);
            if ratio < t.min_contrast() {
                r.contrast.push(ContrastFinding {
                    zone: z.zone.clone(),
                    background: bg_name,
                    ratio,
                });
            }
        }
    }

    // Track the worst pair per vision model even when nothing fails.
    // Indexed like Vision::ALL, and read that way below.
    let mut worst: Vec<(Vision, f64, String, String)> = Vision::ALL
        .iter()
        .map(|&v| (v, f64::INFINITY, String::new(), String::new()))
        .collect();

    // Every border colour on screen, each converted to Lab once per vision
    // model rather than once per pair.
    let mut drawn: Vec<(&str, Srgb)> = zones.iter().map(|z| (z.zone.as_str(), z.color)).collect();
    drawn.extend(
        COMPOSITOR_COLOURS
            .iter()
            .filter_map(|&(name, hex)| Srgb::from_hex(hex).ok().map(|c| (name, c))),
    );
    let labs: Vec<[Lab; Vision::ALL.len()]> = drawn
        .iter()
        .map(|&(_, c)| Vision::ALL.map(|v| simulate(c, v).to_lab()))
        .collect();

    for i in 0..drawn.len() {
        for j in (i + 1)..drawn.len() {
            let (a, b) = (drawn[i].0, drawn[j].0);
            for (k, v) in Vision::ALL.into_iter().enumerate() {
                let d = ciede2000(labs[i][k], labs[j][k]);
                if d < worst[k].1 {
                    worst[k] = (v, d, a.to_string(), b.to_string());
                }
                if d < t.min_delta_e() {
                    r.collisions.push(Collision {
                        a: a.to_string(),
                        b: b.to_string(),
                        channel: Channel::Color,
                        vision: Some(v),
                        delta_e: Some(d),
                        severity: Severity::Critical,
                        detail: format!(
                            "colours are indistinguishable under {} (dE00 {:.2}, floor {:.1}): \
                             {} sees one window edge for both",
                            v.name(),
                            d,
                            t.min_delta_e(),
                            v.prevalence_note(),
                        ),
                    });
                }
            }
        }
    }

    for i in 0..zones.len() {
        for j in (i + 1)..zones.len() {
            let (a, b) = (&zones[i], &zones[j]);
            if let (Some(ga), Some(gb)) = (a.glyph, b.glyph) {
                if ga == gb {
                    r.collisions.push(Collision {
                        a: a.zone.clone(),
                        b: b.zone.clone(),
                        channel: Channel::Glyph,
                        vision: None,
                        delta_e: None,
                        severity: Severity::Warning,
                        detail: format!("both zones use the glyph '{ga}'"),
                    });
                }
            }
            if let (Some(ka), Some(kb)) = (a.label_key(), b.label_key()) {
                if ka == kb {
                    r.collisions.push(Collision {
                        a: a.zone.clone(),
                        b: b.zone.clone(),
                        channel: Channel::Label,
                        vision: None,
                        delta_e: None,
                        severity: Severity::Warning,
                        detail: format!(
                            "labels {:?} and {:?} compare equal once case and \
                             punctuation are folded",
                            a.label.as_deref().unwrap_or(""),
                            b.label.as_deref().unwrap_or("")
                        ),
                    });
                }
            }
        }
    }

    // Sort so the report is stable and the worst thing is first. Critical
    // before warning, then smallest difference first.
    r.collisions.sort_by(|x, y| {
        x.severity.cmp(&y.severity).then_with(|| {
            x.delta_e
                .unwrap_or(f64::INFINITY)
                .partial_cmp(&y.delta_e.unwrap_or(f64::INFINITY))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });

    r.worst_per_vision = worst
        .into_iter()
        .filter(|w| w.1.is_finite())
        .collect();
    r
}

#[cfg(test)]
mod tests {
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
    fn low_contrast_borders_are_reported_per_background() {
        // Near-black: invisible on the dark desktop, fine on the light one.
        let z = [id("ink", "#101010")];
        let r = analyze(&z, Thresholds::default());
        assert_eq!(r.contrast.len(), 1);
        assert_eq!(r.contrast[0].background, "dark");
    }

    #[test]
    fn duplicate_glyphs_and_labels_are_reported() {
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

    /// The finding this crate was written for, pinned as a test: the six
    /// colours Kryptik originally shipped (2026-09-11) fail the invariant.
    /// The zone files now carry the searched palette; zones.rs checks them.
    /// This stays so the metric keeps detecting the palette it was built on.
    #[test]
    fn the_original_palette_fails_the_invariant() {
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
}
