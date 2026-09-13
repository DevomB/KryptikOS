//! The distinctness invariant: can a human tell these two zones apart?
//!
//! # The rule, in one paragraph
//!
//! Every pair of zones must be separable in at least one GLOBAL channel -
//! colour or border pattern - under every vision model, and must additionally
//! have distinct glyphs and distinct labels. Colour alone counts only where
//! colour survives: if two zones' colours fall below the difference floor
//! under protanopia, deuteranopia or tritanopia, then their border patterns
//! must differ, because for a user with that vision the colour channel has
//! simply gone.
//!
//! # Why pattern uniqueness is conditional and colour uniqueness is not
//!
//! Requiring all patterns distinct would cap the system at six zones, since
//! there are six legible border styles. Refusing to start because a user
//! created a seventh zone would be hostile, and would be enforcing a
//! limitation of the enum rather than a property of perception. Requiring
//! patterns to differ only for pairs whose colours have collided expresses
//! what the channel is actually for: pattern is the backup for colour, so it
//! is required exactly where colour has failed. Glyph and label draw on
//! unbounded alphabets, so requiring those unconditionally costs nothing.
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

use crate::color::{contrast_ratio, delta_e, Srgb};
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
/// gamut for six-colour palettes under the 3:1 contrast constraint and its
/// coarse-to-fine search reaches 15.88 (measured 2026-09-13; a finer grid
/// reaches 16.2), so the floor is achievable but not by much: it is the
/// binding constraint, and the shipped colours are the search's result.
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
    /// The pair has no distinguishing global channel under some vision model.
    /// For a user with that vision, the two zones are the same window edge.
    Critical,
    /// Real, but a channel still separates the pair, or it affects legibility
    /// rather than identity.
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
    let mut worst: Vec<(Vision, f64, String, String)> = Vision::ALL
        .iter()
        .map(|&v| (v, f64::INFINITY, String::new(), String::new()))
        .collect();

    for i in 0..zones.len() {
        for j in (i + 1)..zones.len() {
            let (a, b) = (&zones[i], &zones[j]);

            // Colour, under each vision model.
            let mut colour_lost_under: Vec<(Vision, f64)> = Vec::new();
            for v in Vision::ALL {
                let d = delta_e(simulate(a.color, v), simulate(b.color, v));

                if let Some(w) = worst.iter_mut().find(|w| w.0 == v) {
                    if d < w.1 {
                        *w = (v, d, a.zone.clone(), b.zone.clone());
                    }
                }

                if d < t.min_delta_e() {
                    colour_lost_under.push((v, d));
                }
            }

            // Does a global channel still separate this pair where colour did
            // not? Distinct patterns rescue the pair; equal or absent patterns
            // do not.
            let pattern_separates = match (a.pattern, b.pattern) {
                (Some(pa), Some(pb)) => pa != pb,
                _ => false,
            };

            for (v, d) in &colour_lost_under {
                let severity = if pattern_separates {
                    Severity::Warning
                } else {
                    Severity::Critical
                };
                let detail = if pattern_separates {
                    format!(
                        "colours are indistinguishable under {} (dE00 {:.2}), but the \
                         border patterns differ ({} vs {}), so the pair is still \
                         separable at a glance",
                        v.name(),
                        d,
                        a.pattern.map(|p| p.name()).unwrap_or("-"),
                        b.pattern.map(|p| p.name()).unwrap_or("-"),
                    )
                } else {
                    format!(
                        "colours are indistinguishable under {} (dE00 {:.2}, floor {:.1}) \
                         and no border pattern separates them: {} sees one window edge \
                         for both zones. {}",
                        v.name(),
                        d,
                        t.min_delta_e(),
                        v.prevalence_note(),
                        match (a.pattern, b.pattern) {
                            (None, _) | (_, None) =>
                                "At least one zone configures no border_pattern.",
                            _ => "Both zones use the same border_pattern.",
                        }
                    )
                };
                r.collisions.push(Collision {
                    a: a.zone.clone(),
                    b: b.zone.clone(),
                    channel: Channel::Color,
                    vision: Some(*v),
                    delta_e: Some(*d),
                    severity,
                    detail,
                });
            }

            // Glyph and label are required distinct unconditionally: their
            // alphabets are unbounded, so there is never a reason to share one.
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
    fn background_constants_parse() {
        for (_, hex) in BACKGROUNDS {
            assert!(Srgb::from_hex(hex).is_ok(), "{hex}");
        }
    }

    #[test]
    fn identical_colours_collide_critically() {
        let z = [id("a", "#aa3333"), id("b", "#aa3333")];
        let r = analyze(&z, Thresholds::default());
        assert!(r.is_fatal());
        // Same colour fails under every vision model, including normal.
        assert_eq!(r.critical().count(), Vision::ALL.len());
    }

    #[test]
    fn a_distinct_pattern_downgrades_a_colour_collision() {
        let z = [
            id_p("a", "#aa3333", Pattern::Solid),
            id_p("b", "#aa3333", Pattern::Dotted),
        ];
        let r = analyze(&z, Thresholds::default());
        assert!(!r.is_fatal(), "pattern should have rescued the pair");
        assert!(r.collisions.iter().all(|c| c.severity == Severity::Warning));
    }

    #[test]
    fn the_same_pattern_does_not_rescue_anything() {
        let z = [
            id_p("a", "#aa3333", Pattern::Dotted),
            id_p("b", "#aa3333", Pattern::Dotted),
        ];
        assert!(analyze(&z, Thresholds::default()).is_fatal());
    }

    #[test]
    fn a_pattern_on_only_one_side_does_not_rescue_anything() {
        // The asymmetric case, which is what a half-finished migration looks
        // like: one zone file updated, five not.
        let z = [
            id_p("a", "#aa3333", Pattern::Dotted),
            id("b", "#aa3333"),
        ];
        assert!(analyze(&z, Thresholds::default()).is_fatal());
    }

    #[test]
    fn zones_with_no_non_colour_channel_are_reported() {
        let z = [id("a", "#aa3333"), id("b", "#2f6f9f")];
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
    fn worst_per_vision_is_reported_even_when_clean() {
        let z = [id("a", "#000000"), id("b", "#ffffff")];
        let r = analyze(&z, Thresholds::default());
        assert!(!r.is_fatal());
        assert_eq!(r.worst_per_vision.len(), Vision::ALL.len());
        for (_, d, _, _) in &r.worst_per_vision {
            assert!(*d > MIN_DELTA_E);
        }
    }

    #[test]
    fn a_single_zone_cannot_collide_with_itself() {
        let r = analyze(&[id("solo", "#aa3333")], Thresholds::default());
        assert!(r.collisions.is_empty());
        assert!(!r.is_fatal());
    }

    #[test]
    fn empty_input_is_clean() {
        let r = analyze(&[], Thresholds::default());
        assert!(!r.is_fatal());
        assert!(r.worst_per_vision.is_empty());
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
