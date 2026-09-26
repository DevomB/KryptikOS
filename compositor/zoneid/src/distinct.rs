//! The distinctness invariant. Every two border colours the compositor draws
//! (each zone's, and its own for unzoned, unknown and urgent windows) must
//! differ by the floor under every vision model, and zones must have distinct
//! glyphs and labels. Patterns are not drawn, so they separate nothing.

use crate::color::{ciede2000, contrast_ratio, Lab, Srgb};
use crate::cvd::{simulate, Vision};
use crate::identity::{Channel, ZoneIdentity};

/// The colour-difference floor, in CIEDE2000 units. About 1 is just noticeable
/// side by side in a lab, but a border is seen at the edge of vision on an
/// uncalibrated screen. `zoneid propose` reaches 15.70 for six colours under
/// the contrast rule, so 15.0 binds; the shipped colours reach 15.88.
pub const MIN_DELTA_E: f64 = 15.0;

/// Minimum contrast of a zone border against the background: 3:1, as WCAG 2.1
/// SC 1.4.11 requires for user interface components.
pub const MIN_BORDER_CONTRAST: f64 = 3.0;

/// Backgrounds a border is checked against: a colour tuned for one can vanish on the other.
pub const BACKGROUNDS: [(&str, &str); 2] = [("dark", "#1c1c1c"), ("light", "#f0f0f0")];

/// The compositor's own border colours: unzoned windows (the chrome), zones it
/// has no colour for, and urgent windows. gen-zone-colours.py writes the same
/// values into dwl's header, and a test in zones.rs keeps the two equal. They
/// are held to the floor but not the contrast rule: the unzoned grey is light.
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
    /// Two border colours below the floor under some vision model.
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
    /// The vision model it occurs under; `None` for glyph and label.
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
    /// Smallest colour difference per vision model and its pair, reported even on a pass.
    pub worst_per_vision: Vec<(Vision, f64, String, String)>,
}

impl Report {
    pub fn critical(&self) -> impl Iterator<Item = &Collision> {
        self.collisions
            .iter()
            .filter(|c| c.severity == Severity::Critical)
    }

    /// Whether the zone set should be refused. Only critical collisions refuse;
    /// missing channels and low contrast are reported.
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
            // Constants checked by constants_parse; failure is a programming error.
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

    // The worst pair per vision model, indexed like Vision::ALL.
    let mut worst: Vec<(Vision, f64, String, String)> = Vision::ALL
        .iter()
        .map(|&v| (v, f64::INFINITY, String::new(), String::new()))
        .collect();

    // Every border colour on screen, in Lab once per vision model.
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

    // Worst first: critical before warning, then the smallest difference.
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
}
