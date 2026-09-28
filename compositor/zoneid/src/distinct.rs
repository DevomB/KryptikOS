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

/// BACKGROUNDS parsed, in order; constants_parse checks that none is dropped.
pub fn backgrounds() -> Vec<(&'static str, Srgb)> {
    BACKGROUNDS.iter().filter_map(|&(name, hex)| Some((name, Srgb::from_hex(hex).ok()?))).collect()
}

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
    let bgs = backgrounds();

    for z in zones {
        if !z.has_non_color_channel() {
            r.missing.push(MissingChannel {
                zone: z.zone.clone(),
            });
        }
        for &(bg_name, bg) in &bgs {
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
mod tests;
