//! The zone identity model: four channels and what a valid value is in each. Glyphs come from
//! an allowlist, as a denylist missing one confusable lets a zone forge another zone's tag;
//! labels are printable ASCII, which rules out bidi overrides and homographs.

use std::fmt;

use crate::color::{ParseHexError, Srgb};

/// The border stroke a zone asks for: validated, but every border is drawn solid.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Pattern {
    Solid,
    Dashed,
    Dotted,
    Double,
    DashDot,
    Notched,
}

impl Pattern {
    pub const ALL: [Pattern; 6] = [
        Pattern::Solid,
        Pattern::Dashed,
        Pattern::Dotted,
        Pattern::Double,
        Pattern::DashDot,
        Pattern::Notched,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Pattern::Solid => "solid",
            Pattern::Dashed => "dashed",
            Pattern::Dotted => "dotted",
            Pattern::Double => "double",
            Pattern::DashDot => "dash-dot",
            Pattern::Notched => "notched",
        }
    }

    /// Parse a pattern name; an unknown name is an error, never `solid`.
    pub fn parse(s: &str) -> Result<Pattern, IdentityError> {
        Pattern::ALL
            .into_iter()
            .find(|p| p.name() == s)
            .ok_or_else(|| IdentityError::UnknownPattern(s.to_string()))
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Glyphs a zone may use: each is in DejaVu and Liberation, text (not emoji) presentation,
/// distinct from the others at 12px, no mark, control, format or space, unambiguous under NFKC.
pub const GLYPH_ALLOWLIST: &[char] = &[
    // Geometric shapes, U+25xx and U+26xx.
    '\u{25CF}', // ● BLACK CIRCLE
    '\u{25A0}', // ■ BLACK SQUARE
    '\u{25B2}', // ▲ BLACK UP-POINTING TRIANGLE
    '\u{25BC}', // ▼ BLACK DOWN-POINTING TRIANGLE
    '\u{25C6}', // ◆ BLACK DIAMOND
    '\u{25D0}', // ◐ CIRCLE WITH LEFT HALF BLACK
    '\u{25E2}', // ◢ BLACK LOWER RIGHT TRIANGLE
    '\u{2605}', // ★ BLACK STAR
    '\u{2660}', // ♠ BLACK SPADE SUIT
    '\u{2663}', // ♣ BLACK CLUB SUIT
    '\u{2666}', // ♦ BLACK DIAMOND SUIT
    '\u{266A}', // ♪ EIGHTH NOTE
    // ASCII punctuation, for a minimal font.
    '!', '?', '#', '@', '%', '&', '*', '+', '=', '~', '^', '/',
];

/// Which channel a collision was found in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Channel {
    Color,
    Pattern,
    Glyph,
    Label,
}

impl Channel {
    pub fn name(self) -> &'static str {
        match self {
            Channel::Color => "color",
            Channel::Pattern => "pattern",
            Channel::Glyph => "glyph",
            Channel::Label => "label",
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum IdentityError {
    BadColor(ParseHexError),
    UnknownPattern(String),
    GlyphNotSingleChar(String),
    GlyphNotAllowed(char),
    LabelEmpty,
    LabelTooLong(usize),
    LabelNotAscii(char),
    LabelPadded,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::BadColor(e) => write!(f, "border_color: {e}"),
            IdentityError::UnknownPattern(s) => write!(
                f,
                "border_pattern: '{s}' is not a known pattern (expected one of: {})",
                Pattern::ALL
                    .iter()
                    .map(|p| p.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            IdentityError::GlyphNotSingleChar(s) => write!(
                f,
                "glyph: must be exactly one character, got {} in '{s}'",
                s.chars().count()
            ),
            IdentityError::GlyphNotAllowed(c) => write!(
                f,
                "glyph: U+{:04X} is not on the allowlist; see GLYPH_ALLOWLIST",
                *c as u32
            ),
            IdentityError::LabelEmpty => write!(f, "label: must not be empty"),
            IdentityError::LabelTooLong(n) => {
                write!(f, "label: at most 12 characters, got {n}")
            }
            IdentityError::LabelNotAscii(c) => {
                write!(f, "label: U+{:04X} is not printable ASCII", *c as u32)
            }
            IdentityError::LabelPadded => {
                write!(f, "label: must not begin or end with a space")
            }
        }
    }
}

/// A zone's identity as configured; a missing channel stays `None`, as its absence is a finding.
#[derive(Clone, Debug)]
pub struct ZoneIdentity {
    pub zone: String,
    pub color: Srgb,
    pub pattern: Option<Pattern>,
    pub glyph: Option<char>,
    pub label: Option<String>,
}

impl ZoneIdentity {
    /// Build an identity from raw configured strings, validating each channel.
    pub fn new(
        zone: &str,
        color: &str,
        pattern: Option<&str>,
        glyph: Option<&str>,
        label: Option<&str>,
    ) -> Result<ZoneIdentity, IdentityError> {
        let color = Srgb::from_hex(color).map_err(IdentityError::BadColor)?;
        let pattern = pattern.map(Pattern::parse).transpose()?;
        let glyph = glyph.map(validate_glyph).transpose()?;
        let label = label.map(validate_label).transpose()?;
        Ok(ZoneIdentity {
            zone: zone.to_string(),
            color,
            pattern,
            glyph,
            label,
        })
    }

    /// Key for label uniqueness: lowercase alphanumerics only, so `WORK` and `W-O-R-K` collide.
    pub fn label_key(&self) -> Option<String> {
        self.label.as_ref().map(|l| {
            l.chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .map(|c| c.to_ascii_lowercase())
                .collect()
        })
    }

    /// Channels this zone configures.
    pub fn present_channels(&self) -> Vec<Channel> {
        let mut v = vec![Channel::Color];
        if self.pattern.is_some() {
            v.push(Channel::Pattern);
        }
        if self.glyph.is_some() {
            v.push(Channel::Glyph);
        }
        if self.label.is_some() {
            v.push(Channel::Label);
        }
        v
    }

    /// Whether the chrome can name this zone by glyph or label; a pattern is not drawn.
    pub fn has_non_color_channel(&self) -> bool {
        self.glyph.is_some() || self.label.is_some()
    }
}

fn validate_glyph(s: &str) -> Result<char, IdentityError> {
    let mut it = s.chars();
    let (Some(c), None) = (it.next(), it.next()) else {
        return Err(IdentityError::GlyphNotSingleChar(s.to_string()));
    };
    if !GLYPH_ALLOWLIST.contains(&c) {
        return Err(IdentityError::GlyphNotAllowed(c));
    }
    Ok(c)
}

fn validate_label(s: &str) -> Result<String, IdentityError> {
    if s.is_empty() {
        return Err(IdentityError::LabelEmpty);
    }
    // Counted in chars, but every valid label is ASCII so this is also bytes.
    let n = s.chars().count();
    if n > 12 {
        return Err(IdentityError::LabelTooLong(n));
    }
    if let Some(c) = s.chars().find(|c| !matches!(c, ' '..='~')) {
        return Err(IdentityError::LabelNotAscii(c));
    }
    if s.starts_with(' ') || s.ends_with(' ') {
        return Err(IdentityError::LabelPadded);
    }
    Ok(s.to_string())
}

#[cfg(test)]
mod tests;
