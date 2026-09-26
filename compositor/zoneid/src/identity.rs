//! The zone identity model: four channels and what a valid value is in each.
//!
//! Glyphs come from an allowlist, as syscalls do in the seccomp filter: a
//! denylist must foresee every bidi control, combining mark and confusable,
//! and missing one lets a zone file forge another zone's tag. Labels are
//! printable ASCII, which rules out bidi overrides and homographs at once.

use std::fmt;

use crate::color::{ParseHexError, Srgb};

/// The border stroke a zone asks for. Validated to catch typos, but every
/// border is drawn solid, so zoneid gives it no weight.
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

/// Glyphs a zone may use. Each entry is in DejaVu and Liberation, has text
/// (not emoji) presentation, differs from every other entry at 12px, is no
/// mark, control, format character or space, and is unambiguous under NFKC.
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
                "glyph: U+{:04X} is not on the allowlist. Glyphs are allowlisted, \
                 not filtered, so that font coverage and confusability are \
                 reviewed rather than assumed; see GLYPH_ALLOWLIST",
                *c as u32
            ),
            IdentityError::LabelEmpty => write!(f, "label: must not be empty"),
            IdentityError::LabelTooLong(n) => {
                write!(f, "label: at most 12 characters, got {n}")
            }
            IdentityError::LabelNotAscii(c) => write!(
                f,
                "label: U+{:04X} is not printable ASCII. Labels are ASCII-only so \
                 that bidi overrides cannot make one zone render as another",
                *c as u32
            ),
            IdentityError::LabelPadded => {
                write!(f, "label: must not begin or end with a space")
            }
        }
    }
}

/// A zone's visual identity as configured. Missing non-colour channels stay
/// `None` rather than defaulting, because their absence is a finding.
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

    /// Channels this zone actually configures.
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

    /// Whether something other than colour on screen names this zone: the
    /// glyph or label the chrome shows. A pattern is not drawn.
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
mod tests {
    use super::*;

    #[test]
    fn pattern_names_roundtrip() {
        for p in Pattern::ALL {
            assert_eq!(Pattern::parse(p.name()).unwrap(), p);
        }
    }

    #[test]
    fn unknown_pattern_refused() {
        assert_eq!(
            Pattern::parse("soild"),
            Err(IdentityError::UnknownPattern("soild".into()))
        );
    }

    #[test]
    fn glyph_allowlist_has_no_duplicates() {
        let mut seen = Vec::new();
        for &c in GLYPH_ALLOWLIST {
            assert!(!seen.contains(&c), "U+{:04X} listed twice", c as u32);
            seen.push(c);
        }
    }

    #[test]
    fn glyph_allowlist_contains_nothing_dangerous() {
        // The allowlist is the whole defence, so check what is on it.
        for &c in GLYPH_ALLOWLIST {
            assert!(!c.is_control(), "U+{:04X} is a control character", c as u32);
            assert!(!c.is_whitespace(), "U+{:04X} is whitespace", c as u32);
            /* Cf format characters (the bidi controls), and the variation
             * selectors that switch a character to emoji rendering. */
            let n = c as u32;
            assert!(
                !(0x200B..=0x200F).contains(&n),
                "U+{n:04X} is a zero-width or bidi format character"
            );
            assert!(
                !(0x202A..=0x202E).contains(&n),
                "U+{n:04X} is a bidi override"
            );
            assert!(
                !(0x2066..=0x2069).contains(&n),
                "U+{n:04X} is a bidi isolate"
            );
            assert!(
                !(0xFE00..=0xFE0F).contains(&n),
                "U+{n:04X} is a variation selector"
            );
            assert!(!(0xE000..=0xF8FF).contains(&n), "U+{n:04X} is private use");
        }
    }

    #[test]
    fn glyph_must_be_allowlisted() {
        // An ordinary character nobody reviewed.
        assert_eq!(validate_glyph("Z"), Err(IdentityError::GlyphNotAllowed('Z')));
        // A bidi override and a zero-width space.
        assert_eq!(
            validate_glyph("\u{202E}"),
            Err(IdentityError::GlyphNotAllowed('\u{202E}'))
        );
        assert_eq!(
            validate_glyph("\u{200B}"),
            Err(IdentityError::GlyphNotAllowed('\u{200B}'))
        );
        assert!(validate_glyph("\u{25CF}").is_ok());
    }

    #[test]
    fn glyph_is_one_char() {
        assert!(matches!(
            validate_glyph(""),
            Err(IdentityError::GlyphNotSingleChar(_))
        ));
        assert!(matches!(
            validate_glyph("!!"),
            Err(IdentityError::GlyphNotSingleChar(_))
        ));
        // A base plus a combining mark is two chars, refused before the allowlist.
        assert!(matches!(
            validate_glyph("!\u{0301}"),
            Err(IdentityError::GlyphNotSingleChar(_))
        ));
    }

    #[test]
    fn label_rejects_homographs() {
        // RIGHT-TO-LEFT OVERRIDE reverses the text after it.
        assert_eq!(
            validate_label("work\u{202E}"),
            Err(IdentityError::LabelNotAscii('\u{202E}'))
        );
        // Cyrillic o looks like Latin o but compares unequal.
        assert_eq!(
            validate_label("w\u{043E}rk"),
            Err(IdentityError::LabelNotAscii('\u{043E}'))
        );
    }

    #[test]
    fn label_bounds() {
        assert_eq!(validate_label(""), Err(IdentityError::LabelEmpty));
        assert_eq!(
            validate_label("THIRTEEN CHAR"),
            Err(IdentityError::LabelTooLong(13))
        );
        assert_eq!(validate_label(" WORK"), Err(IdentityError::LabelPadded));
        assert_eq!(validate_label("WORK "), Err(IdentityError::LabelPadded));
        assert!(validate_label("UNTRUSTED").is_ok());
    }

    #[test]
    fn label_key_folds_case_and_punctuation() {
        let mk = |l: &str| {
            ZoneIdentity::new("z", "#aa3333", None, None, Some(l))
                .unwrap()
                .label_key()
                .unwrap()
        };
        assert_eq!(mk("WORK"), mk("work"));
        assert_eq!(mk("WORK"), mk("W-O-R-K"));
        assert_ne!(mk("WORK"), mk("W0RK")); // zero vs O is a real difference
    }

    #[test]
    fn missing_channels_not_defaulted() {
        let z = ZoneIdentity::new("work", "#3a7d44", None, None, None).unwrap();
        assert!(!z.has_non_color_channel());
        assert_eq!(z.present_channels(), vec![Channel::Color]);
        let z = ZoneIdentity::new("work", "#3a7d44", Some("dotted"), None, None).unwrap();
        assert!(!z.has_non_color_channel(), "a pattern is not drawn");
    }
}
