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
