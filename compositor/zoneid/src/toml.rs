//! A deliberately small TOML reader for the subset zone files actually use.
//!
//! Hand-rolled for the reason ADR-010 gives for kryptikd doing the same: this
//! parser reads the file that decides what colour a zone is, and pulling a
//! general TOML crate to read four string keys is a supply-chain decision
//! taken for convenience.
//!
//! # What it supports
//!
//! Comments, `[section]` headers, and `key = value` where value is a basic
//! string, a literal string, or a bare token (integers, booleans) kept as
//! text. That is the entire surface of compartments/zones/*.toml.
//!
//! # What it refuses
//!
//! Everything else, loudly: arrays, inline tables, dotted keys, array-of-table
//! headers, multi-line strings. A parser that skips constructs it does not
//! understand would read a file containing an array-of-tables and silently
//! return the wrong zone, and "silently returns the wrong zone" is the failure
//! mode this whole crate exists to prevent. Unsupported syntax is an error, so
//! the day a zone file needs it, this file is updated deliberately.
//!
//! # The bug this was written to avoid
//!
//! `border_color = "#aa3333"`. A naive reader strips everything after the
//! first `#` as a comment and gets an empty colour - or worse, `"` - from a
//! file that is perfectly valid TOML. Comment stripping here is done by the
//! same scanner that tracks string state, so a `#` inside quotes is just a
//! character. There is a test for exactly this.

use std::fmt;

#[derive(Debug, PartialEq)]
pub struct TomlError {
    pub line: usize,
    pub kind: TomlErrorKind,
}

#[derive(Debug, PartialEq)]
pub enum TomlErrorKind {
    UnterminatedString,
    UnterminatedSection,
    EmptySectionName,
    MissingEquals,
    EmptyKey,
    KeyOutsideSection,
    TrailingGarbage(String),
    Unsupported(&'static str),
    BadEscape(char),
}

impl fmt::Display for TomlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: ", self.line)?;
        match &self.kind {
            TomlErrorKind::UnterminatedString => write!(f, "unterminated string"),
            TomlErrorKind::UnterminatedSection => write!(f, "unterminated [section] header"),
            TomlErrorKind::EmptySectionName => write!(f, "empty section name"),
            TomlErrorKind::MissingEquals => write!(f, "expected 'key = value'"),
            TomlErrorKind::EmptyKey => write!(f, "empty key"),
            TomlErrorKind::KeyOutsideSection => {
                write!(f, "key appears before any [section] header")
            }
            TomlErrorKind::TrailingGarbage(s) => {
                write!(f, "unexpected text after value: {s:?}")
            }
            TomlErrorKind::Unsupported(what) => write!(
                f,
                "{what} is not supported by this reader. It is refused rather \
                 than skipped so that a zone file using it is never read as \
                 something other than what it says"
            ),
            TomlErrorKind::BadEscape(c) => write!(f, "unknown string escape \\{c}"),
        }
    }
}

/// A parsed document: sections in file order, each a list of key/value pairs.
///
/// A `Vec` rather than a map because zone files have a handful of keys, order
/// is useful in error messages, and a duplicate key should be visible rather
/// than silently overwriting.
#[derive(Debug, Default, Clone)]
pub struct Document {
    pub sections: Vec<Section>,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub line: usize,
    pub entries: Vec<(String, String)>,
}

impl Document {
    /// First value for `key` in the first section named `section`.
    pub fn get(&self, section: &str, key: &str) -> Option<&str> {
        self.sections
            .iter()
            .find(|s| s.name == section)?
            .entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn has_section(&self, section: &str) -> bool {
        self.sections.iter().any(|s| s.name == section)
    }
}

pub fn parse(input: &str) -> Result<Document, TomlError> {
    let mut doc = Document::default();

    for (idx, raw) in input.lines().enumerate() {
        let line = idx + 1;
        let err = |kind| TomlError { line, kind };

        let text = strip_comment(raw).map_err(err)?;
        let text = text.trim();
        if text.is_empty() {
            continue;
        }

        if let Some(rest) = text.strip_prefix('[') {
            if rest.starts_with('[') {
                return Err(err(TomlErrorKind::Unsupported("an array-of-tables header")));
            }
            let Some(name) = rest.strip_suffix(']') else {
                return Err(err(TomlErrorKind::UnterminatedSection));
            };
            let name = name.trim();
            if name.is_empty() {
                return Err(err(TomlErrorKind::EmptySectionName));
            }
            if name.contains('.') {
                return Err(err(TomlErrorKind::Unsupported("a dotted section name")));
            }
            doc.sections.push(Section {
                name: name.to_string(),
                line,
                entries: Vec::new(),
            });
            continue;
        }

        let Some(eq) = text.find('=') else {
            return Err(err(TomlErrorKind::MissingEquals));
        };
        let key = text[..eq].trim();
        let value = text[eq + 1..].trim();

        if key.is_empty() {
            return Err(err(TomlErrorKind::EmptyKey));
        }
        if key.contains('.') {
            return Err(err(TomlErrorKind::Unsupported("a dotted key")));
        }
        if value.starts_with('[') {
            return Err(err(TomlErrorKind::Unsupported("an array value")));
        }
        if value.starts_with('{') {
            return Err(err(TomlErrorKind::Unsupported("an inline table")));
        }
        if value.starts_with("\"\"\"") || value.starts_with("'''") {
            return Err(err(TomlErrorKind::Unsupported("a multi-line string")));
        }

        let value = parse_value(value).map_err(err)?;

        let Some(section) = doc.sections.last_mut() else {
            return Err(err(TomlErrorKind::KeyOutsideSection));
        };
        section.entries.push((key.to_string(), value));
    }

    Ok(doc)
}

/// Remove a trailing `# comment`, tracking string state so a `#` inside quotes
/// survives. This is the function the whole module is arranged around.
fn strip_comment(line: &str) -> Result<&str, TomlErrorKind> {
    let bytes = line.as_bytes();
    let mut i = 0;
    // Which quote character, if any, we are currently inside.
    let mut quote: Option<u8> = None;

    while i < bytes.len() {
        let c = bytes[i];
        match quote {
            None => match c {
                b'#' => return Ok(&line[..i]),
                b'"' | b'\'' => quote = Some(c),
                _ => {}
            },
            Some(q) => {
                // Escapes apply inside basic strings only; a literal string
                // has no escape character, which is why `'C:\path\'` is not a
                // thing in TOML and must not be treated as one here.
                if q == b'"' && c == b'\\' {
                    i += 1;
                } else if c == q {
                    quote = None;
                }
            }
        }
        i += 1;
    }

    if quote.is_some() {
        return Err(TomlErrorKind::UnterminatedString);
    }
    Ok(line)
}

fn parse_value(v: &str) -> Result<String, TomlErrorKind> {
    if let Some(rest) = v.strip_prefix('"') {
        let (s, consumed) = read_basic_string(rest)?;
        let tail = rest[consumed..].trim();
        if !tail.is_empty() {
            return Err(TomlErrorKind::TrailingGarbage(tail.to_string()));
        }
        return Ok(s);
    }
    if let Some(rest) = v.strip_prefix('\'') {
        let Some(end) = rest.find('\'') else {
            return Err(TomlErrorKind::UnterminatedString);
        };
        let tail = rest[end + 1..].trim();
        if !tail.is_empty() {
            return Err(TomlErrorKind::TrailingGarbage(tail.to_string()));
        }
        return Ok(rest[..end].to_string());
    }
    // A bare token: integer, float, boolean. Kept as text; nothing in a zone
    // file needs it typed, and typing it would mean deciding what a malformed
    // integer means.
    Ok(v.to_string())
}

/// Read a basic string body (after the opening quote). Returns the unescaped
/// value and how many bytes of `s` were consumed including the closing quote.
fn read_basic_string(s: &str) -> Result<(String, usize), TomlErrorKind> {
    let mut out = String::new();
    let mut it = s.char_indices();

    while let Some((i, c)) = it.next() {
        match c {
            '"' => return Ok((out, i + 1)),
            '\\' => {
                let Some((_, e)) = it.next() else {
                    return Err(TomlErrorKind::UnterminatedString);
                };
                out.push(match e {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    '"' => '"',
                    '\\' => '\\',
                    '0' => '\0',
                    // \u and \U are real TOML and genuinely not supported here.
                    // Refusing is the point: a zone label is ASCII-only, so an
                    // escaped code point in one is either a mistake or an
                    // attempt to smuggle a bidi override past a reader that
                    // only inspects the literal bytes.
                    other => return Err(TomlErrorKind::BadEscape(other)),
                });
            }
            other => out.push(other),
        }
    }
    Err(TomlErrorKind::UnterminatedString)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_inside_a_string_is_not_a_comment() {
        // The bug this module was written to avoid.
        let d = parse("[ui]\nborder_color = \"#aa3333\"\n").unwrap();
        assert_eq!(d.get("ui", "border_color"), Some("#aa3333"));
    }

    #[test]
    fn a_comment_after_a_colour_is_still_a_comment() {
        let d = parse("[ui]\nborder_color = \"#aa3333\"  # the untrusted red\n").unwrap();
        assert_eq!(d.get("ui", "border_color"), Some("#aa3333"));
    }

    #[test]
    fn full_line_comments_and_blank_lines() {
        let d = parse("# a zone\n\n[zone]\nname = \"work\"\n").unwrap();
        assert_eq!(d.get("zone", "name"), Some("work"));
    }

    #[test]
    fn bare_values_survive_as_text() {
        let d = parse("[limits]\npids_max = 1024\nmemory_max = \"8G\"\n").unwrap();
        assert_eq!(d.get("limits", "pids_max"), Some("1024"));
        assert_eq!(d.get("limits", "memory_max"), Some("8G"));
    }

    #[test]
    fn literal_strings_do_not_process_escapes() {
        let d = parse("[p]\nseccomp = 'policy\\untrusted.seccomp'\n").unwrap();
        assert_eq!(d.get("p", "seccomp"), Some("policy\\untrusted.seccomp"));
    }

    #[test]
    fn escapes_in_basic_strings() {
        let d = parse("[s]\nv = \"a\\tb\\\"c\\\\d\"\n").unwrap();
        assert_eq!(d.get("s", "v"), Some("a\tb\"c\\d"));
    }

    #[test]
    fn unknown_escape_is_refused() {
        let e = parse("[s]\nv = \"\\u202E\"\n").unwrap_err();
        assert_eq!(e.kind, TomlErrorKind::BadEscape('u'));
        assert_eq!(e.line, 2);
    }

    #[test]
    fn unsupported_constructs_are_errors_not_silence() {
        for (src, what) in [
            ("[a]\nv = [1, 2]\n", "an array value"),
            ("[a]\nv = {x = 1}\n", "an inline table"),
            ("[[a]]\n", "an array-of-tables header"),
            ("[a.b]\n", "a dotted section name"),
            ("[a]\nx.y = 1\n", "a dotted key"),
            ("[a]\nv = \"\"\"x\"\"\"\n", "a multi-line string"),
        ] {
            let e = parse(src).unwrap_err();
            assert_eq!(e.kind, TomlErrorKind::Unsupported(what), "for {src:?}");
        }
    }

    #[test]
    fn unterminated_string_is_an_error() {
        let e = parse("[a]\nv = \"oops\n").unwrap_err();
        assert_eq!(e.kind, TomlErrorKind::UnterminatedString);
    }

    #[test]
    fn key_before_any_section_is_an_error() {
        let e = parse("v = 1\n").unwrap_err();
        assert_eq!(e.kind, TomlErrorKind::KeyOutsideSection);
        assert_eq!(e.line, 1);
    }

    #[test]
    fn error_lines_are_accurate() {
        let e = parse("[a]\n\n# comment\nbroken\n").unwrap_err();
        assert_eq!(e.line, 4);
        assert_eq!(e.kind, TomlErrorKind::MissingEquals);
    }

    #[test]
    fn trailing_garbage_after_a_string_is_refused() {
        let e = parse("[a]\nv = \"x\" y\n").unwrap_err();
        assert!(matches!(e.kind, TomlErrorKind::TrailingGarbage(_)));
    }

    /// A real zone file, verbatim, so the parser is tested against the thing
    /// it actually has to read rather than against invented input.
    #[test]
    fn parses_a_real_zone_file() {
        // r##"..."## rather than r#"..."#, because the file contains `"#`.
        // The same collision the parser itself is built around, one layer up.
        let src = r##"
# untrusted - for opening things you do not trust.
#
# This is the zone the isolation exit test attacks FROM.

[zone]
name        = "untrusted"
description = "Unknown files and sketchy links. Wiped on exit."

[network]
mode = "routed"

[storage]
mode = "ephemeral"

[policy]
seccomp  = "policy/untrusted.seccomp"
landlock = "policy/untrusted.landlock"

[limits]
memory_max = "4G"
pids_max   = 512

[ui]
border_color = "#aa3333"
"##;
        let d = parse(src).unwrap();
        assert_eq!(d.get("zone", "name"), Some("untrusted"));
        assert_eq!(d.get("ui", "border_color"), Some("#aa3333"));
        assert_eq!(d.get("limits", "pids_max"), Some("512"));
        assert!(d.has_section("policy"));
        assert_eq!(d.get("ui", "glyph"), None);
    }
}
