//! The TOML subset zone files use (ADR-010): comments, `[section]` headers, and `key = value`
//! with a basic, literal or bare value, kept as text. Anything else is an error, never skipped.

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
    DuplicateKey(String),
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
            TomlErrorKind::DuplicateKey(k) => write!(f, "{k} is given twice"),
            TomlErrorKind::TrailingGarbage(s) => {
                write!(f, "unexpected text after value: {s:?}")
            }
            TomlErrorKind::Unsupported(what) => write!(f, "{what} is not supported"),
            TomlErrorKind::BadEscape(c) => write!(f, "unknown string escape \\{c}"),
        }
    }
}

/// Sections in file order, read as kryptikd reads them, so the audited colour is the enforced one.
#[derive(Debug, Default, Clone)]
pub struct Document {
    pub sections: Vec<Section>,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub entries: Vec<(String, String)>,
}

impl Document {
    pub fn get(&self, section: &str, key: &str) -> Option<&str> {
        self.sections
            .iter()
            .find(|s| s.name == section)?
            .entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

pub fn parse(input: &str) -> Result<Document, TomlError> {
    let mut doc = Document::default();
    let mut current: Option<usize> = None;

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
            current = Some(match doc.sections.iter().position(|s| s.name == name) {
                Some(i) => i,
                None => {
                    doc.sections.push(Section {
                        name: name.to_string(),
                        entries: Vec::new(),
                    });
                    doc.sections.len() - 1
                }
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

        let Some(i) = current else {
            return Err(err(TomlErrorKind::KeyOutsideSection));
        };
        let section = &mut doc.sections[i];
        if section.entries.iter().any(|(k, _)| k == key) {
            return Err(err(TomlErrorKind::DuplicateKey(format!("{}.{key}", section.name))));
        }
        section.entries.push((key.to_string(), value));
    }

    Ok(doc)
}

/// Remove a trailing `# comment`, tracking quotes so a `#` in a string survives.
fn strip_comment(line: &str) -> Result<&str, TomlErrorKind> {
    let bytes = line.as_bytes();
    let mut i = 0;
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
                // Only basic strings have escapes: in 'C:\path\' the backslashes are literal.
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
    // A bare token (integer, float, boolean), kept as text: nothing needs it typed.
    Ok(v.to_string())
}

/// Unescape a basic string body after its opening quote; returns it and the bytes consumed.
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
                    /* \u and \U are refused: labels are ASCII-only, and an escaped
                     * code point could slip a bidi override past a byte check. */
                    other => return Err(TomlErrorKind::BadEscape(other)),
                });
            }
            other => out.push(other),
        }
    }
    Err(TomlErrorKind::UnterminatedString)
}

#[cfg(test)]
mod tests;
