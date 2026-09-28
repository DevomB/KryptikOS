use super::*;

#[test]
fn hash_in_string_is_not_comment() {
    let d = parse("[ui]\nborder_color = \"#aa3333\"\n").unwrap();
    assert_eq!(d.get("ui", "border_color"), Some("#aa3333"));
}

#[test]
fn comment_after_colour() {
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
fn literal_strings_keep_backslashes() {
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
fn unsupported_constructs_are_errors() {
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
fn key_before_section_is_error() {
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
fn trailing_garbage_refused() {
    let e = parse("[a]\nv = \"x\" y\n").unwrap_err();
    assert!(matches!(e.kind, TomlErrorKind::TrailingGarbage(_)));
}

/// A real zone file, verbatim.
#[test]
fn parses_real_zone_file() {
    // r##: the file contains `"#`.
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
    assert_eq!(d.get("policy", "seccomp"), Some("policy/untrusted.seccomp"));
    assert_eq!(d.get("ui", "glyph"), None);
}

#[test]
fn duplicate_keys() {
    let e = parse("[ui]\nborder_color = \"#111111\"\n[zone]\n[ui]\nborder_color = \"#222222\"\n").unwrap_err();
    assert_eq!(e.kind, TomlErrorKind::DuplicateKey("ui.border_color".into()));
    assert_eq!(e.line, 5);
    let d = parse("[ui]\nglyph = \"!\"\n[zone]\nname = \"a\"\n[ui]\nlabel = \"A\"\n").unwrap();
    assert_eq!(d.get("ui", "glyph"), Some("!"));
    assert_eq!(d.get("ui", "label"), Some("A"));
}
