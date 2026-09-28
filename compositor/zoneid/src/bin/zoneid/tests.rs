use super::*;
use zoneid::distinct::Severity;

fn strings(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

#[test]
fn options_read_flag_values() {
    let a = strings(&["--zones", "x", "--min-delta-e", "12"]);
    let o = options(&a, &["--zones", "--min-delta-e"]).unwrap();
    assert_eq!(flag(&o, "--zones"), Some("x"));
    assert_eq!(flag(&o, "--min-delta-e"), Some("12"));
    assert_eq!(flag(&o, "--nope"), None);
}

#[test]
fn options_refuse_unknown() {
    for bad in [&["--zone", "x"][..], &["--zones"], &["--zones", "x", "--zones", "y"], &["x"]] {
        assert!(options(&strings(bad), &["--zones"]).is_err(), "{bad:?}");
    }
}

#[test]
fn severity_names_are_distinct() {
    assert_ne!(Severity::Critical.name(), Severity::Warning.name());
}
