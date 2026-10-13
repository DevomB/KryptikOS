use super::*;
use crate::distinct::{analyze, Thresholds, MIN_DELTA_E};
use crate::identity::ZoneIdentity;
use std::sync::OnceLock;

/// The default search, run once: it is deterministic and takes seconds.
fn default_six() -> &'static Proposal {
    static P: OnceLock<Proposal> = OnceLock::new();
    P.get_or_init(|| propose(6).unwrap())
}

#[test]
fn candidates_meet_contrast_floor() {
    let cands = build_candidates(MIN_BORDER_CONTRAST, 17);
    assert!(!cands.is_empty());
    for bg in backgrounds() {
        for c in &cands {
            assert!(contrast_ratio(c.srgb, bg) >= MIN_BORDER_CONTRAST);
        }
    }
}

#[test]
fn search_is_deterministic() {
    let a = propose(6).unwrap();
    let b = propose(6).unwrap();
    let ha: Vec<String> = a.colors.iter().map(|c| c.to_hex()).collect();
    let hb: Vec<String> = b.colors.iter().map(|c| c.to_hex()).collect();
    assert_eq!(ha, hb, "the search must return the same palette every run");
}

#[test]
fn proposed_colours_are_distinct() {
    let p = default_six();
    let mut seen: Vec<String> = Vec::new();
    for c in &p.colors {
        let h = c.to_hex();
        assert!(!seen.contains(&h), "{h} proposed twice");
        seen.push(h);
    }
}

/// The floor must be achievable: some six-colour palette passes.
#[test]
fn six_colour_palette_passes() {
    let p = default_six();
    let zones: Vec<ZoneIdentity> = p
        .colors
        .iter()
        .enumerate()
        .map(|(i, c)| {
            ZoneIdentity::new(&format!("z{i}"), &c.to_hex(), None, None, None).unwrap()
        })
        .collect();
    let r = analyze(&zones, Thresholds::default());
    assert!(
        !r.is_fatal(),
        "proposed palette scored {:.2} yet still failed the invariant",
        p.score
    );
    // A worse search result must show, not hide under the floor.
    assert!(p.score >= MIN_DELTA_E + 0.5, "default search reached only {:.2}", p.score);
}

/// The coarse grid alone stays under the floor (13.98 at step 17); refinement reaches it.
#[test]
fn refinement_reaches_floor() {
    let coarse = propose_with(6, SearchOptions { refine: 0, ..SearchOptions::default() }).unwrap();
    let refined = default_six();
    assert!(coarse.score < refined.score, "coarse {:.2} vs refined {:.2}", coarse.score, refined.score);
    assert!(coarse.score < MIN_DELTA_E, "the coarse grid passes alone ({:.2}): update the docs here and on SearchOptions::refine", coarse.score);
}

#[test]
fn one_colour() {
    // Scored against the compositor's colours alone.
    let p = propose(1).unwrap();
    assert_eq!(p.colors.len(), 1);
    assert!(p.score.is_finite() && p.score >= MIN_DELTA_E, "{}", p.score);
}

#[test]
fn zero_colours_returns_none() {
    assert!(propose(0).is_none());
}
