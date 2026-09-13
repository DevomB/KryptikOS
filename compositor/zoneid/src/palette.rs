//! Searching for a palette that actually passes the invariant.
//!
//! Reporting that the shipped palette fails is half a finding. The other half
//! is whether a palette exists that does not, because if none does then the
//! invariant is too strict and the honest fix is to loosen it rather than to
//! demand the impossible. This module answers that by construction.
//!
//! # What is being maximised
//!
//! The score of a candidate palette is the SMALLEST colour difference between
//! any two of its members under any vision model. Maximising a minimum, not an
//! average: an average rewards a palette with four beautifully separated
//! colours and one pair that collides, which is precisely the palette that is
//! already shipping.
//!
//! # Method, and why it is deterministic
//!
//! Farthest-point traversal for an initial set, then steepest-ascent local
//! search - repeatedly replace whichever member most improves the minimum -
//! from several fixed starting points, keeping the best result.
//!
//! No randomness anywhere. A palette search that returns a different answer
//! each run cannot be used to justify a threshold, cannot be checked in CI,
//! and cannot be reproduced by whoever next asks why these six colours. The
//! restarts are at fixed indices for the same reason.
//!
//! This is a heuristic, not an optimum, and the report says so. It establishes
//! a lower bound on what is achievable, which is all the threshold argument
//! needs: if the search finds a palette scoring well above the floor, the
//! floor is not the binding constraint.

use crate::color::{contrast_ratio, ciede2000, Lab, Srgb};
use crate::cvd::{simulate, Vision};
use crate::distinct::{BACKGROUNDS, MIN_BORDER_CONTRAST};

/// A candidate colour with its appearance under every vision model
/// precomputed, because the search evaluates each pair many times.
struct Candidate {
    srgb: Srgb,
    /// Lab of this colour as seen under `Vision::ALL[i]`.
    lab: [Lab; Vision::ALL.len()],
}

/// Knobs the search exposes, so that "what is actually binding here?" is a
/// question that can be answered by measurement rather than argued about.
#[derive(Clone, Copy, Debug)]
pub struct SearchOptions {
    /// Minimum contrast a border must have against BOTH backgrounds.
    ///
    /// Set this to 1.0 to drop the constraint entirely, which is the right
    /// model for a border drawn with a contrasting keyline - see
    /// docs/gui-isolation.md. It is a much bigger lever than it looks.
    pub min_contrast: f64,
    /// Sampling step through each sRGB axis. 17 gives 16 levels per channel.
    pub step: u32,
}

impl Default for SearchOptions {
    fn default() -> Self {
        SearchOptions {
            min_contrast: MIN_BORDER_CONTRAST,
            step: 17,
        }
    }
}

fn build_candidates(min_contrast: f64, step: u32) -> Vec<Candidate> {
    let step = step.max(1);
    let mut out = Vec::new();
    let mut backgrounds = Vec::new();
    for (_, hex) in BACKGROUNDS {
        if let Ok(c) = Srgb::from_hex(hex) {
            backgrounds.push(c);
        }
    }

    let mut r = 0u32;
    while r < 256 {
        let mut g = 0u32;
        while g < 256 {
            let mut b = 0u32;
            while b < 256 {
                let c = Srgb {
                    r: r.min(255) as f64 / 255.0,
                    g: g.min(255) as f64 / 255.0,
                    b: b.min(255) as f64 / 255.0,
                };
                // A border has to be visible against every background the
                // desktop might use, not just the one the designer had open.
                if backgrounds
                    .iter()
                    .all(|&bg| contrast_ratio(c, bg) >= min_contrast)
                {
                    let mut lab = [Lab { l: 0.0, a: 0.0, b: 0.0 }; Vision::ALL.len()];
                    for (i, v) in Vision::ALL.into_iter().enumerate() {
                        lab[i] = simulate(c, v).to_lab();
                    }
                    out.push(Candidate { srgb: c, lab });
                }
                b += step;
            }
            g += step;
        }
        r += step;
    }
    out
}

/// The worst colour difference between two candidates across all vision
/// models. This is the quantity the whole search is about.
fn worst_pair_distance(a: &Candidate, b: &Candidate) -> f64 {
    let mut worst = f64::INFINITY;
    for i in 0..Vision::ALL.len() {
        let d = ciede2000(a.lab[i], b.lab[i]);
        if d < worst {
            worst = d;
        }
    }
    worst
}

fn score(cands: &[Candidate], chosen: &[usize]) -> f64 {
    let mut worst = f64::INFINITY;
    for i in 0..chosen.len() {
        for j in (i + 1)..chosen.len() {
            let d = worst_pair_distance(&cands[chosen[i]], &cands[chosen[j]]);
            if d < worst {
                worst = d;
            }
        }
    }
    worst
}

/// The distance from candidate `c` to the nearest already-chosen colour.
fn distance_to_set(cands: &[Candidate], chosen: &[usize], c: usize) -> f64 {
    chosen
        .iter()
        .map(|&i| worst_pair_distance(&cands[i], &cands[c]))
        .fold(f64::INFINITY, f64::min)
}

pub struct Proposal {
    pub colors: Vec<Srgb>,
    /// Smallest pairwise difference under any vision model.
    pub score: f64,
    /// How many colours the search had to choose from.
    pub candidates_considered: usize,
    /// Per-vision worst pair within the proposal, for the report.
    pub worst_per_vision: Vec<(Vision, f64)>,
}

/// Search for `n` maximally distinguishable colours.
///
/// Returns `None` only if the contrast filter left fewer than `n` candidates,
/// which would mean the contrast requirement itself is unsatisfiable.
pub fn propose(n: usize) -> Option<Proposal> {
    propose_with(n, SearchOptions::default())
}

/// Search with explicit options.
pub fn propose_with(n: usize, opts: SearchOptions) -> Option<Proposal> {
    let cands = build_candidates(opts.min_contrast, opts.step);
    if cands.len() < n || n == 0 {
        return None;
    }

    // Fixed restart points spread through the candidate list. Deterministic by
    // construction - see the module comment on why that matters.
    let restarts: Vec<usize> = (0..7).map(|k| k * cands.len() / 7).collect();

    let mut best: Option<Vec<usize>> = None;
    let mut best_score = f64::NEG_INFINITY;

    for &seed in &restarts {
        let mut chosen = vec![seed];
        // Farthest-point traversal: repeatedly take the candidate furthest
        // from everything already picked.
        while chosen.len() < n {
            let mut best_c = None;
            let mut best_d = f64::NEG_INFINITY;
            for c in 0..cands.len() {
                if chosen.contains(&c) {
                    continue;
                }
                let d = distance_to_set(&cands, &chosen, c);
                if d > best_d {
                    best_d = d;
                    best_c = Some(c);
                }
            }
            match best_c {
                Some(c) => chosen.push(c),
                None => break,
            }
        }

        // Steepest ascent: swap out whichever member most improves the
        // minimum, until no single swap helps.
        loop {
            let current = score(&cands, &chosen);
            let mut improved = false;
            for slot in 0..chosen.len() {
                let original = chosen[slot];
                let mut best_repl = original;
                let mut best_repl_score = current;
                for c in 0..cands.len() {
                    if chosen.contains(&c) {
                        continue;
                    }
                    chosen[slot] = c;
                    let s = score(&cands, &chosen);
                    if s > best_repl_score {
                        best_repl_score = s;
                        best_repl = c;
                    }
                }
                chosen[slot] = best_repl;
                if best_repl != original {
                    improved = true;
                }
            }
            if !improved {
                break;
            }
        }

        let s = score(&cands, &chosen);
        if s > best_score {
            best_score = s;
            best = Some(chosen);
        }
    }

    let chosen = best?;

    let mut worst_per_vision = Vec::new();
    for (i, v) in Vision::ALL.into_iter().enumerate() {
        let mut worst = f64::INFINITY;
        for a in 0..chosen.len() {
            for b in (a + 1)..chosen.len() {
                let d = ciede2000(cands[chosen[a]].lab[i], cands[chosen[b]].lab[i]);
                if d < worst {
                    worst = d;
                }
            }
        }
        worst_per_vision.push((v, worst));
    }

    // Sort the output by lightness so the palette reads as a palette rather
    // than in search order, which is meaningless to a human.
    let mut colors: Vec<Srgb> = chosen.iter().map(|&i| cands[i].srgb).collect();
    colors.sort_by(|a, b| {
        a.relative_luminance()
            .partial_cmp(&b.relative_luminance())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Some(Proposal {
        colors,
        score: if chosen.len() < 2 { f64::INFINITY } else { best_score },
        candidates_considered: cands.len(),
        worst_per_vision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distinct::{analyze, Thresholds};
    use crate::identity::ZoneIdentity;

    #[test]
    fn candidates_all_meet_the_contrast_floor() {
        let cands = build_candidates(MIN_BORDER_CONTRAST, 17);
        assert!(!cands.is_empty());
        for (_, hex) in BACKGROUNDS {
            let bg = Srgb::from_hex(hex).unwrap();
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
        let p = propose(6).unwrap();
        let mut seen: Vec<String> = Vec::new();
        for c in &p.colors {
            let h = c.to_hex();
            assert!(!seen.contains(&h), "{h} proposed twice");
            seen.push(h);
        }
    }

    /// The load-bearing claim: a palette exists that passes.
    ///
    /// Without this, the invariant might simply be unsatisfiable, and
    /// reporting the shipped palette as broken would be reporting that the
    /// standard is wrong rather than that the palette is.
    #[test]
    fn a_passing_six_colour_palette_exists() {
        let p = propose(6).unwrap();
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
    }

    #[test]
    fn asking_for_one_colour_is_not_a_division_by_zero() {
        let p = propose(1).unwrap();
        assert_eq!(p.colors.len(), 1);
        assert!(p.score.is_infinite());
    }

    #[test]
    fn asking_for_zero_colours_returns_none() {
        assert!(propose(0).is_none());
    }
}
