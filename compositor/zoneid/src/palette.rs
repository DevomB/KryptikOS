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
#[derive(Clone)]
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
    /// Sampling step through each sRGB axis for the coarse search. 17 gives
    /// 16 levels per channel.
    pub step: u32,
    /// Sampling step for the refinement pass that follows the coarse
    /// search: each chosen colour is moved through its neighbourhood at
    /// this resolution while the minimum improves. 0 disables refinement.
    ///
    /// The coarse grid alone is not enough. Measured on the default
    /// constraints (2026-09-13, release build): step 17 reaches a floor of
    /// 14.08 in 3 s, step 12 14.66, step 9 15.00 in 15 s, and step 6 15.87
    /// in 2 min 18 s. Sampling finely is what finds a passing palette, and
    /// refining around the coarse optimum is what makes that affordable.
    pub refine: u32,
}

impl Default for SearchOptions {
    fn default() -> Self {
        SearchOptions {
            min_contrast: MIN_BORDER_CONTRAST,
            step: 17,
            refine: 3,
        }
    }
}

/// How far, in sRGB levels per channel, refinement looks around a colour.
/// One coarse cell in each direction: the coarse optimum is somewhere in the
/// cell it was sampled in, and its true neighbours are in the cells around.
const REFINE_RADIUS: i32 = 17;

impl Candidate {
    /// The candidate for an 8-bit sRGB triple, or `None` if it fails the
    /// contrast floor against any background.
    fn from_rgb8(r: i32, g: i32, b: i32, backgrounds: &[Srgb], min_contrast: f64) -> Option<Candidate> {
        if !(0..=255).contains(&r) || !(0..=255).contains(&g) || !(0..=255).contains(&b) {
            return None;
        }
        let c = Srgb {
            r: r as f64 / 255.0,
            g: g as f64 / 255.0,
            b: b as f64 / 255.0,
        };
        // A border has to be visible against every background the desktop
        // might use, not just the one the designer had open.
        if !backgrounds.iter().all(|&bg| contrast_ratio(c, bg) >= min_contrast) {
            return None;
        }
        let mut lab = [Lab { l: 0.0, a: 0.0, b: 0.0 }; Vision::ALL.len()];
        for (i, v) in Vision::ALL.into_iter().enumerate() {
            lab[i] = simulate(c, v).to_lab();
        }
        Some(Candidate { srgb: c, lab })
    }

    fn rgb8(&self) -> (i32, i32, i32) {
        let q = |x: f64| (x * 255.0).round() as i32;
        (q(self.srgb.r), q(self.srgb.g), q(self.srgb.b))
    }
}

fn backgrounds() -> Vec<Srgb> {
    BACKGROUNDS.iter().filter_map(|(_, hex)| Srgb::from_hex(hex).ok()).collect()
}

fn build_candidates(min_contrast: f64, step: u32) -> Vec<Candidate> {
    let step = step.max(1) as i32;
    let bgs = backgrounds();
    let mut out = Vec::new();
    let mut r = 0;
    while r < 256 {
        let mut g = 0;
        while g < 256 {
            let mut b = 0;
            while b < 256 {
                if let Some(c) = Candidate::from_rgb8(r.min(255), g.min(255), b.min(255), &bgs, min_contrast) {
                    out.push(c);
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

/// The score of a palette: its smallest pairwise difference.
fn score_of(pal: &[Candidate]) -> f64 {
    let mut worst = f64::INFINITY;
    for i in 0..pal.len() {
        for j in (i + 1)..pal.len() {
            let d = worst_pair_distance(&pal[i], &pal[j]);
            if d < worst {
                worst = d;
            }
        }
    }
    worst
}

/// The score of the palette `chosen` indexes into `cands`. Same quantity as
/// `score_of`, without materialising the palette: this is evaluated once per
/// candidate per slot in the ascent below, tens of thousands of times a run.
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

/// Coarse-to-fine: move each colour through the cube of radius
/// `REFINE_RADIUS` around it, sampled every `fine` levels, taking the
/// single move that most improves the palette's minimum, until no move
/// does. Candidates are made on demand, so the fine grid never exists in
/// full. Deterministic for the same reason the coarse search is: fixed
/// iteration order, strict improvement only.
fn refine(pal: &mut [Candidate], min_contrast: f64, fine: u32) {
    if fine == 0 || pal.len() < 2 {
        return;
    }
    let fine = fine as i32;
    let bgs = backgrounds();
    loop {
        let mut improved = false;
        for slot in 0..pal.len() {
            let current = score_of(pal);
            let (r0, g0, b0) = pal[slot].rgb8();
            let mut best: Option<Candidate> = None;
            let mut best_score = current;
            let mut r = r0 - REFINE_RADIUS;
            while r <= r0 + REFINE_RADIUS {
                let mut g = g0 - REFINE_RADIUS;
                while g <= g0 + REFINE_RADIUS {
                    let mut b = b0 - REFINE_RADIUS;
                    while b <= b0 + REFINE_RADIUS {
                        if let Some(c) = Candidate::from_rgb8(r, g, b, &bgs, min_contrast) {
                            let saved = std::mem::replace(&mut pal[slot], c);
                            let s = score_of(pal);
                            let moved = std::mem::replace(&mut pal[slot], saved);
                            if s > best_score {
                                best_score = s;
                                best = Some(moved);
                            }
                        }
                        b += fine;
                    }
                    g += fine;
                }
                r += fine;
            }
            if let Some(c) = best {
                pal[slot] = c;
                improved = true;
            }
        }
        if !improved {
            break;
        }
    }
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

    let mut best: Option<Vec<Candidate>> = None;
    let mut best_score = f64::NEG_INFINITY;

    for &seed in &restarts {
        let mut chosen = vec![seed];
        // Membership of `chosen`, by candidate index: the loops below ask
        // it once per candidate, and a scan of `chosen` for each of tens of
        // thousands of candidates was most of the coarse search's time.
        let mut in_set = vec![false; cands.len()];
        in_set[seed] = true;
        // Farthest-point traversal: repeatedly take the candidate furthest
        // from everything already picked. `nearest[c]` is c's distance to
        // the set so far; one pass against the newest pick keeps it current
        // (min is exact, so the result is bit-identical to recomputing).
        let mut nearest: Vec<f64> = cands.iter().map(|c| worst_pair_distance(c, &cands[seed])).collect();
        while chosen.len() < n {
            let mut best_c = None;
            let mut best_d = f64::NEG_INFINITY;
            for c in 0..cands.len() {
                if in_set[c] {
                    continue;
                }
                let d = nearest[c];
                if d > best_d {
                    best_d = d;
                    best_c = Some(c);
                }
            }
            match best_c {
                Some(c) => {
                    chosen.push(c);
                    in_set[c] = true;
                    for (i, near) in nearest.iter_mut().enumerate() {
                        let d = worst_pair_distance(&cands[i], &cands[c]);
                        if d < *near {
                            *near = d;
                        }
                    }
                }
                None => break,
            }
        }

        // Steepest ascent on the coarse grid: swap out whichever member most
        // improves the minimum, until no single swap helps.
        loop {
            let current = score(&cands, &chosen);
            let mut improved = false;
            for slot in 0..chosen.len() {
                let original = chosen[slot];
                let mut best_repl = original;
                let mut best_repl_score = current;
                for c in 0..cands.len() {
                    // Members of the set are skipped, the slot's own colour
                    // included: putting it back scores `current`, which is
                    // never a strict improvement.
                    if in_set[c] {
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
                    in_set[original] = false;
                    in_set[best_repl] = true;
                    improved = true;
                }
            }
            if !improved {
                break;
            }
        }

        // Then off the grid, around what the grid found.
        let mut pal: Vec<Candidate> = chosen.iter().map(|&i| cands[i].clone()).collect();
        refine(&mut pal, opts.min_contrast, opts.refine);

        let s = score_of(&pal);
        if s > best_score {
            best_score = s;
            best = Some(pal);
        }
    }

    let pal = best?;

    let mut worst_per_vision = Vec::new();
    for (i, v) in Vision::ALL.into_iter().enumerate() {
        let mut worst = f64::INFINITY;
        for a in 0..pal.len() {
            for b in (a + 1)..pal.len() {
                let d = ciede2000(pal[a].lab[i], pal[b].lab[i]);
                if d < worst {
                    worst = d;
                }
            }
        }
        worst_per_vision.push((v, worst));
    }

    // Sort the output by lightness so the palette reads as a palette rather
    // than in search order, which is meaningless to a human.
    let mut colors: Vec<Srgb> = pal.iter().map(|c| c.srgb).collect();
    colors.sort_by(|a, b| {
        a.relative_luminance()
            .partial_cmp(&b.relative_luminance())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Some(Proposal {
        colors,
        score: if pal.len() < 2 { f64::INFINITY } else { best_score },
        candidates_considered: cands.len(),
        worst_per_vision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distinct::{analyze, Thresholds, MIN_DELTA_E};
    use crate::identity::ZoneIdentity;
    use std::sync::OnceLock;

    /// One default search, shared: it is deterministic (checked below), and
    /// a coarse-to-fine search is seconds of work per call.
    fn default_six() -> &'static Proposal {
        static P: OnceLock<Proposal> = OnceLock::new();
        P.get_or_init(|| propose(6).unwrap())
    }

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
        let p = default_six();
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
        // The number the search reaches is part of the claim: a change that
        // makes it worse must be seen, not absorbed by the floor.
        assert!(p.score >= MIN_DELTA_E + 0.5, "default search reached only {:.2}", p.score);
    }

    /// The coarse grid alone does not reach the floor (14.08 at step 17);
    /// refinement is what does. Pinned so that removing it cannot look like
    /// a harmless cleanup.
    #[test]
    fn refinement_is_what_reaches_the_floor() {
        let coarse = propose_with(6, SearchOptions { refine: 0, ..SearchOptions::default() }).unwrap();
        let refined = default_six();
        assert!(coarse.score < refined.score, "coarse {:.2} vs refined {:.2}", coarse.score, refined.score);
        assert!(coarse.score < MIN_DELTA_E, "the coarse grid now passes on its own ({:.2}); update this comment and the doc on SearchOptions::refine", coarse.score);
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
