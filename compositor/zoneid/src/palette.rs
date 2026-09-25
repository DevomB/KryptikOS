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
use crate::distinct::{BACKGROUNDS, COMPOSITOR_COLOURS, MIN_BORDER_CONTRAST};

/// A colour in Lab as seen under each of `Vision::ALL`.
type Labs = [Lab; Vision::ALL.len()];

fn labs_of(c: Srgb) -> Labs {
    Vision::ALL.map(|v| simulate(c, v).to_lab())
}

/// A candidate colour with its appearance under every vision model
/// precomputed, because the search evaluates each pair many times.
#[derive(Clone)]
struct Candidate {
    srgb: Srgb,
    lab: Labs,
}

/// Knobs the search exposes, so that "what is actually binding here?" is a
/// question that can be answered by measurement rather than argued about.
#[derive(Clone, Copy, Debug)]
pub struct SearchOptions {
    /// Minimum contrast a border must have against BOTH backgrounds.
    ///
    /// Set this to 1.0 to drop the constraint entirely, which is the right
    /// model for a border drawn with a contrasting keyline. It is a much
    /// bigger lever than it looks.
    pub min_contrast: f64,
    /// Sampling step through each sRGB axis for the coarse search. 17 gives
    /// 16 levels per channel.
    pub step: u32,
    /// Sampling step for the refinement pass that follows the coarse
    /// search: each chosen colour is moved through its neighbourhood at
    /// this resolution while the minimum improves. 0 disables refinement.
    ///
    /// The coarse grid alone is not enough. Measured on the default
    /// constraints with the compositor's colours fixed (2026-09-25, release
    /// build): step 17 alone reaches a floor of 13.98, step 12 14.49, step 9
    /// 15.05 in 1.2 s, step 6 15.42 in 3.1 s; step 17 refined every 3
    /// reaches 15.70 in 1.8 s. Refining around the coarse optimum is what
    /// makes a passing palette cheap.
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
        Some(Candidate { srgb: c, lab: labs_of(c) })
    }

    fn rgb8(&self) -> (i32, i32, i32) {
        let q = |x: f64| (x * 255.0).round() as i32;
        (q(self.srgb.r), q(self.srgb.g), q(self.srgb.b))
    }
}

fn backgrounds() -> Vec<Srgb> {
    BACKGROUNDS.iter().filter_map(|(_, hex)| Srgb::from_hex(hex).ok()).collect()
}

/// The compositor's own colours. Every palette is drawn beside them, so
/// every member is held to the floor against them as well.
fn fixed() -> Vec<Labs> {
    COMPOSITOR_COLOURS.iter().filter_map(|(_, hex)| Srgb::from_hex(hex).ok()).map(labs_of).collect()
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

/// The worst colour difference between two colours across all vision
/// models. This is the quantity the whole search is about.
fn distance(a: &Labs, b: &Labs) -> f64 {
    let mut worst = f64::INFINITY;
    for i in 0..a.len() {
        worst = worst.min(ciede2000(a[i], b[i]));
    }
    worst
}

/// `start` lowered to `c`'s distance from each of `others`, stopping once it
/// is no more than `floor`: the search only asks whether a colour beats the
/// best score so far, and most colours are out of the running early.
fn nearest<'a>(c: &Labs, others: impl IntoIterator<Item = &'a Labs>, start: f64, floor: f64) -> f64 {
    let mut near = start;
    for o in others {
        if near <= floor {
            break;
        }
        near = near.min(distance(c, o));
    }
    near
}

/// A palette's score: its smallest difference, between two members or
/// between a member and a compositor colour.
fn score(pal: &[Labs], fixed: &[Labs]) -> f64 {
    let mut s = f64::INFINITY;
    for (i, a) in pal.iter().enumerate() {
        s = nearest(a, pal[i + 1..].iter().chain(fixed), s, f64::NEG_INFINITY);
    }
    s
}

/// The palette without member `slot`, and that palette's score. Any
/// colour in the slot then scores `nearest(colour, others, rest, ..)`, so a
/// replacement costs one distance per member instead of a whole rescoring.
fn without(pal: &[Labs], slot: usize, fixed: &[Labs]) -> (Vec<Labs>, f64) {
    let others: Vec<Labs> = pal.iter().enumerate().filter(|&(i, _)| i != slot).map(|(_, l)| *l).collect();
    let rest = score(&others, fixed);
    (others, rest)
}

/// Coarse-to-fine: move each colour through the cube of radius
/// `REFINE_RADIUS` around it, sampled every `fine` levels, taking the
/// single move that most improves the palette's minimum, until no move
/// does. Candidates are made on demand, so the fine grid never exists in
/// full. Deterministic for the same reason the coarse search is: fixed
/// iteration order, strict improvement only.
fn refine(pal: &mut [Candidate], fixed: &[Labs], min_contrast: f64, fine: u32) {
    if fine == 0 {
        return;
    }
    let fine = fine as i32;
    let bgs = backgrounds();
    loop {
        let mut improved = false;
        for slot in 0..pal.len() {
            let labs: Vec<Labs> = pal.iter().map(|c| c.lab).collect();
            let (others, rest) = without(&labs, slot, fixed);
            let mut best: Option<Candidate> = None;
            let mut best_score = nearest(&labs[slot], others.iter().chain(fixed), rest, f64::NEG_INFINITY);
            let (r0, g0, b0) = pal[slot].rgb8();
            let mut r = r0 - REFINE_RADIUS;
            while r <= r0 + REFINE_RADIUS {
                let mut g = g0 - REFINE_RADIUS;
                while g <= g0 + REFINE_RADIUS {
                    let mut b = b0 - REFINE_RADIUS;
                    while b <= b0 + REFINE_RADIUS {
                        if let Some(c) = Candidate::from_rgb8(r, g, b, &bgs, min_contrast) {
                            let s = nearest(&c.lab, others.iter().chain(fixed), rest, best_score);
                            if s > best_score {
                                best_score = s;
                                best = Some(c);
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
    /// Smallest difference under any vision model, between two colours or
    /// between a colour and a compositor colour.
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
    let fixed = fixed();
    // Each candidate's distance to the compositor's colours, which no move
    // changes.
    let to_fixed: Vec<f64> = cands.iter().map(|c| nearest(&c.lab, &fixed, f64::INFINITY, f64::NEG_INFINITY)).collect();

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
        // from everything already picked and from the compositor's colours.
        // `near[c]` is that distance; one pass against the newest pick
        // keeps it current.
        let mut near: Vec<f64> =
            cands.iter().zip(&to_fixed).map(|(c, &f)| f.min(distance(&c.lab, &cands[seed].lab))).collect();
        while chosen.len() < n {
            let mut best_c = None;
            let mut best_d = f64::NEG_INFINITY;
            for c in 0..cands.len() {
                if !in_set[c] && near[c] > best_d {
                    best_d = near[c];
                    best_c = Some(c);
                }
            }
            let Some(c) = best_c else { break };
            chosen.push(c);
            in_set[c] = true;
            for (i, d) in near.iter_mut().enumerate() {
                *d = d.min(distance(&cands[i].lab, &cands[c].lab));
            }
        }

        // Ascent on the coarse grid: in each slot in turn, the replacement
        // that most improves the palette's score, until no slot improves.
        loop {
            let mut improved = false;
            for slot in 0..chosen.len() {
                let labs: Vec<Labs> = chosen.iter().map(|&i| cands[i].lab).collect();
                let (others, rest) = without(&labs, slot, &fixed);
                let original = chosen[slot];
                let mut best_c = original;
                let mut best_s = nearest(&labs[slot], &others, rest.min(to_fixed[original]), f64::NEG_INFINITY);
                for c in 0..cands.len() {
                    // Members are skipped, the slot's own colour included.
                    if in_set[c] {
                        continue;
                    }
                    let s = nearest(&cands[c].lab, &others, rest.min(to_fixed[c]), best_s);
                    if s > best_s {
                        best_s = s;
                        best_c = c;
                    }
                }
                if best_c != original {
                    chosen[slot] = best_c;
                    in_set[original] = false;
                    in_set[best_c] = true;
                    improved = true;
                }
            }
            if !improved {
                break;
            }
        }

        // Then off the grid, around what the grid found.
        let mut pal: Vec<Candidate> = chosen.iter().map(|&i| cands[i].clone()).collect();
        refine(&mut pal, &fixed, opts.min_contrast, opts.refine);

        let labs: Vec<Labs> = pal.iter().map(|c| c.lab).collect();
        let s = score(&labs, &fixed);
        if s > best_score {
            best_score = s;
            best = Some(pal);
        }
    }

    let pal = best?;

    let worst_per_vision = Vision::ALL
        .into_iter()
        .enumerate()
        .map(|(k, v)| {
            let mut worst = f64::INFINITY;
            for (i, a) in pal.iter().enumerate() {
                for b in pal[i + 1..].iter().map(|c| &c.lab).chain(&fixed) {
                    worst = worst.min(ciede2000(a.lab[k], b[k]));
                }
            }
            (v, worst)
        })
        .collect();

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
        score: best_score,
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

    /// The claim the floor rests on: a palette exists that passes.
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

    /// The coarse grid alone does not reach the floor (13.98 at step 17);
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
    fn one_colour() {
        // Scored against the compositor's colours alone.
        let p = propose(1).unwrap();
        assert_eq!(p.colors.len(), 1);
        assert!(p.score.is_finite() && p.score >= MIN_DELTA_E, "{}", p.score);
    }

    #[test]
    fn asking_for_zero_colours_returns_none() {
        assert!(propose(0).is_none());
    }
}
