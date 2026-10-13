//! Palette search, to show the floor can be met. A palette scores its smallest difference under
//! any vision model (an average would hide one colliding pair). Farthest-point traversal, then
//! steepest ascent from fixed restarts: reproducible, and a lower bound, not an optimum.

use crate::color::{contrast_ratio, ciede2000, Lab, Srgb};
use crate::cvd::{simulate, Vision};
use crate::distinct::{COMPOSITOR_COLOURS, MIN_BORDER_CONTRAST};

/// A colour in Lab as seen under each of `Vision::ALL`.
type Labs = [Lab; Vision::ALL.len()];

fn labs_of(c: Srgb) -> Labs {
    Vision::ALL.map(|v| simulate(c, v).to_lab())
}

/// A candidate colour, with its Lab under every vision model precomputed.
#[derive(Clone)]
struct Candidate {
    srgb: Srgb,
    lab: Labs,
}

/// Search parameters, for measuring which constraint binds.
#[derive(Clone, Copy, Debug)]
pub struct SearchOptions {
    /// Minimum contrast against both backgrounds; 1.0 models a border with a contrasting keyline.
    pub min_contrast: f64,
    /// Sampling step along each sRGB axis for the coarse search; 17 gives 16 levels per channel.
    pub step: u32,
    /// Refinement step around the coarse result, 0 for none. In a release build step 17 alone
    /// reaches 13.98 (step 6: 15.42 in 3.1 s); refined every 3 it reaches 15.70 in 1.8 s.
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

/// How far refinement looks around a colour, in sRGB levels: one coarse cell each way.
const REFINE_RADIUS: i32 = 17;

impl Candidate {
    /// The candidate for an 8-bit sRGB triple; `None` if out of range or below the contrast floor.
    fn from_rgb8(r: i32, g: i32, b: i32, backgrounds: &[Srgb], min_contrast: f64) -> Option<Candidate> {
        if !(0..=255).contains(&r) || !(0..=255).contains(&g) || !(0..=255).contains(&b) {
            return None;
        }
        let c = Srgb {
            r: r as f64 / 255.0,
            g: g as f64 / 255.0,
            b: b as f64 / 255.0,
        };
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
    crate::distinct::backgrounds().into_iter().map(|(_, c)| c).collect()
}

/// The compositor's own colours, which every member must also clear.
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

/// The smallest difference between two colours across all vision models.
fn distance(a: &Labs, b: &Labs) -> f64 {
    let mut worst = f64::INFINITY;
    for i in 0..a.len() {
        worst = worst.min(ciede2000(a[i], b[i]));
    }
    worst
}

/// `start` lowered to `c`'s distance from each of `others`; stops once at or below `floor`.
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

/// A palette's score: the smallest difference among its members and the compositor's colours.
fn score(pal: &[Labs], fixed: &[Labs]) -> f64 {
    let mut s = f64::INFINITY;
    for (i, a) in pal.iter().enumerate() {
        s = nearest(a, pal[i + 1..].iter().chain(fixed), s, f64::NEG_INFINITY);
    }
    s
}

/// The palette without `slot`, and its score, so a replacement costs one distance per member.
fn without(pal: &[Labs], slot: usize, fixed: &[Labs]) -> (Vec<Labs>, f64) {
    let others: Vec<Labs> = pal.iter().enumerate().filter(|&(i, _)| i != slot).map(|(_, l)| *l).collect();
    let rest = score(&others, fixed);
    (others, rest)
}

/// Move each colour to the best point within `REFINE_RADIUS`, every `fine` levels, until nothing
/// improves; fixed order and strict improvement keep it deterministic.
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
    /// Smallest difference under any vision model, compositor colours included.
    pub score: f64,
    /// How many colours the search had to choose from.
    pub candidates_considered: usize,
    /// Per-vision worst pair within the proposal, for the report.
    pub worst_per_vision: Vec<(Vision, f64)>,
}

/// Search for `n` distinguishable colours; `None` if `n` is 0 or too few clear the contrast floor.
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
    // Each candidate's distance to the compositor's colours, which no move changes.
    let to_fixed: Vec<f64> = cands.iter().map(|c| nearest(&c.lab, &fixed, f64::INFINITY, f64::NEG_INFINITY)).collect();

    // Fixed restart points, spread through the candidates.
    let restarts: Vec<usize> = (0..7).map(|k| k * cands.len() / 7).collect();

    let mut best: Option<Vec<Candidate>> = None;
    let mut best_score = f64::NEG_INFINITY;

    for &seed in &restarts {
        let mut chosen = vec![seed];
        // Membership of `chosen` by candidate index, asked once per candidate below.
        let mut in_set = vec![false; cands.len()];
        in_set[seed] = true;
        /* Farthest-point traversal: `near[c]` is c's distance to everything picked and to the
         * compositor's colours, kept current by one pass against the newest pick. */
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

        // Coarse ascent: per slot, the replacement that most improves the score.
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

    // Report in order of lightness, not search order.
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
mod tests;
