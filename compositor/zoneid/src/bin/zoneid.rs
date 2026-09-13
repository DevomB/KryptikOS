//! zoneid — audit and design Kryptik zone visual identity.
//!
//! Three jobs, deliberately in one binary so the numbers in a report and the
//! numbers behind a proposal can never drift apart:
//!
//!   audit     evaluate the zone set on disk against the invariant
//!   propose   search for a palette that passes it
//!   simulate  show what given colours look like under each vision model
//!
//! Exit codes follow the house convention of meaning something:
//!   0  clean, or informational output
//!   1  the zone set FAILS the invariant
//!   2  usage error
//!   3  could not read or parse the zone files

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use zoneid::color::Srgb;
use zoneid::cvd::{simulate, Vision};
use zoneid::distinct::{analyze, Thresholds, BACKGROUNDS};
use zoneid::identity::ZoneIdentity;
use zoneid::palette::{propose_with, SearchOptions};
use zoneid::toml;

const DEFAULT_ZONE_DIR: &str = "compartments/zones";

fn usage() -> &'static str {
    "zoneid - Kryptik zone visual identity

USAGE:
    zoneid audit [--zones DIR] [--min-delta-e N]
        Evaluate the zone set against the distinctness invariant.
        Exits 1 if any pair of zones is indistinguishable.

    zoneid propose [-n N] [--min-contrast R] [--step S]
        Search for N maximally distinguishable border colours.

    zoneid simulate HEX [HEX...]
        Show colours as they appear under each vision model.

    zoneid explain
        What the invariant is and why it is shaped this way.

Zones are read from compartments/zones/*.toml by default."
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    }
    match args[0].as_str() {
        "audit" => cmd_audit(&args[1..]),
        "propose" => cmd_propose(&args[1..]),
        "simulate" => cmd_simulate(&args[1..]),
        "explain" => {
            print!("{}", EXPLAIN);
            ExitCode::SUCCESS
        }
        "-h" | "--help" | "help" => {
            println!("{}", usage());
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("zoneid: unknown command '{other}'\n\n{}", usage());
            ExitCode::from(2)
        }
    }
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1).map(|s| s.as_str())
}

fn cmd_audit(args: &[String]) -> ExitCode {
    let dir = PathBuf::from(flag(args, "--zones").unwrap_or(DEFAULT_ZONE_DIR));
    let mut t = Thresholds::default();
    if let Some(v) = flag(args, "--min-delta-e") {
        match v.parse::<f64>() {
            Ok(n) if n >= 0.0 => t.min_delta_e_millis = (n * 1000.0) as u32,
            _ => {
                eprintln!("audit: --min-delta-e expects a non-negative number, got '{v}'");
                return ExitCode::from(2);
            }
        }
    }

    let zones = match load_zones(&dir) {
        Ok(z) => z,
        Err(e) => {
            eprintln!("audit: {e}");
            return ExitCode::from(3);
        }
    };
    if zones.is_empty() {
        eprintln!("audit: no zone files found in {}", dir.display());
        return ExitCode::from(3);
    }

    println!(
        "zoneid audit - {} zones from {}",
        zones.len(),
        dir.display()
    );
    println!(
        "  floor: dE00 >= {:.1} under every vision model; border contrast >= {:.1}:1\n",
        t.min_delta_e(),
        t.min_contrast()
    );

    println!("Zones");
    for z in &zones {
        let channels: Vec<&str> = z.present_channels().iter().map(|c| c.name()).collect();
        println!(
            "  {:<12} {}  channels: {}",
            z.zone,
            z.color.to_hex(),
            channels.join(", ")
        );
    }
    println!();

    let r = analyze(&zones, t);

    println!("Worst pair per vision model");
    for (v, d, a, b) in &r.worst_per_vision {
        let verdict = if *d < t.min_delta_e() { "FAIL" } else { "ok" };
        println!(
            "  {:<14} dE00 {:>6.2}  {:<10} vs {:<10} [{}]  ({})",
            v.name(),
            d,
            a,
            b,
            verdict,
            v.prevalence_note()
        );
    }
    println!();

    if !r.collisions.is_empty() {
        println!("Collisions");
        for c in &r.collisions {
            println!(
                "  [{}] {} / {} - {}",
                c.severity.name(),
                c.a,
                c.b,
                c.channel.name()
            );
            println!("      {}", c.detail);
        }
        println!();
    }

    if !r.contrast.is_empty() {
        println!("Border contrast");
        for f in &r.contrast {
            println!(
                "  [warning] {:<12} {:.2}:1 against the {} background (floor {:.1}:1)",
                f.zone,
                f.ratio,
                f.background,
                t.min_contrast()
            );
        }
        println!();
    }

    if !r.missing.is_empty() {
        println!("Zones with no channel that survives colour-vision deficiency");
        for m in &r.missing {
            println!("  [warning] {} - colour only", m.zone);
        }
        println!(
            "      A zone identified by colour alone is unidentified for any user\n\
             \x20     who cannot see that colour. Add border_pattern, glyph and label.\n"
        );
    }

    let crit = r.critical().count();
    if r.is_fatal() {
        println!(
            "FAIL: {crit} critical collision(s). At least one pair of zones presents\n\
             the same window edge to some users, so a window cannot be attributed to\n\
             its zone by looking at it."
        );
        ExitCode::from(1)
    } else {
        println!("PASS: every pair of zones is separable in a global channel under every vision model.");
        ExitCode::SUCCESS
    }
}

fn cmd_propose(args: &[String]) -> ExitCode {
    let n = match flag(args, "-n").unwrap_or("6").parse::<usize>() {
        Ok(n) if n > 0 && n <= 16 => n,
        _ => {
            eprintln!("propose: -n expects 1..=16");
            return ExitCode::from(2);
        }
    };
    let mut opts = SearchOptions::default();
    if let Some(v) = flag(args, "--min-contrast") {
        match v.parse::<f64>() {
            Ok(r) if r >= 1.0 => opts.min_contrast = r,
            _ => {
                eprintln!("propose: --min-contrast expects a number >= 1.0");
                return ExitCode::from(2);
            }
        }
    }
    if let Some(v) = flag(args, "--step") {
        match v.parse::<u32>() {
            Ok(s) if s >= 1 && s <= 64 => opts.step = s,
            _ => {
                eprintln!("propose: --step expects 1..=64");
                return ExitCode::from(2);
            }
        }
    }

    let Some(p) = propose_with(n, opts) else {
        eprintln!(
            "propose: no palette of {n} colours satisfies a contrast floor of {:.1}:1 \
             against both backgrounds",
            opts.min_contrast
        );
        return ExitCode::from(1);
    };

    println!(
        "zoneid propose - {n} colours, chosen from {} candidates\n\
         \x20 constraints: contrast >= {:.1}:1 against both backgrounds; sRGB sampled every {}\n",
        p.candidates_considered, opts.min_contrast, opts.step
    );

    println!("Palette");
    for c in &p.colors {
        let dark = Srgb::from_hex(BACKGROUNDS[0].1).unwrap();
        let light = Srgb::from_hex(BACKGROUNDS[1].1).unwrap();
        println!(
            "  {}   contrast {:>5.2}:1 dark  {:>5.2}:1 light",
            c.to_hex(),
            zoneid::contrast_ratio(*c, dark),
            zoneid::contrast_ratio(*c, light),
        );
    }
    println!();

    println!("Separation achieved");
    for (v, d) in &p.worst_per_vision {
        println!("  {:<14} worst pair dE00 {:>6.2}", v.name(), d);
    }
    println!("\n  overall floor: dE00 {:.2}", p.score);
    println!(
        "\nHeuristic search, not a proven optimum: it establishes a lower bound on\n\
         what is achievable under these constraints."
    );
    ExitCode::SUCCESS
}

fn cmd_simulate(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("simulate: expected one or more #RRGGBB colours");
        return ExitCode::from(2);
    }
    let mut colors = Vec::new();
    for a in args {
        match Srgb::from_hex(a) {
            Ok(c) => colors.push((a.clone(), c)),
            Err(e) => {
                eprintln!("simulate: {a}: {e}");
                return ExitCode::from(2);
            }
        }
    }

    print!("{:<10}", "input");
    for v in Vision::ALL {
        print!("{:<14}", v.name());
    }
    println!();
    for (name, c) in &colors {
        print!("{:<10}", name);
        for v in Vision::ALL {
            print!("{:<14}", simulate(*c, v).to_hex());
        }
        println!();
    }

    if colors.len() > 1 {
        println!("\nPairwise dE00");
        for v in Vision::ALL {
            println!("  {}", v.name());
            for i in 0..colors.len() {
                for j in (i + 1)..colors.len() {
                    let d = zoneid::delta_e(
                        simulate(colors[i].1, v),
                        simulate(colors[j].1, v),
                    );
                    println!(
                        "    {:<10} vs {:<10} {:>6.2}{}",
                        colors[i].0,
                        colors[j].0,
                        d,
                        if d < 15.0 { "  <-- below the floor" } else { "" }
                    );
                }
            }
        }
    }
    ExitCode::SUCCESS
}

/// Read every `*.toml` in `dir` as a zone definition.
///
/// A file without a `[ui] border_color` is skipped rather than failing the
/// run: the directory is a zone directory, not a palette file, and a zone that
/// does not configure a colour is a separate problem from zones whose colours
/// collide.
fn load_zones(dir: &Path) -> Result<Vec<ZoneIdentity>, String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?;

    let mut paths: Vec<PathBuf> = Vec::new();
    for e in entries {
        let e = e.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) == Some("toml") {
            paths.push(p);
        }
    }
    // Sorted so the report is stable across filesystems.
    paths.sort();

    let mut out = Vec::new();
    for p in paths {
        let text = std::fs::read_to_string(&p)
            .map_err(|e| format!("cannot read {}: {e}", p.display()))?;
        let doc = toml::parse(&text).map_err(|e| format!("{}: {e}", p.display()))?;

        let Some(color) = doc.get("ui", "border_color") else {
            continue;
        };
        // Fall back to the filename only if the file does not name itself;
        // the [zone] name is authoritative because that is what kryptikd uses.
        let name = doc
            .get("zone", "name")
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                p.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("?")
                    .to_string()
            });

        let id = ZoneIdentity::new(
            &name,
            color,
            doc.get("ui", "border_pattern"),
            doc.get("ui", "glyph"),
            doc.get("ui", "label"),
        )
        .map_err(|e| format!("{}: [ui] {e}", p.display()))?;
        out.push(id);
    }
    Ok(out)
}

const EXPLAIN: &str = "\
The zone distinctness invariant
===============================

docs/architecture.md says the per-zone window border is \"load-bearing, not
decoration\": if a user cannot tell at a glance which zone a password prompt
belongs to, compartmentalization has failed at the only layer that matters.

That is a claim about human perception, so it has to be checked against a model
of human perception. Comparing colour strings for equality is not one.

THE RULE

Every pair of zones must be separable in at least one GLOBAL channel under
every vision model, and must have distinct glyphs and distinct labels.

CHANNELS

  color     global   the whole window edge      trichromatic vision only
  pattern   global   the whole window edge      survives CVD and monochrome
  glyph     point    the titlebar tag           survives everything, if you look
  label     point    the titlebar tag           survives everything, if you read

Global channels are perceived without looking directly at them. Point channels
require attention. A design with only point channels identifies every window
correctly and still fails the \"at a glance\" standard, because the user has to
stop and read a tag before typing a password.

WHY PATTERN UNIQUENESS IS CONDITIONAL

Colour, glyph and label must always be distinct - their alphabets are
unbounded, so sharing one is never necessary. Border pattern has six legible
values, so requiring all patterns distinct would cap the system at six zones.
Instead it is required to differ only for a pair whose colours have collided,
which is exactly what the channel is for: pattern backs up colour, so it must
differ where colour has failed.

WHAT THIS IS NOT

A collision is a statement about two configured identities, under a stated
vision model, by a stated metric. It is not a claim that a particular person in
a particular room would be confused - that also involves habit, calibration,
ambient light and haste. This is a floor, not a guarantee.
";

#[cfg(test)]
mod tests {
    use super::*;
    use zoneid::distinct::{Severity, MIN_BORDER_CONTRAST};

    #[test]
    fn flag_reads_the_following_argument() {
        let a: Vec<String> = ["--zones", "x", "--min-delta-e", "12"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(flag(&a, "--zones"), Some("x"));
        assert_eq!(flag(&a, "--min-delta-e"), Some("12"));
        assert_eq!(flag(&a, "--nope"), None);
    }

    #[test]
    fn a_trailing_flag_with_no_value_is_none_not_a_panic() {
        let a: Vec<String> = vec!["--zones".to_string()];
        assert_eq!(flag(&a, "--zones"), None);
    }

    #[test]
    fn min_border_contrast_is_referenced() {
        // Keeps the import honest if the default ever stops being used here.
        assert!(MIN_BORDER_CONTRAST > 1.0);
    }

    #[test]
    fn severity_names_are_distinct() {
        assert_ne!(Severity::Critical.name(), Severity::Warning.name());
    }
}
