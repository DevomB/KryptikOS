//! zoneid: audit zone border colours, propose palettes, simulate vision models.
//!
//! Exit codes: 0 clean or informational, 1 the zone set fails the invariant,
//! 2 usage error, 3 the zone files could not be read.

use std::path::PathBuf;
use std::process::ExitCode;

use zoneid::color::Srgb;
use zoneid::cvd::{simulate, Vision};
use zoneid::distinct::{analyze, Thresholds, BACKGROUNDS, COMPOSITOR_COLOURS, MIN_DELTA_E};
use zoneid::palette::{propose_with, SearchOptions};
use zoneid::zones::load_zones;

const DEFAULT_ZONE_DIR: &str = "compartments/zones";

fn usage() -> &'static str {
    "zoneid - Kryptik zone visual identity

USAGE:
    zoneid audit [--zones DIR] [--min-delta-e N]
        Evaluate the zone set against the distinctness invariant.
        Exits 1 if any two border colours the compositor draws are
        indistinguishable.

    zoneid propose [-n N] [--min-contrast R] [--step S] [--refine F]
        Search for N maximally distinguishable border colours: a coarse
        grid every S levels, then refinement every F levels around the
        result (F = 0: coarse only).

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

/// Parse `flag value` pairs, each known flag at most once. Anything else is a
/// usage error, so a misspelt `--zone X` cannot audit the default set and pass.
fn options<'a>(args: &'a [String], known: &[&str]) -> Result<Vec<(&'a str, &'a str)>, String> {
    let mut out: Vec<(&str, &str)> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if !known.contains(&a.as_str()) {
            return Err(format!("unknown argument '{a}'"));
        }
        if out.iter().any(|(k, _)| k == a) {
            return Err(format!("{a} is given twice"));
        }
        let Some(v) = it.next() else {
            return Err(format!("{a} needs a value"));
        };
        out.push((a, v));
    }
    Ok(out)
}

fn flag<'a>(opts: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    opts.iter().find(|(k, _)| *k == name).map(|(_, v)| *v)
}

fn cmd_audit(args: &[String]) -> ExitCode {
    let args = match options(args, &["--zones", "--min-delta-e"]) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("audit: {e}\n\n{}", usage());
            return ExitCode::from(2);
        }
    };
    /* --zones, else compartments/zones here, else the set shipped beside this
     * crate, so cargo run works from anywhere in the tree. */
    let dir = match flag(&args, "--zones") {
        Some(d) => PathBuf::from(d),
        None => {
            let cwd = PathBuf::from(DEFAULT_ZONE_DIR);
            if cwd.is_dir() { cwd } else { zoneid::zones::shipped_zone_dir() }
        }
    };
    let mut t = Thresholds::default();
    if let Some(v) = flag(&args, "--min-delta-e") {
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
    for (name, hex) in COMPOSITOR_COLOURS {
        println!("  {name:<12} {hex}  (the compositor's own)");
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
        println!("Zones the chrome can only show by colour");
        for m in &r.missing {
            println!("  [warning] {} - no glyph or label", m.zone);
        }
        println!();
    }

    let crit = r.critical().count();
    if r.is_fatal() {
        println!(
            "FAIL: {crit} critical collision(s). Two border colours the compositor draws\n\
             are the same window edge to some users, so a window cannot be attributed\n\
             by looking at it."
        );
        ExitCode::from(1)
    } else {
        println!("PASS: every two border colours the compositor draws are separable under every vision model.");
        ExitCode::SUCCESS
    }
}

fn cmd_propose(args: &[String]) -> ExitCode {
    let args = match options(args, &["-n", "--min-contrast", "--step", "--refine"]) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("propose: {e}\n\n{}", usage());
            return ExitCode::from(2);
        }
    };
    let n = match flag(&args, "-n").unwrap_or("6").parse::<usize>() {
        Ok(n) if (1..=16).contains(&n) => n,
        _ => {
            eprintln!("propose: -n expects 1..=16");
            return ExitCode::from(2);
        }
    };
    let mut opts = SearchOptions::default();
    if let Some(v) = flag(&args, "--min-contrast") {
        match v.parse::<f64>() {
            Ok(r) if r >= 1.0 => opts.min_contrast = r,
            _ => {
                eprintln!("propose: --min-contrast expects a number >= 1.0");
                return ExitCode::from(2);
            }
        }
    }
    if let Some(v) = flag(&args, "--step") {
        match v.parse::<u32>() {
            Ok(s) if (1..=64).contains(&s) => opts.step = s,
            _ => {
                eprintln!("propose: --step expects 1..=64");
                return ExitCode::from(2);
            }
        }
    }
    if let Some(v) = flag(&args, "--refine") {
        match v.parse::<u32>() {
            Ok(s) if s <= 17 => opts.refine = s,
            _ => {
                eprintln!("propose: --refine expects 0..=17 (0 = coarse grid only)");
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
         \x20 constraints: contrast >= {:.1}:1 against both backgrounds; sRGB sampled every {}, refined every {}\n",
        p.candidates_considered, opts.min_contrast, opts.step, opts.refine
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
                        if d < MIN_DELTA_E { "  <-- below the floor" } else { "" }
                    );
                }
            }
        }
    }
    ExitCode::SUCCESS
}

const EXPLAIN: &str = "\
The zone distinctness invariant
===============================

A window's border colour is how a person tells which zone it belongs to
(docs/architecture.md). If they cannot tell at a glance which zone a password
prompt belongs to, the zones have failed them.

That is a claim about human perception, so it has to be checked against a model
of human perception. Comparing colour strings for equality is not one.

THE RULE

Every two border colours the compositor draws - each zone's, and its own for a
window from no zone, from an unknown zone, or asking for attention - must
differ by the floor under every vision model. Zones must have distinct glyphs
and distinct labels.

CHANNELS

  color     the whole window border        seen without looking for it
  glyph     the chrome, focused window     seen if you look
  label     the chrome, focused window     seen if you read
  pattern   not drawn                      validated, given no weight

Focus is shown by border width, never by colour, so the colour of the window
taking your keystrokes is exactly its zone's audited colour.

WHAT THIS IS NOT

A collision is a statement about two configured identities, under a stated
vision model, by a stated metric. It is not a claim that a particular person in
a particular room would be confused - that also involves habit, calibration,
ambient light and haste. This is a floor, not a guarantee.
";

#[cfg(test)]
mod tests {
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
}
