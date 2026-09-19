//! The wall clock: what zone 0 will believe about the time
//! (docs/design/time.md).
//!
//! CLOCK_REALTIME is one clock for the whole machine and only zone 0 may set
//! it, but zone 0 has no network; the zone that can ask a time server is the
//! net zone, which is treated as hostile and could not set the clock if it
//! wanted to. So what arrives here is a CLAIM - an offset the net zone says
//! it measured - and this module is what zone 0 knows that the network does
//! not: a floor no claim may cross, a bound on what is believed without
//! asking, and the person's word for anything past it.
//!
//! The decision is a pure function of its inputs. Nothing in it reads a
//! clock, a file or the environment, so every rule below is a unit test.

/// Below this many seconds a correction is slewed rather than stepped, so
/// the clock never runs backwards under a running program.
pub const SLEW_BELOW_SECS: f64 = 1.0;
/// Below this the claim agrees with the clock and nothing is done.
pub const IGNORE_BELOW_SECS: f64 = 0.005;
/// What is believed without asking, per claim and in total, either way.
pub const DEFAULT_BOUND_SECS: i64 = 3600;
/// One claim is considered per interval; the rest are refused unread, so a
/// hostile zone cannot turn the consent prompt into a flood.
pub const CLAIM_INTERVAL_SECS: u64 = 600;

/// What the net zone says: add `offset` seconds to the clock; `sources`
/// servers agreed on it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Claim {
    pub offset: f64,
    pub sources: u8,
}

/// `<seconds> <sources>` as it arrives after the verb. The grammar is
/// narrow on purpose: a sign, at most ten integer digits, at most six
/// fractional ones, and a source count of 1 to 16. No exponent, no
/// infinity, no NaN, nothing a float parser would accept and a person would
/// not have written.
pub fn parse_claim(args: &str) -> Result<Claim, String> {
    let mut it = args.split(' ');
    let (Some(secs), Some(sources), None) = (it.next(), it.next(), it.next()) else {
        return Err("usage: time-offset <seconds> <sources>".into());
    };
    let body = secs.strip_prefix(['-', '+']).unwrap_or(secs);
    let (int, frac) = body.split_once('.').unwrap_or((body, ""));
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(int) || int.len() > 10 || frac.len() > 6 || (body.contains('.') && !digits(frac)) {
        return Err(format!("{secs:?} is not an offset in seconds (sign, up to 10 digits, up to 6 decimals)"));
    }
    let offset: f64 = secs.parse().map_err(|_| format!("{secs:?} is not an offset in seconds"))?;
    let sources: u8 = match sources.parse() {
        Ok(n @ 1..=16) if digits(sources) => n,
        _ => return Err(format!("{sources:?} is not a source count between 1 and 16")),
    };
    Ok(Claim { offset, sources })
}

/// What zone 0 knows when a claim arrives.
#[derive(Debug, Clone, Copy)]
pub struct Knowledge {
    /// The clock now, in seconds since the epoch.
    pub now: f64,
    /// No proposal below this is accepted or offered for consent: the
    /// running image's build date, or a later release this machine has
    /// committed to. The OS cannot have been built in the future of the
    /// present.
    pub floor: i64,
    /// What is believed without asking.
    pub bound: i64,
    /// The corrections already applied without asking since the last time
    /// the clock was anchored (by the person's consent, or by the floor).
    /// A hostile zone may lie by less than the bound every interval; the
    /// bound is on the sum, so it cannot walk the clock by many small steps.
    pub moved_unasked: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// The claim agrees with the clock.
    Ignore,
    /// Apply gradually; the clock never steps backwards.
    Slew { offset: f64 },
    /// Set the clock to `to`.
    Step { to: f64 },
    /// Past the bound: the person decides, shown both times.
    Ask { to: f64 },
    Refuse(String),
}

pub fn decide(k: &Knowledge, c: &Claim) -> Decision {
    if !c.offset.is_finite() || !k.now.is_finite() {
        return Decision::Refuse("the offset is not a number".into());
    }
    let to = k.now + c.offset;
    // The floor first, and before consent: a time the OS cannot have existed
    // in is never put in front of the person as a choice.
    if to < k.floor as f64 {
        return Decision::Refuse(format!(
            "{} is before this system was built ({}); not offered, not applied",
            format_utc(to),
            format_utc(k.floor as f64)
        ));
    }
    let size = c.offset.abs();
    if size < IGNORE_BELOW_SECS {
        return Decision::Ignore;
    }
    if size + k.moved_unasked > k.bound as f64 {
        return Decision::Ask { to };
    }
    if size < SLEW_BELOW_SECS {
        Decision::Slew { offset: c.offset }
    } else {
        Decision::Step { to }
    }
}

/// What `moved_unasked` becomes once a decision has been carried out: an
/// unasked correction adds to the sum, and the person's word (or the floor)
/// anchors the clock and starts the sum again.
pub fn moved_after(k: &Knowledge, c: &Claim, d: &Decision, consented: bool) -> f64 {
    match d {
        Decision::Slew { .. } | Decision::Step { .. } => k.moved_unasked + c.offset.abs(),
        Decision::Ask { .. } if consented => 0.0,
        _ => k.moved_unasked,
    }
}

/// A clock that reads earlier than the floor is wrong by definition - a dead
/// RTC battery starts a machine in 1970 or 2000 - and zone 0 repairs that by
/// itself, with no network: the floor is a time the system is known to have
/// existed at. Returns the time to set, or None when the clock is not below
/// the floor.
pub fn clamp_to_floor(now: f64, floor: i64) -> Option<f64> {
    (now < floor as f64).then_some(floor as f64)
}

/// `built_at` from /etc/kryptik-image.json, as seconds since the epoch. The
/// file is written by the build with `date -Iseconds`
/// (2026-09-19T18:11:28+00:00); only that shape is read, and anything else
/// is None, which the caller must treat as "no floor known", never as zero.
pub fn floor_from_image_json(text: &str) -> Option<i64> {
    let at = text.find("\"built_at\"")?;
    let rest = &text[at + "\"built_at\"".len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start().strip_prefix('"')?;
    parse_iso8601(&rest[..rest.find('"')?])
}

/// YYYY-MM-DDThh:mm:ss followed by Z or a +hh:mm / -hh:mm offset.
pub fn parse_iso8601(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        t.bytes().all(|c| c.is_ascii_digit()).then(|| t.parse().ok()).flatten()
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let zone = match &s[19..] {
        "Z" => 0,
        z if z.len() == 6 && (z.starts_with('+') || z.starts_with('-')) && z.as_bytes()[3] == b':' => {
            let (zh, zm) = (num(20..22)?, num(23..25)?);
            if zh > 23 || zm > 59 {
                return None;
            }
            let secs = zh * 3600 + zm * 60;
            if z.starts_with('-') { -secs } else { secs }
        }
        _ => return None,
    };
    Some(days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se - zone)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// algorithm; exact for every date this system will see).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// A time as the person is shown it and as the history records it: to the
/// minute, in UTC, because that is what a watch can be checked against.
pub fn format_utc(t: f64) -> String {
    let secs = t.floor() as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", rem / 3600, rem % 3600 / 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUILT: i64 = 1_789_841_488; // 2026-09-19 18:11:28 UTC

    fn k(now: f64) -> Knowledge {
        Knowledge { now, floor: BUILT, bound: DEFAULT_BOUND_SECS, moved_unasked: 0.0 }
    }
    fn c(offset: f64) -> Claim {
        Claim { offset, sources: 4 }
    }

    #[test]
    fn a_claim_is_a_sign_some_digits_and_a_source_count_and_nothing_else() {
        assert_eq!(parse_claim("-0.000123 4"), Ok(Claim { offset: -0.000123, sources: 4 }));
        assert_eq!(parse_claim("+12 1"), Ok(Claim { offset: 12.0, sources: 1 }));
        assert_eq!(parse_claim("9999999999.999999 16"), Ok(Claim { offset: 9999999999.999999, sources: 16 }));
        for bad in [
            "", "1", "1 2 3", " 1 2", "1  2", "1e9 4", "inf 4", "NaN 4", "-inf 4", "0x10 4", "1. 4", ".5 4",
            "--1 4", "1,5 4", "12345678901 4", "1.1234567 4", "1 0", "1 17", "1 -1", "1 4.0", "1 +4", "1 four",
            "1\n 4", "1 4\n",
        ] {
            assert!(parse_claim(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn nothing_below_the_floor_is_applied_or_even_offered() {
        let now = BUILT as f64 + 86400.0;
        // A day and a second backwards lands below the floor: refused, and
        // refused rather than asked although it is far past the bound.
        match decide(&k(now), &c(-86401.0)) {
            Decision::Refuse(why) => assert!(why.contains("before this system was built"), "{why}"),
            d => panic!("{d:?}"),
        }
        // Exactly the floor is the earliest time that may be asked about.
        assert_eq!(decide(&k(now), &c(-86400.0)), Decision::Ask { to: BUILT as f64 });
        // A clock already below the floor does not make lower proposals fair.
        assert!(matches!(decide(&k(1000.0), &c(5.0)), Decision::Refuse(_)));
    }

    #[test]
    fn small_corrections_are_slewed_and_larger_ones_inside_the_bound_are_stepped() {
        let now = BUILT as f64 + 1_000_000.0;
        assert_eq!(decide(&k(now), &c(0.001)), Decision::Ignore);
        assert_eq!(decide(&k(now), &c(-0.4)), Decision::Slew { offset: -0.4 });
        assert_eq!(decide(&k(now), &c(0.999)), Decision::Slew { offset: 0.999 });
        assert_eq!(decide(&k(now), &c(1.0)), Decision::Step { to: now + 1.0 });
        assert_eq!(decide(&k(now), &c(-3599.0)), Decision::Step { to: now - 3599.0 });
        assert_eq!(decide(&k(now), &c(3600.0)), Decision::Step { to: now + 3600.0 });
    }

    #[test]
    fn past_the_bound_the_person_decides_in_either_direction() {
        let now = BUILT as f64 + 10_000_000.0;
        assert_eq!(decide(&k(now), &c(3600.5)), Decision::Ask { to: now + 3600.5 });
        assert_eq!(decide(&k(now), &c(-7200.0)), Decision::Ask { to: now - 7200.0 });
        // A machine whose RTC died and was clamped to the build date: the
        // real time is months ahead, and that is a question, not a refusal.
        let months = 200.0 * 86400.0;
        assert_eq!(decide(&k(BUILT as f64), &c(months)), Decision::Ask { to: BUILT as f64 + months });
    }

    #[test]
    fn many_small_lies_are_bounded_by_their_sum() {
        let now = BUILT as f64 + 10_000_000.0;
        let mut know = k(now);
        let lie = c(-900.0);
        let mut applied = 0;
        loop {
            let d = decide(&know, &lie);
            if matches!(d, Decision::Ask { .. }) {
                break;
            }
            assert!(matches!(d, Decision::Step { .. }), "{d:?}");
            know.moved_unasked = moved_after(&know, &lie, &d, false);
            know.now += lie.offset;
            applied += 1;
            assert!(applied <= 4, "the clock walked past the bound in small steps");
        }
        // Four quarter-hours fit in the hour; the fifth asks.
        assert_eq!(applied, 4);
        // The person's word anchors the clock and the sum starts again.
        let d = decide(&know, &lie);
        assert_eq!(moved_after(&know, &lie, &d, true), 0.0);
        // Without it nothing moved and the sum stands.
        assert_eq!(moved_after(&know, &lie, &d, false), 3600.0);
        assert_eq!(moved_after(&know, &lie, &Decision::Refuse("x".into()), false), 3600.0);
    }

    #[test]
    fn a_clock_below_the_floor_is_set_to_the_floor_with_no_network_involved() {
        assert_eq!(clamp_to_floor(0.0, BUILT), Some(BUILT as f64));
        assert_eq!(clamp_to_floor(946_684_800.0, BUILT), Some(BUILT as f64)); // a dead RTC's 2000-01-01
        assert_eq!(clamp_to_floor(BUILT as f64, BUILT), None);
        assert_eq!(clamp_to_floor(BUILT as f64 + 1.0, BUILT), None);
    }

    #[test]
    fn the_floor_is_read_from_the_image_record_as_the_build_wrote_it() {
        let json = "{\n  \"name\": \"kryptik\",\n  \"built_at\": \"2026-09-19T18:11:28+00:00\",\n  \"x\": 1\n}\n";
        assert_eq!(floor_from_image_json(json), Some(BUILT));
        // A build host in another zone writes its local offset; same instant.
        assert_eq!(floor_from_image_json("{\"built_at\":\"2026-09-19T11:11:28-07:00\"}"), Some(BUILT));
        assert_eq!(parse_iso8601("2026-09-19T18:11:28Z"), Some(BUILT));
        assert_eq!(parse_iso8601("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_iso8601("2000-02-29T12:00:00Z"), Some(951_825_600));
        // Missing or malformed is "no floor known", never zero.
        for bad in ["{}", "{\"built_at\": 5}", "{\"built_at\": \"yesterday\"}", "{\"built_at\": \"2026-13-01T00:00:00Z\"}",
                    "{\"built_at\": \"2026-09-19T18:11:28\"}", "{\"built_at\": \"2026-09-19 18:11:28Z\"}"] {
            assert_eq!(floor_from_image_json(bad), None, "{bad}");
        }
    }

    #[test]
    fn times_are_shown_to_the_minute_in_utc() {
        assert_eq!(format_utc(BUILT as f64), "2026-09-19 18:11 UTC");
        assert_eq!(format_utc(0.0), "1970-01-01 00:00 UTC");
        assert_eq!(format_utc(951_825_600.9), "2000-02-29 12:00 UTC");
        assert_eq!(format_utc(-1.0), "1969-12-31 23:59 UTC");
        // Round trip across a span of days, including leap years.
        for day in (-800..40_000).step_by(37) {
            let (y, m, d) = civil_from_days(day);
            assert_eq!(days_from_civil(y, m, d), day);
        }
    }
}
