use super::*;

const BUILT: i64 = 1_789_841_488; // 2026-09-19 18:11:28 UTC

/// A clock that does what it is told and records it.
struct FakeClock {
    t: f64,
    steps: Vec<f64>,
    slews: Vec<f64>,
    rtc_syncs: usize,
    refuse: bool,
}
impl FakeClock {
    fn at(t: f64) -> Self {
        FakeClock { t, steps: vec![], slews: vec![], rtc_syncs: 0, refuse: false }
    }
}
impl Clock for FakeClock {
    fn now(&self) -> f64 {
        self.t
    }
    fn step(&mut self, to: f64) -> io::Result<()> {
        if self.refuse {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        self.t = to;
        self.steps.push(to);
        Ok(())
    }
    fn slew(&mut self, offset: f64) -> io::Result<()> {
        self.slews.push(offset);
        Ok(())
    }
    fn sync_rtc(&mut self) -> io::Result<()> {
        self.rtc_syncs += 1;
        Ok(())
    }
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("kryptik-time-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}
fn nobody(_: &str, _: &str, _: u8) -> Result<(), String> {
    Err("nobody is there to ask".into())
}

#[test]
fn claim_within_bound_steps_clock() {
    let dir = scratch("step");
    let mut clock = FakeClock::at(BUILT as f64 + 1e6);
    let out = consider(&mut clock, &dir, Some(BUILT), 3600, &Claim { offset: 42.5, sources: 3 }, &mut nobody);
    assert_eq!(out, Outcome::Stepped);
    assert_eq!(clock.steps, vec![BUILT as f64 + 1e6 + 42.5]);
    assert_eq!(clock.rtc_syncs, 1);
    let history = std::fs::read_to_string(dir.join("history")).unwrap();
    assert!(history.contains("ok stepped offset=+42.500000 sources=3"), "{history}");
    assert_eq!(load_state(&dir).moved_unasked, 42.5);
    // A slew touches neither the RTC nor the step list.
    let dir2 = scratch("slew");
    let mut clock = FakeClock::at(BUILT as f64 + 1e6);
    assert_eq!(consider(&mut clock, &dir2, Some(BUILT), 3600, &Claim { offset: -0.25, sources: 1 }, &mut nobody), Outcome::Slewed);
    assert_eq!((clock.slews.clone(), clock.steps.len(), clock.rtc_syncs), (vec![-0.25], 0, 0));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

#[test]
fn past_bound_needs_consent() {
    let dir = scratch("ask");
    let start = BUILT as f64;
    let months = 200.0 * 86400.0;
    let claim = Claim { offset: months, sources: 4 };
    // Nobody to ask: refused, clock untouched.
    let mut clock = FakeClock::at(start);
    let out = consider(&mut clock, &dir, Some(BUILT), 3600, &claim, &mut nobody);
    assert!(matches!(&out, Outcome::Refused(w) if w.contains("consent")), "{out:?}");
    assert!(clock.steps.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
    // The user says yes: the clock steps and the unasked sum resets.
    let mut clock = FakeClock::at(start);
    let mut shown = None;
    let out = consider(&mut clock, &dir, Some(BUILT), 3600, &claim, &mut |now: &str, to: &str, n: u8| {
        shown = Some((now.to_string(), to.to_string(), n));
        Ok(())
    });
    assert_eq!(out, Outcome::SteppedAfterConsent);
    assert_eq!(shown, Some(("2026-09-19 18:11 UTC".into(), "2027-04-07 18:11 UTC".into(), 4)));
    assert_eq!(clock.steps, vec![start + months]);
    assert_eq!(load_state(&dir).moved_unasked, 0.0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn one_claim_per_interval() {
    let dir = scratch("rate");
    let mut clock = FakeClock::at(BUILT as f64 + 5e6);
    let far = Claim { offset: 9e6, sources: 2 };
    assert!(matches!(consider(&mut clock, &dir, Some(BUILT), 3600, &far, &mut nobody), Outcome::Refused(_)));
    // A second claim at once is refused unread; the user is not asked.
    let mut asked = 0;
    let out = consider(&mut clock, &dir, Some(BUILT), 3600, &Claim { offset: 5.0, sources: 2 }, &mut |_: &str, _: &str, _: u8| {
        asked += 1;
        Ok(())
    });
    assert!(matches!(&out, Outcome::Refused(w) if w.contains("every 10 minutes")), "{out:?}");
    assert_eq!(asked, 0);
    assert!(clock.steps.is_empty());
    // Stepping the clock back must not reopen the window.
    clock.t -= 300.0;
    assert!(matches!(consider(&mut clock, &dir, Some(BUILT), 3600, &Claim { offset: 5.0, sources: 2 }, &mut nobody), Outcome::Refused(_)));
    // After the interval the next one is considered.
    clock.t += 300.0 + CLAIM_INTERVAL_SECS as f64;
    assert_eq!(consider(&mut clock, &dir, Some(BUILT), 3600, &Claim { offset: 5.0, sources: 2 }, &mut nobody), Outcome::Stepped);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn refused_without_floor_or_permission() {
    let dir = scratch("nofloor");
    let mut clock = FakeClock::at(BUILT as f64 + 1e6);
    let out = consider(&mut clock, &dir, None, 3600, &Claim { offset: 2.0, sources: 1 }, &mut nobody);
    assert!(matches!(&out, Outcome::Refused(w) if w.contains("no floor is known")), "{out:?}");
    assert!(clamp(&mut clock, &dir, None).is_err());
    // EPERM from the kernel is a refusal that gives the reason.
    clock.refuse = true;
    let out = consider(&mut clock, &dir, Some(BUILT), 3600, &Claim { offset: 2.0, sources: 1 }, &mut nobody);
    assert!(matches!(&out, Outcome::Refused(w) if w.contains("could not be set")), "{out:?}");
    assert_eq!(load_state(&dir).moved_unasked, 0.0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn clamp_raises_dead_clock() {
    let dir = scratch("clamp");
    let mut dead = FakeClock::at(946_684_800.0);
    let said = clamp(&mut dead, &dir, Some(BUILT)).unwrap();
    assert!(said.contains("2000-01-01 00:00 UTC") && said.contains("2026-09-19 18:11 UTC"), "{said}");
    assert_eq!((dead.steps.clone(), dead.rtc_syncs), (vec![BUILT as f64], 1));
    assert!(std::fs::read_to_string(dir.join("history")).unwrap().contains("set to the floor"));
    let mut live = FakeClock::at(BUILT as f64 + 10.0);
    assert!(clamp(&mut live, &dir, Some(BUILT)).unwrap().contains("left alone"));
    assert!(live.steps.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn system_clock_denies_unprivileged_step() {
    let mut c = SystemClock;
    let now = c.now();
    assert!(now > 1_600_000_000.0, "the system clock reads {now}");
    if unsafe { libc::geteuid() } != 0 {
        let e = c.step(now).expect_err("an unprivileged process set the clock");
        assert_eq!(e.raw_os_error(), Some(libc::EPERM));
    }
}

fn k(now: f64) -> Knowledge {
    Knowledge { now, floor: BUILT, bound: DEFAULT_BOUND_SECS, moved_unasked: 0.0 }
}
fn c(offset: f64) -> Claim {
    Claim { offset, sources: 4 }
}

#[test]
fn parse_claim_is_strict() {
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
fn below_floor_is_refused() {
    let now = BUILT as f64 + 86400.0;
    // Below the floor: refused, not asked, though far past the bound.
    match decide(&k(now), &c(-86401.0)) {
        Decision::Refuse(why) => assert!(why.contains("before this system was built"), "{why}"),
        d => panic!("{d:?}"),
    }
    // The floor itself is the earliest time that may be asked about.
    assert_eq!(decide(&k(now), &c(-86400.0)), Decision::Ask { to: BUILT as f64 });
    // A clock already below the floor does not lower it.
    assert!(matches!(decide(&k(1000.0), &c(5.0)), Decision::Refuse(_)));
}

#[test]
fn slew_small_step_within_bound() {
    let now = BUILT as f64 + 1_000_000.0;
    assert_eq!(decide(&k(now), &c(0.001)), Decision::Ignore);
    assert_eq!(decide(&k(now), &c(-0.4)), Decision::Slew { offset: -0.4 });
    assert_eq!(decide(&k(now), &c(0.999)), Decision::Slew { offset: 0.999 });
    assert_eq!(decide(&k(now), &c(1.0)), Decision::Step { to: now + 1.0 });
    assert_eq!(decide(&k(now), &c(-3599.0)), Decision::Step { to: now - 3599.0 });
    assert_eq!(decide(&k(now), &c(3600.0)), Decision::Step { to: now + 3600.0 });
}

#[test]
fn past_bound_asks_either_way() {
    let now = BUILT as f64 + 10_000_000.0;
    assert_eq!(decide(&k(now), &c(3600.5)), Decision::Ask { to: now + 3600.5 });
    assert_eq!(decide(&k(now), &c(-7200.0)), Decision::Ask { to: now - 7200.0 });
    // A dead RTC clamped to the build date, months behind: asked, not refused.
    let months = 200.0 * 86400.0;
    assert_eq!(decide(&k(BUILT as f64), &c(months)), Decision::Ask { to: BUILT as f64 + months });
}

#[test]
fn small_lies_bounded_by_sum() {
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
    // Consent resets the sum.
    let d = decide(&know, &lie);
    assert_eq!(moved_after(&know, &lie, &d, true), 0.0);
    // Without consent nothing moved and the sum stands.
    assert_eq!(moved_after(&know, &lie, &d, false), 3600.0);
    assert_eq!(moved_after(&know, &lie, &Decision::Refuse("x".into()), false), 3600.0);
}

#[test]
fn clamp_to_floor_only_below() {
    assert_eq!(clamp_to_floor(0.0, BUILT), Some(BUILT as f64));
    assert_eq!(clamp_to_floor(946_684_800.0, BUILT), Some(BUILT as f64)); // a dead RTC's 2000-01-01
    assert_eq!(clamp_to_floor(BUILT as f64, BUILT), None);
    assert_eq!(clamp_to_floor(BUILT as f64 + 1.0, BUILT), None);
}

#[test]
fn floor_from_image_record() {
    let json = "{\n  \"name\": \"kryptik\",\n  \"built_at\": \"2026-09-19T18:11:28+00:00\",\n  \"x\": 1\n}\n";
    assert_eq!(floor_from_image_json(json), Some(BUILT));
    // A build host's local UTC offset gives the same instant.
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
fn format_utc_to_minute() {
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
