//! Wall-clock policy for zone 0 (docs/design/time.md).
//!
//! Only zone 0 may set the clock and it has no network, so the time arrives
//! as a claim from the untrusted net zone. A claim may not cross the floor,
//! and past a bound on what is believed unasked, the user decides.
//! `decide` is pure: it reads no clock, file or environment.

/// Corrections below this many seconds are slewed, so the clock never runs backwards.
pub const SLEW_BELOW_SECS: f64 = 1.0;
/// Offsets below this many seconds are ignored.
pub const IGNORE_BELOW_SECS: f64 = 0.005;
/// Seconds believed without asking, per claim and in total, either direction.
pub const DEFAULT_BOUND_SECS: i64 = 3600;
/// One claim is considered per interval; others are refused unread, so a
/// hostile zone cannot flood the user with consent prompts.
pub const CLAIM_INTERVAL_SECS: u64 = 600;

/// The net zone's claim: add `offset` seconds, the median of what `sources`
/// time servers answered. Untrusted, like the zone.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Claim {
    pub offset: f64,
    pub sources: u8,
}

/// Parse `<seconds> <sources>`: optional sign, up to ten integer and six
/// fractional digits, and 1 to 16 sources. No exponent, infinity or NaN.
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
    /// Nothing below this is applied or offered: the image's build date, or a
    /// later release this machine has committed to.
    pub floor: i64,
    /// What is believed without asking.
    pub bound: i64,
    /// Unasked corrections since the clock was last anchored (by consent or
    /// the floor). The bound applies to this sum, so small lies cannot add up.
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
    /// Past the bound: the user decides, shown both times.
    Ask { to: f64 },
    Refuse(String),
}

pub fn decide(k: &Knowledge, c: &Claim) -> Decision {
    if !c.offset.is_finite() || !k.now.is_finite() {
        return Decision::Refuse("the offset is not a number".into());
    }
    let to = k.now + c.offset;
    // The floor comes before consent: an impossible time is never offered.
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

/// `moved_unasked` once `d` is carried out: an unasked correction adds to it,
/// and consent resets it.
pub fn moved_after(k: &Knowledge, c: &Claim, d: &Decision, consented: bool) -> f64 {
    match d {
        Decision::Slew { .. } | Decision::Step { .. } => k.moved_unasked + c.offset.abs(),
        Decision::Ask { .. } if consented => 0.0,
        _ => k.moved_unasked,
    }
}

/// The time to set a clock that reads below the floor (say, after a dead RTC
/// battery), or None. Needs no network: the system cannot predate its build.
pub fn clamp_to_floor(now: f64, floor: i64) -> Option<f64> {
    (now < floor as f64).then_some(floor as f64)
}

/// `built_at` from the image record, as written by `date -Iseconds`, in epoch
/// seconds. Anything else is None: no floor known, never zero.
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

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
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

/// A time as the user sees it and the history records it: to the minute, in UTC.
pub fn format_utc(t: f64) -> String {
    let secs = t.floor() as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", rem / 3600, rem % 3600 / 60)
}

// Carrying out a decision.

use std::io::{self, Write};
use std::path::Path;

/// The image record whose `built_at` is the floor.
pub const IMAGE_JSON: &str = "/etc/kryptik-image.json";
/// What zone 0 remembers about the clock between claims and across boots.
pub const STATE_DIR: &str = "/var/lib/kryptik/time";

/// The wall clock, behind a trait so tests can use a fake: no test should set the real one.
pub trait Clock {
    fn now(&self) -> f64;
    fn step(&mut self, to: f64) -> io::Result<()>;
    fn slew(&mut self, offset: f64) -> io::Result<()>;
    /// Copy the system clock to the hardware clock, where there is one.
    fn sync_rtc(&mut self) -> io::Result<()>;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> f64 {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
        ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
    }

    fn step(&mut self, to: f64) -> io::Result<()> {
        let ts = libc::timespec { tv_sec: to.floor() as libc::time_t, tv_nsec: ((to - to.floor()) * 1e9) as _ };
        if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn slew(&mut self, offset: f64) -> io::Result<()> {
        let whole = offset.trunc();
        let tv = libc::timeval { tv_sec: whole as libc::time_t, tv_usec: ((offset - whole) * 1e6) as _ };
        if unsafe { libc::adjtime(&tv, std::ptr::null_mut()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn sync_rtc(&mut self) -> io::Result<()> {
        /* struct rtc_time is nine ints; RTC_SET_TIME is _IOW('p', 0x0a, it).
         * The kernel ignores wday, yday and isdst. The RTC is kept in UTC. */
        const RTC_SET_TIME: libc::c_ulong = 0x4024_700a;
        let f = match std::fs::OpenOptions::new().write(true).open("/dev/rtc0") {
            Ok(f) => f,
            // No RTC; some boards have none.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let secs = self.now().floor() as i64;
        let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
        let (y, m, d) = civil_from_days(days);
        let tm: [libc::c_int; 9] =
            [(rem % 60) as _, (rem % 3600 / 60) as _, (rem / 3600) as _, d as _, (m - 1) as _, (y - 1900) as _, 0, 0, 0];
        use std::os::unix::io::AsRawFd;
        if unsafe { libc::ioctl(f.as_raw_fd(), RTC_SET_TIME as _, tm.as_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// This system's floor, or None if the image record is missing or does not
/// parse; with no floor every claim is refused.
pub fn floor_of_this_system() -> Option<i64> {
    floor_from_image_json(&std::fs::read_to_string(IMAGE_JSON).ok()?)
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
struct State {
    moved_unasked: f64,
    /// When the last claim was considered, whatever came of it: a "no" buys quiet too.
    last_claim: Option<f64>,
}

fn load_state(dir: &Path) -> State {
    let mut s = State::default();
    let Ok(text) = std::fs::read_to_string(dir.join("state")) else { return s };
    for line in text.lines() {
        match line.split_once('=') {
            Some(("moved_unasked", v)) => s.moved_unasked = v.parse().ok().filter(|x: &f64| x.is_finite() && *x >= 0.0).unwrap_or(0.0),
            Some(("last_claim", v)) => s.last_claim = v.parse().ok().filter(|x: &f64| x.is_finite()),
            _ => {}
        }
    }
    s
}

fn ensure_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

/// Written whole and renamed into place, so a power cut leaves old or new state.
fn save_state(dir: &Path, s: &State) -> io::Result<()> {
    ensure_dir(dir)?;
    let tmp = dir.join("state.tmp");
    let mut text = format!("moved_unasked={}\n", s.moved_unasked);
    if let Some(t) = s.last_claim {
        text.push_str(&format!("last_claim={t}\n"));
    }
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, dir.join("state"))
}

/// Append a line to the clock's history (`kryptikd time status` shows the last).
fn record(dir: &Path, at: f64, what: &str) {
    if ensure_dir(dir).is_err() {
        return;
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("history")) {
        let _ = writeln!(f, "{} {what}", format_utc(at));
    }
}

/// What became of a claim, in the words the broker sends back to the zone.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Ignored,
    Slewed,
    Stepped,
    SteppedAfterConsent,
    Refused(String),
}

impl Outcome {
    pub fn reply(&self) -> String {
        match self {
            Outcome::Ignored => "ok ignored".into(),
            Outcome::Slewed => "ok slewed".into(),
            Outcome::Stepped => "ok stepped".into(),
            Outcome::SteppedAfterConsent => "ok stepped after consent".into(),
            Outcome::Refused(why) => format!("refused: {why}"),
        }
    }
}

/// Decide on a claim, ask the user if needed, and carry it out.
/// `ask(now, proposed, sources)` is only called with a proposal at or above the floor.
pub fn consider(
    clock: &mut dyn Clock,
    dir: &Path,
    floor: Option<i64>,
    bound: i64,
    claim: &Claim,
    ask: &mut dyn FnMut(&str, &str, u8) -> Result<(), String>,
) -> Outcome {
    let Some(floor) = floor else {
        return Outcome::Refused(format!("no floor is known ({IMAGE_JSON} is missing or unreadable), so no claim can be judged"));
    };
    let now = clock.now();
    let mut state = load_state(dir);
    if let Some(last) = state.last_claim {
        // abs(): stepping the clock back must not reopen the window.
        if (now - last).abs() < CLAIM_INTERVAL_SECS as f64 {
            return Outcome::Refused(format!("one claim is considered every {} minutes", CLAIM_INTERVAL_SECS / 60));
        }
    }
    state.last_claim = Some(now);
    let know = Knowledge { now, floor, bound, moved_unasked: state.moved_unasked };
    let decision = decide(&know, claim);
    let mut consented = false;
    let outcome = match &decision {
        Decision::Ignore => Outcome::Ignored,
        Decision::Refuse(why) => Outcome::Refused(why.clone()),
        Decision::Slew { offset } => match clock.slew(*offset) {
            Ok(()) => Outcome::Slewed,
            Err(e) => Outcome::Refused(format!("the clock could not be slewed: {e}")),
        },
        Decision::Step { to } => match clock.step(*to) {
            Ok(()) => Outcome::Stepped,
            Err(e) => Outcome::Refused(format!("the clock could not be set: {e}")),
        },
        Decision::Ask { to } => match ask(&format_utc(now), &format_utc(*to), claim.sources) {
            Err(why) => Outcome::Refused(format!("not set without the person's consent: {why}")),
            // Apply the offset to the clock as it reads now: answering takes time.
            Ok(()) => match clock.step(clock.now() + claim.offset) {
                Ok(()) => {
                    consented = true;
                    Outcome::SteppedAfterConsent
                }
                Err(e) => Outcome::Refused(format!("the clock could not be set: {e}")),
            },
        },
    };
    let applied = matches!(outcome, Outcome::Slewed | Outcome::Stepped | Outcome::SteppedAfterConsent);
    if applied {
        state.moved_unasked = moved_after(&know, claim, &decision, consented);
        if !matches!(outcome, Outcome::Slewed) {
            if let Err(e) = clock.sync_rtc() {
                record(dir, clock.now(), &format!("the hardware clock was not updated: {e}"));
            }
        }
        // The window is measured from the clock as it now reads.
        state.last_claim = Some(clock.now());
    }
    record(dir, clock.now(), &format!("{} offset={:+.6} sources={}", outcome.reply(), claim.offset, claim.sources));
    if let Err(e) = save_state(dir, &state) {
        record(dir, clock.now(), &format!("the clock's state could not be saved: {e}"));
    }
    outcome
}

/// At boot, before any network: raise a clock below the floor to it. Returns what was done.
pub fn clamp(clock: &mut dyn Clock, dir: &Path, floor: Option<i64>) -> Result<String, String> {
    let floor = floor.ok_or_else(|| format!("no floor is known: {IMAGE_JSON} is missing or unreadable"))?;
    let now = clock.now();
    let Some(to) = clamp_to_floor(now, floor) else {
        return Ok(format!("the clock ({}) is not before this system was built ({}); left alone", format_utc(now), format_utc(floor as f64)));
    };
    clock.step(to).map_err(|e| format!("the clock could not be set to the floor: {e}"))?;
    let _ = clock.sync_rtc();
    let mut state = load_state(dir);
    // The floor anchors the clock, as consent does.
    state.moved_unasked = 0.0;
    let _ = save_state(dir, &state);
    record(dir, to, &format!("set to the floor: the clock read {}, before this system was built", format_utc(now)));
    Ok(format!("the clock read {}, before this system was built; set to {}", format_utc(now), format_utc(to)))
}

#[cfg(test)]
mod tests {
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
    fn clamp_raises_dead_clock_to_floor() {
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
}
