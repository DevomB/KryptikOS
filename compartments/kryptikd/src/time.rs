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

/// Written whole, so a power cut leaves old or new state.
fn save_state(dir: &Path, s: &State) -> io::Result<()> {
    crate::files::private_dir(dir)?;
    let mut text = format!("moved_unasked={}\n", s.moved_unasked);
    if let Some(t) = s.last_claim {
        text.push_str(&format!("last_claim={t}\n"));
    }
    crate::files::write_atomic(&dir.join("state"), &[text.as_bytes()], 0o600, None)
}

/// Append a line to the clock's history (`kryptikd time status` shows the last).
fn record(dir: &Path, at: f64, what: &str) {
    use std::os::unix::fs::OpenOptionsExt;
    if crate::files::private_dir(dir).is_err() {
        return;
    }
    let history = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(dir.join("history"));
    if let Ok(mut f) = history {
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
mod tests;
