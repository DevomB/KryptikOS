//! The login password, checked for the screen lock (docs/design/laptop.md): the session user's
//! own entry in the shadow file, through crypt(3), with a pause after each wrong one. Nothing
//! else is read from the file, and the password is never written anywhere.

use std::ffi::CStr;
use std::path::Path;
use std::time::{Duration, Instant};

/// Where the hashes are, which root alone reads.
pub const SHADOW: &str = "/etc/shadow";

/* crypt_r's work area: libxcrypt's is 32 KiB and musl's much smaller, so one buffer serves both.
 * kryptikd links musl's libc, which has crypt_r; a glibc build of the tests takes libxcrypt's. */
#[repr(C, align(8))]
struct CryptData([u8; 32768]);

#[cfg_attr(target_env = "gnu", link(name = "crypt"))]
extern "C" {
    fn crypt_r(phrase: *const libc::c_char, setting: *const libc::c_char, data: *mut CryptData) -> *mut libc::c_char;
}

/// The hash `shadow` holds for `user`, if it is one this build can check: SHA-512 or SHA-256
/// crypt, which musl and libxcrypt both know. musl reads any other setting as DES without a
/// word, which would refuse the right password as wrong. An empty field, or one locked with
/// `!` or `*`, holds none.
pub fn hash_of(shadow: &str, user: &str) -> Option<String> {
    shadow
        .lines()
        .find_map(|l| {
            let mut f = l.split(':');
            if f.next()? == user { f.next().map(str::to_string) } else { None }
        })
        .filter(|h| h.starts_with("$6$") || h.starts_with("$5$"))
}

/// Whether `password` hashes to `hash`, compared in constant time.
pub fn matches(password: &[u8], hash: &str) -> bool {
    if password.contains(&0) || hash.as_bytes().contains(&0) {
        return false;
    }
    // Room for the NUL first: a push past the capacity would leave a copy behind, unwiped.
    let mut phrase = Vec::with_capacity(password.len() + 1);
    phrase.extend_from_slice(password);
    phrase.push(0);
    let mut setting = hash.as_bytes().to_vec();
    setting.push(0);
    let mut data = Box::new(CryptData([0; 32768]));
    // SAFETY: both strings end in a NUL, and the work area is zeroed and large enough for either libc.
    let out = unsafe { crypt_r(phrase.as_ptr().cast(), setting.as_ptr().cast(), &mut *data) };
    let ok = !out.is_null() && {
        // SAFETY: crypt_r returned a NUL-terminated string inside `data`, alive until the wipe below.
        let got = unsafe { CStr::from_ptr(out) }.to_bytes();
        got.len() == hash.len() && got.iter().zip(hash.as_bytes()).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0
    };
    phrase.fill(0);
    data.0.fill(0);
    ok
}

/// Wrong secrets in a row, and when the next may be tried: the pause doubles from 2 s to 60 s,
/// and a right one ends it. The screen lock's login password, the state partition's passphrase
/// and each zone volume's keep one each.
#[derive(Debug, Default)]
pub struct Attempts {
    failures: u32,
    next: Option<Instant>,
}

impl Attempts {
    /// How long until a password may be tried, or none if one may be now.
    pub fn wait(&self, now: Instant) -> Option<Duration> {
        self.next.and_then(|n| n.checked_duration_since(now)).filter(|d| !d.is_zero())
    }

    /// "wait N s", N rounded up, while one may not be tried.
    pub fn paused(&self, now: Instant) -> Option<String> {
        self.wait(now).map(|w| format!("wait {} s", w.as_secs() + u64::from(w.subsec_nanos() > 0)))
    }

    pub fn failed(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        let secs = (1u64 << self.failures.min(6)).min(60);
        self.next = Some(now + Duration::from_secs(secs));
    }

    pub fn passed(&mut self) {
        *self = Attempts::default();
    }
}

/// Check `password` against `user`'s entry in the shadow file at `shadow`. A wrong one is told as
/// such and pauses the next; while paused, nothing is checked.
pub fn check(shadow: &Path, user: &str, password: &[u8], attempts: &mut Attempts, now: Instant) -> Result<(), String> {
    if let Some(w) = attempts.paused(now) {
        return Err(w);
    }
    let text = std::fs::read_to_string(shadow).map_err(|e| format!("{}: {e}", shadow.display()))?;
    let hash = hash_of(&text, user).ok_or_else(|| format!("{user} has no SHA-512 or SHA-256 crypt password to check"))?;
    if matches(password, &hash) {
        attempts.passed();
        Ok(())
    } else {
        attempts.failed(now);
        Err("wrong password".into())
    }
}

#[cfg(test)]
mod tests;
