//! The update channel's rules (docs/design/update-channel.md): what zone 0
//! believes about a statement of what is current, and which bytes it will
//! take from the net zone for a release it has been asked to fetch.
//!
//! Nothing here verifies a signature. `kryptik-update check-pointer` and
//! `check-manifest` do that, with the code that verifies a release handed
//! over on a disk, and only text they have verified reaches these functions.
//! What is decided here is everything a signature cannot say: that a
//! statement is for this image's role, that it is not older than one already
//! accepted, how stale it is, and that a byte offered for staging is one the
//! signed manifest provides for, at the place it belongs.

use std::cmp::Ordering;

pub const POINTER_MAGIC: &str = "KRYPTIK-LATEST-1";
/// The pointer and its signature, each.
pub const POINTER_MAX: usize = 8 * 1024;
/// The manifest and its signature, each.
pub const MANIFEST_MAX: u64 = 64 * 1024;
/// A pointer older than this is reported as stale: the release process
/// re-issues it on a schedule, so its age is the only sign of a withheld one.
pub const STALE_AFTER_SECS: i64 = 30 * 86400;
/// One pointer is considered per hour; the rest are refused unread.
pub const POINTER_INTERVAL_SECS: u64 = 3600;

/// A statement of what is current, after its signature has verified.
#[derive(Debug, Clone, PartialEq)]
pub struct Pointer {
    pub role: String,
    pub version: String,
    /// Seconds since the epoch.
    pub issued: i64,
    pub manifest_sha256: String,
    pub base: String,
}

fn is_version(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'~'))
}

/// The pointer's text: the magic line, then each key exactly once. A key it
/// does not know is refused rather than skipped, so a newer format cannot be
/// half-understood by an older system.
pub fn parse_pointer(text: &str) -> Result<Pointer, String> {
    let mut lines = text.lines();
    if lines.next() != Some(POINTER_MAGIC) {
        return Err(format!("not a {POINTER_MAGIC}"));
    }
    let (mut role, mut version, mut issued, mut sha, mut base) = (None, None, None, None, None);
    for line in lines {
        let (k, v) = line.split_once(": ").ok_or_else(|| format!("not a `key: value` line: {line:?}"))?;
        let slot = match k {
            "role" => &mut role,
            "version" => &mut version,
            "issued" => &mut issued,
            "manifest-sha256" => &mut sha,
            "base" => &mut base,
            _ => return Err(format!("unknown key {k:?}")),
        };
        if slot.replace(v.to_string()).is_some() {
            return Err(format!("{k} is given twice"));
        }
    }
    let need = |o: Option<String>, k: &str| o.ok_or_else(|| format!("no {k}"));
    let (role, version, issued, sha, base) =
        (need(role, "role")?, need(version, "version")?, need(issued, "issued")?, need(sha, "manifest-sha256")?, need(base, "base")?);
    if !is_version(&version) {
        return Err(format!("{version:?} is not a version"));
    }
    let issued = crate::time::parse_iso8601(&issued).ok_or_else(|| format!("issued {issued:?} is not a date"))?;
    if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("manifest-sha256 is not 64 lowercase hex digits".into());
    }
    if base.is_empty() || base.len() > 512 || !base.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err("base must be 1 to 512 printable characters without spaces".into());
    }
    Ok(Pointer { role, version, issued, manifest_sha256: sha, base })
}

/// Where a release's files are fetched from. An absolute base is taken as it
/// is; a relative one is resolved against the channel address from the
/// verified root, never against anything the net zone reports. Only a
/// development image may be pointed at plain http. Where the bytes come from
/// decides nothing about what they must be - the pointer carries the
/// manifest's hash - so this is about not leaking the request, not trust.
pub fn resolve_base(channel: &str, base: &str, role: &str) -> Result<String, String> {
    let mut url = if base.contains("://") {
        base.to_string()
    } else {
        if base.starts_with('/') || base.split('/').any(|c| c == "..") {
            return Err(format!("relative base {base:?} must stay under the channel address"));
        }
        format!("{}/{}", channel.trim_end_matches('/'), base)
    };
    if !url.ends_with('/') {
        url.push('/');
    }
    match url.split_once("://").map(|(scheme, _)| scheme) {
        Some("https") => Ok(url),
        Some("http") if role == "development" => Ok(url),
        Some("http") => Err("a production image does not fetch over plain http".into()),
        _ => Err(format!("{url:?} is neither https nor http")),
    }
}

/// Versions compare the way `sort -V` orders them for the release tool: runs
/// of digits as numbers, everything else byte by byte.
pub fn version_cmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i].is_ascii_digit() && b[j].is_ascii_digit() {
            let run = |s: &[u8], from: usize| (from..s.len()).find(|&k| !s[k].is_ascii_digit()).unwrap_or(s.len());
            let (ie, je) = (run(a, i), run(b, j));
            let strip = |s: &[u8]| s.iter().position(|&c| c != b'0').map_or(&s[s.len()..], |p| &s[p..]).to_vec();
            let (x, y) = (strip(&a[i..ie]), strip(&b[j..je]));
            match x.len().cmp(&y.len()).then_with(|| x.cmp(&y)) {
                Ordering::Equal => {}
                o => return o,
            }
            (i, j) = (ie, je);
        } else {
            match a[i].cmp(&b[j]) {
                Ordering::Equal => {}
                o => return o,
            }
            (i, j) = (i + 1, j + 1);
        }
    }
    (a.len() - i).cmp(&(b.len() - j))
}

/// What an accepted pointer says about this machine.
#[derive(Debug, PartialEq)]
pub enum Standing {
    /// It names the running release, or an older one.
    Current,
    Available(String),
}

/// Whether zone 0 accepts a verified pointer. The signature said who wrote
/// it; this says whether it is for this image and whether it is a replay:
/// an `issued` earlier than the newest one already accepted is refused
/// however valid its signature.
pub fn accept_pointer(p: &Pointer, required_role: &str, running: &str, newest_issued: Option<i64>) -> Result<Standing, String> {
    if p.role != required_role {
        return Err(format!("the pointer's role is '{}'; this image requires '{required_role}'", p.role));
    }
    if let Some(seen) = newest_issued {
        if p.issued < seen {
            return Err("older than a statement this machine has already accepted: a replay".into());
        }
    }
    Ok(if version_cmp(&p.version, running) == Ordering::Greater { Standing::Available(p.version.clone()) } else { Standing::Current })
}

/// How many whole days old the newest accepted pointer is, and whether that
/// is past the bound. A clock behind the pointer reads as zero days.
pub fn staleness(now: i64, issued: i64) -> (i64, bool) {
    let age = (now - issued).max(0);
    (age / 86400, age > STALE_AFTER_SECS)
}

/// One file of a release, from the verified manifest.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub name: String,
    pub size: u64,
}

/// The file list `kryptik-update check-manifest` prints for a manifest it
/// has verified: `file <size> <name>` per line, other lines ignored. Names
/// are held to the rule for anything that crosses the broker.
pub fn parse_file_list(text: &str) -> Result<Vec<Entry>, String> {
    let mut out: Vec<Entry> = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("file ") else { continue };
        let (size, name) = rest.split_once(' ').ok_or_else(|| format!("not `file <size> <name>`: {line:?}"))?;
        let size: u64 = size.parse().map_err(|_| format!("{size:?} is not a size"))?;
        crate::broker::check_transfer_name(name)?;
        if name == "manifest" || name == "manifest.sig" || out.iter().any(|e| e.name == name) {
            return Err(format!("the manifest lists {name:?}, which it cannot"));
        }
        out.push(Entry { name: name.to_string(), size });
    }
    if out.is_empty() {
        return Err("the manifest lists no files".into());
    }
    Ok(out)
}

pub fn total_bytes(files: &[Entry]) -> u64 {
    files.iter().map(|e| e.size).sum()
}

/// Whether `len` bytes offered for `name` at `offset` may be written, given
/// how many bytes of it are already held. `files` is `None` until the
/// manifest and its signature have verified, and until then only those two
/// are taken: whole, from byte zero, small. After that: a listed name, at
/// exactly the offset held (so a broken download resumes and nothing is
/// written twice or out of order), never past the signed size.
pub fn may_put(files: Option<&[Entry]>, name: &str, offset: u64, len: u64, held: u64) -> Result<(), String> {
    if len == 0 {
        return Err("nothing to put".into());
    }
    let end = offset.checked_add(len).ok_or("offset and length overflow")?;
    if name == "manifest" || name == "manifest.sig" {
        if files.is_some() {
            return Err(format!("{name} has been verified; it is not replaced"));
        }
        if offset != 0 || end > MANIFEST_MAX {
            return Err(format!("{name} is put whole, from byte 0, in at most {MANIFEST_MAX} bytes"));
        }
        return Ok(());
    }
    let files = files.ok_or("nothing is accepted before the manifest and its signature have verified")?;
    let e = files.iter().find(|e| e.name == name).ok_or_else(|| format!("the signed manifest does not list {name:?}"))?;
    if offset != held {
        return Err(format!("{name}: {held} bytes are held; the next byte wanted is {held}, not {offset}"));
    }
    if end > e.size {
        return Err(format!("{name}: the signed manifest gives it {} bytes; {end} would be past that", e.size));
    }
    Ok(())
}

/// What is still missing and from which byte: the answer to `update-poll`.
pub fn still_needed(files: &[Entry], held: impl Fn(&str) -> u64) -> Vec<(String, u64)> {
    files.iter().filter_map(|e| { let h = held(&e.name); (h < e.size).then(|| (e.name.clone(), h)) }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn pointer_text(version: &str, issued: &str) -> String {
        format!("{POINTER_MAGIC}\nrole: production\nversion: {version}\nissued: {issued}\nmanifest-sha256: {SHA}\nbase: {version}/\n")
    }

    #[test]
    fn a_pointer_parses_and_anything_else_does_not() {
        let p = parse_pointer(&pointer_text("1.0.3", "2027-03-02T14:05:00+00:00")).unwrap();
        assert_eq!((p.role.as_str(), p.version.as_str(), p.base.as_str()), ("production", "1.0.3", "1.0.3/"));
        assert_eq!(p.issued, crate::time::parse_iso8601("2027-03-02T14:05:00Z").unwrap());
        let good = pointer_text("1.0.3", "2027-03-02T14:05:00Z");
        for (what, bad) in [
            ("a manifest's magic", good.replace(POINTER_MAGIC, "KRYPTIK-MANIFEST-1")),
            ("a key twice", format!("{good}role: development\n")),
            ("an unknown key", format!("{good}mirror: https://elsewhere/\n")),
            ("no issued", good.replace("issued: 2027-03-02T14:05:00Z\n", "")),
            ("a date that is not one", good.replace("2027-03-02T14:05:00Z", "yesterday")),
            ("a short hash", good.replace(SHA, &SHA[..63])),
            ("an uppercase hash", good.replace(SHA, &SHA.to_uppercase())),
            ("a version with a space", good.replace("version: 1.0.3", "version: 1.0 3")),
            ("a base with a space", good.replace("base: 1.0.3/", "base: 1.0.3/ x")),
        ] {
            assert!(parse_pointer(&bad).is_err(), "{what} was accepted");
        }
    }

    #[test]
    fn versions_order_as_the_release_tool_orders_them() {
        for (a, b) in [("1.0.3", "1.0.10"), ("1.9", "1.10"), ("1.0", "1.0.1"), ("0.9.9", "1.0"), ("1.0-rc1", "1.0-rc2"), ("1.02", "1.3")] {
            assert_eq!(version_cmp(a, b), Ordering::Less, "{a} < {b}");
            assert_eq!(version_cmp(b, a), Ordering::Greater, "{b} > {a}");
        }
        assert_eq!(version_cmp("1.0.3", "1.0.3"), Ordering::Equal);
        assert_eq!(version_cmp("1.01", "1.1"), Ordering::Equal);
    }

    #[test]
    fn a_pointer_is_accepted_for_this_role_and_never_backwards() {
        let p = parse_pointer(&pointer_text("1.0.3", "2027-03-02T14:05:00Z")).unwrap();
        assert_eq!(accept_pointer(&p, "production", "1.0.2", None), Ok(Standing::Available("1.0.3".into())));
        assert_eq!(accept_pointer(&p, "production", "1.0.3", None), Ok(Standing::Current));
        // An older release named by a newer statement is not an update.
        assert_eq!(accept_pointer(&p, "production", "1.1.0", None), Ok(Standing::Current));
        assert!(accept_pointer(&p, "development", "1.0.2", None).unwrap_err().contains("role"));
        // The same statement again is fine: that is what a re-issue looks
        // like to a machine that polls more often than the schedule.
        assert!(accept_pointer(&p, "production", "1.0.2", Some(p.issued)).is_ok());
        assert!(accept_pointer(&p, "production", "1.0.2", Some(p.issued + 1)).unwrap_err().contains("replay"));
    }

    #[test]
    fn a_pointer_goes_stale_after_the_bound_and_not_before() {
        assert_eq!(staleness(1000 + STALE_AFTER_SECS, 1000), (30, false));
        assert_eq!(staleness(1001 + STALE_AFTER_SECS, 1000), (30, true));
        assert_eq!(staleness(500, 1000), (0, false));
    }

    #[test]
    fn a_base_resolves_against_the_verified_channel_only() {
        let ch = "https://updates.example/stable";
        assert_eq!(resolve_base(ch, "1.0.3/", "production").unwrap(), "https://updates.example/stable/1.0.3/");
        assert_eq!(resolve_base(&format!("{ch}/"), "1.0.3", "production").unwrap(), "https://updates.example/stable/1.0.3/");
        assert_eq!(resolve_base(ch, "https://mirror.example/k/1.0.3/", "production").unwrap(), "https://mirror.example/k/1.0.3/");
        assert!(resolve_base(ch, "../other/1.0.3/", "production").is_err());
        assert!(resolve_base(ch, "/etc/", "production").is_err());
        assert!(resolve_base(ch, "http://mirror.example/1.0.3/", "production").is_err());
        assert!(resolve_base(ch, "http://10.0.2.2:8080/1.0.3/", "development").is_ok());
        assert!(resolve_base(ch, "file:///var/lib/", "development").is_err());
    }

    fn files() -> Vec<Entry> {
        parse_file_list("version: 1.0.3\nfile 1000 kryptik-root.img\nfile 40 kryptik-a.efi\nfile 40 kryptik-b.efi\nfile 9 root.json\n").unwrap()
    }

    #[test]
    fn the_file_list_is_the_verified_manifests_and_nothing_odd() {
        assert_eq!(total_bytes(&files()), 1089);
        for bad in ["file 10 ../x\n", "file 10 .hidden\n", "file ten x\n", "file 10 manifest\n", "file 1 a\nfile 2 a\n", "version: 1\n", "file 10 a b\n"] {
            assert!(parse_file_list(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn nothing_large_is_taken_before_the_manifest_has_verified() {
        assert!(may_put(None, "manifest", 0, 4096, 0).is_ok());
        assert!(may_put(None, "manifest.sig", 0, MANIFEST_MAX, 0).is_ok());
        assert!(may_put(None, "manifest", 0, MANIFEST_MAX + 1, 0).is_err());
        assert!(may_put(None, "manifest", 1, 10, 0).is_err());
        assert!(may_put(None, "kryptik-root.img", 0, 10, 0).unwrap_err().contains("before the manifest"));
        // And once it has, the manifest is what was verified, for good.
        assert!(may_put(Some(&files()), "manifest", 0, 10, 0).is_err());
    }

    #[test]
    fn bytes_are_taken_only_where_the_signed_manifest_provides_for_them() {
        let f = files();
        assert!(may_put(Some(&f), "kryptik-root.img", 0, 1000, 0).is_ok());
        assert!(may_put(Some(&f), "kryptik-root.img", 600, 400, 600).is_ok());
        assert!(may_put(Some(&f), "kryptik-root.img", 600, 401, 600).unwrap_err().contains("past that"));
        assert!(may_put(Some(&f), "kryptik-root.img", 0, 10, 600).unwrap_err().contains("600 bytes are held"));
        assert!(may_put(Some(&f), "kryptik-root.img", 700, 10, 600).is_err());
        assert!(may_put(Some(&f), "kryptik-root.img", 1000, 1, 1000).is_err());
        assert!(may_put(Some(&f), "stowaway", 0, 1, 0).unwrap_err().contains("does not list"));
        assert!(may_put(Some(&f), "root.json", 0, 0, 0).is_err());
        assert!(may_put(Some(&f), "root.json", u64::MAX, 2, u64::MAX).is_err());
    }

    #[test]
    fn a_poll_names_what_is_missing_and_from_which_byte() {
        let held = |n: &str| match n { "kryptik-root.img" => 600, "kryptik-a.efi" => 40, _ => 0 };
        assert_eq!(
            still_needed(&files(), held),
            vec![("kryptik-root.img".to_string(), 600), ("kryptik-b.efi".to_string(), 0), ("root.json".to_string(), 0)]
        );
        assert!(still_needed(&files(), |_| u64::MAX).is_empty());
    }
}
