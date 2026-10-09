use super::*;

const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn pointer_text(version: &str, issued: &str) -> String {
    format!("{POINTER_MAGIC}\nrole: production\nversion: {version}\nissued: {issued}\nmanifest-sha256: {SHA}\nbase: {version}/\n")
}

#[test]
fn missing_role_accepts_nothing() {
    let d = std::env::temp_dir().join(format!("kryptik-role-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let f = d.join("required-role");
    let missing = role_from(&f);
    std::fs::write(&f, " production\r\n").unwrap();
    let written = role_from(&f);
    let _ = std::fs::remove_dir_all(&d);
    assert!(missing.as_ref().is_err_and(|e| e.contains("accepts no release")), "{missing:?}");
    assert_eq!(written.as_deref(), Ok("production"));
}

#[test]
fn parse_pointer_rejects_malformed() {
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
fn versions_order_like_sort_v() {
    for (a, b) in [("1.0.3", "1.0.10"), ("1.9", "1.10"), ("1.0", "1.0.1"), ("0.9.9", "1.0"), ("1.0-rc1", "1.0-rc2"), ("1.02", "1.3")] {
        assert_eq!(version_cmp(a, b), Ordering::Less, "{a} < {b}");
        assert_eq!(version_cmp(b, a), Ordering::Greater, "{b} > {a}");
    }
    assert_eq!(version_cmp("1.0.3", "1.0.3"), Ordering::Equal);
    assert_eq!(version_cmp("1.01", "1.1"), Ordering::Equal);
}

#[test]
fn pointer_accepted_for_role_never_backwards() {
    let p = parse_pointer(&pointer_text("1.0.3", "2027-03-02T14:05:00Z")).unwrap();
    assert_eq!(accept_pointer(&p, "production", "1.0.2", None, p.issued), Ok(Standing::Available("1.0.3".into())));
    assert_eq!(accept_pointer(&p, "production", "1.0.3", None, p.issued), Ok(Standing::Current));
    // An older release named by a newer statement is not an update.
    assert_eq!(accept_pointer(&p, "production", "1.1.0", None, p.issued), Ok(Standing::Current));
    assert!(accept_pointer(&p, "development", "1.0.2", None, p.issued).unwrap_err().contains("role"));
    // The same statement again is fine: polled more often than re-issued.
    assert!(accept_pointer(&p, "production", "1.0.2", Some(p.issued), p.issued).is_ok());
    assert!(accept_pointer(&p, "production", "1.0.2", Some(p.issued + 1), p.issued).unwrap_err().contains("replay"));
    // Dated ahead of the clock: a day is tolerated, more is refused.
    assert!(accept_pointer(&p, "production", "1.0.2", None, p.issued - MAX_AHEAD_SECS).is_ok());
    assert!(accept_pointer(&p, "production", "1.0.2", None, p.issued - MAX_AHEAD_SECS - 1).unwrap_err().contains("clock"));
}

#[test]
fn pointer_stale_only_after_bound() {
    assert_eq!(staleness(1000 + STALE_AFTER_SECS, 1000), (30, false));
    assert_eq!(staleness(1001 + STALE_AFTER_SECS, 1000), (30, true));
    assert_eq!(staleness(500, 1000), (0, false));
}

#[test]
fn base_resolves_under_channel_only() {
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
fn file_list_rejects_odd_entries() {
    assert_eq!(total_bytes(&files()), 1089);
    for bad in ["file 10 ../x\n", "file 10 .hidden\n", "file ten x\n", "file 10 manifest\n", "file 1 a\nfile 2 a\n", "version: 1\n", "file 10 a b\n"] {
        assert!(parse_file_list(bad).is_err(), "{bad:?} was accepted");
    }
}

#[test]
fn nothing_large_before_manifest_verifies() {
    assert!(may_put(None, "manifest", 0, 4096, 0).is_ok());
    assert!(may_put(None, "manifest.sig", 0, MANIFEST_MAX, 0).is_ok());
    assert!(may_put(None, "manifest", 0, MANIFEST_MAX + 1, 0).is_err());
    assert!(may_put(None, "manifest", 1, 10, 0).is_err());
    assert!(may_put(None, "kryptik-root.img", 0, 10, 0).unwrap_err().contains("before the manifest"));
    // Once verified, the manifest is never replaced.
    assert!(may_put(Some(&files()), "manifest", 0, 10, 0).is_err());
}

#[test]
fn bytes_taken_only_where_manifest_allows() {
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
fn poll_names_missing_files_and_offsets() {
    let held = |n: &str| match n { "kryptik-root.img" => 600, "kryptik-a.efi" => 40, _ => 0 };
    assert_eq!(
        still_needed(&files(), held),
        vec![("kryptik-root.img".to_string(), 600), ("kryptik-b.efi".to_string(), 0), ("root.json".to_string(), 0)]
    );
    assert!(still_needed(&files(), |_| u64::MAX).is_empty());
}

// --- the state, in a scratch directory per test ---

/// A check runs on copies of what it reads, in a directory of its own that is its TMPDIR and is
/// gone afterwards; copies readable by the unprivileged account that runs it under root.
#[test]
fn checks_run_on_copies_of_their_own() {
    use std::os::unix::fs::PermissionsExt;
    let d = scratch("checks-copies");
    std::fs::create_dir_all(d.join("from")).unwrap();
    std::fs::write(d.join("from/latest"), b"statement").unwrap();
    std::fs::write(d.join("from/latest.sig"), b"signature").unwrap();
    std::fs::set_permissions(d.join("from/latest"), std::fs::Permissions::from_mode(0o600)).unwrap();
    let tool = d.join("tool");
    std::fs::write(&tool, "#!/bin/sh\necho verb $1; shift\nfor f; do echo \"$f $(stat -c %a \"$f\") $(cat \"$f\")\"; done\necho tmp $TMPDIR\n").unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (p, s) = (d.join("from/latest"), d.join("from/latest.sig"));
    let out = run_check(&tool, &d, "check-pointer", &[(&p, "latest"), (&s, "latest.sig")], false, std::time::Duration::from_secs(60)).unwrap();
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "verb check-pointer");
    let tmp = lines[3].strip_prefix("tmp ").expect("the tool's TMPDIR");
    assert!(tmp.starts_with(d.join("kryptik-check.").to_str().unwrap()), "a fresh directory under the base: {tmp}");
    assert_eq!(lines[1], format!("{tmp}/latest 644 statement"), "a readable copy, not the original");
    assert_eq!(lines[2], format!("{tmp}/latest.sig 644 signature"));
    assert!(!Path::new(tmp).exists(), "the copies outlived the check");
    assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600, "the original was left as it was");
    // One that hangs is ended at its deadline, and its directory goes as well.
    std::fs::write(&tool, "#!/bin/sh\necho started\nsleep 30\n").unwrap();
    let start = std::time::Instant::now();
    let refused = run_check(&tool, &d, "check-pointer", &[(&p, "latest"), (&s, "latest.sig")], false, std::time::Duration::from_secs(1));
    assert!(refused.unwrap_err().contains("gave no answer within 1 s"));
    assert!(start.elapsed() < std::time::Duration::from_secs(10), "the hung check was waited out");
    assert!(std::fs::read_dir(&d).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().starts_with("kryptik-check.")));
    let _ = std::fs::remove_dir_all(&d);
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kryptik-update-test-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

const LISTING: &str = "version: 1.0.3\nsha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\nfile 10 kryptik-root.img\nfile 4 root.json\n";

fn yes() -> Checks<'static> {
    Checks { pointer: &|_, _| Ok(()), manifest: &|_| Ok(LISTING.to_string()) }
}

/// An hour after the statements these tests use were issued.
const T0: i64 = 1_804_000_000;
const CH: &str = "https://updates.example/stable";

#[test]
fn latest_stores_only_valid_statements() {
    let d = scratch("latest");
    let p = pointer_text("1.0.3", "2027-03-02T14:05:00Z");
    let no = Checks { pointer: &|_, _| Err("the pointer signature does NOT verify".into()), manifest: &|_| Err("unused".into()) };
    assert!(latest(&d, &no, T0, "production", "1.0.2", p.as_bytes(), b"sig").unwrap_err().contains("does NOT verify"));
    assert!(stored_pointer(&d).is_none(), "an unverified statement was stored");
    // Looking at that one used the interval up, whoever sent it.
    assert!(latest(&d, &yes(), T0 + 60, "production", "1.0.2", p.as_bytes(), b"sig").unwrap_err().contains("every 60 minutes"));
    let t1 = T0 + POINTER_INTERVAL_SECS as i64;
    assert_eq!(latest(&d, &yes(), t1, "production", "1.0.2", p.as_bytes(), b"sig"), Ok(Standing::Available("1.0.3".into())));
    assert_eq!(stored_pointer(&d).unwrap().version, "1.0.3");
    assert!(!d.join("checking").exists(), "the scratch copy outlived the check");
    // Last year's statement, validly signed, an interval later: a replay.
    let old = pointer_text("1.0.1", "2026-03-02T14:05:00Z");
    let t2 = t1 + POINTER_INTERVAL_SECS as i64;
    assert!(latest(&d, &yes(), t2, "production", "1.0.2", old.as_bytes(), b"sig").unwrap_err().contains("replay"));
    assert_eq!(stored_pointer(&d).unwrap().version, "1.0.3");
    // Next year's, validly signed: refused, and nothing changes.
    let ahead = pointer_text("9.9.9", "2028-03-02T14:05:00Z");
    let t3 = t2 + POINTER_INTERVAL_SECS as i64;
    assert!(latest(&d, &yes(), t3, "production", "1.0.2", ahead.as_bytes(), b"sig").unwrap_err().contains("clock"));
    assert_eq!(stored_pointer(&d).unwrap().version, "1.0.3");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_machine_never_told_counts_from_its_install() {
    let d = scratch("since-install");
    // No statement accepted: nothing until 30 days after the install, and nothing without a channel.
    assert_eq!(stale_line(&d, T0 + 2 * 86400, Some(T0)), None);
    assert_eq!(stale_line(&d, T0 + 31 * 86400, None), None, "an image with no channel expects nothing");
    let line = stale_line(&d, T0 + 31 * 86400, Some(T0)).unwrap();
    assert!(line.starts_with("no statement from the release key since this machine was installed, 31 days ago: "));
    assert!(status(&d, T0 + 31 * 86400, "1.0.2", Some(T0)).contains(&format!("           {line}\n")));
    // Beside the state directory, not in it: `latest` takes only one that is its owner's alone.
    let issue = scratch("since-install-issue");
    let notice = issue.join("kryptik-update.issue");
    refresh_login_notice(&d, &notice, T0 + 31 * 86400, Some(T0)).unwrap();
    assert_eq!(std::fs::read_to_string(&notice).unwrap(), format!("kryptik update: {line}\n"));
    let _ = std::fs::remove_dir_all(&issue);
    // Once one is accepted, its own age counts, however old the install.
    let p = pointer_text("1.0.3", "2027-03-02T14:05:00Z");
    latest(&d, &yes(), T0, "production", "1.0.2", p.as_bytes(), b"sig").unwrap();
    assert_eq!(stale_line(&d, T0 + 2 * 86400, Some(T0 - 90 * 86400)), None);
    // The install is the record's modification time.
    let record = d.join("install.json");
    let f = std::fs::File::create(&record).unwrap();
    f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(T0 as u64)).unwrap();
    assert_eq!(installed_at(&record), Some(T0));
    assert_eq!(installed_at(&d.join("absent")), None);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_clock_behind_the_newest_is_said() {
    let d = scratch("behind");
    // None accepted yet, and the clock reads five days before the install.
    let line = stale_line(&d, T0 - 5 * 86400, Some(T0)).unwrap();
    assert_eq!(line, "no statement from the release key can be accepted while this machine's clock reads 5 days before its install: set the clock");
    assert_eq!(stale_line(&d, T0 - 86400, Some(T0)), None, "a statement may lead the clock by a day");
    // One accepted, then the clock set back three days: every newer one would be refused as ahead of it.
    let p = pointer_text("1.0.3", "2027-03-02T14:05:00Z");
    latest(&d, &yes(), T0, "production", "1.0.2", p.as_bytes(), b"sig").unwrap();
    let back = T0 - 3 * 86400;
    let line = stale_line(&d, back, Some(T0)).unwrap();
    assert!(line.ends_with("clock reads 2 days before the newest one it accepted: set the clock"), "{line}");
    let near = stale_line(&d, T0 - 2 * 86400, Some(T0)).unwrap();
    assert!(near.contains("clock reads 1 day before the newest"), "{near}");
    let said = status(&d, back, "1.0.2", Some(T0));
    assert!(said.contains("newest     1.0.3 (dated 2 day(s) after this machine's clock)\n"), "{said}");
    assert!(said.contains(&format!("           {line}\n")), "{said}");
    let issue = scratch("behind-issue");
    let notice = issue.join("kryptik-update.issue");
    refresh_login_notice(&d, &notice, back, Some(T0)).unwrap();
    assert_eq!(std::fs::read_to_string(&notice).unwrap(), format!("kryptik update: {line}\n"));
    // Set right, the notice goes.
    refresh_login_notice(&d, &notice, T0, Some(T0)).unwrap();
    assert!(!notice.exists());
    let _ = std::fs::remove_dir_all(&issue);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn release_is_staged_in_order() {
    let d = scratch("stage");
    let p = pointer_text("1.0.3", "2027-03-02T14:05:00Z");
    // Nothing asked for: nothing polled for, nothing taken.
    assert_eq!(poll(&d, CH, "production", "1.0.2", T0), "idle");
    assert!(want(&d, Some(CH), "production", "1.0.2").unwrap_err().contains("no statement"));
    latest(&d, &yes(), T0, "production", "1.0.2", p.as_bytes(), b"sig").unwrap();
    assert_eq!(poll(&d, CH, "production", "1.0.2", T0), "idle", "fetching began before the person asked");
    // Status gives the statement's age in whole days, and says when it is overdue.
    assert!(status(&d, T0 + 2 * 86400, "1.0.2", None).contains("newest     1.0.3 (stated 2 day(s) ago)\n"));
    assert!(status(&d, T0 + 31 * 86400, "1.0.2", None).contains("no statement from the release key for 31 days"));
    // The login prompt is told the same, and only while it is so.
    let notice = d.join("issue.d").join("kryptik-update.issue");
    refresh_login_notice(&d, &notice, T0 + 2 * 86400, None).unwrap();
    assert!(!notice.exists(), "a fresh statement gave the login prompt a notice");
    refresh_login_notice(&d, &notice, T0 + 31 * 86400, None).unwrap();
    let said = std::fs::read_to_string(&notice).unwrap();
    assert_eq!(said, format!("kryptik update: {}\n", stale_line(&d, T0 + 31 * 86400, None).unwrap()));
    assert!(said.contains("for 31 days: either nothing has been published, or something is keeping it from this machine"));
    refresh_login_notice(&d, &notice, T0 + 2 * 86400, None).unwrap();
    assert!(!notice.exists(), "the notice outlived the statement's freshness");
    assert!(put(&d, &yes(), T0, "manifest", 0, b"m").unwrap_err().contains("no release has been asked for"));
    assert_eq!(want(&d, Some(CH), "production", "1.0.2").unwrap(), "1.0.3");
    assert!(want(&d, Some(CH), "production", "1.0.3").unwrap_err().contains("newest release known"));

    assert_eq!(poll(&d, CH, "production", "1.0.2", T0), "fetch 1.0.3 https://updates.example/stable/1.0.3/ need manifest 0 manifest.sig 0");
    assert!(put(&d, &yes(), T0, "kryptik-root.img", 0, b"0123456789").unwrap_err().contains("before the manifest"));
    assert_eq!(put(&d, &yes(), T0, "manifest", 0, b"the manifest").unwrap(), "manifest complete");
    assert_eq!(poll(&d, CH, "production", "1.0.2", T0), "fetch 1.0.3 https://updates.example/stable/1.0.3/ need manifest.sig 0");
    assert!(put(&d, &yes(), T0, "manifest.sig", 0, b"its signature").unwrap().contains("the manifest verifies, 2 file(s), 14 bytes"));

    assert_eq!(poll(&d, CH, "production", "1.0.2", T0), "fetch 1.0.3 https://updates.example/stable/1.0.3/ need kryptik-root.img 0 root.json 0");
    assert!(put(&d, &yes(), T0, "manifest", 0, b"another").unwrap_err().contains("not replaced"));
    assert!(put(&d, &yes(), T0, "stowaway", 0, b"x").unwrap_err().contains("does not list"));
    assert_eq!(put(&d, &yes(), T0, "kryptik-root.img", 0, b"01234").unwrap(), "kryptik-root.img 5/10");
    /* The connection dropped: the poll says where to resume, and any other
     * offset is refused without writing. */
    assert_eq!(poll(&d, CH, "production", "1.0.2", T0), "fetch 1.0.3 https://updates.example/stable/1.0.3/ need kryptik-root.img 5 root.json 0");
    assert!(put(&d, &yes(), T0, "kryptik-root.img", 0, b"01234").unwrap_err().contains("5 bytes are held"));
    assert!(put(&d, &yes(), T0, "kryptik-root.img", 5, b"567890").unwrap_err().contains("past that"));
    assert!(complete_stage(&d).unwrap_err().contains("still arriving"));
    assert_eq!(put(&d, &yes(), T0, "kryptik-root.img", 5, b"56789").unwrap(), "kryptik-root.img complete");
    assert_eq!(put(&d, &yes(), T0, "root.json", 0, b"{  }").unwrap(), "root.json complete");
    assert_eq!(poll(&d, CH, "production", "1.0.2", T0), "idle");
    let stage = complete_stage(&d).unwrap();
    assert_eq!(std::fs::read(stage.join("kryptik-root.img")).unwrap(), b"0123456789");
    let mut names: Vec<String> = std::fs::read_dir(&stage).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    names.sort();
    assert_eq!(names, ["kryptik-root.img", "manifest", "manifest.sig", "root.json"], "apply refuses a directory holding anything else");
    // The chrome's launcher reads this line.
    assert!(status(&d, T0, "1.0.2", None).lines().any(|l| l.starts_with("staged     1.0.3: 14 of 14 bytes, complete")));

    // Once the machine runs it, the staging area is gone.
    forget_if_installed(&d, "1.0.2");
    assert!(stage.exists());
    forget_if_installed(&d, "1.0.3");
    assert!(!stage.exists() && wanted(&d).is_none());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn fetch_says_why_this_image_would_not_fetch() {
    let d = scratch("unfetchable");
    latest(&d, &yes(), T0, "production", "1.0.2", pointer_text("1.0.3", "2027-03-02T14:05:00Z").as_bytes(), b"sig").unwrap();
    assert!(want(&d, Some("http://10.0.2.2:8080/"), "production", "1.0.2").unwrap_err().contains("plain http"));
    assert!(want(&d, None, "production", "1.0.2").unwrap_err().contains("no update channel"));
    assert!(wanted(&d).is_none(), "a release this image would not fetch was asked for");
    assert_eq!(poll(&d, "http://10.0.2.2:8080/", "production", "1.0.2", T0), "idle");
    assert_eq!(want(&d, Some(CH), "production", "1.0.2").unwrap(), "1.0.3");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn auto_follows_newest_release() {
    let d = scratch("auto");
    latest(&d, &yes(), T0, "production", "1.0.2", pointer_text("1.0.3", "2027-03-02T14:05:00Z").as_bytes(), b"sig").unwrap();
    assert_eq!(poll(&d, CH, "production", "1.0.2", T0), "idle", "fetching began before it was turned on");
    assert!(status(&d, T0, "1.0.2", None).contains("fetching   only when asked"));
    assert!(set_auto(&d, true, None).unwrap_err().contains("no update channel"));
    assert!(!auto(&d), "turned on with nothing to fetch from");
    set_auto(&d, true, Some(CH)).unwrap();
    assert!(status(&d, T0, "1.0.2", None).contains("fetching   automatically"));
    assert_eq!(poll(&d, CH, "production", "1.0.2", T0), "fetch 1.0.3 https://updates.example/stable/1.0.3/ need manifest 0 manifest.sig 0");
    put(&d, &yes(), T0, "manifest", 0, b"m").unwrap();

    // A newer statement's release replaces the one arriving, stage and all.
    let t1 = T0 + POINTER_INTERVAL_SECS as i64;
    latest(&d, &yes(), t1, "production", "1.0.2", pointer_text("1.0.4", "2027-03-02T15:30:00Z").as_bytes(), b"sig").unwrap();
    assert_eq!(poll(&d, CH, "production", "1.0.2", t1), "fetch 1.0.4 https://updates.example/stable/1.0.4/ need manifest 0 manifest.sig 0");
    assert!(!staging(&d, "1.0.3").exists(), "two releases are held");

    // Off: what was asked for keeps arriving, and nothing newer is asked for.
    set_auto(&d, false, None).unwrap();
    assert!(poll(&d, CH, "production", "1.0.2", t1).starts_with("fetch 1.0.4 "));
    let t2 = t1 + POINTER_INTERVAL_SECS as i64;
    latest(&d, &yes(), t2, "production", "1.0.2", pointer_text("1.0.5", "2027-03-02T16:30:00Z").as_bytes(), b"sig").unwrap();
    assert_eq!(poll(&d, CH, "production", "1.0.2", t2), "idle");
    assert_eq!(wanted(&d).as_deref(), Some("1.0.4"));
    set_auto(&d, true, Some(CH)).unwrap();
    assert!(poll(&d, CH, "production", "1.0.2", t2).starts_with("fetch 1.0.5 "));

    // Once the machine runs it, nothing newer is left to ask for.
    forget_if_installed(&d, "1.0.5");
    assert_eq!(poll(&d, CH, "production", "1.0.5", t2), "idle");
    assert!(wanted(&d).is_none());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn auto_refuses_what_fetch_refuses() {
    let d = scratch("auto-refused");
    latest(&d, &yes(), T0, "production", "1.0.2", pointer_text("1.0.3", "2027-03-02T14:05:00Z").as_bytes(), b"sig").unwrap();
    let plain = "http://10.0.2.2:8080/";
    set_auto(&d, true, Some(plain)).unwrap();
    assert_eq!(poll(&d, plain, "production", "1.0.2", T0), "idle");
    assert!(wanted(&d).is_none(), "a release this image would not fetch was asked for");
    // Only `on` turns it on, so a damaged file reads as off.
    std::fs::write(d.join("auto"), b"o\xff\n").unwrap();
    assert_eq!(poll(&d, CH, "production", "1.0.2", T0), "idle");
    assert!(set_auto(&d, false, None).is_ok() && set_auto(&d, false, None).is_ok(), "turning it off twice failed");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn wrong_manifest_is_discarded() {
    for (tag, listing, why) in [
        ("hash", LISTING.replace("sha256: 0", "sha256: f"), "announced"),
        ("version", LISTING.replace("version: 1.0.3", "version: 1.0.4"), "not for 1.0.3"),
        ("room", LISTING.replace("file 10 ", "file 18446744073709551000 "), "there is room for"),
    ] {
        let d = scratch(tag);
        let p = pointer_text("1.0.3", "2027-03-02T14:05:00Z");
        latest(&d, &yes(), T0, "production", "1.0.2", p.as_bytes(), b"sig").unwrap();
        want(&d, Some(CH), "production", "1.0.2").unwrap();
        let listing_for = move |_: &Path| Ok::<String, String>(listing.clone());
        let checks = Checks { pointer: &|_, _| Ok(()), manifest: &listing_for };
        put(&d, &checks, T0, "manifest", 0, b"m").unwrap();
        assert!(put(&d, &checks, T0, "manifest.sig", 0, b"s").unwrap_err().contains(why), "{tag}");
        assert!(!staging(&d, "1.0.3").exists(), "{tag}: the refused manifest was kept");
        // The next pair would be refused unread for an interval, so none is fetched.
        assert_eq!(poll(&d, CH, "production", "1.0.2", T0 + 60), "idle", "{tag}");
        let again = T0 + POINTER_INTERVAL_SECS as i64;
        assert_eq!(poll(&d, CH, "production", "1.0.2", again), "fetch 1.0.3 https://updates.example/stable/1.0.3/ need manifest 0 manifest.sig 0", "{tag}");
        // A verified but refused manifest starts the interval too.
        put(&d, &checks, T0 + 60, "manifest", 0, b"m").unwrap();
        assert!(put(&d, &checks, T0 + 60, "manifest.sig", 0, b"s").unwrap_err().contains("minutes ago"), "{tag}: retried within the interval");
        let _ = std::fs::remove_dir_all(&d);
    }
    let d = scratch("unsigned");
    let p = pointer_text("1.0.3", "2027-03-02T14:05:00Z");
    latest(&d, &yes(), T0, "production", "1.0.2", p.as_bytes(), b"sig").unwrap();
    want(&d, Some(CH), "production", "1.0.2").unwrap();
    let no = Checks { pointer: &|_, _| Ok(()), manifest: &|_| Err("the manifest signature does NOT verify".into()) };
    put(&d, &no, T0, "manifest", 0, b"m").unwrap();
    assert!(put(&d, &no, T0, "manifest.sig", 0, b"s").unwrap_err().contains("does NOT verify"));
    // Until the interval passes the next pair is not looked at; after it, it is.
    put(&d, &yes(), T0 + 60, "manifest", 0, b"m").unwrap();
    assert!(put(&d, &yes(), T0 + 60, "manifest.sig", 0, b"s").unwrap_err().contains("minutes ago"));
    let later = T0 + POINTER_INTERVAL_SECS as i64;
    put(&d, &no, later, "manifest", 0, b"m").unwrap();
    assert!(put(&d, &no, later, "manifest.sig", 0, b"s").unwrap_err().contains("does NOT verify"));
    assert!(put(&d, &no, T0, "kryptik-root.img", 0, b"x").unwrap_err().contains("before the manifest"));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn discarded_stage_is_asked_for_again() {
    let d = scratch("discard");
    let p = pointer_text("1.0.3", "2027-03-02T14:05:00Z");
    latest(&d, &yes(), T0, "production", "1.0.2", p.as_bytes(), b"sig").unwrap();
    want(&d, Some(CH), "production", "1.0.2").unwrap();
    put(&d, &yes(), T0, "manifest", 0, b"the manifest").unwrap();
    put(&d, &yes(), T0, "manifest.sig", 0, b"its signature").unwrap();
    // Wrong bytes of the right sizes: by its sizes the stage is complete, and stays so.
    put(&d, &yes(), T0, "kryptik-root.img", 0, b"xxxxxxxxxx").unwrap();
    put(&d, &yes(), T0, "root.json", 0, b"xxxx").unwrap();
    assert!(complete_stage(&d).is_ok());
    assert!(put(&d, &yes(), T0, "kryptik-root.img", 0, b"0123456789").is_err(), "a whole file was taken again");
    assert!(discard_stage(&d));
    assert!(!d.join("incoming").exists() && !d.join("files").exists(), "something of the stage is left");
    assert!(d.join("wanted").exists(), "the request went with the stage");
    assert!(complete_stage(&d).unwrap_err().contains("has not arrived"));
    // The same release can arrive again, from the manifest on.
    assert!(put(&d, &yes(), T0, "kryptik-root.img", 0, b"0123456789").unwrap_err().contains("before the manifest"));
    assert_eq!(put(&d, &yes(), T0, "manifest", 0, b"the manifest").unwrap(), "manifest complete");
    assert!(discard_stage(&d) && discard_stage(&d), "nothing staged is nothing to fail on");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn channel_read_from_config() {
    assert_eq!(channel_from("# where releases are\nchannel = https://updates.example/stable\n").as_deref(), Some(CH));
    assert_eq!(channel_from("channel =\n"), None);
    assert_eq!(channel_from("interval = 1\n"), None);
}

#[test]
fn stage_kept_through_trial() {
    let d = scratch("trial");
    std::fs::create_dir_all(staging(&d, "1.0.3")).unwrap();
    std::fs::write(d.join("wanted"), "1.0.3").unwrap();
    std::fs::write(d.join("files"), LISTING).unwrap();
    let trial = d.join("trial");
    std::fs::write(&trial, "b\narmed=1\n").unwrap();
    // The trial runs 1.0.3, but if it fails, kryptik-update names this stage for --retry.
    forget_unless_trial(&d, "1.0.3", &trial);
    assert!(staging(&d, "1.0.3").exists() && wanted(&d).as_deref() == Some("1.0.3"));
    // Judged unhealthy: the record is renamed while 1.0.3 still runs, until the reboot or for good.
    std::fs::rename(&trial, d.join("trial.failed")).unwrap();
    forget_unless_trial(&d, "1.0.3", &trial);
    assert!(staging(&d, "1.0.3").exists() && wanted(&d).as_deref() == Some("1.0.3"));
    // Armed again and committed: the failed record went with the arming, the trial's with the commit.
    std::fs::remove_file(d.join("trial.failed")).unwrap();
    forget_unless_trial(&d, "1.0.3", &trial);
    assert!(!d.join("incoming").exists() && !d.join("files").exists() && wanted(&d).is_none());
    let _ = std::fs::remove_dir_all(&d);
}
