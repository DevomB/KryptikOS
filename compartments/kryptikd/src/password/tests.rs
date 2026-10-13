use super::*;

// The SHA-512 crypt specification's own example, which shadow's ENCRYPT_METHOD SHA512 writes.
const HELLO: &str = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1";

#[test]
fn a_password_matches_its_hash_and_nothing_else_does() {
    assert!(matches(b"Hello world!", HELLO));
    for wrong in [&b"Hello world"[..], b"hello world!", b"", b"Hello world!\0"] {
        assert!(!matches(wrong, HELLO), "{wrong:?}");
    }
    // A hash cut short, or a setting crypt cannot read, matches nothing.
    assert!(!matches(b"Hello world!", &HELLO[..HELLO.len() - 1]));
    assert!(!matches(b"Hello world!", "!"));
}

#[test]
fn the_hash_is_the_named_users_and_only_a_usable_one() {
    let shadow = format!(
        "root:!:20000::::::\ntester:{HELLO}:20000:0:99999:7:::\nlocked:!{HELLO}:20000::::::\nnone::20000::::::\nyes:$y$j9T$salt$hash:20000::::::\n"
    );
    assert_eq!(hash_of(&shadow, "tester").as_deref(), Some(HELLO));
    assert_eq!(hash_of(&shadow, "root"), None);
    assert_eq!(hash_of(&shadow, "locked"), None, "an account locked with ! has no hash to match");
    assert_eq!(hash_of(&shadow, "none"), None, "an empty field is no password, not any password");
    assert_eq!(hash_of(&shadow, "yes"), None, "a kind musl would read as DES");
    assert_eq!(hash_of(&shadow, "test"), None, "a name is matched whole");
    assert_eq!(hash_of(&shadow, "nobody"), None);
}

#[test]
fn a_wrong_password_pauses_the_next_and_a_right_one_clears_it() {
    let dir = std::env::temp_dir().join(format!("kryptik-password-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let shadow = dir.join("shadow");
    std::fs::write(&shadow, format!("tester:{HELLO}:20000:0:99999:7:::\n")).unwrap();
    let mut a = Attempts::default();
    let t0 = Instant::now();
    assert_eq!(check(&shadow, "tester", b"guess", &mut a, t0), Err("wrong password".into()));
    // The next try within the pause is not checked, even with the right password.
    assert_eq!(check(&shadow, "tester", b"Hello world!", &mut a, t0 + Duration::from_millis(500)), Err("wait 2 s".into()));
    assert_eq!(a.wait(t0 + Duration::from_secs(2)), None);
    assert_eq!(check(&shadow, "tester", b"guess", &mut a, t0 + Duration::from_secs(2)), Err("wrong password".into()));
    assert_eq!(a.wait(t0 + Duration::from_secs(2)), Some(Duration::from_secs(4)), "the pause doubles");
    let later = t0 + Duration::from_secs(10);
    assert_eq!(check(&shadow, "tester", b"Hello world!", &mut a, later), Ok(()));
    assert_eq!(a.wait(later), None, "a right password ends the pause");
    assert_eq!(check(&shadow, "nobody", b"Hello world!", &mut a, later), Err("nobody has no SHA-512 or SHA-256 crypt password to check".into()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_pause_stops_at_a_minute() {
    let mut a = Attempts::default();
    let t = Instant::now();
    for _ in 0..20 {
        a.failed(t);
    }
    assert_eq!(a.wait(t), Some(Duration::from_secs(60)));
}
