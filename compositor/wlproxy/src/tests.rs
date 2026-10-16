use super::*;

struct Full;
impl std::io::Write for Full {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSPC))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn log_bounded() {
    let mut log = Log::new("untrusted");
    let mut out: Vec<u8> = Vec::new();
    let long = "x".repeat(4000);
    for _ in 0..10_000 {
        log.put(&long, &mut out);
    }
    let text = String::from_utf8(out).unwrap();
    assert!(text.len() <= Log::MAX_BYTES + 100, "{} bytes logged", text.len());
    assert!(text.lines().all(|l| l.len() <= Log::LINE_MAX + 40));
    assert!(text.ends_with("the log is full; nothing more is logged\n"));
    assert_eq!(text.matches("log is full").count(), 1);
    // A full /run is ignored, not fatal.
    Log::new("untrusted").put("x", &mut Full);
}

#[test]
fn zone_names_bounded() {
    assert!(zone_ok("untrusted") && zone_ok("dev-2") && zone_ok(&"z".repeat(32)));
    assert!(!zone_ok("") && !zone_ok(&"z".repeat(33)) && !zone_ok("a b") && !zone_ok("a/b") && !zone_ok("zoné"));
}

#[test]
fn a_passed_listener_is_taken_in_place_of_a_path() {
    let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let o = parse(&args(&["--zone", "work", "--listen-fd", "3", "--upstream", "/proc/self/fd/4"]));
    assert_eq!(o.listen_fd, Some(3));
    assert!(o.listen.as_os_str().is_empty());
    let o = parse(&args(&["--zone", "work", "--listen", "/tmp/w", "--upstream", "/u"]));
    assert_eq!(o.listen_fd, None);
    assert!(!o.hold_awake, "a zone holds the screen awake only when its file says so");
    assert!(parse(&args(&["--zone", "personal", "--listen-fd", "3", "--upstream", "/u", "--hold-awake"])).hold_awake);
    let path = std::env::temp_dir().join(format!("wlproxy-listening-{}", std::process::id()));
    let sock = std::os::unix::net::UnixListener::bind(&path).unwrap();
    assert!(listening(sock.as_raw_fd()));
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    assert!(!listening(a.as_raw_fd()), "a connected socket is not one");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn clients_fit_limit() {
    assert_eq!(FDS_PER_SESSION, 130);
    assert_eq!(clients_within(1024, 32), 7);
    assert_eq!(clients_within(4096, 32), 31);
    assert_eq!(clients_within(1 << 20, 32), 32);
    assert_eq!(clients_within(64, 32), 1);
    assert_eq!(clients_within(u64::MAX, 16), 16);
}
