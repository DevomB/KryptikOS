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
fn clients_fit_limit() {
    assert_eq!(FDS_PER_SESSION, 130);
    assert_eq!(clients_within(1024, 32), 7);
    assert_eq!(clients_within(4096, 32), 31);
    assert_eq!(clients_within(1 << 20, 32), 32);
    assert_eq!(clients_within(64, 32), 1);
    assert_eq!(clients_within(u64::MAX, 16), 16);
}
