use super::*;

fn copied(owner: u64, mimes: &[&str]) -> Clipboard {
    let mut c = Clipboard::default();
    c.set(Some(Selection { owner, source: 7, mimes: mimes.iter().map(|m| m.to_string()).collect(), data: None }));
    c.actions.clear();
    c
}

/// A move over a socketpair: the proxy's end in a Control, the launcher's end for the test.
fn door(request: &[u8], now: Instant) -> (Control, UnixStream) {
    let (a, mut b) = UnixStream::pair().unwrap();
    b.write_all(request).unwrap();
    (Control::new(a, now), b)
}

fn answer(m: Control, mut t: UnixStream) -> String {
    drop(m);
    let mut out = Vec::new();
    t.read_to_end(&mut out).unwrap();
    String::from_utf8(out).unwrap()
}

/// The descriptor a take asked the copying client to write, from the Send it queued.
fn send_fd(clip: &mut Clipboard) -> (String, OwnedFd) {
    match clip.actions.pop() {
        Some(Action::Send(3, 7, mime, fd)) => (mime, fd),
        other => panic!("no send to the copying client: {other:?}"),
    }
}

#[test]
fn requests_are_read_strictly() {
    assert_eq!(parse(b"take\n"), Ok(Some(Request::Take)));
    assert_eq!(parse(b"tak"), Ok(None));
    assert_eq!(parse(b"clear 12\n"), Ok(Some(Request::Clear(12))));
    assert_eq!(parse(b"give text/plain 5\nhello"), Ok(Some(Request::Give("text/plain".into(), b"hello".to_vec()))));
    assert_eq!(parse(b"give text/plain 5\nhel"), Ok(None), "the bytes are still coming");
    for bad in [
        &b"give text/x-mine 1\na"[..],
        b"give text/plain 5\nhello!",
        b"give text/plain 1048577\n",
        b"give text/plain five\n",
        b"take\nmore",
        b"clear\n",
        b"steal\n",
    ] {
        assert!(parse(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
    }
    assert!(parse(&[b'x'; 200]).is_err(), "a line with no end over the bound");
}

/// A take asks the copying client for the first type of the gesture's list it offers, and
/// answers with the bytes it wrote.
#[test]
fn a_take_reads_the_copy_from_its_client() {
    let now = Instant::now();
    let mut clip = copied(3, &["text/html", "text/plain;charset=utf-8"]);
    let (mut m, t) = door(b"take\n", now);
    assert!(!m.step(&mut clip, now), "it waits on the copying client");
    let (mime, fd) = send_fd(&mut clip);
    assert_eq!(mime, "text/plain;charset=utf-8");
    let mut w = std::fs::File::from(fd);
    w.write_all(b"hello").unwrap();
    drop(w);
    assert!(m.step(&mut clip, now));
    assert_eq!(answer(m, t), format!("ok {} text/plain;charset=utf-8 5\nhello", clip.generation));
}

#[test]
fn an_oversize_copy_moves_nothing() {
    let now = Instant::now();
    let mut clip = copied(3, &["text/plain"]);
    let (mut m, t) = door(b"take\n", now);
    m.step(&mut clip, now);
    let (_, fd) = send_fd(&mut clip);
    nonblocking(fd.as_raw_fd());
    let mut w = std::fs::File::from(fd);
    let chunk = vec![b'x'; 65536];
    let (mut sent, mut over) = (0, false);
    while sent <= policy::MAX_MOVE_BYTES && !over {
        match w.write(&chunk) {
            Ok(n) => sent += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => over = m.step(&mut clip, now),
            Err(_) => break,
        }
    }
    drop(w);
    while !m.step(&mut clip, now) {}
    let said = answer(m, t);
    assert!(said.starts_with("error: the selection is over 1 MiB"), "{said:.80}");
    assert!(clip.selection.is_some(), "the selection stays as it was");
}

#[test]
fn a_stalled_copy_moves_nothing() {
    let now = Instant::now();
    let mut clip = copied(3, &["text/plain"]);
    let (mut m, t) = door(b"take\n", now);
    assert!(!m.step(&mut clip, now));
    let (_, _held) = send_fd(&mut clip);
    assert!(!m.step(&mut clip, now + Duration::from_secs(1)));
    assert!(m.step(&mut clip, now + DEADLINE + Duration::from_millis(1)));
    assert!(answer(m, t).starts_with("error: the copying window did not answer within 2 s"));
}

#[test]
fn a_type_off_the_list_moves_nothing() {
    let now = Instant::now();
    let mut clip = copied(3, &["application/x-kryptik-test"]);
    let (mut m, t) = door(b"take\n", now);
    assert!(m.step(&mut clip, now));
    assert!(clip.actions.is_empty(), "the copying client was never asked");
    assert!(answer(m, t).starts_with("error: the selection offers no type the gesture carries"));
}

#[test]
fn nothing_copied_is_empty() {
    let now = Instant::now();
    let mut clip = Clipboard::default();
    let (mut m, t) = door(b"take\n", now);
    assert!(m.step(&mut clip, now));
    assert_eq!(answer(m, t), "empty\n");
}

/// Given bytes are the zone's selection, offered to the keyboard's client and answered from the
/// proxy's memory, to a take and to a paste alike.
#[test]
fn given_bytes_are_held_and_served_by_the_proxy() {
    let now = Instant::now();
    let mut clip = Clipboard { focus: Some(2), ..Clipboard::default() };
    let (mut m, t) = door(b"give text/plain 5\nhello", now);
    assert!(m.step(&mut clip, now));
    assert_eq!(answer(m, t), "ok\n");
    let sel = clip.selection.as_ref().unwrap();
    assert_eq!((sel.owner, sel.mimes.as_slice(), sel.data.as_deref().map(Vec::as_slice)), (OWN, &["text/plain".to_string()][..], Some(&b"hello"[..])));
    assert!(matches!(clip.actions.as_slice(), [Action::Offer(2)]), "{:?}", clip.actions);
    clip.actions.clear();
    let (mut m, t) = door(b"take\n", now);
    assert!(m.step(&mut clip, now));
    assert!(clip.actions.is_empty(), "no client is asked for what the proxy holds");
    assert_eq!(answer(m, t), format!("ok {} text/plain 5\nhello", clip.generation));
    let (r, w) = UnixStream::pair().unwrap();
    let mut paste = Writer::new(OwnedFd::from(w), clip.selection.as_ref().unwrap().data.clone().unwrap(), now);
    assert!(paste.step(now));
    drop(paste);
    let mut got = Vec::new();
    (&r).read_to_end(&mut got).unwrap();
    assert_eq!(got, b"hello");
}

/// A clear ends the selection taken, and only that one: a copy made since stays.
#[test]
fn a_clear_ends_only_the_selection_taken() {
    let now = Instant::now();
    let mut clip = copied(3, &["text/plain"]);
    let taken = clip.generation;
    let (mut m, t) = door(format!("clear {}\n", taken + 1).as_bytes(), now);
    assert!(m.step(&mut clip, now));
    assert!(answer(m, t).starts_with("error: the selection changed since it was taken"));
    assert!(clip.selection.is_some());
    let (mut m, t) = door(format!("clear {taken}\n").as_bytes(), now);
    assert!(m.step(&mut clip, now));
    assert_eq!(answer(m, t), "ok\n");
    assert!(clip.selection.is_none());
    assert!(matches!(clip.actions.as_slice(), [Action::Cancel(3, 7)]), "the copying client's source is cancelled: {:?}", clip.actions);
}

#[test]
fn the_peer_is_this_user() {
    let (a, _b) = UnixStream::pair().unwrap();
    assert_eq!(peer_uid(a.as_raw_fd()), Some(unsafe { libc::geteuid() }));
}
