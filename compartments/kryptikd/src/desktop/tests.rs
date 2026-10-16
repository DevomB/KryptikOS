use super::*;
use std::os::unix::io::FromRawFd;

#[test]
fn request_names_a_keymap_and_ends() {
    let text = "desktop\nenv XKB_DEFAULT_LAYOUT=us,de\nenv XKB_DEFAULT_VARIANT=,\n\
                env XKB_DEFAULT_OPTIONS=grp:win_space_toggle\nenv KRYPTIK_LAYOUTS=us de\nend\n";
    let env = parse(text).unwrap();
    assert_eq!(env.len(), 4);
    assert_eq!(env[0], ("XKB_DEFAULT_LAYOUT".to_string(), "us,de".to_string()));
    assert_eq!(env[3], ("KRYPTIK_LAYOUTS".to_string(), "us de".to_string()));
    assert!(parse("desktop\nend\n").unwrap().is_empty());
    for bad in [
        "desktop\n",
        "status\nend\n",
        "desktop\nenv LD_PRELOAD=/tmp/x.so\nend\n",
        // dwl names its own display.
        "desktop\nenv WAYLAND_DISPLAY=wayland-1\nend\n",
        "desktop\nenv XKB_DEFAULT_LAYOUT=us\nenv XKB_DEFAULT_LAYOUT=de\nend\n",
        "desktop\nenv XKB_DEFAULT_LAYOUT=../x\nend\n",
        "desktop\nenv XKB_DEFAULT_LAYOUT=us;id\nend\n",
        "desktop\nXKB_DEFAULT_LAYOUT=us\nend\n",
    ] {
        assert!(parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn environment_is_the_daemons_but_the_keymap() {
    let env = environment(Path::new("/run/user/1000"), &[("XKB_DEFAULT_LAYOUT".into(), "us".into())]);
    assert_eq!(
        env,
        vec!["XDG_RUNTIME_DIR=/run/user/1000", "WLR_RENDERER=pixman", "XCURSOR_PATH=/usr/share/icons", "XKB_DEFAULT_LAYOUT=us"]
    );
}

#[test]
fn groups_are_the_logins_less_kryptik() {
    let status = "Name:\tkryptik-launch\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t990 991 1000 \n";
    let (uid, gid, groups) = ids_of(status).unwrap();
    assert_eq!((uid, gid), (1000, 1000));
    assert_eq!(groups, vec![990, 991, 1000]);
    assert_eq!(groups_without(&groups, 991), vec![990, 1000]);
    assert!(ids_of("Uid:\t1000\nGid:\t1000\nGroups:\t\n").unwrap().2.is_empty());
    assert!(ids_of("Uid:\t1000\nGroups:\t1\n").is_none(), "no Gid");
}

fn seqpacket() -> (OwnedFd, OwnedFd) {
    let mut sv = [0; 2];
    // SAFETY: two descriptors into an array of two, each owned once.
    unsafe {
        assert_eq!(libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()), 0);
        (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1]))
    }
}

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut p = [0; 2];
    // SAFETY: as above.
    unsafe {
        assert_eq!(libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC), 0);
        (OwnedFd::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1]))
    }
}

fn log() -> OwnedFd {
    OwnedFd::from(std::fs::OpenOptions::new().write(true).open("/dev/null").unwrap())
}

#[test]
fn three_descriptors_of_their_kinds() {
    let (s, _peer) = seqpacket();
    let (_r, w) = pipe();
    assert!(handed(vec![s, w, log()]).is_ok());

    let (s, _peer) = seqpacket();
    let (_r, w) = pipe();
    assert!(handed(vec![w, s, log()]).is_err(), "out of order");
    let (s, _peer) = seqpacket();
    assert!(handed(vec![s, log()]).is_err(), "two");
    let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let (_r, w) = pipe();
    assert!(handed(vec![OwnedFd::from(stream), w, log()]).is_err(), "a stream socket for the spawner's");
    let (s, _peer) = seqpacket();
    let (r, _w) = pipe();
    assert!(handed(vec![s, r, log()]).is_err(), "the status pipe's read end");
    let (s, _peer) = seqpacket();
    let (_r, w) = pipe();
    let read_only = OwnedFd::from(std::fs::File::open("/dev/null").unwrap());
    assert!(handed(vec![s, w, read_only]).is_err(), "a log open only for reading");
}
