use super::*;
use crate::zone::Zone;

fn zone(mode: &str) -> Zone {
    Zone::from_str(&format!(
        "[zone]\nname = \"t\"\n[network]\nmode = \"{mode}\"\n\
             [storage]\nmode = \"ephemeral\"\nsize = \"256M\"\n[ui]\nborder_color = \"#123456\"\n"
    ))
    .unwrap()
}

/// Taken in a forked child and read from the parent, as `kryptikd status`
/// reads a zone's; the test process itself keeps no cookie.
#[test]
fn task_takes_own_core_cookie() {
    let me = unsafe { libc::getpid() };
    match core_scheduling() {
        CoreSched::Cookies => {}
        CoreSched::NoSmt => {
            assert_eq!(core_cookie_word(me), "no-smt");
            assert_eq!(take_core_cookie().unwrap_err().raw_os_error(), Some(libc::ENODEV));
            eprintln!("no sibling threads online; no cookie to take; skipping the rest");
            return;
        }
        CoreSched::Unavailable => {
            assert_eq!(core_cookie_word(me), "unavailable");
            eprintln!("no core scheduling on this kernel; skipping the rest");
            return;
        }
    }
    let mut p = [0 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0, "pipe failed");
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        unsafe {
            libc::close(p[0]);
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            let b: u8 = if take_core_cookie().is_ok() { 1 } else { 0 };
            libc::write(p[1], &b as *const u8 as *const libc::c_void, 1);
            libc::close(p[1]);
            loop {
                libc::pause();
            }
        }
    }
    unsafe { libc::close(p[1]) };
    let mut b = 0u8;
    let n = unsafe { libc::read(p[0], &mut b as *mut u8 as *mut libc::c_void, 1) };
    unsafe { libc::close(p[0]) };
    let child = core_cookie_of(pid);
    let mine = core_cookie_of(unsafe { libc::getpid() });
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
    }
    assert_eq!((n, b), (1, 1), "the child could not take a cookie");
    let child = child.expect("the parent may read its child's cookie");
    assert_ne!(child, 0, "the child's cookie reads as zero after PR_SCHED_CORE_CREATE");
    assert_eq!(mine.expect("a task may read its own cookie"), 0, "the parent took no cookie and must have none");
    assert_eq!(core_cookie_word(unsafe { libc::getpid() }), "none");
}

#[test]
fn every_zone_gets_net_namespace() {
    assert_ne!(namespace_flags(&zone("none")) & libc::CLONE_NEWNET, 0);
    assert_ne!(namespace_flags(&zone("routed")) & libc::CLONE_NEWNET, 0);
    // The parent moves the physical NIC into this one.
    assert_ne!(namespace_flags(&zone("nic")) & libc::CLONE_NEWNET, 0);
}

#[test]
fn every_zone_gets_core_namespaces() {
    for m in ["none", "routed", "nic"] {
        let f = namespace_flags(&zone(m));
        for (flag, name) in &NAMESPACES[..5] {
            assert_ne!(f & flag, 0, "zone mode {m} is missing the {name} namespace");
        }
    }
}
