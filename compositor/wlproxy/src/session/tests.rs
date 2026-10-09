use super::*;
use std::os::unix::net::UnixStream;
use std::os::unix::io::{AsRawFd, IntoRawFd};
use std::io::{Read, Write};

/// A session over two socketpairs, with the test's client and server ends.
fn make() -> (Session, UnixStream, UnixStream) {
    let (c_test, c_prox) = UnixStream::pair().unwrap();
    let (s_test, s_prox) = UnixStream::pair().unwrap();
    c_test.set_nonblocking(true).unwrap();
    s_test.set_nonblocking(true).unwrap();
    let s = Session::new("work", c_prox.into_raw_fd(), s_prox.into_raw_fd());
    (s, c_test, s_test)
}
fn pump_all(s: &mut Session) -> Result<(), SessionError> {
    loop {
        let a = s.client.read()?;
        let b = s.server.read()?;
        s.pump(Dir::ClientToServer)?;
        s.pump(Dir::ServerToClient)?;
        s.server.flush()?;
        s.client.flush()?;
        if (a == usize::MAX || a == 0) && (b == usize::MAX || b == 0) {
            return Ok(());
        }
    }
}
fn read_all(st: &mut UnixStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match st.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    out
}
fn get_registry(id: u32) -> Vec<u8> {
    MessageWriter::new(1, 1).u32(id).finish().unwrap() // wl_display.get_registry
}
fn global(reg: u32, name: u32, iface: &str, version: u32) -> Vec<u8> {
    MessageWriter::new(reg, WL_REGISTRY_GLOBAL).u32(name).string(iface).u32(version).finish().unwrap()
}
/// A session with toplevel 7 created and the compositor's end drained.
fn with_toplevel() -> (Session, UnixStream, UnixStream) {
    let (mut s, mut c, mut sv) = make();
    c.write_all(&get_registry(2)).unwrap();
    sv.write_all(&global(2, 1, "wl_compositor", 6)).unwrap();
    sv.write_all(&global(2, 2, "xdg_wm_base", 6)).unwrap();
    pump_all(&mut s).unwrap();
    c.write_all(&MessageWriter::new(2, WL_REGISTRY_BIND).u32(1).string("wl_compositor").u32(6).u32(3).finish().unwrap()).unwrap();
    c.write_all(&MessageWriter::new(2, WL_REGISTRY_BIND).u32(2).string("xdg_wm_base").u32(6).u32(4).finish().unwrap()).unwrap();
    c.write_all(&MessageWriter::new(3, 0).u32(5).finish().unwrap()).unwrap(); // create_surface -> 5
    c.write_all(&MessageWriter::new(4, 2).u32(6).u32(5).finish().unwrap()).unwrap(); // get_xdg_surface -> 6
    c.write_all(&MessageWriter::new(6, 1).u32(7).finish().unwrap()).unwrap(); // get_toplevel -> 7
    pump_all(&mut s).unwrap();
    let _ = read_all(&mut sv);
    (s, c, sv)
}
/// A session with wl_shm v2 bound as object 3 and the compositor's end drained.
fn with_shm() -> (Session, UnixStream, UnixStream) {
    let (mut s, mut c, mut sv) = make();
    c.write_all(&get_registry(2)).unwrap();
    sv.write_all(&global(2, 1, "wl_shm", 2)).unwrap();
    pump_all(&mut s).unwrap();
    c.write_all(&MessageWriter::new(2, WL_REGISTRY_BIND).u32(1).string("wl_shm").u32(2).u32(3).finish().unwrap()).unwrap();
    pump_all(&mut s).unwrap();
    let _ = read_all(&mut sv);
    (s, c, sv)
}

#[test]
fn hidden_globals_invisible_and_unbindable() {
    let (mut s, mut c, mut sv) = make();
    c.write_all(&get_registry(2)).unwrap();
    pump_all(&mut s).unwrap();
    assert!(s.has_object(2));
    sv.write_all(&global(2, 1, "wl_compositor", 6)).unwrap();
    sv.write_all(&global(2, 2, "zwlr_screencopy_manager_v1", 3)).unwrap();
    sv.write_all(&global(2, 3, "wl_data_device_manager", 3)).unwrap();
    sv.write_all(&global(2, 4, "wl_shm", 2)).unwrap();
    pump_all(&mut s).unwrap();
    let seen = read_all(&mut c);
    let text = String::from_utf8_lossy(&seen).to_string();
    assert!(text.contains("wl_compositor") && text.contains("wl_shm"));
    assert!(!text.contains("screencopy") && !text.contains("data_device"), "{text}");
    assert_eq!(s.hidden_count, 2);
    // binding the hidden global by guessing its name is refused
    let bind = MessageWriter::new(2, WL_REGISTRY_BIND).u32(2).string("zwlr_screencopy_manager_v1").u32(3).u32(5).finish().unwrap();
    c.write_all(&bind).unwrap();
    let r = pump_all(&mut s);
    assert!(matches!(r, Err(SessionError::HiddenInterface(_))), "{r:?}");
    // a name made up to fill the log is shown as a prefix and a length
    let (mut s, mut c, _sv) = make();
    c.write_all(&get_registry(2)).unwrap();
    let junk = "\u{1b}".repeat(4000);
    c.write_all(&MessageWriter::new(2, WL_REGISTRY_BIND).u32(1).string(&junk).u32(1).u32(3).finish().unwrap()).unwrap();
    let why = pump_all(&mut s).unwrap_err().to_string();
    assert!(why.contains("not advertised") && why.ends_with("(4000 bytes)") && why.len() < 600, "{} bytes: {why:.120}", why.len());
    // and an allowed one at an allowed version is forwarded and tracked
    let (mut s, mut c, mut sv) = make();
    c.write_all(&get_registry(2)).unwrap();
    sv.write_all(&global(2, 1, "wl_compositor", 6)).unwrap();
    pump_all(&mut s).unwrap();
    let bind = MessageWriter::new(2, WL_REGISTRY_BIND).u32(1).string("wl_compositor").u32(6).u32(3).finish().unwrap();
    c.write_all(&bind).unwrap();
    pump_all(&mut s).unwrap();
    assert!(s.has_object(3));
    let got = read_all(&mut sv);
    assert!(got.len() >= bind.len(), "bind forwarded to the compositor");
    // too high a version is refused
    let bind = MessageWriter::new(2, WL_REGISTRY_BIND).u32(1).string("wl_compositor").u32(99).u32(4).finish().unwrap();
    c.write_all(&bind).unwrap();
    assert!(matches!(pump_all(&mut s), Err(SessionError::VersionTooHigh { .. })));
}

#[test]
fn global_remove_reaches_every_registry() {
    let (mut s, mut c, mut sv) = make();
    c.write_all(&get_registry(2)).unwrap();
    c.write_all(&get_registry(3)).unwrap();
    pump_all(&mut s).unwrap();
    for reg in [2, 3] {
        sv.write_all(&global(reg, 1, "wl_shm", 2)).unwrap();
        sv.write_all(&global(reg, 2, "zwlr_screencopy_manager_v1", 3)).unwrap();
    }
    pump_all(&mut s).unwrap();
    read_all(&mut c);
    let remove = |reg: u32, name: u32| MessageWriter::new(reg, WL_REGISTRY_GLOBAL_REMOVE).u32(name).finish().unwrap();
    // Each registry is told of wl_shm's removal; none of the hidden global's.
    for reg in [2, 3] {
        sv.write_all(&remove(reg, 1)).unwrap();
        sv.write_all(&remove(reg, 2)).unwrap();
    }
    pump_all(&mut s).unwrap();
    assert_eq!(read_all(&mut c), [remove(2, 1), remove(3, 1)].concat());
}

#[test]
fn bind_must_match_advertised_global() {
    for (name, version) in [("wl_shm", 1), ("wl_compositor", 2), ("wl_compositor", 0)] {
        let (mut s, mut c, mut sv) = make();
        c.write_all(&get_registry(2)).unwrap();
        sv.write_all(&global(2, 11, "wl_compositor", 1)).unwrap();
        pump_all(&mut s).unwrap();
        read_all(&mut sv);
        let bind = MessageWriter::new(2, WL_REGISTRY_BIND)
            .u32(11).string(name).u32(version).u32(3).finish().unwrap();
        c.write_all(&bind).unwrap();
        assert!(pump_all(&mut s).is_err(), "accepted {name} v{version} for wl_compositor v1");
        assert!(!s.has_object(3), "a rejected binding must not create an object");
        assert!(read_all(&mut sv).is_empty(), "a rejected binding reached the compositor");
    }
}

#[test]
fn live_object_not_replaced() {
    let (mut s, mut c, mut sv) = make();
    c.write_all(&get_registry(2)).unwrap();
    pump_all(&mut s).unwrap();
    read_all(&mut sv);
    // wl_display.sync on the registry's id must not retype it or reach the compositor.
    c.write_all(&MessageWriter::new(1, 0).u32(2).finish().unwrap()).unwrap();
    assert!(pump_all(&mut s).is_err(), "replaced a live registry with a callback");
    assert_eq!(s.objects.get(2).unwrap().0.name, "wl_registry");
    assert!(read_all(&mut sv).is_empty());
}

#[test]
fn id_reusable_after_delete_id() {
    let (mut s, mut c, mut sv) = make();
    c.write_all(&MessageWriter::new(1, 0).u32(2).finish().unwrap()).unwrap();
    pump_all(&mut s).unwrap();
    sv.write_all(&MessageWriter::new(2, 0).u32(0).finish().unwrap()).unwrap();
    sv.write_all(&MessageWriter::new(1, WL_DISPLAY_DELETE_ID).u32(2).finish().unwrap()).unwrap();
    pump_all(&mut s).unwrap();
    assert!(!s.has_object(2));
    c.write_all(&get_registry(2)).unwrap();
    pump_all(&mut s).unwrap();
    assert_eq!(s.objects.get(2).unwrap().0.name, "wl_registry");
}

#[test]
fn ids_stay_dense() {
    // A new id takes a free slot or the next one, as libwayland-server insists.
    let (mut s, mut c, _sv) = make();
    c.write_all(&get_registry(5)).unwrap();
    assert!(matches!(pump_all(&mut s), Err(SessionError::SparseId(5))));
    let (mut s, mut c, _sv) = make();
    c.write_all(&get_registry(2)).unwrap();
    pump_all(&mut s).unwrap();
    assert!(s.has_object(2));
}

#[test]
fn id_slots_bounded() {
    // A client that frees every object and never reuses an id runs out of slots, not memory.
    let mut o = Objects::new((protocol::find("wl_display").unwrap(), 1));
    let callback = (protocol::find("wl_callback").unwrap(), 1);
    let mut id = 2;
    while o.insert(id, callback).is_ok() {
        o.remove(id);
        id += 1;
    }
    assert!(matches!(o.insert(id, callback), Err(SessionError::SparseId(_))));
    assert_eq!(id as usize, policy::MAX_ID_SLOTS);
    assert_eq!((o.client.len(), o.live), (policy::MAX_ID_SLOTS, 1));
}

#[test]
fn popup_refused() {
    let (mut s, mut c, mut sv) = make();
    s.objects.place(2, (protocol::find("xdg_surface").unwrap(), 1));
    s.objects.place(3, (protocol::find("xdg_positioner").unwrap(), 1));
    c.write_all(&MessageWriter::new(2, 2).u32(4).u32(0).u32(3).finish().unwrap()).unwrap();
    assert!(matches!(pump_all(&mut s), Err(SessionError::Forbidden(_))));
    assert!(!s.has_object(4));
    assert!(read_all(&mut sv).is_empty());
}

#[test]
fn toplevel_limit_and_reclaim() {
    let (mut s, mut c, mut sv) = make();
    s.objects.place(2, (protocol::find("xdg_surface").unwrap(), 1));
    for id in 3..3 + policy::MAX_TOPLEVELS_PER_SESSION as u32 {
        c.write_all(&MessageWriter::new(2, 1).u32(id).finish().unwrap()).unwrap();
        pump_all(&mut s).unwrap();
    }
    assert_eq!(s.toplevels, policy::MAX_TOPLEVELS_PER_SESSION);
    read_all(&mut sv);
    let denied = 3 + policy::MAX_TOPLEVELS_PER_SESSION as u32;
    c.write_all(&MessageWriter::new(2, 1).u32(denied).finish().unwrap()).unwrap();
    assert!(matches!(pump_all(&mut s), Err(SessionError::ResourceLimit(_))));
    assert!(!s.has_object(denied));
    assert!(read_all(&mut sv).is_empty());
    sv.write_all(&MessageWriter::new(1, WL_DISPLAY_DELETE_ID).u32(3).finish().unwrap()).unwrap();
    pump_all(&mut s).unwrap();
    assert_eq!(s.toplevels, policy::MAX_TOPLEVELS_PER_SESSION - 1);
}

#[test]
fn shm_pool_limits() {
    let (mut s, mut c, mut sv) = make();
    s.objects.place(3, (protocol::find("wl_shm").unwrap(), 1));
    let (fd, _) = UnixStream::pair().unwrap();
    let create = |id, size| MessageWriter::new(3, 0).u32(id).i32(size).finish().unwrap();
    send_with_fd(c.as_raw_fd(), &create(4, policy::MAX_SHM_POOL_BYTES as i32), fd.as_raw_fd());
    pump_all(&mut s).unwrap();
    assert_eq!(s.shm_pool_bytes, policy::MAX_SHM_POOL_BYTES);
    let grow = MessageWriter::new(4, 2).i32(policy::MAX_SHM_POOL_BYTES as i32 + 1).finish().unwrap();
    c.write_all(&grow).unwrap();
    assert!(matches!(pump_all(&mut s), Err(SessionError::ResourceLimit(_))));
    assert_eq!(s.shm_pool_bytes, policy::MAX_SHM_POOL_BYTES);
    read_all(&mut sv);

    let (mut s, mut c, mut sv) = make();
    s.objects.place(3, (protocol::find("wl_shm").unwrap(), 1));
    for id in 4..4 + policy::MAX_SHM_POOLS_PER_SESSION as u32 {
        send_with_fd(c.as_raw_fd(), &create(id, 4096), fd.as_raw_fd());
        pump_all(&mut s).unwrap();
    }
    assert_eq!(s.shm_pool_count, policy::MAX_SHM_POOLS_PER_SESSION);
    read_all(&mut sv);
    let denied = 4 + policy::MAX_SHM_POOLS_PER_SESSION as u32;
    send_with_fd(c.as_raw_fd(), &create(denied, 4096), fd.as_raw_fd());
    assert!(matches!(pump_all(&mut s), Err(SessionError::ResourceLimit(_))));
    assert!(!s.has_object(denied));
    assert!(read_all(&mut sv).is_empty());

    let (mut s, mut c, mut sv) = make();
    s.objects.place(3, (protocol::find("wl_shm").unwrap(), 1));
    for id in 4..6 {
        send_with_fd(c.as_raw_fd(), &create(id, policy::MAX_SHM_POOL_BYTES as i32), fd.as_raw_fd());
        pump_all(&mut s).unwrap();
    }
    assert_eq!(s.shm_pool_bytes, policy::MAX_SHM_BYTES_PER_SESSION);
    read_all(&mut sv);
    send_with_fd(c.as_raw_fd(), &create(6, 4096), fd.as_raw_fd());
    assert!(matches!(pump_all(&mut s), Err(SessionError::ResourceLimit(_))));
    assert!(read_all(&mut sv).is_empty());
}

#[test]
fn pool_budget_follows_buffers() {
    let (mut s, mut c, mut sv) = make();
    s.objects.place(3, (protocol::find("wl_shm").unwrap(), 1));
    let (fd, _) = UnixStream::pair().unwrap();
    let create = |id| MessageWriter::new(3, 0).u32(id).i32(4096).finish().unwrap();
    send_with_fd(c.as_raw_fd(), &create(4), fd.as_raw_fd());
    c.write_all(&MessageWriter::new(4, 0).u32(5).i32(0).i32(16).i32(16).i32(64).u32(1).finish().unwrap()).unwrap();
    c.write_all(&MessageWriter::new(4, 1).finish().unwrap()).unwrap();
    pump_all(&mut s).unwrap();
    sv.write_all(&MessageWriter::new(1, WL_DISPLAY_DELETE_ID).u32(4).finish().unwrap()).unwrap();
    pump_all(&mut s).unwrap();
    assert_eq!((s.shm_pool_count, s.shm_pool_bytes), (1, 4096));

    send_with_fd(c.as_raw_fd(), &create(4), fd.as_raw_fd());
    pump_all(&mut s).unwrap();
    assert_eq!((s.shm_pool_count, s.shm_pool_bytes), (2, 8192));
    c.write_all(&MessageWriter::new(5, 0).finish().unwrap()).unwrap();
    pump_all(&mut s).unwrap();
    sv.write_all(&MessageWriter::new(1, WL_DISPLAY_DELETE_ID).u32(5).finish().unwrap()).unwrap();
    pump_all(&mut s).unwrap();
    assert_eq!((s.shm_pool_count, s.shm_pool_bytes), (1, 4096));
}

fn delete_ids(sv: &mut UnixStream, ids: &[u32]) {
    for id in ids {
        sv.write_all(&MessageWriter::new(1, WL_DISPLAY_DELETE_ID).u32(*id).finish().unwrap()).unwrap();
    }
}

/// The compositor holds a committed buffer past its wl_buffer and pool: the pool stays charged.
#[test]
fn committed_buffer_keeps_its_pool_charged() {
    let (mut s, mut c, mut sv) = make();
    s.objects.place(3, (protocol::find("wl_shm").unwrap(), 1));
    s.objects.place(8, (protocol::find("wl_compositor").unwrap(), 4));
    let (fd, _) = UnixStream::pair().unwrap();
    c.write_all(&MessageWriter::new(8, 0).u32(9).finish().unwrap()).unwrap(); // create_surface -> 9
    send_with_fd(c.as_raw_fd(), &MessageWriter::new(3, 0).u32(4).i32(4096).finish().unwrap(), fd.as_raw_fd());
    c.write_all(&MessageWriter::new(4, 0).u32(5).i32(0).i32(16).i32(16).i32(64).u32(1).finish().unwrap()).unwrap();
    c.write_all(&MessageWriter::new(9, 1).u32(5).i32(0).i32(0).finish().unwrap()).unwrap(); // attach 5
    c.write_all(&MessageWriter::new(9, 6).finish().unwrap()).unwrap(); // commit
    c.write_all(&MessageWriter::new(5, 0).finish().unwrap()).unwrap(); // the buffer's destroy
    c.write_all(&MessageWriter::new(4, 1).finish().unwrap()).unwrap(); // the pool's destroy
    pump_all(&mut s).unwrap();
    delete_ids(&mut sv, &[5, 4]);
    pump_all(&mut s).unwrap();
    assert_eq!((s.shm_pool_count, s.shm_pool_bytes), (1, 4096));
    // A commit with no buffer lets it go.
    c.write_all(&MessageWriter::new(9, 1).u32(0).i32(0).i32(0).finish().unwrap()).unwrap();
    c.write_all(&MessageWriter::new(9, 6).finish().unwrap()).unwrap();
    pump_all(&mut s).unwrap();
    assert_eq!((s.shm_pool_count, s.shm_pool_bytes), (0, 0));
}

/// Surfaces 11, 12 and 14, with 12 a subsurface of 11 (as 13) and, when `nested`, 14 of 12 (as
/// 15), over a session that knows wl_shm, wl_compositor and wl_subcompositor.
fn with_subsurfaces(nested: bool) -> (Session, UnixStream, UnixStream) {
    let (mut s, mut c, sv) = make();
    s.objects.place(3, (protocol::find("wl_shm").unwrap(), 1));
    s.objects.place(8, (protocol::find("wl_compositor").unwrap(), 4));
    s.objects.place(10, (protocol::find("wl_subcompositor").unwrap(), 1));
    let surface = |id: u32| MessageWriter::new(8, 0).u32(id).finish().unwrap(); // create_surface
    let sub = |id: u32, child: u32, parent: u32| MessageWriter::new(10, 1).u32(id).u32(child).u32(parent).finish().unwrap();
    // In id order: the proxy refuses an id that skips one, as libwayland never does.
    for m in [surface(11), surface(12), sub(13, 12, 11), surface(14)] {
        c.write_all(&m).unwrap();
    }
    if nested {
        c.write_all(&sub(15, 14, 12)).unwrap();
    }
    (s, c, sv)
}

/// Each (pool, buffer) made, attached and committed on `surface`, then deleted.
fn commit_pools(s: &mut Session, c: &mut UnixStream, sv: &mut UnixStream, surface: u32, ids: &[(u32, u32)]) {
    let (fd, _) = UnixStream::pair().unwrap();
    for &(pool, buf) in ids {
        send_with_fd(c.as_raw_fd(), &MessageWriter::new(3, 0).u32(pool).i32(4096).finish().unwrap(), fd.as_raw_fd());
        c.write_all(&MessageWriter::new(pool, 0).u32(buf).i32(0).i32(16).i32(16).i32(64).u32(1).finish().unwrap()).unwrap();
        c.write_all(&MessageWriter::new(surface, 1).u32(buf).i32(0).i32(0).finish().unwrap()).unwrap();
        c.write_all(&MessageWriter::new(surface, 6).finish().unwrap()).unwrap();
        c.write_all(&MessageWriter::new(buf, 0).finish().unwrap()).unwrap();
        c.write_all(&MessageWriter::new(pool, 1).finish().unwrap()).unwrap();
    }
    pump_all(s).unwrap();
    for &(pool, buf) in ids {
        delete_ids(sv, &[buf, pool]);
    }
    pump_all(s).unwrap();
}

fn send(s: &mut Session, c: &mut UnixStream, msgs: &[(u32, u16)]) {
    for &(id, opcode) in msgs {
        c.write_all(&MessageWriter::new(id, opcode).finish().unwrap()).unwrap();
    }
    pump_all(s).unwrap();
}

/// A subsurface's commits are cached until its root commits, each buffer with them.
#[test]
fn subsurface_commits_held_until_the_root_commits() {
    let (mut s, mut c, mut sv) = with_subsurfaces(false);
    commit_pools(&mut s, &mut c, &mut sv, 12, &[(4, 5), (6, 7)]);
    assert_eq!((s.shm_pool_count, s.shm_pool_bytes), (2, 8192));
    // The root's commit applies the subsurface's last: the first pool goes.
    c.write_all(&MessageWriter::new(11, 6).finish().unwrap()).unwrap();
    pump_all(&mut s).unwrap();
    assert_eq!((s.shm_pool_count, s.shm_pool_bytes), (1, 4096));
    // With the surface gone, nothing is held.
    c.write_all(&MessageWriter::new(12, 0).finish().unwrap()).unwrap();
    pump_all(&mut s).unwrap();
    delete_ids(&mut sv, &[12]);
    pump_all(&mut s).unwrap();
    assert_eq!((s.shm_pool_count, s.shm_pool_bytes), (0, 0));
}

/// A root's commit applies a subsurface's cache only through parents with caches of their own.
#[test]
fn nested_subsurface_held_until_its_parent_is_applied() {
    let (mut s, mut c, mut sv) = with_subsurfaces(true);
    commit_pools(&mut s, &mut c, &mut sv, 14, &[(4, 5), (6, 7)]);
    assert_eq!((s.shm_pool_count, s.shm_pool_bytes), (2, 8192));
    // 12 has committed nothing, so wlroots applies nothing under it.
    send(&mut s, &mut c, &[(11, 6)]);
    assert_eq!((s.shm_pool_count, s.shm_pool_bytes), (2, 8192));
    send(&mut s, &mut c, &[(12, 6)]);
    assert_eq!((s.shm_pool_count, s.shm_pool_bytes), (2, 8192));
    // Now the root's commit applies 12's cache and, under it, 14's.
    send(&mut s, &mut c, &[(11, 6)]);
    assert_eq!((s.shm_pool_count, s.shm_pool_bytes), (1, 4096));
}

/// A desynchronized subsurface under a synchronized one stays cached through its parents'
/// commits; the end of its role applies the cache.
#[test]
fn desync_subsurface_under_a_synced_one_stays_cached() {
    let (mut s, mut c, mut sv) = with_subsurfaces(true);
    send(&mut s, &mut c, &[(15, 5)]); // set_desync
    commit_pools(&mut s, &mut c, &mut sv, 14, &[(4, 5), (6, 7)]);
    assert_eq!((s.shm_pool_count, s.shm_pool_bytes), (2, 8192));
    send(&mut s, &mut c, &[(12, 6), (11, 6)]);
    assert_eq!((s.shm_pool_count, s.shm_pool_bytes), (2, 8192));
    send(&mut s, &mut c, &[(15, 0)]); // the wl_subsurface's destroy
    assert_eq!((s.shm_pool_count, s.shm_pool_bytes), (1, 4096));
}

#[test]
fn messages_respect_bound_versions() {
    for (interface, request, dir) in [
        ("wl_shm", MessageWriter::new(3, 1).finish().unwrap(), Dir::ClientToServer), // release requires v2
        ("wl_compositor", MessageWriter::new(4, 9).i32(0).i32(0).i32(1).i32(1).finish().unwrap(), Dir::ClientToServer), // surface.damage_buffer requires v4
        ("wl_output", MessageWriter::new(3, 3).i32(2).finish().unwrap(), Dir::ServerToClient), // scale requires v2
    ] {
        let (mut s, mut c, mut sv) = make();
        c.write_all(&get_registry(2)).unwrap();
        sv.write_all(&global(2, 11, interface, 1)).unwrap();
        pump_all(&mut s).unwrap();
        c.write_all(&MessageWriter::new(2, WL_REGISTRY_BIND)
            .u32(11).string(interface).u32(1).u32(3).finish().unwrap()).unwrap();
        if interface == "wl_compositor" {
            c.write_all(&MessageWriter::new(3, 0).u32(4).finish().unwrap()).unwrap();
        }
        pump_all(&mut s).unwrap();
        read_all(&mut c);
        read_all(&mut sv);
        match dir {
            Dir::ClientToServer => c.write_all(&request).unwrap(),
            Dir::ServerToClient => sv.write_all(&request).unwrap(),
        }
        assert!(pump_all(&mut s).is_err(), "accepted a newer message on {interface} v1 ({dir:?})");
        assert!(read_all(&mut c).is_empty());
        assert!(read_all(&mut sv).is_empty());
    }
}

#[test]
fn titles_and_app_ids_rewritten() {
    let (mut s, mut c, mut sv) = with_toplevel();
    c.write_all(&MessageWriter::new(7, 2).string("Notes").finish().unwrap()).unwrap(); // set_title
    c.write_all(&MessageWriter::new(7, 3).string("editor").finish().unwrap()).unwrap(); // set_app_id
    pump_all(&mut s).unwrap();
    let got = String::from_utf8_lossy(&read_all(&mut sv)).to_string();
    assert!(got.contains("[work] Notes"), "{got}");
    assert!(got.contains("kryptik.work.editor"), "{got}");
    assert!(!got.contains("\0Notes\0"), "the bare title must not pass");
    assert_eq!(s.rewritten, 3, "the title, the app_id, and the stamp at creation");
}

/// The stamp goes out at creation; a later set_app_id replaces it, rewritten.
#[test]
fn unnamed_toplevel_is_stamped() {
    let (mut s, mut c, mut sv) = make();
    c.write_all(&get_registry(2)).unwrap();
    sv.write_all(&global(2, 1, "wl_compositor", 6)).unwrap();
    sv.write_all(&global(2, 2, "xdg_wm_base", 6)).unwrap();
    pump_all(&mut s).unwrap();
    c.write_all(&MessageWriter::new(2, WL_REGISTRY_BIND).u32(1).string("wl_compositor").u32(6).u32(3).finish().unwrap()).unwrap();
    c.write_all(&MessageWriter::new(2, WL_REGISTRY_BIND).u32(2).string("xdg_wm_base").u32(6).u32(4).finish().unwrap()).unwrap();
    c.write_all(&MessageWriter::new(3, 0).u32(5).finish().unwrap()).unwrap(); // create_surface -> 5
    c.write_all(&MessageWriter::new(4, 2).u32(6).u32(5).finish().unwrap()).unwrap(); // get_xdg_surface -> 6
    pump_all(&mut s).unwrap();
    let _ = read_all(&mut sv);
    c.write_all(&MessageWriter::new(6, 1).u32(7).finish().unwrap()).unwrap(); // get_toplevel -> 7
    c.write_all(&MessageWriter::new(5, 6).finish().unwrap()).unwrap(); // wl_surface.commit, and no set_app_id ever
    pump_all(&mut s).unwrap();
    let got = read_all(&mut sv);
    let msgs = split_messages(&got);
    assert_eq!(msgs[0].0, (6, 1), "get_toplevel is forwarded first: {msgs:?}");
    assert_eq!(msgs[1].0, (7, 3), "the proxy's set_app_id follows on the new toplevel: {msgs:?}");
    assert_eq!(msgs[2].0, (5, 6), "the commit comes after the identity: {msgs:?}");
    assert!(String::from_utf8_lossy(&msgs[1].1).contains("kryptik.work.app"), "{:?}", msgs[1]);
    assert_eq!(s.rewritten, 1);
    // A name the client sends later is rewritten.
    c.write_all(&MessageWriter::new(7, 3).string("editor").finish().unwrap()).unwrap();
    pump_all(&mut s).unwrap();
    let got = String::from_utf8_lossy(&read_all(&mut sv)).to_string();
    assert!(got.contains("kryptik.work.editor"), "{got}");
    assert_eq!(s.rewritten, 2);
}

/// (object, opcode) and body of each message in a byte stream.
fn split_messages(mut bytes: &[u8]) -> Vec<((u32, u16), Vec<u8>)> {
    let mut out = Vec::new();
    while bytes.len() >= HEADER_LEN {
        let h = Header::parse(bytes).unwrap();
        let size = h.size as usize;
        out.push(((h.object, h.opcode), bytes[HEADER_LEN..size].to_vec()));
        bytes = &bytes[size..];
    }
    out
}

/// Bounded, prefixed, still valid UTF-8, and the session survives it.
#[test]
fn long_multibyte_title_is_forwarded() {
    let (mut s, mut c, mut sv) = with_toplevel();
    let title = "\u{00e9}".repeat(200); // 400 bytes; byte 253 is mid-character
    c.write_all(&MessageWriter::new(7, 2).string(&title).finish().unwrap()).unwrap();
    pump_all(&mut s).unwrap();
    let got = read_all(&mut sv);
    let h = Header::parse(&got).unwrap();
    assert_eq!((h.object, h.opcode), (7, 2));
    let mut r = ArgReader::new(&got[HEADER_LEN..h.size as usize]);
    let t = r.string().unwrap().unwrap();
    assert!(t.starts_with("[work] \u{00e9}"), "{t:?}");
    assert!(t.len() <= policy::MAX_TITLE_BYTES);
    assert!(t.ends_with("..."));
    assert_eq!(s.rewritten, 2, "the title, and the stamp at creation");
    assert!(!s.client.closed && !s.server.closed, "the session is still up");
}

#[test]
fn fragmented_and_malformed_input() {
    let (mut s, mut c, mut sv) = make();
    let m = get_registry(2);
    c.write_all(&m[..3]).unwrap();
    pump_all(&mut s).unwrap();
    assert!(!s.has_object(2), "half a header creates nothing");
    c.write_all(&m[3..]).unwrap();
    pump_all(&mut s).unwrap();
    assert!(s.has_object(2));
    assert_eq!(read_all(&mut sv), m, "the reassembled message is forwarded whole");
    // a message with size below the header
    let bad = Header { object: 2, opcode: 0, size: 4 }.encode();
    c.write_all(&bad).unwrap();
    assert!(matches!(pump_all(&mut s), Err(SessionError::Wire(WireError::BadSize(4)))));
    // unknown object
    let (mut s, mut c, _sv) = make();
    c.write_all(&MessageWriter::new(77, 0).finish().unwrap()).unwrap();
    assert!(matches!(pump_all(&mut s), Err(SessionError::UnknownObject(77))));
    // unknown opcode on a known object
    let (mut s, mut c, _sv) = make();
    c.write_all(&MessageWriter::new(1, 9).finish().unwrap()).unwrap();
    assert!(matches!(pump_all(&mut s), Err(SessionError::UnknownOpcode { .. })));
    // a client creating an id in the server's range
    let (mut s, mut c, _sv) = make();
    c.write_all(&get_registry(0xFF00_0001)).unwrap();
    assert!(matches!(pump_all(&mut s), Err(SessionError::IdOutOfRange { .. })));
}

#[test]
fn batches_small_messages() {
    let (a, b) = UnixStream::pair().unwrap();
    b.set_nonblocking(true).unwrap();
    let mut out = Endpoint::new(a.into_raw_fd());
    for i in 0..100u32 {
        out.queue(&MessageWriter::new(1, 0).u32(i).finish().unwrap(), Vec::new());
    }
    assert_eq!(out.outq.len(), 1, "a hundred 12-byte messages are one batch");
    assert_eq!(out.pending_out, 1200);
    let (p, _q) = UnixStream::pair().unwrap();
    for _ in 0..30 {
        let fd = unsafe { libc::dup(p.as_raw_fd()) };
        out.queue(&MessageWriter::new(1, 0).u32(0).finish().unwrap(), vec![fd]);
    }
    assert!(out.outq.iter().all(|(_, f)| f.len() <= BATCH_FDS));
    assert!(!out.flush().unwrap(), "everything went");
    let (bytes, fds) = recv_with_fds(b.as_raw_fd());
    assert_eq!(bytes.len(), 1200 + 30 * 12);
    assert_eq!(fds.len(), 30);
    for (i, m) in bytes.chunks(12).take(100).enumerate() {
        assert_eq!(u32::from_ne_bytes(m[8..12].try_into().unwrap()), i as u32, "in order");
    }
    for fd in fds {
        unsafe { libc::close(fd) };
    }
    out.close_all();
}

#[test]
fn descriptors_ride_with_their_message() {
    let (mut s, mut c, sv) = with_shm();
    // wl_shm.create_pool(new_id pool, fd, size): send bytes and one fd together
    let (probe_a, probe_b) = UnixStream::pair().unwrap();
    let msg = MessageWriter::new(3, 0).u32(4).i32(4096).finish().unwrap();
    send_with_fd(c.as_raw_fd(), &msg, probe_a.as_raw_fd());
    pump_all(&mut s).unwrap();
    assert!(s.has_object(4), "the pool object is tracked");
    let (bytes, fds) = recv_with_fds(sv.as_raw_fd());
    assert_eq!(bytes, msg);
    assert_eq!(fds.len(), 1, "exactly one descriptor arrived with create_pool");
    // the descriptor is the same open file: write on it, read on probe_b
    let mut f = unsafe { <UnixStream as std::os::unix::io::FromRawFd>::from_raw_fd(fds[0]) };
    f.write_all(b"same file").unwrap();
    let mut probe_b = probe_b;
    probe_b.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 16];
    let n = probe_b.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"same file");
    // An fd sent with wl_shm.release, which takes none, goes with the next create_pool.
    let (extra_a, _extra_b) = UnixStream::pair().unwrap();
    send_with_fd(c.as_raw_fd(), &MessageWriter::new(3, 1).finish().unwrap(), extra_a.as_raw_fd());
    c.write_all(&MessageWriter::new(3, 0).u32(5).i32(8192).finish().unwrap()).unwrap();
    pump_all(&mut s).unwrap();
    let (bytes, fds) = recv_with_fds(sv.as_raw_fd());
    assert_eq!(bytes.len(), 8 + 16, "release (8) then create_pool (16)");
    assert_eq!(fds.len(), 1);
    for fd in fds { unsafe { libc::close(fd) }; }
}

#[test]
fn message_waits_for_descriptor() {
    let (mut s, mut c, mut sv) = with_shm();
    // most of the bytes first, no fd: nothing is forwarded yet
    let msg = MessageWriter::new(3, 0).u32(4).i32(4096).finish().unwrap();
    c.write_all(&msg[..12]).unwrap();
    pump_all(&mut s).unwrap();
    assert!(!s.has_object(4));
    assert!(read_all(&mut sv).is_empty());
    // the rest arrives with the fd (SCM_RIGHTS needs data): now it goes
    let (a, _b) = UnixStream::pair().unwrap();
    send_with_fd(c.as_raw_fd(), &msg[12..], a.as_raw_fd());
    pump_all(&mut s).unwrap();
    assert!(s.has_object(4));
    let (bytes, fds) = recv_with_fds(sv.as_raw_fd());
    assert_eq!(bytes, msg);
    assert_eq!(fds.len(), 1);
    for fd in fds { unsafe { libc::close(fd) }; }
}

#[test]
fn rejected_message_closes_its_descriptors() {
    for body in [
        MessageWriter::new(3, 0).u32(4).finish().unwrap(), // create_pool: missing size
        MessageWriter::new(3, 0).u32(0).i32(4096).finish().unwrap(), // invalid new object id
    ] {
        let (mut s, c, _sv) = make();
        s.objects.place(3, (protocol::find("wl_shm").unwrap(), 2));
        let (a, mut b) = UnixStream::pair().unwrap();
        b.set_nonblocking(true).unwrap();
        send_with_fd(c.as_raw_fd(), &body, a.as_raw_fd());
        drop(a);
        assert!(pump_all(&mut s).is_err());
        s.refuse("malformed request");
        assert_eq!(b.read(&mut [0u8; 1]).unwrap(), 0, "no received copy may keep the peer alive");
    }
}

#[test]
fn inbound_descriptors_bounded() {
    let (mut s, c, _sv) = make();
    let (a, mut b) = UnixStream::pair().unwrap();
    b.set_nonblocking(true).unwrap();
    for _ in 0..policy::MAX_PENDING_FDS {
        send_with_fd(c.as_raw_fd(), b"x", a.as_raw_fd());
        assert_eq!(s.client.read().unwrap(), 1);
    }
    send_with_fd(c.as_raw_fd(), b"x", a.as_raw_fd());
    assert_eq!(s.client.read().unwrap_err().kind(), io::ErrorKind::InvalidData);
    drop(a);
    s.refuse("descriptor limit");
    assert_eq!(b.read(&mut [0u8; 1]).unwrap(), 0, "all accumulated descriptors closed");
}

#[test]
fn truncated_ancillary_data_is_refused() {
    let (mut s, c, _sv) = make();
    let (a, mut b) = UnixStream::pair().unwrap();
    b.set_nonblocking(true).unwrap();
    send_with_fds(c.as_raw_fd(), b"x", &[a.as_raw_fd(); 80]);
    assert_eq!(s.client.read().unwrap_err().kind(), io::ErrorKind::InvalidData);
    drop(a);
    s.refuse("truncated control data");
    assert_eq!(b.read(&mut [0u8; 1]).unwrap(), 0);
}

#[test]
fn outgoing_descriptors_are_bounded() {
    let (mut s, c, _sv) = make();
    s.objects.place(3, (protocol::find("wl_data_offer").unwrap(), 1));
    let (a, mut b) = UnixStream::pair().unwrap();
    b.set_nonblocking(true).unwrap();
    for i in 0..=policy::MAX_PENDING_FDS {
        let msg = MessageWriter::new(3, 1).string("text/plain").finish().unwrap();
        send_with_fd(c.as_raw_fd(), &msg, a.as_raw_fd());
        s.client.read().unwrap();
        let result = s.pump(Dir::ClientToServer); // the compositor's queue is never flushed
        if i < policy::MAX_PENDING_FDS {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(SessionError::TooManyFds)));
        }
    }
    drop(a);
    s.refuse("outgoing descriptor limit");
    assert_eq!(b.read(&mut [0u8; 1]).unwrap(), 0);
}

#[test]
fn input_bounded_awaiting_fd() {
    let (mut s, mut c, _sv) = make();
    s.objects.place(3, (protocol::find("wl_shm").unwrap(), 2));
    c.write_all(&MessageWriter::new(3, 0).u32(4).i32(4096).finish().unwrap()).unwrap();
    pump_all(&mut s).unwrap();
    let mut refused = false;
    for _ in 0..=policy::MAX_PENDING_BYTES / 4096 {
        c.write_all(&[0u8; 4096]).unwrap();
        if let Err(SessionError::Io(e)) = pump_all(&mut s) {
            assert_eq!(e.kind(), io::ErrorKind::InvalidData);
            refused = true;
            break;
        }
    }
    assert!(refused, "a request waiting for an fd must still have a byte limit");
    assert!(!s.has_object(4));
}

#[test]
fn refusal_closes_both_sides() {
    let (mut s, mut c, sv) = make();
    c.write_all(&get_registry(2)).unwrap();
    pump_all(&mut s).unwrap();
    s.refuse("test refusal");
    let got = read_all(&mut c);
    let text = String::from_utf8_lossy(&got).to_string();
    assert!(text.contains("test refusal"), "the client is told why");
    assert!(s.client.closed && s.server.closed);
    drop(sv);
    // peer EOF is reported as such
    let (mut s, c, _sv) = make();
    drop(c);
    assert_eq!(s.client.read().unwrap(), 0);
}

#[test]
fn object_bound_is_enforced() {
    let (mut s, mut c, mut sv) = make();
    c.write_all(&get_registry(2)).unwrap();
    sv.write_all(&global(2, 1, "wl_compositor", 6)).unwrap();
    pump_all(&mut s).unwrap();
    c.write_all(&MessageWriter::new(2, WL_REGISTRY_BIND).u32(1).string("wl_compositor").u32(6).u32(3).finish().unwrap()).unwrap();
    pump_all(&mut s).unwrap();
    let mut err = None;
    for i in 0..(policy::MAX_OBJECTS as u32 + 5) {
        c.write_all(&MessageWriter::new(3, 0).u32(4 + i).finish().unwrap()).unwrap();
        if let Err(e) = pump_all(&mut s) {
            err = Some(e);
            break;
        }
        let _ = read_all(&mut sv);
    }
    assert!(matches!(err, Some(SessionError::TooManyObjects)), "{err:?}");
}

// --- helpers --------------------------------------------------------------
fn send_with_fd(sock: RawFd, bytes: &[u8], fd: RawFd) {
    send_with_fds(sock, bytes, &[fd]);
}
fn send_with_fds(sock: RawFd, bytes: &[u8], fds: &[RawFd]) {
    assert!(!bytes.is_empty(), "SCM_RIGHTS needs at least one byte of data");
    let mut iov = libc::iovec { iov_base: bytes.as_ptr() as *mut libc::c_void, iov_len: bytes.len() };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    let mut cbuf = [0usize; 128];
    let fd_bytes = std::mem::size_of_val(fds) as u32;
    let space = unsafe { libc::CMSG_SPACE(fd_bytes) } as usize;
    assert!(space <= std::mem::size_of_val(&cbuf));
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(fd_bytes) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(c) as *mut RawFd, fds.len());
        let n = libc::sendmsg(sock, &msg, 0);
        assert!(n >= 0, "sendmsg: {}", io::Error::last_os_error());
    }
}
fn recv_with_fds(sock: RawFd) -> (Vec<u8>, Vec<RawFd>) {
    let mut ep = Endpoint::new(sock);
    loop {
        match ep.read() {
            Ok(usize::MAX) | Ok(0) => break,
            Ok(_) => continue,
            Err(e) => panic!("{e}"),
        }
    }
    let fds: Vec<RawFd> = ep.in_fds.drain(..).collect();
    let bytes = ep.take_inbuf();
    std::mem::forget(ep); // the test owns `sock`; do not close it here
    (bytes, fds)
}

/// Damaged openings sent in random fragments: no panic, and only whole messages forwarded.
#[test]
fn compositor_gets_only_whole_messages() {
    use crate::protocol::tests::Rng;
    let mut rng = Rng(0x5345_5353_494F_4E31);
    let bind = MessageWriter::new(2, 0).u32(1).string("wl_compositor").u32(4).u32(3).finish().unwrap();
    let conversation: Vec<u8> = [
        get_registry(2),
        bind,
        MessageWriter::new(3, 0).u32(4).finish().unwrap(), // wl_compositor.create_surface
        MessageWriter::new(4, 6).finish().unwrap(),        // wl_surface.commit
        MessageWriter::new(4, 0).finish().unwrap(),        // wl_surface.destroy
    ]
    .concat();
    let (mut refused, mut through) = (0u32, 0u32);
    for round in 0..400 {
        let (mut s, mut c, mut sv) = make();
        let mut bytes = conversation.clone();
        if round > 0 {
            for _ in 0..1 + rng.below(3) {
                let at = rng.below(bytes.len());
                match rng.below(4) {
                    0 => bytes[at] ^= 1 << rng.below(8),
                    1 => bytes.truncate(at.max(1)),
                    2 => bytes.insert(at, rng.next() as u8),
                    _ => { let w = (at / 4) * 4; if w + 4 <= bytes.len() { bytes[w..w + 4].copy_from_slice(&[0u32, 4, 8, 0xffff_ffff, 0xfffc_0000][rng.below(5)].to_ne_bytes()); } }
                }
            }
        }
        // Once get_registry has crossed, the compositor advertises the global to bind.
        let mut advertised = false;
        let mut outcome = Ok(());
        let mut rest: &[u8] = &bytes;
        while !rest.is_empty() && outcome.is_ok() {
            let n = (1 + rng.below(24)).min(rest.len());
            c.write_all(&rest[..n]).unwrap();
            rest = &rest[n..];
            outcome = pump_all(&mut s);
            if outcome.is_ok() && !advertised && s.has_object(2) {
                sv.write_all(&global(2, 1, "wl_compositor", 4)).unwrap();
                advertised = true;
                outcome = pump_all(&mut s);
            }
        }
        if outcome.is_ok() { through += 1 } else { refused += 1 }
        // Everything the compositor was given, refused session or not.
        let mut got: &[u8] = &read_all(&mut sv);
        while !got.is_empty() {
            let h = Header::parse(got).unwrap_or_else(|e| panic!("round {round}: the compositor was sent a bad header: {e}"));
            assert!(h.size as usize <= got.len(), "round {round}: the compositor was sent {} bytes of a {}-byte message", got.len(), h.size);
            got = &got[h.size as usize..];
        }
        if round == 0 {
            assert!(outcome.is_ok(), "the undamaged conversation was refused: {:?}", outcome.err().map(|e| e.to_string()));
            assert!(s.has_object(2) && s.has_object(3), "the undamaged conversation did not bind the compositor");
        }
        s.client.close_all();
        s.server.close_all();
    }
    assert!(refused > 50 && through > 5, "the generator reached one side only: {refused} refused, {through} through");
}
