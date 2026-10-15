# Resource limits and ephemeral zones

Host-owned cgroups need a root launcher
([privileged launch](privileged-launch.md)).

## Supervision

The process tree is `kryptikd run` -> intermediate -> zone pid 1, each link
armed with `PR_SET_PDEATHSIG(SIGKILL)`. Signals are forwarded down, pid 1 gets
`SIGKILL` 5 s after a forwarded signal, and when pid 1 dies the pid
namespace takes every other zone process with it.

## Cgroups

The host owns the cgroup: the zone can see that it is confined and cannot
change it.

- kryptikd creates `/sys/fs/cgroup/kryptik/` with `memory`, `pids`, `cpu`
  and `io` enabled. A zone with `[limits]` gets one leaf per launch,
  `kryptik/<zone>.<launcher pid>`, so two overlapping launches of a zone never
  share a limit. The files stay `root:root`; a zone that owned its cgroup
  could raise its own limits.
- The leaf gets `memory.max`, `pids.max` and `cpu.max` (`max` when unset),
  `memory.oom.group = 1` (an OOM kills the whole zone, never one process
  while the rest keep its files and sockets) and `memory.swap.max = 0`.
  `cpu_max` is a percentage of one CPU (`"200%"` is two CPUs' worth of time)
  written as a quota per 100 ms period. The shipped `untrusted` has `"200%"`
  and `net` `"100%"`: the net zone parses what the network sends, and a flaw
  there must not take the machine. `io_max` is bytes per second each
  way, written to `io.max` for the zone's volume mapping and for the devices
  under it, so the bytes count wherever the encrypted writes land. A
  partition among them counts as its disk, the only thing `io.max` takes.
  Only an encrypted zone may set `io_max`, since it bounds nothing else. The
  intermediate is moved in before it unshares with `CLONE_NEWCGROUP`, so the
  zone's cgroup namespace is rooted at its leaf and `/proc/self/cgroup` reads
  `0::/`. `/sys/fs/cgroup` is not mounted in the zone: nothing there needs
  it, and a cgroup2 mount in a user namespace is writable surface.
- Refuse, do not degrade: without one of the four controllers, or if a
  write fails, a zone with `[limits]` does not start. `KRYPTIK_EXPERIMENTAL=1`
  runs it unlimited on a developer host and says so; a root launch on the
  target kernel ignores that variable.
- Teardown writes `cgroup.kill`, the backstop for anything that escaped the
  pid namespace, and retries `rmdir` for 1 s; a leaf that stays is reported
  and left for `gc`. Every launch removes empty leaves whose launcher pid is
  gone, and a leaf with no pid in its name after 5 s. The pid decides, not
  the age, because kernfs dates a cgroup directory from its first `stat`.
  `kryptikd gc` removes every empty leaf and reclaims stale
  [registry](zone-registry.md) entries. Mounts need no cleanup: they die with
  the zone's mount namespace.

Invariants:

- every process of a running zone is in its leaf;
- inside, there is no `/sys/fs/cgroup` and `/proc/self/cgroup` is `0::/`;
- allocating past `memory.max` ends the zone with `SIGKILL` (exit 137), and a
  fork loop stops at `pids.max` with `EAGAIN`;
- after a normal exit, a `kill -9` of kryptikd or a crash of pid 1, no zone
  process, no populated leaf and no host mount under the zone's data path
  remain, and an immediate relaunch works.

## Ephemeral zones

For `storage.mode = "ephemeral"`, kryptikd mounts a tmpfs at the zone's home
inside the zone's own mount namespace (`mode=0700,uid=0,gid=0,size=<storage.size>`,
`nosuid,nodev`; uid 0 is the zone's root). Nothing reaches the persistent
tree. The kernel frees the tmpfs with the namespace when pid 1 dies, so there
is no unmount step for a crash to skip.

- The zone's persistent directory must be empty, or the launch is refused
  (`ephemeral zone "untrusted" has persistent data in <dir> from an earlier
  run; move or delete it`); an ephemeral zone cannot have been persistent.
- `storage.size` is required here and refused for other modes: an unbounded
  tmpfs would let a zone fill host memory with files that outlive the writer.
  A size above `limits.memory_max` is refused too, since the tmpfs is charged
  to the zone's memory cgroup and could never fill.
- tmpfs pages can reach swap, and `memory.swap.max = 0` does not cover pages
  whose writer has exited. `kryptikd explain` and the launch note say so:
  this is not secure erasure.

Invariants:

- after a normal exit or a `kill -9` of kryptikd, the persistent directory is
  empty and the next launch sees an empty `$HOME`;
- the tmpfs is never in the host mount table;
- writing past `storage.size` fails with `ENOSPC`;
- the zone can still write, exec and rename in `$HOME`.

## Tests

The cgroup and ephemeral sections of `compartments/tests/launcher.sh` check
each of these invariants with a positive control, unprivileged where cgroups
are delegated and as root on the installed system (the zones suite).
`build/guest-tests/zones-check.sh` repeats the pid limit and the tmpfs bound
there; `cgroup.rs` and `zone.rs` unit-test the sweep, the limits and
`storage.size`.

Whether a zone's Wayland shared memory is charged to its cgroup is not
confirmed; it takes a measurement on the installed image. Record
`memory.current` and `memory.stat` for the zone's and dwl's cgroups, then run
`wlprobe charge` through `kryptik-launch` in that zone, which commits one
unwritten 4 MiB buffer for ten seconds. Confirm the window was rendered and
compare both cgroups while the buffer is held; if dwl's cgroup is an ancestor
of the zone's, subtract the zone's change. A rise outside the zone with no
matching charge to the zone would mean a zone can make dwl hold memory
outside the zone's limit. The proxy's pool limits apply either way, and a
pool stays charged while the compositor may still hold it: until it and its
buffers are deleted and no surface shows one of them, counting each buffer a
synchronized subsurface committed until wlroots applies that subsurface's
cache.

## Wayland shared memory

A zone's windows reach dwl as shared memory: a client hands dwl a descriptor
(`wl_shm.create_pool`), which dwl maps and draws from. The proxy bounds what
a zone hands over (`compositor/wlproxy/src/policy.rs`):

| Bound | Per connection | Per zone | What it holds |
| --- | --- | --- | --- |
| Pools | 128 | 256 | dwl's mappings, one a pool, far below `vm.max_map_count`, past which dwl's own mappings fail |
| Bytes in pools | 1 GiB | 1 GiB | what dwl maps for a zone at one time, at most 128 MiB a pool (a 6K frame) |
| Windows | 32 | 64 | how many windows a zone puts on the screen |

Passing one ends the client's connection, as Wayland answers a pool or a
window it will not make only with a protocol error. Firefox draws all its
windows over one connection, so a breach closes every one of them at once.

**What a browser needs.** Firefox renders each window into pools of its own:
the buffer on screen, the one it draws and up to three spare
(`widget/gtk/WindowSurfaceWaylandMultiBuffer.cpp`), and GTK holds one or two
for the window itself. At 3840×2160 a frame is 33 MB, so a window takes 100
to 230 MB. Two windows on two 4K heads, developer tools and a
picture-in-picture window come to about 0.7 GB in about 30 pools. The bounds
before these, 128 MiB a connection and 256 MiB a zone, ended Firefox with one
4K window open, and a ninth window under the earlier limit of 8.

**What the zone pays for, and what dwl does.** A page the zone writes is
charged to the zone's cgroup and held by its `memory_max`. A page dwl reads
before the zone has written it is allocated by dwl's fault and charged to
dwl. The byte bounds limit that while the pools live: a zone can make dwl
hold at most 1 GiB this way at one time. They do not limit it after. A zone
that keeps its own descriptor once a pool is gone keeps the pages dwl
faulted, still charged to dwl, and can do it again with a new pool, a
screen's worth of pages a frame. No bound on live pools closes that, at any
size; freeing the pages does.

**Freeing the pages.** The proxy keeps its own copy of each pool's
descriptor and punches the pool's range (`fallocate` with
`FALLOC_FL_PUNCH_HOLE`) once the pool and its buffers are gone and no surface
shows one, which frees what dwl faulted with the rest. It refuses a pool it
could not punch: one not open for writing, one sealed against writes, a file
that is not shared memory; and it seals each pool it takes against a later
write seal (`F_SEAL_SEAL`). The pools of a connection that ended are punched a
second later, once dwl has read the hang-up, and count against the zone until
then. What dwl holds for a zone is then bounded by the per-zone bound. A page
a zone splices into a pipe outlives the punch while the pipe holds it, which
the zone's descriptors and pipe sizes bound. A `memory.max` on the session's
cgroup, not set yet, would contain the rest. Checking at a commit that a
buffer's pages are resident is not enough, as the zone can punch them itself
between the check and dwl's read. The measurement under Tests confirms the
charge on the installed kernel.

## Files

`cgroup.rs`, `spawn.rs` (cgroup setup before the intermediate unshares;
teardown), `rootfs.rs` (the tmpfs, the empty-directory check), `zone.rs`
(`storage.size`), `main.rs` (`gc`).
