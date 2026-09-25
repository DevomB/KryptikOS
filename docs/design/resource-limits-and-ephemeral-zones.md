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

- kryptikd creates `/sys/fs/cgroup/kryptik/` with `memory` and `pids`
  enabled. A zone with `[limits]` gets one leaf per launch,
  `kryptik/<zone>.<launcher pid>`, so two overlapping launches of a zone never
  share a limit. The files stay `root:root`; a zone that owned its cgroup
  could raise its own limits.
- The leaf gets `memory.max` and `pids.max` (`max` when unset),
  `memory.oom.group = 1` (an OOM kills the whole zone, never one process
  while the rest keep its files and sockets) and `memory.swap.max = 0`. The
  intermediate is moved in before it unshares with `CLONE_NEWCGROUP`, so the
  zone's cgroup namespace is rooted at its leaf and `/proc/self/cgroup` reads
  `0::/`. `/sys/fs/cgroup` is not mounted in the zone: nothing there needs it,
  and a cgroup2 mount in a user namespace is writable surface.
- Refuse, do not degrade: without the `memory` or `pids` controller, or if a
  write fails, a zone with `[limits]` does not start. `KRYPTIK_EXPERIMENTAL=1`
  runs it unlimited on a developer host and says so; a root launch on the
  target kernel ignores that variable.
- Teardown writes `cgroup.kill`, the backstop for anything that escaped the
  pid namespace, and retries `rmdir` for 1 s; a leaf that stays is reported
  and left for `gc`. Every launch removes empty leaves whose launcher pid is
  gone, and a leaf with no pid in its name after 5 s; the pid decides rather
  than the age, because kernfs dates a cgroup directory from its first `stat`.
  `kryptikd gc` removes every empty leaf and reclaims stale
  [registry](zone-registry.md) entries. Mounts need no cleanup: they die with
  the zone's mount namespace.

Invariants: every process of a running zone is in its leaf; inside, there is
no `/sys/fs/cgroup` and `/proc/self/cgroup` is `0::/`; allocating past
`memory.max` ends the zone with `SIGKILL` (exit 137), and a fork loop stops
at `pids.max` with `EAGAIN`; after a normal exit, a `kill -9` of kryptikd or a
crash of pid 1, no zone process, no populated leaf and no host mount under
the zone's data path remain, and an immediate relaunch works.

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

Invariants: after a normal exit or a `kill -9` of kryptikd, the persistent
directory is empty and the next launch sees an empty `$HOME`; the tmpfs is
never in the host mount table; writing past `storage.size` fails with
`ENOSPC`; the zone can still write, exec and rename in `$HOME`.

## Tests

The cgroup and ephemeral sections of `compartments/tests/launcher.sh` check
each invariant above with a positive control, unprivileged where cgroups are
delegated and as root on the installed system (the zones suite).
`build/guest-tests/zones-check.sh` repeats the pid limit and the tmpfs bound
there; `cgroup.rs` and `zone.rs` unit-test the sweep, the limits and
`storage.size`.

## Files

`cgroup.rs`, `spawn.rs` (cgroup setup before the intermediate unshares;
teardown), `rootfs.rs` (the tmpfs, the empty-directory check), `zone.rs`
(`storage.size`), `main.rs` (`gc`).
