# Resource limits, supervision, crash cleanup, ephemeral zones

Status: implemented (`cgroup.rs`, the ephemeral branch in `rootfs.rs`,
`storage.size` in `zone.rs`, `kryptikd gc` in `main.rs`). Depends on the
[privileged launch contract](privileged-launch.md): cgroup ownership needs a
root launcher.

## Starting point

- Process tree `kryptikd -> intermediate -> zone pid 1`, each link with
  `PR_SET_PDEATHSIG(SIGKILL)`; signals forwarded down; SIGKILL of pid 1 after
  5 s; pid-namespace collapse kills everything when pid 1 dies. The two
  orphan checks (SIGKILL the launcher, SIGKILL pid 1, then look for
  surviving zone processes) are the baseline regression for everything
  below and belong in `compartments/tests/launcher.sh`.
- There was no cgroup, and `[limits]` was refused without
  `KRYPTIK_EXPERIMENTAL=1`.
- `storage.mode = "ephemeral"` was a persistent directory, refused without
  the override.

## Cgroup ownership and supervision

**Ownership rule: the host owns the cgroup; the zone can see that it is
confined and cannot change it.**

- kryptikd (root) creates `/sys/fs/cgroup/kryptik/` once, writes
  `+memory +pids` to its parent's `cgroup.subtree_control`, and for each
  launch creates `/sys/fs/cgroup/kryptik/<zone>.<pid>/`, where `<pid>` is
  the launcher's pid (two launches of the same zone may overlap, and sharing
  one cgroup would put both under one limit, which is a cross-zone channel).
  Files stay `root:root 0644`; nothing is chowned to the zone identity.
  Delegation to the zone is explicitly *not* wanted: a zone that owns its
  cgroup can raise its own limits.
- Order: create cgroup -> write `memory.max`, `memory.swap.max = 0`,
  `pids.max`, `memory.oom.group = 1` -> write the intermediate's pid to
  `cgroup.procs` -> intermediate does `unshare(... | CLONE_NEWCGROUP)`.
  Because the move precedes the cgroup-namespace unshare, the zone's cgroup
  namespace is rooted at its own cgroup: `/proc/self/cgroup` inside reads
  `0::/`. `/sys/fs/cgroup` is **not mounted** in the zone tree; nothing in
  the zone needs it and a mounted cgroup2 in a userns is writable surface.
- `memory.oom.group = 1`: an OOM kills the whole zone, never one process of
  it. A zone that survives its own OOM half-dead is a debugging nightmare
  and a policy leak (the survivor keeps the zone's sockets).
- Refuse, do not degrade: if `cgroup.controllers` lacks `memory` or `pids`,
  or a write returns an error, a zone with `[limits]` does not start.
  On the unprivileged developer path the rule stays as it was (override
  required, limits reported as not applied).
- Teardown, normal: after `waitpid` on the intermediate returns, write `1`
  to `cgroup.kill` (Linux 5.14+), wait until `cgroup.procs` is empty
  (bounded, 2 s), `rmdir`. `cgroup.kill` is the backstop for a process that
  escaped the pid-namespace collapse. There should be none, and if the wait
  times out kryptikd says so and leaves the directory for the GC.
- Teardown, crash: every `kryptikd run` sweeps `/sys/fs/cgroup/kryptik/*`
  and removes empty leaves older than five seconds (the age keeps it from
  deleting a concurrent launch's cgroup in the instant before its zone is
  moved in). `kryptikd gc` removes every empty leaf regardless of age, since
  `rmdir` on a populated cgroup fails with `EBUSY` anyway, and reclaims
  stale [registry](zone-registry.md) entries, whose reclaim writes
  `cgroup.kill` to the recorded cgroup before removing it. Mounts need no
  GC: they live in the zone's private mount namespace and vanish with it.
  Verify that rather than assume it: the crash test below reads the host's
  `mountinfo`.

**Invariants**

- Every process of a running zone is in `kryptik/<zone>.<pid>` (host-side
  `/proc/<pid>/cgroup` of zone pid 1 and of a grandchild).
- The zone cannot see or write its cgroup: `/sys/fs/cgroup` absent inside;
  `/proc/self/cgroup` is `0::/`.
- The memory limit holds: allocation beyond `memory.max` ends the zone with
  SIGKILL (exit 137 from `kryptikd run`); the host is unaffected.
- `pids.max` holds: a fork loop stops at the limit with `EAGAIN`.
- After exit, crash (`kill -9` kryptikd), or pid 1 crash, no zone process
  exists, no `kryptik/*` cgroup with processes exists, and the host mount
  table has no entry under the zone's data path.
- Relaunch immediately after any of those succeeds.

**Tests (VM, root; positive controls in the same row)**

| check | expected |
|---|---|
| `memory_max = "64M"`; zone runs `head -c 200M /dev/zero \| tail` | exit 137; with `memory_max = "512M"` exit 0 |
| `pids_max = 32`; `for i in $(seq 100); do sleep 30 & done; wait` | fewer than 33 processes ever exist (host counts `cgroup.procs`); with `pids_max = 200`, 100 exist |
| `kill -9` kryptikd while zone sleeps | within 1 s: no zone process; `rmdir` succeeds on the cgroup or `kryptikd gc` removes it; host `mountinfo` has no line containing the data path |
| a child of zone pid 1 dies of SIGSEGV (pid 1 ignores its own signals, so: `sh -c 'sleep 1 & kill -SEGV $!; wait'`), then pid 1 exits | exit code propagated; cgroup removed |
| zone pid 1 killed from the host with SIGKILL | zone gone, exit 137, cgroup removed |
| `kryptikd run` twice back-to-back after the `kill -9` test | second launch works |
| inside zone: `test -d /sys/fs/cgroup` and `cat /proc/self/cgroup` | absent; `0::/` |
| dev host, unprivileged, `[limits]` without override | refused; with override, note printed, no cgroup |

## Ephemeral zones

**Decision: a per-launch tmpfs at the zone's home, mounted by kryptikd inside
the zone's private mount namespace. Nothing is written to the persistent
tree.** Swap is the honest caveat (below).

- In `pivot_into`, for `storage.mode = "ephemeral"`: instead of binding the
  data directory at `/home/<zone>`, mount `tmpfs` there with
  `mode=0700,uid=0,gid=0,size=<storage.size>` (the zone's root is uid 0 in
  its namespace, which is uid N on the host) and `nosuid,nodev`. The mount
  is in the zone's mount namespace only; when pid 1 dies the namespace is
  released and the tmpfs is freed. There is no unmount step to forget and no
  teardown path a crash can skip, which is why the guarantee survives
  `kill -9`. The persistent directory for an ephemeral zone must be
  **empty**; if it contains anything, the launch is refused:
  `ephemeral zone "untrusted" has persistent data in <dir> from an earlier
  run; move or delete it`. This is what turns "labelled ephemeral" into
  "cannot have been persistent".
- The key `storage.size` (validated with `is_size`) is required for
  ephemeral and refused for the other modes. There is no default: a bounded
  tmpfs is part of the guarantee, because an unbounded one lets the zone
  consume host memory by writing files, and those pages outlive the writer.
  A `storage.size` larger than `limits.memory_max` is refused as well: the
  tmpfs is charged to the zone's memory cgroup, so it could never reach its
  stated size before the zone was OOM-killed.
- `/tmp` is already a tmpfs per zone; `/dev/shm` likewise.
- **Swap.** tmpfs pages can be swapped. Until Kryptik ships with encrypted
  swap or none (a kernel and base-image decision), `explain` and the launch
  note say: "ephemeral zone data never touches the zone's persistent
  directory; it can reach swap". `memory.swap.max = 0` stops the zone's
  *process* pages from swapping but not tmpfs pages after the process exits.
  Do not claim more.

**Invariants**

- After a normal exit, the persistent directory is empty and the next
  launch sees an empty `$HOME`.
- After `kill -9` of kryptikd, the same.
- During a run, the host mount table has no tmpfs at the data path (it is
  in the zone's namespace, not the host's) and the persistent directory is
  empty from the host side.
- A non-empty persistent directory for an ephemeral zone is refused.
- Writing more than `storage.size` fails with `ENOSPC` inside the zone.
- The zone can still write, exec and rename in `$HOME` (positive control).

**Tests**: one row for each invariant above, plus: `storage.size` missing or
`"0"` is a zone-file error; `storage.mode = "encrypted"` with `storage.size`
is refused. Run in the VM and on the host (tmpfs in a userns needs no root).

## Files

`cgroup.rs` (creation, limits, teardown, the sweep; no dependency beyond
`libc` and `std::fs`), `spawn.rs` (cgroup setup in the parent before fork;
teardown), `rootfs.rs` (ephemeral branch in `pivot_into`, empty-directory
check), `zone.rs` (`storage.size`), `main.rs` (`gc`), the cgroup and
ephemeral checks in `compartments/tests/launcher.sh`, `explain` text.
