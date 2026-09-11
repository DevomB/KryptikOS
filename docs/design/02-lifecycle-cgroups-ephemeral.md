# Design 02 — Resource limits, supervision, crash cleanup, ephemeral zones (M1, M2)

Status: security design for Opus. Depends on Design 01 (root launch).
Reviewed against the integrated launch path at `2e67a52`.

## What exists

- Process tree `kryptikd -> intermediate -> zone pid 1`, each link with
  `PR_SET_PDEATHSIG(SIGKILL)`; signals forwarded down; SIGKILL of pid 1 after
  5 s; pid-namespace collapse kills everything when pid 1 dies. Verified on
  the host (`fixed-checks.sh`); **not yet in `launcher.sh`** — add the two
  orphan checks from `FINAL_REVIEW.md` §4 first, they are the baseline M1
  regression.
- No cgroup. `[limits]` is refused without `KRYPTIK_EXPERIMENTAL=1`.
- `storage.mode = "ephemeral"` is a persistent directory. Refused without
  the override.

## M1 — cgroup ownership and supervision

**Ownership rule: the host owns the cgroup; the zone can see that it is
confined and cannot change it.**

- kryptikd (root) creates `/sys/fs/cgroup/kryptik/` once, writes
  `+memory +pids` to its parent's `cgroup.subtree_control`, and for each
  launch creates `/sys/fs/cgroup/kryptik/<zone>.<runid>/` where `runid` is
  the intermediate's pid. Files stay `root:root 0644`; nothing is chowned to
  the zone identity. (Delegation to the zone is explicitly *not* wanted:
  a zone that owns its cgroup can raise its own limits.)
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
  or the write returns an error, a zone with `[limits]` does not start.
  On the unprivileged developer path the gate stays as it is (override
  required, limits reported as not applied).
- Teardown, normal: after `waitpid` on the intermediate returns, write `1`
  to `cgroup.kill` (Linux 5.14+), wait until `cgroup.procs` is empty
  (bounded, 2 s), `rmdir`. `cgroup.kill` is the backstop for a process that
  escaped the pid namespace collapse — there should be none, and if the
  wait times out kryptikd says so and leaves the directory for the GC.
- Teardown, crash: every `kryptikd run` and a new `kryptikd gc` first walk
  `/sys/fs/cgroup/kryptik/*`, and for each directory whose `cgroup.procs`
  is empty `rmdir` it. A non-empty one whose `runid` pid no longer exists
  gets `cgroup.kill` then `rmdir`. Mounts need no GC: they live in the
  zone's private mount namespace and vanish with it (verify, do not assume:
  L3 below reads the host's `mountinfo`).

**Invariants**

- I1 Every process of a running zone is in `kryptik/<zone>.<runid>` (host-side
  `/proc/<pid>/cgroup` of zone pid 1 and of a grandchild).
- I2 The zone cannot see or write its cgroup: `/sys/fs/cgroup` absent inside;
  `/proc/self/cgroup` is `0::/`.
- I3 The limits hold: memory allocation beyond `memory.max` ends the zone
  with SIGKILL (exit 137 from `kryptikd run`); the host is unaffected.
- I4 `pids.max` holds: a fork loop stops at the limit with `EAGAIN`.
- I5 After exit, crash (`kill -9` kryptikd), or pid 1 crash, no zone process
  exists, no `kryptik/*` cgroup with processes exists, and the host mount
  table has no entry under the zone's data path.
- I6 Relaunch immediately after any of I5 succeeds.

**Tests (VM, root; positive controls in the same row)**

| id | check | expected |
|---|---|---|
| L1 | `memory_max = "64M"`; zone runs `head -c 200M /dev/zero \| tail` | exit 137; with `memory_max = "512M"` exit 0 |
| L2 | `pids_max = 32`; `for i in $(seq 100); do sleep 30 & done; wait` | fewer than 33 processes ever exist (host counts `cgroup.procs`); with `pids_max = 200`, 100 exist |
| L3 | `kill -9` kryptikd while zone sleeps | within 1 s: no zone process; `rmdir` succeeds on the cgroup or `kryptikd gc` removes it; host `mountinfo` has no line containing the data path |
| L4 | zone pid 1 is `sh -c 'kill -SEGV $$'`… pid 1 ignores its own signals, so use a child: `sh -c 'sleep 1 & kill -SEGV $!; wait'` then exit | exit code propagated; cgroup removed |
| L5 | zone pid 1 killed from the host with SIGKILL | zone gone, exit 137, cgroup removed |
| L6 | `kryptikd run` twice back-to-back after L3 | second launch works |
| L7 | inside zone: `test -d /sys/fs/cgroup` and `cat /proc/self/cgroup` | absent; `0::/` |
| L8 | dev host, unprivileged, `[limits]` without override | refused (existing); with override, note printed, no cgroup |

## M2 — real ephemeral zones

**Decision: a per-launch tmpfs at the zone's home, mounted by kryptikd inside
the zone's private mount namespace. Nothing is written to the persistent
tree.** Swap is the honest caveat (below).

- In `pivot_into`, for `storage.mode = "ephemeral"`: instead of binding the
  data directory at `/home/<zone>`, mount `tmpfs` there with
  `mode=0700,uid=0,gid=0,size=<storage.size>` (the zone's root is uid 0 in
  its namespace, which is uid N on the host) and `nosuid,nodev`. The mount
  is in the zone's mount namespace only; when pid 1 dies the namespace is
  released and the tmpfs is freed. The `--rootfs` base directory for an
  ephemeral zone must be **empty**; if it contains anything, refuse:
  `ephemeral zone "untrusted" has persistent data in <dir> from an earlier
  build; move or delete it`. This is what turns "labelled ephemeral" into
  "cannot have been persistent".
- New key `storage.size` (validated with `is_size`, required for
  ephemeral, refused for encrypted). Default none — a bounded tmpfs is
  part of the guarantee (memory limits in M1 do not count tmpfs pages
  against the zone once the writer exits).
- `/tmp` is already a tmpfs per zone; `/dev/shm` likewise.
- **Swap.** tmpfs pages can be swapped. Until Kryptik ships with encrypted or
  no swap (a kernel/base decision for the build tab), `explain` and the
  handoff say: "ephemeral zone data never touches the zone's persistent
  directory; it can reach swap". `memory.swap.max = 0` in M1 stops the
  zone's *process* pages from swapping but not tmpfs pages after the
  process exits. Do not claim more.

**Invariants**

- E1 After a normal exit, the persistent directory is empty and the next
  launch sees an empty `$HOME`.
- E2 After `kill -9` of kryptikd, the same.
- E3 During a run, the host mount table has no tmpfs at the data path (it is
  in the zone's namespace, not the host's) and the persistent directory is
  empty from the host side.
- E4 A non-empty persistent directory for an ephemeral zone is refused.
- E5 Writing more than `storage.size` fails with `ENOSPC` inside the zone.
- E6 The zone can still write, exec and rename in `$HOME` (positive control).

**Tests**: E1–E6 one row each, plus: E7 `storage.size` missing or `"0"` is a
zone-file error; E8 `storage.mode = "encrypted"` with `storage.size` is
refused. Run in the VM and on the host (tmpfs in a userns needs no root).

## Files

`spawn.rs` (cgroup setup in the parent before fork; teardown; `gc`),
`rootfs.rs` (ephemeral branch in `pivot_into`, empty-dir check), `zone.rs`
(`storage.size`), `main.rs` (`gc`), `launcher.sh` groups L and E,
`explain` text. Keep the cgroup code in a new `cgroup.rs` with no dependency
beyond `libc` and `std::fs`.
