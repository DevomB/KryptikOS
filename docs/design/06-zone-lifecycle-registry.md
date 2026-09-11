# Design 06 — Persistent zone lifecycle: registry, `stop`, concurrency (L-1)

Status: security design for Opus. Depends on M1 (cgroups, landed at
`db00cba`) and the supervision path (`1e807dc`). Blocks M3 (a routed zone
needs a *running* `net` zone to attach to) and M4 (crash recovery closes
volumes of zones that are not running).

Answers the three questions in `security/REQUEST.md` R-6 first, then the
rest of the design.

## The three decisions

**1. Who owns the registry, with what mode.** `/run/kryptik/zones/` is
created by kryptikd, `root:root 0700`, on a tmpfs (`/run`). Every entry
`/run/kryptik/zones/<name>/` is `0700 root:root`. Only the **parent**
`kryptikd run` process writes it; the intermediate and the zone never do.
Nothing under `/run/kryptik` is visible inside any zone (it is not in the
scaffold); M5 later bind-mounts *one socket file* out of an entry into a
zone, never the directory. On the unprivileged developer path the registry
lives at `$XDG_RUNTIME_DIR/kryptik/zones/` (mode 0700, owner = the
launching uid) so the same code and tests run there; `explain` prints which.

**2. What a command does with an entry whose pid is gone.** It is *stale*,
and staleness is decided by a lock, not by the pid: the launcher holds an
`flock(LOCK_EX)` on `<entry>/lock` for its whole life; a live entry is one
whose lock cannot be taken (`LOCK_EX|LOCK_NB` → `EWOULDBLOCK`). An entry
whose lock *can* be taken has no launcher, whatever its pid file says.
Then:
- `run <name>` reclaims it (below) and starts.
- `stop <name>` reclaims it and reports `zone "<name>" was not running
  (stale entry from pid N reclaimed)`, exit 0.
- `list`/`status` shows it as `stale` until something reclaims it.
- `gc` reclaims all stale entries.
Reclaim = take the lock; if `<entry>/cgroup` names a directory that still
exists: `cgroup.kill`, wait ≤ 2 s for empty, `rmdir`; then remove the entry.
**The pid in the file is never signalled**: pids are reused, and a stale
entry's pid may now belong to an unrelated process. (The cgroup is the safe
handle to whatever is left: `cgroup.kill` can only kill what is *in* it.)
On the unprivileged path with no cgroup, reclaim is just removing the
entry; the PDEATHSIG chain already guarantees nothing survives the
launcher.

**3. May `stop` escalate to SIGKILL.** Yes, and it must — through the
existing supervision path, not a second one. `stop <name>` sends `SIGTERM`
to the **launcher** pid (read from the entry, verified live by the lock
*and* by `pidfd_open` + start-time match, below). The launcher forwards to
the intermediate, which forwards to zone pid 1 and arms the 5 s `SIGKILL`
(`spawn.rs`, unchanged). `stop --now` sends `SIGKILL` to the launcher; the
PDEATHSIG chain collapses the zone. There is deliberately no "graceful
only" mode: a zone that ignores `SIGTERM` must not be able to keep itself
alive, and pid 1 of a namespace *cannot* be killed from inside it by
anything but its supervisor. The 5 s window is the whole policy; make it
`stop --grace N` only if a real workload needs it, with a hard upper bound
(60 s).

## Entry contents

```
/run/kryptik/zones/<name>/
  lock          flock target, empty file
  launcher.pid  "<pid> <starttime>"   pid of `kryptikd run`; starttime = field 22 of /proc/<pid>/stat
  init.pid      "<pid> <starttime>"   zone pid 1 as seen from the host pid namespace
  cgroup        "/sys/fs/cgroup/kryptik/<name>.<pid>"   absent when no cgroup
  started       ISO-8601 UTC
  identity      "<uid> <gid>"         the host identity the zone maps to
```
Written with `O_CREAT|O_EXCL` into a fresh directory; the directory itself is
created with `mkdir` (atomic) — **`EEXIST` on `mkdir` is "already
running or stale"**, which is then resolved by the lock: lock taken →
stale, reclaim, retry once; lock refused → `zone "<name>" is already
running (launcher pid N)`, exit 1, command not run.

Pid + start time: whenever an entry's pid is used for anything other than
display (`stop` signalling the launcher), open it with `pidfd_open(pid)` and
compare `/proc/<pid>/stat` start time with the recorded one; mismatch =
stale, do not signal. This closes pid reuse even in the window between
lock check and `kill`.

## Sequence in `spawn.rs`

```
run:   mkdir entry (or reclaim+retry)   -> flock lock
       write identity, started
       [cgroup create/attach as today]  -> write cgroup
       fork intermediate                -> write launcher.pid
       … handshake as today …
       intermediate writes nothing; the PARENT learns init.pid: the
       intermediate sends the grandchild's pid over `ready` (one i32 instead
       of one byte) and the parent writes init.pid
       waitpid                          -> cgroup destroy (M1), remove entry, release lock (implicit)
```
The lock is the last thing released because the fd closes at exit; a crash
releases it too, which is exactly what makes "lock free = stale" true.

## Concurrency

- Different zones: unrestricted; each has its own entry, cgroup, identity.
- Same zone twice: refused (above). One instance per zone name is the v1
  rule. Ephemeral zones that want N instances get `<name>@<n>` later;
  not now.
- `run` while `stop` is in progress: `stop` holds nothing; `run` sees the
  entry live (launcher still exiting) and is refused; the operator retries.
  Acceptable; `stop` blocks until the entry is gone (≤ 5 s + teardown) so
  the sequence `stop && run` works.

## Commands

- `kryptikd stop NAME [--now]` — as above; exit 0 when the zone is gone,
  1 if it was not running, 2 if it did not die (should be impossible: say
  which pid survived and where its cgroup is).
- `kryptikd list --running` / `kryptikd status NAME` — live/stale/absent,
  launcher and init pids, cgroup, since when.
- `kryptikd gc` — reclaim every stale entry and every empty `kryptik/*`
  cgroup (subsumes the M1 sweep; keep the age heuristic in `sweep_stale`
  as a second guard).

## Invariants and tests (host unprivileged and VM root; rows marked R need root)

| id | invariant | test | positive control |
|---|---|---|---|
| LC1 | one instance per zone | `run probe` twice concurrently | second refused with `already running`; first unaffected and its command completes |
| LC2 | `stop` ends a cooperative zone | zone runs `sleep 300`; `stop probe` | launcher exits 143-ish/128+15 mirrored; entry gone; cgroup gone (R); within 1 s |
| LC3 | `stop` ends a zone that ignores TERM | zone runs `trap "" TERM; sleep 300`; `stop probe` | dead at ≈5 s, not before 4 s (the grace is real), exit 137 |
| LC4 | stale entries are reclaimed, never signalled | `kill -9` the launcher; then `stop probe` → reports stale, exit 0; then `run probe` works | LC1 |
| LC5 | pid reuse is safe | craft an entry whose `launcher.pid` is the pid of a live `sleep` with a **wrong** start time, lock free; `stop probe` | the `sleep` is untouched; entry reclaimed |
| LC6 | registry invisible to zones | inside a zone: `/run/kryptik` absent, `/proc/1/…` of the host unreachable | — |
| LC7 | mode and owner | `stat /run/kryptik/zones` = `0700 root` (R) / `0700 <uid>` (host) | — |
| LC8 | `list` is truthful | running zone → `running`; after `kill -9` → `stale`; after `gc` → absent | — |
| LC9 | `stop` waits | `stop probe && run probe` in one line succeeds | — |
| LC10 | init.pid is the zone's pid 1 | host `readlink /proc/<init.pid>/ns/pid` differs from the host's; `/proc/<init.pid>/status` `NSpid` ends in `1` | — |

## Files

`registry.rs` (new; entry create/lock/reclaim/read; `pidfd_open` via
`libc::syscall(libc::SYS_pidfd_open, …)`), `spawn.rs` (sequence above; the
`ready` pipe carries the init pid), `main.rs` (`stop`, `status`, `list
--running`, `gc`), `cgroup.rs` (`sweep_stale` callable from `gc`),
`launcher.sh` group LC. `explain` prints the registry path.

## What this does not do

No daemon. `kryptikd run` is still the supervisor of its zone; the registry
is what lets a *second* kryptikd process find and stop it. A resident
kryptikd (needed for the broker, M5) comes after M3 and will read the same
registry.
