# Persistent zone lifecycle: registry, `stop`, concurrency

Status: implemented (`registry.rs`; `stop`, `status`, `list --running` and
`gc` in `main.rs`). Depends on cgroup ownership and supervision
([resource limits and ephemeral zones](resource-limits-and-ephemeral-zones.md)).
The [net zone](net-zone.md) needs it, because a routed zone attaches to a
*running* `net` zone, and so do [encrypted volumes](encrypted-volumes.md),
because crash recovery closes the volumes of zones that are not running.

The design turns on three decisions, set out first.

## The three decisions

**1. Who owns the registry, with what mode.** `/run/kryptik/zones/` is
created by kryptikd, `root:root 0700`, on a tmpfs (`/run`). Every entry
`/run/kryptik/zones/<name>/` is `0700 root:root`. Only the **parent**
`kryptikd run` process writes it; the intermediate and the zone never do.
Nothing under `/run/kryptik` is visible inside any zone (it is not in the
scaffold); the [broker](broker.md) bind-mounts *one socket file* out of an
entry into a zone, never the directory. On the unprivileged developer path
the registry lives at `$XDG_RUNTIME_DIR/kryptik/zones/` (mode 0700, owner =
the launching uid) so the same code and tests run there; `explain` prints
which.

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
exists (and lies under kryptikd's own cgroup tree): `cgroup.kill`, wait ≤ 2 s
for empty, `rmdir`; then remove the entry.
**The pid in the file is never signalled**: pids are reused, and a stale
entry's pid may now belong to an unrelated process. (The cgroup is the safe
handle to whatever is left: `cgroup.kill` can only kill what is *in* it.)
On the unprivileged path with no cgroup, reclaim is just removing the
entry; the parent-death signal chain already guarantees nothing survives the
launcher.

**3. May `stop` escalate to SIGKILL.** Yes, and it must, through the
existing supervision path rather than a second one. `stop <name>` sends
`SIGTERM` to the **launcher** pid (read from the entry, verified live by the
lock *and* by a start-time match, below). The launcher forwards to the
intermediate, which forwards to zone pid 1 and arms the 5 s `SIGKILL`
(`spawn.rs`, unchanged). `stop --now` sends `SIGKILL` to the launcher; the
parent-death signal chain collapses the zone. There is deliberately no
"graceful only" mode: a zone that ignores `SIGTERM` must not be able to keep
itself alive, and pid 1 of a namespace *cannot* be killed from inside it by
anything but its supervisor. The 5 s window is the whole policy; make it
`stop --grace N` only if a real workload needs it, with a hard upper bound
(60 s).

## Entry contents

```text
/run/kryptik/zones/<name>/
  lock          flock target, empty file
  launcher.pid  "<pid> <starttime>"   pid of `kryptikd run`; starttime = field 22 of /proc/<pid>/stat
  init.pid      "<pid> <starttime>"   zone pid 1 as seen from the host pid namespace
  cgroup        "/sys/fs/cgroup/kryptik/<name>.<pid>"   absent when no cgroup
  started       ISO-8601 UTC
  identity      "<uid> <gid>"         the host identity the zone maps to
```

The [broker](broker.md) adds its own files to a running zone's entry (the
broker and clipboard state, its temporary files, and the staged Wayland
proxy socket); a sweep removes whatever the entry lists, not a set of names
it knows. A probe (`status`, `stop` polling for the entry to go) takes a
shared lock and creates nothing: a directory with no lock file is one
between its `mkdir` and its lock, or between a reclaim's unlink and its
`rmdir`, and reads as not held. An owner (a claim, a reclaim) that finds
the lock taken tries again for 100 ms before it calls the entry live, since
a probe holds it only for an instant.

Entries are written with `O_CREAT|O_EXCL` into a fresh directory; the
directory itself is created with `mkdir` (atomic), and **`EEXIST` on `mkdir`
is "already running or stale"**, which is then resolved by the lock: lock
taken → stale, reclaim, retry once; lock refused → `zone "<name>" is already
running (launcher pid N)`, exit 1, command not run.

Pid + start time: whenever an entry's pid is used for anything other than
display (`stop` signalling the launcher), compare the start time in
`/proc/<pid>/stat` with the recorded one; mismatch = stale, do not signal.
This closes pid reuse in the window between the lock check and `kill`. The
design also proposed holding the process with `pidfd_open`; the
implementation relies on the start-time comparison alone.

## Sequence in `spawn.rs`

```text
run:   mkdir entry (or reclaim+retry)   -> flock lock
       write identity, started
       [cgroup create/attach]           -> write cgroup
       fork intermediate                -> write launcher.pid
       … launch handshake …
       intermediate writes nothing; the PARENT learns init.pid: the
       intermediate sends the grandchild's pid over `ready` (one i32 instead
       of one byte) and the parent writes init.pid
       waitpid                          -> cgroup destroy, remove entry, release lock (implicit)
```

The lock is the last thing released because the fd closes at exit; a crash
releases it too, which is exactly what makes "lock free = stale" true.

## Concurrency

- Different zones: unrestricted; each has its own entry, cgroup, identity.
- Same zone twice: refused (above). One instance per zone name is the rule
  for now. Ephemeral zones that want several instances may get
  `<name>@<n>` later.
- `run` while `stop` is in progress: `stop` holds nothing; `run` sees the
  entry live (launcher still exiting) and is refused; the operator retries.
  Acceptable; `stop` blocks until the entry is gone (≤ 5 s + teardown) so
  the sequence `stop && run` works.

## Commands

- `kryptikd stop NAME [--now]`: as above; exit 0 when the zone is gone,
  1 if it was not running, 2 if it did not die (should be impossible: say
  which pid survived).
- `kryptikd list --running` / `kryptikd status NAME`: live/stale/absent,
  launcher and init pids, cgroup, since when.
- `kryptikd gc`: reclaim every stale entry and every empty `kryptik/*`
  cgroup (this subsumes the cgroup sweep; the age check in `sweep_stale`
  stays as a second guard on the launch path).

## Invariants and tests

Run on the unprivileged host and in the VM as root; rows marked (root) need
root.

| invariant | test | positive control |
|---|---|---|
| one instance per zone | `run probe` twice concurrently | second refused with `already running`; first unaffected and its command completes |
| `stop` ends a cooperative zone | zone runs `sleep 300`; `stop probe` | launcher exits with 128+15 mirrored; entry gone; cgroup gone (root); within 1 s |
| `stop` ends a zone that ignores TERM | zone runs `trap "" TERM; sleep 300`; `stop probe` | dead at ≈5 s, not before 4 s (the grace is real), exit 137 |
| stale entries are reclaimed, never signalled | `kill -9` the launcher; then `stop probe` → reports stale, exit 0; then `run probe` works | the one-instance test |
| pid reuse is safe | craft an entry whose `launcher.pid` is the pid of a live `sleep` with a **wrong** start time, lock free; `stop probe` | the `sleep` is untouched; entry reclaimed |
| registry invisible to zones | inside a zone: `/run/kryptik` absent, `/proc/1/…` of the host unreachable | — |
| mode and owner | `stat /run/kryptik/zones` = `0700 root` (root) / `0700 <uid>` (host) | — |
| `list` is truthful | running zone → `running`; after `kill -9` → `stale`; after `gc` → absent | — |
| `stop` waits | `stop probe && run probe` in one line succeeds | — |
| init.pid is the zone's pid 1 | host `readlink /proc/<init.pid>/ns/pid` differs from the host's; `/proc/<init.pid>/status` `NSpid` ends in `1` | — |

## Files

`registry.rs` (entry create/lock/reclaim/read, start-time checks),
`spawn.rs` (sequence above; the `ready` pipe carries the init pid),
`main.rs` (`stop`, `status`, `list --running`, `gc`), `cgroup.rs`
(`sweep_now` for `gc`), the registry checks in
`compartments/tests/launcher.sh`. `explain` prints the registry path.

## What this does not do

It does not make kryptikd a supervisor daemon. `kryptikd run` is still the
supervisor of its zone; the registry is what lets a *second* kryptikd
process find and stop it. The launch daemon (`kryptikd serve`) and the
[broker](broker.md) read the same registry; `serve` starts zones by running
`kryptikd run`, so each zone still has its own launcher as supervisor.
