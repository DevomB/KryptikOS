# Zone registry

`kryptikd run` supervises its own zone. The registry is how any other
kryptikd process finds it: `stop`, `status`, `list --running`, `gc`, the
launch daemon, broker transfers and the net zone's plumbing. There is no
supervisor daemon; `kryptikd serve` starts zones by running `kryptikd run`.

## Location and ownership

A root launch uses `/run/kryptik/zones/` (tmpfs, `root:root 0700`) with one
0700 entry per running zone, written only by that zone's parent `kryptikd
run`. Zones cannot see the registry; the broker binds one socket file out of
an entry into its zone. An unprivileged launch uses
`$XDG_RUNTIME_DIR/kryptik/zones/` when that is an existing directory the user
owns, and `/tmp/kryptik-<uid>/zones/` otherwise; the base and its parent must
be real directories owned by the user and writable by nobody else (one that
is merely readable by others is tightened to 0700).

## Liveness is a lock

The launcher holds `flock(LOCK_EX)` on `<entry>/lock` for its whole life. An
entry is live if the lock cannot be taken and stale if it can, whatever its
pid file says; the kernel drops the lock when the launcher exits or crashes.
Probes (`status`, `stop` waiting for the entry to go) take a shared lock for
an instant and create nothing, so an owner (a claim or a reclaim) that finds
the lock taken tries again for 100 ms before treating the entry as live. A
directory without a lock file reads as not held.

Stale entries are reclaimed by `run`, by `stop` (which says `zone "<name>" was
not running (stale entry from pid N reclaimed)` and exits 0) and by `gc`;
`list` and `status` show them as `stale`. Reclaim = take the lock; if
`<entry>/cgroup` names a directory under kryptikd's cgroup tree, write
`cgroup.kill` and retry `rmdir` for up to 2 s; then remove the entry. The
recorded pid is never signalled: pids are reused, and `cgroup.kill` reaches
only what is in the cgroup.

## Entries

```text
/run/kryptik/zones/<name>/
  lock          flock target, empty
  launcher.pid  "<pid> <starttime>"   kryptikd run; starttime = field 22 of /proc/<pid>/stat
  init.pid      "<pid> <starttime>"   zone pid 1, as the host sees it
  cgroup        "/sys/fs/cgroup/kryptik/<name>.<pid>"   absent without a cgroup
  started       "@<seconds since the epoch>"
  identity      "<uid> <gid>"         the host identity the zone maps to
```

The [broker](broker.md) adds its socket, the clipboard, temporary files and
the staged Wayland socket; removing an entry removes whatever it holds. The
entry is created with an atomic `mkdir`. `EEXIST` means running or stale and
the lock decides: stale is reclaimed and the `mkdir` retried once; live
fails with `zone "<name>" is already running (launcher pid N)`, exit 1.
Fields are written 0600 with `O_NOFOLLOW`. Before a recorded pid is
signalled, its start time is compared with `/proc/<pid>/stat`, and a mismatch
counts as stale; that closes pid reuse between the lock check and `kill`.

```text
run:   mkdir entry (or reclaim + retry)  -> flock lock, write started
       write identity
       [cgroup create, limits, attach]   -> write cgroup
       write launcher.pid
       ... launch handshake ...
       the intermediate sends pid 1's pid -> the parent writes init.pid
       waitpid                           -> cgroup destroy, remove entry, lock released
```

## Stop

`stop <name>` sends `SIGTERM` to the launcher, which forwards it to zone pid 1
and sends `SIGKILL` 5 s later; `stop --now` sends `SIGKILL` to the launcher
and the parent-death chain takes the zone down. There is no graceful-only
mode: a zone that ignores `SIGTERM` must not keep itself alive. `stop` waits
up to 8 s for the entry to go, so `stop && run` works. It exits 0 when the
zone is gone or was stale, 1 if it was not running, 2 if the launcher
survived. There is one instance per zone name. `gc` also removes empty
`kryptik/*` cgroups and closes volume mappings whose zone is not running.

## Tests

The lifecycle section of `compartments/tests/launcher.sh`, unprivileged and
as root on the installed system: a second concurrent `run` is refused;
`stop` removes the entry and the cgroup and kills a zone that ignores
`SIGTERM` at about 5 s; a killed launcher leaves a stale entry that `stop`
reclaims; an entry naming a live process with the wrong start time does not
get it signalled; `/run/kryptik/zones` is absent inside a zone; the registry
is 0700; `status` is truthful; `stop && run` works; `init.pid` is the zone's
pid 1. `registry.rs` unit tests cover start times, the base-directory rules,
claims and reclaims.

## Files

`registry.rs`, `spawn.rs` (the sequence above), `main.rs` (`stop`,
`status`, `list --running`, `gc`), `cgroup.rs` (`sweep_now`).
