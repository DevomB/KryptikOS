# Privileged launch

Kryptik's kernel is linux-hardened with `CONFIG_USER_NS_UNPRIVILEGED` off
(`build/config/kernel/hardened.fragment`): `unshare(CLONE_NEWUSER)` or
`clone(CLONE_NEWUSER)` without `CAP_SYS_ADMIN` in the initial user namespace
fails with `EPERM`, and `kernel.unprivileged_userns_clone` reads 0. Zones are
therefore created only by a root kryptikd (ADR-003, ADR-010). An unprivileged
`kryptikd run` on WSL or a stock kernel takes a path the target does not
have; it stays for developer hosts and CI, and is not a supported way to run
Kryptik. [Resource limits](resource-limits-and-ephemeral-zones.md),
[the net zone](net-zone.md) and [encrypted volumes](encrypted-volumes.md)
depend on the root launcher.

## Rules

- kryptikd creates zones as uid 0 in the initial user namespace.
- `kryptikd check --target` proves the restriction. It reads the knob the
  kernel has (`kernel.unprivileged_userns_clone`, 0 = restricted, on
  linux-hardened; `kernel.apparmor_restrict_unprivileged_userns`, 1 =
  restricted, on Ubuntu), then forks a child that (as root) drops to uid 65534
  and calls `unshare(CLONE_NEWUSER)`: `EPERM` means the restriction holds, and
  success fails the check. The restriction comes from the kernel
  configuration alone; no sysctl sets it.
- Each zone declares its host identity range: `[identity] uid_base = N`, a
  multiple of 65536, at least 131072, unique in the zone set, so the ranges
  `[N, N+65536)` never overlap. The maps are `0 -> N` and `65534 -> N+65534`
  (so `nobody` inside is its own host uid), gid likewise. `--zone-uid` and
  `--zone-gid` are an override for a zone without `[identity]`; a root launch
  with neither is refused. Ranges are declared, not derived from a zone's
  position, because adding a zone must never change another zone's file
  ownership. The shipped zones use 131072, 196608, ... in name order.
- `/var/lib/kryptik/zones/<zone>` is created on first launch and chowned to
  `N:N`, and never re-owned; a launch refuses one with another owner, a
  symlink, or one with mounts of its own.
- `KRYPTIK_EXPERIMENTAL` is ignored for a root launch while the restriction
  is in force, so a zone that needs it is refused.
- When `unshare` fails with `EPERM`, an unprivileged caller is told that the
  kernel restricts unprivileged user namespaces and kryptikd needs
  `CAP_SYS_ADMIN`; a root caller is asked whether kryptikd is confined by an
  LSM (the AppArmor case), which must not be mistaken for the first.

## The launch handshake

```text
intermediate (uid 0, full capabilities in the initial namespace):
  setgroups(0, NULL)                        supplementary groups gone for good
  PR_SET_PDEATHSIG(SIGKILL); check getppid()
  wait `placed`                             the parent has put it in the zone's cgroup
  unshare(CLONE_NEWUSER | NEWNS | NEWPID | NEWIPC | NEWUTS | NEWCGROUP | NEWNET)
      needs CAP_SYS_ADMIN in the initial namespace, which it has; afterwards it
      holds a full set in the new namespace and none in the initial one
  signal `ready`
parent (uid 0):
  build the zone's network path from outside (net zone, routed zones)
  write /proc/<pid>/setgroups = deny, uid_map "0 N 1", gid_map "0 N 1"
      (plus "65534 N+65534 1"); CAP_SETUID/SETGID in the initial namespace
      allow any mapping
  signal `mapped`
intermediate:
  setresuid(0,0,0); setresgid(0,0,0)        host identity is now N
  PR_SET_PDEATHSIG(SIGKILL); check getppid()  re-armed: the id change cleared it
  core-scheduling cookie; sethostname(zone); fork zone pid 1; supervise
```

The id map is the privilege drop: whoever creates the namespace, the process
that calls `setresuid(0,0,0)` inside it becomes host uid N because the parent
wrote `0 N 1`. Switching to N before the unshare cannot work, since the target
kernel grants `unshare(CLONE_NEWUSER)` only with `CAP_SYS_ADMIN` in the
initial namespace. No `KEEPCAPS`, helper or `setns` is involved. After the
maps:

- Every zone process is host uid/gid N; nothing in the zone is host root.
- The zone has no capabilities in the initial namespace (a task never holds
  any in an ancestor namespace), and `caps.rs` cuts its set in the new one to
  `CAP_NET_BIND_SERVICE` plus what a [zone policy file](zone-policy-files.md)
  keeps, before `exec`. Ambient is empty, keepcaps unset, no securebits.
- Supplementary groups were dropped before the unshare, and `setgroups` is
  `deny` inside.
- Between `unshare` and `setresuid(0,0,0)` the intermediate is host euid 0
  with no capabilities, so owner-permission bits on root-owned files are all
  it has. It uses them once: to open (`O_PATH`) its broker socket and staged
  Wayland socket in its root-owned 0700 registry entry, for binding into the
  zone. Otherwise it only checks that its new network namespace holds nothing
  but loopback, and waits on the handshake.
- The namespace is owned by uid 0, which grants nothing new: root in the
  initial namespace already has every capability over every namespace. Owned
  by N, it would give capabilities over it to any host process running as N.

The unprivileged developer path runs the same handshake without `setgroups`,
mapping the launcher's own uid.

## `PR_SET_PDEATHSIG` and credential changes

`commit_creds()` clears `task->pdeath_signal` when `euid`, `egid`, `fsuid` or
`fsgid` change as kernel ids (after the user-namespace mapping), or when
capabilities are gained (`cred_cap_issubset` treats a child namespace owned
by the caller's euid as a subset). The signal survives
`unshare(CLONE_NEWUSER)`, `PR_CAPBSET_DROP`, Landlock `restrict_self`,
`PR_SET_NO_NEW_PRIVS`, `setgroups`, seccomp, and `execve` of a binary without
set-id bits or file capabilities. It does not survive a
`setresuid`/`setresgid` that changes the kernel id.

An unprivileged host hides this: with the map `0 -> 1000` for a uid-1000
launcher, `setresuid(0,0,0)` maps back to kuid 1000 and the signal is kept,
while with `0 -> N` written by root it changes kuid 0 to N and clears it. A
host suite can pass while a root launch has lost supervision.

**Arm `PR_SET_PDEATHSIG` after the last kernel-id change in each process,
and re-check `getppid()` right after each arming** (the parent may have died
in between).

| process | last id change | arm here |
| --- | --- | --- |
| intermediate | `setresuid(0,0,0)` / `setresgid(0,0,0)` after `mapped` | right after them; arming before `unshare` too is fine but not enough |
| zone pid 1 | none after fork (`PR_CAPBSET_DROP` is a drop; Landlock and seccomp change no ids) | at entry to `zone_init` |
| any future helper that changes identity | its own last `setres*id` | after it |

A new step that changes ids or gains capabilities in a supervised process
must move the arming after it, and the comment at the arming site must name
the step it follows.

## Core scheduling

After the id switch, the intermediate takes a core-scheduling cookie of its
own (`prctl(PR_SCHED_CORE, PR_SCHED_CORE_CREATE)`, no privilege needed), and
every zone task inherits it. On an SMT core the sibling threads then run only
this zone's tasks or nothing, which removes the sibling position that the
cross-thread side channels (L1TF, MDS and later) need. The kernel's
mitigations stay on; ADR-011 turns SMT off altogether
(`mitigations=auto,nosmt`), and the cookies are what would make revisiting
that possible.

A refusal is judged by what the machine is, asked with `PR_SCHED_CORE_GET`,
not by the errno:

- Siblings online and scheduled by cookie: the cookie is all that separates
  two zones on a core, so a zone that cannot get one does not start.
- `ENODEV`: no core has a second thread online (every installed Kryptik under
  `nosmt`, and any CPU or VM without SMT). Nothing shares a core; `kryptikd
  explain` says "no sibling threads online".
- `EINVAL`: no `CONFIG_SCHED_CORE`. The zone's log gets a note and `explain`
  says "not available on this kernel".

`/proc` does not show cookies, so `kryptikd status` asks the kernel for pid
1's and prints `core-sched own`, `no-smt`, `none` or `unavailable`. The
launcher suite passes `own` and `no-smt`, skips `unavailable` and fails
anything else.

## Tests

The launcher suite (`compartments/tests/launcher.sh`) runs as root on the
installed system in the zones suite. It checks that a root launch without an
identity is refused; that the zone runs as uid 0 inside, its files belong to
N and its supplementary groups are gone; that a data directory owned by
another uid is refused; that `KRYPTIK_EXPERIMENTAL` starts nothing on the
target; and, from the host, which relies on nothing the zone says about
itself, that pid 1 has `Uid`/`Gid` N, no groups, `CapEff`/`CapPrm`/`CapBnd`
`0000000000000400`, `NoNewPrivs 1`, `Seccomp 2` and its own user, pid, mnt
and net namespaces. `SIGKILL` of the launcher must leave no zone process: the
only check that catches a lost parent-death signal, since only a root launch
changes the kernel id. `build/guest-tests/zones-check.sh` runs
`check --target`, and `zone.rs` unit-tests the identity rules. On a stock
Ubuntu kernel, `kernel.apparmor_restrict_unprivileged_userns=1` emulates the
restriction; results with it off say nothing about the target.

## Files

`zone.rs` (`[identity]`), `spawn.rs` (`launch_identity`; `intermediate_main`:
the group drop, the handshake, the id switch, the parent-death re-arm, the
refusal messages, the `KRYPTIK_EXPERIMENTAL` rule), `isolate.rs`
(`write_id_maps`, the restriction probe, the core cookie), `main.rs`
(`check --target`, `status`), `caps.rs`, the zone files.
