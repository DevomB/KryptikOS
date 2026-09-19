# The privileged launch contract on Kryptik's kernel

Status: implemented in `kryptikd` (`zone.rs`, `spawn.rs`, `isolate.rs`,
`main.rs`). The cgroup ownership in
[resource limits and ephemeral zones](resource-limits-and-ephemeral-zones.md),
the [net zone](net-zone.md) and [encrypted volumes](encrypted-volumes.md) all
rely on it, because each needs a root launcher.

## The fact WSL cannot show

Kryptik's kernel is linux 6.18 + linux-hardened with
`CONFIG_USER_NS_UNPRIVILEGED` **off** (`build/config/kernel/hardened.fragment`).
On that kernel `unshare(CLONE_NEWUSER)` and `clone(CLONE_NEWUSER)` from a
process without `CAP_SYS_ADMIN` in the initial user namespace fail with
`EPERM`, and the sysctl `kernel.unprivileged_userns_clone` reads `0`.
Every unprivileged `kryptikd run` result on WSL or a stock Ubuntu VM therefore
exercises a path that **does not exist on the target**. On the target, zones
are created only by a root kryptikd. That is the design (ADR-003, ADR-010);
this document makes it a checked contract instead of an assumption.

## The rules

**kryptikd creates zones as uid 0 in the initial user namespace, and only
there.** The unprivileged path stays for developer hosts and CI; it is not a
supported way to run Kryptik.

**Unprivileged user-namespace creation is off on the target, and
`kryptikd check` proves it.** `check` reads whichever restriction knob the
kernel has (`kernel.unprivileged_userns_clone` on linux-hardened, where `0`
means restricted; `kernel.apparmor_restrict_unprivileged_userns` on Ubuntu),
then proves the answer by forking a child that drops to uid 65534 (or stays
as itself on an unprivileged run) and calls `unshare(CLONE_NEWUSER)`. `EPERM`
means the restriction is in force. Success means it is not, and under
`check --target` that is a failure. The restriction currently comes from the
kernel configuration alone: the design also called for an explicit
`kernel.unprivileged_userns_clone = 0` in
`build/config/sysctl.d/99-kryptik-hardening.conf`, and that line is not there
yet.

**Each zone has a fixed, declared, unique host identity range.** Zone files
carry `[identity] uid_base = N` (integer). Validation: `N >= 131072` (the
first aligned range; 100000 is not a multiple of 65536), `N % 65536 == 0`,
unique across the zone set, and the range `[N, N+65536)` must not overlap any
other zone's. The mapping written is `0 -> N` (one uid) and
`65534 -> N+65534` (so "nobody" inside is a distinct host uid, not an
unmapped 65534 alias); gid likewise. `--zone-uid/--zone-gid` remain as an
override only for zones without `[identity]`, and a root launch without
either is refused. Ranges derived from a zone's position in the set were
rejected: adding a zone must never change another zone's file ownership.
Shipped zone files get `uid_base` values `131072, 196608, …` in name order,
assigned once, by hand.

**The data directory belongs to the zone's identity and nothing else.**
`/var/lib/kryptik/zones/<zone>` is created by kryptikd on first launch and
chowned to `N:N`; an existing directory is never re-owned. On every launch
`check_data_dir` refuses any other owner, a symlink, or a directory with
submounts.

**A privileged launch creates the user namespace as root and becomes the
zone's identity through the id map.** Nothing of root reaches the zone; the
handshake and what it guarantees are set out in the next section.

**`KRYPTIK_EXPERIMENTAL` is inert for a root launch on the target.** When
the restriction on unprivileged user namespaces is in force and euid is 0,
the variable is ignored and a zone that needs it is refused. Development
overrides are for development hosts.

**Refusals are named.** When `unshare` fails with `EPERM`, kryptikd says
which restriction refused it instead of printing the bare errno, and it
tells the two callers apart:

- an unprivileged caller is hitting the restriction as intended:
  `creating a user namespace was refused. This kernel restricts unprivileged
  user namespaces (CONFIG_USER_NS_UNPRIVILEGED=n,
  kernel.unprivileged_userns_clone=0, or an LSM policy); kryptikd must be
  started with CAP_SYS_ADMIN in the initial namespace.`
- a root caller being refused means something is confining kryptikd itself
  (the AppArmor case), and must not be mistaken for the first:
  `unshare refused for a root caller: is kryptikd confined by an LSM?`

**The parent-death signal is armed after the last credential change.** See
the section on `PR_SET_PDEATHSIG` below.

## The launch handshake

```text
intermediate (uid 0, full caps in the initial ns):
  setgroups(0, NULL)                       CAP_SETGID; supplementary groups gone for good
  PR_SET_PDEATHSIG(SIGKILL); check getppid()
  wait `placed`                            parent has put us in the zone cgroup
  unshare(CLONE_NEWUSER | NEWNS | NEWPID | NEWIPC | NEWUTS | NEWCGROUP [| NEWNET])
      -> requires CAP_SYS_ADMIN in the initial ns: we have it
      -> afterwards we hold a full capability set IN THE NEW NS and none in the initial ns
  signal `ready`
parent (uid 0):
  write /proc/<pid>/setgroups = deny, uid_map = "0 N 1", gid_map = "0 N 1"
      (plus "65534 N+65534 1" for nobody)
      -> CAP_SETUID/SETGID in the initial ns lets root map any id
  signal `mapped`
intermediate:
  setresuid(0,0,0); setresgid(0,0,0)       inside the new ns: host identity is now N
  PR_SET_PDEATHSIG(SIGKILL); check getppid()   re-armed: the id switch cleared it
  sethostname(zone); fork zone pid 1; supervise
```

The capability that creates the namespace is held by a process that has
never been the zone, and the scheme adds no mechanism: no `KEEPCAPS`, no
helper, no `setns`.

What "carries nothing of root into the zone" means, stated as what is true
*after* the maps rather than before the unshare:

- **Identity:** every process in the zone is host uid/gid N; nothing in the
  zone is uid 0 on the host. The launcher suite's root-launch checks prove it
  from the host side.
- **Capabilities:** after `unshare(CLONE_NEWUSER)` the process has **no**
  capabilities in the initial namespace (a task can never hold capabilities
  in an ancestor namespace), and the full set it holds in the new namespace
  is scoped to objects that namespace owns. `caps.rs` then reduces even
  that to `CAP_NET_BIND_SERVICE` (plus anything a
  [zone policy file](zone-policy-files.md) may keep) before `exec`. Ambient
  is empty; keepcaps is not set; no securebits are needed.
- **Groups:** dropped by root before the unshare; `setgroups` is `deny`
  inside, so they cannot come back.
- **The window:** between `unshare` and the `setresuid(0,0,0)` inside, the
  intermediate is host euid 0 with no capabilities. It does nothing in that
  window except the `ready`/`mapped` handshake. Owner-permission bits on
  root-owned files would apply to it (that is the only power euid 0 has
  without capabilities); it opens no files there. This is the whole cost of
  creating the namespace as root, and it is stated so it can be checked
  rather than assumed.
- **Namespace owner:** the zone's user namespace is owned by uid 0. This
  changes nothing: root in the initial namespace has every capability over
  every namespace regardless of owner. Had the namespace been created as N,
  host processes running as N (none exist except the zone itself) would have
  held capabilities over it; root ownership is, if anything, the tighter of
  the two.

**Unprivileged developer path:** no `setgroups` is possible, the launcher's
own uid is mapped, and the handshake is the same. It is not a supported way
to run Kryptik.

## `PR_SET_PDEATHSIG` and credential changes

`commit_creds()` clears `task->pdeath_signal` (and resets dumpable) whenever
the new credentials differ from the old in any of:

- `euid`, `egid`, `fsuid`, `fsgid` (compared as **kernel** ids, i.e. after
  the user-namespace mapping), or
- capabilities that are **not a subset** of the old ones (a gain, not a
  drop; `cred_cap_issubset` treats a child namespace owned by the caller's
  euid as a subset).

So the signal survives: `unshare(CLONE_NEWUSER)` (new full set in a child
namespace the caller owns), `PR_CAPBSET_DROP` (a drop), Landlock
`restrict_self` and `PR_SET_NO_NEW_PRIVS` (no id or capability change),
`setgroups` (supplementary groups are not in the test), seccomp
installation, and `execve` of a binary with no set-id bit and no file
capabilities. It does **not** survive `setresuid`/`setresgid` when the
kernel id actually changes.

That last clause is why a missing re-arm is invisible on an unprivileged
host: with the map `0 → 1000` written for a uid-1000 launcher, the
in-namespace `setresuid(0,0,0)` maps back to kuid 1000, no change, and the
signal is kept. With the map `0 → N` written by root, the same call changes
kuid 0 → N and the signal is cleared. A host suite can stay green while a
root launch has lost supervision.

**Arm `PR_SET_PDEATHSIG` after the last kernel-id change in each process,
and re-check `getppid()` immediately after each arming.**

| process | last id change | arm here |
|---|---|---|
| intermediate | `setresuid(0,0,0)` / `setresgid(0,0,0)` after `mapped` | immediately after them (arming once more before `unshare` is fine but not sufficient) |
| zone pid 1 | none after fork (`PR_CAPBSET_DROP` is a drop; Landlock/seccomp change no ids) | at entry to `zone_init` |
| any future helper that changes identity | its own last `setres*id` | after it |

Any future step that changes ids or gains capabilities in a supervised
process must move the arming after it, and the comment at the arming site
must name the step it follows. The `getppid()` re-check closes the window in
which the parent died between the credential change and the re-arming.

## Core scheduling

After the id switch and before it forks the zone's pid 1, the intermediate
takes a core-scheduling cookie of its own (`prctl(PR_SCHED_CORE,
PR_SCHED_CORE_CREATE)` on itself; no privilege is needed to cut oneself
off). Every task forked below inherits it, so the whole zone shares one
cookie, and on a core with SMT the kernel runs on the sibling hardware
threads only tasks with that cookie: this zone's, or nothing. Another zone,
the session, the kernel's own threads never share a core with it.

What that buys is exactly the sibling position: the one the cross-thread
side channels (the L1TF, MDS and later families) need. What it does not buy
is a substitute for the mitigations. The kernel's own mitigations stay on;
ADR-011 takes the siblings away altogether with `mitigations=auto,nosmt`,
and the cookies are what makes revisiting that possible, not a reason to
revisit it here.

No answer to that call stops a launch, because none of the zone's other
boundaries depends on it. Two answers are expected:

- `ENODEV`: no core has a second hardware thread online. Under `nosmt` that
  is every installed Kryptik, as it is a processor or a VM without SMT.
  There is no sibling to share, so the property holds with nothing to take;
  the launcher says nothing and `kryptikd explain` says "no sibling threads
  online". The first version treated only `EINVAL` as expected and anything
  else as fatal, and no zone started on the installed system; the suites
  had passed, because their machines have SMT or no core scheduling at all.
  The installed system is the only place this answer is seen.
- `EINVAL`: a kernel without `CONFIG_SCHED_CORE`, as on the developer VM and
  most hosts. A note in the zone's log, and `explain` says "not available on
  this kernel".

Nothing in `/proc` shows a cookie; `kryptikd status` asks the kernel for
the zone's pid 1's with `PR_SCHED_CORE_GET` (allowed with ptrace-read
access, which root has and a user has over the zones it launched) and
prints `core-sched own`, `no-smt`, `none` or `unavailable`. The launcher
suite reads that word: `own` and `no-smt` pass, `unavailable` is a skip, and
`none` - a kernel that could have given a cookie to a zone that has none -
fails.

## Tests

Where: the developer VM as root. Until a Kryptik kernel boots there, the
stock kernel emulates the restriction with
`sysctl kernel.apparmor_restrict_unprivileged_userns=1` (Ubuntu). The
*observable* behaviour (EPERM for unprivileged `unshare`) is the same, and
the test must say which knob it used. The root-launch checks are run with the
restriction on; results measured with it off say nothing about the target
kernel's rule.

| check | expected |
|---|---|
| `kryptikd check --target` with the restriction on | pass; prints `unpriv userns    restricted (EPERM; <knob>)` |
| same with the restriction off | **fail**, names the knob |
| unprivileged `kryptikd run` with the restriction on | exit 1, the unprivileged refusal message above, command did not run |
| root `kryptikd run work -- id -u` with `[identity] uid_base = 196608` | `0` inside; `$ROOTFS/work/x` owned by 196608 on the host; `nobody` inside maps to 262142 (`touch` as nobody via `su`/`setpriv` is optional) |
| two zone files with the same `uid_base` | `kryptikd check` fails: `identity ranges must not overlap` |
| `uid_base = 1000` or `uid_base = 100001` | refused by validation |
| root launch of a zone with no `[identity]` and no `--zone-uid` | refused |
| `KRYPTIK_EXPERIMENTAL=1` root launch of `untrusted` (ephemeral) with the restriction on | refused; message says the override is ignored on the target |
| root launch with `--zone-uid/--zone-gid` and the restriction on | the command runs as zone uid 0 (the positive control for creating the namespace as root) |
| from the host, a running privileged zone's pid 1 (`init.pid` from the [registry](zone-registry.md)) | `/proc/<init>/status` shows `Uid:` and `Gid:` all `N`, `Groups:` empty, `CapEff`/`CapPrm`/`CapBnd` `0000000000000400`, `NoNewPrivs 1`, `Seccomp 2`; `readlink /proc/<init>/ns/{user,pid,mnt,net}` all differ from `/proc/1/ns/*` |
| SIGKILL the launcher of a running zone, restriction on | no zone process survives |
| root launch while kryptikd is confined by an AppArmor profile that denies `userns` (VM only, optional) | the root-caller refusal message above |
| positive control: with the restriction off, an unprivileged launch still works on the dev host | launcher suite unchanged |

The host-side view of pid 1 is the falsifiable check, because it does not
rely on anything the zone reports about itself; the in-zone checks of the
bounding and effective sets (`CapBnd`, `CapEff`) and of `NoNewPrivs` stay as
the inside view. The SIGKILL check is the only one that catches a lost
parent-death signal, because only a root launch with a real kernel-id change
exercises it; it runs in the restricted configuration permanently.

Where the checks live: `compartments/tests/launcher.sh` (the root-launch
checks, the host-side pid 1 check, and the check that SIGKILLs the launcher
and looks for surviving zone processes), the VM's privileged-contract probe,
and unit tests in `zone.rs` for identity-range validation.

## How this changed

The first version of this contract had the privileged launch switch to the
zone's identity (`setresgid(N)`, `setresuid(N)`) **before**
`unshare(CLONE_NEWUSER)`, so that the launch would carry nothing of root into
the zone. That could not work on the target kernel: it allows
`unshare(CLONE_NEWUSER)` only to a caller with `CAP_SYS_ADMIN` in the initial
namespace, and a caller that has just become uid N with no capabilities is
exactly what it refuses. Under emulation the kernel's audit line named
`kryptikd` as the denied `userns_create` caller; on linux-hardened
`create_user_ns` returns `EPERM` for the same reason. No zone would have
started, and the root-launch positive control in the VM caught it.

The premise was also mistaken: the early `setresuid` was never what made the
zone's root map to N. **The id map does that.** Whoever creates the
namespace, the process that later calls `setresuid(0,0,0)` inside it becomes
host uid N because the parent wrote `0 N 1` into `uid_map`. The creator's
identity determines only the namespace's *owner*, and a root-owned namespace
gives root nothing it did not already have. So the early switch was removed,
the namespace is now created as root, and the id map is the privilege drop.

Removing the early switch had a side effect the first version did not
anticipate. The parent-death signal used to be armed after the last
credential change, because the switch happened before it; once the switch
moved to after `mapped`, the in-namespace `setresuid(0,0,0)` cleared the
signal, and a launcher killed with SIGKILL left its zone running. The
launcher suite caught it as zone processes outliving a SIGKILLed launcher.
The re-arming rule above is the fix, and it is written into the contract so
the coupling is visible here and not only in a comment in `spawn.rs`.

## Files

`zone.rs` (parse/validate `[identity]`), `spawn.rs` (`launch_identity`;
`intermediate_main`: group drop, the handshake, the id switch after
`mapped`, the parent-death re-arm, the refusal messages; the
`KRYPTIK_EXPERIMENTAL` rule), `isolate.rs` (`write_id_maps`, the restriction
probe), `main.rs` (`check --target`), `caps.rs`, the six zone files,
`docs/architecture.md` one paragraph under "Zone 0".
