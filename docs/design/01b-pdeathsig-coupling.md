# Design 01b — Amendment: PR_SET_PDEATHSIG is coupled to the last credential change

Status: security amendment to Designs 01/01a, in reply to
`security/REQUEST.md` R-8a. Integration found that applying 01a (unshare as
root, the id map is the drop) silently disarmed the parent-death signal on
the privileged path. The finding is correct; 01a should have said this, and
this document makes the rule explicit so the coupling is visible in the
contract and not only in a comment.

## The kernel rule

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

That last clause is why the regression was invisible unprivileged: with the
map `0 → 1000` written for a uid-1000 launcher, the in-namespace
`setresuid(0,0,0)` maps back to kuid 1000 — no change, signal kept. With the
map `0 → N` written by root, the same call changes kuid 0 → N and the
signal is cleared. The host suite stayed green while the VM lost supervision.

## The rule for kryptikd

**Arm `PR_SET_PDEATHSIG` after the last kernel-id change in each process,
and re-check `getppid()` immediately after each arming.** Concretely:

| process | last id change | arm here |
|---|---|---|
| intermediate | `setresuid(0,0,0)` / `setresgid(0,0,0)` after `mapped` | immediately after them (and once more before `unshare` is fine but not sufficient) |
| zone pid 1 | none after fork (`PR_CAPBSET_DROP` is a drop; Landlock/seccomp change no ids) | at entry to `zone_init`, as today |
| any future helper that changes identity | its own last `setres*id` | after it |

Any future step that changes ids or gains capabilities in a supervised
process must move the arming after it, and the comment at the arming site
must name the step it follows. The `getppid()` re-check closes the window in
which the parent died between the credential change and the re-arming.

## Tests

- **Already landed and sufficient:** L1b and M8 with the restriction on
  (SIGKILL of the launcher leaves no zone process; in a root VM this is the
  only configuration that exercises a real kuid change). Keep them in the
  restricted run permanently; group K alone cannot catch this.
- **T11 as one host-side assertion (requested):** yes, add it as a single
  check on the zone's pid 1 read from the registry (`init.pid`), from the
  host: `/proc/<init>/status` shows `Uid:` and `Gid:` all `N`, `Groups:`
  empty, `CapEff`/`CapPrm`/`CapBnd` `0000000000000400`, `NoNewPrivs 1`,
  `Seccomp 2`, and `readlink /proc/<init>/ns/{user,pid,mnt,net}` all differ
  from `/proc/1/ns/*`. Keep K2/K3/CAP1–CAP3 as the inside view; the
  host-side line is the falsifiable one, because it does not rely on
  anything the zone reports about itself.
- **Design 01 T-series:** T9 (`CapAmb 0`, `NoNewPrivs 1`) is subsumed by T11.

## Recorded evidence, restated

With `kernel.apparmor_restrict_unprivileged_userns=1`: `vm-privileged-contract.sh`
positive control passes; full launcher suite 129 / 0 / 3, identical to the
unrestricted run; `boot-smoke.sh` 21 / 0 with the emulation caveat printed.
This is the first privileged evidence that speaks to the target kernel's
rule — under emulation, until the build tab's kernel boots.
