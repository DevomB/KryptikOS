# Design 01a — Correction to P5: the namespace is created by root; the id map is the privilege drop

Status: security correction to `01-privileged-launch-contract.md`, in reply to
`integration/FINDING-P5.md`. The finding is correct and the contract was
wrong. This amends P5 and P7 and leaves P1–P4, P6 unchanged.

## The error

P5 said: switch to the zone's identity (`setresgid(N)`, `setresuid(N)`)
**before** `unshare(CLONE_NEWUSER)`, without `PR_SET_KEEPCAPS`, so that "a
privileged launch carries nothing of root into the zone". P2 says the target
kernel allows `unshare(CLONE_NEWUSER)` only to a caller with `CAP_SYS_ADMIN`
in the initial namespace. A caller that has just become uid N with no
capabilities is exactly what P2 refuses. Under emulation
(`kernel.apparmor_restrict_unprivileged_userns=1`) the kernel's audit line
names `kryptikd` as the denied `userns_create` caller; on the linux-hardened
kernel `create_user_ns` would return `EPERM` for the same reason. No zone
would start. `vm-privileged-contract.sh`'s positive control was written to
catch exactly this and did.

The premise behind P5 was also mistaken: the early `setresuid` was not what
made the zone's root map to N. **The id map does that.** Whoever creates the
namespace, the process that later calls `setresuid(0,0,0)` inside it becomes
host uid N because the parent wrote `0 N 1` into `uid_map`. The creator's
identity determines only the namespace's *owner* uid, and a root-owned
namespace gives root nothing it did not already have.

## The repair: option (1) from the finding — unshare as root, become the zone via the map

Chosen because it is the only option in which the capability that creates
the namespace is held by a process that has never been the zone, and it
adds no mechanism (no `KEEPCAPS`, no helper, no `setns`).

**P5 (replaced).** A privileged launch creates the user namespace **as
root**, and becomes the zone's identity **through the id map**:

```
intermediate (uid 0, full caps in the initial ns):
  setgroups(0, NULL)                       CAP_SETGID; supplementary groups gone for good
  PR_SET_PDEATHSIG(SIGKILL); check getppid()
  wait `placed`                            parent has put us in the zone cgroup
  unshare(CLONE_NEWUSER | NEWNS | NEWPID | NEWIPC | NEWUTS | NEWCGROUP [| NEWNET])
      -> requires CAP_SYS_ADMIN in the initial ns: we have it (P2 satisfied)
      -> afterwards we hold a full capability set IN THE NEW NS and none in the initial ns
  signal `ready`
parent (uid 0):
  write /proc/<pid>/setgroups = deny, uid_map = "0 N 1", gid_map = "0 N 1"
      -> CAP_SETUID/SETGID in the initial ns lets root map any id
  signal `mapped`
intermediate:
  setresuid(0,0,0); setresgid(0,0,0)       inside the new ns: host identity is now N
  sethostname(zone); fork zone pid 1; supervise
```

What "carries nothing of root into the zone" now means, stated as what is
true *after* the maps rather than before the unshare:

- **Identity:** every process in the zone is host uid/gid N (K3 proves it
  from the host side); nothing in the zone is uid 0 on the host.
- **Capabilities:** after `unshare(CLONE_NEWUSER)` the process has **no**
  capabilities in the initial namespace (a task can never hold capabilities
  in an ancestor namespace), and the full set it holds in the new namespace
  is scoped to objects that namespace owns. `caps.rs` then reduces even
  that to `CAP_NET_BIND_SERVICE` before `exec`. Ambient is empty; keepcaps
  is not set; no securebits are needed.
- **Groups:** dropped by root before the unshare; `setgroups` is `deny`
  inside, so they cannot come back (K4, once it has its positive control).
- **The window:** between `unshare` and the `setresuid(0,0,0)` inside, the
  intermediate is host euid 0 with no capabilities. It does nothing in that
  window except the `ready`/`mapped` handshake. Owner-permission bits on
  root-owned files would apply to it (that is the only power euid 0 has
  without capabilities); it opens no files there. This is the whole cost of
  option (1), and it is stated so it can be checked rather than assumed.
- **Namespace owner:** the zone's user namespace is owned by uid 0. This
  changes nothing: root in the initial namespace has every capability over
  every namespace regardless of owner. (Under the old P5 the owner would
  have been N, which would have given *host processes running as N* — none
  exist except the zone itself — capabilities over it; root ownership is,
  if anything, the tighter of the two.)

**Unprivileged developer path:** unchanged (no `setgroups` possible, own
uid mapped, same handshake). It is not a supported way to run Kryptik (P1).

**P7 (unchanged in intent, now implemented in the same failure path):** when
`unshare` fails with `EPERM` and the caller is not root, the message is
`this kernel does not allow unprivileged user namespaces
(kernel.unprivileged_userns_clone=0); zones are started by the kryptikd
service as root`. When it fails with `EPERM` and the caller **is** root, the
message must say so distinctly (`unshare refused for a root caller: is
kryptikd confined by an LSM?`) — that is the AppArmor case and it must not
be mistaken for the P7 case.

## The code change (for Opus, against integration `70ec3eb`)

In `spawn.rs::intermediate_main`, step 1:

- keep `isolate::drop_supplementary_groups()` for the privileged path, fatal
  on error;
- **delete** the `setresgid(id.gid…)` and `setresuid(id.uid…)` calls before
  `unshare`;
- leave the unprivileged branch as it is.

The parent's `write_id_maps(pid, id.uid, id.gid)` already maps `0 → N`; the
existing `setresuid(0,0,0)`/`setresgid(0,0,0)` after `mapped` is the
identity switch. `launch_identity` and `check_data_dir` are unchanged. Add
the two P7 messages in the `unshare` error path (needs `geteuid()` and the
errno). Nothing else moves.

## Tests

- The existing `vm-privileged-contract.sh` positive control ("root launch
  with --zone-uid/--zone-gid runs the command as zone uid 0") must pass
  **with the restriction on**; that is the regression check for this
  correction. Its two other PASS lines stay.
- K1–K7 unchanged and still required with the restriction on: they were
  measured with it off, so re-run the whole K group under
  `apparmor_restrict_unprivileged_userns=1` and record that.
- New T11: from the host, `/proc/<init.pid>/status` of a running privileged
  zone shows `Uid: N N N N`, `Gid: N N N N`, `Groups:` empty, `CapEff`
  `0000000000000400`; and `readlink /proc/<init.pid>/ns/user` differs from
  `/proc/1/ns/user`.
- New T12 (the window): a root launch whose zone command is `cat
  /etc/shadow` fails with `No such file` (the path does not exist in the
  zone) — and a *host-side* check that no process of the zone ever had
  `Uid: 0` after `mapped`: sample `/proc/<init.pid>/status` immediately
  after `run` prints nothing… this is racy to observe; state instead that
  the intermediate opens no file between `unshare` and `setresuid`, and
  keep T11.
- T1–T10 from Design 01 stand; T3's message is the P7 sentence, T13 is the
  root-EPERM sentence (trigger by confining `kryptikd` with an AppArmor
  profile that denies `userns`, VM only, optional).

## What this does to recorded evidence

Nothing measured with the restriction off changes. Every privileged VM result
so far is stock-kernel evidence and remains labelled that way. After the
repair, the K group and the contract probe re-run with the restriction on
are the first privileged results that speak to the target kernel's rule —
still under emulation until the build tab's kernel boots.
