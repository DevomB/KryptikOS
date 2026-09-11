# Design 07 — Per-zone policy files: enforced, not parsed-and-ignored

Status: security contract, implemented by security in the same increment.
Depends on nothing. Needed by M3 (the `net` zone must open `AF_PACKET` and
`NETLINK_NETFILTER`, which the base policy refuses).

## What a policy file is

`[policy] seccomp = "policy/net.seccomp"` names a file **relative to the zone
directory** (`--zones DIR`). It is not a language. It is a list of additive
directives, one per line, `#` comments, applied on top of the shared base
policy; it can widen the base in three specific, named ways and cannot narrow
it or override a denial:

```
# policy/net.seccomp
allow-syscall     sethostname          # a syscall by name, added to the allowlist
allow-socket      AF_PACKET            # a socket family, added to the socket(2) rule
allow-netlink     NETLINK_NETFILTER    # a netlink protocol, added to the AF_NETLINK rule
```

- `allow-syscall NAME`: NAME must be in `seccomp::SYSCALL_NAMES` (the table is
  the vocabulary; an unknown name is an error, never ignored). A name that
  appears in `DENIED_RATIONALE` is **refused**: no policy file can re-enable
  `ptrace`, `mount`, `setns`, `bpf`, … The base denials are absolute.
- `allow-socket FAMILY`: one of `AF_PACKET`, `AF_NETLINK` (all protocols),
  `AF_KEY`, `AF_ALG`, `AF_VSOCK`, `AF_BLUETOOTH`, `AF_CAN`, `AF_RDS`,
  `AF_TIPC`, `AF_XDP` — named so the widening is visible in review. Any
  other family name is an error.
- `allow-netlink PROTO`: `NETLINK_ROUTE` (already allowed), `NETLINK_NETFILTER`,
  `NETLINK_KOBJECT_UEVENT`, `NETLINK_GENERIC`, `NETLINK_XFRM`, `NETLINK_AUDIT`.
  Adds the protocol to the `AF_NETLINK` branch; `allow-socket AF_NETLINK`
  removes the protocol check entirely.
- `[policy] landlock = ...` stays **unimplemented and refused** without the
  developer override (unchanged); a zone that names one is not started on the
  target. Landlock rules over a pivoted tree are a different design.

## Identities and privileged operations

None. The file is read by the parent `kryptikd run` (whatever it runs as),
before the fork, from the zone directory the operator named. The zone never
sees it. The resulting allowlist is installed in zone pid 1 exactly where the
base one is today.

## Failure behaviour

Any error in the file — unreadable, unknown directive, unknown name, a denied
syscall, a duplicate line, a name that is already in the base list (harmless
but flagged as a warning, not an error) — **refuses the launch** with the file
name and line number. A policy file that cannot be applied is a zone that
does not start. `kryptikd check` parses every zone's policy file and reports
the same errors, so a bad file is found before a launch.

`explain` prints the resulting additions: `seccomp    base + policy/net.seccomp:
+sethostname, socket AF_PACKET, netlink NETFILTER`.

## Invariants and acceptance tests

| id | check | expected |
|---|---|---|
| PF1 | a zone with `seccomp = "policy/x.seccomp"` and no such file | refused, names the path |
| PF2 | `allow-syscall ptrace` | refused: "ptrace is denied by the base policy and cannot be re-allowed" |
| PF3 | `allow-syscall nosuchcall` / `allow-socket AF_NOPE` / `frobnicate x` | refused with the line number |
| PF4 | `allow-socket AF_PACKET` in zone A; zone B has no policy | inside A: `socket(AF_PACKET, SOCK_RAW)` opens (root in userns has CAP_NET_RAW in its netns); inside B: errno 97 (positive control) |
| PF5 | `allow-netlink NETLINK_NETFILTER` | `socket(AF_NETLINK, SOCK_RAW, 12)` opens in that zone; 97 elsewhere |
| PF6 | `allow-syscall sethostname` | `hostname x` inside the zone succeeds (it has CAP_SYS_ADMIN over its UTS ns); without the line, SIGSYS (159) |
| PF7 | the whole base allowlist still evaluates ALLOW and every `DENIED_RATIONALE` entry KILL under a widened program (unit, interpreter) | as listed |
| PF8 | `check --zones` with a bad policy file | exit 1, names the file and line |
| PF9 | `explain` lists the additions | text present |

Files: `seccomp.rs` (`SYSCALL_NAMES`, `Policy`, `build_program_with` taking
extra syscalls and socket/netlink sets), `policy.rs` (parser), `spawn.rs`
(load at launch; install), `main.rs` (`check` parses; `explain`), unit tests,
`security/probes/fixed-checks.sh` PF rows (a fixture zone `packet` with
`policy/packet.seccomp`).


## Update: `[policy] landlock` is implemented (security increment 19)

The text above said a Landlock policy file stayed unimplemented and refused,
because "Landlock rules over a pivoted tree are a different design". The
different design turned out to be one sentence, and it is now built.

**A zone's policy file is a second Landlock layer, applied over the base
rules.** Landlock layers intersect: an access is permitted only if *every*
layer permits it. So a zone policy file can only ever narrow what the base
already allowed, and the kernel enforces that — not the parser, and not a
review of the file. A file asking for more than the base gave receives
nothing more. That is the whole safety argument, and it is why the feature no
longer needs to be refused.

It also settles the question the earlier note was stuck on. Rules are written
against the **pivoted** tree, as the zone sees it, and applied inside the
zone after `pivot_root` — the file is read and parsed in the parent, where
the zone directory is still reachable, so a file that does not parse stops
the launch before anything is built.

```text
# compartments/zones/policy/<name>.landlock
read-exec        /
read-write       /tmp
read-write       /dev
```

Directives: `read`, `read-exec`, `read-write`, `read-write-exec`. Each grants
those rights on the path and everything beneath it.

**There is deliberately no `deny`.** Landlock grants rights on a path
hierarchy; it has no subtraction. Expressing "all of `/home/w` except
`/home/w/.ssh`" would mean enumerating every sibling of `.ssh`, and would
silently stop denying the day someone added another one. Listing what the
zone may reach says the same thing and cannot rot that way.

Rules of the file, each of which is a refusal rather than a warning:

- Paths must be absolute and contain no `..`. A relative path would resolve
  against whatever the launcher's working directory happened to be.
- A path may be named only once.
- A file that grants nothing — empty, or only comments — is refused, because
  it would stop the zone reaching even its own binaries. Omitting
  `[policy] landlock` is how a zone asks for the base rules.
- A path that does not exist at apply time is an error. It would grant
  nothing either way, so the launch would otherwise continue with the zone
  quietly narrower than its file says, and a typo is far likelier than a
  deliberately absent path. An ephemeral zone should therefore name only
  paths that exist at launch, since its `$HOME` is a fresh tmpfs.

`kryptikd explain` prints the base rules, then the line
`-- and then narrowed by <file>, which grants only:` and the file's own
rules, so the two layers are never confused for one list.

**Evidence.** `landlock::tests` includes a kernel-backed test that builds two
layers in a forked child and checks all three properties that matter: a path
the second layer omits becomes unreachable although the first layer allowed
it; a path both layers allow still works; and a right the second layer asks
for but the first never granted is still denied — the last being the one that
would make the feature unsafe if it failed. The boundary probes exercise it
through the real launcher: a zone whose policy grants write only in `/tmp`
and `/dev` can no longer write its own `$HOME`, which the base rules alone
would allow, with a control zone showing the same write succeeding without a
policy file.

No shipped zone declares `[policy] landlock` yet. The six in
`compartments/zones/` keep the base rules until each one's needs are written
down deliberately.
