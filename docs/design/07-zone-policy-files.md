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
