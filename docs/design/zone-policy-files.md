# Per-zone policy files: enforced, not parsed-and-ignored

Status: implemented (`policy.rs` for seccomp policy files, `landlock.rs` for
Landlock policy files). Depends on nothing. The [net zone](net-zone.md) needs
it: it must open `AF_PACKET` and `NETLINK_NETFILTER`, which the base policy
refuses.

A zone file can name two policy files under `[policy]`: `seccomp`, which
widens the base seccomp policy in a few named ways, and `landlock`, which
narrows the base Landlock rules. Both are read by the parent before anything
is built, and an error in either refuses the launch.

## Seccomp policy files

`[policy] seccomp = "policy/net.seccomp"` names a file **relative to the zone
directory** (`--zones DIR`), or an absolute path. It is not a language. It is
a list of additive directives, one per line, `#` comments, applied on top of
the shared base policy; it can widen the base in specific, named ways and
cannot narrow it or override a denial:

```text
# policy/net.seccomp
allow-syscall     sethostname          # a syscall by name, added to the allowlist
allow-socket      AF_PACKET            # a socket family, added to the socket(2) rule
allow-netlink     NETLINK_NETFILTER    # a netlink protocol, added to the AF_NETLINK rule
keep-capability   CAP_NET_RAW          # a capability left in the bounding set
```

- `allow-syscall NAME`: NAME must be in `seccomp::SYSCALL_NAMES` (the table is
  the vocabulary; an unknown name is an error, never ignored). A name that
  appears in `DENIED_RATIONALE` is **refused**: no policy file can re-enable
  `ptrace`, `mount`, `setns`, `bpf`, … The base denials are absolute.
- `allow-socket FAMILY`: one of `AF_PACKET`, `AF_NETLINK` (all protocols),
  `AF_KEY`, `AF_ALG`, `AF_VSOCK`, `AF_BLUETOOTH`, `AF_CAN`, `AF_RDS`,
  `AF_TIPC`, `AF_XDP`, named so the widening is visible in review. Any
  other family name is an error.
- `allow-netlink PROTO`: `NETLINK_ROUTE` (already allowed), `NETLINK_NETFILTER`,
  `NETLINK_KOBJECT_UEVENT`, `NETLINK_GENERIC`, `NETLINK_XFRM`, `NETLINK_AUDIT`.
  Adds the protocol to the `AF_NETLINK` branch; `allow-socket AF_NETLINK`
  removes the protocol check entirely.
- `keep-capability CAP`: leaves one capability in the zone's bounding set in
  addition to `CAP_NET_BIND_SERVICE`, which every zone keeps. Only the short
  list in `caps::KEEPABLE` may be named; no zone can keep `CAP_SYS_ADMIN`,
  `CAP_SYS_PTRACE`, `CAP_DAC_OVERRIDE` or the like by writing a line.
  `CAP_NET_ADMIN` and `CAP_NET_RAW` may be kept only by the zone that owns
  the NIC (`network.mode = "nic"`); a routed zone holding either could
  re-address its end of the veth or forge frames on the segment.

### Identities and privileged operations

None. The file is read by the parent `kryptikd run` (whatever it runs as),
before the fork, from the zone directory the operator named. The zone never
sees it. The resulting allowlist is installed in zone pid 1 exactly where the
base one is.

### Failure behaviour

Any error in the file (unreadable, unknown directive, unknown name, a denied
syscall, a capability outside the keepable list, a duplicate line)
**refuses the launch** with the file name and line number. A line that adds
nothing because the base already allows it is harmless and reported as a
warning, not an error. A policy file that cannot be applied is a zone that
does not start. `kryptikd check` parses every zone's policy file and reports
the same errors, so a bad file is found before a launch.

`explain` prints the resulting additions: `seccomp    base + policy/net.seccomp:
+sethostname, socket AF_PACKET, netlink NETFILTER`.

### Acceptance tests

| check | expected |
|---|---|
| a zone with `seccomp = "policy/x.seccomp"` and no such file | refused, names the path |
| `allow-syscall ptrace` | refused: "ptrace is denied by the base policy and cannot be re-allowed" |
| `allow-syscall nosuchcall` / `allow-socket AF_NOPE` / `frobnicate x` | refused with the line number |
| `allow-socket AF_PACKET` in zone A; zone B has no policy | inside A: `socket(AF_PACKET, SOCK_RAW)` gets past seccomp (it then opens only if the zone also keeps `CAP_NET_RAW`; otherwise the kernel returns EPERM); inside B: errno 97 (positive control) |
| `allow-netlink NETLINK_NETFILTER` | `socket(AF_NETLINK, SOCK_RAW, 12)` opens in that zone; 97 elsewhere |
| `allow-syscall sethostname` | `sethostname` inside the zone is no longer killed by seccomp; without the line, SIGSYS (159) |
| the whole base allowlist still evaluates ALLOW and every `DENIED_RATIONALE` entry KILL under a widened program (unit, interpreter) | as listed |
| `check --zones` with a bad policy file | exit 1, names the file and line |
| `explain` lists the additions | text present |

## Landlock policy files

**A zone's Landlock policy file is a second Landlock layer, applied over the
base rules.** Landlock layers intersect: an access is permitted only if
*every* layer permits it. So a zone policy file can only ever narrow what the
base already allowed, and the kernel enforces that, not the parser and not a
review of the file. A file asking for more than the base gave receives
nothing more. That is the whole safety argument.

Rules are written against the **pivoted** tree, as the zone sees it, and
applied inside the zone after `pivot_root`. The file is read and parsed in
the parent, where the zone directory is still reachable, so a file that does
not parse stops the launch before anything is built.

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
- A file that grants nothing (empty, or only comments) is refused, because
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
for but the first never granted is still denied. The last is the one that
would make the feature unsafe if it failed. The boundary probes
(`compartments/kryptikd/probes/boundary-checks.sh`) exercise it through the
real launcher: a zone whose policy grants write only in `/tmp` and `/dev` can
no longer write its own `$HOME`, which the base rules alone would allow, with
a control zone showing the same write succeeding without a policy file.

No shipped zone declares `[policy] landlock` yet. The six in
`compartments/zones/` keep the base rules until each one's needs are written
down deliberately.

## Files

`seccomp.rs` (`SYSCALL_NAMES`, `Policy`, `build_program_with` taking extra
syscalls and socket/netlink sets), `policy.rs` (the seccomp policy parser),
`caps.rs` (`KEEPABLE`), `landlock.rs` (`parse_policy` and the second layer),
`spawn.rs` (load at launch; install), `main.rs` (`check` parses; `explain`),
unit tests, and the boundary probes with their fixture zones in
`compartments/kryptikd/probes/`.
