# Zone policy files

A zone file can name two policy files under `[policy]`: `seccomp` widens the
base seccomp policy in a few named ways, and `landlock` narrows the base
Landlock rules. Relative paths resolve against the zone directory. The parent
`kryptikd run` parses both before it builds anything, the zone never sees
them, and any error refuses the launch; `kryptikd check` reports the same
errors ahead of time.

## Seccomp policy files

One additive directive per line, `#` comments:

```text
allow-syscall     sched_setscheduler  # added to the allowlist
allow-socket      AF_PACKET           # added to the socket(2) rule
allow-netlink     NETLINK_NETFILTER   # added to the AF_NETLINK rule
keep-capability   CAP_NET_RAW         # left in the bounding set
```

- `allow-syscall`: a name from `seccomp::ADDABLE`. A syscall on the base
  denied list (`DENIED_RATIONALE`: `ptrace`, `mount`, `setns`, `bpf`, ...)
  cannot be re-allowed, one on the base allowlist is reported as already
  allowed, and any other name is an error. The id and capability calls on
  the denied list fail with EPERM instead of killing the caller; the trace
  paragraph below says why.
- `allow-socket`: `AF_PACKET`, `AF_KEY`, `AF_ALG`, `AF_VSOCK`, `AF_BLUETOOTH`,
  `AF_CAN`, `AF_RDS`, `AF_TIPC` or `AF_XDP`; `AF_NETLINK` drops the netlink
  protocol check. `socketpair(2)` stays `AF_UNIX` only whatever the file
  names: the kernel runs a family's create code before it asks for a pair.
- `allow-netlink`: `NETLINK_NETFILTER`, `NETLINK_KOBJECT_UEVENT`,
  `NETLINK_GENERIC`, `NETLINK_XFRM` or `NETLINK_AUDIT`.
- `keep-capability`: one of `caps::KEEPABLE`, kept besides
  `CAP_NET_BIND_SERVICE`, which every zone keeps. `CAP_NET_ADMIN` and
  `CAP_NET_RAW` are accepted only for the `network.mode = "nic"` zone
  (`Policy::check_for_zone`): with either, a routed zone could re-address its
  veth or forge frames. The chown, chmod and xattr calls are in the base
  list, so keeping `CAP_CHOWN`, `CAP_FOWNER` or `CAP_FSETID` takes effect
  with no `allow-syscall` line. A zone's user namespace maps only its root
  and nobody, so the most such a zone can do is move its own files between
  those two.

To find what a program needs, run it under the base filter with `kryptikd
seccomp-trace -- CMD [ARGS]`. Each call the filter would kill the program for
is printed as `KRYPTIK_SECCOMP_DENIED <nr> <name>` and fails with ENOSYS
instead, so one run lists them all rather than stopping at the first. A call
a zone gets an errno for rather than being killed is printed with `soft`
after its name and gets the same errno here:

- `inotify_init` and `inotify_init1` fail with ENOSYS: a watch on the `/usr`
  every zone shares would see each program started anywhere, and programs
  fall back to polling.
- The id and capability calls (the `set*id` family, `setgroups`, `capset`)
  fail with EPERM: ncurses brackets every terminfo open with `setfsuid` and
  `setfsgid`, and `sudo`, `su` and daemons that drop privilege as root call
  the rest, so a kill would take them down unexplained. They stay on the denied
  list, and no id or capability changes either way.

A printed name can go on an `allow-syscall` line unless it is on the denied
list; a call refused for its arguments (namespace flags to `clone`,
`TIOCSTI`) is printed under its syscall's name and stays refused. With
`--zone NAME` the trace runs under that zone's filter, its policy file
included, so a second run shows what is still refused.

An unknown directive or name, a denied syscall, a capability outside
`KEEPABLE`, a duplicate line or an unreadable file is an error that names the
file and line; a line the base already covers is a warning. Every shipped
zone names a policy file, and only `net.seccomp` adds anything. `kryptikd
explain` prints the additions:

```text
policy     policy/net.seccomp: socket AF_PACKET, netlink NETLINK_NETFILTER, netlink NETLINK_GENERIC, keep CAP_NET_ADMIN, keep CAP_NET_RAW
```

## Landlock policy files

The file is a second Landlock layer over the base rules. Layers intersect,
so it can only narrow what the base allows, and the kernel enforces that.

```text
read-exec        /
read-write       /tmp
read-write       /dev
```

`read`, `read-exec`, `read-write` and `read-write-exec` grant rights on a
path and everything beneath it, as the zone sees it; the layer is applied
inside the zone after `pivot_root`. There is no `deny`: Landlock cannot
subtract, and "`/home/w` except `.ssh`" would have to list every sibling of
`.ssh` and would stop denying when a new one appeared.

Refused: a relative path or one containing `..`; a path named twice; a file
that grants nothing (omit `[policy] landlock` to keep the base rules); a path
that does not exist when the layer is applied, since the zone would run
narrower than its file says (so an ephemeral zone should name only paths
that exist at launch); a path that is or passes through a symbolic link,
since a zone that can write a granted directory's parent could swap it for
a link to something wider and widen its own rule at its next start.
`explain` prints the base rules, then
`-- and then narrowed by <file>, which grants only:` and the file's rules.
No shipped zone has a Landlock policy yet.

## Tests

Unit tests in `policy.rs` and `seccomp.rs` (a widened program still refuses
what it does not name), and `landlock::tests::second_layer_narrows_never_widens`,
which builds two real layers and checks that the second can remove access
but never add it. The launcher suite's policy section checks kept
capabilities, the NIC-only rule, refusals and `explain`. The boundary suite
checks an allowed socket family against a zone without the policy, and that
a zone narrowed to `/tmp` and `/dev` cannot write its `$HOME` while a control
zone can, and that a zone which swaps a granted directory for a link to its
`$HOME` is refused at its next start.

## Files

`seccomp.rs`, `policy.rs`, `caps.rs` (`KEEPABLE`), `landlock.rs`
(`parse_policy`), `spawn.rs`, `main.rs` (`check`, `explain`), the policies in
`compartments/zones/policy/`, and the fixture zones in
`compartments/kryptikd/probes/`.
