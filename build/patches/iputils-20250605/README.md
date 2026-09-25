# iputils 20250605: ping with no privilege makes no id calls

Applied by `s_iputils` in stage 04 through `apply_repo_patches`;
`SHA256SUMS` is verified before anything is applied.

Kryptik builds only `ping`, without libcap, and installs it with no setuid
bit and no file capability. In a routed zone it sends over the ICMP datagram
socket that `net.ipv4.ping_group_range` opens to the zone's group
(`docs/design/net-zone.md`). Built without libcap, ping still calls
`seteuid()` and `setuid()` to give up privilege it does not have, and exits
when one fails. A zone's seccomp filter answers every id call with EPERM, so
ping ended before its first packet.

The patch skips the three calls when ping starts with equal effective and
real uids, which is when there is nothing to drop. A setuid-root ping
behaves as upstream's. Not upstream when this was written. Delete this
directory when an iputils release carries an equivalent.
