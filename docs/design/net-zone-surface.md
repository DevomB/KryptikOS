# Narrowing what the net zone reaches in the kernel

**A proposal, waiting for the owner's decision.** Nothing here is built. The
[threat model](../threat-model.md#compromised-net-zone) lists what a
compromised net zone still reaches. This note weighs three ways to narrow it:
a filter on generic-netlink families, wpa_supplicant's privilege separation,
and a time namespace per zone. It gives the cost of each from the tree and
Linux 6.18, and a recommendation. On the owner's word the decision becomes an
ADR in [decisions](../decisions.md), numbered then.

## What the net zone reaches that other zones do not

Its policy (`compartments/zones/policy/net.seccomp`) opens packet sockets
(`AF_PACKET`), `NETLINK_NETFILTER` and `NETLINK_GENERIC`, and keeps
`CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_SETUID`, `CAP_SETGID` and
`CAP_SYS_CHROOT`, each within its own namespaces. The programs that need them:

- `netzone-init.sh`'s `nft`: `NETLINK_NETFILTER` and `CAP_NET_ADMIN`, for NAT
  and the forwarding policy;
- dhcpcd: packet sockets, and generic netlink for nl80211's events, without
  which it exits; its root helper keeps `CAP_NET_ADMIN`, its parsers keep
  nothing;
- wpa_supplicant: nl80211 through generic netlink, and a packet socket for
  EAPOL, as the zone's root (`netzone-init.sh:204`).

Generic netlink is one protocol for every family the kernel builds, so the
policy cannot open nl80211 alone. A family's commands marked
`GENL_ADMIN_PERM` need the initial namespace's administrator and stay closed,
devlink's writes among them. The commands a namespace's administrator may use
(`GENL_UNS_ADMIN_PERM`) and the unprivileged ones are open: ethtool's setters
(offloads, rings, coalescing, EEE, and a pluggable module's firmware, from the
images on the verified root) and the Wi-Fi drivers' vendor commands among
them. The zone itself uses two families, `nlctrl` and `nl80211`.

## A filter on generic-netlink families

**What it would close.** Every family but `nlctrl` and `nl80211`: ethtool's
setters, and the namespace administrator's commands of any other family the
kernel builds.

**Where it could be enforced, from the tree.**

- **seccomp.** The zone's filter is classic BPF over a system call's
  arguments, and allows or refuses a netlink protocol at `socket(2)`
  (`seccomp.rs`, `allow-netlink`). The family is the `nlmsg_type` of a message
  that `sendmsg(2)` reaches through a pointer, which classic BPF cannot read.
- **seccomp's user notification.** kryptikd could read each message as a
  supervisor, but the zone can change it after that read, from another
  thread; `seccomp_unotify(2)` says the mechanism cannot implement a security
  policy.
- **Landlock.** In 6.18 it restricts files, TCP ports, signals and abstract
  unix sockets, not netlink.
- **A BPF LSM.** A program on the `netlink_send` hook sees the message.
  BPF is not built (`build/config/kernel/hardening.fragment:96-99`, with no
  `CGROUP_BPF`), the LSM list is `landlock,lockdown,yama` (`:202`), and loading
  a program needs `bpf(2)` and a loader in kryptikd: turning back on what the
  hardening turned off, for the whole machine.
- **A kernel patch.** An allowlist of family names per network namespace.
  Stage 05 applies linux-hardened's patch (ADR-009) and none of Kryptik's own;
  one would be ported at every LTS bump.

**Suites.** The zones suite would ask for an ethtool setter from the net
zone and expect a refusal, beside the Wi-Fi checks that need nl80211 to keep
working.

## wpa_supplicant's privilege separation

**Today.** wpa_supplicant runs as the zone's root with every capability the
zone keeps, and parses what the air sends: scan results, EAPOL and EAP. A
flaw there gets `CAP_NET_ADMIN` over nf_tables and the routes, and the
broker's socket.

**What hostap offers.** `CONFIG_PRIVSEP` (still in hostap 2.12's defconfig,
unset in `build/recipes/wpa-supplicant.sh`) splits the driver wrapper and
`l2_packet` into `wpa_priv`, which runs as root, and leaves EAP and the WPA
handshakes in a wpa_supplicant that runs as an unprivileged user and asks
`wpa_priv` over a unix socket (hostap's README, "Privilege separation"). The
README's other way, `CAP_NET_ADMIN` and `CAP_NET_RAW` without root, keeps the
network administrator's capability, so it narrows file access and not the
kernel.

**What it costs.**

- **What works.** The privsep wrapper (`src/drivers/driver_privsep.c`)
  implements scan, keys, authentication, association and a few events, and
  the README warns that it lags the full driver interface. Whether SAE, OWE
  and DPP, which the recipe builds (`wpa-supplicant.sh:16-18`), work through
  it is for the hwsim suite to show.
- **The build.** With `CONFIG_PRIVSEP`, wpa_supplicant drives only the privsep
  wrapper, so the zones suite's access point, the same binary in AP mode
  (`CONFIG_AP`, `wpa-supplicant.sh:12`), needs a build of its own.
- **The zone.** A fourth mapped id, beside root, dhcpcd's 100 and nobody;
  `wpa_priv`'s socket directory; `netzone-init.sh` starting `wpa_priv` for each
  radio, then wpa_supplicant as that user; and its control socket, which
  `netzone-init.sh:217` reads for the status line, moved where that user can
  create it.

**What it closes.** A flaw in what parses scan results, EAPOL or EAP gets an
unprivileged user with no capability, instead of the zone's root.

## A time namespace per zone

**Today.** Every zone, the net zone among them, reads the machine's
`CLOCK_MONOTONIC` and `CLOCK_BOOTTIME`, so `/proc/uptime` and every monotonic
timestamp agree across zones; the threat model names `/proc/uptime` as still
shown. It narrows no kernel surface; it is a reading that links zones.

**From 6.18.** `CONFIG_TIME_NS` is built: `init/Kconfig` defaults it to yes,
and no fragment unsets it. kryptikd creates no time namespace
(`isolate.rs`, `ZONE_NAMESPACES`).

**What it would take.** `CLONE_NEWTIME` beside `CLONE_NEWPID` in the
intermediate's `unshare`, as both apply to its children, and a random boot and
monotonic offset written to `/proc/self/timens_offsets` before pid 1 is forked
(`spawn.rs`); 6.18 refuses offsets once a task has entered
(`kernel/time/namespace.c`). Zones cannot make one themselves: their filter
answers `clone3(2)` with ENOSYS and `unshare(2)` with EPERM, and `clone(2)`
cannot ask for one, since `CLONE_NEWTIME` sits in its low byte, the exit
signal (`seccomp.rs`, `CLONE_NS_MASK`).

**What changes, and what does not.** A zone's `/proc/uptime` and the
`btime` of `/proc/stat` shift with its offset (`fs/proc/uptime.c:29`,
`fs/proc/stat.c:95-97`; `/proc/stat` is masked in zones anyway). The idle time
summed in `/proc/uptime` does not (`uptime.c:25`), nor does
`CLOCK_REALTIME`, which zone 0 sets for every zone. The zones suite would
compare a zone's `/proc/uptime` with zone 0's.

## Side by side

| | genl family filter | wpa_supplicant privsep | time namespace |
| --- | --- | --- | --- |
| closes | ethtool's setters, other families' namespace-admin commands | the zone's root for a flaw in Wi-Fi parsing | the shared boot and monotonic clocks |
| leaves | nf_tables, packet sockets, nl80211 | `wpa_priv` as root; the kernel's own 802.11 parsing | idle time, `CLOCK_REALTIME` |
| needs | BPF and a BPF LSM, or a kernel patch | a second build, a mapped id, a trial of WPA3 | a flag and an offsets write in kryptikd |
| a suite can show it | yes | yes, over hwsim | yes |

## Proposed decision

- **A time namespace per zone: build it.** Its cost is a flag and a write in
  kryptikd, it needs no kernel change, and a check can prove it.
- **wpa_supplicant's privilege separation: a trial first.** Build it beside
  the current binary and run the hwsim suite with WPA2 and SAE; adopt it only
  if the networks Kryptik supports still join.
- **The family filter: not now.** Each way to enforce it either builds BPF,
  which the hardening leaves out for the whole machine, or carries a kernel
  patch through every LTS bump, for families the zone's root alone reaches.
  It stays on the threat model's list of what a compromised net zone can
  still reach.
