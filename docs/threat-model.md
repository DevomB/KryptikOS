# Threat model

What Kryptik defends against, and what it does not. A design change that
contradicts the threat model changes the threat model first.

## Assets

1. Long-term secrets (keys, credentials), held in `vault`.
2. Per-identity data (documents, history, cookies), held in per-zone volumes.
3. Identity separation: that `work` and `personal` cannot be linked is an
   asset apart from either zone's contents.
4. Boot integrity: the code running is the code that was signed.

## Adversaries Kryptik defends against

### Malicious application

*Capability: arbitrary code execution as the user, inside one zone.*

**Defended.** The application sees only its own zone's files and processes,
has no route to the physical NIC, and runs under a default-deny seccomp
filter and a Landlock ruleset. Its `/proc` and `/sys` hide the machine-wide
interrupt, scheduling, load, page-fault and allocation, stall and open-file
counters, each CPU's idle counts and frequency (`/proc/cpuinfo` is a copy
taken as the zone starts), which would time keystrokes typed in any zone, and
the disk tables, which would show which encrypted zones are open; `/proc`
gives it a boot ID of its own. Still shown: the per-CPU packet counts in
`/proc/net/softnet_stat`, as `/proc/net` follows each process; the idle time
of all CPUs summed, to a hundredth of a second, in `/proc/uptime`, which `ps`
and `uptime` read; the free memory in `/proc/meminfo`, coarse, which programs
need; and the idle counts of a CPU brought online after the zone started.
Escaping needs a kernel bug
([kernel local privilege escalation](#kernel-local-privilege-escalation)).

### Malicious document or link

*Capability: an exploit for a parser in a viewer or browser.*

**Defended.** Opened in `untrusted`, which is ephemeral. The exploit gets a
tmpfs home that is freed when the zone stops, and a network path that is
already assumed hostile.

### Network attacker

*Capability: observes and modifies traffic, passively or on-path.*

**Partially defended.** Kryptik segments; it does not anonymize. A compromised
`net` zone gets no zone's files and not `vault`. Confidentiality on the wire
is the application's job.

### Compromised net zone

*Capability: root inside `net`, the one zone that holds the physical NICs,
through a flaw in what reads the network: DHCP, DNS, Wi-Fi, NTP, TLS, HTTP.*

**Contained, not prevented.** It gets no zone's files, not `vault` and not
zone 0, but every routed zone's traffic passes through it
([net zone](design/net-zone.md)).

It can still:

- read, alter, answer for or drop any routed zone's traffic, its DNS
  included, and route packets from one routed zone to another, since the
  bridge keeps its ports apart only from each other, not from the net zone's
  own routing;
- reach kernel code that no other zone can: nf_tables, packet sockets on its
  NICs and the bridge, and the generic-netlink commands a network namespace's
  administrator may use, among them the Wi-Fi drivers' vendor commands and
  ethtool's setters (offloads, rings, coalescing, EEE, and a pluggable
  module's firmware, from the images on the verified root); commands that
  need the initial namespace's administrator, devlink's among them, stay
  closed, and nl80211's testmode is not built;
- keep the machine offline, or a routed zone without its lookups or its
  bandwidth;
- read the passphrase of every Wi-Fi network it was given;
- withhold releases, which zone 0 reports once the newest statement is 30
  days old, or, where the image names a channel and none was accepted, the
  install, in `kryptik update status`, above the login prompt and in the
  launcher;
- claim the clock is off, which zone 0 applies up to an hour and beyond that
  only when the user agrees.

What limits it, each with its check, the zones suite's on the installed
system unless named:

- dhcpcd's parsers run as their own user in an empty root with no capability
  (`dhcpcd-separated`), and dnsmasq answers as the zone's `nobody`
  (`dnsmasq-unprivileged`), so a flaw in either does not get the zone's root;
- the update fetcher and the SNTP client give up every capability before they
  read a byte, under no new privileges (`fetch-and-sntp-no-caps`);
- the zone runs on one CPU's worth of time (`net-cpu-max-set`), and its `/sys`
  shows its own NICs and nothing else of the machine
  (`net-zone-sysfs-nics-only`);
- ethtool's ioctl, a PHY register write and the drivers' private ioctls are
  refused, so it cannot rewrite a NIC's EEPROM or flash that way (the unit
  test `nic_writing_ioctls_are_refused`);
- what it leaves on a NIC does not reach the next net zone: a name that is not
  plain becomes `nic<N>` (`uplink-renamed-plain`), the address, MTU,
  altnames and alias are set back (`uplink-state-reset`), Wake-on-LAN is
  turned off (no test machine's NIC has it, so no suite shows it), and a radio
  leaves with one fresh station (`radio-recarried`).

What a routed zone cannot do through it, proven the same way:

- send as another zone: the net zone takes in a routed zone's packets only
  from that zone's own addresses, pinned to its MAC (`zone-source-pinned`);
- reach what else listens in the net zone: from the bridge it takes in only
  DNS, echo requests, neighbour discovery and replies (`bridge-ports-closed`);
- fill the connection-tracking table: one routed zone holds at most an eighth
  of it (`zone-flows-capped`);
- learn another zone's lookups: the resolver keeps no cache and no query
  counts (`dns-cache-off`, `dns-counters-hidden`).

Kept by design:

- confidentiality between a zone and the net zone is the application's, as on
  any network;
- wpa_supplicant runs as the zone's root and reads every passphrase it was
  given, as it must to join those networks;
- nf_tables, packet sockets and generic netlink stay open to it, as NAT, DHCP
  and Wi-Fi need them;
- a routed zone that floods can hold the resolver's 150 forwarding slots, each
  for up to 10 s, and the uplink's bandwidth from the others: its share bounds
  its connections, not its queries or bytes;
- EEE, offloads, rings, coalescing and a radio's wake triggers (nl80211's
  WoWLAN) are not set back between net zones.

### Offline physical access

*Capability: the disk in hand, an evil maid, a stolen laptop; booting external
media.*

**Defended at rest against a reader, not against a writer of the state
partition.** dm-verity and Secure Boot make a modified root or a swapped kernel
fail to boot. The state partition (`/home`, `/var`, the Wi-Fi passphrases, the
shadow file, the `/etc` overlay, the zone volumes' headers) is LUKS2 with a
passphrase at every boot, and the zone volumes inside it are encrypted again;
a stolen disk gives up none of it. It is not authenticated: someone holding
the disk cannot choose new contents for a block, but can damage blocks,
destroy the header, or, with an earlier copy of the disk, put a block or the
header back as it was, so what the system honours from `/etc` without asking is
limited to a list on the verified root
([state partition](design/state-encryption.md)). The ESP, the root slots and
the LUKS header are in the clear, so the disk shows it is Kryptik.

**Not defended while running or suspended.** Keys are in RAM; see
[coercion, and access to a running or suspended machine](#coercion-and-access-to-a-running-or-suspended-machine).

### User error across zones

*Capability: the user pastes the wrong thing into the wrong window.*

**Partially defended.** This is the most common failure, which is why the
clipboard is brokered and zone borders are mandatory. A deliberate
cross-zone paste stays possible, because a system that forbids it gets
circumvented.

## Adversaries Kryptik does not defend against

### Kernel local privilege escalation

Every zone shares one kernel, so a working LPE compromises all of them at
once. [Hardening](hardening.md) raises the cost; it does not remove the class.

**If this is your threat model, use Qubes OS.** Its Xen hypervisor is a
smaller, separate trust boundary. Kryptik gives that up to run on hardware you
already own, at battery life you will tolerate (ADR-002).

### Firmware, hardware and supply-chain implants

UEFI implants, a compromised Management Engine, malicious microcode and
backdoored silicon sit below everything Kryptik controls. Secure Boot assumes
the firmware enforcing it is trustworthy, and device firmware and microcode
ship as vendor binaries (ADR-012).

### Coercion, and access to a running or suspended machine

Keys are in RAM while zones run. Cold-boot and DMA attacks on a running or
suspended machine are out of scope, and no software helps against coercion.

### Microarchitectural side channels

Shared caches and branch predictors allow cross-zone inference. The signed
command line carries `nosmt`, so no two zones share a core's threads. If SMT
were turned back on, a zone would not start without a core-scheduling cookie
of its own (ADR-011 in [decisions](decisions.md)). The cost of `nosmt` on real
hardware is not yet measured. Caches and predictors shared between cores, and
between a zone and the kernel, remain a known gap.

### Well-resourced targeted attack

Chained zero-days across kernel, compositor and firmware defeat this design.
Kryptik raises the cost substantially for commodity and criminal attackers,
not for an adversary willing to spend seven figures on you specifically.

### Traffic analysis

Out of scope. Kryptik separates identities on the host; it does not hide that
traffic came from you, and it ships no Tor or VPN uplink.

## Non-goals

- **Anonymity**: that is Tails and Whonix.
- **Offensive tooling**: Kryptik is a hardened workstation; run Kali in a zone.
- **Amnesia by default**: Kryptik is a daily driver with persistent state.
- **Beginner friendliness**: the zone model imposes real friction, and hiding
  it would weaken it.
