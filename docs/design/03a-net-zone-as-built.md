# Design 03a — The net zone as built (security increments c501c5d…13ba78f)

Status: amendment to `03-net-zone-boundary.md`, recording what the code now
does and where it deliberately stops. Read this before the M3 review.

## Built

| Design 03 item | as built | commit |
|---|---|---|
| NIC ownership | `[network] nic = "eth0"` on the nic zone; the parent moves it into the zone's namespace during the handshake. Without the key the nic zone gets the bridge and no interface, and says so. | `0f4746e` |
| bridge | `kryptik0` 10.19.0.1/24, fd19::1/64 in the nic zone's namespace | `0f4746e` |
| routed zone attachment | veth pair created from inside the nic zone's namespace with the peer landing directly in the routed zone as `eth0`; bridge port isolated; addressed from the declared identity: `uid_base 131072 → .2`, `196608 → .3`, … (`netzone::host_number`); default routes to the bridge | `0f4746e` |
| gateway selection | the running zone whose **file** says `mode = "nic"` (zone directory, root-owned), never a namespace that happens to hold a bridge | `336004c` |
| port isolation (N5) | `IFLA_BRPORT_ISOLATED`, proven behaviourally in a kernel-backed unit test: isolated ports cannot deliver to each other, the bridge address is reachable, clearing the flag restores delivery | `c501c5d` |
| reconnection (N8) | a starting nic zone reattaches every running routed zone; a dead nic zone takes the peers with it (kernel), so routed zones fail closed until then | `acd0ad7` |
| DNS file | routed zones started with a path get `nameserver 10.19.0.1` / `fd19::1`; the nic zone gets a writable `/etc/resolv.conf` (symlink into its `/tmp`) for its DHCP client; unplumbed and offline zones have none | `8d940df` |
| nic zone state paths | the nic zone alone gets private tmpfs mounts at `/run` and `/var/lib` (empty at start, freed with the zone, Landlock write there and nowhere new), because its DHCP client keeps its pid file, control socket and lease database at the paths it was built with; every other zone's `/run` stays read-only with only the broker and proxy sockets in it. `dhcpcd` runs unseparated inside the zone (the synthesized passwd has no `dhcpcd` user); the zone is the sandbox. Found on the first installed system: `dhcpcd` died on `/run/dhcpcd` and no routed zone had a path | `rootfs::pivot_into`, `landlock::nic_zone_rules` |
| forwarding | IPv4/IPv6 forwarding enabled in the nic zone's namespace | `13ba78f` |
| capabilities | routed zones can never keep `CAP_NET_ADMIN`/`CAP_NET_RAW`; only the nic zone may (its shipped policy keeps both, plus `AF_PACKET`, `NETLINK_NETFILTER`, `NETLINK_GENERIC` - dhcpcd opens one at start for nl80211 and exits when refused - and `chown`) | `13ba78f`, `0b7e082` |
| ICMP in routed zones | `ping_group_range` set by the parent in the zone's namespace, naming the zone's own HOST gid (the sysctl takes host ids; the first installed system wrote `0 65534`, which mapped to nothing inside a zone with a real identity, and every echo socket was refused). A zone still has no `CAP_NET_RAW`, so inetutils `ping` fails there by design; the guest checks probe with an ICMP datagram socket (`build/guest-tests/icmp-echo.py`) | `13ba78f`, `netzone::attach_routed` |
| IPv6 | ULA `fd19::/64` on the bridge and zone ends; `accept_ra = 0` in routed zones; no global address ever reaches a routed zone | `0f4746e`, `13ba78f` |

## Not built, and why it is not a gap in the boundary

- **NAT.** Routed-zone addresses are forwarded unchanged. Behind QEMU user
  networking (which accepts any guest source) they reach the outside; behind
  a real NIC they do not, and `explain` says so on every routed zone. Needs
  nftables (`nft` in the image, or nf_tables netlink code); until then the
  world-reaching half of M3 is unproven and must be reported as such.
- **Stub resolver at 10.19.0.1.** `resolv.conf` already points there; nothing
  answers yet. Needs a resolver binary in the image.
- **MAC/IP port pinning (N4).** Designed for nftables `bridge` rules. Its
  purpose was to contain a zone that could re-address its end; that zone no
  longer exists (no `CAP_NET_ADMIN`/`CAP_NET_RAW` in routed zones), so N4 is
  defence in depth, not the boundary.
- **Deny direct traffic to slirp/host addresses from routed zones (N9).**
  Needs the forward-chain rules; today a routed zone can reach whatever the
  nic zone routes to, including the VM gateway. On a real system that is the
  nic zone's uplink and is the intended path.

## Two consequences worth stating

1. **A routed zone cannot escape port isolation at L3.** The only way past
   isolated ports is a host route via the bridge address, which requires
   `CAP_NET_ADMIN` in the zone's namespace, which no routed zone can keep.
   The nic zone can route between zones, and it is trusted to be the
   chokepoint (Design 03, "treated as hostile" refers to what it may reach,
   not to what it may do to zones behind it - a compromised nic zone can
   forward between routed zones; that is the documented cost of a single
   gateway and was already true in Design 03's nftables version, where the
   nic zone owns the rules).
2. **Addresses are identities.** 10.19.0.k is a function of `uid_base`, so
   the broker (Design 05) and any future policy can name zones by address as
   safely as by uid - as long as routed zones cannot change their address,
   which is the previous point.

## VM evidence to record

`security/probes/vm-topology.sh` T1–T10, root, `--nic user`. T9 (a routed
zone pings the VM gateway) is the forwarding path and is expected to pass
only under QEMU user networking; the report must say "forwarding, no NAT".


## Correction (security increment 15): the nic zone's namespace

Until increment 15, `isolate::namespace_flags` gave every zone its own network
namespace EXCEPT the nic zone, a Phase 5 rule ("it owns the real interface;
isolating it from itself is meaningless") written before the topology existed.
The topology code assumed the opposite: `plumb_nic_zone` opens the nic zone's
namespace and moves the NIC into it. With the flags as they were, that
namespace was zone 0's own, the move was a no-op, and the bridge, the
forwarding sysctls and every routed zone's port were created in zone 0.
Nothing measured it: NETR1 in the launcher suite checks that the nic zone
started, and the topology probe that asks whether eth0 left zone 0
(`vm-topology.sh` T1) had not yet run on a target kernel.

As of increment 15 the nic zone gets `CLONE_NEWNET` like every other zone, so
the move is real. Two consequences:

- **The uplink's configuration travels with the NIC.** The kernel flushes
  addresses and routes when an interface changes namespace. The parent reads
  the NIC's IPv4 addresses (`getifaddrs`) and default gateway
  (`/proc/self/net/route`) before the move and re-applies them inside the nic
  zone, then brings the interface up. No DHCP is spoken; what was there is what
  arrives, and a DHCP client running in the nic zone can take over the lease.
  Kernel-backed test: `the_uplink_configuration_travels_with_the_nic`.
- **Zone 0 loses its network path when the nic zone starts**, by design
  (Design 03). In the developer VM this is what `KRYPTIK_VM_DISPOSABLE=1`
  gates. When the nic zone exits, the kernel returns the physical interface to
  zone 0 down and unaddressed; kryptikd does not reconfigure zone 0.

IPv6 on the bridge is additive from increment 15, as it is on the routed side
from increment 14: a namespace where IPv6 cannot be configured still gets its
IPv4 path, and the launcher says so. Every zone's namespace also starts empty
from increment 14: the launcher raises `net.core.fb_tunnels_only_for_init_net`
to 1 before the namespace exists (the target kernel builds SIT in and put
`sit0` into an airgapped zone), and the child refuses, on a privileged launch,
to start in a namespace that holds anything besides loopback.
