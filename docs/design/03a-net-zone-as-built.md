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
| forwarding | IPv4/IPv6 forwarding enabled in the nic zone's namespace | `13ba78f` |
| capabilities | routed zones can never keep `CAP_NET_ADMIN`/`CAP_NET_RAW`; only the nic zone may (its shipped policy keeps both, plus `AF_PACKET` and `NETLINK_NETFILTER`) | `13ba78f`, `0b7e082` |
| ICMP in routed zones | `ping_group_range` set by the parent in the zone's namespace | `13ba78f` |
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
