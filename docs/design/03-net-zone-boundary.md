# Design 03 — The dedicated net zone (M3)

Status: security design for Opus. Depends on Designs 01 and 02 (root launch,
supervision, a zone registry). Everything here runs in the disposable VM
with `-nic user` (slirp); no host NIC is touched.

## Topology

```
 VM NIC (virtio eth0)  ──moved into──▶  net zone netns
                                          eth0: DHCP (udhcpc), v4 + v6
                                          kryptik0 bridge: 10.19.0.1/24, fd19::1/64
                                          nftables: NAT out, port isolation, uplink-only
                                          stub resolver bound to 10.19.0.1 / fd19::1
   veth pair per routed zone:  kv-<zone> (in net, on kryptik0)  <──>  eth0 (in the zone's netns)
 zone 0:  lo only.  No eth0 after net starts; never an address on it before.
 vault:   lo only.  No veth is ever created for mode = "none".
```

## Ownership and who does what

- **Zone 0 never configures the NIC.** kryptikd moves `eth0` into the net
  zone's network namespace (`RTM_NEWLINK` with `IFLA_NET_NS_PID`, or
  `ip link set eth0 netns <pid>` via the `ip` binary in zone 0) while the
  net zone is stopped at the `mapped` handshake, before its seccomp filter.
  Needs `CAP_NET_ADMIN` in the initial namespace: root kryptikd only.
- **veths are created in zone 0 and handed over.** For each routed zone:
  create `kv-<zone>` + `kz-<zone>`, move `kv-<zone>` into net's netns and
  `kz-<zone>` into the routed zone's netns (renamed `eth0` there), both
  while the receiving zone is paused at its handshake. Addresses: net side
  is the bridge; zone side gets `10.19.0.<k>/24` and `fd19::<k>/64` with
  default route `10.19.0.1` / `fd19::1`, assigned by kryptikd (static, from
  the zone registry), not by DHCP — one less daemon in the zone and no
  broadcast domain games.
- **The routed zone owns its netns but not its port.** It has
  `CAP_NET_ADMIN` there (Design 01 P5 drops the bounding set inside the zone
  as part of this milestone: keep only `CAP_NET_BIND_SERVICE`, tested by
  `ip link set eth0 down` failing with `EPERM`). Even so, assume the zone
  can change its MAC and IP: the net zone pins each bridge port with
  nftables `bridge` family rules — traffic entering `kv-<zone>` is dropped
  unless source MAC and IP are the assigned ones, and no frame is forwarded
  between two `kv-*` ports, only `kv-* <-> uplink`.
- **The net zone is the chokepoint and is treated as hostile.** It gets no
  routed zone's data, no broker access to anything but its own clipboard,
  ephemeral storage (Design 02), and the base seccomp policy **plus**
  `AF_PACKET` and `AF_NETLINK/NETLINK_NETFILTER` in its per-zone policy
  (needed by udhcpc and nftables) — the first per-zone policy file, and the
  reason the `[policy]` mechanism gets implemented in this milestone rather
  than later.

## DNS

The net zone runs a stub resolver (`unbound` or `dnsmasq`, from the base
system) bound to `10.19.0.1` and `fd19::1`, forwarding to the DHCP-provided
servers. kryptikd synthesizes `/etc/resolv.conf` inside each routed zone as
`nameserver 10.19.0.1` / `nameserver fd19::1` (`rootfs.rs`, next to `hosts`).
Offline zones get no `resolv.conf`. The net zone's own `resolv.conf` is
whatever udhcpc writes, inside its ephemeral tree.

## IPv6

Routed zones get a ULA (`fd19::/64`) and are masqueraded (NAT66) by the net
zone, same as v4. No RA, no SLAAC inside zones (`accept_ra = 0` set by
kryptikd in the zone's netns before handover); no global address ever
reaches a routed zone, so a routed zone cannot be addressed from outside.
`disable_ipv6 = 1` in **offline** zones' netns (belt and braces; they have
only `lo`).

## Gateway failure and reconnection

- If the net zone dies, the kernel deletes both ends of every veth whose
  net-side peer lived in the dead namespace. Routed zones therefore lose
  `eth0` entirely: **fail closed**, nothing to route through. Invariant N8.
- On net restart, kryptikd re-plumbs every running routed zone from the
  registry (Design 02's `/run/kryptik/zones/<name>/`): new veth pair, move
  the zone end in (the zone is not paused now; moving an interface into a
  running namespace needs only the `netns` fd from `/proc/<pid1>/ns/net`,
  which kryptikd holds), re-address it. The zone sees `eth0` reappear.
- Zone 0 keeps `lo` only throughout; a dead net zone does not return `eth0`
  to zone 0 (the kernel returns a *physical* interface to the initial netns
  when its namespace dies — **kryptikd must immediately move it back into
  the restarted net zone, and until then bring it `down` and leave it
  unaddressed**; N1 is tested across a net crash for exactly this reason).

## Invariants and tests (VM, root, `-nic user`, `ipv6=on` on the slirp NIC)

| id | invariant | test | positive control |
|---|---|---|---|
| N1 | zone 0 has no external route, ever | on the host: `ip -o link` shows only `lo` after net starts; `ip route` empty; repeated 1 s after `kill -9` of the net zone's kryptikd (eth0 may reappear but must be down and unaddressed) | before net starts, `eth0` exists (unconfigured) |
| N2 | net owns the NIC | inside net: `eth0` up with a 10.0.2.x lease and a v6 address; `ping 10.0.2.2` and `ping6 fec0::2` (slirp gateway) succeed | — |
| N3 | routed zone reaches the outside via net | inside `work`: `ip route` default via 10.19.0.1; TCP to `10.0.2.2:80`… slirp has no server there — use the slirp DNS `nslookup example.com` → answer from 10.19.0.1; `curl http://10.0.2.2/` with `-nic user,restrict=off` + a host-side `-netdev user,…,guestfwd=` echo service | with net stopped, the same fails |
| N4 | port pinning | inside `work`: `ip addr flush eth0; ip addr add 10.19.0.1/24 dev eth0` fails with EPERM (bounding set); if it were allowed, frames with the wrong source are dropped by the bridge rules (test with a raw `sendto` after temporarily granting the cap in a test build) | own address passes |
| N5 | no zone-to-zone traffic | `work` cannot `ping`/`nc` `personal`'s 10.19.0.x or fd19::x; `arping` gets no reply | both reach 10.19.0.1 |
| N6 | offline zones stay offline | inside `vault`: only `lo`; `disable_ipv6 = 1`; no `resolv.conf`; connecting to 10.19.0.1 fails with `ENETUNREACH` | `lo` ping works |
| N7 | no global v6 in a routed zone | inside `work`: only `fd19::x` and link-local; `ping6` of the slirp v6 gateway *succeeds* (via NAT66) | — |
| N8 | gateway failure fails closed | `kill -9` net; inside `work` `eth0` is gone within 1 s; `nslookup` fails | after `kryptikd run net` again, `eth0` is back and N3 passes (reconnection) |
| N9 | DNS only via net | inside `work`: `resolv.conf` names 10.19.0.1 only; a query to `10.0.2.3` directly is dropped by the bridge rules (dst must be the bridge or via NAT — routed zones may only talk to the net zone's address and, through NAT, beyond; direct slirp addresses are refused by the forward chain) | query to 10.19.0.1 answers |
| N10 | the net zone's seccomp is the widened per-zone policy and nobody else's | `kryptikd seccomp-test socket-packet` inside `work` → 7; inside `net` → 0 | — |
| N11 | capability bounding set is empty in zones | `grep CapBnd /proc/self/status` inside `work` = `0000000000000400` (NET_BIND_SERVICE only) | `nc -l 80` works in `work` |

## Kernel requirements (build tab)

`hardening.fragment` has `VETH`, `BRIDGE`. Add: `NF_TABLES`, `NF_TABLES_INET`,
`NF_TABLES_BRIDGE`, `NFT_NAT`, `NF_NAT`, `NFT_MASQ`, `NF_CONNTRACK`,
`NF_TABLES_IPV6`, `IPV6`, `BRIDGE_NETFILTER`, `NETFILTER_XT_MATCH_CONNTRACK`
(or the nft equivalents). Deny `NFT_COMPAT`. Keep `NETFILTER_XTABLES` off
if nothing needs it.

## Non-goals here

No firewall policy language, no VPN/Tor plumbing (that is a net-zone
service later), no GUI. The routed address plan is fixed and documented; a
`[network] address = ...` key is refused.
