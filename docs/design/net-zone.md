# The dedicated net zone

Status: implemented. NIC ownership, the bridge, routed-zone attachment, port
isolation, reconnection, NAT and the stub resolver are in the code
(`compartments/kryptikd/src/netzone.rs`, `netlink.rs`, `rootfs.rs`) and in
the net zone's own startup program (`tools/net/netzone-init.sh`, installed
as `/usr/libexec/kryptik/netzone-init.sh` and started by the `net-zone`
service). MAC/IP pinning of bridge ports and the refusal of direct traffic
to the uplink's own addresses are not built; see [As built](#as-built).
Builds on [the privileged launch design](privileged-launch.md) and
[resource limits and ephemeral zones](resource-limits-and-ephemeral-zones.md)
(root launch, supervision, the zone registry). The tests run in the
disposable VM with `-nic user` (slirp); no host NIC is touched.

## Topology

```text
 every physical NIC   ──moved into──▶  net zone netns
 (virtio eth0 in the VM; a laptop's       uplinks: DHCP (dhcpcd) on each, v4 + v6
  wlan0 goes by its wiphy)                wpa_supplicant on each radio, from zone 0's credentials file
                                          kryptik0 bridge: 10.19.0.1/24, fd19::1/64
                                          nftables: NAT out, forward bridge -> uplink only
                                          stub resolver (dnsmasq) bound to 10.19.0.1 / fd19::1
   veth pair per routed zone:  kv-<zone> (in net, on kryptik0, isolated port)  <──>  eth0 (in the zone's netns)
 zone 0:  lo only.  No eth0 after net starts; never an address on it before.
 vault:   lo only.  No veth is ever created for mode = "none".
```

## Ownership and who does what

- **Zone 0 never configures a NIC.** kryptikd moves every physical
  interface into the net zone's network namespace while the net zone is
  stopped at its handshake, before its seccomp filter. The zone file says
  what qualifies: `[network] nic = "*"` is every interface of zone 0 that
  sits on a bus device (`/sys/class/net/<n>/device` exists: PCI, USB, a
  platform device), which excludes loopback, bridges, veth ends and
  tunnels; a single name such as `"eth0"` is still accepted. Wired
  interfaces move by the netdev, wireless ones by their wiphy (see
  [Wireless uplinks](#wireless-uplinks)). kryptikd never guesses beyond
  that rule. Moving them needs `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` in the initial
  namespace: root kryptikd only. An unprivileged developer launch gets a
  note and a zone with loopback.
- **veths are created from inside the net zone's namespace.** For each
  routed zone, kryptikd creates the pair `kv-<zone>` / `eth0` from inside
  the net zone's namespace, with the peer landing directly in the routed
  zone's namespace as `eth0`, while the routed zone is paused at its
  handshake. `kv-<zone>` is enslaved to `kryptik0` and isolated
  (`IFLA_BRPORT_ISOLATED`). Addresses: the net side is the bridge; the zone
  side gets `10.19.0.<k>/24` and `fd19::<k>/64` with default routes via
  `10.19.0.1` / `fd19::1`, assigned by kryptikd from the zone's declared
  identity (`netzone::host_number`: `uid_base` 131072 is `.2`, 196608 is
  `.3`, and so on), not by DHCP: one less daemon in the zone and no
  broadcast domain games.
- **The routed zone owns its netns but not its port.** It can never keep
  `CAP_NET_ADMIN` or `CAP_NET_RAW`: the privileged launch drops the
  capability bounding set to `CAP_NET_BIND_SERVICE` alone, and
  `policy::check_for_zone` refuses a per-zone policy that would keep either
  network capability for a routed zone. `ip link set eth0 down` inside the
  zone fails with `EPERM`. The design also called for pinning each bridge
  port with nftables `bridge` family rules, so that traffic entering
  `kv-<zone>` is dropped unless its source MAC and IP are the assigned ones;
  that is defence in depth now and is not built. No frame is forwarded
  between two `kv-*` ports (port isolation), only `kv-* <-> uplink`.
- **The net zone is the chokepoint and is treated as hostile.** It gets no
  routed zone's data, no broker access to anything but its own clipboard,
  ephemeral storage (see
  [resource limits and ephemeral zones](resource-limits-and-ephemeral-zones.md)),
  and the base seccomp policy **plus** what `compartments/zones/policy/net.seccomp`
  adds: `AF_PACKET`, `NETLINK_NETFILTER`, `NETLINK_GENERIC` (dhcpcd opens
  one as it starts, for nl80211, and exits when refused), `chown` (dhcpcd
  chowns its control socket), and `CAP_NET_ADMIN` / `CAP_NET_RAW` over the
  interfaces it owns. This was the first per-zone policy file, which is
  why the `[policy]` mechanism ([zone policy files](zone-policy-files.md))
  was built alongside the net zone.

## DNS

The net zone runs a stub resolver (`dnsmasq`, from the base system) bound
to `10.19.0.1` and `fd19::1`, forwarding to the servers the uplink's DHCP
lease names (or QEMU user networking's `10.0.2.3` when nothing else is
known). The reserved test TLD (`.test`) is answered locally and never
forwarded, so the guest check that asks `10.19.0.1` for `kryptik.test`
measures the path to the resolver, not the internet. kryptikd synthesizes
`/etc/resolv.conf` inside each routed zone as `nameserver 10.19.0.1` /
`nameserver fd19::1` (`rootfs.rs`, next to `hosts`). Offline zones, and
routed zones started while no gateway was running, get no `resolv.conf`.
The net zone's own `resolv.conf` is a writable file in its ephemeral tree
(a symlink into its `/tmp`), written by dhcpcd.

## IPv6

Routed zones get a ULA (`fd19::/64`) and are masqueraded (NAT66) by the net
zone, as for v4. No RA, no SLAAC inside zones (`accept_ra = 0` set by
kryptikd in the zone's netns before handover); no global address ever
reaches a routed zone, so a routed zone cannot be addressed from outside.
IPv6 is additive: a namespace where it cannot be configured still gets its
IPv4 path, and the launcher says so. The design also set `disable_ipv6 = 1`
in **offline** zones' netns as belt and braces; kryptikd does not do this
today, and those zones have only `lo` either way.

## Wireless uplinks

A radio is an uplink like any other, with three differences.

**It moves by its wiphy.** The kernel marks a wireless netdev
namespace-local, so `RTM_SETLINK` with `IFLA_NET_NS_FD` answers `EINVAL`
for it. What moves is the wiphy: `NL80211_CMD_SET_WIPHY_NETNS` with
`NL80211_ATTR_WIPHY` and `NL80211_ATTR_NETNS_FD` over `NETLINK_GENERIC`
(the family id looked up by name from the controller family, since nl80211
has no fixed id), which is what `iw phy <phy> set netns` does. Every
interface on that wiphy goes along with its name; `wlan0` is `wlan0` inside.
`carry_nic` takes that path when `/sys/class/net/<n>/phy80211` exists and
the netdev path otherwise; the IPv4 configuration is carried the same way
for both. When the net zone's namespace is torn down, cfg80211 returns the
wiphy to the initial namespace on its own, so a dead net zone does not lose
the radio.

**It has to associate before it can lease.** Inside the zone,
`netzone-init.sh` finds its radios by the same `phy80211` link (by the link,
not by name: a second radio is `wlan1`) and starts one `wpa_supplicant` per
radio on `/etc/wpa_supplicant.conf`, with its control directory at
`/run/wpa_supplicant` and its pid file under `/run`. `dhcpcd` is given every
uplink and takes the radio's lease once it has a carrier. The readiness line
gains `wifi=`: `none` (no radio), `unconfigured` (a radio and no credentials
file), `connecting` (a supplicant running, not yet associated), or the SSID
it associated with, read from `wpa_cli status`. `READY` is printed before an
association completes and the line is printed again when that word
changes; a supplicant that dies is restarted, like the resolver.

**Somebody has to know the passphrase, and it is the net zone.** The
credentials live in zone 0 at `/var/lib/kryptik/wifi/wpa_supplicant.conf`,
written only by `kryptikd serve` on `kryptik wifi add <SSID>` (the
passphrase is read from the terminal and travels in the request body,
never on a command line or in a log), `kryptik wifi forget <SSID>` and
listed by `kryptik wifi list` (SSIDs only). The file is the format
wpa_supplicant reads (`network={ ssid="..." psk="..." }`, or a 64-hex-digit
`psk=` for a raw key), so kryptikd derives no keys itself. It is written by
temp-and-rename, owned by the net zone's identity (`uid_base:uid_base`,
mode 0400) in a root-owned 0711 directory: inside the zone root is host uid
N, and a root-owned 0600 file bound in would be unreadable to the one party
that must read it; on the host, nothing but that zone runs as N. At launch
kryptikd bind-mounts it read-only at `/etc/wpa_supplicant.conf` in the nic
zone (and only there, beside the zone's private `/run` and `/var/lib`), and
after a change the `net-zone` service is restarted (`s6-svc -r`) so the
ephemeral zone comes back with the new file; a developer daemon pointed at
another directory with `--wifi-dir` says instead that it restarted nothing.
Root, and the tests, reach the same code directly as
`kryptikd wifi list|add|forget`. `/var` is on `kryptik-state`, so the
passphrases are plaintext at rest, readable by root and the net zone's
identity: the same as NetworkManager's connection files, and the disk
encryption of the state partition is where a stolen laptop's protection
comes from, not this file's mode. A compromised net zone learns the
passphrases of every network it was given. It is the one party that must,
and that is all it learns: it still gets no routed zone's data and no
broker access beyond its own clipboard.

What the VM proves about this is bounded: QEMU has no radio, so the
acceptance run exercises the wired path and the credentials file, and the
wiphy move is proven by a root-only kernel-backed test on `mac80211_hwsim`
where the module exists. The first laptop will say whether
`wpa_supplicant` needs a syscall the zone's seccomp policy refuses: that
shows up as `SIGSYS` in the zone's log and `wifi=connecting` that never
changes.

## Gateway failure and reconnection

- If the net zone dies, the kernel deletes both ends of every veth whose
  net-side peer lived in the dead namespace. Routed zones therefore lose
  `eth0` entirely: **fail closed**, nothing to route through.
- When the net zone starts again, kryptikd reattaches every running routed
  zone from the zone directory and the registry
  (`/run/kryptik/zones/<name>/`): a new veth pair, the zone end moved into
  the running zone through the netns fd from `/proc/<pid1>/ns/net`, which
  kryptikd holds, and re-addressed. The zone sees `eth0` reappear. A routed
  zone keeps the `resolv.conf` it started with; one that started before any
  gateway gets a path on reattachment but no resolver until it is
  restarted, because kryptikd does not reach into a running zone's sealed
  root to change its files.
- Zone 0 keeps `lo` only while the net zone runs. When the net zone's
  namespace dies, the kernel returns the *physical* interface to the
  initial namespace, down and unaddressed; kryptikd leaves it that way and
  does not reconfigure zone 0, and the next net zone start moves it back.

## Invariants and tests (VM, root, `-nic user`, `ipv6=on` on the slirp NIC)

| invariant | test | positive control |
| --- | --- | --- |
| zone 0 has no external route, ever | on the host: `ip -o link` shows only `lo` after net starts; `ip route` empty; repeated 1 s after `kill -9` of the net zone's kryptikd (eth0 may reappear but must be down and unaddressed) | before net starts, `eth0` exists (unconfigured) |
| net owns the NIC | inside net: `eth0` up with a 10.0.2.x lease and a v6 address; `ping 10.0.2.2` and `ping6 fec0::2` (slirp gateway) succeed | — |
| a routed zone reaches the outside via net | inside `work`: `ip route` default via 10.19.0.1; a name lookup is answered by 10.19.0.1; an ICMP echo to the slirp gateway `10.0.2.2` succeeds through NAT | with net stopped, the same fails |
| port pinning (not built) | inside `work`: `ip addr flush eth0; ip addr add 10.19.0.1/24 dev eth0` fails with EPERM (bounding set); if it were allowed, frames with the wrong source would be dropped by the bridge rules | own address passes |
| no zone-to-zone traffic | `work` cannot `ping`/`nc` `personal`'s 10.19.0.x or fd19::x; `arping` gets no reply | both reach 10.19.0.1 |
| offline zones stay offline | inside `vault`: only `lo`; no `resolv.conf`; connecting to 10.19.0.1 fails with `ENETUNREACH` | `lo` ping works |
| no global v6 in a routed zone | inside `work`: only `fd19::x` and link-local; `ping6` of the slirp v6 gateway *succeeds* (via NAT66) | — |
| gateway failure fails closed | `kill -9` net; inside `work` `eth0` is gone within 1 s; name lookups fail | after net starts again, `eth0` is back and the outside is reachable again (reconnection) |
| DNS only via net | inside `work`: `resolv.conf` names 10.19.0.1 only; a query to `10.0.2.3` directly is dropped by the forward chain (not built; see below) | query to 10.19.0.1 answers |
| the net zone's seccomp is the widened per-zone policy and nobody else's | `socket(AF_PACKET)` is refused inside `work` and succeeds inside `net` | — |
| capability bounding set is `CAP_NET_BIND_SERVICE` only in routed zones | `grep CapBnd /proc/self/status` inside `work` = `0000000000000400` | `nc -l 80` works in `work` |

Inside a routed zone, inetutils `ping` fails by design (no `CAP_NET_RAW`);
the guest checks probe with an unprivileged ICMP datagram socket
(`build/guest-tests/icmp-echo.py`).

## Kernel requirements

`hardening.fragment` has `VETH` and `BRIDGE`; `boot.fragment` has
`NF_TABLES`, `NF_TABLES_INET`, `NF_TABLES_IPV4`, `NF_TABLES_IPV6`,
`NFT_NAT`, `NFT_MASQ`, `NFT_CT`, `NFT_REJECT`, `NF_NAT`, `NF_CONNTRACK` and
`NETFILTER_XT_MATCH_CONNTRACK`. `NF_TABLES_BRIDGE` and `BRIDGE_NETFILTER`
would be needed for port pinning and are not enabled. Deny `NFT_COMPAT`.
Keep `NETFILTER_XTABLES` off if nothing needs it. For radios: `CFG80211`,
`MAC80211` and `RFKILL` built in, the wireless drivers as signed modules
that eudev loads, and their firmware under `/lib/firmware` (the
`build/config/kernel/` fragments and stage 05 carry the current set).

## Non-goals here

No firewall policy language, no VPN/Tor plumbing (that is a net-zone
service later), no GUI. The routed address plan is fixed and documented; a
`[network] address = ...` key is refused.

## As built

This section records what the code does and where it deliberately stops.
Where it differs from the design above, it is the current truth.

| item | as built | where |
| --- | --- | --- |
| NIC ownership | `[network] nic = "*"` on the nic zone: every interface of zone 0 on a bus device (`netzone::physical_interfaces`), wired by `RTM_SETLINK`, wireless by `NL80211_CMD_SET_WIPHY_NETNS`; a single name is still accepted. The parent moves them during the handshake. With no such interface, or without the key, the nic zone gets the bridge and no uplink, and says so. | `netzone.rs`, `netlink.rs` |
| wireless bring-up | one `wpa_supplicant` per radio (found by `phy80211`) on the credentials file bound in from zone 0; `wifi=` in the readiness line from `wpa_cli status`; a dead supplicant restarted | `tools/net/netzone-init.sh` |
| credentials | `/var/lib/kryptik/wifi/wpa_supplicant.conf` in zone 0, written by `kryptikd serve` (`wifi-add`, `wifi-forget`, `wifi-list`) for `kryptik wifi`; owned by the net zone's identity, 0400, in a root 0711 directory; bound read-only at `/etc/wpa_supplicant.conf` in the nic zone; the net zone restarted after a change | `wifi.rs`, `serve.rs`, `rootfs.rs`, `tools/kryptik` |
| bridge | `kryptik0` 10.19.0.1/24, fd19::1/64 in the nic zone's namespace | `netzone.rs` |
| routed zone attachment | veth pair created from inside the nic zone's namespace with the peer landing directly in the routed zone as `eth0`; bridge port isolated; addressed from the declared identity (`netzone::host_number`); default routes to the bridge | `netzone::attach_routed` |
| gateway selection | the running zone whose **file** says `mode = "nic"` (zone directory, root-owned), never a namespace that happens to hold a bridge | `netzone.rs` |
| port isolation | `IFLA_BRPORT_ISOLATED`, proven behaviourally in a kernel-backed unit test: isolated ports cannot deliver to each other, the bridge address is reachable, clearing the flag restores delivery | `netlink.rs` |
| reconnection | a starting nic zone reattaches every running routed zone; a dead nic zone takes the peers with it (kernel), so routed zones fail closed until then | `netzone::replumb_routed_zones` |
| DNS file | routed zones started with a path get `nameserver 10.19.0.1` / `fd19::1`; the nic zone gets a writable `/etc/resolv.conf` (symlink into its `/tmp`) for its DHCP client; unplumbed and offline zones have none | `rootfs.rs` |
| nic zone state paths | the nic zone alone gets private tmpfs mounts at `/run` and `/var/lib` (empty at start, freed with the zone, Landlock write there and nowhere new), because its DHCP client keeps its pid file, control socket and lease database at the paths it was built with; every other zone's `/run` stays read-only with only the broker and proxy sockets in it. `dhcpcd` runs unseparated inside the zone (the synthesized passwd has no `dhcpcd` user); the zone is the sandbox. Found on the first installed system: `dhcpcd` died on `/run/dhcpcd` and no routed zone had a path | `rootfs::pivot_into`, `landlock::nic_zone_rules` |
| forwarding | kryptikd leaves IPv4/IPv6 forwarding **off** in the nic zone's namespace when it builds the bridge (written, not assumed: a new namespace may inherit zone 0's setting); `netzone-init.sh` turns it off again as its first act, on only once the nftables ruleset has loaded and been read back, and off if the ruleset ever disappears. The parent never opens the path itself: on a restart it reattaches every running routed zone during the same handshake, and with forwarding on before the policy loaded, those zones would be reachable from the uplink unfiltered | `netzone.rs`, `tools/net/netzone-init.sh` |
| NAT and forward policy | one atomic `nft -f` load of `table inet kryptik`: forward policy drop; established/related accepted; bridge to uplink accepted; bridge to bridge dropped; `10.19.0.0/24` and `fd19::/64` masqueraded out of the uplinks (one anonymous set of every uplink); new DNS connections arriving on an uplink dropped. The readiness line is `netzone: READY uplink=<addr> nat=yes dns=<yes/no> wifi=<ssid/connecting/unconfigured/none> bridge=kryptik0 uplinks=<list>` or `netzone: NOT READY <reason>` (forwarding off) | `tools/net/netzone-init.sh` |
| stub resolver | `dnsmasq` listening on 10.19.0.1, fd19::1 and 127.0.0.1, forwarding to the uplink's servers, restarted if it dies | `tools/net/netzone-init.sh` |
| time | `chronyd -Q` measures how far the machine's clock is from the time servers zone 0 names (`/etc/kryptik/time.conf`, the public pool without it) and sets nothing; the offset goes to zone 0 as a `time-offset` claim through the broker, and `time=` in the readiness line says what was measured or why nothing was. What zone 0 does with the claim is [the clock design](time.md) | `tools/net/netzone-init.sh` |
| uplink configuration | the parent reads the NIC's IPv4 addresses (`getifaddrs`) and default gateway (`/proc/self/net/route`) before the move and re-applies them inside the nic zone, then brings the interface up; `dhcpcd` then takes over the lease if a DHCP server answers. Kernel-backed test: `the_uplink_configuration_travels_with_the_nic` | `netzone.rs` |
| capabilities | routed zones can never keep `CAP_NET_ADMIN`/`CAP_NET_RAW`; only the nic zone may (its shipped policy keeps both, plus `AF_PACKET`, `NETLINK_NETFILTER`, `NETLINK_GENERIC` and `chown`) | `policy.rs`, `compartments/zones/policy/net.seccomp` |
| ICMP in routed zones | `ping_group_range` set by the parent in the zone's namespace, naming the zone's own HOST gid (the sysctl takes host ids; the first installed system wrote `0 65534`, which mapped to nothing inside a zone with a real identity, and every echo socket was refused) | `netzone::attach_routed` |
| IPv6 | ULA `fd19::/64` on the bridge and zone ends; `accept_ra = 0` in routed zones; no global address ever reaches a routed zone | `netzone.rs` |
| empty namespaces | every zone's namespace starts with loopback only: the launcher raises `net.core.fb_tunnels_only_for_init_net` to 1 before the namespace exists (the target kernel builds SIT in, and its first boot put `sit0` into an airgapped zone), and the child refuses, on a privileged launch, to start in a namespace that holds anything besides loopback | `netzone::suppress_fallback_tunnels` |

`kryptikd explain` says the same: a routed zone's path is an isolated port
on the bridge, and forwarding and NAT are the net zone's program's to enable
once its firewall is loaded. kryptikd does not inspect that program, so the
plan line states only what kryptikd itself sets up.

### Not built, and why it is not a gap in the boundary

- **MAC/IP port pinning.** Designed for nftables `bridge` rules. Its
  purpose was to contain a zone that could re-address its end; that zone no
  longer exists (no `CAP_NET_ADMIN`/`CAP_NET_RAW` in routed zones), so
  pinning is defence in depth, not the boundary.
- **Refusing direct traffic to the uplink's own addresses from routed
  zones.** The forward chain accepts anything from the bridge to the
  uplink, so a routed zone can address the VM gateway or the slirp resolver
  directly. On a real system that is the nic zone's uplink and is the
  intended path.

### Two consequences worth stating

1. **A routed zone cannot escape port isolation at L3.** The only way past
   isolated ports is a host route via the bridge address, which requires
   `CAP_NET_ADMIN` in the zone's namespace, which no routed zone can keep.
   The forward chain also drops bridge-to-bridge traffic. The nic zone can
   route between zones, and it is trusted to be the chokepoint ("treated as
   hostile" above refers to what it may reach, not to what it may do to
   zones behind it): a compromised nic zone can forward between routed
   zones. That is the documented cost of a single gateway, and it was
   already true of the design, in which the nic zone owns the rules.
2. **Addresses are identities.** 10.19.0.k is a function of `uid_base`, so
   [the broker](broker.md) and any future policy can name zones by address
   as safely as by uid, as long as routed zones cannot change their
   address, which is the previous point.

### The nic zone's own namespace

The nic zone once shared zone 0's network namespace: `isolate::namespace_flags`
gave every zone its own namespace except the nic zone, a rule ("it owns the
real interface; isolating it from itself is meaningless") written before the
topology existed. The topology code assumed the opposite: `plumb_nic_zone`
opens the nic zone's namespace and moves the NIC into it. With the flags as
they were, that namespace was zone 0's own, the move was a no-op, and the
bridge, the forwarding sysctls and every routed zone's port were created in
zone 0. Nothing measured it: the launcher suite checked only that the nic
zone started, and the VM topology check that asks whether `eth0` left zone 0
had not yet run on a target kernel.

The nic zone now gets `CLONE_NEWNET` like every other zone, so the move is
real, and two things follow. The uplink's configuration travels with the
NIC (the kernel flushes addresses and routes when an interface changes
namespace, so the parent carries them over, as in the table above). And
zone 0 loses its network path when the nic zone starts, by design; in the
developer VM this is what `KRYPTIK_VM_DISPOSABLE=1` gates.

### Evidence

- Unit and kernel-backed tests in `netzone.rs` and `netlink.rs`: host
  numbers from identities, port isolation behaviour, the uplink
  configuration carried across the move, forwarding left off by the bridge
  half, the bus-device rule counting no software device as physical, and
  (root only, on `mac80211_hwsim`) a wireless interface refusing to move on
  its own and moving by its wiphy, name intact, then returning when its
  namespace dies.
- The installed-system guest checks (`build/guest-tests/zones-check.sh`):
  the `net-zone` service is supervised and up and reports `READY` with
  `nat=yes`; `eth0` is no longer in zone 0, zone 0 has no default route and
  cannot reach the VM gateway; a routed zone gets its address from its
  identity, reaches the bridge, reaches the VM gateway through NAT, has a
  ULA and no global IPv6 address, and gets an answer from the resolver;
  one routed zone cannot reach another on the bridge; `vault` has loopback
  only; with the net zone down a routed zone has no egress; after a restart
  the net zone is `READY` again, a newly started zone has egress, and a zone
  that was running throughout has egress again.
