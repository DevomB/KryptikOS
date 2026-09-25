# Net zone

One zone, the net zone (`network.mode = "nic"`), holds every physical network
interface. Zone 0 never configures one and keeps only loopback once the net
zone runs. A routed zone reaches the network through an isolated port on the
net zone's bridge; an offline zone (`mode = "none"`) has loopback only. The
net zone runs DHCP, Wi-Fi, NAT, the zones' resolver, the [clock](time.md)
query and the [update](update-channel.md) fetcher. Builds on
[privileged launch](privileged-launch.md) and the
[zone registry](zone-registry.md).

## Topology

```text
 every physical NIC   ──moved into──▶  net zone netns
 (eth0; a radio moves by its wiphy)       uplinks: DHCP (dhcpcd) on each, v4 + v6
                                          wpa_supplicant on each radio, from zone 0's credentials file
                                          kryptik0 bridge: 10.19.0.1/24, fd19::1/64
                                          nftables: NAT out, forward bridge -> uplink only
                                          stub resolver (dnsmasq) on 10.19.0.1 / fd19::1
   veth pair per routed zone:  kv-<zone> (in net, on kryptik0, isolated port)  <──>  eth0 (in the zone's netns)
 zone 0:  lo only once net runs; never an address on a NIC before that.
 vault:   lo only. No veth is ever created for mode = "none".
```

## Who does what

- **Zone 0 never configures a NIC.** Every zone, the net zone included, has
  its own network namespace. While the net zone waits at its handshake,
  before its seccomp filter, kryptikd moves every physical interface into it.
  `[network] nic = "*"` means every interface of zone 0 on a bus device
  (`/sys/class/net/<n>/device` exists), which excludes loopback, bridges,
  veths and tunnels; a single interface name also works. A move flushes
  addresses and routes, so the parent reads the IPv4 addresses and default
  gateway first and re-applies them inside; dhcpcd takes over if a DHCP
  server answers. Moving needs `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` in the
  initial namespace, so an unprivileged launch gets loopback and a note.
- **veths are created from inside the net zone's namespace.** While a routed
  zone waits at its handshake, kryptikd creates `kv-<zone>` in the net zone
  with its peer born in the routed zone as `eth0`, enslaves `kv-<zone>` to
  `kryptik0` and isolates the port (`IFLA_BRPORT_ISOLATED`), so no frame
  passes between two `kv-*` ports. The zone's addresses, `10.19.0.<k>/24` and
  `fd19::<k>/64` with default routes via the bridge, follow from its declared
  identity (`netzone::host_number`: `uid_base` 131072 is `.2`, 196608 is `.3`,
  and so on), not from DHCP: one less daemon, no broadcast domain.
  `accept_ra = 0` is set first, and `ping_group_range` names the zone's host
  gid so unprivileged ICMP echo works (the sysctl takes host ids, so the
  parent writes it). The image's `ping` is iputils', built without libcap and
  given no setuid bit or file capability: it sends over that datagram socket,
  IPv4 and IPv6, and a patch keeps it from the id calls a zone refuses
  (`build/patches/iputils-20250605`).
- **The gateway is chosen by zone file.** Routed zones attach to the running
  zone whose root-owned file says `mode = "nic"`, never to whatever namespace
  holds a bridge: a zone could create its own `kryptik0`.
- **A routed zone owns its namespace, not its port.** Its bounding set is
  `CAP_NET_BIND_SERVICE`, `policy::check_for_zone` refuses a policy keeping
  `CAP_NET_ADMIN` or `CAP_NET_RAW`, and seccomp refuses packet sockets. It
  cannot change its address or MAC, send from another address, or put a frame
  on the wire that the kernel did not build; `ip link set eth0 down` fails
  with `EPERM`.
- **Every namespace starts with loopback only.** The kernel builds SIT in, so
  the launcher sets `net.core.fb_tunnels_only_for_init_net = 1` first, and a
  privileged launch refuses a namespace holding anything else.
- **The net zone is the chokepoint and is treated as hostile.** It gets no
  routed zone's data, no broker access beyond its own clipboard and the time
  and update verbs, ephemeral storage, and the base seccomp policy plus
  `policy/net.seccomp`: `AF_PACKET`, `NETLINK_NETFILTER`, `NETLINK_GENERIC`
  (dhcpcd opens one for nl80211 and exits if refused), `chown` (dhcpcd chowns
  its control socket), and `CAP_NET_ADMIN` / `CAP_NET_RAW` over its own
  interfaces. It alone gets private tmpfs mounts at `/run` and `/var/lib`
  (writable under Landlock, no exec), where dhcpcd keeps its pid file,
  control socket and leases; every other zone's `/run` is read-only and holds
  only its broker and proxy sockets.

## The net zone's program

`tools/net/netzone-init.sh`, started by the `net-zone` service:

- **Forwarding waits for the firewall.** kryptikd writes IPv4 and IPv6
  forwarding off when it builds the bridge (a new namespace may inherit zone
  0's setting). The script turns it off again, loads `table inet kryptik` in
  one atomic `nft -f`, reads it back, and only then turns forwarding on; if
  the table disappears, forwarding goes off. kryptikd never turns it on: on a
  restart it reattaches running routed zones during the handshake, and with
  forwarding on before the policy they would be reachable from the uplink.
- **The ruleset:** forward policy drop; established and related accepted;
  bridge to uplink accepted; bridge to bridge dropped; `10.19.0.0/24` and
  `fd19::/64` masqueraded out of every uplink; new DNS connections arriving on
  an uplink dropped.
- **The resolver:** `dnsmasq` on 10.19.0.1, fd19::1 and 127.0.0.1,
  forwarding to the uplink lease's servers (QEMU's 10.0.2.3 when nothing else
  is known), restarted if it dies. It answers the test TLD `.test` itself, so
  resolving `kryptik.test` tests the path to the resolver, not the internet.
- **dhcpcd runs without its own privilege separation.** That needs
  `setgroups`, which the zone denies, a `dhcpcd` user, which its synthesized
  passwd lacks, and `CAP_SETUID`, `CAP_SETGID` and `CAP_SYS_CHROOT`. Giving
  the hostile zone three capabilities so one program can build a smaller
  sandbox inside it would be a net loss; the zone is the sandbox.
- **Readiness**, printed again on any change:

```text
netzone: READY uplink=<addr|none> nat=yes dns=<yes|no> wifi=<ssid|connecting|unconfigured|none> time=<offset|no-answer|...> bridge=kryptik0 uplinks=<list>
netzone: NOT READY <reason>        (forwarding off)
```

## DNS

kryptikd writes each routed zone's `/etc/resolv.conf` as
`nameserver 10.19.0.1` and `nameserver fd19::1` (`rootfs.rs`). Offline zones,
and routed zones started while no net zone ran, get none. The net zone's own
`resolv.conf` is a symlink into its `/tmp`, written by dhcpcd.

## IPv6

Routed zones get ULA addresses (`fd19::/64`), masqueraded like IPv4. With no
RA or SLAAC (`accept_ra = 0`), no global address reaches a routed zone, so
nothing outside can address it. IPv6 is additive: where it cannot be
configured the zone keeps its IPv4 path and the launcher says so.

## Wireless uplinks

- **A radio moves by its wiphy.** A wireless netdev is namespace-local
  (`RTM_SETLINK` with `IFLA_NET_NS_FD` answers `EINVAL`), so kryptikd sends
  `NL80211_CMD_SET_WIPHY_NETNS` over `NETLINK_GENERIC` (the family looked up
  by name), as `iw phy <phy> set netns` does, whenever
  `/sys/class/net/<n>/phy80211` exists. Every interface on the wiphy moves
  with its name, and cfg80211 returns the wiphy to the initial namespace when
  the net zone's namespace dies.
- **It associates before it leases.** The script finds radios by their
  `phy80211` link, not by name, and runs one `wpa_supplicant` per radio on
  `/etc/wpa_supplicant.conf`, restarting one that dies; dhcpcd takes the
  lease once there is a carrier. `wifi=` is `none`, `unconfigured` (no
  credentials), `connecting`, or the associated SSID; `READY` does not wait
  for association.
- **The net zone knows the passphrases.** They live in zone 0 at
  `/var/lib/kryptik/wifi/wpa_supplicant.conf`, written only by `kryptikd serve`
  for `kryptik wifi add|forget <SSID>`; the passphrase is read on the terminal
  and never appears on a command line or in a log, and `kryptik wifi list`
  shows SSIDs only. The file is in wpa_supplicant's own format, so kryptikd
  derives no keys. It is rewritten by temp-and-rename, 0400, owned by the net
  zone's identity in a root-owned 0711 directory: the zone's root is host uid
  N, so a root-owned 0600 file would be unreadable to it, and nothing else
  runs as N. It is bound read-only at `/etc/wpa_supplicant.conf` in the net zone only,
  and a change restarts the `net-zone` service (`s6-svc -r`).
- On disk the file is plaintext inside the [encrypted](state-encryption.md)
  state partition, like NetworkManager's connection files. A compromised net
  zone learns the passphrases of the networks it was given, and nothing more.

QEMU has no radio, so the installed system is tested on the wired path; the
wiphy move is tested on `mac80211_hwsim` (below). On real hardware, a seccomp
refusal of `wpa_supplicant` would show as `SIGSYS` in the zone's log and a
`wifi=connecting` that never changes.

## Gateway failure

- If the net zone dies, the kernel deletes both ends of every veth whose net
  side lived in its namespace: routed zones lose `eth0` and fail closed.
- When it starts again, kryptikd reattaches every running routed zone in the
  registry with a new veth pair, moved in through the zone's namespace
  (`/proc/<pid 1>/ns/net`). A zone keeps the `resolv.conf` it started with, so
  one started before any net zone gets a path but no resolver until it
  restarts; kryptikd does not edit a running zone's sealed root.
- The kernel returns the physical interface to the initial namespace, down
  and unaddressed; kryptikd leaves it so until the next net zone start.

## What this guarantees

- Zone 0 has no external route while the net zone runs, and never an address
  on a NIC. Offline zones stay offline.
- Routed zones cannot reach each other: ports are isolated at L2 and the
  forward chain drops bridge-to-bridge traffic. The only way past isolated
  ports is a host route via the bridge address, which needs `CAP_NET_ADMIN`
  in the zone. A compromised net zone can forward between routed zones; that
  is the cost of a single gateway, which owns the rules either way. "Treated
  as hostile" limits what the net zone can reach, not what it can do to the
  zones behind it.
- Addresses are identities: 10.19.0.k follows from `uid_base`, so the broker
  or a future policy can name zones by address as safely as by uid, as long
  as routed zones cannot change their address.

## Not built

- **MAC/IP pinning of bridge ports** (nftables `bridge` rules dropping frames
  with a source that is not the assigned one). A routed zone already cannot
  re-address itself or forge frames. Pinning would check that again inside the
  hostile net zone, and need `NF_TABLES_BRIDGE` and `BRIDGE_NETFILTER` built
  in: more kernel reachable from a hostile zone for no new guarantee. Revisit
  if a routed zone may ever keep either network capability.
- **Refusing routed-zone traffic to the uplink's own addresses.** The forward
  chain accepts anything from the bridge to the uplink, so a routed zone can
  address the VM gateway or QEMU's resolver directly; on real hardware that
  is the uplink, the intended path.

## Tests

- `netzone.rs` and `netlink.rs` unit and kernel-backed tests: host numbers,
  isolated ports blocking delivery between zones while the bridge address
  stays reachable (`netlink::tests::isolated_ports_block_zone_to_zone`), the
  uplink configuration carried across the move
  (`netzone::tests::uplink_config_travels_with_nic`), forwarding written off,
  only bus devices counting as physical, and, as root on `mac80211_hwsim`, a
  radio refusing to move as a netdev and moving by its wiphy
  (`netlink::tests::wireless_moves_by_wiphy`).
- `wifi.rs` unit tests and the serve and cli suites cover the credentials
  file and `kryptik wifi`.
- The launcher suite reads a zone's bounding set (exactly `0x400`) and the
  boundary suite asks for an `AF_PACKET` socket. The launcher suite's
  routed-networking section runs only with `KRYPTIK_VM_DISPOSABLE=1`, since
  starting the net zone takes the host's interface.
- `build/guest-tests/zones-check.sh` on the installed system checks every
  guarantee above under QEMU user networking: the net zone `READY`, zone 0
  offline, a routed zone's address, NAT, ULA-only IPv6 and resolver, zones
  separated, `vault` offline, no egress while the net zone is down, and
  reattachment after a restart. It pings with an unprivileged ICMP socket
  (`build/guest-tests/icmp-echo.py`), since routed zones lack `CAP_NET_RAW`.

## Kernel requirements

`VETH` and `BRIDGE` (`hardening.fragment`). Built in (`boot.fragment`):
`NF_TABLES`, `NF_TABLES_INET`, `NF_TABLES_IPV4`, `NF_TABLES_IPV6`, `NFT_NAT`,
`NFT_MASQ`, `NFT_CT`, `NFT_REJECT`, `NF_NAT` and `NF_CONNTRACK`; netfilter
cannot be modular because the net zone loads its ruleset from inside a user
namespace, for which the kernel does not autoload modules.
`NF_TABLES_BRIDGE` and `BRIDGE_NETFILTER` are off; `NFT_COMPAT` is not
wanted. xtables (`IP_NF_IPTABLES`, `IP6_NF_IPTABLES`, `NETFILTER_XTABLES`) and
ctnetlink (`NF_CT_NETLINK`) are off: the ruleset is nft's alone, and
ctnetlink would be kernel code the nic zone reaches through its netfilter
netlink socket for no use. For radios, `CFG80211`, `MAC80211`, `RFKILL` and
the drivers are signed modules that eudev loads, with firmware under
`/lib/firmware` (see `build/config/kernel/`).

## Non-goals

No firewall policy language, no VPN or Tor plumbing (a later net-zone
service), no GUI. The address plan is fixed; `[network] address` is refused
like any unknown key.

## Files

`netzone.rs` (NIC ownership, attachment, reattachment), `netlink.rs`,
`rootfs.rs` (`resolv.conf`, the net zone's `/run` and `/var/lib`, files bound
into its `/etc`), `landlock.rs` (`nic_zone_rules`), `policy.rs`, `wifi.rs`,
`serve.rs`, `compartments/zones/net.toml` and `policy/net.seccomp`,
`tools/net/netzone-init.sh`, `tools/kryptik`.
