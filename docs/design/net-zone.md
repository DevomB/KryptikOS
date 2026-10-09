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
  passes between two `kv-*` ports. A zone's last run can still hold that name
  for a moment, until the kernel has torn its namespace down; one instance of
  a zone runs at a time, so kryptikd deletes the stale port and waits up to
  5 s for the name. The zone's addresses, `10.19.0.<k>/24` and
  `fd19::<k>/64` with default routes via the bridge, and its MAC,
  `02:19:00:00:00:<k>`, follow from its declared identity
  (`netzone::host_number`: `uid_base` 131072 is `.2`, 196608 is `.3`, and so
  on), not from DHCP: one less daemon, no broadcast domain.
  `accept_ra = 0` is set first, and `ping_group_range` is set to the zone's
  host gid so unprivileged ICMP echo works (the sysctl takes host ids, so the
  parent writes it). The image's `ping` is iputils', built without libcap and
  given no setuid bit or file capability: it sends over that datagram socket,
  IPv4 and IPv6, and a patch keeps it from the id calls a zone refuses
  (`build/patches/iputils-20250605`).
- **The gateway is chosen by zone file.** Routed zones attach to the running
  zone whose root-owned file says `mode = "nic"`, never to whatever namespace
  holds a bridge: a zone could create its own `kryptik0`.
- **A routed zone owns its namespace, not its port.** Its bounding set is
  `CAP_NET_BIND_SERVICE`, `Policy::check_for_zone` refuses a policy keeping
  `CAP_NET_ADMIN` or `CAP_NET_RAW`, and seccomp refuses packet sockets. It
  cannot change its address or MAC, or put a frame on the wire that the
  kernel did not build; `ip link set eth0 down` fails with `EPERM`.
- **A zone's addresses count only with its MAC.** A routed zone can still
  send from an address it does not hold: `IPV6_FREEBIND` needs no capability
  and IPv6 checks no source on the way out. (IPv4 refuses such a source
  unless the socket is transparent, which needs one of the two capabilities.)
  The net zone's ruleset therefore pairs `10.19.0.<k>` and `fd19::<k>` with
  `02:19:00:00:00:<k>` for every host number and, at prerouting ahead of
  conntrack, drops a packet from the bridge whose source and MAC are not a
  pair. From a link-local address only neighbour discovery passes, so one zone
  cannot borrow another's address to reach what that one may, or send the net
  zone's answers to it.
- **Every namespace starts with loopback only.** Kryptik's kernel leaves SIT
  out (`hardening.fragment`). On a kernel whose tunnel drivers give every new
  namespace a fallback device such as `sit0`, the launcher sets
  `net.core.fb_tunnels_only_for_init_net = 1` first. A privileged launch
  refuses a namespace holding anything else.
- **The net zone is the chokepoint and is treated as hostile.** It gets no
  routed zone's data, no broker access beyond its own clipboard and the time
  and update verbs, and ephemeral storage. Its seccomp policy is the base one
  plus `policy/net.seccomp`: `AF_PACKET`, `NETLINK_NETFILTER`,
  `NETLINK_GENERIC` (dhcpcd opens one for nl80211 and exits if refused),
  `CAP_NET_ADMIN` / `CAP_NET_RAW` over its own interfaces, and `CAP_SETUID`,
  `CAP_SETGID` and `CAP_SYS_CHROOT` for dhcpcd's privilege separation.
  `chown`, which dhcpcd calls on its control socket, is in the base list.
  The net zone alone gets private tmpfs mounts at `/run` and `/var/lib`
  (writable under Landlock, no exec), where dhcpcd keeps its pid file,
  control socket and leases. Every
  other zone's `/run` is read-only and holds only its broker and proxy
  sockets.

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
  from the bridge to an uplink, what a gateway carries accepted and the
  uplink's own network refused but to the zones whose definition opens it
  ([below](#the-uplinks-own-networks)); bridge to bridge dropped;
  `10.19.0.0/24` and `fd19::/64` masqueraded out of every uplink; new DNS
  connections arriving on an uplink dropped.
- **The resolver:** `dnsmasq` on 10.19.0.1, fd19::1 and 127.0.0.1,
  forwarding to the uplink lease's servers (QEMU's 10.0.2.3 when nothing else
  is known), restarted if it dies. It binds as the zone's root and then runs
  as the zone's nobody, with no capability but `CAP_NET_BIND_SERVICE` (for
  fd19::1, which stays tentative until the bridge has a port), so a bug in
  what parses an answer does not hold the zone's root. A lease that comes
  after it started, or another network's, reaches it within ten seconds: the
  zone's loop compares the servers `resolv.conf` names with the ones dnsmasq
  was given and on a change replaces the file, which dnsmasq reads before its
  next query (at most once a second), forgetting what the last servers
  answered. A lease that lapsed leaves the last servers in place. It answers
  the test TLD `.test` itself, so resolving `kryptik.test` tests the path to
  the resolver, not the internet.
- **dhcpcd separates its privileges.** What parses a lease, a DHCPv6 reply
  or a router advertisement runs as the zone's `dhcpcd` user, chrooted to an
  empty `/var/empty`, with no capability and dhcpcd's own seccomp filter over
  the zone's; a small helper stays the zone's root. For that the net zone
  keeps `CAP_SETUID`, `CAP_SETGID` and `CAP_SYS_CHROOT` (kept together, and
  by the nic zone alone), its filter allows the five calls they serve
  (`setuid`, `capset`, `setgid`, `setgroups`, `chroot`;
  `seccomp::CAP_CALLS`; dnsmasq's drop to nobody uses the same), its
  user namespace maps a third id, 100, to `uid_base` + 100 and allows
  `setgroups`, and its passwd names the user. In the zone's own namespaces
  these reach only its mapped ids and its own tree.
  The helper still does for the parsers what dhcpcd needs: addresses, routes
  and links over netlink, the net sysctls, and dhcpcd's own files. It also
  runs the hook, with the environment the parsers send it, so the net zone
  does not use dhcpcd's: `dhcpcd-hook` checks every value for form and writes
  nothing but `nameserver` lines (`tools/tests/netzone-hook.sh`). A bug in a
  parser no longer reaches the Wi-Fi credentials, the broker's socket, the
  firewall's netlink socket or a program to run.
- **Readiness**, printed again on any change:

```text
netzone: READY uplink=<addr|none> nat=yes dns=<yes|no> wifi=<ssid|connecting|unconfigured|none> time=<offset|no-answer|...> bridge=kryptik0 uplinks=<list>
netzone: NOT READY <reason>        (forwarding off)
```

  The zone writes to a pipe, never to the log: its launcher marks each line
  `zone net| ` in the catch-all log, replaces control bytes, and logs at most
  a megabyte a start. A line without the mark is the launcher's or a zone 0
  service's, whatever it says. The zone prints words from the network (an
  SSID, a server's refusal) as they came, never as escapes.

## The uplinks' own networks

A zone needs the gateway only as a next hop, and its names go through the
resolver here, so nothing on the network an uplink sits on is part of the
internet a zone asked for: the router's own pages, a printer, the other
machines of a home or a café. A routed zone is refused that network unless
its definition says `[network] local = true`.

- **The rule goes by the route, not by a list of networks.** The forward
  chain accepts a packet from the bridge when its route leaves by a gateway
  and it is not addressed to the gateway itself (`rt ip nexthop @gw4 ip daddr
  != @gw4`, and the same for IPv6). Every other packet for an uplink is
  rejected with an ICMP "prohibited", so a program fails at once instead of
  waiting. The script fills `gw4` and `gw6` from the uplinks' routes when a
  lease arrives and at every 10 s tick. Until a gateway is in the sets
  nothing leaves by it, so a new lease opens no way in before the script has
  seen it.
- **Which zones are let through is read from their definitions.** They are on
  the verified root, which the net zone shares read-only, and a routed zone's
  address follows from its `uid_base`. The script puts the addresses of the
  zones that claim `local` into `local4` and `local6` when it loads the
  ruleset. A routed zone cannot change its address, and the net zone takes
  an address only with that zone's MAC, so the address is the zone. kryptikd
  refuses the key on a zone that is not routed, and `kryptikd explain` says
  which way a zone is set.
- **`untrusted` is the one shipped zone that claims it.** A hotel's or café's
  Wi-Fi asks for a login on a page its gateway serves, and the net zone has
  no browser, so some zone must reach that page: the ephemeral one, already
  treated as hostile and wiped on exit. `work`, `personal` and `dev` are
  refused the local network. The cost is that whatever runs in `untrusted`
  can still address the router and the machines beside it, as every zone
  could before; without the key there, a network with a login page is no
  network at all.
- **The net zone's own address on an uplink is not that network.** It is the
  net zone, which a zone needs only for its resolver on the bridge. From the
  bridge the input chain takes only what is addressed to `10.19.0.1` or
  `fd19::1`, or to a link-local or link-scope multicast address for neighbour
  discovery, so no zone, `local` or not, reaches what the net zone listens on
  over its uplink addresses, such as dhcpcd.
- **What it does not cover.** A network behind the gateway, such as a modem's
  own pages on another subnet, is past the gateway and so allowed. So is the
  gateway's address on its far side: a router that answers its admin page on
  its WAN address to the machines inside serves it to every zone, and the net
  zone cannot know that address to refuse it. An uplink whose default route
  names no gateway, a point-to-point link, carries only the zones that claim
  `local`. The net zone itself reaches the local network, as DHCP and the
  resolver need.

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
  for `kryptik wifi add|forget <SSID>`. The passphrase is read on the
  terminal and never appears on a command line or in a log, and `kryptik wifi
  list` shows SSIDs only. The file is in wpa_supplicant's own format, so
  kryptikd derives no keys. It is rewritten by temp-and-rename, 0400, owned by
  the net zone's identity in a root-owned 0711 directory: the zone's root is
  host uid N, so a root-owned 0600 file would be unreadable to it, and nothing
  else runs as N. Only the net zone gets it, bound read-only at
  `/etc/wpa_supplicant.conf`, and a change restarts the `net-zone` service
  (`s6-svc -r`).
- On disk the file is plaintext inside the [encrypted](state-encryption.md)
  state partition, like NetworkManager's connection files. A compromised net
  zone learns the passphrases of the networks it was given, and nothing more.

QEMU has no radio, so the zones suite makes two with `mac80211_hwsim`, the
kernel's simulated radio, from the signed module the image carries: one goes
into a namespace of its own as the access point (the image's `wpa_supplicant`
in AP mode, `dnsmasq` for the lease), the other is left for the net zone,
which joins the network `kryptik wifi add` gave it, leases an address over
the radio and carries a routed zone's traffic to the access point. Real
hardware is untested: a seccomp refusal of `wpa_supplicant` there would show
as `SIGSYS` in the zone's log and a `wifi=connecting` that never changes.

## Gateway failure

- If the net zone dies, the kernel deletes both ends of every veth whose net
  side lived in its namespace: routed zones lose `eth0` and fail closed.
- When it starts again, kryptikd reattaches every running routed zone in the
  registry with a new veth pair, moved in through the zone's namespace
  (`/proc/<pid 1>/ns/net`). A zone keeps the `resolv.conf` it started with, so
  one started before any net zone gets a path but no resolver until it
  restarts; kryptikd does not edit a running zone's sealed root.
- The kernel returns the physical interface to the initial namespace, down
  and unaddressed, under its own name (`dev<N>` only if zone 0 has an
  interface by that name by then); kryptikd leaves it so until the next net
  zone start, which takes it again whatever its name.

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
- A routed zone reaches the network an uplink sits on only if its definition
  says so. The others reach what a gateway carries, and never the gateway
  itself.
- Addresses are identities: 10.19.0.k follows from `uid_base` and the net
  zone takes it only with that zone's MAC, so the broker or a future policy
  there can name zones by address as safely as by uid, as long as routed
  zones keep neither network capability.

## Not built

- **Pinning by bridge port** (nftables `bridge` rules on each `kv-*` port).
  The `inet` table pins by MAC instead, which a routed zone can neither change
  nor forge, so a port would add nothing, and `NF_TABLES_BRIDGE` and
  `BRIDGE_NETFILTER` would put more kernel within reach of the hostile net
  zone. Revisit if a routed zone may ever keep either network capability.

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
- `tools/tests/netzone-uplink.sh`: the zones a definition lets through, by the
  address kryptikd derives for each, every host's addresses pinned to its own
  MAC and the MAC the same as `netlink::zone_mac`, the gateway sets as nft is
  fed them, and the order of the prerouting, forward and input rules.
- The launcher suite reads a zone's bounding set (exactly `0x400`) and the
  boundary suite asks for an `AF_PACKET` socket. The launcher suite's
  routed-networking section runs only with `KRYPTIK_VM_DISPOSABLE=1`, since
  starting the net zone takes the host's interface.
- `build/guest-tests/zones-check.sh` on the installed system checks every
  guarantee above under QEMU user networking: the net zone `READY`, zone 0
  offline, a routed zone's address, NAT, ULA-only IPv6 and resolver, zones
  separated while each reaches the bridge, a routed zone started again as its
  last run ends keeping its path, a zone's datagrams sent from another zone's
  addresses counted where they reach the net zone and never taken in while its
  own are, `vault` offline, no egress while the net zone is down, the
  uplink back in zone 0 under its own name, down and with no address until
  the next start takes it, a zone running across a restart going out through
  the gateway again once reattached, a zone without `local` refused the VM
  gateway, `untrusted` refused the net zone's own uplink addresses while it
  reaches the gateway, and, on two `mac80211_hwsim` radios, the net zone
  associating, leasing and routing over one while the other is the access
  point, whose own address that zone is refused while it reaches an address
  the access point routes. It pings with an unprivileged ICMP socket
  (`build/guest-tests/icmp-echo.py`), since routed zones lack `CAP_NET_RAW`.

## Kernel requirements

`VETH` and `BRIDGE` (`hardening.fragment`). Built in (`boot.fragment`):
`NF_TABLES`, `NF_TABLES_INET`, `NF_TABLES_IPV4`, `NF_TABLES_IPV6`, `NFT_NAT`,
`NFT_MASQ`, `NFT_CT`, `NFT_REJECT`, `NF_NAT` and `NF_CONNTRACK`; netfilter
cannot be modular because the net zone loads its ruleset from inside a user
namespace, for which the kernel does not autoload modules.
`NF_TABLES_BRIDGE`, `BRIDGE_NETFILTER` and `NFT_COMPAT` are off. xtables
(`IP_NF_IPTABLES`, `IP6_NF_IPTABLES`, `NETFILTER_XTABLES`) and ctnetlink
(`NF_CT_NETLINK`) are off: the ruleset is nft's alone, and ctnetlink would be
kernel code the nic zone reaches through its netfilter netlink socket for no
use. For radios, `CFG80211`, `MAC80211`, `RFKILL` and
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
