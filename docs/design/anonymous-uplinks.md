# Anonymous uplinks for zones

The [roadmap](../roadmap.md) lists anonymity as a zone property: a Tor or VPN
uplink enforced by the net zone. The [threat model](../threat-model.md)
says the opposite today: anonymity is a non-goal ("that is Tails and
Whonix"), traffic analysis is out of scope, and Kryptik "ships no Tor or VPN
uplink". It also says that a design which contradicts it changes it first.
So this document proposes the threat-model change first, then the design: a
zone whose only way out is Tor or a named VPN, closed when that uplink is
down, with its DNS through it. The proposed decision is ADR-020 in
[decisions](../decisions.md).

## The threat-model change

Proposed text, to replace the matching parts of the threat model when the
first anonymous uplink ships.

**Assets**, a fifth:

> 5. For a zone with an anonymous uplink: that its traffic cannot be tied to
>    the machine's network address by the sites it reaches, nor its
>    destinations read by the network the machine is on.

**Network attacker:**

> **Partially defended.** Kryptik segments; for most zones it does not
> anonymize. A zone with an anonymous uplink reaches the network only
> through Tor, or through a VPN the user named, and never in the clear: the
> local network sees Tor or the VPN, not the zone's destinations, and those
> destinations see Tor's exit or the VPN, not the machine. A compromised
> `net` zone gets no zone's files and not `vault`, and sees an anonymous
> zone's traffic only after Tor or the VPN has encrypted it. Confidentiality
> on the wire is the application's job.

**Traffic analysis:**

> Out of scope for ordinary zones: Kryptik separates identities on the host
> and does not hide that their traffic came from you. A zone with an
> anonymous uplink hides its destinations from the local network and its
> address from its destinations, as far as Tor or the VPN does. Not defended
> even there: an observer of both ends of a Tor circuit; the VPN provider,
> who sees everything a VPN zone sends and where the machine is; whatever
> the zone's own programs reveal (a login, a browser fingerprint, the clock,
> screen and fonts it shares with other zones); a compromised gateway zone;
> and timing that links an anonymous zone's activity to another zone's on
> the same machine.

**Non-goals**, the first bullet:

> - **Anonymity of the whole machine, and amnesia by default**: that is
>   Tails and Whonix. A zone can have an anonymous uplink; the system as a
>   whole is not anonymous.

## Where things stand

- **One gateway.** The `net` zone (`network.mode = "nic"`) holds every
  physical interface and runs DHCP, Wi-Fi, NAT and the zones' resolver. A
  routed zone gets one veth into its bridge, `kryptik0`, on an isolated
  port, with an address derived from its identity (`10.19.0.k`,
  `netzone::host_number`) ([net zone](net-zone.md)).
- **Closed when the gateway goes.** If the net zone dies, the kernel deletes
  every veth whose other end lived in it, and routed zones are left with
  loopback.
- **The net zone faces the network.** dhcpcd, wpa_supplicant and dnsmasq
  parse what the local network and the radio send, and the zone is treated
  as hostile for that reason.
- **Only the net zone keeps network capabilities.** `policy::check_for_zone`
  refuses `CAP_NET_ADMIN` and `CAP_NET_RAW` for any other zone, so a routed
  zone cannot re-address itself or forge frames.
- **Netfilter is built in**, nft only: `NFT_NAT`, `NFT_MASQ`, `NFT_CT`,
  `NFT_REJECT`, conntrack (`boot.fragment`).
- **The net-zone design** lists "no VPN or Tor plumbing (a later net-zone
  service)" under its non-goals.

## Constraints

- **ADR-002.** Zones share one kernel, so a zone is anonymous only as long as
  the kernel holds. A kernel privilege escalation in any zone sees every
  zone's traffic before Tor encrypts it.
- **The fail-closed rule.** No packet from an anonymous zone may leave in the
  clear, whatever stops or crashes, and its DNS goes through the uplink too.
  That has to follow from how the zone is wired, not from a daemon staying
  healthy.
- **Zone files decide.** Whether a zone is anonymous is set in its file on
  the verified root. Nothing on the state partition may give a zone a
  clearnet route, or take its anonymous uplink away.
- **The clock.** Tor refuses a clock far from its consensus. Zone 0 keeps the
  clock within bounds from the net zone's measurements ([clock](time.md)).

## Tor

### In the net zone

Tor would run in the net zone as a transparent proxy, with the forward chain
sending an anonymous zone's traffic, by its bridge address, to Tor's ports
and dropping the rest. It is one daemon more in a zone that exists, with
rules keyed on addresses kryptikd assigns. But the net zone is the one that
faces the local network: a dhcpcd or wpa_supplicant bug, reachable by
anyone on the LAN or in radio range, would hand the attacker the Tor client,
with every anonymous zone's destinations and every unencrypted byte. Whonix
keeps its Tor gateway apart from the machine's network for this reason.
Rejected. The roadmap's wording puts the enforcement in the net zone; this
design puts it in how an anonymous zone is wired instead, and keeps Tor out
of the zone that faces the network.

### A gateway zone

A new network mode, `network.mode = "gateway"`, for a zone with two sides:
a routed uplink into the net zone, like any routed zone, and a bridge of its
own that anonymous zones attach to. A shipped `tor` zone, ephemeral, runs
Tor and nothing else. A zone with

```toml
[network]
mode   = "routed"
uplink = "tor"
```

gets its veth into the `tor` zone's bridge (`kryptik1`, `10.20.0.1/24`,
isolated ports, `10.20.0.k` from its identity as on `kryptik0`) instead of
the net zone's.

- **Closed by construction.** An anonymous zone's only interface leads into
  the gateway. The gateway's namespace forwards nothing (forwarding off,
  forward policy drop). The only services on its bridge side are Tor's
  `TransPort`, `DNSPort` and `SocksPort`. Tor stopped: connections are
  refused. Gateway stopped: the kernel deletes the veths and the zone keeps
  loopback, as routed zones do when the net zone dies. The gateway starts
  before any zone that names it, and an anonymous zone whose gateway is not
  running gets no interface and no resolver.
- **The rules are kryptikd's.** kryptikd builds the bridge and veths from
  outside, as it does for the net zone, and loads a fixed ruleset into the
  gateway's namespace during its handshake, before its seccomp filter. The
  gateway keeps no `CAP_NET_ADMIN`, so a compromised Tor cannot change them.
  In the gateway's namespace:
  - nat prerouting: TCP arriving from the bridge is redirected (`dnat`) to
    the TransPort, and DNS on port 53, UDP and TCP, to the DNSPort;
  - input: from the bridge, only those ports and the SocksPort;
  - forward: policy drop;
  - no IPv6 on the bridge (`accept_ra = 0`, no ULA), and UDP and ICMP from
    the bridge dropped: Tor carries TCP, and DNS goes through the DNSPort.

  `NFT_NAT` and conntrack, which TransPort needs to recover a connection's
  original destination, are already built in.
- **DNS.** kryptikd writes the anonymous zone's `resolv.conf` naming
  `10.20.0.1`, as it names `10.19.0.1` for routed zones. Tor resolves through
  the circuit; `.onion` names map into a private range that the TransPort
  serves (`AutomapHostsOnResolve`, `VirtualAddrNetworkIPv4`).
- **Isolation between zones.** Tor keeps streams from different client
  addresses on different circuits by default (`IsolateClientAddr`), so two
  anonymous zones never share a circuit. Programs that speak SOCKS can
  isolate further by credentials on the SocksPort.
- **What the net zone sees:** Tor's encrypted traffic to its guards, as any
  ISP would.
- **Tor itself** is C tor, built from source and pinned with the Tor
  Project's signature. Its own seccomp sandbox needs `allow-syscall seccomp`
  in the gateway's policy, under the zone's filter. Arti, the Rust
  implementation, would suit a chokepoint better (ADR-010's reasoning), but
  has no transparent proxy yet.
- **Costs:** a zone mode and a second bridge in kryptikd; one more zone
  running whenever an anonymous zone does; Tor as a source to keep current.
  The gateway is the single point that deanonymizes every zone behind it if
  compromised, which is why it runs nothing else.

## A VPN

A WireGuard interface keeps its UDP socket in the network namespace where it
was created, and can be moved into another; the WireGuard project documents
this use. kryptikd creates `wg0` in the net zone's namespace, moves it into
the VPN zone's, and only then configures its key and peer, from zone 0, in
the zone's namespace. A zone with

```toml
[network]
mode   = "routed"
uplink = "vpn"
```

has `wg0` and loopback, and no veth at all.

- **Closed by construction.** There is no route but the tunnel. Tunnel
  down: nothing leaves. Net zone gone: the socket's namespace is gone and so
  is every packet's way out. When the net zone comes back, kryptikd deletes
  the old interface and moves in a new one, as it reattaches veths.
- **What the net zone sees:** UDP to the VPN server. It never holds the key,
  which is set after the move, in a namespace it cannot reach.
- **DNS** goes to the provider's resolver inside the tunnel. kryptikd
  writes it into the zone's `resolv.conf` from the VPN's configuration.
- **The configuration** (the provider's endpoint and key, the zone's tunnel
  address and resolver, its private key) is kept like the Wi-Fi passphrases:
  in zone 0 on the state partition, written by `kryptik vpn add NAME` through
  the launch daemon, never on a command line ([net zone](net-zone.md#wireless-uplinks)).
  The state partition is encrypted, and an offline writer cannot choose
  what a block decrypts to, so it can break the configuration but not
  replace it.
- **Kernel:** `WIREGUARD`, as a signed module that kryptikd loads from zone
  0 before it creates the interface.
- **Trust:** the provider sees all the zone's traffic and the machine's
  address. That is less than Tor, and the threat-model text says so.

OpenVPN and other userspace VPNs need a tun device and `CAP_NET_ADMIN` in
the zone that runs them; WireGuard needs neither. They are not offered.

## What an anonymous zone still shares

The network path is the zone property; the rest of the machine is shared.
`uname`, the CPU model in `/proc/cpuinfo`, the screen's size and the
monitor's make and model through `wl_output`, the installed fonts and the
clock are the same in every zone. Firefox in an anonymous zone is not Tor
Browser, whose fingerprinting defences are a project of their own. The
laptop design (`docs/design/laptop.md`, proposed beside this one) has the
proxy rewrite each output's make, model and serial for every zone. The rest
is listed in the threat-model text above.

## Recommendation

- A `gateway` network mode and a shipped, ephemeral `tor` zone that runs Tor
  alone, with rules kryptikd loads and the gateway cannot change.
- WireGuard for VPN uplinks, with the interface moved into the zone and the
  key set by kryptikd from zone 0.
- `uplink = "tor"` or `"vpn"` in a zone file, never from the state
  partition, and a shipped `anon` zone, ephemeral, with `uplink = "tor"`.
- No Tor in the net zone, and no userspace VPN.

## The check that proves it done

`build/guest-tests/zones-check.sh` on the installed system, with a private
Tor network (chutney) and a WireGuard peer in a namespace of the test host,
as the Wi-Fi checks use an access point of their own:

- `anon` has loopback and one veth into the `tor` zone, and fetches a page
  from the test server through the private Tor network;
- with Tor stopped inside the gateway, `anon`'s connections fail, and a
  capture on the net zone's side shows nothing but traffic to the test
  network's relays;
- with the `tor` zone stopped, `anon` has loopback only;
- `anon`'s DNS reaches Tor's DNSPort, a query sent to any other address gets
  no answer, and it has no IPv6 address;
- the VPN zone reaches the test server through the peer, sends nothing once
  the peer stops, and the net zone's capture holds only UDP to the peer;
- `kryptikd check` refuses `uplink` on the nic zone and on a gateway zone,
  and a gateway zone that keeps `CAP_NET_ADMIN`.
