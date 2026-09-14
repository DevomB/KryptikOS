#!/usr/bin/env python3
"""One ICMP echo without privilege: exit 0 on a reply, 1 otherwise.

    icmp-echo.py HOST [TIMEOUT]

A zone keeps no CAP_NET_RAW, and inetutils ping wants a raw socket, so
inside a zone it says "Lacking privilege for icmp socket" whether or not the
host is reachable - which made the guest zone checks' bridge and egress
verdicts unable to pass and their isolation verdicts pass for the wrong
reason. This uses the kernel's unprivileged ICMP datagram socket instead
(net.ipv4.ping_group_range, set by kryptikd in the zone's namespace); the
kernel fills in the identifier and the checksum. Prints PONG or NOPONG and
the reason, so a verdict can quote it.
"""
import socket
import struct
import sys

host = sys.argv[1]
timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0
v6 = ":" in host
fam = socket.AF_INET6 if v6 else socket.AF_INET
proto = socket.IPPROTO_ICMPV6 if v6 else socket.IPPROTO_ICMP
echo_request = 128 if v6 else 8
try:
    s = socket.socket(fam, socket.SOCK_DGRAM, proto)
    s.settimeout(timeout)
    # type, code, checksum (kernel), identifier (kernel), sequence
    s.sendto(struct.pack("!BBHHH", echo_request, 0, 0, 0, 1) + b"kryptik", (host, 0))
    s.recvfrom(1500)
    print("PONG", host)
    sys.exit(0)
except Exception as e:  # noqa: BLE001 - the reason is the point
    print("NOPONG", host, e)
    sys.exit(1)
