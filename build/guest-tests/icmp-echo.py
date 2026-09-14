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

It keeps trying until TIMEOUT has elapsed, one attempt per second: a zone's
IPv6 address is "tentative" for the first second or two of its life
(duplicate address detection), and an echo sent from a tentative address
goes nowhere - the very first probe of a fresh zone said NOPONG for fd19::1
while the same probe four seconds later answered. The verdict wants to
know whether the path exists, not whether it existed at millisecond zero.
"""
import socket
import struct
import sys
import time

host = sys.argv[1]
timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0
v6 = ":" in host
fam = socket.AF_INET6 if v6 else socket.AF_INET
proto = socket.IPPROTO_ICMPV6 if v6 else socket.IPPROTO_ICMP
echo_request = 128 if v6 else 8
deadline = time.monotonic() + timeout
seq = 0
last = "no attempt"
while True:
    seq += 1
    try:
        s = socket.socket(fam, socket.SOCK_DGRAM, proto)
        s.settimeout(1.0)
        # type, code, checksum (kernel), identifier (kernel), sequence
        s.sendto(struct.pack("!BBHHH", echo_request, 0, 0, 0, seq) + b"kryptik", (host, 0))
        s.recvfrom(1500)
        print("PONG", host)
        sys.exit(0)
    except Exception as e:  # noqa: BLE001 - the reason is the point
        last = str(e)
    finally:
        try:
            s.close()
        except Exception:  # noqa: BLE001
            pass
    if time.monotonic() >= deadline:
        print("NOPONG", host, last)
        sys.exit(1)
    time.sleep(0.5)
