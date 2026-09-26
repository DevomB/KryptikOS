#!/usr/bin/env python3
"""One ICMP echo without privilege: PONG and exit 0, or NOPONG, why, and 1.

    icmp-echo.py HOST [TIMEOUT]
"""
# The ICMP datagram socket needs no privilege (net.ipv4.ping_group_range, set
# by kryptikd in the zone). ping uses it too; the reachability checks use this
# instead, so a broken ping fails only the ping checks.
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
# Retry until TIMEOUT; a fresh zone's IPv6 address is tentative at first.
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
