#!/usr/bin/env python3
"""How far this machine's clock is from what time servers say (docs/design/time.md).

    sntp-offset.py [--timeout SECONDS] (--server HOST | --pool HOST)...

Prints "<offset> <answers>": the seconds to add to this clock (signed, six
decimals) and how many servers that is the median of. Exits 1, printing
nothing, if none answered. A plain SNTP query (RFC 4330) that sets nothing;
zone 0 treats the result as an untrusted claim.
"""
import select
import socket
import struct
import sys
import time

NTP_EPOCH = 2208988800          # seconds from 1900 to 1970
ERA = 1 << 32


def to_ntp(t):
    secs = int(t) + NTP_EPOCH
    return struct.pack("!II", secs % ERA, int((t - int(t)) * ERA) % ERA)


def from_ntp(raw, near):
    secs, frac = struct.unpack("!II", raw)
    t = secs - NTP_EPOCH + frac / ERA
    # The 32-bit seconds wrap in 2036; take the era nearest our own clock.
    return t + ERA * round((near - t) / ERA)


def addresses(kind, name):
    host, port = name, 123
    if name.count(":") == 1:        # HOST:PORT, which is how the tests name a server
        host, p = name.split(":")
        port = int(p)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    except OSError:
        return []
    seen, out = set(), []
    for family, _, _, _, addr in infos:
        if addr[0] not in seen:
            seen.add(addr[0])
            out.append((family, addr))
    return out[: 4 if kind == "pool" else 1]


def measure(targets, timeout):
    pending = {}
    for family, addr in targets:
        try:
            s = socket.socket(family, socket.SOCK_DGRAM)
            s.setblocking(False)
            t0 = time.time()
            sent = to_ntp(t0)
            # LI 0, version 4, mode 3 (client); only the transmit timestamp is set.
            s.sendto(b"\x23" + bytes(39) + sent, addr)
            pending[s] = (t0, sent, addr)
        except OSError:
            continue
    offsets = []
    deadline = time.monotonic() + timeout
    while pending and time.monotonic() < deadline:
        ready, _, _ = select.select(list(pending), [], [], max(0.0, deadline - time.monotonic()))
        for s in ready:
            t0, sent, addr = pending.pop(s)
            try:
                data, src = s.recvfrom(512)
                t3 = time.time()
            except OSError:
                continue
            finally:
                s.close()
            if src[0] != addr[0] or len(data) < 48:
                continue
            leap, mode, stratum = data[0] >> 6, data[0] & 7, data[1]
            if mode != 4 or leap == 3 or not 1 <= stratum <= 15:
                continue            # not a server, not synchronised, or a kiss-of-death
            if data[24:32] != sent or data[40:48] == bytes(8):
                continue            # not an answer to what we sent (off-path senders cannot see it)
            t1, t2 = from_ntp(data[32:40], t0), from_ntp(data[40:48], t0)
            offsets.append(((t1 - t0) + (t2 - t3)) / 2)
    for s in pending:
        s.close()
    return offsets


def main(argv):
    timeout, targets = 8.0, []
    it = iter(argv)
    for a in it:
        if a == "--timeout":
            timeout = float(next(it))
        elif a in ("--server", "--pool"):
            targets += addresses(a[2:], next(it))
        else:
            sys.exit(__doc__.strip().splitlines()[2].strip())
    offsets = sorted(measure(targets[:16], timeout))
    if not offsets:
        return 1
    n = len(offsets)
    # The median, so one lying server among three is outvoted.
    median = offsets[n // 2] if n % 2 else (offsets[n // 2 - 1] + offsets[n // 2]) / 2
    print("%+.6f %d" % (median, n))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
