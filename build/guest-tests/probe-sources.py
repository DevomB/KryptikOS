#!/usr/bin/env python3
"""The source and destination of every probe request a radio sends, one line each, until killed.

    probe-sources.py MONITOR

MONITOR is hwsim's own monitor interface (hwsim0), which hears every frame any of its radios
sends, behind a radiotap header.
"""
import socket
import sys

ETH_P_ALL = 0x0003


def mac(b):
    return ":".join("%02x" % o for o in b)


s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
s.bind((sys.argv[1], 0))
while True:
    f = s.recv(4096)
    if len(f) < 4:
        continue
    h = f[int.from_bytes(f[2:4], "little"):]
    # A management frame of subtype 4: its frame control's first byte is 0x40.
    if len(h) >= 16 and h[0] == 0x40:
        print(mac(h[10:16]), mac(h[4:10]), flush=True)
