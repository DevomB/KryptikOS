#!/usr/bin/env python3
"""The net zone's half of the update channel (docs/design/update-channel.md).

    update-fetch.py latest    fetch the statement of what is current and its
                              signature, and hand both to zone 0
    update-fetch.py poll      ask zone 0 whether a release is wanted and, if
                              one is, stream what it says is still missing

This zone is treated as hostile, so nothing here is trusted and nothing here
decides anything: zone 0 verifies every signature, names the address the
files come from (out of the statement it verified), says which file it wants
from which byte, and refuses any piece that is not exactly that. This script
is a pipe with a Range header. It holds nothing: a release is larger than
this zone's storage, so each piece goes from the connection to the broker
and is forgotten.

Where to look is zone 0's to say: `channel = <address>` in
/etc/kryptik/update.conf, on the verified root and read-only here. TLS
authenticates the host and keeps the request private; nothing about the
release's authenticity rests on it.

Exit 0: done, or nothing to do. Exit 1: said why on standard error.
"""
import argparse
import socket
import ssl
import sys
import urllib.request

PIECE = 1 << 20        # the most one update-put carries
SMALL = 8 * 1024       # the most a statement or its signature may be
ROUNDS = 8             # polls per run: the manifest, then the files, then idle


def ask(broker, header, payload=b""):
    """One request to zone 0's broker, one reply line."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(60)
    s.connect(broker)
    s.sendall(header.encode() + b"\n" + payload)
    s.shutdown(socket.SHUT_WR)
    reply = b""
    while len(reply) < 4096:
        chunk = s.recv(4096)
        if not chunk:
            break
        reply += chunk
    s.close()
    return reply.decode("utf-8", "replace").strip()


def fetch(url, ca, offset=0):
    """An open response positioned at `offset`, whether or not the server
    honours a Range: one that ignores it sends the file from the start, and
    the bytes before the offset are read and dropped."""
    headers = {"Range": "bytes=%d-" % offset} if offset else {}
    context = ssl.create_default_context(cafile=ca) if url.startswith("https://") else None
    r = urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30, context=context)
    if offset and r.status != 206:
        left = offset
        while left:
            skipped = r.read(min(left, PIECE))
            if not skipped:
                raise OSError("%s ends before byte %d" % (url, offset))
            left -= len(skipped)
    return r


def channel(conf):
    with open(conf, encoding="utf-8") as f:
        for line in f:
            key, _, value = line.partition("=")
            if key.strip() == "channel" and value.strip():
                return value.strip().rstrip("/") + "/"
    raise OSError("%s names no channel" % conf)


def latest(args):
    base = channel(args.conf)
    parts = []
    for name in ("latest", "latest.sig"):
        body = fetch(base + name, args.ca).read(SMALL + 1)
        if not body or len(body) > SMALL:
            raise OSError("%s%s is empty or larger than %d bytes" % (base, name, SMALL))
        parts.append(body)
    reply = ask(args.broker, "update-latest %d %d" % (len(parts[0]), len(parts[1])), parts[0] + parts[1])
    print(reply)
    return 0 if reply.startswith("ok") else 1


def poll(args):
    for _ in range(ROUNDS):
        words = ask(args.broker, "update-poll").split()
        if words[:1] != ["fetch"]:
            print(" ".join(words) or "no reply")
            return 0 if words == ["idle"] else 1
        # fetch <version> <base> need <name> <offset> [<name> <offset> ...]
        if len(words) < 6 or words[3] != "need" or len(words) % 2:
            raise OSError("zone 0 said something this does not understand: %s" % " ".join(words))
        version, base, need = words[1], words[2], words[4:]
        for name, offset in zip(need[0::2], need[1::2]):
            offset = int(offset)
            r = fetch(base + name, args.ca, offset)
            while True:
                piece = r.read(PIECE)
                if not piece:
                    break
                reply = ask(args.broker, "update-put %s %d %d" % (name, offset, len(piece)), piece)
                if not reply.startswith("ok"):
                    # Zone 0 has the last word: what it refuses is not sent
                    # again, and the next poll says what it wants instead.
                    print("%s %s at byte %d: %s" % (version, name, offset, reply), file=sys.stderr)
                    return 1
                offset += len(piece)
            r.close()
    print("still fetching after %d rounds; the next run carries on" % ROUNDS)
    return 0


def main():
    ap = argparse.ArgumentParser(description="fetch for zone 0's update channel; decides nothing")
    ap.add_argument("what", choices=["latest", "poll"])
    ap.add_argument("--conf", default="/etc/kryptik/update.conf")
    ap.add_argument("--broker", default="/run/kryptik/broker")
    ap.add_argument("--ca", default="/etc/ssl/certs/ca-certificates.crt")
    args = ap.parse_args()
    try:
        return latest(args) if args.what == "latest" else poll(args)
    except (OSError, ValueError) as e:     # urllib's errors are OSErrors
        print("update-fetch: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
