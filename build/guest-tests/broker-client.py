#!/usr/bin/env python3
"""A zone's side of its broker, for the guest checks: one line per call.

    broker-client.py version
    broker-client.py clipboard-set MIME TEXT      (TEXT is the payload, as given)
    broker-client.py clipboard-get
    broker-client.py transfer DEST NAME PATH      (offers PATH to DEST as NAME)

Prints the broker's answer, verbatim, on one line. It exists because the
launch protocol (kryptik-launch, kryptikd serve) carries a command as
lines and refuses an argument with a newline in it, and the first GUI run
on installed media handed every clipboard and transfer probe a multi-line
`python3 -c` program - and a clipboard payload that itself needs a newline
before it in the wire format - so none of them ever reached a zone
("kryptik-launch: argument 2 contains a newline"). The wire format is
Design 05a's: `clipboard-set MIME LEN\\n<LEN bytes>`, `clipboard-get\\n`,
`transfer DEST NAME\\n` with the file's descriptor over SCM_RIGHTS.
"""
import array
import os
import socket
import sys

BROKER = "/run/kryptik/broker"


def talk(header: bytes, payload: bytes = b"", fd: int = -1) -> str:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(90)
    s.connect(BROKER)
    if fd >= 0:
        s.sendmsg([header], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
    else:
        s.sendall(header)
    if payload:
        s.sendall(payload)
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="replace").replace("\n", " ").strip()


def main(argv):
    verb = argv[1] if len(argv) > 1 else ""
    if verb == "version":
        print(talk(b"version\n"))
    elif verb == "clipboard-set" and len(argv) == 4:
        payload = argv[3].encode()
        print(talk(f"clipboard-set {argv[2]} {len(payload)}\n".encode(), payload))
    elif verb == "clipboard-get":
        print(talk(b"clipboard-get\n"))
    elif verb == "transfer" and len(argv) == 5:
        fd = os.open(argv[4], os.O_RDONLY)
        print(talk(f"transfer {argv[2]} {argv[3]}\n".encode(), fd=fd))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
