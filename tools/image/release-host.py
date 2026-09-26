#!/usr/bin/env python3
"""A release host for the suites: static files over HTTP, on loopback only.

    release-host.py ROOT PORTFILE LOG [NORANGE]

Serves ROOT on 127.0.0.1 (10.0.2.2 to a guest on QEMU's user network; nothing
else on the runner's network can reach it) and writes the port to PORTFILE
once listening. Honours `Range: bytes=N-` (docs/design/update-channel.md),
which http.server does not, except while the file NORANGE exists. Streams
files, as a root image is gigabytes. Logs each request as the path and the
Range header or `-`.
"""
import http.server
import os
import shutil
import sys

root, portfile, log = (os.path.realpath(sys.argv[1]), sys.argv[2], sys.argv[3])
norange = sys.argv[4] if len(sys.argv) > 4 else None


class Host(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        # Links inside ROOT may point anywhere (suites link payloads in), but the
        # requested name is normalised and held to ROOT before it is used.
        path = os.path.normpath(os.path.join(root, self.path.split("?", 1)[0].lstrip("/")))
        if not path.startswith(root + os.sep):
            self.send_error(404)
            return
        if not os.path.isfile(path):
            self.send_error(404)
            return
        rng = self.headers.get("Range")
        with open(log, "a") as f:
            f.write("%s %s\n" % (self.path, rng or "-"))
        size = os.path.getsize(path)
        start = 0
        if rng and rng.startswith("bytes=") and not (norange and os.path.exists(norange)):
            try:
                start = int(rng[6:].split("-", 1)[0])
            except ValueError:
                start = 0
            if start >= size:
                self.send_error(416)
                return
            self.send_response(206)
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, size - 1, size))
        else:
            self.send_response(200)
        self.send_header("Content-Length", str(size - start))
        self.end_headers()
        with open(path, "rb") as f:
            f.seek(start)
            try:
                shutil.copyfileobj(f, self.wfile, 1 << 20)
            except (BrokenPipeError, ConnectionResetError):
                pass    # the client went away mid-file: that is a test, not a fault


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Host)
with open(portfile + ".tmp", "w") as f:
    f.write(str(server.server_address[1]))
os.replace(portfile + ".tmp", portfile)
server.serve_forever()
