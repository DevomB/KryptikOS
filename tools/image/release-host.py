#!/usr/bin/env python3
"""A release host for the suites: static files over HTTP, on loopback only.

    release-host.py ROOT PORTFILE LOG [NORANGE]

Serves ROOT on 127.0.0.1 and a port the kernel picks, written to PORTFILE
once the socket is listening. Honours `Range: bytes=N-` with a 206, which is
what the update channel asks a release host for (docs/design/update-channel.md)
and what python's own http.server does not do; while the file NORANGE exists
it ignores Range and sends the whole file, which is the server the fetcher
must also survive. Files are streamed, never read whole: a root image is
gigabytes. Every request is one line in LOG: the path, then the Range header
or `-`.

Loopback only, on purpose: under QEMU's user network the guest reaches this
as 10.0.2.2, and nothing else on the runner's network can ask it anything.
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
        # Links inside ROOT may point anywhere (the suites link to a payload
        # rather than copy it); the requested NAME may not leave ROOT. The
        # name is normalised and held to ROOT before anything touches the
        # filesystem with it.
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
