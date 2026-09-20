#!/usr/bin/env python3
"""Linux regression: only the launch daemon receives the passphrase FD.

Build the real launcher with its two fixed executable/socket paths redirected
to temporary stand-ins. No installed binaries or host services are changed.
"""
import array
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading


def main():
    root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="kryptik-launch-secret-") as tmp:
        work = Path(tmp)
        proxy = work / "proxy"
        launch_socket = work / "launch.sock"
        proxy.write_text("""#!/usr/bin/env python3
import json, os, signal, socket, sys
from pathlib import Path
fds = {}
for name in os.listdir('/proc/self/fd'):
    try:
        fds[name] = os.readlink('/proc/self/fd/' + name)
    except FileNotFoundError:
        pass
Path(os.environ['KRYPTIK_TEST_FD_REPORT']).write_text(json.dumps(fds))
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[sys.argv.index('--listen') + 1])
s.listen(1)
signal.pause()
""")
        proxy.chmod(0o700)
        source = (root / "tools/desktop/kryptik-launch.c").read_text()
        for name, old, new in [
            ("PROXY_BIN", "/usr/bin/kryptik-wlproxy", proxy),
            ("LAUNCH_SOCKET", "/run/kryptik-launch/launch.sock", launch_socket),
        ]:
            definition = f'#define {name} "{old}"'
            assert source.count(definition) == 1, f"update test path substitution for {name}"
            source = source.replace(definition, f'#define {name} "{new}"')
        (work / "launcher.c").write_text(source)
        subprocess.run(["cc", "-O2", "-o", str(work / "launcher"), str(work / "launcher.c")], check=True)
        report = work / "proxy-fds.json"
        secret = work / "secret"
        secret.write_bytes(b"test-passphrase-only")
        secret.chmod(0o600)
        received = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as daemon, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as compositor:
            daemon.bind(str(launch_socket))
            daemon.listen(1)
            daemon.settimeout(5)
            compositor.bind(str(work / "wayland-0"))

            def receive():
                with daemon.accept()[0] as conn:
                    conn.settimeout(5)
                    _, ancillary, _, _ = conn.recvmsg(16384, socket.CMSG_SPACE(4))
                    for level, kind, data in ancillary:
                        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                            fds = array.array("i")
                            fds.frombytes(data)
                            for fd in fds:
                                try:
                                    received.append(os.read(fd, 4096))
                                finally:
                                    os.close(fd)
                    conn.sendall(b"ok 1234\n")

            receiver = threading.Thread(target=receive)
            receiver.start()
            try:
                with secret.open("rb") as f:
                    run = subprocess.run(
                        [str(work / "launcher"), "--passphrase-fd", str(f.fileno()), "work", "--", "/bin/true"],
                        pass_fds=(f.fileno(),), capture_output=True, timeout=8,
                        env={**os.environ, "XDG_RUNTIME_DIR": str(work), "WAYLAND_DISPLAY": "wayland-0", "KRYPTIK_TEST_FD_REPORT": str(report)},
                    )
                receiver.join(timeout=6)
                assert not receiver.is_alive(), "test daemon did not finish"
                assert run.returncode == 0, run.stderr.decode(errors="replace")
                assert received == [b"test-passphrase-only"], "the daemon did not receive the passphrase"
                assert str(secret) not in json.loads(report.read_text()).values(), "passphrase descriptor leaked into the display proxy"
                print("PASS: daemon receives the passphrase; exec'd display proxy has no secret descriptor")
            finally:
                pidfile = work / "kryptik/work/proxy.pid"
                if pidfile.exists():
                    try:
                        os.kill(int(pidfile.read_text()), signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                receiver.join(timeout=6)


if __name__ == "__main__":
    main()
