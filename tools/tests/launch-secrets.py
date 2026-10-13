#!/usr/bin/env python3
"""kryptik-launch hands its passphrase fd to the launch daemon, not the display proxy."""
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
    root = Path(__file__).resolve().parent.parent.parent
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
        # The real launcher, its proxy and socket paths pointed at stand-ins.
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
        # A descriptor is a whole number: "3x", "" or "-1" never reaches the daemon.
        for bad in ["3x", "", "-1", "99999999999"]:
            run = subprocess.run([str(work / "launcher"), "--passphrase-fd", bad, "work", "--", "/bin/true"],
                                 capture_output=True, timeout=8)
            assert run.returncode == 2, f"--passphrase-fd {bad!r} was taken"
        print("PASS: --passphrase-fd takes only a descriptor number")
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
                # Given a passphrase, the launcher first asks whether the zone waits for one since a
                # sleep, then runs.
                for _ in range(2):
                    with daemon.accept()[0] as conn:
                        conn.settimeout(5)
                        request, ancillary, _, _ = conn.recvmsg(16384, socket.CMSG_SPACE(4))
                        for level, kind, data in ancillary:
                            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                                fds = array.array("i")
                                fds.frombytes(data)
                                for fd in fds:
                                    try:
                                        received.append(os.read(fd, 4096))
                                    finally:
                                        os.close(fd)
                        if request.startswith(b"info work"):
                            conn.sendall(b"encrypted yes\nrunning no\nwaiting no\nlabel WORK\nend\n")
                        else:
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

        # A zone that waits for its volume's passphrase since a sleep: the passphrase goes with
        # resume-zone, and nothing is launched, whether a command was given or --resume.
        launch_socket.unlink()
        requests = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as daemon:
            daemon.bind(str(launch_socket))
            daemon.listen(1)
            daemon.settimeout(5)

            def resume(count):
                for _ in range(count):
                    with daemon.accept()[0] as conn:
                        conn.settimeout(5)
                        request, ancillary, _, _ = conn.recvmsg(16384, socket.CMSG_SPACE(4))
                        for level, kind, data in ancillary:
                            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                                fds = array.array("i")
                                fds.frombytes(data)
                                for fd in fds:
                                    try:
                                        received.append(os.read(fd, 4096))
                                    finally:
                                        os.close(fd)
                        requests.append(request)
                        if request.startswith(b"info work"):
                            conn.sendall(b"encrypted yes\nrunning yes\nwaiting yes\nlabel WORK\nend\n")
                        else:
                            conn.sendall(b"ok\n")

            for argv, count in ((["--passphrase-fd", "{fd}", "work", "--", "/bin/true"], 2),
                                (["--passphrase-fd", "{fd}", "--resume", "work"], 1)):
                requests.clear()
                received.clear()
                server = threading.Thread(target=resume, args=(count,))
                server.start()
                with secret.open("rb") as f:
                    run = subprocess.run([str(work / "launcher")] + [a.format(fd=f.fileno()) for a in argv],
                                         pass_fds=(f.fileno(),), capture_output=True, timeout=8)
                server.join(timeout=6)
                assert run.returncode == 0, run.stderr.decode(errors="replace")
                assert requests[-1] == b"resume-zone work\n", f"the daemon was asked {requests!r}"
                assert received == [b"test-passphrase-only"], "the passphrase did not come with resume-zone"
                assert b"goes on where it was" in run.stdout, run.stdout
            print("PASS: a zone that waits since a sleep gets its passphrase through resume-zone, and nothing launches")


if __name__ == "__main__":
    main()
