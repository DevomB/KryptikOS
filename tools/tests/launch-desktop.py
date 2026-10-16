#!/usr/bin/env python3
"""kryptik-launch --desktop starts the session's spawner (dwl's binary, -X), then asks the launch
daemon for dwl with three descriptors: the spawner's socket, dwl's status and the log. When the
daemon starts dwl, the launcher lasts until dwl's end and then waits for the spawner, which ends
the chrome it started on dwl's status. When the daemon does not start dwl, refused, failing or
absent, the launcher becomes dwl itself (-S), with the group, and says so."""
from pathlib import Path
import array
import os
import socket
import stat
import subprocess
import tempfile
import threading
import time

# The stand-in for /usr/bin/dwl: the spawner (-X) starts its command on descriptor 4 once dwl
# names its display, and ends with dwl's end of the socket; dwl itself (-S) names its display and
# writes one status line.
STANDIN = r'''#!/usr/bin/env python3
import os, socket, subprocess, sys
args = sys.argv[1:]
if args[:2] == ["-X", "3"]:
    cmd = args[3:] if args[2:3] == ["--"] else args[2:]
    s = socket.socket(fileno=3)
    chrome = None
    while m := s.recv(64):
        if len(m) > 1 and chrome is None:
            chrome = subprocess.Popen(cmd, stdin=4, env=dict(os.environ, WAYLAND_DISPLAY=m.decode()))
    if chrome:
        chrome.wait()
elif args == ["-S", "3"]:
    socket.socket(fileno=3).send(b"wayland-fallback")
    print("fallback status", flush=True)
else:
    sys.exit("stand-in dwl: " + " ".join(args))
'''


def main():
    root = Path(__file__).resolve().parent.parent.parent
    with tempfile.TemporaryDirectory(prefix="kryptik-launch-desktop-") as tmp:
        work = Path(tmp)
        launch_socket = work / "launch.sock"
        standin = work / "dwl"
        standin.write_text(STANDIN)
        standin.chmod(0o755)
        # The real launcher, its daemon socket and dwl pointed at stand-ins.
        source = (root / "tools/desktop/kryptik-launch.c").read_text()
        for old, new in [('#define LAUNCH_SOCKET "/run/kryptik-launch/launch.sock"', f'#define LAUNCH_SOCKET "{launch_socket}"'),
                         ('#define DWL_BIN "/usr/bin/dwl"', f'#define DWL_BIN "{standin}"')]:
            assert source.count(old) == 1, f"update the test's substitution for {old}"
            source = source.replace(old, new)
        (work / "launcher.c").write_text(source)
        subprocess.run(["cc", "-O2", "-o", str(work / "launcher"), str(work / "launcher.c")], check=True)
        chrome_out, display = work / "chrome.out", work / "display"
        # The chrome, standing in: where it was shown, and the status it read.
        argv = [str(work / "launcher"), "--desktop", "--", "/bin/sh", "-c", f'echo "$WAYLAND_DISPLAY" > {display}; cat > {chrome_out}']
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "XKB_DEFAULT_LAYOUT": "us,de", "KRYPTIK_LAYOUTS": "us de"}

        def launch(act):  # exit, stderr, the request and its descriptors' kinds; no daemon when act is None
            got = []
            daemon = None
            if act is not None:
                daemon = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                daemon.bind(str(launch_socket))
                daemon.listen(1)
                daemon.settimeout(5)

                def serve():
                    with daemon.accept()[0] as conn:
                        conn.settimeout(5)
                        data, anc, _, _ = conn.recvmsg(4096, socket.CMSG_SPACE(4 * array.array("i").itemsize))
                        fds = array.array("i")
                        for level, kind, payload in anc:
                            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                                fds.frombytes(payload[: len(payload) - len(payload) % fds.itemsize])
                        while not data.endswith(b"\nend\n") and (chunk := conn.recv(4096)):
                            data += chunk
                        kinds = [stat.S_IFMT(os.fstat(fd).st_mode) for fd in fds]
                        spawner_type = socket.socket(fileno=os.dup(fds[0])).type if fds else None
                        got.append((data, kinds, spawner_type))
                        act(conn, list(fds))

                thread = threading.Thread(target=serve)
                thread.start()
            try:
                for f in (chrome_out, display):
                    f.unlink(missing_ok=True)
                p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
                _, err = p.communicate(timeout=15)
            finally:
                if daemon is not None:
                    thread.join(timeout=6)
                    daemon.close()
                    launch_socket.unlink(missing_ok=True)
            return p.returncode, err.decode(), got[0] if got else None

        def starts(conn, fds):  # dwl as the daemon starts it: it names its display, writes, ends
            conn.sendall(b"started 4242\n")
            socket.socket(fileno=os.dup(fds[0])).send(b"wayland-test")
            os.write(fds[1], b"status from dwl\n")
            for fd in fds:
                os.close(fd)
            time.sleep(0.2)
            conn.sendall(b"ok dwl exited 0\n")

        def answers(text):
            def act(conn, fds):
                for fd in fds:
                    os.close(fd)
                conn.sendall(text)
            return act

        cases = [
            ("the daemon starts dwl", starts, "wayland-test", "status from dwl\n",
             ["the daemon starts dwl as pid 4242, without group kryptik", "the desktop ended: ok dwl exited 0"]),
            ("the daemon refuses", answers(b"error: uid 1000's desktop runs already\n"), "wayland-fallback", "fallback status\n",
             ["dwl starts with group kryptik, in the session's process: error: uid 1000's desktop runs already"]),
            ("dwl did not start", answers(b"started 4242\nerror: dwl did not start: setresuid: Operation not permitted\n"),
             "wayland-fallback", "fallback status\n", ["dwl starts with group kryptik", "error: dwl did not start: setresuid"]),
            ("no daemon answers", None, "wayland-fallback", "fallback status\n", [f"dwl starts with group kryptik, in the session's process: {launch_socket}:"]),
        ]
        for case, act, want_display, want_status, said in cases:
            rc, err, request = launch(act)
            assert rc == 0, f"{case}: exit {rc}: {err}"
            for line in said:
                assert line in err, f"{case}: stderr says {err!r}, not {line!r}"
            for _ in range(50):
                if chrome_out.exists() and chrome_out.read_text() == want_status:
                    break
                time.sleep(0.1)
            assert display.read_text().strip() == want_display, f"{case}: the chrome was shown on {display.read_text()!r}"
            assert chrome_out.read_text() == want_status, f"{case}: the chrome read {chrome_out.read_text()!r}"
            if request is not None:
                data, kinds, spawner_type = request
                assert data == b"desktop\nenv XKB_DEFAULT_LAYOUT=us,de\nenv KRYPTIK_LAYOUTS=us de\nend\n", f"{case}: asked {data!r}"
                assert kinds[:2] == [stat.S_IFSOCK, stat.S_IFIFO] and len(kinds) == 3, f"{case}: descriptors {kinds}"
                assert spawner_type == socket.SOCK_SEQPACKET, f"{case}: the spawner's socket is {spawner_type}"
            print(f"PASS: {case}: the chrome read dwl's status on {want_display}, and stderr says what ran")

        run = subprocess.run([str(work / "launcher"), "--desktop", "/bin/true"], capture_output=True, timeout=8)
        assert run.returncode == 2 and b"usage:" in run.stderr, f"no -- before the program: {run}"
        print("PASS: --desktop without -- is a usage error")


if __name__ == "__main__":
    main()
