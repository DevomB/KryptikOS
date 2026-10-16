#!/usr/bin/env python3
"""kryptik-launch --desktop asks the launch daemon to move it into the desktop's cgroup, then
becomes the desktop's first program in the same process, so the move covers all the desktop
starts. A refusal, an error or no daemon at all is said on stderr, and the desktop still starts."""
from pathlib import Path
import socket
import subprocess
import tempfile
import threading


def main():
    root = Path(__file__).resolve().parent.parent.parent
    with tempfile.TemporaryDirectory(prefix="kryptik-launch-desktop-") as tmp:
        work = Path(tmp)
        launch_socket = work / "launch.sock"
        # The real launcher, its daemon socket pointed at a stand-in.
        source = (root / "tools/desktop/kryptik-launch.c").read_text()
        definition = '#define LAUNCH_SOCKET "/run/kryptik-launch/launch.sock"'
        assert source.count(definition) == 1, "update test path substitution for LAUNCH_SOCKET"
        (work / "launcher.c").write_text(source.replace(definition, f'#define LAUNCH_SOCKET "{launch_socket}"'))
        subprocess.run(["cc", "-O2", "-o", str(work / "launcher"), str(work / "launcher.c")], check=True)
        # The desktop's first program, standing in for dwl: it says which process it runs as.
        argv = [str(work / "launcher"), "--desktop", "--", "/bin/sh", "-c", "echo ran $$"]

        def launch(answer):  # pid, exit, stdout, stderr and the request; no daemon when answer is None
            got = []
            daemon = None
            if answer is not None:
                daemon = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                daemon.bind(str(launch_socket))
                daemon.listen(1)
                daemon.settimeout(5)

                def serve():
                    with daemon.accept()[0] as conn:
                        conn.settimeout(5)
                        request = b""
                        while chunk := conn.recv(4096):
                            request += chunk
                        got.append(request)
                        conn.sendall(answer)

                thread = threading.Thread(target=serve)
                thread.start()
            try:
                p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = p.communicate(timeout=8)
            finally:
                if daemon is not None:
                    thread.join(timeout=6)
                    daemon.close()
                    launch_socket.unlink(missing_ok=True)
            return p.pid, p.returncode, out.decode(), err.decode(), got[0] if got else None

        cases = [
            ("the daemon moves it", b"ok /sys/fs/cgroup/kryptik-desktop memory.max 4194304000\n",
             "the desktop's cgroup: /sys/fs/cgroup/kryptik-desktop memory.max 4194304000"),
            ("the daemon refuses", b"error: pid 9 runs in a zone's or a proxy's cgroup\n",
             "the desktop runs without its memory bound: error: pid 9 runs in a zone's or a proxy's cgroup"),
            ("no daemon answers", None, f"the desktop runs without its memory bound: {launch_socket}:"),
        ]
        for case, answer, said in cases:
            pid, rc, out, err, request = launch(answer)
            assert rc == 0, f"{case}: exit {rc}: {err}"
            assert out == f"ran {pid}\n", f"{case}: the desktop did not start as the launcher's own process ({out!r}, pid {pid})"
            assert said in err, f"{case}: stderr says {err!r}"
            if answer is not None:
                assert request == b"desktop\n", f"{case}: the daemon was asked {request!r}"
            print(f"PASS: {case}: the desktop starts in the launcher's own process, and stderr says so")

        run = subprocess.run([str(work / "launcher"), "--desktop", "/bin/true"], capture_output=True, timeout=8)
        assert run.returncode == 2 and b"usage:" in run.stderr, f"no -- before the program: {run}"
        print("PASS: --desktop without -- is a usage error")


if __name__ == "__main__":
    main()
