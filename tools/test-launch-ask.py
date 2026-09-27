#!/usr/bin/env python3
"""kryptik-launch --ask reads an encrypted zone's passphrase on its controlling
terminal, and without one hands the question to the chrome. dwl's spawn keeps
the session's stdin, a terminal, but calls setsid(): that launch must reach the
chrome, not die for want of /dev/tty."""
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading


def main():
    root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="kryptik-launch-ask-") as tmp:
        work = Path(tmp)
        called = work / "chrome-args"
        chrome = work / "chrome"
        chrome.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$@\" > '{called}'\n")
        chrome.chmod(0o700)
        launch_socket = work / "launch.sock"
        # The real launcher, its chrome and daemon socket pointed at stand-ins.
        source = (root / "tools/desktop/kryptik-launch.c").read_text()
        for name, old, new in [
            ("CHROME_BIN", "/usr/bin/kryptik-chrome", chrome),
            ("LAUNCH_SOCKET", "/run/kryptik-launch/launch.sock", launch_socket),
        ]:
            definition = f'#define {name} "{old}"'
            assert source.count(definition) == 1, f"update test path substitution for {name}"
            source = source.replace(definition, f'#define {name} "{new}"')
        (work / "launcher.c").write_text(source)
        subprocess.run(["cc", "-O2", "-o", str(work / "launcher"), str(work / "launcher.c")], check=True)

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as daemon:
            daemon.bind(str(launch_socket))
            daemon.listen(1)
            daemon.settimeout(5)

            def info():  # the daemon's answer to "info work", worded as serve.rs words it
                with daemon.accept()[0] as conn:
                    conn.settimeout(5)
                    request = b""
                    while chunk := conn.recv(256):
                        request += chunk
                    assert request == b"info work\n", request
                    conn.sendall(b"encrypted yes\nrunning no\nlabel WORK\nend\n")

            def launch(stdin):  # returns the launcher's result and what the chrome was asked
                called.unlink(missing_ok=True)
                answer = threading.Thread(target=info)
                answer.start()
                run = subprocess.run(
                    [str(work / "launcher"), "--ask", "work", "--", "/bin/true"],
                    stdin=stdin, start_new_session=True, capture_output=True, timeout=8,
                    env={**os.environ, "XDG_RUNTIME_DIR": str(work), "WAYLAND_DISPLAY": "wayland-0"},
                )
                answer.join(timeout=6)
                return run, called.read_text() if called.exists() else ""

            master, slave = os.openpty()
            try:
                cases = [
                    ("a terminal on stdin but none controlling, as dwl spawns", launch(slave)),
                    ("no terminal at all", launch(subprocess.DEVNULL)),
                ]
            finally:
                os.close(slave)
            os.set_blocking(master, False)
            try:
                written = os.read(master, 4096)
            except OSError:
                written = b""
            os.close(master)
            assert b"passphrase" not in written, "asked on a terminal it does not control"
            for case, (run, asked) in cases:
                assert run.returncode == 0, f"{case}: {run.stderr.decode(errors='replace')}"
                assert asked == "--prompt\nwork\n--\n/bin/true\n", f"{case}: the chrome was not asked ({asked!r})"
                print(f"PASS: {case}: the chrome asks for the passphrase")


if __name__ == "__main__":
    main()
