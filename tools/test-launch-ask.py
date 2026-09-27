#!/usr/bin/env python3
"""kryptik-launch --ask reads an encrypted zone's passphrase on its controlling
terminal, and without one hands the question to the chrome. dwl's spawn keeps
the session's stdin, a terminal, but calls setsid(): that launch must reach the
chrome, not die for want of /dev/tty. On a terminal of its own, a passphrase
typed before the prompt is taken whole."""
import array
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
        launcher = str(work / "launcher")

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as daemon:
            daemon.bind(str(launch_socket))
            daemon.listen(2)
            daemon.settimeout(5)
            passphrases = []

            def serve(count):  # the launch daemon for COUNT requests, answered as serve.rs words them
                for _ in range(count):
                    with daemon.accept()[0] as conn:
                        conn.settimeout(5)
                        request, ancillary, _, _ = conn.recvmsg(4096, socket.CMSG_SPACE(4))
                        for level, kind, data in ancillary:
                            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                                fds = array.array("i")
                                fds.frombytes(data)
                                for fd in fds:
                                    passphrases.append(os.read(fd, 4096))
                                    os.close(fd)
                        while chunk := conn.recv(4096):
                            request += chunk
                        if request == b"info work\n":
                            conn.sendall(b"encrypted yes\nrunning no\nlabel WORK\nend\n")
                        else:
                            assert request.startswith(b"run work"), request
                            conn.sendall(b"ok 1234\n")

            def launch(argv, stdin, requests, **extra):  # the result, and what the chrome was asked
                called.unlink(missing_ok=True)
                answer = threading.Thread(target=serve, args=(requests,))
                answer.start()
                try:
                    run = subprocess.run(
                        argv, stdin=stdin, capture_output=True, timeout=8,
                        env={**os.environ, "XDG_RUNTIME_DIR": str(work), "WAYLAND_DISPLAY": "wayland-0"},
                        **extra,
                    )
                finally:
                    answer.join(timeout=6)
                return run, called.read_text() if called.exists() else ""

            ask = [launcher, "--ask", "work", "--", "/bin/true"]
            master, slave = os.openpty()
            try:
                cases = [
                    ("a terminal on stdin but none controlling, as dwl spawns",
                     launch(ask, slave, 1, start_new_session=True)),
                    ("no terminal at all", launch(ask, subprocess.DEVNULL, 1, start_new_session=True)),
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

            # A terminal of its own (setsid --ctty), with the passphrase typed
            # before the prompt appeared: it must be taken whole, not flushed.
            master, slave = os.openpty()
            os.write(master, b"typed-ahead-pass\n")
            try:
                run, asked = launch(["setsid", "--ctty", launcher, "--ask", "--no-display", "work", "--", "/bin/true"], slave, 2)
            except subprocess.TimeoutExpired:
                raise AssertionError("a passphrase typed before the prompt was thrown away: the launcher still waits") from None
            finally:
                os.close(slave)
                os.close(master)
            assert run.returncode == 0, run.stderr.decode(errors="replace")
            assert asked == "", f"the chrome was asked although the terminal was there ({asked!r})"
            assert passphrases == [b"typed-ahead-pass"], f"the daemon got {passphrases!r}"
            print("PASS: its own terminal: a passphrase typed ahead of the prompt reaches the daemon whole")


if __name__ == "__main__":
    main()
