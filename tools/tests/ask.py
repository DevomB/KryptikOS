#!/usr/bin/env python3
"""build/service-scripts/ask.sh, what sysinit and firstboot ask a person: the
question appears on every console, the first line typed on any of them is the
answer, echo is off while a secret is asked and back on afterwards, and no
answer in time, or no console left to answer on, is a failure, not a hang.
Two pseudo-terminals stand in for the screen and a serial port."""
import os
import pty
import select
import subprocess
import sys
import tempfile
import termios
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ASK = os.path.join(ROOT, "build", "service-scripts", "ask.sh")
failed = 0


def check(ok, what):
    global failed
    print(("  ok    " if ok else "  FAIL  ") + what)
    if not ok:
        failed += 1


def consoles():
    """Two terminals: (master, slave fd, slave path) each."""
    out = []
    for _ in range(2):
        m, s = pty.openpty()
        out.append((m, s, os.ttyname(s)))
    return out


def start(args, ttys, run):
    # consoles() is replaced after sourcing, as the terminals are not the
    # machine's; everything else is the file as it ships.
    script = ('. "$ASK"; ask_dir="$RUN"; '
              'consoles() { for t in $TTYS; do echo "$t"; done; }; ask ' + args)
    env = dict(os.environ, ASK=ASK, RUN=run, TTYS=" ".join(t[2] for t in ttys))
    return subprocess.Popen(["sh", "-c", script], env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, start_new_session=True)


def read_until(master, text, secs=5.0):
    seen = b""
    end = time.monotonic() + secs
    while text not in seen and time.monotonic() < end:
        ready, _, _ = select.select([master], [], [], 0.1)
        if ready:
            try:
                seen += os.read(master, 1024)
            except OSError:
                break
    return seen


def echo_on(slave):
    return bool(termios.tcgetattr(slave)[3] & termios.ECHO)


def finish(p, secs=10):
    try:
        out, _ = p.communicate(timeout=secs)
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
        return None, out
    return p.returncode, out


run = tempfile.mkdtemp()

print("-- a secret, answered on the second console")
ttys = consoles()
p = start('-s 30 "Q: "', ttys, run)
shown = all(b"Q: " in read_until(m, b"Q: ") for m, _, _ in ttys)
check(shown, "the question appears on both consoles")
check(not any(echo_on(s) for _, s, _ in ttys), "echo is off on both while it waits")
os.write(ttys[1][0], b"two words\n")
rc, out = finish(p)
check(rc == 0 and out == b"two words", "the second console's line is the answer, spaces kept (rc %s, %r)" % (rc, out))
check(all(echo_on(s) for _, s, _ in ttys), "echo is back on on both")
check(b"two words" not in read_until(ttys[1][0], b"\n", 1), "the secret was not echoed")
check(os.listdir(run) == [], "nothing is left in the run directory")

print("-- a plain question, answered on the first console")
ttys = consoles()
p = start('600 "Name: "', ttys, run)
for m, _, _ in ttys:
    read_until(m, b"Name: ")
check(all(echo_on(s) for _, s, _ in ttys), "echo stays on for a question that is not secret")
os.write(ttys[0][0], b"alice\n")
t0 = time.monotonic()
rc, out = finish(p)
check(rc == 0 and out == b"alice", "the first console's line is the answer (rc %s, %r)" % (rc, out))
check(time.monotonic() - t0 < 5, "it returns at once, not when the 600 s timer would")

print("-- no answer in time")
ttys = consoles()
t0 = time.monotonic()
rc, out = finish(start('-s 1 "Q: "', ttys, run))
check(rc == 1 and out == b"", "it fails when nothing is typed within the time (rc %s)" % rc)
check(time.monotonic() - t0 < 5, "and it does so when the time is up")
check(all(echo_on(s) for _, s, _ in ttys), "echo is back on after a timeout")

print("-- every console gone")
ttys = consoles()
p = start('-s 0 "Q: "', ttys, run)
for m, _, _ in ttys:
    read_until(m, b"Q: ")
for m, _, _ in ttys:
    os.close(m)
rc, out = finish(p)
check(rc == 1, "a question with no console left to answer fails instead of waiting for ever (rc %s)" % rc)

sys.exit(1 if failed else 0)
