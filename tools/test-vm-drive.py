#!/usr/bin/env python3
"""vm-drive.py against a stand-in guest: a socket that answers like the shell.

Every VM suite is written in the driver's steps, and what one step consumes
from the serial stream decides whether the step after it can see what it
needs. That contract is pinned here in a second, with no QEMU: a thread
plays the guest, answering each command line with the command's output, the
exit marker the driver appended and a prompt, and answering su with a
password prompt first. It was first broken by run:, which consumed a
command's output with its marker; the update suite's eighth step then waited
420 s for a word its own command had printed.

Exit 0 when every case passes.
"""
import importlib.util, os, socket, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("vm_drive", os.path.join(HERE, "image", "vm-drive.py"))
vm = importlib.util.module_from_spec(spec); spec.loader.exec_module(vm)

PASS = 0; FAIL = 0
def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  PASS  {name}")
    else:
        FAIL += 1; print(f"  FAIL  {name} (got {got!r}, want {want!r})")

class Guest(threading.Thread):
    """Answers each line the way the login shell would. A command line is
    answered with the output the script names for it, its status behind the
    driver's marker, and a prompt. `su - root -c '...'` is answered with a
    password prompt, and the next line (the password) runs what was quoted.
    poweroff ends with the kernel's last words and the socket closing."""
    def __init__(self, path, script):
        super().__init__(daemon=True)
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(path); self.srv.listen(1)
        self.script = script   # substring of the command -> (output, status)

    def answer(self, c, line):
        if "poweroff" in line:
            c.sendall(b"reboot: Power down\r\n"); c.close(); return False
        out, status = next(((o, s) for k, (o, s) in self.script.items() if k in line), (b"", 0))
        tag = line.rsplit("; echo ", 1)[1].split("=")[0] if "; echo KRC" in line else None
        c.sendall(out + (f"{tag}={status}\r\n".encode() if tag else b"") + b"KDRV$ ")
        return True

    def run(self):
        c, _ = self.srv.accept()
        buf = b""; pending = None
        while True:
            d = c.recv(4096)
            if not d:
                return
            buf += d
            while b"\r" in buf:
                line, _, buf = buf.partition(b"\r")
                line = line.decode()
                if pending is not None:
                    inner, pending = pending, None
                    if not self.answer(c, inner): return
                elif line.startswith("su - root -c '"):
                    pending = line[len("su - root -c '"):-1]
                    c.sendall(b"Password: ")
                else:
                    if not self.answer(c, line): return

T = tempfile.mkdtemp()
sock = os.path.join(T, "serial")
Guest(sock, {
    "kryptik update status": (b"STATED-OK\r\n", 0),
    "false": (b"", 1),
    "id": (b"uid=0(root)\r\n", 0),
}).start()
d = vm.Drive(sock, None, 2)

print("-- run: leaves what the command printed")
d.run("kryptik update status | grep -q newest && echo STATED-OK")
try:
    d.expect("STATED-OK"); got = "found"
except RuntimeError as e:
    got = "timeout" if "timeout" in str(e) else str(e)
check("a word a run: command printed is there for the expect: after it", got, "found")

print("-- run: judges the status")
check("run! reports a failed command's status", d.run("false", require_zero=False), 1)
try:
    d.run("false"); got = "accepted"
except RuntimeError as e:
    got = "refused" if "command failed (1)" in str(e) else str(e)
check("run: refuses a failed command", got, "refused")

print("-- su: leaves what the command printed, as before")
d.su("root-pw", "id")
try:
    d.expect(r"uid=0\(root\)"); got = "found"
except RuntimeError as e:
    got = "timeout" if "timeout" in str(e) else str(e)
check("a word an su: command printed is there for the expect: after it", got, "found")

print("-- the guest goes away")
m = d.su("root-pw", "poweroff")
check("su: returns the shutdown message in place of a status", m.group(1), None)
try:
    d.expect("Power down"); got = "found"
except RuntimeError as e:
    got = str(e)
check("the shutdown message stays for the driver's own expect of it", got, "found")
deadline = time.time() + 2
while not d.closed and time.time() < deadline:
    d._read()
check("wait-exit sees the socket close", d.closed, True)

print()
print(f"{PASS} passed, {FAIL} failed")
sys.exit(0 if FAIL == 0 else 1)
