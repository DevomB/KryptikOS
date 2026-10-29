#!/usr/bin/env python3
"""Test what vm-drive.py's steps consume from the serial stream, against a stand-in shell."""
import importlib.util, json, os, socket, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("vm_drive", os.path.join(HERE, "..", "image", "vm-drive.py"))
vm = importlib.util.module_from_spec(spec); spec.loader.exec_module(vm)

PASS = 0; FAIL = 0
def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  PASS  {name}")
    else:
        FAIL += 1; print(f"  FAIL  {name} (got {got!r}, want {want!r})")

class Guest(threading.Thread):
    """A stand-in login shell: each command's scripted output and status, su, and poweroff."""
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

print("-- su: leaves what the command printed, as run: does")
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

print("-- an unknown step is refused")
import contextlib, io
sock2 = os.path.join(T, "serial2")
Guest(sock2, {}).start()
out = io.StringIO()
argv, sys.argv = sys.argv, ["vm-drive.py", "--serial", sock2, "--timeout", "2", "absent:x"]
with contextlib.redirect_stdout(out):
    rc = vm.main()
sys.argv = argv
check("absent: is refused as an unknown step", (rc, "unknown step" in out.getvalue()), (1, True))

print("-- type-from's value is read only once its line has ended")
class Pieces(threading.Thread):
    """A guest whose line arrives in pieces, as a serial port may send it."""
    def __init__(self, path, pieces):
        super().__init__(daemon=True)
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(path); self.srv.listen(1)
        self.pieces = pieces

    def run(self):
        c, _ = self.srv.accept()
        for p in self.pieces:
            c.sendall(p); time.sleep(0.3)
        time.sleep(2)

sock3 = os.path.join(T, "serial3")
Pieces(sock3, [b"GT CONSENT-CODE 1 4", b"9\r\n"]).start()
d3 = vm.Drive(sock3, None, 2)
check("a code cut across two reads is taken whole", d3.line_value(r"GT CONSENT-CODE 1 ([0-9]+)"), "49")

print("-- a command's status is read only once its line has ended")
sock4 = os.path.join(T, "serial4")
Pieces(sock4, [b"KRC1=1", b"27\r\n"]).start()
d4 = vm.Drive(sock4, None, 2)
check("a status cut across two reads is taken whole", d4.finish("KRC1", "cmd").group(1), b"127")

print("-- plug: and unplug: ask QEMU for a stick, and pull it out")
class Qmp(threading.Thread):
    """A stand-in QMP socket: what it was asked, in order; blockdev-del refused while BUSY lasts."""
    def __init__(self, path, busy):
        super().__init__(daemon=True)
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(path); self.srv.listen(8)
        self.asked = []; self.busy = busy

    def run(self):
        while True:
            c, _ = self.srv.accept()
            f = c.makefile("rwb", buffering=0)
            f.write(b'{"QMP": {}}\n')
            for line in f:
                msg = json.loads(line)
                if msg["execute"] != "qmp_capabilities":
                    self.asked.append((msg["execute"], msg.get("arguments")))
                if msg["execute"] == "blockdev-del" and self.busy > 0:
                    self.busy -= 1
                    f.write(b'{"error": {"class": "GenericError", "desc": "in use"}}\n')
                else:
                    f.write(b'{"return": {}}\n')
            c.close()

sock5 = os.path.join(T, "serial5"); qmp5 = os.path.join(T, "qmp5")
Guest(sock5, {}).start()
q = Qmp(qmp5, busy=1); q.start()
argv, sys.argv = sys.argv, ["vm-drive.py", "--serial", sock5, "--qmp", qmp5, "--timeout", "5",
                            "plug:stick1:stick.img:ro", "unplug:stick1"]
with contextlib.redirect_stdout(io.StringIO()):
    rc = vm.main()
sys.argv = argv
check("plug: and unplug: succeed", rc, 0)
want_file = {"driver": "file", "filename": os.path.abspath("stick.img"), "read-only": True}
check("plug: adds the file read-only, then a USB stick on the xHCI port", q.asked[:2], [
    ("blockdev-add", {"driver": "raw", "node-name": "stick1", "read-only": True, "file": want_file}),
    ("device_add", {"driver": "usb-storage", "id": "stick1", "drive": "stick1", "bus": "xhci.0", "removable": True})])
check("unplug: removes the device, then its drive once QEMU lets it go", q.asked[2:], [
    ("device_del", {"id": "stick1"}), ("blockdev-del", {"node-name": "stick1"}), ("blockdev-del", {"node-name": "stick1"})])

print("-- plug-sound: and unplug-sound: add a USB sound card on an audio backend, and pull it out")
sock6 = os.path.join(T, "serial6"); qmp6 = os.path.join(T, "qmp6")
Guest(sock6, {}).start()
q6 = Qmp(qmp6, busy=0); q6.start()
argv, sys.argv = sys.argv, ["vm-drive.py", "--serial", sock6, "--qmp", qmp6, "--timeout", "5",
                            "plug-sound:usbsound:snd2", "unplug-sound:usbsound"]
with contextlib.redirect_stdout(io.StringIO()):
    rc = vm.main()
sys.argv = argv
check("plug-sound: and unplug-sound: succeed", rc, 0)
check("the card goes on the xHCI port with its backend, and comes off with no drive to remove", q6.asked, [
    ("device_add", {"driver": "usb-audio", "id": "usbsound", "audiodev": "snd2", "bus": "xhci.0"}),
    ("device_del", {"id": "usbsound"})])

print("-- touch: taps the touchscreen on the GPU's first head: a finger down, then lifted")
sock7 = os.path.join(T, "serial7"); qmp7 = os.path.join(T, "qmp7")
Guest(sock7, {}).start()
q7 = Qmp(qmp7, busy=0); q7.start()
argv, sys.argv = sys.argv, ["vm-drive.py", "--serial", sock7, "--qmp", qmp7, "--timeout", "5", "touch:250,500"]
with contextlib.redirect_stdout(io.StringIO()):
    rc = vm.main()
sys.argv = argv
check("touch: succeeds", rc, 0)
mt = lambda kind, tracking, axis="x", value=0: {"type": "mtt", "data": {"type": kind, "slot": 0, "tracking-id": tracking, "axis": axis, "value": value}}
check("the finger goes down at a quarter across and half down, then lifts, both bound to head 0", q7.asked, [
    ("input-send-event", {"device": "gpu0", "head": 0, "events": [
        mt("begin", 1), mt("data", 1, "x", 8191), mt("data", 1, "y", 16383),
        {"type": "btn", "data": {"down": True, "button": "touch"}}]}),
    ("input-send-event", {"device": "gpu0", "head": 0, "events": [
        mt("end", -1), {"type": "btn", "data": {"down": False, "button": "touch"}}]})])
sock8 = os.path.join(T, "serial8")
Guest(sock8, {}).start()
argv, sys.argv = sys.argv, ["vm-drive.py", "--serial", sock8, "--qmp", qmp7, "--timeout", "5", "touch:1200,500"]
with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
    rc = vm.main()
sys.argv = argv
check("a tap off the screen is refused before QEMU is asked", (rc != 0, len(q7.asked)), (True, 2))

print("-- button: clicks the mouse where the pointer is; button-down: and button-up: hold it and let it go")
sock9 = os.path.join(T, "serial9"); qmp9 = os.path.join(T, "qmp9")
Guest(sock9, {}).start()
q9 = Qmp(qmp9, busy=0); q9.start()
argv, sys.argv = sys.argv, ["vm-drive.py", "--serial", sock9, "--qmp", qmp9, "--timeout", "5",
                            "button:left", "button-down:right", "button-up:right", "button:wheel-down"]
with contextlib.redirect_stdout(io.StringIO()):
    rc = vm.main()
sys.argv = argv
check("button:, button-down: and button-up: succeed", rc, 0)
btn = lambda down, name: ("input-send-event", {"events": [{"type": "btn", "data": {"down": down, "button": name}}]})
check("a click is a press then a release; a hold is the press alone, and its release comes when asked", q9.asked, [
    btn(True, "left"), btn(False, "left"), btn(True, "right"), btn(False, "right"),
    btn(True, "wheel-down"), btn(False, "wheel-down")])
sock10 = os.path.join(T, "serial10")
Guest(sock10, {}).start()
argv, sys.argv = sys.argv, ["vm-drive.py", "--serial", sock10, "--qmp", qmp9, "--timeout", "5", "button:side"]
with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
    rc = vm.main()
sys.argv = argv
check("a button not named is refused before QEMU is asked", (rc != 0, len(q9.asked)), (True, 6))

print()
print(f"{PASS} passed, {FAIL} failed")
sys.exit(0 if FAIL == 0 else 1)
