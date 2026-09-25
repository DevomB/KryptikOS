#!/usr/bin/env python3
"""Drive a guest over its serial console: expect, send, log in, run commands.

    tools/image/vm-drive.py --serial SOCK [--log FILE] [--timeout N] [--qmp SOCK]
                            [--record FILE] STEP...

Steps (each one argument):
    expect:REGEX            wait until REGEX matches the serial stream (and
                            consume the stream up to the match)
    seen:REGEX              wait until REGEX has appeared anywhere in the
                            transcript so far, consuming nothing (for a line
                            whose order among the others is not fixed)
    absent:REGEX            fail if REGEX is in the output not yet consumed
    send:TEXT               send TEXT followed by Enter
    login:USER:PASSWORD     wait for "login:", authenticate, wait for a prompt
    run:CMD                 run CMD at the shell, require exit status 0; what
                            it printed stays for the steps that follow
    run!:CMD                run CMD, any exit status
    su:PASSWORD:CMD         run CMD as root through su (root's password);
                            its output stays too
    grab:NAME:CMD           run CMD and record its output under NAME in --record
    sleep:SECONDS
    screendump:FILE         ask QEMU (QMP) for a PPM screenshot
    key:NAME[+NAME...]      press keys on the guest's keyboard through QMP
                            (qcodes, e.g. key:y  key:ret  key:alt+e)
    wait-exit               wait for the serial socket to close (guest gone)

With KRYPTIK_STATE_PASSPHRASE set, the driver answers an installed disk's
state passphrase prompt at every boot; no step names it. Exits 0 when every
step succeeded, else names the failing step. Standard library only.
"""
import json, os, re, socket, sys, time

UNLOCK = re.compile(rb"passphrase for the state partition \(try \d of 3\): ")

class Drive:
    def __init__(self, path, log, timeout):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(path)
        self.s.settimeout(0.5)
        self.buf = b""
        self.all = b""   # everything received, never consumed
        self.log = open(log, "ab") if log else None
        self.timeout = timeout
        self.closed = False
        self.marker = 0
        self.passphrase = os.environ.get("KRYPTIK_STATE_PASSPHRASE")
        self.answered = 0   # how far into the transcript the prompts are answered

    def _read(self):
        try:
            d = self.s.recv(65536)
        except socket.timeout:
            return False
        if not d:
            self.closed = True
            return False
        self.buf += d
        self.all += d
        if self.log:
            self.log.write(d); self.log.flush()
        if self.passphrase:
            # From the last answer, or just before this read: a prompt may
            # straddle two reads, and none is answered twice.
            for m in UNLOCK.finditer(self.all, max(self.answered, len(self.all) - len(d) - 80)):
                self.answered = m.end()
                self.send_secret(self.passphrase)
        return True

    def seen(self, regex, timeout=None):
        """Wait until REGEX is anywhere in the transcript, consumed output included."""
        timeout = self.timeout if timeout is None else timeout
        rx = re.compile(regex.encode(), re.M)
        deadline = time.time() + timeout
        while True:
            if rx.search(self.all):
                return True
            if self.closed:
                raise RuntimeError(f"serial closed before {regex!r} appeared")
            if time.time() > deadline:
                tail = self.all[-600:].decode("utf-8", "replace")
                raise RuntimeError(f"timeout ({timeout}s): {regex!r} never appeared; last output:\n{tail}")
            self._read()

    def expect(self, regex, timeout=None):
        timeout = self.timeout if timeout is None else timeout
        rx = re.compile(regex.encode(), re.M)
        deadline = time.time() + timeout
        while True:
            m = rx.search(self.buf)
            if m:
                self.buf = self.buf[m.end():]
                return m
            if self.closed:
                raise RuntimeError(f"serial closed while waiting for {regex!r}")
            if time.time() > deadline:
                tail = self.buf[-600:].decode("utf-8", "replace")
                raise RuntimeError(f"timeout ({timeout}s) waiting for {regex!r}; last output:\n{tail}")
            self._read()

    def send(self, text, enter=True):
        data = text.encode() + (b"\r" if enter else b"")
        self.s.sendall(data)
        if self.log:
            self.log.write(b"\n<<< " + text.encode() + b"\n"); self.log.flush()

    def send_secret(self, text):
        # Never logged: the transcript is uploaded with every acceptance report.
        self.s.sendall(text.encode() + b"\r")
        if self.log:
            self.log.write(b"\n<<< (a password)\n"); self.log.flush()

    def drain(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            self._read()

    def knock(self, regex, timeout=None, every=5):
        """Send an empty line every EVERY seconds until REGEX matches; consumes like expect()."""
        timeout = self.timeout if timeout is None else timeout
        rx = re.compile(regex.encode(), re.M)
        deadline = time.time() + timeout
        next_knock = 0
        knocks = 0
        while True:
            m = rx.search(self.buf)
            if m:
                self.buf = self.buf[m.end():]
                return m
            if self.closed:
                raise RuntimeError(f"serial closed while waiting for {regex!r}")
            now = time.time()
            if now > deadline:
                tail = self.buf[-600:].decode("utf-8", "replace")
                raise RuntimeError(f"timeout ({timeout}s) waiting for {regex!r} after {knocks} empty lines; last output:\n{tail}")
            if now >= next_knock:
                self.send("")
                knocks += 1
                next_knock = now + every
            self._read()

    def login(self, user, password):
        # agetty (built with AGETTY_RELOAD) prints "login:" only after input,
        # and flushes input that arrives within a second of starting or waking,
        # so one Enter can be lost: knock until the prompt appears.
        self.drain(1)
        self.knock(r"login: ?$", self.timeout)
        self.send(user)
        self.expect(r"Password: ?", 60)
        self.send_secret(password)
        # a fresh shell prompt: bash prints "user@host:dir$ " or "$ "
        self.expect(r"[$#] ?$", 60)
        # make the prompt unambiguous for run()
        self.send("PS1='KDRV\\$ '; export PS1; stty -echo 2>/dev/null; echo READY-$$")
        self.expect(r"READY-\d+", 30)
        self.expect(r"KDRV\$ ?$", 30)

    def run(self, cmd, require_zero=True):
        self.marker += 1
        tag = f"KRC{self.marker}"
        self.send(f"{cmd}; echo {tag}=$?")
        m = self.finish(tag, cmd)
        if m.group(1) is None:
            return 0   # the guest is going down on this command; no status follows
        rc = int(m.group(1))
        if require_zero and rc != 0:
            raise RuntimeError(f"command failed ({rc}): {cmd}")
        return rc

    def su(self, password, cmd):
        # A login shell: plain `su -c` keeps the user's PATH, which has no sbin.
        self.marker += 1
        tag = f"KRC{self.marker}"
        self.send(f"su - root -c '{cmd}; echo {tag}=$?'")
        self.expect(r"Password: ?", 60)
        self.send_secret(password)
        return self.finish(tag, cmd)

    def finish(self, tag, cmd):
        # Wait for the exit marker but leave the command's output for the
        # steps that follow; only the marker is dropped. A shutdown message
        # that matches instead stays, and is returned in place of a status.
        rx = re.compile(rf"{tag}=(\d+)|Power down|reboot: Restarting|Restarting system".encode(), re.M)
        deadline = time.time() + self.timeout
        while True:
            m = rx.search(self.buf)
            if m:
                if m.group(1) is not None:
                    self.buf = self.buf[:m.start()] + self.buf[m.end():]
                return m
            if self.closed:
                raise RuntimeError(f"serial closed while waiting for the end of: {cmd}")
            if time.time() > deadline:
                tail = self.buf[-600:].decode("utf-8", "replace")
                raise RuntimeError(f"timeout ({self.timeout}s) waiting for the end of: {cmd}; last output:\n{tail}")
            self._read()

def qmp(path, cmd, args=None):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path)
    f = s.makefile("rwb", buffering=0)
    f.readline()  # greeting
    f.write(b'{"execute":"qmp_capabilities"}\n'); f.readline()
    msg = {"execute": cmd}
    if args: msg["arguments"] = args
    f.write((json.dumps(msg) + "\n").encode())
    resp = f.readline()
    s.close()
    return json.loads(resp)

def main():
    args = sys.argv[1:]
    serial = log = qmpsock = None; timeout = 180; record = None
    steps = []
    while args:
        a = args.pop(0)
        if a == "--serial": serial = args.pop(0)
        elif a == "--log": log = args.pop(0)
        elif a == "--timeout": timeout = int(args.pop(0))
        elif a == "--qmp": qmpsock = args.pop(0)
        elif a == "--record": record = args.pop(0)
        else: steps.append(a)
    if not serial:
        print(__doc__); return 2
    d = Drive(serial, log, timeout)
    grabbed = {}
    for i, st in enumerate(steps, 1):
        kind, _, rest = st.partition(":")
        try:
            if kind == "expect": d.expect(rest)
            elif kind == "seen": d.seen(rest)
            elif kind == "absent":
                if re.search(rest.encode(), d.buf): raise RuntimeError(f"forbidden output appeared: {rest!r}")
            elif kind == "send": d.send(rest)
            elif kind == "login":
                u, _, p = rest.partition(":"); d.login(u, p)
            elif kind == "run": d.run(rest)
            elif kind == "run!": d.run(rest, require_zero=False)
            elif kind == "su":
                p, _, c = rest.partition(":"); d.su(p, c)
            elif kind == "grab":
                name, _, c = rest.partition(":")
                d.marker += 1; tag = f"KRC{d.marker}"
                d.send(f"echo BEGIN-{tag}; {c}; echo END-{tag}=$?")
                d.expect(rf"BEGIN-{tag}\r?\n")
                start = len(d.buf)
                # read until END tag, keeping the text
                rx = re.compile(rf"END-{tag}=(\d+)".encode())
                deadline = time.time() + timeout
                while not rx.search(d.buf):
                    if time.time() > deadline or d.closed: raise RuntimeError(f"grab timeout: {c}")
                    d._read()
                m = rx.search(d.buf)
                grabbed[name] = d.buf[:m.start()].decode("utf-8", "replace").strip()
                d.buf = d.buf[m.end():]
                d.expect(r"KDRV\$ ?$", 30)
                print(f"[grab {name}] {grabbed[name][:400]}")
            elif kind == "sleep": d.drain(float(rest))
            elif kind == "screendump":
                if not qmpsock: raise RuntimeError("screendump needs --qmp")
                r = qmp(qmpsock, "screendump", {"filename": rest})
                if "error" in r: raise RuntimeError(f"screendump: {r['error']}")
            elif kind == "key":
                if not qmpsock: raise RuntimeError("key needs --qmp")
                keys = [{"type": "qcode", "data": k} for k in rest.split("+")]
                r = qmp(qmpsock, "send-key", {"keys": keys, "hold-time": 80})
                if "error" in r: raise RuntimeError(f"send-key {rest}: {r['error']}")
                time.sleep(0.3)
            elif kind == "wait-exit":
                deadline = time.time() + timeout
                while not d.closed and time.time() < deadline: d._read()
                if not d.closed: raise RuntimeError("guest did not go away")
            else:
                raise RuntimeError(f"unknown step {st!r}")
            print(f"ok   {i:2d} {st[:90]}")
        except Exception as e:
            print(f"FAIL {i:2d} {st[:90]}\n     {e}")
            if record and grabbed:
                json.dump(grabbed, open(record, "w"), indent=2)
            return 1
    if record:
        json.dump(grabbed, open(record, "w"), indent=2)
    return 0

if __name__ == "__main__":
    sys.exit(main())
