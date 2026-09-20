#!/usr/bin/env python3
"""Drive a guest over its serial console: expect, send, log in, run commands.

    tools/image/vm-drive.py --serial SOCK [--log FILE] [--timeout N] [--qmp SOCK] STEP...

Steps (each one argument):
    expect:REGEX            wait until REGEX matches the serial stream (and
                            consume the stream up to the match)
    seen:REGEX              wait until REGEX has appeared ANYWHERE in the
                            transcript so far, consuming nothing - for a line
                            whose order relative to other lines is not fixed
    absent:REGEX            assert REGEX has NOT appeared so far
    send:TEXT               send TEXT followed by Enter
    login:USER:PASSWORD     wait for "login:", authenticate, wait for a prompt
    run:CMD                 run CMD at the shell, require exit status 0
    run!:CMD                run CMD, any exit status
    su:PASSWORD:CMD         run CMD as root through su (root's password)
    grab:NAME:CMD           run CMD and record its output under NAME in --record
    sleep:SECONDS
    screendump:FILE         ask QEMU (QMP) for a PPM screenshot
    key:NAME[+NAME...]      press keys on the guest's keyboard through QMP
                            (qcodes, e.g. key:y  key:ret  key:alt+e)
    wait-exit               wait for the serial socket to close (guest gone)

Exit status 0 when every step succeeded; the failing step is named otherwise.
The whole transcript goes to --log. stdlib only; no pexpect.
"""
import json, os, re, socket, sys, time

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
        self.records = {}
        self.marker = 0

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
        return True

    def seen(self, regex, timeout=None):
        """Wait until REGEX has appeared anywhere in the transcript so far.
        Consumes nothing: a line that was printed before an earlier expect()
        matched (and was discarded from buf) still counts."""
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
        # To the guest and never to the transcript, which is uploaded with every
        # acceptance report. A method of its own, so that no path leads from a
        # password to the log.
        self.s.sendall(text.encode() + b"\r")
        if self.log:
            self.log.write(b"\n<<< (a password)\n"); self.log.flush()

    def drain(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            self._read()

    def knock(self, regex, timeout=None, every=5):
        """Send an empty line, wait up to EVERY seconds for REGEX, and send
        another until it matches or TIMEOUT runs out. Consumes like expect()."""
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
        # The getty may have printed its prompt long before this step (an
        # earlier expect() then discarded it). An empty line makes agetty
        # print a fresh one, so the prompt is waited for, not assumed.
        #
        # One empty line is not enough. agetty prints "login:" only once it
        # sees terminal input (util-linux builds it with AGETTY_RELOAD: the
        # prompt waits in select() for a keypress, an inotify or a netlink
        # event), and it flushes whatever arrived during the second after it
        # started or after such an event woke it. An Enter that lands in that
        # window is discarded, agetty goes back to waiting, and a driver that
        # sent one Enter waits with it: 51500b01's update test, step 4, spent 420 s on
        # a console that had printed agetty's leading newline and nothing
        # else. Every transcript of that run shows the prompt only after the
        # driver's Enter. So knock again every few seconds until one answers.
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

    def run(self, cmd, require_zero=True, record=None):
        self.marker += 1
        tag = f"KRC{self.marker}"
        self.send(f"{cmd}; echo {tag}=$?")
        m = self.expect(rf"{tag}=(\d+)", self.timeout)
        rc = int(m.group(1))
        # output between the echoed command and the tag is what we captured;
        # keep whatever preceded the match for records
        if record is not None:
            self.records[record] = self.last_output.decode("utf-8", "replace") if hasattr(self, "last_output") else ""
        self.expect(r"KDRV\$ ?$", 30)
        if require_zero and rc != 0:
            raise RuntimeError(f"command failed ({rc}): {cmd}")
        return rc

    def grab(self, name, cmd):
        self.marker += 1
        tag = f"KRC{self.marker}"
        self.send(f"echo BEGIN-{tag}; {cmd}; echo END-{tag}=$?")
        self.expect(rf"BEGIN-{tag}\r?\n", self.timeout)
        m = self.expect(rf"END-{tag}=(\d+)", self.timeout)
        # everything consumed up to the END marker is in the discarded prefix;
        # re-search the log-less buffer: simpler to capture during expect
        self.expect(r"KDRV\$ ?$", 30)
        return int(m.group(1))

    def su(self, password, cmd):
        # A login shell for root: the image strips the sbin directories from
        # an ordinary user's PATH, and a plain `su -c` inherits that PATH, so
        # root's reboot and poweroff were "command not found".
        self.marker += 1
        tag = f"KRC{self.marker}"
        self.send(f"su - root -c '{cmd}; echo {tag}=$?'")
        self.expect(r"Password: ?", 60)
        self.send_secret(password)
        # Wait for the exit marker, but keep what the command printed: the
        # steps that follow expect lines of that output ("running slot: a",
        # "ZT END"), and a plain expect() would have consumed them with the
        # marker. Only the marker itself is dropped; a shutdown message that
        # matched instead stays for the driver's own expect of it.
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
