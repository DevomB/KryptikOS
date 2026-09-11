#!/usr/bin/env bash
# Regression probes for the kryptikd zone boundary.
#
#   compartments/kryptikd/probes/boundary-checks.sh [path/to/kryptikd]
#
# Every row is a property some defect once violated, and each one exercises
# the REAL launcher - `kryptikd run` - rather than a helper called directly,
# because the defects that matter were in how the pieces were wired, not in
# the pieces.
#
# Unprivileged by design: this is the developer host's half. Zone identity,
# the NIC move, cgroup enforcement and per-zone uids need root and a
# disposable VM, and the checks that would need them say NOT RUN rather than
# passing on a weaker claim. Exit status is the number of failures.
#
# It lives in the repository, next to the code it tests, because it once did
# not: an earlier copy lived only in a scratch directory and was lost when
# that directory was removed.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
K="${1:-$HERE/../target/debug/kryptikd}"
[[ -x "$K" ]] || { echo "no kryptikd at $K (cargo build first)"; exit 2; }
K="$(cd "$(dirname "$K")" && pwd)/$(basename "$K")"

# shellcheck source=fixtures.sh
source "$HERE/fixtures.sh"

FAILS=0
SKIPS=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; shift; [[ $# -gt 0 ]] && printf '%s\n' "$1" | sed 's/^/      | /'; FAILS=$((FAILS+1)); }
skip() { echo "SKIP  $1"; SKIPS=$((SKIPS+1)); }
head_() { echo; echo "== $1"; }

# Noise every launch prints that no check is about: the experimental hint,
# the swap caveat, inherited groups an unprivileged launcher cannot drop.
denoise() {
    grep -v 'KRYPTIK_EXPERIMENTAL=1 -\|supplementary host group\|not secure erasure\|auto-approve-transfers: every\|NOT encrypted at rest'
}

# zrun ZONE -- CMD...: run CMD in ZONE, leaving $ZOUT and $ZRC.
zrun() {
    local zone="$1"; shift
    [[ "${1:-}" == "--" ]] && shift
    # The rc must be the LAUNCHER's, so the filter runs afterwards: a
    # pipeline reports the LAST command's status, and an earlier draft of
    # this file graded every refusal against grep's exit code instead.
    local raw
    raw="$(timeout 60 "$K" run "$zone" "${ZFLAGS[@]}" --zones "$F/zones" --rootfs "$F/roots" -- "$@" 2>&1)"
    ZRC=$?
    ZOUT="$(denoise <<<"$raw")"
    return 0
}
ZFLAGS=()

# check NAME WANT_RC CMD...: run in `probe` and compare rc, and $MATCH if set.
check() {
    local name="$1" want="$2"; shift 2
    zrun probe -- "$@"
    if [[ "$ZRC" == "$want" ]] && { [[ -z "${MATCH:-}" ]] || grep -q -- "$MATCH" <<<"$ZOUT"; }; then
        pass "$name"
    else
        fail "$name (rc=$ZRC want=$want)" "$ZOUT"
    fi
    unset MATCH
}

# checkz ZONE NAME WANT_RC CMD...: the same, in a named zone.
checkz() {
    local zone="$1" name="$2" want="$3"; shift 3
    zrun "$zone" -- "$@"
    if [[ "$ZRC" == "$want" ]] && { [[ -z "${MATCH:-}" ]] || grep -q -- "$MATCH" <<<"$ZOUT"; }; then
        pass "$name"
    else
        fail "$name (rc=$ZRC want=$want)" "$ZOUT"
    fi
    unset MATCH
}

echo "kryptikd boundary probes - $K"
echo "fixtures in $F (removed on exit); unprivileged: euid=$(id -u)"

# ---------------------------------------------------------------------------
head_ "A. Positive controls: a zone is still a usable machine"
# A boundary that works by breaking every program is not a boundary, it is a
# broken zone. These are the rows that fail when a filter is tightened too far.

MATCH="uid=0(root)"  check "A1  id(1) reports root inside the zone"        0 /bin/sh -c "id"
MATCH="^probe$"      check "A2  the hostname is the zone name"             0 /bin/sh -c "hostname"
MATCH="^pid=1$"      check "A3  the command is pid 1 of its own pid namespace" 0 /bin/sh -c "echo pid=\$\$"
MATCH="^ok$"         check "A4  python3 runs (dynamic linking, ld.so.cache)"  0 /usr/bin/python3 -c "print('ok')"
MATCH="^fork-ok$"    check "A5  fork through glibc (the clone3 ENOSYS fallback)" 0 /usr/bin/python3 -c "import os; pid=os.fork(); os._exit(0) if pid==0 else (os.waitpid(pid,0), print('fork-ok'))"
MATCH="^thread-ok$"  check "A6  threads start and join"                    0 /usr/bin/python3 -c "import threading; t=threading.Thread(target=lambda: None); t.start(); t.join(); print('thread-ok')"
MATCH="^sub-ok$"     check "A7  subprocesses run"                          0 /usr/bin/python3 -c "import subprocess; print(subprocess.run(['/bin/echo','sub-ok'],capture_output=True,text=True).stdout.strip())"
MATCH="^b$"          check "A8  an existing file can be truncated and rewritten" 0 /bin/sh -c "echo a > /tmp/f && echo b > /tmp/f && cat /tmp/f"
MATCH="^x$"          check "A9  rename across directories (Landlock REFER)"  0 /bin/sh -c "mkdir -p /tmp/d && echo x > /tmp/a && mv /tmp/a /tmp/d/ && cat /tmp/d/a"
MATCH="^hi$"         check "A10 the zone can write its own HOME"           0 /bin/sh -c "cd && echo hi > note.txt && cat \$HOME/note.txt"
MATCH="^inet-ok$"    check "A11 AF_INET and AF_UNIX sockets open"          0 /usr/bin/python3 -c "import socket; socket.socket(2,2).close(); socket.socket(1,1).close(); print('inet-ok')"
MATCH="^shm-ok$"     check "A12 /dev/shm is usable"                        0 /bin/sh -c "echo x > /dev/shm/t && rm /dev/shm/t && echo shm-ok"
MATCH="^pts-ok$"     check "A13 a private devpts is mounted"               0 /bin/sh -c "test -c /dev/pts/ptmx && test -L /dev/ptmx && echo pts-ok"
MATCH="^rc=1$"       check "A14 the command's exit code reaches the caller" 1 /bin/sh -c "echo rc=1; exit 1"

# ---------------------------------------------------------------------------
head_ "B. The filesystem boundary"

MATCH="Read-only\|denied" check "B1  writing at / is denied"                1 /bin/sh -c "touch /x"
MATCH="Read-only\|denied" check "B2  writing under /usr is denied"          1 /bin/sh -c "touch /usr/x"
MATCH="Read-only\|denied" check "B3  appending to /etc/passwd is denied"    1 /bin/sh -c "echo x >> /etc/passwd"
MATCH="denied\|Read-only" check "B4  mkdir under /dev is denied"            1 /bin/sh -c "mkdir /dev/evil"
MATCH="^ok$"              check "B5  mkdir at / is denied even though the zone is root" 0 /bin/sh -c "mkdir /newdir 2>/dev/null && echo bad || echo ok"
MATCH="^0$"  check "B6  no host identity in /etc: machine-id, ssh, shadow, fstab absent" 0 /bin/sh -c "ls /etc/machine-id /etc/ssh /etc/shadow /etc/fstab 2>/dev/null | wc -l"
MATCH="^2$"  check "B7  /etc/passwd is synthesized and has exactly two entries" 0 /bin/sh -c "wc -l < /etc/passwd"
MATCH="^0$"  check "B8  no read-write host submount is visible inside the zone" 0 /bin/sh -c "cut -d' ' -f5,6 /proc/self/mountinfo | grep -v '^/tmp \|^/dev\|^/proc \|^/home/probe \|^/sys' | grep -vc ' ro,' ; true"
MATCH="^absent$" check "B9  /run/kryptik/zones - the registry - is not visible in a zone" 0 /bin/sh -c "test -e /run/kryptik/zones && echo VISIBLE || echo absent"
MATCH="^broker$" check "B10 /run/kryptik holds the broker socket and nothing else" 0 /bin/sh -c "ls -A /run/kryptik"

# ---------------------------------------------------------------------------
head_ "C. Descriptors and environment"

MATCH="Bad file descriptor" check "C1  an inherited descriptor 3 does not reach the zone" 0 /bin/sh -c "cat <&3 2>&1; true"
MATCH="^KRYPTIK_ZONE=probe$" check "C2  the environment is rebuilt from an allowlist" 0 /bin/sh -c "env | grep -c KRYPTIK_PROBE_SECRET | grep -q 0 && env | grep KRYPTIK_ZONE"
# The lister opens one descriptor of its own to read the directory, so the
# honest expectation is 0, 1, 2 and that one - four entries, never five.
MATCH="^0 1 2 3$" check "C3  the only descriptors are 0, 1, 2 and the lister's own" 0 /bin/sh -c "echo \$(ls /proc/self/fd)"

# ---------------------------------------------------------------------------
head_ "D. Seccomp"

check "D1  clone(CLONE_NEWUSER) from inside the zone is killed, not refused" 159 /usr/bin/python3 -c "
import ctypes; libc=ctypes.CDLL(None,use_errno=True); print('clone returned', libc.syscall(56, 0x10000000|17,0,0,0,0))"
MATCH="AF_VSOCK refused 97" check "D2  AF_VSOCK, AF_ALG and AF_PACKET are refused by family, with EAFNOSUPPORT" 0 /usr/bin/python3 -c "
import socket
for n,f,t in [('AF_VSOCK',40,1),('AF_ALG',38,5),('AF_PACKET',17,2)]:
    try: socket.socket(f,t); print(n,'OPENED')
    except OSError as e: print(n,'refused',e.errno)"
for p in "clone-newuser 5" "clone3 7" "socket-vsock 7" "socket-netlink-nf 7" "socket-inet 0" "ioctl-tiocsti 5" "setns 5" "unshare 5" "mount 5" "getpid 0"; do
    set -- $p
    "$K" seccomp-test "$1" >/dev/null 2>&1; rc=$?
    if [[ "$rc" == "$2" ]]; then pass "D3  seccomp-test $1 -> $rc"; else fail "D3  seccomp-test $1 -> $rc (want $2)"; fi
done

# ---------------------------------------------------------------------------
head_ "E. Per-zone policy files"

MATCH="^errno 1$" checkz packet "E1  a policy-allowed socket family passes seccomp and is then refused by the kernel" 0 /usr/bin/python3 -c "
import socket
try: socket.socket(17,3); print('OPENED')
except OSError as e: print('errno', e.errno)"
MATCH="^errno 97$" check "E2  the same family is refused by seccomp in a zone without that policy" 0 /usr/bin/python3 -c "
import socket
try: socket.socket(17,3); print('OPENED')
except OSError as e: print('errno', e.errno)"
MATCH="owns the NIC" checkz routedraw "E3  a zone that does not own the NIC may not keep CAP_NET_RAW" 1 /bin/sh -c "echo RAN-ANYWAY"
MATCH="policy" checkz nopolicy "E4  a policy file that does not exist is a refusal, not a fallback" 1 /bin/sh -c "echo RAN-ANYWAY"
MATCH="ptrace" checkz badpolicy "E5  a policy may not re-allow something on the denied list" 1 /bin/sh -c "echo RAN-ANYWAY"

# ---------------------------------------------------------------------------
head_ "F. Guarantees a build cannot give are refused, not implied"

MATCH="storage.mode" checkz sealed "F1  a zone declaring encrypted storage refuses to start" 1 /bin/sh -c "echo RAN-ANYWAY"
if "$K" run capped "${ZFLAGS[@]}" --zones "$F/zones" --rootfs "$F/roots" -- /bin/sh -c "echo LIMITS-RAN" 2>&1 | grep -q LIMITS-RAN; then
    pass "F2  [limits] is enforced here: cgroups are creatable and the zone ran"
else
    zrun capped -- /bin/sh -c "echo LIMITS-RAN"
    if grep -q "RAN-ANYWAY\|LIMITS-RAN" <<<"$ZOUT"; then
        fail "F2  a zone declaring [limits] RAN where they cannot be enforced" "$ZOUT"
    elif grep -q "\[limits\]" <<<"$ZOUT"; then
        pass "F2  [limits] is refused where no cgroup can be created, and the refusal names the setting"
    else
        fail "F2  refused, but the message did not name [limits]" "$ZOUT"
    fi
fi
MATCH="^kept$" checkz keeper "F3  a persistent zone keeps a file across launches (write)" 0 /bin/sh -c "echo kept > \$HOME/keep.txt && cat \$HOME/keep.txt"
MATCH="^kept$" checkz keeper "F4  ... and the next launch still has it"     0 /bin/sh -c "cat \$HOME/keep.txt"
MATCH="^gone$" check "F5  control: an ephemeral zone does NOT keep one"     0 /bin/sh -c "test -e \$HOME/keep.txt && echo KEPT || echo gone"

# ---------------------------------------------------------------------------
head_ "G. The broker: identity, clipboard, transfer"

BRK='
import socket,sys
s=socket.socket(socket.AF_UNIX); s.connect("/run/kryptik/broker")
s.sendall(sys.argv[1].encode())
d=b""
while True:
    c=s.recv(4096)
    if not c: break
    d+=c
print(d.decode().replace("\n"," ").strip())'

MATCH="^kryptik-broker 1 zone=probe$" check "G1  a zone reaches its own broker and is identified by its peer uid" 0 /usr/bin/python3 -c "$BRK" "version
"
MATCH="^error: unknown verb$" check "G2  an unknown verb is refused"        0 /usr/bin/python3 -c "$BRK" "steal
"
MATCH="^ok text/plain 5 hello$" check "G3  clipboard-set then clipboard-get round-trips" 0 /bin/sh -c "python3 -c '$BRK' 'clipboard-set text/plain 5
hello' >/dev/null && python3 -c '$BRK' 'clipboard-get
'"
MATCH="exceeds the 1048576-byte clipboard limit" check "G4  an oversize payload is refused from the header, before any of it is read" 0 /usr/bin/python3 -c "$BRK" "clipboard-set text/plain 1048577
"
MATCH="unsupported MIME type" check "G5  a MIME type outside the fixed list is refused" 0 /usr/bin/python3 -c "$BRK" "clipboard-set text/evil 3
abc"
MATCH="zone 0 act, not a zone verb" check "G6  clipboard-move is not a zone verb" 0 /usr/bin/python3 -c "$BRK" "clipboard-move probe packet
"

TX='
import socket,array,os,sys
dest,name,path,flags=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4])
fd=os.open(path,flags)
s=socket.socket(socket.AF_UNIX); s.connect("/run/kryptik/broker")
s.sendmsg([("transfer %s %s\n"%(dest,name)).encode()],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[fd]))])
print(s.recv(300).decode().strip())'

# G7/G8: the real thing, between two zones running at the same time. `packet`
# waits and then reports what arrived; `probe` offers a file from its own home.
"$K" run packet "${ZFLAGS[@]}" --zones "$F/zones" --rootfs "$F/roots" -- /usr/bin/python3 -c "
import os,time
time.sleep(6)
d='/home/packet/incoming'
if os.path.isdir(d):
    p=d+'/report.txt'
    print('ARRIVED', ','.join(sorted(os.listdir(d))), open(p).read().strip() if os.path.exists(p) else '-', oct(os.stat(p).st_mode & 0o777) if os.path.exists(p) else '-')
else:
    print('ARRIVED none')" > "$F/dest.out" 2>&1 &
DEST=$!
sleep 2
ZFLAGS=(--auto-approve-transfers)
MATCH="^ok report.txt$" check "G7  a zone offers a file from its data mount and learns the name it landed under" 0 /bin/sh -c "echo payload-42 > /home/probe/report.txt && python3 -c '$TX' packet report.txt /home/probe/report.txt 0"
wait $DEST
if grep -q "^ARRIVED report.txt payload-42 0o600$" "$F/dest.out"; then
    pass "G8  the destination finds incoming/report.txt, byte-identical, mode 0600"
else
    fail "G8  the destination side" "$(tail -3 "$F/dest.out")"
fi
MATCH="not a regular file" check "G9  a descriptor to a directory is refused" 0 /bin/sh -c "python3 -c '$TX' packet f /home/probe 0"
MATCH="not on the zone" check "G10 a file from the zone's tmpfs, not its data mount, is refused" 0 /bin/sh -c "echo x > /tmp/f && python3 -c '$TX' packet f /tmp/f 0"
MATCH="not running" check "G11 a destination that is not running is refused"  0 /bin/sh -c "echo x > /home/probe/f && python3 -c '$TX' packet f /home/probe/f 0"
ZFLAGS=()
MATCH="approval" check "G12 without the approval flag every transfer is refused for want of consent" 0 /bin/sh -c "echo x > /home/probe/f && python3 -c '$TX' packet f /home/probe/f 0"
MATCH="does not name" check "G13 a destination outside the sender's [transfer] to is refused before consent" 0 /bin/sh -c "echo x > /home/probe/f && python3 -c '$TX' capped f /home/probe/f 0"
MATCH="single path component" check "G14 a name carrying a path separator is refused at parse time" 0 /bin/sh -c "echo x > /home/probe/f && python3 -c '$TX' packet ../f /home/probe/f 0"

# ---------------------------------------------------------------------------
head_ "H. The zone dies with its launcher"

MARK="kryptik-probe-sleep-$$"
"$K" run probe --zones "$F/zones" --rootfs "$F/roots" -- /bin/sh -c "exec -a $MARK sleep 300" >/dev/null 2>&1 &
P=$!
sleep 2; kill -9 "$P" 2>/dev/null; sleep 1
if pgrep -f "$MARK" >/dev/null; then fail "H1  a zone process outlived a SIGKILLed launcher"; pkill -9 -f "$MARK"; else pass "H1  the zone dies when its launcher is SIGKILLed"; fi
timeout 2 "$K" run probe --zones "$F/zones" --rootfs "$F/roots" -- /bin/sh -c "exec -a $MARK sleep 300" >/dev/null 2>&1; sleep 1
if pgrep -f "$MARK" >/dev/null; then fail "H2  a zone process outlived a SIGTERMed launcher"; pkill -9 -f "$MARK"; else pass "H2  the zone dies when its launcher is SIGTERMed"; fi

# ---------------------------------------------------------------------------
head_ "I. What only a privileged run on the target kernel can show"
if [[ "$(id -u)" -eq 0 ]]; then
    skip "I   running as root here would still not be the target kernel; use security/probes/vm-*.sh in a disposable VM"
else
    skip "I1  per-zone host identity (uid_base): every zone maps to this one user unprivileged"
    skip "I2  the NIC really moving into the nic zone, and routed zones addressed on the bridge"
    skip "I3  cgroup enforcement rather than the refusal, and OOM attribution"
    skip "I4  a transferred file owned by the DESTINATION zone's identity"
fi

echo
echo "failures: $FAILS   not run: $SKIPS"
exit "$FAILS"
