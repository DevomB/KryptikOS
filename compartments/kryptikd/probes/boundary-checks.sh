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
# It also runs as root on the installed system (tools/image/zones-test.sh),
# where kryptikd refuses a zone that would map its root to real root: there
# the fixtures run under a named identity, the way the launcher suite does.
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

# Root must name the identity zones run as (kryptikd refuses to map a zone's
# root to host uid 0), and the fixture roots must then belong to it: the
# zone's setup drops to the mapped uid before it opens its data directory,
# so a 0700 root-owned workspace makes every launch fail with "open(data
# dir): Permission denied", which reads like a kryptikd defect and is not.
IDFLAGS=()
if [[ "$(id -u)" -eq 0 ]]; then
    IDFLAGS=(--zone-uid 100000 --zone-gid 100000)
    chmod 0755 "$F" "$F/zones" "$F/roots"
    chown -R 100000:100000 "$F/roots"
    echo "running as root: zones map to host uid/gid 100000"
fi

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
    #
    # What the zone printed and what the launcher logged are captured APART
    # and joined afterwards, the zone's output first. On one pipe they
    # interleave in mid-line: the installed system once read a broker reply
    # back as `kryptikd[zone error: unknown verb` / `probe]: broker served
    # "steal"`, and a check anchored on the reply's own line failed on a
    # system that had answered correctly. The launcher's log must never
    # decide a probe's verdict by where its bytes happened to land.
    local out="$F/zrun.out" err="$F/zrun.err"
    timeout 60 "$K" run "$zone" "${ZFLAGS[@]}" "${IDFLAGS[@]}" --zones "$F/zones" --rootfs "$F/roots" -- "$@" > "$out" 2> "$err"
    ZRC=$?
    ZOUT="$(cat "$out" "$err" | denoise)"
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

MATCH="uid=0(root)"  check "id(1) reports root inside the zone"        0 /bin/sh -c "id"
MATCH="^probe$"      check "the hostname is the zone name"             0 /bin/sh -c "hostname"
MATCH="^pid=1$"      check "the command is pid 1 of its own pid namespace" 0 /bin/sh -c "echo pid=\$\$"
MATCH="^ok$"         check "python3 runs (dynamic linking, ld.so.cache)"  0 /usr/bin/python3 -c "print('ok')"
MATCH="^fork-ok$"    check "fork through glibc (the clone3 ENOSYS fallback)" 0 /usr/bin/python3 -c "import os; pid=os.fork(); os._exit(0) if pid==0 else (os.waitpid(pid,0), print('fork-ok'))"
MATCH="^thread-ok$"  check "threads start and join"                    0 /usr/bin/python3 -c "import threading; t=threading.Thread(target=lambda: None); t.start(); t.join(); print('thread-ok')"
MATCH="^sub-ok$"     check "subprocesses run"                          0 /usr/bin/python3 -c "import subprocess; print(subprocess.run(['/bin/echo','sub-ok'],capture_output=True,text=True).stdout.strip())"
MATCH="^b$"          check "an existing file can be truncated and rewritten" 0 /bin/sh -c "echo a > /tmp/f && echo b > /tmp/f && cat /tmp/f"
MATCH="^x$"          check "rename across directories (Landlock REFER)"  0 /bin/sh -c "mkdir -p /tmp/d && echo x > /tmp/a && mv /tmp/a /tmp/d/ && cat /tmp/d/a"
MATCH="^hi$"         check "the zone can write its own HOME"           0 /bin/sh -c "cd && echo hi > note.txt && cat \$HOME/note.txt"
MATCH="^inet-ok$"    check "AF_INET and AF_UNIX sockets open"          0 /usr/bin/python3 -c "import socket; socket.socket(2,2).close(); socket.socket(1,1).close(); print('inet-ok')"
MATCH="^shm-ok$"     check "/dev/shm is usable"                        0 /bin/sh -c "echo x > /dev/shm/t && rm /dev/shm/t && echo shm-ok"
MATCH="^pts-ok$"     check "a private devpts is mounted"               0 /bin/sh -c "test -c /dev/pts/ptmx && test -L /dev/ptmx && echo pts-ok"
MATCH="^rc=1$"       check "the command's exit code reaches the caller" 1 /bin/sh -c "echo rc=1; exit 1"

# ---------------------------------------------------------------------------
head_ "B. The filesystem boundary"

MATCH="Read-only\|denied" check "writing at / is denied"                1 /bin/sh -c "touch /x"
MATCH="Read-only\|denied" check "writing under /usr is denied"          1 /bin/sh -c "touch /usr/x"
MATCH="Read-only\|denied" check "appending to /etc/passwd is denied"    1 /bin/sh -c "echo x >> /etc/passwd"
MATCH="denied\|Read-only" check "mkdir under /dev is denied"            1 /bin/sh -c "mkdir /dev/evil"
MATCH="^ok$"              check "mkdir at / is denied even though the zone is root" 0 /bin/sh -c "mkdir /newdir 2>/dev/null && echo bad || echo ok"
MATCH="^0$"  check "no host identity in /etc: machine-id, ssh, shadow, fstab absent" 0 /bin/sh -c "ls /etc/machine-id /etc/ssh /etc/shadow /etc/fstab 2>/dev/null | wc -l"
MATCH="^2$"  check "/etc/passwd is synthesized and has exactly two entries" 0 /bin/sh -c "wc -l < /etc/passwd"
MATCH="^0$"  check "no read-write host submount is visible inside the zone" 0 /bin/sh -c "cut -d' ' -f5,6 /proc/self/mountinfo | grep -v '^/tmp \|^/dev\|^/proc \|^/home/probe \|^/sys' | grep -vc ' ro,' ; true"
MATCH="^absent$" check "/run/kryptik/zones - the registry - is not visible in a zone" 0 /bin/sh -c "test -e /run/kryptik/zones && echo VISIBLE || echo absent"
MATCH="^broker$" check "/run/kryptik holds the broker socket and nothing else" 0 /bin/sh -c "ls -A /run/kryptik"

# ---------------------------------------------------------------------------
head_ "C. Descriptors and environment"

MATCH="Bad file descriptor" check "an inherited descriptor 3 does not reach the zone" 0 /bin/sh -c "cat <&3 2>&1; true"
MATCH="^KRYPTIK_ZONE=probe$" check "the environment is rebuilt from an allowlist" 0 /bin/sh -c "env | grep -c KRYPTIK_PROBE_SECRET | grep -q 0 && env | grep KRYPTIK_ZONE"
# The lister opens one descriptor of its own to read the directory, so the
# honest expectation is 0, 1, 2 and that one - four entries, never five.
MATCH="^0 1 2 3$" check "the only descriptors are 0, 1, 2 and the lister's own" 0 /bin/sh -c "echo \$(ls /proc/self/fd)"

# ---------------------------------------------------------------------------
head_ "D. Seccomp"

# unshare(1) makes the call; the image's python has no ctypes, and a killed
# process reports 128+SIGSYS either way.
check "clone(CLONE_NEWUSER) from inside the zone is killed, not refused" 159 /usr/bin/unshare -U /bin/true
MATCH="AF_VSOCK refused 97" check "AF_VSOCK, AF_ALG and AF_PACKET are refused by family, with EAFNOSUPPORT" 0 /usr/bin/python3 -c "
import socket
for n,f,t in [('AF_VSOCK',40,1),('AF_ALG',38,5),('AF_PACKET',17,2)]:
    try: socket.socket(f,t); print(n,'OPENED')
    except OSError as e: print(n,'refused',e.errno)"
for p in "clone-newuser 5" "clone3 7" "socket-vsock 7" "socket-netlink-nf 7" "socket-inet 0" "ioctl-tiocsti 5" "setns 5" "unshare 5" "mount 5" "getpid 0"; do
    set -- $p
    "$K" seccomp-test "$1" >/dev/null 2>&1; rc=$?
    if [[ "$rc" == "$2" ]]; then pass "seccomp-test $1 -> $rc"; else fail "seccomp-test $1 -> $rc (want $2)"; fi
done

# ---------------------------------------------------------------------------
head_ "E. Per-zone policy files"

MATCH="^errno 1$" checkz packet "a policy-allowed socket family passes seccomp and is then refused by the kernel" 0 /usr/bin/python3 -c "
import socket
try: socket.socket(17,3); print('OPENED')
except OSError as e: print('errno', e.errno)"
MATCH="^errno 97$" check "the same family is refused by seccomp in a zone without that policy" 0 /usr/bin/python3 -c "
import socket
try: socket.socket(17,3); print('OPENED')
except OSError as e: print('errno', e.errno)"
MATCH="owns the NIC" checkz routedraw "a zone that does not own the NIC may not keep CAP_NET_RAW" 1 /bin/sh -c "echo RAN-ANYWAY"
MATCH="policy" checkz nopolicy "a policy file that does not exist is a refusal, not a fallback" 1 /bin/sh -c "echo RAN-ANYWAY"
MATCH="ptrace" checkz badpolicy "a policy may not re-allow something on the denied list" 1 /bin/sh -c "echo RAN-ANYWAY"

# The Landlock half. A zone policy file is a SECOND layer, and layers
# intersect, so it can only take access away - these rows are what that
# means from inside a zone.
MATCH="^ok$"   checkz narrowed "a zone with a Landlock policy still runs and can read its root" 0 /bin/sh -c "test -r /usr/bin/env && echo ok"
MATCH="^ok$"   checkz narrowed "... and writes where the policy grants write" 0 /bin/sh -c "echo x > /tmp/f && echo x > /dev/null && echo ok"
MATCH="^denied$" checkz narrowed "... but NOT its own HOME, which the base rules alone would allow" 0 /bin/sh -c "echo x > \$HOME/f 2>/dev/null && echo WROTE || echo denied"
MATCH="^ok$"   check "control: the same write succeeds in a zone with no Landlock policy" 0 /bin/sh -c "echo x > \$HOME/f && echo ok"
MATCH="deny"   checkz badfs "a Landlock policy using a directive that cannot exist is refused" 1 /bin/sh -c "echo RAN-ANYWAY"
MATCH="absolute" checkz relfs "a Landlock policy naming a relative path is refused" 1 /bin/sh -c "echo RAN-ANYWAY"

# ---------------------------------------------------------------------------
head_ "F. Guarantees a build cannot give are refused, not implied"

# Both refusals name the reason the same way: unprivileged, that a LUKS2
# volume needs a root launch (no plain directory instead); as root, that the
# volume would be opened and the passphrase is the first thing missing. The
# older pattern here matched the unprivileged wording of before eef20e9, so
# this row failed on every developer host while passing on the target.
MATCH="is encrypted:" checkz sealed "a zone declaring encrypted storage does not start on a plain directory" 1 /bin/sh -c "echo RAN-ANYWAY"
if "$K" run capped "${ZFLAGS[@]}" "${IDFLAGS[@]}" --zones "$F/zones" --rootfs "$F/roots" -- /bin/sh -c "echo LIMITS-RAN" 2>&1 | grep -q LIMITS-RAN; then
    pass "[limits] is enforced here: cgroups are creatable and the zone ran"
else
    zrun capped -- /bin/sh -c "echo LIMITS-RAN"
    if grep -q "RAN-ANYWAY\|LIMITS-RAN" <<<"$ZOUT"; then
        fail "a zone declaring [limits] RAN where they cannot be enforced" "$ZOUT"
    elif grep -q "\[limits\]" <<<"$ZOUT"; then
        pass "[limits] is refused where no cgroup can be created, and the refusal names the setting"
    else
        fail "refused, but the message did not name [limits]" "$ZOUT"
    fi
fi
MATCH="^kept$" checkz keeper "a persistent zone keeps a file across launches (write)" 0 /bin/sh -c "echo kept > \$HOME/keep.txt && cat \$HOME/keep.txt"
MATCH="^kept$" checkz keeper "... and the next launch still has it"     0 /bin/sh -c "cat \$HOME/keep.txt"
MATCH="^gone$" check "control: an ephemeral zone does NOT keep one"     0 /bin/sh -c "test -e \$HOME/keep.txt && echo KEPT || echo gone"

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

MATCH="^kryptik-broker 1 zone=probe$" check "a zone reaches its own broker and is identified by its peer uid" 0 /usr/bin/python3 -c "$BRK" "version
"
MATCH="^error: unknown verb$" check "an unknown verb is refused"        0 /usr/bin/python3 -c "$BRK" "steal
"
MATCH="^ok text/plain 5 hello$" check "clipboard-set then clipboard-get round-trips" 0 /bin/sh -c "python3 -c '$BRK' 'clipboard-set text/plain 5
hello' >/dev/null && python3 -c '$BRK' 'clipboard-get
'"
MATCH="exceeds the 1048576-byte clipboard limit" check "an oversize payload is refused from the header, before any of it is read" 0 /usr/bin/python3 -c "$BRK" "clipboard-set text/plain 1048577
"
MATCH="unsupported MIME type" check "a MIME type outside the fixed list is refused" 0 /usr/bin/python3 -c "$BRK" "clipboard-set text/evil 3
abc"
MATCH="zone 0 act, not a zone verb" check "clipboard-move is not a zone verb" 0 /usr/bin/python3 -c "$BRK" "clipboard-move probe packet
"

TX='
import socket,array,os,sys
dest,name,path,flags=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4])
fd=os.open(path,flags)
s=socket.socket(socket.AF_UNIX); s.connect("/run/kryptik/broker")
s.sendmsg([("transfer %s %s\n"%(dest,name)).encode()],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[fd]))])
print(s.recv(300).decode().strip())'

# A transfer for real, between two zones running at the same time. `packet`
# says when it is up, waits for the file and reports what arrived; `probe`
# offers a file from its own home once packet is up. Both waits are bounded
# polls rather than fixed sleeps: a zone is up well within a second on a
# developer host and can take several on the acceptance runner's nested VM,
# and a sleep sized on the one measures the other's speed, not the transfer.
# The broker creates the file under its final name and then fills it, so an
# empty file is one still landing.
"$K" run packet "${ZFLAGS[@]}" "${IDFLAGS[@]}" --zones "$F/zones" --rootfs "$F/roots" -- /usr/bin/python3 -u -c "
import os,time
print('PACKET-UP')
d='/home/packet/incoming'
p=d+'/report.txt'
end=time.time()+90
while time.time()<end and not (os.path.exists(p) and os.path.getsize(p)>0):
    time.sleep(0.2)
if os.path.isdir(d):
    print('ARRIVED', ','.join(sorted(os.listdir(d))), open(p).read().strip() if os.path.exists(p) else '-', oct(os.stat(p).st_mode & 0o777) if os.path.exists(p) else '-')
else:
    print('ARRIVED none')" > "$F/dest.out" 2>&1 &
DEST=$!
for _ in $(seq 1 300); do
    grep -q '^PACKET-UP' "$F/dest.out" 2>/dev/null && break
    kill -0 "$DEST" 2>/dev/null || break
    sleep 0.1
done
ZFLAGS=(--auto-approve-transfers)
MATCH="^ok report.txt$" check "a zone offers a file from its data mount and learns the name it landed under" 0 /bin/sh -c "echo payload-42 > /home/probe/report.txt && python3 -c '$TX' packet report.txt /home/probe/report.txt 0"
wait $DEST
if grep -q "^ARRIVED report.txt payload-42 0o600$" "$F/dest.out"; then
    pass "the destination finds incoming/report.txt, byte-identical, mode 0600"
else
    fail "the destination side" "$(tail -3 "$F/dest.out")"
fi
MATCH="not a regular file" check "a descriptor to a directory is refused" 0 /bin/sh -c "python3 -c '$TX' packet f /home/probe 0"
MATCH="not on the zone" check "a file from the zone's tmpfs, not its data mount, is refused" 0 /bin/sh -c "echo x > /tmp/f && python3 -c '$TX' packet f /tmp/f 0"
MATCH="not running" check "a destination that is not running is refused"  0 /bin/sh -c "echo x > /home/probe/f && python3 -c '$TX' packet f /home/probe/f 0"
ZFLAGS=()
# On a system with a consent channel the question is asked and nobody
# answers; a short deadline keeps that a refusal rather than a timeout of
# the check itself.
KRYPTIK_CONSENT_TIMEOUT=3 MATCH="approv\|consent\|refusal" check "without the approval flag every transfer is refused for want of consent" 0 /bin/sh -c "echo x > /home/probe/f && python3 -c '$TX' packet f /home/probe/f 0"
MATCH="does not name" check "a destination outside the sender's [transfer] to is refused before consent" 0 /bin/sh -c "echo x > /home/probe/f && python3 -c '$TX' capped f /home/probe/f 0"
MATCH="single path component" check "a name carrying a path separator is refused at parse time" 0 /bin/sh -c "echo x > /home/probe/f && python3 -c '$TX' packet ../f /home/probe/f 0"

# ---------------------------------------------------------------------------
head_ "H. The zone dies with its launcher"

# The marker is argv[0] of the zone's command, so `pgrep -f "^$MARK"` finds
# that process and nothing else: the launcher's own command line carries the
# marker too, further along. Each wait is a bounded poll, not a fixed sleep,
# so a slow host measures the property and not itself: the zone is up
# before its launcher is signalled (a launcher killed during setup proves
# less), and it is given a moment to be gone.
MARK="kryptik-probe-sleep-$$"
zone_up()   { for _ in $(seq 1 300); do pgrep -f "^$MARK" >/dev/null && return 0; kill -0 "$1" 2>/dev/null || return 1; sleep 0.1; done; return 1; }
zone_gone() { for _ in $(seq 1 100); do pgrep -f "^$MARK" >/dev/null || return 0; sleep 0.1; done; return 1; }
# dies_with SIG NAME: launch, wait for the zone, signal the launcher, wait.
dies_with() {
    local sig="$1" name="$2" p
    "$K" run probe "${IDFLAGS[@]}" --zones "$F/zones" --rootfs "$F/roots" -- /bin/sh -c "exec -a $MARK sleep 300" > "$F/h.out" 2>&1 &
    p=$!
    if ! zone_up "$p"; then
        fail "$name  the zone never came up, so there was no launcher to signal" "$(denoise < "$F/h.out" | tail -3)"
    else
        kill "-$sig" "$p" 2>/dev/null
        if zone_gone; then
            pass "$name  the zone dies when its launcher is SIG${sig}ed"
        else
            fail "$name  a zone process outlived a SIG${sig}ed launcher"; pkill -9 -f "^$MARK"
        fi
    fi
    wait "$p" 2>/dev/null
}
dies_with KILL H1
dies_with TERM H2

# ---------------------------------------------------------------------------
head_ "I. What only a privileged run on the target kernel can show"
if [[ "$(id -u)" -eq 0 ]]; then
    skip "I   running as root here would still not be the target kernel; use security/probes/vm-*.sh in a disposable VM"
else
    skip "per-zone host identity (uid_base): every zone maps to this one user unprivileged"
    skip "the NIC really moving into the nic zone, and routed zones addressed on the bridge"
    skip "cgroup enforcement rather than the refusal, and OOM attribution"
    skip "a transferred file owned by the DESTINATION zone's identity"
fi

echo
echo "failures: $FAILS   not run: $SKIPS"
exit "$FAILS"
