#!/usr/bin/env bash
# The net zone's half of the clock (docs/design/time.md), offline and in a
# second: the part of tools/net/netzone-init.sh that measures the time and
# tells zone 0, run for real under every POSIX shell on this host with a
# stand-in for chronyd and one for the broker client.
#
# The zone that runs this code is the one Kryptik trusts least, and the image
# runs it under whatever /bin/sh is. So what is checked is what it does with
# what it is given: which lines of zone 0's source list it accepts, that each
# directive reaches chronyd as ONE argument, which number it takes for the
# offset, what it calls silence, a timeout and a seccomp kill, that it never
# asks without an uplink, and that the function's own `set --` leaves the
# script's list of uplinks alone (the whole script hangs off "$@").
#
# It cannot say whether chronyd's sign means what the script says it means;
# the installed system's check sets the clock wrong on purpose for that.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT}/tools/net/netzone-init.sh"
PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); [[ $# -gt 1 ]] && printf '        %s\n' "$2"; }

[[ -r "$SCRIPT" ]] || { echo "no ${SCRIPT}"; exit 1; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"

# The block under test: from TIME_CONF= up to, not including, its first call.
sed -n '/^TIME_CONF=/,/^ask_time "\$@"$/p' "$SCRIPT" | sed '$d' > "$T/block.sh"
if ! grep -q '^ask_time()' "$T/block.sh"; then
    echo "could not find the time block in ${SCRIPT#"$ROOT"/} (did its markers move?)"; exit 1
fi

cat > "$T/bin/chronyd" <<'EOF'
#!/bin/sh
printf 'ARGC=%s\n' "$#" >> "$FAKE_LOG"; for a in "$@"; do printf 'ARG=%s\n' "$a" >> "$FAKE_LOG"; done
case "$FAKE_MODE" in
  behind)  echo "chronyd version 4.9 starting"; echo "System clock wrong by -1.234567 seconds (ignored)"; echo "chronyd exiting" ;;
  ahead)   echo "System clock wrong by 86400.500000 seconds (ignored)" ;;
  twice)   echo "System clock wrong by 9.000000 seconds (ignored)"; echo "System clock wrong by 0.250000 seconds (ignored)" ;;
  junk)    echo "System clock wrong by 1e9 seconds"; echo "System clock wrong by ; rm -rf / seconds" ;;
  timeout) echo "Timeout reached"; echo "chronyd exiting"; exit 1 ;;
  sigsys)  exit 159 ;;
esac
EOF
cat > "$T/bin/python3" <<'EOF'
#!/bin/sh
shift 2
printf 'TOLD=%s %s\n' "$1" "$2" >> "$FAKE_LOG"
echo "ok stepped"
EOF
chmod +x "$T/bin/chronyd" "$T/bin/python3"

cat > "$T/harness.sh" <<EOF
say() { echo "SAY: \$*"; }
uplink_addr() { echo "\$FAKE_ADDR"; }
. "$T/block.sh"
TIME_CONF="\$FAKE_CONF"
set -- eth0 wlan0
ask_time "\$@"
echo "STATE=\$TIME_STATE"
echo "UPLINKS=\$*"
EOF

printf 'server time.example.org\n# a comment\npool   pool.example.net  \nserver bad host\nserver evil;rm\nserver\npeer other.example\n  server  spaced.example  \n' > "$T/time.conf"
: > "$T/empty.conf"

has() { [[ "$1" == *"$2"* ]]; }

SHELLS=()
for s in dash bash busybox; do command -v "$s" >/dev/null 2>&1 && SHELLS+=("$s"); done
[[ ${#SHELLS[@]} -gt 0 ]] || { echo "no shell to run it under"; exit 77; }

for s in "${SHELLS[@]}"; do
    sh_cmd="$s"; [[ "$s" == busybox ]] && sh_cmd="busybox sh"
    echo "under ${sh_cmd}:"
    # shellcheck disable=SC2086  # "busybox sh" is two words on purpose
    r() { : > "$T/log"; OUT="$(PATH="$T/bin:$PATH" FAKE_LOG="$T/log" FAKE_MODE="$1" FAKE_ADDR="$2" FAKE_CONF="$3" $sh_cmd "$T/harness.sh" 2>&1)"; LOG="$(cat "$T/log")"; }

    r behind 10.0.2.15/24 "$T/time.conf"
    if has "$LOG" "ARGC=6" && has "$LOG" "ARG=server time.example.org iburst" && has "$LOG" "ARG=pool pool.example.net iburst maxsources 4" && has "$LOG" "ARG=server spaced.example iburst"; then
        green "each accepted source reaches chronyd as one argument, after -Q -t 10"
    else red "the directives did not reach chronyd as written" "$LOG"; fi
    if ! has "$LOG" "bad host" && ! has "$LOG" "evil" && ! has "$LOG" "peer"; then
        green "a line that is not 'server HOST' or 'pool HOST' is not passed on (spaces, ';', other directives)"
    else red "a malformed source line reached chronyd" "$LOG"; fi
    if has "$OUT" "STATE=-1.234567" && has "$LOG" "TOLD=-1.234567 3"; then
        green "a clock that is ahead: the negative offset is what zone 0 is told, with the source count"
    else red "wrong offset or count for a clock that is ahead" "$OUT | $LOG"; fi
    if has "$OUT" "UPLINKS=eth0 wlan0"; then green "the script's list of uplinks survives the function's own set --"
    else red "ask_time clobbered the script's positional parameters" "$OUT"; fi

    r ahead 10.0.2.15/24 "$T/time.conf"
    if has "$LOG" "TOLD=86400.500000 3"; then green "a clock a day behind: the positive offset is passed on unchanged (zone 0 decides, not this zone)"
    else red "wrong offset for a clock that is behind" "$LOG"; fi

    r twice 10.0.2.15/24 "$T/time.conf"
    if has "$LOG" "TOLD=0.250000 3" && ! has "$LOG" "TOLD=9.000000"; then green "the last measurement is the one reported"
    else red "did not report the last measurement" "$LOG"; fi

    r junk 10.0.2.15/24 "$T/time.conf"
    if has "$OUT" "STATE=no-answer" && ! has "$LOG" "TOLD="; then green "a line that is not a plain decimal is no answer, and nothing is sent"
    else red "junk from the client was treated as an offset" "$OUT | $LOG"; fi

    r timeout 10.0.2.15/24 "$T/time.conf"
    if has "$OUT" "STATE=no-answer" && ! has "$LOG" "TOLD="; then green "a server that does not answer is 'no-answer', not a pass and not a zero offset"
    else red "a timeout was not reported as no answer" "$OUT | $LOG"; fi

    r sigsys 10.0.2.15/24 "$T/time.conf"
    if has "$OUT" "STATE=killed-by-seccomp" && has "$OUT" "seccomp"; then green "a client killed by the zone's seccomp policy is said to be, not mistaken for a quiet network"
    else red "SIGSYS was not reported" "$OUT"; fi

    r behind "" "$T/time.conf"
    if has "$OUT" "STATE=no-uplink" && [[ -z "$LOG" ]]; then green "with no uplink address nothing is asked at all"
    else red "asked the network with no uplink" "$OUT | $LOG"; fi

    r behind 10.0.2.15/24 /nonexistent
    if has "$LOG" "ARGC=4" && has "$LOG" "ARG=pool pool.ntp.org iburst maxsources 4" && has "$LOG" "TOLD=-1.234567 1"; then
        green "without zone 0's source list the default pool is asked, and counted as one source"
    else red "the default source is wrong" "$LOG"; fi

    r behind 10.0.2.15/24 "$T/empty.conf"
    if has "$OUT" "STATE=unconfigured" && [[ -z "$LOG" ]]; then green "a source list that names nothing asks nothing and says so"
    else red "an empty source list was not reported" "$OUT | $LOG"; fi
done

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
