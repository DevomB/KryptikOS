#!/usr/bin/env bash
# The net zone's start (build/services/net-zone/run) against a stand-in sysfs: it waits for a
# network controller a driver has taken until that has its interface, ten seconds at most, and
# for nothing else. The shipped check and wait run as they are, with a sleep that only counts.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN="${ROOT}/build/services/net-zone/run"
PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

sed -n '/^pending() {/,/^}/p; /^waited=0$/,/^fi$/p' "$RUN" > "$T/wait.sh"
grep -q '^pending() {' "$T/wait.sh" && grep -q '^waited=0$' "$T/wait.sh" \
    || { echo "could not find pending and the wait in ${RUN#"$ROOT"/}"; exit 1; }
# A sleep that counts, and once LATE calls have passed gives the radio named in RADIO its phy.
mkdir -p "$T/bin"
cat > "$T/bin/sleep" <<'S'
#!/bin/sh
echo x >> "$SLEPT"
n=$(wc -l < "$SLEPT")
[ -z "${LATE:-}" ] || [ "$n" -lt "$LATE" ] || mkdir -p "$RADIO/ieee80211/phy0"
exit 0
S
chmod +x "$T/bin/sleep"
dev() {   # dev NAME CLASS [driver] [SUBDIR]: a PCI device under the stand-in sysfs
    local d="$T/sys/bus/pci/devices/$1"
    mkdir -p "$d"; echo "$2" > "$d/class"
    [[ "${3:-}" != driver ]] || ln -s "$T" "$d/driver"
    [[ -z "${4:-}" ]] || mkdir -p "$d/$4/x"
}
sed -n '/^pending() {/,/^}/p' "$RUN" > "$T/pending.sh"
waits() { NET_SYS="$T/sys" sh -c '. "$1"; pending' sh "$T/pending.sh"; }   # 0 while it would wait
start() {   # start [LATE]: runs the wait; sets SLEPT_N to the seconds waited and SAID to what it said
    : > "$T/slept"
    SAID="$(NET_SYS="$T/sys" SLEPT="$T/slept" LATE="${1:-}" RADIO="$T/sys/bus/pci/devices/0000:02:00.0" \
        PATH="$T/bin:$PATH" sh "$T/wait.sh" 2>&1)"
    SLEPT_N="$(wc -l < "$T/slept")"
}

echo "-- what is waited for"
dev 0000:01:00.0 0x020000 driver net
dev 0000:00:08.1 0x030000 driver
dev 0000:05:00.0 0x028000
dev 0000:00:03.0 0x020000 driver virtio0/net
if waits; then red "a wire, a display, an unbound radio and a virtio card's interface one level down: nothing to wait for"
else green "a wire, a display, an unbound radio and a virtio card's interface one level down: nothing to wait for"; fi
start
[[ "$SLEPT_N" -eq 0 && -z "$SAID" ]] && green "and the start goes on at once, saying nothing" || red "nothing to wait for: waited ${SLEPT_N} s, said '${SAID}'"
dev 0000:03:00.0 0x020000 driver
if waits; then green "a wired card its driver has taken, with no interface yet, is waited for"
else red "a wired card its driver has taken, with no interface yet, is waited for"; fi
mkdir -p "$T/sys/bus/pci/devices/0000:03:00.0/net/eth1"

echo "-- how long"
dev 0000:02:00.0 0x028000 driver
start
if [[ "$SLEPT_N" -eq 10 ]] && grep -q 'waiting for a network device' <<<"$SAID" \
    && grep -q 'no interface after ten seconds' <<<"$SAID"; then
    green "a radio that never gets its interface: ten seconds, then the start goes on and says so"
else
    red "a radio that never registers: waited ${SLEPT_N} s, said '$(tr '\n' '|' <<<"$SAID")'"
fi
[[ "$(grep -c 'waiting for a network device' <<<"$SAID")" -eq 1 ]] && green "the wait is said once" || red "the wait was said $(grep -c 'waiting' <<<"$SAID") times"
start 3
if [[ "$SLEPT_N" -eq 3 ]] && ! grep -q 'after ten seconds' <<<"$SAID"; then
    green "a radio that registers during the wait ends it there"
else
    red "a radio that registers after 3 s: waited ${SLEPT_N} s, said '$(tr '\n' '|' <<<"$SAID")'"
fi

n_wait="$(grep -n '&& pending; do' "$RUN" | head -1 | cut -d: -f1)"; n_exec="$(grep -n '^exec /usr/bin/kryptikd run net' "$RUN" | cut -d: -f1)"
[[ -n "$n_wait" && -n "$n_exec" && "$n_wait" -lt "$n_exec" ]] && green "the wait comes before the zone starts" || red "the wait at line '${n_wait}' is not before the start at '${n_exec}'"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
