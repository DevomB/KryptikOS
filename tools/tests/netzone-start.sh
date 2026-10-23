#!/usr/bin/env bash
# The net zone's start (build/services/net-zone/run) against a stand-in sysfs: it waits for a
# network controller a driver has taken until that has its interface, and for nothing else.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN="${ROOT}/build/services/net-zone/run"
PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

sed -n '/^pending() {/,/^}/p' "$RUN" > "$T/pending.sh"
grep -q '^pending() {' "$T/pending.sh" || { echo "could not find pending in ${RUN#"$ROOT"/}"; exit 1; }
dev() {   # dev NAME CLASS [driver] [net|ieee80211]: a PCI device under the stand-in sysfs
    local d="$T/sys/bus/pci/devices/$1"
    mkdir -p "$d"; echo "$2" > "$d/class"
    [[ "${3:-}" != driver ]] || ln -s "$T" "$d/driver"
    [[ -z "${4:-}" ]] || mkdir -p "$d/$4/x"
}
waits() { NET_SYS="$T/sys" sh -c '. "$1"; pending' sh "$T/pending.sh"; }   # 0 while it would wait

dev 0000:01:00.0 0x020000 driver net
dev 0000:00:08.1 0x030000 driver
dev 0000:05:00.0 0x028000
if waits; then red "a wire up, a display and an unbound radio: nothing to wait for"; else green "a wire up, a display and an unbound radio: nothing to wait for"; fi
dev 0000:02:00.0 0x028000 driver
if waits; then green "a radio its driver has taken, with no interface yet, is waited for"; else red "a radio its driver has taken, with no interface yet, is waited for"; fi
mkdir -p "$T/sys/bus/pci/devices/0000:02:00.0/ieee80211/phy0"
if waits; then red "its phy registered, it is no longer waited for"; else green "its phy registered, it is no longer waited for"; fi
dev 0000:03:00.0 0x020000 driver
if waits; then green "a wired card its driver has taken, with no interface yet, is waited for too"; else red "a wired card its driver has taken, with no interface yet, is waited for too"; fi
rm -rf "$T/sys"
if waits; then red "no PCI devices at all: nothing to wait for"; else green "no PCI devices at all: nothing to wait for"; fi
grep -qE 'while \[ "\$waited" -lt 10 \] && pending; do' "$RUN" \
    && green "the wait ends after ten seconds whatever the driver does" || red "the wait is not held to ten seconds"
n_wait="$(grep -n '&& pending; do' "$RUN" | head -1 | cut -d: -f1)"; n_exec="$(grep -n '^exec /usr/bin/kryptikd run net' "$RUN" | cut -d: -f1)"
[[ -n "$n_wait" && -n "$n_exec" && "$n_wait" -lt "$n_exec" ]] && green "and it comes before the zone starts" || red "the wait at line '${n_wait}' is not before the start at '${n_exec}'"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
