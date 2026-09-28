#!/usr/bin/env bash
# Test sysinit's prune_etc_upper, taken from the script and run under sh -e:
# the /etc upper layer (on the unauthenticated state partition) keeps only the
# account database, machine identity and clock; the rest is quarantined.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYSINIT="$ROOT/build/service-scripts/sysinit.sh"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
quarantined() { compgen -G "$T/q/$1.*" > /dev/null; }   # an entry NAME.<epoch> exists in the quarantine

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
sed -n '/^ETC_MUTABLE=/,/^}/p' "$SYSINIT" > "$T/fn.sh"
grep -q '^prune_etc_upper()' "$T/fn.sh" || { echo "could not extract prune_etc_upper from $SYSINIT"; exit 1; }

stage() {   # a fresh upper layer holding what an attacker and the system would put there
    rm -rf "$T/up" "$T/q"
    mkdir -p "$T/up/udev/rules.d" "$T/up/kryptik/zones" "$T/up/sysctl.d" "$T/up/passwd"
    printf '/var/lib/evil.so\n' > "$T/up/ld.so.preload"
    printf 'RUN+="/var/lib/evil.sh"\n' > "$T/up/udev/rules.d/99-evil.rules"
    printf '[zone]\n' > "$T/up/kryptik/zones/evil.toml"
    printf 'kernel.kptr_restrict = 0\n' > "$T/up/sysctl.d/99-evil.conf"
    printf 'export PATH=/var/lib/evil:$PATH\n' > "$T/up/profile"
    printf 'passwd: evil\n' > "$T/up/nsswitch.conf"
    for f in shadow group gshadow subuid subgid passwd- .pwd.lock hostname machine-id localtime adjtime resolv.conf; do
        printf 'kept\n' > "$T/up/$f"
    done
}

stage
out="$(sh -e -c ". $T/fn.sh; prune_etc_upper $T/up $T/q" 2>&1)"; rc=$?
[[ "$rc" -eq 0 ]] && ok "prune_etc_upper returns 0 under sh -e" || bad "prune_etc_upper failed under sh -e (rc=$rc): $(tail -2 <<<"$out" | tr '\n' ' ')"

for f in shadow group gshadow subuid subgid passwd- .pwd.lock hostname machine-id localtime adjtime resolv.conf; do
    [[ -f "$T/up/$f" && "$(cat "$T/up/$f")" = kept ]] || bad "allowed entry '$f' was not kept in the upper layer"
done
ok "the account database, the machine's identity and clock stay in the upper layer"

for f in ld.so.preload udev kryptik sysctl.d profile nsswitch.conf; do
    [[ ! -e "$T/up/$f" ]] || bad "'$f' is still in the upper layer"
    quarantined "$f" || bad "'$f' is not in the quarantine directory"
done
ok "a preload library, a udev rule, a zone definition, a sysctl fragment, a profile and nsswitch.conf are quarantined"

[[ ! -e "$T/up/passwd" ]] && quarantined passwd && ok "a directory named after an allowed file is quarantined, not kept" || bad "a directory named passwd stayed in the upper layer"

grep -q "quarantined 'ld.so.preload'" <<<"$out" && ok "each quarantined entry is named on stderr" || bad "the preload library was quarantined silently: $(head -3 <<<"$out" | tr '\n' ' ')"

before="$(ls -A "$T/up" | sort | tr '\n' ' ')"
sh -e -c ". $T/fn.sh; prune_etc_upper $T/up $T/q" >/dev/null 2>&1
after="$(ls -A "$T/up" | sort | tr '\n' ' ')"
[[ "$before" = "$after" ]] && ok "a second pass leaves the allowed entries alone" || bad "a second pass changed the upper layer: '$before' -> '$after'"

# An empty or missing upper layer is fine too (first boot).
rm -rf "$T/up" "$T/q"
sh -e -c ". $T/fn.sh; prune_etc_upper $T/up $T/q" >/dev/null 2>&1 && ok "a missing upper layer is not an error" || bad "a missing upper layer made prune_etc_upper fail"
mkdir -p "$T/up"
sh -e -c ". $T/fn.sh; prune_etc_upper $T/up $T/q" >/dev/null 2>&1 && [[ ! -e "$T/q" ]] && ok "an empty upper layer creates no quarantine directory" || bad "an empty upper layer was not left alone"

# A failed move must fail the call even under `if` (where sh -e is off), so
# the unfiltered layer is never mounted.
stage
if sh -e -c '. "$1"; mv() { return 1; }; if prune_etc_upper "$2" "$3"; then exit 0; else exit 1; fi' sh "$T/fn.sh" "$T/up" "$T/q" >/dev/null 2>&1; then
    bad "a failed quarantine move was reported as success"
else
    [[ -f "$T/up/ld.so.preload" ]] && ok "failed quarantine refuses without deleting the original" || bad "failed quarantine lost the original"
fi

stage
ln -s "$T/up" "$T/linked-upper"
sh -e -c '. "$1"; prune_etc_upper "$2" "$3"' sh "$T/fn.sh" "$T/linked-upper" "$T/q" >/dev/null 2>&1 && bad "symlinked upper accepted" || ok "symlinked upper refused"
ln -s "$T/up" "$T/q"
sh -e -c '. "$1"; prune_etc_upper "$2" "$3"' sh "$T/fn.sh" "$T/up" "$T/q" >/dev/null 2>&1 && bad "symlinked quarantine accepted" || ok "symlinked quarantine refused"
rm "$T/q"
ln -s "$T/up" "$T/work"
sh -e -c '. "$1"; prune_etc_upper "$2" "$3"' sh "$T/fn.sh" "$T/up" "$T/q" >/dev/null 2>&1 && bad "symlinked overlay workdir accepted" || ok "symlinked overlay workdir refused"
rm "$T/work"

stage
rm "$T/up/shadow" "$T/up/group"
ln -s "$T/untrusted-shadow" "$T/up/shadow"
mkfifo "$T/up/group"
printf 'hidden\n' > "$T/up/..hidden"
sh -e -c '. "$1"; prune_etc_upper "$2" "$3"' sh "$T/fn.sh" "$T/up" "$T/q" >/dev/null 2>&1
[[ ! -L "$T/up/shadow" ]] && quarantined shadow && ok "symlinked account file quarantined" || bad "symlinked shadow kept"
[[ ! -e "$T/up/group" ]] && quarantined group && ok "FIFO account file quarantined" || bad "FIFO group kept"
[[ ! -e "$T/up/..hidden" ]] && quarantined ..hidden && ok "double-dot hidden entry quarantined" || bad "double-dot hidden entry missed"

if [[ -f /usr/share/zoneinfo/UTC ]]; then
    rm "$T/up/localtime"
    ln -s /usr/share/zoneinfo/UTC "$T/up/localtime"
    if sh -e -c '. "$1"; prune_etc_upper "$2" "$3"' sh "$T/fn.sh" "$T/up" "$T/q" >/dev/null 2>&1 && [[ -L "$T/up/localtime" ]]; then
        ok "localtime may still link into verified zoneinfo"
    else
        bad "legitimate zoneinfo symlink was not preserved"
    fi
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
