#!/usr/bin/env bash
# sysinit's prune_etc_upper: the /etc overlay's upper layer, on the
# unauthenticated state partition, may carry the account database, the
# machine's identity and clock, and nothing else. Everything else that an
# offline writer put there - a preload library, a udev rule, a zone
# definition, a profile - is moved to a quarantine directory before the
# overlay is mounted. Exercised on a staged upper layer with the function
# taken from the script itself, under `sh -e` as sysinit runs. No root.
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

# A second run over what is left changes nothing: idempotent, as sysinit is.
before="$(ls -A "$T/up" | sort | tr '\n' ' ')"
sh -e -c ". $T/fn.sh; prune_etc_upper $T/up $T/q" >/dev/null 2>&1
after="$(ls -A "$T/up" | sort | tr '\n' ' ')"
[[ "$before" = "$after" ]] && ok "a second pass leaves the allowed entries alone" || bad "a second pass changed the upper layer: '$before' -> '$after'"

# An empty or missing upper layer is fine too (first boot).
rm -rf "$T/up" "$T/q"
sh -e -c ". $T/fn.sh; prune_etc_upper $T/up $T/q" >/dev/null 2>&1 && ok "a missing upper layer is not an error" || bad "a missing upper layer made prune_etc_upper fail"
mkdir -p "$T/up"
sh -e -c ". $T/fn.sh; prune_etc_upper $T/up $T/q" >/dev/null 2>&1 && [[ ! -e "$T/q" ]] && ok "an empty upper layer creates no quarantine directory" || bad "an empty upper layer was not left alone"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
