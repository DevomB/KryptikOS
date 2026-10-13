#!/usr/bin/env bash
#
# Suspend to RAM with the state partition's key dropped, on the INSTALLED system (the suspend
# suite): install from the medium, boot the disk alone with suspend to RAM offered, a virtual
# GPU and keyboard, start the desktop session for an ordinary user and run the guest-side checks
# (build/guest-tests/suspend-check.sh) as root over the serial login, pressing keys through QMP
# where the guest asks for them.
#
#   tools/image/suspend-test.sh --usb IMG [--disk FILE] [--timeout N]
#
# First the way back is proven with the machine up: the key dropped, the caches of dentries and
# inodes dropped, and the screen lock, which the compositor starts, asks for the state passphrase,
# refuses a wrong one and resumes with the right one, while nothing but a writer on /var waits
# on the partition. Then the guest locks and sleeps for real. While it sleeps the host dumps its
# memory, which must hold neither the state partition's key nor the passphrase typed at the lock,
# and must hold the key of the zone volume a frozen zone keeps; it waits past the watchdog's
# timeout and wakes the guest, which waits three minutes at the state prompt before the
# passphrase, typed again, resumes it. Last, a read left waiting on the suspended device keeps
# the kernel from sleeping when the guest is asked again: the refusal is told, and the passphrase
# still brings the partition back. Then each of what else has the machine sleep: the power
# button, pressed through QMP, with the session unlocked and with it locked, kryptik-lock
# --suspend with a lock up already, and idleness after the lock.
set -uo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"
trap - ERR; set +e

USB=""; DISK=""; TIMEOUT=600
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --usb) USB="${2:?}"; shift 2 ;;
        --disk) DISK="${2:?}"; shift 2 ;;
        --timeout) TIMEOUT="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,18p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -f "$USB" ]] || die "--usb IMG is required"
for t in python3 sfdisk truncate od; do have "$t" || die "required tool not found: $t"; done
VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"
DISK="${DISK:-${VMDIR}/suspend.img}"
[[ -e "$DISK" && ! -f "$DISK" ]] && die "refusing: ${DISK} is not a regular file"

# shellcheck source=tools/image/suite-lib.sh
source "${SELF}/suite-lib.sh"
VARSF="${VMDIR}/suspend-vars.fd"; cp /usr/share/OVMF/OVMF_VARS_4M.fd "$VARSF"
DUMP="${VMDIR}/suspend-memory.elf"
# The guest makes a second state passphrase, the seed reversed, which is typed at the lock: the
# seed alone crosses the serial line, so a copy of the passphrase in the guest's memory came from
# its way from the keyboard to cryptsetup.
SEED="$(od -An -N6 -tx1 /dev/urandom | tr -dc 0-9a-f)"
SPASS="$(rev <<<"$SEED")"
SPASS_KEYS=()
for ((i = 0; i < ${#SPASS}; i++)); do SPASS_KEYS+=("key:${SPASS:i:1}"); done

# ----------------------------------------------------------------- step 1 --
step "step 1: install"
fresh_disk "$USB"
install_disk suspend-install "$USB" --vars clean && green "installed" || { red "install failed"; exit 1; }

# ----------------------------------------------------------------- step 2 --
step "step 2: suspend, driven"
rm -f "$DUMP"
start_vm suspend-p2 --net user --gpu --s3 --mem 3072
DRIVE_TIMEOUT=900 drive --qmp "$QMP" \
    "expect:KRYPTIK_SMOKE: END" "seen:kryptik-firstboot: created user '${TUSER}'" "login:${TUSER}:${TPASS}" \
    "send:su - root -c 'bash /usr/lib/kryptik/guest-tests/suspend-check.sh ${TUSER} ${KRYPTIK_STATE_PASSPHRASE} ${SEED} 2>&1; echo SCHECK-DONE'" \
    "expect:Password: ?" "send:${RPASS}" \
    "expect:GT KEY-LOCK 1" "key:alt+shift+l" \
    "expect:GT LOCK-TYPE-STATE-WRONG" "key:n" "key:o" "key:p" "key:e" "key:ret" \
    "expect:GT LOCK-TYPE-STATE 1" "${SPASS_KEYS[@]}" "key:ret" \
    "expect:GT SLEEPING 1" "asleep-or:120:GT DID-NOT-SLEEP 1" "if-asleep:dump:${DUMP}" "if-asleep:sleep:75" "if-asleep:wakeup" \
    "expect:GT LOCK-TYPE-STATE 2" "${SPASS_KEYS[@]}" "key:ret" \
    "expect:GT KEY-LOCK 2" "key:alt+shift+l" \
    "expect:GT SLEEPING 2" "asleep-or:120:GT DID-NOT-SLEEP 2" "if-asleep:sleep:5" "if-asleep:wakeup" \
    "expect:GT LOCK-TYPE-STATE 3" "${SPASS_KEYS[@]}" "key:ret" \
    "expect:GT POWER-KEY 1" "powerkey" "asleep-or:120:GT DID-NOT-SLEEP 3" "if-asleep:sleep:5" "if-asleep:wakeup" \
    "expect:GT POWER-KEY SOON" "powerkey" "asleep-or:30:GT DID-NOT-SLEEP 7" "if-asleep:sleep:5" "if-asleep:wakeup" \
    "expect:GT POWER-KEY 3" "powerkey" "asleep-or:120:GT DID-NOT-SLEEP 8" "if-asleep:sleep:5" "if-asleep:wakeup" \
    "expect:GT LOCK-TYPE-STATE 4" "${SPASS_KEYS[@]}" "key:ret" \
    "expect:GT KEY-LOCK 3" "key:alt+shift+l" \
    "expect:GT POWER-KEY 2" "powerkey" "asleep-or:120:GT DID-NOT-SLEEP 4" "if-asleep:sleep:5" "if-asleep:wakeup" \
    "expect:GT LOCK-TYPE-STATE 5" "${SPASS_KEYS[@]}" "key:ret" \
    "expect:GT KEY-LOCK 4" "key:alt+shift+l" \
    "expect:GT SLEEPING 3" "asleep-or:120:GT DID-NOT-SLEEP 5" "if-asleep:sleep:5" "if-asleep:wakeup" \
    "expect:GT LOCK-TYPE-STATE 6" "${SPASS_KEYS[@]}" "key:ret" \
    "expect:GT SLEEPING 4" "asleep-or:120:GT DID-NOT-SLEEP 6" "if-asleep:sleep:5" "if-asleep:wakeup" \
    "expect:GT LOCK-TYPE-STATE 7" "${SPASS_KEYS[@]}" "key:ret" \
    "expect:GT END" "expect:SCHECK-DONE" \
    "send:su - root -c 'poweroff'" "expect:Password: ?" "send:${RPASS}" \
    "expect:Power down" "wait-exit"
drc=$?
stop_vm
T="$(tr -d '\r' < "$LOG")"
[[ "$drc" -eq 0 ]] && green "the guest checks ran to their end with the keystrokes delivered" || red "the drive failed (see above)"
summary="$(grep -o 'GT SUMMARY passed=[0-9]* failed=[0-9]*' <<<"$T" | tail -1)"
echo "  guest summary: ${summary:-none}"
gp="$(sed -n 's/.*passed=\([0-9]*\).*/\1/p' <<<"$summary")"; gf="$(sed -n 's/.*failed=\([0-9]*\).*/\1/p' <<<"$summary")"
if [[ -n "$summary" && "${gf:-1}" -eq 0 && "${gp:-0}" -ge 15 ]]; then green "every guest check passed (${gp})"; else red "guest checks: ${gp:-0} passed, ${gf:-?} failed"; fi
grep 'GT FAIL' <<<"$T" | sed 's/^/        /'
for name in second-passphrase session-up zones-ticking state-suspended zones-frozen client-told-suspended lock-asks-for-state \
            nothing-else-waits lock-refuses-wrong-passphrase passphrase-resumes zones-thawed writer-resumes zones-tick-again \
            slept-and-woke woke-to-state-prompt prompt-outlasts-watchdog resumed-after-sleep zones-thawed-after-sleep \
            sleep-refusal-told resumed-after-refusal \
            power-key-sleeps power-key-held-off-after-wake power-key-heeded-after-holdoff power-key-resumes \
            power-key-sleeps-locked power-key-locked-resumes \
            lock-pid-written lock-up-sleeps lock-up-resumes lock-pid-removed idle-sleeps idle-sleep-resumes; do
    grep -q "GT PASS ${name}" <<<"$T" && green "guest: ${name}" || red "guest: ${name} (not passed)"
done

# ----------------------------------------------------------------- step 3 --
step "step 3: the memory of the sleeping guest"
skey="$(sed -n 's/^GT STATE-KEY \([0-9a-f]*\)$/\1/p' <<<"$T" | tail -1)"
zkey="$(sed -n 's/^GT ZONE-KEY \([0-9a-f]*\)$/\1/p' <<<"$T" | tail -1)"
if [[ -s "$DUMP" && -n "$skey" && -n "$zkey" ]]; then
    # Each half of an XTS key is a key of its own; the dump is read in pieces that overlap by
    # more than the longest needle.
    verdict="$(python3 - "$DUMP" "$skey" "$zkey" "$SPASS" <<'PY'
import sys
dump, skey, zkey, spass = sys.argv[1:]
def halves(hexkey):
    k = bytes.fromhex(hexkey)
    return [k[:len(k) // 2], k[len(k) // 2:]]
needles = {"state key": halves(skey), "zone key": halves(zkey), "passphrase": [spass.encode()]}
found = {name: [False] * len(n) for name, n in needles.items()}
tail = b""
with open(dump, "rb") as f:
    while True:
        piece = f.read(64 << 20)
        if not piece:
            break
        hay = tail + piece
        for name, ns in needles.items():
            for i, n in enumerate(ns):
                found[name][i] = found[name][i] or n in hay
        tail = hay[-128:]
for name in needles:
    print(f"{name}: {sum(found[name])} of {len(found[name])} found")
PY
)"
    printf '%s\n' "$verdict" | sed 's/^/  /'
    [[ "$verdict" == *"zone key: 2 of 2 found"* ]] && green "the dump holds the zone volume's key, which a frozen zone keeps: the search can find a key" || red "the zone volume's key is not in the dump: it is not the guest's memory, or the search finds nothing"
    [[ "$verdict" == *"state key: 0 of 2 found"* ]] && green "the dump holds no half of the state partition's key" || red "the state partition's key is in the memory of the sleeping guest"
    [[ "$verdict" == *"passphrase: 0 of 1 found"* ]] && green "the dump holds not the passphrase typed at the lock before the sleep" || red "the passphrase typed at the lock is in the memory of the sleeping guest"
else
    red "no memory dump to search (${DUMP}), or the guest gave no keys"
fi
rm -f "$DUMP"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
echo "Serial transcript ${LOG}"
[[ "$FAIL" -eq 0 ]] || exit 1
