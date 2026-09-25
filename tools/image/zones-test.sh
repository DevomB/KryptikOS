#!/usr/bin/env bash
# Zones, the network and encrypted storage on the installed system: install,
# boot the disk alone with a NIC, and run the guest's checks and the
# compartment suites as root over the serial login. The verdicts are the
# guest's own; a missing verdict is a failure.
#
#   tools/image/zones-test.sh --usb IMG [--disk FILE] [--timeout N] [--skip-suites]
#
#   step 1  install, boot alone with QEMU user networking
#   step 2  guest-tests/zones-check.sh: kernel support, the net zone, zone 0
#           offline, routed egress and DNS, zone separation, fail-closed
#           restart, time claims, limits, and the LUKS2 volume lifecycle
#   step 3  the compartment suites' [vm] rows on the target kernel (not with
#           --skip-suites)
#   step 4  reboot; the encrypted zone's data is still there
set -uo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"
trap - ERR; set +e

USB=""; DISK=""; TIMEOUT=600; SUITES=1
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --usb) USB="${2:?}"; shift 2 ;;
        --disk) DISK="${2:?}"; shift 2 ;;
        --timeout) TIMEOUT="${2:?}"; shift 2 ;;
        --skip-suites) SUITES=0; shift ;;
        -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -f "$USB" ]] || die "--usb IMG is required"
for t in python3 sfdisk truncate; do have "$t" || die "required tool not found: $t"; done
VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"
DISK="${DISK:-${VMDIR}/zones.img}"
[[ -e "$DISK" && ! -f "$DISK" ]] && die "refusing: ${DISK} is not a regular file"

# shellcheck source=tools/image/suite-lib.sh
source "${SELF}/suite-lib.sh"
VARSF="${VMDIR}/zones-vars.fd"; cp /usr/share/OVMF/OVMF_VARS_4M.fd "$VARSF"
drive() { python3 "$DRV" --serial "$SER" --timeout "$1" "${@:2}"; }

# ----------------------------------------------------------------- step 1 --
step "step 1: install and boot alone with a NIC"
# Sized from the medium, not a constant: see test-disk-size.sh.
DISK_SIZE="$("${SELF}/test-disk-size.sh" --medium "$USB" --extra-mib 2048)" || die "could not size the test disk from the medium"
rm -f "$DISK"; truncate -s "$DISK_SIZE" "$DISK"
CTL="${VMDIR}/testctl-zones.img"
"${SELF}/mk-testctl.sh" --out "$CTL" install_target=/dev/vda smoke_poweroff=1 install_wait=5 \
    "${PRESEED[@]}" > /dev/null
"${SELF}/run-ovmf.sh" --usb "$USB" --disk "$DISK" --testctl "$CTL" --vars clean --mode smoke --timeout "$TIMEOUT" --name zones-install > /dev/null
tr -d '\r' < "$LATEST" | grep -q 'KRYPTIK_INSTALL: rc=0' && green "installed" || { red "install failed"; exit 1; }

# ----------------------------------------------------------------- step 2 --
step "step 2: the guest-side zone, network and storage checks (as root)"
# 3 GB, not the default 2: ephemeral-size-bound fills untrusted's 2G tmpfs,
# which is RAM, until ENOSPC.
start_vm zones-p2 --net user --mem 3072
drive 900 "expect:KRYPTIK_SMOKE: END" "seen:kryptik-firstboot: created user '${TUSER}'" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'bash /usr/lib/kryptik/guest-tests/zones-check.sh 2>&1 | tee /var/log/kryptik/zones-check.log; echo ZCHECK-DONE')" \
    "expect:ZT END" "expect:ZCHECK-DONE"
rc=$?
T2="$(txt)"
[[ "$rc" -eq 0 ]] && green "zones-check.sh ran to its end" || red "zones-check.sh did not run to its end"
grep -q 'ZT BEGIN' <<<"$T2" || red "no ZT BEGIN: the guest checks never started"
summary="$(grep -o 'ZT SUMMARY passed=[0-9]* failed=[0-9]*' <<<"$T2" | tail -1)"
echo "  guest summary: ${summary:-none}"
zp="$(sed -n 's/.*passed=\([0-9]*\).*/\1/p' <<<"$summary")"; zf="$(sed -n 's/.*failed=\([0-9]*\).*/\1/p' <<<"$summary")"
if [[ -n "$summary" && "${zf:-1}" -eq 0 && "${zp:-0}" -ge 30 ]]; then green "every guest check passed (${zp})"; else red "guest checks: ${zp:-0} passed, ${zf:-?} failed"; fi
grep 'ZT FAIL' <<<"$T2" | sed 's/^/        /'
# The key verdicts one by one, so a pass is not a single line.
for name in kernel-support net-ready zone0-nic zone0-no-route zone0-offline routed-egress routed-dns routed-ipv6-noglobal zone-separation fail-closed net-restart-ready reattach-after-restart time-floor-ran time-clamp time-claim-stepped time-claim-floor time-claim-consent pids-limit ephemeral-size-bound \
            volume-init encrypted-zone-start stop-closes-volume wrong-passphrase persist-reopen no-mapping-after ephemeral-gone concurrent-start-refused full-volume header-restore vault-offline no-passphrase-leak; do
    grep -q "ZT PASS ${name}" <<<"$T2" && green "guest: ${name}" || red "guest: ${name} (not passed)"
done

# ----------------------------------------------------------------- step 3 --
if [[ "$SUITES" -eq 1 ]]; then
step "step 3: the compartment suites on the target kernel (as root)"
# Suites log on the guest, whose disk acceptance does not keep, so the console
# also gets each exit code, summary tail and FAIL row with context.
suite_cmd() {   # suite_cmd TAG TAIL_LINES COMMAND -> the guest command line
    printf '%s > /var/log/kryptik/%s-suite.log 2>&1; echo %s-RC=$?; tail -%s /var/log/kryptik/%s-suite.log; grep -n -A3 "^ *FAIL" /var/log/kryptik/%s-suite.log | sed "s/^/%s-FAIL: /" | head -80' \
        "$3" "${1,,}" "$1" "$2" "${1,,}" "${1,,}" "$1"
}
drive 1800 \
    "$(ROOTSH "$(suite_cmd LAUNCHER 12 'cd /usr/lib/kryptik/compartments/tests && KRYPTIKD=/usr/bin/kryptikd KRYPTIK_SKIP_STALE_CHECK=1 NO_COLOR=1 bash ./launcher.sh')")" "expect:LAUNCHER-RC=[0-9]+" \
    "$(ROOTSH "$(suite_cmd ADVERSARIAL 6 'cd /usr/lib/kryptik/compartments/tests && KRYPTIKD=/usr/bin/kryptikd NO_COLOR=1 bash ./adversarial.sh')")" "expect:ADVERSARIAL-RC=[0-9]+" \
    "$(ROOTSH "$(suite_cmd BOUNDARY 6 'cd /usr/lib/kryptik/compartments/kryptikd/probes && NO_COLOR=1 bash ./boundary-checks.sh /usr/bin/kryptikd')")" "expect:BOUNDARY-RC=[0-9]+" \
    "$(ROOTSH "$(suite_cmd CLI 4 'cd /usr/lib/kryptik/compartments/tests && KRYPTIKD=/usr/bin/kryptikd NO_COLOR=1 bash ./cli.sh')")" "expect:CLI-RC=[0-9]+"
rc=$?
T3="$(txt)"
[[ "$rc" -eq 0 ]] && green "all four suites ran" || red "a suite did not run to its end"
for s in LAUNCHER ADVERSARIAL BOUNDARY CLI; do
    code="$(grep -o "${s}-RC=[0-9]*" <<<"$T3" | tail -1 | cut -d= -f2)"
    if [[ "$code" = 0 ]]; then
        green "${s,,} suite exit 0"
    else
        red "${s,,} suite exit ${code:-none}"
        grep "^${s}-FAIL: " <<<"$T3" | sed "s/^${s}-FAIL: /        /"
    fi
done
# The launcher gaps accepted here; any other is a failure. NETR: the real net
# zone holds the NIC (zones-check covers it). LC15/LC16: unprivileged-only.
# H1c: zone 0 has no interface here.
if grep -q 'LAUNCHER SUITE PASSED$' <<<"$T3"; then
    green "launcher suite passed with no gaps"
elif grep -q 'LAUNCHER SUITE PASSED WITH GAPS' <<<"$T3"; then
    other="$(sed -n '/not run (mandatory gaps/,/^$/p' <<<"$T3" | grep -E '^ *- ' | grep -vE 'NETR|POL6|LC15/LC16|H1c')"
    if [[ -z "$other" ]]; then
        green "launcher suite passed; its only gaps are the accounted-for ones (NETR: the real net zone is measured by zones-check; POL6: by design; LC15/16: unprivileged-only; H1c: zone 0 has no interface here)"
    else
        red "launcher suite passed with unaccounted gaps: $(tr '\n' ' ' <<<"$other")"
    fi
else
    red "launcher suite did not report PASSED"
fi
grep -E 'passed, [0-9]+ failed, [0-9]+ not run' <<<"$T3" | tail -1 | sed 's/^/        launcher: /'
fi

# ----------------------------------------------------------------- step 4 --
step "step 4: reboot; the encrypted zone's data is still there"
drive 300 "$(ROOTSH 'reboot')" "expect:Linux version" "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'kryptikd run personal --zones /usr/lib/kryptik/zones --rootfs /var/lib/kryptik/zones --passphrase-file /root/zt/personal.pass -- cat /home/personal/keep; echo REOPEN-RC=$?')" "expect:secret-data-1" "expect:REOPEN-RC=0" \
    "$(ROOTSH 'ls /dev/mapper | sed s/^/MAPPER:/; echo MAPPER-DONE')" "expect:MAPPER-DONE" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "after a reboot the LUKS2 volume opens with its passphrase and the data is there" || red "step 4 drive failed"
# Only the tagged listing counts: step 2 opens and closes kryptik-personal, so
# the name appears earlier in the transcript.
if txt | grep -q '^MAPPER:kryptik-personal'; then red "a mapping was left open after the reboot check"; else green "no mapping left after the zone exited"; fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
echo "Guest logs: /var/log/kryptik/zones-check.log and the suite logs on the disk ${DISK}; serial transcript ${LOG}"
[[ "$FAIL" -eq 0 ]] || exit 1
