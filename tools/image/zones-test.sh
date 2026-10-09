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
#           restart, the net zone over a mac80211_hwsim radio, time claims,
#           limits, and the LUKS2 volume lifecycle
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
fresh_disk "$USB" --extra-mib 2048
install_disk zones-install "$USB" --vars clean && green "installed" || { red "install failed"; exit 1; }

# ----------------------------------------------------------------- step 2 --
step "step 2: the guest-side zone, network and storage checks (as root)"
# 3 GB, not 2: ephemeral-size-bound fills untrusted's 2G tmpfs, which is RAM, until ENOSPC.
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
for name in kernel-support policies net-ready net-dns dhcpcd-separated dnsmasq-unprivileged zone0-nic zone0-no-route zone0-offline routed-egress routed-ping routed-ping6 routed-dns net-lease-names-resolver dns-follows-lease dns-after-reload routed-ipv6-noglobal zone-separation volume-hidden home-hidden fail-closed net-restart-ready reattach-after-restart uplink-returned uplink-retaken reattach-egress uplink-refused wifi-beyond routed-restart-path uplink-address-refused zone-flows-capped net-cpu-max-set \
            wifi-module wifi-ap wifi-add wifi-associated wifi-lease wifi-egress wifi-forget \
            uplink-renamed-plain \
            time-floor-ran time-clamp time-floor-forged time-claim-stepped time-claim-floor time-claim-consent pids-limit ephemeral-size-bound cpu-max-set lifecycle-repeat lifecycle-registry resolver-after-attach dns-cache-off dns-counters-hidden net-zone-sysfs-nics-only \
            terminal-terminfo man-page text-browser tls-trust no-shared-writable-mount net-zone-no-zone-data no-swap no-dbus \
            volume-init zone-source-pinned bridge-ports-closed encrypted-zone-start stop-closes-volume wrong-passphrase persist-reopen no-mapping-after ephemeral-gone concurrent-start-refused full-volume header-restore volume-destroy vault-offline vault-ping no-passphrase-leak \
            setuid-only-allowed no-file-capabilities sysctls-applied host-activity-hidden fetch-and-sntp-no-caps; do
    grep -q "ZT PASS ${name}" <<<"$T2" && green "guest: ${name}" || red "guest: ${name} (not passed)"
done

# ----------------------------------------------------------------- step 3 --
if [[ "$SUITES" -eq 1 ]]; then
step "step 3: the compartment suites on the target kernel (as root)"
# The guest's disk is not kept, so the console also gets each exit code, summary tail and FAIL row.
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
# Only the launcher gaps named below are accepted here; any other is a failure.
if grep -q 'LAUNCHER SUITE PASSED$' <<<"$T3"; then
    green "launcher suite passed with no gaps"
elif grep -q 'LAUNCHER SUITE PASSED WITH GAPS' <<<"$T3"; then
    other="$(sed -n '/not run (mandatory gaps/,/^$/p' <<<"$T3" | grep -E '^ *- ' | grep -vE 'NETR|LC15/LC16|H1c')"
    if [[ -z "$other" ]]; then
        green "launcher suite passed; its only gaps are the accounted-for ones (NETR: the real net zone is measured by zones-check; LC15/16: unprivileged-only; H1c: zone 0 has no interface here)"
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
# Only the tagged listing counts: step 2 opens and closes personal's mapping,
# so its name appears earlier in the transcript. The state partition's own
# mapping must be in the listing, or a listing that printed nothing would pass.
mappers="$(txt | grep '^MAPPER:')"
if grep -qx 'MAPPER:kryptik-state' <<<"$mappers" && ! grep -q '^MAPPER:kryptik-zone-' <<<"$mappers"; then
    green "no zone's mapping is left after the zone exited (the listing shows the state partition's alone)"
else
    red "after the reboot check /dev/mapper holds: $(tr '\n' ' ' <<<"${mappers:-no listing}")"
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
echo "Guest logs: /var/log/kryptik/zones-check.log and the suite logs on the disk ${DISK}; serial transcript ${LOG}"
[[ "$FAIL" -eq 0 ]] || exit 1
