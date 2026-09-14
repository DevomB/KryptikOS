#!/usr/bin/env bash
#
# Zones, the network and encrypted storage on the INSTALLED system (gates G6
# and G7): install from the medium, boot the disk alone with a NIC, and run
# the guest-side checks and the compartment suites as root over the serial
# login. The verdicts are the guest's own lines; this script only carries
# them and refuses to call an absent verdict a pass.
#
#   tools/image/zones-test.sh --usb IMG [--disk FILE] [--timeout N] [--skip-suites]
#
#   1  install (control disk, preseeded user), boot alone with QEMU user
#      networking (the net zone gets eth0 and NATs the routed zones to the
#      VM gateway, 10.0.2.2)
#   2  /usr/lib/kryptik/guest-tests/zones-check.sh as root: the kernel
#      support, the net zone's readiness, zone 0 offline, routed egress and
#      DNS through net, no global IPv6, zones separated on the bridge, the
#      net zone stopped/restarted (fail closed, reattach), pids/tmpfs limits,
#      lifecycle, and the LUKS2 lifecycle: init, wrong passphrase refused,
#      persist across restarts, mapping and mount gone after stop, ephemeral
#      data gone, concurrent start refused, full volume survived, header
#      backup/restore, the vault offline, no passphrase on any command line
#   3  the compartment suites shipped in the image, as root on the target
#      kernel: launcher.sh, adversarial.sh, boundary-checks.sh, cli.sh - the
#      [vm] rows those suites can only run here
#   4  reboot; the encrypted zone's data is still there
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
        -h|--help) sed -n '2,26p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -f "$USB" ]] || die "--usb IMG is required"
for t in python3 sfdisk truncate; do have "$t" || die "required tool not found: $t"; done
VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"
DISK="${DISK:-${VMDIR}/zones.img}"
[[ -e "$DISK" && ! -f "$DISK" ]] && die "refusing: ${DISK} is not a regular file"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
phase() { printf '\n==> %s\n' "$*"; }
TUSER=tester; TPASS=tester-pw; RPASS=root-pw
TUSER_HASH="$(openssl passwd -6 "$TPASS")"; ROOT_HASH="$(openssl passwd -6 "$RPASS")"
DRV="${SELF}/vm-drive.py"
VARSF="${VMDIR}/zones-vars.fd"; cp /usr/share/OVMF/OVMF_VARS_4M.fd "$VARSF"
LATEST="${KRYPTIK_WORK}/logs/ovmf-serial.latest.log"
ROOTSH() { printf 'su:%s:%s' "$RPASS" "$1"; }
start_vm() { local name="$1"; shift; local out; out="$("${SELF}/run-ovmf.sh" --no-media --disk "$DISK" --vars-file "$VARSF" --mode serve --allow-reboot --net user --name "$name" "$@")"
    SER="$(sed -n 's/^serial=//p' <<<"$out")"; PIDF="$(sed -n 's/^pid=//p' <<<"$out")"; LOG="$(sed -n 's/^log=//p' <<<"$out")"
    [[ -S "$SER" ]] || die "no serial socket: ${out}"; }
stop_vm() { sleep 1; [[ -f "$PIDF" ]] && kill "$(cat "$PIDF")" 2>/dev/null; sleep 1; }
drive() { python3 "$DRV" --serial "$SER" --timeout "$1" "${@:2}"; }
txt() { tr -d '\r' < "$LOG"; }

# ---------------------------------------------------------------- phase 1 --
phase "phase 1: install and boot alone with a NIC"
rm -f "$DISK"; truncate -s 12G "$DISK"
CTL="${VMDIR}/testctl-zones.img"
"${SELF}/mk-testctl.sh" --out "$CTL" install_target=/dev/vda smoke_poweroff=1 install_wait=5 \
    "preseed_user=${TUSER}" "preseed_password_hash=${TUSER_HASH}" "preseed_root_hash=${ROOT_HASH}" > /dev/null
"${SELF}/run-ovmf.sh" --usb "$USB" --disk "$DISK" --testctl "$CTL" --vars clean --mode smoke --timeout "$TIMEOUT" --name zones-install > /dev/null
tr -d '\r' < "$LATEST" | grep -q 'KRYPTIK_INSTALL: rc=0' && green "installed" || { red "install failed"; exit 1; }

# ---------------------------------------------------------------- phase 2 --
phase "phase 2: the guest-side zone, network and storage checks (as root)"
start_vm zones-p2
drive 900 "expect:KRYPTIK_SMOKE: END" "expect:kryptik-firstboot: created user '${TUSER}'" "login:${TUSER}:${TPASS}" \
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
# the verdicts that carry the gates, individually, so a pass is not one line
for name in kernel-support net-ready zone0-nic zone0-no-route zone0-offline routed-egress routed-dns routed-ipv6-noglobal zone-separation fail-closed net-restart-ready reattach-after-restart pids-limit ephemeral-size-bound \
            volume-init encrypted-zone-start stop-closes-volume wrong-passphrase persist-reopen no-mapping-after ephemeral-gone concurrent-start-refused full-volume header-restore vault-offline no-passphrase-leak; do
    grep -q "ZT PASS ${name}" <<<"$T2" && green "guest: ${name}" || red "guest: ${name} (not passed)"
done

# ---------------------------------------------------------------- phase 3 --
if [[ "$SUITES" -eq 1 ]]; then
phase "phase 3: the compartment suites on the target kernel (as root)"
drive 1800 \
    "$(ROOTSH 'cd /usr/lib/kryptik/compartments/tests && KRYPTIKD=/usr/bin/kryptikd KRYPTIK_SKIP_STALE_CHECK=1 NO_COLOR=1 bash ./launcher.sh > /var/log/kryptik/launcher-suite.log 2>&1; echo LAUNCHER-RC=$?; tail -12 /var/log/kryptik/launcher-suite.log')" "expect:LAUNCHER-RC=[0-9]+" \
    "$(ROOTSH 'cd /usr/lib/kryptik/compartments/tests && KRYPTIKD=/usr/bin/kryptikd NO_COLOR=1 bash ./adversarial.sh > /var/log/kryptik/adversarial-suite.log 2>&1; echo ADVERSARIAL-RC=$?; tail -6 /var/log/kryptik/adversarial-suite.log')" "expect:ADVERSARIAL-RC=[0-9]+" \
    "$(ROOTSH 'cd /usr/lib/kryptik/compartments/kryptikd/probes && NO_COLOR=1 bash ./boundary-checks.sh /usr/bin/kryptikd > /var/log/kryptik/boundary-suite.log 2>&1; echo BOUNDARY-RC=$?; tail -6 /var/log/kryptik/boundary-suite.log')" "expect:BOUNDARY-RC=[0-9]+" \
    "$(ROOTSH 'cd /usr/lib/kryptik/compartments/tests && KRYPTIKD=/usr/bin/kryptikd NO_COLOR=1 bash ./cli.sh > /var/log/kryptik/cli-suite.log 2>&1; echo CLI-RC=$?; tail -4 /var/log/kryptik/cli-suite.log')" "expect:CLI-RC=[0-9]+"
rc=$?
T3="$(txt)"
[[ "$rc" -eq 0 ]] && green "all four suites ran" || red "a suite did not run to its end"
for s in LAUNCHER ADVERSARIAL BOUNDARY CLI; do
    code="$(grep -o "${s}-RC=[0-9]*" <<<"$T3" | tail -1 | cut -d= -f2)"
    if [[ "$code" = 0 ]]; then green "${s,,} suite exit 0"; else red "${s,,} suite exit ${code:-none}"; fi
done
# The launcher suite's [vm] network group (NETR) moves the physical NIC into
# a fixture zone; on the installed system the real net zone already holds
# it, and zones-check.sh above proves routing through that one. So NETR
# stays a gap here by design, as do POL6 (Landlock policy files are refused,
# not applied) and LC15/LC16 (unprivileged-only). Any other gap is a failure.
if grep -q 'LAUNCHER SUITE PASSED$' <<<"$T3"; then
    green "launcher suite passed with no gaps"
elif grep -q 'LAUNCHER SUITE PASSED WITH GAPS' <<<"$T3"; then
    other="$(sed -n '/not run (mandatory gaps/,/^$/p' <<<"$T3" | grep -E '^ *- ' | grep -vE 'NETR|POL6|LC15/LC16')"
    if [[ -z "$other" ]]; then
        green "launcher suite passed; its only gaps are the accounted-for ones (NETR: the real net zone is measured by zones-check; POL6: by design; LC15/16: unprivileged-only)"
    else
        red "launcher suite passed with unaccounted gaps: $(tr '\n' ' ' <<<"$other")"
    fi
else
    red "launcher suite did not report PASSED"
fi
grep -E 'passed, [0-9]+ failed, [0-9]+ not run' <<<"$T3" | tail -1 | sed 's/^/        launcher: /'
fi

# ---------------------------------------------------------------- phase 4 --
phase "phase 4: reboot; the encrypted zone's data is still there"
drive 300 "$(ROOTSH 'reboot')" "expect:Linux version" "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'kryptikd run personal --zones /usr/lib/kryptik/zones --rootfs /var/lib/kryptik/zones --passphrase-file /root/zt/personal.pass -- cat /home/personal/keep; echo REOPEN-RC=$?')" "expect:secret-data-1" "expect:REOPEN-RC=0" \
    "$(ROOTSH 'ls /dev/mapper; echo MAPPER-DONE')" "expect:MAPPER-DONE" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "after a reboot the LUKS2 volume opens with its passphrase and the data is there" || red "phase 4 drive failed"
txt | grep -q 'kryptik-personal' && red "a mapping was left open after the reboot check" || green "no mapping left after the zone exited"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
echo "Guest logs: /var/log/kryptik/zones-check.log and the suite logs on the disk ${DISK}; serial transcript ${LOG}"
[[ "$FAIL" -eq 0 ]] || exit 1
