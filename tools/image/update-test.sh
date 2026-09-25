#!/usr/bin/env bash
# OS updates on an installed system: install release A, update to B, reboot
# into it, roll back, and check refusals, interruptions and a broken trial.
#
#   tools/image/update-test.sh --usb-a IMG_A --payload-a DIR_A --payload-b DIR_B
#                              [--disk FILE] [--vars clean|enrolled] [--timeout N]
#
# A and B are two stage 06 releases of this tree (make media KRYPTIK_VERSION=...
# twice). Steps 2-7 give the guest the payload on an ext4 disk image; step 8
# has the net zone fetch it (docs/design/update-channel.md).
#
#   step 1  install A, boot, create a zone volume and a home file
#   step 2  apply B, reboot: slot b committed, data intact
#   step 3  refusals on B: wrong key, modified image, truncated kernel, extra
#           file, older release, full disk, concurrent run; no trial armed
#   step 4  apply A with --recovery, reboot: slot a
#   step 5  rollback: slot b again
#   step 6  the VM killed mid-write, then after arming: both recover
#   step 7  a corrupt trial falls back to slot a, is recorded, needs --retry
#   step 8  B fetched by the net zone from a loopback release host, applied
set -uo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"
trap - ERR; set +e

USB_A=""; PAY_A=""; PAY_B=""; DISK=""; VARS="clean"; TIMEOUT=600
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --usb-a) USB_A="${2:?}"; shift 2 ;;
        --payload-a) PAY_A="${2:?}"; shift 2 ;;
        --payload-b) PAY_B="${2:?}"; shift 2 ;;
        --disk) DISK="${2:?}"; shift 2 ;;
        --vars) VARS="${2:?}"; shift 2 ;;
        --timeout) TIMEOUT="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -f "$USB_A" ]] || die "--usb-a IMG_A is required"
[[ -f "$PAY_A/manifest" && -f "$PAY_B/manifest" ]] || die "--payload-a and --payload-b must be stage 06 payload directories"
for t in python3 mkfs.ext4 truncate ssh-keygen sfdisk; do have "$t" || die "required tool not found: $t"; done
VA="$(awk -F': ' '$1=="version"{print $2}' "$PAY_A/manifest")"; VB="$(awk -F': ' '$1=="version"{print $2}' "$PAY_B/manifest")"
[[ "$VA" != "$VB" ]] || die "A and B are the same version (${VA})"
# Stage 06 publishes B into a channel beside its payload with
# tools/release-channel.sh (this job has no private key): the signed statement
# that B is current, and B under ${VB}/. not-a-pointer, its control, is the
# same text signed by the release key in the manifest's namespace.
CHAN_B="$(dirname "$PAY_B")/channel-${VB}"
for f in latest latest.sig not-a-pointer not-a-pointer.sig "${VB}/manifest"; do
    [[ -s "$CHAN_B/$f" ]] || die "no ${CHAN_B}/${f}: stage 06's payload step publishes it beside the payload"
done
VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"
DISK="${DISK:-${VMDIR}/updated.img}"
[[ -e "$DISK" && ! -f "$DISK" ]] && die "refusing: ${DISK} is not a regular file"

# shellcheck source=tools/image/suite-lib.sh
source "${SELF}/suite-lib.sh"
VARSF="${VMDIR}/updated-vars.fd"
[[ "$VARS" == "enrolled" ]] && cp "${KRYPTIK_WORK}/keys/sb/vars/enrolled.fd" "$VARSF" || cp /usr/share/OVMF/OVMF_VARS_4M.fd "$VARSF"

# A payload as a plain ext4 disk image, which the guest mounts read-only under
# /run (its root is read-only, so no mount point can be made under /mnt).
payload_disk() {   # payload_disk OUT DIR
    rm -f "$1"; local bytes; bytes="$(du -sb "$2" | cut -f1)"
    truncate -s $(( bytes + bytes / 10 + 64 * 1024 * 1024 )) "$1"
    mkfs.ext4 -q -F -d "$2" "$1" || die "payload image"
}
PA="${VMDIR}/payload-a.img"; PB="${VMDIR}/payload-b.img"
payload_disk "$PA" "$PAY_A"; payload_disk "$PB" "$PAY_B"

# Variants of A for the refusals, applied on B with --recovery, which admits
# the older version so the check under test is reached (a variant of the
# running version would stop at "nothing to apply").
BAD="${VMDIR}/bad"; rm -rf "$BAD"; mkdir -p "$BAD"
# Payload A hard-linked, and a real copy of each FILE the variant changes in
# place: a root image is gigabytes, and mkfs -d stores a link once.
mk_variant() {   # mk_variant NAME [FILE...]
    rm -rf "${BAD:?}/$1"
    cp -al "$PAY_A" "$BAD/$1" 2>/dev/null || cp -a --sparse=always "$PAY_A" "$BAD/$1"
    local f; for f in "${@:2}"; do
        rm -f "$BAD/$1/$f"; cp --sparse=always "$PAY_A/$f" "$BAD/$1/$f"
    done
}
mk_variant wrongkey; ssh-keygen -q -t ed25519 -N "" -f "$BAD/otherkey" >/dev/null; rm -f "$BAD/wrongkey/manifest.sig"
ssh-keygen -Y sign -f "$BAD/otherkey" -n kryptik-release "$BAD/wrongkey/manifest" >/dev/null 2>&1
mk_variant modified kryptik-root.img; printf '\xff' | dd of="$BAD/modified/kryptik-root.img" bs=1 seek=$((4096*200+3)) conv=notrunc status=none
mk_variant truncated kryptik-a.efi; truncate -s -1 "$BAD/truncated/kryptik-a.efi"
mk_variant extra; echo "ride along" > "$BAD/extra/extra.bin"
# An empty lost+found (an ext4 payload disk's own) is allowed; a full one is not.
mk_variant hidden; mkdir -p "$BAD/hidden/lost+found"; echo "ride along" > "$BAD/hidden/lost+found/ride"
# The statement and its control, for step 3 to check offline against the real anchor.
mkdir -p "$BAD/statement"; cp "$CHAN_B/latest" "$CHAN_B/latest.sig" "$CHAN_B/not-a-pointer" "$CHAN_B/not-a-pointer.sig" "$BAD/statement/"
BADIMG="${VMDIR}/payload-bad.img"; payload_disk "$BADIMG" "$BAD"

DRIVE_TIMEOUT=420

# Each step starts from the state the last one left, so a failed step ends the run.
stop_unless_ok() {   # stop_unless_ok RC WHAT
    [[ "$1" -eq 0 ]] && return 0
    printf '\n  stopping: %s failed, and every later step starts from the state it leaves.\n' "$2"
    printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
    exit 1
}

# ----------------------------------------------------------------- step 1 --
step "step 1: install ${VA}, boot it, create zone data"
# Sized from the medium, with room for two payloads at once: b from step 2 is
# still on kryptik-state when a arrives in step 4.
DISK_SIZE="$("${SELF}/test-disk-size.sh" --medium "$USB_A" --payloads 2)" || die "could not size the test disk from the medium"
rm -f "$DISK"; truncate -s "$DISK_SIZE" "$DISK"
CTL="${VMDIR}/testctl-update.img"
"${SELF}/mk-testctl.sh" --out "$CTL" install_target=/dev/vda smoke_poweroff=1 install_wait=5 \
    "${PRESEED[@]}" > /dev/null
"${SELF}/run-ovmf.sh" --usb "$USB_A" --disk "$DISK" --testctl "$CTL" --vars "$VARS" --mode smoke --timeout "$TIMEOUT" --name update-install > /dev/null
tr -d '\r' < "${KRYPTIK_WORK}/logs/ovmf-serial.latest.log" | grep -q 'KRYPTIK_INSTALL: rc=0' && green "A installed" || { red "A did not install"; exit 1; }

start_vm update-p1 --disk "$PA"
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "grab:v1:grep ^VERSION_ID= /etc/os-release; cat /run/kryptik/boot-identity" \
    "run:echo before-update > /home/${TUSER}/marker && sync" \
    "$(ROOTSH 'printf zone-pw > /root/zp && chmod 600 /root/zp && kryptikd volume init work --size 64M --passphrase-file /root/zp && sha256sum /var/lib/kryptik/volumes/work.luks > /root/work.sha && echo VOL-OK')" \
    "expect:VOL-OK" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "A boots, zone volume created (${VA})" || red "step 1 drive failed"
stop_unless_ok "$rc" "step 1"
txt | grep -q "version_id=${VA}" && green "guest reports version ${VA}" || red "guest did not report version ${VA}"

# ----------------------------------------------------------------- step 2 --
step "step 2: apply ${VB}, reboot into slot b"
start_vm update-p2 --disk "$PB"
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'mkdir -p /run/upd/p /var/lib/kryptik/updates/b && mount -o ro /dev/vdb /run/upd/p && cp -a /run/upd/p/. /var/lib/kryptik/updates/b/ && umount /run/upd/p && kryptik-update apply /var/lib/kryptik/updates/b && echo APPLY-OK')" \
    "expect:armed: the next boot tries slot b" "expect:APPLY-OK" \
    "$(ROOTSH 'kryptik-update status')" "expect:trial pending:    b" \
    "$(ROOTSH 'reboot')" "expect:Linux version" "expect:KRYPTIK_SMOKE: END" \
    "login:${TUSER}:${TPASS}" \
    "grab:v2:grep ^VERSION_ID= /etc/os-release; cat /run/kryptik/boot-identity; cat /var/lib/kryptik/boot/last-result" \
    "run:test \"\$(cat /home/${TUSER}/marker)\" = before-update" \
    "$(ROOTSH 'sha256sum -c /root/work.sha && kryptik-update status && echo B-OK')" "expect:B-OK" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "B applied, rebooted into slot b, home file and zone volume intact" || red "step 2 drive failed"
stop_unless_ok "$rc" "step 2"
txt | grep -q "KRYPTIK_SMOKE: boot_identity=slot=b" && green "booted slot b" || red "did not boot slot b"
txt | grep -q "version_id=${VB}" && green "guest reports version ${VB}" || red "guest did not report ${VB}"
txt | grep -q "boot-success: committed: BOOTX64.EFI is now slot b" && green "boot-success committed slot b" || red "no commit of slot b"
txt | grep -q "committed slot:   b" && green "status shows committed slot b" || red "committed slot is not b"

# ----------------------------------------------------------------- step 3 --
step "step 3: refusals on the running ${VB}"
start_vm update-p3 --disk "$BADIMG" --disk "$PA"
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'mkdir -p /run/upd/p /run/upd/a && mount -o ro /dev/vdb /run/upd/p && mount -o ro /dev/vdc /run/upd/a && echo MNT-OK')" "expect:MNT-OK" \
    "$(ROOTSH 'kryptik-update apply /run/upd/p/wrongkey; echo RC=$?')" "expect:not enrolled" \
    "$(ROOTSH 'kryptik-update apply /run/upd/p/modified --recovery; echo RC=$?')" "expect:sha256 does not match" \
    "$(ROOTSH 'kryptik-update apply /run/upd/p/truncated --recovery; echo RC=$?')" "expect:truncated or altered" \
    "$(ROOTSH 'kryptik-update apply /run/upd/p/extra --recovery; echo RC=$?')" "expect:unlisted file" \
    "$(ROOTSH 'kryptik-update apply /run/upd/p/hidden --recovery; echo RC=$?')" "expect:lost\\+found is not empty" \
    "$(ROOTSH 'kryptik-update apply /run/upd/a; echo RC=$?')" "expect:older than the running" \
    "$(ROOTSH 'kryptik-update check-pointer /run/upd/p/statement/latest /run/upd/p/statement/latest.sig && echo STATEMENT-OK')" "expect:signed by kryptik-latest" "expect:STATEMENT-OK" \
    "$(ROOTSH 'kryptik-update check-pointer /run/upd/p/statement/not-a-pointer /run/upd/p/statement/not-a-pointer.sig; echo RC=$?')" "expect:does NOT verify" "expect:RC=1" \
    "$(ROOTSH 'flock /run/kryptik/update.lock sleep 20 & sleep 1; kryptik-update apply /run/upd/a --recovery; echo RC=$?')" "expect:another update is in progress" \
    "$(ROOTSH 'fallocate -l 100G /var/filler 2>/dev/null || dd if=/dev/zero of=/var/filler bs=1M 2>/dev/null; cp -a /run/upd/a /var/lib/kryptik/updates/a-full 2>&1 | tail -1; kryptik-update apply /var/lib/kryptik/updates/a-full --recovery; echo RC=$?; rm -rf /var/filler /var/lib/kryptik/updates/a-full')" "expect:RC=1" \
    "$(ROOTSH 'kryptik-update status')" "expect:trial pending:    none" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "wrong key, modified image, truncated kernel, extra file, downgrade, concurrent run and full disk were all refused; no trial armed; the statement of what is current verifies against the image's anchor and one signed by the release key does not" || red "step 3 drive failed"

# ----------------------------------------------------------------- step 4 --
step "step 4: authenticated recovery to ${VA} with --recovery"
start_vm update-p4 --disk "$PA"
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'mkdir -p /run/upd/a /var/lib/kryptik/updates/a && mount -o ro /dev/vdb /run/upd/a && cp -a /run/upd/a/. /var/lib/kryptik/updates/a/ && umount /run/upd/a && kryptik-update apply /var/lib/kryptik/updates/a --recovery && echo REC-OK')" \
    "expect:accepted because --recovery" "expect:REC-OK" \
    "$(ROOTSH 'reboot')" "expect:Linux version" "expect:KRYPTIK_SMOKE: END" \
    "login:${TUSER}:${TPASS}" \
    "run:test \"\$(cat /home/${TUSER}/marker)\" = before-update" \
    "$(ROOTSH 'sha256sum -c /root/work.sha && cat /var/lib/kryptik/boot/last-result && echo A-OK')" "expect:commit a" "expect:A-OK" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "recovery to ${VA}: slot a booted and committed, data intact" || red "step 4 drive failed"
stop_unless_ok "$rc" "step 4"
txt | grep -q "version_id=${VA}" && green "guest reports ${VA} again" || red "guest did not report ${VA}"

# ----------------------------------------------------------------- step 5 --
step "step 5: rollback arms the other slot (b) and it boots"
start_vm update-p5
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'kryptik-update rollback && echo RB-OK')" "expect:armed: the next boot tries slot b" "expect:RB-OK" \
    "$(ROOTSH 'reboot')" "expect:Linux version" "expect:KRYPTIK_SMOKE: END" \
    "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'cat /run/kryptik/boot-identity; cat /var/lib/kryptik/boot/last-result; echo RB2-OK')" "expect:slot=b" "expect:commit b" "expect:RB2-OK" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "rollback: slot b armed, booted and committed" || red "step 5 drive failed"
stop_unless_ok "$rc" "step 5"
txt | grep -q "version_id=${VB}" && green "guest reports ${VB} after rollback" || red "guest did not report ${VB}"

# ----------------------------------------------------------------- step 6 --
step "step 6: interruption during the slot write, then after arming"
# The copy is synced first: the kill drops the guest's page cache, and what is
# under test is an interrupted slot write, not a half-copied payload.
start_vm update-p6 --disk "$PA"
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'mkdir -p /run/upd/a /var/lib/kryptik/updates/a && mount -o ro /dev/vdb /run/upd/a && cp -a /run/upd/a/. /var/lib/kryptik/updates/a/ && umount /run/upd/a && sync && echo COPY-OK')" "expect:COPY-OK" \
    "send:su - root -c 'kryptik-update apply /var/lib/kryptik/updates/a --recovery'" "expect:Password: ?" "send:${RPASS}" \
    "expect:writing kryptik-a"
python3 - "$QMP" <<'PY'
import json, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sys.argv[1]); f = s.makefile("rwb", buffering=0)
f.readline(); f.write(b'{"execute":"qmp_capabilities"}\n'); f.readline(); f.write(b'{"execute":"quit"}\n'); f.readline()
PY
sleep 2; stop_vm
green "VM killed while slot a was being written (QMP quit, no clean shutdown)"
start_vm update-p6b --disk "$PA"
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'cat /run/kryptik/boot-identity; kryptik-update status; echo P6-OK')" "expect:slot=b" "expect:trial pending:    none" "expect:P6-OK" \
    "$(ROOTSH 'kryptik-update apply /var/lib/kryptik/updates/a --recovery && echo ARMED-OK')" "expect:ARMED-OK"
rc=$?
[[ "$rc" -eq 0 ]] && green "after the interrupted write: still slot b, no trial; the apply succeeds again" || red "step 6a drive failed"
stop_unless_ok "$rc" "step 6a"
# armed, now kill again before the reboot: the firmware consumes BootNext at the next boot
python3 - "$QMP" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sys.argv[1]); f = s.makefile("rwb", buffering=0)
f.readline(); f.write(b'{"execute":"qmp_capabilities"}\n'); f.readline(); f.write(b'{"execute":"quit"}\n'); f.readline()
PY
sleep 2; stop_vm
start_vm update-p6c
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'cat /run/kryptik/boot-identity; cat /var/lib/kryptik/boot/last-result; echo P6C-OK')" "expect:slot=a" "expect:commit a" "expect:P6C-OK" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "after a kill between arming and reboot: the trial boot happened and slot a was committed" || red "step 6c drive failed"
stop_unless_ok "$rc" "step 6c"

# ----------------------------------------------------------------- step 7 --
step "step 7: a deliberately broken trial falls back, is recorded, and is refused until retried"
# From slot a: arm B, power off, corrupt slot b from the host, boot. The trial
# panics in dm-verity, panic=10 reboots with BootNext spent, slot a comes up
# and boot-success records the failure; apply then needs --retry. The payload
# copies of steps 2 and 6 go first: a third would not fit beside them.
start_vm update-p7 --disk "$PB"
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'cat /run/kryptik/boot-identity | head -1; rm -rf /var/lib/kryptik/updates/a /var/lib/kryptik/updates/b; mkdir -p /run/upd/p /var/lib/kryptik/updates/b2 && mount -o ro /dev/vdb /run/upd/p && cp -a /run/upd/p/. /var/lib/kryptik/updates/b2/ && umount /run/upd/p && kryptik-update apply /var/lib/kryptik/updates/b2 && echo ARM7-OK')" \
    "expect:slot=a" "expect:ARM7-OK" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "B armed from slot a" || red "step 7 arming failed"
stop_unless_ok "$rc" "step 7 arming"
B_OFF=$(( $(part_start "$DISK" 3) * 512 ))
# The superblock's volume name, the first block a root mount reads (a block
# nothing reads at boot would let the trial succeed).
printf '\xa5' | dd of="$DISK" bs=1 seek=$(( B_OFF + 1024 + 0x78 )) conv=notrunc status=none
green "slot b's root image corrupted from the host (one byte in the superblock)"
start_vm update-p7b
drive "expect:BdsDxe: starting Boot" \
    "expect:device-mapper: verity:.*(corrupt|mismatch|error)|dm-verity device corrupted" \
    "expect:Kernel panic" \
    "expect:Linux version" "expect:KRYPTIK_SMOKE: END" \
    "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'cat /run/kryptik/boot-identity | head -1; cat /var/lib/kryptik/boot/last-result; kryptik-update status; echo P7B-OK')" \
    "expect:slot=a" "expect:trial-failed b" "expect:P7B-OK" \
    "$(ROOTSH 'kryptik-update apply /var/lib/kryptik/updates/b2; echo RC=$?')" "expect:failed to boot" "expect:RC=1" \
    "$(ROOTSH 'kryptik-update apply /var/lib/kryptik/updates/b2 --retry && echo RETRY-OK')" "expect:slot b verifies after write" "expect:RETRY-OK" \
    "$(ROOTSH 'reboot')" "expect:Linux version" "expect:KRYPTIK_SMOKE: END" \
    "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'cat /run/kryptik/boot-identity | head -1; cat /var/lib/kryptik/boot/last-result; echo P7C-OK')" "expect:slot=b" "expect:commit b" "expect:P7C-OK" \
    "run:test \"\$(cat /home/${TUSER}/marker)\" = before-update" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "broken trial: verity panic, fallback to a, trial-failed recorded, refused without --retry, rewritten and committed with it; data intact" || red "step 7 drive failed"
txt | grep -q 'boot-success: trial slot b did NOT boot' && green "boot-success named the failed trial" || red "boot-success did not record the failed trial"
# loglevel=4 keeps the kernel banner off the console (every "Linux version" is
# boot-smoke's, from userspace), so boots are counted by the firmware's line.
starts="$(txt | grep -c 'BdsDxe: starting Boot')"; ups="$(txt | grep -c 'KRYPTIK_SMOKE: END')"; panics="$(txt | grep -c 'Kernel panic')"
if [[ "$starts" -ge 3 && "$ups" -ge 2 && "$panics" -ge 1 ]]; then green "three boots in one session: the corrupt trial (panicked), the fallback and the retried trial (both reached userspace)"; else red "expected three boots: firmware starts=${starts}, userspace ends=${ups}, panics=${panics}"; fi

# ----------------------------------------------------------------- step 8 --
step "step 8: ${VB} once more, fetched by the net zone and staged by zone 0"
# Step 7 leaves B committed with nothing newer to fetch, so roll back to A
# first. Step 7's copy goes too: the disk holds two payloads, not three.
start_vm update-p8
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'rm -rf /var/lib/kryptik/updates/b2; kryptik-update rollback && echo RB8-OK')" "expect:armed: the next boot tries slot a" "expect:RB8-OK" \
    "$(ROOTSH 'reboot')" "expect:Linux version" "expect:KRYPTIK_SMOKE: END" \
    "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'cat /run/kryptik/boot-identity | head -1; cat /var/lib/kryptik/boot/last-result; echo P8A-OK')" "expect:slot=a" "expect:commit a" "expect:P8A-OK" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "back on slot a (${VA}) by rollback, with room for one staged release" || red "step 8: the rollback to slot a failed"
stop_unless_ok "$rc" "step 8 rollback"

# The release host serves the channel stage 06 published, as it stands, on
# loopback (10.0.2.2 to the guest); plain http is for development images only.
# The trap stops the host however the suite ends.
CHAN_LOG="${VMDIR}/channel-requests.log"; : > "$CHAN_LOG"; rm -f "${VMDIR}/channel.port"
python3 "${SELF}/release-host.py" "$CHAN_B" "${VMDIR}/channel.port" "$CHAN_LOG" > "${VMDIR}/channel-host.err" 2>&1 &
CHAN_PID=$!
trap '[[ -n "${CHAN_PID:-}" ]] && kill "$CHAN_PID" 2>/dev/null' EXIT
for _ in $(seq 50); do [[ -s "${VMDIR}/channel.port" ]] && break; sleep 0.1; done
CHAN_PORT="$(cat "${VMDIR}/channel.port" 2>/dev/null)"
[[ -n "$CHAN_PORT" ]] || die "the release host did not start: $(cat "${VMDIR}/channel-host.err")"

# Restart the net zone so it reads the new update.conf, as zones-check.sh
# does, and wait for a new "netzone: READY" line. A ROOTSH command may hold no
# single quote (su -c wraps it in them) and must not exit the shell (the
# driver's marker must still print), hence the subshell.
RESTART_NET='before=$(grep -hc "netzone: READY" /run/uncaught-logs/current 2>/dev/null); before=${before:-0}; s6-svc -d /run/service/net-zone; sleep 3; s6-svc -u /run/service/net-zone; (i=0; until [ "$(grep -hc "netzone: READY" /run/uncaught-logs/current 2>/dev/null || true)" -gt "$before" ]; do i=$((i+1)); [ $i -lt 90 ] || exit 1; sleep 1; done) && echo NET-RESTARTED || echo NET-NOT-READY'
# Waits on progress, not a clock: done at "complete", failed after 100 s with
# no change (the net zone polls once a minute), and after six minutes of
# arrival it passes, for the next wait to take over.
wait_arrival() { printf '%s' '(prev=; same=0; i=0; while [ $i -lt 72 ]; do s="$(kryptik update status | sed -n "s/^staged *//p")"; case "$s" in *"bytes, complete"*) echo ARRIVED-WHOLE; exit 0 ;; esac; if [ "$s" = "$prev" ]; then same=$((same+1)); else same=0; prev="$s"; fi; [ $same -lt 20 ] || { echo "STALLED at: $s"; exit 1; }; i=$((i+1)); sleep 5; done; echo "still arriving: $s")'; }
# Waits until status shows $1, then prints $2 for the driver to expect (echo is
# off, so only the output shows it). Giving up fails the run: step.
wait_status() { printf '(i=0; until kryptik update status | grep -q "%s"; do i=$((i+1)); [ $i -lt 72 ] || exit 1; sleep 5; done) && echo %s || { kryptik update status; false; }' "$1" "$2"; }
# In order: the statement arrives, nothing is fetched until the user asks, the
# release arrives whole, then apply, trial boot and commit.
start_vm update-p8b --net user
# The step assumes slot a; check, as the firmware's own boot order can still
# name the last slot tried.
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'echo P8B-BOOTED-$(sed -n "s/^slot=//p" /run/kryptik/boot-identity | head -1)')" "expect:P8B-BOOTED-a" \
    "$(ROOTSH "mkdir -p /etc/kryptik && printf \"channel = http://10.0.2.2:${CHAN_PORT}/\\n\" > /etc/kryptik/update.conf && echo CONF-OK")" "expect:CONF-OK" \
    "$(ROOTSH "$RESTART_NET")" "expect:NET-RESTARTED" \
    "run:kryptik update status | grep -q 'nothing asked for'" \
    "run:$(wait_status "newest     ${VB} " STATED-OK)" "expect:STATED-OK" \
    "$(ROOTSH 'sleep 70; echo STAGED-UNASKED=$(ls /var/lib/kryptik/update/incoming 2>/dev/null | wc -l)')" "expect:STAGED-UNASKED=0" \
    "run:kryptik update fetch" "expect:${VB} will be fetched" \
    "run:$(wait_status "${VB}: .* bytes, " ARRIVING-OK)" "expect:ARRIVING-OK" \
    "run:$(wait_arrival)" "run:$(wait_arrival)" "run:$(wait_arrival)" "run:$(wait_arrival)" \
    "run:kryptik update status | grep -q 'bytes, complete'" \
    "$(ROOTSH "ls /var/lib/kryptik/update/incoming/${VB} | sort | tr \"\\n\" \" \"; echo LISTED")" "expect:kryptik-a.efi kryptik-b.efi kryptik-root.img manifest manifest.sig root.json LISTED" \
    "run:kryptik update apply" "expect:armed: the next boot tries slot b" \
    "$(ROOTSH 'reboot')" "expect:Linux version" "expect:KRYPTIK_SMOKE: END" \
    "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'cat /run/kryptik/boot-identity | head -1; cat /var/lib/kryptik/boot/last-result; echo P8C-OK')" "expect:slot=b" "expect:commit b" "expect:P8C-OK" \
    "run:test \"\$(cat /home/${TUSER}/marker)\" = before-update" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
kill "$CHAN_PID" 2>/dev/null; CHAN_PID=""
[[ "$rc" -eq 0 ]] && green "the net zone brought the statement, nothing was fetched until it was asked for, ${VB} arrived whole, and it was applied, trial-booted and committed; data intact" || red "step 8 drive failed"
# The step's first boot must report A and its last B; B anywhere is not enough.
first_boot="$(txt | sed -n 's/^KRYPTIK_SMOKE: os_id=.* version_id=//p' | head -1)"
last_boot="$(txt | sed -n 's/^KRYPTIK_SMOKE: os_id=.* version_id=//p' | tail -1)"
[[ "$first_boot" == "$VA" && "$last_boot" == "$VB" ]] && green "the guest booted ${VA} and, after the fetched update, reports ${VB}" \
    || red "the guest's boots in this step: first ${first_boot:-none}, last ${last_boot:-none}; wanted ${VA} then ${VB}"
# What the release host was asked for: the statement, then the manifest and
# its signature before anything large.
first="$(awk '{sub("^/", "", $1); if (!seen[$1]++) print $1}' "$CHAN_LOG" | head -5 | tr '\n' ' ')"
if [[ "$first" == "latest latest.sig ${VB}/manifest ${VB}/manifest.sig "* ]]; then green "the release host was asked for the statement, then the manifest and its signature, before any image"; else red "the release host was asked in another order: ${first}"; fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
echo "Limits: the interruptions are QEMU process kills with cache=writeback and explicit fsyncs;"
echo "they exercise the recovery logic, not a storage controller's power-loss behaviour."
[[ "$FAIL" -eq 0 ]] || exit 1
