#!/usr/bin/env bash
# Boot Kryptik media or an installed disk under OVMF, as real firmware would:
# no -kernel, -initrd, -append or host filesystem sharing.
#
#   tools/image/run-ovmf.sh (--usb IMG [--usb-writable] | --iso ISO | --no-media)
#        [--disk FILE]... [--testctl FILE] [--vars clean|enrolled|ms|FILE]
#        [--vars-file FILE] [--mode console|smoke|serve] [--timeout N]
#        [--log FILE] [--net none|user] [--mem MB] [--cpus N] [--gpu]
#        [--second-head] [--touch] [--s3] [--sound WAV] [--usb-port] [--allow-reboot]
#        [--until REGEX] [--name TAG]
#
#   --usb IMG      the medium as a USB mass-storage device (removable),
#                  write-protected unless --usb-writable says the guest may
#                  write to it: for a copy a test made, never the medium
#   --iso ISO      the medium as a SATA CD-ROM (/dev/sr0 in the guest)
#   --no-media     boot only the --disk(s): an installed system
#   --disk FILE    a virtio disk (repeatable; the first is the install target
#                  or the installed system's disk). Files only, never devices.
#   --disk-readonly, --blkdebug CONF
#                  failure injection for the first --disk: read-only, or I/O
#                  errors through QEMU's blkdebug driver
#   --disk-4k      the first --disk with 4096-byte logical sectors (4Kn), as an
#                  NVMe drive formatted so presents itself
#   --testctl FILE a disk labelled kryptik-testctl (tools/image/mk-testctl.sh)
#   --vars X       variable store template, copied fresh for this run:
#                  clean    OVMF_VARS_4M.fd, no keys, Secure Boot off
#                  enrolled the developer key as PK/KEK/db, Secure Boot on
#                  ms       Microsoft keys only (our kernels must be refused)
#   --vars-file F  use F in place and keep it: firmware state persists across
#                  runs (the A/B trial needs BootNext to survive a reboot)
#   --mode smoke   run to poweroff (or --timeout), serial to --log, exit code
#                  0 = guest powered off, 124 = timeout
#   --until REGEX  smoke mode: stop the guest 10 s after REGEX appears on its
#                  console, for a boot that never powers itself off (a refused
#                  kernel); exit code 2 if it was still running
#   --mode serve   start detached with a serial socket and a QMP socket, print
#                  their paths; tools/image/vm-drive.py talks to them
#   --second-head  with --gpu in serve mode: a second output on the GPU, off
#                  until a VNC client on the printed socket asks for a size
#                  (vm-drive.py's head: step), which plugs a monitor in
#   --touch        with --gpu: a touchscreen over the first output, QEMU's
#                  virtio-multitouch (8.1 on), which vm-drive.py's touch: step taps
#   --s3           offer suspend to RAM, which QEMU otherwise hides: the guest
#                  sleeps until vm-drive.py's wakeup step
#   --sound WAV    two HD Audio cards: the first only plays, into the file WAV
#                  at 48 kHz, and the second plays to nothing and records
#                  silence (QEMU's WAV writer has no input); and snd2, playing
#                  to nothing, for a USB card vm-drive.py's plug-sound: adds
#   --usb-port     an xHCI controller with nothing on it, for sticks that
#                  vm-drive.py's plug: step plugs in while the guest runs
#   --mode console interactive serial console (Ctrl-A X quits)
# shellcheck disable=SC2054  # commas inside QEMU options are option syntax, not array separators
set -Eeuo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"

USB=""; ISO=""; NOMEDIA=0; DISKS=(); TESTCTL=""; VARS="clean"; VARS_FILE=""
MODE="smoke"; TIMEOUT=300; LOG=""; NET="none"; MEM=2048; CPUS=2; GPU=0; HEAD2=0; TOUCH=0; S3=0; SOUND=""; ALLOW_REBOOT=0; NAME="vm"
DISK_RO=0; DISK_4K=0; BLKDEBUG=""; UNTIL=""; USB_PORT=0; USB_RO=on
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --usb)       USB="${2:?}"; shift 2 ;;
        --usb-writable) USB_RO=off; shift ;;
        --iso)       ISO="${2:?}"; shift 2 ;;
        --no-media)  NOMEDIA=1; shift ;;
        --disk)      DISKS+=("${2:?}"); shift 2 ;;
        --disk-readonly) DISK_RO=1; shift ;;
        --disk-4k)   DISK_4K=1; shift ;;
        --blkdebug)  BLKDEBUG="${2:?}"; shift 2 ;;
        --testctl)   TESTCTL="${2:?}"; shift 2 ;;
        --vars)      VARS="${2:?}"; shift 2 ;;
        --vars-file) VARS_FILE="${2:?}"; shift 2 ;;
        --mode)      MODE="${2:?}"; shift 2 ;;
        --timeout)   TIMEOUT="${2:?}"; shift 2 ;;
        --log)       LOG="${2:?}"; shift 2 ;;
        --net)       NET="${2:?}"; shift 2 ;;
        --mem)       MEM="${2:?}"; shift 2 ;;
        --cpus)      CPUS="${2:?}"; shift 2 ;;
        --gpu)       GPU=1; shift ;;
        --second-head) HEAD2=1; shift ;;
        --touch)     TOUCH=1; shift ;;
        --s3)        S3=1; shift ;;
        --sound)     SOUND="${2:?}"; shift 2 ;;
        --usb-port)  USB_PORT=1; shift ;;
        --allow-reboot) ALLOW_REBOOT=1; shift ;;
        --until)     UNTIL="${2:?}"; shift 2 ;;
        --name)      NAME="${2:?}"; shift 2 ;;
        -h|--help)   sed -n '2,51p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n "$USB" || -n "$ISO" || "$NOMEDIA" -eq 1 ]] || die "one of --usb, --iso or --no-media is required"
[[ -n "$USB" && -n "$ISO" ]] && die "--usb and --iso are exclusive"
[[ "$NOMEDIA" -eq 1 && "${#DISKS[@]}" -eq 0 ]] && die "--no-media needs at least one --disk"
[[ -n "$UNTIL" && "$MODE" != smoke ]] && die "--until is for --mode smoke"
[[ "$HEAD2" -eq 1 && ( "$GPU" -ne 1 || "$MODE" != serve ) ]] && die "--second-head is for --gpu in --mode serve"
[[ "$TOUCH" -eq 1 && "$GPU" -ne 1 ]] && die "--touch is for --gpu: the touchscreen covers its first output"
[[ "$HEAD2" -eq 1 && "$S3" -eq 1 ]] && die "--second-head needs virtio-gpu, which --s3 gives up for std VGA's framebuffer"

# Files only. This hands paths to a process that writes to them.
regular_file() {
    [[ -e "$1" ]] || die "no such file: $1"
    [[ -f "$1" ]] || die "refusing to use $1: it is a $(stat -c %F "$1"), not a regular file. Virtual disks are files here."
    case "$(readlink -f "$1")" in /dev/*|/sys/*|/proc/*) die "refusing to use $1" ;; esac
}
[[ -n "$USB" ]] && regular_file "$USB"
[[ -n "$ISO" ]] && regular_file "$ISO"
for d in "${DISKS[@]}"; do regular_file "$d"; done
[[ -n "$TESTCTL" ]] && regular_file "$TESTCTL"

QEMU="${KRYPTIK_QEMU:-$(command -v qemu-system-x86_64 || true)}"
[[ -n "$QEMU" ]] || die "no qemu-system-x86_64 on PATH"
OVMF_DIR="${KRYPTIK_OVMF_DIR:-/usr/share/OVMF}"
CODE="${OVMF_DIR}/OVMF_CODE_4M.secboot.fd"
[[ -f "$CODE" ]] || die "no OVMF firmware at ${CODE} (install ovmf)"

VMDIR="${KRYPTIK_WORK}/vm"
mkdir -p "$VMDIR"
RUN_ID="${NAME}.$(date +%Y%m%dT%H%M%S).$$"

# The variable store: fresh from a template, or a persistent file.
if [[ -n "$VARS_FILE" ]]; then
    regular_file "$VARS_FILE"
    VARS_PATH="$VARS_FILE"
    VARS_DESC="persistent ${VARS_FILE}"
else
    case "$VARS" in
        clean)    src="${OVMF_DIR}/OVMF_VARS_4M.fd" ;;
        ms)       src="${OVMF_DIR}/OVMF_VARS_4M.ms.fd" ;;
        enrolled) src="${KRYPTIK_WORK}/keys/sb/vars/enrolled.fd"
                  [[ -f "$src" ]] || die "no enrolled variable store at ${src}; run tools/image/ovmf-vars.sh" ;;
        *)        regular_file "$VARS"; src="$VARS" ;;
    esac
    [[ -f "$src" ]] || die "no variable store template at ${src}"
    VARS_PATH="${VMDIR}/vars.${RUN_ID}.fd"
    cp "$src" "$VARS_PATH"
    VARS_DESC="fresh copy of ${src}"
fi

ACCEL=kvm; CPUMODEL=host
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then ACCEL=tcg; CPUMODEL=max; warn "no usable /dev/kvm: running under TCG (slow)"; fi

# shellcheck disable=SC2054  # the commas are QEMU option syntax, not array separators
ARGS=(
    -name "kryptik-${RUN_ID}"
    -machine "q35,smm=on,accel=${ACCEL}"
    -cpu "$CPUMODEL" -smp "$CPUS" -m "$MEM"
    -global driver=cfi.pflash01,property=secure,value=on
    -global "ICH9-LPC.disable_s3=$((1 - S3))"
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=${CODE}"
    -drive "if=pflash,format=raw,unit=1,file=${VARS_PATH}"
    -object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-pci,rng=rng0
    -rtc base=utc
    -boot menu=off
)
if [[ "$GPU" -eq 1 && "$S3" -eq 1 ]]; then
    # A sleep resets virtio-gpu under a driver with no .freeze or .restore (6.18's
    # drivers/gpu/drm/virtio/virtgpu_drv.c), whose next commit then waits for good. A guest
    # that sleeps shows through std VGA's framebuffer instead, which OVMF sets up and the
    # kernel's simpledrm drives: it has no bochs driver, and nothing there waits on a device.
    ARGS+=( -display none -vga std -device virtio-keyboard-pci -device virtio-mouse-pci )
elif [[ "$GPU" -eq 1 ]]; then
    # virtio-vga, not virtio-gpu-pci: the firmware framebuffer is in its BAR,
    # so virtio-gpu replaces simpledrm and wlroots sees one DRM device (with
    # two it takes a multi-GPU path the pixman renderer cannot serve).
    # A second output stays off until a display asks for a size on it: the
    # VNC server on that head is where vm-drive.py asks, and stops asking.
    VNC2=""
    if [[ "$HEAD2" -eq 1 ]]; then
        VNC2="${VMDIR}/${RUN_ID}.head2"
        ARGS+=( -display none -vga none -device virtio-vga,id=gpu0,max_outputs=2 -vnc "unix:${VNC2},display=gpu0,head=1" )
    else
        ARGS+=( -display none -vga none -device virtio-vga,id=gpu0 )
    fi
    ARGS+=( -device virtio-keyboard-pci -device virtio-mouse-pci )
    if [[ "$TOUCH" -eq 1 ]]; then
        "$QEMU" -device help 2>/dev/null | grep -q '"virtio-multitouch-pci"' \
            || die "--touch: this QEMU has no virtio-multitouch-pci (QEMU 8.1 or later has)"
        # Bound to the GPU's first head, so an input-send-event naming that head reaches it
        # before the mouse, which takes button events too.
        ARGS+=( -device virtio-multitouch-pci,id=touch0,display=gpu0,head=0 )
    fi
else
    ARGS+=( -display none -vga none )
fi
if [[ -n "$SOUND" ]]; then
    # A comma would end QEMU's path option early.
    [[ "$SOUND" != *,* ]] || die "--sound: no commas in the path: ${SOUND}"
    case "$(readlink -f "$SOUND")" in /dev/*|/sys/*|/proc/*) die "refusing to use ${SOUND}" ;; esac
    ARGS+=( -audiodev "wav,id=snd0,path=${SOUND},out.frequency=48000" -audiodev none,id=snd1 -audiodev none,id=snd2
            -device ich9-intel-hda,id=hda0 -device hda-output,bus=hda0.0,audiodev=snd0
            -device ich9-intel-hda,id=hda1 -device hda-duplex,bus=hda1.0,audiodev=snd1 )
fi
[[ "$ALLOW_REBOOT" -eq 1 ]] || ARGS+=( -no-reboot )
case "$NET" in
    none) ARGS+=( -nic none ) ;;
    user) ARGS+=( -nic user,model=virtio-net-pci ) ;;
    *) die "--net must be none or user" ;;
esac
if [[ -n "$USB" || "$USB_PORT" -eq 1 ]]; then
    ARGS+=( -device qemu-xhci,id=xhci )
fi
if [[ -n "$USB" ]]; then
    ARGS+=(
            -drive "if=none,id=usbmedia,format=raw,readonly=${USB_RO},file=${USB}"
            -device usb-storage,bus=xhci.0,drive=usbmedia,removable=on )
fi
if [[ -n "$ISO" ]]; then
    ARGS+=( -drive "if=none,id=cd0,format=raw,media=cdrom,readonly=on,file=${ISO}"
            -device ide-cd,drive=cd0 )
fi
i=0
for d in "${DISKS[@]}"; do
    if [[ "$i" -eq 0 && -n "$BLKDEBUG" ]]; then
        regular_file "$BLKDEBUG"
        ARGS+=( -drive "file=blkdebug:${BLKDEBUG}:${d},format=raw,if=virtio,cache=writeback,id=vd${i}" )
    elif [[ "$i" -eq 0 && "$DISK_RO" -eq 1 ]]; then
        ARGS+=( -drive "file=${d},format=raw,if=virtio,readonly=on,id=vd${i}" )
    elif [[ "$i" -eq 0 && "$DISK_4K" -eq 1 ]]; then
        ARGS+=( -drive "file=${d},format=raw,if=none,cache=writeback,id=vd${i}"
                -device "virtio-blk-pci,drive=vd${i},logical_block_size=4096,physical_block_size=4096" )
    else
        ARGS+=( -drive "file=${d},format=raw,if=virtio,cache=writeback,id=vd${i}" )
    fi
    i=$((i + 1))
done
[[ -n "$TESTCTL" ]] && ARGS+=( -drive "file=${TESTCTL},format=raw,if=virtio,readonly=on,id=testctl" )

log "OVMF boot: ${RUN_ID}"
dim "  firmware : ${CODE}"
dim "  variables: ${VARS_DESC}"
dim "  medium   : ${USB:-${ISO:-none (installed disk)}}"
[[ "${#DISKS[@]}" -gt 0 ]] && dim "  disks    : ${DISKS[*]}"
[[ -n "$TESTCTL" ]] && dim "  testctl  : ${TESTCTL}"
dim "  accel    : ${ACCEL}   net: ${NET}   mode: ${MODE}"

case "$MODE" in
console)
    exec "$QEMU" "${ARGS[@]}" -serial mon:stdio
    ;;
smoke)
    LOG="${LOG:-${KRYPTIK_WORK}/logs/ovmf-serial.${RUN_ID}.log}"
    mkdir -p "$(dirname "$LOG")"
    # The command line, which acceptance checks for host-side boot inputs.
    { printf '%q ' "$QEMU" "${ARGS[@]}"; echo; } > "${LOG}.cmd"
    ln -sfn "$LOG" "${KRYPTIK_WORK}/logs/ovmf-serial.latest.log"
    echo "serial log: ${LOG}"
    # The console is a socket so the driver can answer the state passphrase
    # prompt; wait=on holds the guest until the driver is connected.
    SER="${VMDIR}/${RUN_ID}.serial"
    set +e; trap - ERR
    "$QEMU" "${ARGS[@]}" -chardev "socket,id=ser0,path=${SER},server=on,wait=on,logfile=${LOG}" -serial chardev:ser0 \
        -monitor none < /dev/null > "${LOG}.qemu" 2>&1 &
    qpid=$!
    for _ in $(seq 1 50); do [[ -S "$SER" ]] && break; sleep 0.2; done
    # The driver decides: 0 when the console closed (the guest is gone, and
    # QEMU's own status is the result), 1 at its timeout (QEMU is killed).
    # QEMU closes its console just before it exits, so its pid cannot tell.
    if [[ ! -S "$SER" ]]; then
        kill "$qpid" 2>/dev/null; wait "$qpid"; rc=$?; [[ "$rc" -eq 0 ]] && rc=1
        warn "QEMU did not open its console socket ${SER}"
    elif [[ -n "$UNTIL" ]]; then
        # The line, then 10 s for anything after it. A guest that powered off
        # meanwhile keeps QEMU's status; one still running is stopped: 2.
        python3 "${SELF}/vm-drive.py" --serial "$SER" --timeout "$TIMEOUT" "expect:${UNTIL}" "sleep:10" > /dev/null
        seen=$?
        for _ in $(seq 1 30); do kill -0 "$qpid" 2>/dev/null || break; sleep 0.1; done
        if kill -0 "$qpid" 2>/dev/null; then
            kill "$qpid" 2>/dev/null; wait "$qpid"
            if [[ "$seen" -eq 0 ]]; then rc=2; else rc=124; fi
        else
            wait "$qpid"; rc=$?
        fi
    elif python3 "${SELF}/vm-drive.py" --serial "$SER" --timeout "$TIMEOUT" wait-exit > /dev/null; then
        # Up to 30 s for QEMU to exit.
        for _ in $(seq 1 300); do kill -0 "$qpid" 2>/dev/null || break; sleep 0.1; done
        if kill -0 "$qpid" 2>/dev/null; then
            kill "$qpid" 2>/dev/null; wait "$qpid"; rc=1
            warn "QEMU did not exit after the guest was gone"
        else
            wait "$qpid"; rc=$?
        fi
    else
        kill "$qpid" 2>/dev/null; wait "$qpid"; rc=124
    fi
    set -e
    [[ "$rc" -eq 124 ]] && warn "QEMU hit the ${TIMEOUT}s timeout"
    if [[ "$rc" -eq 2 && -n "$UNTIL" ]]; then
        echo "stopped 10 s after the awaited line: ${UNTIL}"
    elif [[ "$rc" -ne 0 && "$rc" -ne 124 ]]; then
        warn "QEMU exited ${rc}:"; sed 's/^/  /' "${LOG}.qemu" | tail -5
    fi
    exit "$rc"
    ;;
serve)
    SER="${VMDIR}/${RUN_ID}.serial"; QMP="${VMDIR}/${RUN_ID}.qmp"; PID="${VMDIR}/${RUN_ID}.pid"
    LOG="${LOG:-${KRYPTIK_WORK}/logs/ovmf-serial.${RUN_ID}.log}"
    mkdir -p "$(dirname "$LOG")"
    { printf '%q ' "$QEMU" "${ARGS[@]}"; echo; } > "${LOG}.cmd"
    setsid "$QEMU" "${ARGS[@]}" \
        -chardev "socket,id=ser0,path=${SER},server=on,wait=off,logfile=${LOG}" -serial chardev:ser0 \
        -qmp "unix:${QMP},server=on,wait=off" -monitor none -pidfile "$PID" \
        < /dev/null > "${LOG}.qemu" 2>&1 &
    for _ in $(seq 1 50); do [[ -S "$SER" && -S "$QMP" ]] && break; sleep 0.2; done
    [[ -S "$SER" ]] || die "QEMU did not create ${SER}: $(tail -3 "${LOG}.qemu")"
    printf 'serial=%s\nqmp=%s\npid=%s\nlog=%s\nvars=%s\n' "$SER" "$QMP" "$PID" "$LOG" "$VARS_PATH"
    [[ -z "${VNC2:-}" ]] || printf 'head2=%s\n' "$VNC2"
    ;;
*) die "unknown --mode ${MODE}" ;;
esac
