#!/bin/sh
# kryptik-hwreport: what this machine is made of and what the image lacks for
# it: the machine, each device and the driver that took it, the firmware the
# kernel asked for and did not find, and the kernel log. Serial numbers,
# hardware addresses and UUIDs are left out, and struck from the log.
#
#   kryptik-hwreport           print the report
#   kryptik-hwreport --save    write it onto the USB medium this system booted
#                              from, as kryptik-report/report-N.txt on the
#                              stick's first partition
#
# A stick whose first partition holds a kryptik-report directory gets a report
# at every boot (hw-report.sh). Nothing else writes to a medium.
set -u

PROG=kryptik-hwreport
say() { printf '%s: %s\n' "$PROG" "$*"; }
die() { printf '%s: FAILED: %s\n' "$PROG" "$*" >&2; exit 1; }

# A tree read in place of the running system's, for tools/tests/hwreport.sh.
R="${KRYPTIK_HWREPORT_ROOT:-}"
SYS="$R/sys"

SAVE=0
case "${1:-}" in
    "") ;;
    --save) SAVE=1 ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
esac
[ "$#" -le 1 ] || die "one argument at most"
[ -n "$R" ] || [ "$(id -u)" = 0 ] || die "must run as root: the kernel log is root's to read"

one() { [ -r "$1" ] && head -n 1 "$1" 2>/dev/null; }          # a file's first line
hex() { v="$(one "$1")"; v="${v#0x}"; printf '%s' "${v:--}"; }  # the same, without 0x
target() { [ -e "$1" ] && basename "$(readlink -f "$1")"; }   # what a link names
kmsg() { if [ -n "$R" ]; then cat "$R/dmesg" 2>/dev/null; else dmesg 2>/dev/null; fi; }
# netzone NAME COMMAND...: COMMAND in the net zone's network namespace; the
# fixture tree holds its output as netzone/NAME.
netzone() {
    if [ -n "$R" ]; then cat "$R/netzone/$1" 2>/dev/null; else shift; nsenter -t "$pid" -n "$@" 2>/dev/null; fi
}
sec() { printf '\n== %s ==\n' "$1"; }
or_none() { if [ -s "$1" ]; then sed 's/^/  /' "$1"; else echo "  (none)"; fi; }

# The log prints what must not leave the machine: a network driver its
# address, USB a device's serial number, a filesystem its UUID.
scrub() {
    sed -E \
        -e ':a' -e 's/(^|[^0-9A-Fa-f])([0-9A-Fa-f]{2}:){5,}[0-9A-Fa-f]{2}($|[^0-9A-Fa-f])/\1xx:xx:xx:xx:xx:xx\3/' -e 'ta' \
        -e 's/[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/<uuid>/g' \
        -e 's/([Ss]erial ?([Nn]umber|[Nn]o)[.:= ]+)[^ ,;]+/\1<removed>/g' \
        -e 's/(S\/N[:= ]+)[^ ,;]+/\1<removed>/g'
}

# A driver that is a loadable module cannot hold the root: there is no
# initramfs to load it from (ADR-013).
kind_of() {   # kind_of DRIVER-DIR
    km="$(target "$1/module")"
    if [ -n "$km" ] && [ -e "$SYS/module/$km/initstate" ]; then echo module; else echo "built in"; fi
}

system() {
    os="$R/etc/os-release"
    printf 'kryptik: %s (build %s)\n' "$(sed -n 's/^VERSION_ID=//p' "$os" 2>/dev/null | tr -d '"')" \
        "$(sed -n 's/^BUILD_ID=//p' "$os" 2>/dev/null)"
    printf 'kernel: %s\n' "$(one "$R/proc/sys/kernel/osrelease")"
    id="$R/run/kryptik/boot-identity"
    media="$(sed -n 's/^media=//p' "$id" 2>/dev/null)"
    if [ -n "$media" ]; then printf 'booted: the %s medium\n' "$media"
    else printf 'booted: slot %s, installed\n' "$(sed -n 's/^slot=//p' "$id" 2>/dev/null)"; fi
    printf 'state: %s\n' "$(sed -n 's/^state=//p' "$id" 2>/dev/null)"
    printf 'taken: %s\n' "$(date -u +%Y-%m-%dT%H:%MZ)"
}

machine() {
    for k in sys_vendor product_name product_version product_family product_sku \
             board_vendor board_name board_version bios_vendor bios_version bios_date chassis_type; do
        printf '%s: %s\n' "$k" "$(one "$SYS/class/dmi/id/$k")"
    done
}

efi_byte() {   # the value byte of one of the firmware's own variables
    od -An -tu1 -j4 -N1 "$SYS/firmware/efi/efivars/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c" 2>/dev/null | tr -d ' '
}
firmware() {
    if [ -d "$SYS/firmware/efi" ]; then printf 'uefi: yes, %s-bit\n' "$(one "$SYS/firmware/efi/fw_platform_size")"
    else echo "uefi: no"; fi
    case "$(efi_byte SecureBoot)" in 1) echo "secure boot: on" ;; 0) echo "secure boot: off" ;; *) echo "secure boot: unreadable" ;; esac
    printf 'setup mode: %s\n' "$(efi_byte SetupMode)"
    printf 'lockdown: %s\n' "$(sed -n 's/.*\[\(.*\)\].*/\1/p' "$SYS/kernel/security/lockdown" 2>/dev/null)"
    tpm=none
    for t in "$SYS"/class/tpm/tpm*; do [ -e "$t" ] && tpm="version $(one "$t/tpm_version_major")"; done
    printf 'tpm: %s\n' "$tpm"
}

cpu() {
    awk -F': *' '
        /^model name/ { name = $2 }
        /^vendor_id/  { vendor = $2 }
        /^cpu family/ { family = $2 }
        /^model\t/    { model = $2 }
        /^stepping/   { stepping = $2 }
        /^microcode/  { microcode = $2 }
        /^flags/      { flags = $2 }
        /^processor/  { n++ }
        END {
            printf "model: %s\n", name
            printf "vendor, family/model/stepping: %s, %s/%s/%s\n", vendor, family, model, stepping
            printf "microcode: %s\n", microcode
            printf "threads running: %d\n", n
            printf "of note:"
            split("nx smep smap umip pku ibt user_shstk rdrand rdseed aes sha_ni la57 hypervisor", want, " ")
            split(flags, have, " ")
            for (i in have) has[have[i]] = 1
            for (i = 1; i in want; i++) if (want[i] in has) printf " %s", want[i]
            printf "\n"
        }' "$R/proc/cpuinfo" 2>/dev/null
    printf 'present: %s, online: %s, smt: %s\n' "$(one "$SYS/devices/system/cpu/present")" \
        "$(one "$SYS/devices/system/cpu/online")" "$(one "$SYS/devices/system/cpu/smt/control")"
    kmsg | sed -n 's/^\[[^]]*\] *\(microcode: .*\)/\1/p' | head -n 3
    for f in "$SYS"/devices/system/cpu/vulnerabilities/*; do
        [ -r "$f" ] && printf '%s: %s\n' "${f##*/}" "$(one "$f")"
    done
    printf 'memory: %s MiB\n' "$(awk '/^MemTotal/ { printf "%d", $2 / 1024 }' "$R/proc/meminfo" 2>/dev/null)"
}

# address class vendor device subsystem-vendor subsystem-device revision driver modalias
pci_raw() {
    for d in "$SYS"/bus/pci/devices/*; do
        [ -r "$d/vendor" ] || continue
        drv="$(target "$d/driver")"
        printf '%s %s %s %s %s %s %s %s %s\n' "${d##*/}" "$(hex "$d/class")" "$(hex "$d/vendor")" "$(hex "$d/device")" \
            "$(hex "$d/subsystem_vendor")" "$(hex "$d/subsystem_device")" "$(hex "$d/revision")" "${drv:--}" "$(one "$d/modalias")"
    done
}
# The same, with the names hwdata's list gives the class and the device.
pci_named() {   # pci_named RAW-FILE
    awk -v ids="$R/usr/share/hwdata/pci.ids" '
        BEGIN {
            while ((getline l < ids) > 0) {
                if (l ~ /^C [0-9a-f][0-9a-f]  /) { classes = 1; base = substr(l, 3, 2); cname[base] = substr(l, 7); continue }
                if (classes) {
                    if (l ~ /^\t[0-9a-f][0-9a-f]  /) cname[base substr(l, 2, 2)] = substr(l, 6)
                    continue
                }
                if (l ~ /^[0-9a-f][0-9a-f][0-9a-f][0-9a-f]  /) { v = substr(l, 1, 4); vname[v] = substr(l, 7); continue }
                if (l ~ /^\t[0-9a-f][0-9a-f][0-9a-f][0-9a-f]  /) dname[v ":" substr(l, 2, 4)] = substr(l, 8)
            }
        }
        {
            what = (substr($2, 1, 4) in cname) ? cname[substr($2, 1, 4)] : cname[substr($2, 1, 2)]
            name = vname[$3]
            if (($3 ":" $4) in dname) name = name " " dname[$3 ":" $4]
            printf "%s class %s %s:%s sub %s:%s rev %s driver %s", $1, $2, $3, $4, $5, $6, $7, $8
            if (what != "") printf " | %s", what
            if (name != "") printf " | %s", name
            printf "\n"
        }' "$1"
}

usb() {
    for d in "$SYS"/bus/usb/devices/*; do
        n="${d##*/}"
        if [ -r "$d/idVendor" ]; then
            printf '%s %s:%s speed %s | %s %s\n' "$n" "$(one "$d/idVendor")" "$(one "$d/idProduct")" "$(one "$d/speed")" \
                "$(one "$d/manufacturer")" "$(one "$d/product")"
        elif [ -r "$d/bInterfaceClass" ]; then
            drv="$(target "$d/driver")"
            printf '%s interface class %s/%s/%s driver %s\n' "$n" "$(one "$d/bInterfaceClass")" \
                "$(one "$d/bInterfaceSubClass")" "$(one "$d/bInterfaceProtocol")" "${drv:--}"
        fi
    done
}

# Every device that names what would drive it and has nothing bound.
unbound() {
    for bus in pci usb platform i2c hid serio sdio mmc spi virtio thunderbolt; do
        for d in "$SYS/bus/$bus"/devices/*; do
            [ -e "$d/driver" ] && continue
            alias="$(one "$d/modalias")"
            [ -n "$alias" ] && printf '%s %s %s\n' "$bus" "${d##*/}" "$alias"
        done
    done
}

# Each disk with the drivers between it and the machine; a disk behind a
# module goes to $T/modular as well.
disks() {
    rootdisk="$(sed -n 's/^root_disk=//p' "$R/run/kryptik/boot-identity" 2>/dev/null)"
    for b in "$SYS"/block/*; do
        n="${b##*/}"
        case "$n" in loop*|ram*|dm-*|zram*|fd*) continue ;; esac
        [ -e "$b/device" ] || continue
        chain=""; last=""; modular=""
        p="$(readlink -f "$b/device")"
        while [ -n "$p" ] && [ "$p" != "$SYS" ] && [ "$p" != / ]; do
            if [ -e "$p/driver" ]; then
                drv="$(target "$p/driver")"; k="$(kind_of "$p/driver")"
                [ "$drv" = "$last" ] || chain="${chain}${chain:+, }${drv} (${k})"
                last="$drv"
                [ "$k" = module ] && modular="${modular}${modular:+ }$(target "$p/driver/module")"
            fi
            p="${p%/*}"
        done
        note=""
        [ "$(one "$b/removable")" = 1 ] && note=" removable"
        [ "/dev/$n" = "$rootdisk" ] && note="${note} (the root is here)"
        printf '%s %s GiB%s | %s | %s\n' "$n" "$(awk -v s="$(one "$b/size")" 'BEGIN { printf "%.1f", s * 512 / 1073741824 }')" \
            "$note" "$(one "$b/device/model" | sed 's/ *$//')" "$chain"
        [ -z "$modular" ] || printf '%s: %s\n' "$n" "$modular" >> "$T/modular"
    done
}

display() {
    for c in "$SYS"/class/drm/card*; do
        [ -e "$c" ] || continue
        n="${c##*/}"
        case "$n" in
            *-*) printf '%s %s %s\n' "$n" "$(one "$c/status")" "$(one "$c/modes")" ;;
            *)   printf '%s driver %s\n' "$n" "$(target "$c/device/driver")" ;;
        esac
    done
    for f in "$SYS"/class/graphics/fb[0-9]*; do
        [ -e "$f" ] && printf '%s %s %s\n' "${f##*/}" "$(one "$f/name")" "$(one "$f/virtual_size")"
    done
}

network() {
    for i in "$SYS"/class/net/*; do
        n="${i##*/}"
        [ -e "$i" ] && [ "$n" != lo ] || continue
        kind=wired
        { [ -e "$i/wireless" ] || [ -e "$i/phy80211" ]; } && kind=wireless
        [ -e "$i/device" ] || kind=virtual
        printf '%s %s driver %s state %s\n' "$n" "$kind" "$(target "$i/device/driver")" "$(one "$i/operstate")"
    done
    for r in "$SYS"/class/rfkill/rfkill*; do
        [ -e "$r" ] && printf '%s %s %s soft %s hard %s\n' "${r##*/}" "$(one "$r/type")" "$(one "$r/name")" "$(one "$r/soft")" "$(one "$r/hard")"
    done
    # The machine's interfaces are the net zone's, in its own namespace: each
    # by kind and flags, and the one the default route leaves by.
    pid="$(cut -d' ' -f1 "$R/run/kryptik/zones/net/init.pid" 2>/dev/null)"
    [ -n "$pid" ] || { echo "the net zone is not running"; return 0; }
    echo "in the net zone:"
    radios="$(netzone iw-dev iw dev | awk '$1 == "Interface" { print $2 }' | tr '\n' ' ')"
    netzone ip-link ip -o -d link | awk -v radios="$radios" '
        BEGIN { n = split(radios, r, " "); for (i = 1; i <= n; i++) radio[r[i]] = 1 }
        $2 == "lo:" { next }
        {
            name = $2; sub(/:$/, "", name); sub(/@.*/, "", name)
            kind = ($0 ~ / (bridge|veth|dummy|tun) /) ? "virtual" : (name in radio) ? "wireless" : "wired"
            print "  " name, kind, $3
        }'
    netzone ip-route ip -4 route show default | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") print "  default route by " $(i + 1) }'
}

inputs() {
    awk -F= '/^N: Name/ { name = $2 } /^H: Handlers/ { print name " | " $2 }' "$R/proc/bus/input/devices" 2>/dev/null
}

missing_firmware() {
    kmsg | sed -n \
        -e 's/.*Direct firmware load for \(.*\) failed with error.*/\1/p' \
        -e 's/.*[Uu]nable to load firmware \([^ ,]*\).*/\1/p' \
        -e 's/.*Failed to load DMC firmware \([^ ,]*\).*/\1/p' \
        -e 's/.*maximum version supported: \(iwlwifi-[^ ]*\).*/\1.ucode/p' \
        | sort -u
}

report() {
    pci_raw > "$T/pci"
    unbound > "$T/unbound"
    disks > "$T/disks"
    missing_firmware > "$T/firmware"
    # Storage, network, display, an SD host, input, a USB host, a radio.
    awk '$8 == "-" && $2 ~ /^(01|02|03|0805|09|0c03|0d)/' "$T/pci" > "$T/undriven"
    pci_named "$T/undriven" > "$T/undriven.named"

    echo "kryptik-hwreport 1"
    sec system;   system
    sec machine;  machine
    sec firmware; firmware
    sec cpu;      cpu
    sec missing
    echo "firmware the kernel asked for and did not find, each a line for build/config/firmware.list:"
    or_none "$T/firmware"
    echo "devices with no driver, each wanting its driver's line in build/config/kernel/boot.fragment:"
    or_none "$T/undriven.named"
    echo "disks behind a driver that is a module, which boot.fragment must build in before a root can sit there:"
    or_none "$T/modular"
    sec pci;      pci_named "$T/pci"
    sec usb;      usb
    sec "no driver"; cat "$T/unbound"
    sec storage;  cat "$T/disks"
    sec display;  display
    sec network;  network
    sec input;    inputs
    sec modules;  awk '{ print $1 }' "$R/proc/modules" 2>/dev/null | sort | tr '\n' ' ' | fold -s -w 78; echo
    sec "firmware messages"; kmsg | grep -i firmware
    sec "kernel log"; kmsg
}

T="$(mktemp -d)" || die "no temporary directory"
lock=""; mnt=""
# rmdir, never rm -r: a partition that would not unmount is still under $lock.
cleanup() {
    rm -rf "$T"
    [ -n "$lock" ] || return 0
    mountpoint -q "$mnt" 2>/dev/null && umount "$mnt" 2>/dev/null
    rmdir "$mnt" "$lock" 2>/dev/null
}
trap cleanup EXIT
trap 'exit 1' INT TERM

if [ "$SAVE" = 0 ]; then
    report | scrub
    exit 0
fi

grep -qs '^media=usb$' "$R/run/kryptik/boot-identity" \
    || die "--save writes to the USB medium this system booted from, and this is not one: redirect the output instead"
. /usr/libexec/kryptik/devices.sh
esp="$(kryptik_part kryptik-esp)" || esp=""
[ -b "$esp" ] || die "no single kryptik-esp partition on the medium this system booted from"
[ "$(one "/sys/class/block/${esp##*/}/ro")" = 0 ] || die "the stick is write-protected: no report was written"

umask 077
report | scrub > "$T/report.txt"
mkdir /run/kryptik/hwreport.lock 2>/dev/null || die "another report is being written (/run/kryptik/hwreport.lock)"
lock=/run/kryptik/hwreport.lock; mnt="$lock/esp"
mkdir "$mnt"
mount -o rw,nosuid,nodev,noexec "$esp" "$mnt" 2>/dev/null \
    || die "could not mount ${esp}: is kryptik-install running, or the partition damaged?"
# mount falls back to read-only on a device that refuses writes.
[ -w "$mnt" ] || die "the stick is write-protected: no report was written"
dir="$mnt/kryptik-report"
mkdir -p "$dir" || die "could not make kryptik-report on ${esp}"
n=1
while [ -e "$dir/report-$n.txt" ]; do n=$((n + 1)); done
# Written, fsynced, then renamed: a stick pulled early holds whole reports only.
if ! { cp "$T/report.txt" "$dir/report-$n.tmp" && sync "$dir/report-$n.tmp" && mv "$dir/report-$n.tmp" "$dir/report-$n.txt"; }; then
    rm -f "$dir/report-$n.tmp"
    die "could not write the report onto ${esp}: is it full?"
fi
sync -f "$dir"
umount "$mnt" || die "report-$n.txt is written, but ${esp} did not unmount: do not pull the stick yet"
say "written kryptik-report/report-$n.txt on ${esp}, which is unmounted again"
