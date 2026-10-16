#!/usr/bin/env bash
# What a hardware report (kryptik-hwreport) shows, and the listing it carries
# in docs/hardware/list.tsv (docs/hardware.md): `reported` when it is whole,
# names its machine and holds nothing that is one machine's alone; `certified`
# when it also comes from an installed release with Secure Boot on, a display,
# a network path and nothing missing.
#
#   tools/check-hardware.sh REPORT...   what each report shows and carries
#   tools/check-hardware.sh --list      every row of the list against its
#                                       report, and every report against the list
#
# Exit 1 when a report carries no listing, or a row claims more than its
# report shows.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The fixture suite names a list of its own.
DIR="${KRYPTIK_HARDWARE_DIR:-${ROOT}/docs/hardware}"

section() { awk -v s="== $1 ==" '$0 == s { on = 1; next } on && /^== .* ==$/ { exit } on' "$2"; }   # section NAME REPORT
field() { sed -n "s/^$1: //p" | head -1; }   # field KEY, of the section on stdin
took() { if [[ -n "$1" ]]; then echo "driven by $1"; else echo "not driven"; fi; }   # took DRIVER

# audio_of REPORT: the machine's sound in one line, by the kinds of
# docs/design/laptop-audio.md, each with what drives it. No level asks for any.
audio_of() {
    local a sof codecs sdw acp names amps drv parts=()
    a="$(section audio "$1")"
    [[ -n "$a" ]] || { echo "not in this report"; return; }
    # SOF in place of snd-hda-intel drives what sits behind Intel's DSP.
    sof="$(awk '$1 == "controller" && $NF ~ /^sof-/ { print $NF; exit }' <<<"$a")"
    # The graphics' HDMI codecs (Intel's, AMD's, NVIDIA's) are not the machine's own.
    codecs="$(awk '$1 == "codec" && $2 !~ /^(8086|1002|10de)/ { print $2 }' <<<"$a" | sort -u | paste -sd' ' -)"
    if [[ -n "$codecs" ]]; then parts+=("HD Audio codec ${codecs}")
    elif grep -q '^codec ' <<<"$a"; then parts+=("HD Audio for HDMI alone")
    elif grep -q '^controller ' <<<"$a"; then parts+=("no HD Audio codec found")
    fi
    if awk '$1 == "nhlt:" && $5 + 0 > 0 { found = 1 } END { exit !found }' <<<"$a"; then
        parts+=("digital microphones on Intel's DSP, $(took "$sof")")
    fi
    sdw="$(awk '$1 == "soundwire" && $5 == "part" { print $6 }' <<<"$a" | paste -sd' ' -)"
    [[ -z "$sdw" ]] || parts+=("SoundWire ${sdw}, $(took "$sof")")
    acp="$(awk '$1 == "acp" { print $7, ($9 == "-" ? "" : $9); exit }' <<<"$a")"
    if [[ -n "$acp" ]]; then
        names="$(sed -n 's/^acpi names: //p' <<<"$a" | head -1)"
        drv="${acp#* }"
        if [[ -n "$names" ]]; then parts+=("microphones on AMD's coprocessor (rev ${acp%% *}, ${names// /, }), $(took "$drv")")
        else parts+=("AMD's coprocessor (rev ${acp%% *}) with no microphones its ACPI names"); fi
    fi
    amps="$(awk '$1 == "amplifier" { sub(/:.*/, "", $2); print $2 }' <<<"$a" | sort -u | paste -sd' ' -)"
    if [[ -n "$amps" ]]; then
        # The ACPI device splitter alone drives no amplifier.
        drv="$(awk '$1 == "amplifier" { for (i = 4; i <= NF; i++) if ($i != "-" && $i != "serial-multi-instantiate") print $i }' <<<"$a" | sort -u | paste -sd' ' -)"
        parts+=("amplifiers ${amps}, $(took "$drv")")
    fi
    if [[ "${#parts[@]}" -eq 0 ]]; then echo "no audio device"
    else local IFS=';'; sed 's/;/; /g' <<<"${parts[*]}"; fi
}

# laptop_of REPORT: what a laptop has that a desktop lacks: each backlight
# and its kind, the machine's own batteries and its mains, and the lid switch.
laptop_of() {
    local l bl bat mains parts=()
    grep -qxF '== laptop ==' "$1" || { echo "not in this report"; return; }
    l="$(section laptop "$1")"
    bl="$(awk '$1 == "backlight" { printf "%s%s (%s)", sep, $2, $4; sep = ", " }' <<<"$l")"
    [[ -z "$bl" ]] || parts+=("backlight ${bl}")
    # A mouse's or a headset's battery is the device's, not the machine's.
    bat="$(awk '$1 == "power_supply" && $4 == "Battery" && $6 == "System" {
        printf "%s%s%s", sep, $2, ($10 == "-" ? "" : " (" $10 ")"); sep = ", " }' <<<"$l")"
    [[ -z "$bat" ]] || parts+=("battery ${bat}")
    mains="$(awk '$1 == "power_supply" && $4 == "Mains" { printf "%s%s", sep, $2; sep = " " }' <<<"$l")"
    [[ -z "$mains" ]] || parts+=("mains ${mains}")
    if grep -q '^"Lid Switch"' <<<"$(section input "$1")"; then parts+=("lid switch"); fi
    if [[ "${#parts[@]}" -eq 0 ]]; then echo "none of a laptop's parts: no backlight, battery or lid switch"
    else local IFS=';'; sed 's/;/; /g' <<<"${parts[*]}"; fi
}

# sleep_of REPORT: what a sleep to memory is on the machine, deep (S3) or
# s2idle, and the other kinds it offers; for s2idle, after a sleep, whether
# the last one reached the hardware's own sleep state.
sleep_of() {
    local l states mem chosen others out ok hw pmc
    grep -qxF '== laptop ==' "$1" || { echo "not in this report"; return; }
    l="$(section laptop "$1")"
    states="$(field 'sleep states' <<<"$l")"; mem="$(field 'sleep mem' <<<"$l")"
    grep -qw mem <<<"$states" || { echo "no sleep to memory (offered: ${states:-nothing})"; return; }
    chosen="$(grep -o '\[[a-z0-9]*\]' <<<"$mem" | tr -d '[]')"
    others="$(tr ' ' '\n' <<<"$mem" | grep -v '^\[' | grep . | paste -sd' ' -)"
    if [[ -z "$chosen" ]]; then out="mem offered, of no kind the report names"
    elif [[ -z "$others" ]]; then out="mem is ${chosen}, the only kind offered"
    else out="mem is ${chosen}; ${others} also offered"; fi
    # Deep sleep counts no hardware time, so only s2idle's last sleep is judged, and a time of 0
    # says something only where a power controller driver counts it.
    read -r ok hw <<<"$(awk '$1 == "sleep" && $2 == "stats:" { print $3, $9 }' <<<"$l")"
    pmc="$(field 'power controller' <<<"$l")"
    if [[ "$chosen" == s2idle && "${ok:-}" =~ ^[0-9]+$ && "$ok" -gt 0 && "${hw:-}" =~ ^[0-9]+$ ]]; then
        if [[ "$hw" -gt 0 ]]; then out+="; its last sleep kept the hardware asleep $(( hw / 1000000 )) s"
        elif [[ -n "$pmc" && "$pmc" != none ]]; then out+="; its last sleep never reached the hardware's sleep state, which drains the battery"
        else out+="; no power controller driver counts how long its sleeps reach the hardware's sleep state"; fi
    fi
    echo "$out"
}

# camera_of REPORT: a USB video device and what drives it; and a MIPI
# camera's parts: Intel's image processing unit and what drives it, and the
# sensors ACPI names, behind a Visual Sensing Controller where it has one.
camera_of() {
    local l uvc ipu sensors parts=()
    grep -qxF '== laptop ==' "$1" && grep -qxF '== usb ==' "$1" || { echo "not in this report"; return; }
    l="$(section laptop "$1")"
    # Video's control interface (0e/01), which uvcvideo binds, under its device's IDs.
    uvc="$(section usb "$1" | awk '
        $2 != "interface" { id[$1] = $2; next }
        $4 ~ /^0e\/01\// { d = $1; sub(/:.*/, "", d); if (!(d in seen)) { seen[d] = 1; n++; dev[n] = d; drv[n] = $6 } }
        END { for (i = 1; i <= n; i++) print (dev[i] in id ? id[dev[i]] : "?"), (drv[i] == "-" ? "" : drv[i]) }')"
    while read -r u d; do
        [[ -z "$u" ]] || parts+=("USB video ${u}, $(took "$d")")
    done <<<"$uvc"
    ipu="$(awk '$1 == "camera" && $2 ~ /^ipu/ { print toupper($2), $4, ($6 == "-" ? "" : $6) }' <<<"$l")"
    while read -r k i d; do
        [[ -z "$k" ]] || parts+=("${k} ${i}, $(took "$d")")
    done <<<"$ipu"
    sensors="$(awk '$1 == "camera" && $2 == "acpi" && $4 == "sensor" && NF == 4 { sub(/:.*/, "", $3); print $3 }' <<<"$l" | sort -u | paste -sd' ' -)"
    if [[ -n "$sensors" ]]; then
        [[ "$sensors" == *" "* ]] && sensors="sensors ${sensors}" || sensors="sensor ${sensors}"
        grep -q '^camera acpi .* visual sensing controller$' <<<"$l" && sensors+=", behind a Visual Sensing Controller"
        parts+=("$sensors")
    fi
    if [[ "${#parts[@]}" -eq 0 ]]; then echo "no camera found"
    else local IFS=';'; sed 's/;/; /g' <<<"${parts[*]}"; fi
}

# bluetooth_of REPORT: each Bluetooth controller on USB (e0/01/01) and what
# drives it.
bluetooth_of() {
    local bt out=()
    grep -qxF '== usb ==' "$1" || { echo "not in this report"; return; }
    bt="$(section usb "$1" | awk '
        $2 != "interface" { id[$1] = $2; next }
        $4 == "e0/01/01" { d = $1; sub(/:.*/, "", d); if (!(d in seen)) { seen[d] = 1; n++; dev[n] = d; drv[n] = $6 } }
        END { for (i = 1; i <= n; i++) print (dev[i] in id ? id[dev[i]] : "?"), (drv[i] == "-" ? "" : drv[i]) }')"
    while read -r u d; do
        [[ -z "$u" ]] || out+=("USB ${u}, $(took "$d")")
    done <<<"$bt"
    if [[ "${#out[@]}" -eq 0 ]]; then echo "no Bluetooth controller on USB"
    else local IFS=';'; sed 's/;/; /g' <<<"${out[*]}"; fi
}

# examine REPORT: MACHINE, RELEASE and FACTS, with NOT_REPORTED and
# NOT_CERTIFIED, each empty or one reason per line.
examine() {
    local r="$1" s what lacking
    MACHINE=""; RELEASE=""; FACTS=""; NOT_REPORTED=""; NOT_CERTIFIED=""
    unfit() { NOT_REPORTED+="$*"$'\n'; }
    lacks() { NOT_CERTIFIED+="$*"$'\n'; }
    fact() { FACTS+="$(printf '  %-10s %s' "$1" "$2")"$'\n'; }

    if [[ "$(head -1 "$r")" != "kryptik-hwreport 1" ]]; then
        unfit "not a report this tool reads: it does not open with 'kryptik-hwreport 1'"
        return
    fi
    for s in system machine firmware cpu missing pci storage display network "kernel log"; do
        grep -qxF "== ${s} ==" "$r" || unfit "cut short: no '${s}' section"
    done

    local vendor product model bios
    vendor="$(section machine "$r" | field sys_vendor)"; product="$(section machine "$r" | field product_name)"
    model="$(section machine "$r" | field product_version)"
    bios="$(section machine "$r" | field bios_version) $(section machine "$r" | field bios_date)"
    [[ -n "$vendor" && -n "$product" ]] || unfit "does not name its machine (sys_vendor and product_name)"
    MACHINE="${vendor} ${product}${model:+ (${model})}"
    fact machine "${MACHINE}, firmware ${bios}"

    local kernel booted state
    RELEASE="$(section system "$r" | field kryptik)"; RELEASE="${RELEASE%% (*}"
    kernel="$(section system "$r" | field kernel)"
    booted="$(section system "$r" | field booted)"; state="$(section system "$r" | field state)"
    [[ -n "$RELEASE" && -n "$kernel" ]] || unfit "does not name its release and kernel"
    fact release "${RELEASE}, kernel ${kernel}"
    fact booted "${booted}; state ${state:-unknown}"
    [[ "$booted" =~ ^slot\ [ab],\ installed$ ]] || lacks "not taken on an installed system (booted: ${booted:-unknown})"
    [[ "$state" == persistent ]] || lacks "the state partition is not in use (state: ${state:-unknown})"
    [[ "$RELEASE" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || lacks "${RELEASE:-no version} is not a release (a dated build, or none)"

    local uefi sb lock
    uefi="$(section firmware "$r" | field uefi)"; sb="$(section firmware "$r" | field 'secure boot')"
    lock="$(section firmware "$r" | field lockdown)"
    fact firmware "UEFI ${uefi:-unknown}; Secure Boot ${sb:-unknown}; lockdown ${lock:-unknown}"
    [[ "$uefi" == yes* ]] || lacks "not booted by UEFI firmware"
    [[ "$sb" == on ]] || lacks "Secure Boot is ${sb:-unknown}"
    [[ "$lock" == confidentiality ]] || lacks "lockdown is ${lock:-unknown}, not confidentiality"
    fact microcode "$(section cpu "$r" | field microcode)"
    # What confines a device's DMA, and Thunderbolt's level. No level asks for it.
    local iommu tb dma
    iommu="$(section firmware "$r" | field iommu)"
    tb="$(section firmware "$r" | sed -n 's/^thunderbolt //p' | paste -sd';' -)"
    case "$iommu" in
        "") dma="not in this report" ;;
        none) dma="none: nothing confines a device's DMA" ;;
        *) dma="on: ${iommu}" ;;
    esac
    fact dma "${dma}${tb:+; thunderbolt ${tb//;/; thunderbolt }}"

    # The three lists under `missing`, each "  (none)" or its entries.
    lacking="$(section missing "$r" | awk '
        /^firmware the kernel asked for/ { what = "firmware the kernel did not find:"; next }
        /^devices with no driver/        { what = "no driver for"; next }
        /^disks behind a driver/         { what = "a disk behind a module:"; next }
        /^  / && $0 != "  (none)"        { sub(/^  /, ""); print what, $0 }')"
    if [[ -z "$lacking" ]]; then fact missing nothing
    else
        fact missing "$(grep -c . <<<"$lacking") line(s) for firmware.list or boot.fragment"
        while IFS= read -r what; do lacks "$what"; done <<<"$lacking"
    fi

    local cards outputs
    cards="$(section display "$r" | sed -n 's/^card[0-9]* driver //p' | sort -u | paste -sd' ' -)"
    outputs="$(section display "$r" | sed -n 's/^card[0-9]*-\([^ ]*\) connected *\(.*\)/\1 \2/p' | paste -sd';' -)"
    fact display "${cards:-no DRM device}${outputs:+: ${outputs//;/; }}"
    [[ -n "$cards" && -n "$outputs" ]] || lacks "no display the compositor can use: no DRM device with a connected output"
    fact audio "$(audio_of "$r")"
    fact laptop "$(laptop_of "$r")"
    fact sleep "$(sleep_of "$r")"
    fact camera "$(camera_of "$r")"
    fact bluetooth "$(bluetooth_of "$r")"

    # A path out: the default route leaves by one of the machine's own
    # interfaces, and that one has a carrier.
    local via link
    via="$(section network "$r" | sed -n 's/^  default route by //p' | head -1)"
    link="$(section network "$r" | sed -n '/^in the net zone:$/,$p' \
        | awk -v via="$via" '$1 == via && ($2 == "wired" || $2 == "wireless") && /LOWER_UP/ { print $2, $1 }' | head -1)"
    fact network "${link:-no default route by an interface with a carrier}"
    [[ -n "$link" ]] || lacks "no network path: no default route by a wired or wireless interface with a carrier in the net zone"

    # By line number, never by what the line holds.
    what="$(grep -nE '(^|[^0-9A-Fa-f])([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}($|[^0-9A-Fa-f])|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|[Ss]erial ?([Nn]umber|[Nn]o)[.:= ]+[^< ]' "$r" | cut -d: -f1 | tr '\n' ' ')"
    [[ -z "$what" ]] || unfit "holds a hardware address, a UUID or a serial number: line(s) ${what% }"
}

# carries: the level the examined report carries, or nothing.
carries() {
    if [[ -n "$NOT_REPORTED" ]]; then return
    elif [[ -z "$NOT_CERTIFIED" ]]; then echo certified
    else echo reported; fi
}

show() {   # show REPORT: its facts, and why it falls short; 1 when it carries nothing
    examine "$1"
    echo "${1##*/}"
    printf '%s' "$FACTS"
    local level; level="$(carries)"
    if [[ -z "$level" ]]; then
        printf '  %-10s %s\n' carries "no listing:"
        sed '/^$/d; s/^/      /' <<<"$NOT_REPORTED"
        return 1
    fi
    if [[ "$level" == certified ]]; then printf '  %-10s %s\n' carries certified
    else
        printf '  %-10s %s\n' carries "reported; short of certified:"
        sed '/^$/d; s/^/      /' <<<"$NOT_CERTIFIED"
    fi
}

list() {
    local tsv="${DIR}/list.tsv" bad=0 n=0 report level by day have taken f
    [[ -f "$tsv" ]] || { echo "no list at ${tsv}"; return 1; }
    declare -A seen=()
    fail() { echo "  FAIL  $*"; bad=$((bad + 1)); }
    while read -r report level by day _; do
        [[ -z "$report" || "$report" == \#* ]] && continue
        n=$((n + 1))
        [[ -z "${seen[$report]:-}" ]] || { fail "${report}: listed twice"; continue; }
        seen[$report]=1
        [[ "$report" =~ ^[a-z0-9][a-z0-9.-]*\.txt$ ]] || { fail "${report}: a report's name is lower-case letters, digits, dots and dashes, ending .txt"; continue; }
        [[ -f "${DIR}/${report}" ]] || { fail "${report}: no such report beside the list"; continue; }
        [[ "$level" == reported || "$level" == certified ]] || { fail "${report}: the level is reported or certified, not '${level}'"; continue; }
        [[ -n "$by" && "$day" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || { fail "${report}: a row names who vouches and the day (YYYY-MM-DD)"; continue; }
        examine "${DIR}/${report}"
        have="$(carries)"
        taken="$(section system "${DIR}/${report}" | field taken)"
        if [[ -z "$have" ]]; then
            fail "${report}: carries no listing:"; sed '/^$/d; s/^/          /' <<<"$NOT_REPORTED"
        elif [[ "$level" == certified && "$have" != certified ]]; then
            fail "${report}: listed certified, and its report is short of that:"; sed '/^$/d; s/^/          /' <<<"$NOT_CERTIFIED"
        # The list is of machines, each on the day its report was taken.
        elif section cpu "${DIR}/${report}" | field 'of note' | grep -qw hypervisor; then
            fail "${report}: taken in a virtual machine, and the list holds machines"
        elif [[ "$taken" != "${day}T"* ]]; then
            fail "${report}: its row says ${day}, and the report was taken ${taken:-on no day it names}"
        else
            printf '  ok    %-10s %s, %s (%s, %s)\n' "$level" "$MACHINE" "$RELEASE" "$by" "$day"
        fi
    done < "$tsv"
    for f in "$DIR"/*.txt; do
        [[ -f "$f" ]] || continue
        [[ -n "${seen[${f##*/}]:-}" ]] || fail "${f##*/}: a report with no row in the list"
    done
    [[ "$bad" -eq 0 ]] || { echo "FAIL: ${bad} row(s) or report(s) the list cannot carry"; return 1; }
    echo "ok: ${n} machine(s) listed, each row carried by its report"
}

case "${1:-}" in
    -h|--help|"") sed -n '2,13p' "${BASH_SOURCE[0]}"; [[ -n "${1:-}" ]] ;;
    --list) [[ "$#" -eq 1 ]] || { echo "--list takes no report" >&2; exit 2; }; list ;;
    -*) echo "unknown argument: $1" >&2; exit 2 ;;
    *)
        rc=0
        for report in "$@"; do
            [[ -f "$report" ]] || { echo "no such report: ${report}" >&2; rc=1; continue; }
            show "$report" || rc=1
        done
        exit "$rc" ;;
esac
