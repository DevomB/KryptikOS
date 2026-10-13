#!/usr/bin/env bash
# Sound suite, run as root in the installed guest by tools/image/sound-test.sh, which boots it
# with QEMU's HD Audio controller and a codec that plays and records.
# Verdicts: "GT PASS|FAIL name - detail".
set -u
cd / || exit 1
PASS=0; FAIL=0
pass() { echo "GT PASS $1${2:+ - $2}"; PASS=$((PASS + 1)); }
fail() { echo "GT FAIL $1${2:+ - $2}"; FAIL=$((FAIL + 1)); }
wait_for() {   # wait_for SECONDS CMD...
    local n="$1"; shift
    while [[ "$n" -gt 0 ]]; do "$@" >/dev/null 2>&1 && return 0; n=$((n - 1)); sleep 1; done
    return 1
}
klog() { dmesg | grep -iE 'snd|hda|sound' | tail -"${1:-6}" | tr '\n' ' '; }

# --- the card ------------------------------------------------------------------------------
# eudev loads snd-hda-intel at coldplug, and the card registers once a codec has bound.
card() { grep -q 'HDA-Intel' /proc/asound/cards; }
if wait_for 30 card; then
    pass "sound-card" "$(head -2 /proc/asound/cards | tr -s ' ' | tr '\n' ' ')"
else
    fail "sound-card" "cards: $(tr '\n' ' ' < /proc/asound/cards 2>&1) kernel: $(klog)"
fi

# QEMU's codec has no driver of its own, so the generic parser takes it: it was loaded before
# the controller probed, as the kernel could not load it then.
drv="$(readlink /sys/bus/hdaudio/devices/hdaudioC0D0/driver 2>/dev/null)"
if [[ "${drv##*/}" == snd_hda_codec_generic ]]; then
    pass "codec-bound" "hdaudioC0D0 is driven by ${drv##*/}"
else
    fail "codec-bound" "hdaudioC0D0's driver: ${drv:-none}; kernel: $(klog)"
fi

# Every codec driver modprobe.d names came with the controller, so a codec that has a driver
# of its own is never left to the generic parser.
missing=""
for m in $(grep -v '^[[:space:]]*#' /usr/lib/modprobe.d/sound.conf | grep -oE 'snd-hda-codec-[a-z0-9-]+'); do
    grep -q "^${m//-/_} " /proc/modules || missing+=" $m"
done
if [[ -z "$missing" ]]; then
    pass "codec-drivers-ahead" "$(grep -c '^snd_hda_codec_' /proc/modules) codec modules loaded with snd_hda_intel"
else
    fail "codec-drivers-ahead" "not loaded:${missing}"
fi

if [[ -c /dev/snd/pcmC0D0p && -c /dev/snd/pcmC0D0c ]]; then
    pass "pcm-nodes" "$(cd /dev/snd && echo *)"
else
    fail "pcm-nodes" "/dev/snd: $(ls /dev/snd 2>&1 | tr '\n' ' ')"
fi

echo "GT SUMMARY passed=${PASS} failed=${FAIL}"
echo "GT END"
