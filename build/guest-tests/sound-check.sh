#!/usr/bin/env bash
# Sound suite, run as root in the installed guest by tools/image/sound-test.sh, which boots it
# with two of QEMU's HD Audio cards: the first only plays, the second plays and records.
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

# --- the cards -----------------------------------------------------------------------------
# eudev loads snd-hda-intel at coldplug, and a card registers once its codec has bound.
cards() { [[ "$(grep -c 'HDA-Intel' /proc/asound/cards)" -eq 2 ]]; }
if wait_for 30 cards; then
    pass "sound-card" "$(grep 'HDA-Intel' /proc/asound/cards | tr -s ' ' | tr '\n' ' ')"
else
    fail "sound-card" "cards: $(tr '\n' ' ' < /proc/asound/cards 2>&1) kernel: $(klog)"
fi

# QEMU's codecs have no driver of their own, so the generic parser takes them: it was loaded
# before the controllers probed, as the kernel could not load it then.
drivers=""
for c in hdaudioC0D0 hdaudioC1D0; do
    drv="$(readlink "/sys/bus/hdaudio/devices/$c/driver" 2>/dev/null)"
    drivers+="$c=${drv##*/} "
done
if [[ "$drivers" == "hdaudioC0D0=snd_hda_codec_generic hdaudioC1D0=snd_hda_codec_generic " ]]; then
    pass "codec-bound" "${drivers% }"
else
    fail "codec-bound" "${drivers% }; kernel: $(klog)"
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

if [[ -c /dev/snd/pcmC0D0p && -c /dev/snd/pcmC1D0p && -c /dev/snd/pcmC1D0c ]]; then
    pass "pcm-nodes" "$(cd /dev/snd && echo *)"
else
    fail "pcm-nodes" "/dev/snd: $(ls /dev/snd 2>&1 | tr '\n' ' ')"
fi

echo "GT SUMMARY passed=${PASS} failed=${FAIL}"
echo "GT END"
