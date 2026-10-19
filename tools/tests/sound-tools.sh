#!/usr/bin/env bash
# The sound's C programs compile with the stage's hardening flags as stage 04 builds them
# (build/recipes/sound.sh): the mixer and soundprobe answer no arguments with their usage, and the
# zones' alsa plugin exports the entry alsa-lib looks it up by. A change to one is checked here,
# not first in a Distro build. Without a C compiler or alsa-lib's headers it exits 77.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
command -v cc >/dev/null 2>&1 || { echo "sound-tools.sh: no C compiler here"; exit 77; }
[ -f /usr/include/alsa/asoundlib.h ] || { echo "sound-tools.sh: no alsa-lib headers here"; exit 77; }
# shellcheck source=/dev/null
. "$REPO/build/config/hardening.env"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
S="$REPO/tools/sound"

fail=0
pass() { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; fail=1; }

# The two programs, linked as the recipe links them, and run with no arguments.
for t in kryptik-sound:-lasound soundprobe:"-lasound -lm"; do
    name="${t%%:*}" libs="${t#*:}"
    # shellcheck disable=SC2086
    if ! cc ${CFLAGS} ${LDFLAGS} -o "$W/$name" "$S/$name.c" $libs; then
        bad "tools/sound/$name.c does not compile with the stage's flags"
        continue
    fi
    out="$("$W/$name" 2>&1)"; rc=$?
    if [[ "$rc" -eq 2 && "$out" == *usage:* ]]; then
        pass "$name compiles with the stage's flags and answers no arguments with its usage"
    else
        bad "$name with no arguments: exit $rc, ${out:0:200}"
    fi
done

# The plugin, a shared object as the recipe makes it: -DPIC makes alsa-lib's versioned symbol.
# shellcheck disable=SC2086
if cc ${CFLAGS} -fPIC -DPIC ${LDFLAGS} -shared -o "$W/plugin.so" "$S/pcm_kryptik.c" -lasound; then
    syms="$(nm -D --defined-only "$W/plugin.so" 2>/dev/null)"
    if grep -qw _snd_pcm_kryptik_open <<<"$syms" && grep -qw __snd_pcm_kryptik_open_dlsym_pcm_001 <<<"$syms"; then
        pass "pcm_kryptik.c compiles as a plugin with the entry alsa-lib opens it by"
    else
        bad "the plugin lacks _snd_pcm_kryptik_open or its versioned symbol: $(grep -i kryptik <<<"$syms" | tr '\n' ' ')"
    fi
else
    bad "tools/sound/pcm_kryptik.c does not compile as a plugin with the stage's flags"
fi
exit "$fail"
