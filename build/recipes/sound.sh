#!/usr/bin/env bash

# Zone 0's mixer, a zone's alsa-lib plugin to it with the default device that names it, and the
# sound suite's probe (docs/design/laptop.md). The step's argument is the sources' digest.
s_sound() {
    local d="${KRYPTIK_ROOT}/tools/sound" f out
    echo "inputs: tools/sound ${1:-none}"
    for f in kryptik-sound.c pcm_kryptik.c soundprobe.c 50-kryptik.conf; do
        [[ -f "$d/$f" ]] || { echo "missing ${d}/${f}"; return 1; }
    done
    install -d -m 0755 /usr/libexec/kryptik /usr/lib/alsa-lib /usr/etc/alsa/conf.d
    # shellcheck disable=SC2086
    gcc ${CFLAGS} ${LDFLAGS} -o /usr/libexec/kryptik/kryptik-sound "$d/kryptik-sound.c" -lasound
    # shellcheck disable=SC2086
    gcc ${CFLAGS} -fPIC ${LDFLAGS} -shared -o /usr/lib/alsa-lib/libasound_module_pcm_kryptik.so "$d/pcm_kryptik.c" -lasound
    # shellcheck disable=SC2086
    gcc ${CFLAGS} ${LDFLAGS} -o /usr/libexec/kryptik/soundprobe "$d/soundprobe.c" -lasound -lm
    chmod 0755 /usr/libexec/kryptik/kryptik-sound /usr/libexec/kryptik/soundprobe \
        /usr/lib/alsa-lib/libasound_module_pcm_kryptik.so
    install -m 0644 "$d/50-kryptik.conf" /usr/etc/alsa/conf.d/50-kryptik.conf

    for f in kryptik-sound soundprobe; do
        out="$("/usr/libexec/kryptik/$f" 2>&1 || true)"
        [[ "$out" == *usage:* ]] || { echo "FAIL: ${f} does not run here: ${out}"; return 1; }
    done
    # The default device is the plugin: alsa-lib loads it, and here, where no mixer listens, it
    # says so.
    out="$(/usr/libexec/kryptik/soundprobe tone 440 1 2>&1 || true)"
    [[ "$out" == *"zone 0's mixer is not reachable"* ]] \
        || { echo "FAIL: the default device is not the zone's plugin: ${out}"; return 1; }
    echo "kryptik-sound, the zone's plugin and soundprobe: built, and the default device is the plugin"
}
