#!/usr/bin/env bash

# The PCM, control and mixer interfaces: zone 0's mixer drives the card through them, and a
# zone's programs reach the mixer through an ioplug plugin (docs/design/laptop.md). No MIDI,
# sequencer, use-case manager or DSP topology, which nothing here drives, and none of the
# plugins a second client of the card would need (dmix, dsnoop, softvol): the mixer is its one.
s_alsa_lib() {
    native_build "alsa-lib-${V_ALSA_LIB}.tar.bz2" "alsa-lib-${V_ALSA_LIB}" --disable-static \
        --disable-rawmidi --disable-seq --disable-hwdep --disable-ucm --disable-topology \
        --disable-aload --disable-old-symbols \
        --with-pcm-plugins=copy,linear,route,rate,plug,lfloat,empty,ioplug,mmap_emul \
        --with-ctl-plugins=ext
    ls -la /usr/lib/libasound.so*
    local syms; syms="$(nm -D --defined-only /usr/lib/libasound.so.2)"
    grep -q ' snd_pcm_ioplug_create' <<<"$syms" || { echo "FAIL: libasound has no ioplug, which a zone plays through"; return 1; }
    ! grep -q ' snd_seq_open' <<<"$syms" || { echo "FAIL: libasound was built with the sequencer"; return 1; }
}
