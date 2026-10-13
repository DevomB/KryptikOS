#!/usr/bin/env bash

# The PCM, control and mixer interfaces: zone 0's mixer drives the card through them, and a
# zone's programs reach the mixer through an ioplug plugin (docs/design/laptop.md). The MIDI,
# sequencer and hwdep APIs too, as Firefox's Web MIDI links them (its `alsa` crate calls snd_seq_*
# and snd_rawmidi_*); with no sequencer in the kernel and no /dev/snd in a zone, they find no
# device. No use-case manager or DSP topology, which nothing here drives, and none of the plugins
# a second client of the card would need (dmix, dsnoop, softvol): the mixer is its one.
s_alsa_lib() {
    native_build "alsa-lib-${V_ALSA_LIB}.tar.bz2" "alsa-lib-${V_ALSA_LIB}" --disable-static \
        --disable-ucm --disable-topology --disable-aload --disable-old-symbols \
        --with-pcm-plugins=copy,linear,route,rate,plug,lfloat,empty,ioplug,mmap_emul \
        --with-ctl-plugins=ext
    ls -la /usr/lib/libasound.so*
    local syms; syms="$(nm -D --defined-only /usr/lib/libasound.so.2)"
    grep -q ' snd_pcm_ioplug_create' <<<"$syms" || { echo "FAIL: libasound has no ioplug, which a zone plays through"; return 1; }
    grep -q ' snd_seq_open' <<<"$syms" || { echo "FAIL: libasound has no sequencer, which Firefox's Web MIDI links"; return 1; }
    grep -q ' snd_rawmidi_open' <<<"$syms" || { echo "FAIL: libasound has no raw MIDI, which Firefox's Web MIDI links"; return 1; }
}
