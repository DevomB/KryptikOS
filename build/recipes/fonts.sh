#!/usr/bin/env bash

# DejaVu: havoc renders from the one file its config names; Sans and the bold faces come along.
s_fonts() {
    local src; src="$(unpack "dejavu-fonts-ttf-${V_DEJAVU_FONTS}.tar.bz2" "dejavu-fonts-ttf-${V_DEJAVU_FONTS}")"
    install -d -m 0755 /usr/share/fonts/TTF
    install -m 0644 "$src/ttf/DejaVuSansMono.ttf" "$src/ttf/DejaVuSansMono-Bold.ttf" \
        "$src/ttf/DejaVuSans.ttf" "$src/ttf/DejaVuSans-Bold.ttf" /usr/share/fonts/TTF/
    install -Dm644 "$src/LICENSE" /usr/share/licenses/dejavu-fonts/LICENSE
    local want; want="$(sed -n 's/^path=//p' /usr/share/kryptik/havoc.cfg | head -1)"
    [[ -s "${want:-/nonexistent}" ]] || { echo "havoc.cfg names ${want:-no font}, which is not installed"; return 1; }
    echo "havoc's font: ${want} ($(stat -c %s "$want") bytes)"
}
