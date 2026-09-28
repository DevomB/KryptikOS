#!/usr/bin/env bash
# fonts: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# havoc renders from the one TrueType file its config names
# (/usr/share/fonts/TTF/DejaVuSansMono.ttf); Sans and the bold faces come along.
# Licence: Bitstream Vera terms plus public-domain changes (LICENSE, installed).
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
