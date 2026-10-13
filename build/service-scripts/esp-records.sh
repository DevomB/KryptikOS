#!/bin/sh
# The records Kryptik keeps on an ESP (kryptik/committed-slot,
# kryptik/version-a and version-b) and the kernels beside them. An ESP is
# plain FAT that anyone holding the disk can rewrite, so a record is shown
# only in the shape Kryptik writes it; anything else reads as unknown.
# POSIX sh, sourced.
#   esp_slot FILE [ABSENT]     a or b
#   esp_version FILE [ABSENT]  a release's version
#   esp_put FILE LINE          write a record
#   esp_place SRC DST          copy a kernel into place
# A missing FILE reads as ABSENT (default unknown).

# Drop FILE's clean pages, so the next read is what the device holds; best effort.
uncache() { dd if="$1" iflag=nocache count=0 status=none 2>/dev/null || :; }   # uncache FILE

# Written, fsynced, renamed: a power cut leaves the old record whole, not empty.
esp_put() {
    printf '%s\n' "$2" > "$1.new" && sync -f "$1.new" && mv -f "$1.new" "$1"
}

# A copy that landed wrong, as the device holds it, never takes DST's name.
esp_place() {
    if cp "$1" "$2.new" && sync -f "$2.new" && uncache "$2.new" && cmp -s "$1" "$2.new"; then
        mv -f "$2.new" "$2"
    else
        rm -f "$2.new"
        return 1
    fi
}

esp_slot() {
    [ -e "$1" ] || { echo "${2:-unknown}"; return 0; }
    case "$(head -c 8 "$1" 2>/dev/null | sed -n 1p)" in
        a) echo a ;;
        b) echo b ;;
        *) echo unknown ;;
    esac
}

# MAJOR.MINOR.PATCH as a release is numbered (build/lib/release-keys.sh),
# then the parts a development build adds: 0.1.20261007.1a2b3c4d.1
esp_version() {
    [ -e "$1" ] || { echo "${2:-unknown}"; return 0; }
    ev="$(head -c 80 "$1" 2>/dev/null | sed -n 1p)"
    if [ "${#ev}" -le 64 ] && printf '%s\n' "$ev" \
        | LC_ALL=C grep -E -x -q '(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(\.[0-9a-z]+)*'; then
        printf '%s\n' "$ev"
    else
        echo unknown
    fi
}
