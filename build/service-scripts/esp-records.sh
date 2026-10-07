#!/bin/sh
# The records Kryptik keeps on an ESP (kryptik/committed-slot,
# kryptik/version-a and version-b), read for a terminal or a log. An ESP is
# plain FAT that anyone holding the disk can rewrite, so a record is shown
# only in the shape Kryptik writes it; anything else reads as unknown.
# POSIX sh, sourced.
#   esp_slot FILE [ABSENT]     a or b
#   esp_version FILE [ABSENT]  a release's version
# A missing FILE reads as ABSENT (default unknown).

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
