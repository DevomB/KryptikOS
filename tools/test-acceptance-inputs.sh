#!/usr/bin/env bash
# acceptance.sh's choice of releases: the release under test is the highest-
# versioned medium (or the one named) and its payload is B; A is the previous release
# - the highest version below B with a payload AND a USB medium - which the
# update test installs from its own medium before applying B. Version order
# decides, never modification time: the build makes A first and B second,
# and by mtime the second one looked like A. Exercised on a staged images/
# directory with the inputs block and need_update() taken from the script
# itself. No root, no images beyond empty files.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACC="$ROOT/tools/acceptance.sh"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
sed -n '/ inputs --$/,/^MEDIA_USB_A=/p' "$ACC" > "$T/inputs.sh"
grep -q '^MEDIA_USB_A=' "$T/inputs.sh" || { echo "could not extract the inputs block from $ACC"; exit 1; }
sed -n '/^need_update() {/,/^}/p' "$ACC" > "$T/need.sh"
grep -q '^need_update()' "$T/need.sh" || { echo "could not extract need_update from $ACC"; exit 1; }

release() {   # release VERSION [medium|payload|both]
    local v="$1" what="${2:-both}"
    [[ "$what" != payload ]] && { : > "$IMGDIR/kryptik-$v-usb.img"; : > "$IMGDIR/kryptik-$v.iso"; }
    [[ "$what" != medium ]] && { mkdir -p "$IMGDIR/payload-$v"; : > "$IMGDIR/payload-$v/manifest"; }
    sleep 0.01
}
choose() {   # choose [MEDIA_USB] [PAYLOAD_A] [PAYLOAD_B]: run the block on those inputs
    # shellcheck disable=SC2034  # read by the sourced inputs block
    MEDIA_USB="${1:-}"; MEDIA_ISO=""; PAYLOAD_A="${2:-}"; PAYLOAD_B="${3:-}"
    # shellcheck source=/dev/null
    . "$T/inputs.sh"
    need_vm() { :; }
    # shellcheck source=/dev/null
    . "$T/need.sh"
    NEED="$(need_update)"
}
b() { basename "${1:-}"; }

stage() { rm -rf "$T/images"; IMGDIR="$T/images"; mkdir -p "$IMGDIR"; }

# 1. The build's own order: X first, X.1 second. Newest medium = X.1 = the
#    release under test; A = X, from X's medium.
stage; release 0.1.20260915.abcdef01; release 0.1.20260915.abcdef01.1
choose
[[ "$VER" = 0.1.20260915.abcdef01.1 && "$(b "$PAYLOAD_B")" = payload-0.1.20260915.abcdef01.1 ]] \
    && ok "the newest medium is the release under test and its payload is B" || bad "release under test: VER=$VER B=$(b "$PAYLOAD_B")"
[[ "$(b "$PAYLOAD_A")" = payload-0.1.20260915.abcdef01 && "$(b "$MEDIA_USB_A")" = kryptik-0.1.20260915.abcdef01-usb.img ]] \
    && ok "A is the previous release, installed from its own medium" || bad "A=$(b "$PAYLOAD_A") medium=$(b "$MEDIA_USB_A")"
[[ "$(b "$MEDIA_ISO")" = kryptik-0.1.20260915.abcdef01.1.iso ]] && ok "the ISO is the release under test's" || bad "ISO=$(b "$MEDIA_ISO")"
[[ -z "$NEED" ]] && ok "the update test has what it needs" || bad "need_update: $NEED"

# 2. Built the other way round (B first, so A is the file written last):
#    the same answer, because version order decides, not modification time.
stage; release 0.1.20260915.abcdef01.1; release 0.1.20260915.abcdef01
choose
[[ "$VER" = 0.1.20260915.abcdef01.1 && "$(b "$PAYLOAD_A")" = payload-0.1.20260915.abcdef01 ]] \
    && ok "built in the other order, the choice is the same (version, not mtime)" || bad "reverse order: VER=$VER A=$(b "$PAYLOAD_A")"

# 3. One release only: it is the release under test; there is no A, and the
#    update test is told why instead of running.
stage; release 0.1.20260915.abcdef01
choose
[[ "$VER" = 0.1.20260915.abcdef01 && -n "$PAYLOAD_B" && -z "$PAYLOAD_A" && -z "$MEDIA_USB_A" ]] \
    && ok "a lone release is B with no A" || bad "lone: VER=$VER A=$(b "$PAYLOAD_A") B=$(b "$PAYLOAD_B")"
[[ "$NEED" == *"no previous release"* ]] && ok "need_update names the missing previous release" || bad "need_update: '$NEED'"

# 4. The previous version has a payload but no medium: it cannot be
#    installed, so A is the next one down that has both.
stage; release 0.1.20260914.00000000; release 0.1.20260915.abcdef01 payload; release 0.1.20260915.abcdef01.1
choose
[[ "$(b "$PAYLOAD_A")" = payload-0.1.20260914.00000000 ]] \
    && ok "a previous release without a medium is passed over for one that has it" || bad "A=$(b "$PAYLOAD_A")"

# 5. An explicit medium names the release under test; A is found below IT.
stage; release 0.1.20260914.00000000; release 0.1.20260915.abcdef01; release 0.1.20260915.abcdef01.1
choose "$IMGDIR/kryptik-0.1.20260915.abcdef01-usb.img"
[[ "$VER" = 0.1.20260915.abcdef01 && "$(b "$PAYLOAD_B")" = payload-0.1.20260915.abcdef01 && "$(b "$PAYLOAD_A")" = payload-0.1.20260914.00000000 ]] \
    && ok "an explicit medium is the release under test, and A is the release below it" || bad "explicit medium: VER=$VER A=$(b "$PAYLOAD_A") B=$(b "$PAYLOAD_B")"

# 6. Explicit payloads win, and a pair the wrong way round is named.
stage; release 0.1.20260915.abcdef01; release 0.1.20260915.abcdef01.1
choose "" "$IMGDIR/payload-0.1.20260915.abcdef01.1" "$IMGDIR/payload-0.1.20260915.abcdef01"
[[ "$VER_A" = 0.1.20260915.abcdef01.1 && "$VER_B" = 0.1.20260915.abcdef01 ]] && ok "explicit payloads are taken as given" || bad "explicit payloads: A=$VER_A B=$VER_B"
[[ "$NEED" == *"not older"* ]] && ok "need_update refuses A newer than B" || bad "need_update: '$NEED'"

# 7. A and B the same release: refused.
stage; release 0.1.20260915.abcdef01
choose "" "$IMGDIR/payload-0.1.20260915.abcdef01" "$IMGDIR/payload-0.1.20260915.abcdef01"
[[ "$NEED" == *"same version"* ]] && ok "need_update refuses A and B being one release" || bad "need_update: '$NEED'"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
