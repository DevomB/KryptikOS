#!/usr/bin/env bash
# The probe image: one small program built over the base system, which the zones suite stacks on a
# zone's /usr and runs there. It proves the image stage end to end and ships to no one.
# shellcheck disable=SC2034  # read by build/stages/04-images.sh
image_version="1.0"
# shellcheck disable=SC2034
image_rows=(
    "kryptik-probe" "s_image_probe"
)

s_image_probe() {
    local dir; dir="$(mktemp -d "${BUILDDIR}/probe.XXXXXX")"
    # shellcheck disable=SC2086  # the hardening flags are word lists
    gcc ${CFLAGS} ${LDFLAGS} -o "${dir}/kryptik-probe" "${KRYPTIK_ROOT}/build/images/probe/kryptik-probe.c"
    install -D -m 0755 "${dir}/kryptik-probe" /usr/bin/kryptik-probe
    rm -rf "$dir"
}
