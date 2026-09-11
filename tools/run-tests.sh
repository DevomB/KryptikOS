#!/usr/bin/env bash
#
# Run every Kryptik suite that works without root and without the build chroot,
# then NAME the ones that were not run.
#
# A suite that quietly omits its hardest checks reports a pass it has not
# earned. The privileged tests are precisely the ones that touch the built
# system rather than the scripts that build it, so leaving them out silently
# would be the most misleading thing this script could do.
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

SUITES=(
    test-harness
    test-hardening
    test-services
    test-manifest
    test-s6-init
    test-image-signing
)

failed=()
for t in "${SUITES[@]}"; do
    printf '\n=== %s ===\n' "$t"
    if make --no-print-directory "$t"; then
        :
    else
        failed+=("$t")
    fi
done

printf '\n----------------------------------------------------------------\n'
if [[ "${#failed[@]}" -eq 0 ]]; then
    printf 'all %d unprivileged suites passed\n' "${#SUITES[@]}"
else
    printf '%d of %d suites FAILED:\n' "${#failed[@]}" "${#SUITES[@]}"
    printf '  %s\n' "${failed[@]}"
fi

cat <<'EOF'

NOT run by this target - these need root and the build chroot:

  make test-libc-unwind   can the TARGET libc unwind? Expected to FAIL while
                          the glibc defect in build/BLOCKER.md stands.
  make smoke-userspace    run the built userland inside the chroot
  make image-smoke        build a disk image and boot it under QEMU
EOF

[[ "${#failed[@]}" -eq 0 ]] || exit 1
