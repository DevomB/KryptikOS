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
    test-mkdisk-guards
)

# The compartment suites belong here too. They need no root and no chroot -
# they were simply in a different part of the tree - and leaving them out made
# this script's own promise false in the direction it warns about: a run that
# omits the suites covering the thing being built, and does not say so.
#
# They need a kryptikd, which needs cargo. Where there is none they are NAMED
# as not run rather than dropped, for the same reason.
COMPARTMENT=(zone-test launcher-test cli-test update-test)
skipped=()
if command -v cargo >/dev/null 2>&1; then
    SUITES+=("${COMPARTMENT[@]}")
else
    for t in "${COMPARTMENT[@]}"; do
        skipped+=("$t (no cargo here, so kryptikd cannot be built)")
    done
fi

failed=()
for t in "${SUITES[@]}"; do
    printf '\n=== %s ===\n' "$t"
    make --no-print-directory "$t"
    rc=$?
    # 77 is the autotools convention these suites follow for "a dependency is
    # missing", and it is neither a pass nor a failure of the code.
    if [[ "$rc" -eq 77 ]]; then
        skipped+=("$t (the suite reported a missing dependency)")
    elif [[ "$rc" -ne 0 ]]; then
        failed+=("$t")
    fi
done

printf '\n----------------------------------------------------------------\n'
if [[ "${#failed[@]}" -eq 0 ]]; then
    printf 'all %d unprivileged suites passed\n' "$(( ${#SUITES[@]} - ${#skipped[@]} ))"
else
    printf '%d of %d suites FAILED:\n' "${#failed[@]}" "${#SUITES[@]}"
    printf '  %s\n' "${failed[@]}"
fi

if [[ "${#skipped[@]}" -gt 0 ]]; then
    printf '\nDID NOT RUN (a missing dependency, not a result):\n'
    printf '  %s\n' "${skipped[@]}"
fi

cat <<'EOF'

NOT run by this target - these need root and the build chroot:

  make test-libc-unwind   can the TARGET libc unwind? Expected to FAIL while
                          the glibc defect in build/BLOCKER.md stands.
  make smoke-userspace    run the built userland inside the chroot
  make image-smoke        build a disk image and boot it under QEMU
EOF

[[ "${#failed[@]}" -eq 0 ]] || exit 1
