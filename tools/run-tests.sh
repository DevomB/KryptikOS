#!/usr/bin/env bash
#
# Run every Kryptik suite that works without root and without the build chroot,
# then NAME the ones that were not run - and never let a skip read as a pass.
#
# A suite that quietly omits its hardest checks reports a pass it has not
# earned. The privileged tests are precisely the ones that touch the built
# system rather than the scripts that build it, so leaving them out silently
# would be the most misleading thing this script could do.
#
# The suites are run DIRECTLY, not through make. GNU make reports a failed
# recipe as exit 2 whatever the recipe exited with, so the autotools convention
# these suites follow - exit 77 for "a dependency is missing" - never reached
# this script through `make <suite>`: a missing ssh-keygen and a failed check
# were the same number, and the skip branch below could never run.
#
#   tools/run-tests.sh            run, report, exit 1 if any suite FAILED
#   tools/run-tests.sh --strict   also exit 1 if any suite did NOT RUN
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

STRICT=0
[[ "${1:-}" == "--strict" ]] && STRICT=1

# name|script. The name is the make target of the same suite, so a failure
# here is reproduced with `make <name>`.
SUITES=(
    "test-harness|tools/test-step-errexit.sh"
    "test-hardening|tools/test-hardening-flags.sh"
    "test-services|tools/test-services.sh"
    "test-boot-success|tools/test-boot-success.sh"
    "test-manifest|tools/test-artifact-manifest.sh"
    "test-s6-init|tools/test-s6-init-config.sh"
    "test-image-signing|tools/test-image-signing.sh"
    "test-installer|tools/test-installer.sh"
    "test-mkdisk-guards|tools/test-mkdisk-guards.sh"
)

# The compartment suites need a kryptikd, which needs cargo. They are always
# COUNTED - the total is the total - and where there is no cargo they are
# reported as not run, with the reason, rather than dropped from the list.
COMPARTMENT=(
    "zone-test|compartments/tests/adversarial.sh"
    "launcher-test|compartments/tests/launcher.sh"
    "cli-test|compartments/tests/cli.sh"
    "serve-test|compartments/tests/serve.sh"
    "update-tree-test|compartments/tests/update.sh"
    "identity-test|tools/test-desktop-identity.sh"
    "compositor-test|tools/test-compositor.sh"
)

passed=()
failed=()
skipped=()   # "name (reason)"

run_suite() {   # run_suite <name> <script>
    local name="$1" script="$2" rc
    printf '\n=== %s ===\n' "$name"
    if [[ ! -x "$script" ]]; then
        printf 'not executable or missing: %s\n' "$script"
        failed+=("$name")
        return
    fi
    "$script"
    rc=$?
    if [[ "$rc" -eq 0 ]]; then
        passed+=("$name")
    elif [[ "$rc" -eq 77 ]]; then
        skipped+=("$name (the suite reported a missing dependency)")
    else
        failed+=("$name")
    fi
}

for entry in "${SUITES[@]}"; do
    run_suite "${entry%%|*}" "${entry#*|}"
done

if command -v cargo >/dev/null 2>&1; then
    printf '\n=== building kryptikd for the compartment suites ===\n'
    if ( cd compartments/kryptikd && cargo build --quiet ); then
        # The suites look for the binary; cargo puts it under CARGO_TARGET_DIR
        # when that is set (acceptance points it at the large disk), not the
        # default target/. Tell the suites where it landed - cli.sh and
        # launcher.sh honour $KRYPTIKD, and adversarial.sh does now too.
        for cand in "${CARGO_TARGET_DIR:-compartments/kryptikd/target}/debug/kryptikd" \
                    "compartments/kryptikd/target/debug/kryptikd"; do
            [[ -x "$cand" ]] && { KRYPTIKD="$(cd "$(dirname "$cand")" && pwd)/kryptikd"; export KRYPTIKD; break; }
        done
        for entry in "${COMPARTMENT[@]}"; do
            run_suite "${entry%%|*}" "${entry#*|}"
        done
    else
        printf 'cargo build failed; the compartment suites cannot run\n'
        for entry in "${COMPARTMENT[@]}"; do
            failed+=("${entry%%|*} (kryptikd did not build)")
        done
    fi
else
    for entry in "${COMPARTMENT[@]}"; do
        skipped+=("${entry%%|*} (no cargo here, so kryptikd cannot be built)")
    done
fi

total=$(( ${#SUITES[@]} + ${#COMPARTMENT[@]} ))
printf '\n----------------------------------------------------------------\n'
printf '%d suites: %d passed, %d failed, %d did not run\n' \
       "$total" "${#passed[@]}" "${#failed[@]}" "${#skipped[@]}"

if [[ "${#failed[@]}" -gt 0 ]]; then
    printf '\nFAILED:\n'
    printf '  %s\n' "${failed[@]}"
fi

if [[ "${#skipped[@]}" -gt 0 ]]; then
    printf '\nDID NOT RUN (a missing dependency, not a result):\n'
    printf '  %s\n' "${skipped[@]}"
fi

cat <<'EOF'

NOT run by this target - these need root, the build chroot or a VM:

  make test-libc-unwind   can the TARGET libc unwind through a dlopened
                          object? (docs/glibc-loader-defect.md)
  make smoke-userspace    run the built userland inside the chroot
  make acceptance         the mandatory installed-system evidence: firmware
                          boot, install, verified boot, zones, storage,
                          desktop, updates - see docs/status.md
EOF

[[ "${#failed[@]}" -eq 0 ]] || exit 1
if [[ "$STRICT" -eq 1 && "${#skipped[@]}" -gt 0 ]]; then
    printf '\n--strict: %d suite(s) did not run, which is not a pass.\n' "${#skipped[@]}"
    exit 1
fi
exit 0
