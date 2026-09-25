#!/usr/bin/env bash
# Run every suite that needs no root and no build chroot, and name the ones
# that did not run. Suites run directly, not through make, which would turn
# their exit 77 (a missing dependency) into exit 2.
#
#   tools/run-tests.sh            exit 1 if any suite failed
#   tools/run-tests.sh --strict   also exit 1 if any suite did not run
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

STRICT=0
[[ "${1:-}" == "--strict" ]] && STRICT=1

# Every tools/test-* file is a suite, except these: the first two chroot into
# the built system (acceptance items), the last two run with the compartment
# suites below.
ELSEWHERE=" test-libc-unwind.sh test-userspace-smoke.sh test-desktop-identity.sh test-compositor.sh "
SUITES=()
for t in tools/test-*.sh tools/test-*.py; do
    [[ "$ELSEWHERE" == *" ${t##*/} "* ]] && continue
    n="${t##*/}"; SUITES+=("${n%.*}|$t")
done

# These need a kryptikd built by cargo; without cargo they count as not run.
COMPARTMENT=(
    "zone-test|compartments/tests/adversarial.sh"
    "launcher-test|compartments/tests/launcher.sh"
    "cli-test|compartments/tests/cli.sh"
    "serve-test|compartments/tests/serve.sh"
    "test-desktop-identity|tools/test-desktop-identity.sh"
    "test-compositor|tools/test-compositor.sh"
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
        # cargo builds under CARGO_TARGET_DIR when set; the suites read $KRYPTIKD.
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
                          object? (build/patches/glibc-2.40/README.md)
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
