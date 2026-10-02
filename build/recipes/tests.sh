#!/usr/bin/env bash

# The suites in the image, laid out as in the repository: they find their tree as $HERE/../..
s_tests() {
    echo "inputs digest: ${1:-none}"
    local base=/usr/lib/kryptik
    install -d -m 0755 "$base/compartments/tests" "$base/compartments/kryptikd/probes" \
        "$base/compartments/kryptikd/target/debug" "$base/compartments/kryptikd/src" "$base/guest-tests"
    local t
    for t in "${KRYPTIK_ROOT}"/compartments/tests/*.sh; do
        install -m 0755 "$t" "$base/compartments/tests/$(basename "$t")"
    done
    for t in "${KRYPTIK_ROOT}"/compartments/kryptikd/probes/*.sh; do
        install -m 0755 "$t" "$base/compartments/kryptikd/probes/$(basename "$t")"
    done
    # adversarial.sh checks its namespaces against isolate.rs and its mounts against rootfs.rs.
    for src in isolate.rs rootfs.rs; do
        install -m 0644 "${KRYPTIK_ROOT}/compartments/kryptikd/src/${src}" "$base/compartments/kryptikd/src/${src}"
    done
    ln -sfn /usr/bin/kryptikd "$base/compartments/kryptikd/target/debug/kryptikd"
    for t in "${KRYPTIK_ROOT}"/build/guest-tests/*.sh "${KRYPTIK_ROOT}"/build/guest-tests/*.py; do
        [[ -f "$t" ]] || continue
        install -m 0755 "$t" "$base/guest-tests/$(basename "$t")"
    done
    for t in "$base"/compartments/tests/*.sh "$base"/compartments/kryptikd/probes/*.sh "$base"/guest-tests/*.sh; do
        bash -n "$t" || { echo "FAIL: $t has a syntax error"; return 1; }
    done
    echo "--- installed ---"
    find "$base/compartments" "$base/guest-tests" -type f -o -type l | sort
}
