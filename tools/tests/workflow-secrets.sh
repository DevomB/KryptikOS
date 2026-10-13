#!/usr/bin/env bash
# The Distro workflow keeps each secret to the job that needs it, and nothing another job
# made reaches a job that holds one (docs/release-keys.md): the build jobs run every
# upstream build script as root, so their outputs and artifacts are an attacker's input.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WF="${ROOT}/.github/workflows/distro.yml"
[[ -f "$WF" ]] || { echo "no ${WF}"; exit 1; }

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

job() {   # job NAME: the job's lines, from its key to the next job's
    awk -v key="  $1:" '$0 == key { on = 1; print; next } on && /^  [a-z][a-z0-9_-]*:$/ { exit } on { print }' "$WF"
}
for j in sign acceptance release; do
    [[ -n "$(job "$j")" ]] || { red "no ${j} job in ${WF}"; }
done

# Each key in its own job: a job that names a secret is handed it, whatever it then does.
only_in() {   # only_in SECRET JOB
    local all mine
    all="$(grep -c "secrets\.$1\b" "$WF")"
    mine="$(job "$2" | grep -c "secrets\.$1\b")"
    if [[ "$all" -ge 1 && "$all" -eq "$mine" ]]; then green "${1} is named in the ${2} job alone"; else red "${1} is named ${all} time(s), ${mine} of them in ${2}"; fi
}
only_in KRYPTIK_KEY_MEDIUM sign
only_in KRYPTIK_TESTCTL_KEY acceptance

# A job that holds a secret takes nothing from another job's outputs: the release's
# version, role and channel come from the ref.
for j in sign acceptance release; do
    if job "$j" | grep -qE 'needs\.[a-z_-]+\.outputs'; then
        red "the ${j} job reads another job's outputs: $(job "$j" | grep -nE 'needs\.[a-z_-]+\.outputs' | head -2 | tr '\n' ' ')"
    else
        green "the ${j} job takes nothing from another job's outputs"
    fi
done

# The acceptance part that runs the build's own programs as root on the runner (build:
# the sysroot's chroot and its programs) is outside release-tests, so its runner never
# holds the control-disk key: a root process there could read it from the step's environ.
env_line="$(job acceptance | grep -E '^    environment:')"
if [[ "$env_line" == *"'release-tests'"* && "$env_line" == *"!contains(matrix.suites, 'build')"* ]]; then
    green "the part that runs sysroot programs is outside release-tests"
else
    red "the acceptance environment does not leave out the part that runs sysroot programs: ${env_line:-no environment line}"
fi

echo
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
