#!/usr/bin/env bash
# build/lib/step-files.sh on a stand-in root: a rebuilt step's leftovers go, and nothing another step writes or something links.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0; FAIL=0
ok_()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
for t in find comm readelf; do command -v "$t" > /dev/null || { echo "${t} required"; exit 77; }; done

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
export NO_COLOR=1
# shellcheck source=/dev/null
source "${ROOT}/build/lib/common.sh"
# shellcheck source=/dev/null
source "${ROOT}/build/lib/step-files.sh"
set +e; trap - ERR
STEP_FILES_ROOT="$T/root"; STAMPS="$T/stamps"
mkdir -p "$STEP_FILES_ROOT/usr/bin" "$STEP_FILES_ROOT/usr/lib" "$STEP_FILES_ROOT/usr/share/a" "$STEP_FILES_ROOT/tmp" "$STAMPS"

# run NAME CMD...: CMD as step NAME, stamped, and recorded as stage 04 records it.
run() {
    local name="$1" m; shift
    m="$(step_files_mark)"; sleep 0.05
    ( cd "$STEP_FILES_ROOT" && "$@" )
    sleep 0.05; : > "$STAMPS/bs-$name"
    step_files_record "$name" "$STAMPS/bs-$name" "$m"
}
r() { printf '%s\n' "$STEP_FILES_ROOT$1"; }

# A writes three files and a library; B writes one of A's again; nothing links the library yet.
run a sh -c 'echo 1 > usr/bin/tool; echo 1 > usr/share/a/old; echo 1 > usr/share/a/shared; cp /bin/true usr/lib/libgone.so.1; echo scratch > tmp/x'
run b sh -c 'echo 2 > usr/share/a/shared; echo 2 > usr/bin/other'
grep -qx /usr/share/a/old "$STAMPS/files/a" && ! grep -q '^/tmp' "$STAMPS/files/a" \
    && ok_ "a step's record holds what it wrote, and not the pruned trees" || bad "a's record: $(tr '\n' ' ' < "$STAMPS/files/a")"

# A rebuilt: it no longer writes old, shared or the library.
run a sh -c 'echo 3 > usr/bin/tool'
step_files_sweep a b > "$T/out" 2>&1
if [[ ! -e "$(r /usr/share/a/old)" && -e "$(r /usr/share/a/shared)" && -e "$(r /usr/bin/tool)" && ! -e "$(r /usr/lib/libgone.so.1)" ]]; then
    ok_ "a rebuilt step's leftovers go, and a file another step still writes stays"
else
    bad "after the sweep: $(cd "$STEP_FILES_ROOT" && find . -type f | tr '\n' ' ')"; cat "$T/out"
fi

# A library something links stays even when its step drops it.
needed="$(readelf -d /bin/true 2>/dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | head -1)"
if [[ -n "$needed" ]]; then
    run c sh -c "cp /bin/true usr/bin/linker; cp /bin/true 'usr/lib/${needed}'"
    run c sh -c 'cp /bin/true usr/bin/linker'
    step_files_sweep a b c > "$T/out" 2>&1
    [[ -e "$(r "/usr/lib/${needed}")" ]] && grep -q "something links it" "$T/out" \
        && ok_ "a library something links is kept" || { bad "the linked ${needed} was removed"; cat "$T/out"; }
fi

# A step with no record yet could install any leftover, so nothing goes.
run d sh -c 'echo 1 > usr/share/a/late'
run d sh -c ':'
step_files_sweep a b c d e > "$T/out" 2>&1
[[ -e "$(r /usr/share/a/late)" ]] && grep -q "no record" "$T/out" \
    && ok_ "with a step still unrecorded the leftovers wait" || { bad "a leftover went while a step had no record"; cat "$T/out"; }
step_files_sweep a b c d > "$T/out" 2>&1
[[ ! -e "$(r /usr/share/a/late)" ]] && ok_ "and go once every step has a record" || { bad "the waiting leftover stayed"; cat "$T/out"; }

# A step that did not run keeps its record.
before="$(cat "$STAMPS/files/b")"
m="$(step_files_mark)"; step_files_record b "$STAMPS/bs-b" "$m"
[[ "$(cat "$STAMPS/files/b")" == "$before" ]] && ok_ "a skipped step keeps its record" || bad "a skipped step's record changed"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
