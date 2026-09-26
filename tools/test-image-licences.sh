#!/usr/bin/env bash
# tools/check-image-licences.sh on a staged root: it passes when every listed
# source has licence files or an exception, and Kryptik has its own, and names
# each source that has neither.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
R="$T/repo"; I="$T/image"
mkdir -p "$R/tools" "$R/build/lib" "$R/build/config" "$I/usr/share/licenses"
cp "$ROOT/tools/check-image-licences.sh" "$R/tools/"
cp "$ROOT/build/lib/common.sh" "$R/build/lib/"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "zlib 1.3 https://x/zlib-1.3.tar.xz" "bash 5.3 https://x/bash-5.3.tar.gz" "glibc-fhs-patch 2.40 https://x/glibc-2.40-fhs-1.patch"\n' > "$R/tools/fetch-sources.sh"
chmod 755 "$R/tools/fetch-sources.sh"
printf '# test\nglibc-fhs-patch   # a patch to glibc\n' > "$R/build/config/licence-exceptions.txt"
check() { KRYPTIK_ROOT="$R" NO_COLOR=1 bash "$R/tools/check-image-licences.sh" "$I" 2>&1; }
lic() { mkdir -p "$I/usr/share/licenses/$1"; echo text > "$I/usr/share/licenses/$1/$2"; }

lic zlib LICENSE; lic kryptik LICENSE
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"no licence files: bash"* && "$out" != *"glibc-fhs-patch"* ]] \
    && ok "a source with no licence files fails, by name; an excepted one does not" || bad "missing bash: rc=$rc: $out"
mkdir -p "$I/usr/share/licenses/bash"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"no licence files: bash"* ]] && ok "an empty directory is not a licence" || bad "empty dir: rc=$rc: $out"
lic bash COPYING
out="$(check)"; rc=$?
[[ "$rc" -eq 0 ]] && ok "every source covered, and Kryptik's own: it passes" || bad "all covered: rc=$rc: $out"
rm -r "$I/usr/share/licenses/kryptik"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"no licence files: kryptik"* ]] && ok "Kryptik's own licence is required too" || bad "no kryptik: rc=$rc: $out"
printf '#!/usr/bin/env bash\ntrue\n' > "$R/tools/fetch-sources.sh"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"named no sources"* ]] && ok "an empty source list passes nothing" || bad "empty list: rc=$rc: $out"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
