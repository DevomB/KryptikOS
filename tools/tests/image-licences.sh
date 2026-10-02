#!/usr/bin/env bash
# tools/check-image-licences.sh on a staged root, then header_notices on a libdrm-like tarball.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
R="$T/repo"; I="$T/image"
mkdir -p "$R/tools" "$R/build/lib" "$R/build/config" "$I/usr/share/licenses"
cp "$ROOT/tools/check-image-licences.sh" "$R/tools/"
cp "$ROOT/build/lib/common.sh" "$R/build/lib/"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "zlib 1.3 https://x/zlib-1.3.tar.xz probe github" "bash 5.3 https://x/bash-5.3.tar.gz gnu gnu" "glibc-fhs-patch 2.40 https://x/glibc-2.40-fhs-1.patch none follows:glibc"\n' > "$R/tools/fetch-sources.sh"
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

# header_notices, under the options and ERR trap a stage runs with.
S="$T/src/drm-1"; mkdir -p "$S"
mit=' * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS". IN NO EVENT SHALL THE AUTHORS BE LIABLE
 * FOR ANY CLAIM ARISING FROM THE SOFTWARE OR OTHER DEALINGS IN THE SOFTWARE.'
printf '/**\n * \\file a.c\n * \\author Someone\n */\n\n/*\n * Copyright 1999 First Holder.\n * All Rights Reserved.\n *\n%s\n */\n\nint a;\n' "$mit" > "$S/a.c"
printf '/* b.c -- a hash table\n *\n * Copyright 2000 Second Holder.\n *\n%s\n *\n * DESCRIPTION\n * Not part of the notice.\n */\n' "$mit" > "$S/b.c"
{ printf '/*\n * Copyright 2001 Third Holder.\n%s\n */\n' "$mit"; head -c 2000000 /dev/zero | tr '\0' 'x'; } > "$S/big.c"
printf '/* no notice here */\nint c;\n' > "$S/c.c"
printf '/*\n * Copyright 2002 Fourth Holder.\n * Licensed some other way.\n */\n' > "$S/d.c"
tar -cJf "$T/drm-1.tar.xz" -C "$T/src" drm-1
notices() { bash -c 'source "$1/build/lib/common.sh"; shift; header_notices "$@"' _ "$ROOT" "$T/drm-1.tar.xz" "$@" 2>&1; }

out="$(notices drm-1/a.c drm-1/b.c)"; rc=$?
[[ "$rc" -eq 0 && "$out" == "a.c:"$'\n\n'"Copyright 1999 First Holder."* && "$out" == *$'\n'"b.c:"$'\n\n'"Copyright 2000 Second Holder."* \
   && "$out" == *"OTHER DEALINGS IN THE SOFTWARE." && "$out" != *'\file'* && "$out" != *DESCRIPTION* && "$out" != *' * '* ]] \
    && ok "each file's notice runs from its Copyright line to the end of the MIT text, without comment marks" || bad "notices: rc=$rc: $out"
out="$(notices drm-1/big.c)"; rc=$?
[[ "$rc" -eq 0 && "$out" == *"Third Holder"* && "$out" != *xxx* ]] && ok "a large file is read to its end, so tar gets no SIGPIPE" || bad "big: rc=$rc: ${out:0:300}"
out="$(notices drm-1/a.c drm-1/c.c)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"no licence notice at the head of drm-1/c.c"* ]] && ok "a file without a notice fails, by name" || bad "no notice: rc=$rc: $out"
out="$(notices drm-1/d.c)"; rc=$?
[[ "$rc" -ne 0 && "$out" != *"Fourth Holder"* ]] && ok "a notice that never reaches the end of the MIT text is not taken" || bad "unended: rc=$rc: $out"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
