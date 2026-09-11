#!/usr/bin/env bash
# Focused tests for tools/scan-licenses.sh.
#
#   ./tools/test-scan-licenses.sh
#
# Deterministic and offline. Fixture tarballs are built here, each carrying a
# real excerpt of the licence it is meant to be identified as, and the tool is
# run against a substituted manifest of file:// URLs.
#
# The cases worth having are the ones where a classifier is confidently wrong:
#
#   * a dual licence in ONE file - libcap offers BSD-3-Clause or GPL-2.0, and
#     a scanner that returns on the first match reports one and hides the
#     other;
#   * two licence files - bc ships COPYING and COPYING.LIB;
#   * LGPL-3.0, whose text incorporates GPL-3.0 by reference, so a naive
#     scanner reports a dual licence that is not one;
#   * case - zlib's condition reads "2. Altered source versions must be
#     plainly marked as such", and a case-sensitive pattern reported zlib's
#     own licence as unknown;
#   * no licence file, and a .patch that is not an archive at all, which are
#     different facts from "unknown".
#
# Positive controls throughout: the recognisable licences must be recognised,
# or a scanner that answered `unknown` to everything would satisfy the rest.

set -uo pipefail

# See the same note in the other suites.
unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="${ROOT}/tools/scan-licenses.sh"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

W="$(mktemp -d)"
OUT="${W}/out"
trap 'rm -rf "$W"' EXIT

SRC="${W}/sources"
FAKE="${W}/root"
mkdir -p "$SRC"

# --- licence texts, as upstream writes them ---------------------------------

mkdir -p "${W}/texts"
t() { cat > "${W}/texts/$1"; }

t gpl3 <<'EOF'
                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.
EOF

t gpl2 <<'EOF'
		    GNU GENERAL PUBLIC LICENSE
		       Version 2, June 1991

 Copyright (C) 1989, 1991 Free Software Foundation, Inc.
EOF

# The LGPL v3 is short and says it incorporates the GPL v3 by reference. A
# scanner that adds both reports a dual licence where there is one.
t lgpl3 <<'EOF'
                   GNU LESSER GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

  This version of the GNU Lesser General Public License incorporates
the terms and conditions of version 3 of the GNU General Public
License, supplemented by the additional permissions listed below.
EOF

t lgpl21 <<'EOF'
		  GNU LESSER GENERAL PUBLIC LICENSE
		       Version 2.1, February 1999
EOF

t mit <<'EOF'
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software.
EOF

t isc <<'EOF'
Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.
EOF

t zlib <<'EOF'
  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
EOF

t bsd3 <<'EOF'
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.
EOF

t apache2 <<'EOF'
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/
EOF

# One file, two licences - this is libcap's shape.
t dual_in_one <<'EOF'
Redistribution and use in source and binary forms of libcap, with or without
modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain any existing copyright notice.
2. Neither the name of the copyright holder may be used to endorse products.

Alternatively, this product may be distributed under the terms of the
                    GNU GENERAL PUBLIC LICENSE
                       Version 2, June 1991
EOF

# --- fixture tarballs -------------------------------------------------------

# pkg <name> <licence-filename>=<text> ...
pkg() {
    local name="$1"; shift
    local dir="${W}/build/${name}-1.0"
    rm -rf "${W}/build"; mkdir -p "$dir"
    printf 'int main(void){return 0;}\n' > "${dir}/main.c"
    local spec
    for spec in "$@"; do
        cp "${W}/texts/${spec#*=}" "${dir}/${spec%%=*}"
    done
    tar czf "${SRC}/${name}-1.0.tar.gz" -C "${W}/build" "${name}-1.0"
}

pkg gplpkg    COPYING=gpl3
pkg gpl2pkg   COPYING=gpl2
pkg lgplpkg   COPYING=lgpl3
pkg lgpl21pkg COPYING=lgpl21
pkg mitpkg    LICENSE=mit
pkg iscpkg    COPYING=isc
pkg zlibpkg   LICENSE=zlib
pkg bsdpkg    COPYING=bsd3
pkg apachepkg LICENSE.txt=apache2
pkg dualfiles COPYING=gpl3 COPYING.LIB=lgpl3
pkg dualinone License=dual_in_one
pkg nolicence
printf 'diff --git a/x b/x\n' > "${SRC}/patchy-1.0.patch"

# --- harness ----------------------------------------------------------------

MANIFEST="${W}/manifest"
{
    for n in gplpkg gpl2pkg lgplpkg lgpl21pkg mitpkg iscpkg zlibpkg bsdpkg \
             apachepkg dualfiles dualinone nolicence; do
        printf '%s|1.0|file://%s/%s-1.0.tar.gz\n' "$n" "$SRC" "$n"
    done
    printf 'patchy|1.0|file://%s/patchy-1.0.patch\n' "$SRC"
    printf 'missingpkg|1.0|file://%s/missingpkg-1.0.tar.gz\n' "$SRC"
} > "$MANIFEST"

build_root() {
    rm -rf "$FAKE"
    mkdir -p "${FAKE}/build/config" "${FAKE}/tools"
    : > "${FAKE}/build/config/versions.env"
    cat > "${FAKE}/tools/fetch-sources.sh" <<STUB
#!/usr/bin/env bash
# Test stub: the same three columns as \`fetch-sources.sh --list\`.
sed 's/|/ /g' "$MANIFEST"
STUB
    chmod 755 "${FAKE}/tools/fetch-sources.sh"
}

run() {
    KRYPTIK_ROOT="$FAKE" KRYPTIK_SOURCES="$SRC" NO_COLOR=1 \
        bash "$TOOL" "$@" > "$OUT" 2>&1
}

field() { awk -F'\t' -v s="$1" -v n="$2" '$1==s{print $n; exit}' "$OUT"; }

expect() {
    local name="$1" want_spdx="$2" want_multi="$3"
    local got_spdx got_multi
    got_spdx="$(field "$name" 3)"
    got_multi="$(field "$name" 4)"
    if [[ "$got_spdx" == "$want_spdx" && "$got_multi" == "$want_multi" ]]; then
        green "${name}: ${want_spdx} (multi=${want_multi})"
    else
        red "${name}: expected [${want_spdx} multi=${want_multi}], got [${got_spdx:-none} multi=${got_multi:-none}]"
    fi
}

echo "tools/scan-licenses.sh"
echo

build_root
run --refresh

# --- positive controls: the recognisable ones must be recognised ------------

expect gplpkg    GPL-3.0    no
expect gpl2pkg   GPL-2.0    no
expect mitpkg    MIT        no
expect iscpkg    ISC        no
expect apachepkg Apache-2.0 no
expect bsdpkg    BSD-3-Clause no

# Case-insensitivity: zlib's condition is capitalised mid-sentence.
expect zlibpkg   Zlib       no

# --- the traps --------------------------------------------------------------

# LGPL-3.0 incorporates GPL-3.0 by reference; that is one licence, not two.
expect lgplpkg   LGPL-3.0   no
expect lgpl21pkg LGPL-2.1   no

# Two licence FILES is genuinely two licences.
expect dualfiles GPL-3.0,LGPL-3.0 yes

# One file offering a choice is also genuinely two.
expect dualinone BSD-3-Clause,GPL-2.0 yes

# --- absence is not unknown -------------------------------------------------

expect nolicence unknown no
if [[ "$(field nolicence 6)" == "no-top-level-licence-file" ]]; then
    green "nolicence: method says no licence file was present"
else
    red "nolicence: method was [$(field nolicence 6)]"
fi

expect patchy unknown no
if [[ "$(field patchy 6)" == "not-an-archive" ]]; then
    green "patchy: a .patch is reported as not-an-archive"
else
    red "patchy: method was [$(field patchy 6)]"
fi

expect missingpkg unknown no
if [[ "$(field missingpkg 6)" == "not-downloaded" ]]; then
    green "missingpkg: an absent tarball is reported as not-downloaded"
else
    red "missingpkg: method was [$(field missingpkg 6)]"
fi

# The three above must be distinguishable from each other, or "unknown" would
# be doing three jobs.
a="$(field nolicence 6)"; b="$(field patchy 6)"; c="$(field missingpkg 6)"
if [[ "$a" != "$b" && "$b" != "$c" && "$a" != "$c" ]]; then
    green "the three kinds of 'no answer' are distinct in the method column"
else
    red "the no-answer methods collide: ${a} / ${b} / ${c}"
fi

# --- every row carries the tarball digest it was derived from ---------------

digest="$(field gplpkg 2)"
real="$(sha256sum "${SRC}/gplpkg-1.0.tar.gz" | cut -d' ' -f1)"
if [[ "$digest" == "$real" ]]; then
    green "each row records the sha256 of the tarball it was read from"
else
    red "digest mismatch: row ${digest}, file ${real}"
fi

# --- the cache is keyed by content, not by name -----------------------------

run   # second run, cache warm
expect gplpkg GPL-3.0 no
before="$(grep -c . "${FAKE}/build/work/licences.cache" || true)"

# Change the bytes; the cache key changes with them, so the answer is re-derived
# rather than served stale.
pkg gplpkg COPYING=mit
run
if [[ "$(field gplpkg 3)" == "MIT" ]]; then
    green "changed tarball bytes are rescanned, not served from cache"
else
    red "a changed tarball kept its cached answer [$(field gplpkg 3)]"
fi
after="$(grep -c . "${FAKE}/build/work/licences.cache" || true)"
if [[ "$after" -gt "$before" ]]; then
    green "the rescan added a cache entry rather than replacing one"
else
    red "cache did not grow: ${before} -> ${after}"
fi

# --- --only ------------------------------------------------------------------

run --only=mitpkg
if [[ "$(grep -c . "$OUT")" -eq 1 && "$(field mitpkg 3)" == "MIT" ]]; then
    green "--only scans exactly one source"
else
    red "--only returned $(grep -c . "$OUT") rows"
fi

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} of $((PASS + FAIL)) checks failed."
    exit 1
fi
echo "All ${PASS} checks passed."
