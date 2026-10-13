#!/usr/bin/env bash
# tools/check-rust-licences.sh against a staged Rust dist, cargo registry and repository.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
R="$T/repo"; D="$T/dist"; H="$T/cargo"
STD="$D/rust-std-9.9.9-x86_64-unknown-linux-musl"
SC="$STD/rust-std-x86_64-unknown-linux-musl/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained"
DOC="$D/rustc-9.9.9-x86_64-unknown-linux-gnu/rustc/share/doc/rust"
CRATE="$H/registry/src/index.crates.io-0000/libc-0.2.189"
mkdir -p "$R/tools" "$R/build/lib" "$R/compartments/kryptikd" "$R/compositor" \
         "$R/build/licences/rust" "$R/build/licences/rust-libc" "$R/build/licences/musl" \
         "$SC" "$DOC" "$CRATE"
cp "$ROOT/tools/check-rust-licences.sh" "$R/tools/"
cp "$ROOT/build/lib/common.sh" "$R/build/lib/"

for f in COPYRIGHT LICENSE-APACHE LICENSE-MIT; do echo "rust ${f}" > "$STD/$f"; cp "$STD/$f" "$R/build/licences/rust/"; done
echo "<html>library</html>" > "$DOC/COPYRIGHT-library.html"
gzip -9nc "$DOC/COPYRIGHT-library.html" > "$R/build/licences/rust/COPYRIGHT-library.html.gz"
for f in LICENSE-APACHE LICENSE-MIT; do echo "libc ${f}" > "$CRATE/$f"; cp "$CRATE/$f" "$R/build/licences/rust-libc/"; done
echo "musl COPYRIGHT" > "$R/build/licences/musl/COPYRIGHT"
printf '\0\0junk\0\0\0001.2.5\0\0' > "$SC/libc.a"
lock='version = 3

[[package]]
name = "libc"
version = "0.2.189"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2"

[[package]]
name = "kryptikd"
version = "0.1.0"
dependencies = [
 "libc",
]'
printf '%s\n' "$lock" > "$R/compartments/kryptikd/Cargo.lock"
printf '%s\n' "$lock" > "$R/compositor/Cargo.lock"

check() { KRYPTIK_ROOT="$R" CARGO_HOME="$H" NO_COLOR=1 bash "$R/tools/check-rust-licences.sh" "$D" 2>&1; }

out="$(check)"; rc=$?
[[ "$rc" -eq 0 && "$out" == *"matches rust-std-9.9.9"* ]] && ok "every text matches: it passes" || bad "all match: rc=$rc: $out"

echo changed >> "$R/build/licences/rust/LICENSE-MIT"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"build/licences/rust/LICENSE-MIT is not"* ]] && ok "a changed Rust text fails, by name" || bad "rust text: rc=$rc: $out"
cp "$STD/LICENSE-MIT" "$R/build/licences/rust/"

echo "<html>newer</html>" > "$DOC/COPYRIGHT-library.html"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"COPYRIGHT-library.html.gz is not"* ]] && ok "a stale COPYRIGHT-library.html fails" || bad "library: rc=$rc: $out"
gzip -dc "$R/build/licences/rust/COPYRIGHT-library.html.gz" > "$DOC/COPYRIGHT-library.html"

echo changed >> "$CRATE/LICENSE-MIT"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"build/licences/rust-libc/LICENSE-MIT is not"* ]] && ok "a crate text that differs fails, by name" || bad "crate text: rc=$rc: $out"
cp "$R/build/licences/rust-libc/LICENSE-MIT" "$CRATE/"

echo "extra" > "$R/build/licences/rust-libc/NOTES"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"holds files libc 0.2.189 does not ship"* ]] && ok "a file the crate does not ship fails" || bad "extra file: rc=$rc: $out"
rm "$R/build/licences/rust-libc/NOTES"

sed -i 's/0.2.189/0.2.190/' "$R/compositor/Cargo.lock"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"libc 0.2.190 is not in"* ]] && ok "a locked crate missing from the registry fails" || bad "not fetched: rc=$rc: $out"
sed -i 's/0.2.190/0.2.189/' "$R/compositor/Cargo.lock"

mkdir -p "$R/build/licences/rust-gone"; echo text > "$R/build/licences/rust-gone/LICENSE"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"build/licences/rust-gone is for a crate no lockfile fetches"* ]] && ok "a text for a crate no longer locked fails" || bad "stale crate: rc=$rc: $out"
rm -r "$R/build/licences/rust-gone"

printf '\0\0junk\0\0\0001.2.6\0\0' > "$SC/libc.a"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"links a musl other than 1.2.5"* ]] && ok "a rust-std linking another musl fails" || bad "musl: rc=$rc: $out"
printf '\0\0junk\0\0\0001.2.5\0\0' > "$SC/libc.a"

out="$(check)"; rc=$?
[[ "$rc" -eq 0 ]] && ok "restored, it passes again" || bad "restored: rc=$rc: $out"
out="$(KRYPTIK_ROOT="$R" CARGO_HOME="$H" NO_COLOR=1 bash "$R/tools/check-rust-licences.sh" "$T/nothing" 2>&1)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"no unpacked rust-std"* ]] && ok "a dist with no unpacked tarballs fails" || bad "no dist: rc=$rc: $out"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
