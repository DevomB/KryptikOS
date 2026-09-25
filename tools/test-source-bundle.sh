#!/usr/bin/env bash
# tools/source-bundle.sh on a fake tree: a git checkout with a sources.lock,
# downloaded tarballs and a signature, and a stand-in cargo. The bundle holds
# each tarball as locked, its signature, the repository at the commit and the
# crates, and its MANIFEST verifies; a mismatched, missing or dirty input is
# refused.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
command -v git >/dev/null || { echo "git required"; exit 1; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
R="$T/repo"; S="$T/sources"
mkdir -p "$R/tools" "$R/build/lib" "$R/build/config" "$R/build/patches/demo" \
         "$R/compartments/kryptikd" "$R/compositor" "$S/.signatures" "$T/bin"
cp "$ROOT/tools/source-bundle.sh" "$R/tools/"
cp "$ROOT/build/lib/common.sh" "$R/build/lib/"
: > "$R/build/config/versions.env"
echo patch > "$R/build/patches/demo/0001.patch"
printf 'demo-1.0\n' > "$T/demo.txt"; tar -C "$T" -czf "$S/demo-1.0.tar.gz" demo.txt
printf 'sig\n' > "$S/.signatures/demo-1.0.tar.gz.sig"
printf '%s  demo-1.0.tar.gz\n' "$(sha256sum "$S/demo-1.0.tar.gz" | cut -c1-64)" > "$R/sources.lock"
cat > "$R/tools/fetch-sources.sh" <<'EOF'
#!/usr/bin/env bash
echo "demo 1.0 https://example.org/demo-1.0.tar.gz"
EOF
chmod 755 "$R/tools/fetch-sources.sh"
# A stand-in cargo: vendor writes one crate where it is asked to.
cat > "$T/bin/cargo" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == vendor ]] || exit 1
mkdir -p "${@: -1}/demo-crate-0.1.0" && echo crate > "${@: -1}/demo-crate-0.1.0/lib.rs"
EOF
chmod 755 "$T/bin/cargo"
git -C "$R" init -q && git -C "$R" add -A \
    && git -C "$R" -c user.name=test -c user.email=test@example.invalid commit -q -m fixture
commit="$(git -C "$R" rev-parse HEAD)"

bundle() {   # bundle OUT: run the tool on the fixture
    PATH="$T/bin:$PATH" KRYPTIK_ROOT="$R" KRYPTIK_SOURCES="$S" KRYPTIK_WORK="$T/work" KRYPTIK_OUT="$T/out" \
        NO_COLOR=1 bash "$R/tools/source-bundle.sh" --out "$1" 2>&1
}

out="$(bundle "$T/b1")"; rc=$?
[[ "$rc" -eq 0 ]] && ok "a clean tree with its sources makes a bundle" || bad "bundle: rc=$rc: $out"
[[ -f "$T/b1/sources/demo-1.0.tar.gz" && -f "$T/b1/signatures/demo-1.0.tar.gz.sig" && -f "$T/b1/sources.lock" ]] \
    && ok "it holds the locked tarball, its signature and sources.lock" || bad "tarball, signature or lock missing"
[[ -f "$T/b1/kryptik-${commit:0:12}.tar.gz" ]] && tar -tzf "$T/b1/kryptik-${commit:0:12}.tar.gz" | grep -q 'build/patches/demo/0001.patch' \
    && ok "and the repository at the commit, patches included" || bad "the repository archive is missing or incomplete"
[[ -f "$T/b1/crates/kryptikd/demo-crate-0.1.0/lib.rs" && -f "$T/b1/crates/compositor/demo-crate-0.1.0/lib.rs" ]] \
    && ok "and the crates of both Rust workspaces" || bad "crates missing"
{ head -1 "$T/b1/MANIFEST" | grep -q "$commit" && (cd "$T/b1" && tail -n +2 MANIFEST | sha256sum --quiet -c); } \
    && ok "its MANIFEST names the commit and every file verifies" || bad "MANIFEST does not verify"
[[ -f "$T/b1.tar" ]] && ok "and the whole is one tar" || bad "no ${T}/b1.tar"

echo tampered >> "$S/demo-1.0.tar.gz"
out="$(bundle "$T/b2")"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"does not match sources.lock"* ]] && ok "a tarball that differs from sources.lock is refused" || bad "tampered tarball: rc=$rc: $out"
rm "$S/demo-1.0.tar.gz"
out="$(bundle "$T/b3")"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"not downloaded"* ]] && ok "so is one that is not downloaded" || bad "missing tarball: rc=$rc: $out"
echo stray > "$R/stray.txt"
out="$(bundle "$T/b4")"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"uncommitted changes"* ]] && ok "and a tree with uncommitted changes" || bad "dirty tree: rc=$rc: $out"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
