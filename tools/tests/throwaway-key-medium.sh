#!/usr/bin/env bash
# tools/throwaway-key-medium.sh makes a medium the build accepts through the
# same checks as a release's (build/lib/release-keys.sh's medium_keys), and
# those checks still refuse it once one of its private keys is loosened.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
for t in ssh-keygen openssl; do command -v "$t" > /dev/null || { echo "${t} required"; exit 77; }; done

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
M="$T/medium"
mint() { NO_COLOR=1 bash "$ROOT/tools/throwaway-key-medium.sh" "$1" 2>&1; }
# medium_keys as stage 06 calls it, with work and out trees of their own.
keys() {
    mkdir -p "$T/work" "$T/out"
    KRYPTIK_KEYS="$1" KRYPTIK_WORK="$T/work" KRYPTIK_OUT="$T/out" NO_COLOR=1 bash -c '
        source "$1/build/lib/common.sh"; source "$1/build/lib/release-keys.sh"
        release_keys production && printf "anchor %s\nsb %s\n" "$ANCHOR" "$SB_CERT"' _ "$ROOT" 2>&1
}

out="$(mint "$M")"; rc=$?
[[ "$rc" -eq 0 ]] && ok "a medium is made" || bad "no medium: rc=$rc: $out"
for f in release-signers kryptik-release kryptik-release.pub kryptik-latest kryptik-latest.pub kryptik-sb.key kryptik-sb.crt; do
    [[ -s "$M/$f" ]] || bad "no ${f} in the medium"
done
out="$(keys "$M")"; rc=$?
[[ "$rc" -eq 0 && "$out" == *"anchor $M/release-signers"* && "$out" == *"sb $M/kryptik-sb.crt"* ]] \
    && ok "the build takes it through the checks a release's medium gets" || bad "medium_keys refused it: rc=$rc: $out"
cn="$(openssl x509 -in "$M/kryptik-sb.crt" -noout -subject 2>/dev/null)"
[[ "$cn" == *"throwaway"* ]] && ok "its Secure Boot certificate says it is a throwaway" || bad "certificate subject: ${cn}"

out="$(mint "$M")"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"exists"* ]] && ok "an existing directory is refused" || bad "made over an existing medium: rc=$rc: $out"

chmod 644 "$M/kryptik-release"
out="$(keys "$M")"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"readable by its owner alone"* ]] && ok "a private key others can read is still refused" || bad "loosened key taken: rc=$rc: $out"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
