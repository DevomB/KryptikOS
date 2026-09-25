#!/usr/bin/env bash
# Tests for build/lib/release-keys.sh, the keys stage 06 signs with, in both
# roles. The keys are throwaway ones made here and handed over by path only.

set -uo pipefail

# Exported values would override the paths each case sets.
unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT KRYPTIK_KEYS KRYPTIK_ROLE

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

for t in ssh-keygen openssl stat sha256sum; do
    command -v "$t" >/dev/null 2>&1 || { echo "${t} required"; exit 1; }
done

W="$(mktemp -d)"
OUT="${W}/out"
trap 'rm -rf "$W"' EXIT
show() { sed 's/^/        /' "$OUT"; }
mkdir -p "${W}/built"

# keys ROLE WORK [MEDIUM]: release_keys in a fresh bash, as stage 06 calls it,
# with WORK as the work tree; its output, then the paths it chose, in $OUT.
keys() {
    KRYPTIK_WORK="$2" KRYPTIK_OUT="${W}/built" KRYPTIK_KEYS="${3:-}" NO_COLOR=1 \
        bash -c 'source "$1/build/lib/common.sh"; source "$1/build/lib/release-keys.sh"
                 release_keys "$2"
                 printf "ANCHOR=%s\nRELEASE_KEY=%s\nLATEST_KEY=%s\nSB_KEY=%s\nSB_CERT=%s\n" \
                     "$ANCHOR" "$RELEASE_KEY" "$LATEST_KEY" "$SB_KEY" "$SB_CERT"' \
        _ "$ROOT" "$1" > "$OUT" 2>&1
}
got() { sed -n "s/^$1=//p" "$OUT"; }

# --- development --------------------------------------------------------------
DW="${W}/dev-work"
keys development "$DW"; rc=$?
if [[ "$rc" -eq 0 && "$(got RELEASE_KEY)" == "${DW}/keys/release/kryptik-release" \
      && "$(got ANCHOR)" == "${DW}/keys/release/release-signers" && "$(got SB_CERT)" == "${DW}/keys/sb/kryptik-sb.crt" \
      && -f "${DW}/keys/sb/kryptik-sb.der" ]]; then
    green "development: the keys and the anchor are made on first use, and each key verifies in its own namespace alone"
else
    red "development on an empty work tree (exit ${rc})"; show
fi
first="$(sha256sum "${DW}/keys/release/kryptik-release.pub" "${DW}/keys/release/kryptik-latest.pub" "${DW}/keys/sb/kryptik-sb.crt" 2>&1)"
keys development "$DW"; rc=$?
if [[ "$rc" -eq 0 && "$(sha256sum "${DW}/keys/release/kryptik-release.pub" "${DW}/keys/release/kryptik-latest.pub" "${DW}/keys/sb/kryptik-sb.crt" 2>&1)" == "$first" ]]; then
    green "development: keys once made are kept"
else
    red "development made new keys over existing ones (exit ${rc})"; show
fi
# A developer anchor that lists the release key for statements too is caught.
sed -i 's/^\(kryptik-latest namespaces="kryptik-latest"\) .*/\1 '"$(cut -d' ' -f1,2 < "${DW}/keys/release/kryptik-release.pub" | sed 's/[\/&]/\\&/g')"'/' "${DW}/keys/release/release-signers"
KRYPTIK_WORK="$DW" NO_COLOR=1 bash -c 'source "$1/build/lib/common.sh"; source "$1/build/lib/release-keys.sh"
    ANCHOR="$2/keys/release/release-signers"; RELEASE_KEY="$2/keys/release/kryptik-release"; LATEST_KEY="$2/keys/release/kryptik-latest"
    probe_anchor' _ "$ROOT" "$DW" > "$OUT" 2>&1; rc=$?
if [[ "$rc" -ne 0 ]] && grep -q "accepted a probe signed by kryptik-release in kryptik-latest" "$OUT"; then
    green "the probe catches an anchor that takes the release key for statements"
else
    red "the probe passed an anchor listing the release key twice (exit ${rc})"; show
fi

# --- production -----------------------------------------------------------------
PW="${W}/prod-work"; mkdir -p "$PW"
M="${W}/medium"
make_medium() {   # a complete key medium, as the ceremony leaves it
    rm -rf "$M"; mkdir -p "$M"; chmod 0700 "$M"
    ssh-keygen -q -t ed25519 -N '' -C 'kryptik-release (test)' -f "$M/kryptik-release" < /dev/null
    ssh-keygen -q -t ed25519 -N '' -C 'kryptik-latest (test)' -f "$M/kryptik-latest" < /dev/null
    {
        printf 'kryptik-release namespaces="kryptik-release" %s\n' "$(cut -d' ' -f1,2 < "$M/kryptik-release.pub")"
        printf 'kryptik-latest namespaces="kryptik-latest" %s\n' "$(cut -d' ' -f1,2 < "$M/kryptik-latest.pub")"
    } > "$M/release-signers"
    openssl req -new -x509 -newkey rsa:2048 -nodes -days 30 -sha256 -subj "/CN=test Secure Boot key/" \
        -keyout "$M/kryptik-sb.key" -out "$M/kryptik-sb.crt" 2>/dev/null
    chmod 0600 "$M/kryptik-sb.key"
}
refused() {   # refused WHAT GREP: the medium as it stands must be refused, saying GREP
    keys production "$PW" "$M"; rc=$?
    if [[ "$rc" -ne 0 ]] && grep -q -- "$2" "$OUT"; then green "production refuses $1"; else red "production took $1 (exit ${rc})"; show; fi
}

keys production "$PW"; rc=$?
if [[ "$rc" -ne 0 ]] && grep -q "set KRYPTIK_KEYS" "$OUT"; then
    green "production refuses to run without a key medium"
else
    red "production ran without KRYPTIK_KEYS (exit ${rc})"; show
fi

make_medium
keys production "$PW" "$M"; rc=$?
if [[ "$rc" -eq 0 && "$(got RELEASE_KEY)" == "${M}/kryptik-release" && "$(got LATEST_KEY)" == "${M}/kryptik-latest" \
      && "$(got SB_KEY)" == "${M}/kryptik-sb.key" && "$(got ANCHOR)" == "${M}/release-signers" ]]; then
    green "production signs with the medium's keys, by path"
else
    red "production with a complete medium (exit ${rc})"; show
fi
if [[ ! -e "${PW}/keys" ]] && ! grep -rlq "PRIVATE KEY" "$PW" "${W}/built"; then
    green "production makes no key, and no private key reaches the work or output tree"
else
    red "production wrote under the work tree: $(find "$PW" "${W}/built" -type f | head -3 | tr '\n' ' ')"
fi

rm "$M/kryptik-latest" "$M/kryptik-latest.pub"
keys production "$PW" "$M"; rc=$?
if [[ "$rc" -eq 0 && -z "$(got LATEST_KEY)" ]]; then
    green "a medium without the statement key leaves the channel to the release host"
else
    red "a medium without kryptik-latest (exit ${rc})"; show
fi

for f in release-signers kryptik-release kryptik-release.pub kryptik-sb.key kryptik-sb.crt; do
    make_medium; rm "$M/$f"
    refused "a medium without ${f}" "has no ${f}"
done
make_medium; rm "$M/kryptik-latest.pub"
refused "a statement key without its public half" "kryptik-latest but no kryptik-latest.pub"

make_medium; mv "$M/kryptik-release.pub" "${W}/elsewhere.pub"; ln -s "${W}/elsewhere.pub" "$M/kryptik-release.pub"
refused "a symlinked file" "is a symlink"

make_medium; chmod 0644 "$M/kryptik-release"
refused "a release key others can read" "kryptik-release is mode 644"
make_medium; chmod 0640 "$M/kryptik-sb.key"
refused "a Secure Boot key its group can read" "kryptik-sb.key is mode 640"
if [[ "$EUID" -eq 0 ]]; then
    make_medium; chown 12345 "$M/kryptik-release"
    refused "a release key owned by someone else" "belongs to uid 12345"
fi

rm -rf "${PW}/medium"; M="${PW}/medium"; make_medium
refused "a medium inside the work tree" "is inside"
M="${W}/medium"

make_medium; sed -i '2d' "$M/release-signers"
refused "an anchor without the statement key" "must list both"
make_medium; sed -i 's/namespaces="kryptik-latest"/namespaces="kryptik-release"/' "$M/release-signers"
refused "an anchor that lets the statement key sign releases" "not held to its own namespace"
make_medium; sed -i '1p' "$M/release-signers"
refused "an anchor listing a principal twice" "listed twice"
make_medium; printf 'someone namespaces="someone" %s\n' "$(cut -d' ' -f1,2 < "$M/kryptik-release.pub")" >> "$M/release-signers"
refused "an anchor with a third principal" "neither kryptik-release nor kryptik-latest"
make_medium; sed -i "2s|ssh-ed25519 [^ ]*|$(cut -d' ' -f1,2 < "$M/kryptik-release.pub" | sed 's/[\/&|]/\\&/g')|" "$M/release-signers"
refused "an anchor with one key for both" "are the same key"
make_medium; cp "$M/kryptik-latest.pub" "$M/kryptik-release.pub"
refused "a release key the anchor does not list" "kryptik-release.pub is not the key"
make_medium; printf 'not a certificate\n' > "$M/kryptik-sb.crt"
refused "a Secure Boot certificate that is not one" "not a certificate in force"

keys staging "$PW" "$M"; rc=$?
if [[ "$rc" -ne 0 ]] && grep -q "development or production" "$OUT"; then
    green "a role other than development or production is refused"
else
    red "an unknown role was taken (exit ${rc})"; show
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
