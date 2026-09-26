#!/usr/bin/env bash
# Tests for tools/release-channel.sh, offline, with throwaway ed25519 keys.

set -uo pipefail

# Exported values would override common.sh's derived paths and the signers file.
unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT
unset KRYPTIK_RELEASE_SIGNERS

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="${ROOT}/tools/release-channel.sh"
MTOOL="${ROOT}/tools/release-manifest.sh"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

for t in ssh-keygen sha256sum stat flock; do
    command -v "$t" >/dev/null 2>&1 || { echo "${t} required"; exit 1; }
done

W="$(mktemp -d)"
OUT="${W}/out"
trap 'rm -rf "$W"' EXIT
show() { sed 's/^/        /' "$OUT"; }

mkdir -p "${W}/keys"
ssh-keygen -q -t ed25519 -N '' -C release -f "${W}/keys/release" </dev/null
ssh-keygen -q -t ed25519 -N '' -C latest  -f "${W}/keys/latest"  </dev/null
KEY="${W}/keys/latest"

# The image's anchor: each key held to its own namespace, as stage 04 enrols them.
SIGNERS="${W}/keys/release-signers"
{
    printf 'kryptik-release namespaces="kryptik-release" %s\n' "$(cut -d' ' -f1,2 < "${W}/keys/release.pub")"
    printf 'kryptik-latest namespaces="kryptik-latest" %s\n' "$(cut -d' ' -f1,2 < "${W}/keys/latest.pub")"
} > "$SIGNERS"

# Half-made keys would show up as a dozen misleading failures below.
for _f in "$KEY" "${W}/keys/release" "$SIGNERS"; do
    [[ -s "$_f" ]] || { echo "FATAL: ssh-keygen did not make ${_f}" >&2; exit 1; }
done

make_payload() {   # make_payload DIR VERSION [NOTE]: a signed stand-in for stage 06's payload
    rm -rf "$1"; mkdir -p "$1"
    local f
    for f in kryptik-root.img kryptik-a.efi kryptik-b.efi root.json; do
        printf 'pretend %s of %s %s\n' "$f" "$2" "${3:-}" > "$1/$f"
    done
    if ! NO_COLOR=1 bash "$MTOOL" create --out "$1/manifest" --name kryptik --version "$2" \
            --role development --root "$1" kryptik-root.img kryptik-a.efi kryptik-b.efi root.json \
            > /dev/null 2>&1 \
        || ! NO_COLOR=1 bash "$MTOOL" sign --key "${W}/keys/release" "$1/manifest" > /dev/null 2>&1; then
        echo "FATAL: release-manifest.sh could not make the ${2} payload" >&2
        exit 1
    fi
}

field() { awk -F': ' -v k="$2" '$1 == k { print $2; exit }' "$1"; }
# As zone 0 checks a statement: the anchor, the kryptik-latest principal and namespace.
verifies() {
    ssh-keygen -Y verify -f "$SIGNERS" -I kryptik-latest -n kryptik-latest \
        -s "$1/latest.sig" < "$1/latest" > /dev/null 2>&1
}
channel() {   # channel MODE ARGS...: the tool with this test's anchor; output in $OUT
    local mode="$1"; shift
    NO_COLOR=1 bash "$TOOL" "$mode" --signers "$SIGNERS" "$@" > "$OUT" 2>&1
}
CH="${W}/channel"
pair() { sha256sum "${CH}/latest" "${CH}/latest.sig" 2>/dev/null; }

make_payload "${W}/p1" 1.0.1
channel publish --key "$KEY" --payload "${W}/p1" --out "$CH" --issued 2026-09-01T00:00:00+00:00
rc=$?
if [[ "$rc" -eq 0 ]] && verifies "$CH" \
    && [[ "$(field "${CH}/latest" version)" == 1.0.1 && "$(field "${CH}/latest" base)" == 1.0.1/ \
          && "$(field "${CH}/latest" manifest-sha256)" == "$(sha256sum "${CH}/1.0.1/manifest" | cut -c1-64)" ]]; then
    green "publish writes a statement a client accepts, naming the release under the channel"
else
    red "publish into an empty channel (exit ${rc})"; show
fi

if NO_COLOR=1 bash "$MTOOL" verify --signers "$SIGNERS" --principal kryptik-release \
        --root "${CH}/1.0.1" --exact --strict "${CH}/1.0.1/manifest" > "$OUT" 2>&1; then
    green "the release's directory verifies as the payload does"
else
    red "the release's directory does not verify"; show
fi

if [[ "$(stat -c %i "${W}/p1/kryptik-root.img")" == "$(stat -c %i "${CH}/1.0.1/kryptik-root.img")" ]]; then
    green "the payload's files are linked, not copied"
else
    red "the payload's files were copied"
fi

make_payload "${W}/p2" 1.0.2
channel publish --key "$KEY" --payload "${W}/p2" --out "$CH" --issued 2026-09-02T00:00:00+00:00
rc=$?
if [[ "$rc" -eq 0 && "$(field "${CH}/latest" version)" == 1.0.2 && -f "${CH}/1.0.1/manifest" ]] && verifies "$CH"; then
    green "a newer release becomes current, and the older stays published"
else
    red "publishing a newer release (exit ${rc})"; show
fi

before="$(pair)"
channel publish --key "$KEY" --payload "${W}/p1" --out "$CH"
rc=$?
if [[ "$rc" -ne 0 && "$(pair)" == "$before" ]] && grep -q "older than the installed 1.0.2" "$OUT"; then
    green "an older release is refused (release-manifest.sh's sort -V order)"
else
    red "an older release was not refused (exit ${rc})"; show
fi

make_payload "${W}/p3" 1.0.3
printf 'tampered\n' >> "${W}/p3/kryptik-root.img"
channel publish --key "$KEY" --payload "${W}/p3" --out "$CH"
rc=$?
if [[ "$rc" -ne 0 && ! -e "${CH}/1.0.3" && ! -e "${CH}/.1.0.3.new" && "$(pair)" == "$before" ]]; then
    green "a payload that does not verify is refused before anything is written"
else
    red "a tampered payload was published (exit ${rc})"; show
fi

make_payload "${W}/p2b" 1.0.2 rebuilt
channel publish --key "$KEY" --payload "${W}/p2b" --out "$CH"
rc=$?
if [[ "$rc" -ne 0 && "$(pair)" == "$before" ]] && grep -q "already published with another manifest" "$OUT" \
    && cmp -s "${W}/p2/manifest" "${CH}/1.0.2/manifest"; then
    green "a published version never changes"
else
    red "a published version was replaced (exit ${rc})"; show
fi

# The release key signs in the wrong namespace for a statement: signed, but refused.
make_payload "${W}/p4" 1.0.4
channel publish --key "${W}/keys/release" --payload "${W}/p4" --out "$CH"
rc=$?
if [[ "$rc" -ne 0 && "$(pair)" == "$before" && ! -e "${CH}/.latest.new" && ! -e "${CH}/.latest.new.sig" ]] \
    && verifies "$CH" && grep -q "does not verify against" "$OUT"; then
    green "a statement a client would refuse is not installed, and the old pair stays"
else
    red "a statement signed by the wrong key was installed (exit ${rc})"; show
fi

channel publish --key "$KEY" --payload "${W}/p4" --out "$CH" --issued 2026-09-04T00:00:00+00:00
rc=$?
if [[ "$rc" -eq 0 && "$(field "${CH}/latest" version)" == 1.0.4 ]] && verifies "$CH"; then
    green "the same publish with the right key completes it"
else
    red "publishing again after a refused statement (exit ${rc})"; show
fi

cp "${CH}/latest" "${W}/latest.before"
channel reissue --key "$KEY" --issued 2026-09-20T00:00:00+00:00 "$CH"
rc=$?
if [[ "$rc" -eq 0 && "$(field "${CH}/latest" issued)" == 2026-09-20T00:00:00+00:00 ]] && verifies "$CH" \
    && diff <(grep -v '^issued: ' "${W}/latest.before") <(grep -v '^issued: ' "${CH}/latest") > /dev/null; then
    green "reissue signs the same statement again with a later date"
else
    red "reissue (exit ${rc})"; show
fi

before="$(pair)"
channel reissue --key "$KEY" --issued 2026-09-10T00:00:00+00:00 "$CH"
rc=$?
if [[ "$rc" -ne 0 && "$(pair)" == "$before" ]] && grep -q "replay" "$OUT"; then
    green "an earlier date is refused: clients would take it for a replay"
else
    red "an earlier date was signed (exit ${rc})"; show
fi

channel reissue --key "$KEY" --issued "$(date -u -d '+3 days' +%Y-%m-%dT%H:%M:%S+00:00)" "$CH"
rc=$?
if [[ "$rc" -ne 0 && "$(pair)" == "$before" ]] && grep -q "more than a day ahead" "$OUT"; then
    green "a date more than a day ahead is refused"
else
    red "a date days ahead was signed (exit ${rc})"; show
fi

channel reissue --key "$KEY" --issued 2026-09-30 "$CH"
rc=$?
if [[ "$rc" -ne 0 && "$(pair)" == "$before" ]] && grep -q "is not YYYY-MM-DDTHH:MM:SS" "$OUT"; then
    green "a date zone 0 cannot read is refused"
else
    red "an unreadable date was signed (exit ${rc})"; show
fi

# Another manifest of the same version put in place: reissue must not vouch for it.
# The files are links into the payload, so they are removed, not written over.
make_payload "${W}/p4b" 1.0.4 rebuilt
rm "${CH}/1.0.4/manifest" "${CH}/1.0.4/manifest.sig"
cp "${W}/p4b/manifest" "${W}/p4b/manifest.sig" "${CH}/1.0.4/"
channel reissue --key "$KEY" "$CH"
rc=$?
if [[ "$rc" -ne 0 && "$(pair)" == "$before" ]] && grep -q "not the manifest the statement names" "$OUT"; then
    green "reissue refuses a manifest other than the one the statement names"
else
    red "reissue signed a replaced manifest (exit ${rc})"; show
fi
rm "${CH}/1.0.4/manifest" "${CH}/1.0.4/manifest.sig"
cp "${W}/p4/manifest" "${W}/p4/manifest.sig" "${CH}/1.0.4/"

cp "${CH}/latest" "${W}/latest.kept"
sed -i 's/^version: .*/version: 9.9.9/' "${CH}/latest"
channel reissue --key "$KEY" "$CH"
rc1=$?
make_payload "${W}/p5" 1.0.5
channel publish --key "$KEY" --payload "${W}/p5" --out "$CH"
rc2=$?
if [[ "$rc1" -ne 0 && "$rc2" -ne 0 && ! -e "${CH}/1.0.5" ]] && grep -q "does not verify against" "$OUT"; then
    green "a statement that no longer verifies is neither signed again nor built on"
else
    red "a tampered statement was used (reissue exit ${rc1}, publish exit ${rc2})"; show
fi
cp "${W}/latest.kept" "${CH}/latest"

exec 8< "$CH"
flock -n 8
channel reissue --key "$KEY" "$CH"
rc=$?
exec 8<&-
if [[ "$rc" -ne 0 && "$(pair)" == "$before" ]] && grep -q "another publish or reissue" "$OUT"; then
    green "one run at a time per channel"
else
    red "a second run went ahead (exit ${rc})"; show
fi

if grep -rlq "PRIVATE KEY" "$CH"; then
    red "a private key is in the channel"
else
    green "no private key is in the channel"
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
