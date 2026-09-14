#!/usr/bin/env bash
# kryptik-update reads a payload's manifest ONCE, before it verifies the
# signature, and everything after - the version, the hash list the written
# slot is checked against - comes from that copy.
#
# The defect this guards against: verify_payload verified the signature over
# the manifest in the payload directory and then re-read that same file for
# the version and the hashes. A writer that replaced the manifest between the
# two reads had its unsigned manifest accepted, hashes and all; the review of
# 2026-09-14 reproduced it with the real verifier. This suite runs the real
# verify_payload with a real ssh-keygen and replaces things in the payload
# directory the instant the signature check succeeds. Whatever it replaces,
# the unsigned version 3 must never be what the tool reports.
#
# Needs bash, ssh-keygen (OpenSSH 8.2+ for -Y) and coreutils; no root, no
# devices, no network. Exit 0 when every case passes.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT/tools/update/kryptik-update"
command -v ssh-keygen >/dev/null 2>&1 || { echo "ssh-keygen not found; cannot run"; exit 77; }
# With -Y support the incomplete call complains about find-principals itself;
# without it, about the -Y option.
probe="$(ssh-keygen -Y find-principals 2>&1 || true)"
grep -q "find-principals" <<<"$probe" || { echo "this ssh-keygen has no -Y; cannot run"; exit 77; }

PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
cd "$T" || exit 1

# Two payloads: the signed one (version 2) and an unsigned replacement
# (version 3, different root hash) that a writer will drop in.
mkpayload() {   # mkpayload DIR VERSION
    local d="$1" v="$2" hash
    mkdir -p "$d"
    hash="$(printf '%*s' 64 '' | tr ' ' "$v")"
    printf 'harmless fixture root %s\n' "$v" > "$d/kryptik-root.img"
    printf '%s\n' "$hash" > "$d/kryptik-a.efi"
    printf '%s\n' "$hash" > "$d/kryptik-b.efi"
    # The layout stage 06 writes and the tool reads: one key per line, two spaces in.
    {
        echo "{"
        printf '  "root_hash": "%s",\n' "$hash"
        printf '  "total_bytes": %s,\n' "$(stat -c %s "$d/kryptik-root.img")"
        printf '  "sha256": "%s"\n' "$(sha256sum "$d/kryptik-root.img" | cut -c1-64)"
        echo "}"
    } > "$d/root.json"
    {
        echo "KRYPTIK-MANIFEST-1"
        echo "role: development"
        echo "version: $v"
        echo "files: 4"
        echo "--"
        for f in kryptik-a.efi kryptik-b.efi kryptik-root.img root.json; do
            printf '%s  %s  %s\n' "$(sha256sum "$d/$f" | cut -c1-64)" "$(stat -c %s "$d/$f")" "$f"
        done
    } > "$d/manifest"
}
mkpayload signed 2
mkpayload replacement 3

ssh-keygen -q -t ed25519 -N '' -f key >/dev/null 2>&1 || { echo "cannot make a key"; exit 77; }
printf 'review %s\n' "$(cat key.pub)" > signers
ssh-keygen -Y sign -f key -n kryptik-release signed/manifest >/dev/null 2>&1 || { echo "cannot sign"; exit 77; }
printf 'development\n' > role

# The tool's verify_payload, verbatim, with the environment it expects. die
# exits, as the tool's does; each case runs in its own bash.
{
    echo 'NAMESPACE=kryptik-release'
    echo 'MAGIC=KRYPTIK-MANIFEST-1'
    echo "SIGNERS=$T/signers"
    echo "ROLE_FILE=$T/role"
    echo 'say() { printf "%s\n" "$*"; }'
    echo 'die() { printf "REFUSED: %s\n" "$*"; exit 1; }'
    echo 'hdr() { awk -F": " -v k="$2" '"'"'$1==k {print $2; exit}'"'"' "$1"; }'
    echo 'running_version() { echo 1; }'
    sed -n '/^verify_payload() {/,/^cmd_apply() {/p' "$TOOL" | sed '$d'
} > verify.sh
grep -q '^verify_payload() {' verify.sh || { echo "could not extract verify_payload from $TOOL"; exit 1; }

# run_case NAME WHAT-THE-WRITER-REPLACES: a fresh copy of the signed payload,
# the tool's verify_payload over it, and a writer that lands the moment the
# real ssh-keygen has accepted the signature. Prints the tool's output plus
# VERSION=<what it reported> when it accepted.
run_case() {
    local name="$1" what="$2"
    rm -rf "$T/payload" "$T/snap-$name"; cp -a "$T/signed" "$T/payload"; mkdir -p "$T/snap-$name"
    cat > "$T/case-$name.sh" <<EOF
source $T/verify.sh
ssh-keygen() {
    command ssh-keygen "\$@"
    local rc=\$?
    if [ "\$rc" = 0 ] && [ "\${2:-}" = verify ]; then
        case "$what" in
            manifest) cp $T/replacement/manifest $T/payload/manifest ;;
            all)      cp $T/replacement/* $T/payload/ ;;
        esac
    fi
    return "\$rc"
}
SNAP=$T/snap-$name
verify_payload $T/payload 0 && echo "VERSION=\$VERSION"
EOF
    bash "$T/case-$name.sh" 2>&1
}

# Case 1: nothing is replaced; the signed payload verifies as version 2.
out="$(run_case plain none)"
if [[ "$out" == *"VERSION=2"* ]]; then ok "the signed payload verifies and reports version 2"; else bad "the signed payload did not verify: $(tail -2 <<<"$out" | tr '\n' ' ')"; fi

# Case 2: only the manifest is replaced after the signature check - the
# attack exactly as reproduced. The files are still the signed ones, so the
# copy the tool kept still matches them: version 2, never 3.
out="$(run_case manifest manifest)"
if [[ "$out" == *"VERSION=3"* ]]; then
    bad "the replaced, unsigned manifest was read after the signature check (version 3)"
elif [[ "$out" == *"VERSION=2"* ]]; then
    ok "a manifest replaced after the signature check is not the one read: version stays 2"
else
    bad "unexpected outcome for a replaced manifest: $(tail -2 <<<"$out" | tr '\n' ' ')"
fi
if [[ "$(sed -n 's/^version: //p' "$T/payload/manifest")" = 3 ]]; then
    ok "control: the replacement manifest really was in place when the tool finished"
else
    bad "control: the replacement did not land, so the race was not exercised"
fi

# Case 3: the manifest AND the files are replaced. The kept copy's hashes
# no longer match what is on disk, so the payload is refused - and still
# never reported as version 3.
out="$(run_case all all)"
if [[ "$out" == *"VERSION=3"* ]]; then
    bad "a wholly replaced payload was accepted as version 3"
elif [[ "$out" == *"REFUSED:"*"does not match"* ]]; then
    ok "a wholly replaced payload is refused: its files no longer match the manifest the tool kept"
else
    bad "unexpected outcome for a replaced payload: $(tail -2 <<<"$out" | tr '\n' ' ')"
fi

if command ssh-keygen -Y verify -f signers -I review -n kryptik-release -s "$T/payload/manifest.sig" < "$T/replacement/manifest" >/dev/null 2>&1; then
    bad "control: the replacement manifest has a valid signature, which it must not"
else
    ok "control: the real verifier rejects the replacement manifest"
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
