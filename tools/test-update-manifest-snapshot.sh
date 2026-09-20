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
ssh-keygen -q -t ed25519 -N '' -f latestkey >/dev/null 2>&1 || { echo "cannot make a key"; exit 77; }
# The trust anchor as stage 04 installs it: the release key honoured for
# manifests and nothing else, a second key honoured for statements of what
# is current and nothing else. An anchor without the namespaces would let
# this suite pass things the installed system refuses.
{
    printf 'kryptik-release namespaces="kryptik-release" %s\n' "$(cut -d' ' -f1,2 key.pub)"
    printf 'kryptik-latest namespaces="kryptik-latest" %s\n' "$(cut -d' ' -f1,2 latestkey.pub)"
} > signers
ssh-keygen -Y sign -f key -n kryptik-release signed/manifest >/dev/null 2>&1 || { echo "cannot sign"; exit 77; }
printf 'development\n' > role

# The tool's verify_payload, verbatim, with the environment it expects. die
# exits, as the tool's does; each case runs in its own bash.
{
    echo 'NAMESPACE=kryptik-release'
    echo 'MAGIC=KRYPTIK-MANIFEST-1'
    echo 'LATEST_NAMESPACE=kryptik-latest'
    echo 'LATEST_MAGIC=KRYPTIK-LATEST-1'
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

if command ssh-keygen -Y verify -f signers -I kryptik-release -n kryptik-release -s "$T/payload/manifest.sig" < "$T/replacement/manifest" >/dev/null 2>&1; then
    bad "control: the replacement manifest has a valid signature, which it must not"
else
    ok "control: the real verifier rejects the replacement manifest"
fi

# --- the update channel's two checks -----------------------------------------
# check-manifest and check-pointer (docs/design/update-channel.md) are what
# zone 0 runs on a manifest and on a statement of what is current before it
# believes either. Same functions, same real ssh-keygen, the same trust anchor
# as above; each case in its own bash because die exits.
check() {   # check FUNCTION ARGS... -> the tool's output, REFUSED: on a refusal
    { echo "source $T/verify.sh"; printf 'SNAP=%q\n' "$(mktemp -d "$T/snap.XXXXXX")"; printf '%q ' "$@"; echo; } > "$T/check.sh"
    bash "$T/check.sh" 2>&1
}
staged() {   # staged NAME -> a directory holding only the signed manifest and its signature
    rm -rf "${T:?}/$1"; mkdir -p "$T/$1"; cp "$T/signed/manifest" "$T/signed/manifest.sig" "$T/$1/"
}

staged stage
out="$(check cmd_check_manifest "$T/stage")"
want_sha="$(sha256sum "$T/signed/manifest" | cut -c1-64)"
if [[ "$out" == *"version: 2"* && "$out" == *"sha256: $want_sha"* && "$(grep -c '^file [0-9]* ' <<<"$out")" = 4 ]] \
   && grep -qx "file $(stat -c %s "$T/signed/kryptik-root.img") kryptik-root.img" <<<"$out"; then
    ok "check-manifest: a signed manifest with no payload beside it verifies, and prints its version, its hash and the four files with their sizes"
else
    bad "check-manifest on a signed manifest: $(tail -3 <<<"$out" | tr '\n' ' ')"
fi

# Signed by the right key in the pointer's namespace: a pointer's signature
# must never pass for a manifest's.
staged crossed; rm -f "$T/crossed/manifest.sig"
ssh-keygen -Y sign -f key -n kryptik-latest "$T/crossed/manifest" >/dev/null 2>&1
out="$(check cmd_check_manifest "$T/crossed")"
[[ "$out" == *"REFUSED:"*"does NOT verify"* && "$out" != *"version:"* ]] \
    && ok "check-manifest: a manifest signed in the pointer's namespace is refused" \
    || bad "check-manifest accepted a signature from the pointer's namespace: $(tail -2 <<<"$out" | tr '\n' ' ')"

ssh-keygen -q -t ed25519 -N '' -f otherkey >/dev/null 2>&1
staged stranger; rm -f "$T/stranger/manifest.sig"
ssh-keygen -Y sign -f otherkey -n kryptik-release "$T/stranger/manifest" >/dev/null 2>&1
out="$(check cmd_check_manifest "$T/stranger")"
[[ "$out" == *"REFUSED:"*"not enrolled"* ]] \
    && ok "check-manifest: a manifest signed by a key that is not enrolled is refused" \
    || bad "check-manifest accepted a stranger's key: $(tail -2 <<<"$out" | tr '\n' ' ')"

# The rules `apply` has, because they are the same function: the role, and no
# downgrade (nothing that arrives over the network is a recovery).
resigned() {   # resigned NAME SED-EXPRESSION -> the signed manifest, edited, signed again
    rm -rf "${T:?}/$1"; mkdir -p "$T/$1"
    sed "$2" "$T/signed/manifest" > "$T/$1/manifest"
    ssh-keygen -Y sign -f key -n kryptik-release "$T/$1/manifest" >/dev/null 2>&1
}
resigned prod 's/^role: development/role: production/'
out="$(check cmd_check_manifest "$T/prod")"
[[ "$out" == *"REFUSED:"*"this image requires 'development'"* ]] \
    && ok "check-manifest: a validly signed manifest for another role is refused" \
    || bad "check-manifest accepted another role: $(tail -2 <<<"$out" | tr '\n' ' ')"
resigned older 's/^version: 2/version: 0.9/'
out="$(check cmd_check_manifest "$T/older")"
[[ "$out" == *"REFUSED:"*"older than the running"* ]] \
    && ok "check-manifest: a validly signed older release is refused; the channel has no --recovery" \
    || bad "check-manifest accepted a downgrade: $(tail -2 <<<"$out" | tr '\n' ' ')"
resigned climbs 's|  root.json$|  ../root.json|'
out="$(check cmd_check_manifest "$T/climbs")"
[[ "$out" == *"REFUSED:"*"directory component"* && "$out" != *"file "* ]] \
    && ok "check-manifest: a listed name with a directory component is refused before any name is printed" \
    || bad "check-manifest printed a path that climbs: $(tail -2 <<<"$out" | tr '\n' ' ')"

# The pointer.
mkdir -p "$T/ptr"
printf 'KRYPTIK-LATEST-1\nrole: development\nversion: 2\nissued: 2027-03-02T14:05:00+00:00\nmanifest-sha256: %s\nbase: 2/\n' "$want_sha" > "$T/ptr/latest"
ssh-keygen -Y sign -f latestkey -n kryptik-latest "$T/ptr/latest" >/dev/null 2>&1
out="$(check cmd_check_pointer "$T/ptr/latest" "$T/ptr/latest.sig")"; rc=$?
[[ "$rc" = 0 && "$out" == *"signature verifies"* ]] \
    && ok "check-pointer: a pointer signed by an enrolled key in its own namespace verifies" \
    || bad "check-pointer refused a good pointer: $(tail -2 <<<"$out" | tr '\n' ' ')"

cp "$T/ptr/latest" "$T/ptr/replayed-ns"
ssh-keygen -Y sign -f latestkey -n kryptik-release "$T/ptr/replayed-ns" >/dev/null 2>&1
out="$(check cmd_check_pointer "$T/ptr/replayed-ns" "$T/ptr/replayed-ns.sig")"
[[ "$out" == *"REFUSED:"*"does NOT verify"* ]] \
    && ok "check-pointer: a pointer signed in the manifest's namespace is refused" \
    || bad "check-pointer accepted a signature from the manifest's namespace: $(tail -2 <<<"$out" | tr '\n' ' ')"

cp "$T/ptr/latest" "$T/ptr/stranger"
ssh-keygen -Y sign -f otherkey -n kryptik-latest "$T/ptr/stranger" >/dev/null 2>&1
out="$(check cmd_check_pointer "$T/ptr/stranger" "$T/ptr/stranger.sig")"
[[ "$out" == *"REFUSED:"*"not enrolled"* ]] \
    && ok "check-pointer: a pointer signed by a key that is not enrolled is refused" \
    || bad "check-pointer accepted a stranger's key: $(tail -2 <<<"$out" | tr '\n' ' ')"

# The anchor's own rule, both ways round. The release key signing a pointer
# in the pointer's namespace is a well-formed signature by an enrolled key,
# and is refused because that key is not enrolled for that namespace; so is
# the statement key signing a manifest. This is what lets the statement key
# live where a timer can reach it.
cp "$T/ptr/latest" "$T/ptr/by-release-key"
ssh-keygen -Y sign -f key -n kryptik-latest "$T/ptr/by-release-key" >/dev/null 2>&1
out="$(check cmd_check_pointer "$T/ptr/by-release-key" "$T/ptr/by-release-key.sig")"
[[ "$out" == *"REFUSED:"*"does NOT verify"*"not for kryptik-latest"* ]] \
    && ok "check-pointer: the release key is not honoured for a pointer, whatever namespace it signs in" \
    || bad "check-pointer accepted a pointer signed by the release key: $(tail -2 <<<"$out" | tr '\n' ' ')"
staged by-latest-key; rm -f "$T/by-latest-key/manifest.sig"
ssh-keygen -Y sign -f latestkey -n kryptik-release "$T/by-latest-key/manifest" >/dev/null 2>&1
out="$(check cmd_check_manifest "$T/by-latest-key")"
[[ "$out" == *"REFUSED:"*"does NOT verify"* && "$out" != *"version:"* ]] \
    && ok "check-manifest: the statement key cannot sign a release, whatever namespace it signs in" \
    || bad "check-manifest accepted a manifest signed by the statement key: $(tail -2 <<<"$out" | tr '\n' ' ')"

sed 's/^version: 2/version: 1/' "$T/ptr/latest" > "$T/ptr/edited"
out="$(check cmd_check_pointer "$T/ptr/edited" "$T/ptr/latest.sig")"
[[ "$out" == *"REFUSED:"*"does NOT verify"* ]] \
    && ok "check-pointer: a pointer edited after it was signed is refused" \
    || bad "check-pointer accepted an edited pointer: $(tail -2 <<<"$out" | tr '\n' ' ')"

# A manifest is not a pointer even when someone signs it as one.
cp "$T/signed/manifest" "$T/ptr/manifest-as-pointer"
ssh-keygen -Y sign -f latestkey -n kryptik-latest "$T/ptr/manifest-as-pointer" >/dev/null 2>&1
out="$(check cmd_check_pointer "$T/ptr/manifest-as-pointer" "$T/ptr/manifest-as-pointer.sig")"
[[ "$out" == *"REFUSED:"*"not a KRYPTIK-LATEST-1"* ]] \
    && ok "check-pointer: a manifest presented as a pointer is refused by its first line" \
    || bad "check-pointer accepted a manifest: $(tail -2 <<<"$out" | tr '\n' ' ')"

# The tool itself, not the functions lifted out of it: the two checks need
# neither root nor this installation's disks, and say what they do need.
if [[ "$(id -u)" != 0 ]]; then
    out="$(sh "$TOOL" check-pointer "$T/ptr/latest" "$T/ptr/latest.sig" 2>&1)"
    [[ "$out" != *"must run as root"* && "$out" == *"no trust anchor at /usr/share/kryptik/trust/release-signers"* ]] \
        && ok "check-pointer runs without root and stops at the image's trust anchor, which this host does not have" \
        || bad "the tool's own check-pointer, unprivileged: $(tail -2 <<<"$out" | tr '\n' ' ')"
    # The directory the tool copies into is removed by its exit trap, so it
    # must never be one the caller's environment named.
    mkdir -p "$T/precious"; echo keep > "$T/precious/marker"
    SNAP="$T/precious" sh "$TOOL" check-pointer "$T/ptr/latest" "$T/ptr/latest.sig" >/dev/null 2>&1
    [[ -f "$T/precious/marker" && -z "$(find "$T/precious" -name 'latest*')" ]] \
        && ok "a SNAP in the environment is not where the tool copies, and is not what its exit trap removes" \
        || bad "the tool used, or removed, the directory the environment named as SNAP"
    out="$(sh "$TOOL" apply "$T/signed" 2>&1)"
    [[ "$out" == *"must run as root"* ]] \
        && ok "control: apply still refuses to run without root" \
        || bad "apply without root: $(tail -2 <<<"$out" | tr '\n' ' ')"
fi


printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
