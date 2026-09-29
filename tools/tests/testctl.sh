#!/usr/bin/env bash
# Tests for the medium's control-disk check (build/service-scripts/testctl.sh)
# and the tool that makes a control disk (tools/image/mk-testctl.sh): a file
# is honoured only with a signature by the kryptik-testctl key the anchor
# lists, in that key's namespace. Offline, with throwaway keys; the disk image
# itself is made only where mtools and sfdisk are.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TESTCTL="${ROOT}/build/service-scripts/testctl.sh"
MK="${ROOT}/tools/image/mk-testctl.sh"

command -v ssh-keygen >/dev/null 2>&1 || { echo "ssh-keygen is not installed here; cannot run this test"; exit 77; }

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

# --- keys and an anchor as a medium carries one ----------------------------------------
for k in kryptik-release kryptik-latest kryptik-testctl stranger; do
    ssh-keygen -q -t ed25519 -N '' -C "$k" -f "${W}/${k}" < /dev/null
done
{
    printf 'kryptik-release namespaces="kryptik-release,kryptik-media" %s\n' "$(cut -d' ' -f1,2 "${W}/kryptik-release.pub")"
    printf 'kryptik-latest namespaces="kryptik-latest" %s\n' "$(cut -d' ' -f1,2 "${W}/kryptik-latest.pub")"
    printf 'kryptik-testctl namespaces="kryptik-testctl" %s\n' "$(cut -d' ' -f1,2 "${W}/kryptik-testctl.pub")"
} > "${W}/release-signers"
printf 'install_target=/dev/vda\nsmoke_poweroff=1\n' > "${W}/kryptik-test.conf"

# The medium's check, taken as the medium sources it, against this anchor.
TESTCTL_ANCHOR="${W}/release-signers"
# shellcheck source=build/service-scripts/testctl.sh
. "$TESTCTL"

sign() {   # sign KEY NAMESPACE FILE
    rm -f "$3.sig"
    ssh-keygen -Y sign -f "$1" -n "$2" "$3" < /dev/null > /dev/null 2>&1
}

if testctl_signed "${W}/kryptik-test.conf"; then red "an unsigned control file was honoured"; else green "an unsigned control file is refused"; fi
sign "${W}/kryptik-testctl" kryptik-testctl "${W}/kryptik-test.conf"
if testctl_signed "${W}/kryptik-test.conf"; then green "a file signed by the anchor's kryptik-testctl key, in its namespace, is honoured"; else red "the right signature was refused"; fi
sign "${W}/stranger" kryptik-testctl "${W}/kryptik-test.conf"
if testctl_signed "${W}/kryptik-test.conf"; then red "a stranger's signature was honoured"; else green "a signature by a key the anchor does not list is refused"; fi
sign "${W}/kryptik-release" kryptik-testctl "${W}/kryptik-test.conf"
if testctl_signed "${W}/kryptik-test.conf"; then red "the release key's signature armed an install"; else green "the release key cannot sign a control disk: its namespaces are its own"; fi
sign "${W}/kryptik-testctl" kryptik-release "${W}/kryptik-test.conf"
if testctl_signed "${W}/kryptik-test.conf"; then red "a signature in another namespace was honoured"; else green "the control-disk key's signature counts in its own namespace alone"; fi
sign "${W}/kryptik-testctl" kryptik-testctl "${W}/kryptik-test.conf"
printf 'install_target=/dev/sda\n' >> "${W}/kryptik-test.conf"
if testctl_signed "${W}/kryptik-test.conf"; then red "a file changed after signing was honoured"; else green "a file changed after signing is refused"; fi
printf 'unlisted namespaces="kryptik-testctl" %s\n' "$(cut -d' ' -f1,2 "${W}/stranger.pub")" > "${W}/anchor-stranger"
sign "${W}/stranger" kryptik-testctl "${W}/kryptik-test.conf"
if TESTCTL_ANCHOR="${W}/anchor-stranger" testctl_signed "${W}/kryptik-test.conf"; then
    red "a key listed under another name was honoured"
else
    green "the signer must be listed as kryptik-testctl, not merely listed"
fi

# --- the tool signs what it packs ------------------------------------------------------
if command -v sfdisk >/dev/null 2>&1 && command -v mkfs.vfat >/dev/null 2>&1 && command -v mcopy >/dev/null 2>&1 && command -v mtype >/dev/null 2>&1; then
    out="$(NO_COLOR=1 bash "$MK" --out "${W}/ctl.img" install_target=/dev/vda 2>&1)"; rc=$?
    if [[ "$rc" -ne 0 && "$out" == *"--key is required"* ]]; then green "the tool refuses to make a control disk without the key"; else red "an unsigned control disk was made (exit ${rc}): ${out}"; fi
    if NO_COLOR=1 bash "$MK" --out "${W}/ctl.img" --key "${W}/kryptik-testctl" install_target=/dev/vda smoke_poweroff=1 > /dev/null 2>&1; then
        # The partition starts at sector 2048; read both files out of it.
        dd if="${W}/ctl.img" of="${W}/part.img" bs=512 skip=2048 status=none
        mtype -i "${W}/part.img" ::/kryptik-test.conf > "${W}/packed.conf" 2>/dev/null
        mtype -i "${W}/part.img" ::/kryptik-test.conf.sig > "${W}/packed.conf.sig" 2>/dev/null
        if [[ -s "${W}/packed.conf.sig" ]] && grep -qx 'install_target=/dev/vda' "${W}/packed.conf" && testctl_signed "${W}/packed.conf"; then
            green "the disk holds the control file and a signature the medium's check accepts"
        else
            red "the packed control file or its signature"; sed 's/^/        /' "${W}/packed.conf"
        fi
    else
        red "the tool could not make a signed control disk"
    fi
else
    echo "  (no sfdisk, mkfs.vfat, mcopy or mtype here: the disk image itself is not made)"
fi

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
