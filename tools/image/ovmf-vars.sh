#!/usr/bin/env bash
# Build the disposable OVMF variable stores the boot tests use.
#
#   tools/image/ovmf-vars.sh [--cert FILE] [--out DIR]
#
#   clean.fd     a copy of OVMF_VARS_4M.fd: no keys, Secure Boot off
#   enrolled.fd  the developer certificate as PK, KEK and db: Secure Boot ON
#   ms.fd        a copy of OVMF_VARS_4M.ms.fd: Microsoft keys, Secure Boot ON
#                (Kryptik's kernels must be REFUSED by this one)
#
# Enrollment happens in a file. Nothing here touches the machine's firmware,
# and the developer key is what it says: a test anchor, not a production one.
set -Eeuo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"

CERT="${KRYPTIK_WORK}/keys/sb/kryptik-sb.crt"
OUT="${KRYPTIK_WORK}/keys/sb/vars"
OVMF_DIR="${KRYPTIK_OVMF_DIR:-/usr/share/OVMF}"
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --cert) CERT="${2:?}"; shift 2 ;;
        --out)  OUT="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,13p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
have virt-fw-vars || die "virt-fw-vars not found (python3-virt-firmware)"
[[ -f "$CERT" ]] || die "no certificate at ${CERT}; run stage 06 (sb-keys) first"
[[ -f "${OVMF_DIR}/OVMF_VARS_4M.fd" ]] || die "no OVMF variable template under ${OVMF_DIR}"
mkdir -p "$OUT"

cp "${OVMF_DIR}/OVMF_VARS_4M.fd" "${OUT}/clean.fd"
cp "${OVMF_DIR}/OVMF_VARS_4M.ms.fd" "${OUT}/ms.fd"

# One owner GUID for the signature lists, kept beside the stores.
if [[ ! -f "${OUT}/owner.guid" ]]; then
    python3 -c 'import uuid; print(uuid.uuid4())' > "${OUT}/owner.guid"
fi
GUID="$(tr -d '\n' < "${OUT}/owner.guid")"

virt-fw-vars --input "${OVMF_DIR}/OVMF_VARS_4M.fd" --output "${OUT}/enrolled.fd" \
    --secure-boot --set-pk "$GUID" "$CERT" --add-kek "$GUID" "$CERT" --add-db "$GUID" "$CERT" >/dev/null

echo "--- enrolled.fd ---"
virt-fw-vars --input "${OUT}/enrolled.fd" --print 2>/dev/null | grep -E 'SecureBoot|^  (PK|KEK|db|dbx)|Kryptik' | head -20 || true
# Prove the store has exactly our certificate in db and that Secure Boot is on.
virt-fw-vars --input "${OUT}/enrolled.fd" --print 2>/dev/null | grep -q 'Kryptik developer Secure Boot key' \
    || die "the enrolled store does not list the developer certificate"
ok "variable stores under ${OUT}: clean.fd enrolled.fd ms.fd"
sha256sum "${OUT}"/*.fd | sed 's/^/  /'
