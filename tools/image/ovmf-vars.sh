#!/usr/bin/env bash
# Build the throwaway OVMF variable stores the boot tests use, as files: no firmware is touched.
#
#   tools/image/ovmf-vars.sh [--cert FILE] [--out DIR]
#
#   clean.fd     a copy of OVMF_VARS_4M.fd: no keys, Secure Boot off
#   enrolled.fd  the certificate as PK, KEK and db: Secure Boot on
#   ms.fd        a copy of OVMF_VARS_4M.ms.fd: Microsoft keys, Secure Boot on, Kryptik refused
#
# The certificate is the developer one (a test anchor only) unless --cert gives another.
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
        -h|--help) sed -n '2,10p' "${BASH_SOURCE[0]}"; exit 0 ;;
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

listing="$(virt-fw-vars --input "${OUT}/enrolled.fd" --print --verbose 2>/dev/null || true)"
echo "--- enrolled.fd ---"
grep -E 'SecureBoot|^  (PK|KEK|db|dbx)|Kryptik' <<< "$listing" | head -20 || true
# The enrolled store must list the given certificate, found by its subject's common name.
cn="$(openssl x509 -in "$CERT" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= *//p')"
[[ -n "$cn" ]] || die "${CERT} has no common name to find it by"
grep -qF -- "$cn" <<< "$listing" || die "the enrolled store does not list ${CERT} (${cn})"
ok "variable stores under ${OUT}: clean.fd enrolled.fd ms.fd"
sha256sum "${OUT}"/*.fd | sed 's/^/  /'
