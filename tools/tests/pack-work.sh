#!/usr/bin/env bash
# tools/image/pack-work.sh on a stand-in work tree: what each pack keeps, and that a stray private key fails it.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
for t in tar zstd; do command -v "$t" > /dev/null || { echo "${t} required"; exit 77; }; done

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
tree() {
    rm -rf "$T/work" "$T"/*.tar.zst
    local f
    for f in sysroot/etc/os-release build/linux/certs/signing_key.pem vm/disk.img \
             images/kryptik-root.img images/esp-usb.img images/kryptik-1.0.0-usb.img images/kryptik-1.0.0.iso \
             images-production/kryptik-1.0.1-usb.img images-production/kryptik-1.0.1.iso images-production/channel-1.0.1/latest \
             images-production/payload-1.0.1/manifest images-production/payload-1.0.1/kryptik-root.img images-production/payload-1.0.1/root.json \
             keys/sb/kryptik-sb.key keys/sb/kryptik-sb.crt keys/release/kryptik-release keys/release/kryptik-latest keys/release/kryptik-testctl \
             bound/1.0.0/images/kryptik-root.img bound/1.0.0/stamps/img-rootfs; do
        mkdir -p "$T/work/$(dirname "$f")"; echo "$f" > "$T/work/$f"
    done
}
pack() { SUDO='' bash "$ROOT/tools/image/pack-work.sh" "$1" "$T" > "$T/out" 2>&1; }
has() { tar --zstd -tf "$T/$1.tar.zst" | sed 's|^\./||' | grep -qxF "$2"; }

tree; pack work-after-media; rc=$?
if [[ "$rc" -eq 0 ]] && has work-after-media sysroot/etc/os-release && has work-after-media images/kryptik-1.0.0-usb.img \
      && has work-after-media images-production/payload-1.0.1/manifest && has work-after-media keys/release/kryptik-testctl \
      && ! has work-after-media images/kryptik-root.img && ! has work-after-media images/esp-usb.img \
      && ! has work-after-media images-production/kryptik-1.0.1-usb.img && ! has work-after-media images-production/payload-1.0.1/root.json \
      && ! has work-after-media keys/sb/kryptik-sb.key && ! has work-after-media keys/release/kryptik-release \
      && ! has work-after-media keys/release/kryptik-latest && [[ ! -e "$T/work/build" && ! -e "$T/work/vm" ]]; then
    ok "work-after-media: the media and the pair's manifests, no root image, ESP, kernel tree or signing key"
else
    bad "work-after-media (exit ${rc})"; cat "$T/out"
fi

tree; pack work-bound; rc=$?
if [[ "$rc" -eq 0 ]] && has work-bound bound/1.0.0/images/kryptik-root.img && has work-bound bound/1.0.0/stamps/img-rootfs \
      && has work-bound images/kryptik-root.img && ! has work-bound keys/sb/kryptik-sb.key && ! has work-bound images-production/kryptik-1.0.1-usb.img; then
    ok "work-bound: the bound releases with their root images, and no signing key"
else
    bad "work-bound (exit ${rc})"; cat "$T/out"
fi

tree; pack production-media; rc=$?
if [[ "$rc" -eq 0 ]] && has production-media images-production/kryptik-1.0.1-usb.img && has production-media images-production/payload-1.0.1/root.json \
      && ! has production-media images-production/kryptik-1.0.1.iso && ! has production-media sysroot/etc/os-release; then
    ok "production-media: the pair without its ISOs"
else
    bad "production-media (exit ${rc})"; cat "$T/out"
fi

tree; echo key > "$T/work/bound/1.0.0/kryptik-sb.key"
pack work-bound; rc=$?
if [[ "$rc" -ne 0 ]] && grep -q "a private key is in work-bound" "$T/out"; then
    ok "a Secure Boot key the excludes miss fails the pack"
else
    bad "a stray kryptik-sb.key was packed (exit ${rc})"; cat "$T/out"
fi

tree; pack mystery; rc=$?
[[ "$rc" -ne 0 ]] && ok "an unknown pack is refused" || bad "an unknown pack was made"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
