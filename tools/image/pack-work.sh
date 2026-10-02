#!/usr/bin/env bash
# The Distro workflow's work tree for the next job, packed by root and never with a private key.
#
#   tools/image/pack-work.sh WHAT [DIR]
#
#   work-after-media  the suites' tree: no root image or ESPs, and only the production pair's manifests
#   work-bound        the same, plus the releases a production run bound, for its signing job
#   production-media  the production pair without its ISOs
#
# DIR holds work/ (default /mnt/kryptik); WHAT.tar.zst is written there.
set -Eeuo pipefail

what="${1:?usage: pack-work.sh work-after-media|work-bound|production-media [DIR]}"
cd "${2:-/mnt/kryptik}"
read -ra sudo <<< "${SUDO-sudo}"

pair=(--exclude='images-production/kryptik-*' --exclude='images-production/channel-*'
      --exclude='images-production/payload-*/kryptik-*' --exclude='images-production/payload-*/root.json')
keys=(--exclude='keys/sb/kryptik-sb.key' --exclude='keys/release/kryptik-release' --exclude='keys/release/kryptik-latest')
case "$what" in
    work-after-media|work-bound)
        "${sudo[@]}" rm -rf work/build work/vm
        media=()
        [[ "$what" == work-bound ]] || media=(--exclude='images/kryptik-root.img' --exclude='images/esp-*.img')
        "${sudo[@]}" tar -I 'zstd -T0' -cf "${what}.tar.zst" -C work "${media[@]}" "${pair[@]}" "${keys[@]}" . ;;
    production-media)
        "${sudo[@]}" tar -I 'zstd -T0' -cf "${what}.tar.zst" -C work --exclude='*.iso' images-production ;;
    *) echo "pack-work.sh: no pack named ${what}"; exit 1 ;;
esac
if "${sudo[@]}" tar --zstd -tf "${what}.tar.zst" | grep -E 'kryptik-sb\.key$|keys/release/kryptik-(release|latest)$'; then
    echo "a private key is in ${what}.tar.zst"
    exit 1
fi
"${sudo[@]}" chown "$(id -u):$(id -g)" "${what}.tar.zst"
ls -la "${what}.tar.zst"
df -h . | tail -1
