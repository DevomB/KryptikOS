#!/bin/bash
# After post-build.sh: `make acceptance` on release A (the version post-build
# printed), exporting to the Windows checkout's out/overnight. Runs as root in
# the kryptik-build distro, from the main snapshot worktree.
#
#   run-acceptance.sh              every gate, with the export
#   ONLY=G3,G8 run-acceptance.sh   a repair loop: those gates, no export
set -u
LOGS=/root/kryptik/logs; WT=/root/kryptik/main; IMG=/root/kryptik/work/images
export KRYPTIK_WORK=/root/kryptik/work KRYPTIK_SOURCES=/root/kryptik/sources KRYPTIK_OUT=/root/kryptik/out NO_COLOR=1
export PATH=/root/.cargo/bin:$PATH
A="${A:-$(sed -n 's/.*POST-BUILD DONE: A=\([^ ]*\) .*/\1/p' "$LOGS/post-build.out" 2>/dev/null | tail -1)}"
[[ -n "$A" ]] || { echo "no POST-BUILD DONE line in $LOGS/post-build.out (set A=VERSION to override)"; exit 1; }
USB="$IMG/kryptik-$A-usb.img"; ISO="$IMG/kryptik-$A.iso"
[[ -f "$USB" && -f "$ISO" ]] || { echo "media for $A missing under $IMG:"; ls -la "$IMG" 2>/dev/null; exit 1; }
EXPORT="${EXPORT:-/mnt/c/Coding-Projects/Linux Distro/out/overnight}"
cd "$WT" || exit 1
echo "[$(date -Iseconds)] acceptance on A=$A (snapshot $(git rev-parse --short HEAD))${ONLY:+ ONLY=$ONLY}"
if [[ -n "${ONLY:-}" ]]; then
    make SUDO= acceptance MEDIA_USB="$USB" MEDIA_ISO="$ISO" ONLY="$ONLY" > "$LOGS/acceptance.out" 2>&1
else
    make SUDO= acceptance MEDIA_USB="$USB" MEDIA_ISO="$ISO" EXPORT="$EXPORT" > "$LOGS/acceptance.out" 2>&1
fi
rc=$?
echo "[$(date -Iseconds)] acceptance rc=$rc (log $LOGS/acceptance.out)"
echo "$rc" > "$LOGS/acceptance.rc"
tail -40 "$LOGS/acceptance.out"
