#!/bin/bash
# After the build (build-system.sh) ends well: move the snapshot to main's
# current commit (a safe boundary: no chroot driver is running), rebuild the
# static binaries from it, run the incremental system stage so the steps
# whose inputs moved reinstall, then the kernel and two releases of media
# (A, and B = A's version with .1, which sort -V orders after A, for the
# update test). Runs as root in the kryptik-build distro; waits for the
# build driver first, so it can be started at any time.
set -u
export KRYPTIK_WORK=/root/kryptik/work KRYPTIK_SOURCES=/root/kryptik/sources KRYPTIK_OUT=/root/kryptik/out NO_COLOR=1 KRYPTIK_STALE=rebuild
S="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WT=/root/kryptik/main; LOGS=/root/kryptik/logs
STAMP() { date -Iseconds; }
run_stage() { local label="$1"; shift; echo "[$(STAMP)] BEGIN $label: $*"; "$@" > "$LOGS/$label.log" 2>&1; local rc=$?; echo "[$(STAMP)] END $label rc=$rc (log $LOGS/$label.log)"; echo "$rc" > "$LOGS/$label.rc"; return "$rc"; }

echo "[$(STAMP)] post-build waiting for the build driver"
while :; do
    if grep -q "SYSTEM AND LIBC PROOF DONE" "$LOGS/build-system.out" 2>/dev/null; then break; fi
    if grep -qE "FAILED" "$LOGS/build-system.out" 2>/dev/null; then echo "[$(STAMP)] the build driver reported a failure; not continuing"; tail -3 "$LOGS/build-system.out"; exit 1; fi
    if ! pgrep -f build-system.sh >/dev/null; then echo "[$(STAMP)] the build driver is gone without a verdict; not continuing"; exit 1; fi
    sleep 60
done
echo "[$(STAMP)] build done; libc proof: $(cat "$LOGS/libc-unwind.rc" 2>/dev/null)"
if mount | grep -q /root/kryptik/work/sysroot; then echo "sysroot still mounted; refusing"; exit 1; fi

cd "$WT" || exit 1
if [[ -n "$(git status --porcelain)" ]]; then echo "snapshot worktree is dirty; refusing"; git status --short; exit 1; fi
git checkout -q --detach main || exit 1
echo "[$(STAMP)] snapshot at $(git rev-parse --short HEAD): $(git log -1 --format=%s)"
bash "$S/build-musl.sh" || { echo "build-musl FAILED"; exit 1; }
KD_BIN=/root/kryptik/kryptikd-musl; WL_BIN=/root/kryptik/kryptik-wlproxy-musl
run_stage system2 make SUDO= KRYPTIK_KRYPTIKD_BIN="$KD_BIN" KRYPTIK_WLPROXY_BIN="$WL_BIN" system || { echo "system2 FAILED"; exit 1; }
run_stage kernel make SUDO= KRYPTIK_KRYPTIKD_BIN="$KD_BIN" KRYPTIK_WLPROXY_BIN="$WL_BIN" kernel || { echo "kernel FAILED"; exit 1; }
VER_A="0.1.$(date +%Y%m%d).$(git rev-parse --short=8 HEAD)"
run_stage media-a make SUDO= KRYPTIK_KRYPTIKD_BIN="$KD_BIN" KRYPTIK_WLPROXY_BIN="$WL_BIN" media KRYPTIK_VERSION="$VER_A" || { echo "media-a FAILED"; exit 1; }
run_stage media-b make SUDO= KRYPTIK_KRYPTIKD_BIN="$KD_BIN" KRYPTIK_WLPROXY_BIN="$WL_BIN" media KRYPTIK_VERSION="${VER_A}.1" || { echo "media-b FAILED"; exit 1; }
ls -la "$KRYPTIK_WORK/images/" | grep -E "usb.img|\.iso|payload"
echo "[$(STAMP)] POST-BUILD DONE: A=${VER_A} B=${VER_A}.1"
