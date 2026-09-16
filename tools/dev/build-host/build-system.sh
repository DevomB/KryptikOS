#!/bin/bash
# Kryptik build driver (runs as root inside the kryptik-build WSL distro),
# from the main snapshot worktree /root/kryptik/main. Stages 01 and 02 run
# unprivileged as `build` (the harness refuses root there), stage 04 and the
# target-runtime proof as root with SUDO=. Resumable: stamped steps whose
# inputs are unchanged are skipped, changed ones and everything after them
# rebuild (KRYPTIK_STALE=rebuild).
#
# FRESH=1 starts from nothing, reversibly: stamps are archived the way
# `make reset-stamps` does, and the sysroot and the unpacked build trees are
# RENAMED aside (sysroot.old-<time>, build.old-<time>), not removed. Used
# once, 2026-09-13, after the glibc patch set changed under stage 01: the
# sysroot then held root-owned stage 04 files that an unprivileged stage 01
# could not replace, and everything after stage 01's glibc was invalid by
# the stamp chain. The set-aside trees are the previous build's evidence
# until someone decides to delete them.
#
# These host scripts are conveniences for this machine's layout (see
# docs/status.md, "Environment"); the build itself is `make`.
set -u
export KRYPTIK_WORK=/root/kryptik/work
export KRYPTIK_SOURCES=/root/kryptik/sources
export KRYPTIK_OUT=/root/kryptik/out
export NO_COLOR=1
export KRYPTIK_STALE=rebuild
WT=/root/kryptik/main
LOGS=/root/kryptik/logs
KD_BIN="${KRYPTIK_KRYPTIKD_BIN:-/root/kryptik/kryptikd-musl}"
WL_BIN="${KRYPTIK_WLPROXY_BIN:-/root/kryptik/kryptik-wlproxy-musl}"
BUILD_ENV=(env KRYPTIK_WORK="$KRYPTIK_WORK" KRYPTIK_SOURCES="$KRYPTIK_SOURCES" KRYPTIK_OUT="$KRYPTIK_OUT" NO_COLOR=1 KRYPTIK_STALE=rebuild HOME=/home/build PATH="/home/build/.cargo/bin:$PATH")
mkdir -p "$LOGS"
cd "$WT" || exit 1
STAMP() { date -Iseconds; }
run_stage() {   # run_stage <label> <cmd...>
    local label="$1"; shift
    echo "[$(STAMP)] BEGIN $label: $*"
    "$@" > "$LOGS/$label.log" 2>&1
    local rc=$?
    echo "[$(STAMP)] END $label rc=$rc (log $LOGS/$label.log)"
    echo "$rc" > "$LOGS/$label.rc"
    return "$rc"
}
echo "[$(STAMP)] driver pid $$ commit $(git rev-parse --short HEAD) kryptikd=$KD_BIN wlproxy=$WL_BIN FRESH=${FRESH:-0}"
if [[ "${FRESH:-0}" == 1 ]]; then
    build/stages/03-chroot-prep.sh guard-unmounted || { echo "sysroot has mounts; refusing to set it aside"; exit 1; }
    ts="$(date +%Y%m%dT%H%M%S)"
    if [[ -d "$KRYPTIK_WORK/.stamps" ]]; then
        dest="$KRYPTIK_WORK/.stamps/legacy/reset-$ts"; mkdir -p "$dest"
        for f in "$KRYPTIK_WORK"/.stamps/*; do [[ -f "$f" ]] && mv "$f" "$dest/"; done
        echo "[$(STAMP)] stamps archived to $dest ($(ls "$dest" | wc -l) files)"
    fi
    [[ -d "$KRYPTIK_WORK/sysroot" ]] && mv "$KRYPTIK_WORK/sysroot" "$KRYPTIK_WORK/sysroot.old-$ts"
    [[ -d "$KRYPTIK_WORK/build" ]] && mv "$KRYPTIK_WORK/build" "$KRYPTIK_WORK/build.old-$ts"
    echo "[$(STAMP)] set aside: $KRYPTIK_WORK/sysroot.old-$ts and $KRYPTIK_WORK/build.old-$ts"
    chown build:build "$KRYPTIK_WORK" "$KRYPTIK_WORK/.stamps" "$KRYPTIK_WORK/logs"
fi
rm -f "$LOGS/toolchain.rc" "$LOGS/temp-tools.rc" "$LOGS/system.rc" "$LOGS/libc-unwind.rc"
run_stage toolchain  sudo -u build "${BUILD_ENV[@]}" make toolchain  || { echo "toolchain FAILED"; exit 1; }
run_stage temp-tools sudo -u build "${BUILD_ENV[@]}" make temp-tools || { echo "temp-tools FAILED"; exit 1; }
run_stage system make SUDO= KRYPTIK_KRYPTIKD_BIN="$KD_BIN" KRYPTIK_WLPROXY_BIN="$WL_BIN" system || { echo "system FAILED"; exit 1; }
run_stage libc-unwind make SUDO= test-libc-unwind || { echo "libc-unwind FAILED"; exit 1; }
echo "[$(STAMP)] SYSTEM AND LIBC PROOF DONE"
