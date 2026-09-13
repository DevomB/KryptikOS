#!/bin/bash
# Move the main snapshot worktree to main's current commit, rebuild the
# static binaries from it, and start the build driver detached. Refuses
# while a chroot driver has the sysroot mounted or a build is running: the
# snapshot is an active build input until then. FRESH=1 is passed through.
set -u
S="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd /root/kryptik/main || exit 1
if [[ -n "$(git status --porcelain)" ]]; then echo "snapshot worktree is dirty; refusing"; git status --short; exit 1; fi
if mount | grep -q /root/kryptik/work/sysroot; then echo "sysroot still mounted; refusing to start a second driver"; exit 1; fi
if pgrep -f "04-base-system.sh|build-system.sh" >/dev/null; then echo "a build is already running"; exit 1; fi
git checkout -q --detach main || exit 1
echo "snapshot at $(git rev-parse --short HEAD): $(git log -1 --format=%s)"
bash "$S/build-musl.sh" || exit 1
setsid -f bash "$S/build-system.sh" > /root/kryptik/logs/build-system.out 2>&1
sleep 3
cat /root/kryptik/logs/build-system.out
