#!/bin/bash
# Static (musl) kryptikd and kryptik-wlproxy from the main snapshot, for the
# image. Outputs beside the other build inputs so a stage can fingerprint
# them (stage 04's kryptikd and desktop steps take their digests).
set -u
export PATH=/root/.cargo/bin:$PATH
WT=/root/kryptik/main
OUT=/root/kryptik/logs/musl-build.log
echo "[$(date -Iseconds)] commit $(git -C $WT rev-parse --short HEAD)" > "$OUT"
( cd "$WT/compartments/kryptikd" && CARGO_TARGET_DIR=/root/kryptik/cargo-target/kryptikd-musl cargo build --locked --release --target x86_64-unknown-linux-musl ) >> "$OUT" 2>&1 || { echo "KRYPTIKD MUSL BUILD FAILED" >> "$OUT"; exit 1; }
cp /root/kryptik/cargo-target/kryptikd-musl/x86_64-unknown-linux-musl/release/kryptikd /root/kryptik/kryptikd-musl.new && mv /root/kryptik/kryptikd-musl.new /root/kryptik/kryptikd-musl
( cd "$WT/compositor" && CARGO_TARGET_DIR=/root/kryptik/cargo-target/compositor-musl cargo build --locked --release --target x86_64-unknown-linux-musl -p wlproxy --bin kryptik-wlproxy ) >> "$OUT" 2>&1 || { echo "WLPROXY MUSL BUILD FAILED" >> "$OUT"; exit 1; }
cp /root/kryptik/cargo-target/compositor-musl/x86_64-unknown-linux-musl/release/kryptik-wlproxy /root/kryptik/kryptik-wlproxy-musl.new && mv /root/kryptik/kryptik-wlproxy-musl.new /root/kryptik/kryptik-wlproxy-musl
for b in /root/kryptik/kryptikd-musl /root/kryptik/kryptik-wlproxy-musl; do
    printf '%s  %s  %s\n' "$(sha256sum "$b" | cut -c1-16)" "$(file -b "$b" | cut -d, -f1-3)" "$b" >> "$OUT"
done
echo "[$(date -Iseconds)] DONE" >> "$OUT"
cat "$OUT" | tail -4
