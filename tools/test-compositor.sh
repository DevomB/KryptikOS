#!/usr/bin/env bash
# Run the compositor workspace tests and audit the shipped zone files; exit 77 (skip) without cargo.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/compositor" || { echo "no compositor/ workspace"; exit 1; }
[[ -d "$HOME/.cargo/bin" ]] && PATH="$HOME/.cargo/bin:$PATH"
if ! command -v cargo >/dev/null 2>&1; then
    echo "no cargo here: the compositor tests cannot run (77)"
    exit 77
fi
echo "=== compositor workspace: cargo test --workspace ==="
cargo test --workspace 2>&1
rc=${PIPESTATUS[0]}
echo
echo "=== the shipped zone files pass the identity invariant: zoneid audit ==="
cargo run --quiet -p zoneid -- audit --zones "$ROOT/compartments/zones" 2>&1
rc2=$?
if [[ "$rc" -eq 0 && "$rc2" -eq 0 ]]; then echo "compositor tests: PASS"; exit 0; fi
echo "compositor tests: FAIL (cargo test rc=${rc}, audit rc=${rc2})"
exit 1
