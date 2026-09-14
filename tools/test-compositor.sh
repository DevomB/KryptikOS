#!/usr/bin/env bash
#
# The compositor layer's own tests: kryptik-wlproxy (wire format, policy,
# the live proxy against a real upstream socket) and zoneid (the colour
# identity invariant, the palette search, the shipped zone files). These are
# the regressions behind two of the four failures this run repaired - the
# proxy's pollfd crash and the palette floor - so `make acceptance` runs them
# by name rather than trusting a green unit run from another day.
#
#   tools/test-compositor.sh
#
# Exit 77 when there is no cargo: a suite that cannot run is not a pass.
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
