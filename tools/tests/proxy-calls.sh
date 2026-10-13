#!/usr/bin/env bash
# The Wayland proxy's calls against its seccomp filter (PROXY_ALLOWLIST in kryptikd's
# seccomp.rs): the static musl proxy, built as the image's is, runs its live tests under strace,
# and every call it makes from its exec on must be on the list, with the arguments the filter
# allows. Exit 77 without cargo, strace or the musl target.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ -d "$HOME/.cargo/bin" ]] && PATH="$HOME/.cargo/bin:$PATH"
for t in cargo strace; do
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "no $t here: the proxy's calls cannot be traced (77)"
        exit 77
    fi
done
TARGET=x86_64-unknown-linux-musl
if command -v rustup >/dev/null 2>&1 && ! rustup target list --installed | grep -qx "$TARGET"; then
    echo "no $TARGET target here: the proxy's calls cannot be traced (77)"
    exit 77
fi
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
cd "$ROOT/compositor" || exit 1

# Built first, so the trace holds the tests and the proxy, not the compiler.
build=(cargo test --release --target "$TARGET" -p wlproxy --test live)
if ! "${build[@]}" --no-run > "$T/build.log" 2>&1; then
    tail -20 "$T/build.log"
    echo "proxy calls: FAIL, the live tests did not build for $TARGET"
    exit 1
fi
strace -f -ff -qq -o "$T/trace" "${build[@]}" > "$T/test.log" 2>&1
rc=$?
tail -4 "$T/test.log"
if [[ "$rc" -ne 0 ]]; then
    echo "proxy calls: FAIL, the live tests failed under strace (rc $rc)"
    exit 1
fi

# One file per process: from the line that execs the proxy, every call it made.
awk 'FNR == 1 { on = 0 }
     !on && /^execve\("[^"]*\/kryptik-wlproxy", / && / = 0$/ { on = 1 }
     on && /^[a-z_0-9]+\(/' "$T"/trace.* > "$T/calls"
runs="$(grep -c '^execve(' "$T/calls")"
traced="$(sed -E 's/\(.*//' "$T/calls" | sort -u)"
listed="$(awk '/^pub const PROXY_ALLOWLIST/, /^\];/' "$ROOT/compartments/kryptikd/src/seccomp.rs" \
    | grep -o 'SYS_[a-z0-9_]*' | sed 's/^SYS_//' | sort -u)"
if [[ "$runs" -lt 2 || -z "$listed" ]]; then
    echo "proxy calls: FAIL, $runs proxy runs traced and $(grep -c . <<<"$listed") calls listed"
    exit 1
fi
echo "traced in $runs proxy runs: $(tr '\n' ' ' <<<"$traced")"
echo "listed and not traced here (the gesture, the copies, a resumed poll): $(comm -13 <(printf '%s\n' "$traced") <(printf '%s\n' "$listed") | tr '\n' ' ')"
missing="$(comm -23 <(printf '%s\n' "$traced") <(printf '%s\n' "$listed"))"
# The filter's argument rules: AF_UNIX sockets, FIONBIO alone, nothing mapped executable.
args="$(grep -E '^socket\(' "$T/calls" | grep -v '^socket(AF_UNIX,'
        grep -E '^ioctl\(' "$T/calls" | grep -v '^ioctl([0-9]*, FIONBIO,'
        grep -E '^(mmap|mprotect)\(.*PROT_EXEC' "$T/calls")"
if [[ -n "$missing" || -n "$args" ]]; then
    [[ -n "$missing" ]] && echo "made by the proxy and missing from PROXY_ALLOWLIST: $(tr '\n' ' ' <<<"$missing")"
    [[ -n "$args" ]] && echo "made with arguments its filter kills: $(sort -u <<<"$args" | head -5 | tr '\n' ';')"
    echo "proxy calls: FAIL"
    exit 1
fi
echo "proxy calls: PASS"
