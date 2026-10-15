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
# strace slows every call the tests and the proxy make, so a failed run is named, test and
# panic, and run once more; the trace checked is the run that passed.
traced() {   # traced DIR: the live tests under strace, their output in DIR/test.log
    mkdir -p "$1"
    strace -f -ff -qq -s 256 -o "$1/trace" "${build[@]}" > "$1/test.log" 2>&1
}
failures() { sed -n '/^failures:$/,$p' "$1/test.log" | head -80; }
run="$T/run"
traced "$run"
rc=$?
if [[ "$rc" -ne 0 ]]; then
    failures "$run"
    echo "proxy calls: the live tests failed under strace (rc $rc); running them under it once more"
    run="$T/again"
    traced "$run"
    rc=$?
    if [[ "$rc" -eq 0 ]]; then
        echo "proxy calls: the second run passed; the first run's failure is above"
        # An annotation on the run, so a test that keeps doing it is noticed.
        [[ -z "${GITHUB_ACTIONS:-}" ]] || echo "::warning title=proxy calls::the live tests failed once under strace and passed on the second run"
    fi
fi
tail -4 "$run/test.log"
if [[ "$rc" -ne 0 ]]; then
    failures "$run"
    echo "proxy calls: FAIL, the live tests failed under strace twice (rc $rc)"
    exit 1
fi

# One file per process: from the line that execs the proxy, every call it made, marked "fd"
# when it was started as the launch daemon starts it (--listen-fd) and "path" when it was given
# a path to bind, as only these tests do.
awk 'FNR == 1 { on = 0 }
     !on && /^execve\("[^"]*\/kryptik-wlproxy", / && / = 0$/ { on = 1; mode = index($0, "\"--listen-fd\"") ? "fd" : "path" }
     on && /^[a-z_0-9]+\(/ { print mode "\t" $0 }' "$run"/trace.* > "$T/calls"
cut -f2- "$T/calls" > "$T/lines"
runs="$(grep -c '^execve(' "$T/lines")"
fd_runs="$(grep -c "^fd	execve(" "$T/calls")"
# A path of its own is bound, listened on, given its mode and removed: calls the daemon's proxy
# never makes.
traced="$(awk -F'\t' '{ n = $2; sub(/\(.*/, "", n); if (!($1 == "path" && n ~ /^(bind|listen|unlink|chmod)$/)) print n }' "$T/calls" | sort -u)"
listed="$(awk '/^pub const PROXY_ALLOWLIST/, /^\];/' "$ROOT/compartments/kryptikd/src/seccomp.rs" \
    | grep -o 'SYS_[a-z0-9_]*' | sed 's/^SYS_//' | sort -u)"
if [[ "$runs" -lt 2 || "$fd_runs" -lt 1 || -z "$listed" ]]; then
    echo "proxy calls: FAIL, $runs proxy runs traced ($fd_runs as the daemon starts it) and $(grep -c . <<<"$listed") calls listed"
    exit 1
fi
echo "traced in $runs proxy runs, $fd_runs as the daemon starts it: $(tr '\n' ' ' <<<"$traced")"
echo "listed and not traced here (the gesture, the copies, a resumed poll): $(comm -13 <(printf '%s\n' "$traced") <(printf '%s\n' "$listed") | tr '\n' ' ')"
missing="$(comm -23 <(printf '%s\n' "$traced") <(printf '%s\n' "$listed"))"
# The filter's argument rules: AF_UNIX sockets, sendto with no address, FIONBIO alone, nothing
# mapped executable.
args="$(grep -E '^socket\(' "$T/lines" | grep -v '^socket(AF_UNIX,'
        grep -E '^sendto\(' "$T/lines" | grep -v ', NULL, 0) = '
        grep -E '^ioctl\(' "$T/lines" | grep -v '^ioctl([0-9]*, FIONBIO,'
        grep -E '^(mmap|mprotect)\(.*PROT_EXEC' "$T/lines")"
if [[ -n "$missing" || -n "$args" ]]; then
    [[ -n "$missing" ]] && echo "made by the proxy and missing from PROXY_ALLOWLIST: $(tr '\n' ' ' <<<"$missing")"
    # Where each was made, in the first proxy run's trace (by file name) that has it: that run's
    # exec line, whose arguments tell the daemon's start and a few of the tests apart, and the
    # three calls before it.
    for c in $missing; do
        awk -v c="$c" 'FNR == 1 { on = 0; n = 0 }
            !on && /^execve\("[^"]*\/kryptik-wlproxy", / && / = 0$/ { on = 1; exec = $0; next }
            on && index($0, c "(") == 1 {
                print "  first " c ", in " FILENAME ":"; print "    " substr(exec, 1, 240)
                for (i = n - 3; i < n; i++) if (i >= 0) print "    " substr(prev[i % 3], 1, 200)
                print "  > " substr($0, 1, 240); exit
            }
            on { prev[n % 3] = $0; n++ }' "$run"/trace.*
    done
    [[ -n "$args" ]] && echo "made with arguments its filter kills: $(sort -u <<<"$args" | head -5 | tr '\n' ';')"
    echo "proxy calls: FAIL"
    exit 1
fi
echo "proxy calls: PASS"
