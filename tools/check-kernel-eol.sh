#!/usr/bin/env bash
# Fail if the pinned kernel is end-of-life or not a longterm release.
#
#   ./tools/check-kernel-eol.sh
#
# Why this exists (ADR-009): Kryptik originally pinned linux 6.10.5. That is a
# non-longterm kernel which reached EOL about two months after its August 2024
# release, meaning the pin carried roughly two years of unpatched CVEs while
# looking like a perfectly ordinary version number in versions.env.
#
# A security distribution cannot ship an EOL kernel. This check makes that
# failure loud and mechanical rather than something a person has to remember.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

log "Checking pinned kernel ${V_LINUX} against kernel.org"

RELEASES="${KRYPTIK_WORK}/releases.json"
mkdir -p "$KRYPTIK_WORK"

if ! curl -fsL --max-time 30 -o "$RELEASES" "https://www.kernel.org/releases.json"; then
    warn "could not reach kernel.org; skipping EOL check"
    exit 0
fi

have python3 || have python || die "python required for the EOL check"
PY_BIN="$(command -v python3 || command -v python)"

# Emits: <status>|<moniker>|<message>
result="$("$PY_BIN" - "$RELEASES" "$V_LINUX" <<'PYEOF'
import json, sys

path, pinned = sys.argv[1], sys.argv[2]
with open(path) as fh:
    data = json.load(fh)

series = ".".join(pinned.split(".")[:2])
releases = data.get("releases", [])

# Exact match first, then anything in the same x.y series.
exact = next((r for r in releases if r.get("version") == pinned), None)
same_series = [r for r in releases
               if ".".join(r.get("version", "").split(".")[:2]) == series]

if exact:
    moniker = exact.get("moniker", "unknown")
    iseol = bool(exact.get("iseol"))
    if iseol:
        print(f"EOL|{moniker}|{pinned} is marked end-of-life by kernel.org")
    elif moniker != "longterm":
        print(f"NOTLTS|{moniker}|{pinned} is '{moniker}', not longterm")
    else:
        print(f"OK|{moniker}|{pinned} is longterm and supported")
elif same_series:
    newest = same_series[0]
    moniker = newest.get("moniker", "unknown")
    print(f"OUTDATED|{moniker}|series {series} is at {newest.get('version')}, "
          f"pinned {pinned} is behind")
else:
    # Not listed at all: the series has been dropped from kernel.org entirely.
    lts = [r.get("version") for r in releases if r.get("moniker") == "longterm"]
    print(f"GONE|none|series {series} is no longer listed by kernel.org "
          f"(current longterm: {', '.join(lts[:4])})")
PYEOF
)"

status="${result%%|*}"
rest="${result#*|}"
moniker="${rest%%|*}"
message="${rest#*|}"

case "$status" in
    OK)
        ok "$message"
        ;;
    OUTDATED)
        warn "$message"
        warn "Still longterm, but a point release is available. Bump when convenient."
        ;;
    NOTLTS)
        err "$message"
        die "Kryptik pins longterm kernels only (ADR-009).
A non-longterm kernel reaches EOL within roughly two months of release.
Pick a 'longterm' version from https://www.kernel.org/releases.json"
        ;;
    EOL|GONE)
        err "$message"
        die "The pinned kernel is end-of-life and receives no security updates.
This is disqualifying for a security distribution (ADR-009).
Pick a current 'longterm' release and update V_LINUX in
build/config/versions.env, along with V_LINUX_HARDENED to match."
        ;;
    *)
        warn "inconclusive kernel status: ${result}"
        ;;
esac

# linux-hardened must track the same version, or the patch will not apply.
if [[ -n "${V_LINUX_HARDENED:-}" ]]; then
    if [[ "$V_LINUX_HARDENED" == "${V_LINUX}-hardened"* ]]; then
        ok "linux-hardened ${V_LINUX_HARDENED} matches the pinned kernel"
    else
        err "V_LINUX_HARDENED (${V_LINUX_HARDENED}) does not match V_LINUX (${V_LINUX})"
        die "The linux-hardened patch is version-specific and will not apply.
Find the matching release at
https://github.com/anthraxx/linux-hardened/releases"
    fi
fi
