#!/usr/bin/env bash
# Fail if the pinned kernel is end-of-life or not a longterm release (ADR-009).
#
#   ./tools/check-kernel-eol.sh            informational
#   ./tools/check-kernel-eol.sh --strict   release gate

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

STRICT=0
for a in "$@"; do
    case "$a" in
        --strict) STRICT=1 ;;
        -h|--help) sed -n '2,5p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $a (expected --strict or nothing)" ;;
    esac
done

RELEASES_URL="https://www.kernel.org/releases.json"

# Test hook; it needs a second variable, so a stray one cannot point the gate off kernel.org.
if [[ -n "${KRYPTIK_KERNEL_RELEASES_URL:-}" ]]; then
    [[ "${KRYPTIK_KERNEL_EOL_SELFTEST:-0}" == "1" ]] || die \
"KRYPTIK_KERNEL_RELEASES_URL is set but KRYPTIK_KERNEL_EOL_SELFTEST is not.
Refusing to check the pinned kernel against a substituted release feed."
    RELEASES_URL="$KRYPTIK_KERNEL_RELEASES_URL"
    warn "SELF-TEST MODE: release data from ${RELEASES_URL}"
fi

if [[ "$STRICT" -eq 1 ]]; then
    log "Checking pinned kernel ${V_LINUX} against kernel.org (strict)"
else
    log "Checking pinned kernel ${V_LINUX} against kernel.org"
fi

have python3 || have python || die "python required for the EOL check"
PY_BIN="$(command -v python3 || command -v python)"

RELEASES="${KRYPTIK_WORK}/releases.json"
mkdir -p "$KRYPTIK_WORK"

# An unreachable feed proves nothing: fatal with --strict, a warning otherwise.
if ! curl -fsL --max-time 30 -o "$RELEASES" "$RELEASES_URL"; then
    rm -f "$RELEASES"
    if [[ "$STRICT" -eq 1 ]]; then
        err "could not reach ${RELEASES_URL}"
        die "Kernel support status could not be established (ADR-009); re-run with network access."
    fi
    warn "could not reach ${RELEASES_URL}; kernel support status UNKNOWN"
    warn "this is not a pass: --strict fails here. Re-run with network access"
    exit 0
fi

# First line of output is a status token; the rest is the human message.
classify() {
    "$PY_BIN" - "$RELEASES" "$V_LINUX" <<'PYEOF'
import json, sys

# Monikers kernel.org publishes; any other means a feed this does not understand.
KNOWN = {"mainline", "stable", "longterm", "linux-next"}


def out(status, message):
    print(status)
    print(message)
    raise SystemExit(0)


def parts(v):
    """6.18.50 -> (6, 18, 50). An unparseable component sorts lowest."""
    acc = []
    for chunk in str(v).split("."):
        num = ""
        for ch in chunk:
            if ch.isdigit():
                num += ch
            else:
                break
        acc.append(int(num) if num else -1)
    return tuple(acc)


path, pinned = sys.argv[1], sys.argv[2]

try:
    with open(path) as fh:
        data = json.load(fh)
except (OSError, ValueError) as exc:
    out("MALFORMED", "releases.json is not valid JSON: %s" % exc)

if not isinstance(data, dict):
    out("MALFORMED", "releases.json top level is %s, expected an object"
        % type(data).__name__)

releases = data.get("releases")
if not isinstance(releases, list) or not releases:
    out("MALFORMED", "releases.json has no usable 'releases' list")

for r in releases:
    if not isinstance(r, dict):
        out("MALFORMED", "releases.json contains a non-object release entry")
    if not isinstance(r.get("version"), str) or not r.get("version"):
        out("MALFORMED",
            "releases.json contains a release with no version string")

series = ".".join(pinned.split(".")[:2])


def check(rel, why):
    """Map one release entry onto a verdict, refusing anything ambiguous."""
    ver = rel.get("version")
    moniker = rel.get("moniker")
    iseol = rel.get("iseol")

    if not isinstance(moniker, str) or moniker not in KNOWN:
        out("UNKNOWN", "kernel.org reports moniker %r for %s (%s); this check "
                       "does not recognise it, so support status is unknown"
                       % (moniker, ver, why))
    if not isinstance(iseol, bool):
        out("UNKNOWN", "kernel.org reports iseol=%r for %s (%s); expected a "
                       "boolean, so support status is unknown"
                       % (iseol, ver, why))
    if iseol:
        out("EOL", "%s is marked end-of-life by kernel.org (%s)" % (ver, why))
    if moniker != "longterm":
        out("NOTLTS", "%s is '%s', not longterm (%s)" % (ver, moniker, why))


exact = next((r for r in releases if r.get("version") == pinned), None)
if exact is not None:
    check(exact, "exact match")
    out("OK", "%s is longterm and not end-of-life" % pinned)

same_series = [r for r in releases
               if ".".join(r.get("version").split(".")[:2]) == series]

if not same_series:
    lts = [r.get("version") for r in releases
           if r.get("moniker") == "longterm" and r.get("iseol") is False]
    out("ABSENT", "series %s is not listed by kernel.org at all, so its "
                  "support status cannot be established. Currently supported "
                  "longterm series: %s"
                  % (series, ", ".join(lts) or "none listed"))

# kernel.org lists only each series' current release, so a pin behind it is judged by that release.
newest = max(same_series, key=lambda r: parts(r.get("version")))
check(newest, "series %s, represented by %s" % (series, newest.get("version")))

if parts(pinned) > parts(newest.get("version")):
    out("AHEAD", "pinned %s is newer than anything kernel.org lists for series "
                 "%s (newest: %s), so its support status cannot be established"
                 % (pinned, series, newest.get("version")))

out("STALE", "series %s is longterm and supported, but is at %s while %s is "
             "pinned" % (series, newest.get("version"), pinned))
PYEOF
}

result=""
rc=0
result="$(classify)" || rc=$?
if [[ "$rc" -ne 0 || -z "$result" ]]; then
    err "the kernel classifier failed (exit ${rc})"
    die "Kernel support status could not be established (ADR-009): a defect in this tool, not a pass."
fi

status="$(printf '%s\n' "$result" | head -1)"
message="$(printf '%s\n' "$result" | tail -n +2)"

BUMP_ADVICE="Pin a current longterm release from https://www.kernel.org/releases.json
as V_LINUX in build/config/versions.env, with V_LINUX_HARDENED to match."

case "$status" in
    OK)
        ok "$message"
        ;;
    STALE)
        warn "$message"
        warn "A point release is available: bump when convenient; this is not a security failure."
        ;;
    EOL)
        err "$message"
        die "The pinned kernel receives no security updates (ADR-009).
${BUMP_ADVICE}"
        ;;
    NOTLTS)
        err "$message"
        die "Kryptik pins longterm kernels only (ADR-009); others reach EOL within months.
${BUMP_ADVICE}"
        ;;
    ABSENT)
        err "$message"
        die "A series kernel.org no longer lists cannot be shown to be supported (ADR-009).
${BUMP_ADVICE}"
        ;;
    AHEAD)
        err "$message"
        die "The pin is newer than any release kernel.org lists; check V_LINUX for a typo.
${BUMP_ADVICE}"
        ;;
    UNKNOWN)
        err "$message"
        die "Unknown support status is not support (ADR-009).
If kernel.org changed releases.json, update tools/check-kernel-eol.sh."
        ;;
    MALFORMED)
        err "$message"
        die "The release feed could not be parsed, so support status is unknown.
Re-run; if kernel.org changed the format, update tools/check-kernel-eol.sh."
        ;;
    *)
        err "unrecognised classifier status: ${status}"
        die "tools/check-kernel-eol.sh could not interpret its own result; the kernel pin is unverified."
        ;;
esac

# linux-hardened must track the same version, or the patch will not apply.
if [[ -n "${V_LINUX_HARDENED:-}" ]]; then
    if [[ "$V_LINUX_HARDENED" == "${V_LINUX}-hardened"* ]]; then
        ok "linux-hardened ${V_LINUX_HARDENED} matches the pinned kernel"
    else
        err "V_LINUX_HARDENED (${V_LINUX_HARDENED}) does not match V_LINUX (${V_LINUX})"
        die "Pin the matching release from https://github.com/anthraxx/linux-hardened/releases"
    fi
else
    err "V_LINUX_HARDENED is unset"
    die "Kryptik builds its kernel with linux-hardened; pin the release matching V_LINUX."
fi
