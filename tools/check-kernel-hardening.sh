#!/usr/bin/env bash
# Run kernel-hardening-checker on a resolved kernel config and the shipped
# command line, and hold the result to a list of accepted failures.
#
#   ./tools/check-kernel-hardening.sh --config FILE [--cmdline FILE]
#                                     [--accepted FILE] [--checker-dir DIR]
#
#   --config FILE      the resolved .config (from stage 05 or
#                      tools/resolve-kernel-config.sh)
#   --cmdline FILE     a one-line kernel command line; default: the shipped
#                      shape, built from COMMON_ARGS in build/stages/06-iso.sh
#   --accepted FILE    default build/config/kernel/checker-accepted.txt
#   --checker-dir DIR  an unpacked checker tree; default: the pinned release,
#                      unpacked from KRYPTIK_SOURCES on demand
#
# Each FAIL must be fixed or listed, with its reason, in the accepted file; an
# accepted option that passes now is reported stale. Exit 1 on an unaccepted
# failure, a malformed accepted list, or a checker that could not run.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

CONFIG=""
CMDLINE=""
ACCEPTED="${KRYPTIK_ROOT}/build/config/kernel/checker-accepted.txt"
CHECKER_DIR="${KRYPTIK_KHC_DIR:-}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)      CONFIG="${2:?--config needs a file}"; shift 2 ;;
        --cmdline)     CMDLINE="${2:?--cmdline needs a file}"; shift 2 ;;
        --accepted)    ACCEPTED="${2:?--accepted needs a file}"; shift 2 ;;
        --checker-dir) CHECKER_DIR="${2:?--checker-dir needs a directory}"; shift 2 ;;
        -h|--help)     sed -n '2,18p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -n "$CONFIG" ]] || die "--config FILE is required"
[[ -f "$CONFIG" ]] || die "no such config: ${CONFIG}"
[[ -f "$ACCEPTED" ]] || die "accepted list not found: ${ACCEPTED}"
have python3 || die "python3 required (the checker is Python)"

# The checker runs from its pinned tarball.
if [[ -z "$CHECKER_DIR" ]]; then
    ver="${V_KERNEL_HARDENING_CHECKER:?V_KERNEL_HARDENING_CHECKER is not pinned in versions.env}"
    tarball="${KRYPTIK_SOURCES}/v${ver}.tar.gz"
    CHECKER_DIR="${KRYPTIK_WORK}/kernel-hardening-checker-${ver}"
    if [[ ! -f "${CHECKER_DIR}/bin/kernel-hardening-checker" ]]; then
        [[ -f "$tarball" ]] || die "kernel-hardening-checker ${ver} not fetched (${tarball}). Run: make sources"
        # Re-verified: the copy may have changed since the fetch checked it.
        if [[ -f "${KRYPTIK_LOCK:-}" ]]; then
            want="$(awk -v f="v${ver}.tar.gz" '$2 == f { print $1 }' "$KRYPTIK_LOCK")"
            [[ -n "$want" ]] || die "sources.lock has no entry for v${ver}.tar.gz"
            got="$(sha256_of "$tarball")"
            [[ "$got" == "$want" ]] || die "v${ver}.tar.gz does not match sources.lock (${got} != ${want})"
        fi
        rm -rf "$CHECKER_DIR"; mkdir -p "$CHECKER_DIR"
        tar -xzf "$tarball" -C "$CHECKER_DIR" --strip-components=1
    fi
fi
KHC="${CHECKER_DIR}/bin/kernel-hardening-checker"
[[ -f "$KHC" ]] || die "no kernel-hardening-checker under ${CHECKER_DIR}"
run_khc() { PYTHONPATH="$CHECKER_DIR" python3 "$KHC" "$@"; }
log "kernel-hardening-checker $(run_khc --version 2>&1 | awk '{print $NF}')"

# Without --cmdline, build one of the shipped shape. Stage 06 writes the real
# ones; their hardening-relevant part is COMMON_ARGS, the rest names the root.
CMDLINE_TMP=""
JSON_TMP=""
# shellcheck disable=SC2317  # reached through the EXIT trap below
cleanup() {
    [[ -n "$CMDLINE_TMP" ]] && rm -f "$CMDLINE_TMP"
    [[ -n "$JSON_TMP" ]] && rm -f "$JSON_TMP"
    return 0
}
trap cleanup EXIT
if [[ -z "$CMDLINE" ]]; then
    stage06="${KRYPTIK_ROOT}/build/stages/06-iso.sh"
    common="$(sed -n 's/^COMMON_ARGS="\([^"]*\)"$/\1/p' "$stage06" | head -1)"
    [[ -n "$common" ]] || die "no COMMON_ARGS=\"...\" line in ${stage06}"
    CMDLINE_TMP="$(mktemp)"
    printf 'root=/dev/dm-0 %s kryptik.slot=a\n' "$common" > "$CMDLINE_TMP"
    CMDLINE="$CMDLINE_TMP"
    dim "  command line from COMMON_ARGS: $(cat "$CMDLINE")"
else
    [[ -f "$CMDLINE" ]] || die "no such cmdline file: ${CMDLINE}"
fi

# Twice: once for the reader, once as JSON for the check below.
echo
run_khc -c "$CONFIG" -l "$CMDLINE" -m show_fail 2>&1 | grep -v '^\[!\] WARNING: cmdline option' || true
echo
JSON="$(run_khc -c "$CONFIG" -l "$CMDLINE" -m json 2>/dev/null)" \
    || die "the checker failed on ${CONFIG}"

# Hold the failures to the accepted list; counts come back on the last line.
# The JSON goes through a file because the heredoc already takes stdin.
JSON_TMP="$(mktemp)"
printf '%s' "$JSON" > "$JSON_TMP"
result="$(python3 - "$ACCEPTED" "$JSON_TMP" <<'PY'
import json, sys
accepted_path, json_path = sys.argv[1], sys.argv[2]
with open(json_path, encoding="utf-8") as f:
    findings = json.load(f)

accepted = {}
malformed = []
with open(accepted_path, encoding="utf-8") as f:
    for n, raw in enumerate(f, 1):
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        body, sep, reason = line.partition("#")
        fields = body.split()
        if len(fields) != 2 or fields[0] not in ("kconfig", "cmdline", "sysctl") or not sep or not reason.strip():
            malformed.append((n, line))
            continue
        accepted[(fields[0], fields[1])] = reason.strip()

failing = [x for x in findings if not x["check_result_bool"]]
keys = {(x["type"], x["option_name"]) for x in failing}
unaccepted = [x for x in failing if (x["type"], x["option_name"]) not in accepted]
stale = sorted(k for k in accepted if k not in keys)

if malformed:
    print("MALFORMED accepted entries (each needs '<kconfig|cmdline|sysctl> <name>  # <why it stays>'):")
    for n, line in malformed:
        print(f"  {accepted_path}:{n}: {line}")
if unaccepted:
    print("FAILURES NOT ACCEPTED: fix the fragment or the command line, or accept each with its reason:")
    for x in unaccepted:
        print(f"  {x['type']:7s} {x['option_name']:36s} {x['decision']:>10s} {x['reason']:18s} wants {x['desired_val']!s:>12s}  {x['check_result']}")
if stale:
    print("STALE accepted entries (the option passes now; remove them):")
    for t, name in stale:
        print(f"  {t} {name}")
acc = [x for x in failing if (x["type"], x["option_name"]) in accepted]
print(f"accepted failures: {len(acc)}")
for x in acc:
    print(f"  {x['type']:7s} {x['option_name']:36s} {accepted[(x['type'], x['option_name'])]}")
ok = sum(1 for x in findings if x["check_result_bool"])
print(f"COUNTS {ok} {len(failing)} {len(acc)} {len(unaccepted)} {len(stale)} {len(malformed)}")
PY
)"
printf '%s\n' "$result" | grep -v '^COUNTS '
read -r _ n_ok n_fail n_acc n_unacc n_stale n_bad <<<"$(printf '%s\n' "$result" | grep '^COUNTS ')"

echo
log "Summary"
ok  "checks passing: ${n_ok}"
dim "  failing:      ${n_fail} (${n_acc} accepted with a reason)"
[[ "$n_stale" -gt 0 ]] && warn "stale accepted entries: ${n_stale} (remove them from $(basename "$ACCEPTED"))"
rc=0
if [[ "$n_bad" -gt 0 ]]; then
    err "malformed accepted entries: ${n_bad}"; rc=1
fi
if [[ "$n_unacc" -gt 0 ]]; then
    err "failures not accepted: ${n_unacc}"; rc=1
fi
if [[ "$rc" -eq 0 ]]; then
    ok "every failure the checker reports is accepted, with its reason, in $(basename "$ACCEPTED")"
fi
exit "$rc"
