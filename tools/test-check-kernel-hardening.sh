#!/usr/bin/env bash
# Focused tests for tools/check-kernel-hardening.sh: the contract between the
# checker's findings and build/config/kernel/checker-accepted.txt.
#
#   ./tools/test-check-kernel-hardening.sh
#
# Deterministic and offline. The checker is replaced by a stand-in that prints
# canned findings in the checker's own JSON shape (option_name, type, reason,
# decision, desired_val, check_result, check_result_bool), so what is under
# test is the decision the tool makes about them: every failure accepted with a
# reason passes; one failure not accepted fails; an accepted line without a
# reason fails; an accepted option that now passes is reported stale; the type
# is part of the key; the command line is built from stage 06's COMMON_ARGS
# when none is given; and the repository's own accepted list is well-formed.
#
# Exit 77 when python3 is missing (the tool needs it too).

set -uo pipefail

unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT KRYPTIK_KHC_DIR

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="${ROOT}/tools/check-kernel-hardening.sh"
REAL_ACCEPTED="${ROOT}/build/config/kernel/checker-accepted.txt"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

command -v python3 >/dev/null 2>&1 || { echo "python3 required"; exit 77; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- the stand-in checker ---------------------------------------------------
# Answers --version, prints the file named by FAKE_JSON in json mode and a
# one-line table otherwise, and records the arguments it was given (the tool's
# synthesized command line is read back from there).
mkdir -p "$TMP/khc/bin"
cat > "$TMP/khc/bin/kernel-hardening-checker" <<'PY'
import os, sys
args = sys.argv[1:]
if '--version' in args:
    print('kernel-hardening-checker 0.0.0-fixture'); sys.exit(0)
with open(os.environ['FAKE_ARGS'], 'a') as f:
    f.write(' '.join(args) + '\n')
    if '-l' in args:
        f.write('CMDLINE: ' + open(args[args.index('-l') + 1]).read())
mode = args[args.index('-m') + 1] if '-m' in args else None
if mode == 'json':
    sys.stdout.write(open(os.environ['FAKE_JSON']).read())
else:
    print('[fixture] table')
PY
export FAKE_ARGS="$TMP/args.txt" FAKE_JSON="$TMP/findings.json"
: > "$TMP/config"   # the tool only requires the file to exist

# findings ENTRY...  where ENTRY is type:name:bool  -> FAKE_JSON
findings() {
    python3 - "$FAKE_JSON" "$@" <<'PY'
import json, sys
out = []
for e in sys.argv[2:]:
    t, name, ok = e.split(':')
    out.append({"option_name": name, "type": t, "reason": "self_protection",
                "decision": "kspp", "desired_val": "y",
                "check_result": "OK" if ok == "ok" else 'FAIL: "is not set"',
                "check_result_bool": ok == "ok"})
json.dump(out, open(sys.argv[1], "w"))
PY
}

run() {   # run ACCEPTED-FILE [extra args] -> OUT, RC
    : > "$FAKE_ARGS"
    OUT="$("$TOOL" --config "$TMP/config" --cmdline "$TMP/cmdline" --checker-dir "$TMP/khc" --accepted "$@" 2>&1)"
    RC=$?
}
printf 'root=/dev/dm-0 ro quiet\n' > "$TMP/cmdline"

# --- 1. every failure accepted, with a reason -------------------------------
findings kconfig:CONFIG_A:ok kconfig:CONFIG_B:fail cmdline:foo:fail
cat > "$TMP/acc1" <<'EOF'
# a comment, and a blank line

kconfig  CONFIG_B   # needed by the zone model
cmdline  foo        # the checker's author's preference, not adopted
EOF
run "$TMP/acc1"
if [[ "$RC" -eq 0 ]] && grep -q "accepted failures: 2" <<<"$OUT" \
   && ! grep -q "NOT ACCEPTED\|STALE\|MALFORMED" <<<"$OUT"; then
    green "two failures, both accepted with reasons: exit 0, no complaint"
else
    red "two failures, both accepted with reasons (rc=${RC})"; printf '%s\n' "$OUT" | tail -12
fi

# --- 2. one failure not accepted ---------------------------------------------
findings kconfig:CONFIG_A:ok kconfig:CONFIG_B:fail kconfig:CONFIG_C:fail
run "$TMP/acc1"
if [[ "$RC" -ne 0 ]] && grep -q "FAILURES NOT ACCEPTED" <<<"$OUT" && grep -q "CONFIG_C" <<<"$OUT" \
   && grep -q "failures not accepted: 1" <<<"$OUT"; then
    green "an unaccepted failure fails the run and is named"
else
    red "an unaccepted failure fails the run and is named (rc=${RC})"; printf '%s\n' "$OUT" | tail -12
fi

# --- 3. an accepted line without a reason -------------------------------------
findings kconfig:CONFIG_B:fail
cat > "$TMP/acc3" <<'EOF'
kconfig  CONFIG_B
EOF
run "$TMP/acc3"
if [[ "$RC" -ne 0 ]] && grep -q "MALFORMED" <<<"$OUT" && grep -q "acc3:1" <<<"$OUT"; then
    green "an accepted line without a reason fails, with its line number"
else
    red "an accepted line without a reason fails (rc=${RC})"; printf '%s\n' "$OUT" | tail -12
fi

# A reason-looking comment on the same line but an empty reason after '#'.
cat > "$TMP/acc3b" <<'EOF'
kconfig  CONFIG_B  #
EOF
run "$TMP/acc3b"
if [[ "$RC" -ne 0 ]] && grep -q "MALFORMED" <<<"$OUT"; then
    green "an empty reason after '#' is malformed too"
else
    red "an empty reason after '#' is malformed too (rc=${RC})"
fi

# --- 4. a stale accepted entry ------------------------------------------------
findings kconfig:CONFIG_A:ok kconfig:CONFIG_B:ok
run "$TMP/acc1"     # accepts CONFIG_B and cmdline foo, neither failing now
if [[ "$RC" -eq 0 ]] && grep -q "STALE" <<<"$OUT" && grep -q "kconfig CONFIG_B" <<<"$OUT" \
   && grep -q "cmdline foo" <<<"$OUT" && grep -q "stale accepted entries: 2" <<<"$OUT"; then
    green "accepted options that pass are reported stale, and do not fail the run"
else
    red "stale accepted entries (rc=${RC})"; printf '%s\n' "$OUT" | tail -12
fi

# --- 5. the type is part of the key -------------------------------------------
findings cmdline:nosmt:fail
cat > "$TMP/acc5" <<'EOF'
kconfig  nosmt   # wrong type: this does not cover the cmdline finding
EOF
run "$TMP/acc5"
if [[ "$RC" -ne 0 ]] && grep -q "FAILURES NOT ACCEPTED" <<<"$OUT" && grep -q "STALE" <<<"$OUT"; then
    green "kconfig and cmdline entries of the same name are different keys"
else
    red "type is part of the key (rc=${RC})"; printf '%s\n' "$OUT" | tail -12
fi

# An unknown type is malformed.
cat > "$TMP/acc5b" <<'EOF'
bootarg  nosmt   # not a type the checker has
EOF
run "$TMP/acc5b"
if [[ "$RC" -ne 0 ]] && grep -q "MALFORMED" <<<"$OUT"; then
    green "an unknown type is malformed"
else
    red "an unknown type is malformed (rc=${RC})"
fi

# --- 6. the command line comes from stage 06 when none is given ---------------
findings kconfig:CONFIG_A:ok
: > "$FAKE_ARGS"
OUT="$("$TOOL" --config "$TMP/config" --checker-dir "$TMP/khc" --accepted "$TMP/acc3b" 2>&1)"; RC=$?
# acc3b is malformed, so rc is 1; what matters here is the cmdline handed on.
want="$(sed -n 's/^COMMON_ARGS="\([^"]*\)"$/\1/p' "${ROOT}/build/stages/06-iso.sh" | head -1)"
if [[ -n "$want" ]] && grep -qF "CMDLINE: root=/dev/dm-0 ${want} kryptik.slot=a" "$FAKE_ARGS"; then
    green "without --cmdline, the line handed to the checker is built from stage 06's COMMON_ARGS"
else
    red "cmdline from COMMON_ARGS"; echo "  wanted: ${want}"; grep CMDLINE "$FAKE_ARGS" || echo "  (no CMDLINE recorded)"
fi
if grep -qw "nosmt" <<<"$want" && grep -q "mitigations=auto,nosmt" <<<"$want"; then
    green "stage 06's COMMON_ARGS carry mitigations=auto,nosmt and nosmt"
else
    red "stage 06's COMMON_ARGS carry the SMT parameters (got: ${want})"
fi

# --- 7. the repository's own accepted list ------------------------------------
# Every entry well-formed, and every entry is a real decision the tool would
# read: feed it findings in which exactly those options fail.
mapfile -t entries < <(sed -e 's/#.*//' "$REAL_ACCEPTED" | awk 'NF == 2 {print $1":"$2":fail"}')
if [[ "${#entries[@]}" -gt 0 ]]; then
    findings "${entries[@]}"
    run "$REAL_ACCEPTED"
    if [[ "$RC" -eq 0 ]] && ! grep -q "MALFORMED\|STALE\|NOT ACCEPTED" <<<"$OUT" \
       && grep -q "accepted failures: ${#entries[@]}" <<<"$OUT"; then
        green "build/config/kernel/checker-accepted.txt: ${#entries[@]} entries, each with a reason, each read as a decision"
    else
        red "the repository's accepted list (rc=${RC})"; printf '%s\n' "$OUT" | tail -12
    fi
else
    red "the repository's accepted list has no entries the tool can read"
fi
# ... and no line in it that is neither a comment, blank, nor a two-field entry.
bad_lines="$(grep -vE '^[[:space:]]*(#|$)' "$REAL_ACCEPTED" | awk '{ sub(/#.*/, ""); if (NF != 2) print }')"
if [[ -z "$bad_lines" ]]; then
    green "every non-comment line of the accepted list has exactly a type and a name before its reason"
else
    red "malformed lines in the accepted list:"; printf '    %s\n' "$bad_lines"
fi

# --- 8. a missing config is refused -------------------------------------------
OUT="$("$TOOL" --config "$TMP/does-not-exist" --checker-dir "$TMP/khc" 2>&1)"; RC=$?
if [[ "$RC" -ne 0 ]] && grep -q "no such config" <<<"$OUT"; then
    green "a missing config is refused"
else
    red "a missing config is refused (rc=${RC})"
fi

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
