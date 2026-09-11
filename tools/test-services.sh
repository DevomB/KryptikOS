#!/usr/bin/env bash
# Validate the s6-rc service source tree, offline and in about a second.
#
# s6-rc-compile is the authority, and it only runs inside the chroot at the end
# of a long stage. Everything checked here is a mistake that costs that whole
# round trip to discover: a dependency naming a service that does not exist, a
# bundle listing one, a oneshot whose `up` points at a script the stage never
# installs, a shebang in an `up` file (which is execline, not shell), a
# dependency cycle.
#
# It is deliberately structural. It does not know whether udevd is the right
# program to run; it knows that if you say a service depends on `eudev`, there
# had better be an `eudev`.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${ROOT}/build/services"
SCRIPTS="${ROOT}/build/service-scripts"
PASS=0
FAIL=0

green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }
check() { if [[ "$2" == ok ]]; then green "$1"; else red "$1"; fi; }

[[ -d "$SRC" ]] || { echo "no service tree at ${SRC}"; exit 1; }

echo "s6-rc service tree: ${SRC#"$ROOT"/}"
echo

# --- inventory -------------------------------------------------------------
mapfile -t SERVICES < <(find "$SRC" -mindepth 1 -maxdepth 1 -type d \
                        ! -name scripts -printf '%f\n' | sort)
[[ "${#SERVICES[@]}" -gt 0 ]] || { red "no services defined"; exit 1; }
echo "  ${#SERVICES[@]} services: ${SERVICES[*]}"
echo

is_service() {
    local n="$1" s
    for s in "${SERVICES[@]}"; do [[ "$s" == "$n" ]] && return 0; done
    return 1
}

# --- per-service structure -------------------------------------------------
echo "-- every service is well formed"
for svc in "${SERVICES[@]}"; do
    d="${SRC}/${svc}"

    if [[ ! -f "$d/type" ]]; then
        red "${svc}: no type file"; continue
    fi
    type="$(tr -d '[:space:]' < "$d/type")"
    case "$type" in
        oneshot|longrun|bundle) ;;
        *) red "${svc}: type is '${type}', not oneshot/longrun/bundle"; continue ;;
    esac

    case "$type" in
    oneshot)
        if [[ ! -f "$d/up" ]]; then
            red "${svc}: oneshot with no up script"
        else
            lines="$(grep -c '' < "$d/up")"
            first="$(head -1 "$d/up")"
            # An `up` file is an EXECLINE script. A #! line in it is parsed as
            # execline and fails in a way that does not name the cause.
            if [[ "$first" == '#!'* ]]; then
                red "${svc}: up starts with a shebang - it is execline, not shell"
            elif [[ "$lines" -ne 1 ]]; then
                red "${svc}: up is ${lines} lines; keep it one command line naming a script"
            else
                green "${svc}: oneshot, up is a single command line"
            fi
            # If it names a script this repository ships, that script must exist.
            if [[ "$first" == /usr/libexec/kryptik/* ]]; then
                s="${SCRIPTS}/${first##*/}"
                if [[ -f "$s" ]]; then
                    green "${svc}: up names ${first##*/}, which exists in service-scripts/"
                else
                    red "${svc}: up names ${first} but service-scripts/${first##*/} is missing"
                fi
            fi
        fi
        ;;
    longrun)
        if [[ ! -f "$d/run" ]]; then
            red "${svc}: longrun with no run script"
        elif [[ ! -x "$d/run" ]]; then
            red "${svc}: run is not executable - s6-supervise execs it directly"
        elif [[ "$(head -1 "$d/run")" != '#!'* ]]; then
            red "${svc}: run has no shebang and s6-supervise execs it directly"
        else
            green "${svc}: longrun, run is executable with a shebang"
        fi
        ;;
    bundle)
        if [[ ! -f "$d/contents" ]]; then
            red "${svc}: bundle with no contents"
        else
            missing=0
            while read -r member; do
                [[ -z "$member" ]] && continue
                is_service "$member" || { red "${svc}: contents names '${member}', which is not a service"; missing=1; }
            done < "$d/contents"
            [[ "$missing" -eq 0 ]] && green "${svc}: bundle, every member exists"
        fi
        ;;
    esac

    # Dependencies must name real services, whatever the type.
    if [[ -f "$d/dependencies" ]]; then
        bad=0
        while read -r dep; do
            [[ -z "$dep" ]] && continue
            is_service "$dep" || { red "${svc}: depends on '${dep}', which is not a service"; bad=1; }
        done < "$d/dependencies"
        [[ "$bad" -eq 0 ]] && green "${svc}: dependencies all resolve"
    fi
done

# --- cycles ----------------------------------------------------------------
echo
echo "-- the dependency graph is acyclic"
cycle="$(python3 - "$SRC" <<'PY'
import os, sys
src = sys.argv[1]
deps = {}
for svc in os.listdir(src):
    d = os.path.join(src, svc)
    if not os.path.isdir(d):
        continue
    f = os.path.join(d, "dependencies")
    deps[svc] = [l.strip() for l in open(f)] if os.path.exists(f) else []
    deps[svc] = [x for x in deps[svc] if x]

WHITE, GREY, BLACK = 0, 1, 2
colour = dict.fromkeys(deps, WHITE)
def visit(n, path):
    colour[n] = GREY
    for m in deps.get(n, []):
        if m not in colour:
            continue
        if colour[m] == GREY:
            print(" -> ".join(path + [n, m])); return True
        if colour[m] == WHITE and visit(m, path + [n]):
            return True
    colour[n] = BLACK
    return False
for n in deps:
    if colour[n] == WHITE and visit(n, []):
        break
PY
)"
check "no dependency cycle" "$([[ -z "$cycle" ]] && echo ok)"
[[ -n "$cycle" ]] && echo "        cycle: ${cycle}"

# --- no service may hold a shutdown open ------------------------------------

echo
echo "-- every longrun bounds its own stop"
# s6-svc -d sends the down signal and then waits. Forever, unless timeout-kill
# says otherwise. getty-tty1 is the case that proved this matters: it runs
# `agetty -n -l /usr/bin/bash`, which execs an INTERACTIVE bash, and an
# interactive bash ignores SIGTERM by design. `s6-rc change` blocked on it
# during every shutdown until rc.shutdown's own timeout fired.
#
# So: a down-signal the process will actually honour, and a hard bound after it.
for d in "${SRC}"/*/; do
    svc="$(basename "$d")"
    [[ -f "${d}type" ]] || continue
    [[ "$(cat "${d}type")" == "longrun" ]] || continue
    if [[ -f "${d}timeout-kill" ]]; then
        tk="$(cat "${d}timeout-kill")"
        if [[ "$tk" =~ ^[0-9]+$ && "$tk" -gt 0 ]]; then
            green "${svc}: timeout-kill is ${tk}ms"
        else
            red "${svc}: timeout-kill is '${tk}', which is not a positive number of ms"
        fi
    else
        red "${svc}: longrun with no timeout-kill - it can block a shutdown forever"
    fi
done

# --- what s6-rc-compile itself requires -------------------------------------

echo
echo "-- every directory in the source tree is a service definition"
# s6-rc-compile reads EVERY directory under the source as a service and wants a
# `type` file in each. A stray directory stops the compile with
# "unable to read .../type: No such file or directory". This tree once had a
# scripts/ directory in it and these tests passed anyway, because they checked
# the layout this file expected rather than the layout s6-rc-compile demands.
for d in "${SRC}"/*/; do
    svc="$(basename "$d")"
    if [[ -f "${d}type" ]]; then
        green "${svc}/ has a type file"
    else
        red "${svc}/ has no type file - s6-rc-compile will refuse the whole tree"
    fi
done

# --- scripts ---------------------------------------------------------------
echo
echo "-- the scripts the services name"
for s in "${SCRIPTS}"/*.sh; do
    [[ -f "$s" ]] || continue
    n="$(basename "$s")"
    check "${n}: valid sh"    "$(sh -n "$s" 2>/dev/null && echo ok)"
    check "${n}: executable"  "$([[ -x "$s" ]] && echo ok)"
    # An orphan script is either a service someone forgot to declare or dead
    # weight installed into every image.
    if grep -rqF "/usr/libexec/kryptik/${n}" "$SRC"/*/up 2>/dev/null; then
        green "${n}: referenced by a service"
    else
        red "${n}: installed by the stage but no service runs it"
    fi
done

# --- the contract rc.init depends on ---------------------------------------
echo
echo "-- what rc.init will ask for"
check "a 'default' bundle exists" "$(is_service default && echo ok)"
check "stage 04 installs the scripts" \
      "$(grep -q 'install -m 0755 "\$scripts"/\*\.sh /usr/libexec/kryptik/' \
         "$ROOT/build/stages/04-base-system.sh" && echo ok)"
check "stage 04 compiles the database" \
      "$(grep -q 's6-rc-compile' "$ROOT/build/stages/04-base-system.sh" && echo ok)"
check "rc.init brings up the default bundle" \
      "$(grep -q 's6-rc .*change' "$ROOT/build/stages/04-base-system.sh" && echo ok)"

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} check(s) failed, ${PASS} passed."
    exit 1
fi
echo "All ${PASS} checks passed."
