# shellcheck shell=bash
# Does a resolved .config carry every line of a fragment? Shared by stage 05,
# which asks it inside the chroot about the .config it is about to build, and
# by tools/resolve-kernel-config.sh, which asks it on a host about the same
# fragments resolved against the same source, so CI can answer in minutes
# what a Distro run answers in hours.
#
# merge_config.sh and olddefconfig drop a fragment line without a word in
# three ways, and this build has met all three:
#
#   * an unmet dependency: CONFIG_KSTACK_ERASE needs GCC plugins the compiler
#     may not have, CONFIG_TIGON3 needs PTP_1588_CLOCK_OPTIONAL
#   * a `select` from an enabled symbol, which overrides an explicit
#     "is not set": CONFIG_BLK_DEV_IO_TRACE selected DEBUG_FS back on
#   * a prompt that is invisible, so the line is not even a choice: every
#     `if EXPERT` option keeps its default until EXPERT is set
#
# Each of those leaves a fragment that claims a mitigation or a driver the
# kernel does not have, which is worse than a fragment that never claimed it.
# So: every =value line must come out with that value, and every "is not set"
# line must come out unset (or absent, which is the same thing).

# kconfig_fragment_check <.config> <fragment>...
#
# Prints one line per fragment line that was not honoured and a summary line;
# returns 0 when every line was honoured, 1 otherwise.
kconfig_fragment_check() {
    local config="$1"; shift
    local frag line opt want got total=0 bad=0
    local -a lines
    for frag in "$@"; do
        # The fragment is read into memory first, so the loop's stdin stays
        # free for the reads of the .config inside it.
        mapfile -t lines < "$frag"
        for line in "${lines[@]}"; do
            if [[ "$line" =~ ^(CONFIG_[A-Za-z0-9_]+)=(.*)$ ]]; then
                opt="${BASH_REMATCH[1]}"; want="${BASH_REMATCH[2]}"
                total=$((total + 1))
                got="$(sed -n "s/^${opt}=//p" "$config" | head -1)"
                if [[ "$got" != "$want" ]]; then
                    printf '  DROPPED   %-38s wanted %s, got %s  [%s]\n' \
                        "$opt" "$want" "${got:-nothing}" "$(basename "$frag")"
                    bad=$((bad + 1))
                fi
            elif [[ "$line" =~ ^#[[:space:]]+(CONFIG_[A-Za-z0-9_]+)[[:space:]]+is[[:space:]]+not[[:space:]]+set$ ]]; then
                opt="${BASH_REMATCH[1]}"
                total=$((total + 1))
                got="$(sed -n "s/^${opt}=//p" "$config" | head -1)"
                if [[ "$got" == y || "$got" == m ]]; then
                    printf '  FORCED ON %-38s =%s although requested off  [%s]; find what selects it: grep -rn "select %s" .\n' \
                        "$opt" "$got" "$(basename "$frag")" "${opt#CONFIG_}"
                    bad=$((bad + 1))
                fi
            fi
        done
    done
    printf '  %d fragment lines checked, %d not honoured\n' "$total" "$bad"
    [[ "$bad" -eq 0 ]]
}
