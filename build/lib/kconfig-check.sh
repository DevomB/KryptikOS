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

# The .config, read once into KCONFIG_HAVE[option]=value. Both checks below ask
# it; asking the file instead cost two processes and a pass over the whole
# .config for every fragment line, some 750 forks a run.
declare -gA KCONFIG_HAVE=()
_kconfig_load() {   # <.config>
    local line
    KCONFIG_HAVE=()
    while IFS= read -r line; do
        [[ "$line" =~ ^(CONFIG_[A-Za-z0-9_]+)=(.*)$ ]] || continue
        [[ -v "KCONFIG_HAVE[${BASH_REMATCH[1]}]" ]] || KCONFIG_HAVE["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
    done < "$1"
}

# What Kryptik's guarantees, and the suites that prove them, rest on. The
# fragment check holds a line that IS in a fragment to its value; this holds
# the lines that must be in one at all, so that deleting one is noticed.
# Built in or a module is the fragment's to say: a bool cannot come out =m,
# and a driver the built-in rule made a module is still there.
KCONFIG_CRITICAL="CONFIG_SECURITY_LANDLOCK CONFIG_SECCOMP_FILTER CONFIG_USER_NS
CONFIG_NET_NS CONFIG_EFI_STUB CONFIG_CMDLINE_BOOL CONFIG_CMDLINE_OVERRIDE
CONFIG_DM_INIT CONFIG_EFIVAR_FS CONFIG_OVERLAY_FS CONFIG_DRM_VIRTIO_GPU
CONFIG_NFT_MASQ CONFIG_DM_VERITY CONFIG_DM_CRYPT CONFIG_CRYPTO_XTS
CONFIG_FS_ENCRYPTION CONFIG_MODULE_SIG_FORCE CONFIG_SECURITY_LOCKDOWN_LSM
CONFIG_INIT_ON_ALLOC_DEFAULT_ON CONFIG_SLAB_CANARY
CONFIG_MITIGATION_PAGE_TABLE_ISOLATION"

# kconfig_critical_check <.config>: 0 when every one of them is =y or =m.
kconfig_critical_check() {
    local opt missing=0
    _kconfig_load "$1"
    for opt in $KCONFIG_CRITICAL; do
        if [[ "${KCONFIG_HAVE[$opt]:-}" == [ym] ]]; then
            echo "  ok   ${opt}"
        else
            echo "  MISSING ${opt}"; missing=$((missing + 1))
        fi
    done
    [[ "$missing" -eq 0 ]]
}

# kconfig_fragment_check <.config> <fragment>...
#
# Prints one line per fragment line that was not honoured and a summary line;
# returns 0 when every line was honoured, 1 otherwise.
kconfig_fragment_check() {
    local config="$1"; shift
    local frag line opt want got total=0 bad=0
    local -a lines
    _kconfig_load "$config"
    for frag in "$@"; do
        mapfile -t lines < "$frag"
        for line in "${lines[@]}"; do
            if [[ "$line" =~ ^(CONFIG_[A-Za-z0-9_]+)=(.*)$ ]]; then
                opt="${BASH_REMATCH[1]}"; want="${BASH_REMATCH[2]}"
                total=$((total + 1))
                got="${KCONFIG_HAVE[$opt]:-}"
                if [[ "$got" != "$want" ]]; then
                    printf '  DROPPED   %-38s wanted %s, got %s  [%s]\n' \
                        "$opt" "$want" "${got:-nothing}" "$(basename "$frag")"
                    bad=$((bad + 1))
                fi
            elif [[ "$line" =~ ^#[[:space:]]+(CONFIG_[A-Za-z0-9_]+)[[:space:]]+is[[:space:]]+not[[:space:]]+set$ ]]; then
                opt="${BASH_REMATCH[1]}"
                total=$((total + 1))
                got="${KCONFIG_HAVE[$opt]:-}"
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
