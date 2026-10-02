#!/bin/sh
# The keyboard layout: a name in a firmware variable picks a row of the table
# on the verified root, and the row names the console keymap and the desktop's
# xkb layout (docs/design/keyboard-layout.md). POSIX sh, sourced by sysinit,
# kryptik-install, kryptik-session and `kryptik keyboard`.
#   kb_names        the names the table holds, one per line
#   kb_row NAME     "NAME console-keymap xkb-layout xkb-variant" for one it holds
#   kb_stored       the name the variable holds, when it holds a name
#   kb_load NAME    the row's keymap onto the console, recorded for the session
#   kb_store NAME   the name into the variable
#   kb_current      the layout in force: us when none was loaded
#   kb_export_xkb   XKB_DEFAULT_LAYOUT and _VARIANT from what kb_load recorded

KB_TABLE="${KB_TABLE:-/usr/share/kryptik/keyboard-layouts}"
KB_VAR="${KB_VAR:-/sys/firmware/efi/efivars/KryptikKeyboard-ec0aed97-b78d-446f-997d-10d0c35f5fb6}"
KB_RUN="${KB_RUN:-/run/kryptik-keyboard}"
KB_KEYMAPS="${KB_KEYMAPS:-/usr/share/keymaps}"

kb_names() { awk '!/^#/ && NF >= 4 { print $1 }' "$KB_TABLE"; }

# The variable is not authenticated: what it holds picks a row and never
# reaches a command line.
kb_row() {
    case "$1" in ''|*[!a-z0-9-]*) return 1 ;; esac
    [ "${#1}" -le 32 ] || return 1
    awk -v n="$1" '!/^#/ && NF >= 4 && $1 == n { print $1, $2, $3, $4; found = 1; exit } END { exit !found }' "$KB_TABLE"
}

# Four bytes of attributes, then the name: at most 32 bytes, each a name's.
kb_stored() {
    [ -r "$KB_VAR" ] || return 0
    _kb_n=$(( $(head -c 37 "$KB_VAR" 2>/dev/null | tail -c +5 | wc -c) ))
    _kb_v=$(head -c 37 "$KB_VAR" 2>/dev/null | tail -c +5 | tr -cd 'a-z0-9-')
    if [ "$_kb_n" -ge 1 ] && [ "$_kb_n" -le 32 ] && [ "${#_kb_v}" -eq "$_kb_n" ]; then
        printf '%s\n' "$_kb_v"
    fi
    return 0
}

kb_load() {
    _kb_r=$(kb_row "$1") || return 1
    # shellcheck disable=SC2086  # the row's four words
    set -- $_kb_r
    loadkeys -q "$KB_KEYMAPS/$2" || return 1
    _kb_x=$4
    [ "$_kb_x" != - ] || _kb_x=""
    printf 'layout=%s\nxkb_layout=%s\nxkb_variant=%s\n' "$1" "$3" "$_kb_x" > "$KB_RUN.new" || return 1
    chmod 0644 "$KB_RUN.new" && mv -f "$KB_RUN.new" "$KB_RUN"
}

# efivarfs takes the attributes (non-volatile, boot and runtime access) and
# the value in one write, and marks a variable immutable once it exists.
kb_store() {
    kb_row "$1" > /dev/null || return 1
    [ "$(kb_stored)" != "$1" ] || return 0
    # No variable means us already.
    if [ "$1" = us ] && [ ! -e "$KB_VAR" ]; then return 0; fi
    [ -d "${KB_VAR%/*}" ] || return 1
    chattr -i "$KB_VAR" 2>/dev/null || true
    printf '\007\000\000\000%s' "$1" > "$KB_VAR"
}

kb_current() {
    _kb_c=$(sed -n 's/^layout=//p' "$KB_RUN" 2>/dev/null | head -1)
    if kb_row "${_kb_c:-us}" > /dev/null 2>&1; then printf '%s\n' "${_kb_c:-us}"; else echo us; fi
}

kb_export_xkb() {
    _kb_l=$(sed -n 's/^xkb_layout=//p' "$KB_RUN" 2>/dev/null | head -1)
    _kb_x=$(sed -n 's/^xkb_variant=//p' "$KB_RUN" 2>/dev/null | head -1)
    case "$_kb_l" in ''|*[!a-z0-9_]*) return 0 ;; esac
    case "$_kb_x" in *[!a-z0-9_-]*) _kb_x="" ;; esac
    export XKB_DEFAULT_LAYOUT="$_kb_l" XKB_DEFAULT_VARIANT="$_kb_x"
}
