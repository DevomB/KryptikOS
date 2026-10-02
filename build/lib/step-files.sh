# shellcheck shell=bash
# What each stage 04 step wrote, so the files a rebuilt step no longer installs leave the tree as a clean build's would.
#
#   step_files_mark                       a marker made just before a step runs
#   step_files_record NAME STAMP MARKER   after it: NAME's record, and its last record's files it did not write again
#   step_files_sweep                      at the stage's end: those files, unless a step still writes one or something links it
#
# Records live in ${STAMPS}/files; STEP_FILES_ROOT (default /) is the root they describe.

# Never part of the image, or not the build's to judge.
STEP_FILES_PRUNE=(/proc /sys /dev /run /tmp /tools /kryptik /kryptik-sources /kryptik-work /kryptik-kryptikd /kryptik-wlproxy /lost+found)

step_files_mark() {
    local m; m="$(mktemp)"
    printf '%s' "$m"
}

# Every file or link under the root whose inode changed after MARKER, as root-relative paths.
step_files_written() {
    local marker="$1" root="${STEP_FILES_ROOT:-/}" p prune=()
    for p in "${STEP_FILES_PRUNE[@]}"; do prune+=(-path "${root%/}${p}" -o); done
    find "$root" \( "${prune[@]}" -false \) -prune -o \( -type f -o -type l \) -cnewer "$marker" -print 2>/dev/null \
        | sed "s#^${root%/}##" | LC_ALL=C sort -u
}

step_files_record() {
    local name="$1" stamp="$2" marker="$3" dir="${STAMPS}/files" rec new
    [[ "$stamp" -nt "$marker" ]] || { rm -f "$marker"; return 0; }
    mkdir -p "$dir"
    rec="${dir}/${name}"; new="${rec}.new"
    # A partial list would make files the step wrote look like leftovers, so a failed one changes nothing.
    if ! step_files_written "$marker" > "$new"; then
        warn "${name}: could not list what it wrote; its record stays as it was"
        rm -f "$new" "$marker"
        return 0
    fi
    rm -f "$marker"
    if [[ -f "$rec" ]]; then
        LC_ALL=C comm -23 "$rec" "$new" >> "${dir}/.orphans"
    fi
    mv -f "$new" "$rec"
}

# The sonames and file names the root's ELF objects link, one per line.
step_files_linked() {
    local root="${STEP_FILES_ROOT:-/}" f
    while IFS= read -r -d '' f; do
        [[ "$(head -c 4 "$f" 2>/dev/null | od -An -c | tr -d ' \n')" == '177ELF' ]] || continue
        readelf -d "$f" 2>/dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' || true
    done < <(find "${root%/}/usr" "${root%/}/lib" "${root%/}/lib64" "${root%/}/bin" "${root%/}/sbin" -xdev -type f -print0 2>/dev/null) \
        | LC_ALL=C sort -u
}

step_files_sweep() {   # step_files_sweep STEP...: every step of the stage, in order
    local dir="${STAMPS}/files" root="${STEP_FILES_ROOT:-/}" all linked p so n=0 s missing=0
    [[ -s "${dir}/.orphans" ]] || { rm -f "${dir}/.orphans"; return 0; }
    # A step with no record may install any of these, so nothing goes until every step has one.
    for s in "$@"; do [[ -f "${dir}/${s}" ]] || missing=$((missing + 1)); done
    if [[ "$missing" -gt 0 ]]; then
        warn "${missing} step(s) have no record of what they write yet; the leftovers of rebuilt steps stay until they do"
        return 0
    fi
    all="$(mktemp)"; linked="$(mktemp)"
    find "$dir" -maxdepth 1 -type f ! -name '.*' -exec cat {} + | LC_ALL=C sort -u > "$all"
    step_files_linked > "$linked"
    while IFS= read -r p; do
        [[ -e "${root%/}${p}" || -L "${root%/}${p}" ]] || continue
        if [[ "$p" == *.so || "$p" == *.so.* ]]; then
            so="$(readelf -d "${root%/}${p}" 2>/dev/null | sed -n 's/.*(SONAME).*\[\(.*\)\]/\1/p' || true)"
            if grep -qxF -e "${so:-${p##*/}}" "$linked" || grep -qxF -e "${p##*/}" "$linked"; then
                warn "kept ${p}: no step installs it any more, but something links it"
                continue
            fi
        fi
        rm -f -- "${root%/}${p}"
        n=$((n + 1))
        echo "removed ${p}: the step that installed it no longer does"
    done < <(LC_ALL=C sort -u "${dir}/.orphans" | LC_ALL=C comm -23 - "$all")
    rm -f "${dir}/.orphans" "$all" "$linked"
    [[ "$n" -eq 0 ]] || ok "removed ${n} file(s) rebuilt steps no longer install"
}
