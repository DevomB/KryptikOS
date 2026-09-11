#!/usr/bin/env bash
# Record exactly what a build produced, and exactly what produced it.
#
#   tools/artifact-manifest.sh [--root DIR] [--out FILE]
#   tools/artifact-manifest.sh --verify FILE [--root DIR]
#
# WHAT THIS IS FOR
#
# Three questions get asked about a build tree and none of them can be answered
# by looking at it:
#
#   "is this the sysroot you tested?"
#   "what went into it?"
#   "has anything touched it since?"
#
# A manifest answers all three. It lists every entry in the tree - type, mode,
# owner, size, content hash, symlink target, device numbers - in a stable
# order, preceded by the inputs that produced it: the repository commit, the
# recipes, the pinned configuration, the compiler, the source tarballs by
# content, and the per-step build fingerprints.
#
# DETERMINISM
#
# The body contains no timestamps, no absolute paths, and no hostnames, and is
# sorted with LC_ALL=C. Two manifests of the same tree are byte-identical, so
# `diff` is a meaningful operation and the tree digest is a stable name for the
# artifact. The generation time goes in a comment, outside the digest.
#
# WHAT IT DOES NOT CLAIM
#
# This is an identity record, not a reproducibility claim. Identical inputs are
# NOT expected to yield an identical digest - timestamps, build paths and
# ordering leak into objects all over an LFS build. Saying "the tree hashed the
# same" is a strong statement; saying "therefore the build is reproducible"
# would not be.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

MODE=generate
OUT=""
ROOT=""
VERIFY=""
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --root)   ROOT="${2:?--root needs a path}"; shift 2 ;;
        --out)    OUT="${2:?--out needs a path}"; shift 2 ;;
        --verify) MODE=verify; VERIFY="${2:?--verify needs a manifest}"; shift 2 ;;
        -*)       die "unknown option: $1" ;;
        *)        die "unexpected argument: $1" ;;
    esac
done

ROOT="${ROOT:-$KRYPTIK_SYSROOT}"
ROOT="${ROOT%/}"
[[ -d "$ROOT" ]] || die "no such directory: ${ROOT}"

MANIFEST_FORMAT=1

# --- inputs ----------------------------------------------------------------

emit_inputs() {
    printf 'format\t%s\n' "$MANIFEST_FORMAT"

    # The repository state. --dirty matters: a manifest that names a commit
    # while the tree had uncommitted edits is worse than one that names none.
    local commit="unknown"
    if have git && git -C "$KRYPTIK_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
        commit="$(git -C "$KRYPTIK_ROOT" describe --always --dirty --abbrev=40 2>/dev/null || echo unknown)"
    fi
    printf 'input\trepo-commit\t%s\n' "$commit"

    # The recipes, by content. Not the whole repository: these are the files
    # that decide what gets built and how.
    local f rel
    for f in "$KRYPTIK_ROOT"/build/lib/common.sh \
             "$KRYPTIK_ROOT"/build/stages/*.sh \
             "$KRYPTIK_ROOT"/build/config/versions.env \
             "$KRYPTIK_ROOT"/build/config/hardening.env \
             "$KRYPTIK_ROOT"/build/config/hardening-exceptions.txt \
             "$KRYPTIK_ROOT"/build/config/kernel/*.fragment \
             "$KRYPTIK_ROOT"/sources.lock; do
        [[ -f "$f" ]] || continue
        rel="${f#"$KRYPTIK_ROOT"/}"
        printf 'input\trecipe\t%s\t%s\n' "$rel" "$(sha256_of "$f")"
    done

    # The source tarballs, by content - not by the name they were fetched
    # under. sources.lock records what SHOULD be there; this records what was.
    if [[ -d "$KRYPTIK_SOURCES" ]]; then
        while IFS= read -r -d '' f; do
            printf 'input\tsource\t%s\t%s\n' "$(basename "$f")" "$(sha256_of "$f")"
        done < <(find "$KRYPTIK_SOURCES" -maxdepth 1 -type f \
                      \( -name '*.tar.*' -o -name '*.tgz' -o -name '*.patch' \) -print0 \
                 | LC_ALL=C sort -z)
    fi

    # Every completed step, with the fingerprint of the inputs it was built
    # from. This is the link between "this file exists in the sysroot" and
    # "these are the inputs that put it there".
    local stamps="${KRYPTIK_WORK}/.stamps"
    if [[ -d "$stamps" ]]; then
        local s fp
        while IFS= read -r -d '' s; do
            fp="$(awk '$1 == "fingerprint:" { print $2; exit }' "$s" 2>/dev/null)"
            printf 'input\tstep\t%s\t%s\n' "$(basename "$s")" "${fp:-none}"
        done < <(find "$stamps" -maxdepth 1 -type f -print0 | LC_ALL=C sort -z)
    fi

    # The compiler that was in the sysroot when this was taken. Reported by the
    # target binary itself where one exists, because that is the compiler that
    # will build anything built next, not whatever the host happens to have.
    local ccid="absent"
    if [[ -x "${ROOT}/usr/bin/gcc" ]]; then
        ccid="$("${ROOT}/usr/bin/gcc" --version 2>/dev/null | head -1 || echo unknown)"
    elif have gcc; then
        ccid="host:$(gcc --version 2>/dev/null | head -1)"
    fi
    printf 'input\tcompiler\t%s\n' "$ccid"
}

# --- the tree --------------------------------------------------------------

emit_tree() {
    local hashes; hashes="$(mktemp)"
    local meta;   meta="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '$hashes' '$meta'" RETURN

    # One find for metadata. %P is the path relative to ROOT, which keeps the
    # manifest independent of where the tree happens to live.
    #
    # -xdev is not an optimisation. After stage 03 the sysroot has the host's
    # /dev bind-mounted inside it; without -xdev this would walk the host's
    # device tree and record it as Kryptik's.
    #
    # find's exit status is CHECKED, and its stderr is kept rather than
    # discarded. A sysroot contains directories this tool may not be able to
    # read - /root is 0750, /etc/kryptik/zones is 0700 - and find reports
    # those on stderr and exits 1 while still printing everything else. With
    # the errors sent to /dev/null that looked like a mysterious failure; with
    # the exit status ignored it would have been far worse, quietly producing
    # a manifest that omitted exactly the files nobody could see.
    local ferr; ferr="$(mktemp)"
    local raw;  raw="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '$ferr' '$raw'" RETURN

    local frc=0
    set +e
    find "$ROOT" -xdev -mindepth 1 \
         -printf '%y\t%m\t%U\t%G\t%s\t%P\t%l\n' > "$raw" 2>"$ferr"
    frc=$?
    set -e

    if [[ "$frc" -ne 0 ]]; then
        err "could not read every entry under ${ROOT}:"
        sed 's/^/    /' "$ferr" | head -10 >&2
        [[ "$(grep -c '' < "$ferr")" -gt 10 ]] && echo "    ..." >&2
        die "Refusing to write a manifest that omits what it could not read.

A sysroot has directories only root can enter. An identity record with
holes in it is worse than no identity record, because it still produces a
digest and the digest still looks authoritative.

  sudo tools/artifact-manifest.sh --root ${ROOT} --out ..."
    fi

    LC_ALL=C sort -t "$(printf '\t')" -k6,6 < "$raw" > "$meta"

    # Content hashes for regular files, batched. Fifty thousand sha256sum
    # processes is the difference between a manifest people take and one they
    # do not.
    ( cd "$ROOT" && find . -xdev -mindepth 1 -type f -printf '%P\0' 2>/dev/null \
        | xargs -0 -r sha256sum 2>/dev/null ) > "$hashes"

    # Anything the hash pass could not read is recorded as UNREADABLE by the
    # awk below; the caller turns that into a refusal for the same reason.
    LC_ALL=C awk -F '\t' -v hashfile="$hashes" '
    BEGIN {
        # sha256sum prints "<hash>  <path>", and escapes a leading backslash
        # or an embedded newline by prefixing the line with "\". Those paths
        # are recorded as unhashable rather than silently mis-attributed.
        while ((getline line < hashfile) > 0) {
            if (substr(line, 1, 1) == "\\") { continue }
            h = substr(line, 1, 64)
            p = substr(line, 67)
            H[p] = h
        }
    }
    {
        type = $1; mode = $2; uid = $3; gid = $4; size = $5; path = $6; link = $7
        if (path ~ /\n/) { next }
        if (type == "f") {
            hash = (path in H) ? H[path] : "UNREADABLE"
            printf "f\t%s\t%s\t%s\t%s\t%s\t%s\n", mode, uid, gid, size, hash, path
        } else if (type == "l") {
            printf "l\t%s\t%s\t%s\t-\t-\t%s\t%s\n", mode, uid, gid, path, link
        } else if (type == "d") {
            printf "d\t%s\t%s\t%s\t-\t-\t%s\n", mode, uid, gid, path
        } else {
            # Device nodes, fifos, sockets. Their presence and mode are part of
            # the artifact - stage 03 creates /dev/console and /dev/null by
            # hand, and a sysroot missing them does not boot.
            printf "%s\t%s\t%s\t%s\t-\t-\t%s\n", type, mode, uid, gid, path
        }
    }' "$meta" | LC_ALL=C sort
}

warn_if_mounted() {
    local mounted
    mounted="$(LC_ALL=C awk -v r="$ROOT/" '{ t=$5; gsub(/\\040/," ",t); if (index(t, r) == 1) print t }' \
               /proc/self/mountinfo 2>/dev/null)"
    if [[ -n "$mounted" ]]; then
        warn "filesystems are mounted inside ${ROOT}:"
        printf '  %s\n' $mounted >&2
        warn "-xdev keeps them out of the manifest, but the tree is in use."
        warn "Unmount first for a stable record:  sudo build/stages/03-chroot-prep.sh umount"
    fi
}

build_manifest() {
    { emit_inputs; emit_tree; } | LC_ALL=C sort
}

case "$MODE" in
generate)
    warn_if_mounted
    log "manifesting ${ROOT}"
    body="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '$body'" EXIT
    build_manifest > "$body"

    local unreadable
    unreadable="$(grep -c 'UNREADABLE' < "$body" || true)"
    if [[ "$unreadable" -gt 0 ]]; then
        err "${unreadable} file(s) could not be hashed:"
        grep 'UNREADABLE' "$body" | head -10 | sed 's/^/    /' >&2
        die "Refusing to write a manifest with unhashed entries - see above."
    fi

    digest="$(sha256_of "$body")"
    entries="$(grep -c '' < "$body")"

    OUT="${OUT:-${KRYPTIK_WORK}/artifact-manifest.txt}"
    mkdir -p "$(dirname "$OUT")"
    {
        printf '# kryptik artifact manifest\n'
        printf '# root: %s\n' "$ROOT"
        printf '# generated: %s\n' "$(date -Iseconds)"
        printf '# digest: %s\n' "$digest"
        printf '#\n'
        printf '# The digest covers everything below this block and nothing in it.\n'
        printf '# Verify with: tools/artifact-manifest.sh --verify %s\n' "$OUT"
        cat "$body"
    } > "${OUT}.tmp"
    mv -f "${OUT}.tmp" "$OUT"

    ok "${entries} entries"
    ok "digest ${digest}"
    dim "wrote ${OUT}"
    printf '%s\n' "$digest"
    ;;

verify)
    [[ -f "$VERIFY" ]] || die "no such manifest: ${VERIFY}"
    recorded="$(sed -n 's/^# digest: //p' "$VERIFY" | head -1)"
    [[ -n "$recorded" ]] || die "${VERIFY} has no digest line; it was not written by this tool"

    log "verifying ${ROOT} against ${VERIFY}"
    warn_if_mounted

    old="$(mktemp)"; new="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '$old' '$new'" EXIT
    grep -v '^#' "$VERIFY" > "$old"
    build_manifest > "$new"

    now="$(sha256_of "$new")"
    if [[ "$now" == "$recorded" ]]; then
        ok "digest matches: ${now}"
        exit 0
    fi

    err "digest differs"
    err "  recorded: ${recorded}"
    err "  now     : ${now}"
    echo

    # Report what moved, not a wall of diff. Paths are the last field for tree
    # rows, so compare on the whole line and summarise by kind.
    added="$(LC_ALL=C comm -13 "$old" "$new" | grep -c '' || true)"
    removed="$(LC_ALL=C comm -23 "$old" "$new" | grep -c '' || true)"
    printf '  %s line(s) present now and not in the manifest\n' "$added" >&2
    printf '  %s line(s) in the manifest and not present now\n' "$removed" >&2
    echo >&2
    err "first 40 differences (- manifest, + now):"
    LC_ALL=C diff "$old" "$new" | grep -E '^[<>]' | sed 's/^</  -/; s/^>/  +/' | head -40 >&2

    die "the tree does not match the manifest."
    ;;
esac
