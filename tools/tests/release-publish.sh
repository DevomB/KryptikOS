#!/usr/bin/env bash
# Tests for tools/release-publish.sh against a fixture export, tree and tags.
# GitHub is never called: the staged cases stop before it, and the page cases
# run against a stand-in gh that records what it was asked.

set -uo pipefail
unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECKER="${ROOT}/tools/check-commit-identity.sh"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

# 77: cannot run here, which CI lists apart from the passes.
for t in git ssh-keygen sha256sum zstd numfmt tar cmp; do
    command -v "$t" >/dev/null 2>&1 || { echo "${t} is not installed here; cannot run this test"; exit 77; }
done
NAME="$(sed -n 's/^ALLOWED_NAME="\(.*\)"$/\1/p' "$CHECKER")"
EMAIL="$(sed -n 's/^ALLOWED_EMAIL="\(.*\)"$/\1/p' "$CHECKER")"
[[ -n "$NAME" && -n "$EMAIL" ]] || { echo "could not read the permitted identity from ${CHECKER}"; exit 1; }

W="$(mktemp -d)"
OUT="${W}/out"
ERR="${W}/err"
trap 'rm -rf "$W"' EXIT
show() { sed 's/^/        /' "$ERR"; }

# --- a tree with the tool, tagged at the release's revision ---------------------
T="${W}/tree"
mkdir -p "${T}/tools" "${T}/build/lib"
cp "${ROOT}/tools/release-publish.sh" "${T}/tools/"
cp "${ROOT}/build/lib/common.sh" "${T}/build/lib/"
git -C "$T" init -q
git -C "$T" config user.name "$NAME"
git -C "$T" config user.email "$EMAIL"
git -C "$T" config core.autocrlf false
git -C "$T" add -A && git -C "$T" commit -q -m "The release"
REV="$(git -C "$T" rev-parse HEAD)"
git -C "$T" tag v0.1.0
git -C "$T" commit -q --allow-empty -m "After the release"
git -C "$T" tag v0.1.1

# --- the release key, and the anchor the image carries ---------------------------
K="${W}/keys"; mkdir -p "$K"
ssh-keygen -q -t ed25519 -N '' -C kryptik-release -f "${K}/kryptik-release"
printf 'kryptik-release namespaces="kryptik-release,kryptik-media" %s\n' "$(cut -d' ' -f1,2 "${K}/kryptik-release.pub")" > "${K}/release-signers"

# --- an export as make acceptance writes one --------------------------------------
make_export() {   # make_export DIR VERSION ROLE VERDICT REVISION
    local d="$1" v="$2" role="$3" verdict="$4" rev="$5"
    rm -rf "$d"; mkdir -p "$d/acceptance-logs"
    printf 'the usb image of %s\n' "$v" > "$d/kryptik-${v}-usb.img"
    printf 'the iso of %s\n' "$v" > "$d/kryptik-${v}.iso"
    (cd "$d" && sha256sum "kryptik-${v}-usb.img" "kryptik-${v}.iso" > "kryptik-${v}.SHA256SUMS" \
        && ssh-keygen -Y sign -f "${K}/kryptik-release" -n kryptik-media "kryptik-${v}.SHA256SUMS" 2>/dev/null)
    cp "${K}/release-signers" "$d/"
    printf 'cert\n' > "$d/kryptik-sb.crt"; printf 'der\n' > "$d/kryptik-sb.der"
    printf '{"root_hash": "00"}\n' > "$d/root.json"
    printf 'KRYPTIK-MANIFEST-1\nname: kryptik\nversion: %s\nrole: %s\ncreated: 2026-09-28T00:00:00Z\nfiles: 0\n--\n' "$v" "$role" > "$d/manifest-${v}"
    printf 'sig\n' > "$d/manifest-${v}.sig"
    printf '%s\n' "$rev" > "$d/REVISION.txt"
    printf '# Kryptik %s\n\nReleased 2026-09-28, built from `%s`.\n\n## What was tested\n\nEvery suite.\n' "$v" "$rev" > "$d/RELEASE-NOTES.md"
    printf '# Instructions\n' > "$d/INSTRUCTIONS.md"
    printf '# Report\n\nVerdict: **%s**\n' "$verdict" > "$d/ACCEPTANCE-REPORT.md"
    printf 'a log line\n' > "$d/acceptance-logs/install.log"
    # The payload as acceptance exports it: the same root.json and manifest, under the channel's names.
    mkdir -p "$d/payload"
    printf 'the root image of %s\n' "$v" > "$d/payload/kryptik-root.img"
    printf 'kernel a\n' > "$d/payload/kryptik-a.efi"; printf 'kernel b\n' > "$d/payload/kryptik-b.efi"
    cp "$d/root.json" "$d/payload/root.json"; cp "$d/manifest-${v}" "$d/payload/manifest"; cp "$d/manifest-${v}.sig" "$d/payload/manifest.sig"
    {
        echo "Kryptik ${v}"
        echo "acceptance : ${verdict} (20260928T000000; see ACCEPTANCE-REPORT.md)"
        echo "revision   : ${rev}"
    } > "$d/RELEASE.txt"
    # The record's checksums, as acceptance seals them: the media first, then every other file.
    (cd "$d" && for f in "kryptik-${v}-usb.img" "kryptik-${v}.iso"; do printf '%s  ./%s\n' "$(sha256sum "$f" | cut -c1-64)" "$f"; done > SHA256SUMS \
        && find . -type f ! -name SHA256SUMS ! -name '*.img' ! -name '*.iso' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >> SHA256SUMS)
}
BUNDLE="${W}/source.tar"
(cd "$W" && mkdir -p src && printf 'x\n' > src/MANIFEST && tar -cf source.tar src)

publish() {   # publish EXPORT STAGE [ARGS...]: the tool, staged; stdout in $OUT, stderr in $ERR
    NO_COLOR=1 bash "${T}/tools/release-publish.sh" "$1" --stage "$2" "${@:3}" > "$OUT" 2> "$ERR"
}
has() { grep -qF -- "$1" "$OUT"; }
# The stand-in gh: like the real one it needs a repository, from the git
# remotes of the directory it runs in unless --repo names one; it counts the
# arguments that are files at the time of the call, and records the call.
mkdir -p "${W}/bin"
cat > "${W}/bin/gh" <<'GH'
#!/usr/bin/env bash
set -u
repo=0; for a in "$@"; do [[ "$a" == --repo ]] && repo=1; done
if [[ "$repo" -eq 0 ]] && ! git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    echo 'failed to run git: fatal: not a git repository (or any of the parent directories): .git' >&2
    exit 1
fi
files=0; for a in "$@"; do [[ -e "$a" ]] && files=$((files + 1)); done
printf 'cwd=%s files=%s args=%s\n' "$PWD" "$files" "$*" >> "$GH_LOG"
case "$1 $2" in
    "release view")   [[ -e "${GH_LOG}.created" ]] || exit 1; echo "https://example.invalid/releases/tag/$3" ;;
    "release create") : > "${GH_LOG}.created" ;;
esac
GH
chmod +x "${W}/bin/gh"
GH_LOG="${W}/gh.log"
mkdir -p "${W}/tmp"
page() {   # page EXPORT [ARGS...]: the tool against the stand-in gh, from outside any repository
    rm -f "$GH_LOG" "${GH_LOG}.created"
    ( cd "$W" && PATH="${W}/bin:${PATH}" GH_LOG="$GH_LOG" TMPDIR="${W}/tmp" NO_COLOR=1 \
        bash "${T}/tools/release-publish.sh" "$@" > "$OUT" 2> "$ERR" )
}
refused() { grep -qF -- "$1" "$ERR"; }
sha() { sha256sum "$1" | cut -c1-64; }

# --- a development release, staged whole --------------------------------------------
E="${W}/export"; S="${W}/stage"
make_export "$E" 0.1.0 development PASS "$REV"
publish "$E" "$S" --source-bundle "$BUNDLE"; rc=$?
if [[ "$rc" -eq 0 ]] && has "staged v0.1.0, a pre-release, in ${S}: 23 files and NOTES.md"; then
    green "a development release stages as a pre-release with every file, the payload under its names, and the notes"
else
    red "staging (exit ${rc}): $(cat "$OUT")"; show
fi
if [[ -f "${S}/kryptik-0.1.0-usb.img.zst" && -f "${S}/kryptik-0.1.0.iso.zst" ]] \
    && [[ "$(zstd -dc "${S}/kryptik-0.1.0-usb.img.zst" | sha256sum | cut -c1-64)" == "$(sha "${E}/kryptik-0.1.0-usb.img")" ]] \
    && [[ "$(zstd -dc "${S}/kryptik-0.1.0.iso.zst" | sha256sum | cut -c1-64)" == "$(sha "${E}/kryptik-0.1.0.iso")" ]] \
    && [[ ! -e "${S}/kryptik-0.1.0-usb.img" ]]; then
    green "the two images go up compressed and decompress to what was tested"
else
    red "the compressed images"; ls -la "$S" | sed 's/^/        /'
fi
for f in kryptik-0.1.0.SHA256SUMS kryptik-0.1.0.SHA256SUMS.sig release-signers kryptik-sb.crt kryptik-sb.der root.json \
         manifest-0.1.0 manifest-0.1.0.sig RELEASE.txt REVISION.txt RELEASE-NOTES.md INSTRUCTIONS.md ACCEPTANCE-REPORT.md SHA256SUMS; do
    cmp -s "${E}/${f}" "${S}/${f}" || { red "record file ${f} is missing or changed"; break; }
done
[[ "$f" == SHA256SUMS ]] && cmp -s "${E}/SHA256SUMS" "${S}/SHA256SUMS" && green "the record goes up as tested, every file"
if cmp -s "$BUNDLE" "${S}/source-${REV:0:12}.tar"; then
    green "the source bundle goes up under the name the notes give it"
else
    red "source-${REV:0:12}.tar is missing or differs"
fi
if tar -I zstd -tf "${S}/kryptik-0.1.0-acceptance-logs.tar.zst" 2>/dev/null | grep -qx 'acceptance-logs/install.log'; then
    green "the acceptance logs go up as one compressed tarball"
else
    red "the acceptance logs tarball"
fi
N="${S}/NOTES.md"
zsum="$(sha "${S}/kryptik-0.1.0-usb.img.zst")"; bsum="$(sha "${S}/source-${REV:0:12}.tar")"
if [[ "$(head -1 "$N")" == "# Kryptik 0.1.0" ]] && grep -qF 'built from `'"${REV}"'`' "$N" && grep -qx '## Downloads' "$N" \
    && grep -qF "| \`kryptik-0.1.0-usb.img.zst\` | " "$N" && grep -qF "| \`${zsum}\` |" "$N" && grep -qF "| \`${bsum}\` |" "$N" \
    && grep -qF -- '-s kryptik-0.1.0.SHA256SUMS.sig < kryptik-0.1.0.SHA256SUMS' "$N" && grep -qF 'sha256sum -c --ignore-missing kryptik-0.1.0.SHA256SUMS' "$N"; then
    green "the page's text is the release notes, then each upload's size and hash and how to check a download"
else
    red "NOTES.md"; sed 's/^/        /' "$N"
fi

# --- a production release is a release, not a pre-release ---------------------------
E2="${W}/export-production"; S2="${W}/stage-production"
make_export "$E2" 0.1.0 production PASS "$REV"
publish "$E2" "$S2"; rc=$?
if [[ "$rc" -eq 0 ]] && has "staged v0.1.0, a release, in ${S2}: 22 files and NOTES.md"; then
    green "a production release stages as a release, and without a bundle one file fewer"
else
    red "the production export (exit ${rc}): $(cat "$OUT")"; show
fi

# --- the page, through gh -----------------------------------------------------------
TOP="$(cd "$T" && pwd -P)"
page "$E" --source-bundle "$BUNDLE"; rc=$?
if [[ "$rc" -eq 0 ]] && has "v0.1.0, a pre-release, drafted: https://example.invalid/releases/tag/v0.1.0" \
    && grep -qF "cwd=${TOP} files=24 args=release create v0.1.0 --title Kryptik 0.1.0 --notes-file " "$GH_LOG" \
    && grep -q -- ' --verify-tag --prerelease --draft /' "$GH_LOG"; then
    green "the page is made from the checkout, wherever the tool runs: a draft pre-release with every file"
else
    red "the draft (exit ${rc}): $(cat "$OUT")"; show; sed 's/^/        /' "$GH_LOG" 2>/dev/null
fi
page "$E2" --publish --repo octo/kryptik; rc=$?
if [[ "$rc" -eq 0 ]] && has "v0.1.0, a release, published:" \
    && grep -qF "files=23 args=release create v0.1.0 --title Kryptik 0.1.0 --notes-file " "$GH_LOG" \
    && ! grep -qE -- '--draft|--prerelease' "$GH_LOG" \
    && ! grep -v -- '--repo octo/kryptik$' "$GH_LOG" | grep -q .; then
    green "--publish makes the release live, and --repo names the repository to every call"
else
    red "the published release (exit ${rc}): $(cat "$OUT")"; show; sed 's/^/        /' "$GH_LOG" 2>/dev/null
fi

# --- refusals -----------------------------------------------------------------------
E3="${W}/export-tampered"; cp -r "$E" "$E3"; printf '\n' >> "${E3}/kryptik-0.1.0.SHA256SUMS"
publish "$E3" "${W}/stage-tampered"; rc=$?
if [[ "$rc" -ne 0 ]] && refused "does not check out" && [[ ! -e "${W}/stage-tampered/kryptik-0.1.0-usb.img.zst" ]]; then
    green "a checksum file that no longer matches its signature is refused before anything is staged"
else
    red "the tampered export (exit ${rc})"; show
fi
E4="${W}/export-failed"; make_export "$E4" 0.1.0 development FAIL "$REV"
publish "$E4" "${W}/stage-failed"; rc=$?
if [[ "$rc" -ne 0 ]] && refused "verdict is FAIL"; then
    green "an export whose verdict is not PASS is refused"
else
    red "the failed export (exit ${rc})"; show
fi
E5="${W}/export-moved"; make_export "$E5" 0.1.1 development PASS "$REV"
publish "$E5" "${W}/stage-moved"; rc=$?
if [[ "$rc" -ne 0 ]] && refused "tag v0.1.1 is at" && refused "and the run tested ${REV:0:12}"; then
    green "a tag at another revision than the tested one is refused"
else
    red "the moved tag (exit ${rc})"; show
fi
E6="${W}/export-untagged"; make_export "$E6" 0.2.0 development PASS "$REV"
publish "$E6" "${W}/stage-untagged"; rc=$?
if [[ "$rc" -ne 0 ]] && refused "no tag v0.2.0 here"; then
    green "a version without its tag is refused"
else
    red "the untagged version (exit ${rc})"; show
fi
E7="${W}/export-dated"; make_export "$E7" 0.1.20260928.0123abcd development PASS "$REV"
publish "$E7" "${W}/stage-dated"; rc=$?
if [[ "$rc" -ne 0 ]] && refused "numbered MAJOR.MINOR.PATCH"; then
    green "a dated build is not a release"
else
    red "the dated build (exit ${rc})"; show
fi
mkdir -p "${W}/stage-used"; : > "${W}/stage-used/leftover"
publish "$E" "${W}/stage-used"; rc=$?
if [[ "$rc" -ne 0 ]] && refused "is not empty"; then
    green "a stage directory that already holds files is refused"
else
    red "the used stage directory (exit ${rc})"; show
fi

# --- from 1.0.0 on: a production build, signed by the keys the tree names -----------------
git -C "$T" tag v1.0.0 "$REV"
P="${T}/build/config/release"; mkdir -p "$P"
cp "${K}/release-signers" "$P/"; printf 'cert\n' > "$P/kryptik-sb.crt"
E8="${W}/export-1.0.0"; make_export "$E8" 1.0.0 production PASS "$REV"
publish "$E8" "${W}/stage-1.0.0"; rc=$?
if [[ "$rc" -eq 0 ]] && has "staged v1.0.0, a release"; then
    green "1.0.0 signed by the tree's keys stages as a release"
else
    red "1.0.0 with the tree's keys (exit ${rc})"; show
fi
make_export "$E8" 1.0.0 development PASS "$REV"
publish "$E8" "${W}/stage-1.0.0-dev"; rc=$?
if [[ "$rc" -ne 0 ]] && refused "1.0.0 is a production version"; then
    green "1.0.0 built as a development release is refused"
else
    red "a development 1.0.0 (exit ${rc})"; show
fi
make_export "$E8" 1.0.0 production PASS "$REV"; printf 'another cert\n' > "$P/kryptik-sb.crt"
publish "$E8" "${W}/stage-1.0.0-cert"; rc=$?
if [[ "$rc" -ne 0 ]] && refused "kryptik-sb.crt is not"; then
    green "1.0.0 whose certificate is not the tree's is refused"
else
    red "a 1.0.0 with another certificate (exit ${rc})"; show
fi

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
