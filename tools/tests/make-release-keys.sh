#!/usr/bin/env bash
# tools/make-release-keys.sh against a stand-in gh: a backup that opens, each secret in its place, and a medium the build takes.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
for t in ssh-keygen openssl tar base64; do command -v "$t" > /dev/null || { echo "${t} required"; exit 77; }; done

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
cat > "$T/bin/gh" <<'GH'
#!/usr/bin/env bash
case "$1" in
    api)
        case "$2" in
            */environments/release) printf '%s\n' "${GH_RULES-branch_policy,required_reviewers}" ;;
            */environments/release-tests) echo release-tests ;;
            */environments/github-pages/deployment-branch-policies) printf '%s\n' "${GH_PAGES-branch:main}" ;;
        esac ;;
    secret)
        name="$3"; shift 3; env=repository
        while [[ "$#" -gt 0 ]]; do case "$1" in --env) env="$2"; shift 2 ;; *) shift ;; esac; done
        cat > "${GH_OUT}/${env}-${name}" ;;
esac
GH
chmod +x "$T/bin/gh"
fresh() { rm -rf "$T/backup" "$T/public" "$T/gh"; mkdir -p "$T/gh"; }
mk() {   # mk PASSPHRASE AGAIN: the tool, its output in $T/out
    printf '%s\n%s\n' "$1" "$2" | PATH="$T/bin:$PATH" GH_OUT="$T/gh" NO_COLOR=1 \
        bash "$ROOT/tools/make-release-keys.sh" "$T/backup" --repo owner/repo --public "$T/public" > "$T/out" 2>&1
}
PP="correct horse battery staple"

fresh; mk "$PP" "$PP"; rc=$?
if [[ "$rc" -eq 0 ]] && KP="$PP" openssl enc -d -aes-256-cbc -pbkdf2 -iter 1000000 -pass env:KP -in "$T/backup/kryptik-keys.tar.gz.enc" \
        | tar -tz | sort | tr '\n' ' ' | grep -q 'kryptik-keys/kryptik-release .*kryptik-keys/kryptik-sb.key .*kryptik-keys/kryptik-testctl '; then
    ok "the backup opens with its passphrase and holds every key"
else
    bad "the backup (exit ${rc})"; cat "$T/out"
fi
listing="$(base64 -d "$T/gh/release-KRYPTIK_KEY_MEDIUM" | tar --numeric-owner -tvz 2>/dev/null)"
if [[ "$(wc -l <<< "$listing")" -eq 7 ]] && ! grep -q kryptik-testctl <<< "$listing" \
    && [[ -z "$(awk '$1 != "-rw-------" || $2 != "0/0"' <<< "$listing")" ]]; then
    ok "the release environment's medium is seven owner-only files, without the control-disk key"
else
    bad "the medium: ${listing}"
fi
if head -1 "$T/gh/release-tests-KRYPTIK_TESTCTL_KEY" | grep -q 'OPENSSH PRIVATE KEY' \
    && head -1 "$T/gh/github-pages-KRYPTIK_LATEST_KEY" | grep -q 'OPENSSH PRIVATE KEY' \
    && [[ ! -e "$T/gh/repository-KRYPTIK_LATEST_KEY" ]] \
    && [[ "$(awk '{print $1}' "$T/public/release-signers" | tr '\n' ' ')" == "kryptik-release kryptik-latest kryptik-testctl " ]] \
    && openssl x509 -in "$T/public/kryptik-sb.crt" -noout 2>/dev/null; then
    ok "the control-disk and statement keys go to their environments, none to the whole repository, and the anchor and certificate to the tree"
else
    bad "the other secrets or the public halves: $(ls "$T/gh" "$T/public")"
fi

# What the sign job unpacks must pass the build's own checks of a key medium.
M="$T/medium"; mkdir -m 0700 "$M"; base64 -d "$T/gh/release-KRYPTIK_KEY_MEDIUM" | tar -xz -C "$M"
if KRYPTIK_WORK="$T/work" KRYPTIK_OUT="$T/built" KRYPTIK_KEYS="$M" NO_COLOR=1 bash -c \
        'source "$1/build/lib/common.sh"; source "$1/build/lib/release-keys.sh"; release_keys production; [[ "$RELEASE_KEY" == "$2/kryptik-release" ]]' \
        _ "$ROOT" "$M" > "$T/out" 2>&1; then
    ok "the medium passes the build's checks for production keys"
else
    bad "the build refuses the medium"; cat "$T/out"
fi

mk "$PP" "$PP"; rc=$?
[[ "$rc" -ne 0 ]] && grep -q "made once" "$T/out" && ok "keys that exist are never made again" || { bad "a second run (exit ${rc})"; cat "$T/out"; }

fresh; GH_RULES=branch_policy mk "$PP" "$PP"; rc=$?
[[ "$rc" -ne 0 && -z "$(ls -A "$T/gh")" ]] && grep -q "not a required reviewer" "$T/out" \
    && ok "an environment without a reviewer gets no secret" || { bad "an unreviewed environment (exit ${rc})"; cat "$T/out"; }

# Every branch's workflows could read a statement key that main's alone does not hold.
for pages in "" "branch:main,branch:dev" "tag:v*"; do
    fresh; GH_PAGES="$pages" mk "$PP" "$PP"; rc=$?
    [[ "$rc" -ne 0 && -z "$(ls -A "$T/gh")" ]] && grep -q "not main alone" "$T/out" \
        && ok "a github-pages environment deploying from '${pages:-any branch}' gets no secret" \
        || { bad "github-pages deploying from '${pages}' (exit ${rc})"; cat "$T/out"; }
done

fresh; mk "$PP" "another one entirely"; rc=$?
[[ "$rc" -ne 0 && ! -e "$T/backup/kryptik-keys.tar.gz.enc" && -z "$(ls -A "$T/gh")" ]] \
    && ok "passphrases that differ make nothing" || { bad "differing passphrases (exit ${rc})"; cat "$T/out"; }
fresh; mk short short; rc=$?
[[ "$rc" -ne 0 ]] && ok "a short passphrase is refused" || bad "a short passphrase was taken"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
