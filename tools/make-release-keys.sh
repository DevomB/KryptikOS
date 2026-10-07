#!/usr/bin/env bash
# The release keys, made once (docs/release-keys.md): an encrypted backup, the release environments' secrets, the public halves.
#
#   tools/make-release-keys.sh BACKUP-DIR [--repo OWNER/NAME] [--public DIR]
#
# BACKUP-DIR gets kryptik-keys.tar.gz.enc, the one copy of the private keys outside GitHub: keep it in a second place too.
# The public halves go to DIR (build/config/release by default), to be committed. The plaintext keys live only in
# a temporary directory removed on exit, and nothing is uploaded until the backup has opened with its passphrase.
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

backup="" repo="" public="${KRYPTIK_ROOT}/build/config/release"
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --repo)   repo="${2:?--repo needs OWNER/NAME}"; shift 2 ;;
        --public) public="${2:?--public needs a directory}"; shift 2 ;;
        -*)       die "unknown argument: $1" ;;
        *)        [[ -z "$backup" ]] || die "one backup directory"; backup="$1"; shift ;;
    esac
done
[[ -n "$backup" ]] || die "usage: make-release-keys.sh BACKUP-DIR [--repo OWNER/NAME] [--public DIR]"
for t in ssh-keygen openssl tar base64 gh; do have "$t" || die "${t} is required"; done
[[ -n "$repo" ]] || repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
[[ ! -e "${backup}/kryptik-keys.tar.gz.enc" && ! -e "${public}/release-signers" ]] \
    || die "the keys exist already (${backup}/kryptik-keys.tar.gz.enc or ${public}/release-signers): they are made once, and replaced as docs/release-keys.md says"
mkdir -p "$backup" "$public"
backup="$(cd "$backup" && pwd)"; public="$(cd "$public" && pwd)"

# A secret set in an environment without its rules would be open to any branch.
rules="$(gh api "repos/${repo}/environments/release" --jq '[.protection_rules[].type] | sort | join(",")' 2>/dev/null || true)"
[[ "$rules" == "branch_policy,required_reviewers" ]] \
    || die "the release environment's rules are '${rules:-none}', not a required reviewer and a tag policy (docs/release-keys.md)"
gh api "repos/${repo}/environments/release-tests" --jq '.name' > /dev/null 2>&1 || die "no release-tests environment (docs/release-keys.md)"

read -rs -p "Backup passphrase: " pp; echo
read -rs -p "Again: " pp2; echo
[[ "${#pp}" -ge 12 && "$pp" == "$pp2" ]] || die "the passphrases differ or are shorter than 12 characters"
unset pp2

w="$(mktemp -d)"
trap 'rm -rf "$w"' EXIT
k="${w}/kryptik-keys"; mkdir -p "$k"; cd "$k"
for n in kryptik-release kryptik-latest kryptik-testctl; do
    ssh-keygen -q -t ed25519 -N '' -C "$n" -f "$n" < /dev/null
done
{
    printf 'kryptik-release namespaces="kryptik-release,kryptik-media" %s\n' "$(cut -d' ' -f1,2 kryptik-release.pub)"
    printf 'kryptik-latest namespaces="kryptik-latest" %s\n' "$(cut -d' ' -f1,2 kryptik-latest.pub)"
    printf 'kryptik-testctl namespaces="kryptik-testctl" %s\n' "$(cut -d' ' -f1,2 kryptik-testctl.pub)"
} > release-signers
# MSYS (Git for Windows) would read the subject as a path.
MSYS2_ARG_CONV_EXCL='*' openssl req -new -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
    -subj "/CN=Kryptik Secure Boot/" -keyout kryptik-sb.key -out kryptik-sb.crt 2> /dev/null

export KRYPTIK_BACKUP_PASS="$pp"; unset pp
( cd "$w" && tar -cz kryptik-keys ) \
    | openssl enc -aes-256-cbc -pbkdf2 -iter 1000000 -salt -pass env:KRYPTIK_BACKUP_PASS -out "${backup}/kryptik-keys.tar.gz.enc"
openssl enc -d -aes-256-cbc -pbkdf2 -iter 1000000 -pass env:KRYPTIK_BACKUP_PASS -in "${backup}/kryptik-keys.tar.gz.enc" \
    | tar -tz | grep -qx 'kryptik-keys/kryptik-release' || die "the backup does not open; nothing was uploaded"
unset KRYPTIK_BACKUP_PASS
ok "backup: ${backup}/kryptik-keys.tar.gz.enc"

# The medium the sign job unpacks, every file its owner's alone whatever modes this filesystem keeps.
tar --mode='go-rwx' --owner=0 --group=0 -cz release-signers kryptik-release kryptik-release.pub \
    kryptik-latest kryptik-latest.pub kryptik-sb.key kryptik-sb.crt | base64 -w0 \
    | gh secret set KRYPTIK_KEY_MEDIUM --env release --repo "$repo"
gh secret set KRYPTIK_TESTCTL_KEY --env release-tests --repo "$repo" < kryptik-testctl
gh secret set KRYPTIK_LATEST_KEY --repo "$repo" < kryptik-latest
ok "secrets: KRYPTIK_KEY_MEDIUM (release), KRYPTIK_TESTCTL_KEY (release-tests), KRYPTIK_LATEST_KEY (the repository)"

cp release-signers kryptik-sb.crt "${public}/"
ok "public halves: ${public}/release-signers and ${public}/kryptik-sb.crt, to commit"
echo "The Secure Boot certificate, to compare where it is enrolled: $(openssl x509 -in kryptik-sb.crt -noout -fingerprint -sha256)"
echo "To open the backup: openssl enc -d -aes-256-cbc -pbkdf2 -iter 1000000 -in kryptik-keys.tar.gz.enc | tar -xz"
