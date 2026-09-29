#!/usr/bin/env bash
# A key medium made as docs/release-keys.md makes one, with throwaway keys
# and no passphrases, so a production image can be built and tested. Never for
# a release: these keys are made online and live for one job.
#
#   ./tools/throwaway-key-medium.sh DIR
#
# DIR must not exist yet. It also holds the statement key, which a release's
# medium leaves to the release host, so the build publishes the channel the
# update suite serves. The build checks it as it checks any medium
# (build/lib/release-keys.sh); nothing here is exempt.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

m="${1:?usage: throwaway-key-medium.sh DIR}"
[[ ! -e "$m" ]] || die "${m} exists: a throwaway medium is made fresh"
mkdir -m 0700 "$m"
ssh-keygen -q -t ed25519 -N '' -C kryptik-release -f "${m}/kryptik-release" < /dev/null
ssh-keygen -q -t ed25519 -N '' -C kryptik-latest -f "${m}/kryptik-latest" < /dev/null
ssh-keygen -q -t ed25519 -N '' -C kryptik-testctl -f "${m}/kryptik-testctl" < /dev/null
{
    printf 'kryptik-release namespaces="kryptik-release,kryptik-media" %s\n' "$(cut -d' ' -f1,2 "${m}/kryptik-release.pub")"
    printf 'kryptik-latest namespaces="kryptik-latest" %s\n' "$(cut -d' ' -f1,2 "${m}/kryptik-latest.pub")"
    printf 'kryptik-testctl namespaces="kryptik-testctl" %s\n' "$(cut -d' ' -f1,2 "${m}/kryptik-testctl.pub")"
} > "${m}/release-signers"
openssl req -new -x509 -newkey rsa:3072 -nodes -sha256 -days 7 \
    -subj "/CN=Kryptik Secure Boot (throwaway)/" \
    -keyout "${m}/kryptik-sb.key" -out "${m}/kryptik-sb.crt" 2>/dev/null
chmod 600 "${m}/kryptik-release" "${m}/kryptik-latest" "${m}/kryptik-testctl" "${m}/kryptik-sb.key"
ok "a throwaway key medium in ${m}"
