#!/usr/bin/env bash
# The production pair acceptance's production suite updates across: releases
# 1.0.0 and 1.0.1, signed with a throwaway key medium that lives only while
# they are built (tools/throwaway-key-medium.sh), then moved to
# <work>/images-production, where 1.0.x cannot sort above the development
# releases in images/. Before the medium is deleted, the work tree is searched
# for a line of each private key's secret.
#
#   make production-pair [KRYPTIK_KRYPTIKD_BIN=... KRYPTIK_WLPROXY_BIN=...]
#
# Build it before the development releases: the suites take the release built
# last as the one under test.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

read -ra sudo <<< "${SUDO-sudo}"
t="$(mktemp -d)"
trap 'rm -rf "$t"' EXIT
m="${t}/medium"
"${KRYPTIK_ROOT}/tools/throwaway-key-medium.sh" "$m"
for v in 1.0.0 1.0.1; do
    make -C "$KRYPTIK_ROOT" media KRYPTIK_VERSION="$v" KRYPTIK_ROLE=production KRYPTIK_KEYS="$m"
done

img="${KRYPTIK_WORK}/images" p="${KRYPTIK_WORK}/images-production"
"${sudo[@]}" rm -rf "$p"
"${sudo[@]}" mkdir -p "$p"
"${sudo[@]}" mv "$img"/kryptik-1.0.[01][-.]* "$img"/payload-1.0.[01] "$img"/channel-1.0.[01] "$p/"
"${sudo[@]}" cp "${m}/kryptik-sb.crt" "$p/"

# An OpenSSH key's fifth line holds its seed; the last line of a PEM key's body
# ends its private values.
{ sed -n 5p "${m}/kryptik-release"; sed -n 5p "${m}/kryptik-latest"; tail -n 2 "${m}/kryptik-sb.key" | head -n 1; } > "${t}/lines"
rc=0
"${sudo[@]}" grep -rlF -D skip -f "${t}/lines" "$KRYPTIK_WORK" || rc=$?
case "$rc" in
    0) die "a throwaway private key is in the work tree" ;;
    1) ;;
    *) die "could not search ${KRYPTIK_WORK} for the keys (grep exited ${rc})" ;;
esac
ok "the production pair is in ${p}, and no line of its keys' secrets is in ${KRYPTIK_WORK}"
