#!/usr/bin/env bash

# Mozilla's CA bundle where OpenSSL and python look: releases are signed, but servers are verified.
s_ca_bundle() {
    local pem="${KRYPTIK_SOURCES}/cacert-${V_CA_BUNDLE}.pem"
    [[ -f "$pem" ]] || { echo "FAIL: ${pem} was not fetched"; return 1; }
    local n; n="$(grep -c 'BEGIN CERTIFICATE' "$pem")"
    [[ "$n" -ge 100 ]] || { echo "FAIL: ${pem} holds ${n} certificates; expected Mozilla's set"; return 1; }
    install -D -m 0644 "$pem" "${KRYPTIK_DESTDIR}/etc/ssl/certs/ca-certificates.crt"
    ln -sfn certs/ca-certificates.crt "${KRYPTIK_DESTDIR}/etc/ssl/cert.pem"
    echo "installed ${n} certificates as /etc/ssl/certs/ca-certificates.crt"
    # The default lookup must find it, from both places the image speaks TLS.
    openssl version -d
    python3 -c 'import ssl; n = len(ssl.create_default_context().get_ca_certs()); print("python ssl default context:", n, "CAs"); raise SystemExit(0 if n >= 100 else 1)' \
        || { echo "FAIL: python's default TLS context does not find the bundle"; return 1; }
}
