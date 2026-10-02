#!/usr/bin/env bash

s_iana_etc() {
    # Not a build: /etc/protocols and /etc/services are data files.
    local src; src="$(unpack "iana-etc-${V_IANA_ETC}.tar.gz" "iana-etc-${V_IANA_ETC}")"
    cd "$src"
    cp -v services protocols /etc
}
