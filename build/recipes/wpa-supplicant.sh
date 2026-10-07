#!/usr/bin/env bash

# CONFIG_AP is for the zones suite, whose hwsim access point is this binary in its own namespace.
s_wpa_supplicant() {
    local src; src="$(unpack "wpa_supplicant-${V_WPA_SUPPLICANT}.tar.gz" "wpa_supplicant-${V_WPA_SUPPLICANT}")"
    cd "$src/wpa_supplicant"
    cat > .config <<'EOF'
CONFIG_DRIVER_NL80211=y
CONFIG_LIBNL32=y
CONFIG_CTRL_IFACE=y
CONFIG_BACKEND=file
CONFIG_AP=y
CONFIG_TLS=openssl
CONFIG_IEEE80211W=y
CONFIG_IEEE80211R=y
CONFIG_SAE=y
CONFIG_OWE=y
CONFIG_DPP=y
CONFIG_EAP_TLS=y
CONFIG_EAP_PEAP=y
CONFIG_EAP_TTLS=y
CONFIG_EAP_MSCHAPV2=y
CONFIG_PKCS12=y
CONFIG_DEBUG_FILE=y
EOF
    make BINDIR=/usr/sbin LIBDIR=/usr/lib
    make BINDIR=/usr/sbin LIBDIR=/usr/lib install
    local b
    for b in wpa_supplicant wpa_cli wpa_passphrase; do
        [[ -x "/usr/sbin/$b" ]] || { echo "FAIL: /usr/sbin/$b was not installed"; return 1; }
    done
    wpa_supplicant -v 2>&1 | sed -n 1p
}
