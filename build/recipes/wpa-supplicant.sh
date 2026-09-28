#!/usr/bin/env bash
# wpa-supplicant: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# wpa_supplicant from its own .config: nl80211 through libnl, the unix control
# interface for wpa_cli (no D-Bus or readline), OpenSSL for WPA3-SAE, OWE, DPP
# and enterprise EAP, 802.11r and protected management frames, and AP mode,
# which only the zones suite uses: its access point on mac80211_hwsim is this
# binary in a namespace of its own. Its Makefile takes CFLAGS from the
# environment, so the hardening flags apply.
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
