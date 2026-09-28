#!/usr/bin/env bash
# iputils: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# iputils' ping alone, without libcap, with no setuid bit or file capability:
# in a routed zone it sends over the ICMP datagram socket ping_group_range opens
# (netzone.rs), and the patch stops it making the id calls a zone refuses.
s_iputils() {
    local src; src="$(unpack "iputils-${V_IPUTILS}.tar.xz" "iputils-${V_IPUTILS}")"
    cd "$src"
    apply_repo_patches "iputils-${V_IPUTILS}"
    meson setup build --prefix=/usr --buildtype=plain --wrap-mode=nodownload \
        -DBUILD_PING=true -DBUILD_ARPING=false -DBUILD_CLOCKDIFF=false -DBUILD_TRACEPATH=false \
        -DUSE_CAP=false -DUSE_IDN=false -DUSE_GETTEXT=false -DNO_SETCAP_OR_SUID=true \
        -DBUILD_MANS=true -DBUILD_HTML_MANS=false -DSKIP_TESTS=true
    ninja -C build
    ninja -C build install
    # The tarball's prebuilt ping.8, installed without xsltproc, comes with an
    # HTML copy that nothing reads.
    rm -rf /usr/share/iputils
    [[ -f /usr/share/man/man8/ping.8 ]] || { echo "FAIL: ping.8 was not installed"; return 1; }
    local out; out="$(/usr/bin/ping -V)"
    printf '%s\n' "$out"
    [[ "$out" == *"libcap: no"* ]] || { echo "FAIL: ping was built with libcap"; return 1; }
    [[ "$(stat -c %a /usr/bin/ping)" == 755 ]] || { echo "FAIL: /usr/bin/ping is mode $(stat -c %a /usr/bin/ping), not 755"; return 1; }
    [[ ! -e /usr/bin/ping6 ]] || { echo "FAIL: a ping6 is installed beside ping"; return 1; }
}
