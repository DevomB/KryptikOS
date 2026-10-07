#!/usr/bin/env bash

# chroot goes to /usr/sbin, over the unhardened copy stage 02 put there.
s_coreutils() {
    native_build "coreutils-${V_COREUTILS}.tar.xz" "coreutils-${V_COREUTILS}" \
        --enable-no-install-program=kill,uptime
    mv -f /usr/bin/chroot /usr/sbin/chroot
    mkdir -p /usr/share/man/man8
    if [[ -f /usr/share/man/man1/chroot.1 ]]; then
        mv -f /usr/share/man/man1/chroot.1 /usr/share/man/man8/chroot.8
        sed -i 's/"1"/"8"/' /usr/share/man/man8/chroot.8
    fi
}
