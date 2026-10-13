#!/usr/bin/env bash

# Only ssh-keygen, whose -Y verifies update manifests; no sshd, ssh or host keys.
s_openssh() {
    local src; src="$(unpack "openssh-${V_OPENSSH}.tar.gz" "openssh-${V_OPENSSH}")"
    cd "$src"
    ./configure --prefix=/usr --sysconfdir=/etc/ssh --with-privsep-path=/var/lib/sshd \
        --with-default-path=/usr/bin --with-superuser-path=/usr/sbin:/usr/bin \
        --with-pid-dir=/run --without-pam
    make ssh-keygen
    install -m 0755 ssh-keygen /usr/bin/ssh-keygen
    # Captured, as the usage exits non-zero; with no -Y support it says "unknown option -- Y".
    local out
    out="$(ssh-keygen -Y verify 2>&1 || true)"
    case "$out" in
        *"unknown option"*|*"illegal option"*) echo "FAIL: ssh-keygen has no -Y: ${out}"; return 1 ;;
        *namespace*|*verify*|*usage*) echo "ok: ssh-keygen supports -Y (${out})" ;;
        *) echo "FAIL: unexpected ssh-keygen -Y verify output: ${out}"; return 1 ;;
    esac
}
