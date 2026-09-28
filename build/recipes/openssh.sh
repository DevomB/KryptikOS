#!/usr/bin/env bash
# openssh: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# Only ssh-keygen, whose -Y verifies them; no sshd, ssh or host keys.
s_openssh() {
    local src; src="$(unpack "openssh-${V_OPENSSH}.tar.gz" "openssh-${V_OPENSSH}")"
    cd "$src"
    ./configure --prefix=/usr --sysconfdir=/etc/ssh --with-privsep-path=/var/lib/sshd \
        --with-default-path=/usr/bin --with-superuser-path=/usr/sbin:/usr/bin \
        --with-pid-dir=/run --without-pam
    make ssh-keygen
    install -m 0755 ssh-keygen /usr/bin/ssh-keygen
    # Captured, not piped: the usage exits non-zero. Without -Y ssh-keygen says
    # "unknown option -- Y"; with it, it complains of missing arguments.
    local out
    out="$(ssh-keygen -Y verify 2>&1 || true)"
    case "$out" in
        *"unknown option"*|*"illegal option"*) echo "FAIL: ssh-keygen has no -Y: ${out}"; return 1 ;;
        *namespace*|*verify*|*usage*) echo "ok: ssh-keygen supports -Y (${out})" ;;
        *) echo "FAIL: unexpected ssh-keygen -Y verify output: ${out}"; return 1 ;;
    esac
}
