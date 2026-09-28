#!/usr/bin/env bash
# s6: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_s6_stack() {
    # ADR-006. skarnet packages use their own configure conventions. Whole
    # tarball names, so the step's stamp hashes each one.
    local tb p
    for tb in "skalibs-${V_SKALIBS}.tar.gz" "execline-${V_EXECLINE}.tar.gz" \
              "s6-${V_S6}.tar.gz" "s6-rc-${V_S6_RC}.tar.gz" \
              "s6-linux-init-${V_S6_LINUX_INIT}.tar.gz"; do
        p="${tb%.tar.gz}"
        echo "--- ${p} ---"
        local src; src="$(unpack "$tb" "$p")"
        cd "$src"

        # --skeldir: with --prefix=/usr the skeleton would land in /usr/etc,
        # where s6-linux-init-maker does not look, leaving no stage 2 scripts.
        local extra=()
        case "$p" in
            s6-linux-init-*) extra=(--skeldir=/etc/s6-linux-init/skel) ;;
        esac

        ./configure --prefix=/usr --libdir=/usr/lib --with-dynlib=/usr/lib "${extra[@]}"
        make
        make install
    done
}
