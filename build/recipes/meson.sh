#!/usr/bin/env bash
# meson: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# meson runs uninstalled from its own tree, avoiding the unpinned pip, wheel
# and setuptools.
s_meson() {
    local src; src="$(unpack "meson-${V_MESON}.tar.gz" "meson-${V_MESON}")"
    rm -rf /usr/lib/meson
    mkdir -p /usr/lib/meson
    cp -r "$src/mesonbuild" "$src/meson.py" /usr/lib/meson/
    cat > /usr/bin/meson <<'EOF'
#!/bin/sh
exec /usr/bin/python3 /usr/lib/meson/meson.py "$@"
EOF
    chmod 0755 /usr/bin/meson
    meson --version
}
