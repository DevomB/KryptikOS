#!/usr/bin/env bash
# The browser image: Firefox ESR for Wayland alone, over the toolkit image, built with the rust,
# clang, cbindgen and nasm layers, which it does not carry (docs/design/browser-and-graphics.md).
# Its own copies of NSS, NSPR, libvpx, dav1d and opus stay bundled. Its PDF viewer is the document
# viewer. Pins in build/images/versions.env.
# shellcheck disable=SC2034  # read by build/stages/04-images.sh
image_version="${V_FIREFOX}esr"
# shellcheck disable=SC2034
image_over=(toolkit rust clang cbindgen nasm)
# shellcheck disable=SC2034
image_rows=(
    "firefox"   "s_browser_firefox"
    "licences"  "s_browser_licences"
)

# Stage 04's GCC and hardening flags; libclang only for bindgen. With no network: Firefox's own vendored
# crates and Python packages, no toolchain bootstrap, no Node.js. No D-Bus, which no zone has, no updater
# (updates are the image's), no crash reporter, no EME, no jemalloc (hardened_malloc is preloaded), and
# no sound until sound reaches zones. The first build keeps no wasm sandbox for its libraries. No debug
# symbols: stage 06 strips them anyway, and linking libxul with them would need more than the runner has.
s_browser_firefox() {
    local src llvm="/usr/lib/llvm-${V_LLVM%%.*}"
    src="$(unpack "firefox-${V_FIREFOX}esr.source.tar.xz" "firefox-${V_FIREFOX}")"
    cd "$src"
    cat > mozconfig <<EOF
ac_add_options --prefix=/usr
ac_add_options --enable-application=browser
ac_add_options --enable-default-toolkit=cairo-gtk3-wayland-only
ac_add_options --enable-release
ac_add_options --disable-debug
ac_add_options --disable-debug-symbols
ac_add_options --disable-tests
ac_add_options --disable-bootstrap
ac_add_options --disable-nodejs
ac_add_options --disable-dbus
ac_add_options --disable-necko-wifi
ac_add_options --disable-updater
ac_add_options --disable-crashreporter
ac_add_options --disable-eme
ac_add_options --disable-jemalloc
ac_add_options --disable-audio-backends
ac_add_options --without-wasm-sandboxed-libraries
ac_add_options --with-libclang-path=${llvm}/lib
ac_add_options --with-clang-path=${llvm}/bin/clang
mk_add_options MOZ_OBJDIR=@TOPSRCDIR@/obj
EOF
    env CC=gcc CXX=g++ MOZBUILD_STATE_PATH="${src}/.mozbuild" MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE=none \
        MOZ_NOSPAM=1 ./mach --no-interactive build
    env MOZBUILD_STATE_PATH="${src}/.mozbuild" ./mach --no-interactive install
    test -x /usr/lib/firefox/firefox
    # Enterprise policies: no telemetry or studies, no update checks (updates are the image's), and
    # no question of the default browser, which a zone has no other of.
    install -d -m 0755 /usr/lib/firefox/distribution
    cat > /usr/lib/firefox/distribution/policies.json <<'EOF'
{
  "policies": {
    "DisableTelemetry": true,
    "DisableFirefoxStudies": true,
    "DisableAppUpdate": true,
    "DontCheckDefaultBrowser": true
  }
}
EOF
}

s_browser_licences() {
    echo "$(source_licences < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list-image browser)) licence files"
}
