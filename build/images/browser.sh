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
    local src llvm="/usr/lib/llvm-${V_LLVM%%.*}" gccdir
    # bindgen's libclang finds GCC's C++ headers only under triples it knows, and this GCC's is
    # x86_64-kryptik-linux-gnu: it is named, and a header parsed here first, not an hour into the build.
    gccdir="$(dirname "$(gcc -print-libgcc-file-name)")"
    echo '#include <cstdint>' | "${llvm}/bin/clang" -x c++ -fsyntax-only --gcc-install-dir="$gccdir" -
    src="$(unpack "firefox-${V_FIREFOX}esr.source.tar.xz" "firefox-${V_FIREFOX}")"
    cd "$src"
    # Configure requires unzip, which only packaging runs (make_unzip.py: `unzip ARCHIVE`, into the
    # current directory) and the base system does not have: Python's zipfile does that, here alone.
    # And llvm-objdump, which it finds by asking the compiler when that is clang: GCC's, it is named.
    cat > kryptik-unzip <<'EOF'
#!/usr/bin/env python3
import sys, zipfile
args = [a for a in sys.argv[1:] if a not in ("-q", "-o", "-qo", "-oq")]
dest = "."
if len(args) == 3 and args[1] == "-d":
    dest = args.pop(2)
    args.pop(1)
if len(args) != 1:
    sys.exit("kryptik-unzip: only ARCHIVE [-d DIR]: " + " ".join(sys.argv[1:]))
zipfile.ZipFile(args[0]).extractall(dest)
EOF
    chmod 0755 kryptik-unzip
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
export UNZIP=${src}/kryptik-unzip
export LLVM_OBJDUMP=${llvm}/bin/llvm-objdump
export BINDGEN_CFLAGS="--gcc-install-dir=${gccdir}"
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
