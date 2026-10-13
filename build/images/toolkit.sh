#!/usr/bin/env bash
# The toolkit image: GTK 3 for Wayland alone, without X11, D-Bus or GObject introspection, and the
# libraries under it (docs/design/browser-and-graphics.md). The browser image is built over it; its
# demos are the first GUI programs a zone can run. Sources pinned in build/images/versions.env.
# shellcheck disable=SC2034  # read by build/stages/04-images.sh
image_version="${V_GTK3}"
# shellcheck disable=SC2034
image_rows=(
    "pcre2"        "s_tk_pcre2"
    "glib"         "s_tk_glib"
    "libpng"       "s_tk_libpng"
    "freetype"     "s_tk_freetype"
    "harfbuzz"     "s_tk_harfbuzz"
    "fontconfig"   "s_tk_fontconfig"
    "fribidi"      "s_tk_fribidi"
    "cairo"        "s_tk_cairo"
    "pango"        "s_tk_pango"
    "gdk-pixbuf"   "s_tk_gdk_pixbuf"
    "egl-headers"  "s_tk_egl_headers"
    "libepoxy"     "s_tk_libepoxy"
    "atk"          "s_tk_atk"
    "hicolor"      "s_tk_hicolor"
    "gtk3"         "s_tk_gtk3"
    "licences"     "s_tk_licences"
)

# Only what GLib needs: the 8-bit library, without the JIT, which writes code into memory it runs.
s_tk_pcre2() {
    native_build "pcre2-${V_PCRE2}.tar.bz2" "pcre2-${V_PCRE2}" --disable-static --enable-unicode \
        --disable-jit --disable-pcre2-16 --disable-pcre2-32 --disable-pcre2grep-libz \
        --disable-pcre2grep-libbz2 --disable-pcre2test-libreadline
    rm -f /usr/bin/pcre2grep /usr/bin/pcre2test /usr/bin/pcre2-config
}

s_tk_glib() {
    meson_build "glib-${V_GLIB}.tar.xz" "glib-${V_GLIB}" \
        -Dselinux=disabled -Dlibmount=disabled -Dlibelf=disabled -Dsysprof=disabled \
        -Dintrospection=disabled -Dman-pages=disabled -Ddocumentation=false -Dtests=false \
        -Dinstalled_tests=false -Ddtrace=disabled -Dsystemtap=disabled -Dglib_debug=disabled
}

s_tk_libpng() {
    native_build "libpng-${V_LIBPNG}.tar.xz" "libpng-${V_LIBPNG}" --disable-static
    rm -f /usr/bin/pngfix /usr/bin/png-fix-itxt /usr/bin/libpng-config /usr/bin/libpng16-config
}

# Without HarfBuzz, which is built on it, and without brotli and bzip2, which no shipped font needs.
s_tk_freetype() {
    meson_build "freetype-${V_FREETYPE}.tar.xz" "freetype-${V_FREETYPE}" \
        -Dharfbuzz=disabled -Dbrotli=disabled -Dbzip2=disabled -Dpng=enabled -Dzlib=system -Dtests=disabled
}

# The shaping library alone: no subsetter, rasteriser, vector or GPU paths, and no utilities.
s_tk_harfbuzz() {
    meson_build "harfbuzz-${V_HARFBUZZ}.tar.xz" "harfbuzz-${V_HARFBUZZ}" \
        -Dglib=enabled -Dfreetype=enabled -Dgobject=disabled -Dcairo=disabled -Dchafa=disabled \
        -Dicu=disabled -Dpng=disabled -Dzlib=disabled -Draster=disabled -Dvector=disabled \
        -Dgpu=disabled -Dgpu_demo=disabled -Dsubset=disabled -Dutilities=disabled \
        -Dtests=disabled -Dintrospection=disabled -Ddocs=disabled -Dbenchmark=disabled
}

# Its configuration under /usr/etc, as an image adds nothing outside /usr. No system cache is made: a
# zone's fontconfig keeps one in the user's home.
s_tk_fontconfig() {
    meson_build "fontconfig-${V_FONTCONFIG}.tar.xz" "fontconfig-${V_FONTCONFIG}" --sysconfdir=/usr/etc \
        -Dtools=enabled -Dcache-build=disabled -Ddoc=disabled -Dtests=disabled -Dnls=disabled \
        -Dxml-backend=expat -Dfontations=disabled
    rmdir /var/cache/fontconfig
}

s_tk_fribidi() {
    meson_build "fribidi-${V_FRIBIDI}.tar.xz" "fribidi-${V_FRIBIDI}" -Ddocs=false -Dbin=false -Dtests=false
}

# PDF and PostScript surfaces for GTK's print-to-file; no X11, and no tracer or script interpreter,
# which zlib would otherwise bring.
s_tk_cairo() {
    meson_build "cairo-${V_CAIRO}.tar.xz" "cairo-${V_CAIRO}" \
        -Dxlib=disabled -Dxcb=disabled -Dquartz=disabled -Ddwrite=disabled -Dtee=disabled \
        -Dpng=enabled -Dzlib=enabled -Dfreetype=enabled -Dfontconfig=enabled -Dglib=enabled \
        -Dspectre=disabled -Dsymbol-lookup=disabled -Dlzo=disabled -Dtests=disabled
    rm -rf /usr/lib/cairo /usr/bin/cairo-trace
    rm -f /usr/lib/libcairo-script-interpreter.so* /usr/lib/pkgconfig/cairo-script-interpreter.pc \
        /usr/include/cairo/cairo-script-interpreter.h
}

s_tk_pango() {
    meson_build "pango-${V_PANGO}.tar.xz" "pango-${V_PANGO}" \
        -Dintrospection=disabled -Dbuild-testsuite=false -Dbuild-examples=false -Dfontconfig=enabled \
        -Dfreetype=enabled -Dcairo=enabled -Dlibthai=disabled -Dxft=disabled -Dsysprof=disabled
    rm -f /usr/bin/pango-view /usr/bin/pango-list /usr/bin/pango-segmentation
}

# PNG alone, built in: GTK's theme and icons are PNG, and every other loader is a parser more.
s_tk_gdk_pixbuf() {
    meson_build "gdk-pixbuf-${V_GDK_PIXBUF}.tar.xz" "gdk-pixbuf-${V_GDK_PIXBUF}" \
        -Dpng=enabled -Djpeg=disabled -Dtiff=disabled -Dgif=disabled -Dothers=disabled \
        -Dglycin=disabled -Dandroid=disabled -Dbuiltin_loaders=png -Dgio_sniffing=false \
        -Dthumbnailer=disabled -Dintrospection=disabled -Dman=false -Dtests=false -Dinstalled_tests=false
}

# The Khronos EGL headers that libepoxy and GTK's Wayland backend compile against, and nothing else of
# libglvnd: no EGL library comes with them, as a zone has no GPU. Its README holds the licences.
s_tk_egl_headers() {
    local src; src="$(unpack "libglvnd-v${V_LIBGLVND}.tar.gz" "libglvnd-v${V_LIBGLVND}")"
    install -D -m 0644 -t /usr/include/EGL "${src}"/include/EGL/{egl,eglext,eglplatform}.h
    install -D -m 0644 -t /usr/include/KHR "${src}/include/KHR/khrplatform.h"
    install -D -m 0644 "${src}/README.md" /usr/share/licenses/libglvnd/README.md
}

# EGL only, loaded when a program asks for GL; software zones never do.
s_tk_libepoxy() {
    meson_build "libepoxy-${V_LIBEPOXY}.tar.gz" "libepoxy-${V_LIBEPOXY}" \
        -Dglx=no -Degl=yes -Dx11=false -Dtests=false -Ddocs=false
}

# ATK alone: the accessibility bridge talks D-Bus, which no zone has.
s_tk_atk() {
    local src; src="$(unpack "at-spi2-core-${V_AT_SPI2_CORE}.tar.xz" "at-spi2-core-${V_AT_SPI2_CORE}")"
    cd "$src"
    apply_repo_patches "at-spi2-core-${V_AT_SPI2_CORE}"
    meson setup build --prefix=/usr --buildtype=plain --wrap-mode=nodownload \
        -Datk_only=true -Dintrospection=disabled -Ddocs=false -Dx11=disabled \
        -Dgtk2_atk_adaptor=false -Duse_systemd=false
    ninja -C build
    ninja -C build install
}

s_tk_hicolor() {
    meson_build "hicolor-icon-theme-${V_HICOLOR_ICON_THEME}.tar.xz" "hicolor-icon-theme-${V_HICOLOR_ICON_THEME}"
}

# Wayland alone; input methods built in, so no module cache is read; printing to a file only.
s_tk_gtk3() {
    meson_build "gtk-${V_GTK3}.tar.xz" "gtk-${V_GTK3}" --sysconfdir=/usr/etc \
        -Dx11_backend=false -Dwayland_backend=true -Dbroadway_backend=false -Dxinerama=no \
        -Dcloudproviders=false -Dprofiler=false -Dtracker3=false -Dcolord=no -Dprint_backends=file \
        -Dintrospection=false -Dgtk_doc=false -Dman=false -Ddemos=true -Dexamples=false -Dtests=false \
        -Dinstalled_tests=false -Dbuiltin_immodules=all
    # Property names for interface builders: no program in a zone shows them.
    rm -f /usr/share/locale/*/LC_MESSAGES/gtk30-properties.mo
}

s_tk_licences() {
    echo "$(source_licences < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list-image toolkit)) licence files"
}
