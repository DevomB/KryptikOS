#!/usr/bin/env bash
# groff: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# groff renders man pages for a terminal. Its HTML output and the mm and pdf
# wrappers are not installed: pre-grohtml, mmroff and pdfmom ran commands
# embedded in their input (fixed in groff 1.24.2), and nothing here renders
# HTML. A sysroot from an earlier build still holds them, so they are removed.
s_groff() {
    native_build "groff-${V_GROFF}.tar.gz" "groff-${V_GROFF}"
    rm -f /usr/bin/pre-grohtml /usr/bin/post-grohtml /usr/bin/mmroff /usr/bin/pdfmom
    rm -rf /usr/share/groff/"${V_GROFF}"/font/devhtml /usr/share/groff/"${V_GROFF}"/font/devxhtml
    rm -f /usr/share/man/man1/grohtml.1* /usr/share/man/man1/mmroff.1* /usr/share/man/man1/pdfmom.1*
}
