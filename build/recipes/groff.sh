#!/usr/bin/env bash

# Man pages for a terminal; no HTML output, mmroff or pdfmom, which run commands from their input.
s_groff() {
    native_build "groff-${V_GROFF}.tar.gz" "groff-${V_GROFF}"
    rm -f /usr/bin/pre-grohtml /usr/bin/post-grohtml /usr/bin/mmroff /usr/bin/pdfmom
    rm -rf /usr/share/groff/"${V_GROFF}"/font/devhtml /usr/share/groff/"${V_GROFF}"/font/devxhtml
    rm -f /usr/share/man/man1/grohtml.1* /usr/share/man/man1/mmroff.1* /usr/share/man/man1/pdfmom.1*
}
