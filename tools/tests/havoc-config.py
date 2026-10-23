#!/usr/bin/env python3
"""Kryptik's havoc.cfg, offline: the patch set makes havoc read it, the recipe and stage 04 install
it by digest, and the file names the font fonts.sh installs, keeps scrollback, binds copy and paste,
and every colour reads on its background."""
import configparser
import hashlib
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CFG = os.path.join(ROOT, "build", "desktop", "havoc.cfg")
PSET = os.path.join(ROOT, "build", "patches", "havoc-0.7.0")
failed = 0


def check(ok, what):
    global failed
    print(("  ok    " if ok else "  FAIL  ") + what)
    if not ok:
        failed += 1


def read(*path):
    with open(os.path.join(ROOT, *path), encoding="utf-8") as f:
        return f.read()


def luminance(hexcolour):
    """WCAG 2.1 relative luminance of #rrggbb."""
    def lin(c):
        c /= 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (int(hexcolour[i:i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)


def contrast(a, b):
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


# The patch set: what apply_repo_patches verifies, and the one change it makes.
sums = {}
for line in read("build", "patches", "havoc-0.7.0", "SHA256SUMS").splitlines():
    digest, _, name = line.partition("  ")
    sums[name] = digest
patches = sorted(n for n in os.listdir(PSET) if n.endswith(".patch"))
check(bool(patches) and sorted(sums) == patches, "SHA256SUMS lists every patch, two spaces before each name")
for name in patches:
    with open(os.path.join(PSET, name), "rb") as f:
        check(hashlib.sha256(f.read()).hexdigest() == sums.get(name), f"{name} matches SHA256SUMS")
patch = "".join(read("build", "patches", "havoc-0.7.0", n) for n in patches)
check('-\tf = fopen(CONF_FILE, "r");' in patch and '+\tf = fopen("/usr/share/kryptik/havoc.cfg", "r");' in patch,
      "the patch puts Kryptik's file in place of the working directory's")

# The recipe installs this file, not upstream's, after the patch set, and stage 04 passes its digest.
recipe = read("build", "recipes", "havoc.sh")
check('apply_repo_patches "havoc-${V_HAVOC}"' in recipe, "s_havoc applies the patch set")
check('install -Dm644 "$cfg" /usr/share/kryptik/havoc.cfg' in recipe and "install -Dm644 havoc.cfg" not in recipe,
      "s_havoc installs build/desktop/havoc.cfg, not upstream's")
check(re.search(r'"havoc"\s+"s_havoc \$\(sha256_of "\$\{KRYPTIK_ROOT\}/build/desktop/havoc\.cfg"', read("build", "stages", "04-base-system.sh"))
      is not None, "stage 04 rebuilds havoc when havoc.cfg changes")

# The file itself, read as havoc reads it: sections and key=value lines.
cfg = configparser.ConfigParser(interpolation=None, delimiters=("=",))
cfg.optionxform = str
cfg.read(CFG, encoding="utf-8")
fonts = read("build", "recipes", "fonts.sh")
path = cfg.get("font", "path", fallback="")
check(path.startswith("/usr/share/fonts/TTF/") and os.path.basename(path) in fonts,
      f"the font {path or '(none)'} is one fonts.sh installs")
check(int(cfg.get("terminal", "scrollback", fallback="0")) > 0, "scrollback is kept")
check(cfg.get("bind", "C-S-c", fallback="") == "copy" and cfg.get("bind", "C-S-v", fallback="") == "paste",
      "Ctrl+Shift+C and V copy and paste")
check(cfg.get("window", "opacity", fallback="") == "255", "the window is opaque")
check(not cfg.has_section("child"), "no [child]: a terminal with no program runs /bin/sh, as before")
bg = cfg.get("colors", "background", fallback="")
colours = {k: v for k, v in cfg.items("colors")} if cfg.has_section("colors") else {}
low = [f"{k} {v} {contrast(v, bg):.1f}:1" for k, v in colours.items()
       if k not in ("background", "color0") and contrast(v, bg) < 4.5]
check(re.fullmatch(r"#[0-9a-f]{6}", bg or "") is not None and not low,
      "every colour reads at 4.5:1 or more on the background" + (f" (not: {', '.join(low)})" if low else ""))

print(f"havoc-config: {'ok' if not failed else f'{failed} failed'}")
sys.exit(1 if failed else 0)
