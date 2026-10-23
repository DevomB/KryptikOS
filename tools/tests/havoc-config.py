#!/usr/bin/env python3
"""Kryptik's havoc.cfg and havoc's patch set, offline. The patches make havoc read the file and take
the type zone 0's move gesture carries; the recipe and stage 04 install the file by digest; and the
file, read as havoc 0.7.0 reads it, names the font fonts.sh installs, keeps the scrollback and keys
the user guide names, binds only havoc's actions, gives every colour as #rrggbb, and reads on its
background."""
import hashlib
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PSET = os.path.join(ROOT, "build", "patches", "havoc-0.7.0")
failed = 0

# havoc's main.c: actions[], and what each section's *_config() reads.
ACTIONS = {"copy", "paste", "reset", "hard reset", "scroll up", "scroll down", "scroll up page",
           "scroll down page", "scroll to top", "scroll to bottom"}
COLOURS = ["foreground", "background"] + [f"color{i}" for i in range(16)]
KEYS = {"child": {"program"}, "window": {"opacity", "margin", "decorations"},
        "terminal": {"rows", "columns", "scrollback", "scroll to bottom on input"},
        "font": {"size", "path"}, "colors": set(COLOURS)}


def check(ok, what):
    global failed
    print(("  ok    " if ok else "  FAIL  ") + what)
    if not ok:
        failed += 1


def read(*path):
    with open(os.path.join(ROOT, *path), encoding="utf-8") as f:
        return f.read()


def havoc_read(text):
    """read_config(): a line whose first non-blank is '#' is a comment, '[name]' opens a section,
    and any other line holding '=' splits at its first one, blanks trimmed around key and value.
    [(section, key, value)] in file order; havoc applies them in that order."""
    rows, section = [], None
    for line in text.splitlines():
        key = line.lstrip(" \t")
        if not key or key.startswith("#"):
            continue
        if key.startswith("["):
            if "]" in key:
                section = key[1:key.index("]")]
            continue
        if "=" in key:
            k, _, v = key.partition("=")
            rows.append((section, k.rstrip(" \t"), v.lstrip(" \t").rstrip()))
    return rows


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


# The patch set: what apply_repo_patches verifies, and the lines it adds.
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
added = [ln[1:] for ln in patch.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
check('-\tf = fopen(CONF_FILE, "r");' in patch.splitlines() and '\tf = fopen("/usr/share/kryptik/havoc.cfg", "r");' in added,
      "the patch puts Kryptik's file in place of the working directory's")

# The move gesture carries the first of wlproxy's MOVE_TYPES a source offers: havoc pastes it from the
# clipboard and the primary selection, and its own copies offer it.
m = re.search(r'pub const MOVE_TYPES: &\[&str\] = &\[\s*"([^"]+)"', read("compositor", "wlproxy", "src", "policy.rs"))
move = m.group(1) if m else ""
check(bool(move) and added.count(f'\t\tstrcmp(mime_type, "{move}") == 0)') == 2
      and f'\t\tterm.paste.d_mime = "{move}";' in added and f'\t\tterm.paste.ps_mime = "{move}";' in added,
      f"havoc pastes {move or '(no MOVE_TYPES found)'}, the type the move gesture takes first")
check(bool(move) and f'\twl_data_source_offer(term.d_copy.source, "{move}");' in added,
      f"havoc's copies offer {move or '(no MOVE_TYPES found)'}")

# The recipe applies the set before it builds and installs this file, not upstream's; stage 04
# passes the file's digest.
recipe = read("build", "recipes", "havoc.sh")
ap = re.search(r'^\s*apply_repo_patches "havoc-\$\{V_HAVOC\}"\s*$', recipe, re.M)
mk = re.search(r"^\s*make PREFIX=/usr\s*$", recipe, re.M)
check(ap is not None and mk is not None and ap.start() < mk.start(), "s_havoc applies the patch set before make")
check('install -Dm644 "$cfg" /usr/share/kryptik/havoc.cfg' in recipe and "install -Dm644 havoc.cfg" not in recipe,
      "s_havoc installs build/desktop/havoc.cfg, not upstream's")
check(re.search(r'"havoc"\s+"s_havoc \$\(sha256_of "\$\{KRYPTIK_ROOT\}/build/desktop/havoc\.cfg"', read("build", "stages", "04-base-system.sh"))
      is not None, "stage 04 rebuilds havoc when havoc.cfg changes")

# The file, as havoc reads it.
text = read("build", "desktop", "havoc.cfg")
rows = havoc_read(text)


def last(section, key):
    vals = [v for s, k, v in rows if s == section and k == key]
    return vals[-1] if vals else None


check(all(len(ln.encode()) < 511 for ln in text.splitlines()), "every line fits havoc's 512-byte line buffer")
sections = re.findall(r"^[ \t]*\[([^\]\n]*)\]", text, re.M)
unread = [f"[{s}]" for s in sections if s not in KEYS and s != "bind"]
unread += [f"[{s}] {k}" for s, k, _ in rows if s != "bind" and k not in KEYS.get(s, set())]
check(not unread, "every section and key is one havoc reads" + (f" (not: {', '.join(unread)})" if unread else ""))
check("child" not in sections, "no [child]: a terminal with no program runs /bin/sh")
check(last("window", "opacity") == "255", "the window is opaque")

# fonts.sh checks the first line starting "path=", wherever it is; havoc takes the last in [font].
m = re.search(r"^path=(.*)$", text, re.M)
font = m.group(1) if m else ""
check(bool(font) and font == last("font", "path") and font.startswith("/usr/share/fonts/TTF/")
      and os.path.basename(font) in read("build", "recipes", "fonts.sh"),
      f"the font {font or '(none)'} is the one fonts.sh checks and installs")

check(last("terminal", "scrollback") == "2000", "2000 lines of scrollback, as the user guide says")
check(last("terminal", "scroll to bottom on input") == "yes", "typing returns to the bottom, as the user guide says")
binds = {k: v for s, k, v in rows if s == "bind"}
bad = [f"{k}={v}" for k, v in binds.items() if v not in ACTIONS or not re.fullmatch(r"([SCA]-)*[A-Za-z0-9_]+", k)]
check(bool(binds) and not bad, "every binding is a key havoc parses and one of its ten actions"
      + (f" (not: {', '.join(bad)})" if bad else ""))
guide = {"C-S-c": "copy", "C-S-v": "paste", "C-S-Page_Up": "scroll up page", "C-S-Page_Down": "scroll down page"}
check(all(binds.get(k) == v for k, v in guide.items()), "Ctrl+Shift+c, v, Page Up and Page Down do what the user guide says")

colours = {k: last("colors", k) for k in COLOURS}
malformed = [f"{k}={v}" for k, v in colours.items() if v is None or not re.fullmatch(r"#[0-9a-fA-F]{6}", v)]
check(not malformed, "all 18 colours are #rrggbb, as havoc reads anything else as black"
      + (f" (not: {', '.join(malformed)})" if malformed else ""))
if not malformed:
    bg = colours["background"]
    low = [f"{k} {v} {contrast(v, bg):.2f}:1" for k, v in colours.items()
           if k not in ("background", "color0") and contrast(v, bg) < 4.5]
    check(not low, "every colour but color0 reads at 4.5:1 or more on the background"
          + (f" (not: {', '.join(low)})" if low else ""))
    # nano's error bar is bold white on red, and havoc's libtsm draws bold in the bright colours.
    c = contrast(colours["color15"], colours["color1"])
    check(c >= 4.5, f"color15 on color1, nano's error bar, reads at {c:.2f}:1")

print(f"havoc-config: {'ok' if not failed else f'{failed} failed'}")
sys.exit(1 if failed else 0)
