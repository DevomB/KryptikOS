#!/usr/bin/env python3
"""Kryptik's change to dwl: border colours by zone.

Applied to dwl's dwl.c at build time (stage 04, s_dwl). It is a patch
written as exact-string replacements rather than a unified diff so that it
fails loudly - with the text it could not find - if the pinned dwl ever
differs from the one it was written against (dwl v0.8), instead of applying
a hunk with fuzz to code that has moved.

What it changes:
  * Client gains two colour pointers, chosen when the window maps from the
    `kryptik.<zone>.` app_id prefix the per-zone proxy stamps on every
    client it forwards (Design 05a). The compositor is the only party that
    draws the border, and the proxy is the only party that sets the prefix,
    so a window cannot claim another zone's colour.
  * focusclient and mapnotify draw those colours instead of the two global
    ones. Urgent stays global.
  * setfullscreen keeps the border: a fullscreen window is framed by its
    zone's colour like any other, so going fullscreen cannot remove the
    compositor's statement of which zone it belongs to.

Usage: dwl-zone-borders.py DWL_SOURCE_DIR           (edits dwl.c in place)
       dwl-zone-borders.py --check DWL_SOURCE_DIR   (exit 0 if it would apply)
"""
import os
import sys

EDITS = [
    # (1) Client: the two colour pointers.
    ("""	struct wlr_scene_rect *border[4]; /* top, bottom, left, right */
""",
     """	struct wlr_scene_rect *border[4]; /* top, bottom, left, right */
	const float *zoneborder, *zonefocus; /* Kryptik: chosen by zone from the app_id */
"""),
    # (2) The ZoneColor type, beside Rule so config.h can define the table.
    ("""typedef struct {
	const char *id;
	const char *title;
	uint32_t tags;
	int isfloating;
	int monitor;
} Rule;
""",
     """typedef struct {
	const char *id;
	const char *title;
	uint32_t tags;
	int isfloating;
	int monitor;
} Rule;

typedef struct {
	const char *zone;     /* as it appears in kryptik.<zone>.<app_id> */
	const float border[4];
	const float focus[4];
} ZoneColor;
"""),
    # (3) The chooser, defined before applyrules (its first neighbour).
    ("""void
applyrules(Client *c)
{
""",
     """/* Kryptik: the border colour is the compositor's statement of which zone a
 * window belongs to. Every zone client reaches the compositor through its
 * zone's proxy, which rewrites app_id to kryptik.<zone>.<claimed>; the zone
 * is read from there. A client with no such prefix did not come through a
 * proxy - it is the chrome, or something the session user ran on the
 * session's own display - and is drawn as unzoned. A prefix naming a zone
 * with no colour is drawn as unknown, loudly. */
static void
zonecolors(Client *c)
{
	const char *appid = client_get_appid(c);
	const ZoneColor *z;
	size_t n;

	c->zoneborder = unzonedcolor.border;
	c->zonefocus = unzonedcolor.focus;
	if (!appid || strncmp(appid, "kryptik.", 8) != 0)
		return;
	appid += 8;
	n = strcspn(appid, ".");
	for (z = zonecolors_table; z < END(zonecolors_table); z++) {
		if (strlen(z->zone) == n && strncmp(z->zone, appid, n) == 0) {
			c->zoneborder = z->border;
			c->zonefocus = z->focus;
			return;
		}
	}
	c->zoneborder = unknownzonecolor.border;
	c->zonefocus = unknownzonecolor.focus;
}

void
applyrules(Client *c)
{
"""),
    # (4) mapnotify: the borders are created in the zone's colour.
    ("""	for (i = 0; i < 4; i++) {
		c->border[i] = wlr_scene_rect_create(c->scene, 0, 0,
				c->isurgent ? urgentcolor : bordercolor);
""",
     """	zonecolors(c);
	for (i = 0; i < 4; i++) {
		c->border[i] = wlr_scene_rect_create(c->scene, 0, 0,
				c->isurgent ? urgentcolor : c->zoneborder);
"""),
    # (5) focusclient: focused and unfocused colours come from the zone.
    ("""		if (!exclusive_focus && !seat->drag)
			client_set_border_color(c, focuscolor);
""",
     """		if (!exclusive_focus && !seat->drag) {
			zonecolors(c);
			client_set_border_color(c, c->zonefocus ? c->zonefocus : focuscolor);
		}
"""),
    ("""		} else if (old_c && !client_is_unmanaged(old_c) && (!c || !client_wants_focus(c))) {
			client_set_border_color(old_c, bordercolor);
""",
     """		} else if (old_c && !client_is_unmanaged(old_c) && (!c || !client_wants_focus(c))) {
			client_set_border_color(old_c, old_c->zoneborder ? old_c->zoneborder : bordercolor);
"""),
    # (6) setfullscreen: the border stays. dwl drops it to 0 in fullscreen,
    # which would let a window hide its zone by going fullscreen.
    ("""	c->bw = fullscreen ? 0 : borderpx;
	client_set_fullscreen(c, fullscreen);
""",
     """	/* Kryptik: a fullscreen window keeps its zone border. The border is the
	 * compositor's statement of which zone the window belongs to, and a
	 * window must not be able to remove it by going fullscreen. */
	c->bw = borderpx;
	client_set_fullscreen(c, fullscreen);
"""),
]


def main(argv):
    check = False
    if argv and argv[0] == "--check":
        check = True
        argv = argv[1:]
    if len(argv) != 1:
        sys.stderr.write(__doc__)
        return 2
    path = os.path.join(argv[0], "dwl.c")
    with open(path, encoding="utf-8") as f:
        src = f.read()
    if "zonecolors(Client *c)" in src:
        print("dwl-zone-borders: already applied")
        return 0
    for i, (old, new) in enumerate(EDITS, 1):
        n = src.count(old)
        if n != 1:
            sys.stderr.write(
                "dwl-zone-borders: edit %d: expected exactly one occurrence, found %d:\n" % (i, n)
                + "".join("  | " + l + "\n" for l in old.splitlines())
                + "This dwl is not the one the patch was written for. Refusing.\n")
            return 1
        src = src.replace(old, new)
    if check:
        print("dwl-zone-borders: would apply %d edits to %s" % (len(EDITS), path))
        return 0
    tmp = path + ".kryptik"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(src)
    os.replace(tmp, path)
    print("dwl-zone-borders: applied %d edits to %s" % (len(EDITS), path))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
