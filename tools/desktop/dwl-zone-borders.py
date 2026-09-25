#!/usr/bin/env python3
"""Kryptik's change to dwl: border colours by zone.

Applied to dwl's dwl.c at build time (stage 04, s_dwl). It is a patch
written as exact-string replacements rather than a unified diff so that it
fails loudly - with the text it could not find - if the pinned dwl ever
differs from the one it was written against (dwl v0.8), instead of applying
a hunk with fuzz to code that has moved.

What it changes:
  * Client gains its zone's colour, chosen from the `kryptik.<zone>.` app_id
    prefix the per-zone proxy stamps on every client it forwards
    (docs/design/broker.md). The compositor is the only party that draws
    the border, and the proxy is the only party that sets the prefix, so a
    window cannot claim another zone's colour.
  * The border is always that colour, focused or not, so every colour on
    screen is one zoneid audits. Focus is shown by width: an unfocused
    window has a band of the root colour over the inner `bandpx` of its
    border. Urgent stays global.
  * setfullscreen keeps the border: a fullscreen window is framed by its
    zone's colour like any other, so going fullscreen cannot remove the
    compositor's statement of which zone it belongs to.

Usage: dwl-zone-borders.py DWL_SOURCE_DIR           (edits dwl.c in place)
       dwl-zone-borders.py --check DWL_SOURCE_DIR   (exit 0 if it would apply)
"""
import os
import sys

EDITS = [
    # (1) Client: the zone's colour and the band that marks it unfocused.
    ("""	struct wlr_scene_rect *border[4]; /* top, bottom, left, right */
""",
     """	struct wlr_scene_rect *border[4]; /* top, bottom, left, right */
	const float *zoneborder; /* Kryptik: chosen by zone from the app_id */
	struct wlr_scene_rect *band; /* Kryptik: over the border's inner edge while unfocused */
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
 * with no colour is drawn as unknown. */
static void
zonecolors(Client *c)
{
	const char *appid = client_get_appid(c);
	const ZoneColor *z;
	size_t n;

	c->zoneborder = unzonedcolor;
	if (!appid || strncmp(appid, "kryptik.", 8) != 0)
		return;
	appid += 8;
	n = strcspn(appid, ".");
	for (z = zonecolors_table; z < END(zonecolors_table); z++) {
		if (strlen(z->zone) == n && strncmp(z->zone, appid, n) == 0) {
			c->zoneborder = z->border;
			return;
		}
	}
	c->zoneborder = unknownzonecolor;
}

void
applyrules(Client *c)
{
"""),
    # (4) mapnotify: the borders in the zone's colour, then the band over
    # them and under the surface. It starts enabled: a new window is
    # unfocused until focusclient says otherwise.
    ("""	for (i = 0; i < 4; i++) {
		c->border[i] = wlr_scene_rect_create(c->scene, 0, 0,
				c->isurgent ? urgentcolor : bordercolor);
		c->border[i]->node.data = c;
	}
""",
     """	zonecolors(c);
	for (i = 0; i < 4; i++) {
		c->border[i] = wlr_scene_rect_create(c->scene, 0, 0,
				c->isurgent ? urgentcolor : c->zoneborder);
		c->border[i]->node.data = c;
	}
	c->band = wlr_scene_rect_create(c->scene, 0, 0, rootcolor);
	c->band->node.data = c;
	wlr_scene_node_raise_to_top(&c->scene_surface->node);
"""),
    # (5) resize: the band is the ring of the border nearest the surface.
    ("""	wlr_scene_node_set_position(&c->border[3]->node, c->geom.width - c->bw, c->bw);
""",
     """	wlr_scene_node_set_position(&c->border[3]->node, c->geom.width - c->bw, c->bw);
	wlr_scene_node_set_position(&c->band->node, c->bw - bandpx, c->bw - bandpx);
	wlr_scene_rect_set_size(c->band, c->geom.width - 2 * (c->bw - bandpx),
			c->geom.height - 2 * (c->bw - bandpx));
"""),
    # (6) focusclient: the colour is the zone's either way; focus hides the band.
    ("""		if (!exclusive_focus && !seat->drag)
			client_set_border_color(c, focuscolor);
""",
     """		if (!exclusive_focus && !seat->drag) {
			zonecolors(c);
			client_set_border_color(c, c->zoneborder);
			wlr_scene_node_set_enabled(&c->band->node, 0);
		}
"""),
    ("""		} else if (old_c && !client_is_unmanaged(old_c) && (!c || !client_wants_focus(c))) {
			client_set_border_color(old_c, bordercolor);
""",
     """		} else if (old_c && !client_is_unmanaged(old_c) && (!c || !client_wants_focus(c))) {
			client_set_border_color(old_c, old_c->zoneborder);
			wlr_scene_node_set_enabled(&old_c->band->node, 1);
"""),
    # (7) setfullscreen: the border stays. dwl drops it to 0 in fullscreen,
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
