#!/usr/bin/env python3
"""Patch dwl.c (dwl v0.8) so every window's border is its zone's colour.

Usage: dwl-zone-borders.py DWL_SOURCE_DIR           (edits dwl.c in place)
       dwl-zone-borders.py --check DWL_SOURCE_DIR   (exit 0 if it would apply)
"""
import os
import sys

# Exact-string edits rather than a diff, so a different dwl fails with the text
# not found instead of patching with fuzz. The colour comes from the app_id
# prefix only the zone's proxy sets; focus is shown by width (a band of the
# root colour when unfocused), and fullscreen keeps the border.
EDITS = [
    # (1) Client: the zone's colour and the band that marks it unfocused.
    ("""	struct wlr_scene_rect *border[4]; /* top, bottom, left, right */
""",
     """	struct wlr_scene_rect *border[4]; /* top, bottom, left, right */
	const float *zoneborder; /* Kryptik: chosen by zone from the app_id */
	struct wlr_scene_tree *band; /* Kryptik: over the border's inner edge while unfocused */
	struct wlr_scene_rect *bands[4]; /* top, bottom, left, right */
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
    # (4) mapnotify: zone-coloured borders, then the band over them as four
    # strips. The surface stays below both, or a buffer larger than its
    # configure would paint over the right and bottom borders. A new window
    # starts unfocused, so the band starts enabled.
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
	c->band = wlr_scene_tree_create(c->scene);
	for (i = 0; i < 4; i++) {
		c->bands[i] = wlr_scene_rect_create(c->band, 0, 0, rootcolor);
		c->bands[i]->node.data = c;
	}
"""),
    # (5) resize: the band is the ring of the border nearest the surface.
    ("""	wlr_scene_node_set_position(&c->border[3]->node, c->geom.width - c->bw, c->bw);
""",
     """	wlr_scene_node_set_position(&c->border[3]->node, c->geom.width - c->bw, c->bw);
	wlr_scene_rect_set_size(c->bands[0], c->geom.width - 2 * (c->bw - bandpx), bandpx);
	wlr_scene_rect_set_size(c->bands[1], c->geom.width - 2 * (c->bw - bandpx), bandpx);
	wlr_scene_rect_set_size(c->bands[2], bandpx, c->geom.height - 2 * c->bw);
	wlr_scene_rect_set_size(c->bands[3], bandpx, c->geom.height - 2 * c->bw);
	wlr_scene_node_set_position(&c->bands[0]->node, c->bw - bandpx, c->bw - bandpx);
	wlr_scene_node_set_position(&c->bands[1]->node, c->bw - bandpx, c->geom.height - c->bw);
	wlr_scene_node_set_position(&c->bands[2]->node, c->bw - bandpx, c->bw);
	wlr_scene_node_set_position(&c->bands[3]->node, c->geom.width - c->bw, c->bw);
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
    # (7) focusclient, the window losing focus: its band comes back.
    ("""		} else if (old_c && !client_is_unmanaged(old_c) && (!c || !client_wants_focus(c))) {
			client_set_border_color(old_c, bordercolor);
""",
     """		} else if (old_c && !client_is_unmanaged(old_c) && (!c || !client_wants_focus(c))) {
			client_set_border_color(old_c, old_c->zoneborder);
			wlr_scene_node_set_enabled(&old_c->band->node, 1);
"""),
    # (8) setfullscreen: keep the border; dwl's 0 would let a window hide its zone.
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
