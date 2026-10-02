#!/usr/bin/env python3
"""Patch dwl.c (dwl v0.8) for zone borders, focus and scene layers.

Usage: dwl-zone-borders.py DWL_SOURCE_DIR           (edits dwl.c in place)
       dwl-zone-borders.py --check DWL_SOURCE_DIR   (exit 0 if it would apply)
"""
import os
import sys

# Exact-string edits, not a diff: a different dwl fails on missing text instead of fuzzing.
EDITS = [
    # Client: the zone's colour and the band that marks it unfocused.
    ("""	struct wlr_scene_rect *border[4]; /* top, bottom, left, right */
""",
     """	struct wlr_scene_rect *border[4]; /* top, bottom, left, right */
	const float *zoneborder; /* Kryptik: chosen by zone from the app_id */
	struct wlr_scene_tree *band; /* Kryptik: over the border's inner edge while unfocused */
	struct wlr_scene_rect *bands[4]; /* top, bottom, left, right */
"""),
    # The ZoneColor type, beside Rule so config.h can define the table.
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
    # The chooser, placed before applyrules.
    ("""void
applyrules(Client *c)
{
""",
     """/* Kryptik: the zone comes from the kryptik.<zone>. app_id prefix its proxy stamps; without
 * one a client is zone 0's and drawn unzoned, and a zone with no colour is drawn unknown. */
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
    # mapnotify: zone borders, then the band (a new window is unfocused); the surface stays below both.
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
    # resize: the band is the ring of the border nearest the surface.
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
    # focusclient: the colour is the zone's either way; focus hides the band.
    ("""		if (!exclusive_focus && !seat->drag)
			client_set_border_color(c, focuscolor);
""",
     """		if (!exclusive_focus && !seat->drag) {
			zonecolors(c);
			client_set_border_color(c, c->zoneborder);
			wlr_scene_node_set_enabled(&c->band->node, 0);
		}
"""),
    # focusclient, the window losing focus: its band comes back.
    ("""		} else if (old_c && !client_is_unmanaged(old_c) && (!c || !client_wants_focus(c))) {
			client_set_border_color(old_c, bordercolor);
""",
     """		} else if (old_c && !client_is_unmanaged(old_c) && (!c || !client_wants_focus(c))) {
			client_set_border_color(old_c, old_c->zoneborder);
			wlr_scene_node_set_enabled(&old_c->band->node, 1);
"""),
    # setfullscreen: keep the border; dwl's 0 would let a window hide its zone.
    ("""	c->bw = fullscreen ? 0 : borderpx;
	client_set_fullscreen(c, fullscreen);
""",
     """	/* Kryptik: a fullscreen window keeps its zone border, or it could hide its zone. */
	c->bw = borderpx;
	client_set_fullscreen(c, fullscreen);
"""),
    # Mapping a different zone must not move it ahead of the active window.
    ("""\twl_list_insert(&clients, &c->link);
\twl_list_insert(&fstack, &c->flink);
""",
     """\twl_list_insert(&clients, &c->link);
\t/* Compare with the seat's keyboard focus, which may be on another monitor. */
\tw = NULL;
\ttoplevel_from_wlr_surface(seat->keyboard_state.focused_surface, &w, NULL);
\tif (c->zoneborder != unzonedcolor && w && !client_is_unmanaged(w)
\t\t\t&& w->zoneborder != c->zoneborder)
\t\twl_list_insert(&w->flink, &c->flink);
\telse
\t\twl_list_insert(&fstack, &c->flink);
"""),
    # Keep zone clients out of the float and fullscreen scene layers.
    ("""\t\tif (c->mon != m || c->scene->node.parent == layers[LyrFS])
\t\t\tcontinue;

\t\twlr_scene_node_reparent(&c->scene->node,
""",
     """\t\tif (c->mon != m || c->scene->node.parent == layers[LyrFS])
\t\t\tcontinue;
\t\t/* Zone 0 stays above every zoned tile, even in floating layout. */
\t\tif (c->zoneborder == unzonedcolor) {
\t\t\twlr_scene_node_reparent(&c->scene->node, layers[LyrFloat]);
\t\t\tcontinue;
\t\t}

\t\twlr_scene_node_reparent(&c->scene->node,
"""),
    ("""setfloating(Client *c, int floating)
{
\tClient *p = client_get_parent(c);
\tc->isfloating = floating;
""",
     """setfloating(Client *c, int floating)
{
\tClient *p = client_get_parent(c);
\tc->isfloating = c->zoneborder != unzonedcolor ? 0 : floating;
"""),
    ("""setfullscreen(Client *c, int fullscreen)
{
\tc->isfullscreen = fullscreen;
""",
     """setfullscreen(Client *c, int fullscreen)
{
\t/* Only zone 0 can use LyrFS, which sits above the trusted windows. */
\tc->isfullscreen = c->zoneborder != unzonedcolor ? 0 : fullscreen;
\tfullscreen = c->isfullscreen;
"""),
    # A zone mapping must not cancel another zone's fullscreen either.
    ("""\t\tif (w != c && w != p && w->isfullscreen && m == w->mon && (w->tags & c->tags))
\t\t\tsetfullscreen(w, 0);
""",
     """\t\tif (w != c && w != p && w->isfullscreen && m == w->mon && (w->tags & c->tags)
\t\t\t\t&& (c->zoneborder == unzonedcolor || w->zoneborder == c->zoneborder))
\t\t\tsetfullscreen(w, 0);
"""),
    # setmon also picks focus after mapping: keep another zone's keyboard focus across monitors.
    ("""\t\tsetfloating(c, c->isfloating);
\t}
\tfocusclient(focustop(selmon), 1);
}
""",
     """\t\tsetfloating(c, c->isfloating);
\t}
\tClient *focused = NULL;
\ttoplevel_from_wlr_surface(seat->keyboard_state.focused_surface, &focused, NULL);
\tif (c->zoneborder != unzonedcolor && focused
\t\t\t&& focused->zoneborder != c->zoneborder)
\t\tfocusclient(focused, 1);
\telse
\t\tfocusclient(focustop(selmon), 1);
}
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
