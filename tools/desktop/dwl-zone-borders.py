#!/usr/bin/env python3
"""Patch dwl.c (dwl v0.8) for zone borders, focus and scene layers.

Usage: dwl-zone-borders.py DWL_SOURCE_DIR           (edits dwl.c in place)
       dwl-zone-borders.py --check DWL_SOURCE_DIR   (exit 0 if it would apply)
"""
import os
import sys

# Exact-string edits rather than a diff, so a different dwl fails with the text
# not found instead of patching with fuzz. The colour comes from the app_id
# prefix only the zone's proxy sets; focus is shown by width (a band of the
# root colour when unfocused), and fullscreen keeps the border under a bar
# that names the zone.

# The bar's lettering, 5x7: capitals for the letters, digits and '-' of a zone name.
FONT = {
    "a": "01110 10001 10001 10001 11111 10001 10001",
    "b": "11110 10001 10001 11110 10001 10001 11110",
    "c": "01110 10001 10000 10000 10000 10001 01110",
    "d": "11100 10010 10001 10001 10001 10010 11100",
    "e": "11111 10000 10000 11110 10000 10000 11111",
    "f": "11111 10000 10000 11110 10000 10000 10000",
    "g": "01110 10001 10000 10111 10001 10001 01111",
    "h": "10001 10001 10001 11111 10001 10001 10001",
    "i": "01110 00100 00100 00100 00100 00100 01110",
    "j": "00111 00010 00010 00010 00010 10010 01100",
    "k": "10001 10010 10100 11000 10100 10010 10001",
    "l": "10000 10000 10000 10000 10000 10000 11111",
    "m": "10001 11011 10101 10101 10001 10001 10001",
    "n": "10001 10001 11001 10101 10011 10001 10001",
    "o": "01110 10001 10001 10001 10001 10001 01110",
    "p": "11110 10001 10001 11110 10000 10000 10000",
    "q": "01110 10001 10001 10001 10101 10010 01101",
    "r": "11110 10001 10001 11110 10100 10010 10001",
    "s": "01111 10000 10000 01110 00001 00001 11110",
    "t": "11111 00100 00100 00100 00100 00100 00100",
    "u": "10001 10001 10001 10001 10001 10001 01110",
    "v": "10001 10001 10001 10001 10001 01010 00100",
    "w": "10001 10001 10001 10101 10101 10101 01010",
    "x": "10001 10001 01010 00100 01010 10001 10001",
    "y": "10001 10001 10001 01010 00100 00100 00100",
    "z": "11111 00001 00010 00100 01000 10000 11111",
    "0": "01110 10001 10011 10101 11001 10001 01110",
    "1": "00100 01100 00100 00100 00100 00100 01110",
    "2": "01110 10001 00001 00010 00100 01000 11111",
    "3": "11111 00010 00100 00010 00001 10001 01110",
    "4": "00010 00110 01010 10010 11111 00010 00010",
    "5": "11111 10000 11110 00001 00001 10001 01110",
    "6": "00110 01000 10000 11110 10001 10001 01110",
    "7": "11111 00001 00010 00100 01000 01000 01000",
    "8": "01110 10001 10001 01110 10001 10001 01110",
    "9": "01110 10001 10001 01111 00001 00010 01100",
    "-": "00000 00000 00000 11111 00000 00000 00000",
}
FONT_ROWS = "".join("\t['%s'] = {%s},\n" % (ch, ", ".join("0x%02x" % int(r, 2) for r in rows.split()))
                    for ch, rows in FONT.items())

ZONEBAR = """/* Kryptik: the bar's lettering, indexed by the lower-case name; bit 4 is leftmost. */
static const unsigned char zonefont[128][7] = {
""" + FONT_ROWS + """};

/* Kryptik: a fullscreen window leaves the top barpx rows of its output to a
 * bar in its zone's colour that names the zone, outside the window's frame:
 * its surfaces are clipped to the frame, and a zone has no popups. */
static void
zonebar(Client *c)
{
\tstatic const float black[] = {0, 0, 0, 1}, white[] = {1, 1, 1, 1};
\tconst char *id = client_get_appid(c);
\tconst float *ink;
\tstruct wlr_box box = c->mon->m;
\tchar name[16] = "zone 0";
\tint s = (int)barscale, pad = ((int)barpx - 7 * s) / 2, x, row, col, n;
\tsize_t i;

\tzonecolors(c);
\tif (c->zoneborder != unzonedcolor && strncmp(id, "kryptik.", 8) == 0)
\t\tsnprintf(name, sizeof(name), "%.*s", (int)strcspn(id + 8, "."), id + 8);
\tink = 0.299f * c->zoneborder[0] + 0.587f * c->zoneborder[1]
\t\t\t+ 0.114f * c->zoneborder[2] > 0.5f ? black : white;

\tbox.y += (int)barpx;
\tbox.height -= (int)barpx;
\tresize(c, box, 0);

\twlr_scene_node_destroy(&c->bar->node);
\tc->bar = wlr_scene_tree_create(c->scene);
\twlr_scene_node_set_position(&c->bar->node, 0, -(int)barpx);
\twlr_scene_rect_create(c->bar, box.width, (int)barpx, c->zoneborder);
\t/* One rect per run of lit pixels in a row of a glyph. */
\tfor (i = 0, x = pad; name[i]; i++, x += 6 * s) {
\t\tfor (row = 0; row < 7; row++) {
\t\t\tfor (col = 0; col < 5; col += n + 1) {
\t\t\t\tfor (n = 0; col + n < 5 && ((zonefont[name[i] & 0x7f][row] >> (4 - col - n)) & 1); n++)
\t\t\t\t\t;
\t\t\t\tif (n)
\t\t\t\t\twlr_scene_node_set_position(&wlr_scene_rect_create(c->bar,
\t\t\t\t\t\t\tn * s, s, ink)->node, x + col * s, pad + row * s);
\t\t\t}
\t\t}
\t}
}

"""

EDITS = [
    # Client: the zone's colour, the band that marks it unfocused, the bar.
    ("""	struct wlr_scene_rect *border[4]; /* top, bottom, left, right */
""",
     """	struct wlr_scene_rect *border[4]; /* top, bottom, left, right */
	const float *zoneborder; /* Kryptik: chosen by zone from the app_id */
	struct wlr_scene_tree *band; /* Kryptik: over the border's inner edge while unfocused */
	struct wlr_scene_rect *bands[4]; /* top, bottom, left, right */
	struct wlr_scene_tree *bar; /* Kryptik: names the zone above a fullscreen window */
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
    # mapnotify: zone-coloured borders, then the band over them as four
    # strips. The surface stays below both, or a buffer larger than its
    # configure would paint over the right and bottom borders. A new window
    # starts unfocused, so the band starts enabled; the bar starts hidden.
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
	c->bar = wlr_scene_tree_create(c->scene);
	wlr_scene_node_set_enabled(&c->bar->node, 0);
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
     """	/* Kryptik: a fullscreen window keeps its zone border. The border is the
	 * compositor's statement of which zone the window belongs to, and a
	 * window must not be able to remove it by going fullscreen. */
	c->bw = borderpx;
	client_set_fullscreen(c, fullscreen);
"""),
    # Mapping a different zone must not move it ahead of the active window.
    ("""\twl_list_insert(&clients, &c->link);
\twl_list_insert(&fstack, &c->flink);
""",
     """\twl_list_insert(&clients, &c->link);
\t/* Compare with the actual keyboard focus, which may be on another monitor. */
\tw = NULL;
\ttoplevel_from_wlr_surface(seat->keyboard_state.focused_surface, &w, NULL);
\tif (c->zoneborder != unzonedcolor && w && !client_is_unmanaged(w)
\t\t\t&& w->zoneborder != c->zoneborder)
\t\twl_list_insert(&w->flink, &c->flink);
\telse
\t\twl_list_insert(&fstack, &c->flink);
"""),
    # Keep zone clients out of the float scene layer.
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
    # A zone's window reaches LyrFS, above the chrome, only fullscreen itself.
    ("""\twlr_scene_node_reparent(&c->scene->node, layers[c->isfullscreen ||
\t\t\t(p && p->isfullscreen) ? LyrFS
""",
     """\t/* Kryptik: a zone's child stays out of LyrFS, where it would cover its parent's bar. */
\twlr_scene_node_reparent(&c->scene->node, layers[c->isfullscreen ||
\t\t\t(p && p->isfullscreen && c->zoneborder == unzonedcolor) ? LyrFS
"""),
    # A zone's request may take its window out of fullscreen, never into it.
    ("""\tClient *c = wl_container_of(listener, c, fullscreen);
\tsetfullscreen(c, client_wants_fullscreen(c));
""",
     """\tClient *c = wl_container_of(listener, c, fullscreen);
\t/* Kryptik: a zone window goes fullscreen only by the user's key, and zone
\t * 0's only while it has the focus, so it never covers the focused window. */
\tsetfullscreen(c, client_wants_fullscreen(c) && (c->isfullscreen
\t\t\t|| (c->zoneborder == unzonedcolor && c->mon && c == focustop(c->mon))));
"""),
    # The bar, defined before setfullscreen, its first caller.
    ("""void
setfullscreen(Client *c, int fullscreen)
{
""",
     ZONEBAR + """void
setfullscreen(Client *c, int fullscreen)
{
"""),
    # setfullscreen and updatemons: a fullscreen window is sized below its bar.
    ("""\tif (fullscreen) {
\t\tc->prev = c->geom;
\t\tresize(c, c->mon->m, 0);
\t} else {
""",
     """\twlr_scene_node_set_enabled(&c->bar->node, fullscreen);
\tif (fullscreen) {
\t\tc->prev = c->geom;
\t\tzonebar(c);
\t} else {
"""),
    ("""\t\tif ((c = focustop(m)) && c->isfullscreen)
\t\t\tresize(c, m->m, 0);
""",
     """\t\tif ((c = focustop(m)) && c->isfullscreen)
\t\t\tzonebar(c);
"""),
    # xytonode: the pointer goes to what is on top. dwl looks on through lower
    # layers past a border or background, which over a fullscreen window would
    # hand clicks on its bar to another zone's window hidden below.
    ("""\t\tif (c && c->type == LayerShell) {
\t\t\tc = NULL;
\t\t\tl = pnode->data;
\t\t}
\t}
""",
     """\t\tif (c && c->type == LayerShell) {
\t\t\tc = NULL;
\t\t\tl = pnode->data;
\t\t}
\t\t/* Kryptik: never past the first thing drawn under the pointer. */
\t\tbreak;
\t}
"""),
    # A zone's child cannot be drawn above its fullscreen parent (it stays in
    # the tile layer), so it ends that fullscreen; zone 0's child follows its
    # parent up, as dwl has it. A zone mapping must not cancel another zone's
    # fullscreen either.
    ("""\tMonitor *m;
\tint i;

\t/* Create scene tree for this client and its border */
""",
     """\tMonitor *m;
\tint i, refocus = 0;

\t/* Create scene tree for this client and its border */
"""),
    ("""\t\tif (w != c && w != p && w->isfullscreen && m == w->mon && (w->tags & c->tags))
\t\t\tsetfullscreen(w, 0);
\t}
}
""",
     """\t\tif (w != c && (w != p || w->zoneborder != unzonedcolor) && w->isfullscreen && m == w->mon && (w->tags & c->tags)
\t\t\t\t&& (c->zoneborder == unzonedcolor || w->zoneborder == c->zoneborder)) {
\t\t\tsetfullscreen(w, 0);
\t\t\trefocus = 1;
\t\t}
\t}
\t/* Kryptik: the focus was chosen above while the fullscreen window still
\t * covered the new one; shown now, it may take the keyboard. */
\tif (refocus)
\t\tfocusclient(focustop(selmon), 1);
}
"""),
    # A fullscreen window covers the tile and float layers, so while one shows
    # only its own layer is on screen. The keyboard never goes to what is
    # hidden: focusclient redirects it, and focustop, focusstack and zoom skip
    # covered windows. Defined before focusclient, the first user.
    ("""void
focusclient(Client *c, int lift)
{
""",
     """/* Kryptik: with a fullscreen window on the monitor, a window in any other
 * layer is hidden below it and must not take the focus. */
static int
covered(Client *c, Monitor *m)
{
\tClient *w;
\tif (c->scene->node.parent == layers[LyrFS])
\t\treturn 0;
\twl_list_for_each(w, &clients, link)
\t\tif (w != c && VISIBLEON(w, m) && w->isfullscreen && w->scene->node.parent == layers[LyrFS])
\t\t\treturn 1;
\treturn 0;
}

void
focusclient(Client *c, int lift)
{
"""),
    ("""\tLayerSurface *old_l = NULL;

\tif (locked)
\t\treturn;

\t/* Raise client in stacking order if requested */
""",
     """\tLayerSurface *old_l = NULL;

\tif (locked)
\t\treturn;
\t/* Kryptik: a window hidden under a fullscreen one never takes the keyboard. */
\tif (c && c->mon && covered(c, c->mon))
\t\tc = focustop(c->mon);

\t/* Raise client in stacking order if requested */
"""),
    ("""\t\tif (VISIBLEON(c, selmon) && !c->isfloating) {
\t\t\tif (c != sel)
\t\t\t\tbreak;
""",
     """\t\tif (VISIBLEON(c, selmon) && !c->isfloating && !covered(c, selmon)) {
\t\t\tif (c != sel)
\t\t\t\tbreak;
"""),
    ("""\tif (arg->i > 0) {
\t\twl_list_for_each(c, &sel->link, link) {
\t\t\tif (&c->link == &clients)
\t\t\t\tcontinue; /* wrap past the sentinel node */
\t\t\tif (VISIBLEON(c, selmon))
\t\t\t\tbreak; /* found it */
\t\t}
\t} else {
\t\twl_list_for_each_reverse(c, &sel->link, link) {
\t\t\tif (&c->link == &clients)
\t\t\t\tcontinue; /* wrap past the sentinel node */
\t\t\tif (VISIBLEON(c, selmon))
\t\t\t\tbreak; /* found it */
\t\t}
\t}
""",
     """\tif (arg->i > 0) {
\t\twl_list_for_each(c, &sel->link, link) {
\t\t\tif (&c->link == &clients)
\t\t\t\tcontinue; /* wrap past the sentinel node */
\t\t\tif (VISIBLEON(c, selmon) && !covered(c, selmon))
\t\t\t\tbreak; /* found it */
\t\t}
\t} else {
\t\twl_list_for_each_reverse(c, &sel->link, link) {
\t\t\tif (&c->link == &clients)
\t\t\t\tcontinue; /* wrap past the sentinel node */
\t\t\tif (VISIBLEON(c, selmon) && !covered(c, selmon))
\t\t\t\tbreak; /* found it */
\t\t}
\t}
"""),
    ("""\twl_list_for_each(c, &fstack, flink) {
\t\tif (VISIBLEON(c, m))
\t\t\treturn c;
\t}
""",
     """\twl_list_for_each(c, &fstack, flink) {
\t\tif (VISIBLEON(c, m) && !covered(c, m))
\t\t\treturn c;
\t}
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
    # setcursor: a client's cursor image is drawn above every layer, anywhere
    # its hotspot puts it, so a zone's pointer shows dwl's default instead.
    ("""\tstruct wlr_seat_pointer_request_set_cursor_event *event = data;
""",
     """\tstruct wlr_seat_pointer_request_set_cursor_event *event = data;
\tClient *c = NULL;
"""),
    ("""\tif (event->seat_client == seat->pointer_state.focused_client)
\t\twlr_cursor_set_surface(cursor, event->surface,
\t\t\t\tevent->hotspot_x, event->hotspot_y);
""",
     """\tif (event->seat_client != seat->pointer_state.focused_client)
\t\treturn;
\t/* Kryptik: a zone never gets its own cursor image, which would draw over the chrome. */
\ttoplevel_from_wlr_surface(seat->pointer_state.focused_surface, &c, NULL);
\tif (c && c->zoneborder != unzonedcolor)
\t\twlr_cursor_set_xcursor(cursor, cursor_mgr, "default");
\telse
\t\twlr_cursor_set_surface(cursor, event->surface,
\t\t\t\tevent->hotspot_x, event->hotspot_y);
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
