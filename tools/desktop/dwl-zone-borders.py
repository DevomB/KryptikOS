#!/usr/bin/env python3
"""Patch dwl.c (dwl v0.8) for zone sockets, borders, focus, scene layers, popups, the lid
and the keys heeded under the screen lock.

Usage: dwl-zone-borders.py DWL_SOURCE_DIR           (edits dwl.c in place)
       dwl-zone-borders.py --check DWL_SOURCE_DIR   (exit 0 if it would apply)
"""
import os
import sys

# Exact-string edits rather than a diff, so a different dwl fails with the text
# not found instead of patching with fuzz. Each zone reaches dwl through a
# socket of its own, taken from its proxy's uid and the session's own programs
# alone and offered only the globals the proxy lets through, and a window's
# zone, which places it and colours it, is the socket its client came through.
# Its border is that
# zone's colour; focus is shown by width (a band of the root colour when
# unfocused), and fullscreen keeps the border under a bar that names the
# zone, and the zones that hold the microphone and the camera. A zone's
# popups are drawn inside its window's frame and last while the window has
# the keyboard.

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

/* Kryptik: the zones that hold the microphone and the camera, which the bar
 * over a fullscreen window names: that window covers the chrome's own windows
 * that say so. Each comes from a file only its writer can leave, the mixer's
 * for the microphone and kryptikd's for the camera. */
#define MICMARK "/run/kryptik-sound/control/microphone"
#define CAMMARK "/run/kryptik-camera/grant"
#define MARKEVENTS (IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM | IN_DELETE)
#define SOUNDUID 87 /* the mixer's, build/services/kryptik-sound/run */
static char miczone[16], camzone[16];
static int markfd = -1;
static struct wl_event_source *marktimer;

/* The zone FILE names after PREFIX on its first line, into OUT: nothing unless
 * FILE is a regular file of OWNER's that no one else may write, and the name a
 * zone of zonecolors_table, the zones dwl serves a socket. */
static void
readmark(const char *file, uid_t owner, const char *prefix, char *out, size_t size)
{
\tchar buf[64], *name;
\tconst ZoneColor *z;
\tstruct stat st;
\tssize_t n = 0;
\tint fd;

\tout[0] = '\\0';
\tif ((fd = open(file, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)) < 0)
\t\treturn;
\tif (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == owner && !(st.st_mode & 022))
\t\tn = read(fd, buf, sizeof(buf) - 1);
\tclose(fd);
\tif (n <= 0)
\t\treturn;
\tbuf[n] = '\\0';
\tbuf[strcspn(buf, "\\n")] = '\\0';
\tif (strncmp(buf, prefix, strlen(prefix)) != 0)
\t\treturn;
\tname = buf + strlen(prefix);
\tfor (z = zonecolors_table; z < END(zonecolors_table); z++)
\t\tif (strcmp(z->zone, name) == 0)
\t\t\tsnprintf(out, size, "%s", name);
}

/* Kryptik: a fullscreen window leaves the top barpx rows of its output to a
 * bar in its zone's colour that names the zone, outside the window's frame:
 * its surfaces and its popups are clipped to the frame. After the name, the
 * zones that hold the microphone and the camera, whichever zones they are. */
static void
zonebar(Client *c)
{
\tstatic const float black[] = {0, 0, 0, 1}, white[] = {1, 1, 1, 1};
\tconst ZoneColor *z = clientzone(c);
\tconst float *ink;
\tstruct wlr_box box = c->mon->m;
\tchar name[64] = "zone 0";
\tint s = (int)barscale, pad = ((int)barpx - 7 * s) / 2, x, row, col, n;
\tsize_t i;

\tzonecolors(c);
\tif (z)
\t\tsnprintf(name, sizeof(name), "%s", z->zone);
\tif (miczone[0])
\t\tsnprintf(name + strlen(name), sizeof(name) - strlen(name), "   mic %s", miczone);
\tif (camzone[0])
\t\tsnprintf(name + strlen(name), sizeof(name) - strlen(name), "   cam %s", camzone);
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

/* Kryptik: both files read again, and every fullscreen window's bar drawn again
 * if either holder changed. Both watches are set again too: a directory made
 * anew, or mounted over, drops its watch, which would hide every later grant. */
static void
marksupdate(void)
{
\tchar mic[16], cam[16];
\tClient *c;

\tif (markfd >= 0) {
\t\tinotify_add_watch(markfd, "/run/kryptik-sound/control", MARKEVENTS);
\t\tinotify_add_watch(markfd, "/run/kryptik-camera", MARKEVENTS);
\t}
\treadmark(MICMARK, SOUNDUID, "", mic, sizeof(mic));
\treadmark(CAMMARK, 0, "zone ", cam, sizeof(cam));
\tif (strcmp(mic, miczone) == 0 && strcmp(cam, camzone) == 0)
\t\treturn;
\tsnprintf(miczone, sizeof(miczone), "%s", mic);
\tsnprintf(camzone, sizeof(camzone), "%s", cam);
\twl_list_for_each(c, &clients, link)
\t\tif (c->isfullscreen && c->mon)
\t\t\tzonebar(c);
}

/* Kryptik: a change in either file's directory, a dropped watch among them. */
static int
marksread(int fd, uint32_t mask, void *data)
{
\tchar events[4096];

\twhile (read(fd, events, sizeof(events)) > 0)
\t\t;
\tmarksupdate();
\treturn 0;
}

/* Kryptik: a look each second besides the watches, should one have gone. */
static int
markstick(void *data)
{
\tmarksupdate();
\tif (marktimer)
\t\twl_event_source_timer_update(marktimer, 1000);
\treturn 0;
}

"""

EDITS = [
    # Client: the zone's colour, the band that marks it unfocused, the bar.
    ("""	struct wlr_scene_rect *border[4]; /* top, bottom, left, right */
""",
     """	struct wlr_scene_rect *border[4]; /* top, bottom, left, right */
	const float *zoneborder; /* Kryptik: the colour of the zone whose socket its client came through */
	struct wlr_scene_tree *band; /* Kryptik: over the border's inner edge while unfocused */
	struct wlr_scene_rect *bands[4]; /* top, bottom, left, right */
	struct wlr_scene_tree *bar; /* Kryptik: names the zone above a fullscreen window */
	int unasked; /* Kryptik: mapped behind another zone's focus; no keyboard until the user picks it */
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
	const char *zone;     /* its socket's name under /run/kryptik-compositor/<uid> */
	const float border[4];
	unsigned int proxy;   /* its proxy's uid: with the session's, the one peer its socket takes */
} ZoneColor;
"""),
    # A client's zone and its colour, placed before applyrules.
    ("""void
applyrules(Client *c)
{
""",
     """/* Kryptik: the zone whose socket the client came through (zonesockets), or
 * none for a client of dwl's own socket: the chrome, or something the
 * session user ran on the session's own display. */
static const ZoneColor *
clientzone(Client *c)
{
	return wl_client_get_user_data(wl_resource_get_client(client_surface(c)->resource));
}

/* Kryptik: the border colour is the compositor's statement of which zone a
 * window belongs to: the zone of its client's socket, whatever app_id or
 * title the client set. A client of dwl's own socket is drawn as unzoned. */
static void
zonecolors(Client *c)
{
	const ZoneColor *z = clientzone(c);

	c->zoneborder = z ? z->border : unzonedcolor;
}

void
applyrules(Client *c)
{
"""),
    # applyrules: a zone's window matches the rules by its socket's zone, never by its claims.
    ("""\t/* rule matching */
\tconst char *appid, *title;
\tuint32_t newtags = 0;
\tint i;
\tconst Rule *r;
\tMonitor *mon = selmon, *m;

\tappid = client_get_appid(c);
\ttitle = client_get_title(c);
""",
     """\t/* rule matching */
\tconst char *appid, *title;
\tuint32_t newtags = 0;
\tint i;
\tconst Rule *r;
\tMonitor *mon = selmon, *m;
\tconst ZoneColor *z = clientzone(c);
\tchar zoneid[64];

\tappid = client_get_appid(c);
\ttitle = client_get_title(c);
\t/* Kryptik: a zone's window is placed by the zone its socket names, never by
\t * what its client claims: the rules see kryptik.<zone>. and no title. */
\tif (z) {
\t\tsnprintf(zoneid, sizeof(zoneid), "kryptik.%s.", z->zone);
\t\tappid = zoneid;
\t\ttitle = "";
\t}
"""),
    # The zones' sockets: one each, accepted by hand so that dwl knows the
    # zone of every client, and the globals a zone's client is offered.
    ("""#include <getopt.h>
""",
     """#define _GNU_SOURCE /* Kryptik: struct ucred, for the peer of a zone's socket */
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
"""),
    ("""#include <stdlib.h>
#include <sys/wait.h>
""",
     """#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
"""),
    ("""void
run(char *startup_cmd)
{
""",
     """/* Kryptik: what a zone's socket offers, the list its proxy lets through
 * (compositor/wlproxy/src/policy.rs): both must be wrong before a zone gets
 * a global the proxy hides. */
static const char *const zoneglobals[] = {
\t"wl_compositor", "wl_subcompositor", "wl_shm", "wl_seat", "wl_output",
\t"xdg_wm_base", "zxdg_decoration_manager_v1", "wp_viewporter",
\t"wp_cursor_shape_manager_v1",
};

/* Kryptik: a client of a zone's socket is told only of zoneglobals, and
 * binding another global by its number ends its connection; a client of
 * dwl's own socket sees them all. */
static bool
zoneglobal(const struct wl_client *client, const struct wl_global *global, void *data)
{
\tconst char *name = wl_global_get_interface(global)->name;
\tsize_t i;

\tif (!wl_client_get_user_data((struct wl_client *)client))
\t\treturn true;
\tfor (i = 0; i < LENGTH(zoneglobals); i++)
\t\tif (strcmp(zoneglobals[i], name) == 0)
\t\t\treturn true;
\treturn false;
}

/* Kryptik: a zone socket's clients at once (its proxy holds at most 32), and per zone the
 * live clients and the refused connections. */
static const unsigned int zoneclientsmax = 64;
static unsigned int zoneclients[LENGTH(zonecolors_table)], zonerefused[LENGTH(zonecolors_table)];

struct zoneclient {
\tstruct wl_listener destroy;
\tsize_t zone;
};

static void
zoneclientgone(struct wl_listener *listener, void *data)
{
\tstruct zoneclient *zc = wl_container_of(listener, zc, destroy);

\tzoneclients[zc->zone]--;
\twl_list_remove(&zc->destroy.link);
\tfree(zc);
}

/* Kryptik: a client accepted on a zone's socket is that zone's while it is connected. Anyone
 * reaches the socket; the session's own programs and the zone's proxy alone are taken, and no
 * more at once than zoneclientsmax, so not even the proxy fills dwl's descriptors. */
static int
zoneaccept(int fd, uint32_t mask, void *data)
{
\tconst ZoneColor *z = data;
\tsize_t i = (size_t)(z - zonecolors_table);
\tstruct zoneclient *zc = NULL;
\tstruct wl_client *client;
\tstruct ucred cr = {0};
\tsocklen_t len = sizeof(cr);
\tint cfd = accept(fd, NULL, NULL);

\tif (cfd < 0)
\t\treturn 0;
\tif (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cr, &len) < 0
\t\t\t|| (cr.uid != getuid() && cr.uid != z->proxy) || zoneclients[i] >= zoneclientsmax) {
\t\t/* Said at the 1st, 2nd, 4th, 8th... refusal, so no flood of them fills the log. */
\t\tzonerefused[i]++;
\t\tif ((zonerefused[i] & (zonerefused[i] - 1)) == 0)
\t\t\tfprintf(stderr, "dwl: zone %s refused a client of uid %u (%u refused)\\n",
\t\t\t\t\tz->zone, (unsigned int)cr.uid, zonerefused[i]);
\t\tclose(cfd);
\t\treturn 0;
\t}
\tif (fcntl(cfd, F_SETFD, FD_CLOEXEC) < 0 || !(zc = calloc(1, sizeof(*zc)))
\t\t\t|| !(client = wl_client_create(dpy, cfd))) {
\t\tfree(zc);
\t\tclose(cfd);
\t\treturn 0;
\t}
\twl_client_set_user_data(client, data, NULL);
\tzc->zone = i;
\tzc->destroy.notify = zoneclientgone;
\twl_client_add_destroy_listener(client, &zc->destroy);
\tzoneclients[i]++;
\treturn 0;
}

/* Kryptik: a socket for each zone, /run/kryptik-compositor/<uid>/<zone>, in the directory
 * kryptikd makes for the session; kryptikd gives it the zone's proxy as its upstream. */
static void
zonesockets(void)
{
\tconst ZoneColor *z;
\tstruct sockaddr_un sa = {.sun_family = AF_UNIX};
\tstruct stat st;
\tchar dir[sizeof(sa.sun_path)];
\tint fd;

\twl_display_set_global_filter(dpy, zoneglobal, NULL);
\tsnprintf(dir, sizeof(dir), "/run/kryptik-compositor/%u", (unsigned int)getuid());
\tif (stat(dir, &st) < 0)
\t\tdie("startup: %s, which kryptikd makes for the session:", dir);
\t/* A zone whose socket fails opens no window; the others' still do. */
\tfor (z = zonecolors_table; z < END(zonecolors_table); z++) {
\t\tif (snprintf(sa.sun_path, sizeof(sa.sun_path), "%s/%s", dir, z->zone) >= (int)sizeof(sa.sun_path)) {
\t\t\tfprintf(stderr, "dwl: zone %s gets no socket: its path is too long\\n", z->zone);
\t\t\tcontinue;
\t\t}
\t\tunlink(sa.sun_path);
\t\tif ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)) < 0) {
\t\t\tfprintf(stderr, "dwl: zone %s gets no socket: %s\\n", z->zone, strerror(errno));
\t\t} else if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 || chmod(sa.sun_path, 0666) < 0
\t\t\t\t|| listen(fd, 16) < 0
\t\t\t\t|| !wl_event_loop_add_fd(event_loop, fd, WL_EVENT_READABLE, zoneaccept, (void *)z)) {
\t\t\tfprintf(stderr, "dwl: zone %s gets no socket at %s: %s\\n", z->zone, sa.sun_path, strerror(errno));
\t\t\tclose(fd);
\t\t}
\t}
}

void
run(char *startup_cmd)
{
"""),
    ("""\tsetenv("WAYLAND_DISPLAY", socket, 1);
""",
     """\tsetenv("WAYLAND_DISPLAY", socket, 1);
\t/* Kryptik: and a socket for each zone, its proxy's. */
\tzonesockets();
"""),
    # The status the chrome reads names the zone the same way.
    ("""\t\t\tprintf("%s appid %s\\n", m->wlr_output->name, client_get_appid(c));
""",
     """\t\t\tprintf("%s appid %s\\n", m->wlr_output->name, client_get_appid(c));
\t\t\tprintf("%s zone %s\\n", m->wlr_output->name, clientzone(c) ? clientzone(c)->zone : "0");
"""),
    ("""\t\t\tprintf("%s appid \\n", m->wlr_output->name);
""",
     """\t\t\tprintf("%s appid \\n", m->wlr_output->name);
\t\t\tprintf("%s zone \\n", m->wlr_output->name);
"""),
    # The browser key and the menu's b put a zone's open browser in front
    # (docs/design/browser-and-graphics.md). The window is found by the zone of
    # its client's socket and the app_id its proxy stamps, kryptik.<zone>.<claimed>,
    # so a client that claims another zone's browser is never taken.
    ("""} ZoneColor;
""",
     """} ZoneColor;

typedef struct {
\tconst char *zone;     /* whose window is sought, by its socket */
\tconst char *claimed;  /* the app_id its client claims, before the proxy's kryptik.<zone>. */
\tconst char **cmd;     /* started when the zone has no such window */
} FocusOrLaunch;
"""),
    ("""static void focusmon(const Arg *arg);
""",
     """static void focusmon(const Arg *arg);
static void focusorlaunch(const Arg *arg);
"""),
    ("""void
focusmon(const Arg *arg)
{
""",
     """#include <sys/inotify.h>

/* Kryptik: ZONE's window whose app_id is kryptik.ZONE.CLAIMED, the one used
 * last, or NULL. The zone is its socket's, never the client's word. */
static Client *
zonewindow(const char *zone, const char *claimed)
{
\tconst ZoneColor *z;
\tchar want[160];
\tClient *c;

\tif (snprintf(want, sizeof(want), "kryptik.%s.%s", zone, claimed) >= (int)sizeof(want))
\t\treturn NULL;
\twl_list_for_each(c, &fstack, flink) {
\t\tz = clientzone(c);
\t\tif (c->mon && z && strcmp(z->zone, zone) == 0 && strcmp(client_get_appid(c), want) == 0)
\t\t\treturn c;
\t}
\treturn NULL;
}

/* Kryptik: C put in front where it is, never moved to another tag: its first
 * tag viewed on its own monitor when it is not shown there, then the keyboard,
 * as Alt and the tag's number and a pick would. */
static void
bringforward(Client *c)
{
\tArg a;

\tif (locked || !c->mon)
\t\treturn;
\tselmon = c->mon;
\tif (!VISIBLEON(c, c->mon)) {
\t\ta.ui = c->tags & -c->tags;
\t\tview(&a);
\t}
\tfocusclient(c, 1);
}

/* Kryptik: the zone's open window of that app_id in front, or its command
 * started when it has none: the browser key. */
void
focusorlaunch(const Arg *arg)
{
\tconst FocusOrLaunch *f = arg->v;
\tClient *c = zonewindow(f->zone, f->claimed);
\tArg a = {.v = f->cmd};

\tif (c)
\t\tbringforward(c);
\telse
\t\tspawn(&a);
}

/* Kryptik: the chrome's menu asks for a zone's open browser in front with one
 * line naming the zone in $XDG_RUNTIME_DIR/kryptik/browser-front. It is taken
 * only from a regular file of the session user's that no one else may write,
 * in a directory of that user's that no one else may write, and removed before
 * it is acted on. It only brings a window forward: every launch stays the
 * chrome's, which asks a zone's passphrase on its own terminal. */
static char frontdir[256], frontfile[288];
static int frontfd = -1;
static struct wl_event_source *fronttimer;

static void
frontread(void)
{
\tchar buf[64];
\tconst ZoneColor *z;
\tstruct stat st, dir;
\tssize_t n = 0;
\tClient *c;
\tint fd;

\tif (!frontfile[0])
\t\treturn;
\tif (frontfd >= 0)
\t\tinotify_add_watch(frontfd, frontdir, IN_CLOSE_WRITE | IN_MOVED_TO);
\tif ((fd = open(frontfile, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)) < 0) {
\t\tif (errno != ENOENT)
\t\t\tunlink(frontfile);
\t\treturn;
\t}
\tif (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == getuid() && !(st.st_mode & 022)
\t\t\t&& stat(frontdir, &dir) == 0 && dir.st_uid == getuid() && !(dir.st_mode & 022))
\t\tn = read(fd, buf, sizeof(buf) - 1);
\tclose(fd);
\tunlink(frontfile);
\tif (n <= 0)
\t\treturn;
\tbuf[n] = '\\0';
\tbuf[strcspn(buf, "\\n")] = '\\0';
\tfor (z = zonecolors_table; z < END(zonecolors_table); z++)
\t\tif (strcmp(z->zone, buf) == 0 && (c = zonewindow(z->zone, browserappid)))
\t\t\tbringforward(c);
}

static int
frontevent(int fd, uint32_t mask, void *data)
{
\tchar events[4096];

\twhile (read(fd, events, sizeof(events)) > 0)
\t\t;
\tfrontread();
\treturn 0;
}

/* Kryptik: a look each second besides the watch, which the directory, made by
 * the chrome after dwl starts, may not have yet. */
static int
fronttick(void *data)
{
\tfrontread();
\twl_event_source_timer_update(fronttimer, 1000);
\treturn 0;
}

static void
frontwatch(void)
{
\tconst char *rt = getenv("XDG_RUNTIME_DIR");

\tif (!rt || snprintf(frontdir, sizeof(frontdir), "%s/kryptik", rt) >= (int)sizeof(frontdir)
\t\t\t|| snprintf(frontfile, sizeof(frontfile), "%s/browser-front", frontdir) >= (int)sizeof(frontfile)) {
\t\tfrontfile[0] = '\\0';
\t\treturn;
\t}
\tif ((frontfd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC)) >= 0)
\t\twl_event_loop_add_fd(event_loop, frontfd, WL_EVENT_READABLE, frontevent, NULL);
\tif ((fronttimer = wl_event_loop_add_timer(event_loop, fronttick, NULL)))
\t\tfronttick(NULL);
}

void
focusmon(const Arg *arg)
{
"""),
    # printstatus: the zones whose browser is open, for the menu's b, among the
    # selected output's lines, before the layout line that ends them.
    ("""\t\tprintf("%s layout %s\\n", m->wlr_output->name, m->ltsymbol);
""",
     """\t\tif (m == selmon) {
\t\t\tconst ZoneColor *z;

\t\t\tprintf("%s browsers", m->wlr_output->name);
\t\t\tfor (z = zonecolors_table; z < END(zonecolors_table); z++)
\t\t\t\tif (zonewindow(z->zone, browserappid))
\t\t\t\t\tprintf(" %s", z->zone);
\t\t\tprintf("\\n");
\t\t}
\t\tprintf("%s layout %s\\n", m->wlr_output->name, m->ltsymbol);
"""),
    # run: the menu's requests watched once the event loop runs.
    ("""\tzonesockets();
""",
     """\tzonesockets();
\t/* Kryptik: the menu's requests to put a zone's open browser in front. */
\tfrontwatch();
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
    # Mapping a different zone must not move it ahead of the active window,
    # nor right behind it, where it would get the keyboard when that one closes;
    # nor ahead of everything while the session is locked, or it would get the
    # keyboard at the unlock.
    ("""\twl_list_insert(&clients, &c->link);
\twl_list_insert(&fstack, &c->flink);
""",
     """\twl_list_insert(&clients, &c->link);
\t/* Compare with the actual keyboard focus, which may be on another monitor.
\t * Another zone's window goes to the back of the focus order: right behind
\t * the focused window it would take the keyboard when that one closes.
\t * While locked the lock has it, and nobody picked a window mapped then. */
\tw = NULL;
\ttoplevel_from_wlr_surface(seat->keyboard_state.focused_surface, &w, NULL);
\tif (c->zoneborder != unzonedcolor && (locked || (w && !client_is_unmanaged(w)
\t\t\t&& w->zoneborder != c->zoneborder))) {
\t\twl_list_insert(fstack.prev, &c->flink);
\t\tc->unasked = 1;
\t} else
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
\t\tif (VISIBLEON(c, m) && !covered(c, m) && !c->unasked)
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
    # A window nobody picked yet is passed over by focustop, so nothing but the
    # user hands it the keyboard: focusstack starts there when nothing else
    # shows, and focusclient marks it picked.
    ("""\tClient *c, *sel = focustop(selmon);
\tif (!sel || (sel->isfullscreen && !client_has_children(sel)))
\t\treturn;
""",
     """\tClient *c, *sel = focustop(selmon);
\tif (!sel)
\t\twl_list_for_each(c, &clients, link)
\t\t\tif (VISIBLEON(c, selmon) && !covered(c, selmon)) {
\t\t\t\tsel = c;
\t\t\t\tbreak;
\t\t\t}
\tif (!sel || (sel->isfullscreen && !client_has_children(sel)))
\t\treturn;
"""),
    ("""\t\tselmon = c->mon;
\t\tc->isurgent = 0;
""",
     """\t\tselmon = c->mon;
\t\tc->isurgent = 0;
\t\tc->unasked = 0;
"""),
    # A zone's popup is placed inside its window, below its border. dwl
    # parents a popup to the client's tree, beside the clipped surface, and
    # places it on the whole monitor.
    ("""\tbox.y -= (type == LayerShell ? l->scene->node.y : c->geom.y);
\twlr_xdg_popup_unconstrain_from_box(popup, &box);
""",
     """\tbox.y -= (type == LayerShell ? l->scene->node.y : c->geom.y);
\t/* Kryptik: a zone's popup is placed inside its window, below its border. */
\tif (c && c->zoneborder != unzonedcolor)
\t\tbox = (struct wlr_box){(int)c->bw, (int)c->bw, c->geom.width - 2 * (int)c->bw, c->geom.height - 2 * (int)c->bw};
\twlr_xdg_popup_unconstrain_from_box(popup, &box);
"""),
    # A client may draw a popup of any size wherever it is placed, so before
    # each frame every zone popup is clipped to its window's content.
    ("""void
rendermon(struct wl_listener *listener, void *data)
{
""",
     """/* Kryptik: a zone's popups, and theirs in turn, are drawn inside its window
 * and nowhere else, whatever their size or place. The clip is in each popup
 * surface's own coordinates; an empty one would turn clipping off. */
static void
clippopups(Client *c, struct wlr_xdg_surface *parent)
{
\tstruct wlr_xdg_popup *popup;
\tstruct wlr_scene_tree *tree;
\tstruct wlr_box clip;
\tint x, y;

\twl_list_for_each(popup, &parent->popups, link) {
\t\tif (!(tree = popup->base->surface->data))
\t\t\tcontinue;
\t\twlr_scene_node_coords(&tree->node, &x, &y);
\t\tclip = (struct wlr_box){
\t\t\t.x = c->geom.x + (int)c->bw - x + popup->base->geometry.x,
\t\t\t.y = c->geom.y + (int)c->bw - y + popup->base->geometry.y,
\t\t\t.width = c->geom.width - 2 * (int)c->bw,
\t\t\t.height = c->geom.height - 2 * (int)c->bw,
\t\t};
\t\twlr_scene_node_set_enabled(&tree->node, !wlr_box_empty(&clip));
\t\tif (wlr_box_empty(&clip))
\t\t\tcontinue;
\t\twlr_scene_subsurface_tree_set_clip(&tree->node, &clip);
\t\t/* That reached its children's trees too, in the wrong coordinates. */
\t\tclippopups(c, popup->base);
\t}
}

void
rendermon(struct wl_listener *listener, void *data)
{
"""),
    ("""\t/* Render if no XDG clients have an outstanding resize and are visible on
\t * this monitor. */
""",
     """\t/* Kryptik: a zone's popups, wherever they moved since, stay inside its window. */
\twl_list_for_each(c, &clients, link)
\t\tif (c->zoneborder != unzonedcolor)
\t\t\tclippopups(c, c->surface.xdg);

\t/* Render if no XDG clients have an outstanding resize and are visible on
\t * this monitor. */
"""),
    # A popup's grab, which wlroots grants without checking its serial, keeps
    # the keyboard where it is: focusclient ends every popup, not only the old
    # window's, before the keyboard moves. The new window's own go as well: one
    # made while the window had no keyboard could only grab it unasked, and its
    # grab would swallow the window's enter while the keys went on to the old
    # window. A session lock and a keyboard layer call focusclient(NULL) first.
    ("""void
focusclient(Client *c, int lift)
{
""",
     """/* Kryptik: popups last while their window keeps the keyboard. */
static void
endpopups(void)
{
\tstruct wlr_xdg_popup *popup, *tmp;
\tClient *c;

\twl_list_for_each(c, &clients, link)
\t\twl_list_for_each_safe(popup, tmp, &c->surface.xdg->popups, link)
\t\t\twlr_xdg_popup_destroy(popup);
}

void
focusclient(Client *c, int lift)
{
"""),
    ("""\tif ((old_client_type = toplevel_from_wlr_surface(old, &old_c, &old_l)) == XDGShell) {
\t\tstruct wlr_xdg_popup *popup, *tmp;
\t\twl_list_for_each_safe(popup, tmp, &old_c->surface.xdg->popups, link)
\t\t\twlr_xdg_popup_destroy(popup);
\t}
""",
     """\told_client_type = toplevel_from_wlr_surface(old, &old_c, &old_l);
\tendpopups();
"""),
    # A lock surface takes the keyboard without focusclient, which does
    # nothing while the session is locked: each such hand-over ends every
    # popup first, or a zone's grab, made at any moment, would keep the
    # keyboard from the lock.
    ("""static void focusclient(Client *c, int lift);
""",
     """static void focusclient(Client *c, int lift);
static void endpopups(void);
"""),
    ("""\tif (m == selmon)
\t\tclient_notify_enter(lock_surface->surface, wlr_seat_get_keyboard(seat));
""",
     """\tif (m == selmon) {
\t\tendpopups();
\t\tclient_notify_enter(lock_surface->surface, wlr_seat_get_keyboard(seat));
\t}
"""),
    ("""\t\tsurface = wl_container_of(cur_lock->surfaces.next, surface, link);
\t\tclient_notify_enter(surface->surface, wlr_seat_get_keyboard(seat));
""",
     """\t\tsurface = wl_container_of(cur_lock->surfaces.next, surface, link);
\t\tendpopups();
\t\tclient_notify_enter(surface->surface, wlr_seat_get_keyboard(seat));
"""),
    ("""\t\tif (selmon->lock_surface) {
\t\t\tclient_notify_enter(selmon->lock_surface->surface,
""",
     """\t\tif (selmon->lock_surface) {
\t\t\tendpopups();
\t\t\tclient_notify_enter(selmon->lock_surface->surface,
"""),
    # The lid: dwl leaves switch devices alone, and a lid is one. Closed, it runs
    # suspendcmd, the lock that then has the machine sleep, as the power key does;
    # it runs while the session is locked too, when that lock is asked instead.
    ("""#include <wlr/types/wlr_subcompositor.h>
""",
     """#include <wlr/types/wlr_subcompositor.h>
#include <wlr/types/wlr_switch.h>
"""),
    ("""static void createpointer(struct wlr_pointer *pointer);
""",
     """static void createpointer(struct wlr_pointer *pointer);
static void createswitch(struct wlr_switch *sw);
"""),
    ("""\tcase WLR_INPUT_DEVICE_POINTER:
\t\tcreatepointer(wlr_pointer_from_input_device(device));
\t\tbreak;
""",
     """\tcase WLR_INPUT_DEVICE_POINTER:
\t\tcreatepointer(wlr_pointer_from_input_device(device));
\t\tbreak;
\tcase WLR_INPUT_DEVICE_SWITCH:
\t\tcreateswitch(wlr_switch_from_input_device(device));
\t\tbreak;
"""),
    ("""void
inputdevice(struct wl_listener *listener, void *data)
{
""",
     """/* Kryptik: a switch, the lid's or another's, with its listeners and when it came. */
typedef struct {
\tstruct wl_listener toggle;
\tstruct wl_listener destroy;
\tstruct timespec added;
} Switch;

/* Kryptik: an output other than the built-in panel is on, or only blanked: the laptop is
 * docked, and its lid closes with the work going on elsewhere. */
static int
docked(void)
{
\tMonitor *m;
\twl_list_for_each(m, &mons, link) {
\t\tconst char *n = m->wlr_output->name;
\t\tif ((m->wlr_output->enabled || m->asleep) && strncmp(n, "eDP", 3)
\t\t\t\t&& strncmp(n, "LVDS", 4) && strncmp(n, "DSI", 3))
\t\t\treturn 1;
\t}
\treturn 0;
}

static void
switchtoggle(struct wl_listener *listener, void *data)
{
\tSwitch *s = wl_container_of(listener, s, toggle);
\tstruct wlr_switch_toggle_event *event = data;
\tstruct timespec now;
\tif (event->switch_type != WLR_SWITCH_TYPE_LID || event->switch_state != WLR_SWITCH_STATE_ON)
\t\treturn;
\t/* libinput tells a lid closed already when the device comes, for a switch it trusts:
\t * a session started with the lid shut must not sleep for it. */
\tclock_gettime(CLOCK_MONOTONIC, &now);
\tif (now.tv_sec - s->added.tv_sec < 2 || docked())
\t\treturn;
\tspawn(&(Arg){.v = suspendcmd});
}

static void
switchdestroy(struct wl_listener *listener, void *data)
{
\tSwitch *s = wl_container_of(listener, s, destroy);
\twl_list_remove(&s->toggle.link);
\twl_list_remove(&s->destroy.link);
\tfree(s);
}

void
createswitch(struct wlr_switch *sw)
{
\tSwitch *s = ecalloc(1, sizeof(*s));
\tclock_gettime(CLOCK_MONOTONIC, &s->added);
\tLISTEN(&sw->events.toggle, &s->toggle, switchtoggle);
\tLISTEN(&sw->base.events.destroy, &s->destroy, switchdestroy);
}

void
inputdevice(struct wl_listener *listener, void *data)
{
"""),
    # Locked, dwl heeds no key at all, so a laptop that starts to play aloud under the lock
    # is silenced only by unlocking. It heeds config.h's lockedkeys instead: the volume and
    # brightness keys, which reach no zone and nothing typed at the lock. A key held from
    # before the lock repeats through the same table.
    ("""\tconst Key *k;
\tfor (k = keys; k < END(keys); k++) {
""",
     """\t/* Kryptik: while the session is locked, lockedkeys alone. */
\tconst Key *k = locked ? lockedkeys : keys, *end = locked ? END(lockedkeys) : END(keys);
\tfor (; k < end; k++) {
"""),
    # The marks' headers.
    ("#include <sys/wait.h>\n",
     "#include <sys/inotify.h>\n#include <sys/wait.h>\n"),
    # setup: one inotify descriptor on the two files' directories, read at once.
    ("""\tseat = wlr_seat_create(dpy, "seat0");
""",
     """\t/* Kryptik: the microphone's and the camera's holders, for the bar: watched,
\t * and looked at each second besides. */
\tif ((markfd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC)) >= 0)
\t\twl_event_loop_add_fd(event_loop, markfd, WL_EVENT_READABLE, marksread, NULL);
\tmarktimer = wl_event_loop_add_timer(event_loop, markstick, NULL);
\tmarkstick(NULL);
\tseat = wlr_seat_create(dpy, "seat0");
"""),
    ("""\t/* On _press_ if there is no active screen locker,
\t * attempt to process a compositor keybinding. */
\tif (!locked && event->state == WL_KEYBOARD_KEY_STATE_PRESSED) {
""",
     """\t/* On _press_ attempt to process a compositor keybinding, which while
\t * the session is locked is one of lockedkeys. */
\tif (event->state == WL_KEYBOARD_KEY_STATE_PRESSED) {
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
